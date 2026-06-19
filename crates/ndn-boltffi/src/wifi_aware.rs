//! Wi-Fi Aware (NAN) coordination face — the FFI seam.
//!
//! Wi-Fi Aware is AP-less peer Wi-Fi whose native primitive is publish/subscribe
//! by service *name* — NDN's model in silicon, and the real AirDrop transport.
//! The radio lives behind [`NdnNanBackend`], implemented in the app over the
//! platform's NAN API (Android `WifiAwareManager`). Because the radio is async
//! and event-driven while FFI calls are synchronous, the seam is **two-way**:
//!
//! - **app → engine** ([`NdnNanBackend`], a callback the engine holds): the
//!   engine asks the radio to `broadcast` a follow-up frame and to
//!   `publish`/`subscribe` a service.
//! - **engine ← app**: the app pushes each received follow-up and each
//!   discovered peer back in by calling
//!   [`NdnEngine::nan_deliver_followup`](crate::NdnEngine::nan_deliver_followup) /
//!   [`NdnEngine::nan_on_match`](crate::NdnEngine::nan_on_match) — methods on the
//!   engine handle it already holds (boltffi opaque handles are not returnable
//!   nor passable across exports, so the receive side lives on `NdnEngine`).
//!
//! [`NdnEngine::attach_wifi_aware`](crate::NdnEngine::attach_wifi_aware) wires a
//! [`NanCoordFace`](ndn_face_wifi_aware::NanCoordFace) over this seam into the
//! running engine and stores the [`NanSeam`] those receive methods feed.

use boltffi::export;

/// The platform NAN radio, implemented in the app (e.g. Android `WifiAwareManager`
/// via JNI). All calls are fire-and-forget: the radio op runs asynchronously on
/// the platform side; received frames/peers come back through
/// [`NdnEngine::nan_deliver_followup`](crate::NdnEngine::nan_deliver_followup) /
/// [`NdnEngine::nan_on_match`](crate::NdnEngine::nan_on_match).
#[export]
pub trait NdnNanBackend: Send + Sync {
    /// Send `frame` (an NDN packet, possibly LP-fragmented) as a NAN follow-up to
    /// every currently-matched peer in the cluster — the connectionless broadcast.
    fn broadcast(&self, frame: Vec<u8>);
    /// Advertise NDN service `service` so subscribing peers discover this node.
    fn publish(&self, service: String);
    /// Subscribe to discover peers advertising NDN service `service`.
    fn subscribe(&self, service: String);
}

// The adapter half needs the `ndn-face-wifi-aware` face types, so it is gated on
// the feature. The `NdnNanBackend` trait above carries only primitives and is
// always compiled, so `attach_wifi_aware`'s signature (and its boltffi callback
// binding) exist in every build — its body no-ops when the feature is off.
#[cfg(feature = "wifi-aware")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "wifi-aware")]
use bytes::Bytes;
#[cfg(feature = "wifi-aware")]
use ndn_face_wifi_aware::{FaceError, FollowupFrame, NanBackend, NanMatch, NanServiceName};
#[cfg(feature = "wifi-aware")]
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// Upper bound on undrained discovered-peer records (see [`NanSeam::on_match`]).
#[cfg(feature = "wifi-aware")]
const MATCH_BUFFER_CAP: usize = 64;

/// Bound on the engine-side follow-up queue: drops under backpressure instead of
/// growing without limit (radio frames are lossy; an unbounded queue would leak
/// memory if the face reader ever stalled).
#[cfg(feature = "wifi-aware")]
const FOLLOWUP_QUEUE_CAP: usize = 256;

/// The engine-held receive side of the seam: the app's delivered follow-ups feed
/// the face's `next_followup`, and discovered peers feed its `drain_matches`.
/// Stored on [`NdnEngine`](crate::NdnEngine); not an FFI type itself.
#[cfg(feature = "wifi-aware")]
pub(crate) struct NanSeam {
    tx: mpsc::Sender<FollowupFrame>,
    matches: Arc<Mutex<Vec<NanMatch>>>,
}

#[cfg(feature = "wifi-aware")]
impl NanSeam {
    /// Deliver one received follow-up message. `peer` is the sender's 6-byte NAN
    /// management-interface MAC (empty if unknown); `rssi` is dBm (0 = unknown).
    pub(crate) fn deliver_followup(&self, frame: Vec<u8>, peer: Vec<u8>, rssi: i32) {
        // Non-blocking: drop the frame if the bounded queue is full (lossy radio).
        let _ = self.tx.try_send(FollowupFrame {
            frame: Bytes::from(frame),
            peer: <[u8; 6]>::try_from(peer.as_slice()).ok(),
            rssi_dbm: i8::try_from(rssi).ok().filter(|&r| r != 0),
        });
    }

    /// Record that `peer` (6-byte NAN MAC) was discovered advertising `service`.
    /// The runtime attach installs no `NanDiscovery`, so nothing drains these in
    /// that path (they're available for signal/density use); bound the buffer so
    /// repeated discovery callbacks can't grow it without limit.
    pub(crate) fn on_match(&self, service: String, peer: Vec<u8>) {
        if let Ok(peer) = <[u8; 6]>::try_from(peer.as_slice()) {
            let mut matches = self.matches.lock().unwrap();
            if matches.len() >= MATCH_BUFFER_CAP {
                matches.remove(0);
            }
            matches.push(NanMatch {
                service: NanServiceName(service),
                peer,
            });
        }
    }
}

/// Rust adapter: presents the app's [`NdnNanBackend`] + the seam channel as the
/// [`NanBackend`] the coordination face drives.
#[cfg(feature = "wifi-aware")]
pub(crate) struct FfiNanBackend {
    app: Arc<dyn NdnNanBackend>,
    rx: AsyncMutex<mpsc::Receiver<FollowupFrame>>,
    matches: Arc<Mutex<Vec<NanMatch>>>,
}

#[cfg(feature = "wifi-aware")]
#[async_trait::async_trait]
impl NanBackend for FfiNanBackend {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        self.app.broadcast(frame.to_vec());
        Ok(())
    }

    async fn next_followup(&self) -> Result<FollowupFrame, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn publish(&self, service: &NanServiceName) -> Result<(), FaceError> {
        self.app.publish(service.0.clone());
        Ok(())
    }

    async fn subscribe(&self, service: &NanServiceName) -> Result<(), FaceError> {
        self.app.subscribe(service.0.clone());
        Ok(())
    }

    fn drain_matches(&self) -> Vec<NanMatch> {
        std::mem::take(&mut self.matches.lock().unwrap())
    }
}

/// Build the face-side adapter + engine-side seam sharing one follow-up channel
/// and one match queue.
#[cfg(feature = "wifi-aware")]
pub(crate) fn make_seam(app: Box<dyn NdnNanBackend>) -> (Arc<FfiNanBackend>, NanSeam) {
    let (tx, rx) = mpsc::channel(FOLLOWUP_QUEUE_CAP);
    let matches = Arc::new(Mutex::new(Vec::new()));
    let backend = Arc::new(FfiNanBackend {
        app: app.into(),
        rx: AsyncMutex::new(rx),
        matches: Arc::clone(&matches),
    });
    (backend, NanSeam { tx, matches })
}

#[cfg(all(test, feature = "wifi-aware"))]
mod tests {
    use super::*;

    /// Records what the engine asked the radio to do.
    #[derive(Default)]
    struct MockState {
        broadcasts: Mutex<Vec<Vec<u8>>>,
        published: Mutex<Vec<String>>,
        subscribed: Mutex<Vec<String>>,
    }

    struct MockBackend(Arc<MockState>);

    impl NdnNanBackend for MockBackend {
        fn broadcast(&self, frame: Vec<u8>) {
            self.0.broadcasts.lock().unwrap().push(frame);
        }
        fn publish(&self, service: String) {
            self.0.published.lock().unwrap().push(service);
        }
        fn subscribe(&self, service: String) {
            self.0.subscribed.lock().unwrap().push(service);
        }
    }

    /// The adapter bridges both directions: engine→radio calls reach the app
    /// backend, and app→engine pushes (via the seam) surface on the face's
    /// `next_followup` / `drain_matches`.
    #[tokio::test]
    async fn ffi_adapter_bridges_both_directions() {
        let state = Arc::new(MockState::default());
        let (ffi, seam) = make_seam(Box::new(MockBackend(Arc::clone(&state))));

        // engine → radio: the face's NanBackend calls land on the app backend.
        let svc = NanServiceName("ndn-airdrop".into());
        ffi.publish(&svc).await.unwrap();
        ffi.subscribe(&svc).await.unwrap();
        ffi.broadcast(Bytes::from_static(b"interest-wire"))
            .await
            .unwrap();
        assert_eq!(state.published.lock().unwrap().as_slice(), ["ndn-airdrop"]);
        assert_eq!(state.subscribed.lock().unwrap().as_slice(), ["ndn-airdrop"]);
        assert_eq!(
            state.broadcasts.lock().unwrap().as_slice(),
            [b"interest-wire".to_vec()]
        );

        // app → engine: a delivered follow-up surfaces on next_followup, carrying
        // the peer MAC and RSSI through unchanged.
        let peer = vec![0x02, 0, 0, 0, 0, 0x7a];
        seam.deliver_followup(b"data-wire".to_vec(), peer.clone(), -42);
        let got = ffi.next_followup().await.unwrap();
        assert_eq!(got.frame.as_ref(), b"data-wire");
        assert_eq!(got.peer, Some([0x02, 0, 0, 0, 0, 0x7a]));
        assert_eq!(got.rssi_dbm, Some(-42));

        // app → engine: a discovered peer surfaces (once) on drain_matches.
        seam.on_match("ndn-airdrop".into(), peer);
        let matches = ffi.drain_matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service.0, "ndn-airdrop");
        assert_eq!(matches[0].peer, [0x02, 0, 0, 0, 0, 0x7a]);
        assert!(ffi.drain_matches().is_empty(), "matches drain once");
    }

    /// Unknown/short peer MACs and a 0 RSSI degrade to `None` rather than
    /// fabricating addressing — consistent with [[no-host-addressing-assumption]].
    #[tokio::test]
    async fn unknown_peer_and_rssi_degrade_to_none() {
        let state = Arc::new(MockState::default());
        let (ffi, seam) = make_seam(Box::new(MockBackend(state)));

        seam.deliver_followup(b"x".to_vec(), Vec::new(), 0);
        let got = ffi.next_followup().await.unwrap();
        assert_eq!(got.peer, None);
        assert_eq!(got.rssi_dbm, None);

        // A short (non-6-byte) MAC on a match is dropped, not truncated.
        seam.on_match("svc".into(), vec![1, 2, 3]);
        assert!(ffi.drain_matches().is_empty());
    }
}
