//! BLE advertising face — the FFI seam.
//!
//! Connectionless BLE **advertising**: pairless, association-less broadcast that
//! carries NDN packets in advertisements. Every scanning peer in range hears
//! every frame; the NDN *name* is the addressing. It's the widest-support
//! named-radio face — BLE is on essentially every phone/wearable/MCU, where
//! Wi-Fi Aware is not — so it's the universal floor for presence/discovery and
//! small Interest/Data, complementing (not replacing) the higher-throughput
//! [`wifi_aware`](crate::wifi_aware) face.
//!
//! Like the NAN seam this is two-way, because the radio is async/event-driven
//! while FFI calls are synchronous:
//!
//! - **app → engine** ([`NdnBleBackend`]): the engine asks the radio to
//!   `broadcast` a frame as a BLE advertisement.
//! - **engine ← app**: the app pushes each scanned advertisement in via
//!   [`NdnEngine::ble_deliver_frame`](crate::NdnEngine::ble_deliver_frame) — a
//!   method on the engine handle it already holds (boltffi opaque handles are
//!   neither returnable nor passable across exports).
//!
//! [`NdnEngine::attach_ble`](crate::NdnEngine::attach_ble) wires a
//! [`BleAdvFace`](ndn_face_ble_adv::BleAdvFace) over this seam into the running
//! engine and stores the [`BleSeam`] that receive method feeds.

use boltffi::export;

/// The platform BLE radio, implemented in the app (e.g. Android
/// `BluetoothLeAdvertiser` + `BluetoothLeScanner`). Fire-and-forget: the advert
/// is queued/transmitted asynchronously; scanned frames come back through
/// [`NdnEngine::ble_deliver_frame`](crate::NdnEngine::ble_deliver_frame).
#[export]
pub trait NdnBleBackend: Send + Sync {
    /// Transmit `frame` (an NDN packet, possibly LP-fragmented to the extended-
    /// advertising MTU) as a BLE advertisement to every scanner in range.
    fn broadcast(&self, frame: Vec<u8>);
}

// The adapter half needs the `ndn-face-ble-adv` face types, so it is gated on the
// feature. The `NdnBleBackend` trait above carries only primitives and is always
// compiled, so `attach_ble`'s signature (and its boltffi callback binding) exist
// in every build — its body no-ops when the feature is off.
#[cfg(feature = "ble")]
use std::sync::Arc;

#[cfg(feature = "ble")]
use bytes::Bytes;
#[cfg(feature = "ble")]
use ndn_face_ble_adv::{AdvBackend, FaceError, ScannedFrame};
#[cfg(feature = "ble")]
use tokio::sync::{Mutex as AsyncMutex, mpsc};

/// How many scanned frames the engine-side queue holds before it sheds load.
/// BLE scanning is a firehose (the same advert is reported many times a second),
/// so the queue is **bounded** and drops under backpressure rather than growing
/// without limit — radio frames are lossy by nature, and an unbounded queue is a
/// memory leak if the face reader ever falls behind or stalls.
#[cfg(feature = "ble")]
const SCAN_QUEUE_CAP: usize = 256;

/// The engine-held receive side of the seam: the app's scanned advertisements
/// feed the face's `next_scanned`. Stored on [`NdnEngine`](crate::NdnEngine);
/// not an FFI type itself.
#[cfg(feature = "ble")]
pub(crate) struct BleSeam {
    tx: mpsc::Sender<ScannedFrame>,
}

#[cfg(feature = "ble")]
impl BleSeam {
    /// Deliver one scanned advertisement. `addr` is the sender's 6-byte BD_ADDR
    /// (empty if the controller didn't surface it / it's randomized); `rssi` is
    /// dBm (0 = unknown). Both are link-layer hints (dedup, per-neighbour RSSI),
    /// never the addressing — the NDN name inside `frame` is. Non-blocking: drops
    /// the frame if the bounded queue is full (the reader has fallen behind).
    pub(crate) fn deliver_frame(&self, frame: Vec<u8>, addr: Vec<u8>, rssi: i32) {
        let _ = self.tx.try_send(ScannedFrame {
            frame: Bytes::from(frame),
            addr: <[u8; 6]>::try_from(addr.as_slice()).ok(),
            rssi_dbm: i8::try_from(rssi).ok().filter(|&r| r != 0),
        });
    }
}

/// Rust adapter: presents the app's [`NdnBleBackend`] + the seam channel as the
/// [`AdvBackend`] the advertising face drives.
#[cfg(feature = "ble")]
pub(crate) struct FfiBleBackend {
    app: Arc<dyn NdnBleBackend>,
    rx: AsyncMutex<mpsc::Receiver<ScannedFrame>>,
}

#[cfg(feature = "ble")]
#[async_trait::async_trait]
impl AdvBackend for FfiBleBackend {
    async fn broadcast(&self, frame: Bytes) -> Result<(), FaceError> {
        self.app.broadcast(frame.to_vec());
        Ok(())
    }

    async fn next_scanned(&self) -> Result<ScannedFrame, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }
}

/// Build the face-side adapter + engine-side seam sharing one scanned-frame channel.
#[cfg(feature = "ble")]
pub(crate) fn make_seam(app: Box<dyn NdnBleBackend>) -> (Arc<FfiBleBackend>, BleSeam) {
    let (tx, rx) = mpsc::channel(SCAN_QUEUE_CAP);
    let backend = Arc::new(FfiBleBackend {
        app: app.into(),
        rx: AsyncMutex::new(rx),
    });
    (backend, BleSeam { tx })
}
