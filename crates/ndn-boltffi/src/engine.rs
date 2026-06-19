//! [`NdnEngine`] — embedded NDN forwarder for Android and iOS.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use boltffi::export;
use tokio::runtime::Runtime;

use bytes::Bytes;
use ndn_app::{Connection, Consumer, InProcConnection, Producer, Subscriber};
use ndn_face::local::InProcHandle;
use ndn_mobile::{MobileEngine, MobileEngineBuilder};
use ndn_packet::Name;

use crate::handlers::{
    NdnApprovalGate, NdnEnclaveBackend, NdnInterestHandler, NdnPinHandler, NdnRecoverySigner,
    NdnSampleHandler,
};
use crate::identity_core::IdentityCore;
use crate::types::{
    NdnActionClass, NdnContext, NdnData, NdnDelegationScope, NdnEngineConfig, NdnEnrollConfig,
    NdnEnrolledIdentity, NdnError, NdnFaceSpec, NdnRecoveredIdentity, NdnRevocation, NdnSample,
    into_security_profile,
};

/// Embedded NDN forwarder with an owned Tokio runtime. Construct once at app
/// startup, then drive it through `fetch` / `get` / `serve` / `subscribe`.
///
/// BoltFFI's object model can't pass or cross-create exported objects (a
/// deliberate trade for zero per-object marshalling), so consumer/producer/
/// subscriber operations are methods on this one object rather than separate
/// handles. The rich typed `Consumer` / `Producer` / `Subscriber` remain in
/// `ndn-app` for native Rust callers.
pub struct NdnEngine {
    pub(crate) inner: Mutex<Option<MobileEngine>>,
    /// Shared with every derived consumer/producer.
    pub(crate) rt: Arc<Runtime>,
    /// Primary handle from `builder.build()`; consumed by the first `fetch`.
    default_handle: Mutex<Option<InProcHandle>>,
    /// Lazily-built shared consumer for `fetch` / `get` (serialized).
    consumer: Mutex<Option<Consumer>>,
    /// Identity + signing + trust-context state, run over an in-proc connection
    /// to this engine's own embedded forwarder. The shared core that both
    /// `NdnEngine` and `NdnClient` delegate identity operations to.
    identity_core: IdentityCore,
    /// Engine-side receive end of the Wi-Fi Aware (NAN) seam; `Some` once
    /// [`Self::attach_wifi_aware`] has been called. `nan_deliver_followup` /
    /// `nan_on_match` push the radio's events into it.
    #[cfg(feature = "wifi-aware")]
    nan_seam: Mutex<Option<crate::wifi_aware::NanSeam>>,
    /// Engine-side receive end of the BLE seam; `Some` once [`Self::attach_ble`]
    /// has been called. `ble_deliver_frame` pushes scanned adverts into it.
    #[cfg(feature = "ble")]
    ble_seam: Mutex<Option<crate::ble::BleSeam>>,
    /// Nearby-peer discovery: the presence table + the live serve guard for the
    /// `/localhost/discovery/peers` dataset. `Some` once `start_discovery` ran.
    discovery: Mutex<Option<(Arc<crate::discovery::DiscoveryState>, ndn_app::demux::ServeGuard)>>,
    /// Tap-to-share producer board (cert + manifest + per-file serve loops).
    /// `None` until [`Self::start_offer_board`].
    offer_board: Mutex<Option<Arc<crate::offer::OfferBoard>>>,
    /// Bulk-fetch progress for [`Self::fetch_object_to_fd`], polled by a UI
    /// thread while the (blocking) fetch runs. Reset at the start of each fetch.
    fetch_received: Arc<std::sync::atomic::AtomicU64>,
    fetch_total: Arc<std::sync::atomic::AtomicU64>,
    /// This node's current AP-assigned IPv4 (from the platform's WifiManager), for
    /// raising same-AP InfraTunnel bulk faces. `None` until [`Self::set_infra_addr`].
    local_infra_addr: Mutex<Option<String>>,
    /// Peers we've already raised (or attempted) an InfraTunnel face to, so the
    /// per-beacon `note_peer` attaches at most once. Cleared on an address change.
    infra_peers: Mutex<std::collections::HashSet<String>>,
    /// A Wi-Fi-network-bound UDP socket fd from the platform (bound to our AP
    /// address + the Wi-Fi `Network`, so it egresses Wi-Fi not the default
    /// network). Consumed by the first InfraTunnel attach. `None` → no same-AP
    /// bulk face is raised and the peer stays on the coordination radios.
    infra_socket_fd: Mutex<Option<i32>>,
}

#[export]
impl NdnEngine {
    /// Blocking; errors with [`NdnError::Engine`] on runtime / setup failure.
    pub fn new(config: NdnEngineConfig) -> Result<Self, NdnError> {
        crate::init_platform_tracing();
        let threads = (config.pipeline_threads as usize).max(1);
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .map_err(NdnError::engine)?,
        );

        let (mobile_engine, default_handle) = rt.block_on(build_engine(config))?;

        // An in-process connection to this engine's own embedded forwarder backs
        // the shared identity core, so identity ops route over the same generic
        // `Connection` seam the cross-process `NdnClient` uses. The registering
        // variant writes the FIB on `register_prefix` (the in-proc rib/register),
        // so a served `serve_remote_signer` prefix actually routes back to it.
        // Face allocation spawns the face task, so build it inside the runtime.
        let id_conn = {
            let _guard = rt.enter();
            mobile_engine.new_registering_app_connection()
        };
        let identity_core = IdentityCore::new(rt.clone(), id_conn);

        Ok(Self {
            inner: Mutex::new(Some(mobile_engine)),
            rt,
            default_handle: Mutex::new(Some(default_handle)),
            consumer: Mutex::new(None),
            identity_core,
            #[cfg(feature = "wifi-aware")]
            nan_seam: Mutex::new(None),
            #[cfg(feature = "ble")]
            ble_seam: Mutex::new(None),
            discovery: Mutex::new(None),
            offer_board: Mutex::new(None),
            fetch_received: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fetch_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            local_infra_addr: Mutex::new(None),
            infra_peers: Mutex::new(std::collections::HashSet::new()),
            infra_socket_fd: Mutex::new(None),
        })
    }

    /// Pause network face I/O; in-process traffic keeps flowing. Call from
    /// `Activity.onStop` / `applicationDidEnterBackground`.
    pub fn suspend_network_faces(&self) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(engine) = guard.as_mut() {
            engine.suspend_network_faces();
        }
    }

    /// Inverse of [`Self::suspend_network_faces`]; call from
    /// `Activity.onResume` / `applicationWillEnterForeground`.
    pub fn resume_network_faces(&self) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(engine) = guard.as_mut() {
            self.rt.block_on(engine.resume_network_faces());
        }
    }

    /// Drains in-flight packets; the engine is unusable after this returns.
    pub fn shutdown(&self) {
        if let Some(engine) = self.inner.lock().unwrap().take() {
            self.rt.block_on(engine.shutdown());
        }
    }

    /// Blocking fetch; returns the full Data (name + content). Blocks up to the
    /// Interest lifetime (~4.5 s). Calls are serialized through one shared
    /// app face — issue them from a background thread.
    pub fn fetch(&self, name: String) -> Result<NdnData, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::from_handle(self.take_consumer_handle()?));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch(parsed))
            .map(NdnData::from_packet)
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Like [`Self::fetch`] but returns just the `Content` bytes.
    pub fn get(&self, name: String) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::from_handle(self.take_consumer_handle()?));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.get(parsed))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// RDR whole-object fetch: discovers `<name>/32=metadata`, then pulls and
    /// reassembles every `<name>/v=<ver>/seg=<n>` segment into the full content.
    /// Use this (not [`Self::get`]) for files / multi-segment objects. Blocking —
    /// run on a worker thread; serialized through the one shared consumer.
    pub fn fetch_object(&self, name: String) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::from_handle(self.take_consumer_handle()?));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch_object(parsed))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Verified whole-object fetch — the **secure** counterpart to
    /// [`Self::fetch_object`]: metadata + every segment are verified against this
    /// node's trust anchors (own self-cert + any pinned via
    /// [`Self::pin_trust_anchor`]) before reassembly; unsigned/untrusted is refused.
    pub fn fetch_object_verified(&self, name: String) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let validator = std::sync::Arc::new(self.identity_core.build_validator());
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::from_handle(self.take_consumer_handle()?));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch_object_verified(parsed, validator))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Verified bulk fetch that **streams to a descriptor, engine-side**. The
    /// caller (a leaf over Binder, or a native bench) passes the object `name`,
    /// a forwarding `hint`, and a writable `fd`; this fetches and verifies every
    /// segment over the engine's *in-process* connection and writes it to `fd` as
    /// it lands. Unlike the leaf's [`NdnClient::fetch_object_to_fd`], the bytes
    /// never cross the IPC seam and verification runs on the engine's multi-thread
    /// runtime — this is the bulk data plane the offer/file fetch should use.
    /// Returns total bytes written; progress polls the same getters as the leaf.
    #[cfg(unix)]
    pub fn fetch_object_to_fd(
        &self,
        name: String,
        hint: String,
        fd: i32,
    ) -> Result<u64, NdnError> {
        use std::os::fd::FromRawFd;
        use std::sync::atomic::Ordering;
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let hint_name: Name = hint.parse().map_err(|_| NdnError::invalid_name(&hint))?;
        let validator = std::sync::Arc::new(self.identity_core.build_validator());
        // SAFETY: caller detached ownership of a writable fd; we adopt it once.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::from_handle(self.take_consumer_handle()?));
        }
        let consumer = guard.as_mut().unwrap();
        self.fetch_received.store(0, Ordering::Relaxed);
        self.fetch_total.store(0, Ordering::Relaxed);
        let received = Arc::clone(&self.fetch_received);
        let total = Arc::clone(&self.fetch_total);
        let result = self.rt.block_on(consumer.fetch_object_to_file_hinted_progress(
            parsed,
            validator,
            &[hint_name],
            &file,
            move |r, t| {
                total.store(t, Ordering::Relaxed);
                received.store(r, Ordering::Relaxed);
            },
        ));
        tracing::debug!(
            target: "ndn_boltffi::engine",
            %name, %hint,
            result = ?result.as_ref().map(|n| *n),
            segs_total = self.fetch_total.load(Ordering::Relaxed),
            segs_recv = self.fetch_received.load(Ordering::Relaxed),
            "fetch_object_to_fd done"
        );
        result.map_err(|e| NdnError::from_app(e, &name))
    }

    /// Segments received so far by the in-flight [`Self::fetch_object_to_fd`].
    /// Poll alongside [`Self::fetch_progress_total`] from a UI thread; reads
    /// atomics outside the fetch lock. Reset to 0 at the start of each fetch.
    pub fn fetch_progress_received(&self) -> u64 {
        self.fetch_received.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total segments in the object being fetched (0 until metadata lands).
    pub fn fetch_progress_total(&self) -> u64 {
        self.fetch_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Pin a certificate (Data wire) as a trust anchor for
    /// [`Self::fetch_object_verified`].
    pub fn pin_trust_anchor(&self, cert_wire: Vec<u8>) -> Result<bool, NdnError> {
        self.identity_core.pin_trust_anchor(cert_wire)
    }

    /// RDR whole-object publish: segments `content` under `<name>/v=<ver>` and
    /// serves it (metadata + segments) until the engine connection closes —
    /// blocking, run on a worker thread. `chunk_size == 0` uses the 8 KiB
    /// default. Signed with the loaded operator identity if present. Pairs with
    /// [`Self::fetch_object_verified`]; the core of file sharing over the node.
    pub fn publish_object(
        &self,
        name: String,
        content: Vec<u8>,
        chunk_size: u32,
    ) -> Result<bool, NdnError> {
        self.identity_core
            .publish_object(name, content, chunk_size as usize)
    }

    /// Attach a **Wi-Fi Aware (NAN)** coordination face — AP-independent peer
    /// Wi-Fi, the real AirDrop transport. The platform radio (Android
    /// `WifiAwareManager`) is supplied as `backend`; the engine drives it to
    /// broadcast NDN follow-ups and to publish/subscribe NDN `service`.
    ///
    /// This makes the node a full forwarding peer with no AP and no gateway:
    /// Interests/Data flow over NAN exactly as over any other face. Call once,
    /// after the engine is running and Wi-Fi Aware is available/permitted. The
    /// app then drives the receive side by calling [`Self::nan_deliver_followup`]
    /// from its NAN message callback and [`Self::nan_on_match`] from discovery.
    ///
    /// Errors if the `wifi-aware` feature was not compiled in (the trait + this
    /// binding always exist so the FFI surface is stable, but the NAN bearer is
    /// gated). The method is intentionally kept in this one `#[export] impl`:
    /// boltffi emits each method's extern wrapper unconditionally, so a
    /// per-method `#[cfg]` would leave a dangling wrapper, and a second
    /// `#[export] impl` block collides on the generated `_free` — hence the
    /// always-present signature with a feature-gated body.
    pub fn attach_wifi_aware(
        &self,
        service: String,
        backend: Box<dyn crate::wifi_aware::NdnNanBackend>,
    ) -> Result<bool, NdnError> {
        #[cfg(feature = "wifi-aware")]
        {
            use ndn_face_wifi_aware::{NanBackend, NanServiceName};
            let (ffi, seam) = crate::wifi_aware::make_seam(backend);
            let mut guard = self.inner.lock().unwrap();
            let engine = guard
                .as_mut()
                .ok_or_else(|| NdnError::engine("engine is shut down"))?;
            // add_face spawns the NAN face I/O task and publish/subscribe touch
            // the platform radio — both want the ambient runtime.
            self.rt.block_on(async {
                engine.attach_wifi_aware(Arc::clone(&ffi) as Arc<dyn NanBackend>);
                let svc = NanServiceName(service);
                ffi.publish(&svc).await.ok();
                ffi.subscribe(&svc).await.ok();
            });
            *self.nan_seam.lock().unwrap() = Some(seam);
            Ok(true)
        }
        #[cfg(not(feature = "wifi-aware"))]
        {
            let _ = (service, backend);
            Err(NdnError::engine("wifi-aware feature not enabled"))
        }
    }

    /// Deliver a follow-up frame the NAN radio received into the engine's NAN
    /// face (the engine ← app half of the seam). Call from the app's
    /// `onMessageReceived` callback. `peer` is the sender's 6-byte NAN MAC
    /// (empty if unknown); `rssi` is dBm (0 = unknown). No-op if Wi-Fi Aware
    /// isn't attached / not compiled in.
    pub fn nan_deliver_followup(&self, frame: Vec<u8>, peer: Vec<u8>, rssi: i32) {
        #[cfg(feature = "wifi-aware")]
        if let Some(seam) = self.nan_seam.lock().unwrap().as_ref() {
            seam.deliver_followup(frame, peer, rssi);
        }
        #[cfg(not(feature = "wifi-aware"))]
        let _ = (frame, peer, rssi);
    }

    /// Record that a peer (6-byte NAN MAC) was discovered advertising `service`.
    /// Call from the app's subscribe/discovery callback. No-op if Wi-Fi Aware
    /// isn't attached / not compiled in.
    pub fn nan_on_match(&self, service: String, peer: Vec<u8>) {
        #[cfg(feature = "wifi-aware")]
        if let Some(seam) = self.nan_seam.lock().unwrap().as_ref() {
            seam.on_match(service, peer);
        }
        #[cfg(not(feature = "wifi-aware"))]
        let _ = (service, peer);
    }

    /// Attach a connectionless **BLE advertising** face — the widest-support
    /// named-radio face (BLE is near-universal). The platform radio (Android
    /// `BluetoothLeAdvertiser` + `BluetoothLeScanner`) is supplied as `backend`;
    /// the engine drives it to broadcast NDN frames, and the app pushes scanned
    /// advertisements back in via [`Self::ble_deliver_frame`].
    ///
    /// Complements Wi-Fi Aware: attach BOTH and the node forwards over each at
    /// once (the broadcast strategy fans Interests over all). BLE is the
    /// universal floor (presence/discovery, small Interest/Data); Wi-Fi Aware is
    /// the high-throughput path where available. Errors if the `ble` feature was
    /// not compiled in. (Kept in the one `#[export] impl` with a feature-gated
    /// body — see [`Self::attach_wifi_aware`] for why.)
    pub fn attach_ble(
        &self,
        backend: Box<dyn crate::ble::NdnBleBackend>,
    ) -> Result<bool, NdnError> {
        #[cfg(feature = "ble")]
        {
            use ndn_face_ble_adv::AdvBackend;
            let (ffi, seam) = crate::ble::make_seam(backend);
            let mut guard = self.inner.lock().unwrap();
            let engine = guard
                .as_mut()
                .ok_or_else(|| NdnError::engine("engine is shut down"))?;
            // add_face spawns the BLE face I/O task → wants the ambient runtime.
            self.rt
                .block_on(async { engine.attach_ble(Arc::clone(&ffi) as Arc<dyn AdvBackend>) });
            *self.ble_seam.lock().unwrap() = Some(seam);
            Ok(true)
        }
        #[cfg(not(feature = "ble"))]
        {
            let _ = backend;
            Err(NdnError::engine("ble feature not enabled"))
        }
    }

    /// Deliver a scanned BLE advertisement into the engine's BLE face (the engine
    /// ← app half of the seam). Call from the app's scan callback. `addr` is the
    /// sender's 6-byte BD_ADDR (empty if unknown/randomized); `rssi` is dBm
    /// (0 = unknown). No-op if BLE isn't attached / not compiled in.
    pub fn ble_deliver_frame(&self, frame: Vec<u8>, addr: Vec<u8>, rssi: i32) {
        #[cfg(feature = "ble")]
        if let Some(seam) = self.ble_seam.lock().unwrap().as_ref() {
            seam.deliver_frame(frame, addr, rssi);
        }
        #[cfg(not(feature = "ble"))]
        let _ = (frame, addr, rssi);
    }

    /// Start **nearby-peer discovery**: record this node's own presence
    /// (`node_id` + human `label`) and serve the peer table as an NDN dataset at
    /// `/localhost/discovery/peers`. A leaf (e.g. Ripple) fetches that name over
    /// the seam to render its "nearby" list — no side-channel API. The platform
    /// radios feed observed peers in via [`Self::note_peer`]. Idempotent: a second
    /// call replaces the presence record and the dataset server.
    pub fn start_discovery(&self, node_id: String, label: String) -> bool {
        // Declare our own routable `/ndn/node/<id>` prefix as a producer region,
        // so a peer fetching our identity-named content with
        // `ForwardingHint = /ndn/node/<id>` (tap-to-share) has the hint stripped
        // here and the Interest delivered by name to the local producer.
        if let Ok(prefix) = crate::discovery::peer_node_prefix(&node_id).parse::<Name>()
            && let Some(engine) = self.inner.lock().unwrap().as_ref()
        {
            engine.add_producer_region(&prefix);
        }
        let state = crate::discovery::new_state(node_id, label);
        // Registers the dataset prefix (FIB) and spawns the server task — needs
        // the runtime for both.
        let guard = self.rt.block_on(crate::discovery::serve_peers_dataset(
            &self.identity_core.demux,
            Arc::clone(&state),
        ));
        *self.discovery.lock().unwrap() = Some((state, guard));
        true
    }

    /// Record (or refresh) a nearby peer the radio observed — `id` + human
    /// `label` from its presence beacon, the `face` it was heard on ("ble",
    /// "wifi-aware", …), `rssi` in dBm (0 = unknown), and the peer's AP-assigned
    /// IPv4 if its beacon carried one (empty = none). Call from the platform
    /// discovery callbacks. No-op if [`Self::start_discovery`] hasn't run.
    pub fn note_peer(&self, id: String, label: String, face: String, rssi: i32, infra_addr: String) {
        if id.is_empty() {
            return;
        }
        let infra = (!infra_addr.is_empty()).then(|| infra_addr.clone());
        if let Some((state, _)) = self.discovery.lock().unwrap().as_ref() {
            state.note_peer(id.clone(), label, face.clone(), rssi, infra.clone());
        }
        // Cost-aware "route to deliver": install a route to the peer's node prefix
        // toward the radio it was heard on, so a fetch to it takes the best face
        // instead of flooding every radio (`/` stays multicast for first-contact).
        if let Ok(prefix) = crate::discovery::peer_node_prefix(&id).parse::<Name>()
            && let Some(engine) = self.inner.lock().unwrap().as_ref()
        {
            engine.note_peer_route(&prefix, &face);
            // Same-AP bulk fallback: if the peer advertised an address on our
            // subnet and we haven't already raised one, attach an InfraTunnel face
            // so a file fetch rides a real Wi-Fi unicast link, not the radios.
            if let Some(peer_ip) = infra.as_deref() {
                self.maybe_attach_infra_tunnel(&id, &prefix, peer_ip, engine);
            }
        }
    }

    /// Tell the engine its current AP-assigned IPv4 (from the platform's
    /// `WifiManager`), so it can raise same-AP InfraTunnel bulk faces to peers on
    /// the same subnet. Empty clears it; a change re-arms the per-peer attach.
    pub fn set_infra_addr(&self, ipv4: String) {
        let mut guard = self.local_infra_addr.lock().unwrap();
        let next = (!ipv4.is_empty()).then_some(ipv4);
        if *guard != next {
            *guard = next;
            self.infra_peers.lock().unwrap().clear();
        }
    }

    /// Hand the engine a **Wi-Fi-network-bound** UDP socket fd (the platform binds
    /// it to our AP address + the Wi-Fi `Network` so it routes over Wi-Fi, which a
    /// Rust-bound socket can't guarantee). The first same-subnet peer adopts it as
    /// the InfraTunnel bulk face. Without it, no same-AP face is raised and peers
    /// stay on the coordination radios. Takes ownership of the fd.
    pub fn set_infra_socket(&self, fd: i32) {
        let prev = self.infra_socket_fd.lock().unwrap().replace(fd);
        // Replaced an unused fd — close it so we don't leak the descriptor.
        #[cfg(unix)]
        if let Some(old) = prev {
            use std::os::fd::FromRawFd;
            // SAFETY: a replaced, not-yet-adopted fd we own; close it exactly once.
            unsafe { drop(std::fs::File::from_raw_fd(old)) };
        }
        #[cfg(not(unix))]
        drop(prev);
        self.infra_peers.lock().unwrap().clear();
    }

    /// Verified whole-object fetch steered by an NDNLPv2 **ForwardingHint** —
    /// like [`Self::fetch_object_verified`] but every Interest carries `hint`
    /// (a routable delegation, e.g. a peer's `/ndn/node/<peerId>`), so content
    /// named under the peer's own identity is forwarded toward it and stripped
    /// at the peer's node. The cross-peer fetch for tap-to-share.
    pub fn fetch_object_verified_hinted(
        &self,
        name: String,
        hint: String,
    ) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let hint_name: Name = hint.parse().map_err(|_| NdnError::invalid_name(&hint))?;
        let validator = std::sync::Arc::new(self.identity_core.build_validator());
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch_object_verified_hinted(parsed, validator, &[hint_name]))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    // ── Tap-to-share offer board ────────────────────────────────────────────

    /// Start the tap-to-share **offer board** for this node's discovery
    /// `node_id`: serve the offerer cert at `/ndn/node/<id>/cert` and a signed
    /// manifest at `/ndn/node/<id>/offers`. Idempotent. Requires a loaded
    /// identity. Pair with [`Self::add_offer`].
    pub fn start_offer_board(&self, node_id: String) -> Result<bool, NdnError> {
        #[cfg(feature = "identity")]
        {
            // Ensure our routable `/ndn/node/<id>` is a producer region, so a peer
            // fetching a file with `ForwardingHint=/ndn/node/<id>` has the hint
            // stripped here and the Interest delivered by name to the board's
            // producer — even if start_discovery hasn't run. Idempotent.
            if let Ok(prefix) = crate::discovery::peer_node_prefix(&node_id).parse::<Name>()
                && let Some(engine) = self.inner.lock().unwrap().as_ref()
            {
                engine.add_producer_region(&prefix);
            }
            let board = self.identity_core.start_offer_board(node_id)?;
            *self.offer_board.lock().unwrap() = Some(board);
            Ok(true)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = node_id;
            Err(NdnError::engine("identity feature not enabled in this build"))
        }
    }

    /// Become the producer of record for `public_name`, serving it as a
    /// node-signed RDR object whose segment content is streamed from a keyless
    /// leaf over `source_prefix` (the leaf's internal content prefix). The node
    /// key signs each segment locally — the leaf never signs and is never on the
    /// per-segment path ("bulk off the seam", producer side). `size` is the
    /// file's length. The leaf calls this over the seam (Layer 4 AIDL) after it
    /// has begun serving `source_prefix` via a streaming producer.
    pub fn register_object_relay(
        &self,
        public_name: String,
        source_prefix: String,
        size: u64,
    ) -> Result<bool, NdnError> {
        #[cfg(feature = "identity")]
        {
            let public: Name = public_name
                .parse()
                .map_err(|_| NdnError::invalid_name(&public_name))?;
            let source: Name = source_prefix
                .parse()
                .map_err(|_| NdnError::invalid_name(&source_prefix))?;
            // The node key holder signs the relayed segments. (v0: any loaded
            // operator key; the per-source capability/name-scope check is the
            // authorization follow-up.)
            let signer = self.identity_core.current_signer().ok_or_else(|| {
                NdnError::engine("no operator identity loaded — cannot sign relayed object")
            })?;
            let guard = self.inner.lock().unwrap();
            let engine = guard
                .as_ref()
                .ok_or_else(|| NdnError::engine("engine shut down"))?;
            // Enter the engine's Tokio runtime: the relay's setup spawns tasks
            // (TokioRuntime::spawn == tokio::spawn, which panics without an
            // ambient runtime), and this is called on a binder thread.
            let _enter = self.rt.enter();
            // 8 KiB segments — the proven-good RDR chunk for the offer board.
            engine.spawn_object_relay(public, source, size, 8192, signer);
            Ok(true)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (public_name, source_prefix, size);
            Err(NdnError::engine("identity feature not enabled in this build"))
        }
    }

    /// Offer a file: serve `content` as a signed RDR object under this node's
    /// identity and add it to the manifest. Returns the routable object name.
    /// Requires [`Self::start_offer_board`] first.
    pub fn add_offer(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        content: Vec<u8>,
    ) -> Result<String, NdnError> {
        match self.offer_board.lock().unwrap().clone() {
            Some(board) => board.add_offer(file_id, display_name, mime, content),
            None => Err(NdnError::engine(
                "offer board not started — call start_offer_board first",
            )),
        }
    }

    /// Stop offering `file_id`; returns whether one was removed.
    pub fn remove_offer(&self, file_id: String) -> Result<bool, NdnError> {
        Ok(self
            .offer_board
            .lock()
            .unwrap()
            .clone()
            .map(|board| board.remove_offer(&file_id))
            .unwrap_or(false))
    }

    /// This node's current offerings as JSON (for its own UI). Empty when no
    /// board is running.
    pub fn list_offers(&self) -> String {
        self.offer_board
            .lock()
            .unwrap()
            .clone()
            .map(|board| board.list_offers())
            .unwrap_or_else(|| "{\"node\":\"\",\"offers\":[]}".to_string())
    }

    /// Blocking producer loop: registers `prefix` and dispatches each Interest
    /// to `handler`, returning the handler's bytes (or dropping on `None`).
    /// Returns when the engine connection closes. Run on a background thread.
    pub fn serve(
        &self,
        prefix: String,
        handler: Box<dyn NdnInterestHandler>,
    ) -> Result<bool, NdnError> {
        // Non-unit `Ok` dodges the boltffi 0.25 `Result<(), E>` FFI segfault —
        // see [`load_identity`](Self::load_identity).
        let name: Name = prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&prefix))?;
        let producer = self.register_producer_internal(name)?;
        let handler: Arc<dyn NdnInterestHandler> = handler.into();
        self.rt
            .block_on(producer.serve(move |interest, responder| {
                let name = interest.name.to_string();
                let result = handler.handle_interest(name).map(Bytes::from);
                async move {
                    if let Some(wire) = result {
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            }))
            .map(|()| true)
            .map_err(NdnError::engine)
    }

    /// Mount one half of a host-created `socketpair()` as a local **app face** —
    /// the cross-process seam for the VpnService / Network-Extension split. The
    /// engine runs in the tunnel process; the host passes the engine-side fd
    /// here, and the UI process wraps the other half with [`NdnClient::from_fd`]
    /// and speaks NDN to this engine over it. Call once per UI client at face
    /// setup. Returns true on success. Unix only.
    #[cfg(unix)]
    pub fn mount_app_fd(&self, fd: i32) -> Result<bool, NdnError> {
        let engine_guard = self.inner.lock().unwrap();
        let engine = engine_guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        // Adopting the fd builds a tokio UnixStream and `add_face` spawns the
        // face I/O task — both need an ambient runtime with the IO driver.
        self.rt.block_on(async {
            engine
                .mount_app_fd(fd as std::os::fd::RawFd)
                .map(|_| true)
                .map_err(|e| NdnError::engine(format!("mount app fd: {e}")))
        })
    }

    /// Adopt an app-established **Wi-Fi Aware NDP** (Network Data Path) UDP
    /// socket as a high-throughput bulk face to a discovered peer (the WS3 fast
    /// path). The Android `NanRadio` negotiates the NDP
    /// (`WifiAwareManager.requestNetwork`), binds a UDP socket on the resulting
    /// IPv6 link-local network, then calls this with the socket's `fd`, the
    /// peer's link-local address `peer_ip` + its interface `scope_id`, and the
    /// agreed `peer_port`. The engine wraps the fd as a `UdpFace` and routes
    /// `/ndn/node/<node_id>` over it at UDP cost (10), so `BestRoute` moves the
    /// peer's traffic onto this reliable, high-throughput link while the
    /// connectionless Wi-Fi Aware / BLE faces stay for discovery + fallback.
    ///
    /// `node_id` is the peer's discovery id (its `/ndn/node/<id>` prefix). Takes
    /// ownership of `fd`. Returns the new face id. Unix only; no-op-safe to call
    /// once the NDP is up. Errors if the engine is shut down or the address is
    /// unparseable.
    #[cfg(unix)]
    pub fn attach_ndp_face(
        &self,
        node_id: String,
        fd: i32,
        peer_ip: String,
        peer_port: u32,
        scope_id: u32,
    ) -> Result<u64, NdnError> {
        let prefix: Name = crate::discovery::peer_node_prefix(&node_id)
            .parse()
            .map_err(|_| NdnError::invalid_name(crate::discovery::peer_node_prefix(&node_id)))?;
        let ip: std::net::Ipv6Addr = peer_ip
            .parse()
            .map_err(|_| NdnError::engine(format!("unparseable NDP peer IPv6 '{peer_ip}'")))?;
        let peer =
            std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, peer_port as u16, 0, scope_id));
        let guard = self.inner.lock().unwrap();
        let engine = guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        self.rt.block_on(async {
            engine
                .attach_ndp_face(&prefix, fd as std::os::fd::RawFd, peer)
                .map(|id| id.0)
                .map_err(|e| NdnError::engine(format!("attach NDP face: {e}")))
        })
    }

    /// Tear down an NDP bulk face by its id (from [`Self::attach_ndp_face`]) when
    /// the platform reports the Wi-Fi Aware network lost. Removes the face + its
    /// FIB nexthops so routing falls back to the coordination radios until the
    /// NDP is re-established. No-op if the engine is shut down. Unix only.
    #[cfg(unix)]
    pub fn detach_ndp_face(&self, face_id: u64) {
        if let Some(engine) = self.inner.lock().unwrap().as_ref() {
            engine.detach_ndp_face(face_id);
        }
    }

    /// Adopt an app-bound UDP socket as a high-throughput **Wi-Fi Direct** bulk
    /// face to a peer on the P2P group subnet. After NAN/BLE discovery, the
    /// Android `WifiP2pManager` forms an autonomous group (5 GHz); both phones
    /// land on `192.168.49.0/24`. The app binds a UDP socket on the P2P
    /// interface and calls this with the socket `fd`, the peer's IPv4 `peer_ip`,
    /// and the agreed `peer_port`. The engine wraps the fd as a `UdpFace` tagged
    /// `wifi-direct` and routes `/ndn/node/<node_id>` over it at cost 8 — below
    /// NDP/LAN UDP (10) and well below Wi-Fi Aware (20) / BLE (50) — so
    /// `BestRoute` moves bulk Data onto the fast 5 GHz link while the
    /// connectionless radios stay for discovery + fallback. The group-owner
    /// election and DHCP stay entirely in the Kotlin glue, below this Face.
    ///
    /// `node_id` is the peer's discovery id (`/ndn/node/<id>`). Takes ownership
    /// of `fd`. Returns the new face id. Detach with [`Self::detach_ndp_face`]
    /// (it removes any bulk face by id) when the group is torn down. Unix only.
    #[cfg(unix)]
    pub fn attach_wifi_direct_face(
        &self,
        node_id: String,
        fd: i32,
        peer_ip: String,
        peer_port: u32,
    ) -> Result<u64, NdnError> {
        let prefix: Name = crate::discovery::peer_node_prefix(&node_id)
            .parse()
            .map_err(|_| NdnError::invalid_name(crate::discovery::peer_node_prefix(&node_id)))?;
        let ip: std::net::IpAddr = peer_ip.parse().map_err(|_| {
            NdnError::engine(format!("unparseable Wi-Fi Direct peer ip '{peer_ip}'"))
        })?;
        let peer = std::net::SocketAddr::new(ip, peer_port as u16);
        let guard = self.inner.lock().unwrap();
        let engine = guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        self.rt.block_on(async {
            engine
                .attach_wifi_direct_face(&prefix, fd as std::os::fd::RawFd, peer)
                .map(|id| id.0)
                .map_err(|e| NdnError::engine(format!("attach Wi-Fi Direct face: {e}")))
        })
    }

    /// Attach a **Wi-Fi Direct one-to-many** face: join the NDN multicast group
    /// on the P2P interface whose local IPv4 is `local_ip`, and install the
    /// multicast strategy at `/` so one Interest fans to every peer in the group
    /// and the Data collapses back via PIT aggregation — the "seed a file to the
    /// room" path. Wi-Fi multicast frames run at the basic rate and are un-ACKed,
    /// so use this for coordination + Interests (and FEC-coded one-to-many bulk);
    /// 1:1 bulk uses [`Self::attach_wifi_direct_face`]. Returns the face id.
    /// Unix only.
    #[cfg(unix)]
    pub fn attach_wifi_direct_multicast_face(&self, local_ip: String) -> Result<u64, NdnError> {
        let ip: std::net::Ipv4Addr = local_ip.parse().map_err(|_| {
            NdnError::engine(format!("unparseable Wi-Fi Direct local IPv4 '{local_ip}'"))
        })?;
        let guard = self.inner.lock().unwrap();
        let engine = guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        self.rt.block_on(async {
            engine
                .attach_wifi_direct_multicast_face(ip)
                .await
                .map(|id| id.0)
                .map_err(|e| NdnError::engine(format!("attach Wi-Fi Direct multicast face: {e}")))
        })
    }

    /// Blocking SVS subscribe loop: delivers each publication in `group_prefix`
    /// to `handler` until the subscription ends. Run on a background thread.
    pub fn subscribe(
        &self,
        group_prefix: String,
        handler: Box<dyn NdnSampleHandler>,
    ) -> Result<bool, NdnError> {
        let group: Name = group_prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&group_prefix))?;
        let local_name = group
            .clone()
            .append(format!("node-{}", std::process::id()).as_bytes());
        let handle = self.alloc_app_handle()?;
        let conn: Arc<dyn Connection> = Arc::new(InProcConnection::new(handle));
        let _guard = self.rt.enter();
        let mut sub = Subscriber::from_connection(conn, group, local_name, Default::default())
            .map_err(NdnError::engine)?;
        while let Some(sample) = self.rt.block_on(sub.recv()) {
            handler.on_sample(NdnSample::from_sample(sample));
        }
        Ok(true)
    }

    // ── Trust contexts (§6: the participant's memberships) ─────────────────

    /// Adopt (join) a trust context from its encoded content and `version` —
    /// the participant model's "join a context" (the QR / NFC payload). The
    /// context's anchors become trusted for its namespace. Anti-rollback: a
    /// version strictly older than one already held for the same namespace is
    /// refused. Returns the adopted (or already-held) context view.
    pub fn join_context(&self, context_wire: Vec<u8>, version: u64) -> Result<NdnContext, NdnError> {
        self.identity_core.join_context(context_wire, version)
    }

    /// List the adopted trust contexts (§6 home: "what contexts am I in").
    pub fn list_contexts(&self) -> Vec<NdnContext> {
        self.identity_core.list_contexts()
    }

    /// Forget (leave) a context by namespace; returns whether one was removed.
    pub fn forget_context(&self, namespace: String) -> Result<bool, NdnError> {
        self.identity_core.forget_context(namespace)
    }

    // ── Operator identity + signing (native-only; the `identity` feature) ──
    // The phone holds the operator key and signs management commands /
    // RemoteSigner responses through it. BoltFFI's one-object model means these
    // are methods on the engine, not a separate handle.

    /// Restore a **software** operator identity from a password-encrypted
    /// `SafeBag` (the bytes the device persisted). The key is held in memory and
    /// used by [`sign`](Self::sign). For an enclave-held key the platform layer
    /// owns the key and signs through a custodian instead. Blocking; errors with
    /// [`NdnError::Identity`] on a bad bag / password / key name. Requires the
    /// `identity` feature (native builds); otherwise errors "feature not enabled".
    //
    // The method is always present (BoltFFI generates its FFI glue unconditionally
    // — a per-method `#[cfg]` would leave a dangling extern); only the *body* is
    // feature-gated, since it pulls ndn-safebag / ndn-mobile's enroll (not wasm-safe).
    pub fn load_identity(
        &self,
        safebag: Vec<u8>,
        password: Vec<u8>,
        key_name: String,
    ) -> Result<String, NdnError> {
        // Returns the loaded principal's `did:ndn` (so the caller doesn't need a
        // follow-up `principal_did`). NB: the return type is deliberately *not*
        // `Result<(), _>` — boltffi 0.25 maps a `Result<(), E>` export to a
        // `void` Kotlin/Swift binding while the native `.so` still returns the
        // encoded result by value, so the FFI call writes the result to a
        // garbage sret pointer and segfaults. A non-unit `Ok` dodges that.
        self.identity_core.load_identity(safebag, password, key_name)
    }

    /// Whether an operator identity is loaded.
    pub fn has_identity(&self) -> bool {
        self.identity_core.has_identity()
    }

    /// Sign `region` with the loaded operator identity — e.g. a signed management
    /// command or a RemoteSigner response. Blocking; errors with
    /// [`NdnError::Identity`] if no identity is loaded or signing fails.
    pub fn sign(&self, region: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.sign(region)
    }

    /// Run NDNCERT enrollment (the `pin` challenge) and **load** the issued
    /// identity for signing. `pin_handler` is called once when the CA asks for
    /// the PIN; on success the identity is installed (subsequent [`sign`](Self::sign)
    /// works) and the result carries a password-encrypted SafeBag for the host to
    /// persist. A route to the CA prefix must already exist (a gateway peer +
    /// route). Blocking; requires the `identity` feature.
    pub fn enroll(
        &self,
        config: NdnEnrollConfig,
        pin_handler: Box<dyn NdnPinHandler>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let ca: Name = config
                .ca_prefix
                .parse()
                .map_err(|_| NdnError::invalid_name(config.ca_prefix.clone()))?;
            let identity: Name = config
                .identity
                .parse()
                .map_err(|_| NdnError::invalid_name(config.identity.clone()))?;
            let cfg = ndn_mobile::enroll::EnrollConfig::new(ca, identity)
                .validity_secs(config.validity_secs);

            let guard = self.inner.lock().unwrap();
            let engine = guard
                .as_ref()
                .ok_or_else(|| NdnError::engine("engine is shut down"))?;
            let enrolled = self
                .rt
                .block_on(engine.enroll_pin(cfg, move |req| async move {
                    pin_handler.provide_pin(req.request_id)
                }))
                .map_err(NdnError::identity)?;
            drop(guard);

            let bag = enrolled
                .to_safebag(&config.persist_password)
                .map_err(NdnError::identity)?;
            let result = NdnEnrolledIdentity {
                key_name: enrolled.key_name().to_string(),
                cert_name: enrolled.cert_name().to_string(),
                certificate: enrolled.certificate().map(|b| b.to_vec()),
                safebag: bag.encode().to_vec(),
            };
            self.identity_core.set_identity(enrolled.signer());
            Ok(result)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (config, pin_handler);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    /// Run NDNCERT enrollment via the **`token`** challenge (the "scan an
    /// invitation" flow) and **load** the issued identity. `token` is the
    /// invitation token carried by an `ndn-trust://invite/…` envelope; no
    /// interactive prompt is needed. On success the identity is installed and the
    /// result carries a password-encrypted SafeBag to persist. A route to the CA
    /// prefix must already exist. Blocking; requires the `identity` feature.
    pub fn enroll_with_token(
        &self,
        config: NdnEnrollConfig,
        token: String,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.enroll_with_token(config, token)
    }

    /// Enroll a **hardware-backed** key with the CA via the token challenge: the
    /// enclave key (behind `enclave`) is certified by `config.ca_prefix` and
    /// installed. Signing the NDNCERT requests prompts biometric per signature.
    /// No SafeBag (non-exportable); the key persists in hardware. Requires the
    /// `identity` feature.
    pub fn enroll_with_token_enclave(
        &self,
        config: NdnEnrollConfig,
        token: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core
            .enroll_with_token_enclave(config, token, enclave)
    }

    /// Generate a **self-signed** local identity (no CA) for a fresh device,
    /// install it for signing, and return a persistable SafeBag. The device can
    /// then be *sponsored* — a principal delegates a scope to this name (§3). A
    /// long-lived device key (no CA renewal path). Requires the `identity` feature.
    pub fn generate_identity(
        &self,
        name: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.generate_identity(name, persist_password)
    }

    /// Generate a **hardware-backed** identity for `name`: the private key lives
    /// in the device enclave (Android StrongBox / iOS Secure Enclave) behind
    /// `enclave` and never leaves it — signing is biometric per use. Self-signs
    /// its certificate with the enclave key (one biometric prompt now) and
    /// installs it. There is no SafeBag (non-exportable); the key persists in
    /// hardware and the host re-binds the backend on next launch. Requires the
    /// `identity` feature.
    pub fn generate_identity_enclave(
        &self,
        name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.generate_identity_enclave(name, enclave)
    }

    /// Re-bind a previously generated hardware identity after restart: rebuild
    /// the enclave-backed signer for the persisted `key_name` / `cert_name` (no
    /// new key, no self-sign, **no biometric**) and install it. The enclave key
    /// persists in hardware; the host passes the same backend. Requires the
    /// `identity` feature.
    pub fn load_identity_enclave(
        &self,
        key_name: String,
        cert_name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<bool, NdnError> {
        self.identity_core
            .load_identity_enclave(key_name, cert_name, enclave)
    }

    /// Serve **one** RemoteSigner request (the phone-as-second-factor): decode the
    /// `WireSignRequest`, render a spoof-proof summary from its signed region, ask
    /// `gate` (the platform biometric prompt), and — if approved — sign the region
    /// with the loaded identity. Returns the `WireSignResponse` wire (Approved with
    /// the signature, or Denied) for the host to send back over its transport.
    /// The host owns the channel (BLE / Wi-Fi Aware / socket); this is the
    /// single-shot core. Blocking; requires the `identity` feature + a loaded identity.
    pub fn respond_to_sign_request(
        &self,
        request: Vec<u8>,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core.respond_to_sign_request(request, gate)
    }

    /// Serve a **RemoteSigner responder** at `prefix` (the phone-as-fob, over the
    /// shared forwarder): each incoming Interest carries a `WireSignRequest` in
    /// its application parameters; this decodes it, consults the §7 scoped-signing
    /// policy (a live grant auto-approves, sensitive actions always prompt via
    /// `gate`), signs the region with the loaded identity, and answers with the
    /// `WireSignResponse` as the Data content. Unlike [`Self::respond_to_sign_request`]
    /// the signing is `await`ed *inside* the serve loop (no nested `block_on`), so
    /// the whole responder runs safely on one background thread. Blocking; returns
    /// when the engine connection closes. Run on a background thread. Requires the
    /// `identity` feature + a loaded identity.
    #[cfg(feature = "identity")]
    pub fn serve_remote_signer(
        &self,
        prefix: String,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<bool, NdnError> {
        self.identity_core.serve_remote_signer(prefix, gate)
    }

    /// Announce a served prefix to the upstream gateway so Interests for it route
    /// back to this node — NFD **remote prefix registration**. Sends a signed
    /// `/localhop/nfd/rib/register` command (no FaceId → the gateway installs the
    /// route for the *requesting* face, i.e. this node's peer face) over the
    /// engine; the default route carries it one hop to the gateway. The command
    /// is signed by the loaded identity; the gateway validates it against its
    /// localhop trust anchors (a CA-issued operator cert validates against the
    /// CA anchor `ndn-fwd` auto-installs for a `[demo_ca]`). Returns true on a
    /// 2xx `ControlResponse`. Without this, a served `<id>/signer` responder is
    /// only reachable if the operator adds the route on the gateway by hand.
    /// Requires the `identity` feature, a loaded identity, and a gateway peer.
    #[cfg(feature = "identity")]
    pub fn announce_prefix(&self, prefix: String) -> Result<bool, NdnError> {
        self.identity_core.announce_prefix(prefix)
    }

    /// Open a §7 scoped-signing grant: auto-approve `action` requests (no
    /// biometric prompt) for `ttl_secs`, until [`Self::stop_signing_scope`], or
    /// until the engine restarts. `ttl_secs` is clamped to a 24h hard ceiling
    /// (no "forever"). Sensitive commands (trust anchors, policy, approve/deny,
    /// revoke) are always-ask and ignore the grant. Requires the `identity`
    /// feature.
    pub fn grant_signing_scope(
        &self,
        action: NdnActionClass,
        ttl_secs: u64,
    ) -> Result<u32, NdnError> {
        // Returns the number of active grants after this one. The non-unit `Ok`
        // is also required to avoid the boltffi 0.25 `Result<(), E>` segfault —
        // see [`load_identity`](Self::load_identity).
        self.identity_core.grant_signing_scope(action, ttl_secs)
    }

    /// The loaded operator identity's `did:ndn` URI (the technical identifier).
    /// Errors if no identity is loaded. Requires the `identity` feature.
    pub fn principal_did(&self) -> Result<String, NdnError> {
        self.identity_core.principal_did()
    }

    /// The loaded operator identity's human-readable NDN name (e.g.
    /// `/ndn/mobile/alice`) — the name-centric §6.2 signer-line identifier to
    /// show in UIs. Errors if no identity is loaded. Requires the `identity`
    /// feature.
    pub fn principal_name(&self) -> Result<String, NdnError> {
        self.identity_core.principal_name()
    }

    /// The loaded identity's raw public key — the bytes a verifier feeds to
    /// [`verify_delegation`](Self::verify_delegation) / [`sign_delegated`](Self::sign_delegated)
    /// (and that a sponsor puts in an `ndn-trust://delegation/…` envelope). Errors
    /// if no identity is loaded.
    pub fn principal_public_key(&self) -> Result<Vec<u8>, NdnError> {
        self.identity_core.principal_public_key()
    }

    /// A certificate for the loaded identity — the unit a paired operator console
    /// imports to provision a **remote signer** (`provision_remote_signer_from_cert`):
    /// it carries the operator name, public key, and algorithm, and doubles as the
    /// TOFU trust anchor for the signatures the console will receive. Re-signed by
    /// the identity itself over its existing cert name (or a `…/self` name if none),
    /// so it can be produced without the original CA exchange. Requires the
    /// `identity` feature + a loaded identity.
    #[cfg(feature = "identity")]
    pub fn principal_cert_wire(&self) -> Result<Vec<u8>, NdnError> {
        self.identity_core.principal_cert_wire()
    }

    /// Derive the Ed25519 **public** key (32 bytes) from a 32-byte recovery
    /// **seed** — the pubkey to pass to [`make_recoverable`](Self::make_recoverable).
    /// The host generates the seed (the secret to back up), commits the pubkey,
    /// and later restores with the seed.
    pub fn recovery_public_key(&self, recovery_seed: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.recovery_public_key(recovery_seed)
    }

    /// Issue a signed device delegation: grant `scope` to the `device`
    /// namespace, signed by the loaded operator identity. Returns the
    /// `SignedDelegation` wire for the host to hand to the device (which
    /// presents it; any verifier checks it against this principal's key).
    /// `device` must be under the principal's namespace. Requires the
    /// `identity` feature.
    pub fn add_device(
        &self,
        device: String,
        scope: NdnDelegationScope,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core.add_device(device, scope)
    }

    /// **Device side**: verify a `SignedDelegation` received from a principal
    /// against the principal's public key, returning the scope it grants (what
    /// names this device may sign for). Errors if the wire is malformed or the
    /// signature/namespace doesn't check out. Requires the `identity` feature.
    pub fn verify_delegation(
        &self,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<NdnDelegationScope, NdnError> {
        self.identity_core
            .verify_delegation(delegation_wire, principal_pubkey)
    }

    /// **Device side**: sign `region` with this device's loaded identity, but
    /// only if `delegation_wire` (verified against `principal_pubkey`)
    /// authorizes the region's leading Name. Closes the delegation loop: the
    /// device acts on the principal's behalf strictly within the granted scope,
    /// refusing out-of-scope names. Requires the `identity` feature + a loaded
    /// (device) identity.
    pub fn sign_delegated(
        &self,
        region: Vec<u8>,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core
            .sign_delegated(region, delegation_wire, principal_pubkey)
    }

    /// Convenience over [`sign_delegated`](Self::sign_delegated): build the
    /// to-be-signed region from `name` (TLV-encoded so it's the scope-checked
    /// leading Name) plus `payload`, then sign it under the delegation. Errors if
    /// `name` is outside the granted scope. Requires the `identity` feature.
    pub fn sign_delegated_named(
        &self,
        name: String,
        payload: Vec<u8>,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core
            .sign_delegated_named(name, payload, delegation_wire, principal_pubkey)
    }

    /// Make the loaded identity **recoverable** by committing to an out-of-band
    /// recovery key, and return the recovery **bundle** (the backup bytes the
    /// host stores — cloud / paper / another device). `recovery_pubkey` is a
    /// 32-byte Ed25519 public key the user holds the private half of elsewhere;
    /// only it can later authorize recovery. The bundle carries no private keys.
    /// Requires the `identity` feature + a loaded identity.
    ///
    /// (The fresh-device *restore* from a bundle is a follow-on — it has its own
    /// operational-key persistence flow.)
    pub fn make_recoverable(&self, recovery_pubkey: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.make_recoverable(recovery_pubkey)
    }

    /// **Fresh-device restore**: recover the identity from a backup `bundle`
    /// plus the user's 32-byte Ed25519 `recovery_seed` (the private half of the
    /// key `make_recoverable` committed to). Generates a fresh ECDSA-P256
    /// operational key under `identity_name`, has the recovery key authorize it,
    /// loads it into the engine, and returns the key plus a `persist_password`-
    /// encrypted SafeBag to store and the updated recovery bundle.
    ///
    /// `identity_name` must match the bundle's principal (recovery preserves the
    /// identity, swaps the key). The new key gets a self-signed cert; the DID
    /// proof chain in the returned bundle is its authorization. Requires the
    /// `identity` feature.
    pub fn restore_identity(
        &self,
        bundle: Vec<u8>,
        recovery_seed: Vec<u8>,
        identity_name: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnRecoveredIdentity, NdnError> {
        self.identity_core
            .restore_identity(bundle, recovery_seed, identity_name, persist_password)
    }

    /// Like [`Self::restore_identity`], but the recovery key never enters this
    /// device: `recovery_signer` (an enclave / a second device) signs the new
    /// key-state via callback. The secure restore path. Requires the `identity`
    /// feature.
    pub fn restore_identity_remote(
        &self,
        bundle: Vec<u8>,
        identity_name: String,
        persist_password: Vec<u8>,
        recovery_signer: Box<dyn NdnRecoverySigner>,
    ) -> Result<NdnRecoveredIdentity, NdnError> {
        self.identity_core
            .restore_identity_remote(bundle, identity_name, persist_password, recovery_signer)
    }

    /// Self-revoke the loaded identity: sign a [`RevocationRecord`] declaring
    /// the loaded key dead (`reason` e.g. "compromised") and return its wire to
    /// publish. Any verifier that trusts the key will honor it. Requires the
    /// `identity` feature + a loaded identity.
    pub fn revoke_identity(&self, reason: String) -> Result<Vec<u8>, NdnError> {
        self.identity_core.revoke_identity(reason)
    }

    /// Verify a received [`RevocationRecord`] against the signer's public key
    /// and return what it revokes. Feed `revoked` into the verifier's
    /// revocation list. Requires the `identity` feature.
    pub fn verify_revocation(
        &self,
        record: Vec<u8>,
        signer_pubkey: Vec<u8>,
    ) -> Result<NdnRevocation, NdnError> {
        self.identity_core.verify_revocation(record, signer_pubkey)
    }

    /// "Tap Stop" — revoke all active scoped-signing grants; subsequent
    /// requests prompt the biometric gate again. No-op without a loaded scope.
    pub fn stop_signing_scope(&self) {
        self.identity_core.stop_signing_scope()
    }

    /// How many scoped-signing grants are live right now (0 when none / off
    /// the `identity` feature). For a "scope active" indicator.
    pub fn active_signing_scopes(&self) -> u32 {
        self.identity_core.active_signing_scopes()
    }
}

/// The fixed UDP port both ends bind for the same-AP [`FaceKind::InfraTunnel`]
/// bulk fallback (after NDP's 7654 and Wi-Fi Direct's 7655).
const INFRA_PORT: u16 = 7656;

/// True if two IPv4 dotted-quads share a /24 — a cheap "same AP / same LAN"
/// test before raising an InfraTunnel face to a peer's advertised address.
fn same_subnet24(a: &str, b: &str) -> bool {
    fn prefix(s: &str) -> Option<&str> {
        s.rsplit_once('.').map(|(net, _host)| net)
    }
    matches!((prefix(a), prefix(b)), (Some(x), Some(y)) if x == y)
}

impl NdnEngine {
    /// Raise a same-AP [`FaceKind::InfraTunnel`] bulk face to `peer_ip` if we know
    /// our own AP address, the peer is on our /24, and we haven't already. Called
    /// per beacon from [`Self::note_peer`]; `engine` is the already-locked inner
    /// engine. Best-effort — a failure just leaves the peer on the radios.
    fn maybe_attach_infra_tunnel(
        &self,
        id: &str,
        prefix: &Name,
        peer_ip: &str,
        engine: &MobileEngine,
    ) {
        let Some(local_ip) = self.local_infra_addr.lock().unwrap().clone() else {
            return;
        };
        if !same_subnet24(&local_ip, peer_ip) {
            return;
        }
        let Ok(peer) = format!("{peer_ip}:{INFRA_PORT}").parse::<SocketAddr>() else {
            return;
        };
        if !self.infra_peers.lock().unwrap().insert(id.to_string()) {
            return; // already raised (or attempted) for this peer
        }
        // Adopt the platform's Wi-Fi-bound socket (one per device). Without it,
        // leave the peer unreserved so a later beacon (after set_infra_socket) can
        // still raise the face, and stay on the coordination radios meanwhile.
        let Some(fd) = self.infra_socket_fd.lock().unwrap().take() else {
            self.infra_peers.lock().unwrap().remove(id);
            return;
        };
        let _rt = self.rt.enter();
        match engine.attach_infra_tunnel_fd(prefix, fd, peer) {
            Ok(fid) => {
                tracing::info!(%prefix, %peer, ?fid, "InfraTunnel bulk face up (Wi-Fi-bound, same-AP)")
            }
            Err(e) => {
                tracing::warn!(%prefix, %peer, error = %e, "InfraTunnel attach failed; staying on the radios");
                self.infra_peers.lock().unwrap().remove(id);
            }
        }
    }

    /// First call returns the primary handle; later calls allocate fresh ones.
    pub(crate) fn take_consumer_handle(&self) -> Result<InProcHandle, NdnError> {
        let mut guard = self.default_handle.lock().unwrap();
        if let Some(h) = guard.take() {
            return Ok(h);
        }
        let engine_guard = self.inner.lock().unwrap();
        let engine = engine_guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        let (_, h) = engine.new_app_handle();
        Ok(h)
    }

    pub(crate) fn alloc_app_handle(&self) -> Result<InProcHandle, NdnError> {
        let engine_guard = self.inner.lock().unwrap();
        let engine = engine_guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        let (_, h) = engine.new_app_handle();
        Ok(h)
    }

    pub(crate) fn register_producer_internal(&self, name: Name) -> Result<Producer, NdnError> {
        let engine_guard = self.inner.lock().unwrap();
        let engine = engine_guard
            .as_ref()
            .ok_or_else(|| NdnError::engine("engine is shut down"))?;
        Ok(engine.register_producer(name))
    }
}

async fn build_engine(config: NdnEngineConfig) -> Result<(MobileEngine, InProcHandle), NdnError> {
    let mut builder: MobileEngineBuilder = MobileEngine::builder()
        .cs_capacity_mb(config.cs_capacity_mb as usize)
        .pipeline_threads(config.pipeline_threads as usize)
        .security_profile(into_security_profile(config.security_profile));

    // Mount NFD-compatible management so a client over a face (the UI process on
    // the socketpair seam) can register prefixes and drive `/localhost/nfd/...`.
    // `/localhost` is scope-gated to local faces, so only app faces can manage —
    // network (gateway) faces can't. Open (no command validator); the seam peer
    // is the same app's UI process.
    #[cfg(feature = "management")]
    {
        builder = builder.with_management();
    }

    // The face set: bring up each declared face. A node is a forwarder over
    // whatever faces it is given — a local multicast face by default, optional
    // TCP uplink faces, serial — not a client of one gateway.
    let mut had_uplink = false;
    for face in &config.faces {
        match face {
            NdnFaceSpec::Multicast { iface } => {
                let addr: Ipv4Addr = iface
                    .parse()
                    .map_err(|_| NdnError::invalid_addr(iface))?;
                builder = builder.with_udp_multicast(addr);
            }
            NdnFaceSpec::Uplink { address } => {
                let addr: SocketAddr = address
                    .parse()
                    .map_err(|_| NdnError::invalid_addr(address))?;
                // Persistent TCP face — survives NAT, `adb reverse`-tunnelable.
                builder = builder.with_tcp_peer(addr);
                had_uplink = true;
            }
            NdnFaceSpec::Serial { port, baud } => {
                builder = builder.with_serial(port.clone(), *baud);
            }
        }
    }

    if let Some(node_name) = config.node_name {
        let name: Name = node_name
            .parse()
            .map_err(|_| NdnError::invalid_name(&node_name))?;
        builder = builder.with_discovery(name);
    }

    #[cfg(any(feature = "fjall", feature = "sqlite-cs"))]
    if let Some(path) = config.persistent_cs_path {
        builder = builder.with_persistent_cs(path);
    }
    #[cfg(not(any(feature = "fjall", feature = "sqlite-cs")))]
    if config.persistent_cs_path.is_some() {
        tracing::warn!(
            "NdnEngineConfig.persistent_cs_path set but no persistent-CS feature \
             ('fjall' or 'sqlite-cs') is enabled; falling back to in-memory cache"
        );
    }

    let had_multicast = config
        .faces
        .iter()
        .any(|f| matches!(f, NdnFaceSpec::Multicast { .. }));

    // A node with a broadcast/mesh bearer (multicast — and, attached at runtime,
    // Wi-Fi Aware / BLE) is a mesh peer, not a single-uplink leaf: it can't know
    // which bearer reaches a given peer, so it must fan each not-locally-served
    // Interest over ALL of them. That's `Multicast` strategy. `BestRoute` (the
    // default) would forward to just one nexthop of `/` — e.g. the local
    // multicast face — and never try the NAN face to a peer on another network.
    // A pure uplink leaf keeps `BestRoute`.
    if had_multicast {
        builder = builder.with_strategy(ndn_mobile::MobileStrategy::Multicast);
    }

    let (engine, handle) = builder.build().await.map_err(NdnError::engine)?;

    // A multicast face is added unrouted: serving over it needs only a prefix
    // registration, but FETCHING needs an outbound route to it. Install `/` →
    // multicast so the node is symmetric — any Interest not served locally
    // broadcasts to peers on the group. This is what makes a local-first node a
    // full participant (publish AND fetch), not just a producer.
    if had_multicast {
        engine.route_to_multicast("/");
    }

    // An uplink is a default route out: install `/` toward each TCP-uplink peer so
    // enroll / fetch / join Interests that aren't satisfied locally forward out
    // (peers connect a face but don't install a route themselves).
    if had_uplink {
        let root: Name = "/".parse().map_err(|_| NdnError::engine("bad root name"))?;
        for peer in engine.peers() {
            engine.route_to_peer(root.clone(), &peer, 0);
        }
    }
    Ok((engine, handle))
}

#[cfg(all(test, feature = "identity"))]
mod identity_tests {
    use super::*;
    use crate::types::NdnSecurityProfile;
    use ndn_packet::encode::DataBuilder;
    use ndn_security::{EcdsaP256Signer, Signer};

    fn test_config() -> NdnEngineConfig {
        NdnEngineConfig {
            cs_capacity_mb: 1,
            security_profile: NdnSecurityProfile::Default,
            faces: Vec::new(),
            node_name: None,
            pipeline_threads: 1,
            persistent_cs_path: None,
        }
    }

    /// The VpnService / Network-Extension seam: `mount_app_fd` adopts one half
    /// of a `socketpair()` as a `FaceKind::App` face; a `NdnClient` over the
    /// other half registers a prefix (NFD `rib/register` over the seam) and
    /// serves it, and an engine-side fetch routes across the seam to that
    /// client and back. Exercises the full Remote↔Local data + management path.
    #[cfg(feature = "management")]
    #[test]
    fn mount_app_fd_seam_carries_management_and_data() {
        use crate::client::NdnClient;
        use crate::handlers::NdnInterestHandler;
        use ndn_packet::encode::DataBuilder;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let engine = std::sync::Arc::new(NdnEngine::new(test_config()).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        engine.mount_app_fd(a.into_raw_fd()).unwrap();

        // UI side: a client over the other half registers /seam over the seam and
        // serves it. The handler returns a Data packet named after the Interest.
        let client = NdnClient::from_fd(b.into_raw_fd()).unwrap();
        struct H;
        impl NdnInterestHandler for H {
            fn handle_interest(&self, name: String) -> Option<Vec<u8>> {
                let n: Name = name.parse().ok()?;
                Some(DataBuilder::new(n, b"world").build().to_vec())
            }
        }
        std::thread::spawn(move || {
            let _ = client.serve("/seam".to_string(), Box::new(H));
        });
        std::thread::sleep(Duration::from_millis(500));

        // Engine-side fetch routes across the seam to the UI client and back.
        let content = engine
            .get("/seam/hello".to_string())
            .expect("fetch over the seam");
        assert_eq!(content, b"world");

        engine.shutdown();
    }

    /// Mirrors the Android Anchor path that's failing on-device: a `NdnClient`
    /// over the seam serves a SIGNED **RDR object** via `publish_object` (not the
    /// single-Data `serve`), and an engine-side `fetch_object` (RDR metadata +
    /// segments) routes across the seam to it. If this is green on host but the
    /// phone isn't, the gap is NAN-specific, not the seam producer path.
    #[cfg(feature = "management")]
    #[test]
    fn publish_object_over_seam_round_trips() {
        use crate::client::NdnClient;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let engine = std::sync::Arc::new(NdnEngine::new(test_config()).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        engine.mount_app_fd(a.into_raw_fd()).unwrap();

        let client = NdnClient::from_fd(b.into_raw_fd()).unwrap();
        client
            .generate_identity("/seam/share".to_string(), b"pw".to_vec())
            .expect("generate identity over the seam");
        let payload: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let to_publish = payload.clone();
        std::thread::spawn(move || {
            let _ = client.publish_object("/seam/share/file".to_string(), to_publish, 0);
        });
        std::thread::sleep(Duration::from_millis(500));

        let got = engine
            .fetch_object("/seam/share/file".to_string())
            .expect("RDR fetch over the seam must reach the client producer");
        assert_eq!(got, payload, "round-tripped RDR content must match");

        engine.shutdown();
    }

    /// The full Android Anchor topology on host: two engines joined by a
    /// loopback NAN bearer; engine A serves a SIGNED RDR object via a `NdnClient`
    /// over its seam (the producer the phone runs in its UI process), and engine
    /// B fetches it — the Interest egresses B over NAN, reaches A, must route to
    /// A's seam producer and come back. Reproduces (or clears) the on-device
    /// "A receives the Interest over NAN but never serves the Data" failure.
    #[cfg(feature = "wifi-aware")]
    #[cfg(feature = "management")]
    #[test]
    fn rdr_object_round_trips_between_two_engines_over_loopback_nan() {
        use crate::client::NdnClient;
        use crate::wifi_aware::NdnNanBackend;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;

        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();

        // A loopback NAN radio: broadcast → the peer engine's NAN inbox. The peer
        // is set after both engines exist (chicken-and-egg).
        struct LoopbackNan {
            peer: Arc<StdMutex<Option<Arc<NdnEngine>>>>,
        }
        impl NdnNanBackend for LoopbackNan {
            fn broadcast(&self, frame: Vec<u8>) {
                if let Some(peer) = self.peer.lock().unwrap().clone() {
                    peer.nan_deliver_followup(frame, Vec::new(), 0);
                }
            }
            fn publish(&self, _service: String) {}
            fn subscribe(&self, _service: String) {}
        }

        let peer_of_a: Arc<StdMutex<Option<Arc<NdnEngine>>>> = Arc::new(StdMutex::new(None));
        let peer_of_b: Arc<StdMutex<Option<Arc<NdnEngine>>>> = Arc::new(StdMutex::new(None));

        // No multicast face → the only `/` route is the NAN face (BestRoute), so
        // the transfer is unambiguously over the loopback NAN bearer. A forwarder
        // is NOT the trust authority and can't hold (or fetch over NAN) every
        // producer's cert, so its data-path validation is Disabled: it forwards
        // signed Data without dropping it. The END consumer makes the trust
        // decision below (fetch_object_verified against the pinned producer cert).
        // `Default`/`AcceptSigned` would drop A's Data at B (can't resolve the cert).
        let mut cfg = test_config();
        cfg.security_profile = NdnSecurityProfile::Disabled;
        let engine_a = Arc::new(NdnEngine::new(cfg.clone()).unwrap());
        let engine_b = Arc::new(NdnEngine::new(cfg).unwrap());
        *peer_of_a.lock().unwrap() = Some(engine_b.clone()); // A broadcasts → B
        *peer_of_b.lock().unwrap() = Some(engine_a.clone()); // B broadcasts → A
        engine_a
            .attach_wifi_aware(
                "ndn".to_string(),
                Box::new(LoopbackNan { peer: peer_of_a }),
            )
            .unwrap();
        engine_b
            .attach_wifi_aware(
                "ndn".to_string(),
                Box::new(LoopbackNan { peer: peer_of_b }),
            )
            .unwrap();

        // A's producer: a NdnClient over A's seam serves a signed RDR object.
        let (a0, a1) = UnixStream::pair().unwrap();
        engine_a.mount_app_fd(a0.into_raw_fd()).unwrap();
        let producer = NdnClient::from_fd(a1.into_raw_fd()).unwrap();
        producer
            .generate_identity("/ndn/airdrop/alice".to_string(), b"pw".to_vec())
            .unwrap();
        // A's cert (carries A's public key) — what B pins to verify A's Data.
        let producer_cert: Arc<StdMutex<Option<Vec<u8>>>> = Arc::new(StdMutex::new(Some(
            producer.principal_cert_wire().expect("producer cert wire"),
        )));
        let payload: Vec<u8> = (0..3_000u32).map(|i| (i % 251) as u8).collect();
        let to_publish = payload.clone();
        std::thread::spawn(move || {
            let _ = producer.publish_object(
                "/ndn/airdrop/alice/hi".to_string(),
                to_publish,
                0,
            );
        });
        std::thread::sleep(Duration::from_millis(600));

        // B's consumer is a SEPARATE NdnClient over B's seam (exactly like the
        // phone's UI process), which pins A's cert and does the VERIFIED fetch —
        // the END-TO-END trust decision the forwarder doesn't make. The Interest
        // egresses B over NAN → A's seam producer → back, and every segment + the
        // metadata is checked against A's pinned cert. Secure by default: signed
        // on publish, verified on fetch, forwarders merely relay.
        let (c0, c1) = UnixStream::pair().unwrap();
        engine_b.mount_app_fd(c0.into_raw_fd()).unwrap();
        let consumer = NdnClient::from_fd(c1.into_raw_fd()).unwrap();
        let a_cert = producer_cert.lock().unwrap().clone().expect("producer cert");
        assert!(consumer.pin_trust_anchor(a_cert).unwrap());
        let got = consumer
            .fetch_object_verified("/ndn/airdrop/alice/hi".to_string())
            .expect("verified RDR fetch over the seam must cross NAN and validate");
        assert_eq!(got, payload, "verified content round-tripped over loopback NAN must match");

        engine_a.shutdown();
        engine_b.shutdown();
    }

    /// BLE counterpart of the two-engine NAN round-trip: two engines joined by a
    /// loopback BLE advertising face; A serves a SIGNED RDR object over its seam,
    /// B fetches and VERIFIES it across the BLE link. Proves the BLE face carries
    /// the full secure object plane the same as Wi-Fi Aware — the two faces are
    /// interchangeable to the app and usable in tandem.
    #[cfg(feature = "ble")]
    #[cfg(feature = "management")]
    #[test]
    fn rdr_object_round_trips_between_two_engines_over_loopback_ble() {
        use crate::ble::NdnBleBackend;
        use crate::client::NdnClient;
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;

        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();

        // A loopback BLE radio: an advertised frame reaches the PEER engine's scan
        // inbox (a node never hears its own adverts — half-duplex), never itself.
        struct LoopbackBle {
            peer: Arc<StdMutex<Option<Arc<NdnEngine>>>>,
        }
        impl NdnBleBackend for LoopbackBle {
            fn broadcast(&self, frame: Vec<u8>) {
                if let Some(peer) = self.peer.lock().unwrap().clone() {
                    peer.ble_deliver_frame(frame, Vec::new(), 0);
                }
            }
        }

        let peer_of_a: Arc<StdMutex<Option<Arc<NdnEngine>>>> = Arc::new(StdMutex::new(None));
        let peer_of_b: Arc<StdMutex<Option<Arc<NdnEngine>>>> = Arc::new(StdMutex::new(None));

        // Forwarders relay signed Data (Disabled); the END consumer verifies.
        let mut cfg = test_config();
        cfg.security_profile = NdnSecurityProfile::Disabled;
        let engine_a = Arc::new(NdnEngine::new(cfg.clone()).unwrap());
        let engine_b = Arc::new(NdnEngine::new(cfg).unwrap());
        *peer_of_a.lock().unwrap() = Some(engine_b.clone());
        *peer_of_b.lock().unwrap() = Some(engine_a.clone());
        engine_a
            .attach_ble(Box::new(LoopbackBle { peer: peer_of_a }))
            .unwrap();
        engine_b
            .attach_ble(Box::new(LoopbackBle { peer: peer_of_b }))
            .unwrap();

        // A's producer over A's seam serves a signed RDR object.
        let (a0, a1) = UnixStream::pair().unwrap();
        engine_a.mount_app_fd(a0.into_raw_fd()).unwrap();
        let producer = NdnClient::from_fd(a1.into_raw_fd()).unwrap();
        producer
            .generate_identity("/ndn/airdrop/bob".to_string(), b"pw".to_vec())
            .unwrap();
        let a_cert = producer.principal_cert_wire().expect("producer cert wire");
        // Smaller payload: BLE extended-adv MTU (~245 B) means more LP fragments,
        // so keep the loopback test quick while still exercising fragmentation.
        let payload: Vec<u8> = (0..1_500u32).map(|i| (i % 251) as u8).collect();
        let to_publish = payload.clone();
        std::thread::spawn(move || {
            let _ = producer.publish_object("/ndn/airdrop/bob/file".to_string(), to_publish, 0);
        });
        std::thread::sleep(Duration::from_millis(600));

        // B's consumer over B's seam pins A's cert and does the VERIFIED fetch.
        let (c0, c1) = UnixStream::pair().unwrap();
        engine_b.mount_app_fd(c0.into_raw_fd()).unwrap();
        let consumer = NdnClient::from_fd(c1.into_raw_fd()).unwrap();
        assert!(consumer.pin_trust_anchor(a_cert).unwrap());
        let got = consumer
            .fetch_object_verified("/ndn/airdrop/bob/file".to_string())
            .expect("verified RDR fetch must cross BLE and validate against the pinned cert");
        assert_eq!(got, payload, "verified content round-tripped over loopback BLE must match");

        engine_a.shutdown();
        engine_b.shutdown();
    }

    /// Nearby-peer discovery: noted peers appear in the `/localhost/discovery/
    /// peers` NDN dataset a leaf fetches; self and empty ids are excluded.
    #[test]
    fn discovery_dataset_lists_noted_peers() {
        // The node forwards/serves without dropping (Disabled), like the phone.
        let mut cfg = test_config();
        cfg.security_profile = NdnSecurityProfile::Disabled;
        let engine = NdnEngine::new(cfg).unwrap();
        assert!(engine.start_discovery("node-a".to_string(), "Alice's S23".to_string()));
        engine.note_peer(
            "node-b".to_string(),
            "Bob's Pixel".to_string(),
            "ble".to_string(),
            -55,
            String::new(),
        );
        engine.note_peer(
            "node-c".to_string(),
            "Carol".to_string(),
            "wifi-aware".to_string(),
            -70,
            String::new(),
        );
        // Our own id and empty ids never list.
        engine.note_peer("node-a".to_string(), "me".to_string(), "ble".to_string(), 0, String::new());
        engine.note_peer(String::new(), "ghost".to_string(), "ble".to_string(), 0, String::new());

        let json = String::from_utf8(
            engine
                .get("/localhost/discovery/peers".to_string())
                .expect("fetch the discovery dataset"),
        )
        .unwrap();
        assert!(json.contains("\"id\":\"node-b\""), "{json}");
        assert!(json.contains("Bob's Pixel"), "{json}");
        assert!(json.contains("\"id\":\"node-c\""), "{json}");
        assert!(json.contains("\"ble\""));
        assert!(json.contains("\"rssi\":-55"));
        // node-a is us: it appears under "self", never in the peers array.
        let peers_part = json.split("\"peers\":").nth(1).expect("peers array");
        assert!(!peers_part.contains("node-a"), "self must not be a peer: {json}");
        assert!(!json.contains("ghost"), "empty-id peer must not appear");
        engine.shutdown();
    }

    /// The native UI loads a persisted operator identity into the engine and
    /// signs through it — the FFI surface for the operator console / RemoteSigner.
    #[test]
    fn load_identity_then_sign() {
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[4u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let bytes = bag.encode().to_vec();

        let engine = NdnEngine::new(test_config()).unwrap();
        assert!(!engine.has_identity());
        // Wrong password fails cleanly.
        assert!(
            engine
                .load_identity(bytes.clone(), b"wrong".to_vec(), key_name.to_string())
                .is_err()
        );
        // Correct load → the engine signs through the identity.
        engine
            .load_identity(bytes, b"pw".to_vec(), key_name.to_string())
            .unwrap();
        assert!(engine.has_identity());
        let sig = engine.sign(b"a signed command".to_vec()).unwrap();
        assert!(!sig.is_empty());
        engine.shutdown();
    }

    /// The phone-as-second-factor: a desktop's `WireSignRequest` is gated by the
    /// (mock) biometric approval, signed by the loaded identity, and answered with
    /// a `WireSignResponse` — approved with a signature, or denied.
    #[test]
    fn remote_signer_responds_under_approval_and_denial() {
        use ndn_security::custodian::{WireSignRequest, WireSignResponse};

        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[6u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        let request = WireSignRequest {
            req_id: 42,
            region: bytes::Bytes::from_static(b"a command to sign"),
        }
        .encode()
        .to_vec();

        struct Approve;
        impl NdnApprovalGate for Approve {
            fn approve(&self, _summary: String) -> bool {
                true
            }
        }
        let resp = engine
            .respond_to_sign_request(request.clone(), Box::new(Approve))
            .unwrap();
        match WireSignResponse::decode(&resp).unwrap() {
            WireSignResponse::Approved { req_id, signature } => {
                assert_eq!(req_id, 42);
                assert!(!signature.is_empty());
            }
            WireSignResponse::Denied { .. } => panic!("should be approved"),
        }

        struct Deny;
        impl NdnApprovalGate for Deny {
            fn approve(&self, _summary: String) -> bool {
                false
            }
        }
        let resp = engine
            .respond_to_sign_request(request, Box::new(Deny))
            .unwrap();
        assert!(matches!(
            WireSignResponse::decode(&resp).unwrap(),
            WireSignResponse::Denied { req_id: 42 }
        ));

        engine.shutdown();
    }

    /// The serve-based RemoteSigner responder (`serve_remote_signer`): a consumer
    /// sends a `WireSignRequest` as an Interest's application parameters to the
    /// `…/signer` prefix; the responder signs it within a live scoped grant and
    /// answers with the `WireSignResponse` as Data content — the exact NDN path
    /// the dashboard's transport drives, exercised here over an in-proc face.
    #[test]
    fn serve_remote_signer_answers_a_sign_interest() {
        use ndn_security::custodian::{WireSignRequest, WireSignResponse};
        use ndn_packet::encode::InterestBuilder;
        use std::sync::Arc;
        use std::time::Duration;

        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[9u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = Arc::new(NdnEngine::new(test_config()).unwrap());
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();
        // Open a Route grant so in-scope requests auto-approve (deny-gate below).
        engine.grant_signing_scope(NdnActionClass::Route, 900).unwrap();

        struct Deny;
        impl NdnApprovalGate for Deny {
            fn approve(&self, _summary: String) -> bool {
                false
            }
        }
        // The responder serve loop runs until shutdown — on its own thread.
        let responder = engine.clone();
        std::thread::spawn(move || {
            let _ = responder
                .serve_remote_signer("/ndn/mobile/alice/signer".to_string(), Box::new(Deny));
        });
        std::thread::sleep(Duration::from_millis(300));

        // A consumer sends an in-scope Route command sign request.
        let region: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = WireSignRequest {
            req_id: 7,
            region: region.encode_to_tlv(),
        }
        .encode();
        let prefix: Name = "/ndn/mobile/alice/signer".parse().unwrap();
        let data = engine
            .rt
            .block_on(async {
                // app-handle allocation spawns → run inside the runtime.
                let handle = engine.alloc_app_handle().unwrap();
                let mut consumer = Consumer::from_handle(handle);
                let builder = InterestBuilder::new(prefix)
                    .app_parameters(wire.to_vec())
                    .lifetime(Duration::from_secs(5));
                consumer.fetch_with(builder).await
            })
            .expect("signer responds with Data");
        let resp = WireSignResponse::decode(data.content().expect("non-empty response")).unwrap();
        assert!(
            matches!(resp, WireSignResponse::Approved { req_id: 7, .. }),
            "expected approval over the face, got {resp:?}"
        );

        engine.shutdown();
    }

    /// RDR object surface: `publish_object` serves a multi-segment object (it
    /// registers the name + answers metadata/segment Interests on a worker
    /// thread), and `fetch_object` discovers the metadata and reassembles every
    /// segment back into the original bytes — the file-sharing path, end to end
    /// over an in-proc engine. Unsigned here (no identity) → DigestSha256.
    #[test]
    fn publish_object_round_trips_through_fetch_object() {
        use std::sync::Arc;
        use std::time::Duration;

        let engine = Arc::new(NdnEngine::new(test_config()).unwrap());
        // > 8 KiB so it spans several segments through the metadata/FinalBlockID
        // discovery path, not just a single chunk.
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

        let producer = engine.clone();
        let to_publish = payload.clone();
        std::thread::spawn(move || {
            // chunk_size 0 → 8 KiB default → 3 segments for 20 000 bytes.
            let _ = producer.publish_object("/share/file.bin".to_string(), to_publish, 0);
        });
        std::thread::sleep(Duration::from_millis(300));

        let got = engine
            .fetch_object("/share/file.bin".to_string())
            .expect("fetch_object reassembles the published object");
        assert_eq!(got, payload, "round-tripped object content must be identical");

        engine.shutdown();
    }

    /// Secure object plane: with an identity loaded, `publish_object` SIGNS every
    /// segment, and `fetch_object_verified` reassembles it only after verifying
    /// each against the node's own self-cert anchor — the secure-by-default file
    /// path, end to end over an in-proc engine. (Resolution fix: generate_identity
    /// now names its self-cert == key_name, matching the KeyLocator sign_with_sync
    /// writes, so the chain anchors instead of returning Pending.)
    #[test]
    fn signed_publish_object_round_trips_through_verified_fetch() {
        use std::sync::Arc;
        use std::time::Duration;

        let engine = Arc::new(NdnEngine::new(test_config()).unwrap());
        // Identity named so the object sits hierarchically under it.
        engine
            .generate_identity("/share/secure".to_string(), b"pw".to_vec())
            .expect("generate identity");
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

        let producer = engine.clone();
        let to_publish = payload.clone();
        std::thread::spawn(move || {
            let _ = producer.publish_object("/share/secure/file".to_string(), to_publish, 0);
        });
        std::thread::sleep(Duration::from_millis(300));

        let got = engine
            .fetch_object_verified("/share/secure/file".to_string())
            .expect("verified fetch of a SIGNED object must succeed");
        assert_eq!(got, payload, "verified round-tripped content must be identical");

        engine.shutdown();
    }

    /// §7 scoped signing: a live Route grant auto-approves a route command even
    /// when the gate would deny (the gate is never consulted) — but a Sensitive
    /// command still falls through to the (denying) gate.
    #[test]
    fn scoped_grant_auto_approves_bypassing_the_gate() {
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[7u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        // A gate that always denies — so any approval must come from the scope.
        struct Deny;
        impl NdnApprovalGate for Deny {
            fn approve(&self, _summary: String) -> bool {
                false
            }
        }

        let sign_req = |region: &Name| {
            ndn_security::custodian::WireSignRequest {
                req_id: 7,
                region: region.encode_to_tlv(),
            }
            .encode()
            .to_vec()
        };

        // Before any grant: the denying gate wins → Denied.
        assert_eq!(engine.active_signing_scopes(), 0);
        let route_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let r = engine
            .respond_to_sign_request(sign_req(&route_name), Box::new(Deny))
            .unwrap();
        assert!(matches!(
            ndn_security::custodian::WireSignResponse::decode(&r).unwrap(),
            ndn_security::custodian::WireSignResponse::Denied { .. }
        ));

        // Grant route edits for 15m → auto-approves despite the denying gate.
        engine
            .grant_signing_scope(NdnActionClass::Route, 900)
            .unwrap();
        assert_eq!(engine.active_signing_scopes(), 1);
        let r = engine
            .respond_to_sign_request(sign_req(&route_name), Box::new(Deny))
            .unwrap();
        assert!(matches!(
            ndn_security::custodian::WireSignResponse::decode(&r).unwrap(),
            ndn_security::custodian::WireSignResponse::Approved { req_id: 7, .. }
        ));

        // A Sensitive command still falls through to the denying gate.
        let sensitive_name: Name = "/localhost/nfd/security/anchor-add".parse().unwrap();
        let r = engine
            .respond_to_sign_request(sign_req(&sensitive_name), Box::new(Deny))
            .unwrap();
        assert!(matches!(
            ndn_security::custodian::WireSignResponse::decode(&r).unwrap(),
            ndn_security::custodian::WireSignResponse::Denied { .. }
        ));

        // Stop → route edits prompt (and get denied) again.
        engine.stop_signing_scope();
        assert_eq!(engine.active_signing_scopes(), 0);
        let r = engine
            .respond_to_sign_request(sign_req(&route_name), Box::new(Deny))
            .unwrap();
        assert!(matches!(
            ndn_security::custodian::WireSignResponse::decode(&r).unwrap(),
            ndn_security::custodian::WireSignResponse::Denied { .. }
        ));

        engine.shutdown();
    }

    /// The principal/device surface: the loaded identity exposes a DID, and
    /// add_device issues a SignedDelegation the device can present and any
    /// verifier checks against the principal's key. Out-of-namespace is refused.
    #[test]
    fn add_device_issues_a_verifiable_delegation() {
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[8u8; 32], kn.clone()).unwrap();
        let pubkey = signer.public_key().unwrap().to_vec();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        // Principal DID — the §6.2 signer-line identifier.
        let did = engine.principal_did().unwrap();
        assert!(!did.is_empty(), "principal DID present");

        // Issue a delegation to a device under the principal's namespace.
        let scope = NdnDelegationScope {
            sign_patterns: vec!["/ndn/mobile/alice/device/laptop/<**rest>".to_string()],
            unwrap_for: true,
            enroll: false,
            mgmt: false,
        };
        let wire = engine
            .add_device("/ndn/mobile/alice/device/laptop".to_string(), scope)
            .unwrap();

        // The wire decodes and verifies against the principal's public key.
        let deleg = ndn_identity::SignedDelegation::decode(&wire).expect("decode");
        assert_eq!(
            deleg.subordinate.to_string(),
            "/ndn/mobile/alice/device/laptop"
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let granted = rt.block_on(deleg.verify(&pubkey)).expect("verify");
        assert!(granted.unwrap_for);
        assert!(granted.sign[0].matches(
            &"/ndn/mobile/alice/device/laptop/data".parse().unwrap(),
            &mut std::collections::HashMap::new()
        ));

        // A device outside the principal's namespace is refused.
        let bad = NdnDelegationScope {
            sign_patterns: vec![],
            unwrap_for: false,
            enroll: false,
            mgmt: false,
        };
        assert!(engine.add_device("/other/device/x".to_string(), bad).is_err());

        engine.shutdown();
    }

    /// The device side: a device verifies a delegation it received and signs
    /// strictly within the granted scope — in-scope names succeed, out-of-scope
    /// are refused.
    #[test]
    fn sign_delegated_enforces_a_received_grant() {
        use ndn_identity::{CapabilitySet, SignedDelegation};
        use ndn_security::trust_schema::NamePattern;
        use ndn_security::{KeyChain, SecurityManager};
        use std::sync::Arc;

        // A principal issues a delegation scoped to /ndn/lab/device/*.
        let mgr = Arc::new(SecurityManager::new());
        let pkey: Name = "/ndn/lab/KEY/k0".parse().unwrap();
        mgr.generate_ed25519(pkey.clone()).unwrap();
        let principal_pubkey = mgr
            .get_signer_sync(&pkey)
            .unwrap()
            .public_key()
            .unwrap()
            .to_vec();
        let principal = KeyChain::from_parts(mgr, "/ndn/lab".parse().unwrap(), pkey);
        let scope = CapabilitySet {
            sign: vec![NamePattern::parse("/ndn/lab/device/<**rest>").unwrap()],
            unwrap_for: false,
            enroll: false,
            mgmt: false,
        };
        let wire =
            SignedDelegation::issue(&principal, "/ndn/lab/device".parse().unwrap(), scope)
                .unwrap()
                .encode()
                .to_vec();

        // The device loads its own (unrelated) key and receives the delegation.
        let dkey = "/ndn/mobile/alice/KEY/v=1";
        let dkn: Name = dkey.parse().unwrap();
        let dsigner = EcdsaP256Signer::from_seed(&[5u8; 32], dkn.clone()).unwrap();
        let cert = DataBuilder::new(dkn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &dsigner.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), dkey.to_string())
            .unwrap();

        // verify_delegation surfaces what the device may sign.
        let view = engine
            .verify_delegation(wire.clone(), principal_pubkey.clone())
            .unwrap();
        assert_eq!(view.sign_patterns.len(), 1);

        // In-scope name signs with the device key; out-of-scope is refused.
        let in_region = "/ndn/lab/device/data/1"
            .parse::<Name>()
            .unwrap()
            .encode_to_tlv()
            .to_vec();
        let sig = engine
            .sign_delegated(in_region, wire.clone(), principal_pubkey.clone())
            .expect("in-scope signs");
        assert!(!sig.is_empty());

        let out_region = "/ndn/lab/secret"
            .parse::<Name>()
            .unwrap()
            .encode_to_tlv()
            .to_vec();
        assert!(
            engine
                .sign_delegated(out_region, wire, principal_pubkey)
                .is_err(),
            "out-of-scope must be refused"
        );

        engine.shutdown();
    }

    /// make_recoverable commits the loaded identity to a recovery key and yields
    /// a backup bundle that a fresh device can actually recover from.
    #[test]
    fn make_recoverable_yields_a_working_backup() {
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[3u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        // A user-held recovery key (private half stays with them).
        let rk = ndn_security::Ed25519Signer::from_seed(&[1u8; 32], "/r/KEY/r".parse().unwrap());
        let bundle = engine.make_recoverable(rk.public_key_bytes().to_vec()).unwrap();

        // The bundle is a recoverable genesis (one proof, recovery committed).
        let history = ndn_identity::recovery_bundle::decode_history(&bundle).unwrap();
        assert_eq!(history.len(), 1);
        assert!(history[0].recovery.is_some());

        // A fresh device recovers from the bundle alone + the recovery key.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let recovered = rt
            .block_on(ndn_identity::Identity::recover_from_bundle(
                &bundle,
                ndn_security::KeyChain::ephemeral("/ndn/mobile/alice").unwrap(),
                &[(0, &rk)],
            ))
            .expect("recover from the produced bundle");
        assert_eq!(recovered.current_key_state().unwrap().seq, 1);

        // A non-32-byte recovery key is rejected.
        assert!(engine.make_recoverable(vec![0u8; 16]).is_err());

        engine.shutdown();
    }

    /// Full recovery loop across devices: device A makes its identity
    /// recoverable; a fresh device B restores from the bundle + recovery seed,
    /// can sign immediately, and the returned SafeBag reloads on a later launch.
    #[test]
    fn restore_round_trips_through_a_fresh_device() {
        // Device A: load an identity, commit to a recovery key, get the bundle.
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[2u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let device_a = NdnEngine::new(test_config()).unwrap();
        device_a
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        let recovery_seed = [4u8; 32];
        let rk = ndn_security::Ed25519Signer::from_seed(&recovery_seed, "/r/KEY/r".parse().unwrap());
        let bundle = device_a.make_recoverable(rk.public_key_bytes().to_vec()).unwrap();

        // Device B (fresh, no identity): restore from bundle + recovery seed.
        let device_b = NdnEngine::new(test_config()).unwrap();
        assert!(!device_b.has_identity());
        let restored = device_b
            .restore_identity(
                bundle.clone(),
                recovery_seed.to_vec(),
                "/ndn/mobile/alice".to_string(),
                b"newpw".to_vec(),
            )
            .expect("restore");
        // The recovered key is loaded and can sign immediately.
        assert!(device_b.has_identity());
        assert!(!device_b.sign(b"after recovery".to_vec()).unwrap().is_empty());

        // The returned bundle carries the recovery link (genesis + recovery).
        let history = ndn_identity::recovery_bundle::decode_history(&restored.bundle).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].seq, 1);

        // The returned SafeBag persists and reloads on a later launch.
        let device_b_relaunch = NdnEngine::new(test_config()).unwrap();
        device_b_relaunch
            .load_identity(restored.safebag, b"newpw".to_vec(), restored.key_name)
            .expect("recovered SafeBag reloads");
        assert!(device_b_relaunch.has_identity());

        // A wrong-length recovery seed is rejected.
        assert!(
            device_b
                .restore_identity(bundle, vec![0u8; 16], "/ndn/mobile/alice".into(), b"x".to_vec())
                .is_err()
        );

        device_a.shutdown();
        device_b.shutdown();
        device_b_relaunch.shutdown();
    }

    /// Secure restore: the recovery key signs via callback (never enters the
    /// restoring device). Equivalent outcome to the seed path; a refusing
    /// callback fails the restore.
    #[test]
    fn restore_via_callback_recovery_signer() {
        use ndn_security::{Ed25519Signer, Signer};

        // Device A: recoverable identity committed to a recovery key.
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[2u8; 32], kn.clone()).unwrap();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let device_a = NdnEngine::new(test_config()).unwrap();
        device_a
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();
        let rk = Ed25519Signer::from_seed(&[4u8; 32], "/r/KEY/r".parse().unwrap());
        let bundle = device_a.make_recoverable(rk.public_key_bytes().to_vec()).unwrap();

        // The recovery key lives behind a callback (here, a local Ed25519 key).
        struct LocalRecovery(Ed25519Signer);
        impl NdnRecoverySigner for LocalRecovery {
            fn sign(&self, challenge: Vec<u8>) -> Vec<u8> {
                self.0
                    .sign_sync(&challenge)
                    .map(|b| b.to_vec())
                    .unwrap_or_default()
            }
        }
        struct Refuse;
        impl NdnRecoverySigner for Refuse {
            fn sign(&self, _challenge: Vec<u8>) -> Vec<u8> {
                Vec::new() // refuse
            }
        }

        let device_b = NdnEngine::new(test_config()).unwrap();
        let restored = device_b
            .restore_identity_remote(
                bundle.clone(),
                "/ndn/mobile/alice".to_string(),
                b"pw".to_vec(),
                Box::new(LocalRecovery(Ed25519Signer::from_seed(
                    &[4u8; 32],
                    "/r/KEY/r".parse().unwrap(),
                ))),
            )
            .expect("callback restore");
        assert!(device_b.has_identity());
        assert!(!device_b.sign(b"x".to_vec()).unwrap().is_empty());
        assert_eq!(
            ndn_identity::recovery_bundle::decode_history(&restored.bundle)
                .unwrap()
                .len(),
            2
        );

        // A refusing callback fails the restore.
        let device_c = NdnEngine::new(test_config()).unwrap();
        assert!(
            device_c
                .restore_identity_remote(
                    bundle,
                    "/ndn/mobile/alice".to_string(),
                    b"pw".to_vec(),
                    Box::new(Refuse),
                )
                .is_err()
        );

        device_a.shutdown();
        device_b.shutdown();
        device_c.shutdown();
    }

    /// The loaded identity self-revokes; the record verifies against its key and
    /// surfaces the revoked name + reason, and a wrong key is rejected.
    #[test]
    fn self_revoke_then_verify() {
        let key_name = "/ndn/mobile/alice/KEY/v=1";
        let kn: Name = key_name.parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[2u8; 32], kn.clone()).unwrap();
        let pubkey = signer.public_key().unwrap().to_vec();
        let cert = DataBuilder::new(kn.clone(), b"cert").build();
        let bag =
            ndn_security::safebag::SafeBag::encrypt(cert, &signer.to_pkcs8_der().unwrap(), b"pw").unwrap();
        let engine = NdnEngine::new(test_config()).unwrap();
        engine
            .load_identity(bag.encode().to_vec(), b"pw".to_vec(), key_name.to_string())
            .unwrap();

        let wire = engine.revoke_identity("compromised".to_string()).unwrap();
        let rev = engine.verify_revocation(wire.clone(), pubkey).unwrap();
        assert!(rev.self_revocation);
        assert_eq!(rev.reason, "compromised");
        assert_eq!(rev.revoked, key_name);

        // A wrong key fails verification.
        let other = EcdsaP256Signer::from_seed(&[9u8; 32], kn).unwrap();
        assert!(
            engine
                .verify_revocation(wire, other.public_key().unwrap().to_vec())
                .is_err()
        );

        engine.shutdown();
    }
}

#[cfg(all(test, not(feature = "identity")))]
mod enroll_surface_tests {
    use super::*;
    use crate::handlers::NdnPinHandler;
    use crate::types::NdnSecurityProfile;

    struct NoPin;
    impl NdnPinHandler for NoPin {
        fn provide_pin(&self, _request_id: String) -> String {
            String::new()
        }
    }

    /// Without the `identity` feature the enroll surface still exists and degrades
    /// to an error (not a panic). The full NDNCERT flow needs a live CA and is
    /// integration-tested via the testbed, like ndn-mobile's enroll.
    #[test]
    fn enroll_without_identity_feature_errors_gracefully() {
        let cfg = NdnEngineConfig {
            cs_capacity_mb: 1,
            security_profile: NdnSecurityProfile::Default,
            faces: Vec::new(),
            node_name: None,
            pipeline_threads: 1,
            persistent_cs_path: None,
        };
        let engine = NdnEngine::new(cfg).unwrap();
        let ec = NdnEnrollConfig {
            ca_prefix: "/ndn".into(),
            identity: "/ndn/mobile/alice".into(),
            validity_secs: 86_400,
            persist_password: b"pw".to_vec(),
        };
        assert!(matches!(
            engine.enroll(ec, Box::new(NoPin)),
            Err(NdnError::Identity { .. })
        ));
        engine.shutdown();
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;
    use crate::types::NdnSecurityProfile;
    use ndn_security::SignedTrustContext;

    fn cfg() -> NdnEngineConfig {
        NdnEngineConfig {
            cs_capacity_mb: 1,
            security_profile: NdnSecurityProfile::Default,
            faces: Vec::new(),
            node_name: None,
            pipeline_threads: 1,
            persistent_cs_path: None,
        }
    }

    /// The participant model: join contexts, list memberships, anti-rollback on
    /// re-join, and forget.
    #[test]
    fn join_list_forget_contexts() {
        let engine = NdnEngine::new(cfg()).unwrap();
        assert!(engine.list_contexts().is_empty());

        // A published context's content (version is carried out-of-band).
        let wire = SignedTrustContext::hierarchical("/home/bob".parse().unwrap())
            .encode_content()
            .to_vec();

        let joined = engine.join_context(wire.clone(), 2).unwrap();
        assert_eq!(joined.namespace, "/home/bob");
        assert_eq!(joined.version, 2);
        assert!(joined.enforces_hierarchy);

        let list = engine.list_contexts();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].namespace, "/home/bob");

        // Adopting a second context is additive.
        let work = SignedTrustContext::hierarchical("/work/acme".parse().unwrap())
            .encode_content()
            .to_vec();
        engine.join_context(work, 1).unwrap();
        assert_eq!(engine.list_contexts().len(), 2);

        // Anti-rollback: a strictly older version is refused; held stays 2.
        let v = engine.join_context(wire, 1).unwrap();
        assert_eq!(v.version, 2);
        assert_eq!(engine.list_contexts().len(), 2);

        // Forget removes one; forgetting again is a no-op.
        assert!(engine.forget_context("/home/bob".to_string()).unwrap());
        assert_eq!(engine.list_contexts().len(), 1);
        assert!(!engine.forget_context("/home/bob".to_string()).unwrap());

        engine.shutdown();
    }
}
