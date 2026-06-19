//! [`NdnClient`] — the **Remote backend**: a bare NDN client over an existing
//! forwarder connection, no embedded engine.
//!
//! This is the mobile UI↔tunnel split (see `ndn-mobile` / the VPN notes). The
//! tunnel process owns the [`NdnEngine`](crate::NdnEngine) (engine + content
//! store + network faces); the UI process holds an `NdnClient` over one end of
//! a `socketpair()` the tunnel hands across Binder. Interests and Data cross
//! that fd to the tunnel's forwarder; the UI keeps no PIT/FIB/CS.
//!
//! Like [`NdnEngine`](crate::NdnEngine), BoltFFI can't pass exported objects, so
//! consumer (`fetch`/`get`) and producer (`serve`) operations are methods on
//! this one object. Unix only — the seam is a POSIX socket, and the mobile
//! targets (`aarch64-apple-ios`, `aarch64-linux-android`) are Unix.

#![cfg(unix)]

use std::sync::{Arc, Mutex};

use boltffi::export;
use bytes::Bytes;
use ndn_app::{Connection, Consumer, IpcConnection};
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use tokio::runtime::Runtime;

use crate::handlers::NdnInterestHandler;
#[cfg(feature = "identity")]
use crate::handlers::{NdnApprovalGate, NdnEnclaveBackend, NdnRecoverySigner};
use crate::identity_core::IdentityCore;
#[cfg(feature = "identity")]
use crate::types::{
    NdnActionClass, NdnDelegationScope, NdnEnrollConfig, NdnEnrolledIdentity, NdnRecoveredIdentity,
    NdnRevocation,
};
use crate::types::{NdnContext, NdnData, NdnError};

/// A pure NDN client bound to a forwarder over a duplex fd. Construct once with
/// the fd handed across the platform IPC boundary, then drive it through
/// `fetch` / `get` / `serve`. Calls are blocking — issue them from a background
/// thread (`Dispatchers.IO` / `Task.detached`).
pub struct NdnClient {
    rt: Arc<Runtime>,
    /// Lazily-built shared consumer for `fetch` / `get` (serialized).
    consumer: Mutex<Option<Consumer>>,
    /// Identity + signing + trust-context state, run over the forwarder
    /// connection. Identity lives in the UI process; the same core the embedded
    /// `NdnEngine` uses, here over the cross-process seam.
    identity_core: IdentityCore,
    /// Tap-to-share producer board (cert + manifest + per-file serve loops).
    /// `None` until [`Self::start_offer_board`].
    offer_board: Mutex<Option<Arc<crate::offer::OfferBoard>>>,
    /// Live progress of the most recent object fetch (segments received / total).
    /// Kept *outside* the `consumer` lock so a UI poller can read it concurrently
    /// while a blocking fetch holds that lock — drives a download progress bar.
    fetch_received: Arc<std::sync::atomic::AtomicU64>,
    fetch_total: Arc<std::sync::atomic::AtomicU64>,
    /// Congestion-control strategy applied to object fetches (default AIMD;
    /// swap to CUBIC at runtime via `set_congestion_strategy` to A/B the link).
    cc_strategy: Mutex<ndn_app::CongestionStrategy>,
}

#[export]
impl NdnClient {
    /// Adopt an already-connected `SOCK_STREAM` fd — the UI end of the
    /// `socketpair()` the tunnel's `VpnService` returns across Binder as a
    /// `ParcelFileDescriptor`. Takes ownership of the fd.
    pub fn from_fd(fd: i32) -> Result<Self, NdnError> {
        crate::init_platform_tracing();
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(NdnError::engine)?,
        );
        // Adopting the fd builds a tokio UnixStream → needs the IO driver in
        // context; do it inside the runtime.
        let client = rt
            .block_on(async { ForwarderClient::from_raw_fd(fd as std::os::fd::RawFd) })
            .map_err(NdnError::engine)?;
        let conn = Arc::new(IpcConnection::new(client));
        // IdentityCore wraps the seam in a DemuxConnection; share that one demux
        // for ALL of this client's I/O (fetch / get / serve) so there is a single
        // reader of the data plane. (ForwarderClient already demuxes mgmt below.)
        let identity_core = IdentityCore::new(rt.clone(), conn as Arc<dyn Connection>);
        Ok(Self {
            rt,
            consumer: Mutex::new(None),
            identity_core,
            offer_board: Mutex::new(None),
            fetch_received: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fetch_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cc_strategy: Mutex::new(ndn_app::CongestionStrategy::default()),
        })
    }

    /// Select the congestion-control strategy for subsequent object fetches:
    /// `"aimd"` (default) or `"cubic"`. CUBIC grows the window more aggressively
    /// on high bandwidth-delay paths — toggle it at runtime to A/B a link.
    ///
    /// Returns `Ok(true)`: the non-unit `Ok` dodges the boltffi 0.25
    /// `Result<(), E>` FFI segfault (a unit-Ok export crashes on call).
    pub fn set_congestion_strategy(&self, strategy: String) -> Result<bool, NdnError> {
        let s = ndn_app::CongestionStrategy::parse(&strategy)
            .ok_or_else(|| NdnError::engine("congestion strategy must be 'aimd' or 'cubic'"))?;
        *self.cc_strategy.lock().unwrap() = s;
        Ok(true)
    }

    /// Blocking fetch; returns the full Data (name + content). Blocks up to the
    /// Interest lifetime (~4.5 s). Calls are serialized — use a worker thread.
    pub fn fetch(&self, name: String) -> Result<NdnData, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
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
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
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
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch_object(parsed))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Verified whole-object fetch — the **secure** counterpart to
    /// [`Self::fetch_object`]: the metadata Data and every segment are verified
    /// against this node's trust anchors (its own self-cert + any pinned via
    /// [`Self::pin_trust_anchor`]) before reassembly, so an unsigned or untrusted
    /// object is refused. Prefer this for received content.
    pub fn fetch_object_verified(&self, name: String) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let validator = std::sync::Arc::new(self.identity_core.build_validator());
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
        }
        let consumer = guard.as_mut().unwrap();
        self.rt
            .block_on(consumer.fetch_object_verified(parsed, validator))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Pin a certificate (Data wire — e.g. a peer's exported
    /// [`Self::principal_cert_wire`]) as a trust anchor for
    /// [`Self::fetch_object_verified`]. The explicit cross-peer trust decision.
    pub fn pin_trust_anchor(&self, cert_wire: Vec<u8>) -> Result<bool, NdnError> {
        self.identity_core.pin_trust_anchor(cert_wire)
    }

    /// RDR whole-object publish: segments `content` under `<name>/v=<ver>` and
    /// serves it (metadata + segments) until the connection closes — blocking,
    /// run on a worker thread. `chunk_size == 0` uses the 8 KiB default. Signed
    /// with the loaded operator identity if present. Pairs with
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

    /// Blocking producer loop: registers `prefix` with the forwarder (so it
    /// routes matching Interests across the seam), then dispatches each Interest
    /// to `handler`, returning the handler's bytes (or dropping on `None`).
    /// Returns when the connection closes. Run on a background thread.
    pub fn serve(
        &self,
        prefix: String,
        handler: Box<dyn NdnInterestHandler>,
    ) -> Result<bool, NdnError> {
        // Non-unit `Ok` dodges the boltffi 0.25 `Result<(), E>` FFI segfault.
        let name: Name = prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&prefix))?;
        // Serve over the shared demux (registers the prefix + dispatches) so this
        // producer loop coexists with the client's fetches and identity serves on
        // the one connection.
        let handler: Arc<dyn NdnInterestHandler> = handler.into();
        self.rt
            .block_on(self.identity_core.demux.serve(name, move |interest, responder| {
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

    /// Verified whole-object fetch steered by an NDNLPv2 **ForwardingHint** —
    /// like [`Self::fetch_object_verified`] but every Interest carries `hint`
    /// (a routable delegation, e.g. a peer's `/ndn/node/<peerId>`), so content
    /// named under the peer's own identity is forwarded toward it and stripped
    /// at the peer's node. The cross-peer fetch for tap-to-share: pin the peer's
    /// cert first (fetch `/ndn/node/<peerId>/cert` → [`Self::pin_trust_anchor`]).
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
        consumer.set_congestion_strategy(*self.cc_strategy.lock().unwrap());
        use std::sync::atomic::Ordering;
        self.fetch_received.store(0, Ordering::Relaxed);
        self.fetch_total.store(0, Ordering::Relaxed);
        let received = Arc::clone(&self.fetch_received);
        let total = Arc::clone(&self.fetch_total);
        self.rt
            .block_on(consumer.fetch_object_verified_hinted_progress(
                parsed,
                validator,
                &[hint_name],
                move |r, t| {
                    total.store(t, Ordering::Relaxed);
                    received.store(r, Ordering::Relaxed);
                },
            ))
            .map(|b| b.to_vec())
            .map_err(|e| NdnError::from_app(e, &name))
    }

    /// Segments received so far by the most recent
    /// [`fetch_object_verified_hinted`](Self::fetch_object_verified_hinted).
    /// Poll alongside [`Self::fetch_progress_total`] from a UI thread *while* the
    /// (blocking) fetch runs — these read atomics outside the fetch lock — to
    /// drive a download progress bar. Reset to 0 at the start of each fetch.
    pub fn fetch_progress_received(&self) -> u64 {
        self.fetch_received.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total segments in the object being fetched (0 until the metadata lands).
    pub fn fetch_progress_total(&self) -> u64 {
        self.fetch_total.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Verified hinted fetch that **streams to a descriptor**: each verified
    /// segment is written to `fd` at its byte offset as it arrives, so an
    /// arbitrarily large object is received without ever buffering it in memory
    /// (removes the receive-side memory ceiling). `fd` is a writable, seekable
    /// descriptor (e.g. Android `ParcelFileDescriptor.detachFd()` of a Downloads
    /// entry opened "w"); ownership transfers and it is closed when done.
    /// Returns the total bytes written. Progress is reported through the same
    /// [`fetch_progress_received`](Self::fetch_progress_received) getters.
    #[cfg(unix)]
    pub fn fetch_object_to_fd(
        &self,
        name: String,
        hint: String,
        fd: i32,
    ) -> Result<u64, NdnError> {
        use std::os::fd::FromRawFd;
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let hint_name: Name = hint.parse().map_err(|_| NdnError::invalid_name(&hint))?;
        let validator = std::sync::Arc::new(self.identity_core.build_validator());
        // SAFETY: caller detached ownership of a writable fd; we adopt it once.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut guard = self.consumer.lock().unwrap();
        if guard.is_none() {
            *guard = Some(Consumer::new(self.identity_core.demux.clone() as Arc<dyn Connection>));
        }
        let consumer = guard.as_mut().unwrap();
        consumer.set_congestion_strategy(*self.cc_strategy.lock().unwrap());
        use std::sync::atomic::Ordering;
        self.fetch_received.store(0, Ordering::Relaxed);
        self.fetch_total.store(0, Ordering::Relaxed);
        let received = Arc::clone(&self.fetch_received);
        let total = Arc::clone(&self.fetch_total);
        self.rt
            .block_on(consumer.fetch_object_to_file_hinted_progress(
                parsed,
                validator,
                &[hint_name],
                &file,
                move |r, t| {
                    total.store(t, Ordering::Relaxed);
                    received.store(r, Ordering::Relaxed);
                },
            ))
            .map_err(|e| NdnError::from_app(e, &name))
    }

    // ── Tap-to-share offer board ────────────────────────────────────────────

    /// Start the tap-to-share **offer board** for this node's discovery
    /// `node_id` (read from the `self` field of `/localhost/discovery/peers`):
    /// serve the offerer cert at `/ndn/node/<id>/cert` and a signed manifest at
    /// `/ndn/node/<id>/offers`. Idempotent (replaces any prior board). Requires
    /// a loaded identity. Pair with [`Self::add_offer`].
    pub fn start_offer_board(&self, node_id: String) -> Result<bool, NdnError> {
        #[cfg(feature = "identity")]
        {
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

    /// Offer a file: serve `content` as a signed RDR object under this node's
    /// identity and add it to the manifest. `file_id` is a stable handle (used
    /// in the object name and to [`Self::remove_offer`]); `display_name` / `mime`
    /// are shown to a peer. Returns the routable object name. Requires
    /// [`Self::start_offer_board`] first.
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

    /// Offer a **file by descriptor** — segments are read from the file on
    /// demand, so an arbitrarily large file is shared without copying it into
    /// memory (the fix for large offers silently failing when the whole file
    /// was loaded as one buffer). `fd` is a readable, seekable file descriptor
    /// (e.g. Android `ParcelFileDescriptor.detachFd()` of the picked file);
    /// ownership transfers to the engine, which closes it when the offer is
    /// removed. `size` is the file's length in bytes. Otherwise like
    /// [`Self::add_offer`].
    #[cfg(unix)]
    pub fn add_offer_fd(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        fd: i32,
        size: u64,
    ) -> Result<String, NdnError> {
        use std::os::fd::FromRawFd;
        // SAFETY: the caller passes a fd it has detached ownership of (so it
        // won't double-close); we adopt it into a File that owns it henceforth.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        match self.offer_board.lock().unwrap().clone() {
            Some(board) => board.add_offer_file(file_id, display_name, mime, file, size),
            None => Err(NdnError::engine(
                "offer board not started — call start_offer_board first",
            )),
        }
    }

    /// Offer a file by descriptor via the **streaming relay** path (producer-side
    /// "bulk off the seam"): the leaf serves the file's raw segments as a stream
    /// on `/localhost/ripple/content/<file_id>`; the node engine must then be
    /// registered as producer-of-record for the returned public name via
    /// [`NdnEngine::register_object_relay`](crate::NdnEngine::register_object_relay)
    /// (over AIDL, with the same `file_id`/`size`) so it re-signs + serves the
    /// segments. Removes the per-segment RemoteSigner round-trip for bulk.
    /// Returns the public object name. Otherwise like [`Self::add_offer_fd`].
    #[cfg(unix)]
    pub fn add_offer_fd_streamed(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        fd: i32,
        size: u64,
    ) -> Result<String, NdnError> {
        use std::os::fd::FromRawFd;
        // SAFETY: the caller detached ownership of `fd`; we adopt it once.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        match self.offer_board.lock().unwrap().clone() {
            Some(board) => board.add_offer_file_streamed(file_id, display_name, mime, file, size),
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

    /// This node's current offerings as JSON (for its own UI) — same shape as
    /// the served manifest. Empty when no board is running.
    pub fn list_offers(&self) -> String {
        self.offer_board
            .lock()
            .unwrap()
            .clone()
            .map(|board| board.list_offers())
            .unwrap_or_else(|| "{\"node\":\"\",\"offers\":[]}".to_string())
    }

    // ── Identity + signing + trust contexts ───────────────────────────────
    // Identity lives in the UI process; these delegate to the shared
    // `IdentityCore`, running over the forwarder connection (the socketpair
    // seam) exactly as `NdnEngine`'s identity methods run over its embedded
    // engine. Same names / signatures / feature gates as `NdnEngine`.

    /// Adopt (join) a trust context from its encoded content and `version`.
    pub fn join_context(&self, context_wire: Vec<u8>, version: u64) -> Result<NdnContext, NdnError> {
        self.identity_core.join_context(context_wire, version)
    }

    /// List the adopted trust contexts.
    pub fn list_contexts(&self) -> Vec<NdnContext> {
        self.identity_core.list_contexts()
    }

    /// Forget (leave) a context by namespace; returns whether one was removed.
    pub fn forget_context(&self, namespace: String) -> Result<bool, NdnError> {
        self.identity_core.forget_context(namespace)
    }

    /// Restore a software operator identity from a password-encrypted SafeBag.
    pub fn load_identity(
        &self,
        safebag: Vec<u8>,
        password: Vec<u8>,
        key_name: String,
    ) -> Result<String, NdnError> {
        self.identity_core.load_identity(safebag, password, key_name)
    }

    /// Whether an operator identity is loaded.
    pub fn has_identity(&self) -> bool {
        self.identity_core.has_identity()
    }

    /// Become **keyless**: install a remote signer so every published object is
    /// signed via the RemoteSigner served at `signer_prefix` (the device's Anchor),
    /// presenting `cert_wire` (the Anchor's certificate) as this leaf's KeyLocator
    /// and served cert. Replaces any loaded SafeBag. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn use_remote_signer(
        &self,
        signer_prefix: String,
        cert_wire: Vec<u8>,
    ) -> Result<bool, NdnError> {
        self.identity_core
            .use_remote_signer(signer_prefix, cert_wire)
    }

    /// Sign `region` with the loaded operator identity.
    pub fn sign(&self, region: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.sign(region)
    }

    /// NDNCERT token-challenge enrollment over the forwarder seam; loads the
    /// issued identity. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn enroll_with_token(
        &self,
        config: NdnEnrollConfig,
        token: String,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.enroll_with_token(config, token)
    }

    /// Hardware-backed token-challenge enrollment over the forwarder seam.
    /// Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn enroll_with_token_enclave(
        &self,
        config: NdnEnrollConfig,
        token: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core
            .enroll_with_token_enclave(config, token, enclave)
    }

    /// Generate a self-signed local identity and install it for signing.
    /// Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn generate_identity(
        &self,
        name: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.generate_identity(name, persist_password)
    }

    /// Generate a hardware-backed identity. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn generate_identity_enclave(
        &self,
        name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        self.identity_core.generate_identity_enclave(name, enclave)
    }

    /// Re-bind a previously generated hardware identity after restart.
    /// Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn load_identity_enclave(
        &self,
        key_name: String,
        cert_name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<bool, NdnError> {
        self.identity_core
            .load_identity_enclave(key_name, cert_name, enclave)
    }

    /// Serve one RemoteSigner request (the single-shot core).
    #[cfg(feature = "identity")]
    pub fn respond_to_sign_request(
        &self,
        request: Vec<u8>,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core.respond_to_sign_request(request, gate)
    }

    /// Serve a RemoteSigner responder at `prefix` over the forwarder seam.
    /// Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn serve_remote_signer(
        &self,
        prefix: String,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<bool, NdnError> {
        self.identity_core.serve_remote_signer(prefix, gate)
    }

    /// Announce a served prefix to the upstream gateway (remote prefix
    /// registration) over the forwarder seam. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn announce_prefix(&self, prefix: String) -> Result<bool, NdnError> {
        self.identity_core.announce_prefix(prefix)
    }

    /// Open a §7 scoped-signing grant. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn grant_signing_scope(
        &self,
        action: NdnActionClass,
        ttl_secs: u64,
    ) -> Result<u32, NdnError> {
        self.identity_core.grant_signing_scope(action, ttl_secs)
    }

    /// The loaded operator identity's `did:ndn` URI. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn principal_did(&self) -> Result<String, NdnError> {
        self.identity_core.principal_did()
    }

    /// The loaded operator identity's human-readable NDN name. Requires the
    /// `identity` feature.
    #[cfg(feature = "identity")]
    pub fn principal_name(&self) -> Result<String, NdnError> {
        self.identity_core.principal_name()
    }

    /// The loaded identity's raw public key.
    pub fn principal_public_key(&self) -> Result<Vec<u8>, NdnError> {
        self.identity_core.principal_public_key()
    }

    /// A certificate for the loaded identity. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn principal_cert_wire(&self) -> Result<Vec<u8>, NdnError> {
        self.identity_core.principal_cert_wire()
    }

    /// Derive the Ed25519 public key from a 32-byte recovery seed.
    pub fn recovery_public_key(&self, recovery_seed: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.recovery_public_key(recovery_seed)
    }

    /// Issue a signed device delegation. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn add_device(
        &self,
        device: String,
        scope: NdnDelegationScope,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core.add_device(device, scope)
    }

    /// Verify a received `SignedDelegation`. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn verify_delegation(
        &self,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<NdnDelegationScope, NdnError> {
        self.identity_core
            .verify_delegation(delegation_wire, principal_pubkey)
    }

    /// Sign `region` within a received delegation's granted scope. Requires the
    /// `identity` feature.
    #[cfg(feature = "identity")]
    pub fn sign_delegated(
        &self,
        region: Vec<u8>,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        self.identity_core
            .sign_delegated(region, delegation_wire, principal_pubkey)
    }

    /// Convenience over [`Self::sign_delegated`]. Requires the `identity` feature.
    #[cfg(feature = "identity")]
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

    /// Make the loaded identity recoverable. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn make_recoverable(&self, recovery_pubkey: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        self.identity_core.make_recoverable(recovery_pubkey)
    }

    /// Fresh-device restore from a bundle + recovery seed. Requires the
    /// `identity` feature.
    #[cfg(feature = "identity")]
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

    /// Secure restore where the recovery key signs via callback. Requires the
    /// `identity` feature.
    #[cfg(feature = "identity")]
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

    /// Self-revoke the loaded identity. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn revoke_identity(&self, reason: String) -> Result<Vec<u8>, NdnError> {
        self.identity_core.revoke_identity(reason)
    }

    /// Verify a received `RevocationRecord`. Requires the `identity` feature.
    #[cfg(feature = "identity")]
    pub fn verify_revocation(
        &self,
        record: Vec<u8>,
        signer_pubkey: Vec<u8>,
    ) -> Result<NdnRevocation, NdnError> {
        self.identity_core.verify_revocation(record, signer_pubkey)
    }

    /// "Tap Stop" — revoke all active scoped-signing grants.
    pub fn stop_signing_scope(&self) {
        self.identity_core.stop_signing_scope()
    }

    /// How many scoped-signing grants are live right now.
    pub fn active_signing_scopes(&self) -> u32 {
        self.identity_core.active_signing_scopes()
    }
}
