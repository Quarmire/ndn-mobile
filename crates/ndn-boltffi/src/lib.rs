//! BoltFFI bindings exposing the embedded NDN forwarder
//! ([`MobileEngine`](ndn_mobile::MobileEngine)) to Android (Kotlin), iOS/
//! iPadOS (Swift), and WASM/TypeScript from one `#[export]` surface.
//!
//! The engine is the single stateful object: `fetch` / `get` (consumer),
//! `serve` (producer, with an [`NdnInterestHandler`] callback), and
//! `subscribe` (SVS, with an [`NdnSampleHandler`] callback). BoltFFI can't
//! pass or cross-create exported objects, so these are methods on
//! [`NdnEngine`] rather than separate handles — the rich typed
//! `Consumer` / `Producer` / `Subscriber` live in `ndn-app` for native Rust.
//!
//! The serve/subscribe loops and `fetch`/`get` are blocking; call them from
//! `Dispatchers.IO` / `Task.detached` / a worker. [`NdnCodec`] /
//! [`NdntsReassembler`] are stateless wire helpers for BLE clients.
//!
//! Two more top-level objects ride a forwarder connection rather than an
//! embedded engine: [`NdnClient`] (a bare consumer/producer over the tunnel's
//! data fd) and, behind the native-only `dashboard` feature,
//! [`NdnDashboard`](dashboard::NdnDashboard) — the operator console that polls a
//! forwarder's management plane for faces / routes / CS / strategies / status.
//!
//! Generate bindings with `boltffi generate <lang>`; package with
//! `boltffi pack android|apple`.

#[cfg(unix)]
pub mod client;
pub mod codec;

/// Route the engine's `tracing` events to Android logcat (tag `ndn`), once.
///
/// On mobile, boltffi is the platform entry point — no Rust binary owns the
/// subscriber — so it installs one here. Android-only; a no-op everywhere else
/// (and `try_init` is a no-op if a subscriber is already set, e.g. a host test).
/// Set `RUST_LOG` (e.g. via the app) to override the default filter.
pub(crate) fn init_platform_tracing() {
    #[cfg(target_os = "android")]
    {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,ndn_engine=debug,ndn_face=debug,ndn_mobile=debug,\
                     ndn_face_wifi_aware=debug,ndn_mgmt=info,ndn_boltffi=debug,\
                     ndn_app::fetch=debug",
                )
            });
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(paranoid_android::AndroidLogMakeWriter::new("ndn".to_owned())),
                )
                .try_init();
        });
    }
}

#[cfg(all(unix, feature = "dashboard"))]
pub mod dashboard;
mod discovery;
pub mod engine;
pub mod handlers;
pub(crate) mod identity_core;
pub(crate) mod offer;
#[cfg(feature = "identity")]
pub(crate) mod remote_signer_client;
pub mod trust;
pub mod types;
// Always compiled: the `NdnNanBackend` / `NdnBleBackend` traits (primitives
// only) are part of the FFI surface in every build so the `attach_*` bindings
// exist; the `ndn-face-*`-backed adapters inside are feature-gated.
pub mod ble;
pub mod wifi_aware;

#[cfg(unix)]
pub use client::NdnClient;
#[cfg(all(unix, feature = "dashboard"))]
pub use dashboard::{
    NdnCsInfo, NdnDashboard, NdnDashboardState, NdnFaceInfo, NdnFibEntry, NdnForwarderStatus,
    NdnIdentityState, NdnMgmtResponse, NdnNextHop, NdnPendingApproval, NdnSecurityKey,
    NdnStrategyEntry, NdnTrustAnchor,
};
pub use codec::{NdnCodec, NdntsReassembler};
pub use engine::NdnEngine;
pub use trust::NdnTrust;
pub use handlers::{
    NdnApprovalGate, NdnEnclaveBackend, NdnInterestHandler, NdnPinHandler, NdnRecoverySigner,
    NdnSampleHandler,
};
pub use types::{
    NdnActionClass, NdnContext, NdnData, NdnDelegationScope, NdnEngineConfig, NdnEnrollConfig,
    NdnEnrolledIdentity, NdnError, NdnFaceSpec, NdnRecoveredIdentity, NdnRevocation, NdnSample,
    NdnSecurityProfile, NdnTrustEnvelope,
};
pub use ble::NdnBleBackend;
pub use wifi_aware::NdnNanBackend;
