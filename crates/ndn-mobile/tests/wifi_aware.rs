//! Witness for the mobile Wi-Fi Aware wiring (Phase 4).
//!
//! `with_wifi_aware` must mount the NAN coordination face on the engine and
//! re-mount it across suspend/resume (the platform radio backend is retained);
//! `wifi_aware_discover`/`advertise` must build without error (they register a
//! `NanDiscovery`). End-to-end forwarding/discovery over the bearer is proven at
//! the `ndn-face-wifi-aware` crate level.

#![cfg(feature = "wifi-aware")]

use std::sync::Arc;

use ndn_face_wifi_aware::LoopbackNanBus;
use ndn_mobile::{MobileEngine, Name, NanBackend, SecurityProfile};
use ndn_transport::FaceKind;

fn has_wifi_aware_face(engine: &MobileEngine) -> bool {
    engine
        .engine()
        .faces()
        .face_entries()
        .iter()
        .any(|(_, kind)| *kind == FaceKind::WifiAware)
}

#[tokio::test]
async fn with_wifi_aware_mounts_face_and_survives_suspend_resume() {
    let bus = LoopbackNanBus::new();
    let backend: Arc<dyn NanBackend> = Arc::new(bus.endpoint(1, [0xA0; 6], -50));

    let (mut engine, _handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_wifi_aware(backend)
        // Discovery bindings register a NanDiscovery — must build cleanly.
        .wifi_aware_advertise("ndn-svc")
        .wifi_aware_discover("ndn-svc", "/svc".parse::<Name>().unwrap())
        .build()
        .await
        .expect("engine build with wifi-aware");

    assert!(
        has_wifi_aware_face(&engine),
        "with_wifi_aware should mount a WifiAware coordination face"
    );

    engine.suspend_network_faces();
    engine.resume_network_faces().await;

    assert!(
        has_wifi_aware_face(&engine),
        "the NAN coordination face must be rebuilt on resume"
    );

    engine.shutdown().await;
}
