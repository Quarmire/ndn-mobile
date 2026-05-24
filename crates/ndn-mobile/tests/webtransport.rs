//! Witness for gap #6 — WebTransport dial-out face.
//!
//! `with_webtransport_peer` must dial a real WebTransport listener and mount the
//! resulting session as a routable, suspend/resume-tracked face. Pins that the
//! mobile builder wires the native `WebTransportFace::connect` client (the
//! cellular-NAT-friendly path), which did not exist pre-rework.

#![cfg(feature = "webtransport")]

use std::time::Duration;

use ndn_face_webtransport::{WebTransportListener, WtTlsConfig};
use ndn_mobile::{ClientTls, MobileEngine, SecurityProfile};
use ndn_transport::FaceId;

#[tokio::test]
async fn webtransport_peer_dials_and_is_routable() {
    // A self-signed loopback listener; the mobile face pins its leaf by SHA-256.
    let listener = WebTransportListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        WtTlsConfig::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind WT listener");
    let server_addr = listener.local_addr();
    let hash = listener.leaf_cert_sha256().expect("leaf cert hash");
    // Accept the dial the engine build will make.
    let accept = tokio::spawn(async move { listener.accept(FaceId(9999)).await });

    let url = format!("https://{server_addr}/ndn");
    let (engine, _handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_webtransport_peer(url.clone(), ClientTls::CertHashes(vec![hash]))
        .build()
        .await
        .expect("engine build");

    // The dial succeeded server-side.
    tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("accept within 5s")
        .expect("accept task")
        .expect("listener accepted the mobile dial");

    // The WT peer is listed and routable, and its face is live in the table.
    let peers = engine.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].uri(), url);

    engine.route_to_peer("/ndn", &peers[0], 0);
    let peer_id = engine
        .engine()
        .fib()
        .lpm(&"/ndn".parse().unwrap())
        .expect("route installed")
        .nexthops[0]
        .face_id;
    assert!(
        engine.engine().faces().get(peer_id).is_some(),
        "the dialed WebTransport face must be mounted in the face table",
    );

    engine.shutdown().await;
}
