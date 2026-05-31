//! Live NDNCERT enrollment witness for `MobileEngine::enroll_pin` (gap #3).
//!
//! This drives the full NEW → CHALLENGE(pin) → cert exchange against a real CA
//! reachable over TCP, so it is `#[ignore]`d (skipped in CI, like the
//! `enroll-ndncert` interop tool which it mirrors). Run it against a CA with:
//!
//! ```text
//! NDN_TEST_TCP_PEER=127.0.0.1:6363 \
//! NDN_TEST_CA_PREFIX=/ndn \
//! NDN_TEST_IDENTITY=/ndn/mobile/test \
//! NDN_TEST_PIN=123456 \
//!   cargo test -p ndn-mobile --features enroll --test enroll_ca -- --ignored --nocapture
//! ```
//!
//! `NDN_TEST_PIN` is the out-of-band code the CA issued for the `pin` challenge.
//! On success it asserts a cert name under the requester identity was issued.

#![cfg(feature = "enroll")]

use ndn_mobile::{EnrollConfig, MobileEngine, Name, SecurityProfile};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "requires a live NDNCERT CA; set NDN_TEST_* env vars (see file header)"]
async fn enroll_pin_against_live_ca() {
    let tcp_peer = env("NDN_TEST_TCP_PEER").expect("NDN_TEST_TCP_PEER");
    let ca_prefix_str = env("NDN_TEST_CA_PREFIX").unwrap_or_else(|| "/ndn".to_string());
    let identity_str = env("NDN_TEST_IDENTITY").unwrap_or_else(|| "/ndn/mobile/test".to_string());
    let pin = env("NDN_TEST_PIN").expect("NDN_TEST_PIN (out-of-band CA code)");
    let ca_prefix: Name = ca_prefix_str.parse().expect("NDN_TEST_CA_PREFIX");
    let identity: Name = identity_str.parse().expect("NDN_TEST_IDENTITY");

    let (engine, _h) = MobileEngine::builder()
        // Real-CA enrollment validates the CA's signed responses against the
        // configured trust profile.
        .security_profile(SecurityProfile::Default)
        .with_tcp_peer(
            tcp_peer
                .parse()
                .expect("NDN_TEST_TCP_PEER must be host:port"),
        )
        .build()
        .await
        .expect("engine build");

    // Route the CA prefix toward the gateway peer so enrollment Interests reach it.
    let peer = engine
        .peers()
        .into_iter()
        .next()
        .expect("the TCP peer should be configured");
    engine.route_to_peer(ca_prefix.clone(), &peer, 0);

    let id = engine
        .enroll_pin(EnrollConfig::new(ca_prefix, identity), |req| {
            eprintln!("CA requested PIN (request_id={})", req.request_id);
            async move { pin }
        })
        .await
        .expect("enrollment should complete");

    eprintln!("issued cert: {}", id.cert_name());
    assert!(
        id.cert_name().to_string().starts_with(&identity_str),
        "issued cert {} should be under identity {identity_str}",
        id.cert_name(),
    );

    engine.shutdown().await;
}
