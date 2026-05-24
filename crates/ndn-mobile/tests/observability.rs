//! Witness for gap #7 — observability hook.
//!
//! `with_observability` must install a span publisher on the engine: exposed
//! via `MobileEngine::observability()` and reachable over NDN at
//! `/localhost/nfd/observability` (a FIB route the publisher's `install`
//! registers). Without it, neither is present.

#![cfg(feature = "observability")]

use ndn_mobile::{MobileEngine, Name, SecurityProfile};

#[tokio::test]
async fn observability_installs_publisher_and_route() {
    let (engine, _h) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_observability()
        .build()
        .await
        .expect("engine build");

    let publisher = engine
        .observability()
        .expect("with_observability should install a publisher");
    assert_eq!(
        publisher.prefix().to_string(),
        "/localhost/nfd/observability",
    );

    // install() registered the serving prefix in the FIB.
    let probe: Name = "/localhost/nfd/observability/recent".parse().unwrap();
    assert!(
        engine.engine().fib().lpm(&probe).is_some(),
        "the observability prefix should be routable after install",
    );

    engine.shutdown().await;
}

#[tokio::test]
async fn no_observability_by_default() {
    let (engine, _h) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine build");
    assert!(engine.observability().is_none());
    engine.shutdown().await;
}
