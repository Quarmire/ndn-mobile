//! Witness for gap #5 — wiring host-owned handlers into the mgmt dispatcher.
//!
//! `/localhost/nfd/compute/list` reports "compute module not wired" until a
//! `ComputeMgmtBackend` is installed; `with_compute_mgmt_backend` must install
//! it so the verb serves the function dataset instead. This pins that the
//! builder threads the handler into `MgmtHandles.compute_handler` (previously
//! hardcoded `None`).
//!
//! `compute/list` is a public read-only introspection dataset (see
//! `ndn_mgmt::auth::is_public_dataset_verb`), so an unsigned query reaches the
//! handler directly — no command signing needed.

#![cfg(feature = "management")]

use std::sync::Arc;
use std::time::Duration;

use ndn_config::ControlResponse;
use ndn_mgmt::{ComputeDeterminism, ComputeFnKind, ComputeFunctionInfo, ComputeMgmtBackend};
use ndn_mobile::{InProcHandle, MobileEngine, Name, SecurityProfile};
use ndn_packet::{Data, encode::InterestBuilder};

struct OneFn;
impl ComputeMgmtBackend for OneFn {
    fn list(&self) -> Vec<ComputeFunctionInfo> {
        vec![ComputeFunctionInfo {
            prefix: "/svc/echo".parse().unwrap(),
            determinism: ComputeDeterminism::Transparent,
            kind: ComputeFnKind::Typed,
            fuel: None,
        }]
    }
}

async fn fetch_compute_list(handle: &InProcHandle) -> Data {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"compute")
        .append(b"list");
    let wire = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .build();
    handle.send(wire).await.expect("send");
    let resp = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response present");
    Data::decode(resp).expect("Data decode")
}

fn is_not_wired(data: &Data) -> bool {
    matches!(
        ControlResponse::decode(data.content().cloned().unwrap_or_default()),
        Ok(cr) if cr.status_text.contains("not wired")
    )
}

/// Without a backend, compute/list reaches the handler (public read) and
/// reports "not wired".
#[tokio::test]
async fn compute_list_unwired_without_backend() {
    let (engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_management()
        .build()
        .await
        .expect("engine build");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let data = fetch_compute_list(&handle).await;
    assert!(
        is_not_wired(&data),
        "compute/list should report 'not wired' with no backend",
    );
    engine.shutdown().await;
}

/// With `with_compute_mgmt_backend`, compute/list serves the dataset instead of
/// the "not wired" error.
#[tokio::test]
async fn compute_list_wired_with_backend() {
    let (engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_management()
        .with_compute_mgmt_backend(Arc::new(OneFn))
        .build()
        .await
        .expect("engine build");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let data = fetch_compute_list(&handle).await;
    assert!(
        !is_not_wired(&data),
        "compute/list must serve the dataset once a backend is wired",
    );
    // Served as a dataset segment under the query name, not an inline response.
    assert!(
        data.name.len() > 4,
        "expected a dataset segment under .../compute/list, got {}",
        data.name,
    );
    engine.shutdown().await;
}
