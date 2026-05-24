//! Witness for gap #5 — wiring host-owned handlers into the mgmt dispatcher.
//!
//! `/localhost/nfd/compute/list` reports "compute module not wired" until a
//! `ComputeMgmtBackend` is installed; `with_compute_mgmt_backend` must install
//! it so the verb serves the function dataset instead. This pins that the
//! builder threads the handler into `MgmtHandles.compute_handler` (previously
//! hardcoded `None`).
//!
//! `compute` is an extension module whose read is signed-command-gated, so the
//! witness mounts secured management, installs the signer's self-signed cert as
//! a trust anchor, and sends an ECDSA-signed query that clears the gate.

#![cfg(feature = "management")]

use std::sync::Arc;
use std::time::Duration;

use ndn_config::ControlResponse;
use ndn_mgmt::{ComputeDeterminism, ComputeFnKind, ComputeFunctionInfo, ComputeMgmtBackend};
use ndn_mobile::{InProcHandle, MobileEngine, Name, SecurityProfile};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, SignatureType};
use ndn_security::{Certificate, EcdsaP256Signer, Signer, TrustSchema, Validator};

const KEY_NAME: &str = "/ndn/mobile/node/KEY/v=1";

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

/// Build a secured-mgmt engine whose validator trusts `signer`'s self-signed
/// cert as an anchor, optionally wiring a compute backend.
async fn build(with_backend: bool) -> (MobileEngine, InProcHandle, Arc<EcdsaP256Signer>) {
    let key_name: Name = KEY_NAME.parse().unwrap();
    let signer = Arc::new(EcdsaP256Signer::from_seed(&[2u8; 32], key_name.clone()).unwrap());

    // Self-signed cert (content = the signer's SPKI) named at the key name, so
    // the command's KeyLocator resolves to it.
    let cert_wire = DataBuilder::new(key_name.clone(), &signer.public_key().unwrap()).build();
    let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();

    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    validator.add_trust_anchor(cert);

    let mut b = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_management_secured(validator, signer.clone() as Arc<dyn Signer>);
    if with_backend {
        b = b.with_compute_mgmt_backend(Arc::new(OneFn));
    }
    let (engine, handle) = b.build().await.expect("engine build");
    tokio::time::sleep(Duration::from_millis(50)).await;
    (engine, handle, signer)
}

async fn signed_compute_list(handle: &InProcHandle, signer: &Arc<EcdsaP256Signer>) -> Data {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"compute")
        .append(b"list");
    let key_name: Name = KEY_NAME.parse().unwrap();
    let s = signer.clone() as Arc<dyn Signer>;
    let wire = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .sign_fallible(
            SignatureType::SignatureSha256WithEcdsa,
            Some(&key_name),
            move |region| {
                let s = s.clone();
                let owned = region.to_vec();
                async move { s.sign(&owned).await }
            },
        )
        .await
        .expect("sign");
    handle.send(wire).await.expect("send");
    let resp = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response present");
    Data::decode(resp).expect("Data decode")
}

fn decoded(data: &Data) -> Option<(u64, String)> {
    ControlResponse::decode(data.content().cloned().unwrap_or_default())
        .ok()
        .map(|c| (c.status_code, c.status_text))
}

/// Without a backend, a properly signed compute/list clears auth and reaches
/// the handler, which reports "not wired".
#[tokio::test]
async fn compute_list_unwired_without_backend() {
    let (engine, handle, signer) = build(false).await;
    let data = signed_compute_list(&handle, &signer).await;
    let cr = decoded(&data);
    assert!(
        matches!(&cr, Some((_, t)) if t.contains("not wired")),
        "expected 'not wired' from the handler; got {cr:?}",
    );
    engine.shutdown().await;
}

/// With `with_compute_mgmt_backend`, the same signed query serves the dataset
/// (no "not wired", and not an auth rejection).
#[tokio::test]
async fn compute_list_wired_with_backend() {
    let (engine, handle, signer) = build(true).await;
    let data = signed_compute_list(&handle, &signer).await;
    let cr = decoded(&data);
    assert!(
        !matches!(&cr, Some((_, t)) if t.contains("not wired")),
        "backend wired, must not be 'not wired'; got {cr:?}",
    );
    assert!(
        !matches!(&cr, Some((403, _))),
        "backend wired, must clear auth; got {cr:?}",
    );
    engine.shutdown().await;
}
