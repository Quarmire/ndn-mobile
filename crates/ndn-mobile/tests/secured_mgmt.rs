//! Witness for gap #1 — secured management.
//!
//! `with_management_secured` must flip command authentication on: a privileged
//! control command sent **unsigned** is rejected (403 UNAUTHORIZED), whereas
//! the same unsigned command against an engine mounted with the open
//! `with_management` is processed (not an auth rejection). This pins that the
//! builder actually wires `require_signed_commands` + `command_validator` into
//! the dispatcher, instead of mounting all-`None`/unauthenticated.

#![cfg(feature = "management")]

use std::sync::Arc;
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_mobile::{InProcHandle, MobileEngine, Name, SecurityProfile};
use ndn_packet::{Data, encode::InterestBuilder};
use ndn_security::{EcdsaP256Signer, Signer, TrustSchema, Validator};

fn rib_register_wire(prefix: &str) -> bytes::Bytes {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"rib")
        .append(b"register");
    let cp = ControlParameters {
        name: Some(prefix.parse().unwrap()),
        ..Default::default()
    };
    InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .app_parameters(cp.encode().to_vec())
        .build()
}

async fn send_unsigned_rib_register(handle: &InProcHandle) -> ControlResponse {
    handle
        .send(rib_register_wire("/witness/route"))
        .await
        .expect("send");
    let wire = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response present");
    let data = Data::decode(wire).expect("Data decode");
    ControlResponse::decode(data.content().cloned().unwrap_or_default())
        .expect("ControlResponse decode")
}

/// Secured mgmt rejects an unsigned privileged command with 403.
#[tokio::test]
async fn secured_management_rejects_unsigned_command() {
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    let signer: Arc<dyn Signer> = Arc::new(
        EcdsaP256Signer::from_seed(&[1u8; 32], "/ndn/mobile/node/KEY/v=1".parse().unwrap())
            .unwrap(),
    );

    let (engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_management_secured(validator, signer)
        .build()
        .await
        .expect("engine build");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cr = send_unsigned_rib_register(&handle).await;
    assert_eq!(
        cr.status_code, 403,
        "unsigned command must be 403 under secured mgmt; got {} {:?}",
        cr.status_code, cr.status_text
    );

    engine.shutdown().await;
}

/// Open mgmt (the existing `with_management`) processes the same unsigned
/// command — it is not auth-rejected — proving the secured path is what flips
/// the gate, not something else.
#[tokio::test]
async fn open_management_processes_unsigned_command() {
    let (engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_management()
        .build()
        .await
        .expect("engine build");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cr = send_unsigned_rib_register(&handle).await;
    assert_ne!(
        cr.status_code, 403,
        "open mgmt must not auth-reject; got {} {:?}",
        cr.status_code, cr.status_text
    );

    engine.shutdown().await;
}
