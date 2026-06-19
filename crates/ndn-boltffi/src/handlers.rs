//! Callback interfaces implemented in the host language (Kotlin/Swift/TS) and
//! passed to the blocking [`NdnEngine::serve`](crate::NdnEngine::serve) /
//! [`NdnEngine::subscribe`](crate::NdnEngine::subscribe) loops.

use boltffi::export;

use crate::types::NdnSample;

/// Answers Interests under a served prefix. Return `Some(payload)` to satisfy
/// the Interest with a Data packet, or `None` to drop it.
#[export]
pub trait NdnInterestHandler: Send + Sync {
    fn handle_interest(&self, name: String) -> Option<Vec<u8>>;
}

/// Receives publications from a subscribed SVS group.
#[export]
pub trait NdnSampleHandler: Send + Sync {
    fn on_sample(&self, sample: NdnSample);
}

/// Supplies the out-of-band PIN during NDNCERT enrollment
/// ([`NdnEngine::enroll`](crate::NdnEngine::enroll)). The host shows the request
/// to the user — `request_id` correlates with how the CA delivered the code
/// (SMS / email / operator) — and returns the code. Called once, only after the
/// CA asks for the PIN.
#[export]
pub trait NdnPinHandler: Send + Sync {
    fn provide_pin(&self, request_id: String) -> String;
}

/// The biometric / user-verification gate for the **RemoteSigner responder**
/// ([`NdnEngine::respond_to_sign_request`](crate::NdnEngine::respond_to_sign_request)).
/// `summary` is rendered from the request's signed region itself (not any
/// requester-supplied hint), so what the user approves is what gets signed.
/// Return `true` to authorize the signature (after the platform biometric
/// prompt), `false` to deny.
#[export]
pub trait NdnApprovalGate: Send + Sync {
    fn approve(&self, summary: String) -> bool;
}

/// The recovery key for the **secure restore** path
/// ([`NdnEngine::restore_identity_remote`](crate::NdnEngine::restore_identity_remote)):
/// the recovery key lives on another device or in an enclave and never enters
/// this device. `challenge` is the new key-state's canonical bytes; sign it
/// with the **recovery key** (Ed25519) and return the raw signature, or an
/// empty vector to refuse. The signature must verify under the public key the
/// identity committed to via `make_recoverable`.
#[export]
pub trait NdnRecoverySigner: Send + Sync {
    fn sign(&self, challenge: Vec<u8>) -> Vec<u8>;
}

/// A hardware-backed signing key held in the device enclave (Android StrongBox /
/// iOS Secure Enclave) for [`NdnEngine::generate_identity_enclave`](crate::NdnEngine::generate_identity_enclave).
/// The private key never leaves the enclave; the host implements this to expose
/// it. All P-256 (ECDSA-SHA256).
#[export]
pub trait NdnEnclaveBackend: Send + Sync {
    /// Whether the key is usable right now (present, biometry enrolled, device unlocked).
    fn is_available(&self) -> bool;

    /// The enclave key's public key as SPKI DER (91 bytes for P-256), or the raw
    /// SEC1 uncompressed point. Empty if unavailable. (Android `PublicKey.getEncoded()`
    /// already returns SPKI DER.)
    fn public_key(&self) -> Vec<u8>;

    /// Sign `region` inside the enclave — the host shows the biometric prompt,
    /// signs, and returns the DER ECDSA signature (or empty to refuse / on error).
    fn sign(&self, region: Vec<u8>) -> Vec<u8>;
}
