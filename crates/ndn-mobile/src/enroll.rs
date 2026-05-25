//! NDNCERT 0.3 identity enrollment for the mobile engine, plus SafeBag
//! export/import for persistence across process restarts.
//!
//! [`MobileEngine::enroll_pin`] drives the standard NDNCERT exchange — NEW →
//! CHALLENGE (`pin`, trigger + submit) → best-effort cert fetch — over the
//! engine's in-process app consumer, reusing the [`ndn_cert::EnrollmentSession`]
//! state machine (the same one the `enroll-ndncert` tool drives). Interests for
//! the CA route out whatever face reaches it, so the caller must first install a
//! route toward the CA prefix, e.g.:
//!
//! ```no_run
//! # async fn doc(engine: &ndn_mobile::MobileEngine) -> anyhow::Result<()> {
//! use ndn_mobile::enroll::EnrollConfig;
//! let peer = &engine.peers()[0];               // a gateway added with with_tcp_peer/…
//! engine.route_to_peer("/ndn", peer, 0);       // CA lives under /ndn
//! let id = engine
//!     .enroll_pin(
//!         EnrollConfig::new("/ndn", "/ndn/mobile/alice"),
//!         |req| async move { ask_user_for_pin(&req.request_id).await },
//!     )
//!     .await?;
//! let bag = id.to_safebag(b"device-passphrase")?; // persist via App Group / Keychain
//! # let _ = bag; Ok(())
//! # }
//! # async fn ask_user_for_pin(_id: &str) -> String { String::new() }
//! ```
//!
//! The private key never leaves the device: [`EnrolledIdentity::to_safebag`]
//! produces an `ndnsec export`-compatible, password-encrypted bag the native
//! layer stores (iOS App Group / Keychain, Android keystore-wrapped file), and
//! [`MobileEngine::load_identity`] restores it.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_cert::EnrollmentSession;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Name, SignatureType};
use ndn_safebag::SafeBag;
use ndn_security::{EcdsaP256Signer, Signer};

use crate::engine::MobileEngine;

/// Default Interest lifetime for the enrollment exchange.
const INTEREST_LIFETIME: Duration = Duration::from_secs(10);

/// What to enroll: the CA prefix to reach and the identity to certify.
#[derive(Clone, Debug)]
pub struct EnrollConfig {
    /// CA prefix, e.g. `/ndn` — Interests go to `<ca_prefix>/CA/{NEW,CHALLENGE}`.
    pub ca_prefix: Name,
    /// Identity to certify, e.g. `/ndn/mobile/alice`. A fresh
    /// `<identity>/KEY/v=<ts>` key is generated for it.
    pub identity: Name,
    /// Requested certificate validity in seconds (default 1 day).
    pub validity_secs: u64,
}

impl EnrollConfig {
    pub fn new(ca_prefix: impl Into<Name>, identity: impl Into<Name>) -> Self {
        Self {
            ca_prefix: ca_prefix.into(),
            identity: identity.into(),
            validity_secs: 86_400,
        }
    }

    pub fn validity_secs(mut self, secs: u64) -> Self {
        self.validity_secs = secs;
        self
    }
}

/// Handed to the PIN callback so the app can surface the request to the user
/// and collect the out-of-band code the CA delivered (SMS / email / operator).
#[derive(Clone, Debug)]
pub struct PinRequest {
    /// Hex CA request id, useful to correlate with an out-of-band PIN delivery.
    pub request_id: String,
    /// The CA's `challenge-status` message, if any.
    pub status_message: Option<String>,
}

/// The result of a successful enrollment: the signing identity plus the issued
/// certificate name (and wire, if the CA's repo served it).
pub struct EnrolledIdentity {
    signer: Arc<EcdsaP256Signer>,
    key_name: Name,
    cert_name: Name,
    certificate: Option<Bytes>,
}

impl EnrolledIdentity {
    /// The certified key name (`<identity>/KEY/v=<ts>`).
    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    /// The issued certificate name (`<identity>/KEY/v=<ts>/<issuer>/v=<n>`).
    pub fn cert_name(&self) -> &Name {
        &self.cert_name
    }

    /// The issued certificate wire (NDN Certificate v2 Data), if it was fetched.
    /// `None` when the CA does not pair a repo to serve issued certs.
    pub fn certificate(&self) -> Option<&Bytes> {
        self.certificate.as_ref()
    }

    /// The signing identity, with its `KeyLocator` set to the issued cert name,
    /// ready to sign subscriptions / management commands.
    pub fn signer(&self) -> Arc<dyn Signer> {
        self.signer.clone()
    }

    /// Encrypt the private key + issued certificate into a password-protected
    /// [`SafeBag`] for on-device persistence (`ndnsec import`-compatible).
    /// Requires the issued certificate to have been fetched (see
    /// [`Self::certificate`]).
    pub fn to_safebag(&self, password: &[u8]) -> Result<SafeBag, EnrollError> {
        let cert = self
            .certificate
            .clone()
            .ok_or(EnrollError::NoCertificate)?;
        let pkcs8 = self
            .signer
            .to_pkcs8_der()
            .map_err(|e| EnrollError::Key(e.to_string()))?;
        SafeBag::encrypt(cert, &pkcs8, password).map_err(|e| EnrollError::SafeBag(e.to_string()))
    }
}

/// Errors from enrollment and identity persistence.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("key generation/export: {0}")]
    Key(String),
    #[error("NDNCERT protocol: {0}")]
    Cert(String),
    #[error("Interest signing: {0}")]
    Sign(String),
    #[error("fetch from CA failed: {0}")]
    Fetch(String),
    #[error("CA response missing content")]
    EmptyResponse,
    #[error("enrollment did not complete after PIN submission")]
    Incomplete,
    #[error("no issued cert was fetched; SafeBag needs the certificate")]
    NoCertificate,
    #[error("SafeBag: {0}")]
    SafeBag(String),
}

async fn sign_interest(
    builder: InterestBuilder,
    key_name: &Name,
    signer: &Arc<EcdsaP256Signer>,
) -> Result<Bytes, EnrollError> {
    let s: Arc<dyn Signer> = signer.clone();
    let kn = key_name.clone();
    builder
        .sign_fallible(
            SignatureType::SignatureSha256WithEcdsa,
            Some(&kn),
            move |region| {
                let s = Arc::clone(&s);
                let owned = region.to_vec();
                async move { s.sign(&owned).await }
            },
        )
        .await
        .map_err(|e: ndn_security::TrustError| EnrollError::Sign(e.to_string()))
}

impl MobileEngine {
    /// Run NDNCERT 0.3 enrollment for `cfg.identity` against `cfg.ca_prefix`,
    /// using the `pin` challenge. `pin_cb` is invoked once the CA asks for the
    /// PIN (delivered out-of-band) and must return the code. A route toward the
    /// CA prefix must already be installed (see module docs).
    pub async fn enroll_pin<F, Fut>(
        &self,
        cfg: EnrollConfig,
        pin_cb: F,
    ) -> Result<EnrolledIdentity, EnrollError>
    where
        F: FnOnce(PinRequest) -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let key_name: Name = cfg
            .identity
            .clone()
            .append("KEY")
            .append_version(ts_ms);
        let signer = Arc::new(
            EcdsaP256Signer::generate(key_name.clone())
                .map_err(|e| EnrollError::Key(e.to_string()))?,
        );

        // A standalone token bounds the enrollment app face; the face also
        // self-cleans when `consumer` is dropped at the end of the call.
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut consumer = self.engine().app_consumer(cancel.child_token());
        let mut session =
            EnrollmentSession::new(key_name.clone(), signer.clone(), cfg.validity_secs);

        // Step 1: NEW
        let new_params = session
            .new_request_body()
            .await
            .map_err(|e| EnrollError::Cert(e.to_string()))?;
        let new_name = cfg.ca_prefix.clone().append("CA").append("NEW");
        let new_wire = sign_interest(
            InterestBuilder::new(new_name).app_parameters(new_params),
            &key_name,
            &signer,
        )
        .await?;
        let new_data = consumer
            .fetch_wire(new_wire, INTEREST_LIFETIME + Duration::from_millis(500))
            .await
            .map_err(|e| EnrollError::Fetch(format!("NEW: {e}")))?;
        session
            .handle_new_response(new_data.content().ok_or(EnrollError::EmptyResponse)?)
            .map_err(|e| EnrollError::Cert(e.to_string()))?;
        let request_id_bytes = session
            .request_id_bytes()
            .ok_or_else(|| EnrollError::Cert("no request_id after NEW".into()))?
            .to_vec();

        // Step 2a: CHALLENGE trigger (select "pin", no code yet)
        let challenge_name = cfg
            .ca_prefix
            .clone()
            .append("CA")
            .append("CHALLENGE")
            .append(&request_id_bytes);
        let trigger_params = session
            .challenge_request_body("pin", serde_json::Map::new())
            .map_err(|e| EnrollError::Cert(e.to_string()))?;
        let trigger_wire = sign_interest(
            InterestBuilder::new(challenge_name.clone()).app_parameters(trigger_params),
            &key_name,
            &signer,
        )
        .await?;
        let trigger_data = consumer
            .fetch_wire(trigger_wire, INTEREST_LIFETIME + Duration::from_millis(500))
            .await
            .map_err(|e| EnrollError::Fetch(format!("CHALLENGE trigger: {e}")))?;
        session
            .handle_challenge_response(trigger_data.content().ok_or(EnrollError::EmptyResponse)?)
            .map_err(|e| EnrollError::Cert(e.to_string()))?;

        // Some CAs auto-complete (no PIN); otherwise collect the code.
        if !session.is_complete() {
            let pin = pin_cb(PinRequest {
                request_id: hex_encode(&request_id_bytes),
                status_message: session.challenge_status_message().map(str::to_string),
            })
            .await;

            // Step 2b: CHALLENGE submit (the PIN code)
            let mut code = serde_json::Map::new();
            code.insert("code".to_string(), serde_json::Value::String(pin));
            let submit_params = session
                .challenge_request_body("pin", code)
                .map_err(|e| EnrollError::Cert(e.to_string()))?;
            let submit_wire = sign_interest(
                InterestBuilder::new(challenge_name).app_parameters(submit_params),
                &key_name,
                &signer,
            )
            .await?;
            let submit_data = consumer
                .fetch_wire(submit_wire, INTEREST_LIFETIME + Duration::from_millis(500))
                .await
                .map_err(|e| EnrollError::Fetch(format!("CHALLENGE submit: {e}")))?;
            session
                .handle_challenge_response(
                    submit_data.content().ok_or(EnrollError::EmptyResponse)?,
                )
                .map_err(|e| EnrollError::Cert(e.to_string()))?;
        }

        if !session.is_complete() {
            return Err(EnrollError::Incomplete);
        }

        let cert_name = session
            .issued_cert_name()
            .ok_or_else(|| EnrollError::Cert("no issued cert name".into()))?
            .clone();

        // ── Step 3 (best-effort): fetch the issued cert (served by a repo). ─
        let certificate = match consumer.fetch(cert_name.clone()).await {
            Ok(data) => data.content().cloned(),
            Err(e) => {
                tracing::debug!(error = %e, "issued cert fetch skipped (no repo)");
                None
            }
        };

        // Stamp the issued cert name on the signer so it signs with the right
        // KeyLocator going forward.
        let signer = Arc::new(
            EcdsaP256Signer::from_pkcs8_der(
                &signer
                    .to_pkcs8_der()
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
                key_name.clone(),
            )
            .map_err(|e| EnrollError::Key(e.to_string()))?
            .with_cert_name(cert_name.clone()),
        );

        Ok(EnrolledIdentity {
            signer,
            key_name,
            cert_name,
            certificate,
        })
    }

    /// Restore an identity persisted as a [`SafeBag`] (the inverse of
    /// [`EnrolledIdentity::to_safebag`]). Returns the signing identity ready to
    /// sign; the caller installs it where needed. Only ECDSA-P256 keys are
    /// supported (the interop-safe curve — ndn-cxx / NFD reject Ed25519).
    pub fn load_identity(
        bag: &SafeBag,
        password: &[u8],
        key_name: impl Into<Name>,
    ) -> Result<Arc<dyn Signer>, EnrollError> {
        let pkcs8 = bag
            .decrypt_pkcs8(password)
            .map_err(|e| EnrollError::SafeBag(e.to_string()))?;
        let signer = EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name.into())
            .map_err(|e| EnrollError::Key(e.to_string()))?;
        Ok(Arc::new(signer))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;

    /// The persistence half of enrollment is testable without a CA: an
    /// identity exported to a password-encrypted SafeBag and restored via
    /// `load_identity` must be the *same* signing key (identical signatures).
    #[test]
    fn safebag_round_trip_preserves_signing_identity() {
        let key_name: Name = "/ndn/mobile/alice/KEY/v=1".parse().unwrap();
        let original = EcdsaP256Signer::from_seed(&[9u8; 32], key_name.clone()).unwrap();

        // SafeBag wants the issued cert Data wire; any Data stands in here since
        // load_identity only consumes the encrypted key half.
        let cert_wire = DataBuilder::new(key_name.clone(), b"cert-stub").build();
        let pkcs8 = original.to_pkcs8_der().unwrap();
        let password = b"device-passphrase";
        let bag = SafeBag::encrypt(cert_wire, &pkcs8, password).unwrap();

        let restored = MobileEngine::load_identity(&bag, password, key_name).unwrap();
        assert_eq!(
            original.sign_sync(b"signed subscription").unwrap(),
            restored.sign_sync(b"signed subscription").unwrap(),
            "restored identity must produce identical signatures",
        );
    }

    /// A wrong SafeBag password fails cleanly rather than yielding a bad key.
    #[test]
    fn safebag_wrong_password_is_rejected() {
        let key_name: Name = "/ndn/mobile/bob/KEY/v=1".parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[3u8; 32], key_name.clone()).unwrap();
        let cert_wire = DataBuilder::new(key_name.clone(), b"cert-stub").build();
        let bag = SafeBag::encrypt(cert_wire, &signer.to_pkcs8_der().unwrap(), b"right").unwrap();

        assert!(MobileEngine::load_identity(&bag, b"wrong", key_name).is_err());
    }
}
