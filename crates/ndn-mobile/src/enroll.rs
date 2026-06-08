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
use ndn_app::{Connection, Consumer, EngineAppExt};
use ndn_cert::EnrollmentSession;
use ndn_custodian::{Custodian, CustodianSigner, KeyId};
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
///
/// The key's **provenance** determines whether it can be persisted as a
/// [`SafeBag`]: a *software* key ([`enroll_pin`](MobileEngine::enroll_pin)) holds
/// exportable private-key material; a *custodian* key
/// ([`enroll_pin_custodian`](MobileEngine::enroll_pin_custodian) — the device
/// enclave / a remote fob) never exposes its private key, so [`to_safebag`] is
/// unavailable and persistence is the custodian's job.
///
/// [`to_safebag`]: Self::to_safebag
pub struct EnrolledIdentity {
    signer: Arc<dyn Signer>,
    key_name: Name,
    cert_name: Name,
    certificate: Option<Bytes>,
    /// Exportable private key — `Some` for a software key (SafeBag-able),
    /// `None` for a custodian/enclave-held key.
    exportable: Option<Arc<EcdsaP256Signer>>,
}

impl EnrolledIdentity {
    /// Wrap an already-certified **custodian-held** key (e.g. an enclave key
    /// loaded at startup with its stored certificate) as an enrolled identity.
    /// `signer` must route through the custodian (a
    /// [`CustodianSigner`](ndn_custodian::CustodianSigner)). Not SafeBag-exportable.
    pub fn from_custodian(
        signer: Arc<dyn Signer>,
        key_name: Name,
        cert_name: Name,
        certificate: Option<Bytes>,
    ) -> Self {
        Self {
            signer,
            key_name,
            cert_name,
            certificate,
            exportable: None,
        }
    }

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
    /// ready to sign subscriptions / management commands. For a custodian key
    /// this signs *through* the custodian (enclave biometric per use).
    pub fn signer(&self) -> Arc<dyn Signer> {
        self.signer.clone()
    }

    /// Whether the private key can be exported (software provenance). `false` for
    /// a custodian/enclave-held key, whose key never leaves the device.
    pub fn is_exportable(&self) -> bool {
        self.exportable.is_some()
    }

    /// Encrypt the private key + issued certificate into a password-protected
    /// [`SafeBag`] for on-device persistence (`ndnsec import`-compatible).
    /// Errors with [`EnrollError::NotExportable`] for a custodian/enclave key
    /// (its private key can't leave the device), and
    /// [`EnrollError::NoCertificate`] if the issued cert wasn't fetched.
    pub fn to_safebag(&self, password: &[u8]) -> Result<SafeBag, EnrollError> {
        let exportable = self.exportable.as_ref().ok_or(EnrollError::NotExportable)?;
        let cert = self.certificate.clone().ok_or(EnrollError::NoCertificate)?;
        let pkcs8 = exportable
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
    #[error("custodian/enclave key is not exportable to a SafeBag")]
    NotExportable,
    #[error("SafeBag: {0}")]
    SafeBag(String),
}

async fn sign_interest(
    builder: InterestBuilder,
    key_name: &Name,
    signer: &Arc<dyn Signer>,
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
        let key_name: Name = cfg.identity.clone().append("KEY").append_version(ts_ms);
        let ecdsa = Arc::new(
            EcdsaP256Signer::generate(key_name.clone())
                .map_err(|e| EnrollError::Key(e.to_string()))?,
        );
        let signer: Arc<dyn Signer> = ecdsa.clone();

        let (cert_name, certificate) = self.run_ndncert(&cfg, &key_name, &signer, pin_cb).await?;

        // Re-stamp the issued cert name on a fresh software signer (`with_cert_name`
        // consumes self, and the original is shared with the session).
        let stamped = Arc::new(
            EcdsaP256Signer::from_pkcs8_der(
                &ecdsa
                    .to_pkcs8_der()
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
                key_name.clone(),
            )
            .map_err(|e| EnrollError::Key(e.to_string()))?
            .with_cert_name(cert_name.clone()),
        );

        Ok(EnrolledIdentity {
            signer: stamped.clone(),
            key_name,
            cert_name,
            certificate,
            exportable: Some(stamped),
        })
    }

    /// Run NDNCERT 0.3 enrollment using the **`token`** challenge — a one-round
    /// exchange where an invitation token is the proof (the "scan an invitation"
    /// flow). Mirrors [`enroll_pin`](Self::enroll_pin) but needs no interactive
    /// callback. A route toward the CA prefix must already be installed.
    pub async fn enroll_token(
        &self,
        cfg: EnrollConfig,
        token: String,
    ) -> Result<EnrolledIdentity, EnrollError> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let key_name: Name = cfg.identity.clone().append("KEY").append_version(ts_ms);
        let ecdsa = Arc::new(
            EcdsaP256Signer::generate(key_name.clone())
                .map_err(|e| EnrollError::Key(e.to_string()))?,
        );
        let signer: Arc<dyn Signer> = ecdsa.clone();

        let (cert_name, certificate) =
            self.run_ndncert_token(&cfg, &key_name, &signer, &token).await?;

        // Re-stamp the issued cert name on a fresh software signer (as enroll_pin).
        let stamped = Arc::new(
            EcdsaP256Signer::from_pkcs8_der(
                &ecdsa
                    .to_pkcs8_der()
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
                key_name.clone(),
            )
            .map_err(|e| EnrollError::Key(e.to_string()))?
            .with_cert_name(cert_name.clone()),
        );

        Ok(EnrolledIdentity {
            signer: stamped.clone(),
            key_name,
            cert_name,
            certificate,
            exportable: Some(stamped),
        })
    }

    /// Generate a **self-signed** local identity for `name` — a fresh device key
    /// with no CA. The key self-signs its own certificate; the result is
    /// persistable as a SafeBag exactly like an enrolled identity. Intended for a
    /// blank device that will then be *sponsored* (a principal delegates a scope
    /// to this name). Associated fn — needs no engine/network.
    pub async fn generate_identity(
        name: Name,
        validity_secs: u64,
    ) -> Result<EnrolledIdentity, EnrollError> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let key_name: Name = name.append("KEY").append_version(ts_ms);
        let ecdsa = Arc::new(
            EcdsaP256Signer::generate(key_name.clone())
                .map_err(|e| EnrollError::Key(e.to_string()))?,
        );
        let pubkey = ecdsa
            .public_key()
            .ok_or_else(|| EnrollError::Key("generated key has no public key".into()))?;

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let until_ns = now_ns.saturating_add(validity_secs.saturating_mul(1_000_000_000));
        let cert_name = key_name.clone().append("self").append_version(0);
        let cert_wire =
            ndn_security::encode_cert_data(&cert_name, &pubkey, ecdsa.as_ref(), now_ns, until_ns)
                .await
                .map_err(|e| EnrollError::Cert(e.to_string()))?;

        let stamped = Arc::new(
            EcdsaP256Signer::from_pkcs8_der(
                &ecdsa
                    .to_pkcs8_der()
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
                key_name.clone(),
            )
            .map_err(|e| EnrollError::Key(e.to_string()))?
            .with_cert_name(cert_name.clone()),
        );
        Ok(EnrolledIdentity {
            signer: stamped.clone(),
            key_name,
            cert_name,
            certificate: Some(cert_wire),
            exportable: Some(stamped),
        })
    }

    /// NDNCERT NEW → CHALLENGE(`token`) → best-effort cert-fetch. The token is
    /// submitted in a single challenge round (it is the proof). Structurally
    /// mirrors [`run_ndncert`](Self::run_ndncert)'s pin path.
    async fn run_ndncert_token(
        &self,
        cfg: &EnrollConfig,
        key_name: &Name,
        signer: &Arc<dyn Signer>,
        token: &str,
    ) -> Result<(Name, Option<Bytes>), EnrollError> {
        // A standalone token bounds the enrollment app face; the face also
        // self-cleans when `consumer` is dropped at the end of the call.
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut consumer = self.engine().app_consumer(cancel.child_token());
        run_ndncert_token_on(&mut consumer, cfg, key_name, signer, token).await
    }
}

/// The NDNCERT NEW → CHALLENGE(`token`) → best-effort cert-fetch exchange over an
/// arbitrary [`Consumer`] — the connection-generic core of
/// [`MobileEngine::run_ndncert_token`]. Lets the same enrollment run over an
/// embedded engine's in-proc face *or* a cross-process forwarder connection.
async fn run_ndncert_token_on(
    consumer: &mut Consumer,
    cfg: &EnrollConfig,
    key_name: &Name,
    signer: &Arc<dyn Signer>,
    token: &str,
) -> Result<(Name, Option<Bytes>), EnrollError> {
    let mut session = EnrollmentSession::new(key_name.clone(), signer.clone(), cfg.validity_secs);

    {
        // Step 1: NEW
        let new_params = session
            .new_request_body()
            .await
            .map_err(|e| EnrollError::Cert(e.to_string()))?;
        let new_name = cfg.ca_prefix.clone().append("CA").append("NEW");
        let new_wire = sign_interest(
            InterestBuilder::new(new_name).app_parameters(new_params),
            key_name,
            signer,
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

        // Step 2: CHALLENGE("token", {token}) — one round; the token is the proof.
        let challenge_name = cfg
            .ca_prefix
            .clone()
            .append("CA")
            .append("CHALLENGE")
            .append(&request_id_bytes);
        let mut params = serde_json::Map::new();
        params.insert(
            "token".to_string(),
            serde_json::Value::String(token.to_string()),
        );
        let challenge_params = session
            .challenge_request_body("token", params)
            .map_err(|e| EnrollError::Cert(e.to_string()))?;
        let challenge_wire = sign_interest(
            InterestBuilder::new(challenge_name).app_parameters(challenge_params),
            key_name,
            signer,
        )
        .await?;
        let challenge_data = consumer
            .fetch_wire(challenge_wire, INTEREST_LIFETIME + Duration::from_millis(500))
            .await
            .map_err(|e| EnrollError::Fetch(format!("CHALLENGE token: {e}")))?;
        session
            .handle_challenge_response(challenge_data.content().ok_or(EnrollError::EmptyResponse)?)
            .map_err(|e| EnrollError::Cert(e.to_string()))?;

        if !session.is_complete() {
            return Err(EnrollError::Incomplete);
        }

        let cert_name = session
            .issued_cert_name()
            .ok_or_else(|| EnrollError::Cert("no issued cert name".into()))?
            .clone();

        // Step 3 (best-effort): fetch the issued cert (served by a repo).
        let certificate = match consumer.fetch(cert_name.clone()).await {
            // The fetched Data IS the cert; embed its full wire (Data TLV 0x06)
            // so the SafeBag round-trips — not its Content (the SPKI key, 0x30).
            Ok(data) => Some(data.raw().clone()),
            Err(e) => {
                tracing::debug!(error = %e, "issued cert fetch skipped (no repo)");
                None
            }
        };

        Ok((cert_name, certificate))
    }
}

/// Run NDNCERT 0.3 token-challenge enrollment for `cfg.identity` over an
/// arbitrary forwarder [`Connection`] — the connection-generic twin of
/// [`MobileEngine::enroll_token`]. Used by the FFI layer so identity enrollment
/// runs over either an embedded engine's in-proc face or a cross-process
/// socketpair connection. A route toward the CA prefix must already exist.
pub async fn enroll_token_conn(
    conn: Arc<dyn Connection>,
    cfg: EnrollConfig,
    token: String,
) -> Result<EnrolledIdentity, EnrollError> {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let key_name: Name = cfg.identity.clone().append("KEY").append_version(ts_ms);
    let ecdsa = Arc::new(
        EcdsaP256Signer::generate(key_name.clone()).map_err(|e| EnrollError::Key(e.to_string()))?,
    );
    let signer: Arc<dyn Signer> = ecdsa.clone();

    let mut consumer = Consumer::new(conn);
    let (cert_name, certificate) =
        run_ndncert_token_on(&mut consumer, &cfg, &key_name, &signer, &token).await?;

    // Re-stamp the issued cert name on a fresh software signer (as enroll_token).
    let stamped = Arc::new(
        EcdsaP256Signer::from_pkcs8_der(
            &ecdsa
                .to_pkcs8_der()
                .map_err(|e| EnrollError::Key(e.to_string()))?,
            key_name.clone(),
        )
        .map_err(|e| EnrollError::Key(e.to_string()))?
        .with_cert_name(cert_name.clone()),
    );

    Ok(EnrolledIdentity {
        signer: stamped.clone(),
        key_name,
        cert_name,
        certificate,
        exportable: Some(stamped),
    })
}

/// As [`enroll_token_conn`], but for a **custodian/enclave-held** key over an
/// arbitrary [`Connection`] — the connection-generic twin of
/// [`MobileEngine::enroll_token_custodian`]. The private key never leaves the
/// custodian and the result is **not** SafeBag-exportable.
pub async fn enroll_token_custodian_conn(
    conn: Arc<dyn Connection>,
    cfg: EnrollConfig,
    custodian: Arc<dyn Custodian>,
    key_id: KeyId,
    public_key: Bytes,
    token: String,
) -> Result<EnrolledIdentity, EnrollError> {
    let key_name = key_id.as_name().clone();
    let make_signer = || {
        CustodianSigner::new(
            custodian.clone(),
            key_id.clone(),
            SignatureType::SignatureSha256WithEcdsa,
            Some(public_key.clone()),
        )
    };
    let signer: Arc<dyn Signer> = Arc::new(make_signer());

    let mut consumer = Consumer::new(conn);
    let (cert_name, certificate) =
        run_ndncert_token_on(&mut consumer, &cfg, &key_name, &signer, &token).await?;

    let stamped: Arc<dyn Signer> = Arc::new(make_signer().with_cert_name(cert_name.clone()));
    Ok(EnrolledIdentity {
        signer: stamped,
        key_name,
        cert_name,
        certificate,
        exportable: None,
    })
}

impl MobileEngine {
    /// Run NDNCERT 0.3 enrollment for `cfg.identity` using a key held by a
    /// [`Custodian`](ndn_custodian::Custodian) — the device enclave (StrongBox /
    /// Secure Enclave) or a remote fob. The custodian must already hold the key
    /// under `key_id` with the given ECDSA-P256 `public_key`. The private key
    /// never leaves the custodian — every enrollment signature is produced inside
    /// it (biometric per use) — and the result is **not** SafeBag-exportable.
    /// Wrap the result as an `ndn_identity::Identity` with
    /// `Identity::from_signer(.., enrolled.key_name().clone(), enrolled.signer())`.
    pub async fn enroll_pin_custodian<F, Fut>(
        &self,
        cfg: EnrollConfig,
        custodian: Arc<dyn Custodian>,
        key_id: KeyId,
        public_key: Bytes,
        pin_cb: F,
    ) -> Result<EnrolledIdentity, EnrollError>
    where
        F: FnOnce(PinRequest) -> Fut,
        Fut: std::future::Future<Output = String>,
    {
        let key_name = key_id.as_name().clone();
        let make_signer = || {
            CustodianSigner::new(
                custodian.clone(),
                key_id.clone(),
                SignatureType::SignatureSha256WithEcdsa,
                Some(public_key.clone()),
            )
        };
        let signer: Arc<dyn Signer> = Arc::new(make_signer());

        let (cert_name, certificate) = self.run_ndncert(&cfg, &key_name, &signer, pin_cb).await?;

        let stamped: Arc<dyn Signer> = Arc::new(make_signer().with_cert_name(cert_name.clone()));
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate,
            exportable: None,
        })
    }

    /// As [`enroll_pin_custodian`](Self::enroll_pin_custodian), but via the
    /// **token** challenge — a hardware/enclave key certified by the CA after a
    /// one-round token challenge (no interactive PIN). Each NDNCERT request is
    /// signed by the custodian key, so the platform prompts for biometric per
    /// signature. Returns a non-exportable identity.
    pub async fn enroll_token_custodian(
        &self,
        cfg: EnrollConfig,
        custodian: Arc<dyn Custodian>,
        key_id: KeyId,
        public_key: Bytes,
        token: String,
    ) -> Result<EnrolledIdentity, EnrollError> {
        let key_name = key_id.as_name().clone();
        let make_signer = || {
            CustodianSigner::new(
                custodian.clone(),
                key_id.clone(),
                SignatureType::SignatureSha256WithEcdsa,
                Some(public_key.clone()),
            )
        };
        let signer: Arc<dyn Signer> = Arc::new(make_signer());

        let (cert_name, certificate) =
            self.run_ndncert_token(&cfg, &key_name, &signer, &token).await?;

        let stamped: Arc<dyn Signer> = Arc::new(make_signer().with_cert_name(cert_name.clone()));
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate,
            exportable: None,
        })
    }

    /// The shared NDNCERT NEW → CHALLENGE(pin) → best-effort cert-fetch exchange,
    /// signing every request with `signer` (software or custodian). Returns the
    /// issued cert name and its wire (if a repo served it).
    async fn run_ndncert<F, Fut>(
        &self,
        cfg: &EnrollConfig,
        key_name: &Name,
        signer: &Arc<dyn Signer>,
        pin_cb: F,
    ) -> Result<(Name, Option<Bytes>), EnrollError>
    where
        F: FnOnce(PinRequest) -> Fut,
        Fut: std::future::Future<Output = String>,
    {
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
            key_name,
            signer,
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
            key_name,
            signer,
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
                key_name,
                signer,
            )
            .await?;
            let submit_data = consumer
                .fetch_wire(submit_wire, INTEREST_LIFETIME + Duration::from_millis(500))
                .await
                .map_err(|e| EnrollError::Fetch(format!("CHALLENGE submit: {e}")))?;
            session
                .handle_challenge_response(submit_data.content().ok_or(EnrollError::EmptyResponse)?)
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
            // The fetched Data IS the cert; embed its full wire (Data TLV 0x06)
            // so the SafeBag round-trips — not its Content (the SPKI key, 0x30).
            Ok(data) => Some(data.raw().clone()),
            Err(e) => {
                tracing::debug!(error = %e, "issued cert fetch skipped (no repo)");
                None
            }
        };

        Ok((cert_name, certificate))
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
        use ndn_safebag::SafeBagAlgorithm;
        use ndn_security::Ed25519Signer;

        let key_name = key_name.into();
        let pkcs8 = bag
            .decrypt_pkcs8(password)
            .map_err(|e| EnrollError::SafeBag(e.to_string()))?;
        // Dispatch on the key algorithm: enrolled identities are ECDSA-P256,
        // recovered operational keys are Ed25519 (the did:ndn key-state type).
        let alg = bag
            .algorithm(password)
            .map_err(|e| EnrollError::SafeBag(e.to_string()))?;
        let signer: Arc<dyn Signer> = match alg {
            SafeBagAlgorithm::Ed25519 => Arc::new(
                Ed25519Signer::from_pkcs8_der(&pkcs8, key_name)
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
            ),
            SafeBagAlgorithm::EcdsaP256 => Arc::new(
                EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name)
                    .map_err(|e| EnrollError::Key(e.to_string()))?,
            ),
            SafeBagAlgorithm::Other(oid) => {
                return Err(EnrollError::Key(format!("unsupported key algorithm {oid}")));
            }
        };
        Ok(signer)
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

    /// A custodian/enclave-held identity routes signing through the custodian but
    /// cannot be exported to a SafeBag — its private key never leaves the device.
    #[test]
    fn custodian_provenance_is_not_safebag_exportable() {
        let key_name: Name = "/ndn/mobile/enclave/KEY/v=1".parse().unwrap();
        // A stand-in signer; provenance (exportable = None) is what's under test.
        let signer: Arc<dyn Signer> =
            Arc::new(EcdsaP256Signer::from_seed(&[7u8; 32], key_name.clone()).unwrap());
        let cert = DataBuilder::new(key_name.clone(), b"cert-stub").build();
        let id = EnrolledIdentity::from_custodian(
            signer,
            key_name.clone(),
            key_name.clone(),
            Some(cert),
        );

        assert!(!id.is_exportable());
        assert!(matches!(
            id.to_safebag(b"pw"),
            Err(EnrollError::NotExportable)
        ));
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
