//! NDNCERT 0.3 identity enrollment for the mobile engine, plus SafeBag
//! export/import for persistence across process restarts.
//!
//! [`MobileEngine::enroll_pin`] drives the standard NDNCERT exchange — NEW →
//! CHALLENGE (`pin`, trigger + submit) → best-effort cert fetch — over the
//! engine's in-process app consumer, via the shared [`ndn_cert::client::enroll`]
//! driver (the same one the `enroll-ndncert` tool runs). Interests for
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
use ndn_cert::{CaExchange, CertError, ChallengeRound};
use ndn_packet::{Data, Name, SignatureType};
use ndn_security::custodian::{Custodian, CustodianSigner, KeyId};
use ndn_security::safebag::SafeBag;
use ndn_security::{EcdsaP256Signer, Ed25519Signer, Signer};

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
    /// Exportable private key as PKCS#8 DER (algorithm-agnostic) — `Some` for a
    /// software key (SafeBag-able), `None` for a custodian/enclave-held key.
    exportable: Option<Vec<u8>>,
}

impl EnrolledIdentity {
    /// Wrap an already-certified **custodian-held** key (e.g. an enclave key
    /// loaded at startup with its stored certificate) as an enrolled identity.
    /// `signer` must route through the custodian (a
    /// [`CustodianSigner`](ndn_security::custodian::CustodianSigner)). Not SafeBag-exportable.
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
        let pkcs8 = self.exportable.as_ref().ok_or(EnrollError::NotExportable)?;
        let cert = self.certificate.clone().ok_or(EnrollError::NoCertificate)?;
        SafeBag::encrypt(cert, pkcs8, password).map_err(|e| EnrollError::SafeBag(e.to_string()))
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
    #[error("enrollment did not complete after PIN submission")]
    Incomplete,
    #[error("no issued cert was fetched; SafeBag needs the certificate")]
    NoCertificate,
    #[error("custodian/enclave key is not exportable to a SafeBag")]
    NotExportable,
    #[error("SafeBag: {0}")]
    SafeBag(String),
}

impl From<CertError> for EnrollError {
    fn from(e: CertError) -> Self {
        match e {
            CertError::Transport(m) => EnrollError::Fetch(m),
            CertError::Security(e) => EnrollError::Sign(e.to_string()),
            CertError::ChallengePending(_) => EnrollError::Incomplete,
            e => EnrollError::Cert(e.to_string()),
        }
    }
}

/// [`CaExchange`] over an app [`Consumer`] — an embedded engine's in-proc face
/// or a cross-process forwarder connection.
struct ConsumerExchange<'a>(&'a mut Consumer);

impl CaExchange for ConsumerExchange<'_> {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        self.0
            .fetch_wire(interest, INTEREST_LIFETIME + Duration::from_millis(500))
            .await
            .map_err(|e| CertError::Transport(e.to_string()))
    }
}

/// The NDNCERT exchange over an arbitrary [`Consumer`] — the connection-generic
/// core of every enrollment flow here: the shared NEW → CHALLENGE driver
/// signing with `signer`, then a best-effort fetch of the issued cert (served
/// by a repo). Returns the issued cert name and its wire, if fetched.
async fn run_ndncert_on<F, Fut>(
    consumer: &mut Consumer,
    cfg: &EnrollConfig,
    signer: &Arc<dyn Signer>,
    challenge_type: &str,
    respond: F,
) -> Result<(Name, Option<Bytes>), EnrollError>
where
    F: FnMut(ChallengeRound) -> Fut,
    Fut: Future<Output = Result<Option<serde_json::Map<String, serde_json::Value>>, CertError>>,
{
    let mut exchange = ConsumerExchange(consumer);
    let cert_name = ndn_cert::client::enroll(
        &mut exchange,
        &cfg.ca_prefix,
        signer.clone(),
        cfg.validity_secs,
        challenge_type,
        respond,
    )
    .await?;

    let certificate = match ndn_cert::client::fetch_issued_cert(&mut exchange, &cert_name).await {
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

/// NDNCERT `token` challenge: one round; the token is the proof.
async fn run_ndncert_token_on(
    consumer: &mut Consumer,
    cfg: &EnrollConfig,
    signer: &Arc<dyn Signer>,
    token: &str,
) -> Result<(Name, Option<Bytes>), EnrollError> {
    let mut params = serde_json::Map::new();
    params.insert(
        "token".to_string(),
        serde_json::Value::String(token.to_string()),
    );
    let mut params = Some(params);
    run_ndncert_on(consumer, cfg, signer, "token", |_| {
        std::future::ready(Ok(params.take()))
    })
    .await
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

        let (cert_name, certificate) = self.run_ndncert(&cfg, &signer, pin_cb).await?;

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

        let exportable = stamped.to_pkcs8_der().map_err(|e| EnrollError::Key(e.to_string()))?;
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate,
            exportable: Some(exportable),
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

        let (cert_name, certificate) = self.run_ndncert_token(&cfg, &signer, &token).await?;

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

        let exportable = stamped.to_pkcs8_der().map_err(|e| EnrollError::Key(e.to_string()))?;
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate,
            exportable: Some(exportable),
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
        // Ed25519 by default: ~7× faster sign+verify than ECDSA P-256, which is
        // the object-fetch throughput ceiling once the link is fast. The cert
        // path is algorithm-generic (`Signer::public_key` returns SPKI for both).
        let key = Arc::new(
            Ed25519Signer::generate(key_name.clone()).map_err(|e| EnrollError::Key(e.to_string()))?,
        );
        let pubkey = key
            .public_key()
            .ok_or_else(|| EnrollError::Key("generated key has no public key".into()))?;

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let until_ns = now_ns.saturating_add(validity_secs.saturating_mul(1_000_000_000));
        // The self-signed cert is named EXACTLY the key name (KeyChain convention)
        // so a verifier resolving the Data's KeyLocator finds it.
        let cert_name = key_name.clone();
        let cert_wire =
            ndn_security::encode_cert_data(&cert_name, &pubkey, key.as_ref(), now_ns, until_ns)
                .await
                .map_err(|e| EnrollError::Cert(e.to_string()))?;

        let pkcs8 = key.to_pkcs8_der().map_err(|e| EnrollError::Key(e.to_string()))?;
        let stamped: Arc<dyn Signer> = Arc::new(
            Ed25519Signer::from_pkcs8_der(&pkcs8, key_name.clone())
                .map_err(|e| EnrollError::Key(e.to_string()))?
                .with_cert_name(cert_name.clone()),
        );
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate: Some(cert_wire),
            exportable: Some(pkcs8),
        })
    }

    /// NDNCERT NEW → CHALLENGE(`token`) → best-effort cert-fetch over the
    /// engine's in-process app consumer.
    async fn run_ndncert_token(
        &self,
        cfg: &EnrollConfig,
        signer: &Arc<dyn Signer>,
        token: &str,
    ) -> Result<(Name, Option<Bytes>), EnrollError> {
        // A standalone token bounds the enrollment app face; the face also
        // self-cleans when `consumer` is dropped at the end of the call.
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut consumer = self.engine().app_consumer(cancel.child_token());
        run_ndncert_token_on(&mut consumer, cfg, signer, token).await
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
    let (cert_name, certificate) = run_ndncert_token_on(&mut consumer, &cfg, &signer, &token).await?;

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

    let exportable = stamped.to_pkcs8_der().map_err(|e| EnrollError::Key(e.to_string()))?;
    Ok(EnrolledIdentity {
        signer: stamped,
        key_name,
        cert_name,
        certificate,
        exportable: Some(exportable),
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
    let (cert_name, certificate) = run_ndncert_token_on(&mut consumer, &cfg, &signer, &token).await?;

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
    /// [`Custodian`](ndn_security::custodian::Custodian) — the device enclave (StrongBox /
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

        let (cert_name, certificate) = self.run_ndncert(&cfg, &signer, pin_cb).await?;

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

        let (cert_name, certificate) = self.run_ndncert_token(&cfg, &signer, &token).await?;

        let stamped: Arc<dyn Signer> = Arc::new(make_signer().with_cert_name(cert_name.clone()));
        Ok(EnrolledIdentity {
            signer: stamped,
            key_name,
            cert_name,
            certificate,
            exportable: None,
        })
    }

    /// NDNCERT NEW → CHALLENGE(`pin`: trigger round, then the code `pin_cb`
    /// returns) → best-effort cert-fetch over the engine's in-process app
    /// consumer, signing every request with `signer` (software or custodian).
    /// Some CAs auto-complete after the trigger round; `pin_cb` is then never
    /// called.
    async fn run_ndncert<F, Fut>(
        &self,
        cfg: &EnrollConfig,
        signer: &Arc<dyn Signer>,
        pin_cb: F,
    ) -> Result<(Name, Option<Bytes>), EnrollError>
    where
        F: FnOnce(PinRequest) -> Fut,
        Fut: Future<Output = String>,
    {
        // A standalone token bounds the enrollment app face; the face also
        // self-cleans when `consumer` is dropped at the end of the call.
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut consumer = self.engine().app_consumer(cancel.child_token());
        let mut pin_cb = Some(pin_cb);
        run_ndncert_on(&mut consumer, cfg, signer, "pin", |round| {
            // Round 0 is the trigger (select "pin", no code yet); round 1
            // submits the code; anything further is incomplete.
            let cb = if round.round == 1 { pin_cb.take() } else { None };
            async move {
                match (round.round, cb) {
                    (0, _) => Ok(Some(serde_json::Map::new())),
                    (_, Some(cb)) => {
                        let pin = cb(PinRequest {
                            request_id: round.request_id,
                            status_message: round.status_message,
                        })
                        .await;
                        let mut code = serde_json::Map::new();
                        code.insert("code".to_string(), serde_json::Value::String(pin));
                        Ok(Some(code))
                    }
                    (_, None) => Ok(None),
                }
            }
        })
        .await
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
        use ndn_security::safebag::SafeBagAlgorithm;
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
