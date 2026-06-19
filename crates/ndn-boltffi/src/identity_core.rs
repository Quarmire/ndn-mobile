//! [`IdentityCore`] — the connection-generic identity + signing core shared by
//! [`NdnEngine`](crate::NdnEngine) (over its embedded engine's in-proc face) and
//! [`NdnClient`](crate::NdnClient) (over a cross-process forwarder connection).
//!
//! The phone holds the operator key and signs management commands / RemoteSigner
//! responses through it. Whether the forwarder is embedded in this process or
//! lives in a separate tunnel process, identity lives in the UI: every operation
//! that needs the network (enroll, the served RemoteSigner responder, remote
//! prefix announce) runs over the generic [`ndn_app::Connection`], so the same
//! code path serves both the Local (embedded) and Remote (socketpair) backends.
//!
//! This struct is intentionally **not** `#[export]`ed — it is delegated to from
//! the exported `NdnEngine` / `NdnClient` FFI methods.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_app::{Connection, Consumer, DemuxConnection};
use ndn_packet::Name;
use tokio::runtime::Runtime;

use crate::handlers::{NdnApprovalGate, NdnEnclaveBackend, NdnRecoverySigner};
use crate::types::{
    NdnActionClass, NdnContext, NdnDelegationScope, NdnEnrollConfig, NdnEnrolledIdentity, NdnError,
    NdnRecoveredIdentity,
};

/// The signing identity + trust state shared by both FFI backends. Holds the
/// loaded operator signer, the §7 scoped-signing policy, the adopted trust
/// contexts, the shared runtime, and a forwarder `Connection` (in-proc for the
/// embedded engine, IPC for the cross-process client).
pub(crate) struct IdentityCore {
    pub(crate) rt: Arc<Runtime>,
    /// The forwarder seam, wrapped in a [`DemuxConnection`] so the RemoteSigner
    /// responder and the (reflexive) announce can serve and fetch concurrently
    /// over it — a bare `Connection` has no demux and the two readers race. Held
    /// as `dyn Connection` for the `Consumer`-based methods; [`Self::demux`] is
    /// the same object, typed, for the serve side.
    pub(crate) conn: Arc<dyn Connection>,
    pub(crate) demux: Arc<DemuxConnection>,
    /// The loaded operator identity (signs management commands / RemoteSigner
    /// responses). Set by `load_identity`; used by `sign`.
    identity: Mutex<Option<Arc<dyn ndn_security::Signer>>>,
    /// The CA-issued certificate (Data wire) for the loaded identity, retained
    /// so the node can serve it to a gateway that fetches it reflexively while
    /// authorising a `/localhop` prefix registration. Distinct from the
    /// self-signed `principal_cert_wire()` — only this one chains to the CA's
    /// localhop anchor. `None` until a cert-bearing identity is loaded.
    cert_wire: Mutex<Option<bytes::Bytes>>,
    /// §7 scoped-signing grants consulted by `respond_to_sign_request` before
    /// the biometric gate.
    #[cfg(feature = "identity")]
    sign_policy: Mutex<ndn_security::custodian::ScopedSigningPolicy>,
    /// The participant's adopted trust contexts (§6 "contexts I'm in").
    // `Arc`, not `Mutex`: `Keyring` is interior-mutable (DashMap), and context-sync
    // (F18) needs to share the same keyring into a background `context_sync::run`
    // task so adopted contexts land where `build_validator` reads them.
    keyring: Arc<ndn_security::Keyring>,
    /// Trust anchors pinned for verifying fetched content (a peer's cert, or an
    /// operator/context root). Combined with the own self-cert when building the
    /// validator for [`Self::fetch_object_verified`].
    pinned_anchors: Mutex<Vec<ndn_security::Certificate>>,
}

impl IdentityCore {
    /// Build a core over `conn` (the forwarder seam) sharing runtime `rt`.
    pub(crate) fn new(rt: Arc<Runtime>, conn: Arc<dyn Connection>) -> Self {
        // `DemuxConnection::new` spawns its recv loop with `tokio::spawn`, which
        // needs an entered runtime — `IdentityCore::new` is called from plain
        // (non-async) constructors, so enter `rt` for the spawn.
        let demux = {
            let _guard = rt.enter();
            DemuxConnection::new(conn)
        };
        Self {
            rt,
            conn: demux.clone(),
            demux,
            identity: Mutex::new(None),
            cert_wire: Mutex::new(None),
            #[cfg(feature = "identity")]
            sign_policy: Mutex::new(ndn_security::custodian::ScopedSigningPolicy::new()),
            keyring: Arc::new(ndn_security::Keyring::new()),
            pinned_anchors: Mutex::new(Vec::new()),
        }
    }

    // ── Trust anchors + verified fetch (secure-by-default object reception) ──

    /// Pin a certificate (Data wire) as a trust anchor for verifying fetched
    /// content — a peer's cert, or an operator/context root. Verified fetches
    /// then accept objects signed by a key that chains to it.
    pub(crate) fn pin_trust_anchor(&self, cert_wire: Vec<u8>) -> Result<bool, NdnError> {
        let data = ndn_packet::Data::decode(Bytes::from(cert_wire))
            .map_err(|e| NdnError::engine(format!("trust anchor not a Data: {e}")))?;
        let cert = ndn_security::Certificate::decode(&data)
            .map_err(|e| NdnError::engine(format!("trust anchor not a certificate: {e}")))?;
        tracing::debug!(
            target: "ndn_boltffi::remote_signer",
            cert_name = %cert.name,
            pubkey_head = ?cert.public_key[..cert.public_key.len().min(8)].to_vec(),
            "pinned trust anchor"
        );
        self.pinned_anchors.lock().unwrap().push(cert);
        Ok(true)
    }

    /// A hierarchical [`Validator`](ndn_security::Validator) trusting this node's
    /// own self-cert (for content it published) plus every pinned anchor. The
    /// trust root for verified fetches.
    pub(crate) fn build_validator(&self) -> ndn_security::Validator {
        let v = ndn_security::Validator::new(ndn_security::TrustSchema::hierarchical());
        // Our ACTUAL signing cert — the one our Data's KeyLocator references (set
        // by generate_identity / enroll / load) — so content we published chains.
        // (Not a reconstruction: a fabricated self-cert wouldn't match KeyLocator
        // and the chain wouldn't resolve.)
        if let Some(cert_wire) = self.cert_wire.lock().unwrap().clone()
            && let Ok(data) = ndn_packet::Data::decode(cert_wire)
            && let Ok(cert) = ndn_security::Certificate::decode(&data)
        {
            // add_trust_anchor (not just cert_cache.insert): the cert must be a
            // recognized ROOT, else the hierarchical walk never finds an anchor
            // and returns Pending ("certificate chain not resolved").
            v.add_trust_anchor(cert);
        }
        for cert in self.pinned_anchors.lock().unwrap().iter() {
            v.add_trust_anchor(cert.clone());
        }
        // F20 (NDF D-45): verify via held context. Seed the validator with every
        // adopted trust context (joined via `join_context` / context-sync), so a
        // peer's content named under a context we hold verifies against that
        // context's anchors + schema — no per-transfer `pin_trust_anchor` (TOFU).
        // Validation dispatches per-namespace (longest-prefix `context_for`), with
        // the own-cert + pinned anchors above as the ambient fallback. TOFU pinning
        // stays available as the bootstrap, not the steady state.
        for ctx in self.keyring.contexts() {
            v.adopt_context(ctx);
        }
        v
    }

    // ── Trust contexts (§6: the participant's memberships) ─────────────────

    pub(crate) fn join_context(
        &self,
        context_wire: Vec<u8>,
        version: u64,
    ) -> Result<NdnContext, NdnError> {
        let ctx = ndn_security::SignedTrustContext::decode_content(&context_wire, version)
            .map_err(|e| NdnError::Engine {
                msg: format!("malformed trust context: {e}"),
            })?;
        let ns = ctx.namespace().clone();
        self.keyring.adopt(Arc::new(ctx));
        Ok(NdnContext::from_ctx(&self.keyring.context_for(&ns)))
    }

    pub(crate) fn list_contexts(&self) -> Vec<NdnContext> {
        self.keyring
            .contexts()
            .iter()
            .map(|c| NdnContext::from_ctx(c))
            .collect()
    }

    pub(crate) fn forget_context(&self, namespace: String) -> Result<bool, NdnError> {
        let ns: Name = namespace
            .parse()
            .map_err(|_| NdnError::invalid_name(&namespace))?;
        Ok(self.keyring.forget(&ns))
    }

    // ── Named objects (RDR: whole-object publish / fetch) ──────────────────

    /// The loaded operator signer, if any — used to sign published objects so
    /// fetched content is authentic (else `DigestSha256`, integrity only).
    pub(crate) fn current_signer(&self) -> Option<Arc<dyn ndn_security::Signer>> {
        self.identity.lock().unwrap().clone()
    }

    /// Make this node **keyless**: install a remote signer as the signing
    /// identity, so every signature round-trips to the RemoteSigner served at
    /// `prefix` (the device's Anchor). `cert_wire` is the signing node's
    /// certificate — both the source of the KeyLocator metadata and the cert this
    /// node serves (so peers verify what it produces). Replaces any loaded key.
    #[cfg(feature = "identity")]
    pub(crate) fn use_remote_signer(
        &self,
        prefix: String,
        cert_wire: Vec<u8>,
    ) -> Result<bool, NdnError> {
        let prefix: Name = prefix.parse().map_err(|_| NdnError::invalid_name(&prefix))?;
        let signer = crate::remote_signer_client::RemoteSignerClient::from_cert(
            self.demux.clone(),
            prefix,
            &cert_wire,
        )
        .map_err(|e| NdnError::engine(format!("remote signer setup: {e}")))?;
        *self.identity.lock().unwrap() = Some(Arc::new(signer));
        *self.cert_wire.lock().unwrap() = Some(Bytes::from(cert_wire));
        Ok(true)
    }

    /// RDR whole-object publish: slice `content` into `chunk_size`-byte segments
    /// under `<name>/v=<ver>`, register `name` with the forwarder, and serve the
    /// metadata + segment Interests until the connection closes (blocking — run
    /// on a worker thread). Signs with the operator key if one is loaded. Serves
    /// over the shared [`DemuxConnection`] so it coexists with this node's
    /// fetches and RemoteSigner responder on the one connection. Pairs with
    /// [`Consumer::fetch_object`](ndn_app::Consumer::fetch_object).
    pub(crate) fn publish_object(
        &self,
        name: String,
        content: Vec<u8>,
        chunk_size: usize,
    ) -> Result<bool, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let prepared = Arc::new(ndn_app::rdr::PreparedObject::build(
            parsed.clone(),
            Bytes::from(content),
            if chunk_size == 0 { 8192 } else { chunk_size },
        ));
        let signer = self.current_signer();
        self.rt
            .block_on(self.demux.serve(parsed, move |interest, responder| {
                let prepared = prepared.clone();
                let signer = signer.clone();
                async move {
                    if let Ok(Some(wire)) =
                        prepared.answer_interest(&interest.name, signer.as_deref()).await
                    {
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            }))
            .map(|()| true)
            .map_err(NdnError::engine)
    }

    /// Stand up a tap-to-share [`OfferBoard`](crate::offer::OfferBoard) for this
    /// node's discovery `node_id`: serve the offerer cert + a signed manifest
    /// over the shared connection, with each added file served as a signed RDR
    /// object under the loaded identity. Requires a loaded operator identity.
    #[cfg(feature = "identity")]
    pub(crate) fn start_offer_board(
        &self,
        node_id: String,
    ) -> Result<Arc<crate::offer::OfferBoard>, NdnError> {
        let signer = self.current_signer().ok_or_else(|| NdnError::Identity {
            msg: "no identity loaded — load one before sharing".into(),
        })?;
        let identity_prefix = self.loaded_identity()?.name().clone();
        let cert_wire = self.principal_cert_wire()?;
        crate::offer::OfferBoard::new(
            Arc::clone(&self.rt),
            Arc::clone(&self.demux),
            signer,
            cert_wire,
            &node_id,
            identity_prefix,
        )
    }

    // ── Operator identity + signing ────────────────────────────────────────

    pub(crate) fn load_identity(
        &self,
        safebag: Vec<u8>,
        password: Vec<u8>,
        key_name: String,
    ) -> Result<String, NdnError> {
        #[cfg(feature = "identity")]
        {
            let bag = ndn_security::safebag::SafeBag::decode(&safebag).map_err(NdnError::identity)?;
            let name: Name = key_name
                .parse()
                .map_err(|_| NdnError::invalid_name(key_name.clone()))?;
            let signer = ndn_mobile::MobileEngine::load_identity(&bag, &password, name)
                .map_err(NdnError::identity)?;
            // Retain the CA-issued cert (inside the bag) so we can serve it to a
            // gateway that fetches it reflexively during localhop registration.
            *self.cert_wire.lock().unwrap() = Some(bag.certificate.clone());
            *self.identity.lock().unwrap() = Some(signer);
            Ok(self.loaded_identity()?.did())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (safebag, password, key_name);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn has_identity(&self) -> bool {
        self.identity.lock().unwrap().is_some()
    }

    /// Install a signer as the loaded operator identity — used by `NdnEngine`'s
    /// engine-bound enroll variants (the PIN challenge) that produce a signer
    /// through the embedded engine rather than over the generic connection.
    #[cfg(feature = "identity")]
    pub(crate) fn set_identity(&self, signer: Arc<dyn ndn_security::Signer>) {
        *self.identity.lock().unwrap() = Some(signer);
    }

    pub(crate) fn sign(&self, region: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        let signer = self
            .identity
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;
        let sig = self
            .rt
            .block_on(signer.sign(&region))
            .map_err(|e| NdnError::Identity { msg: e.to_string() })?;
        Ok(sig.to_vec())
    }

    pub(crate) fn enroll_with_token(
        &self,
        config: NdnEnrollConfig,
        token: String,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let ca: Name = config
                .ca_prefix
                .parse()
                .map_err(|_| NdnError::invalid_name(config.ca_prefix.clone()))?;
            let identity: Name = config
                .identity
                .parse()
                .map_err(|_| NdnError::invalid_name(config.identity.clone()))?;
            let cfg = ndn_mobile::enroll::EnrollConfig::new(ca, identity)
                .validity_secs(config.validity_secs);

            // Connection-generic enrollment: NEW → CHALLENGE(token) over `self.conn`,
            // so it runs over the embedded engine *or* the socketpair seam.
            let conn = self.conn.clone();
            let enrolled = self
                .rt
                .block_on(ndn_mobile::enroll::enroll_token_conn(conn, cfg, token))
                .map_err(NdnError::identity)?;

            let bag = enrolled
                .to_safebag(&config.persist_password)
                .map_err(NdnError::identity)?;
            let result = NdnEnrolledIdentity {
                key_name: enrolled.key_name().to_string(),
                cert_name: enrolled.cert_name().to_string(),
                certificate: enrolled.certificate().map(|b| b.to_vec()),
                safebag: bag.encode().to_vec(),
            };
            *self.cert_wire.lock().unwrap() = enrolled.certificate().cloned();
            *self.identity.lock().unwrap() = Some(enrolled.signer());
            Ok(result)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (config, token);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn enroll_with_token_enclave(
        &self,
        config: NdnEnrollConfig,
        token: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::custodian::{Custodian, EnclaveCustodian, KeyId};

            let ca: Name = config
                .ca_prefix
                .parse()
                .map_err(|_| NdnError::invalid_name(config.ca_prefix.clone()))?;
            let identity: Name = config
                .identity
                .parse()
                .map_err(|_| NdnError::invalid_name(config.identity.clone()))?;
            let cfg = ndn_mobile::enroll::EnrollConfig::new(ca, identity.clone())
                .validity_secs(config.validity_secs);

            let backend: Arc<dyn ndn_security::custodian::EnclaveBackend> =
                Arc::new(CallbackEnclaveBackend { callback: enclave });
            if !backend.is_available() {
                return Err(NdnError::Identity {
                    msg: "enclave key not available (biometry / keystore)".into(),
                });
            }
            let pubkey = backend.public_key();
            let custodian: Arc<dyn Custodian> =
                Arc::new(EnclaveCustodian::new(backend, config.identity.clone()));

            let ts_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let key_name: Name = identity.append("KEY").append_version(ts_ms);
            let key_id = KeyId(key_name);

            // Connection-generic enrollment over `self.conn`.
            let conn = self.conn.clone();
            let enrolled = self
                .rt
                .block_on(ndn_mobile::enroll::enroll_token_custodian_conn(
                    conn, cfg, custodian, key_id, pubkey, token,
                ))
                .map_err(NdnError::identity)?;

            let result = NdnEnrolledIdentity {
                key_name: enrolled.key_name().to_string(),
                cert_name: enrolled.cert_name().to_string(),
                certificate: enrolled.certificate().map(|b| b.to_vec()),
                safebag: Vec::new(),
            };
            *self.cert_wire.lock().unwrap() = enrolled.certificate().cloned();
            *self.identity.lock().unwrap() = Some(enrolled.signer());
            Ok(result)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (config, token, enclave);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn generate_identity(
        &self,
        name: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let id_name: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
            const VALIDITY_SECS: u64 = 10 * 365 * 24 * 60 * 60;
            let generated = self
                .rt
                .block_on(ndn_mobile::MobileEngine::generate_identity(
                    id_name,
                    VALIDITY_SECS,
                ))
                .map_err(NdnError::identity)?;
            let bag = generated
                .to_safebag(&persist_password)
                .map_err(NdnError::identity)?;
            let result = NdnEnrolledIdentity {
                key_name: generated.key_name().to_string(),
                cert_name: generated.cert_name().to_string(),
                certificate: generated.certificate().map(|b| b.to_vec()),
                safebag: bag.encode().to_vec(),
            };
            *self.cert_wire.lock().unwrap() = generated.certificate().cloned();
            *self.identity.lock().unwrap() = Some(generated.signer());
            Ok(result)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (name, persist_password);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn generate_identity_enclave(
        &self,
        name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::custodian::{Custodian, CustodianSigner, EnclaveCustodian, KeyId};
            use ndn_packet::SignatureType;

            let id_name: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
            let backend: Arc<dyn ndn_security::custodian::EnclaveBackend> =
                Arc::new(CallbackEnclaveBackend { callback: enclave });
            if !backend.is_available() {
                return Err(NdnError::Identity {
                    msg: "enclave key not available (biometry / keystore)".into(),
                });
            }
            let pubkey = backend.public_key();
            if pubkey.is_empty() {
                return Err(NdnError::Identity {
                    msg: "enclave returned no public key".into(),
                });
            }
            let custodian: Arc<dyn Custodian> =
                Arc::new(EnclaveCustodian::new(backend, name.clone()));

            let ts_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let key_name: Name = id_name.append("KEY").append_version(ts_ms);
            let key_id = KeyId(key_name.clone());

            let signer = CustodianSigner::new(
                custodian.clone(),
                key_id.clone(),
                SignatureType::SignatureSha256WithEcdsa,
                Some(pubkey.clone()),
            );
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            const VALIDITY_SECS: u64 = 10 * 365 * 24 * 60 * 60;
            let until_ns = now_ns.saturating_add(VALIDITY_SECS.saturating_mul(1_000_000_000));
            let cert_name = key_name.clone().append("self").append_version(0);
            let cert_wire = self
                .rt
                .block_on(ndn_security::encode_cert_data(
                    &cert_name, &pubkey, &signer, now_ns, until_ns,
                ))
                .map_err(|e| NdnError::Identity {
                    msg: format!("enclave self-cert failed: {e}"),
                })?;

            let stamped: Arc<dyn ndn_security::Signer> = Arc::new(
                CustodianSigner::new(
                    custodian,
                    key_id,
                    SignatureType::SignatureSha256WithEcdsa,
                    Some(pubkey),
                )
                .with_cert_name(cert_name.clone()),
            );
            let result = NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: cert_name.to_string(),
                certificate: Some(cert_wire.to_vec()),
                safebag: Vec::new(),
            };
            *self.identity.lock().unwrap() = Some(stamped);
            Ok(result)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (name, enclave);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn load_identity_enclave(
        &self,
        key_name: String,
        cert_name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
    ) -> Result<bool, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::custodian::{Custodian, CustodianSigner, EnclaveCustodian, KeyId};
            use ndn_packet::SignatureType;

            let kname: Name = key_name
                .parse()
                .map_err(|_| NdnError::invalid_name(&key_name))?;
            let cname: Name = cert_name
                .parse()
                .map_err(|_| NdnError::invalid_name(&cert_name))?;
            let backend: Arc<dyn ndn_security::custodian::EnclaveBackend> =
                Arc::new(CallbackEnclaveBackend { callback: enclave });
            if !backend.is_available() {
                return Err(NdnError::Identity {
                    msg: "enclave key not available (biometry / keystore)".into(),
                });
            }
            let pubkey = backend.public_key();
            if pubkey.is_empty() {
                return Err(NdnError::Identity {
                    msg: "enclave returned no public key".into(),
                });
            }
            let custodian: Arc<dyn Custodian> =
                Arc::new(EnclaveCustodian::new(backend, key_name));
            let signer: Arc<dyn ndn_security::Signer> = Arc::new(
                CustodianSigner::new(
                    custodian,
                    KeyId(kname),
                    SignatureType::SignatureSha256WithEcdsa,
                    Some(pubkey),
                )
                .with_cert_name(cname),
            );
            *self.identity.lock().unwrap() = Some(signer);
            Ok(true)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (key_name, cert_name, enclave);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn respond_to_sign_request(
        &self,
        request: Vec<u8>,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::custodian::{Decision, WireSignRequest, WireSignResponse};
            let req = WireSignRequest::decode(&request)
                .map_err(|e| NdnError::Identity { msg: e.to_string() })?;
            let approved = match self
                .sign_policy
                .lock()
                .unwrap()
                .decide(&req.region, std::time::SystemTime::now())
            {
                Decision::AutoApprove => true,
                Decision::Prompt => gate.approve(signing_summary(&req.region)),
            };
            let response = if approved {
                let signer =
                    self.identity
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or_else(|| NdnError::Identity {
                            msg: "no identity loaded".into(),
                        })?;
                match self.rt.block_on(signer.sign(&req.region)) {
                    Ok(signature) => WireSignResponse::Approved {
                        req_id: req.req_id,
                        signature,
                    },
                    Err(_) => WireSignResponse::Denied { req_id: req.req_id },
                }
            } else {
                WireSignResponse::Denied { req_id: req.req_id }
            };
            Ok(response.encode().to_vec())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (request, gate);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    #[cfg(feature = "identity")]
    pub(crate) fn serve_remote_signer(
        &self,
        prefix: String,
        gate: Box<dyn NdnApprovalGate>,
    ) -> Result<bool, NdnError> {
        use ndn_security::custodian::{Decision, WireSignRequest, WireSignResponse};
        let name: Name = prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&prefix))?;
        let gate: Arc<dyn NdnApprovalGate> = gate.into();
        let identity = &self.identity;
        let sign_policy = &self.sign_policy;
        self.rt.block_on(async move {
            // Serve over the demux so this long-lived responder coexists with the
            // announce's concurrent fetch/reflexive-serve on the same connection
            // (a bare `Connection` would race the two readers). Works over the
            // embedded engine or the cross-process seam alike.
            self.demux
                .serve(name, move |interest, responder| {
                    let req_wire = interest.app_parameters().cloned();
                    let reply_name = (*interest.name).clone();
                    let gate = gate.clone();
                    async move {
                        let Some(req_wire) = req_wire else { return };
                        let Ok(req) = WireSignRequest::decode(&req_wire) else {
                            return;
                        };
                        // Decision (policy + biometric gate) runs in the serve
                        // loop; it's a fast lock for AutoApprove and user-paced
                        // for Prompt. Snapshot the signer here too.
                        let approved = {
                            let decision = sign_policy
                                .lock()
                                .unwrap()
                                .decide(&req.region, std::time::SystemTime::now());
                            match decision {
                                Decision::AutoApprove => true,
                                Decision::Prompt => gate.approve(signing_summary(&req.region)),
                            }
                        };
                        let signer = if approved {
                            identity.lock().unwrap().clone()
                        } else {
                            None
                        };
                        // Spawn the actual sign + respond so the serve loop
                        // dispatches the next request immediately. The reply
                        // crosses the seam, so awaiting it inline serializes the
                        // whole responder — pacing a big file at one signed
                        // segment per round-trip. Captures only owned values.
                        tokio::spawn(async move {
                            let response = match signer {
                                Some(signer) => match signer.sign(&req.region).await {
                                    Ok(signature) => WireSignResponse::Approved {
                                        req_id: req.req_id,
                                        signature,
                                    },
                                    Err(_) => WireSignResponse::Denied { req_id: req.req_id },
                                },
                                None => WireSignResponse::Denied { req_id: req.req_id },
                            };
                            responder.respond(reply_name, response.encode()).await.ok();
                        });
                    }
                })
                .await
                .map_err(NdnError::engine)?;
            Ok::<bool, NdnError>(true)
        })
    }

    #[cfg(feature = "identity")]
    pub(crate) fn announce_prefix(&self, prefix: String) -> Result<bool, NdnError> {
        use ndn_config::nfd_command::{module, verb};
        use ndn_config::{ControlParameters, ControlResponse};
        use ndn_packet::NameComponent;
        use ndn_packet::encode::InterestBuilder;

        let prefix_name: Name = prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&prefix))?;
        let signer = self
            .identity
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;

        let params = ControlParameters {
            name: Some(prefix_name),
            ..Default::default()
        };
        let cmd_name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhop")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::copy_from_slice(module::RIB)),
            NameComponent::generic(Bytes::copy_from_slice(verb::REGISTER)),
            NameComponent::generic(params.encode()),
        ]);

        let sig_type = signer.sig_type();
        let key_loc = signer.cert_name().or_else(|| Some(signer.key_name())).cloned();
        // The CA-issued cert to serve to the gateway over the reflexive reverse
        // path (so it validates the command against its localhop anchor without a
        // FIB cert-fetch). `None` for a self-signed/recovered identity — the pull
        // then returns empty and the gateway falls back to its FIB fetcher.
        let cert_wire = self.cert_wire.lock().unwrap().clone();

        self.rt.block_on(async move {
            use ndn_packet::encode::{DataBuilder, random_reflexive_name};
            let signer_for_sign = signer.clone();
            // Remote registration is a 2-hop round trip: this leaf → gateway, and
            // the gateway validates the signed command before answering — which
            // for a `/localhop` register means chaining the requester's cert to
            // its localhop anchor. Rather than have the gateway fetch our cert via
            // its FIB (which routes our identity prefix at the CA, not us — a slow
            // timeout), we carry a single-use reflexive name `R`: each on-path
            // forwarder installs a reverse route `R -> incoming face`, and the
            // gateway pulls our cert under `R` straight back to us (RICE §8 /
            // draft-oran-icnrg-reflexive-forwarding). The lifetime still bounds
            // the whole exchange so the ControlResponse returns over the PIT path.
            const ANNOUNCE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10);
            let reflexive = random_reflexive_name();
            let wire = InterestBuilder::new(cmd_name)
                .must_be_fresh()
                .lifetime(ANNOUNCE_LIFETIME)
                .reflexive_name(reflexive.clone())
                .sign_fallible(sig_type, key_loc.as_ref(), |region: &[u8]| {
                    let region = Bytes::copy_from_slice(region);
                    async move {
                        signer_for_sign
                            .sign(&region)
                            .await
                            .map_err(|e| NdnError::Identity { msg: e.to_string() })
                    }
                })
                .await?;
            // Serve the gateway's reverse pull(s) under `R` with our certificate
            // for the duration of this announce. The demux routes `R/<…>`
            // Interests to this handler (so they don't race the responder or this
            // fetch), and the guard unregisters `R` when the announce returns.
            let _serve = self.demux.serve_scoped(reflexive, move |reverse, responder| {
                // Answer the reverse pull (named under `R`) with our CA-issued
                // cert as the content.
                let body = cert_wire.clone().unwrap_or_default();
                let name = (*reverse.name).clone();
                async move {
                    let _ = responder
                        .respond_bytes(DataBuilder::new(name, &body).build())
                        .await;
                }
            });
            // Issue the command. Wait a touch longer than the Interest lifetime so
            // the consumer doesn't give up before the PIT-bounded window closes.
            let mut consumer = Consumer::new(self.conn.clone());
            let data = consumer
                .fetch_wire(wire, ANNOUNCE_LIFETIME + std::time::Duration::from_secs(1))
                .await
                .map_err(|e| NdnError::engine(format!("announce: no ControlResponse: {e}")))?;
            let resp = ControlResponse::decode(data.content().cloned().unwrap_or_default())
                .map_err(|e| NdnError::engine(format!("announce: bad ControlResponse: {e:?}")))?;
            Ok((200..300).contains(&resp.status_code))
        })
    }

    pub(crate) fn grant_signing_scope(
        &self,
        action: NdnActionClass,
        ttl_secs: u64,
    ) -> Result<u32, NdnError> {
        #[cfg(feature = "identity")]
        {
            const MAX_TTL_SECS: u64 = 24 * 60 * 60;
            let ttl = ttl_secs.clamp(1, MAX_TTL_SECS);
            let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(ttl);
            self.sign_policy
                .lock()
                .unwrap()
                .grant(ndn_security::custodian::ScopedGrant {
                    expires_at,
                    action_filter: action_filter(action),
                });
            Ok(self.active_signing_scopes())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (action, ttl_secs);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn principal_did(&self) -> Result<String, NdnError> {
        #[cfg(feature = "identity")]
        {
            Ok(self.loaded_identity()?.did())
        }
        #[cfg(not(feature = "identity"))]
        {
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn principal_name(&self) -> Result<String, NdnError> {
        #[cfg(feature = "identity")]
        {
            Ok(self.loaded_identity()?.name().to_string())
        }
        #[cfg(not(feature = "identity"))]
        {
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn principal_public_key(&self) -> Result<Vec<u8>, NdnError> {
        let signer = self
            .identity
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;
        signer
            .public_key()
            .map(|b| b.to_vec())
            .ok_or_else(|| NdnError::Identity {
                msg: "loaded identity has no exportable public key".into(),
            })
    }

    #[cfg(feature = "identity")]
    pub(crate) fn principal_cert_wire(&self) -> Result<Vec<u8>, NdnError> {
        // Prefer the ACTUAL signing cert (set on load/generate/enroll) — its name
        // is what our Data's KeyLocator references, so a peer that pins it can
        // resolve our signatures. Re-encoding a fresh self-cert below would name
        // it `<key>/self/v=0`, which does NOT match the key-name KeyLocator
        // sign_with_sync writes → the peer's chain stays unresolved.
        if let Some(cert_wire) = self.cert_wire.lock().unwrap().clone() {
            return Ok(cert_wire.to_vec());
        }
        let signer = self
            .identity
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;
        let pubkey = signer.public_key().ok_or_else(|| NdnError::Identity {
            msg: "loaded identity has no exportable public key".into(),
        })?;
        let cert_name = signer.cert_name().cloned().unwrap_or_else(|| {
            signer.key_name().clone().append("self").append_version(0)
        });
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        const VALIDITY_SECS: u64 = 10 * 365 * 24 * 60 * 60;
        let until_ns = now_ns.saturating_add(VALIDITY_SECS.saturating_mul(1_000_000_000));
        let cert_wire = self
            .rt
            .block_on(ndn_security::encode_cert_data(
                &cert_name, &pubkey, &*signer, now_ns, until_ns,
            ))
            .map_err(|e| NdnError::Identity {
                msg: format!("encode operator cert: {e}"),
            })?;
        Ok(cert_wire.to_vec())
    }

    pub(crate) fn recovery_public_key(
        &self,
        recovery_seed: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        let seed: [u8; 32] = recovery_seed
            .as_slice()
            .try_into()
            .map_err(|_| NdnError::Identity {
                msg: format!(
                    "recovery seed must be 32 bytes (Ed25519), got {}",
                    recovery_seed.len()
                ),
            })?;
        let signer = ndn_security::Ed25519Signer::from_seed(
            &seed,
            "/recovery/KEY/r".parse().expect("static recovery key name"),
        );
        Ok(signer.public_key_bytes().to_vec())
    }

    pub(crate) fn add_device(
        &self,
        device: String,
        scope: NdnDelegationScope,
    ) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::trust_schema::NamePattern;
            let device_name: Name =
                device.parse().map_err(|_| NdnError::invalid_name(&device))?;
            let mut sign = Vec::with_capacity(scope.sign_patterns.len());
            for p in &scope.sign_patterns {
                sign.push(NamePattern::parse(p).map_err(|e| NdnError::Identity {
                    msg: format!("invalid sign pattern '{p}': {e:?}"),
                })?);
            }
            let capset = ndn_identity::CapabilitySet {
                sign,
                unwrap_for: scope.unwrap_for,
                enroll: scope.enroll,
                mgmt: scope.mgmt,
            };
            let deleg = self
                .loaded_identity()?
                .issue_delegation(device_name, capset)
                .map_err(NdnError::identity)?;
            Ok(deleg.encode().to_vec())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (device, scope);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn verify_delegation(
        &self,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<NdnDelegationScope, NdnError> {
        #[cfg(feature = "identity")]
        {
            let deleg =
                ndn_identity::SignedDelegation::decode(&delegation_wire).map_err(|e| {
                    NdnError::Identity {
                        msg: format!("malformed delegation: {e:?}"),
                    }
                })?;
            let scope = self
                .rt
                .block_on(deleg.verify(&principal_pubkey))
                .map_err(|e| NdnError::Identity {
                    msg: format!("delegation did not verify: {e:?}"),
                })?;
            Ok(scope_to_ffi(&scope))
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (delegation_wire, principal_pubkey);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn sign_delegated(
        &self,
        region: Vec<u8>,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            let signer = self
                .identity
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| NdnError::Identity {
                    msg: "no device identity loaded".into(),
                })?;
            let deleg =
                ndn_identity::SignedDelegation::decode(&delegation_wire).map_err(|e| {
                    NdnError::Identity {
                        msg: format!("malformed delegation: {e:?}"),
                    }
                })?;
            let name = Name::decode_from_tlv(bytes::Bytes::copy_from_slice(&region)).map_err(
                |_| NdnError::Identity {
                    msg: "region has no leading Name to scope-check".into(),
                },
            )?;
            let ds = self
                .rt
                .block_on(ndn_identity::DelegatedSigner::from_delegation(
                    signer,
                    &deleg,
                    &principal_pubkey,
                ))
                .map_err(|e| NdnError::Identity {
                    msg: format!("delegation did not verify: {e:?}"),
                })?;
            let sig = self
                .rt
                .block_on(ds.sign(&name, &region))
                .map_err(NdnError::identity)?;
            Ok(sig.to_vec())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (region, delegation_wire, principal_pubkey);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn sign_delegated_named(
        &self,
        name: String,
        payload: Vec<u8>,
        delegation_wire: Vec<u8>,
        principal_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            let n: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
            let mut region = n.encode_to_tlv().to_vec();
            region.extend_from_slice(&payload);
            self.sign_delegated(region, delegation_wire, principal_pubkey)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (name, payload, delegation_wire, principal_pubkey);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn make_recoverable(
        &self,
        recovery_pubkey: Vec<u8>,
    ) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            let rk: [u8; 32] =
                recovery_pubkey
                    .as_slice()
                    .try_into()
                    .map_err(|_| NdnError::Identity {
                        msg: format!(
                            "recovery key must be 32 bytes (Ed25519), got {}",
                            recovery_pubkey.len()
                        ),
                    })?;
            let keychain = self.loaded_identity()?.into_keychain();
            let recoverable = ndn_identity::Identity::create(
                keychain,
                ndn_security::RecoveryCommitment::Key(rk),
            )
            .map_err(NdnError::identity)?;
            Ok(recoverable.export_recovery_bundle())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = recovery_pubkey;
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn restore_identity(
        &self,
        bundle: Vec<u8>,
        recovery_seed: Vec<u8>,
        identity_name: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnRecoveredIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let seed: [u8; 32] =
                recovery_seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| NdnError::Identity {
                        msg: format!(
                            "recovery seed must be 32 bytes (Ed25519), got {}",
                            recovery_seed.len()
                        ),
                    })?;
            let recovery_signer: Arc<dyn ndn_security::Signer> =
                Arc::new(ndn_security::Ed25519Signer::from_seed(
                    &seed,
                    "/recovery/KEY/r".parse().unwrap(),
                ));
            self.restore_with(&bundle, recovery_signer, &identity_name, &persist_password)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (bundle, recovery_seed, identity_name, persist_password);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn restore_identity_remote(
        &self,
        bundle: Vec<u8>,
        identity_name: String,
        persist_password: Vec<u8>,
        recovery_signer: Box<dyn NdnRecoverySigner>,
    ) -> Result<NdnRecoveredIdentity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let adapter: Arc<dyn ndn_security::Signer> = Arc::new(CallbackRecoverySigner {
                callback: recovery_signer,
                key_name: "/recovery/KEY/r".parse().unwrap(),
            });
            self.restore_with(&bundle, adapter, &identity_name, &persist_password)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (bundle, identity_name, persist_password, recovery_signer);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn revoke_identity(&self, reason: String) -> Result<Vec<u8>, NdnError> {
        #[cfg(feature = "identity")]
        {
            let keychain = self.loaded_identity()?.into_keychain();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| NdnError::Identity { msg: e.to_string() })?
                .as_millis() as u64;
            let rec = ndn_identity::RevocationRecord::self_revoke(&keychain, reason, now_ms)
                .map_err(NdnError::identity)?;
            Ok(rec.encode().to_vec())
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = reason;
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn verify_revocation(
        &self,
        record: Vec<u8>,
        signer_pubkey: Vec<u8>,
    ) -> Result<crate::types::NdnRevocation, NdnError> {
        #[cfg(feature = "identity")]
        {
            let rec =
                ndn_identity::RevocationRecord::decode(&record).map_err(|e| NdnError::Identity {
                    msg: format!("malformed revocation: {e:?}"),
                })?;
            self.rt
                .block_on(rec.verify(&signer_pubkey))
                .map_err(|e| NdnError::Identity {
                    msg: format!("revocation did not verify: {e:?}"),
                })?;
            Ok(crate::types::NdnRevocation {
                revoked: rec.revoked.to_string(),
                reason: rec.reason.clone(),
                revoked_at_ms: rec.revoked_at_ms,
                self_revocation: rec.is_self_revocation(),
            })
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (record, signer_pubkey);
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn stop_signing_scope(&self) {
        #[cfg(feature = "identity")]
        {
            self.sign_policy.lock().unwrap().clear();
        }
    }

    pub(crate) fn active_signing_scopes(&self) -> u32 {
        #[cfg(feature = "identity")]
        {
            self.sign_policy
                .lock()
                .unwrap()
                .active_grants(std::time::SystemTime::now()) as u32
        }
        #[cfg(not(feature = "identity"))]
        {
            0
        }
    }
}

#[cfg(feature = "identity")]
impl IdentityCore {
    /// The recovery seam shared by every restore variant: generate a fresh
    /// ECDSA-P256 operational key, self-sign its container cert, let
    /// `recovery_signer` authorize the recovery, persist + load the key.
    fn restore_with(
        &self,
        bundle: &[u8],
        recovery_signer: Arc<dyn ndn_security::Signer>,
        identity_name: &str,
        persist_password: &[u8],
    ) -> Result<NdnRecoveredIdentity, NdnError> {
        use ndn_security::{Ed25519Signer, KeyChain, SecurityManager, Signer};

        let id_name: Name = identity_name
            .parse()
            .map_err(|_| NdnError::invalid_name(identity_name))?;

        let mut key_id = [0u8; 8];
        getrandom::getrandom(&mut key_id).map_err(|e| NdnError::Identity {
            msg: format!("rng: {e}"),
        })?;
        let key_id_hex: String = key_id.iter().map(|b| format!("{b:02x}")).collect();
        let key_name: Name = format!("{identity_name}/KEY/{key_id_hex}")
            .parse()
            .map_err(|_| NdnError::Identity {
                msg: "could not build key name".into(),
            })?;
        let mut op_seed = [0u8; 32];
        getrandom::getrandom(&mut op_seed).map_err(|e| NdnError::Identity {
            msg: format!("rng: {e}"),
        })?;
        let op = Ed25519Signer::from_seed(&op_seed, key_name.clone());
        let pkcs8 =
            ndn_security::safebag::ed25519_seed_to_pkcs8(&op_seed).map_err(|e| NdnError::Identity {
                msg: format!("pkcs8: {e}"),
            })?;
        let pubkey = op.public_key().ok_or_else(|| NdnError::Identity {
            msg: "operational key exposes no public key".into(),
        })?;
        let op_arc: Arc<dyn Signer> = Arc::new(op);

        let cert_name: Name = format!("{key_name}/self/v=1")
            .parse()
            .map_err(|_| NdnError::Identity {
                msg: "could not build cert name".into(),
            })?;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| NdnError::Identity { msg: e.to_string() })?
            .as_nanos() as u64;
        const TEN_YEARS_NS: u64 = 10 * 365 * 24 * 3600 * 1_000_000_000;
        let cert_wire = self
            .rt
            .block_on(ndn_security::encode_cert_data(
                &cert_name,
                &pubkey,
                op_arc.as_ref(),
                now_ns,
                now_ns + TEN_YEARS_NS,
            ))
            .map_err(NdnError::identity)?;

        let mgr = Arc::new(SecurityManager::new());
        mgr.register_signer(key_name.clone(), op_arc.clone());
        let keychain = KeyChain::from_parts(mgr, id_name, key_name.clone());
        let recovered = self
            .rt
            .block_on(ndn_identity::Identity::recover_from_bundle(
                bundle,
                keychain,
                &[(0, recovery_signer.as_ref())],
            ))
            .map_err(NdnError::identity)?;

        let safebag = ndn_security::safebag::SafeBag::encrypt(cert_wire, &pkcs8, persist_password)
            .map_err(|e| NdnError::Identity {
                msg: format!("safebag: {e}"),
            })?;
        *self.identity.lock().unwrap() = Some(op_arc);

        Ok(NdnRecoveredIdentity {
            key_name: key_name.to_string(),
            cert_name: cert_name.to_string(),
            safebag: safebag.encode().to_vec(),
            bundle: recovered.export_recovery_bundle(),
        })
    }

    /// Wrap the loaded operator signer as an `Identity` principal.
    fn loaded_identity(&self) -> Result<ndn_identity::Identity, NdnError> {
        let signer = self
            .identity
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;
        let key_name = signer.key_name().clone();
        let id_name = identity_of_key(&key_name).ok_or_else(|| NdnError::Identity {
            msg: format!("key name {key_name} has no /KEY/ component"),
        })?;
        ndn_identity::Identity::from_signer(id_name, key_name, signer).map_err(NdnError::identity)
    }
}

/// Adapts an FFI [`NdnRecoverySigner`] callback to a `Signer` for the secure
/// restore path. Recovery signatures are Ed25519; only `sign_sync` is needed.
#[cfg(feature = "identity")]
struct CallbackRecoverySigner {
    callback: Box<dyn NdnRecoverySigner>,
    key_name: Name,
}

#[cfg(feature = "identity")]
impl ndn_security::Signer for CallbackRecoverySigner {
    fn sig_type(&self) -> ndn_packet::SignatureType {
        ndn_packet::SignatureType::SignatureEd25519
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(
        &'a self,
        region: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Bytes, ndn_security::TrustError>> + Send + 'a>,
    > {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, ndn_security::TrustError> {
        let sig = self.callback.sign(region.to_vec());
        if sig.is_empty() {
            return Err(ndn_security::TrustError::KeyStore(
                "recovery signer refused (empty signature)".into(),
            ));
        }
        Ok(Bytes::from(sig))
    }
}

/// Adapts the host's [`NdnEnclaveBackend`] FFI callback to the Rust
/// [`EnclaveBackend`](ndn_security::custodian::EnclaveBackend).
#[cfg(feature = "identity")]
struct CallbackEnclaveBackend {
    callback: Box<dyn NdnEnclaveBackend>,
}

#[cfg(feature = "identity")]
#[async_trait::async_trait]
impl ndn_security::custodian::EnclaveBackend for CallbackEnclaveBackend {
    fn public_key(&self) -> Bytes {
        Bytes::from(self.callback.public_key())
    }

    async fn sign(&self, region: &[u8]) -> Result<Bytes, ndn_security::custodian::CustodianError> {
        let sig = self.callback.sign(region.to_vec());
        if sig.is_empty() {
            Err(ndn_security::custodian::CustodianError::SignFailed(
                "enclave refused or unavailable".into(),
            ))
        } else {
            Ok(Bytes::from(sig))
        }
    }

    fn is_available(&self) -> bool {
        self.callback.is_available()
    }
}

/// Render a granted `CapabilitySet` as the FFI scope view.
#[cfg(feature = "identity")]
fn scope_to_ffi(scope: &ndn_identity::CapabilitySet) -> NdnDelegationScope {
    NdnDelegationScope {
        sign_patterns: scope.sign.iter().map(|p| p.to_string()).collect(),
        unwrap_for: scope.unwrap_for,
        enroll: scope.enroll,
        mgmt: scope.mgmt,
    }
}

/// Derive the identity name from a key name by dropping the `/KEY/<id>…` tail.
#[cfg(feature = "identity")]
fn identity_of_key(key_name: &Name) -> Option<Name> {
    let s = key_name.to_string();
    let (id, _) = s.split_once("/KEY/")?;
    id.parse::<Name>().ok()
}

/// Map the FFI action class to a scoped-signing filter (`Any` → no filter).
#[cfg(feature = "identity")]
fn action_filter(a: NdnActionClass) -> Option<ndn_security::custodian::ActionClass> {
    use ndn_security::custodian::ActionClass as A;
    match a {
        NdnActionClass::Any => None,
        NdnActionClass::Route => Some(A::Route),
        NdnActionClass::Face => Some(A::Face),
        NdnActionClass::Strategy => Some(A::Strategy),
        NdnActionClass::ContentStore => Some(A::ContentStore),
        NdnActionClass::Other => Some(A::Other),
    }
}

/// A spoof-proof one-line summary of what a RemoteSigner request would sign.
#[cfg(feature = "identity")]
fn signing_summary(region: &[u8]) -> String {
    match ndn_packet::Name::decode_from_tlv(bytes::Bytes::copy_from_slice(region)) {
        Ok(name) => format!("Authorize signing for {name}"),
        Err(_) => format!("Authorize signing {} bytes", region.len()),
    }
}
