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
    NdnActionClass, NdnCertValidity, NdnContext, NdnDelegationScope, NdnEnrollConfig,
    NdnEnrolledIdentity, NdnError, NdnRecoveredIdentity, NdnRenewal,
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
    /// The certificates of this core's identities, by key: the one each was
    /// installed with (CA-issued, renewed, or a self-issued identity's own
    /// self-certificate) and any fetched by key name that chains to an
    /// adopted trust context — never one minted for a key that was installed
    /// without one. The loaded identity's *current* certificate — the one
    /// its key-name KeyLocator resolves to, served to a gateway that fetches
    /// it reflexively while authorising a `/localhop` registration and
    /// returned by `principal_cert_wire()` — is the newest valid one
    /// recorded for its key ([`Self::current_cert`]).
    certs: ndn_security::CertCache,
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
            certs: ndn_security::CertCache::new(),
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
        if let Some(cert) = self.current_cert() {
            // add_trust_anchor (not just cert_cache.insert): the cert must be a
            // recognized ROOT, else the hierarchical walk never finds an anchor
            // and returns Pending ("certificate chain not resolved").
            v.add_trust_anchor(cert);
        }
        for cert in self.pinned_anchors.lock().unwrap().iter() {
            v.add_trust_anchor(cert.clone());
        }
        // F20 (NDF D-45): verify via held context. Seed the validator with every
        // adopted trust context (adopted via `adopt_context` / context-sync), so a
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

    /// Adopt a scanned anchor envelope's signed context — only if its
    /// signature verifies under the anchor `fingerprint` pins and it roots
    /// `namespace` (TOFU; `ndn_cert::adopt_with_tofu`). A mismatched pin, a
    /// tampered context, or an older version than the one held is an error.
    pub(crate) fn adopt_context(
        &self,
        context_data: Vec<u8>,
        namespace: String,
        fingerprint: Vec<u8>,
    ) -> Result<NdnContext, NdnError> {
        let ns: Name = namespace
            .parse()
            .map_err(|_| NdnError::invalid_name(&namespace))?;
        let fingerprint: [u8; 32] = fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| NdnError::engine("anchor fingerprint must be 32 bytes (SHA-256)"))?;
        let data = ndn_packet::Data::decode(Bytes::from(context_data))
            .map_err(|e| NdnError::engine(format!("malformed trust-context Data: {e}")))?;
        let ctx = ndn_cert::adopt_with_tofu(&self.keyring, &data, &ns, &fingerprint).map_err(
            |e| NdnError::Identity {
                msg: format!("trust context refused: {e}"),
            },
        )?;
        Ok(NdnContext::adopted(&ctx, &data, &fingerprint))
    }

    /// Adopt the namespace a scanned `ndn-trust://anchor` link names,
    /// the same way the `ndn-fwd` daemon does
    /// (`ndn_identity::adopt_anchor_link_via_engine`): an inline context is
    /// verified against the link's expected fingerprint; a fingerprint-only
    /// link fetches the context by name through `engine` — whose validator
    /// admits exactly the expected context meanwhile — and requires at least
    /// the version the link names. Blocking (network round trips). The
    /// result carries the signed context for the host to persist.
    #[cfg(feature = "identity")]
    pub(crate) fn adopt_context_link(
        &self,
        engine: &ndn_app::ForwarderEngine,
        link_uri: String,
    ) -> Result<NdnContext, NdnError> {
        let refused = |e: ndn_cert::AdoptError| NdnError::Identity {
            msg: format!("trust context refused: {e}"),
        };
        let link = ndn_cert::AnchorLink::from_uri(&link_uri).map_err(refused)?;
        let adopted = self
            .rt
            .block_on(ndn_identity::adopt_anchor_link_via_engine(
                engine,
                &self.keyring,
                &link,
            ))
            .map_err(refused)?;
        Ok(NdnContext::adopted(
            &adopted.context,
            &adopted.data,
            &link.expected_fingerprint,
        ))
    }

    /// Check each held trust context (only `namespace`, when given) for a
    /// newer version through `engine`, the way the `ndn-fwd` daemon does
    /// (`ndn_identity::refresh_context_via_engine`): the newest version's name
    /// by RDR metadata, then the signed context, adopted only if it is newer
    /// and signed by an anchor of the version held (continuity). A refused or
    /// failed check changes nothing. Blocking (network round trips).
    #[cfg(feature = "identity")]
    pub(crate) fn refresh_contexts(
        &self,
        engine: &ndn_app::ForwarderEngine,
        namespace: Option<String>,
    ) -> Result<Vec<crate::types::NdnContextRefresh>, NdnError> {
        use crate::types::NdnContextRefresh;
        use ndn_cert::ContextRefresh;

        let held = self.keyring.contexts();
        let targets = match namespace {
            Some(ns) => {
                let name: Name = ns.parse().map_err(|_| NdnError::invalid_name(&ns))?;
                let ctx = held
                    .into_iter()
                    .find(|c| *c.namespace() == name)
                    .ok_or_else(|| NdnError::Identity {
                        msg: format!("no trust context is held for {ns}; adopt it first"),
                    })?;
                vec![ctx]
            }
            None => held,
        };
        let mut results = Vec::with_capacity(targets.len());
        for ctx in targets {
            let ns = ctx.namespace().clone();
            let entry = |state: &str, version, revoked, detail, context| NdnContextRefresh {
                namespace: ns.to_string(),
                state: state.to_string(),
                held_version: ctx.version(),
                version,
                revoked,
                detail,
                context,
            };
            let outcome = self.rt.block_on(ndn_identity::refresh_context_via_engine(
                engine,
                &self.keyring,
                &ns,
            ));
            results.push(match outcome {
                Ok(ContextRefresh::Current { version }) => entry(
                    "current",
                    version,
                    Vec::new(),
                    format!("the namespace serves v{version}, the version held"),
                    None,
                ),
                Ok(ContextRefresh::UpstreamOlder { held, offered }) => entry(
                    "upstream-older",
                    held,
                    Vec::new(),
                    format!("what answered serves v{offered}, older than the held v{held}"),
                    None,
                ),
                Ok(ContextRefresh::Updated(update)) => {
                    let fingerprint = ndn_cert::anchor_fingerprint(&update.signer);
                    // A walk (`ndn_cert::follow_versions`) went through the
                    // versions in between; the signer is an anchor of the
                    // last of them.
                    let walked: Vec<String> = update
                        .walked
                        .iter()
                        .map(|s| format!("v{}", s.context.version()))
                        .collect();
                    let from = update
                        .walked
                        .last()
                        .map_or(update.previous, |s| s.context.version());
                    let through = if walked.is_empty() {
                        String::new()
                    } else {
                        format!(" (followed through {})", walked.join(", "))
                    };
                    entry(
                        "updated",
                        update.context.version(),
                        update.revoked.iter().map(Name::to_string).collect(),
                        format!(
                            "adopted v{} signed by {}, an anchor of v{from}{through}",
                            update.context.version(),
                            update.signer.name,
                        ),
                        Some(NdnContext::adopted(&update.context, &update.data, &fingerprint)),
                    )
                }
                Err(e) => entry("failed", ctx.version(), Vec::new(), e.to_string(), None),
            });
        }
        Ok(results)
    }

    /// Enroll this device with the CA an `ndn-trust://invite` link names, as
    /// `<ns>/<role>/<device>`, the same way the `ndn-fwd` daemon does
    /// (`ndn_identity::enroll_with_invite_via_engine`): adopt the
    /// namespace's trust context if it is not held (checked against the
    /// invite's root fingerprint), generate a fresh ECDSA-P256 key here,
    /// obtain a certificate for it with the invite's token and check its chain
    /// to the root. On success the identity is installed for signing and the
    /// result carries a password-encrypted SafeBag (key + issued certificate)
    /// and any trust context adopted on the way for the host to persist; a
    /// failure that adopted the context reports it in
    /// [`NdnError::EnrollmentFailed`]. Blocking (network round trips);
    /// `engine` needs a face and a route for the namespace.
    #[cfg(feature = "identity")]
    pub(crate) fn enroll_with_invite(
        &self,
        engine: &ndn_app::ForwarderEngine,
        invite_uri: String,
        device: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        use ndn_security::EcdsaP256Signer;

        let refused = |e: &dyn std::fmt::Display| NdnError::Identity {
            msg: format!("enrollment refused: {e}"),
        };
        let key_error = |e: &dyn std::fmt::Display| NdnError::Identity {
            msg: format!("device key: {e}"),
        };
        let invite = ndn_cert::InviteLink::from_uri(&invite_uri).map_err(|e| refused(&e))?;
        let identity = invite.device_identity(&device).map_err(|e| refused(&e))?;
        let key_name = ndn_cert::new_device_key_name(&identity);
        let key = EcdsaP256Signer::generate(key_name.clone()).map_err(|e| key_error(&e))?;
        let pkcs8 = key.to_pkcs8_der().map_err(|e| key_error(&e))?;
        let adopted_context = |adopted: &Option<ndn_cert::LinkAdoption>| {
            adopted.as_ref().zip(invite.expected_fingerprint.as_ref()).map(|(a, fp)| {
                NdnContext::adopted(&a.context, &a.data, fp)
            })
        };
        let enrollment = self
            .rt
            .block_on(ndn_identity::enroll_with_invite_via_engine(
                engine,
                &self.keyring,
                &invite,
                Arc::new(key),
            ))
            .map_err(|failure| NdnError::EnrollmentFailed {
                msg: format!("enrollment refused: {}", failure.error),
                adopted_context: adopted_context(&failure.adopted),
            })?;

        let cert_name = (*enrollment.issued.cert.name).clone();
        let cert_wire = enrollment.issued.data.raw().clone();
        let bag = ndn_security::safebag::SafeBag::encrypt(
            cert_wire.clone(),
            &pkcs8,
            &persist_password,
        )
        .map_err(|e| key_error(&e))?;
        // The KeyLocator names the key; verifiers resolve it to the newest
        // valid certificate (this one, a renewed one after renew_certificate).
        let signer = EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name.clone())
            .map_err(|e| key_error(&e))?;
        self.record_cert(&cert_wire);
        *self.identity.lock().unwrap() = Some(Arc::new(signer));
        Ok(NdnEnrolledIdentity {
            key_name: key_name.to_string(),
            cert_name: cert_name.to_string(),
            certificate: Some(cert_wire.to_vec()),
            safebag: bag.encode().to_vec(),
            adopted_context: adopted_context(&enrollment.adopted),
            issuers: enrollment.issued.issuers.iter().map(|d| d.raw().to_vec()).collect(),
        })
    }

    /// Renew the certificate in `safebag` at its namespace's CA (same key,
    /// proof of the current certificate, no invite). Renewed: the identity
    /// is loaded with the new certificate, and the outcome carries a new
    /// SafeBag (same key, same `password`) and the new certificate's issuer
    /// chain to persist. Otherwise the outcome says whether retrying can help
    /// ([`ndn_cert::RenewalError::is_final`]): `Refused` when it cannot,
    /// `Failed` when it can. `issuers` are the issuer certificates kept from
    /// the enrollment or earlier renewal (empty = none kept; undecodable
    /// entries are skipped): after a recovery the namespace's CA runs a later
    /// CA key and renews the certificate only with this chain. An `Err` is an
    /// unusable `safebag` or `password`, found before anything is sent.
    /// Blocking (network round trips).
    #[cfg(feature = "identity")]
    pub(crate) fn renew_certificate(
        &self,
        engine: &ndn_app::ForwarderEngine,
        safebag: Vec<u8>,
        password: Vec<u8>,
        issuers: Vec<Vec<u8>>,
    ) -> Result<NdnRenewal, NdnError> {
        use ndn_security::safebag::SafeBag;

        let unusable = |why: String| NdnError::Identity {
            msg: format!("renewal not attempted: {why}"),
        };
        let bag = SafeBag::decode(&safebag).map_err(|e| {
            unusable(format!(
                "the SafeBag cannot be read ({e}); pass the bag persisted from the enrollment or \
                 the last renewal"
            ))
        })?;
        let current = ndn_packet::Data::decode(bag.certificate.clone()).map_err(|e| {
            unusable(format!(
                "the SafeBag's certificate is not a Data packet ({e}); pass the bag persisted \
                 from the enrollment or the last renewal"
            ))
        })?;
        let key_name = ndn_cert::key_name_of(&current.name).ok_or_else(|| {
            unusable(format!(
                "the SafeBag's certificate {} names no key; pass the bag persisted from the \
                 enrollment or the last renewal",
                current.name
            ))
        })?;
        let opened = |e: &dyn std::fmt::Display| {
            unusable(format!(
                "the SafeBag's key does not open with this password ({e}); pass the password it \
                 was persisted with"
            ))
        };
        let signer = ndn_mobile::MobileEngine::load_identity(&bag, &password, key_name.clone())
            .map_err(|e| opened(&e))?;
        let pkcs8 = bag.decrypt_pkcs8(&password).map_err(|e| opened(&e))?;
        let kept: Vec<ndn_packet::Data> = issuers
            .into_iter()
            .filter_map(|wire| ndn_packet::Data::decode(wire.into()).ok())
            .collect();
        let issued = match self.rt.block_on(ndn_identity::renew_via_engine(
            engine,
            &self.keyring,
            &current,
            &kept,
            Arc::clone(&signer),
        )) {
            Ok(issued) => issued,
            Err(e) if e.is_final() => return Ok(NdnRenewal::Refused { detail: e.to_string() }),
            Err(e) => return Ok(NdnRenewal::Failed { detail: e.to_string() }),
        };
        let cert_wire = issued.data.raw().clone();
        let renewed = match SafeBag::encrypt(cert_wire.clone(), &pkcs8, &password) {
            Ok(renewed) => renewed,
            Err(e) => {
                return Ok(NdnRenewal::Failed {
                    detail: format!(
                        "the CA renewed the certificate as {}, but sealing it into a new SafeBag \
                         failed ({e}); the current certificate stays in use: renew again",
                        issued.cert.name
                    ),
                });
            }
        };
        self.record_cert(&cert_wire);
        *self.identity.lock().unwrap() = Some(signer);
        Ok(NdnRenewal::Renewed {
            identity: NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: issued.cert.name.to_string(),
                certificate: Some(cert_wire.to_vec()),
                safebag: renewed.encode().to_vec(),
                adopted_context: None,
                issuers: issued.issuers.iter().map(|d| d.raw().to_vec()).collect(),
            },
        })
    }

    /// The validity of the loaded identity's current certificate, with
    /// when to renew it (a third of the lifetime left).
    pub(crate) fn certificate_validity(&self) -> Result<NdnCertValidity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let wire = self.require_cert_wire()?;
            let cert = ndn_packet::Data::decode(wire)
                .ok()
                .and_then(|data| ndn_security::Certificate::decode(&data).ok())
                .ok_or_else(|| NdnError::Identity {
                    msg: "the loaded identity's certificate cannot be decoded".into(),
                })?;
            let renew_at = ndn_identity::RenewBefore::ONE_THIRD
                .renew_at(cert.valid_from, cert.valid_until);
            const NS: u64 = 1_000_000_000;
            Ok(NdnCertValidity {
                cert_name: cert.name.to_string(),
                valid_from_secs: cert.valid_from / NS,
                valid_until_secs: cert.valid_until / NS,
                renew_at_secs: renew_at / NS,
            })
        }
        #[cfg(not(feature = "identity"))]
        {
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
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
        self.record_cert(&Bytes::from(cert_wire));
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
            self.record_cert(&bag.certificate);
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

    /// Install a signer as the loaded operator identity with its
    /// certificate, if one was issued — used by `NdnEngine`'s engine-bound
    /// enroll variants (the PIN challenge) that produce a signer through the
    /// embedded engine rather than over the generic connection.
    #[cfg(feature = "identity")]
    pub(crate) fn set_identity(
        &self,
        signer: Arc<dyn ndn_security::Signer>,
        certificate: Option<&Bytes>,
    ) {
        if let Some(wire) = certificate {
            self.record_cert(wire);
        }
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
                adopted_context: None,
                issuers: Vec::new(),
            };
            if let Some(wire) = enrolled.certificate() {
                self.record_cert(wire);
            }
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
                adopted_context: None,
                issuers: Vec::new(),
            };
            // A CA that pairs no repo returns no certificate: the current one
            // is then fetched by key name when first needed, and taken only
            // when it chains to an adopted trust context.
            if let Some(wire) = enrolled.certificate() {
                self.record_cert(wire);
            }
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
                adopted_context: None,
                issuers: Vec::new(),
            };
            if let Some(wire) = generated.certificate() {
                self.record_cert(wire);
            }
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

            // The KeyLocator names the key; verifiers resolve it to the newest
            // valid certificate (this self-cert, or a later one for the key).
            let signer: Arc<dyn ndn_security::Signer> = Arc::new(CustodianSigner::new(
                custodian,
                key_id,
                SignatureType::SignatureSha256WithEcdsa,
                Some(pubkey.clone()),
            ));
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            const VALIDITY_SECS: u64 = 10 * 365 * 24 * 60 * 60;
            let until_ns = now_ns.saturating_add(VALIDITY_SECS.saturating_mul(1_000_000_000));
            let cert_name = ndn_security::cert_name::new_cert_name(
                &key_name,
                ndn_security::cert_name::SELF_ISSUER,
            );
            let cert_wire = self
                .rt
                .block_on(ndn_security::encode_cert_data(
                    &cert_name, &pubkey, &*signer, now_ns, until_ns,
                ))
                .map_err(|e| NdnError::Identity {
                    msg: format!("enclave self-cert failed: {e}"),
                })?;

            let result = NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: cert_name.to_string(),
                certificate: Some(cert_wire.to_vec()),
                safebag: Vec::new(),
                adopted_context: None,
                issuers: Vec::new(),
            };
            self.record_cert(&cert_wire);
            *self.identity.lock().unwrap() = Some(signer);
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

    /// Re-bind the enclave key `key_name` with `certificate`, the one the host
    /// persisted for it (none: fetched by key name when first needed). The
    /// certificate must be of `key_name` and certify the enclave's public key.
    pub(crate) fn load_identity_enclave(
        &self,
        key_name: String,
        enclave: Box<dyn NdnEnclaveBackend>,
        certificate: Option<Vec<u8>>,
    ) -> Result<bool, NdnError> {
        #[cfg(feature = "identity")]
        {
            use ndn_security::custodian::{Custodian, CustodianSigner, EnclaveCustodian, KeyId};
            use ndn_packet::SignatureType;

            let kname: Name = key_name
                .parse()
                .map_err(|_| NdnError::invalid_name(&key_name))?;
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
            let certificate = certificate
                .map(|wire| enclave_certificate(&kname, &pubkey, wire))
                .transpose()?;
            let custodian: Arc<dyn Custodian> =
                Arc::new(EnclaveCustodian::new(backend, key_name));
            // The KeyLocator names the key: verifiers resolve it to the newest
            // valid certificate, so a renewal needs no re-bind here. Without a
            // persisted certificate (or once it has expired) the current one is
            // fetched by key name when first needed ([`Self::resolve_cert_wire`]).
            let signer: Arc<dyn ndn_security::Signer> = Arc::new(CustodianSigner::new(
                custodian,
                KeyId(kname),
                SignatureType::SignatureSha256WithEcdsa,
                Some(pubkey),
            ));
            if let Some(wire) = certificate {
                self.record_cert(&wire);
            }
            *self.identity.lock().unwrap() = Some(signer);
            Ok(true)
        }
        #[cfg(not(feature = "identity"))]
        {
            let _ = (key_name, enclave, certificate);
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
        // FIB cert-fetch). `None` for an identity with no certificate — the pull
        // then returns empty and the gateway falls back to its FIB fetcher.
        let cert_wire = self.resolve_cert_wire();

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
        Ok(self.require_cert_wire()?.to_vec())
    }

    /// The loaded identity's current certificate ([`Self::resolve_cert_wire`]),
    /// or why there is none and what to do. Never minted: a certificate
    /// made up here would hide the one the namespace's CA issued for the key.
    #[cfg(feature = "identity")]
    fn require_cert_wire(&self) -> Result<Bytes, NdnError> {
        let key = self
            .identity
            .lock()
            .unwrap()
            .as_ref()
            .map(|signer| signer.key_name().clone())
            .ok_or_else(|| NdnError::Identity {
                msg: "no identity loaded".into(),
            })?;
        self.resolve_cert_wire().ok_or_else(|| NdnError::Identity {
            msg: format!(
                "no certificate of {key} is held or reachable: pass the certificate persisted \
                 for this identity (NdnEnrolledIdentity.certificate) to load_identity_enclave, \
                 or reach a forwarder that serves the certificate the namespace's CA issued for \
                 this key (it is taken only when it chains to an adopted trust context: adopt \
                 the namespace's trust context first)"
            ),
        })
    }

    /// Record `wire`, a certificate (Data) of one of this core's identities.
    #[cfg(feature = "identity")]
    fn record_cert(&self, wire: &Bytes) {
        let cert = ndn_packet::Data::decode(wire.clone())
            .map_err(|e| e.to_string())
            .and_then(|data| ndn_security::Certificate::decode(&data).map_err(|e| e.to_string()));
        match cert {
            Ok(cert) => self.certs.insert(cert),
            Err(e) => tracing::warn!(
                target: "ndn_boltffi::identity",
                error = %e,
                "not recording an undecodable identity certificate"
            ),
        }
    }

    /// The loaded identity's current certificate among those recorded: the
    /// newest valid one of its key, else the newest.
    fn current_cert(&self) -> Option<ndn_security::Certificate> {
        let key = Arc::new(self.identity.lock().unwrap().as_ref()?.key_name().clone());
        self.certs.get(&key)
    }

    /// The loaded identity's current certificate (Data wire). With no valid
    /// one recorded, fetch the newest certificate of its key by key name
    /// ([`Self::fetch_cert`]) and record it. `None` with no identity, or no
    /// certificate recorded or reachable.
    #[cfg(feature = "identity")]
    fn resolve_cert_wire(&self) -> Option<Bytes> {
        let signer = self.identity.lock().unwrap().clone()?;
        if self.certs.get_valid(signer.key_name()).is_none()
            && let Some(wire) = self.fetch_cert(signer.as_ref())
        {
            self.record_cert(&wire);
        }
        self.current_cert()?.data_wire()
    }

    /// The newest certificate of `signer`'s key the network serves — asked by
    /// key name (CanBePrefix, MustBeFresh: the CA serves the certificates it
    /// issued) — when it names that key, certifies exactly `signer`'s public
    /// key, is valid now and chains to the root of an adopted trust context
    /// under its schema ([`ndn_cert::check_chain`], which fetches the issuer
    /// certificates and verifies every hop). Anything else is not taken.
    #[cfg(feature = "identity")]
    fn fetch_cert(&self, signer: &dyn ndn_security::Signer) -> Option<Bytes> {
        use ndn_cert::{CaExchange, IssuedCheckError};
        use ndn_packet::encode::InterestBuilder;

        let key = signer.key_name();
        let not_taken = |certificate: &Name, why: String| {
            tracing::warn!(
                target: "ndn_boltffi::identity",
                key = %key,
                certificate = %certificate,
                "not taking a fetched certificate of the identity's key: {why}"
            );
            None
        };
        let mut consumer = Consumer::new(self.conn.clone());
        let mut exchange = ndn_mobile::enroll::ConsumerExchange(&mut consumer);
        self.rt.block_on(async {
            let interest = InterestBuilder::new(key.clone())
                .can_be_prefix()
                .must_be_fresh()
                .build();
            let data = match exchange.express(interest).await {
                Ok(data) => data,
                Err(e) => {
                    tracing::debug!(
                        target: "ndn_boltffi::identity",
                        key = %key,
                        error = %e,
                        "no certificate of the identity's key reachable"
                    );
                    return None;
                }
            };
            let cert = match ndn_security::Certificate::decode(&data) {
                Ok(cert) => cert,
                Err(e) => return not_taken(&data.name, format!("not a certificate: {e}")),
            };
            if cert.key_name() != *key {
                return not_taken(&cert.name, "it is not a certificate of this key".into());
            }
            if !signer
                .public_key()
                .is_some_and(|pk| same_public_key(&pk, &cert.public_key))
            {
                return not_taken(&cert.name, "it certifies a different public key".into());
            }
            if !cert.is_valid_now() {
                return not_taken(&cert.name, "it is not valid now".into());
            }
            let namespace = self.keyring.context_for(key).namespace().clone();
            match ndn_cert::check_chain(&data, &self.keyring, &mut exchange, &namespace).await {
                Ok(_) => Some(data.raw().clone()),
                Err(IssuedCheckError::Refused(why) | IssuedCheckError::Signing(why)) => {
                    not_taken(&cert.name, why)
                }
                Err(IssuedCheckError::Exchange(e)) => not_taken(
                    &cert.name,
                    format!("an issuer certificate of its chain is unreachable: {e}"),
                ),
            }
        })
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

        self.record_cert(&cert_wire);
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

/// The certificate the host persisted for the enclave key `key_name` (its
/// public key `pubkey`), checked to be a certificate of that key certifying
/// exactly that public key.
#[cfg(feature = "identity")]
fn enclave_certificate(key_name: &Name, pubkey: &[u8], wire: Vec<u8>) -> Result<Bytes, NdnError> {
    let refused = |why: String| NdnError::Identity {
        msg: format!(
            "the certificate passed for {key_name} is refused: {why}; pass the certificate \
             persisted with this identity (NdnEnrolledIdentity.certificate), or none to fetch it \
             from the namespace's CA"
        ),
    };
    let wire = Bytes::from(wire);
    let data = ndn_packet::Data::decode(wire.clone())
        .map_err(|e| refused(format!("it is not a Data packet ({e})")))?;
    let cert = ndn_security::Certificate::decode(&data)
        .map_err(|e| refused(format!("it is not a certificate ({e})")))?;
    if cert.key_name() != *key_name {
        return Err(refused(format!("it is {}, a certificate of another key", cert.name)));
    }
    if !same_public_key(pubkey, &cert.public_key) {
        return Err(refused("it certifies a different public key than the enclave's".into()));
    }
    Ok(wire)
}

/// A public key decoded from the encodings a signer reports or a certificate
/// carries: Ed25519 as SPKI or the raw 32 bytes, P-256 as SPKI DER or the
/// SEC1 point.
#[cfg(feature = "identity")]
#[derive(PartialEq)]
enum PublicKey {
    Ed25519([u8; ndn_security::spki::ED25519_KEY_LEN]),
    P256(p256::PublicKey),
}

#[cfg(feature = "identity")]
impl PublicKey {
    fn decode(bytes: &[u8]) -> Option<Self> {
        use p256::pkcs8::DecodePublicKey;
        if let Some(raw) = ndn_security::spki::unwrap_ed25519(bytes) {
            return Some(Self::Ed25519(raw));
        }
        if let Ok(raw) = bytes.try_into() {
            return Some(Self::Ed25519(raw));
        }
        p256::PublicKey::from_public_key_der(bytes)
            .or_else(|_| p256::PublicKey::from_sec1_bytes(bytes))
            .ok()
            .map(Self::P256)
    }
}

/// Whether `a` and `b` encode the same public key (an undecodable one is
/// the same as nothing).
#[cfg(feature = "identity")]
fn same_public_key(a: &[u8], b: &[u8]) -> bool {
    matches!((PublicKey::decode(a), PublicKey::decode(b)), (Some(a), Some(b)) if a == b)
}
