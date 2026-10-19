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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_app::{Connection, Consumer, DemuxConnection};
use ndn_cert::report::MembershipEvent;
use ndn_packet::Name;
use tokio::runtime::Runtime;

use crate::handlers::{NdnApprovalGate, NdnEnclaveBackend, NdnRecoverySigner};
use crate::types::{
    NdnActionClass, NdnCertValidity, NdnContext, NdnDelegationScope, NdnEnrollConfig,
    NdnEnrolledIdentity, NdnError, NdnIdentity, NdnRecoveredIdentity, NdnRenewal,
};

#[cfg(feature = "identity")]
mod approval;
#[cfg(feature = "identity")]
mod host;

/// The identities and trust state shared by both FFI backends. Holds every
/// identity the app is enrolled as (or loaded, generated, restored), the
/// node identity among them, the §7 scoped-signing policy, the adopted
/// trust contexts, the shared runtime, and a forwarder `Connection`
/// (in-proc for the embedded engine, IPC for the cross-process client).
pub(crate) struct IdentityCore {
    pub(crate) rt: Arc<Runtime>,
    /// The forwarder seam, wrapped in a [`DemuxConnection`] so the RemoteSigner
    /// responder and the (reflexive) announce can serve and fetch concurrently
    /// over it — a bare `Connection` has no demux and the two readers race. Held
    /// as `dyn Connection` for the `Consumer`-based methods; [`Self::demux`] is
    /// the same object, typed, for the serve side.
    pub(crate) conn: Arc<dyn Connection>,
    pub(crate) demux: Arc<DemuxConnection>,
    /// Every identity the app signs as, each with the key it signs with,
    /// over this core's keyring: a packet is signed by the identity its name
    /// chooses ([`SecurityManager::signer_for`](ndn_security::SecurityManager::signer_for)),
    /// never by another trusted prefix's key. Its certificate cache holds the
    /// certificates of these identities' keys: the one each was installed
    /// with (CA-issued, renewed, or a self-issued identity's own
    /// self-certificate) and any fetched by key name that chains to an
    /// adopted trust context — never one minted for a key that was installed
    /// without one. An identity's *current* certificate — the one its
    /// key-name KeyLocator resolves to — is the newest valid one recorded for
    /// its key ([`Self::current_cert_of`]).
    signing: ndn_security::SecurityManager,
    /// The node identity: what the app signs its own traffic as (principal
    /// operations, RemoteSigner responses, management commands, the link
    /// key). The first identity the app held, unless the app chose another
    /// ([`Self::set_node_identity`]); an enrollment never changes it.
    node: parking_lot::Mutex<Option<Name>>,
    /// Bumped when an identity is added or the node identity changes: the
    /// device's links present its memberships again
    /// ([`ndn_link::Links::identities_changed`]).
    changes: tokio::sync::watch::Sender<u64>,
    /// The issuer certificates (Data wires, nearest first) of each key's
    /// certificate, as kept from its enrollment or renewal or passed by the
    /// host: the rest of the chain a link hello carries.
    issuers: parking_lot::Mutex<HashMap<Name, Vec<Bytes>>>,
    /// The membership changes the library's operations report
    /// ([`Self::watch_memberships`]).
    memberships: tokio::sync::broadcast::Sender<MembershipEvent>,
    /// Cancelled when the engine shuts down: ends the membership watch.
    #[cfg(feature = "identity")]
    closed: tokio_util::sync::CancellationToken,
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

/// How many membership changes a slow watcher may fall behind by before it
/// misses some (it is told, and reads `memberships` for the current state).
const MEMBERSHIP_EVENTS: usize = 64;

impl IdentityCore {
    /// Build a core over `conn` (the forwarder seam) sharing runtime `rt`,
    /// adopting trust contexts into `keyring`: the embedded engine's
    /// validator keyring, so the forwarder validates Data under an adopted
    /// namespace against its context (as `ndn-fwd` does), or a keyring of
    /// its own without an engine validator.
    pub(crate) fn new(
        rt: Arc<Runtime>,
        conn: Arc<dyn Connection>,
        keyring: Arc<ndn_security::Keyring>,
    ) -> Self {
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
            signing: ndn_security::SecurityManager::with_keyring(Arc::clone(&keyring)),
            node: parking_lot::Mutex::new(None),
            changes: tokio::sync::watch::Sender::new(0),
            issuers: parking_lot::Mutex::new(HashMap::new()),
            memberships: tokio::sync::broadcast::channel(MEMBERSHIP_EVENTS).0,
            #[cfg(feature = "identity")]
            closed: tokio_util::sync::CancellationToken::new(),
            #[cfg(feature = "identity")]
            sign_policy: Mutex::new(ndn_security::custodian::ScopedSigningPolicy::new()),
            keyring,
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
    /// own identities' certificates (for content it published) plus every
    /// pinned anchor. The trust root for verified fetches.
    pub(crate) fn build_validator(&self) -> ndn_security::Validator {
        let v = ndn_security::Validator::new(ndn_security::TrustSchema::hierarchical());
        // Our ACTUAL signing certs — the ones our Data's KeyLocators reference
        // (set by generate_identity / enroll / load) — so content we published
        // under any of our identities chains. (Not a reconstruction: a
        // fabricated self-cert wouldn't match KeyLocator and the chain
        // wouldn't resolve.)
        for identity in self.signing.signing_identities() {
            if let Some(cert) = self.current_cert_of(&identity.key) {
                // add_trust_anchor (not just cert_cache.insert): the cert must be
                // a recognized ROOT, else the hierarchical walk never finds an
                // anchor and returns Pending ("certificate chain not resolved").
                v.add_trust_anchor(cert);
            }
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
        let ctx =
            ndn_cert::adopt_with_tofu(&self.keyring, &data, &ns, &fingerprint).map_err(|e| {
                NdnError::Identity {
                    msg: format!("trust context refused: {e}"),
                }
            })?;
        Ok(NdnContext::adopted(&ctx, &data, &fingerprint))
    }

    /// Adopt the namespace a scanned `ndn-trust://anchor` link names, as
    /// the `ndn-fwd` daemon does ([`ndn_namespace::keep::adopt_link`]): an
    /// inline context is verified against the link's expected fingerprint; a
    /// fingerprint-only link fetches the context by name through `engine` —
    /// whose validator admits exactly the expected context meanwhile — and
    /// requires at least the version the link names. Blocking (network round
    /// trips). The result carries the signed context for the host to
    /// persist.
    #[cfg(feature = "identity")]
    pub(crate) fn adopt_context_link(
        &self,
        engine: &ndn_app::ForwarderEngine,
        link_uri: String,
    ) -> Result<NdnContext, NdnError> {
        let refused = |reason: String| NdnError::Identity {
            msg: format!("trust context refused: {reason}"),
        };
        let link = ndn_cert::AnchorLink::from_uri(&link_uri).map_err(|e| refused(e.to_string()))?;
        let contexts = Arc::new(host::AppContexts::default());
        let participant = self.participant(engine, &contexts);
        self.rt
            .block_on(ndn_namespace::keep::adopt_link(&participant, &link))
            .map_err(|e| refused(e.reason))?;
        contexts
            .newest(&link.namespace)
            .ok_or_else(|| refused(format!("{} was not kept", link.namespace)))
    }

    /// Check each held trust context (only `namespace`, when given) for a
    /// newer version through `engine`, as the `ndn-fwd` daemon does
    /// ([`ndn_namespace::refresh::refresh_contexts`]): the newest version's
    /// name by RDR metadata, then the signed context, adopted only if it is
    /// newer and signed by an anchor of the version held (continuity),
    /// following the versions in between after a recovery. A refused or
    /// failed check changes nothing. Blocking (network round trips).
    #[cfg(feature = "identity")]
    pub(crate) fn refresh_contexts(
        &self,
        engine: &ndn_app::ForwarderEngine,
        namespace: Option<String>,
    ) -> Result<Vec<crate::types::NdnContextRefresh>, NdnError> {
        use ndn_namespace::RefreshState;

        let namespace = namespace
            .map(|ns| ns.parse::<Name>().map_err(|_| NdnError::invalid_name(&ns)))
            .transpose()?;
        let contexts = Arc::new(host::AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let results = self
            .rt
            .block_on(ndn_namespace::refresh::refresh_contexts(
                &participant,
                namespace,
            ))
            .map_err(host::refused)?;
        Ok(results
            .into_iter()
            .map(|info| {
                let context = match info.state {
                    RefreshState::Updated => info
                        .namespace
                        .parse::<Name>()
                        .ok()
                        .and_then(|ns| contexts.newest(&ns)),
                    _ => None,
                };
                crate::types::NdnContextRefresh {
                    state: match info.state {
                        RefreshState::Updated => "updated",
                        RefreshState::Current => "current",
                        RefreshState::UpstreamOlder => "upstream-older",
                        RefreshState::Behind => "behind",
                        RefreshState::Source => "source",
                        RefreshState::Unreachable => "unreachable",
                        RefreshState::Failed => "failed",
                    }
                    .to_string(),
                    namespace: info.namespace,
                    held_version: info.held_version,
                    version: info.version,
                    revoked: info.revoked,
                    detail: info.detail,
                    context,
                }
            })
            .collect())
    }

    /// Enroll this device with the CA an `ndn-trust://invite` link names, as
    /// `<ns>/<role>/<device>`, the way the `ndn-fwd` daemon does
    /// ([`ndn_namespace::enroll`]): adopt the namespace's trust context if
    /// it is not held (checked against the invite's root fingerprint), else
    /// check the held one is signed by that root; generate a fresh ECDSA-P256
    /// key here, redeem the invite's token for a certificate and check its
    /// chain to the root. On success the identity is installed for signing
    /// and the result carries a password-encrypted SafeBag (key + issued
    /// certificate) and any trust context adopted on the way for the host to
    /// persist; a failure that adopted the context reports it in
    /// [`NdnError::EnrollmentFailed`]. A role the namespace certifies on an
    /// admin's approval is refused here: ask with `request_enrollment`.
    /// Blocking (network round trips); `engine` needs a face and a route
    /// for the namespace.
    #[cfg(feature = "identity")]
    pub(crate) fn enroll_with_invite(
        &self,
        engine: &ndn_app::ForwarderEngine,
        invite_uri: String,
        device: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnEnrolledIdentity, NdnError> {
        use ndn_cert::EnrollLink;
        use ndn_namespace::enroll::{Enrolling, Route, ensure_context, route};

        let refused = |e: &dyn std::fmt::Display| NdnError::Identity {
            msg: format!("enrollment refused: {e}"),
        };
        let invite = ndn_cert::InviteLink::from_uri(&invite_uri).map_err(|e| refused(&e))?;
        let identity = invite.device_identity(&device).map_err(|e| refused(&e))?;
        let namespace = invite.namespace.clone();
        let role = invite.role;
        let link = EnrollLink::Invite(invite);
        let contexts = Arc::new(host::AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let vault = host::AppVault::new(self, String::new(), persist_password);
        let failed = |reason: String| NdnError::EnrollmentFailed {
            msg: format!("enrollment refused: {reason}"),
            adopted_context: contexts.newest(&namespace),
        };
        let adopted = self
            .rt
            .block_on(ensure_context(&participant, &link))
            .map_err(|e| failed(e.reason))?;
        match route(&participant, &link, role).map_err(|e| failed(e.reason))? {
            Route::Invite => {}
            Route::Approval { .. } => {
                return Err(failed(format!(
                    "{namespace} certifies {role} devices on an admin's approval: ask with \
                     request_enrollment"
                )));
            }
        }
        let EnrollLink::Invite(invite) = &link else {
            unreachable!("an invite link")
        };
        let enrolling = Enrolling {
            namespace: namespace.clone(),
            identity,
            previous_identity: None,
            adopted_context: adopted,
            context_check: None,
        };
        self.rt
            .block_on(ndn_namespace::enroll::enroll_by_invite(
                &participant,
                &vault,
                invite,
                enrolling,
            ))
            .map_err(|e| failed(e.reason))?;
        vault
            .installed(contexts.newest(&namespace))
            .ok_or_else(|| failed("the issued certificate was not installed".into()))
    }

    /// Renew the certificate in `safebag` at its namespace's CA (same key,
    /// proof of the current certificate, no invite), as the `ndn-fwd`
    /// daemon does ([`ndn_namespace::renewal::renew_now`]). Renewed: the
    /// identity is loaded with the new certificate, and the outcome carries
    /// a new SafeBag (same key, same `password`) and the new certificate's
    /// issuer chain to persist. Otherwise the outcome says whether retrying
    /// can help: `Refused` when it cannot (a revoked key, a role the CA does
    /// not renew, a certificate no namespace CA issued in a namespace this
    /// app holds), `Failed` when it can. `issuers` are the issuer
    /// certificates kept from the enrollment or earlier renewal (empty =
    /// none kept; undecodable entries are skipped): after a recovery the
    /// namespace's CA runs a later CA key and renews the certificate only
    /// with this chain. An `Err` is an unusable `safebag` or `password`,
    /// found before anything is sent. Blocking (network round trips).
    #[cfg(feature = "identity")]
    pub(crate) fn renew_certificate(
        &self,
        engine: &ndn_app::ForwarderEngine,
        safebag: Vec<u8>,
        password: Vec<u8>,
        issuers: Vec<Vec<u8>>,
    ) -> Result<NdnRenewal, NdnError> {
        use ndn_namespace::RenewalState;
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
        let held = host::Held {
            key: key_name.clone(),
            cert: current,
            pkcs8: Some(pkcs8),
            signer: Arc::clone(&signer),
        };
        let vault = host::AppVault::holding(self, held, issuers, password);
        let contexts = Arc::new(host::AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let renewed = match self
            .rt
            .block_on(ndn_namespace::renewal::renew_now(&participant, &vault))
        {
            Ok(renewed) => renewed,
            // Nothing a namespace CA issued in a namespace this app holds.
            Err(e) => return Ok(NdnRenewal::Refused { detail: e.reason }),
        };
        let Some(info) = renewed
            .into_iter()
            .find(|info| info.key == key_name.to_string())
        else {
            return Ok(NdnRenewal::Refused {
                detail: format!("{key_name} is not a certificate a namespace CA issued"),
            });
        };
        match info.state {
            RenewalState::Renewed => {
                let mut identity = vault
                    .installed(None)
                    .ok_or_else(|| unusable("the renewed certificate was not sealed".into()))?;
                if let Some(cert) = &identity.certificate {
                    self.record_cert(&Bytes::from(cert.clone()));
                }
                identity.node_identity = self.add_identity(signer)?;
                Ok(NdnRenewal::Renewed { identity })
            }
            RenewalState::Refused => Ok(NdnRenewal::Refused {
                detail: info.detail,
            }),
            RenewalState::Failed => Ok(NdnRenewal::Failed {
                detail: info.detail,
            }),
        }
    }

    /// The validity of the node identity's current certificate, with when
    /// to renew it (a third of the lifetime left). Every identity's:
    /// [`Self::identities`].
    pub(crate) fn certificate_validity(&self) -> Result<NdnCertValidity, NdnError> {
        #[cfg(feature = "identity")]
        {
            let wire = self.require_cert_wire()?;
            ndn_packet::Data::decode(wire)
                .ok()
                .and_then(|data| ndn_security::Certificate::decode(&data).ok())
                .map(|cert| validity(&cert))
                .ok_or_else(|| NdnError::Identity {
                    msg: "the node identity's certificate cannot be decoded".into(),
                })
        }
        #[cfg(not(feature = "identity"))]
        {
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    /// Every identity the app signs as, sorted by name, with its current
    /// certificate (as recorded; never fetched here) and the trusted prefix
    /// it is in.
    pub(crate) fn identities(&self) -> Vec<NdnIdentity> {
        let node = self.node.lock().clone();
        self.signing
            .signing_identities()
            .into_iter()
            .map(|s| {
                let cert = self.current_cert_of(&s.key);
                let ctx = self.keyring.context_for(&s.identity);
                let namespace = if Arc::ptr_eq(&ctx, self.keyring.ambient()) {
                    String::new()
                } else {
                    ctx.namespace().to_string()
                };
                NdnIdentity {
                    node_identity: node.as_ref() == Some(&s.identity),
                    identity: s.identity.to_string(),
                    key_name: s.key.to_string(),
                    namespace,
                    certificate: cert
                        .as_ref()
                        .and_then(|c| c.data_wire())
                        .map(|w| w.to_vec()),
                    #[cfg(feature = "identity")]
                    validity: cert.as_ref().map(validity),
                    #[cfg(not(feature = "identity"))]
                    validity: None,
                }
            })
            .collect()
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

    /// The node identity's signer, if the app holds any identity.
    pub(crate) fn current_signer(&self) -> Option<Arc<dyn ndn_security::Signer>> {
        let node = self.node.lock().clone()?;
        self.signing.identity_signer(&node).ok()
    }

    /// The signer of a packet named `name`: the identity its name chooses
    /// ([`SecurityManager::signer_for`](ndn_security::SecurityManager::signer_for)).
    /// Refused, saying why, when the app only follows the trusted prefix
    /// covering `name` or no identity of it covers `name`.
    pub(crate) fn signer_for(
        &self,
        name: &Name,
    ) -> Result<Arc<dyn ndn_security::Signer>, NdnError> {
        self.signing.signer_for(name).map_err(|e| match e {
            ndn_security::TrustError::NoSigningIdentity { name: refused, why } => {
                let ctx = self.keyring.context_for(name);
                if Arc::ptr_eq(&ctx, self.keyring.ambient()) {
                    NdnError::NoSigningIdentity {
                        why: format!(
                            "no identity of this app covers {refused}: enroll in a trusted prefix \
                             that covers it (enroll_with_invite, request_enrollment), or load or \
                             generate an identity whose name is a prefix of it"
                        ),
                        name: refused,
                        follows: None,
                    }
                } else {
                    NdnError::NoSigningIdentity {
                        name: refused,
                        follows: Some(ctx.namespace().to_string()),
                        why,
                    }
                }
            }
            other => NdnError::Identity {
                msg: format!("cannot sign {name}: {other}"),
            },
        })
    }

    /// Sign through a remote signer: add the identity of `cert_wire` (the
    /// signing node's certificate — both the source of the KeyLocator
    /// metadata and the cert this node serves, so peers verify what it
    /// produces) with a signer whose every signature round-trips to the
    /// RemoteSigner served at `prefix` (the device's Anchor). Names under
    /// that identity are signed through it; it is the node identity only
    /// when the app held no identity before (a keyless node).
    #[cfg(feature = "identity")]
    pub(crate) fn use_remote_signer(
        &self,
        prefix: String,
        cert_wire: Vec<u8>,
    ) -> Result<bool, NdnError> {
        let prefix: Name = prefix
            .parse()
            .map_err(|_| NdnError::invalid_name(&prefix))?;
        let signer = crate::remote_signer_client::RemoteSignerClient::from_cert(
            self.demux.clone(),
            prefix,
            &cert_wire,
        )
        .map_err(|e| NdnError::engine(format!("remote signer setup: {e}")))?;
        self.record_cert(&Bytes::from(cert_wire));
        self.add_identity(Arc::new(signer))?;
        Ok(true)
    }

    /// RDR whole-object publish: slice `content` into `chunk_size`-byte segments
    /// under `<name>/v=<ver>`, register `name` with the forwarder, and serve the
    /// metadata + segment Interests until the connection closes (blocking — run
    /// on a worker thread). Signs with the identity `name` chooses
    /// ([`Self::signer_for`]; refused, saying why, when none may) when the
    /// app holds any identity, else with `DigestSha256` (integrity only). Serves
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
        let signer = if self.has_identity() {
            Some(self.signer_for(&parsed)?)
        } else {
            None
        };
        self.rt
            .block_on(self.demux.serve(parsed, move |interest, responder| {
                let prepared = prepared.clone();
                let signer = signer.clone();
                async move {
                    if let Ok(Some(wire)) = prepared
                        .answer_interest(&interest.name, signer.as_deref())
                        .await
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
    /// object under the node identity. Requires an identity.
    #[cfg(feature = "identity")]
    pub(crate) fn start_offer_board(
        &self,
        node_id: String,
    ) -> Result<Arc<crate::offer::OfferBoard>, NdnError> {
        let signer = self.current_signer().ok_or_else(|| NdnError::Identity {
            msg: "no identity loaded — load one before sharing".into(),
        })?;
        let identity_prefix = self.node_principal()?.name().clone();
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

    /// Whether `key_name` is a namespace recovery key: `<ns>/KEY/r<hex>`, named
    /// after its certificate's public key (`ndn_cert::recovery_key_name`). A
    /// file recovery kit's SafeBag holds one; it recovers a namespace and is
    /// never an operator identity.
    #[cfg(feature = "identity")]
    fn is_namespace_recovery_key(key_name: &Name, certificate: &Bytes) -> bool {
        let components = key_name.components();
        let Some(namespace_len) = components.len().checked_sub(2) else {
            return false;
        };
        let Some(cert) = ndn_packet::Data::decode(certificate.clone())
            .ok()
            .and_then(|data| ndn_security::Certificate::decode(&data).ok())
        else {
            return false;
        };
        let namespace = Name::from_components(components[..namespace_len].iter().cloned());
        ndn_cert::recovery_key_name(&namespace, &cert.public_key) == *key_name
    }

    // ── Identities + signing ───────────────────────────────────────────────

    /// Add the identity in `safebag` to the identities the app signs as
    /// (its other identities stay); returns its `did:ndn`.
    pub(crate) fn load_identity(
        &self,
        safebag: Vec<u8>,
        password: Vec<u8>,
        key_name: String,
    ) -> Result<String, NdnError> {
        #[cfg(feature = "identity")]
        {
            let bag =
                ndn_security::safebag::SafeBag::decode(&safebag).map_err(NdnError::identity)?;
            let name: Name = key_name
                .parse()
                .map_err(|_| NdnError::invalid_name(key_name.clone()))?;
            if Self::is_namespace_recovery_key(&name, &bag.certificate) {
                return Err(NdnError::Identity {
                    msg: format!(
                        "{key_name} is the recovery key of a namespace recovery kit, not an \
                         identity: use the kit to recover its namespace"
                    ),
                });
            }
            let signer = ndn_mobile::MobileEngine::load_identity(&bag, &password, name)
                .map_err(NdnError::identity)?;
            // Retain the CA-issued cert (inside the bag) so we can serve it to a
            // gateway that fetches it reflexively during localhop registration.
            self.record_cert(&bag.certificate);
            self.add_identity(Arc::clone(&signer))?;
            Ok(principal_of(signer)?.did())
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
        self.node.lock().is_some()
    }

    /// Add `signer`'s identity (`<identity>/KEY/<id>`) to the identities the
    /// app signs as, signing with `signer`'s key from now on (record its
    /// certificate first, so a link presents it); the other identities stay
    /// as they were. The app's first identity becomes its node identity.
    /// Tells the device's links. Returns whether it is the node identity.
    fn add_identity(&self, signer: Arc<dyn ndn_security::Signer>) -> Result<bool, NdnError> {
        let key = signer.key_name().clone();
        let identity = identity_of_key(&key).ok_or_else(|| NdnError::Identity {
            msg: format!("{key} names no identity: a key is named <identity>/KEY/<key-id>"),
        })?;
        self.signing.register_identity_signer(key, signer);
        let node = self.node.lock().get_or_insert_with(|| identity.clone()) == &identity;
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
        Ok(node)
    }

    /// Record `identity`, the app's first, as its node identity, before its
    /// key is added ([`Self::add_identity`]).
    #[cfg(feature = "identity")]
    fn record_node(&self, identity: &Name) {
        self.node.lock().get_or_insert_with(|| identity.clone());
    }

    /// The key each identity the app holds signs with.
    #[cfg(feature = "identity")]
    fn keys(&self) -> Vec<Name> {
        self.signing
            .signing_identities()
            .into_iter()
            .map(|s| s.key)
            .collect()
    }

    /// The signer of `key`, one of the app's identities' keys.
    #[cfg(feature = "identity")]
    fn signer_of_key(&self, key: &Name) -> Option<Arc<dyn ndn_security::Signer>> {
        self.signing.get_signer_sync(key).ok()
    }

    /// Whether `identity` is the node identity.
    pub(crate) fn is_node(&self, identity: &Name) -> bool {
        self.node.lock().as_ref() == Some(identity)
    }

    /// The node identity's name, if the app holds any identity.
    pub(crate) fn node_identity(&self) -> Option<Name> {
        self.node.lock().clone()
    }

    /// Make `identity`, one the app holds, its node identity: what it signs
    /// its own traffic as from now on. The host keeps the choice and makes
    /// it again at launch, after loading the identities.
    pub(crate) fn set_node_identity(&self, identity: String) -> Result<bool, NdnError> {
        let name: Name = identity
            .parse()
            .map_err(|_| NdnError::invalid_name(&identity))?;
        if self.signing.identity_signer(&name).is_err() {
            let held: Vec<String> = self
                .signing
                .signing_identities()
                .iter()
                .map(|s| s.identity.to_string())
                .collect();
            return Err(NdnError::Identity {
                msg: format!(
                    "this app holds no key of {identity} (it holds {}): load its SafeBag \
                     (load_identity) or its enclave key (load_identity_enclave) first",
                    if held.is_empty() {
                        "none".to_string()
                    } else {
                        held.join(", ")
                    }
                ),
            });
        }
        *self.node.lock() = Some(name);
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
        Ok(true)
    }

    /// Ticks each time an identity is added or the node identity changes.
    #[cfg(feature = "identity")]
    pub(crate) fn identity_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// The adopted trust contexts links are admitted under.
    #[cfg(feature = "identity")]
    pub(crate) fn keyring(&self) -> &Arc<ndn_security::Keyring> {
        &self.keyring
    }

    /// Keep `issuers` (Data wires, nearest first) as the issuer chain of
    /// `key`'s certificate.
    #[cfg(feature = "identity")]
    pub(crate) fn set_issuers(&self, key: &Name, issuers: Vec<Bytes>) {
        self.issuers.lock().insert(key.clone(), issuers);
    }

    /// Every issuer certificate kept for the app's keys.
    #[cfg(feature = "identity")]
    pub(crate) fn kept_issuers(&self) -> Vec<Bytes> {
        self.issuers.lock().values().flatten().cloned().collect()
    }

    /// `key`'s certificate (`valid`: only a currently valid one) among those
    /// recorded, then its issuers — never fetched (links ask for it inside a
    /// handshake).
    #[cfg(feature = "identity")]
    fn chain_of(&self, key: &Name, valid: bool) -> Option<Vec<Bytes>> {
        let cert = if valid {
            self.signing.cert_cache().get_valid(key)
        } else {
            self.current_cert_of(key)
        };
        let mut chain = vec![cert?.data_wire()?];
        chain.extend(self.issuers.lock().get(key).into_iter().flatten().cloned());
        Some(chain)
    }

    /// The node identity's certificate chain: what a link hello carries for
    /// the link key.
    #[cfg(feature = "identity")]
    pub(crate) fn own_chain(&self) -> Vec<Bytes> {
        self.current_signer()
            .and_then(|signer| self.chain_of(signer.key_name(), false))
            .unwrap_or_default()
    }

    /// The app's membership in each held trusted prefix it signs in: the
    /// identity it signs the prefix's Data as, with its currently valid
    /// certificate's chain — shown on each link beside the link key.
    #[cfg(feature = "identity")]
    pub(crate) fn own_memberships(&self) -> Vec<ndn_link::OwnMembership> {
        self.keyring
            .contexts()
            .iter()
            .filter_map(|ctx| {
                let s = self.signing.signing_identity_for(ctx.namespace()).ok()?;
                Some(ndn_link::OwnMembership {
                    namespace: ctx.namespace().clone(),
                    chain: self.chain_of(&s.key, true)?,
                    signer: s.signer,
                })
            })
            .collect()
    }

    /// A certificate of this core's identities, by certificate or key name.
    #[cfg(feature = "identity")]
    pub(crate) fn recorded_certificate(&self, name: &Name) -> Option<ndn_security::Certificate> {
        self.signing.cert_cache().get_valid(name)
    }

    /// Add a signer's identity with its certificate, if one was issued —
    /// used by `NdnEngine`'s engine-bound enroll variants (the PIN
    /// challenge) that produce a signer through the embedded engine rather
    /// than over the generic connection. Returns whether it is the node
    /// identity.
    #[cfg(feature = "identity")]
    pub(crate) fn set_identity(
        &self,
        signer: Arc<dyn ndn_security::Signer>,
        certificate: Option<&Bytes>,
    ) -> Result<bool, NdnError> {
        if let Some(wire) = certificate {
            self.record_cert(wire);
        }
        self.add_identity(signer)
    }

    /// Sign `region`, the signed portion of a packet named `name`: a
    /// management command (`/localhost/…`, `/localhop/…`) with the node
    /// identity — the node's own traffic — and anything else with the
    /// identity `name` chooses ([`Self::signer_for`]).
    pub(crate) fn sign(&self, name: String, region: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        let parsed: Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let management = parsed
            .components()
            .first()
            .is_some_and(|c| matches!(c.value.as_ref(), b"localhost" | b"localhop"));
        let signer = if management {
            self.node_signer()?
        } else {
            self.signer_for(&parsed)?
        };
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
            if let Some(wire) = enrolled.certificate() {
                self.record_cert(wire);
            }
            let node_identity = self.add_identity(enrolled.signer())?;
            Ok(NdnEnrolledIdentity {
                key_name: enrolled.key_name().to_string(),
                cert_name: enrolled.cert_name().to_string(),
                certificate: enrolled.certificate().map(|b| b.to_vec()),
                safebag: bag.encode().to_vec(),
                adopted_context: None,
                issuers: Vec::new(),
                node_identity,
            })
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

            // A CA that pairs no repo returns no certificate: the current one
            // is then fetched by key name when first needed, and taken only
            // when it chains to an adopted trust context.
            if let Some(wire) = enrolled.certificate() {
                self.record_cert(wire);
            }
            let node_identity = self.add_identity(enrolled.signer())?;
            Ok(NdnEnrolledIdentity {
                key_name: enrolled.key_name().to_string(),
                cert_name: enrolled.cert_name().to_string(),
                certificate: enrolled.certificate().map(|b| b.to_vec()),
                safebag: Vec::new(),
                adopted_context: None,
                issuers: Vec::new(),
                node_identity,
            })
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
            if let Some(wire) = generated.certificate() {
                self.record_cert(wire);
            }
            let node_identity = self.add_identity(generated.signer())?;
            Ok(NdnEnrolledIdentity {
                key_name: generated.key_name().to_string(),
                cert_name: generated.cert_name().to_string(),
                certificate: generated.certificate().map(|b| b.to_vec()),
                safebag: bag.encode().to_vec(),
                adopted_context: None,
                issuers: Vec::new(),
                node_identity,
            })
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
            use ndn_packet::SignatureType;
            use ndn_security::custodian::{Custodian, CustodianSigner, EnclaveCustodian, KeyId};

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

            self.record_cert(&cert_wire);
            let node_identity = self.add_identity(signer)?;
            Ok(NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: cert_name.to_string(),
                certificate: Some(cert_wire.to_vec()),
                safebag: Vec::new(),
                adopted_context: None,
                issuers: Vec::new(),
                node_identity,
            })
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
            use ndn_packet::SignatureType;
            use ndn_security::custodian::{Custodian, CustodianSigner, EnclaveCustodian, KeyId};

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
            let custodian: Arc<dyn Custodian> = Arc::new(EnclaveCustodian::new(backend, key_name));
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
            self.add_identity(signer)?;
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
                let signer = self.node_signer()?;
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
        let core = self;
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
                            core.current_signer()
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
        let signer = self.node_signer()?;

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
        let key_loc = signer
            .cert_name()
            .or_else(|| Some(signer.key_name()))
            .cloned();
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
            let _serve = self
                .demux
                .serve_scoped(reflexive, move |reverse, responder| {
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
            Ok(self.node_principal()?.did())
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
            Ok(self.node_principal()?.name().to_string())
        }
        #[cfg(not(feature = "identity"))]
        {
            Err(NdnError::Identity {
                msg: "identity feature not enabled in this build".into(),
            })
        }
    }

    pub(crate) fn principal_public_key(&self) -> Result<Vec<u8>, NdnError> {
        self.node_signer()?
            .public_key()
            .map(|b| b.to_vec())
            .ok_or_else(|| NdnError::Identity {
                msg: "the node identity has no exportable public key".into(),
            })
    }

    /// The node identity's signer, or why there is none.
    fn node_signer(&self) -> Result<Arc<dyn ndn_security::Signer>, NdnError> {
        self.current_signer().ok_or_else(|| NdnError::Identity {
            msg: "no identity loaded: load, generate or enroll one".into(),
        })
    }

    #[cfg(feature = "identity")]
    pub(crate) fn principal_cert_wire(&self) -> Result<Vec<u8>, NdnError> {
        Ok(self.require_cert_wire()?.to_vec())
    }

    /// The node identity's current certificate ([`Self::resolve_cert_wire`]),
    /// or why there is none and what to do. Never minted: a certificate
    /// made up here would hide the one the namespace's CA issued for the key.
    #[cfg(feature = "identity")]
    fn require_cert_wire(&self) -> Result<Bytes, NdnError> {
        let key = self.node_signer()?.key_name().clone();
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
            Ok(cert) => self.signing.cert_cache().insert(cert),
            Err(e) => tracing::warn!(
                target: "ndn_boltffi::identity",
                error = %e,
                "not recording an undecodable identity certificate"
            ),
        }
    }

    /// `key`'s current certificate among those recorded: the newest valid
    /// one, else the newest.
    fn current_cert_of(&self, key: &Name) -> Option<ndn_security::Certificate> {
        self.signing.cert_cache().get(&Arc::new(key.clone()))
    }

    /// The node identity's current certificate (Data wire). With no valid
    /// one recorded, fetch the newest certificate of its key by key name
    /// ([`Self::fetch_cert`]) and record it. `None` with no identity, or no
    /// certificate recorded or reachable.
    #[cfg(feature = "identity")]
    fn resolve_cert_wire(&self) -> Option<Bytes> {
        let signer = self.current_signer()?;
        if self
            .signing
            .cert_cache()
            .get_valid(signer.key_name())
            .is_none()
            && let Some(wire) = self.fetch_cert(signer.as_ref())
        {
            self.record_cert(&wire);
        }
        self.current_cert_of(signer.key_name())?.data_wire()
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

    pub(crate) fn recovery_public_key(&self, recovery_seed: Vec<u8>) -> Result<Vec<u8>, NdnError> {
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
            let device_name: Name = device
                .parse()
                .map_err(|_| NdnError::invalid_name(&device))?;
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
                .node_principal()?
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
            let deleg = ndn_identity::SignedDelegation::decode(&delegation_wire).map_err(|e| {
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
            // The delegation authorises the device (its node identity) to
            // sign names under the principal's scope, outside its own names.
            let signer = self.node_signer()?;
            let deleg = ndn_identity::SignedDelegation::decode(&delegation_wire).map_err(|e| {
                NdnError::Identity {
                    msg: format!("malformed delegation: {e:?}"),
                }
            })?;
            let name =
                Name::decode_from_tlv(bytes::Bytes::copy_from_slice(&region)).map_err(|_| {
                    NdnError::Identity {
                        msg: "region has no leading Name to scope-check".into(),
                    }
                })?;
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

    pub(crate) fn make_recoverable(&self, recovery_pubkey: Vec<u8>) -> Result<Vec<u8>, NdnError> {
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
            let keychain = self.node_principal()?.into_keychain();
            let recoverable =
                ndn_identity::Identity::create(keychain, ndn_security::RecoveryCommitment::Key(rk))
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
            let recovery_signer: Arc<dyn ndn_security::Signer> = Arc::new(
                ndn_security::Ed25519Signer::from_seed(&seed, "/recovery/KEY/r".parse().unwrap()),
            );
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
            let keychain = self.node_principal()?.into_keychain();
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
            let rec = ndn_identity::RevocationRecord::decode(&record).map_err(|e| {
                NdnError::Identity {
                    msg: format!("malformed revocation: {e:?}"),
                }
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
    /// Pass on `event`, a membership change an operation of the library
    /// reported, to the watchers ([`Self::watch_memberships`]).
    pub(crate) fn publish_membership(&self, event: MembershipEvent) {
        // No watcher: nobody to tell.
        let _ = self.memberships.send(event);
    }

    /// Hand each membership change to `handler` as it happens, until the
    /// engine shuts down ([`Self::close`]). Blocking.
    pub(crate) fn watch_memberships(
        &self,
        handler: Box<dyn crate::handlers::NdnMembershipHandler>,
    ) -> Result<bool, NdnError> {
        use tokio::sync::broadcast::error::RecvError;

        let mut events = self.memberships.subscribe();
        self.rt.block_on(async {
            loop {
                tokio::select! {
                    () = self.closed.cancelled() => return,
                    event = events.recv() => match event {
                        Ok(event) => handler.on_membership(crate::types::NdnMembershipEvent::from_event(event)),
                        Err(RecvError::Lagged(missed)) => tracing::warn!(
                            target: "ndn_boltffi::identity",
                            missed,
                            "a membership watcher fell behind and missed changes; read memberships for the current state"
                        ),
                        Err(RecvError::Closed) => return,
                    },
                }
            }
        });
        Ok(true)
    }

    /// The engine shut down: end the membership watches.
    pub(crate) fn close(&self) {
        self.closed.cancel();
    }

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
        let pkcs8 = ndn_security::safebag::ed25519_seed_to_pkcs8(&op_seed).map_err(|e| {
            NdnError::Identity {
                msg: format!("pkcs8: {e}"),
            }
        })?;
        let pubkey = op.public_key().ok_or_else(|| NdnError::Identity {
            msg: "operational key exposes no public key".into(),
        })?;
        let op_arc: Arc<dyn Signer> = Arc::new(op);

        let cert_name: Name =
            format!("{key_name}/self/v=1")
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
        self.add_identity(op_arc)?;

        Ok(NdnRecoveredIdentity {
            key_name: key_name.to_string(),
            cert_name: cert_name.to_string(),
            safebag: safebag.encode().to_vec(),
            bundle: recovered.export_recovery_bundle(),
        })
    }

    /// The node identity as an `Identity` principal.
    fn node_principal(&self) -> Result<ndn_identity::Identity, NdnError> {
        principal_of(self.node_signer()?)
    }
}

/// `signer`'s identity as an `Identity` principal.
#[cfg(feature = "identity")]
fn principal_of(signer: Arc<dyn ndn_security::Signer>) -> Result<ndn_identity::Identity, NdnError> {
    let key_name = signer.key_name().clone();
    let id_name = identity_of_key(&key_name).ok_or_else(|| NdnError::Identity {
        msg: format!("key name {key_name} has no /KEY/ component"),
    })?;
    ndn_identity::Identity::from_signer(id_name, key_name, signer).map_err(NdnError::identity)
}

/// The validity of `cert`, with when to renew it (a third of the lifetime
/// left, the `ndn-fwd` daemon's default).
#[cfg(feature = "identity")]
fn validity(cert: &ndn_security::Certificate) -> NdnCertValidity {
    const NS: u64 = 1_000_000_000;
    let renew_at = ndn_identity::RenewBefore::ONE_THIRD.renew_at(cert.valid_from, cert.valid_until);
    NdnCertValidity {
        cert_name: cert.name.to_string(),
        valid_from_secs: cert.valid_from / NS,
        valid_until_secs: cert.valid_until / NS,
        renew_at_secs: renew_at / NS,
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
        return Err(refused(format!(
            "it is {}, a certificate of another key",
            cert.name
        )));
    }
    if !same_public_key(pubkey, &cert.public_key) {
        return Err(refused(
            "it certifies a different public key than the enclave's".into(),
        ));
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
