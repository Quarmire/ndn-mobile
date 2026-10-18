//! Enrollment by an admin's approval on the app's embedded engine — the
//! same flow as the `ndn-fwd` daemon's (`ndn-fwd enroll <anchor link>
//! --role admin|node`, `ndn-fwd approvals`), on the library calls it makes
//! ([`ndn_identity::request_status_via_engine`],
//! [`ndn_identity::poll_approval_via_engine`],
//! [`ndn_identity::fetch_pending_via_engine`],
//! [`ndn_identity::push_decision_via_engine`]):
//!
//! - **requester**: a fresh key asks the namespace's CA for a role the
//!   namespace's trust context puts under approval; the request is recorded
//!   durably in the app's storage (`<storage_dir>/requests/`,
//!   [`ndn_cert::RequestStore`]) with the key sealed under the host's
//!   password beside it, so the app waits on it to its end across restarts
//!   — with held status Interests at the CA, answered the moment an admin
//!   decides. Asking again while it is pending answers with the same
//!   request.
//! - **approver**: the loaded identity, when it is a current admin
//!   certificate of the namespace, lists what is pending at the CA and
//!   pushes a signed approval or denial.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_cert::approval::{
    STATUS_ANSWER_MARGIN, STATUS_LIFETIME, STATUS_PROBE_LIFETIME, status_hold,
};
use ndn_cert::roles::{Role, device_identity, parse_device_key};
use ndn_cert::{
    AnchorLink, ApprovalPoll, ApprovalPolicy, ApprovalRecord, ApprovalState, Decision,
    InviteLink, OutgoingRequest, OutgoingState, RequestStatus, RequestStore, anchor_fingerprint,
    new_device_key_name,
};
use ndn_packet::Name;
use ndn_security::safebag::SafeBag;
use ndn_security::{Certificate, EcdsaP256Signer, Signer, SignedTrustContext};

use super::IdentityCore;
use crate::types::{
    NdnApprovalOutcome, NdnContext, NdnEnrolledIdentity, NdnEnrollmentRequest, NdnError,
    NdnPendingApproval,
};

/// Where the outgoing requests live under the app's storage directory, as
/// beside the daemon's PIB.
const REQUESTS_DIR: &str = "requests";

fn refused(msg: impl Into<String>) -> NdnError {
    NdnError::Identity { msg: msg.into() }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The request records under `storage_dir`.
fn request_store(storage_dir: &str) -> Result<RequestStore, NdnError> {
    if storage_dir.is_empty() {
        return Err(refused(
            "no storage directory given: pass the app's private files directory, where its \
             requests for an admin's approval are recorded",
        ));
    }
    RequestStore::open(Path::new(storage_dir).join(REQUESTS_DIR)).map_err(|e| {
        refused(format!(
            "cannot open the request records under {storage_dir}: {e}"
        ))
    })
}

fn request_of(r: &OutgoingRequest) -> NdnEnrollmentRequest {
    let detail = match &r.state {
        OutgoingState::Pending => String::new(),
        OutgoingState::Issued { certificate } => certificate.clone(),
        OutgoingState::Denied { reason }
        | OutgoingState::Expired { reason }
        | OutgoingState::Failed { reason } => reason.clone(),
    };
    NdnEnrollmentRequest {
        namespace: r.namespace.clone(),
        ca_prefix: r.ca_prefix.clone(),
        identity: r.identity.clone(),
        key_name: r.key_name.clone(),
        request_id: r.request_id.clone(),
        code: r.code.clone(),
        created_secs: r.created_secs,
        expires_secs: r.expires_secs,
        state: r.state.as_str().to_string(),
        detail,
    }
}

/// The outcome a recorded request that has ended reports.
fn ended_outcome(r: &OutgoingRequest) -> Option<NdnApprovalOutcome> {
    let request = request_of(r);
    match &r.state {
        OutgoingState::Denied { reason } => Some(NdnApprovalOutcome::Denied {
            request,
            reason: reason.clone(),
        }),
        OutgoingState::Expired { reason } => Some(NdnApprovalOutcome::Expired {
            request,
            reason: reason.clone(),
        }),
        OutgoingState::Failed { reason } => Some(NdnApprovalOutcome::Failed {
            request,
            reason: reason.clone(),
        }),
        OutgoingState::Pending | OutgoingState::Issued { .. } => None,
    }
}

/// Save `request`'s new state; a failure is logged (the next poll finds it
/// as it was).
fn record(store: &RequestStore, request: &OutgoingRequest) {
    if let Err(e) = store.save(request) {
        tracing::error!(
            target: "ndn_boltffi::identity",
            request = %request.request_id,
            state = request.state.as_str(),
            error = %e,
            "could not record a request's new state"
        );
    }
}

/// End `outgoing` (its key `key_name`) on the CA's final word `why`: the
/// sealed key is deleted and the record says why (`state`).
fn end(
    store: &RequestStore,
    mut outgoing: OutgoingRequest,
    key_name: &Name,
    why: &str,
    state: impl FnOnce(String) -> OutgoingState,
) -> NdnApprovalOutcome {
    if let Err(removed) = store.remove_sealed_key(&outgoing.key_name) {
        tracing::error!(
            target: "ndn_boltffi::identity",
            key = %key_name,
            error = %removed,
            "could not delete the key of an ended request"
        );
    }
    outgoing.state = state(format!("{why}; the key {key_name} was deleted"));
    record(store, &outgoing);
    ended_outcome(&outgoing).expect("ended")
}

/// The key a request was made with, sealed under the host's password (a
/// password-encrypted PKCS#8 while pending; the SafeBag once issued).
fn seal(pkcs8: &[u8], password: &[u8]) -> Result<Bytes, String> {
    SafeBag::encrypt(Bytes::new(), pkcs8, password)
        .map(|bag| bag.encrypted_key)
        .map_err(|e| e.to_string())
}

/// The PKCS#8 of a sealed request key: a SafeBag (issued) or a bare
/// password-encrypted PKCS#8 (pending).
fn unseal(sealed: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let bag = SafeBag::decode(sealed).unwrap_or_else(|_| SafeBag {
        certificate: Bytes::new(),
        encrypted_key: Bytes::copy_from_slice(sealed),
    });
    bag.decrypt_pkcs8(password).map_err(|e| e.to_string())
}

/// The link a request was asked with.
enum EnrollLink {
    /// `ndn-trust://invite`: for a namespace that certifies the role on an
    /// invite AND an admin's approval.
    Invite(InviteLink),
    /// `ndn-trust://anchor`: the namespace and its root's expected
    /// fingerprint.
    Anchor(AnchorLink),
}

impl EnrollLink {
    fn parse(uri: &str) -> Result<Self, NdnError> {
        if let Ok(invite) = InviteLink::from_uri(uri) {
            return Ok(Self::Invite(invite));
        }
        AnchorLink::from_uri(uri).map(Self::Anchor).map_err(|e| {
            refused(format!(
                "the link is neither an anchor link nor an invite ({e}): pass the namespace's \
                 ndn-trust://anchor link (its root device prints it as anchor_uri)"
            ))
        })
    }

    fn namespace(&self) -> &Name {
        match self {
            Self::Invite(invite) => &invite.namespace,
            Self::Anchor(anchor) => &anchor.namespace,
        }
    }

    fn expected_fingerprint(&self) -> Option<[u8; 32]> {
        match self {
            Self::Invite(invite) => invite.expected_fingerprint,
            Self::Anchor(anchor) => Some(anchor.expected_fingerprint),
        }
    }
}

/// The admin key that decides, with what the CA needs to check it.
struct AdminCredential {
    namespace: Name,
    ca_prefix: Name,
    signer: Arc<dyn Signer>,
    chain: Vec<Bytes>,
}

impl IdentityCore {
    fn held_context(&self, namespace: &Name) -> Option<Arc<SignedTrustContext>> {
        self.keyring
            .contexts()
            .into_iter()
            .find(|c| c.namespace() == namespace)
    }

    /// Hold the trust context of the namespace `link` names: adopt it when
    /// it is not held (the link must name its root's expected fingerprint),
    /// else check the held one is signed by the root the link expects.
    /// `Some`: the context adopted now.
    fn ensure_context(
        &self,
        engine: &ndn_app::ForwarderEngine,
        link: &EnrollLink,
    ) -> Result<Option<NdnContext>, NdnError> {
        let namespace = link.namespace();
        let expected = link.expected_fingerprint();
        if let Some(held) = self.held_context(namespace) {
            let Some(expected) = expected else {
                return Ok(None);
            };
            let fingerprints: Vec<[u8; 32]> = held
                .anchors()
                .iter()
                .map(|a| anchor_fingerprint(a.value()))
                .collect();
            if fingerprints.contains(&expected) {
                return Ok(None);
            }
            return Err(refused(format!(
                "the trust context this app holds for {namespace} is signed by a different root \
                 than the link expects: check where the link came from; the app keeps the \
                 context it holds"
            )));
        }
        let Some(expected_fingerprint) = expected else {
            return Err(refused(format!(
                "this app holds no trust context for {namespace} and the invite names no \
                 expected fingerprint to adopt it with: adopt the namespace's anchor link first \
                 (adopt_context_link)"
            )));
        };
        let from_invite;
        let anchor = match link {
            EnrollLink::Anchor(anchor) => anchor,
            EnrollLink::Invite(_) => {
                from_invite = AnchorLink {
                    namespace: namespace.clone(),
                    expected_fingerprint,
                    min_version: None,
                    context_data: None,
                };
                &from_invite
            }
        };
        let adopted = self
            .rt
            .block_on(ndn_identity::adopt_anchor_link_via_engine(
                engine,
                &self.keyring,
                anchor,
            ))
            .map_err(|e| refused(format!("trust context refused: {e}")))?;
        Ok(Some(NdnContext::adopted(
            &adopted.context,
            &adopted.data,
            &expected_fingerprint,
        )))
    }

    // ── Requester ──────────────────────────────────────────────────────

    /// Ask the CA of the namespace `link_uri` names to certify a new key of
    /// this device as `<ns>/<role>/<device>` on an admin's approval. See
    /// [`NdnEngine::request_enrollment`](crate::NdnEngine::request_enrollment).
    pub(crate) fn request_enrollment(
        &self,
        engine: &ndn_app::ForwarderEngine,
        storage_dir: String,
        link_uri: String,
        role: String,
        device: String,
        persist_password: Vec<u8>,
    ) -> Result<NdnApprovalOutcome, NdnError> {
        let store = request_store(&storage_dir)?;
        let link = EnrollLink::parse(&link_uri)?;
        let namespace = link.namespace().clone();
        let role: Role = role.parse().map_err(|e| {
            refused(format!("{e}: ask as admin or node (the roles a namespace certifies on an admin's approval)"))
        })?;
        let identity = device_identity(&namespace, role, &device)
            .map_err(|e| refused(format!("enrollment refused: {e}")))?;

        let adopted = self.ensure_context(engine, &link)?;
        let fail = |msg: String| NdnError::EnrollmentFailed {
            msg,
            adopted_context: adopted.clone(),
        };
        let ctx = self
            .held_context(&namespace)
            .ok_or_else(|| fail(format!("no trust context is held for {namespace}")))?;
        let policy = ApprovalPolicy::of_context(&ctx);
        if !policy.roles.contains(&role) {
            return Err(fail(format!(
                "{namespace} certifies {role} devices by invite, not on an admin's approval \
                 ({}): ask an admin for a {role} invite and enroll with it (enroll_with_invite)",
                policy.describe()
            )));
        }
        let token = match (&link, policy.invite_also) {
            (EnrollLink::Invite(invite), true) => Some(invite.token.clone()),
            (EnrollLink::Anchor(_), true) => {
                return Err(fail(format!(
                    "{namespace} certifies a {role} device only on an invite AND an admin's \
                     approval: ask an admin for a {role} invite and pass its link here"
                )));
            }
            (_, false) => None,
        };

        let outstanding = store
            .outstanding(&identity.to_string())
            .map_err(|e| fail(format!("cannot read this app's request records: {e}")))?;
        if let Some(outstanding) = outstanding {
            return Ok(NdnApprovalOutcome::Pending {
                request: request_of(&outstanding),
                detail: String::new(),
                adopted_context: adopted,
            });
        }

        let ca_prefix = match &link {
            EnrollLink::Invite(invite) => invite.ca_prefix.clone(),
            EnrollLink::Anchor(_) => ndn_cert::approval::ca_prefix_of(&ctx),
        };
        let key_name = new_device_key_name(&identity);
        let key = EcdsaP256Signer::generate(key_name.clone())
            .map_err(|e| fail(format!("device key: {e}")))?;
        let pkcs8 = key
            .to_pkcs8_der()
            .map_err(|e| fail(format!("device key: {e}")))?;
        let poll = self.rt.block_on(ndn_identity::poll_approval_via_engine(
            engine,
            &self.keyring,
            &namespace,
            &ca_prefix,
            Arc::new(key),
            None,
            token.as_deref(),
        ));
        match poll {
            Ok(ApprovalPoll::Pending(pending)) => {
                let request = OutgoingRequest {
                    namespace: namespace.to_string(),
                    ca_prefix: ca_prefix.to_string(),
                    identity: identity.to_string(),
                    key_name: key_name.to_string(),
                    request_id: pending.request_id,
                    code: pending.code,
                    created_secs: now_secs(),
                    expires_secs: pending.expires_secs,
                    state: OutgoingState::Pending,
                };
                // The key first: a record whose key is missing could never
                // finish.
                let kept = seal(&pkcs8, &persist_password)
                    .and_then(|sealed| {
                        store
                            .save_sealed_key(&request.key_name, &sealed)
                            .map_err(|e| e.to_string())
                    })
                    .and_then(|()| store.save(&request).map_err(|e| e.to_string()));
                if let Err(e) = kept {
                    let _ = store.remove_sealed_key(&request.key_name);
                    return Err(fail(format!(
                        "the CA holds request {} (code {}), but this app could not record it \
                         ({e}), so it would never finish it: the key was deleted. Fix the \
                         storage directory ({storage_dir}) and ask again; an admin can deny \
                         request {}",
                        request.request_id, request.code, request.request_id
                    )));
                }
                Ok(NdnApprovalOutcome::Pending {
                    request: request_of(&request),
                    detail: String::new(),
                    adopted_context: adopted,
                })
            }
            Ok(ApprovalPoll::Issued(issued)) => {
                let identity_out = self.install_issued(
                    &key_name,
                    &pkcs8,
                    &issued,
                    &persist_password,
                    adopted.clone(),
                )?;
                let request = OutgoingRequest {
                    namespace: namespace.to_string(),
                    ca_prefix: ca_prefix.to_string(),
                    identity: identity.to_string(),
                    key_name: key_name.to_string(),
                    request_id: String::new(),
                    code: String::new(),
                    created_secs: now_secs(),
                    expires_secs: 0,
                    state: OutgoingState::Issued {
                        certificate: issued.cert.name.to_string(),
                    },
                };
                Ok(NdnApprovalOutcome::Issued {
                    request: request_of(&request),
                    identity: identity_out,
                })
            }
            Err(e) => Err(fail(format!(
                "request for an admin's approval refused: {e}; nothing was kept for the new key"
            ))),
        }
    }

    /// Wait up to `wait_secs` for the CA's decision on the recorded request
    /// `request` (its id or key name). See
    /// [`NdnEngine::poll_enrollment`](crate::NdnEngine::poll_enrollment).
    pub(crate) fn poll_enrollment(
        &self,
        engine: &ndn_app::ForwarderEngine,
        storage_dir: String,
        request: String,
        wait_secs: u32,
        persist_password: Vec<u8>,
    ) -> Result<NdnApprovalOutcome, NdnError> {
        let store = request_store(&storage_dir)?;
        let mut outgoing = store
            .list()
            .map_err(|e| refused(format!("cannot read this app's request records: {e}")))?
            .into_iter()
            .find(|r| r.request_id == request || r.key_name == request)
            .ok_or_else(|| {
                refused(format!(
                    "no request {request} is recorded under {storage_dir}: list them with \
                     enrollment_requests, or ask again (request_enrollment)"
                ))
            })?;
        if let Some(ended) = ended_outcome(&outgoing) {
            return Ok(ended);
        }
        let parsed = (
            outgoing.namespace.parse::<Name>(),
            outgoing.ca_prefix.parse::<Name>(),
            outgoing.key_name.parse::<Name>(),
        );
        let (Ok(namespace), Ok(ca_prefix), Ok(key_name)) = parsed else {
            outgoing.state = OutgoingState::Failed {
                reason: "the request record names no valid namespace, CA or key; ask again \
                         (request_enrollment)"
                    .into(),
            };
            record(&store, &outgoing);
            return Ok(ended_outcome(&outgoing).expect("failed"));
        };
        let sealed = match store.sealed_key(&outgoing.key_name) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => {
                outgoing.state = OutgoingState::Failed {
                    reason: format!(
                        "the key {key_name} of this request is gone from {storage_dir}; nothing \
                         can be certified for it: ask again (request_enrollment)"
                    ),
                };
                record(&store, &outgoing);
                return Ok(ended_outcome(&outgoing).expect("failed"));
            }
            Err(e) => {
                return Err(refused(format!(
                    "cannot read the key of request {}: {e}; poll again once the storage \
                     directory is readable",
                    outgoing.request_id
                )));
            }
        };
        let pkcs8 = unseal(&sealed, &persist_password).map_err(|e| {
            refused(format!(
                "the key of request {} does not open with this password ({e}); pass the \
                 password the request was made with",
                outgoing.request_id
            ))
        })?;

        // Issued earlier, and the outcome may not have reached the host:
        // load it again from the SafeBag kept for it.
        if let OutgoingState::Issued { .. } = &outgoing.state {
            return self.reissued(&storage_dir, &outgoing, &sealed, &pkcs8, &key_name);
        }

        let signer = EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name.clone())
            .map_err(|e| refused(format!("device key: {e}")))?;

        // Held status Interests until the CA says the request is decided or
        // expired, or until `wait_secs` end.
        let deadline = Instant::now() + Duration::from_secs(wait_secs.into());
        let mut retry = Duration::from_secs(1);
        let mut not_reached: Option<String> = None;
        // After an early answer (the CA stopped) or none: short Interests
        // until the CA holds one again.
        let mut probing = false;
        let decided = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // At least the answer margin: the CA answers that at once.
            let longest = if probing { STATUS_PROBE_LIFETIME } else { STATUS_LIFETIME };
            let lifetime = remaining.min(longest).max(STATUS_ANSWER_MARGIN);
            let asked = Instant::now();
            let status = self.rt.block_on(ndn_identity::request_status_via_engine(
                engine,
                &self.keyring,
                &namespace,
                &ca_prefix,
                &outgoing.request_id,
                &outgoing.key_name,
                lifetime,
            ));
            let early = match status {
                Ok(RequestStatus::Pending { expires_secs, .. }) => {
                    not_reached = None;
                    if expires_secs != outgoing.expires_secs && expires_secs != 0 {
                        outgoing.expires_secs = expires_secs;
                        record(&store, &outgoing);
                    }
                    // Answered well before the CA's hold: never loop fast.
                    asked.elapsed() < status_hold(Some(lifetime)) / 2
                }
                Ok(decided) => break Some(decided),
                Err(e) => {
                    not_reached = Some(e.to_string());
                    true
                }
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining <= STATUS_ANSWER_MARGIN || (early && remaining <= retry) {
                break None;
            }
            probing = early;
            if early {
                self.rt.block_on(tokio::time::sleep(retry));
                retry = (retry * 2).min(STATUS_LIFETIME);
            }
        };
        match decided {
            None => {
                return Ok(NdnApprovalOutcome::Pending {
                    request: request_of(&outgoing),
                    detail: not_reached
                        .map(|e| format!("{e}; poll again later"))
                        .unwrap_or_default(),
                    adopted_context: None,
                });
            }
            Some(RequestStatus::Denied { reason, .. }) => {
                return Ok(end(&store, outgoing, &key_name, &reason, |reason| {
                    OutgoingState::Denied { reason }
                }));
            }
            Some(RequestStatus::Expired { reason, .. }) => {
                return Ok(end(&store, outgoing, &key_name, &reason, |reason| {
                    OutgoingState::Expired { reason }
                }));
            }
            // Approved.
            Some(_) => {}
        }

        // Approved: the issuance exchange, now.
        let poll = self.rt.block_on(ndn_identity::poll_approval_via_engine(
            engine,
            &self.keyring,
            &namespace,
            &ca_prefix,
            Arc::new(signer),
            Some(&outgoing.request_id),
            None,
        ));
        match poll {
            Ok(ApprovalPoll::Pending(_)) => Ok(NdnApprovalOutcome::Pending {
                request: request_of(&outgoing),
                detail: String::new(),
                adopted_context: None,
            }),
            Ok(ApprovalPoll::Issued(issued)) => {
                let identity = self.install_issued(
                    &key_name,
                    &pkcs8,
                    &issued,
                    &persist_password,
                    None,
                )?;
                // Kept so a poll after a restart reports it again: the bag
                // in place of the bare key, the issuer chain beside the
                // records (`<storage_dir>/issuers`, as beside a PIB).
                if let Err(e) = store
                    .save_sealed_key(&outgoing.key_name, &identity.safebag)
                    .map_err(|e| e.to_string())
                    .and_then(|()| {
                        ndn_cert::issuers::keep_issuer_certs(Path::new(&storage_dir), &issued.issuers)
                            .map(drop)
                            .map_err(|e| e.to_string())
                    })
                {
                    tracing::warn!(
                        target: "ndn_boltffi::identity",
                        request = %outgoing.request_id,
                        error = %e,
                        "issued, but the certificate was not kept beside the request; persist the outcome's SafeBag"
                    );
                }
                outgoing.state = OutgoingState::Issued {
                    certificate: issued.cert.name.to_string(),
                };
                record(&store, &outgoing);
                Ok(NdnApprovalOutcome::Issued {
                    request: request_of(&outgoing),
                    identity,
                })
            }
            Err(e) if !e.is_final() => Ok(NdnApprovalOutcome::Pending {
                request: request_of(&outgoing),
                detail: format!("{e}; poll again later"),
                adopted_context: None,
            }),
            Err(e) => Ok(end(&store, outgoing, &key_name, &e.to_string(), |reason| {
                OutgoingState::ended(&e, reason)
            })),
        }
    }

    /// The `Issued` outcome of a request issued at an earlier poll, loaded
    /// again from the SafeBag kept for it (the identity becomes the loaded
    /// one).
    fn reissued(
        &self,
        storage_dir: &str,
        outgoing: &OutgoingRequest,
        sealed: &[u8],
        pkcs8: &[u8],
        key_name: &Name,
    ) -> Result<NdnApprovalOutcome, NdnError> {
        let lost = |why: String| {
            refused(format!(
                "request {} was issued, but {why}: ask again (request_enrollment)",
                outgoing.request_id
            ))
        };
        let bag = SafeBag::decode(sealed).map_err(|e| lost(format!("its SafeBag is unreadable ({e})")))?;
        let data = ndn_packet::Data::decode(bag.certificate.clone())
            .map_err(|e| lost(format!("its certificate is unreadable ({e})")))?;
        let cert = Certificate::decode(&data)
            .map_err(|e| lost(format!("its certificate is unreadable ({e})")))?;
        let kept = ndn_cert::issuers::stored_issuer_certs(Path::new(storage_dir));
        let issuers: Vec<Vec<u8>> = ndn_cert::approval::admin_chain(&data, &cert, &kept)
            .into_iter()
            .skip(1)
            .map(|wire| wire.to_vec())
            .collect();
        let signer = EcdsaP256Signer::from_pkcs8_der(pkcs8, key_name.clone())
            .map_err(|e| refused(format!("device key: {e}")))?;
        self.record_cert(data.raw());
        *self.identity.lock().unwrap() = Some(Arc::new(signer));
        Ok(NdnApprovalOutcome::Issued {
            request: request_of(outgoing),
            identity: NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: cert.name.to_string(),
                certificate: Some(data.raw().to_vec()),
                safebag: sealed.to_vec(),
                adopted_context: None,
                issuers,
            },
        })
    }

    /// The requests for an admin's approval recorded under `storage_dir`,
    /// oldest first.
    pub(crate) fn enrollment_requests(
        &self,
        storage_dir: String,
    ) -> Result<Vec<NdnEnrollmentRequest>, NdnError> {
        let store = request_store(&storage_dir)?;
        store
            .list()
            .map(|list| list.iter().map(request_of).collect())
            .map_err(|e| refused(format!("cannot read this app's request records: {e}")))
    }

    // ── Approver ───────────────────────────────────────────────────────

    /// The loaded identity as an admin of its namespace, or why it decides
    /// nothing. `issuers`: the issuer certificates persisted with it.
    fn admin_credential(&self, issuers: Vec<Vec<u8>>) -> Result<AdminCredential, NdnError> {
        let signer = self.identity.lock().unwrap().clone().ok_or_else(|| {
            refused(
                "no identity is loaded: load this device's admin identity (its SafeBag) before \
                 listing or deciding requests",
            )
        })?;
        let key = signer.key_name().clone();
        let found = self.keyring.contexts().into_iter().find_map(|ctx| {
            parse_device_key(ctx.namespace(), &key).map(|device| (ctx, device))
        });
        let Some((ctx, device)) = found else {
            return Err(refused(format!(
                "the loaded identity {key} is not a device key of a namespace whose trust \
                 context this app holds: adopt the namespace's context (adopt_context) and load \
                 its admin identity"
            )));
        };
        let namespace = ctx.namespace().clone();
        if device.role != Role::Admin {
            return Err(refused(format!(
                "the loaded identity {key} is a {} device of {namespace}, not an admin: only an \
                 admin's key decides requests. Decide on an admin device of {namespace} or on its \
                 root device (`ndn-fwd approvals`)",
                device.role
            )));
        }
        let wire = self.require_cert_wire()?;
        let data = ndn_packet::Data::decode(wire)
            .map_err(|e| refused(format!("the admin certificate is unreadable: {e}")))?;
        let cert = Certificate::decode(&data)
            .map_err(|e| refused(format!("the admin certificate is unreadable: {e}")))?;
        if !cert.is_valid_now() {
            return Err(refused(format!(
                "the admin certificate {} is not valid now: renew it (renew_certificate) before \
                 deciding requests",
                cert.name
            )));
        }
        if self.keyring.context_for(&cert.name).is_revoked(&cert.name) {
            return Err(refused(format!(
                "the admin certificate {} is revoked in {namespace}'s trust context: it decides \
                 nothing; ask an admin to enroll this device again",
                cert.name
            )));
        }
        let ca_prefix = ndn_cert::issuing_ca_prefix(&cert).ok_or_else(|| {
            refused(format!(
                "the admin certificate {} names no CA of {namespace} as its issuer",
                cert.name
            ))
        })?;
        let kept: Vec<Bytes> = issuers.into_iter().map(Bytes::from).collect();
        let chain = ndn_cert::approval::admin_chain(&data, &cert, &kept);
        Ok(AdminCredential {
            namespace,
            ca_prefix,
            signer,
            chain,
        })
    }

    fn fetch_pending(
        &self,
        engine: &ndn_app::ForwarderEngine,
        cred: &AdminCredential,
    ) -> Result<Vec<ApprovalRecord>, NdnError> {
        self.rt
            .block_on(ndn_identity::fetch_pending_via_engine(
                engine,
                &self.keyring,
                &cred.namespace,
                &cred.ca_prefix,
                &cred.signer,
                &cred.chain,
            ))
            .map_err(|e| refused(format!("listing at {}: {e}", cred.ca_prefix)))
    }

    /// The requests pending at the loaded admin identity's CA. See
    /// [`NdnEngine::list_pending_approvals`](crate::NdnEngine::list_pending_approvals).
    pub(crate) fn list_pending_approvals(
        &self,
        engine: &ndn_app::ForwarderEngine,
        issuers: Vec<Vec<u8>>,
    ) -> Result<Vec<NdnPendingApproval>, NdnError> {
        let cred = self.admin_credential(issuers)?;
        Ok(self
            .fetch_pending(engine, &cred)?
            .iter()
            .map(pending_approval)
            .collect())
    }

    /// Approve (`reason` `None`) or deny the pending request `target` (its
    /// id or verification code) as the loaded admin identity.
    pub(crate) fn decide_request(
        &self,
        engine: &ndn_app::ForwarderEngine,
        target: String,
        decision: Decision,
        issuers: Vec<Vec<u8>>,
    ) -> Result<NdnPendingApproval, NdnError> {
        let cred = self.admin_credential(issuers)?;
        let pending = self.fetch_pending(engine, &cred)?;
        let record = ndn_cert::approval::find_pending_in(&pending, &target).map_err(|r| {
            refused(format!(
                "{} (at {}): check the code on the new device against list_pending_approvals; a \
                 request that expired or was decided is not pending",
                r.reason, cred.ca_prefix
            ))
        })?;
        self.rt
            .block_on(ndn_identity::push_decision_via_engine(
                engine,
                &self.keyring,
                &cred.namespace,
                &record,
                &decision,
                &cred.signer,
                &cred.chain,
            ))
            .map(|r| pending_approval(&r))
            .map_err(|e| refused(format!("deciding at {}: {e}", cred.ca_prefix)))
    }
}

fn pending_approval(r: &ApprovalRecord) -> NdnPendingApproval {
    let (approver, reason) = match &r.state {
        ApprovalState::Pending => (String::new(), String::new()),
        ApprovalState::Approved { by, .. } => (by.describe(), String::new()),
        ApprovalState::Denied { by, reason, .. } => (by.describe(), reason.clone()),
    };
    NdnPendingApproval {
        request_id: r.request_id.clone(),
        key_name: r.key_name.clone(),
        namespace: r.ca_prefix.clone(),
        role: r.role.clone().unwrap_or_default(),
        device: r.device.clone().unwrap_or_default(),
        code: r.code.clone(),
        state: r.state.as_str().to_string(),
        created_secs: r.created_secs,
        expires_secs: r.expires_secs,
        approver,
        reason,
    }
}
