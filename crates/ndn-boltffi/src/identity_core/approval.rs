//! Enrollment by an admin's approval on the app's embedded engine — the
//! same flow as the `ndn-fwd` daemon's (`ndn-fwd enroll <anchor link>
//! --role admin|node`, `ndn-fwd approvals`), on the same library
//! ([`ndn_namespace::enroll`], [`ndn_namespace::approval_wait`],
//! [`ndn_namespace::approver`]):
//!
//! - **requester**: a fresh key asks the namespace's CA for a role the
//!   namespace's trust context puts under approval; the request is recorded
//!   durably in the app's storage (`<storage_dir>/requests/`,
//!   [`ndn_cert::RequestStore`]) with the key sealed under the host's
//!   password beside it ([`super::host::AppVault`]), so the app waits on it
//!   to its end across restarts — with held status Interests at the CA,
//!   answered the moment an admin decides. Asking again while it is pending
//!   answers with the same request.
//! - **approver**: each identity of the app that is a current admin
//!   certificate of a namespace lists what is pending at that namespace's
//!   CA and pushes a signed approval or denial.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_cert::roles::{Role, device_identity, parse_device_key};
use ndn_cert::{ApprovalRecord, ApprovalState, Decision, OutgoingRequest, OutgoingState};
use ndn_namespace::approval_wait::Waited;
use ndn_namespace::approver::{AdminCredential, admin_credentials};
use ndn_namespace::enroll::{Enrolling, Route};
use ndn_namespace::{EnrollOutcome, KeyVault, TrustRefusal};
use ndn_packet::Name;
use ndn_security::Certificate;
use ndn_security::safebag::SafeBag;
use tokio_util::sync::CancellationToken;

use super::IdentityCore;
use super::host::{
    AppContexts, AppParticipant, AppVault, app_detail, app_text, request_store, unseal,
};
use crate::types::{
    NdnApprovalOutcome, NdnEnrolledIdentity, NdnEnrollmentRequest, NdnError, NdnPendingApproval,
};

fn refused(msg: impl Into<String>) -> NdnError {
    NdnError::Identity { msg: msg.into() }
}

fn request_of(r: &OutgoingRequest) -> NdnEnrollmentRequest {
    let detail = match &r.state {
        OutgoingState::Pending => String::new(),
        OutgoingState::Issued { certificate } => certificate.clone(),
        OutgoingState::Denied { reason }
        | OutgoingState::Expired { reason }
        | OutgoingState::Failed { reason } => app_detail(reason),
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
            reason: app_detail(reason),
        }),
        OutgoingState::Expired { reason } => Some(NdnApprovalOutcome::Expired {
            request,
            reason: app_detail(reason),
        }),
        OutgoingState::Failed { reason } => Some(NdnApprovalOutcome::Failed {
            request,
            reason: app_detail(reason),
        }),
        OutgoingState::Pending | OutgoingState::Issued { .. } => None,
    }
}

impl IdentityCore {
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
        request_store(&storage_dir).map_err(refused)?;
        let link =
            ndn_namespace::enroll::parse_link(&link_uri).map_err(|e| refused(app_text(&e)))?;
        let namespace = link.namespace().clone();
        let role: Role = role.parse().map_err(|e| {
            refused(format!(
                "{e}: ask as admin or node (the roles a namespace certifies on an admin's approval)"
            ))
        })?;
        let identity = device_identity(&namespace, role, &device)
            .map_err(|e| refused(format!("enrollment refused: {e}")))?;

        let contexts = Arc::new(AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let vault = AppVault::new(self, storage_dir, persist_password);
        let failed = |msg: String| NdnError::EnrollmentFailed {
            msg,
            adopted_context: contexts.newest(&namespace),
        };
        let fail = |e: TrustRefusal| failed(app_text(&e));
        let adopted = self
            .rt
            .block_on(ndn_namespace::enroll::ensure_context(&participant, &link))
            .map_err(fail)?;
        let (ca_prefix, token) =
            match ndn_namespace::enroll::route(&participant, &link, role).map_err(fail)? {
                Route::Approval { ca_prefix, token } => (ca_prefix, token),
                Route::Invite => {
                    return Err(failed(format!(
                        "{namespace} certifies {role} devices by invite, not on an admin's \
                         approval: enroll with the invite (enroll_with_invite)"
                    )));
                }
            };
        let enrolling = Enrolling {
            namespace: namespace.clone(),
            identity: identity.clone(),
            previous_identity: None,
            adopted_context: adopted,
            context_check: None,
        };
        let outcome = self
            .rt
            .block_on(ndn_namespace::enroll::enroll_by_approval(
                &participant,
                &vault,
                &ca_prefix,
                role,
                token,
                enrolling,
            ))
            .map_err(fail)?;
        let adopted_context = contexts.newest(&namespace);
        match outcome {
            EnrollOutcome::Pending(pending) => {
                let request = vault
                    .request_store()
                    .ok()
                    .and_then(|store| store.list().ok())
                    .and_then(|list| list.into_iter().find(|r| r.key_name == pending.key))
                    .map(|r| request_of(&r))
                    .unwrap_or_else(|| NdnEnrollmentRequest {
                        namespace: pending.namespace,
                        ca_prefix: pending.ca,
                        identity: pending.identity,
                        key_name: pending.key,
                        request_id: pending.request,
                        code: pending.code,
                        created_secs: 0,
                        expires_secs: 0,
                        state: OutgoingState::Pending.as_str().to_string(),
                        detail: String::new(),
                    });
                Ok(NdnApprovalOutcome::Pending {
                    request,
                    detail: String::new(),
                    adopted_context,
                })
            }
            EnrollOutcome::Enrolled(enrolled) => {
                let identity_out = vault
                    .installed(adopted_context)
                    .ok_or_else(|| refused("the issued certificate was not installed"))?;
                let request = OutgoingRequest {
                    namespace: namespace.to_string(),
                    ca_prefix: ca_prefix.to_string(),
                    identity: identity.to_string(),
                    key_name: enrolled.key,
                    request_id: String::new(),
                    code: String::new(),
                    created_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    expires_secs: 0,
                    state: OutgoingState::Issued {
                        certificate: enrolled.certificate,
                    },
                };
                Ok(NdnApprovalOutcome::Issued {
                    request: request_of(&request),
                    identity: identity_out,
                })
            }
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
        let deadline = Instant::now() + Duration::from_secs(wait_secs.into());
        let vault = AppVault::new(self, storage_dir.clone(), persist_password.clone());
        let contexts = Arc::new(AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let outgoing = ndn_namespace::enroll::enroll_status(&participant, &vault)
            .map_err(|e| refused(app_text(&e)))?
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
        let store = request_store(&storage_dir).map_err(refused)?;
        // The key opens with this password before anything is asked; a key
        // gone from storage ends the request (the library records why).
        if let Ok(Some(sealed)) = store.sealed_key(&outgoing.key_name) {
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
                return self.reissued(&storage_dir, &outgoing, &sealed, &pkcs8);
            }
        }

        let waited = self
            .rt
            .block_on(ndn_namespace::approval_wait::wait_for_decision(
                &participant,
                &vault,
                &outgoing.key_name,
                Some(deadline),
                &CancellationToken::new(),
            ));
        match waited {
            Waited::Pending {
                request,
                not_reached,
            } => Ok(NdnApprovalOutcome::Pending {
                request: request_of(&request),
                detail: not_reached
                    .map(|e| format!("{e}; poll again later"))
                    .unwrap_or_default(),
                adopted_context: None,
            }),
            Waited::Ended(request) => match ended_outcome(&request) {
                Some(ended) => Ok(ended),
                None => {
                    let identity = vault.installed(None).ok_or_else(|| {
                        refused(format!(
                            "request {} was issued earlier: poll again to load it",
                            request.request_id
                        ))
                    })?;
                    Ok(NdnApprovalOutcome::Issued {
                        request: request_of(&request),
                        identity,
                    })
                }
            },
            Waited::NotRecorded => Err(refused(format!(
                "no request {request} is recorded under {storage_dir}: list them with \
                 enrollment_requests, or ask again (request_enrollment)"
            ))),
            Waited::Unreadable(e) => Err(refused(format!(
                "cannot read this app's request records: {e}; poll again once the storage \
                 directory is readable"
            ))),
        }
    }

    /// The `Issued` outcome of a request issued at an earlier poll, loaded
    /// again from the SafeBag kept for it (the identity is added beside the
    /// app's others).
    fn reissued(
        &self,
        storage_dir: &str,
        outgoing: &OutgoingRequest,
        sealed: &[u8],
        pkcs8: &[u8],
    ) -> Result<NdnApprovalOutcome, NdnError> {
        let lost = |why: String| {
            refused(format!(
                "request {} was issued, but {why}: ask again (request_enrollment)",
                outgoing.request_id
            ))
        };
        let key_name: Name = outgoing
            .key_name
            .parse()
            .map_err(|_| lost("its record names no valid key".into()))?;
        let bag = SafeBag::decode(sealed)
            .map_err(|e| lost(format!("its SafeBag is unreadable ({e})")))?;
        let data = ndn_packet::Data::decode(bag.certificate.clone())
            .map_err(|e| lost(format!("its certificate is unreadable ({e})")))?;
        let cert = Certificate::decode(&data)
            .map_err(|e| lost(format!("its certificate is unreadable ({e})")))?;
        let kept = ndn_cert::issuers::stored_issuer_certs(std::path::Path::new(storage_dir));
        let issuers: Vec<Vec<u8>> = ndn_cert::approval::admin_chain(&data, &cert, &kept)
            .into_iter()
            .skip(1)
            .map(|wire| wire.to_vec())
            .collect();
        let signer = ndn_security::EcdsaP256Signer::from_pkcs8_der(pkcs8, key_name.clone())
            .map_err(|e| refused(format!("device key: {e}")))?;
        self.record_cert(data.raw());
        let node_identity = self.add_identity(Arc::new(signer))?;
        Ok(NdnApprovalOutcome::Issued {
            request: request_of(outgoing),
            identity: NdnEnrolledIdentity {
                key_name: key_name.to_string(),
                cert_name: cert.name.to_string(),
                certificate: Some(data.raw().to_vec()),
                safebag: sealed.to_vec(),
                adopted_context: None,
                issuers,
                node_identity,
            },
        })
    }

    /// The requests for an admin's approval recorded under `storage_dir`,
    /// oldest first.
    pub(crate) fn enrollment_requests(
        &self,
        engine: &ndn_app::ForwarderEngine,
        storage_dir: String,
    ) -> Result<Vec<NdnEnrollmentRequest>, NdnError> {
        let contexts = Arc::new(AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let vault = AppVault::new(self, storage_dir, Vec::new());
        ndn_namespace::enroll::enroll_status(&participant, &vault)
            .map(|list| list.iter().map(request_of).collect())
            .map_err(|e| refused(app_text(&e)))
    }

    // ── Approver ───────────────────────────────────────────────────────

    /// The app's identities that are admins of a namespace whose trust
    /// context it holds, one per namespace
    /// ([`ndn_namespace::approver::admin_credentials`] over every identity
    /// the app holds), or why none decides anything. `issuers`: the issuer
    /// certificates persisted with the admin identities.
    fn admin_credentials(
        &self,
        engine: &ndn_app::ForwarderEngine,
        issuers: Vec<Vec<u8>>,
    ) -> Result<(AppParticipant<'_>, Vec<AdminCredential>), NdnError> {
        if !self.has_identity() {
            return Err(refused(
                "no identity is loaded: load this device's admin identity (its SafeBag) before \
                 listing or deciding requests",
            ));
        }
        let vault = AppVault::with_issuers(self, issuers);
        let contexts = Arc::new(AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let creds =
            admin_credentials(&participant, &vault, &[]).map_err(|e| refused(app_text(&e)))?;
        if !creds.is_empty() {
            return Ok((participant, creds));
        }
        // Why each identity decides nothing.
        let why: Vec<String> = vault
            .keys()
            .unwrap_or_default()
            .iter()
            .map(|key| {
                let found = self.keyring.contexts().into_iter().find_map(|ctx| {
                    parse_device_key(ctx.namespace(), key).map(|device| (ctx, device))
                });
                match found {
                    None => format!(
                        "{key} is not a device key of a namespace whose trust context this app \
                         holds (adopt the namespace's context with adopt_context)"
                    ),
                    Some((ctx, device)) if device.role != Role::Admin => format!(
                        "{key} is a {} device of {}, not an admin",
                        device.role,
                        ctx.namespace()
                    ),
                    Some((ctx, _)) => format!(
                        "{key}'s admin certificate of {ns} is not valid now, its trust context \
                         revokes it, or it names no CA of {ns} as its issuer (renew it with \
                         renew_certificate, or ask an admin to enroll this device again)",
                        ns = ctx.namespace()
                    ),
                }
            })
            .collect();
        Err(refused(format!(
            "no identity of this app decides requests: {}. Only an admin's key decides \
             requests: decide on an admin device of the namespace or on its root device \
             (`ndn-fwd approvals`)",
            why.join("; ")
        )))
    }

    /// The requests pending at the loaded admin identity's CA. See
    /// [`NdnEngine::list_pending_approvals`](crate::NdnEngine::list_pending_approvals).
    pub(crate) fn list_pending_approvals(
        &self,
        engine: &ndn_app::ForwarderEngine,
        issuers: Vec<Vec<u8>>,
    ) -> Result<Vec<NdnPendingApproval>, NdnError> {
        let (participant, creds) = self.admin_credentials(engine, issuers)?;
        let listing = self
            .rt
            .block_on(ndn_namespace::approver::list(&participant, &[], || {
                Ok(creds)
            }))
            .map_err(|e| refused(app_text(&e)))?;
        if let Some(note) = listing.notes.first()
            && listing.records.is_empty()
        {
            return Err(refused(app_detail(note)));
        }
        Ok(listing.records.iter().map(pending_approval).collect())
    }

    /// Approve (`reason` `None`) or deny the pending request `target` (its
    /// id or verification code) as the app's admin identity of its namespace.
    pub(crate) fn decide_request(
        &self,
        engine: &ndn_app::ForwarderEngine,
        target: String,
        decision: Decision,
        issuers: Vec<Vec<u8>>,
    ) -> Result<NdnPendingApproval, NdnError> {
        let (participant, creds) = self.admin_credentials(engine, issuers)?;
        // Names the decider of a local CA's request only; the app runs none.
        let operator = "this app";
        self.rt
            .block_on(ndn_namespace::approver::decide(
                &participant,
                &[],
                || Ok(creds),
                &target,
                decision,
                operator,
            ))
            .map(|r| pending_approval(&r))
            .map_err(|e| refused(app_text(&e)))
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
