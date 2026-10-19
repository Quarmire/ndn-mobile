//! The app's side of [`ndn_namespace`]: what the library's operations keep
//! goes to the host through the FFI results, not to files the app owns.
//!
//! - [`AppContexts`] ([`ContextStore`]): every trust-context version an
//!   operation keeps is handed to the host (in the operation's result) to
//!   persist and adopt again at launch; the app holds no root key and
//!   publishes nothing.
//! - [`AppVault`] ([`KeyVault`]): the keys are the identities the app holds
//!   ([`IdentityCore`]: every one it enrolled as, loaded, generated or
//!   restored — the host persists each SafeBag and loads them all at
//!   launch), or, for a renewal, the one identity the call opened from its
//!   SafeBag. A key generated here, or opened from a sealed request key
//!   under the host's password, lives in memory for the call, and the
//!   certificate the CA issues is sealed with its key into a SafeBag the
//!   result carries. Requests for an admin's approval are recorded under
//!   `<storage_dir>/requests/` with their key sealed beside them
//!   ([`ndn_cert::RequestStore`]); the issuer certificates of a request
//!   issued there are kept under `<storage_dir>/issuers/`
//!   ([`ndn_cert::issuers`]).
//! - [`AppParticipant`]: the [`Participant`] a call works through; the
//!   membership changes it reports reach the app's watchers
//!   ([`IdentityCore::watch_memberships`]).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

use bytes::Bytes;
use ndn_cert::RequestStore;
use ndn_cert::report::MembershipEvent;
use ndn_namespace::{
    Activation, ContextStore, HostWords, KeyUnavailable, KeyVault, Participant, ParticipantParts,
    StoredContext,
};
use ndn_packet::{Data, Name};
use ndn_security::safebag::SafeBag;
use ndn_security::{Certificate, EcdsaP256Signer, SignedTrustContext, Signer};

use super::{IdentityCore, identity_of_key};
use crate::types::{NdnContext, NdnEnrolledIdentity, NdnError, NdnMembership};

/// Where the outgoing requests live under the app's storage directory, as
/// beside the daemon's PIB.
const REQUESTS_DIR: &str = "requests";

/// The trust-context versions an operation kept, for its result.
#[derive(Default)]
pub(crate) struct AppContexts {
    kept: Mutex<Vec<Bytes>>,
}

impl ContextStore for AppContexts {
    fn location(&self) -> String {
        "the app's storage (the host persists each version it is handed)".into()
    }

    fn persist(&self, _ctx: &SignedTrustContext, data: &Data) -> Result<String, String> {
        self.kept.lock().push(data.raw().clone());
        Ok("with the host (persist the context the result carries)".into())
    }

    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
        Ok(Vec::new())
    }

    fn stored_versions(&self, _namespace: &Name) -> Result<Vec<StoredContext>, String> {
        Ok(Vec::new())
    }

    fn holds_root_key(&self, _ctx: &SignedTrustContext) -> bool {
        false
    }
}

impl AppContexts {
    /// The newest version of `namespace` kept, with the fingerprint of the
    /// anchor that signed it: what the host persists and adopts again at
    /// launch (`adopt_context`).
    pub(crate) fn newest(&self, namespace: &Name) -> Option<NdnContext> {
        self.kept
            .lock()
            .iter()
            .filter_map(|wire| {
                let data = Data::decode(wire.clone()).ok()?;
                let (ctx, signer) = ndn_cert::open_signed_context(&data).ok()?;
                (ctx.namespace() == namespace).then(|| {
                    NdnContext::adopted(&ctx, &data, &ndn_cert::anchor_fingerprint(&signer))
                })
            })
            .max_by_key(|c| c.version)
    }
}

/// The request records under `storage_dir`.
pub(crate) fn request_store(storage_dir: &str) -> Result<RequestStore, String> {
    if storage_dir.is_empty() {
        return Err(
            "no storage directory given: pass the app's private files directory, where \
                    its requests for an admin's approval are recorded"
                .into(),
        );
    }
    RequestStore::open(Path::new(storage_dir).join(REQUESTS_DIR))
        .map_err(|e| format!("cannot open the request records under {storage_dir}: {e}"))
}

/// A key sealed under the host's password: a password-encrypted PKCS#8.
fn seal(pkcs8: &[u8], password: &[u8]) -> Result<Bytes, String> {
    SafeBag::encrypt(Bytes::new(), pkcs8, password)
        .map(|bag| bag.encrypted_key)
        .map_err(|e| e.to_string())
}

/// The PKCS#8 of a sealed request key: a SafeBag (issued) or a bare
/// password-encrypted PKCS#8 (pending).
pub(crate) fn unseal(sealed: &[u8], password: &[u8]) -> Result<Vec<u8>, String> {
    let bag = SafeBag::decode(sealed).unwrap_or_else(|_| SafeBag {
        certificate: Bytes::new(),
        encrypted_key: Bytes::copy_from_slice(sealed),
    });
    bag.decrypt_pkcs8(password).map_err(|e| e.to_string())
}

/// A key the vault holds open for the call.
struct OpenKey {
    pkcs8: Option<Vec<u8>>,
    signer: Arc<dyn Signer>,
}

/// The certificate the vault installed during the call.
struct Installed {
    key: Name,
    cert: Bytes,
    safebag: Vec<u8>,
    issuers: Vec<Vec<u8>>,
}

/// The one identity a renewal works with: the key it holds (a loaded
/// SafeBag) and its certificate.
pub(crate) struct Held {
    pub(crate) key: Name,
    pub(crate) cert: Data,
    /// Its PKCS#8, when the call may seal a renewed certificate with it.
    pub(crate) pkcs8: Option<Vec<u8>>,
    pub(crate) signer: Arc<dyn Signer>,
}

/// The app's [`KeyVault`] for one FFI call (see the [module docs](self)).
pub(crate) struct AppVault<'a> {
    core: &'a IdentityCore,
    /// Where requests (and the issuer certificates of a request issued)
    /// are kept; empty: none.
    storage_dir: String,
    password: Vec<u8>,
    /// The one identity a renewal works with; `None`: every identity the
    /// app holds.
    held: Option<Held>,
    /// The issuer certificates the host kept and passed in.
    passed_issuers: Vec<Bytes>,
    open: Mutex<HashMap<Name, OpenKey>>,
    installed: Mutex<Option<Installed>>,
}

impl<'a> AppVault<'a> {
    /// A vault over every identity the app holds, generating and recording
    /// requests under `storage_dir` with keys sealed under `password`.
    pub(crate) fn new(core: &'a IdentityCore, storage_dir: String, password: Vec<u8>) -> Self {
        Self {
            core,
            storage_dir,
            password,
            held: None,
            passed_issuers: Vec::new(),
            open: Mutex::new(HashMap::new()),
            installed: Mutex::new(None),
        }
    }

    /// A vault over every identity the app holds, with the issuer
    /// certificates the host kept for them.
    pub(crate) fn with_issuers(core: &'a IdentityCore, issuers: Vec<Vec<u8>>) -> Self {
        Self {
            passed_issuers: issuers.into_iter().map(Bytes::from).collect(),
            ..Self::new(core, String::new(), Vec::new())
        }
    }

    /// A vault holding only `held` (opened from its SafeBag by the host) and
    /// the issuer certificates the host kept: a renewal of that identity.
    pub(crate) fn holding(
        core: &'a IdentityCore,
        held: Held,
        issuers: Vec<Vec<u8>>,
        password: Vec<u8>,
    ) -> Self {
        let vault = Self {
            passed_issuers: issuers.into_iter().map(Bytes::from).collect(),
            ..Self::new(core, String::new(), password)
        };
        vault.open.lock().insert(
            held.key.clone(),
            OpenKey {
                pkcs8: held.pkcs8.clone(),
                signer: Arc::clone(&held.signer),
            },
        );
        Self {
            held: Some(held),
            ..vault
        }
    }

    fn requests(&self) -> Result<RequestStore, String> {
        request_store(&self.storage_dir)
    }

    /// Whether `key` is the key of a request recorded under the storage
    /// directory.
    fn is_request_key(&self, key: &Name) -> bool {
        !self.storage_dir.is_empty()
            && self
                .requests()
                .and_then(|store| {
                    store
                        .sealed_key(&key.to_string())
                        .map_err(|e| e.to_string())
                })
                .is_ok_and(|sealed| sealed.is_some())
    }

    /// The identity the CA issued during the call, for the host to persist.
    pub(crate) fn installed(
        &self,
        adopted_context: Option<NdnContext>,
    ) -> Option<NdnEnrolledIdentity> {
        let installed = self.installed.lock();
        let installed = installed.as_ref()?;
        let cert_name = Data::decode(installed.cert.clone()).ok()?.name.to_string();
        Some(NdnEnrolledIdentity {
            key_name: installed.key.to_string(),
            cert_name,
            certificate: Some(installed.cert.to_vec()),
            safebag: installed.safebag.clone(),
            adopted_context,
            issuers: installed.issuers.clone(),
            node_identity: identity_of_key(&installed.key)
                .is_some_and(|identity| self.core.is_node(&identity)),
        })
    }
}

impl KeyVault for AppVault<'_> {
    fn location(&self) -> String {
        if self.storage_dir.is_empty() {
            "the app's storage".into()
        } else {
            self.storage_dir.clone()
        }
    }

    fn default_identity(&self) -> Result<Option<Name>, String> {
        Ok(self.core.node_identity())
    }

    fn request_store(&self) -> Result<RequestStore, String> {
        self.requests()
    }

    fn generate(&self, key: &Name) -> Result<Arc<dyn Signer>, String> {
        let signer = EcdsaP256Signer::generate(key.clone()).map_err(|e| e.to_string())?;
        let pkcs8 = signer.to_pkcs8_der().map_err(|e| e.to_string())?;
        let signer: Arc<dyn Signer> = Arc::new(signer);
        self.open.lock().insert(
            key.clone(),
            OpenKey {
                pkcs8: Some(pkcs8),
                signer: Arc::clone(&signer),
            },
        );
        Ok(signer)
    }

    fn keep_pending(&self, key: &Name) -> Result<(), String> {
        let open = self.open.lock();
        let pkcs8 = open
            .get(key)
            .and_then(|opened| opened.pkcs8.as_ref())
            .ok_or_else(|| format!("the key {key} is not open"))?;
        let sealed = seal(pkcs8, &self.password)?;
        self.requests()?
            .save_sealed_key(&key.to_string(), &sealed)
            .map_err(|e| e.to_string())
    }

    fn signer(&self, key: &Name) -> Result<Arc<dyn Signer>, KeyUnavailable> {
        if let Some(opened) = self.open.lock().get(key) {
            return Ok(Arc::clone(&opened.signer));
        }
        if self.held.is_none()
            && let Some(signer) = self.core.signer_of_key(key)
        {
            return Ok(signer);
        }
        let store = self.requests().map_err(KeyUnavailable::Unreadable)?;
        let sealed = match store.sealed_key(&key.to_string()) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => {
                return Err(KeyUnavailable::Gone(format!(
                    "gone from {}",
                    self.storage_dir
                )));
            }
            Err(e) => return Err(KeyUnavailable::Unreadable(e.to_string())),
        };
        let pkcs8 = unseal(&sealed, &self.password).map_err(KeyUnavailable::Unreadable)?;
        let signer: Arc<dyn Signer> = Arc::new(
            EcdsaP256Signer::from_pkcs8_der(&pkcs8, key.clone())
                .map_err(|e| KeyUnavailable::Unreadable(format!("device key: {e}")))?,
        );
        self.open.lock().insert(
            key.clone(),
            OpenKey {
                pkcs8: Some(pkcs8),
                signer: Arc::clone(&signer),
            },
        );
        Ok(signer)
    }

    fn discard(&self, key: &Name) -> Result<(), String> {
        self.open.lock().remove(key);
        if self.storage_dir.is_empty() {
            return Ok(());
        }
        self.requests()?
            .remove_sealed_key(&key.to_string())
            .map_err(|e| e.to_string())
    }

    fn store_certificate(&self, key: &Name, cert: &Data) -> Result<(), String> {
        let pkcs8 = self
            .open
            .lock()
            .get(key)
            .and_then(|opened| opened.pkcs8.clone())
            .ok_or_else(|| format!("the key {key} is not open"))?;
        let bag = SafeBag::encrypt(cert.raw().clone(), &pkcs8, &self.password)
            .map_err(|e| format!("device key: {e}"))?;
        let safebag = bag.encode().to_vec();
        // Kept so a poll after a restart reports it again: the bag in
        // place of the bare request key.
        if self.is_request_key(key)
            && let Err(e) = self.requests().and_then(|store| {
                store
                    .save_sealed_key(&key.to_string(), &safebag)
                    .map_err(|e| e.to_string())
            })
        {
            tracing::warn!(
                target: "ndn_boltffi::identity",
                key = %key,
                error = %e,
                "issued, but the certificate was not kept beside the request; persist the outcome's SafeBag"
            );
        }
        *self.installed.lock() = Some(Installed {
            key: key.clone(),
            cert: cert.raw().clone(),
            safebag,
            issuers: Vec::new(),
        });
        Ok(())
    }

    fn make_default(&self, identity: &Name) -> Result<(), String> {
        // The app's first identity: its node identity from now on. The
        // host persists which identity it is (`node_identity` in the
        // result) and chooses it again at launch.
        self.core.record_node(identity);
        Ok(())
    }

    fn keep_issuers(&self, issuers: &[Data]) -> Result<(), String> {
        let mut installed = self.installed.lock();
        if let Some(installed) = installed.as_mut() {
            installed.issuers = issuers.iter().map(|d| d.raw().to_vec()).collect();
            // A link hello carries the chain too.
            self.core.set_issuers(
                &installed.key,
                issuers.iter().map(|d| d.raw().clone()).collect(),
            );
            if self.is_request_key(&installed.key) {
                ndn_cert::issuers::keep_issuer_certs(Path::new(&self.storage_dir), issuers)
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fn issuers(&self) -> Vec<Bytes> {
        let mut issuers = self.passed_issuers.clone();
        issuers.extend(self.core.kept_issuers());
        if !self.storage_dir.is_empty() {
            issuers.extend(ndn_cert::issuers::stored_issuer_certs(Path::new(
                &self.storage_dir,
            )));
        }
        issuers
    }

    fn keys(&self) -> Result<Vec<Name>, String> {
        Ok(match &self.held {
            Some(held) => vec![held.key.clone()],
            None => self.core.keys(),
        })
    }

    fn certificate(&self, key: &Name) -> Option<Certificate> {
        match &self.held {
            Some(held) if held.key == *key => Certificate::decode(&held.cert).ok(),
            Some(_) => None,
            None => self.core.current_cert_of(key),
        }
    }

    fn issued_certificate(&self, key: &Name) -> Result<Option<Bytes>, String> {
        Ok(match &self.held {
            Some(held) if held.key == *key => Some(held.cert.raw().clone()),
            Some(_) => None,
            None => self.core.current_cert_of(key).and_then(|c| c.data_wire()),
        })
    }

    fn activate(
        &self,
        _identity: &Name,
        key: &Name,
        signer: Arc<dyn Signer>,
        _first_identity: bool,
    ) -> Activation {
        if let Some(installed) = self.installed.lock().as_ref()
            && installed.key == *key
        {
            self.core.record_cert(&installed.cert);
        }
        // Beside the app's other identities; the first one (recorded by
        // `make_default`) is its node identity.
        match self.core.add_identity(signer) {
            Ok(node_identity) => Activation {
                signing_now: true,
                node_identity,
                at_next_start: Vec::new(),
            },
            Err(e) => Activation {
                signing_now: false,
                node_identity: false,
                at_next_start: vec![e.to_string()],
            },
        }
    }
}

/// The [`Participant`] an FFI call works through; dropped at the end of the
/// call, it hands the membership changes it reported to the app's watchers,
/// each with the app's relation to the namespace after the call (judged
/// over the identities the app holds, as [`IdentityCore::memberships`]: the
/// library judges an event's relation by the engine's key store, which holds
/// none of the app's identities).
pub(crate) struct AppParticipant<'a> {
    participant: Participant,
    events: tokio::sync::broadcast::Receiver<MembershipEvent>,
    core: &'a IdentityCore,
}

impl std::ops::Deref for AppParticipant<'_> {
    type Target = Participant;

    fn deref(&self) -> &Participant {
        &self.participant
    }
}

impl Drop for AppParticipant<'_> {
    fn drop(&mut self) {
        use tokio::sync::broadcast::error::TryRecvError;
        let mut events = Vec::new();
        loop {
            match self.events.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Lagged(_)) => continue,
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }
        if events.is_empty() {
            return;
        }
        let vault = AppVault::new(self.core, String::new(), Vec::new());
        let now = ndn_namespace::membership::memberships(&self.participant, &vault);
        for mut event in events {
            if let Some(info) = now.iter().find(|m| m.namespace == event.namespace) {
                event.relation = info.relation;
            }
            self.core.publish_membership(event);
        }
    }
}

impl IdentityCore {
    /// The [`Participant`] an FFI call works through: `engine`, this core's
    /// keyring, and `contexts` collecting what the call keeps. Nothing is
    /// published, served or synced by the app.
    pub(crate) fn participant(
        &self,
        engine: &ndn_app::ForwarderEngine,
        contexts: &Arc<AppContexts>,
    ) -> AppParticipant<'_> {
        let participant = Participant::new(ParticipantParts {
            engine: engine.clone(),
            keyring: Arc::clone(&self.keyring),
            store: Arc::clone(contexts) as Arc<dyn ContextStore>,
            publisher: None,
            own_certs: None,
            sync: None,
            cas: Vec::new(),
            words: app_words(),
        });
        AppParticipant {
            events: participant.membership_events(),
            participant,
            core: self,
        }
    }

    /// The app's membership in every trusted prefix it holds, sorted by
    /// prefix ([`ndn_namespace::membership::memberships`] over the
    /// identities the app holds).
    pub(crate) fn memberships(&self, engine: &ndn_app::ForwarderEngine) -> Vec<NdnMembership> {
        let contexts = Arc::new(AppContexts::default());
        let participant = self.participant(engine, &contexts);
        let vault = AppVault::new(self, String::new(), Vec::new());
        ndn_namespace::membership::memberships(&participant, &vault)
            .into_iter()
            .map(NdnMembership::from_info)
            .collect()
    }
}

/// How the person using the app does what a library refusal or log line
/// asks of them: the app's calls, never a forwarder's commands or its PIB.
/// What only a root device does (making invites, showing the anchor link,
/// its root key) keeps the library's neutral words.
pub(crate) fn app_words() -> HostWords {
    HostWords {
        enroll_again: "request_enrollment".into(),
        enroll_first: "enroll_with_invite".into(),
        enroll_with_invite: "enroll with the invite (enroll_with_invite)".into(),
        enroll_with_invite_as: "ask with the invite as {role} (request_enrollment)".into(),
        enroll_as_admin: "a request as admin from the namespace's anchor link \
                          (request_enrollment)"
            .into(),
        adopt: "adopt_context_link with its anchor link".into(),
        refresh_context: "refresh_contexts for {namespace}".into(),
        list_approvals: "list_pending_approvals".into(),
        decide_approvals: "Decide with approve_request".into(),
        key_storage: "the app's key storage".into(),
        key_storage_dir: "the app's key storage".into(),
        make_key_storage_readable: "Make the app's key storage readable".into(),
        contexts_not_served: "this app serves no trust contexts".into(),
        ..HostWords::default()
    }
}

/// An [`NdnError`] from a library refusal.
pub(crate) fn refused(refusal: ndn_namespace::TrustRefusal) -> NdnError {
    NdnError::Identity {
        msg: refusal.reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The library's messages, worded for the app, name the app's calls and
    /// none of a forwarder's commands, configuration or PIB.
    #[test]
    fn app_words_name_no_forwarder() {
        let w = app_words();
        let ns: Name = "/home/bob".parse().unwrap();
        let messages = [
            w.context_check_timed_out(8, &ns),
            w.request_expired_unanswered(),
            w.not_an_enroll_link("bad"),
            w.invite_for_another_role(&ns, "member", "guest"),
            w.role_by_invite(&ns, "member", "admin, node"),
            w.role_by_invite_and_approval(&ns, "node"),
            w.invite_spent(),
            w.approval_used(),
            w.request_not_recorded("r1", "123456", "full", "the app's storage"),
            w.enrolled(),
            w.request_names_no_ca(),
            w.request_names_no_key(),
            w.request_key_gone(&ns, "gone"),
            w.no_pending_request("123456", "the CAs of the namespaces this node administers"),
            w.nothing_to_approve(),
            w.no_context(&ns),
            w.renewal_unreadable("unreadable"),
            w.nothing_to_renew("the app's storage"),
            w.renewal_waits_for_storage(),
            w.renew_before_too_long(),
            w.not_published(),
            w.already_certified(&ns, "/home/bob/member/phone/KEY/k1", ""),
        ];
        for m in &messages {
            for forwarder in [
                "ndn-fwd",
                "PIB",
                "[security]",
                "`",
                " --",
                "{role}",
                "{namespace}",
            ] {
                assert!(!m.contains(forwarder), "{m:?} names {forwarder:?}");
            }
        }
        assert_eq!(
            w.no_context(&ns),
            "this node holds no trust context for /home/bob; adopt it first (adopt_context_link \
             with its anchor link)"
        );
    }
}
