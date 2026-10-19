//! Enrollment by an admin's approval through the FFI: a namespace's CA
//! (`/home/bob`, and others where an app takes part in several) runs
//! in-process (its root device initialized as `ndn-fwd init` does) and is
//! served on each app engine, so requests, listings and decisions travel
//! through the engine as in the field.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_cert::approval::DEFAULT_REQUEST_TTL;
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::{
    ApprovalPoll, ApprovalService, ApprovalStore, Decision, DeviceApprovalChallenge, FileCaStore,
    HierarchicalPolicy, NewRootStore, RequestStore, RolePolicy, anchor_fingerprint, ca_key_name,
    init_namespace_in_pib, new_device_key_name,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name, SignatureType};
use ndn_security::{
    Certificate, EcdsaP256Signer, FilePib, SecurityManager, Signer, VerifyOutcome,
    verify_by_sig_type,
};
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

use crate::NdnEngine;
use crate::handlers::NdnMembershipHandler;
use crate::types::{
    NdnApprovalOutcome, NdnEngineConfig, NdnEnrolledIdentity, NdnEnrollmentRequest, NdnError,
    NdnIdentity, NdnMembershipEvent, NdnSecurityProfile,
};

const NS: &str = "/home/bob";
const PASSWORD: &[u8] = b"app password";

fn ns() -> Name {
    NS.parse().unwrap()
}

/// A fresh private directory (removed on drop).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("ndn-boltffi-approval-{tag}-{hex}"));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn arg(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The namespace's root device and its CA (device-approval, role issuance).
struct Namespace {
    ns: Name,
    _root: TempDir,
    ca: Arc<CaState>,
    approvals: ApprovalStore,
    service: ApprovalService,
    /// `ndn-trust://anchor` link carrying the signed context inline.
    link: String,
    context: Data,
    fingerprint: [u8; 32],
}

impl Namespace {
    fn new() -> Self {
        Self::of(NS)
    }

    /// The namespace `ns`, rooted on its own root device.
    fn of(ns: &str) -> Self {
        let ns: Name = ns.parse().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let root = TempDir::new("root");
        let pib = FilePib::new(root.path()).unwrap();
        let out = rt
            .block_on(init_namespace_in_pib(
                &pib,
                &ns,
                "desk",
                false,
                &NewRootStore::File,
            ))
            .unwrap();
        let mgr = SecurityManager::new();
        mgr.register_signer(out.ca_key.clone(), pib.get_signer(&out.ca_key).unwrap());
        mgr.cert_cache().insert(out.ca_cert.clone());
        let context = Data::decode(out.init.context_data.raw().clone()).unwrap();
        let fingerprint = anchor_fingerprint(&out.init.anchor);
        let keyring = Arc::new(ndn_security::Keyring::new());
        ndn_cert::adopt_with_tofu(&keyring, &context, &ns, &fingerprint).unwrap();

        let store = Arc::new(FileCaStore::open(root.path().join("ca")).unwrap());
        let approvals = ApprovalStore::with_store(
            ns.clone(),
            Some(ns.clone()),
            DEFAULT_REQUEST_TTL,
            store.clone(),
        )
        .unwrap();
        let challenges: Vec<Box<dyn ChallengeHandler>> =
            vec![Box::new(DeviceApprovalChallenge::new(approvals.clone()))];
        let mut config = CaConfig::new(
            ns.clone(),
            "namespace CA".to_string(),
            Duration::from_secs(90 * 86_400),
            Duration::from_secs(90 * 86_400),
            challenges,
            Box::new(HierarchicalPolicy),
        )
        .with_signing_key(ca_key_name(&ns))
        .emit_attestations(true);
        config.issuance = Box::new(RolePolicy::new(ns.clone()));
        let ca = Arc::new(CaState::with_store(config, Arc::new(mgr), store).unwrap());
        let service = ApprovalService::new(approvals.clone(), keyring, Arc::clone(&ca));
        let link = TrustEnvelope::Anchor {
            namespace: Some(ns.to_string()),
            fingerprint: Some(fingerprint),
            version: None,
            context_data: Some(context.raw().clone()),
            context_content: None,
        }
        .to_uri();
        Self {
            ns,
            _root: root,
            ca,
            approvals,
            service,
            link,
            context,
            fingerprint,
        }
    }

    /// An app engine with this namespace's CA reachable through it.
    fn engine(&self) -> NdnEngine {
        let engine = NdnEngine::new(NdnEngineConfig {
            cs_capacity_mb: 1,
            security_profile: NdnSecurityProfile::Default,
            faces: Vec::new(),
            node_name: None,
            pipeline_threads: 1,
            persistent_cs_path: None,
        })
        .unwrap();
        self.serve_on(&engine);
        engine
    }

    /// Serve this namespace's CA on `engine`.
    fn serve_on(&self, engine: &NdnEngine) {
        let forwarder = engine
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .engine()
            .clone();
        let (ns, ca, service) = (self.ns.clone(), Arc::clone(&self.ca), self.service.clone());
        // Registered before any request goes out; served as long as the
        // engine's runtime runs. Each Interest is answered from its own task,
        // as the CA's producer does, so a held status delays no other.
        let producer = {
            let _rt = engine.rt.enter();
            forwarder.register_producer(ns.clone(), CancellationToken::new())
        };
        engine.rt.spawn(async move {
            let _ = producer
                .serve(move |interest, responder| {
                    let (ns, ca, service) = (ns.clone(), Arc::clone(&ca), service.clone());
                    tokio::spawn(async move {
                        if let Some(wire) = answer(&ns, &ca, &service, &interest).await {
                            let _ = responder.respond_bytes(wire).await;
                        }
                    });
                    async {}
                })
                .await;
        });
    }

    /// The pending request `id` an app asked, approved by the CA host's
    /// local operator.
    fn approve_locally(&self, id: &str) {
        self.approvals
            .decide_locally(id, Decision::Approve, "uid 0 (setup)")
            .unwrap();
    }

    fn is_pending(&self, id: &str) -> bool {
        self.approvals.get(id).unwrap().is_pending()
    }
}

/// The CA of `ns`'s answer to `interest`, as its producer would send it.
async fn answer(
    ns: &Name,
    ca: &CaState,
    service: &ApprovalService,
    interest: &Interest,
) -> Option<Bytes> {
    let comps = interest.name.components();
    let verb = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);
    let params = || interest.app_parameters().cloned().unwrap_or_default();
    let name = interest.name.as_ref().clone();
    let body = if verb(b"APPROVAL").is_some() {
        service.handle_decision(&params()).await
    } else if verb(b"PENDING").is_some() {
        service.handle_listing(interest).await
    } else if verb(b"STATUS").is_some() {
        let id = ndn_cert::approval::status_request_id(ns, &name)?;
        let held = service.hold_status(&id).ok()?;
        service
            .answer_status(&held, ndn_cert::approval::status_hold(interest.lifetime()))
            .await
    } else if verb(b"NEW").is_some() {
        ca.handle_new(&params()).await.ok()?
    } else if let Some(i) = verb(b"CHALLENGE") {
        let rid: String = comps[i + 1]
            .value
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        ca.handle_challenge(&rid, &params()).await.ok()?
    } else {
        return ca
            .cert_for_interest(&interest.name, interest.selectors().can_be_prefix)
            .map(Bytes::from);
    };
    let (signer, cert) = ca.response_signer()?;
    DataBuilder::new(name, &body)
        .sign_fallible(signer.sig_type(), Some(&cert), |region| {
            let region = region.to_vec();
            async move { signer.sign(&region).await }
        })
        .await
        .ok()
}

fn pending(outcome: NdnApprovalOutcome) -> NdnEnrollmentRequest {
    match outcome {
        NdnApprovalOutcome::Pending { request, .. } => request,
        other => panic!("expected a pending request: {other:?}"),
    }
}

/// An app enrolled as `<ns>/<role>/<device>` through the FFI, approved by
/// the CA host's operator: its identity is loaded. Returns the engine and
/// the persisted issuer chain.
fn enrolled(bob: &Namespace, role: &str, device: &str) -> (NdnEngine, Vec<Vec<u8>>, TempDir) {
    let engine = bob.engine();
    let storage = TempDir::new(device);
    let identity = enroll_in(&engine, bob, &storage, role, device);
    (engine, identity.issuers, storage)
}

/// `engine`'s app enrolled in `ns` as `<ns>/<role>/<device>` through the
/// FFI, its request recorded in `storage`, approved by the CA host's
/// operator: what the app persists.
fn enroll_in(
    engine: &NdnEngine,
    ns: &Namespace,
    storage: &TempDir,
    role: &str,
    device: &str,
) -> NdnEnrolledIdentity {
    let request = pending(
        engine
            .request_enrollment(
                storage.arg(),
                ns.link.clone(),
                role.into(),
                device.into(),
                PASSWORD.to_vec(),
            )
            .unwrap(),
    );
    ns.approve_locally(&request.request_id);
    match engine
        .poll_enrollment(storage.arg(), request.request_id, 0, PASSWORD.to_vec())
        .unwrap()
    {
        NdnApprovalOutcome::Issued { identity, .. } => identity,
        other => panic!("expected the {role} certificate issued: {other:?}"),
    }
}

/// A member device: members enroll by invite, so it is certified at the CA
/// directly (as the root device would through an invite), then loaded into
/// an app from its SafeBag.
fn member(bob: &Namespace) -> NdnEngine {
    let engine = bob.engine();
    let key_name = new_device_key_name(&ns().append("member").append("phone")).unwrap();
    let key = EcdsaP256Signer::generate(key_name.clone()).unwrap();
    let pkcs8 = key.to_pkcs8_der().unwrap();
    let key: Arc<dyn Signer> = Arc::new(key);
    let keyring = Arc::new(ndn_security::Keyring::new());
    ndn_cert::adopt_with_tofu(&keyring, &bob.context, &ns(), &bob.fingerprint).unwrap();
    let forwarder = engine
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .engine()
        .clone();
    let poll = |resume: Option<String>| {
        engine
            .rt
            .block_on(ndn_identity::poll_approval_via_engine(
                &forwarder,
                &keyring,
                &ns(),
                &ns(),
                Arc::clone(&key),
                resume.as_deref(),
                None,
            ))
            .unwrap()
    };
    let ApprovalPoll::Pending(request) = poll(None) else {
        panic!("expected the member's request pending");
    };
    bob.approve_locally(&request.request_id);
    let ApprovalPoll::Issued(issued) = poll(Some(request.request_id)) else {
        panic!("expected the member's certificate issued");
    };
    let bag = ndn_security::safebag::SafeBag::encrypt(issued.data.raw().clone(), &pkcs8, PASSWORD)
        .unwrap();
    engine
        .adopt_context(
            bob.context.raw().to_vec(),
            NS.into(),
            bob.fingerprint.to_vec(),
        )
        .unwrap();
    engine
        .load_identity(
            bag.encode().to_vec(),
            PASSWORD.to_vec(),
            key_name.to_string(),
        )
        .unwrap();
    engine
}

/// The code the requesting app shows is the code the admin's listing shows
/// for that request, and another key's request shows another code; asking
/// again while pending answers with the same request.
#[test]
fn the_requester_and_the_admin_see_one_code_per_key() {
    let bob = Namespace::new();
    let (admin, issuers, _admin_storage) = enrolled(&bob, "admin", "laptop");

    let (vps, vps_storage) = (bob.engine(), TempDir::new("vps"));
    let ask = |engine: &NdnEngine, storage: &TempDir, device: &str| {
        pending(
            engine
                .request_enrollment(
                    storage.arg(),
                    bob.link.clone(),
                    "node".into(),
                    device.into(),
                    PASSWORD.to_vec(),
                )
                .unwrap(),
        )
    };
    let request = ask(&vps, &vps_storage, "vps");
    let again = ask(&vps, &vps_storage, "vps");
    assert_eq!(
        (
            again.request_id.as_str(),
            again.key_name.as_str(),
            again.code.as_str()
        ),
        (
            request.request_id.as_str(),
            request.key_name.as_str(),
            request.code.as_str()
        ),
        "asking again while pending answers with the same request"
    );
    let (pi, pi_storage) = (bob.engine(), TempDir::new("pi"));
    let other = ask(&pi, &pi_storage, "pi");

    let listed = admin.list_pending_approvals(issuers).unwrap();
    let shown = |id: &str| {
        listed
            .iter()
            .find(|r| r.request_id == id)
            .unwrap_or_else(|| panic!("request {id} listed: {listed:?}"))
            .code
            .clone()
    };
    assert_eq!(shown(&request.request_id), request.code);
    assert_eq!(shown(&other.request_id), other.code);
    assert_ne!(request.code, other.code, "another key shows another code");
}

/// Only an admin decides: a member's approval is refused on the device and
/// the request stays pending; an admin's approval (by code) issues the
/// certificate when the requester next asks — from an app restarted on the
/// same storage — and a denial reaches a requester waiting on it at once,
/// with its reason, and deletes the request's key.
#[test]
fn only_an_admin_decides_and_the_requester_learns_the_outcome() {
    let bob = Namespace::new();
    let (admin, issuers, _admin_storage) = enrolled(&bob, "admin", "laptop");
    let member = member(&bob);

    let storage = TempDir::new("vps");
    let request = pending(
        bob.engine()
            .request_enrollment(
                storage.arg(),
                bob.link.clone(),
                "node".into(),
                "vps".into(),
                PASSWORD.to_vec(),
            )
            .unwrap(),
    );
    let refused = member
        .approve_request(request.code.clone(), Vec::new())
        .unwrap_err();
    assert!(refused.to_string().contains("not an admin"), "{refused}");
    assert!(bob.is_pending(&request.request_id));

    let decided = admin
        .approve_request(request.code.replace(' ', ""), issuers.clone())
        .unwrap();
    assert_eq!(
        (decided.request_id.as_str(), decided.state.as_str()),
        (request.request_id.as_str(), "approved")
    );
    // The app restarted: it adopts its persisted context again and polls.
    let restarted = bob.engine();
    restarted
        .adopt_context(
            bob.context.raw().to_vec(),
            NS.into(),
            bob.fingerprint.to_vec(),
        )
        .unwrap();
    match restarted
        .poll_enrollment(
            storage.arg(),
            request.request_id.clone(),
            0,
            PASSWORD.to_vec(),
        )
        .unwrap()
    {
        NdnApprovalOutcome::Issued { identity, .. } => {
            assert_eq!(identity.key_name, request.key_name);
            assert!(
                identity.cert_name.starts_with(&request.key_name),
                "{}",
                identity.cert_name
            );
        }
        other => panic!("expected the approved request issued: {other:?}"),
    }
    let listed = restarted.enrollment_requests(storage.arg()).unwrap();
    assert_eq!(listed[0].state, "issued");

    let denied_storage = TempDir::new("pi");
    let denied_app = bob.engine();
    let denied = pending(
        denied_app
            .request_enrollment(
                denied_storage.arg(),
                bob.link.clone(),
                "node".into(),
                "pi".into(),
                PASSWORD.to_vec(),
            )
            .unwrap(),
    );
    // The app waits on the request (a held status at the CA); the admin's
    // denial reaches it at once, long before the wait would end.
    let waited = std::thread::scope(|s| {
        let waiting = s.spawn(|| {
            let started = std::time::Instant::now();
            let outcome = denied_app
                .poll_enrollment(
                    denied_storage.arg(),
                    denied.request_id.clone(),
                    20,
                    PASSWORD.to_vec(),
                )
                .unwrap();
            (outcome, started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !waiting.is_finished(),
            "the app waits while the request is pending"
        );
        admin
            .deny_request(denied.request_id.clone(), "not my device".into(), issuers)
            .unwrap();
        waiting.join().unwrap()
    });
    match waited {
        (NdnApprovalOutcome::Denied { reason, .. }, took) => {
            assert!(reason.contains("not my device"), "{reason}");
            assert!(
                took < Duration::from_secs(5),
                "answered at the denial, not after {took:?}"
            );
        }
        other => panic!("expected the request denied: {other:?}"),
    }
    let store = RequestStore::open(denied_storage.path().join("requests")).unwrap();
    assert_eq!(
        store.sealed_key(&denied.key_name).unwrap(),
        None,
        "the key was deleted"
    );
}

/// Keeps what an app's membership watch hands over.
struct Watcher(Arc<parking_lot::Mutex<Vec<NdnMembershipEvent>>>);

impl NdnMembershipHandler for Watcher {
    fn on_membership(&self, event: NdnMembershipEvent) {
        self.0.lock().push(event);
    }
}

/// Whether `signature` over `region` verifies under the key `identity`'s
/// certificate certifies.
fn signed_by(identity: &NdnEnrolledIdentity, region: &[u8], signature: &[u8]) -> bool {
    let wire = Bytes::from(identity.certificate.clone().expect("a certificate"));
    let cert = Certificate::decode(&Data::decode(wire).unwrap()).unwrap();
    let outcome = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(verify_by_sig_type(
            SignatureType::SignatureSha256WithEcdsa,
            region,
            signature,
            &cert.public_key,
        ));
    matches!(outcome, Ok(VerifyOutcome::Valid))
}

/// What must not change about an identity when the app enrolls elsewhere.
fn view(i: &NdnIdentity) -> (String, String, String, Option<Vec<u8>>, bool) {
    (
        i.identity.clone(),
        i.key_name.clone(),
        i.namespace.clone(),
        i.certificate.clone(),
        i.node_identity,
    )
}

/// Each name under `/home/bob` and `/work/acme` is signed by the app's key
/// in that prefix — never the other's.
fn signs_each_prefix_with_its_own_key(
    app: &NdnEngine,
    home: &NdnEnrolledIdentity,
    work: &NdnEnrolledIdentity,
) {
    let region = b"the signed portion".to_vec();
    for (name, own, other) in [
        ("/home/bob/admin/phone/doc", home, work),
        ("/home/bob/shared/doc", home, work),
        ("/work/acme/node/phone/doc", work, home),
        ("/work/acme/shared/doc", work, home),
    ] {
        let signature = app.sign(name.into(), region.clone()).unwrap();
        assert!(
            signed_by(own, &region, &signature),
            "{name} not signed with {}",
            own.key_name
        );
        assert!(
            !signed_by(other, &region, &signature),
            "{name} signed with {}",
            other.key_name
        );
    }
}

/// An app takes part in several trusted prefixes at once: enrolled in
/// `/home/bob`, then in `/work/acme` (a late approval there), it signs each
/// prefix's names with its own key there, and nothing about `/home/bob`
/// changes — its identity, certificate and node identity stay. A prefix it
/// only follows (`/club`) is refused with why, as is a name no identity
/// covers. The membership report and watch show each prefix. After a
/// restart, the SafeBags the host persisted load both identities again, and
/// the node identity it persisted is chosen again.
#[test]
fn an_app_takes_part_in_several_trusted_prefixes() {
    let bob = Namespace::new();
    let acme = Namespace::of("/work/acme");
    let club = Namespace::of("/club");
    let app = bob.engine();
    acme.serve_on(&app);
    let storage = TempDir::new("phone");
    let changes = Arc::new(parking_lot::Mutex::new(Vec::new()));

    let (home, work) = std::thread::scope(|s| {
        let watching = s.spawn(|| app.watch_memberships(Box::new(Watcher(Arc::clone(&changes)))));
        std::thread::sleep(Duration::from_millis(200));

        let home = enroll_in(&app, &bob, &storage, "admin", "phone");
        assert!(
            home.node_identity,
            "the first identity is the node identity"
        );
        let before: Vec<_> = app.identities().iter().map(view).collect();
        assert_eq!(before.len(), 1);
        let validity = app.certificate_validity().unwrap();

        let work = enroll_in(&app, &acme, &storage, "node", "phone");
        assert!(
            !work.node_identity,
            "enrolling elsewhere keeps the node identity"
        );
        let after = app.identities();
        assert_eq!(after.len(), 2, "{after:?}");
        let home_now = after.iter().find(|i| i.namespace == NS).unwrap();
        assert_eq!(
            view(home_now),
            before[0],
            "/home/bob changed when the app enrolled in /work/acme"
        );
        let work_now = after.iter().find(|i| i.namespace == "/work/acme").unwrap();
        assert_eq!(
            (work_now.key_name.as_str(), work_now.node_identity),
            (work.key_name.as_str(), false)
        );
        assert_eq!(app.principal_name().unwrap(), "/home/bob/admin/phone");
        assert_eq!(
            app.certificate_validity().unwrap().cert_name,
            validity.cert_name
        );

        signs_each_prefix_with_its_own_key(&app, &home, &work);

        // A prefix the app only follows, and a name no identity covers.
        app.adopt_context(
            club.context.raw().to_vec(),
            "/club".into(),
            club.fingerprint.to_vec(),
        )
        .unwrap();
        match app.sign("/club/news".into(), b"x".to_vec()) {
            Err(NdnError::NoSigningIdentity {
                follows: Some(prefix),
                why,
                ..
            }) => {
                assert_eq!(prefix, "/club");
                assert!(
                    why.contains("follows /club") && why.contains("enroll in /club"),
                    "{why}"
                );
            }
            other => panic!("expected a refusal: the app only follows /club: {other:?}"),
        }
        match app.sign("/elsewhere/doc".into(), b"x".to_vec()) {
            Err(NdnError::NoSigningIdentity {
                follows: None, why, ..
            }) => {
                assert!(why.contains("no identity of this app covers"), "{why}");
            }
            other => panic!("expected a refusal: no identity covers it: {other:?}"),
        }

        let memberships = app.memberships().unwrap();
        let of = |ns: &str| {
            let m = memberships.iter().find(|m| m.namespace == ns).unwrap();
            (
                m.relation.as_str(),
                m.role.as_str(),
                m.identity.as_str(),
                m.node_identity,
            )
        };
        assert_eq!(memberships.len(), 3, "{memberships:?}");
        assert_eq!(of("/club"), ("following", "", "", false));
        assert_eq!(of(NS), ("member", "admin", "/home/bob/admin/phone", true));
        assert_eq!(
            of("/work/acme"),
            ("member", "node", "/work/acme/node/phone", false)
        );

        app.shutdown();
        watching.join().unwrap().unwrap();
        (home, work)
    });
    let seen: Vec<(String, String, String)> = changes
        .lock()
        .iter()
        .map(|e| (e.namespace.clone(), e.change.clone(), e.relation.clone()))
        .collect();
    for ns in [NS, "/work/acme"] {
        // Adopted when the app asked to enroll; a member once issued.
        assert!(
            seen.contains(&(ns.into(), "adopted".into(), "following".into())),
            "{seen:?}"
        );
        assert!(
            seen.contains(&(ns.into(), "enrolled".into(), "member".into())),
            "{seen:?}"
        );
    }
    // The followed prefix, adopted from its envelope.
    assert!(
        seen.contains(&("/club".into(), "adopted".into(), "following".into())),
        "{seen:?}"
    );
    // Each enrollment waited for an approval: it names the request; each
    // change is told once.
    for e in changes.lock().iter().filter(|e| e.change == "enrolled") {
        assert!(
            e.request.is_some() && e.key.is_some() && e.valid_until.is_some(),
            "{e:?}"
        );
    }
    for change in &seen {
        assert_eq!(seen.iter().filter(|c| *c == change).count(), 1, "{seen:?}");
    }

    // The app restarts: it adopts its persisted contexts and loads every
    // persisted SafeBag, whatever the order, then chooses its persisted node
    // identity again.
    let relaunched = bob.engine();
    for ns in [&bob, &acme] {
        relaunched
            .adopt_context(
                ns.context.raw().to_vec(),
                ns.ns.to_string(),
                ns.fingerprint.to_vec(),
            )
            .unwrap();
    }
    for identity in [&work, &home] {
        relaunched
            .load_identity(
                identity.safebag.clone(),
                PASSWORD.to_vec(),
                identity.key_name.clone(),
            )
            .unwrap();
    }
    let unknown = relaunched
        .set_node_identity("/club/member/phone".into())
        .unwrap_err();
    assert!(unknown.to_string().contains("load_identity"), "{unknown}");
    relaunched
        .set_node_identity("/home/bob/admin/phone".into())
        .unwrap();
    assert_eq!(
        relaunched.principal_name().unwrap(),
        "/home/bob/admin/phone"
    );
    assert_eq!(relaunched.identities().len(), 2);
    signs_each_prefix_with_its_own_key(&relaunched, &home, &work);
    relaunched.shutdown();
}

/// The plain adoption of a persisted or scanned context (`adopt_context`)
/// is told to the membership watchers as every adoption is: `adopted`, once
/// per prefix new to the app — at a launch restoring the persisted contexts
/// too — and nothing when the version is already held.
#[test]
fn a_plain_adoption_is_told_once() {
    let bob = Namespace::new();
    let club = Namespace::of("/club");
    let app = bob.engine();
    let changes = Arc::new(parking_lot::Mutex::new(Vec::new()));
    std::thread::scope(|s| {
        let watching = s.spawn(|| app.watch_memberships(Box::new(Watcher(Arc::clone(&changes)))));
        std::thread::sleep(Duration::from_millis(200));
        for ns in [&bob, &club, &bob] {
            app.adopt_context(
                ns.context.raw().to_vec(),
                ns.ns.to_string(),
                ns.fingerprint.to_vec(),
            )
            .unwrap();
        }
        std::thread::sleep(Duration::from_millis(200));
        app.shutdown();
        watching.join().unwrap().unwrap();
    });
    let seen: Vec<(String, String, String, u64)> = changes
        .lock()
        .iter()
        .map(|e| {
            (
                e.namespace.clone(),
                e.change.clone(),
                e.relation.clone(),
                e.version,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (NS.into(), "adopted".into(), "following".into(), 1),
            ("/club".into(), "adopted".into(), "following".into(), 1),
        ]
    );
}
