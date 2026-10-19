//! The app's link flow through the FFI an app calls (`NdnEngine`), against
//! a relay and a desktop device running in this process on the link library
//! `ndn-fwd` runs (`ndn_link` on an engine): the phone links to its
//! namespace's relay, reaches the desktop device and is reached by it
//! through the relay and then over a direct path, changes a link's mode,
//! goes to the background and back, moves to another socket, hands the
//! relay a wake token the relay's notifier gets while the phone is asleep,
//! and is admitted by a relay of another trusted prefix by its membership
//! there.

#![allow(
    clippy::result_large_err,
    reason = "NdnError is the FFI's error type, returned as the app gets it"
)]

use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;

use ndn_app::{EngineAppExt, ForwarderEngine};
use ndn_boltffi::{
    NdnEngine, NdnEngineConfig, NdnError, NdnInterestHandler, NdnLinkMode, NdnLinkReport,
    NdnLinkStatus, NdnLinksConfig, NdnRelay, NdnSecurityProfile,
};
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, HoldLimits, LinkSetup, LinkTrust, Links, PeerSpec,
    RelaySource, RelayUse, WakeNotifier, WakeRequest,
};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{
    Certificate, EcdsaP256Signer, Ed25519Signer, Keyring, SecurityManager, SecurityProfile,
    SignedTrustContext, Signer,
};
use tokio_util::sync::CancellationToken;

const NS: &str = "/home";
const PASSWORD: &[u8] = b"pw";
const WITHIN: Duration = Duration::from_secs(20);

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A namespace (`/home` unless named): its root key, its signed trust
/// context (default link policy: members link, `node` devices relay, direct
/// paths on).
struct Home {
    ns: String,
    root: SecurityManager,
    root_key: Name,
    anchor: Certificate,
    context_data: ndn_packet::Data,
    context: Arc<SignedTrustContext>,
}

impl Home {
    fn new() -> Self {
        Self::of(NS)
    }

    fn of(ns: &str) -> Self {
        // RUST_LOG shows the link library's view when a test fails.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let root = SecurityManager::new();
        let root_key = n(&format!("{ns}/KEY/root"));
        root.generate_ed25519(root_key.clone()).unwrap();
        let signer = root.get_signer_sync(&root_key).unwrap();
        let anchor = root
            .issue_self_signed(&root_key, signer.public_key().unwrap(), u64::MAX)
            .unwrap();
        let ctx = SignedTrustContext::hierarchical(n(ns)).with_version(1);
        ctx.add_anchor(anchor.clone());
        let context_data = ctx.sign_into_data(signer.as_ref()).unwrap();
        Self {
            ns: ns.to_string(),
            root,
            root_key,
            anchor,
            context_data,
            context: Arc::new(ctx),
        }
    }

    /// The root's certificate for `key_name` certifying `public_key`.
    fn certify(&self, key_name: &Name, public_key: Bytes) -> Certificate {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.root.certify_as(
                key_name,
                public_key,
                &self.root_key,
                3_600_000,
                ndn_security::cert_name::NDNCERT_ISSUER,
                None,
            ))
            .unwrap()
    }

    /// Adopt this namespace's context in the app.
    fn adopt_in(&self, app: &NdnEngine) {
        app.adopt_context(
            self.context_data.raw().to_vec(),
            self.ns.clone(),
            ndn_cert::anchor_fingerprint(&self.anchor).to_vec(),
        )
        .unwrap();
    }

    /// Load the app's identity `<ns>/member/phone` in this namespace: a
    /// SafeBag with the certificate the root issued, as the host persisted.
    fn load_phone_identity(&self, app: &NdnEngine, seed: u8) {
        let key_name = n(&format!("{}/member/phone/KEY/p{seed}", self.ns));
        let signer = EcdsaP256Signer::from_seed(&[seed; 32], key_name.clone()).unwrap();
        let cert = self.certify(&key_name, signer.public_key().unwrap());
        let bag = ndn_security::safebag::SafeBag::encrypt(
            cert.data_wire().unwrap(),
            &signer.to_pkcs8_der().unwrap(),
            PASSWORD,
        )
        .unwrap();
        app.load_identity(
            bag.encode().to_vec(),
            PASSWORD.to_vec(),
            key_name.to_string(),
        )
        .unwrap();
    }

    fn keyring(&self) -> Arc<Keyring> {
        let keyring = Arc::new(Keyring::new());
        assert!(keyring.adopt(Arc::clone(&self.context)));
        keyring
    }
}

/// A device's trust data in this process: the namespace and its own chain.
struct HostTrust {
    keyring: Arc<Keyring>,
    chain: Vec<Bytes>,
}

impl LinkTrust for HostTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }
    fn own_chain(&self) -> Vec<Bytes> {
        self.chain.clone()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// The wake requests a relay's notifier was handed: for which device, with
/// which token.
#[derive(Default)]
struct Woken(Mutex<Vec<(Option<Name>, Bytes)>>);

impl WakeNotifier for Woken {
    fn wake(&self, request: WakeRequest) {
        self.0.lock().push((request.device, request.token));
    }
}

/// A device running the link library on an engine in this process, as
/// `ndn-fwd` does: the relay (listening) or the desktop device (dialling
/// the relay).
struct Host {
    rt: tokio::runtime::Runtime,
    engine: ForwarderEngine,
    /// Held: the link tasks stop when the last reference goes.
    _links: Arc<Links>,
    addr: SocketAddr,
    cancel: CancellationToken,
    _shutdown: ShutdownHandle,
}

impl Host {
    fn start(
        home: &Home,
        device: &str,
        seed: u8,
        peers: Vec<PeerSpec>,
        setup: impl FnOnce(&mut LinkSetup),
    ) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let key_name = n(&format!("{}{device}/KEY/k{seed}", home.ns));
        let signer = Arc::new(Ed25519Signer::from_seed(&[seed; 32], key_name.clone()));
        let cert = home.certify(&key_name, signer.public_key().unwrap());
        let key = LinkKey::from_signer(signer).unwrap();
        let (engine, shutdown) = rt.block_on(async {
            EngineBuilder::new(EngineConfig::default())
                .security_profile(SecurityProfile::Disabled)
                .build()
                .await
                .unwrap()
        });
        let cancel = CancellationToken::new();
        let (links, addr) = rt.block_on(async {
            let transport = LinkTransportConfig::default();
            let socket = Arc::new(
                LinkEndpoint::bind(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(key.clone()) as Arc<dyn LinkKeySource>,
                    &transport,
                    true,
                )
                .unwrap(),
            );
            let addr = socket.local_addr().unwrap();
            let mut s = LinkSetup {
                peers,
                key: Arc::new(key) as Arc<dyn LinkKeySource>,
                trust: Arc::new(HostTrust {
                    keyring: home.keyring(),
                    chain: vec![cert.data_wire().unwrap()],
                }),
                faces: Arc::new(EngineFaces(engine.clone())),
                paths: Arc::new(ConfiguredEndpoints),
                candidates: Vec::new(),
                socket: Some(socket),
                transport,
                relays: Default::default(),
                service: Default::default(),
                direct: Default::default(),
            };
            setup(&mut s);
            (Links::start(s, cancel.clone()), addr)
        });
        Self {
            rt,
            engine,
            _links: links,
            addr,
            cancel,
            _shutdown: shutdown,
        }
    }

    /// Answer every Interest under `prefix` with `content`.
    fn serve(&self, prefix: &str, content: &'static [u8]) {
        let _guard = self.rt.enter();
        let producer = self
            .engine
            .register_producer(n(prefix), self.cancel.child_token());
        self.rt.spawn(async move {
            let _ = producer
                .serve(|interest, responder| async move {
                    let _ = responder.respond((*interest.name).clone(), content).await;
                })
                .await;
        });
    }

    /// The content of `name`, fetched from this device.
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        let _guard = self.rt.enter();
        let mut consumer = self.engine.app_consumer(self.cancel.child_token());
        self.rt
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), consumer.get(n(name))).await
            })
            .ok()?
            .ok()
            .map(|b| b.to_vec())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The relay `<ns>/node/relay`, serving its namespace (the default),
/// holding Interests for sleeping devices that ask and handing their wake
/// tokens to `woken`; it answers `<ns>/node/relay/hello` itself.
fn relay(home: &Home, woken: &Arc<Woken>) -> Host {
    let notifier: Arc<dyn WakeNotifier> = Arc::clone(woken) as Arc<dyn WakeNotifier>;
    let relay = Host::start(home, "/node/relay", 1, Vec::new(), move |s| {
        s.service.wake = Some(notifier);
        s.service.hold = Some(HoldLimits {
            per_device: 16,
            total: 64,
            max_hold: Duration::from_secs(10),
        });
    });
    relay.serve(&format!("{}/node/relay/hello", home.ns), b"from the relay");
    relay
}

/// The desktop device `/home/member/desk`, linked to the relay.
fn desk(home: &Home, relay: &Host) -> Host {
    let to_relay = PeerSpec {
        label: "relay".into(),
        device: Some(n(&format!("{NS}/node/relay"))),
        endpoints: vec![relay.addr.to_string()],
        persistent: true,
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: 0,
        }),
        ..Default::default()
    };
    let desk = Host::start(home, "/member/desk", 2, vec![to_relay], |_| {});
    desk.serve(&format!("{NS}/member/desk/hello"), b"from the desk");
    desk
}

fn engine_config() -> NdnEngineConfig {
    NdnEngineConfig {
        cs_capacity_mb: 1,
        // The relay and the desk run without validation too: these tests
        // are about links; validation has its own.
        security_profile: NdnSecurityProfile::Disabled,
        faces: Vec::new(),
        node_name: None,
        pipeline_threads: 2,
        persistent_cs_path: None,
    }
}

struct Answer(&'static [u8]);

impl NdnInterestHandler for Answer {
    fn handle_interest(&self, name: String) -> Option<Vec<u8>> {
        Some(
            DataBuilder::new(name.parse::<Name>().ok()?, self.0)
                .build()
                .to_vec(),
        )
    }
}

/// The phone `/home/member/phone`: the app adopts the namespace's context,
/// loads its identity (a SafeBag with the certificate the root issued),
/// serves `/home/member/phone/hello` and starts links.
fn phone(home: &Home) -> Arc<NdnEngine> {
    let engine = Arc::new(NdnEngine::new(engine_config()).unwrap());
    home.adopt_in(&engine);
    home.load_phone_identity(&engine, 9);
    let server = Arc::clone(&engine);
    std::thread::spawn(move || {
        let _ = server.serve(
            format!("{NS}/member/phone"),
            Box::new(Answer(b"from the phone")),
        );
    });
    engine
        .start_links(NdnLinksConfig {
            socket_fd: None,
            bind: Some("127.0.0.1:0".into()),
            listen: false,
            relay_count: 1,
            use_namespace_relays: false,
            namespace_relay_mode: NdnLinkMode::Always,
            namespace_relay_hold: false,
            issuers: Vec::new(),
            keep_alive_secs: None,
            idle_timeout_secs: None,
        })
        .unwrap();
    engine
}

fn home_relay(relay: &Host, mode: NdnLinkMode, hold: bool) -> NdnRelay {
    prefix_relay("home", NS, relay, mode, hold)
}

/// The relay `<ns>/node/relay` as the user adds it, labelled `label`.
fn prefix_relay(label: &str, ns: &str, relay: &Host, mode: NdnLinkMode, hold: bool) -> NdnRelay {
    NdnRelay {
        label: label.into(),
        key: None,
        device: Some(format!("{ns}/node/relay")),
        endpoints: vec![relay.addr.to_string()],
        preference: 0,
        mode,
        hold,
        routes: Vec::new(),
    }
}

fn status(phone: &NdnEngine) -> NdnLinkReport {
    phone.link_status().unwrap()
}

fn link<'a>(report: &'a NdnLinkReport, label: &str) -> Option<&'a NdnLinkStatus> {
    report.links.iter().find(|l| l.label == label)
}

/// Whether the phone's link to its relay `home` is up.
fn relay_up(phone: &NdnEngine) -> bool {
    linked(phone, "home")
}

/// Whether the phone's link labelled `label` is up.
fn linked(phone: &NdnEngine, label: &str) -> bool {
    link(&status(phone), label).is_some_and(|l| l.paths.iter().any(|p| p.kind == "link"))
}

fn until(what: &str, mut done: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < WITHIN, "not within {WITHIN:?}: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
    start.elapsed()
}

fn phone_gets(phone: &NdnEngine, name: &str) -> Result<Vec<u8>, NdnError> {
    phone.get(name.into())
}

#[test]
fn the_app_reaches_a_desktop_device_through_its_relay_and_then_directly() {
    let home = Home::new();
    let woken = Arc::new(Woken::default());
    let relay = relay(&home, &woken);
    let desk = desk(&home, &relay);
    let phone = phone(&home);
    phone
        .add_relay(home_relay(&relay, NdnLinkMode::Always, false))
        .unwrap();
    until("the phone links to its relay", || relay_up(&phone));
    let r = status(&phone);
    let home_link = link(&r, "home").unwrap();
    assert_eq!(home_link.device.as_deref(), Some("/home/node/relay"));
    assert_eq!(
        home_link.relay.as_ref().unwrap().state,
        "linked",
        "{home_link:?}"
    );

    // Through the relay, both ways.
    let desk_hello = format!("{NS}/member/desk/hello");
    until("the phone reaches the desk", || {
        phone_gets(&phone, &desk_hello).is_ok_and(|c| c == b"from the desk")
    });
    until("the desk reaches the phone", || {
        desk.get(&format!("{NS}/member/phone/hello"))
            .is_some_and(|c| c == b"from the phone")
    });

    // Members linked to the same relay get a direct path by membership: no
    // peer entry names the desk.
    until("a direct path between the phone and the desk", || {
        status(&phone).links.iter().any(|l| {
            l.device.as_deref() == Some("/home/member/desk")
                && l.paths.iter().any(|p| p.kind == "direct")
        })
    });
    assert!(phone_gets(&phone, &desk_hello).is_ok_and(|c| c == b"from the desk"));
    assert!(woken.0.lock().is_empty(), "the relay woke an awake phone");
    phone.shutdown();
}

#[test]
fn link_modes_and_the_app_lifecycle() {
    let home = Home::new();
    let woken = Arc::new(Woken::default());
    let relay = relay(&home, &woken);
    let desk = desk(&home, &relay);
    let desk_hello = format!("{NS}/member/desk/hello");
    let phone = phone(&home);

    // Off: configured, not linked until the app asks.
    phone
        .add_relay(home_relay(&relay, NdnLinkMode::Off, false))
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !relay_up(&phone),
        "an off link linked: {:?}",
        status(&phone)
    );
    phone.connect_link("home".into()).unwrap();
    until("the app asked for the off link", || relay_up(&phone));
    until("the phone reaches the desk", || {
        phone_gets(&phone, &desk_hello).is_ok()
    });
    phone.disconnect_link("home".into()).unwrap();
    until("the off link closed when the app said so", || {
        !relay_up(&phone)
    });
    std::thread::sleep(Duration::from_secs(2));
    assert!(!relay_up(&phone), "an off link linked again by itself");

    // On demand: linked while the app is active, closed after the idle time
    // in the background, linked again for an outgoing Interest. The phone
    // has a direct path to the desk by now; it asks for a name only the
    // relay serves, so the Interest needs the relay link.
    phone
        .set_link_mode("home".into(), NdnLinkMode::OnDemand { idle_secs: 2 })
        .unwrap();
    until("an on-demand link links while the app is active", || {
        relay_up(&phone)
    });
    assert!(matches!(
        link(&status(&phone), "home").unwrap().mode,
        Some(NdnLinkMode::OnDemand { idle_secs: 2 })
    ));
    phone.set_app_active(false);
    assert!(!status(&phone).active);
    until("the on-demand link closes idle in the background", || {
        !relay_up(&phone)
    });
    assert!(
        phone_gets(&phone, &format!("{NS}/node/relay/hello")).is_ok_and(|c| c == b"from the relay"),
        "an outgoing Interest links the on-demand link again"
    );
    assert!(relay_up(&phone));
    phone.set_app_active(true);

    // Always: linked, whatever the app does.
    phone
        .set_link_mode("home".into(), NdnLinkMode::Always)
        .unwrap();
    phone.set_app_active(false);
    std::thread::sleep(Duration::from_secs(4));
    assert!(relay_up(&phone), "an always link closed in the background");
    drop(desk);
    phone.shutdown();
}

#[test]
fn a_sleeping_phone_is_woken_and_gets_the_held_interest() {
    let home = Home::new();
    let woken = Arc::new(Woken::default());
    let relay = Arc::new(relay(&home, &woken));
    let phone = phone(&home);
    let phone_hello = format!("{NS}/member/phone/hello");
    phone
        .add_relay(home_relay(
            &relay,
            NdnLinkMode::OnDemand { idle_secs: 1 },
            true,
        ))
        .unwrap();
    until("the phone links to its relay", || relay_up(&phone));
    phone
        .set_wake_token("home".into(), Some(b"push-token".to_vec()))
        .unwrap();
    // An awake phone is never woken.
    until("the relay reaches the phone", || {
        relay.get(&phone_hello).is_some()
    });
    assert!(woken.0.lock().is_empty(), "the relay woke an awake phone");

    phone.set_app_active(false);
    until("the phone sleeps", || !relay_up(&phone));
    // The relay's own engine asks the sleeping phone: the relay holds the
    // Interest and hands the token to its notifier; the app, woken, links
    // again and the held Interest is answered within its lifetime.
    let asker = std::thread::spawn({
        let relay = Arc::clone(&relay);
        move || relay.get(&phone_hello)
    });
    until("the relay wakes the phone", || !woken.0.lock().is_empty());
    let (device, token) = woken.0.lock()[0].clone();
    assert_eq!(device, Some(n("/home/member/phone")));
    assert_eq!(&token[..], b"push-token");
    phone.set_app_active(true);
    assert_eq!(
        asker.join().unwrap().as_deref(),
        Some(&b"from the phone"[..])
    );
    phone.shutdown();
}

#[test]
fn a_network_change_moves_the_links() {
    let home = Home::new();
    let woken = Arc::new(Woken::default());
    let relay = relay(&home, &woken);
    let desk = desk(&home, &relay);
    let desk_hello = format!("{NS}/member/desk/hello");
    let phone = phone(&home);
    phone
        .add_relay(home_relay(&relay, NdnLinkMode::Always, false))
        .unwrap();
    until("the phone reaches the desk", || {
        phone_gets(&phone, &desk_hello).is_ok()
    });
    let before = status(&phone).local_address.unwrap();

    // The platform hands over a socket on the new network.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let after = socket.local_addr().unwrap().to_string();
    assert_ne!(before, after);
    phone.network_changed(Some(socket.into_raw_fd())).unwrap();
    assert_eq!(
        status(&phone).local_address.as_deref(),
        Some(after.as_str())
    );
    until("the relay link survives the move", || relay_up(&phone));
    until("the phone reaches the desk from its new address", || {
        phone_gets(&phone, &desk_hello).is_ok_and(|c| c == b"from the desk")
    });
    until("the desk reaches the phone at its new address", || {
        desk.get(&format!("{NS}/member/phone/hello")).is_some()
    });
    phone.shutdown();
}

#[test]
fn the_link_calls_say_why_they_refuse() {
    let home = Home::new();
    let engine = NdnEngine::new(engine_config()).unwrap();
    let not_running = engine.link_status().unwrap_err().to_string();
    assert!(not_running.contains("start_links"), "{not_running}");
    let config = NdnLinksConfig {
        socket_fd: None,
        bind: Some("127.0.0.1:0".into()),
        listen: false,
        relay_count: 1,
        use_namespace_relays: true,
        namespace_relay_mode: NdnLinkMode::Always,
        namespace_relay_hold: false,
        issuers: Vec::new(),
        keep_alive_secs: None,
        idle_timeout_secs: None,
    };
    let no_identity = engine.start_links(config.clone()).unwrap_err().to_string();
    assert!(no_identity.contains("no identity loaded"), "{no_identity}");
    engine.shutdown();

    let woken = Arc::new(Woken::default());
    let relay = relay(&home, &woken);
    let phone = phone(&home);
    let again = phone.start_links(config).unwrap_err().to_string();
    assert!(again.contains("stop_links"), "{again}");
    let bad_key = NdnRelay {
        label: "community".into(),
        key: Some("not-a-key".into()),
        device: None,
        ..home_relay(&relay, NdnLinkMode::Always, false)
    };
    let refused = phone.add_relay(bad_key).unwrap_err().to_string();
    assert!(refused.contains("64 hex digits"), "{refused}");
    phone
        .add_relay(home_relay(&relay, NdnLinkMode::Always, false))
        .unwrap();
    let twice = phone
        .add_relay(home_relay(&relay, NdnLinkMode::Always, false))
        .unwrap_err()
        .to_string();
    assert!(twice.contains("already has a relay"), "{twice}");
    let unknown = phone
        .set_link_mode("nowhere".into(), NdnLinkMode::Off)
        .unwrap_err()
        .to_string();
    assert!(unknown.contains("link_status"), "{unknown}");
    phone.remove_relay("home".into()).unwrap();
    assert!(link(&status(&phone), "home").is_none());
    phone.stop_links();
    assert!(phone.link_status().is_err());
    phone.shutdown();
}

/// The phone is a member of `/home` (its node identity: its link key) and,
/// enrolled after its links started, of `/work`. A relay of `/work` — which
/// holds only `/work`'s trust context, and serves only `/work` — admits it
/// by the `/work` membership its hello carries, bound to the link.
#[test]
fn a_relay_of_another_prefix_admits_the_phone_by_its_membership_there() {
    let home = Home::new();
    let work = Home::of("/work");
    let woken = Arc::new(Woken::default());
    let relay = relay(&work, &woken);
    let phone = phone(&home);

    work.adopt_in(&phone);
    work.load_phone_identity(&phone, 10);
    let identities = phone.identities();
    assert_eq!(identities.len(), 2, "{identities:?}");
    assert_eq!(
        phone.principal_name().unwrap(),
        "/home/member/phone",
        "the node identity stays"
    );

    phone
        .add_relay(prefix_relay(
            "work",
            "/work",
            &relay,
            NdnLinkMode::Always,
            false,
        ))
        .unwrap();
    until(
        "the /work relay admits the phone by its /work membership",
        || linked(&phone, "work"),
    );
    assert_eq!(
        link(&status(&phone), "work").unwrap().device.as_deref(),
        Some("/work/node/relay")
    );
    until("the phone reaches the /work relay", || {
        phone_gets(&phone, "/work/node/relay/hello").is_ok_and(|c| c == b"from the relay")
    });
    phone.shutdown();
}
