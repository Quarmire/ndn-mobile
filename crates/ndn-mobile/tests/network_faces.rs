//! Witnesses for the network-face builder gaps:
//!
//! - #4 ergonomic route-to-peer: `with_*_peer` reserve stable face ids that
//!   surface as opaque [`PeerRef`]s, and `route_to_peer` installs a FIB route
//!   toward one without the caller ever naming a raw face id.
//! - #2 complete suspend/resume: every configured peer (not just multicast) is
//!   rebuilt on `resume_network_faces` with its original face id, so routes
//!   installed toward it stay valid across a background/foreground cycle.
//! - #8 strategy selection: the root forwarding strategy follows
//!   `with_strategy`.
//!
//! UDP unicast is used because `UdpFace::bind` binds an ephemeral local socket
//! and only records the peer address — it needs no reachable peer, so these run
//! without privileges or a second endpoint, on any CI host.

use ndn_mobile::{MobileEngine, MobileStrategy, Name, SecurityProfile};

const PEER_A: &str = "127.0.0.1:16363";
const PEER_B: &str = "127.0.0.1:16364";

async fn engine_with_udp_peers(peers: &[&str]) -> MobileEngine {
    let mut b = MobileEngine::builder().security_profile(SecurityProfile::Disabled);
    for p in peers {
        b = b.with_unicast_peer(p.parse().unwrap());
    }
    let (engine, _handle) = b.build().await.expect("engine build failed");
    engine
}

/// #4: a configured unicast peer is listed as a `PeerRef` carrying its URI, and
/// `route_to_peer` installs a FIB nexthop toward it that LPM resolves.
#[tokio::test]
async fn unicast_peer_is_listed_and_routable() {
    let engine = engine_with_udp_peers(&[PEER_A]).await;

    let peers = engine.peers();
    assert_eq!(peers.len(), 1, "one configured peer expected");
    assert_eq!(peers[0].uri(), format!("udp4://{PEER_A}"));

    let prefix: Name = "/ndn".parse().unwrap();
    engine.route_to_peer(prefix.clone(), &peers[0], 7);

    let entry = engine
        .engine()
        .fib()
        .lpm(&"/ndn/example/data".parse().unwrap())
        .expect("route_to_peer should have installed a FIB entry under /ndn");
    assert_eq!(entry.nexthops.len(), 1);
    assert_eq!(entry.nexthops[0].cost, 7);

    engine.shutdown().await;
}

/// #4: distinct peers get distinct stable face ids (distinct nexthops).
#[tokio::test]
async fn distinct_peers_get_distinct_faces() {
    let engine = engine_with_udp_peers(&[PEER_A, PEER_B]).await;
    let peers = engine.peers();
    assert_eq!(peers.len(), 2);

    engine.route_to_peer("/to/a", &peers[0], 0);
    engine.route_to_peer("/to/b", &peers[1], 0);

    let fib = engine.engine().fib();
    let a = fib.lpm(&"/to/a".parse().unwrap()).unwrap().nexthops[0].face_id;
    let b = fib.lpm(&"/to/b".parse().unwrap()).unwrap().nexthops[0].face_id;
    assert_ne!(a, b, "each peer must route out its own face");

    engine.shutdown().await;
}

/// #2: a unicast peer survives suspend/resume — it is rebuilt with the same
/// face id, so the route installed toward it before suspend still resolves to a
/// live face afterward. (Before this fix only the multicast face was rebuilt;
/// unicast/TCP/WS/serial peers were cancelled and never restored.)
#[tokio::test]
async fn peer_and_route_survive_suspend_resume() {
    let mut engine = engine_with_udp_peers(&[PEER_A]).await;
    let peers = engine.peers();
    engine.route_to_peer("/ndn", &peers[0], 0);

    let fib = engine.engine().fib();
    let peer_id_before = fib.lpm(&"/ndn".parse().unwrap()).unwrap().nexthops[0].face_id;
    assert!(
        engine.engine().faces().get(peer_id_before).is_some(),
        "peer face present after build"
    );

    engine.suspend_network_faces();
    engine.resume_network_faces().await;

    // The route still resolves to the same stable id, and a face is live there.
    let peer_id_after = engine
        .engine()
        .fib()
        .lpm(&"/ndn".parse().unwrap())
        .expect("route survives suspend/resume")
        .nexthops[0]
        .face_id;
    assert_eq!(
        peer_id_before, peer_id_after,
        "peer face id must be stable across suspend/resume"
    );
    assert!(
        engine.engine().faces().get(peer_id_after).is_some(),
        "peer face must be rebuilt on resume"
    );

    // peers() still reports the same peer.
    assert_eq!(engine.peers()[0].uri(), format!("udp4://{PEER_A}"));

    engine.shutdown().await;
}

/// #8: the root strategy defaults to best-route.
#[tokio::test]
async fn strategy_defaults_to_best_route() {
    let (engine, _h) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .unwrap();
    let root = engine
        .engine()
        .strategy_table()
        .lpm(&Name::root())
        .expect("a root strategy is always installed");
    assert!(
        root.name().to_string().contains("best-route"),
        "default root strategy should be best-route, got {}",
        root.name()
    );
    engine.shutdown().await;
}

/// #8: `with_strategy(Multicast)` installs the multicast strategy at the root.
#[tokio::test]
async fn strategy_selection_installs_multicast() {
    let (engine, _h) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .with_strategy(MobileStrategy::Multicast)
        .build()
        .await
        .unwrap();
    let root = engine
        .engine()
        .strategy_table()
        .lpm(&Name::root())
        .expect("a root strategy is always installed");
    assert!(
        root.name().to_string().contains("multicast"),
        "with_strategy(Multicast) should install multicast, got {}",
        root.name()
    );
    engine.shutdown().await;
}
