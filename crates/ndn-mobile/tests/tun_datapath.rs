//! Integration witness for the two-endpoint VPN datapath (`tun` feature).
//!
//! Stands up two independent `ForwarderEngine`s linked by an in-memory
//! engine↔engine face (`MemoryLink`, the `dv_integration` pattern), runs the
//! persistent-Interest tunnel (`spawn_tunnel`) on each, and asserts that an IP
//! packet injected at one endpoint's tun handle emerges at the other's — in
//! both directions. This exercises the full path: `TunHandle::inject` →
//! producer streams Data into the peer's persistent PIT entry → forwarded over
//! the link → peer's `Consumer::subscribe` recv → `TunHandle::next`.
//!
//! Reverify: `cargo test -p ndn-mobile --features tun --test tun_datapath`
#![cfg(feature = "tun")]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_mobile::{Name, TunConfig, TunHandle, spawn_tunnel};
use ndn_security::{TrustSchema, Validator};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

/// One end of an in-memory bidirectional engine↔engine face. Local-scope
/// (`App`) so the pipeline carries raw NDN packets without LP framing — both
/// ends match.
struct MemoryLink {
    id: FaceId,
    rx: Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

impl MemoryLink {
    fn pair(id_a: FaceId, id_b: FaceId, buffer: usize) -> (MemoryLink, MemoryLink) {
        let (a_to_b_tx, a_to_b_rx) = mpsc::channel(buffer);
        let (b_to_a_tx, b_to_a_rx) = mpsc::channel(buffer);
        (
            MemoryLink { id: id_a, rx: Mutex::new(b_to_a_rx), tx: a_to_b_tx },
            MemoryLink { id: id_b, rx: Mutex::new(a_to_b_rx), tx: b_to_a_tx },
        )
    }
}

impl Transport for MemoryLink {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::App
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

/// A minimal IPv4/UDP-shaped packet so `parse_ip_flow` recognizes it; the
/// `marker` byte distinguishes packets. Content is opaque to the tunnel.
fn ip_packet(marker: u8) -> Bytes {
    let mut p = vec![0u8; 32];
    p[0] = 0x45; // IPv4, IHL=5
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p[20..22].copy_from_slice(&4242u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[28] = marker;
    Bytes::from(p)
}

async fn build_engine() -> ForwarderEngine {
    // An accept-all validator makes the PIT install *true* persistence for the
    // signed subscription Interest (one Interest → many Data). Without it the
    // persistent Interest degrades to one-shot. A real deployment swaps in a
    // trust schema; the subscription Interest is signed either way.
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(validator)
        .build()
        .await
        .expect("engine build");
    // Keep the engine alive for the test's duration.
    std::mem::forget(shutdown);
    engine
}

/// Inject `pkt` at `from` and assert it emerges intact at `to` within 5 s.
async fn assert_traverses(from: &TunHandle, to: &TunHandle, pkt: Bytes) {
    from.inject(pkt.clone()).await.expect("inject");
    let got = tokio::time::timeout(Duration::from_secs(5), to.next())
        .await
        .expect("packet did not traverse the tunnel within 5s")
        .expect("tun handle closed");
    assert_eq!(got, pkt, "packet corrupted in transit");
}

/// Two engines linked by an in-memory face, each running a tunnel endpoint:
/// A (self=/vpn/a, peer=/vpn/b) and B (self=/vpn/b, peer=/vpn/a). Returns the
/// two tun handles. `cancel` owns every spawned task and face.
async fn two_endpoint_tunnel(cancel: &CancellationToken) -> (Arc<TunHandle>, Arc<TunHandle>) {
    let engine_a = build_engine().await;
    let engine_b = build_engine().await;

    let link_a_id = engine_a.faces().alloc_id();
    let link_b_id = engine_b.faces().alloc_id();
    let (link_a, link_b) = MemoryLink::pair(link_a_id, link_b_id, 256);
    engine_a.add_face(link_a, cancel.child_token());
    engine_b.add_face(link_b, cancel.child_token());

    let prefix_a = Name::from("/vpn/a");
    let prefix_b = Name::from("/vpn/b");

    // Route each endpoint's *peer* prefix across the link. `spawn_tunnel`
    // installs the local route for each endpoint's *own* (producer) prefix.
    engine_a.fib().add_nexthop(&prefix_b, link_a_id, 0);
    engine_b.fib().add_nexthop(&prefix_a, link_b_id, 0);

    let tun_a = spawn_tunnel(&engine_a, TunConfig::new(prefix_a.clone(), prefix_b.clone()), cancel.child_token());
    let tun_b = spawn_tunnel(&engine_b, TunConfig::new(prefix_b, prefix_a), cancel.child_token());

    // Keep the engines alive for the test (faces/tasks hold clones internally,
    // but the ForwarderEngine handle must outlive them).
    std::mem::forget((engine_a, engine_b));
    (tun_a, tun_b)
}

/// WIRING WITNESS: an IP packet injected at one endpoint emerges at the other,
/// in both directions. Exercises the full path inject → produce → forward over
/// the link → subscribe recv → deliver. This is the end-to-end datapath proof.
#[tokio::test]
async fn ip_packet_traverses_two_endpoint_tunnel_both_ways() {
    let cancel = CancellationToken::new();
    let (tun_a, tun_b) = two_endpoint_tunnel(&cancel).await;

    assert_traverses(&tun_a, &tun_b, ip_packet(0xA1)).await; // uplink A→B
    assert_traverses(&tun_b, &tun_a, ip_packet(0xB2)).await; // uplink B→A

    cancel.cancel();
}

/// STREAMING WITNESS: many packets each way over one persistent subscription.
///
/// This is the sparkstream contract — the subscription Interest is signed
/// (`Consumer::subscribe`) and the engine runs a validator (`build_engine`), so
/// `check_persistent` installs true persistence: one Interest is satisfied by
/// many Data (credit decrement), no per-packet re-expression. Reverify:
/// `cargo test -p ndn-mobile --features tun --test tun_datapath`
#[tokio::test]
async fn datapath_streams_multiple_packets() {
    let cancel = CancellationToken::new();
    let (tun_a, tun_b) = two_endpoint_tunnel(&cancel).await;

    for i in 0..5u8 {
        assert_traverses(&tun_a, &tun_b, ip_packet(0xA0 | i)).await;
        assert_traverses(&tun_b, &tun_a, ip_packet(0xB0 | i)).await;
    }

    cancel.cancel();
}
