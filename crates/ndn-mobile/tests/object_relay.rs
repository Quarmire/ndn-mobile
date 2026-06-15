//! End-to-end witness for the producer-side "bulk off the seam" relay
//! (`ndn_mobile::spawn_object_relay`).
//!
//! Two engines linked by an in-memory face model the leaf↔node seam:
//! - **Engine A (leaf):** holds the file, serves it as a *raw* stream
//!   (`serve_object_stream`) under an internal content prefix — no key.
//! - **Engine B (node):** runs the relay/producer-of-record for the public,
//!   node-signed name. It serves the signed RDR metadata and, on segment demand,
//!   streams the raw segments from A, re-signs each with the node key, and caches
//!   them. A verifying consumer on B fetches the public object and gets back
//!   authentic, reassembled content.
//!
//! This proves the whole mechanism without a device: one streamed subscription
//! over the seam (not per-segment pull), signing at the key holder, and the
//! windowed fetch served from the node CS.
//!
//! Reverify: `cargo test -p ndn-mobile --test object_relay`

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use ndn_app::rdr::PreparedObject;
use ndn_app::{Consumer, EngineAppExt, serve_object_stream};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_mobile::spawn_object_relay;
use ndn_packet::Name;
use ndn_security::{KeyChain, TrustSchema, Validator};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

/// One end of an in-memory bidirectional engine↔engine face (the
/// `tun_datapath` pattern). `App` scope so raw NDN packets cross without LP.
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
            MemoryLink {
                id: id_a,
                rx: Mutex::new(b_to_a_rx),
                tx: a_to_b_tx,
            },
            MemoryLink {
                id: id_b,
                rx: Mutex::new(a_to_b_rx),
                tx: b_to_a_tx,
            },
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

/// Accept-all engine validator so the relay's signed subscription Interest
/// installs *true* persistence (one Interest → many Data); a real deployment
/// swaps in a trust schema. (Same rationale as the tun datapath witness.)
async fn build_engine() -> ForwarderEngine {
    build_engine_cs(64 * 1024 * 1024).await
}

/// As [`build_engine`] but with an explicit CS capacity, to force the
/// object-larger-than-CS case the demand-paced relay must survive.
async fn build_engine_cs(cs_bytes: usize) -> ForwarderEngine {
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    let mut config = EngineConfig::default();
    config.cs_capacity_bytes = cs_bytes;
    let (engine, shutdown) = EngineBuilder::new(config)
        .validator(validator)
        .build()
        .await
        .expect("engine build");
    std::mem::forget(shutdown);
    engine
}

#[tokio::test]
async fn relay_serves_node_signed_object_streamed_from_a_keyless_leaf() {
    let cancel = CancellationToken::new();

    // The node identity (key holder). The public object is named under it so the
    // hierarchical schema accepts node-signed segments + metadata.
    let node_kc = KeyChain::ephemeral("/ndn/node/test").expect("node keychain");
    let node_signer = node_kc.signer().expect("node signer");

    let engine_a = build_engine().await; // leaf (content source, keyless)
    let engine_b = build_engine().await; // node (relay / producer of record)

    // Seam link A↔B.
    let link_a_id = engine_a.faces().alloc_id();
    let link_b_id = engine_b.faces().alloc_id();
    let (link_a, link_b) = MemoryLink::pair(link_a_id, link_b_id, 256);
    engine_a.add_face(link_a, cancel.child_token());
    engine_b.add_face(link_b, cancel.child_token());

    let internal: Name = "/localhost/leaf/content/f1".parse().unwrap();
    let public: Name = "/ndn/node/test/file/f1".parse().unwrap();

    // B reaches the leaf's internal content prefix across the seam.
    engine_b.fib().add_nexthop(&internal, link_b_id, 0);

    // Payload: ~5 segments at 8 KiB.
    let payload: Vec<u8> = (0..34_000u32).map(|i| (i & 0xff) as u8).collect();
    let size = payload.len() as u64;

    // Leaf (A): serve the file as a raw stream — unsigned, no key.
    {
        let producer = engine_a.register_producer(internal.clone(), cancel.child_token());
        let prepared = Arc::new(PreparedObject::build(
            internal.clone(),
            Bytes::from(payload.clone()),
            8192,
        ));
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            let _ = serve_object_stream(producer, prepared, cancel).await;
        });
    }

    // Node (B): producer of record — serves signed metadata + relays signed
    // segments from the leaf stream.
    spawn_object_relay(
        &engine_b,
        public.clone(),
        internal.clone(),
        size,
        8192,
        node_signer,
        512,
        cancel.child_token(),
    );

    // Verifying consumer on B: authentic whole-object fetch against the node cert.
    let consumer: Consumer = engine_b.app_consumer(cancel.child_token());
    let reassembled = tokio::time::timeout(
        Duration::from_secs(10),
        consumer
            .verifying(node_kc.validator())
            .fetch_object(public.clone()),
    )
    .await
    .expect("fetch completed within 10s")
    .expect("verified fetch of the node-signed, leaf-streamed object");

    assert_eq!(
        reassembled.as_ref(),
        payload.as_slice(),
        "relayed + node-signed object reassembles to the leaf's content"
    );

    std::mem::forget((engine_a, engine_b));
    cancel.cancel();
}

/// Demand-pacing witness: an object **much larger than the node CS** still
/// completes. The relay keeps only `lookahead` segments ahead of the consumer's
/// demand front, so it never races ahead and evicts a not-yet-fetched segment
/// (which, before pacing, stalled big-file transfers at 0 segments received).
#[tokio::test]
async fn relay_streams_object_larger_than_cs_without_stalling() {
    let cancel = CancellationToken::new();

    let node_kc = KeyChain::ephemeral("/ndn/node/test").expect("node keychain");
    let node_signer = node_kc.signer().expect("node signer");

    let engine_a = build_engine().await; // leaf: full CS, holds its own copy
    // Node CS holds ~128 segments (1 MiB) — far smaller than the 300-segment
    // (~2.4 MB) object, so without pacing the relay races ahead and evicts a
    // not-yet-fetched segment (the big-file stall). The CS must still exceed the
    // consumer window (≤48) + the relay lookahead (32 below), the invariant the
    // demand-paced relay relies on.
    let engine_b = build_engine_cs(1024 * 1024).await;

    let link_a_id = engine_a.faces().alloc_id();
    let link_b_id = engine_b.faces().alloc_id();
    let (link_a, link_b) = MemoryLink::pair(link_a_id, link_b_id, 256);
    engine_a.add_face(link_a, cancel.child_token());
    engine_b.add_face(link_b, cancel.child_token());

    let internal: Name = "/localhost/leaf/content/big".parse().unwrap();
    let public: Name = "/ndn/node/test/file/big".parse().unwrap();
    engine_b.fib().add_nexthop(&internal, link_b_id, 0);

    // 300 segments at 8 KiB ≈ 2.4 MB ≫ the 512 KiB node CS.
    let payload: Vec<u8> = (0..(300u32 * 8192)).map(|i| (i & 0xff) as u8).collect();
    let size = payload.len() as u64;

    {
        let producer = engine_a.register_producer(internal.clone(), cancel.child_token());
        let prepared = Arc::new(PreparedObject::build(
            internal.clone(),
            Bytes::from(payload.clone()),
            8192,
        ));
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            let _ = serve_object_stream(producer, prepared, cancel).await;
        });
    }

    // Lookahead 32 ≪ the CS's ~64 segments, so the relay's bounded lead fits.
    spawn_object_relay(
        &engine_b,
        public.clone(),
        internal.clone(),
        size,
        8192,
        node_signer,
        32,
        cancel.child_token(),
    );

    let consumer: Consumer = engine_b.app_consumer(cancel.child_token());
    let reassembled = tokio::time::timeout(
        Duration::from_secs(30),
        consumer
            .verifying(node_kc.validator())
            .fetch_object(public.clone()),
    )
    .await
    .expect("object larger than the CS completed (demand pacing, no eviction stall)")
    .expect("verified fetch of the large node-signed object");

    assert_eq!(reassembled.len(), payload.len(), "full object reassembled");
    assert_eq!(reassembled.as_ref(), payload.as_slice());

    std::mem::forget((engine_a, engine_b));
    cancel.cancel();
}
