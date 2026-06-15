//! Engine-side **producer of record** for a node-signed object whose segment
//! content is streamed from a keyless source — the producer half of "bulk off
//! the seam" (see `.claude/notes/vpn/` + the substrate-extension PIT doctrine).
//!
//! A leaf app (e.g. a share UI) holds a file but no key. Instead of the leaf
//! answering one signed Interest per segment across the process seam (the
//! measured ~1.4 Mbps ceiling), the **engine** — which holds the node key and
//! owns the radio faces — becomes the producer of record:
//!
//! - it serves the public RDR **metadata** (signed) from a metadata-only
//!   [`PreparedObject`], so it owns naming without holding bytes;
//! - on the first radio segment demand it starts a **demand-paced relay** that
//!   streams the leaf's raw segments ([`serve_object_stream`](ndn_app::serve_object_stream)),
//!   re-signs each with the node key, and inserts it into the engine CS — but
//!   only ever `LOOKAHEAD` segments ahead of the consumer's actual demand, so its
//!   CS footprint is bounded regardless of file size;
//! - for a segment the relay has already passed and that has aged out of the CS
//!   (a radio-loss retransmit, or a fresh fetch of an old offer), it does a
//!   **backward re-fetch**: a one-shot pull of that one segment from the leaf,
//!   re-signed and served. This is what lets a file larger than the CS survive
//!   loss — the relay alone is forward-only and could not re-serve such a segment.
//!
//! Demand is read from the consumer's segment Interests that miss the CS and
//! reach the producer-of-record handler: the highest is the *demand front* (paces
//! the relay forward); a miss *below* the relay's produced front is a backward
//! re-fetch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;

use ndn_app::rdr::PreparedObject;
use ndn_app::{Consumer, EngineAppExt, Producer, Responder, SubscribeOptions};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::{SignWith, Signer};
use ndn_store::{CsMeta, ErasedContentStore};

/// Default lookahead: how far ahead of the consumer's demand front the relay
/// keeps the CS filled. Bounds the relay's lead (and CS footprint ≈ this many
/// segments ≈ 4 MB at 8 KiB) regardless of file size. Must be comfortably below
/// the engine CS capacity (the CS must hold the consumer window + this lead).
pub const DEFAULT_LOOKAHEAD: u64 = 512;
/// Re-express cadence for the relay's subscription to the leaf. Also bounds how
/// far the leaf streams past the relay's read while the relay is paused.
const RELAY_CREDIT: u32 = 64;
/// Persistent PIT lifetime for the relay's subscription to the source.
const RELAY_LIFETIME: Duration = Duration::from_secs(300);
/// Freshness stamped on relayed segments so they stay servable from the CS for
/// the duration of a transfer (the in-flight window; not durable storage).
const SEGMENT_FRESHNESS: Duration = Duration::from_secs(120);
/// Lifetime / wait for a one-shot backward re-fetch from the leaf.
const REFETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared between the producer-of-record serve loop (which advances it) and the
/// relay loop (which paces to it): the highest segment the consumer has demanded,
/// and a notifier to wake the relay when it advances.
#[derive(Clone)]
struct Demand {
    front: Arc<AtomicU64>,
    wake: Arc<Notify>,
}

/// State the serve handler shares with the relay for backward re-fetch:
/// the relay's produced front (segments below it that miss are evicted), and the
/// leaf's versioned content prefix (learned from the stream) to pull them from.
#[derive(Clone)]
struct Refetch {
    produced: Arc<AtomicU64>,
    source_versioned: Arc<StdMutex<Option<Name>>>,
    consumer: Arc<AsyncMutex<Consumer>>,
    public_versioned: Name,
    signer: Arc<dyn Signer>,
    cs: Arc<dyn ErasedContentStore>,
}

/// Everything the relay loop needs; taken once (lazily, on first demand) so an
/// offer that is never fetched costs nothing.
struct RelayInputs {
    consumer: Consumer,
    cs: Arc<dyn ErasedContentStore>,
    producer: Arc<Producer>,
    signer: Arc<dyn Signer>,
    /// `<public>/v=<ver>` — the segment prefix the relay names + signs under.
    versioned: Name,
    /// The leaf's internal content prefix the relay subscribes to.
    source_prefix: Name,
    last_seg: u64,
    lookahead: u64,
    demand: Demand,
    /// Shared with the handler: produced front + learned source versioned prefix.
    produced: Arc<AtomicU64>,
    source_versioned: Arc<StdMutex<Option<Name>>>,
    cancel: CancellationToken,
}

/// Stand up the producer of record for `public_name`, relaying signed segments
/// from `source_prefix`. `size`/`chunk` define the RDR metadata; `signer` is the
/// node key. Serving stops when `cancel` fires. Spawns its tasks on the current
/// Tokio runtime — call from within the engine's runtime.
#[allow(clippy::too_many_arguments)]
pub fn spawn_object_relay(
    engine: &ForwarderEngine,
    public_name: Name,
    source_prefix: Name,
    size: u64,
    chunk: usize,
    signer: Arc<dyn Signer>,
    lookahead: u64,
    cancel: CancellationToken,
) {
    let meta = Arc::new(PreparedObject::build_metadata(
        public_name.clone(),
        size,
        chunk,
    ));
    let versioned = meta.versioned_name.clone();
    let last_seg = meta.last_seg;

    let producer = Arc::new(engine.register_producer(public_name.clone(), cancel.child_token()));

    let demand = Demand {
        front: Arc::new(AtomicU64::new(0)),
        wake: Arc::new(Notify::new()),
    };
    let produced = Arc::new(AtomicU64::new(0));
    let source_versioned = Arc::new(StdMutex::new(None));

    // Shared backward-re-fetch context (one-shot pull of an evicted segment).
    let refetch = Refetch {
        produced: Arc::clone(&produced),
        source_versioned: Arc::clone(&source_versioned),
        consumer: Arc::new(AsyncMutex::new(engine.app_consumer(cancel.child_token()))),
        public_versioned: versioned.clone(),
        signer: Arc::clone(&signer),
        cs: engine.cs(),
    };

    let inputs = Arc::new(StdMutex::new(Some(RelayInputs {
        consumer: engine.app_consumer(cancel.child_token()),
        cs: engine.cs(),
        producer: Arc::clone(&producer),
        signer: Arc::clone(&signer),
        versioned,
        source_prefix,
        last_seg,
        lookahead: lookahead.max(1),
        demand: demand.clone(),
        produced,
        source_versioned,
        cancel: cancel.child_token(),
    })));

    let serve_producer = Arc::clone(&producer);
    tokio::spawn(async move {
        let _ = serve_producer
            .serve(move |interest, responder| {
                let meta = Arc::clone(&meta);
                let signer = Arc::clone(&signer);
                let inputs = Arc::clone(&inputs);
                let demand = demand.clone();
                let refetch = refetch.clone();
                async move {
                    if let Ok(Some(wire)) =
                        meta.answer_interest(&interest.name, Some(signer.as_ref())).await
                    {
                        // Metadata discovery.
                        responder.respond_bytes(wire).await.ok();
                        return;
                    }
                    let Some(seg) = interest
                        .name
                        .components()
                        .last()
                        .and_then(|c| c.as_segment())
                    else {
                        return;
                    };
                    // Advance the demand front so the relay paces to it, and start
                    // the relay if it isn't running.
                    demand.front.fetch_max(seg, Ordering::Relaxed);
                    demand.wake.notify_one();
                    if let Some(inp) = inputs.lock().unwrap().take() {
                        tokio::spawn(run_relay(inp));
                    }
                    // A miss for a segment the relay already passed is an evicted
                    // segment (radio-loss retransmit / fresh fetch of an old
                    // offer): the forward-only relay won't re-stream it, so pull
                    // it one-shot from the leaf and serve it. Forward misses
                    // (>= produced front) are served by the relay's publish.
                    if seg < refetch.produced.load(Ordering::Relaxed) {
                        let src_ver = refetch.source_versioned.lock().unwrap().clone();
                        if let Some(src_ver) = src_ver {
                            tokio::spawn(backward_refetch(refetch, src_ver, seg, responder));
                        }
                    }
                }
            })
            .await;
    });
}

/// One-shot pull of a single evicted segment from the leaf, re-signed under the
/// public name and served to the pending Interest (and re-cached).
async fn backward_refetch(refetch: Refetch, source_versioned: Name, seg: u64, responder: Responder) {
    let src_seg = source_versioned.append_segment(seg);
    let interest = InterestBuilder::new(src_seg)
        .lifetime(REFETCH_TIMEOUT)
        .build();
    let data = {
        let mut consumer = refetch.consumer.lock().await;
        match consumer.fetch_wire(interest, REFETCH_TIMEOUT).await {
            Ok(d) => d,
            Err(_) => return,
        }
    };
    let content = data.content().cloned().unwrap_or_default();
    let pub_seg = refetch.public_versioned.append_segment(seg);
    let wire = match DataBuilder::new(pub_seg.clone(), content.as_ref())
        .freshness(SEGMENT_FRESHNESS)
        .sign_with(refetch.signer.as_ref())
        .await
    {
        Ok(w) => w,
        Err(_) => return,
    };
    let stale_at = now_ns() + SEGMENT_FRESHNESS.as_nanos() as u64;
    refetch
        .cs
        .insert_erased(wire.clone(), Arc::new(pub_seg), CsMeta { stale_at })
        .await;
    responder.respond_bytes(wire).await.ok();
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// The demand-paced relay loop: stream the source, re-sign each segment under the
/// public versioned name, cache + publish it — pausing whenever produced reaches
/// `demand_front + lookahead` so the lead (and CS footprint) stays bounded.
async fn run_relay(inp: RelayInputs) {
    let RelayInputs {
        consumer,
        cs,
        producer,
        signer,
        versioned,
        source_prefix,
        last_seg,
        lookahead,
        demand,
        produced,
        source_versioned,
        cancel,
    } = inp;
    let opts = SubscribeOptions {
        max_data_count: RELAY_CREDIT,
        lifetime: RELAY_LIFETIME,
        ..SubscribeOptions::default()
    };
    'resubscribe: loop {
        if cancel.is_cancelled() {
            return;
        }
        let mut sub = match consumer.subscribe(source_prefix.clone(), opts.clone()).await {
            Ok(s) => s,
            Err(_) => {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
                }
            }
        };
        loop {
            // Pace: don't read (so the leaf doesn't stream) more than `lookahead`
            // past the demand front. Pausing the read back-pressures the leaf.
            while produced.load(Ordering::Relaxed) > demand.front.load(Ordering::Relaxed) + lookahead
                && produced.load(Ordering::Relaxed) <= last_seg
            {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = demand.wake.notified() => {}
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                r = sub.recv() => match r {
                    Ok(data) => {
                        let Some(seg) = data
                            .name
                            .components()
                            .last()
                            .and_then(|c| c.as_segment())
                        else {
                            continue;
                        };
                        // Learn the leaf's versioned content prefix (everything but
                        // the trailing segment) for backward re-fetch.
                        if source_versioned.lock().unwrap().is_none() {
                            let comps = data.name.components();
                            if !comps.is_empty() {
                                *source_versioned.lock().unwrap() = Some(Name::from_components(
                                    comps[..comps.len() - 1].iter().cloned(),
                                ));
                            }
                        }
                        let content = data.content().cloned().unwrap_or_default();
                        let name = versioned.clone().append_segment(seg);
                        let wire = match DataBuilder::new(name.clone(), content.as_ref())
                            .freshness(SEGMENT_FRESHNESS)
                            .sign_with(signer.as_ref())
                            .await
                        {
                            Ok(w) => w,
                            Err(_) => continue,
                        };
                        let stale_at = now_ns() + SEGMENT_FRESHNESS.as_nanos() as u64;
                        cs.insert_erased(wire.clone(), Arc::new(name), CsMeta { stale_at })
                            .await;
                        producer.publish(wire).await.ok();
                        produced.store(produced.load(Ordering::Relaxed).max(seg + 1), Ordering::Relaxed);
                    }
                    Err(_) => continue 'resubscribe,
                }
            }
        }
    }
}
