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
//! - on the first radio segment demand it starts a **demand-paced relay**: it
//!   streams the leaf's raw segments
//!   ([`serve_object_stream`](ndn_app::serve_object_stream)), re-signs each with
//!   the node key, and inserts it into the engine CS — but only ever stays
//!   `LOOKAHEAD` segments ahead of the consumer's actual demand.
//!
//! **Demand pacing** is the key to handling files larger than the CS. The
//! consumer's segment Interests that miss the CS reach the producer-of-record
//! handler; the highest such segment is the *demand front*. The relay produces
//! up to `demand_front + LOOKAHEAD` and then pauses (back-pressuring the leaf
//! via the seam) until the demand front advances. So its lead — and therefore
//! its CS footprint — is bounded by `LOOKAHEAD`, independent of file size, and it
//! never races ahead and evicts a segment the consumer hasn't fetched yet (which
//! a forward-only relay could not re-serve — the bug that stalled big files).
//! Each freshly produced segment is also published, satisfying the pending
//! front Interest immediately instead of waiting for the consumer's retransmit.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use ndn_app::rdr::PreparedObject;
use ndn_app::{Consumer, EngineAppExt, Producer, SubscribeOptions};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{SignWith, Signer};
use ndn_store::{CsMeta, ErasedContentStore};

/// Default lookahead: how far ahead of the consumer's demand front the relay
/// keeps the CS filled. Bounds the relay's lead (and CS footprint ≈ this many
/// segments ≈ 4 MB at 8 KiB) regardless of file size, so it never evicts a
/// not-yet-fetched segment. Must be comfortably below the engine CS capacity.
pub const DEFAULT_LOOKAHEAD: u64 = 512;
/// Re-express cadence for the relay's subscription to the leaf. Also bounds how
/// far the leaf streams past the relay's read while the relay is paused.
const RELAY_CREDIT: u32 = 64;
/// Persistent PIT lifetime for the relay's subscription to the source.
const RELAY_LIFETIME: Duration = Duration::from_secs(300);
/// Freshness stamped on relayed segments so they stay servable from the CS for
/// the duration of a transfer (the in-flight window; not durable storage).
const SEGMENT_FRESHNESS: Duration = Duration::from_secs(120);

/// Shared between the producer-of-record serve loop (which advances it) and the
/// relay loop (which paces to it): the highest segment the consumer has demanded
/// (a CS-miss Interest), and a notifier to wake the relay when it advances.
#[derive(Clone)]
struct Demand {
    front: Arc<AtomicU64>,
    wake: Arc<Notify>,
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
    /// Last segment index of the object (FinalBlockID), so the relay stops.
    last_seg: u64,
    /// Segments to keep produced ahead of the demand front.
    lookahead: u64,
    demand: Demand,
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
    // Metadata-only: serves correct RDR metadata for the public name; segment
    // reads return None (content comes from the relay).
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

    // Relay inputs, taken exactly once on first segment demand.
    let inputs = Arc::new(Mutex::new(Some(RelayInputs {
        consumer: engine.app_consumer(cancel.child_token()),
        cs: engine.cs(),
        producer: Arc::clone(&producer),
        signer: Arc::clone(&signer),
        versioned,
        source_prefix,
        last_seg,
        lookahead: lookahead.max(1),
        demand: demand.clone(),
        cancel: cancel.child_token(),
    })));

    // Serve loop: answer metadata (signed); on a segment Interest, advance the
    // demand front (so the relay paces to it) and lazily start the relay. The
    // Interest pends and is served from the CS / the relay's publish.
    let serve_producer = Arc::clone(&producer);
    tokio::spawn(async move {
        let _ = serve_producer
            .serve(move |interest, responder| {
                let meta = Arc::clone(&meta);
                let signer = Arc::clone(&signer);
                let inputs = Arc::clone(&inputs);
                let demand = demand.clone();
                async move {
                    match meta.answer_interest(&interest.name, Some(signer.as_ref())).await {
                        Ok(Some(wire)) => {
                            // Metadata discovery.
                            responder.respond_bytes(wire).await.ok();
                        }
                        _ => {
                            // Segment demand (metadata-only object reads None):
                            // advance the demand front to this segment so the
                            // relay produces up to it + LOOKAHEAD, and start the
                            // relay if it isn't running.
                            if let Some(seg) = interest
                                .name
                                .components()
                                .last()
                                .and_then(|c| c.as_segment())
                            {
                                demand.front.fetch_max(seg, Ordering::Relaxed);
                                demand.wake.notify_one();
                            }
                            if let Some(inp) = inputs.lock().unwrap().take() {
                                tokio::spawn(run_relay(inp));
                            }
                        }
                    }
                }
            })
            .await;
    });
}

/// The demand-paced relay loop: stream the source, re-sign each segment under
/// the public versioned name, cache + publish it — pausing whenever produced
/// reaches `demand_front + LOOKAHEAD` so the lead (and CS footprint) stays
/// bounded and no not-yet-fetched segment is evicted.
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
        cancel,
    } = inp;
    let opts = SubscribeOptions {
        max_data_count: RELAY_CREDIT,
        lifetime: RELAY_LIFETIME,
        ..SubscribeOptions::default()
    };
    // Next segment we expect to produce; the leaf streams in order.
    let mut produced: u64 = 0;
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
            // Pace: don't read (and so don't let the leaf stream) more than
            // LOOKAHEAD past the consumer's demand front. Pausing the read
            // back-pressures the leaf through the seam.
            while produced > demand.front.load(Ordering::Relaxed) + lookahead && produced <= last_seg
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
                        // Cache for the windowed pull (ahead-of-demand segments
                        // have no pending PIT, so caching is what serves them);
                        // also publish to satisfy a segment already pending.
                        let now_ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as u64;
                        let stale_at = now_ns + SEGMENT_FRESHNESS.as_nanos() as u64;
                        cs.insert_erased(wire.clone(), Arc::new(name), CsMeta { stale_at })
                            .await;
                        producer.publish(wire).await.ok();
                        produced = produced.max(seg + 1);
                    }
                    // Budget spent / source flap: re-subscribe and continue.
                    Err(_) => continue 'resubscribe,
                }
            }
        }
    }
}
