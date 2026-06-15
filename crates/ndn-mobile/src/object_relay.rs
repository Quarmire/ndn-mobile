//! Engine-side **producer of record** for a node-signed object whose segment
//! content is streamed from a keyless source — the producer half of "bulk off
//! the seam" (see `.claude/notes/vpn/` + the substrate-extension PIT doctrine).
//!
//! A leaf app (e.g. a share UI) holds a file but no key. Instead of the leaf
//! answering one signed Interest per segment across the process seam (4 seam
//! crossings/segment, the measured ~1.4 Mbps ceiling), the **engine** — which
//! holds the node key and owns the radio faces — becomes the producer of record:
//!
//! - it serves the public RDR **metadata** (signed) from a metadata-only
//!   [`PreparedObject`], so it owns naming without holding bytes;
//! - on the first radio segment demand it starts a **relay**: one persistent
//!   subscription to the leaf's internal content prefix
//!   ([`serve_object_stream`](ndn_app::serve_object_stream)), each raw segment
//!   re-framed under the public versioned name, **signed with the node key**, and
//!   inserted into the engine Content Store (the in-flight window). The radio
//!   consumer's windowed fetch is served from that CS.
//!
//! So the leaf is never on the per-segment path and never signs; the key holder
//! signs once per segment, locally, and the seam carries one credit-gated stream
//! instead of per-segment pulls.
//!
//! v0 scope: credit is a fixed window (bounds how far ahead of demand we stream);
//! full radio-demand coupling and the one-shot re-fetch of a CS-evicted far-back
//! segment are follow-ups. Authorization (the leaf's capability / name scope) is
//! expected to be checked by the caller before invoking this.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;

use ndn_app::rdr::PreparedObject;
use ndn_app::{Consumer, EngineAppExt, Producer, SubscribeOptions};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{SignWith, Signer};
use ndn_store::{CsMeta, ErasedContentStore};

/// Segments one relay subscription pulls before re-expression — bounds how far
/// ahead of radio demand the relay streams from the source.
const RELAY_CREDIT: u32 = 64;
/// Persistent PIT lifetime for the relay's subscription to the source.
const RELAY_LIFETIME: Duration = Duration::from_secs(300);
/// Freshness stamped on relayed segments so they stay servable from the CS for
/// the duration of a transfer (the in-flight window; not durable storage).
const SEGMENT_FRESHNESS: Duration = Duration::from_secs(120);

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

    let producer = Arc::new(engine.register_producer(public_name.clone(), cancel.child_token()));

    // Relay inputs, taken exactly once on first segment demand.
    let inputs = Arc::new(Mutex::new(Some(RelayInputs {
        consumer: engine.app_consumer(cancel.child_token()),
        cs: engine.cs(),
        producer: Arc::clone(&producer),
        signer: Arc::clone(&signer),
        versioned,
        source_prefix,
        cancel: cancel.child_token(),
    })));

    // Serve loop: answer metadata (signed); on a segment Interest, lazily start
    // the relay and let its CS fills satisfy the windowed fetch.
    let serve_producer = Arc::clone(&producer);
    tokio::spawn(async move {
        let _ = serve_producer
            .serve(move |interest, responder| {
                let meta = Arc::clone(&meta);
                let signer = Arc::clone(&signer);
                let inputs = Arc::clone(&inputs);
                async move {
                    match meta.answer_interest(&interest.name, Some(signer.as_ref())).await {
                        Ok(Some(wire)) => {
                            // Metadata discovery.
                            responder.respond_bytes(wire).await.ok();
                        }
                        _ => {
                            // Segment demand (metadata-only object reads None):
                            // start the relay once; the Interest pends and is
                            // served from the CS as the relay fills it.
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

/// The relay loop: subscribe to the source stream, re-sign each segment under the
/// public versioned name, and cache it (plus publish, to satisfy any already-
/// pending segment Interest promptly).
async fn run_relay(inp: RelayInputs) {
    let RelayInputs {
        consumer,
        cs,
        producer,
        signer,
        versioned,
        source_prefix,
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
                    }
                    // Budget spent / source flap: re-subscribe and continue.
                    Err(_) => continue 'resubscribe,
                }
            }
        }
    }
}
