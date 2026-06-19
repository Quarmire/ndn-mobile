//! Offer board — the tap-to-share producer surface.
//!
//! A node that wants to share files serves three routable things, all reachable
//! by a peer over the cost-aware `/ndn/node/<id>` route that discovery installs
//! (see [`crate::discovery`]):
//!
//! - the offerer's **certificate** at `/ndn/node/<id>/cert` — the TOFU pin
//!   target. A consumer fetches it on tap and pins it, so everything signed by
//!   this node then verifies. It is the same cert
//!   [`principal_cert_wire`](crate::identity_core::IdentityCore::principal_cert_wire)
//!   exports for the manual flow.
//! - a signed **manifest** at `/ndn/node/<id>/offers` — a JSON list of the
//!   current offerings (display name, MIME, size, and each file's routable
//!   object name). Rebuilt on every add/remove; signed with the operator key so
//!   a consumer that pinned the cert can verify the listing is authentic.
//! - each offered file as a signed RDR object under the offerer's **own
//!   identity**, `/<identity>/file/<fileId>` — an identity-stable,
//!   location-independent name (forward-compatible with the durable-repo
//!   roadmap). The consumer fetches it with `ForwardingHint = /ndn/node/<id>`;
//!   the Interest routes to this node, which strips the hint (its producer
//!   region, declared at discovery start) and forwards by name to this producer.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_app::demux::ServeGuard;
use ndn_app::rdr::PreparedObject;
use ndn_app::{Connection, DemuxConnection};
use ndn_packet::{Name, SubscriptionRequest};
use ndn_security::Signer;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

use crate::discovery::peer_node_prefix;
use crate::types::NdnError;

/// Where a file's **raw** segment content is streamed for the engine relay to
/// pull, re-sign, and serve under the public name (producer-side "bulk off the
/// seam"). Local scope: never leaves the leaf↔engine seam.
const INTERNAL_CONTENT_PREFIX: &str = "/localhost/ripple/content";

/// Segment size for offered file objects. 8 KiB is the proven-good value — a
/// 16 KiB experiment regressed cross-peer fetch to timeouts on-device (more
/// NDNLP fragments per Data → more loss over the lossy NDP UDP path), so stay at
/// what the working transfers used.
const OFFER_CHUNK: usize = 8192;

/// How many recent manifest versions to keep servable. Each add/remove bumps the
/// RDR version; a consumer mid-fetch (metadata for version N, then segments) must
/// still reach version N after a rebuild swapped in N+1, or its segment Interests
/// get `None` and the offer load hangs. A few covers overlapping offer churn.
const MANIFEST_HISTORY: usize = 6;

/// One shared file, with the guard that keeps its serve registration alive
/// (dropping it stops serving — see [`OfferBoard::remove_offer`]).
struct OfferEntry {
    display_name: String,
    mime: String,
    /// Routable object name: `/<identity>/file/<file_id>`.
    name: Name,
    size: usize,
    _guard: ServeGuard,
}

/// The tap-to-share producer board. Held by [`NdnClient`](crate::NdnClient) /
/// [`NdnEngine`](crate::NdnEngine) for the process lifetime; serving stops when
/// it (and its guards) drop.
pub(crate) struct OfferBoard {
    rt: Arc<Runtime>,
    demux: Arc<DemuxConnection>,
    signer: Arc<dyn Signer>,
    /// `/<identity>` — where file objects are named.
    identity_prefix: Name,
    /// `/ndn/node/<id>` — the routable node prefix (manifest at `.../offers`).
    node_prefix: Name,
    offers: Mutex<BTreeMap<String, OfferEntry>>,
    /// Recent signed manifest objects (newest first), shared with the serve loop.
    /// Each add/remove pushes a *new version* (RDR version = build timestamp) so
    /// content changes bust the cache; keeping the last few versions servable lets
    /// a consumer that fetched metadata for one version still pull its segments
    /// after a rebuild swapped in a newer one (otherwise `answer_interest` returns
    /// `None` for the now-stale version and the fetch hangs — the offer-load-fails-
    /// when-something-is-offered bug).
    manifest: Arc<Mutex<VecDeque<Arc<PreparedObject>>>>,
    _cert_guard: ServeGuard,
    _manifest_guard: ServeGuard,
}

impl OfferBoard {
    /// Stand up the board for `node_id` (this node's discovery id): register and
    /// serve the cert + manifest endpoints. Requires a loaded operator identity
    /// (so offerings can be signed and the manifest verified). Non-blocking —
    /// the serve loops run in the background.
    pub(crate) fn new(
        rt: Arc<Runtime>,
        demux: Arc<DemuxConnection>,
        signer: Arc<dyn Signer>,
        cert_wire: Vec<u8>,
        node_id: &str,
        identity_prefix: Name,
    ) -> Result<Arc<Self>, NdnError> {
        let node_prefix: Name = peer_node_prefix(node_id)
            .parse()
            .map_err(|_| NdnError::invalid_name(peer_node_prefix(node_id)))?;
        let cert_name = node_prefix.clone().append("cert");
        let manifest_name = node_prefix.clone().append("offers");

        // Initial (empty) manifest, signed; a new version is pushed on every
        // add/remove, keeping the last [`MANIFEST_HISTORY`] versions servable.
        let manifest = {
            let mut ring = VecDeque::with_capacity(MANIFEST_HISTORY);
            ring.push_front(build_manifest(&manifest_name, &node_prefix, &BTreeMap::new()));
            Arc::new(Mutex::new(ring))
        };

        // Cert endpoint: an RDR object whose content is the cert wire, for a
        // consumer to pin (TOFU). RDR (not a single Data) so it rides the
        // consumer's resilient `fetch_object` retry path and segments cleanly if
        // the cert exceeds a radio frame. Unsigned — pinning is the trust act.
        let cert_object = Arc::new(PreparedObject::build(
            cert_name.clone(),
            Bytes::from(cert_wire),
            8192,
        ));
        let manifest_for_serve = Arc::clone(&manifest);
        let signer_for_serve = Arc::clone(&signer);

        let (cert_guard, manifest_guard) = rt.block_on(async {
            // Register both endpoints with the forwarder so radio-arriving
            // Interests route across the seam to these handlers.
            demux.register_prefix(&cert_name).await.ok();
            demux.register_prefix(&manifest_name).await.ok();

            let cert_guard = demux.serve_scoped(cert_name.clone(), move |interest, responder| {
                let cert_object = Arc::clone(&cert_object);
                async move {
                    if let Ok(Some(wire)) = cert_object.answer_interest(&interest.name, None).await {
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            });

            // Manifest endpoint: answer RDR Interests from the current signed
            // manifest object.
            let manifest_guard =
                demux.serve_scoped(manifest_name.clone(), move |interest, responder| {
                    // Snapshot the recent versions (Arc clones, cheap).
                    let versions: Vec<Arc<PreparedObject>> =
                        manifest_for_serve.lock().unwrap().iter().cloned().collect();
                    let signer = Arc::clone(&signer_for_serve);
                    async move {
                        // Newest first: a metadata Interest is answered by the
                        // latest version; a `seg` Interest by whichever version it
                        // names — so a fetch that began before a rebuild still
                        // completes from the kept history instead of getting `None`.
                        for m in &versions {
                            if let Ok(Some(wire)) =
                                m.answer_interest(&interest.name, Some(signer.as_ref())).await
                            {
                                responder.respond_bytes(wire).await.ok();
                                return;
                            }
                        }
                    }
                });
            (cert_guard, manifest_guard)
        });

        Ok(Arc::new(Self {
            rt,
            demux,
            signer,
            identity_prefix,
            node_prefix,
            offers: Mutex::new(BTreeMap::new()),
            manifest,
            _cert_guard: cert_guard,
            _manifest_guard: manifest_guard,
        }))
    }

    /// Add (or replace) an in-memory offering: serve `content` as a signed RDR
    /// object at `/<identity>/file/<file_id>` and rebuild the manifest. Returns
    /// the routable object name a consumer fetches (with a `/ndn/node/<id>` hint).
    /// For large files prefer [`Self::add_offer_file`] (no full-RAM copy).
    pub(crate) fn add_offer(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        content: Vec<u8>,
    ) -> Result<String, NdnError> {
        if file_id.is_empty() {
            return Err(NdnError::engine("offer file_id must not be empty"));
        }
        let size = content.len();
        let object_name = self.identity_prefix.clone().append("file").append(&file_id);
        let prepared = Arc::new(PreparedObject::build(
            object_name.clone(),
            Bytes::from(content),
            OFFER_CHUNK,
        ));
        self.serve_prepared(file_id, display_name, mime, object_name, prepared, size)
    }

    /// Add (or replace) a **file-backed** offering: segments are read from `file`
    /// on demand, so an arbitrarily large file is served without ever loading it
    /// into RAM. `size` is the file's length. Fixes the offer-side memory ceiling
    /// (a large file as one `Vec<u8>` blew the Android heap → silent no-op).
    #[cfg(unix)]
    pub(crate) fn add_offer_file(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        file: std::fs::File,
        size: u64,
    ) -> Result<String, NdnError> {
        if file_id.is_empty() {
            return Err(NdnError::engine("offer file_id must not be empty"));
        }
        let object_name = self.identity_prefix.clone().append("file").append(&file_id);
        tracing::debug!(
            target: "ndn_boltffi::offer",
            %object_name, size, segs = size.div_ceil(OFFER_CHUNK as u64),
            "offer board: building file object"
        );
        let prepared = Arc::new(PreparedObject::build_from_file(
            object_name.clone(),
            file,
            size,
            OFFER_CHUNK,
        ));
        self.serve_prepared(file_id, display_name, mime, object_name, prepared, size as usize)
    }

    /// Shared tail of `add_offer` / `add_offer_file`: install the per-object
    /// serve loop and (re)build the manifest.
    fn serve_prepared(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        object_name: ndn_packet::Name,
        prepared: Arc<PreparedObject>,
        size: usize,
    ) -> Result<String, NdnError> {
        let signer = Arc::clone(&self.signer);
        let prepared_for_serve = Arc::clone(&prepared);
        let serve_name = object_name.clone();
        let guard = self.rt.block_on(async {
            self.demux.register_prefix(&serve_name).await.ok();
            self.demux
                .serve_scoped(serve_name, move |interest, responder| {
                    let prepared = Arc::clone(&prepared_for_serve);
                    let signer = Arc::clone(&signer);
                    async move {
                        if let Ok(Some(wire)) =
                            prepared.answer_interest(&interest.name, Some(signer.as_ref())).await
                        {
                            responder.respond_bytes(wire).await.ok();
                        }
                    }
                })
        });

        {
            let mut offers = self.offers.lock().unwrap();
            offers.insert(
                file_id,
                OfferEntry {
                    display_name,
                    mime,
                    name: object_name.clone(),
                    size,
                    _guard: guard,
                },
            );
            self.rebuild_manifest(&offers);
        }
        Ok(object_name.to_string())
    }

    /// Offer a file via the **streaming relay** path (producer-side "bulk off the
    /// seam"). Instead of answering one signed Interest per segment across the
    /// seam, the leaf serves the file's **raw** segments as a stream on an
    /// internal content prefix; the engine (the caller, over AIDL) then becomes
    /// producer-of-record for the public name via
    /// [`NdnEngine::register_object_relay`](crate::NdnEngine::register_object_relay),
    /// re-signing each segment with the node key and serving it. Returns the
    /// public object name; the internal source prefix is
    /// `/localhost/ripple/content/<file_id>` (derive it to register the relay).
    #[cfg(unix)]
    pub(crate) fn add_offer_file_streamed(
        &self,
        file_id: String,
        display_name: String,
        mime: String,
        file: std::fs::File,
        size: u64,
    ) -> Result<String, NdnError> {
        if file_id.is_empty() {
            return Err(NdnError::engine("offer file_id must not be empty"));
        }
        let public_name = self.identity_prefix.clone().append("file").append(&file_id);
        let internal_name: Name = INTERNAL_CONTENT_PREFIX
            .parse::<Name>()
            .map_err(|_| NdnError::invalid_name(INTERNAL_CONTENT_PREFIX))?
            .append(&file_id);
        tracing::debug!(
            target: "ndn_boltffi::offer",
            %public_name, %internal_name, size,
            "offer board: serving raw content stream (engine relay signs + serves public)"
        );
        // Raw, file-backed: segments are read on demand and emitted unsigned —
        // the engine relay re-signs under the public name.
        let prepared = Arc::new(PreparedObject::build_from_file(
            internal_name.clone(),
            file,
            size,
            OFFER_CHUNK,
        ));
        let guard = self.serve_content_stream(internal_name, prepared);

        let mut offers = self.offers.lock().unwrap();
        offers.insert(
            file_id,
            OfferEntry {
                display_name,
                mime,
                name: public_name.clone(),
                size: size as usize,
                _guard: guard,
            },
        );
        self.rebuild_manifest(&offers);
        Ok(public_name.to_string())
    }

    /// Serve `prepared`'s raw segments on `internal_name` as a credit-gated
    /// stream over the shared demux: a persistent subscription (the engine
    /// relay's) grants budget and a single in-order streamer publishes segments;
    /// a plain `…/seg=` Interest is answered one-shot (the relay's re-fetch of a
    /// segment aged out of its window). Mirrors [`ndn_app::serve_object_stream`]
    /// but over `serve_scoped` (the leaf serves on the shared seam, so it must
    /// not drain the demux fallback that the consumer's fetches read).
    fn serve_content_stream(&self, internal_name: Name, prepared: Arc<PreparedObject>) -> ServeGuard {
        let budget = Arc::new(Semaphore::new(0));
        let last = prepared.last_seg;

        // In-order streamer: publish seg 0..=last over the demux, one per budget
        // permit (granted by the subscriber's max_data_count).
        {
            let demux = Arc::clone(&self.demux) as Arc<dyn Connection>;
            let budget = Arc::clone(&budget);
            let prepared = Arc::clone(&prepared);
            self.rt.spawn(async move {
                let mut seg: u64 = 0;
                while seg <= last {
                    let permit = match budget.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    permit.forget();
                    let seg_name = prepared.versioned_name.clone().append_segment(seg);
                    match prepared.answer_interest(&seg_name, None).await {
                        Ok(Some(wire)) => {
                            if demux.send(wire).await.is_err() {
                                return;
                            }
                        }
                        _ => return,
                    }
                    seg += 1;
                }
            });
        }

        let prepared_for_serve = Arc::clone(&prepared);
        self.rt.block_on(async {
            self.demux.register_prefix(&internal_name).await.ok();
            self.demux
                .serve_scoped(internal_name, move |interest, responder| {
                    let budget = Arc::clone(&budget);
                    let prepared = Arc::clone(&prepared_for_serve);
                    async move {
                        if let Some(sr) = interest
                            .app_parameters()
                            .and_then(SubscriptionRequest::find_in)
                        {
                            budget.add_permits(sr.max_data_count.max(1) as usize);
                        } else if let Ok(Some(wire)) =
                            prepared.answer_interest(&interest.name, None).await
                        {
                            responder.respond_bytes(wire).await.ok();
                        }
                    }
                })
        })
    }

    /// Stop offering `file_id` (drops its serve guard) and rebuild the manifest.
    /// Returns whether an offering was removed.
    pub(crate) fn remove_offer(&self, file_id: &str) -> bool {
        let mut offers = self.offers.lock().unwrap();
        let removed = offers.remove(file_id).is_some();
        if removed {
            self.rebuild_manifest(&offers);
        }
        removed
    }

    /// The current offerings as JSON, for this node's own UI (same shape served
    /// in the manifest).
    pub(crate) fn list_offers(&self) -> String {
        let offers = self.offers.lock().unwrap();
        offers_json(&self.node_prefix, &offers)
    }

    /// Rebuild the signed manifest object from the current offerings and swap it
    /// in for the serve loop.
    fn rebuild_manifest(&self, offers: &BTreeMap<String, OfferEntry>) {
        let manifest_name = self.node_prefix.clone().append("offers");
        let rebuilt = build_manifest(&manifest_name, &self.node_prefix, offers);
        let mut ring = self.manifest.lock().unwrap();
        ring.push_front(rebuilt); // newest first
        ring.truncate(MANIFEST_HISTORY); // keep the last few versions servable
    }
}

/// Build the manifest as a fresh RDR object (signing happens per-Interest in the
/// serve loop).
fn build_manifest(
    manifest_name: &Name,
    node_prefix: &Name,
    offers: &BTreeMap<String, OfferEntry>,
) -> Arc<PreparedObject> {
    let json = offers_json(node_prefix, offers);
    Arc::new(PreparedObject::build(
        manifest_name.clone(),
        Bytes::from(json.into_bytes()),
        8192,
    ))
}

/// Render the offerings as JSON: `{"node":"/ndn/node/<id>","offers":[{...}]}`.
/// `node` is the routable prefix a consumer uses as the ForwardingHint when
/// fetching each `name`.
fn offers_json(node_prefix: &Name, offers: &BTreeMap<String, OfferEntry>) -> String {
    let mut out = String::from("{\"node\":");
    push_json_str(&mut out, &node_prefix.to_string());
    out.push_str(",\"offers\":[");
    for (i, (file_id, e)) in offers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"file_id\":");
        push_json_str(&mut out, file_id);
        out.push_str(",\"display_name\":");
        push_json_str(&mut out, &e.display_name);
        out.push_str(",\"mime\":");
        push_json_str(&mut out, &e.mime);
        out.push_str(",\"size\":");
        out.push_str(&e.size.to_string());
        out.push_str(",\"name\":");
        push_json_str(&mut out, &e.name.to_string());
        out.push('}');
    }
    out.push_str("]}");
    out
}

/// Append `s` to `out` as a JSON string literal (minimal escaping).
fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
}
