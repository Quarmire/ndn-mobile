//! Nearby-peer discovery — the node's presence table, served as an NDN dataset.
//!
//! Tiered, to match an AirDrop-style "nearby" experience:
//!
//! - **Tier 1 (cheap presence)** — each node beacons a lightweight `{id, label}`
//!   over its broadcast faces (Wi-Fi Aware service-info, BLE advertisement). The
//!   platform radios observe peers' beacons and feed them in via
//!   [`NdnEngine::note_peer`](crate::NdnEngine::note_peer). That builds this
//!   table: who is nearby, on which face, at what signal.
//! - **Tier 2 (resolve on demand)** — only when the user taps a peer to share or
//!   receive does the leaf fetch that peer's full operator identity / certificate
//!   by name and verify it. Trust isn't paid for every beacon, only on use.
//!
//! The table is exposed the NDN-native way: the node serves it as a dataset at
//! `/localhost/discovery/peers` (localhost scope — only the local seam faces,
//! i.e. the UI / a leaf app like Ripple, can read it; it never hits the network).
//! A leaf fetches that name to render its "nearby" list — no side-channel API.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ndn_app::demux::ServeGuard;
use ndn_app::{Connection, DemuxConnection};
use ndn_packet::encode::DataBuilder;
use ndn_packet::Name;
use std::sync::Arc;

/// The dataset name a leaf fetches to read the nearby-peer list.
pub(crate) const PEERS_DATASET: &str = "/localhost/discovery/peers";

/// Routable per-node prefix root. A discovered peer with id `X` is reachable at
/// `/ndn/node/X`; discovery installs a cost-aware route to it (see
/// `MobileEngine::note_peer_route`), and content a peer serves carries a
/// ForwardingHint to its own `/ndn/node/<id>` so it routes there over the best
/// face. One documented convention rather than a magic string at each use site.
///
/// NOTE (tracked debt): this presence/peer model and the table below duplicate
/// `ndn_discovery_core::NeighborTable`; the deliberate de-dup is to make this a
/// view over that one shared table (it already tracks node_name + per-face
/// reachability + a quality metric), adding only a human label.
pub(crate) const NODE_PREFIX: &str = "/ndn/node";

/// The routable prefix for a peer with discovery id `id` (see [`NODE_PREFIX`]).
pub(crate) fn peer_node_prefix(id: &str) -> String {
    format!("{NODE_PREFIX}/{id}")
}

/// A peer dropped from the list after this long without a fresh beacon.
const PEER_TTL: Duration = Duration::from_secs(30);

struct PeerEntry {
    label: String,
    /// Which faces this peer has been heard on ("ble", "wifi-aware", …).
    faces: BTreeSet<String>,
    rssi_dbm: i32,
    /// The peer's AP-assigned IPv4, if it advertised one in its beacon — used to
    /// raise a same-AP [`InfraTunnel`](ndn_transport::FaceKind::InfraTunnel) bulk
    /// face. `None` until heard.
    infra_addr: Option<String>,
    last_seen: Instant,
}

/// The node's presence + the table of observed peers, behind the
/// `/localhost/discovery/peers` dataset.
pub(crate) struct DiscoveryState {
    local_id: String,
    local_label: String,
    peers: Mutex<HashMap<String, PeerEntry>>,
}

impl DiscoveryState {
    fn new(local_id: String, local_label: String) -> Self {
        Self {
            local_id,
            local_label,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Record (or refresh) a peer heard on `face`. Called from the platform
    /// radios' discovery callbacks. `rssi` is dBm (0 = unknown).
    pub(crate) fn note_peer(
        &self,
        id: String,
        label: String,
        face: String,
        rssi: i32,
        infra_addr: Option<String>,
    ) {
        if id.is_empty() || id == self.local_id {
            return; // never list ourselves
        }
        let mut peers = self.peers.lock().unwrap();
        let entry = peers.entry(id).or_insert_with(|| PeerEntry {
            label: label.clone(),
            faces: BTreeSet::new(),
            rssi_dbm: rssi,
            infra_addr: None,
            last_seen: Instant::now(),
        });
        if !label.is_empty() {
            entry.label = label;
        }
        if !face.is_empty() {
            entry.faces.insert(face);
        }
        if infra_addr.is_some() {
            entry.infra_addr = infra_addr;
        }
        entry.rssi_dbm = rssi;
        entry.last_seen = Instant::now();
    }

    /// Render the current table as JSON for the dataset, pruning stale peers.
    fn snapshot_json(&self) -> String {
        let now = Instant::now();
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|_, e| now.duration_since(e.last_seen) < PEER_TTL);
        let mut out = String::from("{\"self\":{\"id\":");
        push_json_str(&mut out, &self.local_id);
        out.push_str(",\"label\":");
        push_json_str(&mut out, &self.local_label);
        out.push_str("},\"peers\":[");
        for (i, (id, e)) in peers.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"id\":");
            push_json_str(&mut out, id);
            out.push_str(",\"label\":");
            push_json_str(&mut out, &e.label);
            out.push_str(",\"faces\":[");
            for (j, f) in e.faces.iter().enumerate() {
                if j > 0 {
                    out.push(',');
                }
                push_json_str(&mut out, f);
            }
            out.push_str("],\"rssi\":");
            out.push_str(&e.rssi_dbm.to_string());
            out.push_str(",\"age_ms\":");
            out.push_str(&now.duration_since(e.last_seen).as_millis().to_string());
            if let Some(ref addr) = e.infra_addr {
                out.push_str(",\"infra\":");
                push_json_str(&mut out, addr);
            }
            out.push('}');
        }
        out.push_str("]}");
        out
    }
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

/// Serve `/localhost/discovery/peers` over `demux`, answering each Interest with
/// a fresh JSON snapshot of `state`. The returned guard keeps the registration
/// alive — drop it to stop serving.
pub(crate) async fn serve_peers_dataset(
    demux: &Arc<DemuxConnection>,
    state: Arc<DiscoveryState>,
) -> ServeGuard {
    let prefix: Name = PEERS_DATASET.parse().expect("static dataset name");
    // `serve_scoped` only wires the demux's local dispatch; register the prefix
    // with the forwarder too so Interests for it actually route to this handler.
    let _ = demux.register_prefix(&prefix).await;
    demux.serve_scoped(prefix, move |interest, responder| {
        let state = Arc::clone(&state);
        async move {
            let json = state.snapshot_json();
            // Fresh (1 s) so a polling leaf always gets the current list, and the
            // local CS doesn't serve a stale snapshot.
            let data = DataBuilder::new(interest.name.as_ref().clone(), json.as_bytes())
                .freshness(Duration::from_secs(1))
                .build();
            responder.respond_bytes(data).await.ok();
        }
    })
}

/// Build a [`DiscoveryState`] for a node's local presence.
pub(crate) fn new_state(local_id: String, local_label: String) -> Arc<DiscoveryState> {
    Arc::new(DiscoveryState::new(local_id, local_label))
}
