//! Operator-console FFI: poll a forwarder's management plane and surface
//! faces, routes, content store, strategies, and status to native UI.
//!
//! [`NdnDashboard`] connects to a forwarder's IPC-listener socket — the phone
//! driving its own [`MobileEngine`](ndn_mobile::MobileEngine), or any
//! NFD-compatible forwarder — as a **separate** management connection (not the
//! [`NdnClient`](crate::NdnClient) data fd). The headless console logic lives
//! in `ndn-dashboard-core`; this module is the thin FFI skin: a
//! [`ManagementClient`] over the ndn-ipc socket client plus `#[data]`
//! view-models the host renders.
//!
//! Native-only — `ndn-dashboard-core` is not wasm-safe.

use std::sync::{Arc, Mutex};

use boltffi::{data, export};
use ndn_config::ControlParameters;
use ndn_dashboard_core::types::{
    CsInfo, FaceInfo, FibEntry, ForwarderStatus, NextHop, StrategyEntry,
};
use ndn_dashboard_core::types::{AnchorInfo, SecurityKeyInfo};
use ndn_dashboard_core::{
    DashboardEngine, DashboardState, IdentityState, ManagementClient, MgmtResponse,
};
use ndn_ipc::MgmtClient;
use tokio::runtime::Runtime;

use crate::types::NdnError;

/// boltffi-local newtype implementing the core-defined [`ManagementClient`]
/// over the ndn-ipc Unix-socket client. The orphan rule forbids
/// `impl ManagementClient for MgmtClient` here (both foreign), so we wrap it —
/// the same shape as the desktop `NativeMgmtClient`.
struct BoltMgmtClient(MgmtClient);

#[async_trait::async_trait(?Send)]
impl ManagementClient for BoltMgmtClient {
    async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse, String> {
        let (status_code, status_text, body) = self
            .0
            .send_cmd_raw(module, verb, params)
            .await
            .map_err(|e| e.to_string())?;
        Ok(MgmtResponse {
            status_code,
            status_text,
            body,
        })
    }
}

/// Headless operator console over a forwarder's management plane.
///
/// Calls are blocking — poll from a background thread (`Dispatchers.IO` /
/// `Task.detached`).
pub struct NdnDashboard {
    rt: Arc<Runtime>,
    engine: Mutex<DashboardEngine<BoltMgmtClient>>,
}

#[export]
impl NdnDashboard {
    /// Connect to a forwarder's management socket (e.g. the `MobileEngine`'s
    /// IPC listener path, or `/run/nfd/nfd.sock`). Blocking.
    pub fn connect(socket: String) -> Result<Self, NdnError> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(NdnError::engine)?,
        );
        let mgmt = rt
            .block_on(MgmtClient::connect(&socket))
            .map_err(NdnError::engine)?;
        Ok(Self {
            rt,
            engine: Mutex::new(DashboardEngine::new(BoltMgmtClient(mgmt))),
        })
    }

    /// Refresh the forwarding view (status, faces, routes, CS, strategies) by
    /// polling the management plane, then return the current snapshot.
    /// Blocking. A failed dataset query leaves that axis's prior value in
    /// place (the core engine swallows per-dataset errors), so the returned
    /// view is always the last good one rather than going blank on a hiccup.
    pub fn poll(&self) -> NdnDashboardState {
        let mut engine = self.engine.lock().unwrap();
        self.rt.block_on(engine.poll_forwarding());
        NdnDashboardState::from_state(engine.state())
    }

    // --- Commands (signed management Interests under the hood) ---------------
    //
    // Each blocks on one management round-trip. The `ControlParameters` for
    // every verb are built in `ndn-dashboard-core` (and witnessed there:
    // `command_builders_construct_expected_params` /
    // `route_register_omits_zero_face_id`); this layer is the FFI dispatch +
    // `MgmtResponse` bridge. A non-2xx `status_code` is returned in the
    // response, not raised as an error — only transport/parse failures error.

    /// Create a face to `uri` (e.g. `udp4://203.0.113.7:6363`,
    /// `ether://[aa:bb:..]`). The new face id is echoed in the response body.
    pub fn face_create(&self, uri: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.face_create(uri)))
    }

    /// Destroy face `face_id`.
    pub fn face_destroy(&self, face_id: u64) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.face_destroy(face_id)))
    }

    /// Register a route: send Interests under `prefix` to `face_id` at `cost`.
    /// `face_id == 0` means "the requesting face" (forwarder resolves it).
    pub fn route_register(
        &self,
        prefix: String,
        face_id: u64,
        cost: u64,
    ) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.route_register(&prefix, face_id, cost)))
    }

    /// Remove the `prefix → face_id` route.
    pub fn route_unregister(
        &self,
        prefix: String,
        face_id: u64,
    ) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.route_unregister(&prefix, face_id)))
    }

    /// Bind `prefix` to the named forwarding `strategy`
    /// (e.g. `/localhost/nfd/strategy/best-route`).
    pub fn strategy_set(
        &self,
        prefix: String,
        strategy: String,
    ) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.strategy_set(&prefix, &strategy)))
    }

    /// Clear the strategy binding at `prefix` (falls back to the parent's).
    pub fn strategy_unset(&self, prefix: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.strategy_unset(&prefix)))
    }

    /// Set the content-store capacity in bytes.
    pub fn cs_capacity(&self, capacity: u64) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.cs_capacity(capacity)))
    }

    /// Erase cached Data under `prefix` from the content store.
    pub fn cs_erase(&self, prefix: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.cs_erase(&prefix)))
    }

    /// Ask the forwarder to shut down.
    pub fn shutdown(&self) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.shutdown()))
    }

    // --- Identity / trust plane ---------------------------------------------

    /// Refresh and return the CA pending-approval queue — device-enrollment
    /// requests awaiting an operator decision. Polled on demand (e.g. when the
    /// operator opens the approvals view), separately from `poll`.
    pub fn poll_identity(&self) -> NdnIdentityState {
        let mut engine = self.engine.lock().unwrap();
        self.rt.block_on(engine.poll_identity());
        NdnIdentityState::from_state(engine.identity_state())
    }

    /// Approve a pending request by id (signed command — the operator
    /// identity loaded on the forwarder authorises it).
    pub fn ca_approve(&self, request_id: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.ca_approve(&request_id)))
    }

    /// Deny a pending request by id. An empty `reason` records the default
    /// denial detail.
    pub fn ca_deny(&self, request_id: String, reason: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.ca_deny(&request_id, &reason)))
    }

    /// Withdraw local trust in an anchor by its certificate key name (a signed
    /// command — not a network revocation).
    pub fn anchor_remove(&self, key_name: String) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.anchor_remove(&key_name)))
    }

    /// Install a trust anchor from a certificate's wire bytes. `key_name` must
    /// equal the certificate's own name (the forwarder cross-checks).
    pub fn anchor_add(
        &self,
        key_name: String,
        cert_wire: Vec<u8>,
    ) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(self.rt.block_on(e.anchor_add(&key_name, &cert_wire)))
    }

    /// Import an ndn-cxx-compatible SafeBag (encrypted key + cert) as a signing
    /// identity. `key_name` is the key the bag carries; `passphrase` decrypts
    /// the wrapped PKCS#8.
    pub fn safebag_import(
        &self,
        key_name: String,
        safebag_wire: Vec<u8>,
        passphrase: Vec<u8>,
    ) -> Result<NdnMgmtResponse, NdnError> {
        let mut e = self.engine.lock().unwrap();
        finish(
            self.rt
                .block_on(e.safebag_import(&key_name, &safebag_wire, &passphrase)),
        )
    }
}

/// Map a core command result into the FFI surface: a non-error response
/// (whatever its status code) bridges; a transport/parse `String` error
/// becomes [`NdnError::Engine`].
fn finish(r: Result<MgmtResponse, String>) -> Result<NdnMgmtResponse, NdnError> {
    r.map(NdnMgmtResponse::from).map_err(NdnError::engine)
}

/// Forwarder summary counters (`status/general`).
#[data]
#[derive(Debug, Clone)]
pub struct NdnForwarderStatus {
    pub n_faces: u64,
    pub n_fib: u64,
    pub n_pit: u64,
    pub n_cs: u64,
    pub nfd_version: String,
}

/// One face from `faces/list`, with its lifetime traffic counters.
#[data]
#[derive(Debug, Clone)]
pub struct NdnFaceInfo {
    pub face_id: u64,
    pub remote_uri: Option<String>,
    pub local_uri: Option<String>,
    pub persistency: String,
    pub kind: Option<String>,
    pub face_scope: u64,
    pub link_type: u64,
    pub mtu: Option<u64>,
    pub n_in_interests: u64,
    pub n_out_interests: u64,
    pub n_in_data: u64,
    pub n_out_data: u64,
    pub n_in_bytes: u64,
    pub n_out_bytes: u64,
    pub n_in_nacks: u64,
    pub n_out_nacks: u64,
    /// NFD FaceFlags bitmap (bit 0 LocalFields, 1 LpReliability, 2 Congestion).
    pub flags: u64,
}

/// A next-hop (face + cost) under a FIB prefix.
#[data]
#[derive(Debug, Clone, Copy)]
pub struct NdnNextHop {
    pub face_id: u64,
    pub cost: u32,
}

/// One FIB entry from `fib/list`.
#[data]
#[derive(Debug, Clone)]
pub struct NdnFibEntry {
    pub prefix: String,
    pub nexthops: Vec<NdnNextHop>,
}

/// Content-store counters and config (`cs/info`).
#[data]
#[derive(Debug, Clone)]
pub struct NdnCsInfo {
    pub capacity_bytes: u64,
    pub n_entries: u64,
    pub used_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub variant: String,
}

/// A prefix→strategy binding from `strategy-choice/list`.
#[data]
#[derive(Debug, Clone)]
pub struct NdnStrategyEntry {
    pub prefix: String,
    pub strategy: String,
}

/// A management command result: the forwarder's `ControlResponse` status plus
/// the raw response body (e.g. the echoed `ControlParameters` carrying a new
/// face id after `face_create`). `status_code` follows NFD conventions —
/// `200` ok, `400`/`404`/`409` client errors, `500` server.
#[data]
#[derive(Debug, Clone)]
pub struct NdnMgmtResponse {
    pub status_code: u64,
    pub status_text: String,
    pub body: Vec<u8>,
}

impl From<MgmtResponse> for NdnMgmtResponse {
    fn from(r: MgmtResponse) -> Self {
        Self {
            status_code: r.status_code,
            status_text: r.status_text,
            body: r.body.to_vec(),
        }
    }
}

/// One pending device-approval request the operator can approve or deny.
#[data]
#[derive(Debug, Clone)]
pub struct NdnPendingApproval {
    /// Opaque request id — pass to `ca_approve` / `ca_deny`.
    pub request_id: String,
    /// The certificate name the device is requesting.
    pub cert_name: String,
    /// How the requester satisfied the challenge (may be empty).
    pub description: String,
}

/// A local identity key and its certificate posture.
#[data]
#[derive(Debug, Clone)]
pub struct NdnSecurityKey {
    pub name: String,
    /// Whether the key has an issued certificate.
    pub has_cert: bool,
    /// Raw validity string from the forwarder (`never`, `-`, or `<ns>ns`).
    pub valid_until: String,
    /// Base64 public key, empty when unavailable.
    pub public_key_b64: String,
    /// Days until cert expiry — negative if expired, `None` if permanent/absent.
    pub days_to_expiry: Option<i64>,
}

/// A configured trust anchor.
#[data]
#[derive(Debug, Clone)]
pub struct NdnTrustAnchor {
    pub name: String,
    /// Which store it lives in (`engine` / `mgmt` / `localhop`); `None` on
    /// older forwarders.
    pub source: Option<String>,
}

/// The identity/trust-plane snapshot the host renders: the pending-approval
/// queue plus the trust posture (local identities and anchors).
#[data]
#[derive(Debug, Clone)]
pub struct NdnIdentityState {
    pub approvals: Vec<NdnPendingApproval>,
    pub identities: Vec<NdnSecurityKey>,
    pub anchors: Vec<NdnTrustAnchor>,
}

impl NdnIdentityState {
    fn from_state(s: &IdentityState) -> Self {
        Self {
            approvals: s
                .approvals
                .iter()
                .map(|a| NdnPendingApproval {
                    request_id: a.request_id.clone(),
                    cert_name: a.cert_name.clone(),
                    description: a.description.clone(),
                })
                .collect(),
            identities: s.identities.iter().map(from_key).collect(),
            anchors: s.anchors.iter().map(from_anchor).collect(),
        }
    }
}

fn from_key(k: &SecurityKeyInfo) -> NdnSecurityKey {
    NdnSecurityKey {
        name: k.name.clone(),
        has_cert: k.has_cert,
        valid_until: k.valid_until.clone(),
        public_key_b64: k.public_key_b64.clone(),
        days_to_expiry: k.days_to_expiry(),
    }
}

fn from_anchor(a: &AnchorInfo) -> NdnTrustAnchor {
    NdnTrustAnchor {
        name: a.name.clone(),
        source: a.source.clone(),
    }
}

/// The full forwarding snapshot the host renders.
#[data]
#[derive(Debug, Clone)]
pub struct NdnDashboardState {
    pub status: Option<NdnForwarderStatus>,
    pub faces: Vec<NdnFaceInfo>,
    pub routes: Vec<NdnFibEntry>,
    pub cs: Option<NdnCsInfo>,
    pub strategies: Vec<NdnStrategyEntry>,
}

impl NdnDashboardState {
    fn from_state(s: &DashboardState) -> Self {
        Self {
            status: s.status.as_ref().map(from_status),
            faces: s.faces.iter().map(from_face).collect(),
            routes: s.routes.iter().map(from_fib).collect(),
            cs: s.cs.as_ref().map(from_cs),
            strategies: s.strategies.iter().map(from_strategy).collect(),
        }
    }
}

fn from_status(s: &ForwarderStatus) -> NdnForwarderStatus {
    NdnForwarderStatus {
        n_faces: s.n_faces,
        n_fib: s.n_fib,
        n_pit: s.n_pit,
        n_cs: s.n_cs,
        nfd_version: s.nfd_version.clone(),
    }
}

fn from_face(f: &FaceInfo) -> NdnFaceInfo {
    NdnFaceInfo {
        face_id: f.face_id,
        remote_uri: f.remote_uri.clone(),
        local_uri: f.local_uri.clone(),
        persistency: f.persistency.clone(),
        kind: f.kind.clone(),
        face_scope: f.face_scope,
        link_type: f.link_type,
        mtu: f.mtu,
        n_in_interests: f.n_in_interests,
        n_out_interests: f.n_out_interests,
        n_in_data: f.n_in_data,
        n_out_data: f.n_out_data,
        n_in_bytes: f.n_in_bytes,
        n_out_bytes: f.n_out_bytes,
        n_in_nacks: f.n_in_nacks,
        n_out_nacks: f.n_out_nacks,
        flags: f.flags,
    }
}

fn from_fib(e: &FibEntry) -> NdnFibEntry {
    NdnFibEntry {
        prefix: e.prefix.clone(),
        nexthops: e
            .nexthops
            .iter()
            .map(|h: &NextHop| NdnNextHop {
                face_id: h.face_id,
                cost: h.cost,
            })
            .collect(),
    }
}

fn from_cs(c: &CsInfo) -> NdnCsInfo {
    NdnCsInfo {
        capacity_bytes: c.capacity_bytes,
        n_entries: c.n_entries,
        used_bytes: c.used_bytes,
        hits: c.hits,
        misses: c.misses,
        variant: c.variant.clone(),
    }
}

fn from_strategy(s: &StrategyEntry) -> NdnStrategyEntry {
    NdnStrategyEntry {
        prefix: s.prefix.clone(),
        strategy: s.strategy.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Witness: the FFI-specific logic here is the `DashboardState` →
    // `#[data]` bridge (the live poll is witnessed in `ndn-dashboard-core`).
    // Build a known core snapshot and assert every axis maps through.
    #[test]
    fn bridges_dashboard_state_to_ffi_view_model() {
        let state = DashboardState {
            status: Some(ForwarderStatus {
                n_faces: 2,
                n_fib: 3,
                n_pit: 0,
                n_cs: 7,
                nfd_version: "ndn-rs".into(),
            }),
            faces: vec![FaceInfo {
                face_id: 256,
                remote_uri: Some("udp4://1.2.3.4:6363".into()),
                local_uri: None,
                persistency: "persistent".into(),
                kind: Some("udp".into()),
                face_scope: 0,
                link_type: 0,
                mtu: Some(1500),
                n_in_interests: 10,
                n_out_interests: 11,
                n_in_data: 12,
                n_out_data: 13,
                n_in_bytes: 100,
                n_out_bytes: 200,
                n_in_nacks: 0,
                n_out_nacks: 0,
                flags: 1,
            }],
            routes: vec![FibEntry {
                prefix: "/ndn".into(),
                nexthops: vec![NextHop {
                    face_id: 256,
                    cost: 0,
                }],
            }],
            cs: Some(CsInfo {
                capacity_bytes: 65536,
                n_entries: 7,
                used_bytes: 4096,
                hits: 5,
                misses: 2,
                variant: "lru".into(),
            }),
            strategies: vec![StrategyEntry {
                prefix: "/ndn".into(),
                strategy: "/localhost/nfd/strategy/best-route".into(),
            }],
        };

        let vm = NdnDashboardState::from_state(&state);

        let status = vm.status.expect("status bridged");
        assert_eq!(status.n_faces, 2);
        assert_eq!(status.n_cs, 7);
        assert_eq!(status.nfd_version, "ndn-rs");

        assert_eq!(vm.faces.len(), 1);
        assert_eq!(vm.faces[0].face_id, 256);
        assert_eq!(vm.faces[0].remote_uri.as_deref(), Some("udp4://1.2.3.4:6363"));
        assert_eq!(vm.faces[0].mtu, Some(1500));
        assert_eq!(vm.faces[0].n_out_bytes, 200);
        assert_eq!(vm.faces[0].flags, 1);

        assert_eq!(vm.routes.len(), 1);
        assert_eq!(vm.routes[0].prefix, "/ndn");
        assert_eq!(vm.routes[0].nexthops[0].face_id, 256);

        let cs = vm.cs.expect("cs bridged");
        assert_eq!(cs.n_entries, 7);
        assert_eq!(cs.variant, "lru");

        assert_eq!(vm.strategies.len(), 1);
        assert_eq!(
            vm.strategies[0].strategy,
            "/localhost/nfd/strategy/best-route"
        );
    }

    // Witness the command-result bridge (the FFI-specific half of the command
    // path; the ControlParameters builders are witnessed in ndn-dashboard-core).
    #[test]
    fn bridges_mgmt_response_to_ffi() {
        let resp = MgmtResponse {
            status_code: 200,
            status_text: "OK".into(),
            body: bytes::Bytes::from_static(&[0x68, 0x01, 0x02]),
        };
        let vm = NdnMgmtResponse::from(resp);
        assert_eq!(vm.status_code, 200);
        assert_eq!(vm.status_text, "OK");
        assert_eq!(vm.body, vec![0x68, 0x01, 0x02]);
    }

    // Witness the identity-axis bridge (IdentityState → #[data]); poll_identity
    // and the approve/deny builders are witnessed in ndn-dashboard-core.
    #[test]
    fn bridges_identity_state_to_ffi() {
        let state = IdentityState {
            approvals: vec![ndn_dashboard_core::PendingApproval {
                request_id: "req-7".into(),
                cert_name: "/lab/eve/devices/cam".into(),
                description: "PIN".into(),
            }],
            identities: SecurityKeyInfo::parse_list(
                "name=/lab/alice has_cert=true valid_until=never",
            ),
            anchors: AnchorInfo::parse_list("name=/lab/router-ca/KEY/k0 source=mgmt"),
        };
        let vm = NdnIdentityState::from_state(&state);

        assert_eq!(vm.approvals.len(), 1);
        assert_eq!(vm.approvals[0].request_id, "req-7");
        assert_eq!(vm.approvals[0].cert_name, "/lab/eve/devices/cam");
        assert_eq!(vm.approvals[0].description, "PIN");

        assert_eq!(vm.identities.len(), 1);
        assert_eq!(vm.identities[0].name, "/lab/alice");
        assert!(vm.identities[0].has_cert);
        assert_eq!(vm.identities[0].days_to_expiry, None); // "never" → permanent

        assert_eq!(vm.anchors.len(), 1);
        assert_eq!(vm.anchors[0].name, "/lab/router-ca/KEY/k0");
        assert_eq!(vm.anchors[0].source.as_deref(), Some("mgmt"));
    }
}
