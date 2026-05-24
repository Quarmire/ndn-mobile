//! [`MobileEngine`] and [`MobileEngineBuilder`].

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use ndn_app::{Consumer, Producer};
use ndn_discovery::{DiscoveryConfig, DiscoveryProfile, NeighborProbeProtocol};
use ndn_discovery_core::DiscoveryProtocol;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, RoutingProtocol, ShutdownHandle};
use ndn_face_native::local::{InProcFace, InProcHandle, IpcListener};
use ndn_face_native::net::{MulticastUdpFace, UdpFace, WebSocketFace, tcp_face_connect};
use ndn_face_native::serial::serial_face_open;
use ndn_packet::Name;
use ndn_security::SecurityProfile;
use ndn_strategy::{BestRouteStrategy, MulticastStrategy};
use ndn_transport::{FaceId, FaceKind, FacePersistency};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "compute")]
use ndn_compute::{ComputeFace, ComputeRegistry};
#[cfg(feature = "tun")]
use crate::tun::{TunConfig, TunHandle, spawn_tunnel};

/// Forwarding strategy installed at the engine root. Chosen via
/// [`MobileEngineBuilder::with_strategy`]; the engine keeps the
/// `/localhost/nfd/strategy-choice` table so per-prefix overrides still work,
/// this only sets the root default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MobileStrategy {
    /// Single lowest-cost nexthop — the standard forwarder behavior, and the
    /// right default for a leaf/VPN endpoint with one gateway.
    #[default]
    BestRoute,
    /// Flood to every viable nexthop. Useful on ad-hoc / mesh links where the
    /// best path is unknown and redundancy beats efficiency.
    Multicast,
    /// Cross-layer (RSSI / signal-aware) forwarding. Requires the `cclf`
    /// feature; falls back to a build error otherwise.
    #[cfg(feature = "cclf")]
    Cclf,
}

/// How to (re)build a network face after suspend — retained so
/// [`MobileEngine::resume_network_faces`] can rebuild every peer, not just
/// multicast.
#[derive(Clone, Debug)]
enum PeerSpec {
    UdpUnicast(SocketAddr),
    Tcp(SocketAddr),
    WebSocket(String),
    Serial(String, u32),
}

impl PeerSpec {
    /// Human-readable URI for logs and [`PeerRef::uri`].
    fn uri(&self) -> String {
        match self {
            PeerSpec::UdpUnicast(a) => format!("udp4://{a}"),
            PeerSpec::Tcp(a) => format!("tcp4://{a}"),
            PeerSpec::WebSocket(u) => u.clone(),
            PeerSpec::Serial(p, b) => format!("serial://{p}?baud={b}"),
        }
    }
}

/// An opaque handle to a configured network peer, returned by
/// [`MobileEngine::peers`]. It carries the peer's stable face id internally but
/// does **not** expose it — apps register routes toward a peer via
/// [`MobileEngine::route_to_peer`], never by naming a raw face id
/// (cf. the app↔router connection model).
#[derive(Clone, Debug)]
pub struct PeerRef {
    id: FaceId,
    uri: String,
}

impl PeerRef {
    /// The peer's URI (e.g. `tcp4://10.0.0.1:6363`, a `ws(s)://` URL), suitable
    /// for display and for matching the peer the caller configured.
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// (Re)build the network face described by `spec` at the stable `id` and mount
/// it on `engine` as a `Persistent` face. Shared by initial build and
/// `resume_network_faces` so a peer comes back with the same id (its FIB routes
/// — `Persistent` faces are retained on suspend — stay valid).
async fn build_peer_face(
    engine: &ForwarderEngine,
    id: FaceId,
    spec: &PeerSpec,
    cancel: CancellationToken,
) {
    match spec {
        PeerSpec::UdpUnicast(peer) => {
            let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
            match UdpFace::bind(local, *peer, id).await {
                Ok(face) => {
                    engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent)
                }
                Err(e) => tracing::warn!(%peer, error = %e, "UDP unicast face setup failed"),
            }
        }
        PeerSpec::Tcp(peer) => match tcp_face_connect(id, *peer).await {
            Ok(face) => {
                engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent)
            }
            Err(e) => tracing::warn!(%peer, error = %e, "TCP face setup failed"),
        },
        PeerSpec::WebSocket(url) => match WebSocketFace::connect(id, url).await {
            Ok(face) => {
                engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent)
            }
            Err(e) => tracing::warn!(%url, error = %e, "WebSocket face setup failed"),
        },
        PeerSpec::Serial(port, baud) => match serial_face_open(id, port, *baud) {
            Ok(face) => {
                engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent)
            }
            Err(e) => tracing::warn!(%port, baud, error = %e, "serial face setup failed"),
        },
    }
}

/// In-process forwarder paired with an [`InProcFace`] for app traffic and
/// optional UDP multicast/unicast for the network side.
pub struct MobileEngine {
    engine: ForwarderEngine,
    shutdown: ShutdownHandle,
    /// Parent token for every network face; cancelling it suspends network
    /// I/O without touching the in-process face or engine state.
    network_cancel: CancellationToken,
    multicast_iface: Option<Ipv4Addr>,
    /// Stable across suspend/resume so existing FIB entries survive.
    multicast_face_id: FaceId,
    /// Unicast/TCP/WebSocket/serial peers with their stable face ids. Retained
    /// so `resume_network_faces` rebuilds every one (not just multicast) with
    /// the same id, and so `route_to_peer` can resolve a [`PeerRef`].
    network_peers: Vec<(FaceId, PeerSpec)>,
    /// Shared registry for in-process compute handlers; `None` unless
    /// `with_compute` was called. Register handlers via [`MobileEngine::compute_registry`].
    #[cfg(feature = "compute")]
    compute_registry: Option<Arc<ComputeRegistry>>,
    /// Platform side of the VPN datapath face; `None` unless `with_tun` was
    /// called. Drive it from the native tun pump via [`MobileEngine::tun_handle`].
    #[cfg(feature = "tun")]
    tun_handle: Option<Arc<TunHandle>>,
}

/// Mobile-tuned defaults: 8 MB CS, single pipeline thread, full chain validation.
pub struct MobileEngineBuilder {
    cs_capacity_mb: usize,
    security_profile: SecurityProfile,
    multicast_iface: Option<Ipv4Addr>,
    unicast_peers: Vec<SocketAddr>,
    tcp_peers: Vec<SocketAddr>,
    ws_peers: Vec<String>,
    serial_ports: Vec<(String, u32)>,
    ipc_listen_path: Option<String>,
    routing_protocols: Vec<Arc<dyn RoutingProtocol>>,
    discovery_protocol: Option<Arc<dyn DiscoveryProtocol>>,
    node_name: Option<Name>,
    strategy: MobileStrategy,
    pipeline_threads: usize,
    #[cfg_attr(not(feature = "management"), allow(dead_code))]
    enable_management: bool,
    /// `Some` once `with_management_secured` is called: the validator that
    /// authenticates signed command Interests and the signer for control
    /// responses. When set, command auth + anti-replay + a locked-down
    /// runtime policy are installed; when `None`, management is mounted open
    /// (suitable only for a trusted local IPC face).
    #[cfg(feature = "management")]
    secured_mgmt: Option<(
        Arc<ndn_security::Validator>,
        Arc<dyn ndn_security::Signer>,
    )>,
    /// Host-owned log ring for the `/localhost/nfd/log` module. The binary
    /// owns tracing init, so it supplies this; libraries never install it.
    #[cfg(feature = "management")]
    log_inspector: Option<Arc<ndn_mgmt::LogInspector>>,
    /// Read-only `/localhost/nfd/compute/list` backend (e.g. a
    /// `ComputeService::mgmt_backend()`). Distinct from `with_compute`'s
    /// in-process `ComputeRegistry`, which carries no introspection metadata.
    #[cfg(feature = "management")]
    compute_mgmt_backend: Option<Arc<dyn ndn_mgmt::ComputeMgmtBackend>>,
    #[cfg(feature = "compute")]
    compute_prefix: Option<Name>,
    #[cfg(feature = "ratelimit")]
    rate_limit: Option<Option<String>>,
    #[cfg(feature = "fec")]
    enable_fec: bool,
    #[cfg(feature = "tun")]
    tun_config: Option<TunConfig>,
    #[cfg_attr(not(feature = "fjall"), allow(dead_code))]
    persistent_cs_path: Option<PathBuf>,
}

impl Default for MobileEngineBuilder {
    fn default() -> Self {
        Self {
            cs_capacity_mb: 8,
            security_profile: SecurityProfile::Default,
            multicast_iface: None,
            unicast_peers: Vec::new(),
            tcp_peers: Vec::new(),
            ws_peers: Vec::new(),
            serial_ports: Vec::new(),
            ipc_listen_path: None,
            routing_protocols: Vec::new(),
            discovery_protocol: None,
            node_name: None,
            strategy: MobileStrategy::default(),
            pipeline_threads: 1,
            enable_management: false,
            #[cfg(feature = "management")]
            secured_mgmt: None,
            #[cfg(feature = "management")]
            log_inspector: None,
            #[cfg(feature = "management")]
            compute_mgmt_backend: None,
            #[cfg(feature = "compute")]
            compute_prefix: None,
            #[cfg(feature = "ratelimit")]
            rate_limit: None,
            #[cfg(feature = "fec")]
            enable_fec: false,
            #[cfg(feature = "tun")]
            tun_config: None,
            persistent_cs_path: None,
        }
    }
}

impl MobileEngineBuilder {
    pub fn cs_capacity_mb(mut self, mb: usize) -> Self {
        self.cs_capacity_mb = mb;
        self
    }

    pub fn security_profile(mut self, p: SecurityProfile) -> Self {
        self.security_profile = p;
        self
    }

    /// Single-thread default keeps wake-ups (and battery drain) low.
    pub fn pipeline_threads(mut self, n: usize) -> Self {
        self.pipeline_threads = n.max(1);
        self
    }

    /// Choose the root forwarding strategy (default [`MobileStrategy::BestRoute`]).
    /// A single-gateway leaf wants `BestRoute`; a mesh node may prefer
    /// `Multicast` or (with the `cclf` feature) `Cclf`.
    pub fn with_strategy(mut self, strategy: MobileStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Joins NDN multicast `224.0.23.170:6363` on `iface`.
    pub fn with_udp_multicast(mut self, iface: Ipv4Addr) -> Self {
        self.multicast_iface = Some(iface);
        self
    }

    pub fn with_unicast_peer(mut self, addr: SocketAddr) -> Self {
        self.unicast_peers.push(addr);
        self
    }

    /// Connect a persistent TCP face to a router/gateway.
    pub fn with_tcp_peer(mut self, addr: SocketAddr) -> Self {
        self.tcp_peers.push(addr);
        self
    }

    /// Connect a persistent WebSocket face to `url` (`ws://` or `wss://`).
    /// The carrier-NAT- and firewall-friendly way to reach a gateway over
    /// cellular. `wss://` requires the `websocket-tls` feature on `ndn-face-native`.
    pub fn with_websocket_peer(mut self, url: impl Into<String>) -> Self {
        self.ws_peers.push(url.into());
        self
    }

    /// Open a serial face (USB-OTG / accessory UART) at `port`, `baud`,
    /// COBS-framed.
    pub fn with_serial(mut self, port: impl Into<String>, baud: u32) -> Self {
        self.serial_ports.push((port.into(), baud));
        self
    }

    /// Listen on a Unix-domain socket at `path` and mount each accepted
    /// connection as a local `FaceKind::App` face — the cross-process seam for
    /// an on-device UI / VPN-extension client. Connections are *not* granted
    /// operator-level management trust; privileged verbs still require signed
    /// commands. The listener survives `suspend_network_faces` (it is a local,
    /// not a network, face).
    pub fn with_ipc_listener(mut self, path: impl Into<String>) -> Self {
        self.ipc_listen_path = Some(path.into());
        self
    }

    /// Mount the NFD-compatible management dispatcher
    /// (`/localhost/nfd/<module>/<verb>`) inside the engine, so an on-device
    /// UI can register routes, list faces, query the CS, etc. over NDN.
    /// Requires the `management` feature.
    #[cfg(feature = "management")]
    pub fn with_management(mut self) -> Self {
        self.enable_management = true;
        self
    }

    /// Mount the management dispatcher with **command authentication**:
    /// `command_validator` verifies signed command Interests against its trust
    /// schema, `command_response_signer` signs control responses, signed
    /// commands are required, and an anti-replay `SignatureTime` cache plus a
    /// locked-down runtime policy are installed. This is the secure default for
    /// any engine exposed to a UI/VPN client.
    ///
    /// The identity typically comes from [`enrollment`](crate::enroll): persist
    /// the [`EnrolledIdentity`](crate::enroll::EnrolledIdentity) as a SafeBag on
    /// first run, then on later runs `load_identity` it and build a `Validator`
    /// anchored on the CA, passing both here. Requires the `management` feature.
    #[cfg(feature = "management")]
    pub fn with_management_secured(
        mut self,
        command_validator: Arc<ndn_security::Validator>,
        command_response_signer: Arc<dyn ndn_security::Signer>,
    ) -> Self {
        self.enable_management = true;
        self.secured_mgmt = Some((command_validator, command_response_signer));
        self
    }

    /// Supply the host-owned log ring backing `/localhost/nfd/log`. The
    /// embedding app installs the tracing layer (libraries never do) and passes
    /// the resulting [`LogInspector`](ndn_mgmt::LogInspector) here. Requires the
    /// `management` feature.
    #[cfg(feature = "management")]
    pub fn with_log_inspector(mut self, inspector: Arc<ndn_mgmt::LogInspector>) -> Self {
        self.log_inspector = Some(inspector);
        self
    }

    /// Wire a read-only compute-introspection backend behind
    /// `/localhost/nfd/compute/list` (e.g. from a `ComputeService`). Without
    /// this the `compute` mgmt module reports "not wired". Requires the
    /// `management` feature.
    #[cfg(feature = "management")]
    pub fn with_compute_mgmt_backend(
        mut self,
        backend: Arc<dyn ndn_mgmt::ComputeMgmtBackend>,
    ) -> Self {
        self.compute_mgmt_backend = Some(backend);
        self
    }

    /// Register a routing protocol (e.g. `StaticProtocol`, `DvProtocol`,
    /// `NlsrProtocol` from `ndn-routing`). The caller constructs the protocol
    /// with its own config — a mobile leaf typically needs only static routes
    /// or `add_route`; a mesh node runs DV/NLSR.
    pub fn with_routing_protocol(mut self, proto: Arc<dyn RoutingProtocol>) -> Self {
        self.routing_protocols.push(proto);
        self
    }

    /// Use a custom service-discovery / autoconfig protocol (e.g.
    /// `ServiceDiscoveryProtocol`) instead of the built-in Hello probe.
    /// Mutually exclusive with [`Self::with_discovery`]; the custom protocol
    /// wins if both are set.
    pub fn with_discovery_protocol(mut self, proto: Arc<dyn DiscoveryProtocol>) -> Self {
        self.discovery_protocol = Some(proto);
        self
    }

    /// Mount an in-process compute face at `prefix`. Register handlers on the
    /// returned-by-[`MobileEngine::compute_registry`] registry. Native Rust
    /// handlers only — the wasmtime/JIT executor is not built (iOS forbids JIT).
    /// Requires the `compute` feature.
    #[cfg(feature = "compute")]
    pub fn with_compute(mut self, prefix: impl Into<Name>) -> Self {
        self.compute_prefix = Some(prefix.into());
        self
    }

    /// Enable per-face/prefix rate limiting. `policy_toml` is an optional
    /// `[rate_limit]` TOML block (same schema as the forwarder config); `None`
    /// starts with an empty table to be populated at runtime via management.
    /// Requires the `ratelimit` feature.
    #[cfg(feature = "ratelimit")]
    pub fn with_rate_limit(mut self, policy_toml: Option<String>) -> Self {
        self.rate_limit = Some(policy_toml);
        self
    }

    /// EXPERIMENTAL: enable the FEC / network-coding policy surface (draft
    /// `ndn-coding`). Only effective with the `management` feature, which
    /// exposes the policy table over `/localhost/nfd/coding/...`.
    /// Requires the `fec` feature.
    #[cfg(feature = "fec")]
    pub fn with_fec(mut self) -> Self {
        self.enable_fec = true;
        self
    }

    /// Mount the VPN datapath (tap-tunnel pull model) with `config`'s self/peer
    /// prefixes. Drive the OS tun device from [`MobileEngine::tun_handle`].
    /// Requires the `tun` feature.
    #[cfg(feature = "tun")]
    pub fn with_tun(mut self, config: TunConfig) -> Self {
        self.tun_config = Some(config);
        self
    }

    /// Enables Hello-protocol neighbor discovery with [`DiscoveryProfile::Mobile`].
    /// Requires [`Self::with_udp_multicast`]; otherwise discovery is silently
    /// disabled at build time.
    pub fn with_discovery(mut self, node_name: impl Into<Name>) -> Self {
        self.node_name = Some(node_name.into());
        self
    }

    /// On-disk content store at `path` (e.g. iOS App Group container,
    /// Android `Context.getFilesDir()`). Requires the `fjall` feature.
    #[cfg(feature = "fjall")]
    pub fn with_persistent_cs(mut self, path: impl Into<PathBuf>) -> Self {
        self.persistent_cs_path = Some(path.into());
        self
    }

    /// Returns `(engine, default_app_handle)`; pass the handle to
    /// `Consumer::from_handle` or use [`MobileEngine::register_producer`].
    pub async fn build(self) -> Result<(MobileEngine, InProcHandle), anyhow::Error> {
        let config = EngineConfig {
            cs_capacity_bytes: self.cs_capacity_mb * 1024 * 1024,
            pipeline_threads: self.pipeline_threads,
            pipeline_channel_cap: 1024,
            ..EngineConfig::default()
        };

        // Use the builder's counter for every face ID so the FaceTable stays
        // consistent. Allocate the InProcFace ID first so it lands as FaceId(1).
        let mut builder = EngineBuilder::new(config).security_profile(self.security_profile);
        builder = match self.strategy {
            MobileStrategy::BestRoute => builder.strategy(BestRouteStrategy::new()),
            MobileStrategy::Multicast => builder.strategy(MulticastStrategy::new()),
            #[cfg(feature = "cclf")]
            MobileStrategy::Cclf => builder.strategy(ndn_strategy_cclf::native::CclfStrategy::new()),
        };
        let app_face_id = builder.alloc_face_id();
        let (app_face, app_handle) = InProcFace::new(app_face_id, 256);
        builder = builder.face(app_face);

        #[cfg(feature = "fjall")]
        if let Some(ref path) = self.persistent_cs_path {
            let cs =
                ndn_store::FjallCs::open(path, self.cs_capacity_mb * 1024 * 1024).map_err(|e| {
                    anyhow::anyhow!("failed to open persistent CS at {}: {e}", path.display())
                })?;
            builder = builder.content_store(Arc::new(cs));
        }

        // Reserve the multicast face ID so resume() can recreate it without
        // invalidating existing FIB entries.
        let multicast_face_id = if self.multicast_iface.is_some() {
            Some(builder.alloc_face_id())
        } else {
            None
        };

        // Rate-limit hook (engine pipeline stage). The table is also handed to
        // the management dispatcher below so policies are runtime-mutable.
        #[cfg(feature = "ratelimit")]
        #[cfg_attr(not(feature = "management"), allow(unused_variables))]
        let rate_limit_table = match self.rate_limit {
            Some(ref toml) => {
                let table = ndn_ratelimit::RateLimitPolicyTable::new();
                if let Some(src) = toml
                    && let Err(e) = ndn_ratelimit::RateLimitConfig::from_toml(src)
                        .and_then(|c| c.populate(&table))
                {
                    tracing::warn!(error = %e, "rate-limit policy parse failed; starting empty");
                }
                let table = Arc::new(table);
                builder = builder.with_rate_limit_hook(Some(Arc::new(
                    ndn_ratelimit::EngineRateLimitHook::new(Arc::clone(&table)),
                )));
                Some(table)
            }
            None => None,
        };

        // FEC / network-coding policy table (experimental; surfaced via mgmt).
        #[cfg(feature = "fec")]
        #[cfg_attr(not(feature = "management"), allow(unused_variables))]
        let coding_table = if self.enable_fec {
            Some(Arc::new(ndn_coding::CodingPolicyTable::new()))
        } else {
            None
        };

        // Discovery: a custom service-discovery protocol wins over the
        // built-in Hello probe. When the built-in probe runs, expose a snapshot
        // of its config for `/localhost/nfd` query.
        #[cfg(feature = "management")]
        let mut discovery_cfg_snapshot: Option<Arc<std::sync::RwLock<DiscoveryConfig>>> = None;
        if let Some(proto) = self.discovery_protocol {
            builder.register_discovery(proto);
        } else if let Some(ref node_name) = self.node_name {
            let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile);
            let discovery = NeighborProbeProtocol::new(
                node_name.clone(),
                cfg.hello_interval_base,
                cfg.liveness_miss_count as u8,
            );
            #[cfg(feature = "management")]
            {
                discovery_cfg_snapshot = Some(Arc::new(std::sync::RwLock::new(cfg)));
            }
            builder.register_discovery(Arc::new(discovery));
        }

        for proto in self.routing_protocols {
            builder.register_routing_protocol(proto);
        }

        let (engine, shutdown) = builder.build().await?;
        let network_cancel = shutdown.cancel_token().child_token();

        if let Some(face_id) = multicast_face_id {
            let iface = self.multicast_iface.unwrap();
            match MulticastUdpFace::ndn_default(iface, face_id).await {
                Ok(face) => {
                    engine.add_face(face, network_cancel.child_token());
                }
                Err(e) => {
                    tracing::warn!(%iface, error = %e, "UDP multicast face setup failed");
                }
            }
        }

        // Reserve a stable face id per peer and mount it. The (id, spec) pairs
        // are retained on `MobileEngine` so `resume_network_faces` rebuilds
        // every peer with the same id and `route_to_peer` can resolve a peer.
        let mut network_peers: Vec<(FaceId, PeerSpec)> = Vec::new();
        for peer in self.unicast_peers {
            network_peers.push((engine.faces().alloc_id(), PeerSpec::UdpUnicast(peer)));
        }
        for peer in self.tcp_peers {
            network_peers.push((engine.faces().alloc_id(), PeerSpec::Tcp(peer)));
        }
        for url in self.ws_peers {
            network_peers.push((engine.faces().alloc_id(), PeerSpec::WebSocket(url)));
        }
        for (port, baud) in self.serial_ports {
            network_peers.push((engine.faces().alloc_id(), PeerSpec::Serial(port, baud)));
        }
        for (id, spec) in &network_peers {
            build_peer_face(&engine, *id, spec, network_cancel.child_token()).await;
        }

        // In-process compute face: dispatch Interests under `prefix` to the
        // registry's native handlers. Register handlers via
        // `MobileEngine::compute_registry()`.
        #[cfg(feature = "compute")]
        let compute_registry = if let Some(prefix) = self.compute_prefix {
            let registry = Arc::new(ComputeRegistry::new());
            let face_id = engine.faces().alloc_id();
            engine.add_face(
                ComputeFace::new(face_id, Arc::clone(&registry)),
                shutdown.cancel_token().child_token(),
            );
            engine.fib().add_nexthop(&prefix, face_id, 0);
            Some(registry)
        } else {
            None
        };

        // VPN datapath (tap-tunnel pull model): a consumer+producer app, not a
        // forwarding face. Uses the shutdown token so it stays up for the
        // tunnel process's life, independent of network-face suspend/resume.
        #[cfg(feature = "tun")]
        let tun_handle = self
            .tun_config
            .map(|config| spawn_tunnel(&engine, config, shutdown.cancel_token().child_token()));

        // Local IPC listener (the cross-process UI / VPN-extension seam). Uses
        // the shutdown token, not network_cancel, so it survives backgrounding.
        if let Some(path) = self.ipc_listen_path {
            match IpcListener::bind(&path) {
                Ok(listener) => {
                    let engine = engine.clone();
                    let cancel = shutdown.cancel_token().child_token();
                    tokio::spawn(async move {
                        tracing::info!(uri = %listener.uri(), "IPC face listener ready");
                        loop {
                            let face_id = engine.faces().alloc_id();
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                r = listener.accept_as(face_id, FaceKind::App) => match r {
                                    Ok(face) => engine.add_face(face, cancel.child_token()),
                                    Err(e) => {
                                        tracing::warn!(error = %e, "IPC listener accept error");
                                        continue;
                                    }
                                },
                            }
                        }
                        listener.cleanup();
                    });
                }
                Err(e) => tracing::warn!(%path, error = %e, "IPC listener bind failed"),
            }
        }

        // NFD-compatible management dispatcher inside the engine.
        #[cfg(feature = "management")]
        if self.enable_management {
            let cancel = shutdown.cancel_token().child_token();
            let config = std::sync::Arc::new(ndn_config::ForwarderConfig::default());

            #[cfg(feature = "ratelimit")]
            let rate_limit_handler = rate_limit_table.as_ref().map(|t| {
                Arc::new(ndn_ratelimit::RateLimitMgmtHandler::new(Arc::clone(t)))
                    as Arc<dyn ndn_mgmt::RateLimitMgmtBackend>
            });
            #[cfg(not(feature = "ratelimit"))]
            let rate_limit_handler: Option<Arc<dyn ndn_mgmt::RateLimitMgmtBackend>> = None;

            #[cfg(feature = "fec")]
            let coding_handler = coding_table.as_ref().map(|t| {
                Arc::new(ndn_coding::CodingMgmtHandler::new(Arc::clone(t)))
                    as Arc<dyn ndn_mgmt::CodingHandler>
            });
            #[cfg(not(feature = "fec"))]
            let coding_handler: Option<Arc<dyn ndn_mgmt::CodingHandler>> = None;

            // Secured vs open management. When `with_management_secured` was
            // used, require signed commands, verify them against the supplied
            // validator, sign responses, install anti-replay, and lock the
            // runtime policy. Otherwise mount open (trusted local face only).
            let (
                command_validator,
                command_response_signer,
                require_signed_commands,
                command_replay_cache,
                runtime_policy,
                security_is_ephemeral,
            ) = match self.secured_mgmt {
                Some((validator, signer)) => (
                    Some(validator),
                    Some(signer),
                    true,
                    Some(Arc::new(std::sync::Mutex::new(
                        std::collections::HashMap::new(),
                    ))),
                    Some(Arc::new(std::sync::RwLock::new(
                        ndn_mgmt::MgmtAccessPolicy {
                            ephemeral_allowed: false,
                            localhop_disabled: true,
                            replay_window_secs: 120,
                            require_signed_commands: true,
                            validator_anchor: None,
                        },
                    ))),
                    false,
                ),
                None => (None, None, false, None, None, true),
            };

            let handles = ndn_mgmt::MgmtHandles {
                discovery_cfg: discovery_cfg_snapshot,
                security_is_ephemeral,
                command_validator,
                localhop_command_validator: None,
                require_signed_commands,
                command_replay_cache,
                command_response_signer,
                log_inspector: self.log_inspector,
                coding_handler,
                rate_limit_handler,
                compute_handler: self.compute_mgmt_backend,
                webtransport_status_handler: None,
                ble_handler: None,
                approval_handler: None,
                runtime_policy,
            };
            let fut = ndn_mgmt::mount_management(
                &engine,
                cancel,
                None,
                Vec::new(),
                config,
                None,
                handles,
            );
            tokio::spawn(fut);
        }

        Ok((
            MobileEngine {
                engine,
                shutdown,
                network_cancel,
                multicast_iface: self.multicast_iface,
                multicast_face_id: multicast_face_id.unwrap_or(FaceId(0)),
                network_peers,
                #[cfg(feature = "compute")]
                compute_registry,
                #[cfg(feature = "tun")]
                tun_handle,
            },
            app_handle,
        ))
    }
}

impl MobileEngine {
    pub fn builder() -> MobileEngineBuilder {
        MobileEngineBuilder::default()
    }

    /// Allocate a new in-process face for an independent app component.
    pub fn new_app_handle(&self) -> (FaceId, InProcHandle) {
        let face_id = self.engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, 256);
        let cancel = self.shutdown.cancel_token().child_token();
        self.engine.add_face(face, cancel);
        (face_id, handle)
    }

    /// Allocates an in-process face, installs a FIB route for `prefix`, and
    /// returns a [`Producer`] bound to that face. Delegates to the shared
    /// [`EngineAppExt`](ndn_app::EngineAppExt) helper so desktop, mobile, and
    /// embedded all register producers the same way.
    pub fn register_producer(&self, prefix: impl Into<Name>) -> Producer {
        use ndn_app::EngineAppExt;
        self.engine
            .register_producer(prefix, self.shutdown.cancel_token().child_token())
    }

    pub fn consumer(&self, handle: InProcHandle) -> Consumer {
        Consumer::from_handle(handle)
    }

    pub fn add_route(&self, prefix: &Name, face_id: FaceId, cost: u32) {
        self.engine.fib().add_nexthop(prefix, face_id, cost);
    }

    /// Cancels every network face (multicast, unicast, TCP, WebSocket, serial);
    /// in-process traffic and the IPC listener continue. Call from
    /// `applicationDidEnterBackground` / `onPause`. The configured peer faces
    /// are `Persistent`, so they (and their FIB routes) are retained — call
    /// [`Self::resume_network_faces`] to rebuild them on `onResume`.
    /// Platform-supplied faces (e.g. Bluetooth) added against
    /// [`Self::network_cancel_token`] suspend with them but must be re-added by
    /// the caller after resume.
    pub fn suspend_network_faces(&mut self) {
        tracing::debug!("suspending network faces");
        self.network_cancel.cancel();
        // Fresh token so `resume_network_faces` doesn't immediately cancel.
        self.network_cancel = self.shutdown.cancel_token().child_token();
    }

    /// Rebuilds every configured network face — multicast and all unicast / TCP
    /// / WebSocket / serial peers — with its original `FaceId`, so FIB entries
    /// (including routes installed via [`Self::route_to_peer`]) stay valid
    /// across suspend/resume. Call from `applicationWillEnterForeground` /
    /// `onResume`.
    pub async fn resume_network_faces(&mut self) {
        tracing::debug!("resuming network faces");
        if let Some(iface) = self.multicast_iface {
            match MulticastUdpFace::ndn_default(iface, self.multicast_face_id).await {
                Ok(face) => {
                    self.engine
                        .add_face(face, self.network_cancel.child_token());
                    tracing::debug!(%iface, face_id = %self.multicast_face_id, "multicast face resumed");
                }
                Err(e) => {
                    tracing::warn!(%iface, error = %e, "multicast face resume failed");
                }
            }
        }
        for (id, spec) in &self.network_peers {
            build_peer_face(&self.engine, *id, spec, self.network_cancel.child_token()).await;
            tracing::debug!(face_id = %id, uri = %spec.uri(), "network peer resumed");
        }
    }

    /// The configured network peers (unicast / TCP / WebSocket / serial), each
    /// an opaque [`PeerRef`]. Use with [`Self::route_to_peer`] to register a
    /// prefix toward a specific peer. Multicast is managed by discovery and is
    /// not listed here.
    pub fn peers(&self) -> Vec<PeerRef> {
        self.network_peers
            .iter()
            .map(|(id, spec)| PeerRef {
                id: *id,
                uri: spec.uri(),
            })
            .collect()
    }

    /// Register a FIB route for `prefix` toward `peer`, so Interests under
    /// `prefix` forward out that peer's face. The ergonomic, raw-face-id-free
    /// way to point traffic at a gateway: `route_to_peer("/ndn", &peer, 0)`.
    /// The route is installed at the peer's stable face id, so it survives
    /// suspend/resume.
    pub fn route_to_peer(&self, prefix: impl Into<Name>, peer: &PeerRef, cost: u32) {
        self.engine
            .fib()
            .add_nexthop(&prefix.into(), peer.id, cost);
    }

    pub fn engine(&self) -> &ForwarderEngine {
        &self.engine
    }

    /// The compute registry, if `with_compute` was set. Register native
    /// handlers on it via `ComputeRegistry::register`.
    #[cfg(feature = "compute")]
    pub fn compute_registry(&self) -> Option<&Arc<ComputeRegistry>> {
        self.compute_registry.as_ref()
    }

    /// Platform side of the VPN datapath face, if `with_tun` was set. The
    /// native tun pump injects OS packets via [`TunHandle::inject`] and drains
    /// engine output via [`TunHandle::next`].
    #[cfg(feature = "tun")]
    pub fn tun_handle(&self) -> Option<Arc<TunHandle>> {
        self.tun_handle.clone()
    }

    /// Pass (a child of) this token when registering platform-supplied
    /// faces (e.g. Bluetooth) so they suspend with the built-in network ones.
    pub fn network_cancel_token(&self) -> CancellationToken {
        self.network_cancel.child_token()
    }

    /// Drains in-flight packets before returning.
    pub async fn shutdown(self) {
        self.shutdown.shutdown().await;
    }
}
