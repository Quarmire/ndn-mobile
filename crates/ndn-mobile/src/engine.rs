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

#[cfg(feature = "tun")]
use crate::tun::{TunConfig, TunHandle, spawn_tunnel};
#[cfg(feature = "compute")]
use ndn_compute::{ComputeFace, ComputeRegistry};

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
    #[cfg(feature = "webtransport")]
    WebTransport(String, ndn_transport::ClientTls),
}

impl PeerSpec {
    /// Human-readable URI for logs and [`PeerRef::uri`].
    fn uri(&self) -> String {
        match self {
            PeerSpec::UdpUnicast(a) => format!("udp4://{a}"),
            PeerSpec::Tcp(a) => format!("tcp4://{a}"),
            PeerSpec::WebSocket(u) => u.clone(),
            PeerSpec::Serial(p, b) => format!("serial://{p}?baud={b}"),
            #[cfg(feature = "webtransport")]
            PeerSpec::WebTransport(u, _) => u.clone(),
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
    // Try once, bounded by a short timeout, so a reachable peer (a live gateway,
    // or any UDP peer — bind is instant) is connected by the time `build()`
    // returns. This preserves the synchronous-success contract (and the
    // suspend/resume rebuild) without stalling build when the gateway is
    // unreachable.
    const FIRST_ATTEMPT: std::time::Duration = std::time::Duration::from_secs(2);
    let _ = tokio::time::timeout(
        FIRST_ATTEMPT,
        connect_peer_once(engine, id, spec, cancel.child_token()),
    )
    .await;

    // Then supervise for the engine's life: keep the peer connected. A mobile
    // leaf's gateway is unreachable at build time (radio / VPN tunnel / `adb
    // reverse` come up late) AND drops later (cell handover, gateway restart) —
    // giving up either way stranded the node with no upstream until the next full
    // engine rebuild. The engine drops a dead Persistent face but KEEPS its FIB
    // routes, so re-dialing at the same `id` restores the upstream with no route
    // churn. The token is cancelled on engine shutdown/rebuild, stopping the loop.
    let engine = engine.clone();
    let spec = spec.clone();
    tokio::spawn(async move {
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(10);
        const PROBE: std::time::Duration = std::time::Duration::from_secs(2);
        loop {
            // (Re)dial with capped exponential backoff until the face is present.
            let mut backoff = std::time::Duration::from_millis(250);
            while engine.faces().get(id).is_none() {
                if cancel.is_cancelled() {
                    return;
                }
                match connect_peer_once(&engine, id, &spec, cancel.child_token()).await {
                    Ok(()) => {
                        tracing::info!(?spec, "peer face connected");
                        break;
                    }
                    Err(e) => tracing::warn!(
                        ?spec, error = %e,
                        retry_in_ms = backoff.as_millis() as u64,
                        "peer dial failed; retrying"
                    ),
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            // Connected. Watch for the face dropping, then loop to re-dial.
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(PROBE) => {}
                }
                if engine.faces().get(id).is_none() {
                    tracing::info!(?spec, "peer face dropped; reconnecting");
                    break;
                }
            }
        }
    });
}

/// One dial attempt for `spec`: connect the transport and mount it as a
/// `Persistent` face at the stable `id`. Returns `Err` so the caller can retry.
async fn connect_peer_once(
    engine: &ForwarderEngine,
    id: FaceId,
    spec: &PeerSpec,
    cancel: CancellationToken,
) -> Result<(), String> {
    match spec {
        PeerSpec::UdpUnicast(peer) => {
            let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let face = UdpFace::bind(local, *peer, id)
                .await
                .map_err(|e| e.to_string())?;
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
        }
        PeerSpec::Tcp(peer) => {
            let face = tcp_face_connect(id, *peer)
                .await
                .map_err(|e| e.to_string())?;
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
        }
        PeerSpec::WebSocket(url) => {
            let face = WebSocketFace::connect(id, url)
                .await
                .map_err(|e| e.to_string())?;
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
        }
        PeerSpec::Serial(port, baud) => {
            let face = serial_face_open(id, port, *baud).map_err(|e| e.to_string())?;
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
        }
        #[cfg(feature = "webtransport")]
        PeerSpec::WebTransport(url, tls) => {
            let face = ndn_face_webtransport::WebTransportFace::connect(id, url, tls.clone())
                .await
                .map_err(|e| e.to_string())?;
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
        }
    }
    Ok(())
}

/// Battery-conscious span retention for a phone: a short window and small ring
/// vs the forwarder's 1-hour / 8-MiB / 10k-span default.
#[cfg(feature = "observability")]
fn mobile_low_retention() -> ndn_observability::SpanRetention {
    ndn_observability::SpanRetention {
        window: std::time::Duration::from_secs(5 * 60),
        max_bytes: 1024 * 1024,
        max_spans: 1_000,
    }
}

/// Wi-Fi Aware (NAN) configuration: the platform radio backend plus the
/// service↔prefix discovery bindings to install.
#[cfg(feature = "wifi-aware")]
struct WifiAwareCfg {
    backend: Arc<dyn ndn_face_wifi_aware::NanBackend>,
    discover: Vec<(ndn_face_wifi_aware::NanServiceName, Name)>,
    advertise: Vec<ndn_face_wifi_aware::NanServiceName>,
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
    /// Span publisher serving OTLP Data; `None` unless `with_observability`.
    #[cfg(feature = "observability")]
    observability: Option<Arc<ndn_observability::SpanPublisher>>,
    /// NAN coordination face (stable id + platform backend), rebuilt on resume.
    /// `None` unless `with_wifi_aware`.
    #[cfg(feature = "wifi-aware")]
    wifi_aware: Option<(FaceId, Arc<dyn ndn_face_wifi_aware::NanBackend>)>,
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
    #[cfg(feature = "webtransport")]
    webtransport_peers: Vec<(String, ndn_transport::ClientTls)>,
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
    secured_mgmt: Option<(Arc<ndn_security::Validator>, Arc<dyn ndn_security::Signer>)>,
    /// Host-owned log ring for the `/localhost/nfd/log` module. The binary
    /// owns tracing init, so it supplies this; libraries never install it.
    #[cfg(feature = "management")]
    log_inspector: Option<Arc<ndn_mgmt::LogInspector>>,
    /// Read-only `/localhost/nfd/compute/list` backend (e.g. a
    /// `ComputeService::mgmt_backend()`). Distinct from `with_compute`'s
    /// in-process `ComputeRegistry`, which carries no introspection metadata.
    #[cfg(feature = "management")]
    compute_mgmt_backend: Option<Arc<dyn ndn_mgmt::ComputeMgmtBackend>>,
    /// `Some` once `with_wifi_aware` is called: the NAN coordination bearer.
    #[cfg(feature = "wifi-aware")]
    wifi_aware: Option<WifiAwareCfg>,
    /// `Some((prefix, retention))` once `with_observability[_config]` is called:
    /// install a span publisher serving OTLP Data at `prefix`.
    #[cfg(feature = "observability")]
    observability: Option<(Name, ndn_observability::SpanRetention)>,
    #[cfg(feature = "compute")]
    compute_prefix: Option<Name>,
    #[cfg(feature = "ratelimit")]
    rate_limit: Option<Option<String>>,
    #[cfg(feature = "fec")]
    enable_fec: bool,
    #[cfg(feature = "tun")]
    tun_config: Option<TunConfig>,
    #[cfg_attr(
        not(any(feature = "fjall", feature = "sqlite-cs")),
        allow(dead_code)
    )]
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
            #[cfg(feature = "webtransport")]
            webtransport_peers: Vec::new(),
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
            #[cfg(feature = "observability")]
            observability: None,
            #[cfg(feature = "wifi-aware")]
            wifi_aware: None,
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

    /// Dial a WebTransport (QUIC/HTTP3) face to a gateway at `url`
    /// (`https://host:port[/path]`). The NAT/firewall-friendliest cellular
    /// path: HTTP3 traverses CGNAT like HTTPS. `tls` is
    /// [`ClientTls::CertHashes`] to pin a self-signed gateway leaf, or
    /// [`ClientTls::WebPki`] for an ACME/publicly-trusted one — TLS
    /// authenticates the *link*; NDN trust is layered on signed Data. Like the
    /// other peers it gets a stable face id and is rebuilt on resume. Requires
    /// the `webtransport` feature (native only). Per the connection model, route
    /// toward it with [`MobileEngine::route_to_peer`], not a raw face id.
    #[cfg(feature = "webtransport")]
    pub fn with_webtransport_peer(
        mut self,
        url: impl Into<String>,
        tls: ndn_transport::ClientTls,
    ) -> Self {
        self.webtransport_peers.push((url.into(), tls));
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

    /// Publish completed `tracing` spans as OTLP Data under
    /// `/localhost/nfd/observability`, using a battery-conscious retention
    /// (short window, small ring) suited to a phone. The embedding app's
    /// tracing layer decides *which* spans are recorded (the sampling rate);
    /// this only serves what it records. Requires the `observability` feature.
    #[cfg(feature = "observability")]
    pub fn with_observability(mut self) -> Self {
        let prefix = Name::root()
            .append(b"localhost")
            .append(b"nfd")
            .append(b"observability");
        self.observability = Some((prefix, mobile_low_retention()));
        self
    }

    /// Like [`Self::with_observability`] but with an explicit serving `prefix`
    /// and [`SpanRetention`](ndn_observability::SpanRetention) (e.g. a larger
    /// ring on Wi-Fi/charging, tighter on cellular/battery).
    #[cfg(feature = "observability")]
    pub fn with_observability_config(
        mut self,
        prefix: impl Into<Name>,
        retention: ndn_observability::SpanRetention,
    ) -> Self {
        self.observability = Some((prefix.into(), retention));
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

    /// Mount a Wi-Fi Aware (NAN) connectionless coordination face over the
    /// platform-supplied `backend` (Android `WifiAwareManager` via JNI). The
    /// AP-less, association-less named-radio bearer; carries NDN over NAN
    /// follow-up messages and suspends/resumes with the other network faces.
    /// Pair with [`Self::wifi_aware_discover`] / [`Self::wifi_aware_advertise`]
    /// for pub/sub route installation. Requires the `wifi-aware` feature.
    #[cfg(feature = "wifi-aware")]
    pub fn with_wifi_aware(mut self, backend: Arc<dyn ndn_face_wifi_aware::NanBackend>) -> Self {
        self.wifi_aware = Some(WifiAwareCfg {
            backend,
            discover: Vec::new(),
            advertise: Vec::new(),
        });
        self
    }

    /// Subscribe to NAN service `service` and install a route for `prefix`
    /// toward the NAN coordination face when a peer advertising it appears.
    /// No-op unless [`Self::with_wifi_aware`] was called. Registering any
    /// `discover`/`advertise` binding installs a `NanDiscovery` as the engine's
    /// discovery protocol (takes precedence over the built-in Hello probe; an
    /// explicit [`Self::with_discovery_protocol`] still wins).
    #[cfg(feature = "wifi-aware")]
    pub fn wifi_aware_discover(
        mut self,
        service: impl Into<ndn_face_wifi_aware::NanServiceName>,
        prefix: impl Into<Name>,
    ) -> Self {
        if let Some(cfg) = self.wifi_aware.as_mut() {
            cfg.discover.push((service.into(), prefix.into()));
        }
        self
    }

    /// Advertise NAN service `service` so peers discover this node. No-op unless
    /// [`Self::with_wifi_aware`] was called.
    #[cfg(feature = "wifi-aware")]
    pub fn wifi_aware_advertise(
        mut self,
        service: impl Into<ndn_face_wifi_aware::NanServiceName>,
    ) -> Self {
        if let Some(cfg) = self.wifi_aware.as_mut() {
            cfg.advertise.push(service.into());
        }
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
    /// Android `Context.getFilesDir()`). Requires the `fjall` or `sqlite-cs`
    /// feature; on Android the SQLite backend is used (fjall's directory lock
    /// is unsupported there).
    #[cfg(any(feature = "fjall", feature = "sqlite-cs"))]
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
            MobileStrategy::Cclf => {
                builder.strategy(ndn_strategy_cclf::native::CclfStrategy::new())
            }
        };
        let app_face_id = builder.alloc_face_id();
        let (app_face, app_handle) = InProcFace::new(app_face_id, 256);
        builder = builder.face(app_face);

        #[cfg(any(feature = "fjall", feature = "sqlite-cs"))]
        if let Some(ref path) = self.persistent_cs_path {
            let max_bytes = self.cs_capacity_mb * 1024 * 1024;
            // Android: fjall's directory lock (`std::fs::File::try_lock`) returns
            // `Unsupported` on `target_os = "android"`, so use the SQLite backend
            // there. Desktop/iOS keep fjall. Either satisfies `content_store`.
            #[cfg(all(feature = "sqlite-cs", target_os = "android"))]
            let cs: Arc<dyn ndn_store::ErasedContentStore> = Arc::new(
                ndn_store::SqliteCs::open(path, max_bytes).map_err(|e| {
                    anyhow::anyhow!("failed to open SQLite CS at {}: {e}", path.display())
                })?,
            );
            #[cfg(all(feature = "sqlite-cs", not(feature = "fjall"), not(target_os = "android")))]
            let cs: Arc<dyn ndn_store::ErasedContentStore> = Arc::new(
                ndn_store::SqliteCs::open(path, max_bytes).map_err(|e| {
                    anyhow::anyhow!("failed to open SQLite CS at {}: {e}", path.display())
                })?,
            );
            #[cfg(all(feature = "fjall", not(all(feature = "sqlite-cs", target_os = "android"))))]
            let cs: Arc<dyn ndn_store::ErasedContentStore> = Arc::new(
                ndn_store::FjallCs::open(path, max_bytes).map_err(|e| {
                    anyhow::anyhow!("failed to open persistent CS at {}: {e}", path.display())
                })?,
            );
            builder = builder.content_store(cs);
        }

        // Reserve the multicast face ID so resume() can recreate it without
        // invalidating existing FIB entries.
        let multicast_face_id = if self.multicast_iface.is_some() {
            Some(builder.alloc_face_id())
        } else {
            None
        };

        // Reserve the NAN coordination face id before build so a NanDiscovery
        // can target it, and so resume() recreates it without invalidating FIB.
        #[cfg(feature = "wifi-aware")]
        let wifi_aware_coord_id = self.wifi_aware.as_ref().map(|_| builder.alloc_face_id());

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

        // A NanDiscovery (NAN pub/sub → routes) when wifi-aware bindings exist.
        #[cfg(feature = "wifi-aware")]
        let nan_discovery: Option<Arc<dyn DiscoveryProtocol>> =
            match (self.wifi_aware.as_ref(), wifi_aware_coord_id) {
                (Some(cfg), Some(coord_id))
                    if !cfg.discover.is_empty() || !cfg.advertise.is_empty() =>
                {
                    let mut disc =
                        ndn_face_wifi_aware::NanDiscovery::new(Arc::clone(&cfg.backend), coord_id);
                    for (service, prefix) in &cfg.discover {
                        disc = disc
                            .discover(service.clone(), prefix.clone())
                            .await
                            .map_err(|e| anyhow::anyhow!("wifi-aware subscribe: {e}"))?;
                    }
                    for service in &cfg.advertise {
                        disc = disc
                            .advertise(service.clone())
                            .await
                            .map_err(|e| anyhow::anyhow!("wifi-aware publish: {e}"))?;
                    }
                    Some(Arc::new(disc))
                }
                _ => None,
            };
        #[cfg(not(feature = "wifi-aware"))]
        let nan_discovery: Option<Arc<dyn DiscoveryProtocol>> = None;

        // Discovery priority: explicit `with_discovery_protocol` > NAN pub/sub >
        // built-in Hello probe. When the probe runs, expose a config snapshot
        // for `/localhost/nfd` query.
        #[cfg(feature = "management")]
        let mut discovery_cfg_snapshot: Option<Arc<std::sync::RwLock<DiscoveryConfig>>> = None;
        if let Some(proto) = self.discovery_protocol {
            builder.register_discovery(proto);
        } else if let Some(proto) = nan_discovery {
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
        #[cfg(feature = "webtransport")]
        for (url, tls) in self.webtransport_peers {
            network_peers.push((engine.faces().alloc_id(), PeerSpec::WebTransport(url, tls)));
        }
        for (id, spec) in &network_peers {
            build_peer_face(&engine, *id, spec, network_cancel.child_token()).await;
        }

        // NAN coordination face: a connectionless AdHoc bearer over the
        // platform radio backend. Suspends with the network faces; resume
        // rebuilds it at the same id (routes installed by NanDiscovery survive).
        #[cfg(feature = "wifi-aware")]
        let wifi_aware = match (self.wifi_aware, wifi_aware_coord_id) {
            (Some(cfg), Some(coord_id)) => {
                engine.add_face(
                    ndn_face_wifi_aware::NanCoordFace::new(coord_id, Arc::clone(&cfg.backend)),
                    network_cancel.child_token(),
                );
                Some((coord_id, cfg.backend))
            }
            _ => None,
        };

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

        // Span publisher: serve completed tracing spans as OTLP Data. Uses the
        // shutdown token so it lives for the engine's life.
        #[cfg(feature = "observability")]
        let observability = self.observability.map(|(prefix, retention)| {
            let publisher = ndn_observability::SpanPublisher::new(prefix, retention);
            Arc::clone(&publisher).install(&engine, shutdown.cancel_token().child_token());
            publisher
        });

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

            // A mobile node is an *intermediate* forwarder: the UI process drives
            // `/localhost` over the seam (handled locally), but `/localhop` is the
            // node's own upstream registration to its gateway and must EGRESS
            // there, not be claimed here (this node has no localhop validator).
            // `mount_management` always installs a `/localhop/nfd` FIB entry to the
            // internal mgmt face; clear it so `/localhop` falls through to the
            // default route to the gateway — the same path the non-management
            // in-process engine took.
            engine
                .fib()
                .set_nexthops(&ndn_mgmt::mgmt_localhop_prefix(), vec![]);
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
                #[cfg(feature = "observability")]
                observability,
                #[cfg(feature = "wifi-aware")]
                wifi_aware,
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

    /// Adopt one half of a `socketpair()` — an already-connected `SOCK_STREAM`
    /// fd — as a `FaceKind::App` face. This is the cross-process seam: the
    /// engine runs in the tunnel process (Android `VpnService` / iOS Network
    /// Extension) and the UI process holds the other half, speaking NDN
    /// Interest/Data (and NFD management) to this engine over it. The face is a
    /// plain `StreamFace`, so it forwards exactly like any other face; the fd
    /// is owned by the face and closed when the peer hangs up or the engine
    /// shuts down. Returns the new face id. Unix only.
    #[cfg(unix)]
    pub fn mount_app_fd(&self, fd: std::os::fd::RawFd) -> std::io::Result<FaceId> {
        let face_id = self.engine.faces().alloc_id();
        let face = ndn_face_native::local::ipc_face_from_raw_fd(
            face_id,
            ndn_transport::FaceKind::App,
            fd,
        )?;
        self.engine
            .add_face(face, self.shutdown.cancel_token().child_token());
        Ok(face_id)
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

    /// Allocate an in-process app face and return a connection-generic
    /// [`Connection`](ndn_app::Connection) over it whose `register_prefix`
    /// installs a FIB route to this face directly (the in-proc equivalent of the
    /// cross-process NFD `rib/register`). Lets a caller drive producers /
    /// consumers over the embedded engine through the same `Connection` API used
    /// for a cross-process forwarder, registering prefixes uniformly.
    pub fn new_registering_app_connection(&self) -> Arc<dyn ndn_app::Connection> {
        let (face_id, handle) = self.new_app_handle();
        Arc::new(RegisteringInProcConnection {
            inner: ndn_app::InProcConnection::new(handle),
            fib: self.engine.fib(),
            face_id,
        })
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
        #[cfg(feature = "wifi-aware")]
        if let Some((id, backend)) = &self.wifi_aware {
            self.engine.add_face(
                ndn_face_wifi_aware::NanCoordFace::new(*id, Arc::clone(backend)),
                self.network_cancel.child_token(),
            );
            tracing::debug!(face_id = %id, "NAN coordination face resumed");
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
        self.engine.fib().add_nexthop(&prefix.into(), peer.id, cost);
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

    /// The span publisher, if `with_observability` was set — for the host to
    /// query buffered spans or wire its tracing layer's output into it.
    #[cfg(feature = "observability")]
    pub fn observability(&self) -> Option<&Arc<ndn_observability::SpanPublisher>> {
        self.observability.as_ref()
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

/// A connection-generic [`Connection`](ndn_app::Connection) over an embedded
/// engine's in-process app face whose `register_prefix` installs a FIB route to
/// the face directly — the in-proc equivalent of the cross-process NFD
/// `rib/register`. `send` / `recv` delegate to the wrapped
/// [`InProcConnection`](ndn_app::InProcConnection). Built by
/// [`MobileEngine::new_registering_app_connection`].
//
// Implemented without `async_trait` (ndn-mobile doesn't depend on the macro):
// the trait's async methods desugar to boxed-future returns, matched here.
struct RegisteringInProcConnection {
    inner: ndn_app::InProcConnection,
    fib: Arc<ndn_engine::Fib>,
    face_id: FaceId,
}

impl ndn_app::Connection for RegisteringInProcConnection {
    fn send<'a, 'async_trait>(
        &'a self,
        wire: bytes::Bytes,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ndn_app::AppError>> + Send + 'async_trait>,
    >
    where
        'a: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.send(wire)
    }

    fn recv<'a, 'async_trait>(
        &'a self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<bytes::Bytes>> + Send + 'async_trait>,
    >
    where
        'a: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.recv()
    }

    fn recv_with_meta<'a, 'async_trait>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<(bytes::Bytes, ndn_app::LpInfo)>>
                + Send
                + 'async_trait,
        >,
    >
    where
        'a: 'async_trait,
        Self: 'async_trait,
    {
        self.inner.recv_with_meta()
    }

    fn register_prefix<'a, 'b, 'async_trait>(
        &'a self,
        prefix: &'b Name,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ndn_app::AppError>> + Send + 'async_trait>,
    >
    where
        'a: 'async_trait,
        'b: 'async_trait,
        Self: 'async_trait,
    {
        // Embedded engine: write the FIB directly (the in-proc rib/register).
        self.fib.add_nexthop(prefix, self.face_id, 0);
        Box::pin(async { Ok(()) })
    }
}
