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
use ndn_transport::{FaceId, FaceKind, FacePersistency};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "compute")]
use ndn_compute::{ComputeFace, ComputeRegistry};
#[cfg(feature = "tun")]
use crate::tun::{TunConfig, TunHandle, spawn_tunnel};

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
    pipeline_threads: usize,
    #[cfg_attr(not(feature = "management"), allow(dead_code))]
    enable_management: bool,
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
            pipeline_threads: 1,
            enable_management: false,
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
        // built-in Hello probe.
        if let Some(proto) = self.discovery_protocol {
            builder.register_discovery(proto);
        } else if let Some(ref node_name) = self.node_name {
            let cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Mobile);
            let discovery = NeighborProbeProtocol::new(
                node_name.clone(),
                cfg.hello_interval_base,
                cfg.liveness_miss_count as u8,
            );
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

        for peer in self.unicast_peers {
            let face_id = engine.faces().alloc_id();
            let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
            match UdpFace::bind(local, peer, face_id).await {
                Ok(face) => {
                    engine.add_face_with_persistency(
                        face,
                        network_cancel.child_token(),
                        FacePersistency::Persistent,
                    );
                }
                Err(e) => {
                    tracing::warn!(%peer, error = %e, "UDP unicast face setup failed");
                }
            }
        }

        for peer in self.tcp_peers {
            let face_id = engine.faces().alloc_id();
            match tcp_face_connect(face_id, peer).await {
                Ok(face) => engine.add_face_with_persistency(
                    face,
                    network_cancel.child_token(),
                    FacePersistency::Persistent,
                ),
                Err(e) => tracing::warn!(%peer, error = %e, "TCP face setup failed"),
            }
        }

        for url in self.ws_peers {
            let face_id = engine.faces().alloc_id();
            match WebSocketFace::connect(face_id, &url).await {
                Ok(face) => engine.add_face_with_persistency(
                    face,
                    network_cancel.child_token(),
                    FacePersistency::Persistent,
                ),
                Err(e) => tracing::warn!(%url, error = %e, "WebSocket face setup failed"),
            }
        }

        for (port, baud) in self.serial_ports {
            let face_id = engine.faces().alloc_id();
            match serial_face_open(face_id, &port, baud) {
                Ok(face) => engine.add_face_with_persistency(
                    face,
                    network_cancel.child_token(),
                    FacePersistency::Persistent,
                ),
                Err(e) => tracing::warn!(%port, baud, error = %e, "serial face setup failed"),
            }
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

            let handles = ndn_mgmt::MgmtHandles {
                discovery_cfg: None,
                security_is_ephemeral: true,
                command_validator: None,
                localhop_command_validator: None,
                require_signed_commands: false,
                command_replay_cache: None,
                command_response_signer: None,
                log_inspector: None,
                coding_handler,
                rate_limit_handler,
                compute_handler: None,
                webtransport_status_handler: None,
                ble_handler: None,
                approval_handler: None,
                runtime_policy: None,
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

    /// Cancels every network face; in-process traffic continues. Call from
    /// `applicationDidEnterBackground` / `onPause`. Unicast peers and
    /// Bluetooth faces must be re-added via [`Self::engine`] +
    /// [`Self::network_cancel_token`] after resume.
    pub fn suspend_network_faces(&mut self) {
        tracing::debug!("suspending network faces");
        self.network_cancel.cancel();
        // Fresh token so `resume_network_faces` doesn't immediately cancel.
        self.network_cancel = self.shutdown.cancel_token().child_token();
    }

    /// Recreates the multicast face with its original `FaceId` so FIB
    /// entries stay valid across suspend/resume. Call from
    /// `applicationWillEnterForeground` / `onResume`.
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
