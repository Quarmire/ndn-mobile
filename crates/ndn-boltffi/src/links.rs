//! The QUIC links this device hosts: [`ndn_link`] on the embedded engine,
//! with the same admission, relay choice, link modes, held Interests, wake
//! tokens and direct paths as the `ndn-fwd` daemon. This module only wires
//! the app's parts in: the loaded identity (its key, certificate and
//! issuers), the adopted trust contexts, the engine's faces and RIB, the
//! socket the platform hands over, and the app's lifecycle and network
//! changes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::ForwarderEngine;
use ndn_face_quic::{KeyError, KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, HostCandidates, LinkHints, LinkMode, LinkReport, LinkSetup, LinkTrust,
    Links, PeerId, PeerSpec, RelayOptions, RelaySource, RelayUse,
};
use ndn_packet::Name;
use ndn_security::{Certificate, Keyring};
use tokio_util::sync::CancellationToken;

use crate::identity_core::IdentityCore;
use crate::types::{
    NdnError, NdnLinkMode, NdnLinkReport, NdnLinkStatus, NdnLinksConfig, NdnPathStatus, NdnRelay,
    NdnRelaySource, NdnRelayStatus,
};

/// The key this device links with: the loaded identity, read at each
/// handshake, so an identity installed later (an enrollment) is the one the
/// next link presents.
struct IdentityKey(Arc<IdentityCore>);

impl LinkKeySource for IdentityKey {
    fn current(&self) -> Result<LinkKey, KeyError> {
        let signer = self.0.current_signer().ok_or_else(|| {
            KeyError::Unsupported(
                "this device has no identity loaded: load, generate or enroll one, then start links".into(),
            )
        })?;
        LinkKey::from_signer(signer)
    }
}

/// The trust data links are admitted from: the adopted trust contexts, this
/// device's certificate and issuers, and the certificates the engine has
/// validated.
struct AppTrust {
    core: Arc<IdentityCore>,
    engine: ForwarderEngine,
}

impl LinkTrust for AppTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        self.core.keyring()
    }

    fn own_chain(&self) -> Vec<Bytes> {
        self.core.own_chain()
    }

    fn known_certificate(&self, name: &Name) -> Option<Certificate> {
        self.core
            .recorded_certificate(name)
            .or_else(|| self.engine.validator().and_then(|v| v.cert_cache().get_valid(name)))
    }

    fn known_certificate_of_key(&self, fingerprint: &KeyFingerprint) -> Option<Certificate> {
        self.engine
            .validator()
            .and_then(|v| v.cert_cache().get_by_key_digest(&fingerprint.0))
    }
}

/// How a person at this device does what a refusal asks, in the app's terms.
fn hints() -> LinkHints {
    LinkHints {
        enroll: "enroll this device in the app with an invite link, or by an admin's approval".into(),
        renew: "renew this device's certificate in the app".into(),
        refresh: "refresh the namespace's trust context in the app".into(),
        peer_entry: "relay".into(),
        expect_key: "add this device on the other device with expected key {key}".into(),
    }
}

fn link_mode(mode: &NdnLinkMode) -> LinkMode {
    match mode {
        NdnLinkMode::Always => LinkMode::Always,
        NdnLinkMode::OnDemand { idle_secs } => LinkMode::OnDemand {
            idle: Duration::from_secs(u64::from(*idle_secs)),
        },
        NdnLinkMode::Off => LinkMode::Off,
    }
}

fn ndn_link_mode(mode: &LinkMode) -> NdnLinkMode {
    match mode {
        LinkMode::Always => NdnLinkMode::Always,
        LinkMode::OnDemand { idle } => NdnLinkMode::OnDemand {
            idle_secs: u32::try_from(idle.as_secs()).unwrap_or(u32::MAX),
        },
        LinkMode::Off => NdnLinkMode::Off,
    }
}

fn refused(what: &str, why: impl std::fmt::Display) -> NdnError {
    NdnError::Engine {
        msg: format!("{what}: {why}"),
    }
}

/// A UDP socket the platform made, owned from here on.
fn adopt_socket(fd: i32) -> Result<std::net::UdpSocket, NdnError> {
    use std::os::fd::FromRawFd;
    if fd < 0 {
        return Err(refused("link socket", format!("{fd} is not a file descriptor")));
    }
    // SAFETY: the caller hands over an open UDP socket it no longer uses
    // (documented on every FFI call taking `socket_fd`).
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    socket
        .local_addr()
        .map_err(|e| refused("link socket", format!("fd {fd} is not a bound UDP socket: {e}")))?;
    Ok(socket)
}

/// The links' keep-alive and idle timeout: the host's, within the bounds
/// NAT bindings allow, else the library's.
fn transport(config: &NdnLinksConfig) -> Result<LinkTransportConfig, NdnError> {
    match (config.keep_alive_secs, config.idle_timeout_secs) {
        (None, None) => Ok(LinkTransportConfig::default()),
        (keep_alive, idle) => {
            let default = LinkTransportConfig::default();
            LinkTransportConfig::bounded(
                keep_alive.map_or(default.keep_alive, |s| Duration::from_secs(u64::from(s))),
                idle.map_or(default.idle_timeout, |s| Duration::from_secs(u64::from(s))),
            )
            .map_err(|why| refused("links not started", why))
        }
    }
}

/// The device's links, while they run.
pub(crate) struct PhoneLinks {
    links: Arc<Links>,
    socket: Arc<LinkEndpoint>,
    cancel: CancellationToken,
    active: AtomicBool,
}

impl PhoneLinks {
    /// Bind the link socket and start the links. Runs inside the engine's
    /// runtime (it spawns the link tasks).
    pub(crate) fn start(
        core: &Arc<IdentityCore>,
        engine: &ForwarderEngine,
        config: NdnLinksConfig,
        cancel: CancellationToken,
    ) -> Result<Self, NdnError> {
        let key: Arc<dyn LinkKeySource> = Arc::new(IdentityKey(Arc::clone(core)));
        // Fail now, with the reason, when the identity cannot link (none
        // loaded, an enclave key that signs only asynchronously, …).
        key.current().map_err(|e| refused("links not started", e))?;
        let transport = transport(&config)?;
        if !config.issuers.is_empty() {
            core.set_issuers(config.issuers.into_iter().map(Bytes::from).collect());
        }
        let socket = match config.socket_fd {
            Some(fd) => LinkEndpoint::from_socket(adopt_socket(fd)?, Arc::clone(&key), &transport, config.listen),
            None => {
                let bind = config.bind.as_deref().unwrap_or("0.0.0.0:0");
                let addr: SocketAddr = bind.parse().map_err(|_| NdnError::invalid_addr(bind))?;
                LinkEndpoint::bind(addr, Arc::clone(&key), &transport, config.listen)
            }
        }
        .map_err(|e| refused("cannot open the link socket", e))?;
        let socket = Arc::new(socket);
        let links = Links::start(
            LinkSetup {
                peers: Vec::new(),
                key,
                trust: Arc::new(AppTrust {
                    core: Arc::clone(core),
                    engine: engine.clone(),
                }),
                faces: Arc::new(EngineFaces(engine.clone())),
                paths: Arc::new(ConfiguredEndpoints),
                candidates: vec![Arc::new(HostCandidates::default())],
                socket: Some(Arc::clone(&socket)),
                transport,
                hints: hints(),
                relays: RelayOptions {
                    count: config.relay_count.max(1) as usize,
                    use_namespace: config.use_namespace_relays,
                    namespace_mode: link_mode(&config.namespace_relay_mode),
                    namespace_hold: config.namespace_relay_hold,
                },
                service: Default::default(),
                direct: Default::default(),
            },
            cancel.clone(),
        );
        // An app starts links from the foreground; it says otherwise with
        // set_app_active(false).
        links.set_active(true);
        tokio::spawn(relink_on_switch(
            Arc::downgrade(&links),
            core.identity_switches(),
            cancel.clone(),
        ));
        Ok(Self {
            links,
            socket,
            cancel,
            active: AtomicBool::new(true),
        })
    }

    /// The configured peer (a relay the user added, or one a namespace
    /// lists) called `label`.
    fn peer(&self, label: &str) -> Result<PeerId, NdnError> {
        self.links
            .report()
            .links
            .iter()
            .find(|l| l.label == label)
            .and_then(|l| l.peer)
            .ok_or_else(|| refused(label, "no relay or peer of this device has this label (see link_status)"))
    }

    pub(crate) fn add_relay(&self, relay: NdnRelay) -> Result<(), NdnError> {
        let label = relay.label.trim().to_owned();
        if label.is_empty() {
            return Err(refused("relay not added", "it needs a label"));
        }
        if self.links.report().links.iter().any(|l| l.label == label) {
            return Err(refused(
                &format!("relay {label} not added"),
                "this device already has a relay or peer with this label: remove it first, or choose another",
            ));
        }
        let what = format!("relay {label} not added");
        let key = relay
            .key
            .as_deref()
            .map(|k| KeyFingerprint::from_hex(k).ok_or_else(|| refused(&what, "its key is not 64 hex digits")))
            .transpose()?;
        let device = relay
            .device
            .as_deref()
            .map(|d| d.parse::<Name>().map_err(|_| NdnError::invalid_name(d)))
            .transpose()?;
        if key.is_none() && device.is_none() {
            return Err(refused(
                &what,
                "name its expected key (a relay of another namespace) or its device (a relay of this \
                 device's namespace)",
            ));
        }
        if relay.endpoints.is_empty() {
            return Err(refused(&what, "it needs at least one host:port endpoint"));
        }
        let routes = relay
            .routes
            .iter()
            .map(|r| r.parse::<Name>().map_err(|_| NdnError::invalid_name(r)))
            .collect::<Result<Vec<_>, _>>()?;
        self.links.add_peer(PeerSpec {
            label,
            key,
            device,
            endpoints: relay.endpoints,
            routes: (!routes.is_empty()).then_some(routes),
            persistent: true,
            mode: link_mode(&relay.mode),
            hold: relay.hold,
            relay_use: Some(RelayUse {
                source: RelaySource::User,
                preference: relay.preference,
            }),
            ..Default::default()
        });
        Ok(())
    }

    pub(crate) fn remove_relay(&self, label: &str) -> Result<(), NdnError> {
        self.links.remove_peer(self.peer(label)?);
        Ok(())
    }

    pub(crate) fn set_mode(&self, label: &str, mode: &NdnLinkMode) -> Result<(), NdnError> {
        self.links.set_mode(self.peer(label)?, link_mode(mode));
        Ok(())
    }

    pub(crate) fn connect(&self, label: &str) -> Result<(), NdnError> {
        self.links.connect(self.peer(label)?);
        Ok(())
    }

    pub(crate) fn disconnect(&self, label: &str) -> Result<(), NdnError> {
        self.links.disconnect(self.peer(label)?);
        Ok(())
    }

    pub(crate) fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
        self.links.set_active(active);
    }

    pub(crate) fn set_wake_token(&self, label: &str, token: Option<Vec<u8>>) -> Result<(), NdnError> {
        self.links.set_wake_token(self.peer(label)?, token.map(Bytes::from));
        Ok(())
    }

    /// The device moved to another network: links migrate to `socket_fd`
    /// (or a fresh socket), dropped links are dialled again and direct
    /// paths punched again now.
    pub(crate) fn network_changed(&self, socket_fd: Option<i32>) -> Result<(), NdnError> {
        let socket = socket_fd.map(adopt_socket).transpose()?;
        self.links.network_changed(socket);
        Ok(())
    }

    pub(crate) fn report(&self) -> NdnLinkReport {
        report(
            &self.links.report(),
            self.socket.local_addr().ok(),
            self.active.load(Ordering::Relaxed),
        )
    }

    /// Tell every linked device this one is going, then stop.
    pub(crate) async fn shutdown(self) {
        self.links.shutdown().await;
        self.cancel.cancel();
    }
}

fn report(r: &LinkReport, local: Option<SocketAddr>, active: bool) -> NdnLinkReport {
    NdnLinkReport {
        key: r.key.map(|k| k.to_string()),
        local_address: local.map(|a| a.to_string()),
        active,
        probes_sent: r.probes_sent,
        punches_refused: r.punches_refused,
        links: r
            .links
            .iter()
            .map(|l| NdnLinkStatus {
                label: l.label.clone(),
                key: l.key.map(|k| k.to_string()),
                device: l.device.as_ref().map(ToString::to_string),
                mode: l.mode.as_ref().map(ndn_link_mode),
                relay: l.relay.as_ref().map(|r| NdnRelayStatus {
                    source: match &r.source {
                        RelaySource::User => NdnRelaySource::User,
                        RelaySource::Namespace(ns) => NdnRelaySource::Namespace {
                            namespace: ns.to_string(),
                        },
                    },
                    preference: r.preference,
                    state: r.state.as_str().to_owned(),
                    text: r.text.clone(),
                }),
                paths: l
                    .paths
                    .iter()
                    .map(|p| NdnPathStatus {
                        kind: p.kind.as_str().to_owned(),
                        remote: p.remote.map(|a| a.to_string()),
                        rtt_ms: p.rtt.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                        age_secs: p.age.as_secs(),
                        via: p.via.clone(),
                    })
                    .collect(),
                down: l.down.clone(),
                direct_state: l.direct.state.as_str().to_owned(),
                direct_text: l.direct.text.clone(),
                direct_retry_secs: l.direct.retry_in.map(|d| d.as_secs()),
            })
            .collect(),
    }
}

/// Each time another identity is installed (an enrollment), make the
/// enrollment links of its namespace again as full links.
async fn relink_on_switch(
    links: std::sync::Weak<Links>,
    mut switches: tokio::sync::watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = switches.changed() => if changed.is_err() { return },
        }
        let Some(links) = links.upgrade() else { return };
        links.key_switched();
    }
}
