//! VPN datapath — IP-over-NDN via **persistent-Interest streaming**.
//!
//! Evolves the tap-tunnel pull model onto persistent Interests (the
//! `SubscriptionRequest` extension) so the downlink is idle-cheap — no Interest
//! re-expression while quiet. See the prior-art survey and the efficiency
//! discussion in `.claude/notes/vpn/`.
//!
//! Each endpoint runs both roles against the engine (over whatever real network
//! face — UDP/TCP/WS — reaches the peer):
//!
//! - **Producer / uplink.** Registers `self_prefix`. The peer's persistent
//!   Interest grants a streaming *budget* (its `SubscriptionRequest.max_data_count`);
//!   captured outbound IP packets are published as `self_prefix/seg=<n>` Data,
//!   one per budget unit, satisfying the live persistent PIT entry. No
//!   Interest-per-packet.
//! - **Consumer / downlink.** One [`Consumer::subscribe`](ndn_app::Consumer::subscribe)
//!   on `peer_prefix`; `Subscription::recv()` streams downlink Data, each
//!   carrying one IP packet written back to the OS tun. While the link is quiet
//!   the persistent Interest just pends — zero polling.
//!
//! Not a `Transport`/forwarding face: it is an application (consumer +
//! producer). The OS tun (Android `ParcelFileDescriptor` fd / iOS
//! `NEPacketTunnelProvider.packetFlow`, no fd assumed) is pumped via [`TunHandle`].

use std::time::Duration;

use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use ndn_app::{EngineAppExt, SubscribeOptions};
use ndn_engine::ForwarderEngine;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, SubscriptionRequest};

/// Tunnel configuration: the two routable prefixes and the subscription budget.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Prefix our producer streams outbound IP under (the peer subscribes here).
    pub self_prefix: Name,
    /// Prefix our consumer subscribes to for downlink IP (the peer's producer).
    pub peer_prefix: Name,
    /// Data packets one persistent Interest carries before the consumer
    /// re-subscribes (and the budget we grant a subscribing peer).
    pub credit: u32,
    /// Persistent PIT lifetime per subscription.
    pub lifetime: Duration,
}

impl TunConfig {
    pub fn new(self_prefix: impl Into<Name>, peer_prefix: impl Into<Name>) -> Self {
        Self {
            self_prefix: self_prefix.into(),
            peer_prefix: peer_prefix.into(),
            credit: 4096,
            lifetime: Duration::from_secs(300),
        }
    }

    pub fn credit(mut self, n: u32) -> Self {
        self.credit = n.max(1);
        self
    }

    pub fn lifetime(mut self, d: Duration) -> Self {
        self.lifetime = d;
        self
    }
}

const TUN_QUEUE_CAP: usize = 1024;
/// Freshness on streamed tunnel Data — satisfies the consumer's MustBeFresh
/// without lingering in any CS (names are unique per seq anyway).
const TUN_DATA_FRESHNESS: Duration = Duration::from_secs(1);

/// Platform side of the datapath. The native tun pump injects OS packets via
/// [`TunHandle::inject`] (OS → engine) and drains engine output via
/// [`TunHandle::next`] (engine → OS). No fd is assumed.
pub struct TunHandle {
    /// Outbound IP captured from the OS tun (OS → producer streamer).
    inject_tx: mpsc::Sender<Bytes>,
    /// Downlink IP to write to the OS tun (subscription → OS).
    deliver_rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl TunHandle {
    /// Submit an IP packet read from the OS tun device (apps → tunnel).
    pub async fn inject(&self, ip_packet: Bytes) -> Result<(), TunClosed> {
        self.inject_tx.send(ip_packet).await.map_err(|_| TunClosed)
    }

    /// Next IP packet to write to the OS tun device (tunnel → apps). `None`
    /// once the tunnel is gone.
    pub async fn next(&self) -> Option<Bytes> {
        self.deliver_rx.lock().await.recv().await
    }
}

/// The tunnel was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunClosed;

impl std::fmt::Display for TunClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tun datapath closed")
    }
}
impl std::error::Error for TunClosed {}

/// Start the persistent-Interest VPN datapath against `engine`. Spawns the
/// producer serve loop (grants streaming budget per peer subscription), the
/// uplink streamer (publishes outbound IP as Data), and the downlink
/// subscription (pulls IP back). Returns the [`TunHandle`] for the platform tun
/// pump. All tasks stop when `cancel` fires.
pub fn spawn_tunnel(
    engine: &ForwarderEngine,
    config: TunConfig,
    cancel: CancellationToken,
) -> Arc<TunHandle> {
    let (inject_tx, mut inject_rx) = mpsc::channel::<Bytes>(TUN_QUEUE_CAP);
    let (deliver_tx, deliver_rx) = mpsc::channel::<Bytes>(TUN_QUEUE_CAP);

    let producer = Arc::new(engine.register_producer(config.self_prefix.clone(), cancel.child_token()));
    // Streaming budget: a peer's persistent Interest adds `max_data_count`
    // permits; the streamer consumes one per published Data.
    let budget = Arc::new(Semaphore::new(0));

    // ── Producer serve loop: grant budget per (persistent) Interest. ────────
    {
        let producer = Arc::clone(&producer);
        let budget = Arc::clone(&budget);
        tokio::spawn(async move {
            let _ = producer
                .serve(move |interest, _responder| {
                    let budget = Arc::clone(&budget);
                    async move {
                        // The persistent PIT entry already exists; we stream
                        // Data into it separately, so the Responder is dropped.
                        let credit = interest
                            .app_parameters()
                            .and_then(SubscriptionRequest::find_in)
                            .map(|s| s.max_data_count as usize)
                            .unwrap_or(1);
                        budget.add_permits(credit);
                    }
                })
                .await;
        });
    }

    // ── Uplink streamer: publish outbound IP as Data while budget remains. ──
    {
        let producer = Arc::clone(&producer);
        let budget = Arc::clone(&budget);
        let self_prefix = config.self_prefix.clone();
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            let mut seq: u64 = 0;
            loop {
                // Wait for an outbound packet first, so budget is only consumed
                // when there is something to send.
                let ip = tokio::select! {
                    _ = cancel.cancelled() => break,
                    x = inject_rx.recv() => match x { Some(i) => i, None => break },
                };
                let permit = tokio::select! {
                    _ = cancel.cancelled() => break,
                    p = budget.acquire() => match p { Ok(p) => p, Err(_) => break },
                };
                permit.forget(); // consume one budget unit

                // Name Data at the logical prefix + seq. The forwarder strips the
                // subscriber Interest's ParametersSha256Digest at insert (PIT
                // doctrine), keying the persistent entry at `self_prefix`, so
                // `self_prefix/seg=<n>` Data match it (CanBePrefix).
                if let Some(flow) = parse_ip_flow(&ip) {
                    tracing::trace!(?flow, len = ip.len(), "tun: streaming outbound IP");
                }
                let name = self_prefix.clone().append_segment(seq);
                seq += 1;
                let data = DataBuilder::new(name, &ip).freshness(TUN_DATA_FRESHNESS).build();
                if producer.publish(data).await.is_err() {
                    break;
                }
            }
        });
    }

    // ── Downlink: one persistent subscription pulls IP back to the OS. ──────
    {
        let consumer = engine.app_consumer(cancel.child_token());
        let peer_prefix = config.peer_prefix.clone();
        let opts = SubscribeOptions {
            max_data_count: config.credit,
            lifetime: config.lifetime,
        };
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            // Re-subscribe on the same face if the peer producer is down or the
            // subscription errors (Nack/Closed); reuses one app face, no churn.
            'resubscribe: loop {
                if cancel.is_cancelled() {
                    break;
                }
                let mut sub = match consumer.subscribe(peer_prefix.clone(), opts.clone()).await {
                    Ok(s) => s,
                    Err(_) => {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
                        }
                    }
                };
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break 'resubscribe,
                        r = sub.recv() => match r {
                            Ok(data) => {
                                if let Some(content) = data.content()
                                    && deliver_tx.send(content.clone()).await.is_err()
                                {
                                    break 'resubscribe; // OS side gone
                                }
                            }
                            Err(_) => break, // re-subscribe
                        },
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
            }
        });
    }

    Arc::new(TunHandle {
        inject_tx,
        deliver_rx: Mutex::new(deliver_rx),
    })
}

/// IP 5-tuple extracted from a packet header — the basis any flow-based naming
/// or filtering needs. Ports are `0` for non-TCP/UDP protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpFlow {
    pub version: u8,
    pub protocol: u8,
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Best-effort 5-tuple parse of an IPv4/IPv6 packet. `None` for truncated or
/// unrecognized headers. Does not walk IPv6 extension headers (first Next
/// Header only); good enough for flow keying / logging.
pub fn parse_ip_flow(pkt: &[u8]) -> Option<IpFlow> {
    use std::net::IpAddr;
    let version = pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            let protocol = pkt[9];
            let src = IpAddr::from([pkt[12], pkt[13], pkt[14], pkt[15]]);
            let dst = IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]]);
            let (src_port, dst_port) = l4_ports(protocol, pkt.get(ihl..));
            Some(IpFlow { version: 4, protocol, src, dst, src_port, dst_port })
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let protocol = pkt[6]; // Next Header (first hop only)
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            let (src_port, dst_port) = l4_ports(protocol, pkt.get(40..));
            Some(IpFlow {
                version: 6,
                protocol,
                src: IpAddr::from(s),
                dst: IpAddr::from(d),
                src_port,
                dst_port,
            })
        }
        _ => None,
    }
}

/// (src_port, dst_port) for TCP (6) / UDP (17); `(0, 0)` otherwise.
fn l4_ports(protocol: u8, l4: Option<&[u8]>) -> (u16, u16) {
    match (protocol, l4) {
        (6 | 17, Some(seg)) if seg.len() >= 4 => (
            u16::from_be_bytes([seg[0], seg[1]]),
            u16::from_be_bytes([seg[2], seg[3]]),
        ),
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_udp_flow() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // v4, IHL=5
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&5000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        let f = parse_ip_flow(&pkt).unwrap();
        assert_eq!(f.version, 4);
        assert_eq!(f.protocol, 17);
        assert_eq!(f.src_port, 5000);
        assert_eq!(f.dst_port, 53);
    }

    #[test]
    fn parse_rejects_truncated_and_nonip() {
        assert!(parse_ip_flow(&[]).is_none());
        assert!(parse_ip_flow(&[0x45, 0x00]).is_none());
        assert!(parse_ip_flow(&[0x00]).is_none());
    }

    #[test]
    fn config_credit_floor_is_one() {
        let c = TunConfig::new("/vpn/self", "/vpn/peer").credit(0);
        assert_eq!(c.credit, 1);
    }
}
