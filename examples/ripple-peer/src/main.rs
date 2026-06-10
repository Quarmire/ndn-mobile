//! `ripple-peer` — a desktop NDN node that shares and fetches named objects over
//! the local Wi-Fi NDN multicast group, with **no gateway**.
//!
//! It's the desktop counterpart to the Anchor/Ripple phone app: it runs the
//! *same* object-plane code ([`Producer::publish_object`] /
//! [`Consumer::fetch_object`] over a `MobileEngine` multicast face), so it
//! doubles as (a) the second node for verifying gateway-free AirDrop-style
//! transfer phone↔laptop, and (b) a reference desktop leaf.
//!
//! ```text
//! ripple-peer <iface-ipv4> publish <ndn-name> <file>     # serve a file by name
//! ripple-peer <iface-ipv4> fetch   <ndn-name> <outfile>  # fetch it into outfile
//! ```
//!
//! `<iface-ipv4>` is the site-local IPv4 of the Wi-Fi interface to bind the NDN
//! multicast face to (e.g. the address `ifconfig`/`ip addr` shows for your Wi-Fi).
//! Both peers must be on the same Wi-Fi (multicast 224.0.23.170:6363).

use anyhow::{Context, Result, bail};
use ndn_mobile::{Consumer, MobileEngine, Name, Producer};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    if let Err(e) = run().await {
        eprintln!("ripple-peer: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         ripple-peer <iface-ipv4> publish <ndn-name> <file>      # over NDN multicast\n  \
         ripple-peer <iface-ipv4> fetch   <ndn-name> <outfile>   # over NDN multicast\n  \
         ripple-peer via <ip:port> fetch  <ndn-name> <outfile>   # verified, unicast via a forwarder"
    );
    std::process::exit(2);
}

async fn run() -> Result<()> {
    // Binaries own subscriber init (libraries never do); honors RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init()
        .ok();

    let args: Vec<String> = std::env::args().skip(1).collect();
    // Two transports:
    //   <iface-ipv4> <cmd> <name> <path>   — over the local NDN multicast group
    //   via <ip:port> <cmd> <name> <path>  — unicast through a forwarder (e.g. a
    //                                         laptop ndn-fwd the phone uplinks to);
    //                                         isolates the secure transfer from
    //                                         the AP's multicast behaviour.
    let via = args.first().map(|s| s.as_str()) == Some("via");
    let base = if via { 1 } else { 0 };
    if args.len() != base + 4 {
        usage();
    }
    let uplink: Option<std::net::SocketAddr> = if via {
        Some(
            args[1]
                .parse()
                .with_context(|| format!("bad forwarder addr `{}`", args[1]))?,
        )
    } else {
        None
    };
    let iface: std::net::Ipv4Addr = if via {
        std::net::Ipv4Addr::UNSPECIFIED
    } else {
        args[0]
            .parse()
            .with_context(|| format!("bad interface IPv4 `{}`", args[0]))?
    };
    let cmd = args[base + 1].as_str();
    let name_str = args[base + 2].clone();
    let name: Name = name_str
        .parse()
        .with_context(|| format!("bad NDN name `{name_str}`"))?;
    let path = &args[base + 3];

    // Persisted NDN identity, named for the object so it sits hierarchically
    // above it — secure by default: published Data is SIGNED with this key, and
    // fetches are VERIFIED against it (a hierarchical trust schema anchored on
    // this self-cert). NDN security travels with the data; this peer never
    // produces unsigned Data nor accepts unverified Data. To trust a *different*
    // peer's content, pin its cert via RIPPLE_TRUST=<cert.der> (the cross-peer
    // anchor — in the full product that anchor is the operator's TrustContext).
    let id_dir = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".ripple-peer");
    std::fs::create_dir_all(&id_dir).ok();
    let id_path = id_dir.join(name_str.trim_start_matches('/').replace('/', "_"));
    let keychain = ndn_security::KeyChain::open_or_create(&id_path, &name_str)
        .map_err(|e| anyhow::anyhow!("identity: {e}"))?;
    let pinned: Option<ndn_security::Certificate> = match std::env::var("RIPPLE_TRUST") {
        Ok(cert_path) => {
            let der = std::fs::read(&cert_path).with_context(|| format!("reading {cert_path}"))?;
            let data = ndn_packet::Data::decode(bytes::Bytes::from(der))
                .map_err(|e| anyhow::anyhow!("RIPPLE_TRUST not a Data/cert: {e}"))?;
            let cert = ndn_security::Certificate::decode(&data)
                .map_err(|e| anyhow::anyhow!("RIPPLE_TRUST cert: {e}"))?;
            eprintln!("pinned trust anchor from {cert_path}");
            Some(cert)
        }
        Err(_) => None,
    };

    // A full forwarding node. Default face = the local NDN multicast group
    // (gateway-free); with `via`, a unicast TCP face to the forwarder instead.
    let builder = match uplink {
        Some(addr) => MobileEngine::builder().with_tcp_peer(addr),
        None => MobileEngine::builder().with_udp_multicast(iface),
    };
    let (engine, _default_handle) = builder
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("engine build failed: {e}"))?;

    match cmd {
        "publish" => {
            let content = std::fs::read(path).with_context(|| format!("reading {path}"))?;
            // Register the object prefix so multicast Interests for it route to
            // this producer, then serve SIGNED metadata + segments until Ctrl-C.
            let conn = engine.new_registering_app_connection();
            conn.register_prefix(&name)
                .await
                .map_err(|e| anyhow::anyhow!("register {name}: {e}"))?;
            let signer = keychain
                .signer()
                .map_err(|e| anyhow::anyhow!("signer: {e}"))?;
            let producer = Producer::new(conn, name.clone()).with_signer(signer);
            eprintln!(
                "serving {name} ({} bytes) signed as {} on multicast via {iface}; Ctrl-C to stop",
                content.len(),
                keychain.name(),
            );
            // publish_object runs a serve loop until the connection closes; race
            // it against Ctrl-C so the CLI exits cleanly.
            tokio::select! {
                r = producer.publish_object(name.clone(), bytes::Bytes::from(content), 0) =>
                    r.map_err(|e| anyhow::anyhow!("serving {name}: {e}"))?,
                _ = tokio::signal::ctrl_c() => eprintln!("\nstopped."),
            }
        }
        "fetch" => {
            // Egress route for our Interests: `/` → the multicast face, or `/` →
            // the forwarder face when uplinking.
            match uplink {
                None => {
                    if !engine.route_to_multicast("/") {
                        bail!("no multicast face — cannot fetch over the group");
                    }
                }
                Some(_) => {
                    let root: Name = "/".parse().unwrap();
                    for peer in engine.peers() {
                        engine.route_to_peer(root.clone(), &peer, 0);
                    }
                }
            }
            let (_face_id, handle) = engine.new_app_handle();
            // Build the validator (own anchors) and register the pinned peer cert
            // as a TERMINAL anchor (add_trust_anchor, so the chain walk stops at
            // it — not just cert-cached). verifying(): every segment + the metadata
            // Data is checked before reassembly; unsigned/untrusted is refused.
            let validator = keychain.validator();
            if let Some(cert) = pinned.clone() {
                validator.add_trust_anchor(cert);
            }
            let mut consumer = Consumer::from_handle(handle).verifying(validator);
            eprintln!("fetching {name} (verified) …");
            let bytes = consumer
                .fetch_object(name.clone())
                .await
                .map_err(|e| anyhow::anyhow!("verified fetch of {name}: {e}"))?;
            std::fs::write(path, &bytes).with_context(|| format!("writing {path}"))?;
            eprintln!("verified + fetched {} bytes -> {path}", bytes.len());
        }
        _ => usage(),
    }
    Ok(())
}
