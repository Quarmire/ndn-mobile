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
         ripple-peer <iface-ipv4> publish <ndn-name> <file>\n  \
         ripple-peer <iface-ipv4> fetch   <ndn-name> <outfile>"
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
    if args.len() != 4 {
        usage();
    }
    let iface: std::net::Ipv4Addr = args[0]
        .parse()
        .with_context(|| format!("bad interface IPv4 `{}`", args[0]))?;
    let cmd = args[1].as_str();
    let name: Name = args[2]
        .parse()
        .with_context(|| format!("bad NDN name `{}`", args[2]))?;
    let path = &args[3];

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
    let id_path = id_dir.join(args[2].trim_start_matches('/').replace('/', "_"));
    let keychain = ndn_security::KeyChain::open_or_create(&id_path, &args[2])
        .map_err(|e| anyhow::anyhow!("identity: {e}"))?;
    if let Ok(cert_path) = std::env::var("RIPPLE_TRUST") {
        let der = std::fs::read(&cert_path).with_context(|| format!("reading {cert_path}"))?;
        let data = ndn_packet::Data::decode(bytes::Bytes::from(der))
            .map_err(|e| anyhow::anyhow!("RIPPLE_TRUST not a Data/cert: {e}"))?;
        let cert = ndn_security::Certificate::decode(&data)
            .map_err(|e| anyhow::anyhow!("RIPPLE_TRUST cert: {e}"))?;
        keychain.add_trust_anchor(cert);
        eprintln!("pinned trust anchor from {cert_path}");
    }

    // A full forwarding node whose only face is the local NDN multicast group —
    // gateway-free.
    let (engine, _default_handle) = MobileEngine::builder()
        .with_udp_multicast(iface)
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
            // A consumer must egress its Interests onto the group: the multicast
            // face is added unrouted, so install `/` → multicast first.
            if !engine.route_to_multicast("/") {
                bail!("no multicast face — cannot fetch over the group");
            }
            let (_face_id, handle) = engine.new_app_handle();
            // verifying(): every segment + the metadata Data is checked against
            // the pinned anchors before reassembly — unsigned/untrusted is refused.
            let mut consumer = Consumer::from_handle(handle).verifying(keychain.validator());
            eprintln!("fetching {name} over multicast via {iface} (verified) …");
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
