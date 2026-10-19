//! A phone without the phone: the `ndn-boltffi` FFI surface an app calls,
//! driven line by line over stdin, so the end-to-end harness can run the
//! app's link flow (identity, relays, link modes, lifecycle, network
//! changes) against real `ndn-fwd` daemons.
//!
//! Every command answers `ok [...]` or `err <why>`, then any detail lines,
//! then a line holding only `.`:
//!
//! ```text
//! generate <identity>                 a self-certified identity (links before enrollment)
//! links <bind> [listen]               start_links on a socket bound to <bind>
//! relay <label> <device|-> <key|-> <endpoint> <mode> [hold] [pref=<n>] [route=<prefix>]...
//! unrelay <label>                     remove_relay
//! enroll <invite-uri> <device>        enroll_with_invite (over the relay's enrollment link)
//! mode <label> <mode>                 set_link_mode; <mode>: always | off | on-demand:<idle secs>
//! connect <label> | disconnect <label>
//! active <true|false>                 set_app_active
//! wake <label> <hex|->                set_wake_token
//! net [<bind>]                        network_changed (a socket bound to <bind>, else fresh)
//! status                              link_status, one fact per line
//! publish <name> <text>               publish_object, signed with the identity
//! get <name>                          get: the Data of exactly <name>; prints its content in hex
//!                                     (`<prefix>/seg=0` of a single-segment `ndn-put`)
//! quit
//! ```

use std::io::{BufRead, Write};
use std::os::fd::IntoRawFd;
use std::sync::Arc;

use ndn_boltffi::{
    NdnEngine, NdnEngineConfig, NdnLinkMode, NdnLinkReport, NdnLinksConfig, NdnRelay, NdnRelaySource,
    NdnSecurityProfile,
};

const PASSWORD: &[u8] = b"phone-host";

fn mode(word: &str) -> Result<NdnLinkMode, String> {
    match word {
        "always" => Ok(NdnLinkMode::Always),
        "off" => Ok(NdnLinkMode::Off),
        _ => word
            .strip_prefix("on-demand:")
            .and_then(|s| s.parse().ok())
            .map(|idle_secs| NdnLinkMode::OnDemand { idle_secs })
            .ok_or_else(|| format!("{word:?} is not a mode (always, off, on-demand:<idle secs>)")),
    }
}

fn mode_word(mode: &NdnLinkMode) -> String {
    match mode {
        NdnLinkMode::Always => "always".into(),
        NdnLinkMode::Off => "off".into(),
        NdnLinkMode::OnDemand { idle_secs } => format!("on-demand:{idle_secs}"),
    }
}

fn opt(word: &str) -> Option<String> {
    (word != "-").then(|| word.to_owned())
}

fn hex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err(format!("{text:?} is not hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| format!("{text:?} is not hex")))
        .collect()
}

fn bound_socket(bind: &str) -> Result<i32, String> {
    let socket = std::net::UdpSocket::bind(bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    Ok(socket.into_raw_fd())
}

fn status_lines(r: &NdnLinkReport) -> Vec<String> {
    let or_dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    let mut lines = vec![
        format!("key {}", or_dash(&r.key)),
        format!("local {}", or_dash(&r.local_address)),
        format!("active {}", r.active),
        format!("probes-sent {}", r.probes_sent),
        format!("punches-refused {}", r.punches_refused),
    ];
    for l in &r.links {
        lines.push(format!("link {}", l.label));
        lines.push(format!("  key {}", or_dash(&l.key)));
        lines.push(format!("  device {}", or_dash(&l.device)));
        lines.push(format!("  mode {}", l.mode.as_ref().map_or_else(|| "-".to_owned(), mode_word)));
        if let Some(down) = &l.down {
            lines.push(format!("  down {down}"));
        }
        if let Some(relay) = &l.relay {
            let source = match &relay.source {
                NdnRelaySource::User => "user".to_owned(),
                NdnRelaySource::Namespace { namespace } => format!("namespace:{namespace}"),
            };
            lines.push(format!(
                "  relay {} source={source} preference={} {}",
                relay.state, relay.preference, relay.text
            ));
        }
        for p in &l.paths {
            let mut line = format!("  path {}", p.kind);
            if let Some(remote) = &p.remote {
                line.push_str(&format!(" remote={remote}"));
            }
            if let Some(via) = &p.via {
                line.push_str(&format!(" via={via}"));
            }
            lines.push(line);
        }
        let retry = l
            .direct_retry_secs
            .map(|s| format!(" retry-in-s={s}"))
            .unwrap_or_default();
        lines.push(format!("  direct {}{retry} {}", l.direct_state, l.direct_text));
    }
    lines
}

fn run(engine: &Arc<NdnEngine>, line: &str) -> Result<Vec<String>, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let e = |r: ndn_boltffi::NdnError| r.to_string();
    match words.as_slice() {
        ["generate", identity] => {
            let id = engine.generate_identity((*identity).to_owned(), PASSWORD.to_vec()).map_err(e)?;
            Ok(vec![id.key_name])
        }
        ["links", bind, rest @ ..] => {
            let fd = bound_socket(bind)?;
            let key = engine
                .start_links(NdnLinksConfig {
                    socket_fd: Some(fd),
                    bind: None,
                    listen: rest.contains(&"listen"),
                    relay_count: 1,
                    use_namespace_relays: true,
                    namespace_relay_mode: NdnLinkMode::Always,
                    namespace_relay_hold: false,
                    issuers: Vec::new(),
                    keep_alive_secs: None,
                    idle_timeout_secs: None,
                })
                .map_err(e)?;
            Ok(vec![key])
        }
        ["relay", label, device, key, endpoint, link_mode, rest @ ..] => {
            let mut relay = NdnRelay {
                label: (*label).to_owned(),
                key: opt(key),
                device: opt(device),
                endpoints: vec![(*endpoint).to_owned()],
                preference: 0,
                mode: mode(link_mode)?,
                hold: false,
                routes: Vec::new(),
            };
            for word in rest {
                if *word == "hold" {
                    relay.hold = true;
                } else if let Some(p) = word.strip_prefix("pref=") {
                    relay.preference = p.parse().map_err(|_| format!("{word:?}: not a number"))?;
                } else if let Some(r) = word.strip_prefix("route=") {
                    relay.routes.push(r.to_owned());
                } else {
                    return Err(format!("unknown relay option {word:?}"));
                }
            }
            engine.add_relay(relay).map_err(e)?;
            Ok(Vec::new())
        }
        ["unrelay", label] => engine.remove_relay((*label).to_owned()).map(|_| Vec::new()).map_err(e),
        ["enroll", invite, device] => {
            let id = engine
                .enroll_with_invite((*invite).to_owned(), (*device).to_owned(), PASSWORD.to_vec())
                .map_err(e)?;
            Ok(vec![id.cert_name])
        }
        ["mode", label, link_mode] => engine
            .set_link_mode((*label).to_owned(), mode(link_mode)?)
            .map(|_| Vec::new())
            .map_err(e),
        ["connect", label] => engine.connect_link((*label).to_owned()).map(|_| Vec::new()).map_err(e),
        ["disconnect", label] => engine.disconnect_link((*label).to_owned()).map(|_| Vec::new()).map_err(e),
        ["active", active] => {
            engine.set_app_active(active.parse().map_err(|_| format!("{active:?}: true or false"))?);
            Ok(Vec::new())
        }
        ["wake", label, token] => {
            let token = if *token == "-" { None } else { Some(hex(token)?) };
            engine.set_wake_token((*label).to_owned(), token).map(|_| Vec::new()).map_err(e)
        }
        ["net"] => engine.network_changed(None).map(|_| Vec::new()).map_err(e),
        ["net", bind] => engine
            .network_changed(Some(bound_socket(bind)?))
            .map(|_| Vec::new())
            .map_err(e),
        ["status"] => engine.link_status().map(|r| status_lines(&r)).map_err(e),
        ["publish", name, text @ ..] => {
            // Serves until the engine stops: a worker thread, as an app would.
            let (engine, name, content) = (Arc::clone(engine), (*name).to_owned(), text.join(" ").into_bytes());
            std::thread::spawn(move || {
                if let Err(why) = engine.publish_object(name.clone(), content, 0) {
                    eprintln!("phone-host: publishing {name} ended: {why}");
                }
            });
            Ok(Vec::new())
        }
        ["get", name] => {
            let content = engine.get((*name).to_owned()).map_err(e)?;
            Ok(vec![content.iter().map(|b| format!("{b:02x}")).collect()])
        }
        _ => Err(format!("unknown command {line:?}")),
    }
}

fn main() {
    // The engine's log to stderr (the harness keeps it as phone_host.log),
    // filtered by RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let engine = Arc::new(
        NdnEngine::new(NdnEngineConfig {
            cs_capacity_mb: 4,
            security_profile: NdnSecurityProfile::Default,
            faces: Vec::new(),
            node_name: None,
            pipeline_threads: 2,
            persistent_cs_path: None,
        })
        .expect("engine"),
    );
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "quit" {
            break;
        }
        match run(&engine, line) {
            Ok(lines) => {
                let _ = writeln!(out, "ok");
                for l in lines {
                    let _ = writeln!(out, "{l}");
                }
            }
            Err(why) => {
                let _ = writeln!(out, "err {}", why.replace('\n', " "));
            }
        }
        let _ = writeln!(out, ".");
        let _ = out.flush();
    }
    engine.shutdown();
}
