//! FFI-safe value types and error enum.
//!
//! Every type uses `#[data]` (not `#[error]`) so `boltffi`'s helper doesn't
//! clash with `thiserror`'s `#[error(...)]` helper attribute.

use boltffi::data;
use ndn_app::AppError;

#[data]
#[derive(Debug, Clone)]
pub struct NdnData {
    pub name: String,
    pub content: Vec<u8>,
}

impl NdnData {
    pub(crate) fn from_packet(data: ndn_packet::Data) -> Self {
        Self {
            name: data.name.to_string(),
            content: data.content().map(|b| b.to_vec()).unwrap_or_default(),
        }
    }
}

/// One publication from an NDN sync group; `payload` is `None` when the
/// subscriber has `auto_fetch` disabled.
#[data]
#[derive(Debug, Clone)]
pub struct NdnSample {
    pub name: String,
    pub publisher: String,
    pub seq: u64,
    pub payload: Option<Vec<u8>>,
}

impl NdnSample {
    pub(crate) fn from_sample(s: ndn_app::Sample) -> Self {
        Self {
            name: s.name.to_string(),
            publisher: s.publisher,
            seq: s.seq,
            payload: s.payload.map(|b| b.to_vec()),
        }
    }
}

/// What to enroll via NDNCERT ([`NdnEngine::enroll`](crate::NdnEngine::enroll)).
#[data]
#[derive(Debug, Clone)]
pub struct NdnEnrollConfig {
    /// CA prefix, e.g. `/ndn` — Interests go to `<ca_prefix>/CA/{NEW,CHALLENGE}`.
    pub ca_prefix: String,
    /// Identity to certify, e.g. `/ndn/mobile/alice`.
    pub identity: String,
    /// Requested certificate validity in seconds.
    pub validity_secs: u64,
    /// Password to encrypt the persistable SafeBag returned in the result.
    pub persist_password: Vec<u8>,
}

/// The result of a successful enrollment. The identity is also loaded into the
/// engine (so `sign` works); `safebag` is the encrypted bag the host persists.
#[data]
#[derive(Debug, Clone)]
pub struct NdnEnrolledIdentity {
    pub key_name: String,
    pub cert_name: String,
    /// Issued certificate wire, if the CA's repo served it.
    pub certificate: Option<Vec<u8>>,
    /// Password-encrypted SafeBag to persist (App Group / Keychain).
    pub safebag: Vec<u8>,
}

/// A class of management action for a §7 scoped-signing grant
/// ([`NdnEngine::grant_signing_scope`](crate::NdnEngine::grant_signing_scope)).
/// `Any` covers every non-sensitive class; the others narrow the grant.
/// Trust/custody/policy commands (the `security` and `ca` modules) are
/// *always-ask* and can't be granted — they always interrupt with a prompt.
//
// NOTE: keep `/*` out of these doc comments — boltffi wraps them into Kotlin
// KDoc, and Kotlin nests block comments, so an inner `/*` swallows the closing
// `*/` and breaks the generated binding.
#[data]
#[derive(Debug, Clone, Copy)]
pub enum NdnActionClass {
    /// Any non-sensitive action.
    Any,
    /// Route register / unregister (`rib` module).
    Route,
    /// Face create / destroy / update (`faces` module).
    Face,
    /// Strategy set / unset (`strategy-choice` module).
    Strategy,
    /// Content-store config / erase (`cs` module).
    ContentStore,
    /// Application Data signing / unknown commands.
    Other,
}

/// The result of a fresh-device restore
/// ([`NdnEngine::restore_identity`](crate::NdnEngine::restore_identity)). The
/// recovered operational key is loaded into the engine; persist `safebag`
/// (App Group / Keychain) so next launch is `load_identity`, and re-back-up
/// `bundle` (the recovery bundle, now with the recovery link appended).
#[data]
#[derive(Debug, Clone)]
pub struct NdnRecoveredIdentity {
    pub key_name: String,
    pub cert_name: String,
    /// Password-encrypted SafeBag of the new operational key.
    pub safebag: Vec<u8>,
    /// The recovery bundle with this recovery appended — store it as the new backup.
    pub bundle: Vec<u8>,
}

/// One adopted trust context — a participant membership
/// ([`NdnEngine::list_contexts`](crate::NdnEngine::list_contexts)). `namespace`
/// is the relationship's name (e.g. `/home/bob`, `/work/acme`); `anchor_count`
/// is how many trust anchors it carries.
#[data]
#[derive(Debug, Clone)]
pub struct NdnContext {
    pub namespace: String,
    pub version: u64,
    pub anchor_count: u64,
    pub enforces_hierarchy: bool,
}

impl NdnContext {
    pub(crate) fn from_ctx(c: &ndn_security::SignedTrustContext) -> Self {
        Self {
            namespace: c.namespace().to_string(),
            version: c.version(),
            anchor_count: c.anchors().len() as u64,
            enforces_hierarchy: c.enforces_hierarchy(),
        }
    }
}

/// A verified revocation
/// ([`NdnEngine::verify_revocation`](crate::NdnEngine::verify_revocation)): a
/// signed statement that `revoked` is dead. Feed `revoked` into a verifier's
/// revocation list. `self_revocation` is true when the key revoked itself
/// (accept it from any trusted key without a further authority check).
#[data]
#[derive(Debug, Clone)]
pub struct NdnRevocation {
    pub revoked: String,
    pub reason: String,
    pub revoked_at_ms: u64,
    pub self_revocation: bool,
}

/// The scope a §3 device delegation grants
/// ([`NdnEngine::add_device`](crate::NdnEngine::add_device)). `sign_patterns`
/// are trust-schema pattern strings (e.g. `/alice/device/phone/<**rest>`); the
/// flags grant content-key unwrap, sub-enrollment, and management authority.
#[data]
#[derive(Debug, Clone)]
pub struct NdnDelegationScope {
    pub sign_patterns: Vec<String>,
    pub unwrap_for: bool,
    pub enroll: bool,
    pub mgmt: bool,
}

/// A parsed `ndn-trust://` onboarding/pairing envelope ([`NdnTrust::parse`](crate::NdnTrust::parse)).
/// Each variant routes to a different flow; the host matches on the variant and
/// calls the corresponding engine method.
#[data]
#[derive(Debug, Clone)]
pub enum NdnTrustEnvelope {
    /// Adopt a trust context — feed to `join_context(context_content, version)`.
    Anchor {
        version: u64,
        context_content: Vec<u8>,
    },
    /// NDNCERT enrollment invitation — drive token-enroll against `ca_prefix`.
    Invite {
        ca_prefix: String,
        identity_namespace: String,
        token: String,
        ttl_secs: Option<u64>,
    },
    /// A signed delegation to import (sponsorship) — verify + use via the
    /// delegated-signing path.
    Delegation {
        signed_delegation: Vec<u8>,
        principal_pubkey: Vec<u8>,
    },
    /// A recovery bundle — feed to `restore_identity`.
    Recovery { bundle: Vec<u8> },
    /// A password-encrypted SafeBag — feed to `load_identity(safebag, password, key_name)`.
    Bag { key_name: String, safebag: Vec<u8> },
    /// An ephemeral scoped capability (pairing). `is_grant` distinguishes a
    /// peer's request (false) from an issued grant (true); `grant` carries the
    /// signed capability wire on a grant.
    Capability {
        is_grant: bool,
        namespace: String,
        scope_patterns: Vec<String>,
        ttl_secs: u64,
        nonce: Vec<u8>,
        grant: Option<Vec<u8>>,
    },
}

#[data]
#[derive(Debug, Clone)]
pub enum NdnSecurityProfile {
    /// Full chain validation with certificate fetching.
    Default,
    /// Verify signature only; skip trust schema and chain walk.
    AcceptSigned,
    /// All Data accepted unchecked.
    Disabled,
}

pub(crate) fn into_security_profile(p: NdnSecurityProfile) -> ndn_security::SecurityProfile {
    match p {
        NdnSecurityProfile::Default => ndn_security::SecurityProfile::Default,
        NdnSecurityProfile::AcceptSigned => ndn_security::SecurityProfile::AcceptSigned,
        NdnSecurityProfile::Disabled => ndn_security::SecurityProfile::Disabled,
    }
}

/// A **face** to bring up on the node — NDN's native transport abstraction (the
/// `Face`): a way the forwarder reaches peers and data over some underlying
/// transport. A node is configured with a *set* of faces, not a single gateway:
/// the device is a full forwarding node over whatever faces it has (a local
/// multicast face by default, optional uplink faces, serial), so connectivity is
/// declared declaratively rather than skewed toward one host. Mirrors NFD's
/// face-creation model (a FaceUri per face), typed.
///
/// These are the **self-contained** faces (no platform backend needed).
/// Backend-requiring radio faces — **Wi-Fi Aware** (NAN) and **BLE advertising**
/// — attach a platform radio backend (Android JNI: an
/// `ndn_face_wifi_aware::NanBackend` / `ndn_face_ble_adv::AdvBackend`); they ride
/// a separate FFI backend-trait seam (cf. `NdnEnclaveBackend`) and land once that
/// JNI glue exists. Named-radio / Ethernet-multicast are further faces on the
/// same model. See the face roadmap.
#[data]
#[derive(Debug, Clone)]
pub enum NdnFaceSpec {
    /// Local NDN UDP multicast face over `iface` (the site-local IPv4 to bind),
    /// group `224.0.23.170:6363` — the default peer-to-peer, gateway-free face.
    /// (`iface` not `interface`: the latter is a reserved word in some targets.)
    Multicast { iface: String },
    /// A unicast TCP **uplink** face (`"<ip>:<port>"`) to a forwarder/gateway,
    /// dialed persistently with a default route (`/`) toward it — additive reach
    /// to a CA / the internet, NOT how the node primarily connects.
    Uplink { address: String },
    /// A serial-link face (LoRa / UART bridge): device `port` at `baud`.
    Serial { port: String, baud: u32 },
}

#[data]
#[derive(Debug, Clone)]
pub struct NdnEngineConfig {
    pub cs_capacity_mb: u32,
    pub security_profile: NdnSecurityProfile,
    /// The node's **face set** — how it reaches peers and data. A forwarder over
    /// whatever faces it is given; empty = isolated (only in-proc / seam faces).
    /// A local multicast face by default, optional uplinks — see [`NdnFaceSpec`].
    pub faces: Vec<NdnFaceSpec>,
    /// Named-beacon discovery node name, e.g. `"/anchor/node/ab12"`. Requires a
    /// [`NdnFaceSpec::Multicast`] face.
    pub node_name: Option<String>,
    pub pipeline_threads: u32,
    /// On-disk CS dir; needs the `fjall`/`sqlite-cs` feature, otherwise ignored.
    pub persistent_cs_path: Option<String>,
}

#[data]
#[derive(Debug, thiserror::Error)]
pub enum NdnError {
    #[error("timeout waiting for data: {name}")]
    Timeout { name: String },
    #[error("interest nacked ({reason}): {name}")]
    Nacked { name: String, reason: String },
    #[error("engine error: {msg}")]
    Engine { msg: String },
    #[error("invalid NDN name: {name}")]
    InvalidName { name: String },
    #[error("invalid address: {addr}")]
    InvalidAddress { addr: String },
    #[error("identity error: {msg}")]
    Identity { msg: String },
}

impl NdnError {
    pub(crate) fn from_app(e: AppError, name: &str) -> Self {
        match e {
            AppError::Timeout => NdnError::Timeout {
                name: name.to_string(),
            },
            AppError::Nacked { reason } => NdnError::Nacked {
                name: name.to_string(),
                reason: reason
                    .map(|reason| format!("{reason:?}"))
                    .unwrap_or_else(|| "Unspecified".to_string()),
            },
            AppError::Connection(e) => NdnError::Engine { msg: e.to_string() },
            AppError::Closed => NdnError::Engine {
                msg: "connection closed".into(),
            },
            AppError::Protocol(msg) => NdnError::Engine { msg },
            AppError::Unverified(why) => NdnError::Engine {
                msg: format!("verification failed: {why}"),
            },
        }
    }

    pub(crate) fn engine(e: impl std::fmt::Display) -> Self {
        NdnError::Engine { msg: e.to_string() }
    }

    #[cfg(feature = "identity")]
    pub(crate) fn identity(e: impl std::fmt::Display) -> Self {
        NdnError::Identity { msg: e.to_string() }
    }

    pub(crate) fn invalid_name(name: impl Into<String>) -> Self {
        NdnError::InvalidName { name: name.into() }
    }

    pub(crate) fn invalid_addr(addr: impl Into<String>) -> Self {
        NdnError::InvalidAddress { addr: addr.into() }
    }
}
