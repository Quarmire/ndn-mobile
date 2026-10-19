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
    /// The identity's certificate (Data wire): the issued one, if the CA's
    /// repo served it, or a generated identity's self-certificate. For an
    /// enclave identity (no SafeBag) persist it and pass it to
    /// `load_identity_enclave` at every launch.
    pub certificate: Option<Vec<u8>>,
    /// Password-encrypted SafeBag to persist (App Group / Keychain).
    pub safebag: Vec<u8>,
    /// The trust context adopted on the way (`None` when it was already
    /// held), with its signed Data: persist it and adopt it again at launch.
    pub adopted_context: Option<NdnContext>,
    /// The issuer certificates (signed Data wires, in walk order) of the
    /// certificate's chain, as checked under the namespace's trust context.
    /// Persist them beside the SafeBag and pass them to `renew_certificate`:
    /// after the namespace's root device is replaced through a recovery kit,
    /// nobody else may serve the CA certificate that issued this one, and the
    /// new CA renews it only with this chain. Empty after a token, PIN,
    /// generated or enclave identity: those paths do not check the chain
    /// against a trust context, so they have no verified chain to keep.
    pub issuers: Vec<Vec<u8>>,
}

/// The validity of the loaded identity's certificate, so the host can
/// schedule its renewal with `renew_certificate` (before `renew_at_secs`,
/// and well before `valid_until_secs`: an expired certificate is never
/// renewed — the device then needs a new invite).
#[data]
#[derive(Debug, Clone)]
pub struct NdnCertValidity {
    pub cert_name: String,
    /// Unix seconds.
    pub valid_from_secs: u64,
    /// Unix seconds.
    pub valid_until_secs: u64,
    /// When to renew, Unix seconds: once a third of the lifetime is left
    /// (the `ndn-fwd` daemon's default).
    pub renew_at_secs: u64,
}

/// The outcome of a renewal attempt
/// ([`NdnEngine::renew_certificate`](crate::NdnEngine::renew_certificate)),
/// in the `ndn-fwd` daemon's terms: renewed, refused (retrying cannot help)
/// or failed (retry later). After a refusal or failure the current
/// certificate stays in use.
#[data]
#[derive(Debug, Clone)]
pub enum NdnRenewal {
    /// A new certificate for the same key was issued and is loaded. Persist
    /// `identity.safebag` and `identity.issuers` in place of the old ones.
    Renewed { identity: NdnEnrolledIdentity },
    /// Not renewable as it stands: the CA refused (a revoked key, a role it
    /// does not renew, …), the certificate expired or names no CA of its
    /// namespace, or the certificate the CA issued was refused. Retrying
    /// cannot help; `detail` says why and what to do instead (usually:
    /// enroll again with a new invite).
    Refused { detail: String },
    /// The attempt failed — the CA was unreachable or the device key could
    /// not sign — and can be retried later; `detail` says why.
    Failed { detail: String },
}

/// A request this device made for an admin's approval, as recorded in the
/// app's storage (`<storage_dir>/requests/`, one record per key).
#[data]
#[derive(Debug, Clone)]
pub struct NdnEnrollmentRequest {
    pub namespace: String,
    /// The namespace CA's prefix (`/<ns>` for `/<ns>/CA`).
    pub ca_prefix: String,
    /// The identity asked for, `/<ns>/<role>/<device>`.
    pub identity: String,
    /// The key generated on this device for it.
    pub key_name: String,
    pub request_id: String,
    /// The six-digit verification code: show it, so the person approving
    /// can compare it with the code their admin screen lists.
    pub code: String,
    /// Unix seconds.
    pub created_secs: u64,
    /// When the CA expires the request undecided, Unix seconds (`0`:
    /// unknown).
    pub expires_secs: u64,
    /// `pending`, `issued`, `denied`, `expired` or `failed`.
    pub state: String,
    /// For an ended request: why, and what to do (`issued`: the
    /// certificate's name).
    pub detail: String,
}

/// Where a request for an admin's approval stands
/// ([`NdnEngine::request_enrollment`](crate::NdnEngine::request_enrollment),
/// [`NdnEngine::poll_enrollment`](crate::NdnEngine::poll_enrollment)).
#[data]
#[derive(Debug, Clone)]
pub enum NdnApprovalOutcome {
    /// Waiting for an admin: show `request.code`, poll again later.
    /// `detail` is empty, or says why this poll could not reach the CA.
    /// `adopted_context`: the trust context adopted while asking (`None`
    /// when it was held): persist it and adopt it again at launch.
    Pending {
        request: NdnEnrollmentRequest,
        detail: String,
        adopted_context: Option<NdnContext>,
    },
    /// Approved: the certificate is issued, checked and loaded (`sign`
    /// works). Persist `identity.safebag` (sealed with the password the
    /// request was made with) and `identity.issuers`, as after
    /// `enroll_with_invite`.
    Issued {
        request: NdnEnrollmentRequest,
        identity: NdnEnrolledIdentity,
    },
    /// An admin denied the request; the key was deleted. `reason` says why
    /// and what to do.
    Denied {
        request: NdnEnrollmentRequest,
        reason: String,
    },
    /// The request expired undecided or the CA no longer holds it; the key
    /// was deleted. Ask again.
    Expired {
        request: NdnEnrollmentRequest,
        reason: String,
    },
    /// The request cannot finish (its key is gone or unreadable, the CA
    /// refused it, or the issued certificate was refused); `reason` says
    /// why and what to do.
    Failed {
        request: NdnEnrollmentRequest,
        reason: String,
    },
}

/// One request for an admin's approval the operator can approve or deny —
/// as the CA host's management lists it (`NdnDashboard`) and as an admin
/// device fetches it from the namespace's CA
/// ([`NdnEngine::list_pending_approvals`](crate::NdnEngine::list_pending_approvals)).
#[data]
#[derive(Debug, Clone)]
pub struct NdnPendingApproval {
    /// The request id — pass it (or `code`) to `ca_approve` / `ca_deny`,
    /// or `approve_request` / `deny_request`.
    pub request_id: String,
    /// The key to certify, `/<ns>/<role>/<device>/KEY/<id>`.
    pub key_name: String,
    /// The CA the request was made to (the namespace, for a namespace CA).
    pub namespace: String,
    /// The role and device asked for (empty off the role layout).
    pub role: String,
    pub device: String,
    /// The verification code the requesting device shows too (`482 913`).
    pub code: String,
    /// `pending`, `approved` or `denied`.
    pub state: String,
    /// When it was made (Unix seconds); its age is now minus this.
    pub created_secs: u64,
    /// Pending: when it expires undecided; decided: until when it is kept.
    pub expires_secs: u64,
    /// Who decided (empty while pending).
    pub approver: String,
    /// A denial's reason (empty otherwise).
    pub reason: String,
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
///
/// Right after an adoption (`adopt_context`, `adopt_context_link`, an
/// enrollment that adopted) `context_data` and `expected_fingerprint` are
/// set: the engine keeps the context in memory only, so the host persists
/// them and calls `adopt_context(context_data, namespace,
/// expected_fingerprint)` at every launch. `list_contexts` leaves them `None`.
#[data]
#[derive(Debug, Clone)]
pub struct NdnContext {
    pub namespace: String,
    pub version: u64,
    pub anchor_count: u64,
    pub enforces_hierarchy: bool,
    /// The signed context Data wire, as adopted.
    pub context_data: Option<Vec<u8>>,
    /// SHA-256 of the root anchor's public key it was checked against.
    pub expected_fingerprint: Option<Vec<u8>>,
}

impl NdnContext {
    pub(crate) fn from_ctx(c: &ndn_security::SignedTrustContext) -> Self {
        Self {
            namespace: c.namespace().to_string(),
            version: c.version(),
            anchor_count: c.anchors().len() as u64,
            enforces_hierarchy: c.enforces_hierarchy(),
            context_data: None,
            expected_fingerprint: None,
        }
    }

    /// A context just adopted from `data`, checked against `fingerprint`:
    /// carries what the host persists to adopt it again at launch.
    pub(crate) fn adopted(
        c: &ndn_security::SignedTrustContext,
        data: &ndn_packet::Data,
        fingerprint: &[u8; 32],
    ) -> Self {
        Self {
            context_data: Some(data.raw().to_vec()),
            expected_fingerprint: Some(fingerprint.to_vec()),
            ..Self::from_ctx(c)
        }
    }
}

/// What [`NdnEngine::refresh_contexts`](crate::NdnEngine::refresh_contexts)
/// found for one held trust context. `state` is `updated` (a newer version,
/// signed by an anchor of the held one, is now held), `current`,
/// `upstream-older` (what answered serves an older version; nothing
/// changed), `behind` (what answered is older than a version known to
/// exist; refresh again), `source` (this device holds the namespace's root
/// key), `unreachable` (nothing answered; the held version stays) or
/// `failed` (`detail` says why; the held version stays in force) — the
/// `ndn-fwd` daemon's states.
///
/// For `updated`, `context` carries the new signed context and the
/// fingerprint of the root that signed it: persist both in place of the
/// stored ones, and pass them to `adopt_context` at every launch.
#[data]
#[derive(Debug, Clone)]
pub struct NdnContextRefresh {
    pub namespace: String,
    pub state: String,
    /// The version held before the check.
    pub held_version: u64,
    /// The version held now.
    pub version: u64,
    /// Revocation entries (key names) the new version adds.
    pub revoked: Vec<String>,
    pub detail: String,
    pub context: Option<NdnContext>,
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
    /// Adopt a namespace's trust context. With `context_data` (root-signed
    /// Data inline) feed it to `adopt_context(context_data, namespace,
    /// fingerprint)`, which verifies the signature against the pinned anchor
    /// (TOFU) before adopting. Without it (a fingerprint-only link) pass the
    /// scanned URI to `adopt_context_link`, which fetches the context by name.
    Anchor {
        /// The context namespace the envelope pins (NDN URI).
        namespace: String,
        /// SHA-256 of the root anchor's public key (32 bytes) — the TOFU pin;
        /// show it for out-of-band confirmation.
        fingerprint: Vec<u8>,
        /// The context version, when the envelope states it (informational;
        /// the signed Data's name is authoritative).
        version: Option<u64>,
        /// The signed context Data wire, when the link carries it inline.
        context_data: Option<Vec<u8>>,
    },
    /// NDNCERT enrollment invitation — drive token-enroll against `ca_prefix`.
    Invite {
        ca_prefix: String,
        identity_namespace: String,
        token: String,
        ttl_secs: Option<u64>,
        /// SHA-256 of the CA's root anchor public key (32 bytes), pinning the
        /// CA to trust, when the invite carries one.
        anchor_fingerprint: Option<Vec<u8>>,
    },
    /// A signed delegation to import (sponsorship) — verify + use via the
    /// delegated-signing path.
    Delegation {
        signed_delegation: Vec<u8>,
        principal_pubkey: Vec<u8>,
    },
    /// A recovery bundle — feed to `restore_identity`.
    Recovery { bundle: Vec<u8> },
    /// A password-encrypted SafeBag. Without `namespace` it is an identity
    /// key: feed it to `load_identity(safebag, password, key_name)`. With
    /// `namespace` it is a namespace's file recovery kit (its recovery key,
    /// not an identity): `load_identity` refuses it.
    Bag {
        key_name: String,
        safebag: Vec<u8>,
        /// The namespace a recovery kit recovers (NDN URI).
        namespace: Option<String>,
        /// The namespace's expected fingerprint (32 bytes) when the kit was
        /// made, when the kit carries it.
        fingerprint: Option<Vec<u8>>,
    },
    /// An ephemeral scoped capability (pairing). `is_grant` distinguishes a
    /// peer's request (false) from an issued grant (true); `grant` carries the
    /// operator's certificate (signed NDN Data wire) on a grant.
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
    /// Full chain validation with certificate fetching, against the trust
    /// contexts adopted into the engine (`adopt_context`,
    /// `adopt_context_link`). Fails closed: Data from a network face whose
    /// name no adopted context governs is refused `untrusted-root` when it
    /// names a signer.
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
/// `ndn_face_wifi_aware::NanBackend` / `ndn_phy_ble::AdvBackend`); they ride
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

/// When a link to a relay is up — the user's choice per relay, with its
/// battery and data cost: `Always` keeps the link and its keep-alives
/// (reachable at once; the radio wakes for every keep-alive), `OnDemand`
/// links while the app is active or when there is something to send and
/// closes after `idle_secs` without traffic (reachable only while linked,
/// unless the relay holds Interests or wakes the app), `Off` links only
/// when the app asks ([`NdnEngine::connect_link`](crate::NdnEngine::connect_link)).
#[data]
#[derive(Debug, Clone)]
pub enum NdnLinkMode {
    Always,
    OnDemand { idle_secs: u32 },
    Off,
}

/// Where a relay this device uses comes from.
#[data]
#[derive(Debug, Clone)]
pub enum NdnRelaySource {
    /// The user added it ([`NdnEngine::add_relay`](crate::NdnEngine::add_relay)).
    User,
    /// The signed trust context of `namespace` lists it: every member uses
    /// it without configuring anything.
    Namespace { namespace: String },
}

/// A relay the user adds: their own server, a community relay or a hosted
/// service. It is identified by its key, never by an address.
#[data]
#[derive(Debug, Clone)]
pub struct NdnRelay {
    /// How status and errors name it; unique among this device's relays.
    pub label: String,
    /// The expected fingerprint of the relay's key (64 hex digits). Needed
    /// for a relay of another namespace; the link fails unless the relay
    /// presents exactly this key.
    pub key: Option<String>,
    /// The relay's device name (`/<namespace>/<role>/<device>`), for a relay
    /// of a namespace this device holds: it must prove to be that device.
    pub device: Option<String>,
    /// `host:port` endpoints, tried in order.
    pub endpoints: Vec<String>,
    /// Lower is preferred; the most preferred reachable relays are used
    /// (`NdnLinksConfig.relay_count` of them) and the next takes over when
    /// one is lost.
    pub preference: u32,
    pub mode: NdnLinkMode,
    /// Ask the relay to hold Interests for this device while it is not
    /// linked (up to their lifetime), delivered when it links again.
    pub hold: bool,
    /// The prefixes routed over the relay's link; empty = the default (its
    /// namespace, for a relay of this device's namespace; its device name
    /// otherwise). `/` sends everything this device does not reach
    /// otherwise through the relay.
    pub routes: Vec<String>,
}

/// How this device hosts QUIC links
/// ([`NdnEngine::start_links`](crate::NdnEngine::start_links)).
#[data]
#[derive(Debug, Clone)]
pub struct NdnLinksConfig {
    /// A UDP socket the platform made and bound to the network to use
    /// (Android `Network.bindSocket`, iOS a socket on the chosen
    /// interface); the engine takes ownership. `None`: the engine binds
    /// `bind` itself.
    pub socket_fd: Option<i32>,
    /// The address to bind when no `socket_fd` is given (default
    /// `0.0.0.0:0`, a port the system picks).
    pub bind: Option<String>,
    /// Accept links other devices dial to this one. A phone usually dials
    /// only; direct paths of its punches are accepted either way.
    pub listen: bool,
    /// How many relays to keep linked at once (at least 1).
    pub relay_count: u32,
    /// Use the relays the trust contexts of this device's namespaces list.
    pub use_namespace_relays: bool,
    /// The mode of those relays' links.
    pub namespace_relay_mode: NdnLinkMode,
    /// Ask those relays to hold Interests while this device is not linked.
    pub namespace_relay_hold: bool,
    /// The issuer certificates (Data wires, nearest first) of this device's
    /// certificate, as persisted from its enrollment or renewal
    /// (`NdnEnrolledIdentity.issuers`); a link hello carries them.
    pub issuers: Vec<Vec<u8>>,
    /// Seconds between keep-alives on a link (2–60; `None`: 10). Shorter
    /// keeps NAT bindings and a lost link noticed sooner, at the cost of
    /// waking the radio more often.
    pub keep_alive_secs: Option<u32>,
    /// Seconds without anything heard before a link counts as lost (at
    /// least 3 × the keep-alive, at most 600; `None`: 30).
    pub idle_timeout_secs: Option<u32>,
}

/// What reaches a device now.
#[data]
#[derive(Debug, Clone)]
pub struct NdnPathStatus {
    /// `link` (a dialled or accepted link), `direct` (a punched direct
    /// path) or `relay` (through the relay named in `via`).
    pub kind: String,
    /// The address the connection reaches (for a relay path, the relay's).
    pub remote: Option<String>,
    pub rtt_ms: Option<u64>,
    pub age_secs: u64,
    pub via: Option<String>,
}

/// A relay's part in this device's links.
#[data]
#[derive(Debug, Clone)]
pub struct NdnRelayStatus {
    pub source: NdnRelaySource,
    pub preference: u32,
    /// `linked`, `trying`, `down` (not reachable now; `text` says why),
    /// `standby` (more preferred relays are linked; it takes over when one
    /// is lost) or `off`.
    pub state: String,
    /// For a person: why, and what to do if anything.
    pub text: String,
}

/// One device this device links with, is configured to, or punched.
#[data]
#[derive(Debug, Clone)]
pub struct NdnLinkStatus {
    pub label: String,
    /// Its key's fingerprint, once known.
    pub key: Option<String>,
    pub device: Option<String>,
    /// Its link mode; `None` for a device that is not configured (one that
    /// linked to this one, or a direct path by membership).
    pub mode: Option<NdnLinkMode>,
    /// Set for a relay.
    pub relay: Option<NdnRelayStatus>,
    /// The ways it is reached now; empty when it is not.
    pub paths: Vec<NdnPathStatus>,
    /// Why a configured relay or peer is not linked now, and what to do if
    /// anything.
    pub down: Option<String>,
    /// Its direct path: `none`, `off`, `trying`, `up`, `not-possible`,
    /// `refused`.
    pub direct_state: String,
    /// Why, and what to do if anything.
    pub direct_text: String,
    pub direct_retry_secs: Option<u64>,
}

/// This device's links ([`NdnEngine::link_status`](crate::NdnEngine::link_status)).
#[data]
#[derive(Debug, Clone)]
pub struct NdnLinkReport {
    /// The fingerprint of the key this device links with (what another
    /// device names as its expected key); `None` with no usable key.
    pub key: Option<String>,
    /// The address of the link socket.
    pub local_address: Option<String>,
    /// Whether the app last said it is active.
    pub active: bool,
    pub probes_sent: u64,
    pub punches_refused: u64,
    pub links: Vec<NdnLinkStatus>,
}

#[data]
#[derive(Debug, thiserror::Error)]
pub enum NdnError {
    #[error("timeout waiting for data: {name}")]
    Timeout { name: String },
    #[error("interest nacked ({reason}): {name}")]
    Nacked { name: String, reason: String },
    /// This device's forwarder refused the Data that answered the Interest
    /// for `name`: it failed validation. `refusal` is a stable token to match
    /// on — `chain`, `revoked`, `bad-signature`, `schema`, `untrusted-root`,
    /// `context`, `unverifiable`. `final_verdict` is false only for
    /// `unverifiable` (the signing certificate could not be fetched yet): ask
    /// again later; every other refusal gets the same answer if asked again.
    /// `hint` says what to do, in one user-facing line.
    #[error(
        "refused ({refusal}, {}): {name}: {hint}",
        if *.final_verdict { "final" } else { "refused for now" }
    )]
    Refused {
        name: String,
        refusal: String,
        final_verdict: bool,
        hint: String,
    },
    #[error("engine error: {msg}")]
    Engine { msg: String },
    #[error("invalid NDN name: {name}")]
    InvalidName { name: String },
    #[error("invalid address: {addr}")]
    InvalidAddress { addr: String },
    #[error("identity error: {msg}")]
    Identity { msg: String },
    /// An enrollment that produced no certificate. When it adopted the
    /// namespace's trust context on the way, that context stays adopted (it
    /// passed the fingerprint check by itself): persist `adopted_context`
    /// as after `adopt_context`.
    #[error("identity error: {msg}")]
    EnrollmentFailed {
        msg: String,
        adopted_context: Option<NdnContext>,
    },
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
            AppError::Refused { reason } => NdnError::Refused {
                name: name.to_string(),
                refusal: reason.as_str().to_string(),
                final_verdict: reason.is_final(),
                hint: reason.next_step().to_string(),
            },
            AppError::Connection(e) => NdnError::Engine { msg: e.to_string() },
            AppError::Closed => NdnError::Engine {
                msg: "connection closed".into(),
            },
            AppError::Protocol(msg) => NdnError::Engine { msg },
            AppError::Unverified(why) => NdnError::Engine {
                msg: format!("verification failed: {why}"),
            },
            AppError::Unsupported(why) => NdnError::Engine {
                msg: format!("unsupported: {why}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Refusal;

    /// A refusal reaches apps as `NdnError::Refused` with the stable token
    /// (not a Debug string), whether asking again can help, and what to do.
    #[test]
    fn a_refusal_maps_to_its_token_finality_and_next_step() {
        for reason in Refusal::ALL {
            match NdnError::from_app(AppError::Refused { reason }, "/home/bob/doc") {
                NdnError::Refused {
                    name,
                    refusal,
                    final_verdict,
                    hint,
                } => {
                    assert_eq!(name, "/home/bob/doc");
                    assert_eq!(Refusal::from_token(&refusal), Some(reason));
                    assert_eq!(final_verdict, reason != Refusal::Unverifiable, "{refusal}");
                    assert_eq!(hint, reason.next_step());
                }
                other => panic!("{reason}: {other:?}"),
            }
        }
    }
}
