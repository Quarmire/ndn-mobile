//! Parse the shared `ndn-trust://` onboarding/pairing envelope into a typed
//! value the host routes to the right flow. The wire/text format lives in the
//! `ndn-trust-envelope` crate so the issuer side (CLIs, dashboard) and the
//! mobile consumers share one source of truth.

use boltffi::export;
use bytes::Bytes;
use ndn_trust_envelope::{CapDirection, Capability, TrustEnvelope};

use crate::types::{NdnError, NdnTrustEnvelope};

/// Stateless parser for `ndn-trust://` payloads. No engine needed — a scanned
/// QR / opened deep-link / pasted string is turned into a typed envelope, then
/// the host calls the matching engine method for that variant.
pub struct NdnTrust;

#[export]
impl NdnTrust {
    /// Parse an `ndn-trust://<kind>/<base64url>` URI (also accepts the legacy
    /// `ndn-ctx:1:…` anchor form and the `https://…/t/<kind>#…` universal-link
    /// mirror) into a typed [`NdnTrustEnvelope`]. Errors with
    /// [`NdnError::Engine`] on a malformed or unrecognized payload.
    pub fn parse(uri: String) -> Result<NdnTrustEnvelope, NdnError> {
        let env = TrustEnvelope::from_uri(&uri).map_err(NdnError::engine)?;
        Ok(convert(env))
    }

    /// Build an `ndn-trust://delegation/…` URI a sponsor shows to a device: the
    /// signed delegation ([`NdnEngine::add_device`](crate::NdnEngine::add_device))
    /// plus the sponsor's public key
    /// ([`principal_public_key`](crate::NdnEngine::principal_public_key)) the
    /// device needs to verify it.
    pub fn build_delegation(signed_delegation: Vec<u8>, principal_pubkey: Vec<u8>) -> String {
        TrustEnvelope::Delegation {
            signed_delegation: Bytes::from(signed_delegation),
            principal_pubkey: Bytes::from(principal_pubkey),
        }
        .to_uri()
    }

    /// Build an `ndn-trust://recovery/…` URI carrying a recovery **bundle** (the
    /// public backup from [`NdnEngine::make_recoverable`](crate::NdnEngine::make_recoverable)).
    /// The recovery *seed* is the secret and is never in the envelope.
    pub fn build_recovery(bundle: Vec<u8>) -> String {
        TrustEnvelope::Recovery {
            bundle: Bytes::from(bundle),
        }
        .to_uri()
    }

    /// Build an `ndn-trust://capability/…` URI for pairing. `is_grant=false` is a
    /// peer's *request* (what it wants + a TTL); `is_grant=true` is the operator's
    /// *grant* acknowledgement, with `grant` carrying the operator's public key so
    /// the peer can verify the signatures it later receives.
    pub fn build_capability(
        is_grant: bool,
        namespace: String,
        scope_patterns: Vec<String>,
        ttl_secs: u64,
        nonce: Vec<u8>,
        grant: Option<Vec<u8>>,
    ) -> String {
        TrustEnvelope::Capability(Capability {
            direction: if is_grant { CapDirection::Grant } else { CapDirection::Request },
            namespace,
            scope_patterns,
            ttl_secs,
            nonce: Bytes::from(nonce),
            grant: grant.map(Bytes::from),
        })
        .to_uri()
    }
}

fn convert(e: TrustEnvelope) -> NdnTrustEnvelope {
    match e {
        TrustEnvelope::Anchor {
            version,
            context_content,
        } => NdnTrustEnvelope::Anchor {
            version,
            context_content: context_content.to_vec(),
        },
        TrustEnvelope::Invite {
            ca_prefix,
            identity_namespace,
            token,
            ttl_secs,
        } => NdnTrustEnvelope::Invite {
            ca_prefix,
            identity_namespace,
            token,
            ttl_secs,
        },
        TrustEnvelope::Delegation {
            signed_delegation,
            principal_pubkey,
        } => NdnTrustEnvelope::Delegation {
            signed_delegation: signed_delegation.to_vec(),
            principal_pubkey: principal_pubkey.to_vec(),
        },
        TrustEnvelope::Recovery { bundle } => NdnTrustEnvelope::Recovery {
            bundle: bundle.to_vec(),
        },
        TrustEnvelope::Bag { key_name, safebag } => NdnTrustEnvelope::Bag {
            key_name,
            safebag: safebag.to_vec(),
        },
        TrustEnvelope::Capability(c) => NdnTrustEnvelope::Capability {
            is_grant: matches!(c.direction, CapDirection::Grant),
            namespace: c.namespace,
            scope_patterns: c.scope_patterns,
            ttl_secs: c.ttl_secs,
            nonce: c.nonce.to_vec(),
            grant: c.grant.map(|b| b.to_vec()),
        },
    }
}
