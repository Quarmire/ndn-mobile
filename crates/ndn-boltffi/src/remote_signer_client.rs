//! Client side of the RemoteSigner seam: a [`Signer`] that holds no key and
//! signs by round-tripping each request to a served RemoteSigner (the node's
//! identity) over the forwarder connection.
//!
//! This is how a **keyless leaf** (Ripple) signs: its authority is the node's
//! (Anchor's) identity, scoped by the capability the server enforces, and it
//! never holds key material. The produced Data carry the node's KeyLocator (read
//! from the node's certificate), so a peer verifies them against that cert
//! exactly as if the node had signed locally — which, over the seam, it did.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::DemuxConnection;
use ndn_security::custodian::{WireSignRequest, WireSignResponse};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, Name, SignatureType};
use ndn_security::{Signer, TrustError};

type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// How long to wait for the RemoteSigner's reply before failing a signature.
const SIGN_TIMEOUT: Duration = Duration::from_secs(8);

/// A [`Signer`] that signs over the RemoteSigner seam. It reports the signing
/// node's identity metadata (so produced Data carry the node's KeyLocator) but
/// performs no local cryptography — each `sign` is an Interest/Data exchange with
/// the responder served at `prefix`.
pub(crate) struct RemoteSignerClient {
    conn: Arc<DemuxConnection>,
    prefix: Name,
    sig_type: SignatureType,
    key_name: Name,
    cert_name: Option<Name>,
    public_key: Option<Bytes>,
    req_seq: AtomicU64,
}

impl RemoteSignerClient {
    /// Build from the served `prefix` and the signing node's certificate wire.
    /// The KeyLocator metadata (key/cert name, algorithm, public key) is read
    /// from the cert; the cert itself is what a peer pins to verify produced Data.
    pub(crate) fn from_cert(
        conn: Arc<DemuxConnection>,
        prefix: Name,
        cert_wire: &[u8],
    ) -> Result<Self, TrustError> {
        let data = ndn_packet::Data::decode(Bytes::copy_from_slice(cert_wire))
            .map_err(|e| TrustError::KeyStore(format!("remote signer cert decode: {e:?}")))?;
        let cert = ndn_security::Certificate::decode(&data)?;
        let cert_name: Name = (*cert.name).clone();
        let key_name = key_name_from_cert(&cert_name);
        tracing::debug!(
            target: "ndn_boltffi::remote_signer",
            %cert_name, %key_name, sig_type = ?cert.sig_type,
            pubkey_len = cert.public_key.len(),
            "remote signer client built from cert"
        );
        Ok(Self {
            conn,
            prefix,
            sig_type: cert.sig_type,
            key_name,
            cert_name: Some(cert_name),
            public_key: Some(cert.public_key),
            req_seq: AtomicU64::new(1),
        })
    }
}

/// Decode a reply wire as Data, unwrapping an NDNLP fragment if present.
fn decode_reply(reply: Bytes) -> Result<Data, String> {
    let raw = if is_lp_packet(&reply) {
        LpPacket::decode(reply.clone())
            .map_err(|e| format!("lp decode: {e:?}"))?
            .fragment
            .ok_or_else(|| "lp packet had no fragment".to_string())?
    } else {
        reply
    };
    Data::decode(raw).map_err(|e| format!("data decode: {e:?}"))
}

/// `<identity>/KEY/<key-id>` from a full cert name
/// `<identity>/KEY/<key-id>/<issuer>/<version>`; falls back to the whole name.
fn key_name_from_cert(cert_name: &Name) -> Name {
    let comps = cert_name.components();
    if let Some(key_idx) = comps.iter().position(|c| c.value.as_ref() == b"KEY") {
        let end = (key_idx + 2).min(comps.len());
        return Name::from_components(comps[..end].iter().cloned());
    }
    cert_name.clone()
}

impl Signer for RemoteSignerClient {
    fn sig_type(&self) -> SignatureType {
        self.sig_type
    }
    fn key_name(&self) -> &Name {
        &self.key_name
    }
    fn cert_name(&self) -> Option<&Name> {
        self.cert_name.as_ref()
    }
    fn public_key(&self) -> Option<Bytes> {
        self.public_key.clone()
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        let conn = self.conn.clone();
        let prefix = self.prefix.clone();
        let req_id = self.req_seq.fetch_add(1, Ordering::Relaxed);
        let region = Bytes::copy_from_slice(region);
        Box::pin(async move {
            let req = WireSignRequest { req_id, region };
            tracing::debug!(
                target: "ndn_boltffi::remote_signer", %prefix, req_id,
                region_len = req.region.len(),
                region_head = ?&req.region[..req.region.len().min(8)],
                "remote sign requested"
            );
            // The ParametersSha256Digest over (req_id, region) makes each Interest
            // name unique, so distinct requests neither collapse in the PIT nor
            // serve a stale signature from the CS. The responder echoes that name
            // as the Data name, and we fetch by that exact name over the demux so
            // concurrent segment signs never receive each other's signatures (the
            // bare recv FIFO does — the bug this replaces).
            let wire = InterestBuilder::new(prefix)
                .must_be_fresh()
                .lifetime(SIGN_TIMEOUT)
                .app_parameters(req.encode().to_vec())
                .build();
            let expected = Interest::decode(wire.clone())
                .map_err(|e| TrustError::KeyStore(format!("remote signer: own interest: {e:?}")))?
                .name;
            let reply = conn
                .fetch_correlated((*expected).clone(), wire, SIGN_TIMEOUT + Duration::from_secs(1))
                .await
                .map_err(|e| {
                    tracing::warn!(target: "ndn_boltffi::remote_signer", req_id, error = %e, "remote sign: no reply");
                    TrustError::KeyStore(format!("remote signer: no reply: {e}"))
                })?;
            let data = decode_reply(reply).map_err(|e| {
                TrustError::KeyStore(format!("remote signer: undecodable Data: {e}"))
            })?;
            let got_name = (*data.name).clone();
            if got_name != *expected {
                tracing::error!(
                    target: "ndn_boltffi::remote_signer", req_id,
                    expected = %expected, got = %got_name,
                    "remote sign CORRELATION MISMATCH (wrong reply for this request)"
                );
                return Err(TrustError::KeyStore(
                    "remote signer: correlation mismatch".into(),
                ));
            }
            tracing::debug!(
                target: "ndn_boltffi::remote_signer", req_id,
                name = %got_name, "remote sign reply correlated v2"
            );
            let body = data.content().cloned().unwrap_or_default();
            match WireSignResponse::decode(&body) {
                Ok(WireSignResponse::Approved { signature, .. }) => {
                    tracing::debug!(
                        target: "ndn_boltffi::remote_signer", req_id,
                        sig_len = signature.len(),
                        sig_head = ?&signature[..signature.len().min(8)],
                        "remote sign approved"
                    );
                    Ok(signature)
                }
                Ok(WireSignResponse::Denied { .. }) => {
                    tracing::warn!(target: "ndn_boltffi::remote_signer", req_id, "remote sign denied");
                    Err(TrustError::KeyStore("remote signer denied the request".into()))
                }
                Err(e) => Err(TrustError::KeyStore(format!(
                    "remote signer: undecodable reply: {e:?}"
                ))),
            }
        })
    }
}
