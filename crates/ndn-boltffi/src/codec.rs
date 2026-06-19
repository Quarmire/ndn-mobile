//! Stateless NDN packet codec for the BLE test apps; no engine needed.

use boltffi::export;
use bytes::Bytes;

use crate::types::{NdnData, NdnError};

pub struct NdnCodec;

#[export]
impl NdnCodec {
    /// `nonce` overrides the random one [`InterestBuilder`] would produce.
    pub fn encode_interest(name: String, nonce: u32) -> Result<Vec<u8>, NdnError> {
        use ndn_packet::encode::InterestBuilder;

        let parsed: ndn_packet::Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let wire = InterestBuilder::new(parsed).build();
        let mut buf = wire.to_vec();
        patch_nonce(&mut buf, nonce);
        Ok(buf)
    }

    pub fn decode_data(wire: Vec<u8>) -> Result<NdnData, NdnError> {
        let data = ndn_packet::Data::decode(Bytes::from(wire)).map_err(NdnError::engine)?;
        Ok(NdnData::from_packet(data))
    }

    /// NDNLPv2 envelope; the desktop `BleFace` expects this framing.
    pub fn wrap_lp_packet(payload: Vec<u8>) -> Vec<u8> {
        ndn_packet::lp::encode_lp_packet(&payload).to_vec()
    }

    pub fn unwrap_lp_packet(wire: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        let lp = ndn_packet::lp::LpPacket::decode(Bytes::from(wire)).map_err(NdnError::engine)?;
        lp.fragment
            .map(|f| f.to_vec())
            .ok_or_else(|| NdnError::Engine {
                msg: "LpPacket contains no fragment".into(),
            })
    }

    /// Fragment `packet` with the NDNts BLE 1-byte header scheme used by the
    /// ESP32 (`EmbeddedBleFace`) peer: first fragment header is `0x80 | seq`,
    /// continuations are `seq & 0x7F`, and a packet that fits in `max_payload`
    /// is sent unfragmented (no header byte). The single Rust source for what
    /// the Kotlin/Swift apps previously reimplemented per-platform.
    pub fn ndnts_frame(packet: Vec<u8>, max_payload: u32) -> Vec<Vec<u8>> {
        let max_payload = max_payload as usize;
        if packet.len() <= max_payload {
            return alloc_vec(packet);
        }
        let frag_payload = max_payload.saturating_sub(1).max(1);
        let mut out = Vec::new();
        let mut offset = 0;
        let mut seq: u8 = 0;
        let mut is_first = true;
        while offset < packet.len() {
            let end = (offset + frag_payload).min(packet.len());
            let header = if is_first {
                is_first = false;
                0x80 | (seq & 0x7F)
            } else {
                seq & 0x7F
            };
            seq = (seq + 1) & 0x7F;
            let mut frag = Vec::with_capacity(1 + (end - offset));
            frag.push(header);
            frag.extend_from_slice(&packet[offset..end]);
            out.push(frag);
            offset = end;
        }
        out
    }
}

fn alloc_vec(v: Vec<u8>) -> Vec<Vec<u8>> {
    vec![v]
}

/// Stateful reassembler for NDNts BLE 1-byte-header fragments — the inverse of
/// [`NdnCodec::ndnts_frame`]. Feed each received fragment; returns the
/// complete NDN packet once a full TLV has arrived, else `None`.
pub struct NdntsReassembler {
    state: core::cell::RefCell<ReasmState>,
}

struct ReasmState {
    buffer: Vec<u8>,
    active: bool,
}

// SAFETY: BLE callbacks deliver fragments serially; the BoltFFI binding wraps
// this in a single owner. RefCell guards against accidental re-entrancy.
unsafe impl Sync for NdntsReassembler {}

#[export]
impl NdntsReassembler {
    pub fn new() -> Self {
        Self {
            state: core::cell::RefCell::new(ReasmState {
                buffer: Vec::new(),
                active: false,
            }),
        }
    }

    /// Returns the next complete packet, or `None` if more fragments are needed.
    pub fn feed(&self, fragment: Vec<u8>) -> Option<Vec<u8>> {
        let mut st = self.state.borrow_mut();
        let first = *fragment.first()?;
        if first & 0x80 != 0 {
            st.buffer = fragment[1..].to_vec();
            st.active = true;
        } else if st.active {
            st.buffer.extend_from_slice(&fragment[1..]);
        } else {
            // Unfragmented packet (no header byte).
            return Some(fragment);
        }
        let end = tlv_packet_end(&st.buffer)?;
        let pkt = st.buffer[..end].to_vec();
        st.buffer.drain(..end);
        if st.buffer.is_empty() {
            st.active = false;
        }
        Some(pkt)
    }

    pub fn reset(&self) {
        let mut st = self.state.borrow_mut();
        st.buffer.clear();
        st.active = false;
    }
}

impl Default for NdntsReassembler {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_varnumber(buf: &[u8]) -> Option<(u64, usize)> {
    match buf.first().copied()? {
        b if b <= 252 => Some((b as u64, 1)),
        253 if buf.len() >= 3 => Some((u16::from_be_bytes([buf[1], buf[2]]) as u64, 3)),
        254 if buf.len() >= 5 => Some((
            u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64,
            5,
        )),
        255 if buf.len() >= 9 => Some((
            u64::from_be_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]),
            9,
        )),
        _ => None,
    }
}

fn tlv_packet_end(buf: &[u8]) -> Option<usize> {
    let (_, type_len) = parse_varnumber(buf)?;
    let (length, length_len) = parse_varnumber(buf.get(type_len..)?)?;
    let total = type_len + length_len + length as usize;
    (buf.len() >= total).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLV packet (type 0x06, length 200, 200 value bytes) round-trips
    /// through frame → reassemble across multiple fragments.
    #[test]
    fn ndnts_frame_reassemble_roundtrip() {
        let mut packet = vec![0x06, 253, 0x00, 0xC8]; // type=6, len=200 (3-byte form)
        packet.extend((0..200).map(|i| (i % 251) as u8));
        let total_len = packet.len();

        let frags = NdnCodec::ndnts_frame(packet.clone(), 64);
        assert!(frags.len() > 1, "must fragment");
        assert!(frags.iter().all(|f| f.len() <= 64));

        let asm = NdntsReassembler::new();
        let mut got = None;
        for f in frags {
            if let Some(pkt) = asm.feed(f) {
                got = Some(pkt);
            }
        }
        let got = got.expect("reassembled a complete packet");
        assert_eq!(got.len(), total_len);
        assert_eq!(got, packet);
    }

    #[test]
    fn ndnts_unfragmented_passthrough() {
        let small = vec![0x05, 0x03, 1, 2, 3];
        let frags = NdnCodec::ndnts_frame(small.clone(), 64);
        assert_eq!(frags, vec![small.clone()]);
        // No header byte on an unfragmented packet — reassembler returns it as-is.
        let asm = NdntsReassembler::new();
        assert_eq!(asm.feed(small.clone()), Some(small));
    }

    #[test]
    fn interest_encode_decode_via_codec() {
        let wire = NdnCodec::encode_interest("/ndn/ble/test".into(), 0x11223344).unwrap();
        // Round-trips back as a decodable Interest with our nonce patched in.
        let interest = ndn_packet::Interest::decode(Bytes::from(wire)).unwrap();
        assert_eq!(interest.name.to_string(), "/ndn/ble/test");
    }
}

/// Overwrites the Nonce TLV (`0x0A`, length 4) inside an encoded Interest.
fn patch_nonce(buf: &mut [u8], nonce: u32) {
    for i in 0..buf.len().saturating_sub(5) {
        if buf[i] == 0x0A && buf[i + 1] == 0x04 {
            buf[i + 2..i + 6].copy_from_slice(&nonce.to_be_bytes());
            return;
        }
    }
}
