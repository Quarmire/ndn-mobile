//! NDN face over a Bluetooth byte stream (RFCOMM or L2CAP) using COBS
//! framing, the same codec as
//! [`SerialFace`](ndn_face_native::serial::SerialFace).
//!
//! This type does not open the connection. The caller (JNI / Swift FFI)
//! provides pre-split async halves; LP fragmentation is enabled so NDN
//! packets up to ~8.8 KiB span the small Bluetooth MTU.

use tokio::io::{AsyncRead, AsyncWrite};

use ndn_face_native::serial::cobs::CobsCodec;
use ndn_transport::{FaceId, FaceKind, StreamFace};

pub type BluetoothFace<R, W> = StreamFace<R, W, CobsCodec>;

/// `peer` is a human-readable URI used in logs.
pub fn bluetooth_face_from_parts<R, W>(
    id: FaceId,
    peer: impl Into<String>,
    reader: R,
    writer: W,
) -> BluetoothFace<R, W>
where
    R: AsyncRead + Send + Sync + Unpin,
    W: AsyncWrite + Send + Sync + Unpin,
{
    let uri = peer.into();
    StreamFace::new(
        id,
        FaceKind::Bluetooth,
        Some(uri),
        None,
        reader,
        writer,
        CobsCodec::new(),
    )
}
