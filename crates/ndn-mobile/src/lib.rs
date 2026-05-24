//! In-process NDN forwarder for Android and iOS/iPadOS. Excludes only the
//! sandbox-incompatible faces (raw Ethernet / WFB and POSIX-SHM) so it builds
//! cleanly for `aarch64-linux-android` and `aarch64-apple-ios`. Available
//! faces: in-process app, UDP unicast/multicast, TCP, WebSocket(S), serial,
//! a Unix-socket IPC listener (the cross-process UI seam), and Bluetooth via a
//! platform-supplied stream. Optional NFD-compatible management via the
//! `management` feature.
//!
//! ```no_run
//! use ndn_mobile::{Consumer, MobileEngine};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let (engine, handle) = MobileEngine::builder().build().await?;
//!     let mut consumer = Consumer::from_handle(handle);
//!     let data = consumer.fetch("/ndn/edu/example/data/1").await?;
//!     println!("got {} bytes", data.content().map_or(0, |b| b.len()));
//!     engine.shutdown().await;
//!     Ok(())
//! }
//! ```

#![allow(missing_docs)]

pub mod bluetooth;
pub mod engine;
#[cfg(feature = "enroll")]
pub mod enroll;
#[cfg(feature = "tun")]
pub mod tun;

pub use bluetooth::bluetooth_face_from_parts;
pub use engine::{MobileEngine, MobileEngineBuilder, MobileStrategy, PeerRef};
#[cfg(feature = "enroll")]
pub use enroll::{EnrollConfig, EnrollError, EnrolledIdentity, PinRequest};
#[cfg(feature = "tun")]
pub use tun::{IpFlow, TunConfig, TunHandle, parse_ip_flow, spawn_tunnel};

pub use ndn_app::{AppError, Consumer, Producer};
pub use ndn_discovery::DiscoveryProfile;
pub use ndn_face_native::local::InProcHandle;
pub use ndn_packet::{Data, Interest, Name};
pub use ndn_security::SecurityProfile;
pub use ndn_transport::FaceId;
/// Re-exported for [`MobileEngineBuilder::with_webtransport_peer`].
#[cfg(feature = "webtransport")]
pub use ndn_transport::ClientTls;
/// Re-exported for [`MobileEngineBuilder::with_observability_config`].
#[cfg(feature = "observability")]
pub use ndn_observability::{SpanPublisher, SpanRetention};
pub use tokio_util::sync::CancellationToken;
