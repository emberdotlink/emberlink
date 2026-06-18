//! CLASSIFICATION: PUBLIC
//!
//! ember-relay — bidirectional UDS<->TCP relay for the yolo VM trust-broker bridge.
//! Two binaries:
//!   - `ember-relay-host` (macOS host): TCP listener -> AF_UNIX dialer (to daemon sock)
//!   - `ember-relay-vm` (Linux VM): AF_UNIX listener -> TCP dialer (to host relay)
//!
//! META-YOLO-RELAY-DAEMONS-SHIPPED-CHECKPOINT
//!
//! ## Topology (canonical wire diagram)
//!
//! ```text
//!   [VM agent] --AF_UNIX--> [ember-relay-vm] --TLS/TCP--> [ember-relay-host] --AF_UNIX--> [emberd]
//! ```
//!
//! The VM-side relay LISTENS on AF_UNIX (where the agent connects) and DIALS
//! TCP+TLS to the host. The host-side relay LISTENS on TCP+TLS and DIALS
//! AF_UNIX to the local emberd socket.
//!
//! Brief discrepancy note: an earlier sketch in the task brief had the host
//! relay listening on AF_UNIX (`daemon-vm-bridge.sock`). That is incorrect —
//! the daemon already owns its own AF_UNIX listener at
//! `~/.ember/run/daemon.sock`; the host relay must DIAL that socket on
//! behalf of remote (VM) callers, not stand up a second one. The brief's
//! re-derivation paragraph corrected itself; the implementation follows the
//! corrected arg shape:
//!   - `ember-relay-host`: `--tcp-listen <addr> --uds-target <daemon-sock> --cert ... --key ... --ca ...`
//!   - `ember-relay-vm`:   `--uds-listen <path> --tcp-target <host:port>  --cert ... --key ... --ca ... --claimed-persona <id>`
//!
//! ## Wire protocol
//!
//! After the mTLS handshake completes the connection is byte-transparent
//! except for a single HELLO frame written by the VM-side relay before any
//! agent bytes flow. The frame schema lives in [`handshake`]; the host-side
//! relay forwards it verbatim (the daemon parses it — that's
//! META-EMBERD-RELAY-PRINCIPAL-OPTIN).
//!
//! ## Security invariants
//!
//! - mTLS is required on the TCP hop. Both sides verify peer certs against a
//!   bundled CA. Anonymous TCP connections are refused at handshake time.
//! - Credential bytes are NEVER logged. Only peer/uid/handshake-result lines.
//! - The AF_UNIX listener on the VM side is created with mode 0660 and (best
//!   effort) group `ember`; permission errors on chown are non-fatal but
//!   warned.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod handshake;
pub mod mtls;

/// Default soft drain timeout on SIGTERM. In-flight connections get this long
/// to finish before the process exits.
pub const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Errors produced by the relay binaries and shared helpers.
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("config: {0}")]
    Config(String),
}

/// Bidirectional byte pump between two async streams.
///
/// Returns when either side closes or errors. Returns the number of bytes
/// copied in each direction.
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (a_to_b, b_to_a) = tokio::io::copy_bidirectional(a, b).await?;
    Ok((a_to_b, b_to_a))
}

/// Write a length-prefixed JSON HELLO frame to a stream and flush.
pub async fn write_hello<W: AsyncWrite + Unpin>(
    w: &mut W,
    hello: &handshake::Hello,
) -> Result<(), RelayError> {
    let bytes = handshake::encode_hello(hello)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON HELLO frame from a stream.
pub async fn read_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<handshake::Hello, RelayError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > handshake::MAX_HELLO_BYTES {
        return Err(RelayError::Handshake(format!(
            "hello frame too large: {len} > {}",
            handshake::MAX_HELLO_BYTES
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    handshake::decode_hello_body(&buf)
}
