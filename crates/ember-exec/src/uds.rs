//! CLASSIFICATION: PUBLIC
//!
//! UDS frame protocol for `ember-exec` (SCION-EMBER-EXEC-A-BIN-UDS).
//!
//! Wire format: length-prefixed JSON frames. Each frame is a `u32` big-endian
//! byte length followed by `length` bytes of UTF-8 JSON. The JSON deserialises
//! into an [`ExecFrame`] enum with a `type` discriminant per `serde(tag)`.
//!
//! The hash-verify, setuid-drop, and spawn-integration layers (subtasks B and
//! C of the SCION-EMBER-EXEC-AS-SERVICE decomposition) consume these frames
//! but do not modify the protocol — the protocol stays stable across the
//! three-step rollout.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum allowed frame payload size in bytes. Defends against a malicious
/// or buggy peer that sends a giant length prefix.
pub const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// A `SpawnDirective` instructs `ember-exec` to verify, privilege-drop, and
/// exec a target binary. Sent once at the start of a connection. The hash
/// verification and privilege drop are subtask B's responsibility; this
/// module owns only the wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnDirective {
    pub binary_path: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default)]
    pub credential_env: Vec<(String, String)>,
    pub target_uid: u32,
    pub target_gid: u32,
    pub content_hash_expected: String,
}

/// `ExecFrame` is the union of every wire message `ember-exec` accepts or
/// emits. The `serde(tag = "type")` representation keeps the JSON shape
/// self-describing for offline analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecFrame {
    /// Initial direct from peer: verify, drop privilege, exec.
    SpawnDirective(SpawnDirective),
    /// Bytes destined for the spawned child's stdin (via the pty master).
    StdinBytes { bytes: Vec<u8> },
    /// Terminal window resize event.
    Resize { rows: u16, cols: u16 },
    /// Unix signal to deliver to the child process.
    Signal { signal: i32 },
    /// Bytes from the child's stdout/stderr (via the pty master).
    OutputBytes { bytes: Vec<u8> },
    /// Final exit status of the spawned child.
    Exit { code: i32 },
    /// Content-hash check failed; child never spawned. Closes the connection.
    HashMismatch { expected: String, actual: String },
}

/// Frame-level wire errors. Distinguished from spawn-side errors so a peer
/// can decide to reconnect (transient) vs abort (oversized / bad JSON).
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("frame length {0} exceeds MAX_FRAME_BYTES ({MAX_FRAME_BYTES})")]
    LengthExceeded(u32),
    #[error("frame payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("frame payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Read one frame from the stream. Returns `Ok(None)` on clean EOF (no bytes
/// read before connection close); `Ok(Some(_))` on a complete frame; `Err`
/// on partial-read, oversized length, or JSON parse failure.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<ExecFrame>, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let length = u32::from_be_bytes(len_buf);
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::LengthExceeded(length));
    }
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    let json = String::from_utf8(payload)?;
    let frame: ExecFrame = serde_json::from_str(&json)?;
    Ok(Some(frame))
}

/// Write one frame to the stream. The length prefix is the byte-length of the
/// UTF-8 JSON encoding of the frame (NOT the char count).
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ExecFrame,
) -> Result<(), FrameError> {
    let json = serde_json::to_vec(frame)?;
    let length = u32::try_from(json.len()).map_err(|_| FrameError::LengthExceeded(u32::MAX))?;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::LengthExceeded(length));
    }
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;

    fn directive() -> SpawnDirective {
        SpawnDirective {
            binary_path: "/bin/echo".to_string(),
            argv: vec!["echo".to_string(), "hi".to_string()],
            env_allowlist: vec!["PATH".to_string()],
            credential_env: vec![("TOKEN".to_string(), "secret".to_string())],
            target_uid: 1000,
            target_gid: 1000,
            content_hash_expected: "deadbeef".to_string(),
        }
    }

    #[tokio::test]
    async fn write_then_read_roundtrips_spawn_directive() {
        let (mut a, mut b) = duplex(64 * 1024);
        let frame = ExecFrame::SpawnDirective(directive());
        write_frame(&mut a, &frame).await.unwrap();
        let read = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(read, frame);
    }

    #[tokio::test]
    async fn write_then_read_roundtrips_all_variants() {
        let cases = vec![
            ExecFrame::StdinBytes {
                bytes: b"hello\n".to_vec(),
            },
            ExecFrame::Resize {
                rows: 42,
                cols: 100,
            },
            ExecFrame::Signal { signal: 15 },
            ExecFrame::OutputBytes {
                bytes: vec![0, 1, 2, 3],
            },
            ExecFrame::Exit { code: 37 },
            ExecFrame::HashMismatch {
                expected: "aa".to_string(),
                actual: "bb".to_string(),
            },
        ];
        for frame in cases {
            let (mut a, mut b) = duplex(64 * 1024);
            write_frame(&mut a, &frame).await.unwrap();
            let read = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(read, frame);
        }
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let empty: Vec<u8> = vec![];
        let mut cursor = Cursor::new(empty);
        let result = read_frame(&mut cursor).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_length() {
        let mut payload = (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
        // No body bytes — the length check fires first.
        payload.extend_from_slice(&[]);
        let mut cursor = Cursor::new(payload);
        let result = read_frame(&mut cursor).await;
        assert!(matches!(result, Err(FrameError::LengthExceeded(_))));
    }
}
