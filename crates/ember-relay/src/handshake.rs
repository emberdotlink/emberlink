//! CLASSIFICATION: PUBLIC
//!
//! HELLO frame schema for the relay bridge.
//!
//! Wire format: 4-byte little-endian unsigned length prefix, followed by a
//! JSON-encoded [`Hello`] body. Maximum body size is [`MAX_HELLO_BYTES`]
//! (1 KiB); anything larger is rejected as malformed.
//!
//! The frame is written ONCE by the VM-side relay immediately after the TLS
//! handshake completes, before any agent bytes flow. The host-side relay
//! forwards it verbatim to the daemon (which interprets the
//! `claimed_persona` field per META-EMBERD-RELAY-PRINCIPAL-OPTIN).
//!
//! `relay_protocol_version` is bumped whenever the frame schema changes in a
//! way the daemon must observe.

use serde::{Deserialize, Serialize};

use crate::RelayError;

/// Maximum permitted size of the HELLO body in bytes (not including the
/// 4-byte length prefix). Frames larger than this are rejected at parse
/// time — the schema is a fixed, small record so an oversize frame implies
/// either corruption or an attacker probing for resource exhaustion.
pub const MAX_HELLO_BYTES: usize = 1024;

/// Current relay protocol version. Bump whenever the [`Hello`] schema
/// changes in a backwards-incompatible way.
pub const PROTOCOL_VERSION: u32 = 1;

/// HELLO frame body. Composed by `ember-relay-vm` and forwarded by
/// `ember-relay-host` to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Persona id the VM-side caller claims to be acting on behalf of. The
    /// daemon enforces grants — the field is a *claim*, not authority.
    pub claimed_persona: String,
    /// Wire-format version. Receivers MAY reject unknown versions.
    pub relay_protocol_version: u32,
}

impl Hello {
    /// Construct a HELLO with the current [`PROTOCOL_VERSION`].
    pub fn new(claimed_persona: impl Into<String>) -> Self {
        Hello {
            claimed_persona: claimed_persona.into(),
            relay_protocol_version: PROTOCOL_VERSION,
        }
    }
}

/// Encode a HELLO with the 4-byte LE length prefix.
pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>, RelayError> {
    let body = serde_json::to_vec(hello)
        .map_err(|e| RelayError::Handshake(format!("encode hello: {e}")))?;
    if body.len() > MAX_HELLO_BYTES {
        return Err(RelayError::Handshake(format!(
            "hello body too large: {} > {MAX_HELLO_BYTES}",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a HELLO body (without the length prefix — the caller is expected
/// to have already read the 4-byte length and a buffer of that exact size).
pub fn decode_hello_body(body: &[u8]) -> Result<Hello, RelayError> {
    serde_json::from_slice(body).map_err(|e| RelayError::Handshake(format!("decode hello: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = Hello::new("user-alpha");
        let bytes = encode_hello(&h).expect("encode");
        // Length prefix is correct.
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, bytes.len() - 4);
        let decoded = decode_hello_body(&bytes[4..]).expect("decode");
        assert_eq!(decoded, h);
        assert_eq!(decoded.relay_protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn rejects_oversize_persona() {
        let h = Hello::new("x".repeat(2048));
        let err = encode_hello(&h).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("too large"), "got {msg}");
    }
}
