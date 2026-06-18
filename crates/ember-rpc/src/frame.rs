//! Hand-rolled, fixed-layout bridge frame codec (ADR 155 priv-sep, SLICE 2a).
//!
//! The cross-uid bridge lane carries the cert-derived caller identity
//! ([`core_personas::MtlsPrincipal`]'s three fields) **out-of-band** from the
//! JSON-RPC payload, so a same-uid client can no longer forge it by injecting a
//! `_mtls_principal` request field (that path was deleted in SLICE 1). The
//! `ember-rpc` sibling — which terminates mTLS and extracts the principal from
//! the client cert SAN — ENCODES this frame and forwards it to emberd core over
//! the dedicated `0700` rpc-forward UDS; emberd core DECODES it (with the
//! hardened, trust-boundary decoder in `ember-daemon`'s `infra::bridge_frame`)
//! and stamps `DispatchSource::Bridge`.
//!
//! # Wire layout (fixed, little-endian, self-describing)
//!
//! ```text
//! ┌─────────┬──────────────────┬───────────┬───────────┬───────────┬───────────┬─────────────┐
//! │ 1 byte  │ 32 bytes         │ 2 bytes   │ N bytes   │ 2 bytes   │ M bytes   │ rest        │
//! │ version │ cert_fingerprint │ u16 plen  │ persona   │ u16 clen  │ container │ payload     │
//! │ = 0x01  │ (SHA-256 of cert)│ (LE)      │ (UTF-8)   │ (LE)      │ (UTF-8)   │ (serde_json)│
//! └─────────┴──────────────────┴───────────┴───────────┴───────────┴───────────┴─────────────┘
//! ```
//!
//! The payload is "the rest of the frame" — there is no payload-length prefix;
//! the daemon reads one frame per connection up to [`MAX_FRAME_BYTES`] (the
//! sibling half-closes the write half after the frame). The inner payload stays
//! `serde_json` (a [`crate::JsonRpcRequest`]); only the REQUEST direction carries
//! this typed header — the response is plain newline-delimited JSON.
//!
//! **Codec choice (operator-locked):** a hand-rolled fixed layout, never
//! `bincode` (bincode 3.0 ships the xkcd-2347 `compile_error!`; the dep was
//! already removed from this crate). The goal is the smallest residual parser
//! that runs *inside* the vault-bearing daemon. The header wire struct is
//! deliberately NOT named `MtlsPrincipal` (the single-definition grep-lint
//! `scripts/lint/check-mtls-principal-singleton.sh` matches `pub struct
//! MtlsPrincipal`); [`core_personas::MtlsPrincipal`] is reconstructed
//! field-by-field on the daemon side and is NOT modified by this codec.

/// Current (and only supported) frame version byte. The daemon-reader and the
/// sibling-encoder are deployed independently; a reader fails closed on any
/// other version (`FrameError::UnsupportedVersion`) so a forward-incompatible
/// sibling cannot have its frame mis-parsed. Bumping this is a coordinated
/// rolling-upgrade event (the version-negotiation contract is formalized in a
/// later sub-slice / the ADR amendment).
pub const FRAME_VERSION: u8 = 0x01;

/// Length of the cert fingerprint field (SHA-256 of the DER client cert).
pub const CERT_FINGERPRINT_LEN: usize = 32;

/// Max bytes for each length-prefixed UTF-8 string (persona_id, container_id).
/// The persona grammar is `[a-z][a-z0-9-]{0,62}` (≤63) and the container
/// grammar is `[a-z0-9:_-]{1,128}` (≤128); 256 is a comfortable ceiling that
/// the `u16` length field can always express.
pub const MAX_STRING_BYTES: usize = 256;

/// Max bytes for the inner JSON-RPC payload. Mirrors the listener's
/// `MAX_FRAME_BYTES` ceiling for a single in-container agent call.
pub const MAX_PAYLOAD_BYTES: usize = 1 << 20; // 1 MiB

/// Hard ceiling on a whole frame the daemon will read off the wire before
/// refusing — header (≤ 1 + 32 + 2 + 256 + 2 + 256 = 549) + payload. Used by
/// the accept loop to bound the read so a malicious sibling cannot OOM emberd.
pub const MAX_FRAME_BYTES: usize =
    1 + CERT_FINGERPRINT_LEN + 2 + MAX_STRING_BYTES + 2 + MAX_STRING_BYTES + MAX_PAYLOAD_BYTES;

/// The decoded parts of a bridge frame. Owned, plain data — the daemon-side
/// `bridge_frame` decoder re-validates the SAN shape and builds an
/// [`core_personas::MtlsPrincipal`] from these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    /// SHA-256 of the DER-encoded client cert the sibling terminated.
    pub cert_fingerprint: [u8; CERT_FINGERPRINT_LEN],
    /// Persona id extracted from the cert's `spiffe://emberd/persona/<id>` SAN.
    pub persona_id: String,
    /// Container id extracted from the cert's `spiffe://emberd/container/<id>` SAN.
    pub container_id: String,
    /// The opaque inner JSON-RPC payload bytes (a serialized [`crate::JsonRpcRequest`]).
    pub payload: Vec<u8>,
}

/// Errors from frame encode/decode. Every decode error is fail-closed — the
/// daemon refuses the frame and drops the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Frame ended before a required field could be read.
    TooShort,
    /// Version byte was not [`FRAME_VERSION`].
    UnsupportedVersion(u8),
    /// A length-prefixed string exceeded [`MAX_STRING_BYTES`].
    StringTooLong,
    /// The payload exceeded [`MAX_PAYLOAD_BYTES`].
    PayloadTooLong,
    /// A length-prefixed string was not valid UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort => write!(f, "bridge frame truncated"),
            FrameError::UnsupportedVersion(v) => {
                write!(f, "unsupported bridge frame version {v:#x}")
            }
            FrameError::StringTooLong => {
                write!(f, "bridge frame string exceeds {MAX_STRING_BYTES} bytes")
            }
            FrameError::PayloadTooLong => {
                write!(f, "bridge frame payload exceeds {MAX_PAYLOAD_BYTES} bytes")
            }
            FrameError::InvalidUtf8 => write!(f, "bridge frame string is not valid UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode a bridge frame (sibling side). Validates the string and payload
/// caps up front so the daemon never receives an over-cap frame from a
/// well-behaved sibling.
///
/// **Pre:** `persona_id.len() <= MAX_STRING_BYTES`, `container_id.len() <=
/// MAX_STRING_BYTES`, `payload.len() <= MAX_PAYLOAD_BYTES`.
/// **Errors:** `StringTooLong` / `PayloadTooLong` if a cap is exceeded.
pub fn encode(
    cert_fingerprint: &[u8; CERT_FINGERPRINT_LEN],
    persona_id: &str,
    container_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    if persona_id.len() > MAX_STRING_BYTES || container_id.len() > MAX_STRING_BYTES {
        return Err(FrameError::StringTooLong);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(FrameError::PayloadTooLong);
    }
    let mut out = Vec::with_capacity(
        1 + CERT_FINGERPRINT_LEN + 2 + persona_id.len() + 2 + container_id.len() + payload.len(),
    );
    out.push(FRAME_VERSION);
    out.extend_from_slice(cert_fingerprint);
    // `as u16` is lossless: both strings are bounded by MAX_STRING_BYTES (256) above.
    out.extend_from_slice(&(persona_id.len() as u16).to_le_bytes());
    out.extend_from_slice(persona_id.as_bytes());
    out.extend_from_slice(&(container_id.len() as u16).to_le_bytes());
    out.extend_from_slice(container_id.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode a bridge frame (the byte-level half; the daemon's `bridge_frame`
/// wraps this with SAN re-validation, JSON depth-capping, and `catch_unwind`).
///
/// Panic-free by construction: every read is bounds-checked via slice `get`,
/// never indexed; UTF-8 is validated (`std::str::from_utf8`), never assumed.
///
/// **Errors:** `TooShort` (truncated), `UnsupportedVersion`, `StringTooLong`,
/// `PayloadTooLong`, `InvalidUtf8`.
pub fn decode(buf: &[u8]) -> Result<DecodedFrame, FrameError> {
    let mut cur = 0usize;

    let version = *buf.get(cur).ok_or(FrameError::TooShort)?;
    cur += 1;
    if version != FRAME_VERSION {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let fp_slice = buf
        .get(cur..cur + CERT_FINGERPRINT_LEN)
        .ok_or(FrameError::TooShort)?;
    let mut cert_fingerprint = [0u8; CERT_FINGERPRINT_LEN];
    cert_fingerprint.copy_from_slice(fp_slice);
    cur += CERT_FINGERPRINT_LEN;

    let persona_id = read_lp_string(buf, &mut cur)?;
    let container_id = read_lp_string(buf, &mut cur)?;

    let payload = buf.get(cur..).ok_or(FrameError::TooShort)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(FrameError::PayloadTooLong);
    }

    Ok(DecodedFrame {
        cert_fingerprint,
        persona_id,
        container_id,
        payload: payload.to_vec(),
    })
}

/// Read a `u16-LE length + UTF-8 bytes` string, advancing `cur`. Bounds- and
/// length-checked; rejects strings over [`MAX_STRING_BYTES`] BEFORE allocating.
fn read_lp_string(buf: &[u8], cur: &mut usize) -> Result<String, FrameError> {
    let len_bytes = buf.get(*cur..*cur + 2).ok_or(FrameError::TooShort)?;
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    *cur += 2;
    if len > MAX_STRING_BYTES {
        return Err(FrameError::StringTooLong);
    }
    let s_bytes = buf.get(*cur..*cur + len).ok_or(FrameError::TooShort)?;
    *cur += len;
    let s = std::str::from_utf8(s_bytes).map_err(|_| FrameError::InvalidUtf8)?;
    Ok(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let payload = br#"{"jsonrpc":"2.0","method":"list_grants","params":{}}"#;
        let frame = encode(&fp(0xAB), "persona-x", "ctr-y", payload).unwrap();
        let decoded = decode(&frame).unwrap();
        assert_eq!(decoded.cert_fingerprint, fp(0xAB));
        assert_eq!(decoded.persona_id, "persona-x");
        assert_eq!(decoded.container_id, "ctr-y");
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn round_trip_empty_payload_and_strings_with_bytes() {
        // container_id at the max length round-trips.
        let big = "a".repeat(MAX_STRING_BYTES);
        let frame = encode(&fp(1), "p", &big, b"").unwrap();
        let decoded = decode(&frame).unwrap();
        assert_eq!(decoded.container_id, big);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn encode_rejects_oversized_string() {
        let too_long = "a".repeat(MAX_STRING_BYTES + 1);
        assert_eq!(
            encode(&fp(0), &too_long, "c", b""),
            Err(FrameError::StringTooLong)
        );
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            encode(&fp(0), "p", "c", &payload),
            Err(FrameError::PayloadTooLong)
        );
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut frame = encode(&fp(0), "p", "c", b"x").unwrap();
        frame[0] = 0x02;
        assert_eq!(decode(&frame), Err(FrameError::UnsupportedVersion(0x02)));
    }

    #[test]
    fn decode_rejects_empty_and_truncated() {
        assert_eq!(decode(&[]), Err(FrameError::TooShort));
        let frame = encode(&fp(0), "persona", "container", b"payload").unwrap();
        // Truncate at every length from 1..header to prove no panic + fail-closed.
        for n in 1..frame.len() - 7 {
            assert_eq!(decode(&frame[..n]), Err(FrameError::TooShort), "len {n}");
        }
    }

    #[test]
    fn decode_rejects_oversized_string_length_field() {
        // Hand-craft a frame whose persona length field claims > MAX_STRING_BYTES.
        let mut frame = vec![FRAME_VERSION];
        frame.extend_from_slice(&fp(0));
        frame.extend_from_slice(&((MAX_STRING_BYTES as u16) + 1).to_le_bytes());
        frame.extend_from_slice(&[b'a'; 8]); // some bytes, fewer than claimed
        assert_eq!(decode(&frame), Err(FrameError::StringTooLong));
    }

    #[test]
    fn decode_rejects_non_utf8_string() {
        let mut frame = vec![FRAME_VERSION];
        frame.extend_from_slice(&fp(0));
        frame.extend_from_slice(&3u16.to_le_bytes());
        frame.extend_from_slice(&[0xff, 0xfe, 0xfd]); // invalid UTF-8
        assert_eq!(decode(&frame), Err(FrameError::InvalidUtf8));
    }

    #[test]
    fn decode_rejects_oversized_payload() {
        // A frame whose trailing payload exceeds the cap is refused.
        let mut frame = vec![FRAME_VERSION];
        frame.extend_from_slice(&fp(0));
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.push(b'p');
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.push(b'c');
        frame.extend_from_slice(&vec![0u8; MAX_PAYLOAD_BYTES + 1]);
        assert_eq!(decode(&frame), Err(FrameError::PayloadTooLong));
    }
}
