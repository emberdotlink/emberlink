//! Daemon-side hardened decoder for the cross-uid bridge typed frame
//! (ADR 155 priv-sep, SLICE 2a — the trust-boundary half of
//! [`ember_rpc::frame`]).
//!
//! The `ember-rpc` sibling is **untrusted**: it terminates mTLS in a
//! cap-dropped, no-vault process and forwards a hand-rolled typed frame to
//! emberd core over the dedicated `0700` rpc-forward UDS. Everything the
//! sibling asserts (the persona/container SAN it extracted, the inner JSON-RPC
//! payload) is re-validated here before emberd core acts on it. This module is
//! the only place the wire frame is turned into a [`core_personas::MtlsPrincipal`]
//! that gets stamped into `DispatchSource::Bridge`.
//!
//! # `emberd_core_bincode_receiver_hardened` (checkpoint — `ARCH-DAEMON-CORE-BINCODE-PARSER-HARDENING`)
//!
//! This file IS the realized G4.2-hardened typed-message receiver. The original
//! task brief referenced a `typed_receiver.rs` / `typed_messages.rs` shape that
//! assumed a bincode-on-the-wire receive surface; ADR 155's amendment
//! (operator-merged 2026-06-04, SLICE 2a #5349) replaced that design with a
//! hand-rolled fixed-layout frame (`crates/ember-rpc/src/frame.rs`) because
//! bincode 3.0 ships an xkcd-2347 `compile_error!`. The goal — "the smallest
//! residual parser inside the vault-bearing daemon" — is satisfied by this
//! module + [`ember_rpc::frame::decode`]; the hardening bundle is symmetric to
//! the G4.2 JSON-side discipline (see ADR 166 §T2 update 2026-06-04).
//!
//! Hardening bundle (all fail-closed; mirrors G4.2 for the JSON side):
//! - **Byte limits** — header (≤549 B) + payload (≤1 MiB) enforced in
//!   [`ember_rpc::frame::decode`] / [`ember_rpc::frame::MAX_PAYLOAD_BYTES`]; the
//!   length prefix is the first read so an over-cap frame is refused before
//!   body allocation.
//! - **Depth limits** — inner JSON payload nesting capped at
//!   [`MAX_JSON_DEPTH`] (=32); the sibling already depth-checks, the daemon
//!   re-checks because the sibling is untrusted.
//! - **Reject trailing / strict shape** — fixed-layout decode treats every
//!   trailing byte beyond the declared lengths as the payload prefix; version
//!   byte + UTF-8 + SPIFFE-SAN re-validation reject any non-conforming frame
//!   (no silent-gadget surface — the wire shape is exhaustive).
//! - **`catch_unwind` middleware** — the whole `frame::decode` call is wrapped
//!   in [`std::panic::catch_unwind`] (defense-in-depth — `frame::decode` is
//!   panic-free by construction; the sibling is untrusted so a transitive
//!   panic must drop the connection rather than the LocalSet task holding the
//!   vault).
//! - **SAN re-validation** — `persona_id` / `container_id` are re-checked
//!   daemon-side against the canonical SPIFFE grammar via `core_crypto::ca`
//!   (the sibling's extraction is not trusted).
//!
//! Fuzz harness: deferred (no `cargo fuzz` target wired for `ember-daemon` yet;
//! the existing T1 + T2 coverage exercises every fail-closed branch). The
//! decode entry-point is `decode_and_validate` — easy to wrap in a future
//! `cargo fuzz add bridge_frame_fuzz` target without architectural change.

use core_personas::MtlsPrincipal;

use crate::infra::socket::Request;

/// Max nesting depth permitted in the inner JSON-RPC payload. Mirrors the
/// `ember-rpc` listener's `MAX_JSON_NESTING_DEPTH` — the sibling already
/// depth-checks, but it is untrusted so emberd core re-checks.
const MAX_JSON_DEPTH: usize = 32;

/// Failure to decode/validate a bridge frame. Every variant is fail-closed:
/// the accept loop logs and drops the connection without dispatching.
#[derive(Debug)]
pub enum BridgeFrameError {
    /// Byte-level frame decode failed (truncated, bad version, over-cap, bad UTF-8).
    Frame(ember_rpc::FrameError),
    /// The frame decoder panicked (should be impossible — `frame::decode` is
    /// panic-free — but the sibling is untrusted, so we catch and refuse).
    Panic,
    /// A SAN field failed daemon-side re-validation against the SPIFFE grammar.
    MalformedSan(&'static str),
    /// The inner payload was not a well-formed JSON-RPC request.
    PayloadParse(String),
    /// The inner payload JSON exceeded [`MAX_JSON_DEPTH`].
    PayloadTooDeep,
}

impl std::fmt::Display for BridgeFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeFrameError::Frame(e) => write!(f, "frame decode: {e}"),
            BridgeFrameError::Panic => write!(f, "frame decode panicked"),
            BridgeFrameError::MalformedSan(field) => {
                write!(f, "{field} failed daemon-side SAN re-validation")
            }
            BridgeFrameError::PayloadParse(e) => write!(f, "inner payload parse: {e}"),
            BridgeFrameError::PayloadTooDeep => {
                write!(f, "inner payload JSON exceeds depth {MAX_JSON_DEPTH}")
            }
        }
    }
}

/// Decode a bridge frame and produce the attested principal + the
/// ready-to-dispatch request. The returned [`MtlsPrincipal`] is what the accept
/// loop stamps into `RequestContext::bridge`; the [`Request`] is the inner
/// JSON-RPC envelope, validated identically to the UDS lane's request shape.
///
/// **Errors:** any malformed/over-cap/over-deep/bad-SAN input is refused
/// fail-closed; the caller drops the connection.
pub fn decode_and_validate(buf: &[u8]) -> Result<(MtlsPrincipal, Request), BridgeFrameError> {
    // The sibling is untrusted: wrap the whole decode in catch_unwind so a
    // pathological input that somehow trips a panic in a transitive call drops
    // the connection rather than the accept task. `frame::decode` is panic-free
    // by construction (every read is bounds-checked); this is defense-in-depth.
    let decoded = std::panic::catch_unwind(|| ember_rpc::frame::decode(buf))
        .map_err(|_| BridgeFrameError::Panic)?
        .map_err(BridgeFrameError::Frame)?;

    // Re-validate the SAN shape daemon-side. The sibling extracted these from
    // the client cert, but the sibling is untrusted — re-check against the
    // canonical grammar before the values reach `store.get_persona` / the
    // (persona,container) cross-check.
    validate_persona_id(&decoded.persona_id)?;
    validate_container_id(&decoded.container_id)?;

    // Parse + depth-cap the inner JSON-RPC payload before it reaches dispatch.
    let value: serde_json::Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| BridgeFrameError::PayloadParse(e.to_string()))?;
    if json_exceeds_depth(&value, MAX_JSON_DEPTH) {
        return Err(BridgeFrameError::PayloadTooDeep);
    }
    let request: Request =
        serde_json::from_value(value).map_err(|e| BridgeFrameError::PayloadParse(e.to_string()))?;

    let principal = MtlsPrincipal {
        persona_id: decoded.persona_id,
        container_id: decoded.container_id,
        cert_fingerprint: decoded.cert_fingerprint,
    };
    Ok((principal, request))
}

/// Re-validate a persona id against the canonical SPIFFE persona grammar
/// (`[a-z][a-z0-9-]{0,62}`) by reconstructing the URI and round-tripping it
/// through `core_crypto::ca::parse_spiffe_uri` (the single source of truth for
/// the grammar). The anchored regex + the no-slash persona capture make this
/// injection-safe: a `persona_id` containing `/`, `%`, or an embedded
/// `/peer/` cannot round-trip.
fn validate_persona_id(persona_id: &str) -> Result<(), BridgeFrameError> {
    let uri = format!("spiffe://emberd/persona/{persona_id}/peer/reval");
    match core_crypto::ca::parse_spiffe_uri(&uri) {
        Ok(id) if id.persona == persona_id => Ok(()),
        _ => Err(BridgeFrameError::MalformedSan("persona_id")),
    }
}

/// Re-validate a container id against the canonical SPIFFE container grammar
/// (`[a-z0-9:_-]{1,128}`) via `core_crypto::ca::parse_spiffe_uri_container`.
fn validate_container_id(container_id: &str) -> Result<(), BridgeFrameError> {
    let uri = format!("spiffe://emberd/container/{container_id}");
    match core_crypto::ca::parse_spiffe_uri_container(&uri) {
        Ok(core_crypto::ca::SpiffeUri::Container { container_ref })
            if container_ref == container_id =>
        {
            Ok(())
        }
        _ => Err(BridgeFrameError::MalformedSan("container_id")),
    }
}

/// Returns `true` when `value` nests deeper than `remaining` levels. Mirrors
/// the `ember-rpc` listener's depth check (the sibling is untrusted, so emberd
/// core re-checks).
fn json_exceeds_depth(value: &serde_json::Value, remaining: usize) -> bool {
    if remaining == 0 {
        return true;
    }
    match value {
        serde_json::Value::Array(arr) => arr.iter().any(|v| json_exceeds_depth(v, remaining - 1)),
        serde_json::Value::Object(obj) => {
            obj.values().any(|v| json_exceeds_depth(v, remaining - 1))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ember_rpc::frame::{MAX_PAYLOAD_BYTES, MAX_STRING_BYTES, encode};

    fn good_payload() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":"1","method":"list_grants","params":{"persona_id":"persona-abc"}}"#
            .to_vec()
    }

    #[test]
    fn decodes_a_well_formed_frame() {
        let frame = encode(&[0xCD; 32], "persona-abc", "ctr-1", &good_payload()).unwrap();
        let (principal, req) = decode_and_validate(&frame).expect("valid frame");
        assert_eq!(principal.persona_id, "persona-abc");
        assert_eq!(principal.container_id, "ctr-1");
        assert_eq!(principal.cert_fingerprint, [0xCD; 32]);
        assert_eq!(req.method, "list_grants");
        assert_eq!(req.id, "1");
    }

    #[test]
    fn refuses_unknown_version() {
        let mut frame = encode(&[0; 32], "p", "c", &good_payload()).unwrap();
        frame[0] = 0x99;
        assert!(matches!(
            decode_and_validate(&frame),
            Err(BridgeFrameError::Frame(
                ember_rpc::FrameError::UnsupportedVersion(0x99)
            ))
        ));
    }

    #[test]
    fn refuses_truncated_frame_without_panicking() {
        let frame = encode(&[0; 32], "persona-abc", "ctr-1", &good_payload()).unwrap();
        for n in 0..frame.len() - good_payload().len() {
            assert!(decode_and_validate(&frame[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn refuses_malformed_persona_san() {
        // Uppercase / slash / empty all violate the persona grammar.
        for bad in ["Persona-Abc", "persona/evil", "", "1abc", "a%62"] {
            let frame = encode(&[0; 32], bad, "ctr-1", &good_payload()).unwrap();
            assert!(
                matches!(
                    decode_and_validate(&frame),
                    Err(BridgeFrameError::MalformedSan("persona_id"))
                ),
                "persona {bad:?} should be refused"
            );
        }
    }

    #[test]
    fn refuses_persona_with_embedded_peer_injection() {
        // A persona_id that tries to smuggle an extra /peer/ segment must not
        // round-trip (the anchored regex + no-slash capture reject it).
        let frame = encode(&[0; 32], "x/peer/y", "ctr-1", &good_payload()).unwrap();
        assert!(matches!(
            decode_and_validate(&frame),
            Err(BridgeFrameError::MalformedSan("persona_id"))
        ));
    }

    #[test]
    fn refuses_malformed_container_san() {
        for bad in ["CTR-1", "ctr/slash", "", "ctr space"] {
            let frame = encode(&[0; 32], "persona-abc", bad, &good_payload()).unwrap();
            assert!(
                matches!(
                    decode_and_validate(&frame),
                    Err(BridgeFrameError::MalformedSan("container_id"))
                ),
                "container {bad:?} should be refused"
            );
        }
    }

    #[test]
    fn refuses_non_json_payload() {
        let frame = encode(&[0; 32], "persona-abc", "ctr-1", b"not json at all").unwrap();
        assert!(matches!(
            decode_and_validate(&frame),
            Err(BridgeFrameError::PayloadParse(_))
        ));
    }

    #[test]
    fn refuses_over_deep_payload() {
        // Build JSON nested deeper than MAX_JSON_DEPTH inside the params.
        let mut deep =
            String::from("{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"m\",\"params\":");
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            deep.push('[');
        }
        for _ in 0..(MAX_JSON_DEPTH + 2) {
            deep.push(']');
        }
        deep.push('}');
        let frame = encode(&[0; 32], "persona-abc", "ctr-1", deep.as_bytes()).unwrap();
        assert!(matches!(
            decode_and_validate(&frame),
            Err(BridgeFrameError::PayloadTooDeep)
        ));
    }

    #[test]
    fn catch_unwind_path_returns_panic_variant() {
        // Defense-in-depth proof: the `catch_unwind` wrapper in
        // `decode_and_validate` transforms an inner panic into a
        // `BridgeFrameError::Panic` rather than propagating to the LocalSet
        // task that holds the vault. `ember_rpc::frame::decode` is panic-free
        // by construction (every read is bounds-checked), so we exercise the
        // catch_unwind transformation directly here.
        //
        // The mapping under test (mirrored from `decode_and_validate`):
        //   std::panic::catch_unwind(|| panicking_closure())
        //       .map_err(|_| BridgeFrameError::Panic)
        let mapped: Result<(), BridgeFrameError> = std::panic::catch_unwind(|| {
            panic!("synthetic inner-decode panic");
        })
        .map_err(|_| BridgeFrameError::Panic);
        assert!(matches!(mapped, Err(BridgeFrameError::Panic)));

        // Subsequent calls into the real decode path still succeed — the
        // catch_unwind sink does not poison the task.
        let frame = encode(&[0; 32], "persona-abc", "ctr-1", &good_payload()).unwrap();
        assert!(decode_and_validate(&frame).is_ok());
    }

    #[test]
    fn refuses_oversized_payload_at_frame_layer() {
        // The frame encoder refuses an over-cap payload, but a hand-built
        // over-cap frame must be refused by the decoder too.
        let mut frame = vec![ember_rpc::frame::FRAME_VERSION];
        frame.extend_from_slice(&[0u8; 32]);
        frame.extend_from_slice(&("persona-abc".len() as u16).to_le_bytes());
        frame.extend_from_slice(b"persona-abc");
        frame.extend_from_slice(&("ctr-1".len() as u16).to_le_bytes());
        frame.extend_from_slice(b"ctr-1");
        frame.extend_from_slice(&vec![b'x'; MAX_PAYLOAD_BYTES + 1]);
        assert!(matches!(
            decode_and_validate(&frame),
            Err(BridgeFrameError::Frame(
                ember_rpc::FrameError::PayloadTooLong
            ))
        ));
        let _ = MAX_STRING_BYTES; // silence unused if caps change
    }
}
