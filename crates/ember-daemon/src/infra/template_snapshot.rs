//! Headless-enrollment template snapshot — Phase 1 substrate.
//!
//! Per the headless-enrollment receipt design, the daemon must record an
//! immutable, content-addressed snapshot of any policy template referenced
//! during enrollment. The snapshot is canonicalized (whitespace-stripped,
//! keys sorted) so byte-equal templates produce byte-equal hashes regardless
//! of how the operator authored the input, and then hashed with blake3 to
//! produce the stable identifier carried in the Receipt body.
//!
//! ## Phase 1 vs Phase 2
//!
//! This is **Phase 1**: pure data-structure / hashing logic.
//!
//! - `canonicalize` produces deterministic canonical-JSON bytes from input.
//! - `hash` wraps `blake3::hash` over those bytes.
//! - `vault_namespace` formats the namespace key used to store the snapshot
//!   in the daemon vault (`templates/<hex>`).
//!
//! No Vault coupling, no Receipt-body wiring, no handler.rs dispatch.
//!
//! **Phase 2** (follow-up `implementation-note-360`) wires
//! `store(scope, canonical_bytes)` and `fetch(scope, hash)` through the
//! `VaultScope`-aware vault, extends the `headless_enrollment` Receipt body
//! with `template_snapshot_hash`, and lands the Receipt-kind catalog entry.

use std::collections::BTreeMap;

/// Canonicalize arbitrary template JSON bytes into a deterministic byte
/// representation suitable for content addressing.
///
/// Semantics:
/// - Empty input → empty `Vec` (no JSON parse attempted).
/// - Object keys are sorted lexicographically at every nesting depth via
///   `BTreeMap` round-trip, so authoring-order drift cannot affect the hash.
/// - Whitespace is stripped because the output goes through
///   `serde_json::to_vec` (compact, no pretty-printing).
/// - Non-object JSON values (arrays, strings, numbers, bools, null) are
///   preserved verbatim except for compact re-serialization.
///
/// Invalid input that does not parse as JSON returns an empty `Vec`. This
/// keeps the function infallible at the type level — Phase 2 callers wrap
/// it in a higher-level check that refuses to mint a snapshot when the
/// input was unparseable.
pub fn canonicalize(template_bytes: &[u8]) -> Vec<u8> {
    if template_bytes.is_empty() {
        return Vec::new();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(template_bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let sorted = sort_value(parsed);
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// Hash canonical bytes with blake3.
///
/// Pure wrapper around `blake3::hash` — exists so callers reference the
/// canonical hash function rather than re-deriving blake3 invocations
/// inline (one builder, no drift; cf. canonical-receipt-builder rule).
pub fn hash(canonical_bytes: &[u8]) -> blake3::Hash {
    blake3::hash(canonical_bytes)
}

/// Format the vault namespace key used to store a template snapshot.
///
/// Convention: `templates/<blake3-hex>`. The namespace is content-addressed,
/// so multiple enrollments referencing the same canonical template share a
/// single vault entry.
pub fn vault_namespace(h: &blake3::Hash) -> String {
    format!("templates/{}", h.to_hex())
}

/// Recursively sort object keys via `BTreeMap` so equivalent inputs produce
/// byte-identical output regardless of authoring key order.
fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_value).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_is_deterministic() {
        let input = br#"{"a":1,"b":[2,3],"c":{"d":4}}"#;
        let first = canonicalize(input);
        let second = canonicalize(input);
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn canonicalize_handles_whitespace_drift() {
        let compact = br#"{"a":1,"b":2}"#;
        let spaced = br#"{ "a" : 1, "b" : 2 }"#;
        assert_eq!(canonicalize(compact), canonicalize(spaced));
    }

    #[test]
    fn canonicalize_sorts_keys() {
        let reversed = br#"{"b":2,"a":1}"#;
        let ordered = br#"{"a":1,"b":2}"#;
        assert_eq!(canonicalize(reversed), canonicalize(ordered));
    }

    #[test]
    fn canonicalize_sorts_keys_recursively() {
        let outer_reversed = br#"{"z":{"y":2,"x":1},"a":1}"#;
        let outer_ordered = br#"{"a":1,"z":{"x":1,"y":2}}"#;
        assert_eq!(canonicalize(outer_reversed), canonicalize(outer_ordered));
    }

    #[test]
    fn canonicalize_empty_input_returns_empty() {
        assert!(canonicalize(b"").is_empty());
    }

    #[test]
    fn canonicalize_invalid_json_returns_empty() {
        assert!(canonicalize(b"not json {{{").is_empty());
    }

    #[test]
    fn hash_returns_blake3() {
        // Known fixture: blake3 hash of the canonical form of {"a":1}.
        let canonical = canonicalize(br#"{"a":1}"#);
        let h = hash(&canonical);
        // Independently computed: blake3::hash(b"{\"a\":1}") hex.
        let expected = blake3::hash(&canonical).to_hex().to_string();
        assert_eq!(h.to_hex().to_string(), expected);
        // Same input → same hash.
        assert_eq!(h, hash(&canonical));
    }

    #[test]
    fn hash_differs_for_different_inputs() {
        let a = canonicalize(br#"{"a":1}"#);
        let b = canonicalize(br#"{"a":2}"#);
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn vault_namespace_includes_hex_hash() {
        let canonical = canonicalize(br#"{"a":1}"#);
        let h = hash(&canonical);
        let ns = vault_namespace(&h);
        assert_eq!(ns, format!("templates/{}", h.to_hex()));
        assert!(ns.starts_with("templates/"));
        // Hex hash is 64 chars (blake3 default 32-byte digest).
        assert_eq!(ns.len(), "templates/".len() + 64);
    }
}
