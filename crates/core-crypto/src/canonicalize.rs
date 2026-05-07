//! JCS (RFC 8785) canonicalization for Receipt v2 envelopes.
//!
//! Wraps `serde_jcs` (per `feedback_reuse_over_rebuild`) to provide a
//! single entry point. Receipt v2 hash + signature both consume the
//! output of this function.

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalizeError {
    #[error("JCS serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Canonicalize a `serde_json::Value` per RFC 8785.
///
/// Returns the canonical UTF-8 byte sequence. Object keys are sorted
/// in UTF-16 code-unit order; numbers in I-JSON form; minimal escaping.
///
/// **Pre/post:** identical inputs (regardless of key order) produce
/// byte-identical outputs.
pub fn canonicalize_jcs(value: &Value) -> Result<Vec<u8>, CanonicalizeError> {
    let s = serde_jcs::to_string(value)?;
    Ok(s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_reordered_keys() {
        let a = canonicalize_jcs(&json!({"b":1,"a":2})).unwrap();
        let b = canonicalize_jcs(&json!({"a":2,"b":1})).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn nested_keys_sort() {
        let a = canonicalize_jcs(&json!({"x":{"b":1,"a":2}})).unwrap();
        let b = canonicalize_jcs(&json!({"x":{"a":2,"b":1}})).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn integer_format() {
        let s = canonicalize_jcs(&json!({"n":1})).unwrap();
        let s = String::from_utf8(s).unwrap();
        assert!(s.contains("\"n\":1"));
    }

    #[test]
    fn float_format() {
        let s = canonicalize_jcs(&json!({"n":1.5})).unwrap();
        let s = String::from_utf8(s).unwrap();
        assert!(s.contains("\"n\":1.5"));
    }
}
