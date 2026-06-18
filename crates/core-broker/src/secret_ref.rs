//! Opaque SecretRef contract for ember-broker.
//!
//! Agent processes hold a `SecretRef` (an opaque ID) and present it to
//! ember-proxy / ember-tools when the actual credential is needed at a
//! trust boundary. Plaintext never returns to the agent process.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Opaque reference to a broker-issued credential.
///
/// The wrapped string is the broker grant ID (UUID-shaped). Treat it as
/// opaque — don't parse it, don't log it, don't string-compare across
/// brokers. Pass it to ember-proxy / ember-tools and let those resolve.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display abbreviates so logs don't grow unbounded; full form is
        // available via .as_str() when actually resolving.
        if self.0.len() > 12 {
            write!(f, "secref:{}…", &self.0[..8])
        } else {
            write!(f, "secref:{}", self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn round_trips_through_serde() {
        let r = SecretRef::new("01234567-89ab-cdef-0123-456789abcdef");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"01234567-89ab-cdef-0123-456789abcdef\"");
        let r2: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn display_abbreviates_long_ids() {
        let r = SecretRef::new("01234567-89ab-cdef-0123-456789abcdef");
        let s = format!("{r}");
        assert_eq!(s, "secref:01234567…");
    }

    #[test]
    fn display_doesnt_truncate_short_ids() {
        let r = SecretRef::new("ab12");
        assert_eq!(format!("{r}"), "secref:ab12");
    }
}
