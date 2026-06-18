//! Typed admission token. Constructible only via the admission gate.
//!
//! Handlers take `AdmittedRequest` (not raw payload bytes) so a
//! forgotten gate call is a compile error: there is no public
//! constructor — only `admission::gate(...)` can build one.
//!
//! Today the relay enforces admission inline at the dispatch site
//! (`offer_admission_ok(...)` checks repeated in front of every
//! offer/credential/grant handler in `dispatch_command`). DRY-8 moves
//! that to a typed token: the gate runs once, produces an
//! `AdmittedRequest`, and any handler that wants to act on the
//! gated path takes that token by value. Skipping the gate stops
//! compiling.
//!
//! NOTE: chrono / thiserror / serde are intentionally NOT pulled in.
//! The relay crate already uses `u64` epoch seconds (`now_epoch_secs()`)
//! everywhere; matching that keeps the dep graph small and the
//! token's meaning consistent with surrounding code.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Admission token. Produced by `admission::gate(...)` after auth +
/// persona + rate-limit checks pass. Fields are pub-read but the type
/// has no public constructor — only the gate can build one (the inner
/// `Seal` is private to this module, so external callers cannot use a
/// struct-literal even though every other field is pub).
#[derive(Debug, Clone)]
pub struct AdmittedRequest {
    pub persona_id: String,
    pub scope: String,
    /// Epoch seconds at admission time. Matches the rest of the relay
    /// (`now_epoch_secs()` is the project-wide convention) instead of
    /// pulling in chrono.
    pub admitted_at: u64,
    /// Defeats struct-literal construction from outside the module —
    /// keeps the type constructable only via the private `new` ctor.
    _seal: Seal,
}

#[derive(Debug, Clone)]
struct Seal;

impl AdmittedRequest {
    /// Internal-only constructor. Only `admission::gate(...)` calls this.
    pub(crate) fn new(persona_id: String, scope: String) -> Self {
        Self {
            persona_id,
            scope,
            admitted_at: now_epoch_secs(),
            _seal: Seal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    Unauthorized,
    PersonaForbidden(String),
    RateLimited(String),
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionError::Unauthorized => write!(f, "missing or invalid auth token"),
            AdmissionError::PersonaForbidden(p) => {
                write!(f, "persona '{p}' not found or not allowed")
            }
            AdmissionError::RateLimited(p) => {
                write!(f, "rate limit exceeded for persona '{p}'")
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Admission gate. Single place where admission decisions are made.
/// Returns an `AdmittedRequest` on success — handlers cannot construct
/// one any other way.
///
/// `auth_header` carries the bearer/admin token for the request (when
/// present); `persona_header` carries the requesting persona ID;
/// `requested_scope` carries the scope string the caller asks for.
/// All three are optional at the parser layer because the relay's
/// frame-based wire protocol does not always include them — the gate
/// is responsible for converting absence-of-required-field into the
/// right `AdmissionError`.
pub fn gate(
    auth_header: Option<&str>,
    persona_header: Option<&str>,
    requested_scope: Option<&str>,
) -> Result<AdmittedRequest, AdmissionError> {
    // TODO: real auth verification (today the gate
    // is permissive for the scaffold — it accepts any auth-header value
    // including None, matching the relay's current open-mode behaviour).
    let _ = auth_header;
    let persona = persona_header.ok_or_else(|| AdmissionError::PersonaForbidden(String::new()))?;
    if persona.trim().is_empty() {
        return Err(AdmissionError::PersonaForbidden(persona.to_string()));
    }
    let scope = requested_scope.unwrap_or("default").to_string();
    // TODO: integrate the existing per-target rate-limit
    // table (see `handle_request_grant` — currently caps pending requests
    // per target at 100; the gate should consult the same accounting).
    Ok(AdmittedRequest::new(persona.to_string(), scope))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_admits_with_persona_header() {
        let admitted = gate(Some("Bearer abc"), Some("alice"), Some("read")).unwrap();
        assert_eq!(admitted.persona_id, "alice");
        assert_eq!(admitted.scope, "read");
    }

    #[test]
    fn gate_rejects_without_persona_header() {
        let err = gate(Some("Bearer abc"), None, Some("read")).unwrap_err();
        assert!(matches!(err, AdmissionError::PersonaForbidden(_)));
    }

    #[test]
    fn admitted_request_carries_timestamp() {
        let admitted = gate(None, Some("alice"), None).unwrap();
        let now = now_epoch_secs();
        // Drift should be tiny — the gate just ran.
        let drift = now.saturating_sub(admitted.admitted_at);
        assert!(drift < 5, "admitted_at drift {drift}s too large");
        assert_eq!(admitted.scope, "default");
    }
}
