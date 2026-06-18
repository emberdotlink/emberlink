//! CLASSIFICATION: PUBLIC
//!
//! Typed JSON-RPC error taxonomy for daemon handlers (AUDIT-V030-TYPED-RPC-ERROR-TAXONOMY).
//!
//! Today's `Result<Value, (i32, String)>` shape loses semantic class at the
//! wire boundary — clients are forced to string-match for retryable vs
//! authority-denied vs presence-required. This module introduces a typed
//! `RpcError` enum whose `code(&self) -> i32` PRESERVES the existing wire
//! codes EXACTLY (no renumbering in this lane — that is a separate breaking
//! change), so the migration is wire-compatible. A `From<RpcError> for (i32,
//! String)` shim lets unmigrated handler arms keep compiling without touching
//! them in this PR.
//!
//! Wire-code inventory (from `crates/ember-daemon/src/infra/handler*.rs`):
//!
//! | Code     | Semantic class                                   | Variant                              |
//! |----------|--------------------------------------------------|--------------------------------------|
//! | -32000   | Internal / unclassified server error             | `Internal(String)`                   |
//! | -32001   | Authority class not met (presence-class gate)    | `AuthorityClassNotMet`               |
//! | -32002   | Caller does not own the referenced grant         | `GrantOwnershipMismatch(String)`     |
//! | -32003   | Policy denied                                    | `PolicyDenied(String)`               |
//! | -32004   | Not found (grant / receipt / approval / event)   | `NotFound(String)`                   |
//! | -32005   | Conflict / invalid-state (one-shot, name in use) | `Conflict(String)`                   |
//! | -32006   | Statement revoked (per-statement isolation)      | `StatementRevoked`                   |
//! | -32007   | Credential not bound to grant statement          | `CredentialNotBound(String)`         |
//! | -32020   | Execution-domain pool exhausted (retryable)      | `PoolExhausted { retry_after_ms }`   |
//! | -32029   | Operation temporarily unavailable (retryable)    | `Retryable { message }`              |
//! | -32030   | Presence gate locked / vault sealed              | `PresenceLocked(String)`             |
//! | -32031   | Sandbox spawn requires bridge CA (vault sealed)  | `BridgeCaUnavailable(String)`        |
//! | -32032   | Last-presence-device revoke guard refusal        | `LastPresenceDeviceGuard(String)`    |
//! | -32401   | Operator co-sign / attestation failure           | `OperatorAttestationFailed(String)`  |
//! | -32601   | JSON-RPC method not found                        | `MethodNotFound`                     |
//! | -32602   | Invalid params                                   | `InvalidParams(String)`              |
//! | -32603   | JSON-RPC internal error (audit repair tail)      | `JsonRpcInternal(String)`            |
//!
//! Composes `META-EXEC-DOMAIN-POOL-EXHAUSTED-ERROR` (per ADR 155 Component
//! 10) as the `PoolExhausted` variant carrying the structured
//! `retry_after_ms` hint that the construct-shim's bounded backoff consumes.
//!
//! Anchor: `enum RpcError` appears below. Do not rename.

use std::fmt;

/// Typed JSON-RPC error taxonomy for daemon handlers.
///
/// Every variant maps to an existing `-32xxx` wire code via [`Self::code`].
/// No renumbering happens in this lane — taxonomy first; the wire-code value
/// surface is a separate breaking change.
///
/// New variants MUST pick from the existing inventory above or reserve a new
/// code via an ADR. Do not invent codes ad-hoc.
#[derive(Debug, Clone)]
pub enum RpcError {
    /// -32000 — unclassified server error. The catch-all bucket today's
    /// `.map_err(|e| (-32000, e.to_string()))` shapes lower into. Carries
    /// the upstream error stringified.
    Internal(String),

    /// -32001 — authority-class gate denied (presence-class device required
    /// per ADR 200 / ADR 206). Body deliberately omits the method name so an
    /// attacker probing arms cannot learn the classification table.
    AuthorityClassNotMet,

    /// -32002 — caller does not own the referenced grant (chain attenuation
    /// / persona binding violation). Carries the upstream message; the
    /// caller persona is logged on the daemon side, not echoed.
    GrantOwnershipMismatch(String),

    /// -32003 — policy denied. Carries the matched-rule label so the caller
    /// surface (CLI / dashboard) can render an actionable explanation.
    PolicyDenied(String),

    /// -32004 — referenced grant / receipt / approval / audit event was not
    /// found. Distinguished from -32005 (state conflict) at the wire so
    /// clients can decide whether to retry-with-fresh-id vs hard-fail.
    NotFound(String),

    /// -32005 — invalid-state conflict (one-shot grant re-use, name already
    /// in use, persona slot poisoned). Surfaces actionable signal that the
    /// resource exists but is in the wrong state for the requested verb.
    Conflict(String),

    /// -32006 — composite-statement revocation. The grant remains live but
    /// the specific statement authorizing this credential read has been
    /// revoked (per-statement isolation per DEMO-MAY3-COMPOSITE-PER-STMT-REVOKE).
    StatementRevoked,

    /// -32007 — caller asked for a credential by name that isn't bound to
    /// any statement on the grant chain (composite multi-cred shape).
    CredentialNotBound(String),

    /// -32020 — execution-domain pool exhausted (composes
    /// META-EXEC-DOMAIN-POOL-EXHAUSTED-ERROR per ADR 155 Component 10).
    /// Carries `retry_after_ms` so the construct-shim's bounded backoff
    /// (3 attempts at 100ms / 300ms / 1s) consumes a structured hint
    /// rather than a guess.
    PoolExhausted { retry_after_ms: u64 },

    /// -32029 — operation is temporarily unavailable but the same call may
    /// succeed shortly. Distinct from -32020 (`PoolExhausted`) because this
    /// variant carries no structured backoff hint — it's the catch-all
    /// "transient state, just try again" shape that handler arms emit when
    /// they observe a race-prone in-flight transition (e.g., session
    /// attachment still rebinding). Distinct from -32030 (`PresenceLocked`)
    /// because no operator action is required to unblock — only time.
    Retryable { message: String },

    /// -32030 — presence gate locked (vault sealed, lease expired, quiet
    /// hours, locked session). Distinct from -32001 because -32001 is "you
    /// will never have authority for this op from this device class", while
    /// -32030 is "re-authenticate / unlock and retry".
    PresenceLocked(String),

    /// -32031 — sandbox spawn requires the bridge CA but the vault is
    /// sealed (ADR 216). A specialized presence-locked shape that the
    /// sandbox subsystem surfaces so operators see actionable wording.
    BridgeCaUnavailable(String),

    /// -32032 — `identity.device.revoke` refused because the targeted Device
    /// is the lone Active `presence`-class Device under the operator root
    /// (the structural last-presence-device guard, ADR 200 §5). Split out of
    /// -32030 so the CLI can render the typed "enroll a replacement Device
    /// first via `ember device enroll --backup`" affordance instead of the
    /// generic presence-locked help (META-V030-DEVICE-REVOKE-ERROR-CODE-
    /// SUBSPACE, F9.2 LOW on PR #5898). Other revoke refusals (unknown
    /// device id, already-revoked, signer-not-an-active-presence) stay on
    /// -32030.
    ///
    /// Anchor: `device_revoke_last_device_distinct_error_code_landed`.
    LastPresenceDeviceGuard(String),

    /// -32401 — operator co-signature / attestation did not verify against
    /// the enrolled presence-class Device under the operator root (ADR 200
    /// §6). HTTP-401-shaped because the failure semantic is "authentication
    /// proof did not check out", not "policy denied".
    OperatorAttestationFailed(String),

    /// -32601 — JSON-RPC method not found (the dispatcher fall-through arm).
    MethodNotFound,

    /// -32602 — JSON-RPC invalid params (missing required field, type
    /// mismatch, malformed sub-object). The single largest bucket in the
    /// inventory — every `params["x"].as_str().ok_or(...)` lowers here.
    InvalidParams(String),

    /// -32603 — JSON-RPC internal error. Distinguished from
    /// [`Self::Internal`] (-32000) because -32603 is the standard JSON-RPC
    /// "internal error" code, used by the audit-repair handler for the
    /// catch-all RepairError variants that don't map onto a more specific
    /// class.
    JsonRpcInternal(String),
}

impl RpcError {
    /// Stable wire code for the variant. PRESERVES today's `-32xxx` values
    /// EXACTLY — no renumbering. Adding a new variant means picking from
    /// the inventory table in this module's doc-comment or reserving a new
    /// code via an ADR.
    pub fn code(&self) -> i32 {
        match self {
            RpcError::Internal(_) => -32000,
            RpcError::AuthorityClassNotMet => -32001,
            RpcError::GrantOwnershipMismatch(_) => -32002,
            RpcError::PolicyDenied(_) => -32003,
            RpcError::NotFound(_) => -32004,
            RpcError::Conflict(_) => -32005,
            RpcError::StatementRevoked => -32006,
            RpcError::CredentialNotBound(_) => -32007,
            RpcError::PoolExhausted { .. } => -32020,
            RpcError::Retryable { .. } => -32029,
            RpcError::PresenceLocked(_) => -32030,
            RpcError::BridgeCaUnavailable(_) => -32031,
            RpcError::LastPresenceDeviceGuard(_) => -32032,
            RpcError::OperatorAttestationFailed(_) => -32401,
            RpcError::MethodNotFound => -32601,
            RpcError::InvalidParams(_) => -32602,
            RpcError::JsonRpcInternal(_) => -32603,
        }
    }

    /// The wire `message` field for the variant. Stable but human-readable;
    /// fixtures should assert against [`Self::code`], not against this
    /// string, because variants with embedded context emit context-sensitive
    /// messages.
    pub fn message(&self) -> String {
        match self {
            RpcError::Internal(msg) => msg.clone(),
            RpcError::AuthorityClassNotMet => "authority_class_not_met".to_string(),
            RpcError::GrantOwnershipMismatch(msg) => msg.clone(),
            RpcError::PolicyDenied(msg) => msg.clone(),
            RpcError::NotFound(msg) => msg.clone(),
            RpcError::Conflict(msg) => msg.clone(),
            RpcError::StatementRevoked => "statement revoked".to_string(),
            RpcError::CredentialNotBound(msg) => msg.clone(),
            RpcError::PoolExhausted { retry_after_ms } => {
                format!("pool_exhausted retry_after_ms={retry_after_ms}")
            }
            RpcError::Retryable { message } => message.clone(),
            RpcError::PresenceLocked(msg) => msg.clone(),
            RpcError::BridgeCaUnavailable(msg) => msg.clone(),
            RpcError::LastPresenceDeviceGuard(msg) => msg.clone(),
            RpcError::OperatorAttestationFailed(msg) => msg.clone(),
            RpcError::MethodNotFound => "Method not found".to_string(),
            RpcError::InvalidParams(msg) => msg.clone(),
            RpcError::JsonRpcInternal(msg) => msg.clone(),
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for RpcError {}

/// Shim into the existing `(i32, String)` wire shape so handler arms that
/// haven't been migrated yet keep compiling. New handler code should prefer
/// returning `RpcError` directly and using `?` against `Result<T, RpcError>`,
/// then converting once at the dispatcher boundary.
impl From<RpcError> for (i32, String) {
    fn from(e: RpcError) -> Self {
        (e.code(), e.message())
    }
}

#[cfg(test)]
mod tests {
    //! T1 — pure, no I/O. Round-trip wire codes and From shim.

    use super::*;

    /// Round-trip: every variant's `code()` matches the documented wire code.
    /// One assertion per variant — adding a new variant FORCES updating this
    /// test, which forces a deliberate decision about wire-code stability.
    #[test]
    fn code_round_trip_preserves_every_wire_code() {
        assert_eq!(RpcError::Internal("x".into()).code(), -32000);
        assert_eq!(RpcError::AuthorityClassNotMet.code(), -32001);
        assert_eq!(RpcError::GrantOwnershipMismatch("x".into()).code(), -32002);
        assert_eq!(RpcError::PolicyDenied("x".into()).code(), -32003);
        assert_eq!(RpcError::NotFound("x".into()).code(), -32004);
        assert_eq!(RpcError::Conflict("x".into()).code(), -32005);
        assert_eq!(RpcError::StatementRevoked.code(), -32006);
        assert_eq!(RpcError::CredentialNotBound("x".into()).code(), -32007);
        assert_eq!(
            RpcError::PoolExhausted {
                retry_after_ms: 100
            }
            .code(),
            -32020
        );
        assert_eq!(
            RpcError::Retryable {
                message: "x".into()
            }
            .code(),
            -32029
        );
        assert_eq!(RpcError::PresenceLocked("x".into()).code(), -32030);
        assert_eq!(RpcError::BridgeCaUnavailable("x".into()).code(), -32031);
        assert_eq!(
            RpcError::LastPresenceDeviceGuard("x".into()).code(),
            -32032
        );
        assert_eq!(
            RpcError::OperatorAttestationFailed("x".into()).code(),
            -32401
        );
        assert_eq!(RpcError::MethodNotFound.code(), -32601);
        assert_eq!(RpcError::InvalidParams("x".into()).code(), -32602);
        assert_eq!(RpcError::JsonRpcInternal("x".into()).code(), -32603);
    }

    /// `From<RpcError> for (i32, String)` produces the expected pair for
    /// every variant — this is the compatibility shim that unmigrated
    /// handler arms rely on.
    #[test]
    fn from_shim_produces_code_message_pair() {
        let cases: Vec<(RpcError, i32, &str)> = vec![
            (RpcError::Internal("boom".into()), -32000, "boom"),
            (
                RpcError::AuthorityClassNotMet,
                -32001,
                "authority_class_not_met",
            ),
            (
                RpcError::GrantOwnershipMismatch("not owner".into()),
                -32002,
                "not owner",
            ),
            (
                RpcError::PolicyDenied("rule: deny-all".into()),
                -32003,
                "rule: deny-all",
            ),
            (
                RpcError::NotFound("grant g1 not found".into()),
                -32004,
                "grant g1 not found",
            ),
            (
                RpcError::Conflict("name in use".into()),
                -32005,
                "name in use",
            ),
            (RpcError::StatementRevoked, -32006, "statement revoked"),
            (
                RpcError::CredentialNotBound("c1 not bound".into()),
                -32007,
                "c1 not bound",
            ),
            (
                RpcError::Retryable {
                    message: "session not yet rebound".into(),
                },
                -32029,
                "session not yet rebound",
            ),
            (RpcError::PresenceLocked("locked".into()), -32030, "locked"),
            (
                RpcError::BridgeCaUnavailable("sealed".into()),
                -32031,
                "sealed",
            ),
            (
                RpcError::LastPresenceDeviceGuard("would brick".into()),
                -32032,
                "would brick",
            ),
            (
                RpcError::OperatorAttestationFailed("bad sig".into()),
                -32401,
                "bad sig",
            ),
            (RpcError::MethodNotFound, -32601, "Method not found"),
            (
                RpcError::InvalidParams("missing 'id'".into()),
                -32602,
                "missing 'id'",
            ),
            (
                RpcError::JsonRpcInternal("repair: x".into()),
                -32603,
                "repair: x",
            ),
        ];
        for (variant, expected_code, expected_msg) in cases {
            let (code, msg): (i32, String) = variant.clone().into();
            assert_eq!(code, expected_code, "code for {variant:?}");
            assert_eq!(msg, expected_msg, "message for {variant:?}");
        }
    }

    /// PoolExhausted carries a structured retry hint — assert the hint
    /// survives into the message shim so the construct-shim's bounded
    /// backoff can parse it. (The structured-data shape — moving the hint
    /// out of the message and into the JSON-RPC `data` field — is a
    /// separate ADR-tracked change; today it lowers into the message
    /// string per the existing wire convention.)
    #[test]
    fn pool_exhausted_carries_retry_hint() {
        let e = RpcError::PoolExhausted {
            retry_after_ms: 1500,
        };
        assert_eq!(e.code(), -32020);
        let (_code, msg): (i32, String) = e.into();
        assert!(
            msg.contains("retry_after_ms=1500"),
            "expected retry_after_ms in message, got: {msg}"
        );
    }

    /// Display formats as `[code] message` for log-friendly output.
    #[test]
    fn display_formats_code_and_message() {
        let e = RpcError::Conflict("name in use".into());
        assert_eq!(format!("{e}"), "[-32005] name in use");
    }

    /// Retryable preserves its `message` text verbatim through the From
    /// shim — the caller-facing wording (e.g.,
    /// "session_attach: attachment 'x' not yet rebound") survives the
    /// lowering into the legacy `(i32, String)` shape that the dispatcher
    /// emits, so existing string-matching clients keep working during the
    /// taxonomy migration.
    #[test]
    fn retryable_round_trips_message_text() {
        let original = "session_attach: attachment 'abc123' not yet rebound";
        let e = RpcError::Retryable {
            message: original.into(),
        };
        let (code, msg): (i32, String) = e.into();
        assert_eq!(code, -32029);
        assert_eq!(msg, original);
    }
}
