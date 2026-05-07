//! crates/core-approval/src/lifecycle.rs

use core_grants::Grant;
use core_types::approval::RequestedScope;
use serde::{Deserialize, Serialize};

use crate::outcome::ApprovalOutcome;

/// Opaque newtype identifier for a submitted approval request. Layout-stable
/// (string-backed) so callers can serialise without depending on the
/// implementation crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestId(pub String);

/// Caller-supplied metadata for an approval request. Carries the fields
/// `submit_request` previously dropped on the floor — action verb, TTL, risk
/// level, and tool/agent context. Required by the daemon's existing audit
/// shape (`approval.submitted` events log all of these) and by the dashboard
/// approval card UI.
///
/// design PHASE-C-0-5: amends the `submit_request` signature so production
/// callers in `handler.rs` can migrate without losing the metadata they
/// currently set on the returned request struct (`tool_name`, `target_host`,
/// `target_url`, `agent_framework`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitMetadata {
    /// Logical action verb (e.g. `credential.access`, `tool.invoke`). Used by
    /// the policy engine for rule matching.
    pub action: String,
    /// Optional TTL hint. `None` defers to policy / persona defaults.
    pub ttl_secs: Option<u64>,
    /// Risk classification (`low`, `medium`, `high`). Drives dashboard sort +
    /// auto-approve eligibility.
    pub risk_level: String,
    /// Agent-side tool name that triggered the request (best-effort).
    pub tool_name: Option<String>,
    /// Host portion of the resource the agent intended to reach.
    pub target_host: Option<String>,
    /// Full URL the agent intended to reach (audit trail).
    pub target_url: Option<String>,
    /// Agent framework label (`claude-code`, `aider`, `cursor`, etc.).
    pub agent_framework: Option<String>,
}

/// The lifecycle Interface every approval consumer depends on.
///
/// **Doc-comment pre/post conditions are load-bearing** — the property tests
/// in `crates/core-approval/tests/state_machine.rs` assert each one.
#[async_trait::async_trait]
pub trait ApprovalLifecycle: Send + Sync {
    /// Submit a new approval request.
    ///
    /// **Pre:** `persona` is a known persona ID; `credential` resolves to a
    /// vault entry the persona may *request* (read-policy check is the
    /// caller's responsibility); `scope` is non-empty; the request is not
    /// a duplicate of a `Pending` request from the same persona for the
    /// same credential within the dedup-window (default 5s).
    ///
    /// **Post:** returns a `RequestId` whose corresponding `ApprovalStatus`
    /// is `Pending`. Emits one `approval.submitted` audit event. The
    /// returned `RequestId` is unique forever (UUIDv4-backed).
    ///
    /// **Errors:** `LifecycleError::DuplicateRequest` (idempotency hit),
    /// `LifecycleError::UnknownPersona`, `LifecycleError::InvalidScope`.
    async fn submit_request(
        &self,
        persona: &str,
        credential: &str,
        scope: RequestedScope,
        metadata: SubmitMetadata,
    ) -> Result<RequestId, LifecycleError>;

    /// Decide a pending approval.
    ///
    /// **Pre:** `request_id` exists; its current status is `Pending`; the
    /// caller is authorised to decide for the persona that owns the
    /// request (caller-supplied authority check; trait does not gate).
    ///
    /// **Post:** the request transitions to a terminal status per the table
    /// in §State machine. Returns `Some(grant)` iff `outcome ∈ {Approved,
    /// Narrowed(_), Always(_)}` and a Grant was successfully minted; returns
    /// `None` on `Denied`. Emits exactly one `approval.decided` event. The
    /// state machine guarantees: a request transitions exactly once.
    ///
    /// **Errors:** `LifecycleError::UnknownRequest`, `LifecycleError::Already
    /// Decided`, `LifecycleError::ScopeNotNarrowing` (Narrowed-outcome with
    /// a wider scope than requested), `LifecycleError::GrantMintFailed`.
    ///
    /// implementation-note-3: returns `core_grants::Grant`
    /// (design approval → grant boundary; design phase C).
    async fn decide(
        &self,
        request_id: &RequestId,
        outcome: ApprovalOutcome,
    ) -> Result<Option<Grant>, LifecycleError>;

    /// Apply (or refresh) a standing approval pattern.
    ///
    /// **Pre:** `pattern` is a non-empty `RequestedScope` shape that future
    /// `submit_request` calls can match against; `ttl_seconds > 0`.
    ///
    /// **Post:** returns a freshly-minted Grant whose scope is `pattern`
    /// and whose TTL is `ttl_seconds`. Future `submit_request` calls whose
    /// scope is a subset of `pattern` short-circuit to `Pending →
    /// Approved` (no human prompt) until the Grant expires or is revoked.
    /// Idempotent across identical patterns within the same persona —
    /// re-applying refreshes the TTL rather than minting a new Grant.
    ///
    /// implementation-note-3: returns `core_grants::Grant`
    /// (design approval → grant boundary; design phase C).
    async fn apply_standing(
        &self,
        persona: &str,
        pattern: RequestedScope,
        ttl_seconds: u64,
    ) -> Result<Grant, LifecycleError>;
}

/// Errors the lifecycle surfaces. All variants are deterministic functions
/// of (input, current state). No I/O errors leak to this layer — the
/// adapter wraps them as `LifecycleError::Storage`.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("unknown persona: {0}")]
    UnknownPersona(String),
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    #[error("duplicate request within dedup window")]
    DuplicateRequest,
    #[error("unknown request id")]
    UnknownRequest,
    #[error("request already decided")]
    AlreadyDecided,
    #[error("narrowed scope is not a subset of request")]
    ScopeNotNarrowing,
    #[error("grant mint failed: {0}")]
    GrantMintFailed(String),
    #[error("storage error: {0}")]
    Storage(String),
}
