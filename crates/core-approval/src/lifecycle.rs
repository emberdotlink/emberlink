//! crates/core-approval/src/lifecycle.rs

use core_grant_types::{Budget, approval::RequestedScope};
use core_grants::Grant;
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
/// ADR 113 PHASE-C-0-5: amends the `submit_request` signature so production
/// callers in `handler.rs` can migrate without losing the metadata they
/// currently set on the returned request struct (`tool_name`, `target_host`,
/// `target_url`, `agent_framework`).
///
/// Extends the metadata
/// with the five grant-shaping fields (`max_delegation_depth`,
/// `max_uses_per_hour`, `allowed_hours_start`, `allowed_hours_end`,
/// `allowed_targets`) that the `create_grant` socket call previously silently
/// dropped when policy required approval. The same metadata now also carries
/// the operator-requested budget and standing-parent fields so approval-path
/// and auto-approve grants converge on the same post-mint shape.
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
    /// Stamped onto the minted grant row after approval-resolution; sets themax depth
    /// the resulting grant may be re-delegated. `None` means the resolver
    /// defers to the grant default. Stamped on the minted grant row after
    /// approval-resolution so approval-path grants carry the same delegation
    /// cap the auto-approve path would have written via `create_grant`.
    pub max_delegation_depth: Option<u32>,
    /// Stamped onto the minted grant row after approval-resolution; sets therate-limit
    /// hint on the resulting grant. `None` leaves the grant unbounded on this
    /// axis. Re-applied to the minted grant row alongside `max_delegation_depth`.
    pub max_uses_per_hour: Option<u64>,
    /// Stamped onto the minted grant row after approval-resolution; sets thelower hour
    /// bound (UTC, 0..=23) of the allowed-usage window on the resulting grant.
    /// `None` leaves the grant time-unbounded. Companion to
    /// `allowed_hours_end`.
    pub allowed_hours_start: Option<u32>,
    /// Stamped onto the minted grant row after approval-resolution; sets theupper hour
    /// bound (UTC, 0..=23) of the allowed-usage window on the resulting
    /// grant. `None` mirrors `allowed_hours_start`.
    pub allowed_hours_end: Option<u32>,
    /// Stamped onto the minted grant row after approval-resolution; sets theJSON-array
    /// string of allowed-target patterns the broker enforces on each grant
    /// use. `None` means unrestricted targets. Stored as serialised JSON so
    /// the column shape mirrors the auto-approve path's
    /// `grants.allowed_targets` write.
    pub allowed_targets: Option<String>,
    /// Serialized budget to mint into block-zero when the request is
    /// ultimately approved. `None` means unbudgeted.
    pub budget: Option<Budget>,
    /// Daily child-mint ceiling for a standing parent. `None` means the grant
    /// remains a normal one-shot grant.
    pub max_children_per_day: Option<u64>,
    /// Optional auto-delegation scope template paired with
    /// `max_children_per_day` when the created grant is marked standing.
    pub auto_delegate_scope_template: Option<String>,
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
    /// Returns `core_grants::Grant`
    /// (ADR 113 approval → grant boundary; ADR 114 phase C).
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
    /// Returns `core_grants::Grant`
    /// (ADR 113 approval → grant boundary; ADR 114 phase C).
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
