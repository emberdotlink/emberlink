//! Workflow-grant Receipt body extensions — `PregrantPath` enum.
//!
//! Per ADR 158 §Component 5, as amended by ADR 205 §6 (BKR-4c). Every
//! credentialed Receipt (`credential_provisioned`, `credential_revoked`,
//! `broker.execution_domain`, etc.) stamps three fields linking the call back
//! to the authorizing standing grant:
//!
//! - `delegation_id: Option<String>` — the standing grant id that covered the
//!   action's need (historically the sidecar's ULID; field name retained for
//!   Receipt-schema stability).
//! - `delegation_template: Option<String>` — the session's chosen template name.
//! - `pregrant_path: Option<PregrantPath>` — which evaluation lane approved
//!   (or denied) the call.
//!
//! These live as `Option<>` because system-class callers (the daemon's own
//! housekeeping) may emit Receipts without a workflow context — the absent
//! variant is the legitimate signal.
//!
//! `PregrantPath` lives in core-event-types (not core-grants) to break the
//! dependency cycle: `core-events::receipt::body` needs this enum on
//! `ReceiptBody`, but `core-events` cannot depend on `core-grants` (which
//! already depends on `core-event-types`). Hosting the enum here keeps
//! both consumers downstream of a single definition.
//!
//! Anchor: `delegation_receipt_pregrant_path_landed`.
//!
//! Also anchors `pregrant_receipt_correlation_landed` — the canonical
//! `ReceiptBody` schema extension (per ADR 158 §Component 5) is shipped
//! in `core-events::receipt::body::ReceiptBody` (T1 property tests verified);
//! consumers on the broker.resolve hot path stamp the audit-log payload via
//! `ember-daemon::broker::handler::DelegationReceiptContext` (checkpoint
//! `delegation_receipt_body_stamp_landed`).

use serde::{Deserialize, Serialize};

/// Which broker-resolve evaluation lane approved (or denied) a single
/// `broker.resolve` call. The ordering is also the resolution priority —
/// the broker tries `StandingGrant` first, then `PerAction`, then `Jit`, then
/// returns `Deny`. Per ADR 158 §Component 2 + §Component 5, as amended by
/// ADR 205 §6 (BKR-4c: the legacy delegation sidecar lane became the
/// runtime persona's standing grant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PregrantPath {
    /// The session persona's standing grant covered the action's need
    /// (`need ⊆ grant`) — the BKR-4c successor to the per-session
    /// legacy delegation sidecar lane retired by ADR 205 §6.
    StandingGrant,
    /// A standing per-action pre-grant permitted the action.
    PerAction,
    /// JIT path — operator was prompted for Touch ID for this single call.
    Jit,
    /// All paths refused; broker returned a deny error.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_snake_case() {
        let cases = [
            (PregrantPath::StandingGrant, "\"standing_grant\""),
            (PregrantPath::PerAction, "\"per_action\""),
            (PregrantPath::Jit, "\"jit\""),
            (PregrantPath::Deny, "\"deny\""),
        ];
        for (variant, expected) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, expected, "variant {variant:?}");
            let back: PregrantPath = serde_json::from_str(&s).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn rejects_unknown_variant() {
        assert!(serde_json::from_str::<PregrantPath>("\"unknown\"").is_err());
    }
}

// delegation_receipt_pregrant_path_landed
