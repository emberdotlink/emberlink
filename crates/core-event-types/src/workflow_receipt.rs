//! Workflow-grant Receipt body extensions — `PregrantPath` enum.
//!
//! Per design §Component 5. Every credentialed Receipt (`credential_provisioned`,
//! `credential_revoked`, `broker.execution_domain`, etc.) stamps three fields
//! linking the call back to the active workflow grant:
//!
//! - `workflow_id: Option<String>` — ULID-shaped per-grant identifier.
//! - `workflow_template: Option<String>` — human-readable template name.
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
//! Anchor: `workflow_receipt_pregrant_path_landed`.
//!
//! Also anchors `pregrant_receipt_correlation_landed` — the canonical
//! `ReceiptBody` schema extension (per design §Component 5) is shipped
//! in `core-events::receipt::body::ReceiptBody` (T1 property tests verified);
//! consumers on the broker.resolve hot path stamp the audit-log payload via
//! `ember-daemon::broker::handler::WorkflowReceiptContext` (checkpoint
//! `workflow_receipt_body_stamp_landed`).

use serde::{Deserialize, Serialize};

/// Which broker-resolve evaluation lane approved (or denied) a single
/// `broker.resolve` call. The ordering is also the resolution priority —
/// the broker tries `Workflow` first, then `PerAction`, then `Jit`, then
/// returns `Deny`. Per design §Component 2 + §Component 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PregrantPath {
    /// The session's active `WorkflowGrant` permitted the action.
    Workflow,
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
            (PregrantPath::Workflow, "\"workflow\""),
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

// workflow_receipt_pregrant_path_landed
