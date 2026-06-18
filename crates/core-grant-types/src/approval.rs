//! Approval queue types (P31).
//!
//! Types for the grant approval workflow — agents or humans request grants,
//! humans approve/deny from extension or mobile. The approval queue is the
//! missing piece between "agent requests access" and "human approves."

use serde::{Deserialize, Serialize};

use core_types::ValidationError;

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    /// Approved but with a narrower scope than requested.
    NarrowedAndApproved,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Expired => write!(f, "expired"),
            Self::NarrowedAndApproved => write!(f, "narrowed_and_approved"),
        }
    }
}

/// The scope being requested in an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedScope {
    /// Grant capability type (e.g., "ReadCredential", "UsePasskey").
    pub capability: String,
    /// Specific resource ID, or None for "any matching resource."
    pub resource_id: Option<String>,
    /// Additional human-readable constraints.
    pub constraints: Vec<String>,
}

/// Valid status transitions for the approval state machine.
/// Prevents clients from manufacturing already-approved requests.
impl ApprovalStatus {
    /// Whether a transition from `self` to `target` is valid.
    pub fn can_transition_to(&self, target: &ApprovalStatus) -> bool {
        matches!(
            (self, target),
            (ApprovalStatus::Pending, ApprovalStatus::Approved)
                | (ApprovalStatus::Pending, ApprovalStatus::Denied)
                | (ApprovalStatus::Pending, ApprovalStatus::Expired)
                | (ApprovalStatus::Pending, ApprovalStatus::NarrowedAndApproved)
        )
    }
}

/// A request for grant approval, created by an agent or human.
///
/// **Security:** New requests MUST be created with `ApprovalRequest::new()` which
/// forces `status = Pending`. Resolution fields are only set via `resolve()`.
/// Direct deserialization is allowed for storage/transport but the resolver MUST
/// re-validate transitions before acting on a deserialized request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    /// Principal ID of the requester (agent or human).
    pub requester_id: String,
    /// Human-readable label (e.g., "Claude agent", "Bob's phone").
    pub requester_label: Option<String>,
    pub requested_scope: RequestedScope,
    /// Requested duration in seconds, or None for "until revoked."
    pub requested_duration_secs: Option<u64>,
    /// Human-readable reason for the request.
    pub reason: Option<String>,
    /// Unix timestamp (seconds) when the request was created.
    pub created_at: u64,
    pub status: ApprovalStatus,
    /// Unix timestamp when the request was resolved.
    pub resolved_at: Option<u64>,
    /// Principal ID of whoever approved/denied.
    pub resolver_id: Option<String>,
    /// If scope was narrowed on approval.
    pub narrowed_scope: Option<RequestedScope>,
    /// Reason for denial.
    pub denial_reason: Option<String>,
}

impl ApprovalRequest {
    /// Create a new pending approval request. Resolution fields are forced to None.
    pub fn new(
        request_id: String,
        requester_id: String,
        requester_label: Option<String>,
        requested_scope: RequestedScope,
        requested_duration_secs: Option<u64>,
        reason: Option<String>,
        created_at: u64,
    ) -> Self {
        Self {
            request_id,
            requester_id,
            requester_label,
            requested_scope,
            requested_duration_secs,
            reason,
            created_at,
            status: ApprovalStatus::Pending,
            resolved_at: None,
            resolver_id: None,
            narrowed_scope: None,
            denial_reason: None,
        }
    }

    /// Resolve this request. Validates the status transition.
    pub fn resolve(&mut self, response: &ApprovalResponse) -> Result<(), ValidationError> {
        if !self.status.can_transition_to(&response.status) {
            return Err(ValidationError::state_violation(format!(
                "cannot transition from {} to {}",
                self.status, response.status,
            )));
        }
        if self.request_id != response.request_id {
            return Err(ValidationError::invalid_format(
                "response request_id does not match request",
            ));
        }
        self.status = response.status.clone();
        self.resolved_at = Some(response.resolved_at);
        self.resolver_id = Some(response.resolver_id.clone());
        self.narrowed_scope = response.narrowed_scope.clone();
        self.denial_reason = response.denial_reason.clone();
        Ok(())
    }
}

/// Response to an approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub request_id: String,
    pub status: ApprovalStatus,
    pub resolver_id: String,
    /// Unix timestamp when resolved.
    pub resolved_at: u64,
    /// Narrowed scope, if the approver reduced the requested scope.
    pub narrowed_scope: Option<RequestedScope>,
    pub denial_reason: Option<String>,
    /// Granted duration — may differ from requested.
    pub granted_duration_secs: Option<u64>,
}

/// COHORT-A-4 — block-and-poll RPC request shape.
///
/// Sent by a caller awaiting resolution of an approval `request_id` minted by
/// an escalation path (e.g. the ADR 191 payment lane's `evaluate_tool_call`
/// reserve entry, which returns a `RequireApproval` outcome with a
/// `request_id`). The daemon polls `get_approval(request_id)` every 500ms
/// up to `timeout_secs` and returns the resolved [`ApprovalDecision`] (or
/// [`ApprovalDecision::TimedOut`] if the deadline fires first).
///
/// Wire shape is intentionally minimal — the request_id was already minted
/// at `submit_approval` time, and the caller does not need to re-supply
/// the persona/tool/scope context. The default 5-minute timeout is
/// configurable per-call so a future EmberConfig surface can tune
/// it without a wire-format bump.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwaitApprovalRequest {
    pub request_id: String,
    pub timeout_secs: u64,
}

/// COHORT-A-4 — block-and-poll RPC response.
///
/// Wraps the resolved [`ApprovalDecision`] for the awaited request. A
/// dedicated wrapper rather than returning `ApprovalDecision` directly
/// keeps room to add response-level fields (latency, resolver hint) in
/// future revisions without breaking the wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwaitApprovalResponse {
    pub decision: ApprovalDecision,
}

/// Outcome of a block-and-poll [`AwaitApprovalRequest`].
///
/// Three variants matching the resolved approval state machine:
/// * `Approved` — the request was approved (also matches NarrowedAndApproved
///   on the daemon side; the proxy treats both as permit).
/// * `Denied` — the request was denied or expired by an operator decision.
///   `reason` carries the human-readable message for the agent.
/// * `TimedOut` — the daemon's poll deadline fired before any resolution.
///   Mapped to deny on the hook side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied { reason: String },
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_request_roundtrip() {
        let req = ApprovalRequest {
            request_id: "req-001".into(),
            requester_id: "agent-claude".into(),
            requester_label: Some("Claude agent".into()),
            requested_scope: RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: Some("cred-netflix".into()),
                constraints: vec!["read-only".into()],
            },
            requested_duration_secs: Some(3600),
            reason: Some("Need Netflix password to set up streaming".into()),
            created_at: 1700000000,
            status: ApprovalStatus::Pending,
            resolved_at: None,
            resolver_id: None,
            narrowed_scope: None,
            denial_reason: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request_id, "req-001");
        assert_eq!(back.status, ApprovalStatus::Pending);
        assert_eq!(
            back.requested_scope.resource_id,
            Some("cred-netflix".into())
        );
    }

    #[test]
    fn approval_response_roundtrip() {
        let resp = ApprovalResponse {
            request_id: "req-001".into(),
            status: ApprovalStatus::NarrowedAndApproved,
            resolver_id: "persona-josh".into(),
            resolved_at: 1700000060,
            narrowed_scope: Some(RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: Some("cred-netflix".into()),
                constraints: vec!["read-only".into(), "1-hour-max".into()],
            }),
            denial_reason: None,
            granted_duration_secs: Some(1800),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ApprovalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, ApprovalStatus::NarrowedAndApproved);
        assert_eq!(back.granted_duration_secs, Some(1800));
    }

    #[test]
    fn approval_status_display() {
        assert_eq!(ApprovalStatus::Pending.to_string(), "pending");
        assert_eq!(ApprovalStatus::Approved.to_string(), "approved");
        assert_eq!(ApprovalStatus::Denied.to_string(), "denied");
        assert_eq!(ApprovalStatus::Expired.to_string(), "expired");
        assert_eq!(
            ApprovalStatus::NarrowedAndApproved.to_string(),
            "narrowed_and_approved"
        );
    }

    #[test]
    fn new_request_is_always_pending() {
        let req = ApprovalRequest::new(
            "req-1".into(),
            "agent-1".into(),
            None,
            RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: None,
                constraints: vec![],
            },
            Some(3600),
            None,
            1700000000,
        );
        assert_eq!(req.status, ApprovalStatus::Pending);
        assert!(req.resolved_at.is_none());
        assert!(req.resolver_id.is_none());
    }

    #[test]
    fn resolve_valid_transition() {
        let mut req = ApprovalRequest::new(
            "req-1".into(),
            "agent-1".into(),
            None,
            RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: None,
                constraints: vec![],
            },
            None,
            None,
            1700000000,
        );
        let resp = ApprovalResponse {
            request_id: "req-1".into(),
            status: ApprovalStatus::Approved,
            resolver_id: "josh".into(),
            resolved_at: 1700000060,
            narrowed_scope: None,
            denial_reason: None,
            granted_duration_secs: Some(3600),
        };
        assert!(req.resolve(&resp).is_ok());
        assert_eq!(req.status, ApprovalStatus::Approved);
    }

    #[test]
    fn resolve_invalid_transition_fails() {
        let mut req = ApprovalRequest::new(
            "req-1".into(),
            "agent-1".into(),
            None,
            RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: None,
                constraints: vec![],
            },
            None,
            None,
            1700000000,
        );
        // First resolve to Approved.
        let resp1 = ApprovalResponse {
            request_id: "req-1".into(),
            status: ApprovalStatus::Approved,
            resolver_id: "josh".into(),
            resolved_at: 1700000060,
            narrowed_scope: None,
            denial_reason: None,
            granted_duration_secs: None,
        };
        req.resolve(&resp1).unwrap();

        // Try to re-resolve — should fail (Approved -> Denied is invalid).
        let resp2 = ApprovalResponse {
            request_id: "req-1".into(),
            status: ApprovalStatus::Denied,
            resolver_id: "attacker".into(),
            resolved_at: 1700000120,
            narrowed_scope: None,
            denial_reason: Some("forged".into()),
            granted_duration_secs: None,
        };
        assert!(req.resolve(&resp2).is_err());
    }

    #[test]
    fn resolve_mismatched_request_id_fails() {
        let mut req = ApprovalRequest::new(
            "req-1".into(),
            "agent-1".into(),
            None,
            RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: None,
                constraints: vec![],
            },
            None,
            None,
            1700000000,
        );
        let resp = ApprovalResponse {
            request_id: "req-WRONG".into(),
            status: ApprovalStatus::Approved,
            resolver_id: "josh".into(),
            resolved_at: 1700000060,
            narrowed_scope: None,
            denial_reason: None,
            granted_duration_secs: None,
        };
        assert!(req.resolve(&resp).is_err());
    }

    #[test]
    fn denied_response_with_reason() {
        let resp = ApprovalResponse {
            request_id: "req-002".into(),
            status: ApprovalStatus::Denied,
            resolver_id: "persona-josh".into(),
            resolved_at: 1700000120,
            narrowed_scope: None,
            denial_reason: Some("Not authorized for this credential".into()),
            granted_duration_secs: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ApprovalResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, ApprovalStatus::Denied);
        assert!(back.denial_reason.is_some());
    }

    // ---- COHORT-A-4: await_approval RPC types -----------------------

    #[test]
    fn await_approval_request_roundtrip() {
        let req = AwaitApprovalRequest {
            request_id: "approval-abc".into(),
            timeout_secs: 300,
        };
        let wire = serde_json::to_string(&req).unwrap();
        let back: AwaitApprovalRequest = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.request_id, "approval-abc");
        assert_eq!(back.timeout_secs, 300);
    }

    #[test]
    fn approval_decision_approved_roundtrip() {
        let d = ApprovalDecision::Approved;
        let wire = serde_json::to_string(&d).unwrap();
        let back: ApprovalDecision = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, ApprovalDecision::Approved);
    }

    #[test]
    fn approval_decision_denied_roundtrip() {
        let d = ApprovalDecision::Denied {
            reason: "policy block".into(),
        };
        let wire = serde_json::to_string(&d).unwrap();
        let back: ApprovalDecision = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            back,
            ApprovalDecision::Denied {
                reason: "policy block".into(),
            }
        );
    }

    #[test]
    fn approval_decision_timed_out_roundtrip() {
        let d = ApprovalDecision::TimedOut;
        let wire = serde_json::to_string(&d).unwrap();
        let back: ApprovalDecision = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, ApprovalDecision::TimedOut);
    }

    #[test]
    fn await_approval_response_roundtrip() {
        let resp = AwaitApprovalResponse {
            decision: ApprovalDecision::Approved,
        };
        let wire = serde_json::to_string(&resp).unwrap();
        let back: AwaitApprovalResponse = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.decision, ApprovalDecision::Approved);
    }
}
