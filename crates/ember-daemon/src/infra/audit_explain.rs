use serde::{Deserialize, Serialize};

use crate::infra::audit::{AuditEntry, AuditFilter};
use crate::infra::store::{DaemonStore, StoreError};
use crate::trust::policy::{ApprovalRequirement, PolicyEngine, RiskLevel, Tier};

/// Daemon-owned current-state explanation for a single audit event.
///
/// The `event` row is historical evidence from the audit log. The `current_*`
/// projections are explicitly present-day views over the daemon's live grant
/// table and currently loaded policy engine; they do NOT attempt to reconstruct
/// the historical state at the event timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExplainView {
    pub event: AuditEntry,
    pub current_grant: Option<AuditExplainGrantView>,
    pub current_policy: AuditExplainPolicyView,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExplainGrantView {
    pub id: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExplainPolicyView {
    pub requirement: ApprovalRequirement,
    pub risk: RiskLevel,
    pub tier: Tier,
    pub matched_rule: Option<String>,
}

impl From<crate::trust::grant::GrantInfo> for AuditExplainGrantView {
    fn from(grant: crate::trust::grant::GrantInfo) -> Self {
        Self {
            id: grant.id,
            scope: grant.scope,
            created_at: grant.created_at,
            expires_at: grant.expires_at,
            status: grant.status,
        }
    }
}

impl From<core_approval::policy::PolicyEvaluation> for AuditExplainPolicyView {
    fn from(eval: core_approval::policy::PolicyEvaluation) -> Self {
        Self {
            requirement: eval.requirement,
            risk: eval.risk,
            tier: eval.tier,
            matched_rule: eval.matched_rule,
        }
    }
}

pub fn build_audit_explain(
    store: &DaemonStore,
    policy: &PolicyEngine,
    id: i64,
) -> Result<AuditExplainView, StoreError> {
    let event = store
        .query_audit(&AuditFilter {
            id: Some(id),
            limit: Some(1),
            ..Default::default()
        })?
        .into_iter()
        .next()
        .ok_or(StoreError::NotFound)?;

    let current_grant = match (&event.agent_id, &event.credential) {
        (Some(agent_id), Some(credential_name)) => store
            .evaluate_grant(agent_id, credential_name)
            .ok()
            .map(AuditExplainGrantView::from),
        _ => None,
    };

    let current_policy = AuditExplainPolicyView::from(policy.evaluate(&event.action));

    Ok(AuditExplainView {
        event,
        current_grant,
        current_policy,
        note: "Current-state explanation: the event row is historical audit evidence, but grant and policy sections reflect the daemon's current live state.".to_string(),
    })
}
