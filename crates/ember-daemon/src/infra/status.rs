use serde::{Deserialize, Serialize};

/// Aggregated daemon-owned status rows for the installed operator path.
///
/// This RPC surface intentionally stops at data the daemon already owns:
/// personas, active grants, sandboxes, pending approvals, recent audit rows,
/// the standing-grant / audit totals, and the daemon quarantine latch.
/// Runtime/process/config presentation details (PID file liveness, configured
/// vault backend, dashboard probe) stay in the CLI for now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSummary {
    pub personas: Vec<crate::infra::persona::PersonaInfo>,
    pub grants: Vec<crate::trust::grant::GrantInfo>,
    #[serde(default)]
    pub grant_live_leases: Vec<String>,
    pub sandboxes: Vec<crate::infra::sandbox::SandboxInfo>,
    pub approvals: Vec<crate::trust::approval::ApprovalRequestInfo>,
    pub recent_activity: Vec<crate::infra::audit::AuditEntry>,
    pub standing_grants: usize,
    pub audit_events_total: u64,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_authority: Option<String>,
}
