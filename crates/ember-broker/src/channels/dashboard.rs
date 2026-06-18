//! Dashboard approval channel — surfaces the request in the
//! `/approvals` view of `ember-dashboard`.
//!
//! Stub: logs at info and returns `TimedOut`. Real wire lives in the
//! dashboard handler that polls the daemon socket for pending requests.

use anyhow::Result;
use async_trait::async_trait;

use super::{ApprovalChannel, ApprovalDecision, GrantRequest};

pub struct DashboardChannel;

impl DashboardChannel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DashboardChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalChannel for DashboardChannel {
    fn name(&self) -> &str {
        "dashboard"
    }

    async fn request(&self, req: GrantRequest) -> Result<ApprovalDecision> {
        tracing::info!(
            ?req,
            "dashboard channel: stub — would surface in /approvals"
        );
        Ok(ApprovalDecision::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn stub_returns_timed_out() {
        let c = DashboardChannel::new();
        let req = GrantRequest {
            request_id: "r1".into(),
            persona: "p1".into(),
            scope: "s1".into(),
            reason: "test".into(),
            expires_at: chrono::Utc::now() + Duration::minutes(5),
        };
        let result = c.request(req).await.unwrap();
        assert!(matches!(result, ApprovalDecision::TimedOut));
        assert_eq!(c.name(), "dashboard");
    }
}
