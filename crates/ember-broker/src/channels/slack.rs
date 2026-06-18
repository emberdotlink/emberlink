//! Slack approval channel — posts a message to a Slack webhook and
//! awaits a button click on the resulting block-kit message.
//!
//! Stub: logs at info and returns `TimedOut`. Real wire ships in
//! `TZ-CHANNEL-SLACK-WIRE` (Slack webhook POST + interactivity
//! callback).

use anyhow::Result;
use async_trait::async_trait;

use super::{ApprovalChannel, ApprovalDecision, GrantRequest};

pub struct SlackChannel;

impl SlackChannel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SlackChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalChannel for SlackChannel {
    fn name(&self) -> &str {
        "slack"
    }

    async fn request(&self, req: GrantRequest) -> Result<ApprovalDecision> {
        // TODO: POST to the configured Slack
        // webhook URL with a block-kit Approve/Deny message, then poll
        // the interactivity callback queue for the operator's reply.
        tracing::info!(?req, "slack channel: stub — would post webhook");
        Ok(ApprovalDecision::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn stub_returns_timed_out() {
        let c = SlackChannel::new();
        let req = GrantRequest {
            request_id: "r1".into(),
            persona: "p1".into(),
            scope: "s1".into(),
            reason: "test".into(),
            expires_at: chrono::Utc::now() + Duration::minutes(5),
        };
        let result = c.request(req).await.unwrap();
        assert!(matches!(result, ApprovalDecision::TimedOut));
        assert_eq!(c.name(), "slack");
    }
}
