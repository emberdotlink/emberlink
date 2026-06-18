//! iMessage approval channel — sends an iMessage via AppleScript and
//! awaits a reply that matches the `approve`/`deny` keyword.
//!
//! Stub: logs at info and returns `TimedOut`. Real wire ships in
//! `TZ-CHANNEL-IMESSAGE-WIRE` (AppleScript bridge + Messages.app
//! reply polling).

use anyhow::Result;
use async_trait::async_trait;

use super::{ApprovalChannel, ApprovalDecision, GrantRequest};

pub struct IMessageChannel;

impl IMessageChannel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IMessageChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalChannel for IMessageChannel {
    fn name(&self) -> &str {
        "imessage"
    }

    async fn request(&self, req: GrantRequest) -> Result<ApprovalDecision> {
        // TODO: drive Messages.app via
        // AppleScript (`tell application "Messages" to send …`) and
        // poll the chat database for a matching reply.
        tracing::info!(?req, "imessage channel: stub — would send via AppleScript");
        Ok(ApprovalDecision::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn stub_returns_timed_out() {
        let c = IMessageChannel::new();
        let req = GrantRequest {
            request_id: "r1".into(),
            persona: "p1".into(),
            scope: "s1".into(),
            reason: "test".into(),
            expires_at: chrono::Utc::now() + Duration::minutes(5),
        };
        let result = c.request(req).await.unwrap();
        assert!(matches!(result, ApprovalDecision::TimedOut));
        assert_eq!(c.name(), "imessage");
    }
}
