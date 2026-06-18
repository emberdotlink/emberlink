//! Email approval channel — emails the request and awaits a reply
//! containing an approve/deny token.
//!
//! Stub: logs at info and returns `TimedOut`. Real wire ships in
//! `TZ-CHANNEL-EMAIL-WIRE` (SMTP send + IMAP / inbox webhook reply
//! polling).

use anyhow::Result;
use async_trait::async_trait;

use super::{ApprovalChannel, ApprovalDecision, GrantRequest};

pub struct EmailChannel;

impl EmailChannel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EmailChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ApprovalChannel for EmailChannel {
    fn name(&self) -> &str {
        "email"
    }

    async fn request(&self, req: GrantRequest) -> Result<ApprovalDecision> {
        // TODO: send via SMTP and poll the
        // configured IMAP inbox (or webhook callback) for a reply
        // containing the request's approve/deny token.
        tracing::info!(?req, "email channel: stub — would send via SMTP");
        Ok(ApprovalDecision::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn stub_returns_timed_out() {
        let c = EmailChannel::new();
        let req = GrantRequest {
            request_id: "r1".into(),
            persona: "p1".into(),
            scope: "s1".into(),
            reason: "test".into(),
            expires_at: chrono::Utc::now() + Duration::minutes(5),
        };
        let result = c.request(req).await.unwrap();
        assert!(matches!(result, ApprovalDecision::TimedOut));
        assert_eq!(c.name(), "email");
    }
}
