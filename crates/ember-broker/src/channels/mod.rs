//! Approval-delivery channel trait + per-channel module re-exports.
//!
//! Each channel implementation is currently a stub — it logs the
//! outbound request and returns `ApprovalDecision::TimedOut`. The
//! trait shape is what policy and the kernel commit to; real wire
//! ships per-channel in `TZ-CHANNEL-SLACK-WIRE` /
//! `TZ-CHANNEL-IMESSAGE-WIRE` / `TZ-CHANNEL-EMAIL-WIRE`.
//!
//! TODO: wire `preferred_channels:
//! Option<Vec<String>>` into the persona policy schema in
//! `ember-daemon::policy`. The current `PolicyRule` is action-keyed
//! and has no persona-routing surface; adding the field here would
//! be premature without a persona-policy struct to attach it to.
//! Once a persona-keyed policy section exists, `preferred_channels`
//! becomes the routing key the kernel hands to the channel registry
//! (`name() == channel`).

pub mod dashboard;
pub mod email;
pub mod imessage;
pub mod slack;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One pending grant request the channel must surface to the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    pub request_id: String,
    pub persona: String,
    pub scope: String,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
}

/// The operator's response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ApprovalDecision {
    Approved {
        decided_at: DateTime<Utc>,
        note: Option<String>,
    },
    Denied {
        decided_at: DateTime<Utc>,
        reason: String,
    },
    TimedOut,
}

/// Pluggable approval delivery. Implementations send the request to the
/// operator via their channel and await/poll for a decision.
#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Channel name (matches policy ConfigMap routing keys).
    fn name(&self) -> &str;

    /// Surface the request and wait for a decision.
    async fn request(&self, req: GrantRequest) -> Result<ApprovalDecision>;
}
