//! ember-broker — approval-delivery channels and grant routing.
//!
//! Locks the SHAPE of the approval-channel surface so policy can route
//! `persona → channels[]` and the kernel knows which adapter to call.
//! Real wire (Slack webhook, AppleScript iMessage, SMTP) lands in
//! per-channel follow-up tasks (`TZ-CHANNEL-SLACK-WIRE`,
//! `TZ-CHANNEL-IMESSAGE-WIRE`, `TZ-CHANNEL-EMAIL-WIRE`).
pub mod aws_sts;
pub mod azure;
pub mod channels;
pub mod fly;
pub mod gcp;
pub mod github_app;
pub mod github_broker;
pub mod hashivault;
pub mod okta;
pub mod ssh_agent;
pub mod ssh_agent_bridge;
pub mod vercel;

pub use aws_sts::{AwsLongLivedCredentials, AwsStsBroker, AwsStsMode, AwsStsScope};
pub use azure::{AzureAuthMethod, AzureCliBroker, AzureScope, AzureServicePrincipal};
pub use fly::{FlyBroker, FlyParentToken, FlyScope};
pub use gcp::{GcpAuthMethod, GcpBroker, GcpScope, GcpServiceAccountKey};
pub use github_broker::{GitHubBroker, GithubScope};
pub use hashivault::{HashiVaultBroker, HashiVaultParentToken, HashiVaultScope};
pub use okta::{OktaBroker, OktaScope, OktaServiceApp};
pub use vercel::{VercelBroker, VercelParentToken, VercelScope};

pub(crate) fn install_jwt_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

#[cfg(target_os = "macos")]
pub mod secure_enclave;

#[cfg(target_os = "macos")]
pub mod ssh_agent_macos;
