//! ember-broker — approval-delivery channels and grant routing.
//!
//! Locks the SHAPE of the approval-channel surface so policy can route
//! `persona → channels[]` and the kernel knows which adapter to call.
//! Real wire (Slack webhook, AppleScript iMessage, SMTP) lands in
//! per-channel follow-up tasks (`implementation-note-21`,
//! `implementation-note-20`, `implementation-note-19`).
pub mod channels;
pub mod github_app;
pub mod ssh_agent;

#[cfg(target_os = "macos")]
pub mod secure_enclave;

#[cfg(target_os = "macos")]
pub mod ssh_agent_macos;
