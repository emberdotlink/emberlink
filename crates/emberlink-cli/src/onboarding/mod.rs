//! Onboarding helpers for launcher integrations like
//! `ember init --for claude` and `ember init --for codex`.
//!
//! Per design §2. The `claude_code` submodule is the orchestration layer for
//! the one-command first-run flow (persona create, scope template, grant
//! create, and GitHub setup guidance). The `github_app` submodule
//! (implementation-note-445) exposes the public GitHub App manifest doc
//! and install URL for adopters who want to install Emberlink against a real
//! GitHub account or org.
//!
//! The brokered Claude session's `permissions.deny` overlay is no longer
//! authored from this module — V030-CLAUDE-OVERLAY moved it to a
//! per-Construct `[settings_overlay]` block in each `construct.toml`,
//! unioned by the launcher into a fresh overlay `settings.json` in a
//! relocated `CLAUDE_CONFIG_DIR`. See
//! [`crate::launcher::settings_overlay`].

pub mod claude_code;
pub mod codex;
pub mod first_grant;
pub mod github_app;
