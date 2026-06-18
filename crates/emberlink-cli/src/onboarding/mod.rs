//! Onboarding helpers for launcher integrations like
//! `ember init --for claude`, `ember init --for codex`, and
//! `ember init --for cursor`.
//!
//! Per ADR 120 §2. The `claude_code` submodule is the orchestration layer for
//! the one-command first-run flow (persona create, scope template, grant
//! create, and GitHub setup guidance). The `github_app` submodule exposes the
//! GitHub App permission-floor reference and install URL for adopters who want
//! to install Emberlink against a real GitHub account or org.
//!
//! The brokered Claude session's `permissions.deny` overlay is no longer
//! authored from this module — V030-CLAUDE-OVERLAY moved it to a
//! per-Construct `[settings_overlay]` block in each `construct.toml`,
//! unioned by the launcher into a fresh overlay `settings.json` in a
//! relocated `CLAUDE_CONFIG_DIR`. See
//! [`crate::launcher::settings_overlay`].

pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod first_grant;
pub mod gemini;
pub mod github_app;
