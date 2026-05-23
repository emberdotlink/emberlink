//! Onboarding helpers for launcher integrations like
//! `ember init --for claude` and `ember init --for codex`.
//!
//! Per design §2. The `claude_code` submodule is the orchestration layer for
//! the one-command first-run flow (persona create, scope template, grant
//! create, settings.json patch, and GitHub setup guidance). The
//! `settings_patch` submodule holds the lower-level JSON-patch primitives
//! that both `init --for claude` and `uninstall --for claude`
//! call into. The `github_app` submodule (implementation-note-511)
//! exposes the public GitHub App manifest doc and install URL for adopters
//! who want to install Emberlink against a real GitHub account or org.

pub mod claude_code;
pub mod codex;
pub mod first_grant;
pub mod github_app;
pub mod settings_patch;

pub use settings_patch::{
    EMBER_PROXY_HOOK_COMMAND, PatchError, RAW_TOOL_DENY_LIST, add_permissions_deny_outside_shadow,
    add_command_hook, add_pretooluse_hook, has_command_hook, has_pretooluse_hook,
    patch_settings_json,
    remove_permissions_deny_outside_shadow, remove_pretooluse_hook,
};
