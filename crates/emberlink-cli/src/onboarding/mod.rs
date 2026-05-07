//! Cohort A onboarding: idempotent setup steps for `ember init --for claude-code`.
//!
//! Per design §2. The `claude_code` submodule is the orchestration layer for
//! the one-command first-run flow (persona create, scope template, grant
//! create, settings.json patch, optional GH PAT capture). The
//! `settings_patch` submodule holds the lower-level JSON-patch primitives
//! that both `init --for claude-code` and `uninstall --for claude-code`
//! call into.

pub mod claude_code;
pub mod settings_patch;

pub use settings_patch::{
    add_pretooluse_hook, has_pretooluse_hook, patch_settings_json, remove_pretooluse_hook,
    PatchError, EMBER_PROXY_HOOK_COMMAND,
};
