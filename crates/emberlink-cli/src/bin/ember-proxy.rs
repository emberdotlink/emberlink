//! `ember-claude-hook` binary alias.
//!
//! Per implementation-note-92 / design §2: shipped under `emberlink-cli` so
//! `cargo install emberlink` produces both `ember` and `ember-claude-hook`
//! binaries on $PATH in one step. The implementation lives in the
//! `ember-claude-hook` library crate to avoid duplication.

fn main() {
    ember_claude_hook::run_main()
}
