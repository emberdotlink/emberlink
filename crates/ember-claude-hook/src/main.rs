//! `ember-proxy` binary entry point.
//!
//! Today the only documented surface is the Claude Code PreToolUse hook
//! (implementation-note-85). The full HTTP credential-injection
//! proxy still lives inside `ember-daemon::proxy`; this binary exists so
//! Claude Code users get a single, simple install command:
//!
//! ```json
//! { "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [
//!   { "type": "command", "command": "ember-proxy hook" }
//! ]}]}}
//! ```
//!
//! Both `ember-proxy hook` and `ember-proxy --claude-code-hook` dispatch
//! to the same code path so the docs and the binary stay in lockstep.
//!
//! Per implementation-note-90 / design §2: the implementation lives in the library
//! crate (`ember_proxy::run_main`) so that `emberlink-cli` can declare an
//! `ember-proxy` bin alias and `cargo install emberlink` produces both
//! `ember` and `ember-proxy` on $PATH in one step.

fn main() {
    ember_claude_hook::run_main()
}
