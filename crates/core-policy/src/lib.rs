//! Scope template schema + evaluator types for Ember Grant policy.
//!
//! Per design §3 (cohort A claude-code default scope template). Compiles
//! to `wasm32-unknown-unknown` per `.claude/rules/library-crates.md`: pure
//! types, no I/O.

pub mod scope_template;

pub use scope_template::{
    DEFAULT_CLAUDE_CODE_TEMPLATE_ID, DEFAULT_CLAUDE_CODE_TEMPLATE_TOML, ParseError, ScopeDecision,
    ScopeTemplate,
};
