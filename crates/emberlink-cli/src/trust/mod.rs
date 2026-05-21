//! `ember trust …` CLI surfaces for trust-set introspection.
//!
//! Per design §Component 2. Phase 1 ships `ember trust list`. Phase 2
//! ships `ember trust show <root-id>` drill-down. Phase 3 ships
//! `ember trust explain <artifact-path>` chain walk (binary_manifest +
//! receipt artifact kinds at minimum; workflow_grant lands in
//! implementation-note-400).
//!
//! All three surfaces are wired in `crates/emberlink-cli/src/bin/ember.rs`
//! via `TrustAction::{List,Show,Explain}` dispatch arms. Daemon-side
//! handlers live in `crates/ember-daemon/src/trust/introspect.rs` as
//! `handle_trust_list`, `handle_trust_show`, and `handle_trust_explain`.
//!
//! Sentinels: `trust_cli_module_landed` (Phase 1) /
//! `trust_show_landed` (Phase 2) / `trust_explain_landed` (Phase 3) /
//! `trust_explain_receipt_chain_walked` (receipt artifact kind) /
//! `trust_list_show_explain_landed` (umbrella — all three surfaces live).
//!
//! Component 4 (`ember trust backup` / `ember trust restore`) lives in
//! the `backup` + `restore` submodules — encrypted IR export for
//! cross-workstation portability + F-AUTHORITY-3/4 recovery.
//! Anchor: `trust_backup_restore_landed` (implementation-note-30).

pub mod backup;
pub mod explain;
pub mod list;
pub mod restore;
pub mod show;
