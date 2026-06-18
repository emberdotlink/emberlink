//! `ember trust …` CLI surfaces for trust-set introspection.
//!
//! Per ADR 162 §Component 2. Phase 1 ships `ember trust list`. Phase 2
//! ships `ember trust show <root-id>` drill-down. Phase 3 ships
//! `ember trust explain <artifact-path>` chain walk (binary_manifest +
//! receipt artifact kinds at minimum; authority_delegation lands in
//! META-TRUST-EXPLAIN-WORKFLOW-GRANT).
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
//! the `backup` + `restore` submodules — encrypted operator-role /
//! workstation Durable Persona export for compatibility recovery of
//! software-custodied material. Device-rooted operator-authority
//! recovery is handled by presence-device enrollment.
//! Anchor: `trust_backup_restore_landed` (META-TRUST-BACKUP-RESTORE).

pub mod backup;
pub mod explain;
pub mod list;
pub mod principal_keychain;
pub mod restore;
pub mod rotate;
pub mod show;
