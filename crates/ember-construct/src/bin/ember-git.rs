//! `ember-git` shadow-PATH shim.
//!
//! shim_subprocess_log_without_session_landed: when invoked with
//! `EMBER_SESSION_ID` unset, the shared runtime entry point
//! `ember_construct::run("git")` routes through
//! `core_construct_runtime::runtime::run_construct_full`, which calls
//! `log_unsessioned_subprocess` (see
//! `crates/core-construct-runtime/src/runtime.rs::log_unsessioned_subprocess`)
//! before either refusing a credential-bearing action
//! (`UnsessionedOutcome::DeniedNoSession`) or passing a read-only verb
//! through to the wrapped binary (`UnsessionedOutcome::PassthroughNoClassify`).
//! Each call writes one row to the daemon's tamper-evident audit chain
//! via `subprocess_audit_log` JSON-RPC — best-effort with a 50 ms
//! timeout, silently swallowed when the daemon is unreachable so the
//! shim never blocks the wrapped tool. The checkpoint anchors that
//! contract here so a grep verifies the per-vendor binary's audit
//! coverage as a single unit. Per
//! META-AP-EMBER-SHIM-SUBPROCESS-LOG-WITHOUT-SESSION + ADR 154.

use std::process::ExitCode;
fn main() -> ExitCode {
    ember_construct::run("git")
}
