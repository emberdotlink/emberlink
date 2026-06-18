//! TOFU (Trust-On-First-Use) credential binding confirmation.
//!
//! META-ARCH-DCC-3B-TOFU-BIOMETRIC — replaces the DCC-3A stub with real
//! ADR-124 biometric prompt integration. The flow:
//!
//! 1. `submit_approval` writes a pending row into the approvals table
//!    with `risk_level = "medium"` and an `action = "bind:<remote>@<url>"`
//!    describing the binding the user is being asked to confirm.
//! 2. The daemon's existing approval-resolution surfaces (dashboard tap,
//!    `ember approve <id>`, CLI biometric prompt via
//!    `resolve_approval_with_biometric`) update the row to `approved` /
//!    `denied`.
//! 3. This function polls `get_approval` at 100ms intervals until the
//!    status leaves `pending` or the 120s timeout elapses.
//! 4. The outcome maps to `TofuOutcome::Confirmed | Refused | TimedOut`.
//!    `TimedOut` is the soft-failure path — the caller refuses the
//!    broker_exec but does NOT delete the (still-pending) approval row;
//!    on a stale-pending sweep, the dismiss path will clean it up.
//!
//! Test-mock hook: a global `MOCK_OUTCOME` cell short-circuits the
//! approval flow under `#[cfg(test)]` so unit tests can exercise the
//! caller's confirm/refuse paths without spinning up a real approval
//! surface. Default mock outcome is `Refused` so existing DCC-6 tests
//! that asserted the stub-Refused behavior continue to pass.

use std::time::Duration;
use uuid::Uuid;

use crate::infra::store::DaemonStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuOutcome {
    Confirmed,
    Refused,
    TimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum TofuError {
    #[error("biometric layer unavailable: {0}")]
    BiometricUnavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

// Three constants used by the production `tofu_confirm_binding` polling
// loop. Under `cargo build --tests`, that fn's `#[cfg(test)] { return
// mock::... }` short-circuit at function entry skips the polling loop
// entirely, so the constants look unused at the test-build target.
// `#[allow(dead_code)]` keeps the documented constants in place under
// both builds — the dead-code warning would otherwise mislead future
// readers into thinking these have been retired.

/// Biometric-prompt timeout. 120s matches the credgate poll loop's
/// timeout in `handler.rs::handle_broker_issue`.
#[allow(dead_code)]
const BIOMETRIC_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Poll interval — mirrors the credgate loop's 50ms but a touch slower
/// since TOFU prompts are out-of-band rather than mid-flight.
#[allow(dead_code)]
const BIOMETRIC_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Approval-row TTL hint for the row's `ttl_secs` field. Soft hint —
/// the load-bearing limit is `BIOMETRIC_PROMPT_TIMEOUT` enforced here.
#[allow(dead_code)]
const APPROVAL_ROW_TTL_SECS: u64 = 300;

/// Confirm a new credential binding via TOFU.
///
/// Submits an approval request and polls until the user resolves it
/// (confirm / deny) or the timeout fires. Caller (DCC-6 allowlist
/// gate) treats:
///
/// - `TofuOutcome::Confirmed` → persist the binding via DCC-1's
///   `bindings::insert`, then proceed with credential mint.
/// - `TofuOutcome::Refused` / `TimedOut` → refuse the broker_exec
///   with JSON-RPC code `-32007 binding_not_confirmed`.
///
/// Per ADR-150's doctrine: this function is the ONLY interactive path
/// for net-new binding establishment. Non-interactive bootstrap uses
/// `ember bind register` (admin verb, DCC-7) or signed manifest
/// (DCC-9, pending).
pub async fn tofu_confirm_binding(
    store: &DaemonStore,
    principal_id: &Uuid,
    working_tree_id: &str,
    remote_name: &str,
    remote_url: &str,
    proposed_scope: &str,
) -> Result<TofuOutcome, TofuError> {
    #[cfg(test)]
    {
        // Test mock: short-circuit the approval flow. Default outcome
        // is Refused so DCC-6's `allowlist_refuses_unbound_remote` test
        // (asserting stub-equivalent behavior) continues to pass.
        let _ = (store, working_tree_id, remote_url, proposed_scope);
        let outcome = mock::current_outcome().unwrap_or(TofuOutcome::Refused);
        let _ = (principal_id, remote_name);
        return Ok(outcome);
    }

    #[cfg(not(test))]
    {
        biometric_prompt_for_binding(
            store,
            principal_id,
            working_tree_id,
            remote_name,
            remote_url,
            proposed_scope,
        )
        .await
    }
}

/// Real biometric prompt path — submit_approval + poll loop +
/// outcome mapping. Lives under `cfg(not(test))` so unit tests bypass
/// it through the mock-outcome short-circuit above.
///
/// META-ARCH-DCC-3B-TOFU-BIOMETRIC: biometric_prompt_for_binding checkpoint.
#[cfg(not(test))]
async fn biometric_prompt_for_binding(
    store: &DaemonStore,
    principal_id: &Uuid,
    working_tree_id: &str,
    remote_name: &str,
    remote_url: &str,
    proposed_scope: &str,
) -> Result<TofuOutcome, TofuError> {
    // Approval-row shape. Prompt content surfaces via the existing
    // approval-rendering paths (dashboard + CLI) which read the same
    // columns: `credential_name`, `scope`, `action`. We pack the
    // load-bearing TOFU context (working tree, remote name, URL) into
    // `action` so the renderer can show a single human-readable line
    // without schema changes.
    let credential_name = format!("credential-binding:{remote_name}");
    let action = format!("bind:{remote_name} @ {remote_url} (tree={working_tree_id})");

    let info = store
        .submit_approval(
            &principal_id.to_string(),
            &credential_name,
            proposed_scope,
            Some(APPROVAL_ROW_TTL_SECS),
            &action,
            "medium",
        )
        .map_err(|e| TofuError::Internal(format!("submit_approval failed: {e}")))?;

    let request_id = info.id;
    let started = std::time::Instant::now();

    loop {
        if started.elapsed() >= BIOMETRIC_PROMPT_TIMEOUT {
            // Best-effort dismiss so the row doesn't linger as
            // "pending forever". If dismiss errors, the stale-row
            // sweep will catch it.
            let _ = store.dismiss_approval(&request_id);
            return Ok(TofuOutcome::TimedOut);
        }
        tokio::time::sleep(BIOMETRIC_POLL_INTERVAL).await;

        match store.get_approval(&request_id) {
            Ok(row) if row.status == "approved" => {
                return Ok(TofuOutcome::Confirmed);
            }
            Ok(row) if row.status == "denied" => {
                return Ok(TofuOutcome::Refused);
            }
            Ok(row) if row.status == "dismissed" || row.status == "expired" => {
                // Operator dismissed the row out of band (or it
                // expired on its own). Treat as timeout — the caller
                // refuses without retry.
                return Ok(TofuOutcome::TimedOut);
            }
            Ok(_) => continue, // still pending
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    request_id = %request_id,
                    "tofu_confirm_binding: get_approval transient error; retrying"
                );
                continue;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! Test-only mock outcome injection for `tofu_confirm_binding`.
    //!
    //! The daemon is single-threaded (tokio LocalSet), but unit tests
    //! can run in parallel by default. `parking_lot::Mutex` keeps the
    //! mock state safe across them; tests that mutate the outcome
    //! should also serialize on a single-thread test runtime if they
    //! interleave with other approval-flow tests in the same module.
    use super::TofuOutcome;
    use std::sync::Mutex;

    static MOCK: Mutex<Option<TofuOutcome>> = Mutex::new(None);

    pub fn set(outcome: Option<TofuOutcome>) {
        *MOCK.lock().unwrap() = outcome;
    }

    pub fn current_outcome() -> Option<TofuOutcome> {
        *MOCK.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::store::DaemonStore;
    use std::sync::Mutex;

    // Serialize all mock-mutating tests so parallel execution doesn't
    // interleave `mock::set` calls. Held for the duration of each test's
    // set-call-assert window.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_store() -> DaemonStore {
        DaemonStore::open_in_memory().expect("in-memory store")
    }

    #[tokio::test]
    async fn default_mock_returns_refused() {
        let _g = TEST_LOCK.lock().unwrap();
        // No mock set → default behavior is Refused. Matches the
        // DCC-3A stub semantics so existing DCC-6 tests still pass.
        mock::set(None);
        let store = fixture_store();
        let outcome = tofu_confirm_binding(
            &store,
            &Uuid::nil(),
            "abc123",
            "origin",
            "https://github.com/foo/bar",
            "contents:write",
        )
        .await
        .unwrap();
        assert_eq!(outcome, TofuOutcome::Refused);
    }

    #[tokio::test]
    async fn mock_confirms_returns_confirmed() {
        let _g = TEST_LOCK.lock().unwrap();
        mock::set(Some(TofuOutcome::Confirmed));
        let store = fixture_store();
        let outcome = tofu_confirm_binding(
            &store,
            &Uuid::nil(),
            "abc123",
            "origin",
            "https://github.com/foo/bar",
            "contents:write",
        )
        .await
        .unwrap();
        assert_eq!(outcome, TofuOutcome::Confirmed);
        mock::set(None);
    }

    #[tokio::test]
    async fn mock_refuses_returns_refused() {
        let _g = TEST_LOCK.lock().unwrap();
        mock::set(Some(TofuOutcome::Refused));
        let store = fixture_store();
        let outcome = tofu_confirm_binding(
            &store,
            &Uuid::nil(),
            "abc123",
            "origin",
            "https://github.com/foo/bar",
            "contents:write",
        )
        .await
        .unwrap();
        assert_eq!(outcome, TofuOutcome::Refused);
        mock::set(None);
    }

    #[tokio::test]
    async fn mock_times_out_returns_timed_out() {
        let _g = TEST_LOCK.lock().unwrap();
        mock::set(Some(TofuOutcome::TimedOut));
        let store = fixture_store();
        let outcome = tofu_confirm_binding(
            &store,
            &Uuid::nil(),
            "abc123",
            "origin",
            "https://github.com/foo/bar",
            "contents:write",
        )
        .await
        .unwrap();
        assert_eq!(outcome, TofuOutcome::TimedOut);
        mock::set(None);
    }
}
