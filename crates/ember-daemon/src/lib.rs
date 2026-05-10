pub mod trust;
pub mod broker;
pub mod infra;

pub mod age;
pub mod binary_manifest;
pub mod bootstrap;
pub mod device;
pub mod install;
pub mod pricing;
pub mod session_watcher;
pub mod session;
pub mod signature_verifier;
pub mod sops;
pub mod snapshot;
pub mod trust_graph;

/// implementation-note-38: server-side WebAuthn relying-party that
/// gates dashboard approvals on a verified passkey assertion.
/// Feature-gated so non-default builds (e.g. embedded test
/// targets) don't pull in the webauthn-rs dep tree.
#[cfg(feature = "webauthn")]
pub mod webauthn;

/// Process-wide test lock for tests that mutate process-global state
/// (env vars, the `STREAMING_REQUESTS_INFLIGHT` atomic in `proxy.rs`,
/// etc.).
///
/// Cargo's default test parallelism runs tests across module boundaries
/// concurrently. Per-module locks (e.g. one in `vault::tests`, another
/// in `proxy::tests`) only serialize within their module — they let
/// `vault::tests::open_from_config_roundtrip` race with another module's
/// test that touches the same global. One process-wide lock makes
/// every globally-stateful test serialize against every other.
///
/// Pattern (mirrors the `headless-runtime::PROCESS_CWD_LOCK` fix from #1438):
/// ```ignore
/// let _guard = crate::PROCESS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
/// // ... test body that mutates env vars or other process-global state ...
/// ```
/// `unwrap_or_else(...into_inner())` recovers the guard even if a prior
/// test paniced while holding it.
#[doc(hidden)]
pub static PROCESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
