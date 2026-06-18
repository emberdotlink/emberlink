pub mod broker;
pub mod grants;
pub mod infra;
pub mod presence;
pub mod scion;
pub mod spawn;
pub mod trust;

pub mod age;
pub mod auth;
pub mod binary_manifest;
pub mod bootstrap;
pub mod device;
pub mod install;
pub mod install_manifest;
pub mod launcher_watch;
/// Per-OS daemon filesystem layout per ADR 218 — system paths only.
/// Counterpart to `crates/internal-automation/src/engine/paths.rs::EnginePaths`.
pub mod paths;
/// P22-S2 — the token/cost metering module moved into
/// `proxy-forward-runtime` (the forwarding core depends on it). Re-exported
/// here so existing `crate::pricing::*` call sites (proxy.rs, proxy tests)
/// keep resolving unchanged.
pub use proxy_forward_runtime::pricing;
#[cfg(target_os = "macos")]
pub mod se_probe;
pub mod session;
pub mod session_watcher;
pub mod signature_verifier;
pub mod snapshot;
pub mod sops;
/// Empirical-sample telemetry for the v0.3.0 friendly-drop window.
/// Per `META-EMPIRICAL-SAMPLE-PRE-V031-RETUNE`; distinct from `infra::telemetry`
/// (the ADR 212 Prometheus exposition surface). See `docs/v030-empirical-sample-window.md`.
/// Anchor: `empirical_sample_pre_v031_retune_landed`
pub mod telemetry;
pub mod trust_graph;

/// DEMO-MAY3-BIO-REAL: server-side WebAuthn relying-party that
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
/// Pattern (mirrors the `internal-automation::PROCESS_CWD_LOCK` fix from #1438):
/// ```ignore
/// let _guard = crate::PROCESS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
/// // ... test body that mutates env vars or other process-global state ...
/// ```
/// `unwrap_or_else(...into_inner())` recovers the guard even if a prior
/// test paniced while holding it.
#[doc(hidden)]
pub static PROCESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
