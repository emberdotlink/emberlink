//! core-construct-runtime — shared boilerplate for per-Construct shims.
//!
//! Per design §1, every Construct binary (e.g. `ember-gh`, `ember-git`,
//! `ember-kubectl`) follows the same lifecycle:
//!
//! 1. **env-detect** — if the session env var is absent, the production
//!    `run_construct_full` path fails closed for classified credential-bearing
//!    actions and only passthrough-execs unclassified/read-only verbs.
//!    (`run_construct` keeps the older stub-mode direct-passthrough contract.)
//! 2. **classify** — turn argv into a stable `ActionKey` for policy lookup.
//! 3. **broker.resolve** — ask the daemon for a credential lease (stubbed).
//! 4. **broker.exec** — invoke the wrapped binary with the lease (stubbed).
//! 5. Return the child's `ExitCode`.
//!
//! This crate is the seam that lets each Construct's `main.rs` stay 10–20
//! lines: the caller wires up an argv classifier and a `ConstructSpec`, and
//! `run_construct` does the rest.

pub mod pty_bridge;
pub mod rpc;
pub mod runtime;

pub use runtime::{
    BrokerTransactionError, BrokerTransport, ConstructSpec, CredentialAuditKind,
    DaemonRpcTransport, ExecOutcome, SpawnHandle, UnsessionedOutcome, exec_via_broker,
    log_unsessioned_subprocess, resolve_via_broker, run_construct, run_construct_full,
    run_construct_with_transport,
};

/// Stable identifier for a classified Construct action.
///
/// Produced by a [`ClassifyArgv`] implementation; consumed by `broker.resolve`
/// for policy lookup. The string form is `<construct>.<verb>[.<noun>]`,
/// e.g. `gh.pr.create` or `git.push`. Construct-specific classifiers own
/// the exact grammar; this newtype is just a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionKey(pub String);

impl std::fmt::Display for ActionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Maps a Construct's argv to an [`ActionKey`].
///
/// Implementations live in each Construct crate (e.g. `ember-gh`'s
/// `classify_gh_argv`). Returning `None` means the argv could not be
/// classified — the runtime treats that as a non-fatal error and exits
/// with code 2 so the caller can fall back to a passthrough invocation.
pub trait ClassifyArgv {
    fn classify(&self, argv: &[String]) -> Option<ActionKey>;
}

/// Per-tool integration surface for the full broker_exec PTY lifecycle.
///
/// Each Construct binary implements this trait to supply the construct-specific
/// bits. [`run_construct`] uses these to drive env-detect → classify →
/// broker.exec → PTY bridge → exit.
pub trait ConstructConfig: ClassifyArgv {
    /// Stable vendor identifier for this Construct (e.g. `"gh"`, `"git"`,
    /// `"kubectl"`). Used by `run_construct_full`'s env-detect passthrough
    /// branch to tag best-effort `subprocess_audit_log` RPC calls with the
    /// vendor name, so an unsessioned subprocess invocation appears in the
    /// daemon's tamper-evident audit chain under
    /// `subprocess.<vendor>.invoke_no_session` even though no broker
    /// mediation occurred.
    ///
    /// Default implementation returns `"unknown"` for back-compat with
    /// existing test scaffolding; production shims (ember-construct's
    /// `ManifestConfig`) override this to forward the
    /// `VendorManifest::name` row.
    fn vendor(&self) -> &'static str {
        "unknown"
    }

    /// Env var that signals we're inside an ember session (e.g. `"EMBER_SESSION_ID"`).
    /// If absent at runtime, `run_construct_full` refuses classified
    /// credential-bearing actions and only passthrough-execs
    /// unclassified/read-only verbs.
    fn session_id_env(&self) -> &'static str;

    /// Embedded `Construct.toml` bytes (for future broker.resolve payload).
    fn construct_toml_bytes(&self) -> &'static [u8];

    /// Resolve the absolute path to the wrapped binary.
    ///
    /// Implementations may check an env var override (e.g. `EMBER_GH_BINARY`)
    /// and fall back to PATH lookup. Called only when inside a session.
    fn resolve_binary(&self) -> String;

    /// Env var keys whose current values should be forwarded to the daemon
    /// in the `broker_exec` RPC (e.g. `["GH_TOKEN", "GITHUB_TOKEN"]`).
    fn env_passthrough(&self) -> &'static [&'static str];

    /// Translate emberlink-shaped argv into the wrapped tool's native argv.
    ///
    /// Default implementation is identity — the construct's argv reaches the
    /// real binary unchanged. Vendors with emberlink-specific flags that the
    /// real binary doesn't understand (per design §4 — e.g. `ember-scion`
    /// receives `--persona` / `--max-depth` / `--brief` / `--template` which
    /// are policy inputs the daemon consumes, not flags scion recognises)
    /// override this to strip / rename / inject so the upstream binary sees
    /// only its own native vocabulary.
    ///
    /// Called by [`run_construct_full`] AFTER classify and BEFORE
    /// [`build_broker_exec_params`] — broker.resolve sees emberlink-argv (so
    /// the daemon can evaluate policy on the originally-intended flags), and
    /// the exec'd binary sees translated-argv.
    ///
    /// Passthrough-exec paths (env-detect bypass at runtime line 571, and
    /// classify=None bypass) do NOT translate — those branches exit the shim
    /// contract entirely. The fix for emberlink-flag passthrough in those
    /// branches is to eliminate the bypass (e.g. broker.exec default per
    /// implementation-note-17 step 3), not to add
    /// translation here.
    ///
    /// Anchor: `construct_config_translate_argv_hook_landed`.
    fn translate_argv(&self, argv: &[String]) -> Vec<String> {
        argv.to_vec()
    }
}

pub mod layout;
pub mod manifest;
pub mod permission_gaps;
pub mod preflight;
