//! core-construct-runtime — shared boilerplate for per-Construct shims.
//!
//! Per design §1, every Construct binary (e.g. `ember-gh`, `ember-git`,
//! `ember-kubectl`) follows the same lifecycle:
//!
//! 1. **env-detect** — if the session env var is absent, exec the wrapped
//!    binary directly (passthrough; no broker round-trip).
//! 2. **classify** — turn argv into a stable `ActionKey` for policy lookup.
//! 3. **broker.resolve** — ask the daemon for a credential lease (stubbed).
//! 4. **broker.exec** — invoke the wrapped binary with the lease (stubbed).
//! 5. Return the child's `ExitCode`.
//!
//! This crate is the seam that lets each Construct's `main.rs` stay 10–20
//! lines: the caller wires up an argv classifier and a `ConstructSpec`, and
//! `run_construct` does the rest.

pub mod runtime;

pub use runtime::{ConstructSpec, run_construct};

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
