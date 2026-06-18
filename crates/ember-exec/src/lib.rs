//! CLASSIFICATION: PUBLIC
//!
//! ember-exec — standalone pty-bridge spike for the SCION runtime.
//!
//! Proves that a process can be spawned inside a container with a full TTY,
//! with stdin/stdout/stderr routed through a Unix-domain socket (UDS),
//! SIGWINCH (window resize) propagated to the child, and exit codes surfaced
//! to the caller.
//!
//! # Open questions (for the promote-spike-to-production follow-up)
//!
//! 1. **`forkpty` vs `openpty` + manual setsid/setctty**: `forkpty(3)` is
//!    simpler but it forks. In a tokio multi-thread runtime this is safe as
//!    long as the child immediately `exec`s (which `tokio::process::Command`
//!    does), but the narrow fork-safety window means we must not touch any
//!    tokio handles between `forkpty` and `exec`. The current implementation
//!    uses `forkpty` for simplicity. A production implementation might prefer
//!    `posix_spawn` + a pre-exec hook via `CommandExt::pre_exec`.
//!
//! 2. **Framing protocol**: the current wire format
//!    (`TAG_DATA` / `TAG_WINSIZE`) is copied from the existing
//!    `core-construct-runtime::pty_bridge` module. A shared `ember-exec-wire`
//!    crate should own the protocol so both sides stay in sync.
//!
//! 3. **Error surface on `connect`**: when the server side exits before the
//!    client finishes reading, the UDS EOF can race with partial output.
//!    Production needs a length-prefixed response stream or explicit EOF
//!    checkpoint so the client knows when the child's last byte has been flushed.
//!
//! 4. **SIGWINCH in async context**: the current implementation installs a
//!    raw C signal handler. Tokio provides `tokio::signal::unix::signal` for
//!    signal handling that is async-safe. Production should prefer the tokio
//!    signal stream over a raw `libc::signal` call.
//!
//! 5. **Platform portability**: `forkpty(3)` is POSIX but not on all
//!    platforms (notably not on Fuchsia or WASI). If `ember-exec` needs to
//!    compile to targets beyond Linux/macOS, the pty implementation needs
//!    feature gating.

pub mod pty;

/// SCION-EMBER-EXEC-A-BIN-UDS: UDS frame protocol consumed by the
/// `ember-exec` binary. Subtask B layers content-hash verification on top;
/// subtask C wires `PtyBridge` for the real spawn.
pub mod uds;

/// SCION-EMBER-EXEC-B-HASH-SETUID: privilege-boundary mechanisms.
/// [`spawn::verify_content_hash`] is the CRIT-B mitigation gate;
/// [`spawn::drop_privileges`] locks the real / effective / saved IDs.
/// Subtask C wires both into the SpawnDirective handler.
pub mod spawn;
