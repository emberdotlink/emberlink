// CLASSIFICATION: PUBLIC

//! Root-required Linux e2e test that **actually observes the
//! `setuid` privilege drop** in the spawn-helper.
//!
//! Greppable marker: `setuid_drops_to_target_uid_observed_via_id_u`
//!
//! ## Why this file exists
//!
//! Every test in `spawn_shim_e2e.rs` runs with
//! `target_uid == current_uid` — so the `setuid()` call in
//! `emberd_spawn_shim.rs:301` (and the `setresuid()` calls in
//! `emberd_spawn_helper_linux.rs:541`) are kernel no-ops. The
//! security-critical privilege drop is never observed there. A
//! regression that silently broke `setuid` (e.g. `errno=EPERM`
//! swallowed by the shim, conditional skipping, code deletion during
//! refactor) would still pass every existing test on macOS and on
//! non-root Linux CI.
//!
//! This test closes that gap on Linux. It launches the Linux helper
//! binary as root, sends a directive whose `target_uid` is **not**
//! the current uid, and asserts that the child process actually
//! reports the target uid back via `id -u`. If `setresuid` silently
//! becomes a no-op, the child's reported uid would still be 0 (root)
//! — and this assertion catches that.
//!
//! ## How to run this test
//!
//! The test is **gated by both `target_os = "linux"` AND the env var
//! `EMBER_SPAWN_HELPER_RUN_AS_ROOT=1`**. When the env var is unset,
//! the test prints a `skipping` message and returns success — so
//! ordinary `cargo test` runs (developer laptop, CI) do not require
//! root and do not run this test. To exercise the privilege-drop
//! observation:
//!
//! ```text
//! # As root, on a hardened Linux host with a writable /tmp:
//! sudo -E env EMBER_SPAWN_HELPER_RUN_AS_ROOT=1 \
//!     cargo test -p ember-spawn-helper --test setuid_drop_root -- \
//!     --nocapture
//! ```
//!
//! This root-required test is not wired into the default CI workflow. Run it
//! manually on a root shell on a hardened-Linux host when the spawn-helper's
//! privilege-drop chain changes.
//!
//! ## What the test asserts
//!
//! 1. The helper accepts the directive and spawns `/usr/bin/id -u`.
//! 2. The child's stdout (captured via a tmpfile the construct
//!    `>`-redirects to before exec) reports `target_uid`, NOT the
//!    caller's uid (0).
//! 3. The helper returns `HelperFrame::Exit { code: 0, .. }`.
//!
//! Plus a negative-path companion test:
//!
//! 4. A directive whose `target_uid` falls outside the helper's
//!    `--pool-uid-base..pool_uid_base+pool_size` range is refused
//!    with `RefuseReason::UidOutOfPool` BEFORE any `setresuid` call
//!    is attempted. No child process is launched. The refusal goes
//!    through the shared `validate_directive` gate (see
//!    `ember_spawn_helper::validate_directive`).

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::Duration;

use ember_spawn_helper::{HelperFrame, SpawnDirective, WIRE_VERSION, read_frame, write_frame};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::Command;

fn helper_linux_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_emberd-spawn-helper-linux"))
}

fn current_uid() -> u32 {
    // SAFETY: getuid is async-signal-safe and always succeeds.
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    // SAFETY: getgid is async-signal-safe and always succeeds.
    unsafe { libc::getgid() }
}

fn blake3_of(path: &std::path::Path) -> String {
    let mut f = std::fs::File::open(path).expect("open binary for hash");
    let mut h = blake3::Hasher::new();
    std::io::copy(&mut f, &mut h).expect("read binary for hash");
    h.finalize().to_hex().to_string()
}

fn fresh_socket() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("ember-setuid-drop-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let sock = dir.path().join("h.sock");
    (dir, sock)
}

/// Gate the entire test on `EMBER_SPAWN_HELPER_RUN_AS_ROOT=1`. Returns
/// `false` (with an explanatory `eprintln!`) when the env var is unset
/// — callers should `return` early in that case.
fn root_gate_enabled() -> bool {
    if std::env::var("EMBER_SPAWN_HELPER_RUN_AS_ROOT").is_err() {
        eprintln!(
            "skipping setuid_drop_root: set EMBER_SPAWN_HELPER_RUN_AS_ROOT=1 \
             and run as root to enable. See top-of-file doc-comment for the \
             full invocation."
        );
        return false;
    }
    if current_uid() != 0 {
        eprintln!(
            "skipping setuid_drop_root: EMBER_SPAWN_HELPER_RUN_AS_ROOT=1 set \
             but current_uid={} (not root). The setresuid drop requires \
             CAP_SETUID; re-run via `sudo -E`.",
            current_uid()
        );
        return false;
    }
    true
}

/// Spawn the Linux helper bound to a tempdir socket. The helper runs
/// with `--no-socket-chown`-equivalent semantics by virtue of running
/// in tests (the chown happens unconditionally in production; tests
/// run as root so the chown succeeds). The `EXPECTED_SHIM_HASH` env
/// var is irrelevant on Linux (the shim path is macOS-only), so we
/// just pass an empty value.
async fn spawn_helper(
    socket: &std::path::Path,
    daemon_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
) -> tokio::process::Child {
    let mut cmd = Command::new(helper_linux_bin());
    cmd.arg("--socket")
        .arg(socket)
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--pool-uid-base")
        .arg(pool_uid_base.to_string())
        .arg("--pool-size")
        .arg(pool_size.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    let child = cmd.spawn().expect("spawn linux helper");
    for _ in 0..500 {
        if socket.exists() && UnixStream::connect(socket).await.is_ok() {
            return child;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "Linux helper did not become ready at {} within 5s",
        socket.display()
    );
}

async fn send_directive_and_read(
    socket: &std::path::Path,
    directive: SpawnDirective,
) -> HelperFrame {
    let mut stream = UnixStream::connect(socket)
        .await
        .expect("connect helper socket");
    write_frame(&mut stream, &HelperFrame::Spawn(directive))
        .await
        .expect("write directive");
    stream.flush().await.expect("flush");
    read_frame(&mut stream)
        .await
        .expect("read reply")
        .expect("reply frame")
}

// ──────────────────────────────────────────────────────────────────
// setuid_drops_to_target_uid_observed_via_id_u
// ──────────────────────────────────────────────────────────────────

/// Observe the privilege drop directly: spawn a construct that writes
/// `/usr/bin/id -u`'s output to a tmpfile, then read that tmpfile and
/// assert it reports `target_uid` (NOT the helper's uid 0). This is
/// the **load-bearing** assertion for the spawn-helper's security-
/// critical setresuid call: a regression that silently turned the
/// setresuid into a no-op would still let the existing
/// `target_uid==current_uid` tests pass, but would fail HERE because
/// the child's reported uid would still be 0.
///
/// Greppable marker: `setuid_drops_to_target_uid_observed_via_id_u`.
#[tokio::test]
async fn setuid_drops_to_target_uid_observed_via_id_u() {
    if !root_gate_enabled() {
        return;
    }

    let (_dir, socket) = fresh_socket();
    // Helper accepts connections only from `daemon_uid` — we're
    // running as root, so set the helper's expected daemon uid to 0
    // and connect from this same root process.
    let daemon_uid = current_uid();
    // Pool range chosen to avoid colliding with system uids. The
    // spawn-helper's production pool sits at high-numbered uids per
    // `ember_daemon::install::SPAWN_POOL_UID_BASE`; here we pick a
    // range that's safe on any Linux box for an ephemeral test.
    let pool_uid_base: u32 = 65500;
    let pool_size: u32 = 4;
    let target_uid: u32 = pool_uid_base; // first slot in the pool.
    let target_gid: u32 = pool_uid_base;

    // Sanity: the test setup MUST have target_uid != current_uid;
    // otherwise the setresuid call is a no-op and the test is
    // vacuous. This is the inverse of the assertion in
    // spawn_shim_e2e.rs.
    assert_ne!(
        target_uid,
        current_uid(),
        "setuid_drop_root test must run with target_uid != current_uid; \
         otherwise the setresuid call is a no-op and the observation is vacuous"
    );

    let mut child = spawn_helper(&socket, daemon_uid, pool_uid_base, pool_size).await;

    // The construct writes its uid to a tmpfile the test then reads.
    // We use /bin/sh -c '/usr/bin/id -u > <path>' so the construct
    // can capture stdout in a way the helper protocol doesn't
    // currently surface (the protocol returns only the exit code).
    let scratch = tempfile::Builder::new()
        .prefix("ember-setuid-drop-out-")
        .tempdir_in("/tmp")
        .expect("scratch tempdir");
    // World-writable so the dropped target_uid can write to it.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o777))
        .expect("chmod 777 scratch");
    let uid_out = scratch.path().join("uid.txt");

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("/usr/bin/id -u > {}", uid_out.display()),
        ],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid,
        target_gid,
        content_hash_blake3: construct_hash,
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: None,
    };

    let reply = send_directive_and_read(&socket, directive).await;
    match reply {
        HelperFrame::Exit { code, .. } => {
            assert_eq!(code, 0, "construct exited non-zero: {code}");
        }
        other => panic!("expected Exit, got {other:?}"),
    }

    // Read back the uid the child reported via `id -u`. If
    // setresuid silently became a no-op, this would still be 0
    // (root) and the assertion would fail.
    let reported = std::fs::read_to_string(&uid_out)
        .unwrap_or_else(|e| panic!("read {}: {}", uid_out.display(), e));
    let reported_uid: u32 = reported
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("parse {reported:?}: {e}"));
    assert_eq!(
        reported_uid, target_uid,
        "construct's `id -u` reported {reported_uid}, expected {target_uid} \
         (target_uid). If this is 0, the setresuid drop is silently failing \
         or has been removed."
    );
    // Defense-in-depth: the reported uid MUST NOT be the helper's
    // uid (0/root). This is the exact regression class the brief
    // calls out.
    assert_ne!(
        reported_uid,
        current_uid(),
        "construct ran with uid={reported_uid} (helper's uid); setresuid drop \
         did not occur"
    );

    let _ = child.kill().await;
}

// ──────────────────────────────────────────────────────────────────
// uid_out_of_pool_refused_before_setuid_attempted
// ──────────────────────────────────────────────────────────────────

/// Companion negative-path test (AC #5): a directive whose
/// `target_uid` is outside the helper's `--pool-uid-base..pool_size`
/// range MUST be refused via the shared `validate_directive` gate
/// BEFORE any `setresuid` call is attempted. The helper returns
/// `HelperFrame::Refused { reason: "uid_out_of_pool", .. }` and no
/// child process is launched. This pins the pool-validation refusal
/// path that the brief explicitly calls out.
#[tokio::test]
async fn uid_out_of_pool_refused_before_setuid_attempted() {
    if !root_gate_enabled() {
        return;
    }

    let (_dir, socket) = fresh_socket();
    let daemon_uid = current_uid();
    let pool_uid_base: u32 = 65500;
    let pool_size: u32 = 4;
    // Out-of-pool: one slot ABOVE the inclusive max.
    let out_of_pool_uid: u32 = pool_uid_base + pool_size;

    let mut child = spawn_helper(&socket, daemon_uid, pool_uid_base, pool_size).await;

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: out_of_pool_uid,
        target_gid: current_gid(),
        content_hash_blake3: construct_hash,
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: None,
    };

    let reply = send_directive_and_read(&socket, directive).await;
    match reply {
        HelperFrame::Refused { reason, detail: _ } => {
            assert_eq!(
                reason, "uid_out_of_pool",
                "expected uid_out_of_pool refusal, got reason={reason}"
            );
        }
        other => panic!(
            "expected Refused(uid_out_of_pool); construct must NOT reach \
             setresuid for an out-of-pool target_uid. Got: {other:?}"
        ),
    }

    let _ = child.kill().await;
}
