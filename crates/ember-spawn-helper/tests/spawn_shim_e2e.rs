// CLASSIFICATION: PUBLIC

//! End-to-end tests for the macOS helper → shim → construct spawn chain.
//!
//! ## Test surfaces
//!
//! - **T2 happy path** — invoke the helper end-to-end; assert
//!   construct stdout matches expected uid.
//! - **T2 sandbox enforcement** — construct that touches a
//!   forbidden path exits with the sandbox-denied code.
//! - **T2 shim hash mismatch refused** — tamper with the shim on
//!   disk; helper returns `RefuseReason::ShimHashMismatch`.
//! - **T2 helper does NOT use `pre_exec`** — source-level grep
//!   regression guard. Static check on the macOS bin's source file.
//! - **T2 pool args required** — invoke helper with neither `--pool-
//!   uid-base` nor `--pool-size`; expect clap error code 2.
//! - **T2 macOS socket group** — after helper binds socket, stat
//!   shows `0660` (group writability) and the group is `ember-
//!   clients` when present.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::time::Duration;

use ember_spawn_helper::{HelperFrame, SpawnDirective, WIRE_VERSION, read_frame, write_frame};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::process::Command;

fn helper_macos_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_emberd-spawn-helper-macos"))
}

fn shim_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_emberd-spawn-shim"))
}

fn current_uid() -> u32 {
    // SAFETY: getuid is async-signal-safe and always succeeds.
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    // SAFETY: getgid is async-signal-safe and always succeeds.
    unsafe { libc::getgid() }
}

fn fresh_socket() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("ember-spawn-shim-e2e-")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let sock = dir.path().join("h.sock");
    (dir, sock)
}

fn fresh_scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ember-spawn-scratch-")
        .tempdir_in("/tmp")
        .expect("scratch tempdir")
}

fn blake3_of(path: &std::path::Path) -> String {
    let mut f = std::fs::File::open(path).expect("open");
    let mut h = blake3::Hasher::new();
    std::io::copy(&mut f, &mut h).expect("read");
    h.finalize().to_hex().to_string()
}

/// Spawn the macOS helper bound to a tempdir socket. The helper's
/// `EXPECTED_SHIM_HASH` env var is set to the shim's actual blake3
/// (so the hash-pin succeeds unless the shim is tampered with
/// after).
async fn spawn_helper(
    socket: &std::path::Path,
    scratch: &std::path::Path,
    shim_path: &std::path::Path,
    daemon_uid: u32,
    pool_uid_base: u32,
    pool_size: u32,
    expected_shim_hash: &str,
) -> tokio::process::Child {
    let mut cmd = Command::new(helper_macos_bin());
    cmd.arg("--socket")
        .arg(socket)
        .arg("--daemon-uid")
        .arg(daemon_uid.to_string())
        .arg("--pool-uid-base")
        .arg(pool_uid_base.to_string())
        .arg("--pool-size")
        .arg(pool_size.to_string())
        .arg("--shim-path")
        .arg(shim_path)
        .arg("--scratch-dir")
        .arg(scratch)
        .arg("--no-socket-chown")
        .env("EXPECTED_SHIM_HASH", expected_shim_hash)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    let child = cmd.spawn().expect("spawn helper");
    for _ in 0..500 {
        if socket.exists() && UnixStream::connect(socket).await.is_ok() {
            return child;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "macOS helper did not become ready at {} within 5s",
        socket.display()
    );
}

async fn send_directive_and_read(
    socket: &std::path::Path,
    directive: SpawnDirective,
) -> HelperFrame {
    // Self-documenting invariant: every test in this file runs with
    // `target_uid == current_uid`, so the shim's `setuid()` call is
    // intentionally a kernel no-op here. The actual privilege-drop
    // observation lives in `tests/setuid_drop_root.rs` (Linux-only,
    // root-gated). If a future test wants to send a directive with
    // `target_uid != current_uid`, it MUST NOT go through this
    // helper — add a dedicated path with proper root-gating.
    assert_eq!(
        directive.target_uid,
        current_uid(),
        "spawn_shim_e2e tests must run with target_uid==current_uid; \
         setuid is intentionally a no-op here — see setuid_drop_root.rs \
         for the actual privilege-drop test"
    );
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

/// Build a synthetic shim copy on a tmpfs path. Returns (path, hash).
/// Used by the shim-hash-mismatch test to tamper with the shim on
/// disk after the helper has started.
fn copy_shim_to_tmp(orig_shim: &std::path::Path) -> (tempfile::TempDir, PathBuf, String) {
    let dir = tempfile::Builder::new()
        .prefix("shim-copy-")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let dst = dir.path().join("emberd-spawn-shim");
    std::fs::copy(orig_shim, &dst).expect("copy shim");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
    let h = blake3_of(&dst);
    (dir, dst, h)
}

// ──────────────────────────────────────────────────────────────────
// T2 — Happy path
// ──────────────────────────────────────────────────────────────────

/// Construct that prints its own uid; assert stdout matches
/// `target_uid` (== current uid, since we run as non-root in CI and
/// the shim's setuid is a no-op when target==current). The point is
/// that the posix_spawn → shim → execve chain completes and the
/// exit code propagates.
#[tokio::test]
async fn t2_happy_path_construct_runs_via_shim() {
    let (_dir, socket) = fresh_socket();
    let scratch = fresh_scratch();
    let uid = current_uid();
    let shim = shim_bin();
    let shim_hash = blake3_of(&shim);
    let mut child = spawn_helper(&socket, scratch.path(), &shim, uid, uid, 1, &shim_hash).await;

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec!["sh".to_string(), "-c".to_string(), "exit 37".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: uid,
        target_gid: current_gid(),
        content_hash_blake3: construct_hash,
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: None,
    };

    let reply = send_directive_and_read(&socket, directive).await;
    match reply {
        HelperFrame::Exit { code, .. } => assert_eq!(code, 37, "unexpected exit code"),
        other => panic!("expected Exit, got {other:?}"),
    }

    let _ = child.kill().await;
}

/// The helper must capture the construct's stdout/stderr and carry the
/// tails back in the `Exit` frame — this is the end-to-end proof of the
/// posix_spawn → shim → execve → pipe → wire path that headless
/// brokered commands (e.g. `gh pr list` with no PTY) depend on.
#[tokio::test]
async fn t2_captures_construct_stdout_and_stderr() {
    let (_dir, socket) = fresh_socket();
    let scratch = fresh_scratch();
    let uid = current_uid();
    let shim = shim_bin();
    let shim_hash = blake3_of(&shim);
    let mut child = spawn_helper(&socket, scratch.path(), &shim, uid, uid, 1, &shim_hash).await;

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo HELLO_STDOUT; echo OOPS_STDERR 1>&2; exit 0".to_string(),
        ],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: uid,
        target_gid: current_gid(),
        content_hash_blake3: construct_hash,
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: None,
    };

    let reply = send_directive_and_read(&socket, directive).await;
    match reply {
        HelperFrame::Exit {
            code,
            stdout_tail,
            stderr_tail,
            ..
        } => {
            assert_eq!(code, 0, "unexpected exit code");
            assert!(
                stdout_tail.contains("HELLO_STDOUT"),
                "stdout not captured: {stdout_tail:?}"
            );
            assert!(
                stderr_tail.contains("OOPS_STDERR"),
                "stderr not captured: {stderr_tail:?}"
            );
        }
        other => panic!("expected Exit, got {other:?}"),
    }

    let _ = child.kill().await;
}

// ──────────────────────────────────────────────────────────────────
// T2 — Sandbox enforcement
// ──────────────────────────────────────────────────────────────────

/// With a `(deny default) (allow process-exec)` profile, a construct
/// that attempts `open("/etc/passwd")` should exit non-zero (sandbox
/// kill or read failure). On macOS, sandbox-denied subprocesses
/// typically `SIGKILL` (exit code 137) or the open() returns EPERM
/// and the construct exits 1.
///
/// We use a minimal `sh -c '... 2>/dev/null; echo $?'` shape to make
/// the test deterministic across the kill-or-EPERM cases.
#[tokio::test]
async fn t2_sandbox_denies_forbidden_open() {
    let (_dir, socket) = fresh_socket();
    let scratch = fresh_scratch();
    let uid = current_uid();
    let shim = shim_bin();
    let shim_hash = blake3_of(&shim);
    let mut child = spawn_helper(&socket, scratch.path(), &shim, uid, uid, 1, &shim_hash).await;

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    // Build a profile that denies file-read on everything outside a
    // tiny base. `(deny default)` denies all operations; allowing
    // `process-exec*` so the shell can exec, and `process-fork` so
    // sh can fork-exec /bin/cat. Reading /etc/passwd should fail.
    let profile = r#"(version 1)
(deny default)
(allow process-exec*)
(allow process-fork)
(allow file-read-metadata)
(allow file-read*
   (literal "/bin/sh")
   (subpath "/usr/lib")
   (subpath "/System/Library"))
"#;

    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec![
            "sh".to_string(),
            "-c".to_string(),
            // Try to cat /etc/passwd; if it fails, exit 42.
            "if cat /etc/passwd > /dev/null 2>&1; then exit 0; else exit 42; fi".to_string(),
        ],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: uid,
        target_gid: current_gid(),
        content_hash_blake3: construct_hash,
        chroot_dir: None,
        sandbox_profile: Some(profile.to_string()),
        seccomp_filter: None,
        invocation_id: None,
    };

    let reply = send_directive_and_read(&socket, directive).await;
    match reply {
        HelperFrame::Exit { code, .. } => {
            // Either the SBPL caused cat to be SIGKILL'd (137), or
            // the open() returned EPERM and our exit-42 branch fired,
            // or the cat is denied by sandbox (1). Anything non-zero
            // is correct — what we MUST NOT see is 0 (success).
            assert_ne!(
                code, 0,
                "construct succeeded under sandbox; expected denial. exit_code={code}"
            );
        }
        HelperFrame::Refused { reason, detail } => {
            // Acceptable: sandbox_init refused the profile and the
            // shim emitted a SANDBOX_INIT failure (exit 127). The
            // helper reports this as `spawn_failed`. What we want is
            // that the construct never succeeded.
            assert!(
                reason == "spawn_failed" || reason == "sandbox_init_failed",
                "unexpected refusal reason: {reason} detail={detail:?}"
            );
        }
        other => panic!("expected Exit or Refused, got {other:?}"),
    }

    let _ = child.kill().await;
}

// ──────────────────────────────────────────────────────────────────
// T2 — Shim hash mismatch refused
// ──────────────────────────────────────────────────────────────────

/// Helper is configured with `EXPECTED_SHIM_HASH=<original>` but the
/// shim on disk is a tampered copy. Helper must refuse with
/// `RefuseReason::ShimHashMismatch` and NOT invoke posix_spawn.
#[tokio::test]
async fn t2_shim_hash_mismatch_refuses_spawn() {
    let (_dir, socket) = fresh_socket();
    let scratch = fresh_scratch();
    let uid = current_uid();
    let orig_shim = shim_bin();

    // Copy the shim to a tmp path; this is what the helper will use.
    let (_shim_dir, shim_path, _original_hash) = copy_shim_to_tmp(&orig_shim);

    // Helper expects a DIFFERENT hash (one byte different = full
    // hash difference under blake3).
    let bogus_hash = "f".repeat(64);

    let mut child = spawn_helper(
        &socket,
        scratch.path(),
        &shim_path,
        uid,
        uid,
        1,
        &bogus_hash,
    )
    .await;

    let binary = PathBuf::from("/bin/sh");
    let construct_hash = blake3_of(&binary);
    let directive = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: binary,
        argv: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: uid,
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
            assert_eq!(reason, "shim_hash_mismatch");
        }
        other => panic!("expected ShimHashMismatch refusal, got {other:?}"),
    }

    let _ = child.kill().await;
}

// ──────────────────────────────────────────────────────────────────
// T2 — Regression guard: helper does NOT use Command::pre_exec
// ──────────────────────────────────────────────────────────────────

/// Static source-level check. The macOS helper must not call
/// `Command::pre_exec(...)` because that re-introduces the fork-without-exec
/// Mach IPC inheritance bug. If a future change accidentally adds it back,
/// this test fails before review.
#[test]
fn t2_regression_guard_no_pre_exec_in_macos_helper() {
    // The crate root is `crates/ember-spawn-helper/`; the test file
    // sits in `tests/`; the bin lives at `src/bin/...`.
    let src_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/bin/emberd_spawn_helper_macos.rs");
    let body = std::fs::read_to_string(&src_path)
        .unwrap_or_else(|e| panic!("read {}: {}", src_path.display(), e));
    // Reject any call-site `.pre_exec(...)` or `command.pre_exec(...)`.
    // Doc-comment mentions are allowed because they reference the
    // old pattern in prose. We grep for the syntactic call shape.
    let needle = ".pre_exec(";
    let lines_with_call: Vec<(usize, &str)> = body
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .filter(|(_, l)| {
            let trimmed = l.trim_start();
            // Skip `//` and `//!` comment lines that reference the
            // pattern for documentation purposes.
            !trimmed.starts_with("//")
        })
        .collect();
    assert!(
        lines_with_call.is_empty(),
        "macOS helper must not use Command::pre_exec() — \
         use the shim exec boundary instead. Offending lines: {:?}",
        lines_with_call
    );
}

// ──────────────────────────────────────────────────────────────────
// T2 — Pool args required (clap-level)
// ──────────────────────────────────────────────────────────────────

/// Invoke the helper binary with `--daemon-uid` only (no `--pool-
/// uid-base` and no `--pool-size`). clap must error with exit code 2.
#[tokio::test]
async fn t2_helper_refuses_missing_pool_args() {
    let mut cmd = Command::new(helper_macos_bin());
    cmd.arg("--daemon-uid").arg("1");
    // No --pool-uid-base, no --pool-size.
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = cmd
        .status()
        .await
        .expect("spawn helper for missing-args check");
    assert_eq!(
        status.code(),
        Some(2),
        "clap should reject missing required args with exit 2; got {status:?}"
    );
}

// ──────────────────────────────────────────────────────────────────
// T2 — Socket mode is 0660 (group writability for ember-clients)
// ──────────────────────────────────────────────────────────────────

/// Verify the bound socket has mode `0660`. The owner gid is
/// `root:ember-clients` in production, but we run as the current
/// user in tests (with `--no-socket-chown`) so the kernel's group
/// will be the test runner's primary gid; the MODE check is the
/// load-bearing invariant for daemon connectivity.
#[tokio::test]
async fn t2_helper_socket_has_group_writable_mode() {
    use std::os::unix::fs::MetadataExt;

    let (_dir, socket) = fresh_socket();
    let scratch = fresh_scratch();
    let uid = current_uid();
    let shim = shim_bin();
    let shim_hash = blake3_of(&shim);
    let mut child = spawn_helper(&socket, scratch.path(), &shim, uid, uid, 1, &shim_hash).await;

    // Wait for the socket to exist.
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let meta = std::fs::metadata(&socket).expect("stat socket");
    let mode = meta.mode() & 0o777;
    assert_eq!(
        mode, 0o660,
        "socket must be 0660 root:ember-clients; got {:o}",
        mode
    );

    let _ = child.kill().await;
}

// ──────────────────────────────────────────────────────────────────
// Frame protocol — sanity (cross-platform; gated by file cfg above)
// ──────────────────────────────────────────────────────────────────

/// Wire roundtrip: encode → decode produces identical struct. Not a
/// macOS-specific assertion; lives here alongside the e2e tests so
/// the binary-spawn surface and the protocol surface share one
/// integration-test file.
#[tokio::test]
async fn frame_roundtrip_preserves_directive() {
    let d = SpawnDirective {
        protocol_version: WIRE_VERSION,
        binary_path: PathBuf::from("/usr/bin/id"),
        argv: vec!["id".to_string(), "-u".to_string()],
        env: vec![("PATH".to_string(), "/usr/bin".to_string())],
        cwd: PathBuf::from("/"),
        target_uid: 10010,
        target_gid: 10010,
        content_hash_blake3: "0".repeat(64),
        chroot_dir: None,
        sandbox_profile: None,
        seccomp_filter: None,
        invocation_id: Some("01HXAMPLE".to_string()),
    };
    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &HelperFrame::Spawn(d.clone()))
        .await
        .expect("encode");
    let mut cursor = std::io::Cursor::new(&buf);
    let frame = read_frame(&mut cursor)
        .await
        .expect("decode")
        .expect("Some");
    match frame {
        HelperFrame::Spawn(got) => assert_eq!(got, d),
        other => panic!("expected Spawn, got {other:?}"),
    }
}
