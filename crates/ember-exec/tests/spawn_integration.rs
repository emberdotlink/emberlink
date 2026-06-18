//! CLASSIFICATION: PUBLIC
//!
//! SCION-EMBER-EXEC-E-MISSING-T2-TESTS: integration coverage for two
//! parent-task acceptance criteria that subtasks B/C/D shipped behavior for
//! but did not test end-to-end via `handle_spawn_directive`:
//!
//! 1. `test_setuid_drop_before_execve` — verifies the spawn flow executes
//!    the privilege-drop codepath and the child observes the expected uid.
//!    Runs as the current user (no real escalation tested), so this only
//!    exercises the syscall plumbing — the same path that fires for real
//!    in production when ember-exec runs as root.
//!
//! 2. `test_hash_mismatch_refuses_exec` — verifies a wrong
//!    `content_hash_expected` causes `handle_spawn_directive` to emit a
//!    `HashMismatch` frame and refuse to spawn the child. The "refuses to
//!    spawn" half is verified by asserting no `OutputBytes` and no `Exit`
//!    frame precede `HashMismatch`.
//!
//! Test shape and helpers parallel `spawn_pty.rs` (PR #2694): real
//! `handle_spawn_directive` invocation, `tokio::io::duplex` for the peer
//! stream, `ExecFrame` decode on the drain side.
#![cfg(unix)]

use ember_exec::spawn::handle_spawn_directive;
use ember_exec::uds::{ExecFrame, SpawnDirective, read_frame};
use std::path::PathBuf;
use tokio::io::duplex;

fn id_path() -> Option<PathBuf> {
    let candidates = ["/usr/bin/id", "/bin/id"];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn blake3_of_file(path: &std::path::Path) -> String {
    let mut f = std::fs::File::open(path).expect("open binary for hash");
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut f, &mut hasher).expect("hash binary");
    hasher.finalize().to_hex().to_string()
}

/// SCION-EMBER-EXEC-E-MISSING-T2-TESTS: dispatch a `SpawnDirective` for
/// `/usr/bin/id` and assert the child's output reports the expected uid.
/// Because the test runs as the current user with `target_uid = current
/// uid`, the privilege-drop codepath (when running as root) reduces to a
/// no-op `setresuid` to the current uid — but the `id` output proves the
/// child still observed the right uid through the spawn path.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn test_setuid_drop_before_execve() {
    let Some(id_bin) = id_path() else {
        eprintln!("test_setuid_drop_before_execve: no id binary found, skipping");
        return;
    };
    let target_uid = nix::unistd::Uid::current().as_raw();
    let target_gid = nix::unistd::Gid::current().as_raw();
    let directive = SpawnDirective {
        binary_path: id_bin.display().to_string(),
        argv: vec![],
        env_allowlist: vec![],
        credential_env: vec![],
        target_uid,
        target_gid,
        content_hash_expected: blake3_of_file(&id_bin),
    };

    let (mut peer, mut server) = duplex(64 * 1024);
    let handle = tokio::spawn(async move { handle_spawn_directive(directive, &mut server).await });

    // Drain OutputBytes frames until Exit arrives; concatenate the child's
    // stdout so we can assert the expected `uid=<n>` substring.
    let mut collected: Vec<u8> = Vec::new();
    let mut saw_exit = false;
    while let Ok(Some(frame)) = read_frame(&mut peer).await {
        match frame {
            ExecFrame::OutputBytes { bytes } => collected.extend_from_slice(&bytes),
            ExecFrame::Exit { .. } => {
                saw_exit = true;
                break;
            }
            _ => {}
        }
    }
    handle
        .await
        .expect("task join")
        .expect("handle_spawn_directive");
    let text = String::from_utf8_lossy(&collected);
    assert!(saw_exit, "expected Exit frame");
    let needle = format!("uid={target_uid}");
    assert!(
        text.contains(&needle),
        "expected '{needle}' in id(1) output, got: {text:?}"
    );
}

/// SCION-EMBER-EXEC-E-MISSING-T2-TESTS: dispatch a `SpawnDirective` with a
/// wrong `content_hash_expected`. The hash gate must close the connection
/// with a `HashMismatch` frame before any privilege drop or spawn. The
/// stricter assertion is that NO `OutputBytes` and NO `Exit` precede
/// `HashMismatch` — that is how we know the child never ran.
#[tokio::test(flavor = "multi_thread")]
async fn test_hash_mismatch_refuses_exec() {
    let Some(id_bin) = id_path() else {
        eprintln!("test_hash_mismatch_refuses_exec: no id binary found, skipping");
        return;
    };
    let target_uid = nix::unistd::Uid::current().as_raw();
    let target_gid = nix::unistd::Gid::current().as_raw();
    let directive = SpawnDirective {
        binary_path: id_bin.display().to_string(),
        argv: vec![],
        env_allowlist: vec![],
        credential_env: vec![],
        target_uid,
        target_gid,
        // 64 zero hex chars: syntactically valid blake3 but will never
        // match the real hash of /usr/bin/id.
        content_hash_expected: "0".repeat(64),
    };

    let (mut peer, mut server) = duplex(64 * 1024);
    let handle = tokio::spawn(async move { handle_spawn_directive(directive, &mut server).await });

    // The first (and only) frame must be HashMismatch. Reaching an
    // OutputBytes or Exit frame before that would prove the child spawned,
    // which is the failure mode this test guards against. The loop is
    // intentionally single-shot — every non-mismatch arm panics or breaks,
    // so allowing clippy::never_loop here preserves the assertion shape.
    let mut saw_mismatch = false;
    #[allow(clippy::never_loop)]
    while let Ok(Some(frame)) = read_frame(&mut peer).await {
        match frame {
            ExecFrame::HashMismatch { .. } => {
                saw_mismatch = true;
                break;
            }
            ExecFrame::OutputBytes { .. } => {
                panic!(
                    "OutputBytes frame arrived before HashMismatch — child spawned despite bad hash"
                );
            }
            ExecFrame::Exit { .. } => {
                panic!("Exit frame arrived before HashMismatch — child spawned despite bad hash");
            }
            other => {
                panic!("unexpected frame before HashMismatch: {other:?}");
            }
        }
    }
    handle
        .await
        .expect("task join")
        .expect("handle_spawn_directive");
    assert!(saw_mismatch, "expected HashMismatch frame");
}
