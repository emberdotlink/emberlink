//! CLASSIFICATION: PUBLIC
//!
//! SCION-EMBER-EXEC-D-PTY-WIRE: integration tests for `handle_spawn_directive`
//! routed through the real pty pump (`pump_connection`) instead of a plain
//! piped `Command`.
//!
//! Three scenarios exercise the trust-boundary loop:
//!
//! 1. `test_exit_code_via_pty` — pty path emits the child's exit code as an
//!    `ExecFrame::Exit { code }` after a bash `exit 37`. Replaces subtask C's
//!    `handle_spawn_directive_runs_and_emits_exit` (which used the simple
//!    `Command` path).
//!
//! 2. `test_stdin_proxied_through_pty` — `StdinBytes` frames from the peer
//!    reach the child via the pty master, and the child's echo surfaces as
//!    `OutputBytes` frames.
//!
//! 3. `test_resize_propagated` — `Resize` frames from the peer reach the pty
//!    master via `TIOCSWINSZ` before stdin, and the child's `stty size`
//!    observes the new geometry in its `OutputBytes`.
#![cfg(target_os = "linux")]

use ember_exec::spawn::handle_spawn_directive;
use ember_exec::uds::{ExecFrame, SpawnDirective, read_frame, write_frame};
use tokio::io::duplex;

fn sh_path() -> Option<&'static str> {
    let candidates = ["/bin/bash", "/usr/bin/bash"];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Some(*c);
        }
    }
    None
}

fn blake3_of_file(path: &str) -> String {
    let mut f = std::fs::File::open(path).expect("open sh");
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut f, &mut hasher).expect("hash sh");
    hasher.finalize().to_hex().to_string()
}

fn build_directive(binary_path: &str, argv: Vec<String>) -> SpawnDirective {
    SpawnDirective {
        binary_path: binary_path.to_string(),
        argv,
        env_allowlist: vec![],
        credential_env: vec![],
        target_uid: nix::unistd::getuid().as_raw(),
        target_gid: nix::unistd::getgid().as_raw(),
        content_hash_expected: blake3_of_file(binary_path),
    }
}

/// SCION-EMBER-EXEC-D-PTY-WIRE: bash exits 37 via the pty pump; the wire-side
/// peer must see `Exit { code: 37 }`.
#[tokio::test(flavor = "multi_thread")]
async fn test_exit_code_via_pty() {
    let Some(bash) = sh_path() else {
        eprintln!("test_exit_code_via_pty: no bash found, skipping");
        return;
    };
    let directive = build_directive(
        bash,
        vec!["bash".to_string(), "-c".to_string(), "exit 37".to_string()],
    );

    // Server side: the in-flight stream `handle_spawn_directive` reads from
    // (peer-emitted frames) and writes to (child output / exit). The peer
    // half is the test driver.
    let (mut peer, mut server) = duplex(64 * 1024);
    let handle = tokio::spawn(async move { handle_spawn_directive(directive, &mut server).await });

    // Drain frames from the peer side until we see Exit.
    let mut saw_exit = None;
    while let Ok(Some(frame)) = read_frame(&mut peer).await {
        if let ExecFrame::Exit { code } = frame {
            saw_exit = Some(code);
            break;
        }
    }
    handle
        .await
        .expect("task join")
        .expect("handle_spawn_directive");
    assert_eq!(saw_exit, Some(37), "expected Exit(37), got {saw_exit:?}");
}

/// SCION-EMBER-EXEC-D-PTY-WIRE: stdin bytes the peer sends must route through
/// the pty master to the child; the child's echo must surface as
/// `OutputBytes` frames.
#[tokio::test(flavor = "multi_thread")]
async fn test_stdin_proxied_through_pty() {
    let Some(bash) = sh_path() else {
        eprintln!("test_stdin_proxied_through_pty: no bash found, skipping");
        return;
    };
    let directive = build_directive(
        bash,
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "read x; echo got=$x".to_string(),
        ],
    );

    let (mut peer, mut server) = duplex(64 * 1024);
    let handle = tokio::spawn(async move { handle_spawn_directive(directive, &mut server).await });

    // Send a StdinBytes frame so `read x` completes.
    write_frame(
        &mut peer,
        &ExecFrame::StdinBytes {
            bytes: b"hello\n".to_vec(),
        },
    )
    .await
    .expect("write StdinBytes");

    // Collect output frames until Exit.
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
    assert!(
        text.contains("got=hello"),
        "expected 'got=hello' in pty output, got: {text:?}"
    );
}

/// SCION-EMBER-EXEC-D-PTY-WIRE: a `Resize` frame the peer sends must apply
/// `TIOCSWINSZ` to the pty master before the child runs `stty size`, so the
/// child reads the new geometry.
#[tokio::test(flavor = "multi_thread")]
async fn test_resize_propagated() {
    let Some(bash) = sh_path() else {
        eprintln!("test_resize_propagated: no bash found, skipping");
        return;
    };
    let directive = build_directive(
        bash,
        vec![
            "bash".to_string(),
            "-c".to_string(),
            // Wait briefly so the resize frame applies before stty runs.
            "sleep 0.1; stty size; read".to_string(),
        ],
    );

    let (mut peer, mut server) = duplex(64 * 1024);
    let handle = tokio::spawn(async move { handle_spawn_directive(directive, &mut server).await });

    // Send Resize first.
    write_frame(
        &mut peer,
        &ExecFrame::Resize {
            rows: 42,
            cols: 100,
        },
    )
    .await
    .expect("write Resize");

    // Send a newline so the `read` completes and the child exits.
    // Use a small delay so the resize takes effect before stty runs.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    write_frame(
        &mut peer,
        &ExecFrame::StdinBytes {
            bytes: b"\n".to_vec(),
        },
    )
    .await
    .expect("write StdinBytes newline");

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
    assert!(
        text.contains("42 100"),
        "expected '42 100' in stty size output, got: {text:?}"
    );
}
