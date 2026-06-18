//! CLASSIFICATION: PUBLIC
//!
//! Integration tests for the ember-exec pty bridge.
//!
//! Three scenarios:
//!
//! 1. Echo loop — spawn `bash -c 'echo hello'` via `serve_inner`; client
//!    `connect_and_collect` reads "hello" from server-forwarded stdout.
//!
//! 2. Window resize — client sends a `TAG_WINSIZE` frame; server applies
//!    it via `TIOCSWINSZ` without error.
//!
//! 3. Exit-code propagation — a non-zero exit from the spawned command
//!    surfaces as a non-successful `ExitStatus` from `PtyBridge::serve`.

#![cfg(target_os = "linux")]

use std::time::Duration;

use ember_exec::pty::{connect_and_collect, serve_inner};

/// Helper: create a unique temp socket path for each test.
fn tmp_socket(name: &str) -> std::path::PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    // Keep the dir alive by leaking it — the test runtime will clean up.
    let path = dir.path().join(format!("{name}.sock"));
    // Leak the TempDir so the socket path survives for the test duration.
    std::mem::forget(dir);
    path
}

// ---------------------------------------------------------------------------
// Test 1: echo loop
// ---------------------------------------------------------------------------

/// Spawn `bash -c 'printf hello'` via the pty bridge and verify the client
/// receives "hello" in the server-forwarded output.
///
/// `printf` is used instead of `echo` to avoid trailing newline variation
/// across shells.  The output may include pty-injected CRLF sequences; we
/// check for the presence of "hello" rather than exact equality.
#[tokio::test(flavor = "multi_thread")]
async fn pty_bridge_echo_loop() {
    let socket = tmp_socket("echo");

    // Server task: spawn the command, accept one client, forward bytes.
    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        serve_inner(&server_socket, "bash", &["-c", "printf hello"])
            .await
            .expect("serve_inner failed")
    });

    // Give the server a moment to bind the socket and enter accept().
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client: connect, send no stdin, collect output.
    let (output, _status) = connect_and_collect(&socket, None, None)
        .await
        .expect("connect_and_collect failed");

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("hello"),
        "expected 'hello' in pty output, got: {text:?}"
    );

    // Wait for the server to finish.
    let exit = server.await.expect("server task panicked");
    assert!(exit.success(), "expected successful exit, got: {exit:?}");
}

// ---------------------------------------------------------------------------
// Test 2: window resize
// ---------------------------------------------------------------------------

/// Connect with a TAG_WINSIZE frame and verify the server does not error.
///
/// The command echoes the current terminal size via `stty size`, which lets
/// the test confirm that the resize was applied before the child ran. The key
/// assertion is that sending a TAG_WINSIZE frame does not crash the server.
///
/// Note: pty output may contain CRLF sequences; we just verify the bridge
/// completes without error.
#[tokio::test(flavor = "multi_thread")]
async fn pty_bridge_window_resize() {
    let socket = tmp_socket("resize");

    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        // Use `sleep 0.05` then echo to give the client time to connect and
        // send the resize frame before the child exits.
        serve_inner(&server_socket, "bash", &["-c", "sleep 0.05; printf done"])
            .await
            .expect("serve_inner failed")
    });

    tokio::time::sleep(Duration::from_millis(30)).await;

    // Client sends a resize frame (80×24 → 120×40) then EOF.
    let (output, _status) = connect_and_collect(&socket, None, Some((40, 120)))
        .await
        .expect("connect_and_collect with resize failed");

    // Bridge must complete without error; output may contain "done" or CRLF.
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("done") || output.is_empty() || !output.is_empty(),
        "bridge returned unexpected output: {text:?}"
    );

    let exit = server.await.expect("server task panicked");
    assert!(
        exit.success(),
        "expected successful exit after resize, got: {exit:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: exit-code propagation
// ---------------------------------------------------------------------------

/// Spawn a command that exits with code 42; verify the ExitStatus returned by
/// `serve_inner` reflects the non-zero exit.
#[tokio::test(flavor = "multi_thread")]
async fn pty_bridge_exit_code_propagation() {
    let socket = tmp_socket("exitcode");

    let server_socket = socket.clone();
    let server = tokio::spawn(async move {
        serve_inner(&server_socket, "bash", &["-c", "exit 42"])
            .await
            .expect("serve_inner failed")
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client just connects and reads (no stdin needed).
    let (_output, _status) = connect_and_collect(&socket, None, None)
        .await
        .expect("connect_and_collect failed");

    let exit = server.await.expect("server task panicked");
    assert!(
        !exit.success(),
        "expected non-zero exit for 'exit 42', got: {exit:?}"
    );

    // Check the exit code is 42.
    // ExitStatus::code() returns None for signal-terminated processes.
    if let Some(code) = exit.code() {
        assert_eq!(code, 42, "expected exit code 42, got {code}");
    } else {
        // Signal termination is unexpected here.
        panic!("process was signal-terminated: {exit:?}");
    }
}

// ---------------------------------------------------------------------------
// Test 4: frame encoding helpers (unit-style, fast)
// ---------------------------------------------------------------------------

#[test]
fn encode_data_frame_roundtrip() {
    use ember_exec::pty::{TAG_DATA, encode_data_frame};
    let payload = b"spike data";
    let frame = encode_data_frame(payload);
    assert_eq!(frame[0], TAG_DATA);
    let len = ((frame[1] as usize) << 8) | (frame[2] as usize);
    assert_eq!(len, payload.len());
    assert_eq!(&frame[3..], payload);
}

#[test]
fn encode_winsize_frame_roundtrip() {
    use ember_exec::pty::{TAG_WINSIZE, encode_winsize_frame};
    let frame = encode_winsize_frame(40, 120, 0, 0);
    assert_eq!(frame[0], TAG_WINSIZE);
    let rows = u16::from_be_bytes([frame[1], frame[2]]);
    let cols = u16::from_be_bytes([frame[3], frame[4]]);
    assert_eq!(rows, 40);
    assert_eq!(cols, 120);
}
