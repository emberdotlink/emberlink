//! SCION-EMBER-EXEC-G-EMBERD-SPAWN-SENDER — T2 round-trip test for the
//! emberd-side `send_spawn_directive` sender.
//!
//! Stands up a mock `ember-exec` listener on a tempfile UDS, calls
//! `send_spawn_directive` from the test, and asserts:
//!
//! 1. The mock listener decoded a `SpawnDirective` matching every field
//!    of the input (binary_path, argv, env_allowlist, credential_env,
//!    target_uid, target_gid, content_hash_expected).
//! 2. The returned `UnixStream` is still open + writable (the test
//!    writes a trailing no-op byte after the frame, and flush succeeds).
//! 3. No extra bytes appear on the wire beyond the encoded frame the
//!    test wrote (the no-op trailer is consumed separately by the
//!    listener's drain).
//!
//! Subtask C's `handle_spawn_directive` (already shipped in PR #2681)
//! consumes the same wire shape on the in-container side — this test
//! exercises only the emberd half of the contract.

#![cfg(unix)]

use std::time::Duration;

use ember_daemon::spawn::scion::send_spawn_directive;
use ember_exec::uds::{ExecFrame, SpawnDirective, read_frame};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

#[tokio::test]
async fn test_send_spawn_directive_round_trip() {
    // Stage a tempfile UDS as the mock ember-exec listener. The path
    // lives under TempDir so the test cleans up regardless of pass/fail.
    let tmp = TempDir::new().expect("tempdir");
    let socket_path = tmp.path().join("mock-ember-exec.sock");

    let listener = UnixListener::bind(&socket_path).expect("bind UDS");

    // Build a known SpawnDirective. Every field is distinct so a
    // serialiser drift in any one is caught by the field-by-field
    // assertions below.
    let directive = SpawnDirective {
        binary_path: "/usr/local/bin/scion-test-binary".to_string(),
        argv: vec![
            "scion-test-binary".to_string(),
            "--foo".to_string(),
            "bar".to_string(),
        ],
        env_allowlist: vec!["PATH".to_string(), "HOME".to_string()],
        credential_env: vec![
            (
                "GITHUB_TOKEN".to_string(),
                "ghs_test_token_value".to_string(),
            ),
            (
                "AWS_SESSION_TOKEN".to_string(),
                "aws_test_sts_token".to_string(),
            ),
        ],
        target_uid: 1234,
        target_gid: 5678,
        content_hash_expected: "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d"
            .to_string(),
    };

    // Spawn the mock accept loop. It accepts one connection, reads
    // exactly one ExecFrame::SpawnDirective, then drains until EOF and
    // returns what it saw. The drain captures any extra trailing bytes
    // so the test can assert "exactly one frame + the test-side
    // trailer."
    let expected_directive = directive.clone();
    let mock_handle = tokio::spawn(async move {
        let (mut stream, _addr) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept failed");

        // Read exactly one frame — must be SpawnDirective.
        let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
            .await
            .expect("read_frame timeout")
            .expect("read_frame io error")
            .expect("read_frame returned None at EOF");

        let got_directive = match frame {
            ExecFrame::SpawnDirective(d) => d,
            other => panic!("expected SpawnDirective, got {other:?}"),
        };
        assert_eq!(got_directive, expected_directive);

        // Drain remaining bytes. The test side writes a single trailer
        // byte after the frame to prove the returned stream is still
        // writable; that byte arrives here.
        use tokio::io::AsyncReadExt as _;
        let mut trailer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut trailer))
            .await
            .expect("drain timeout");
        trailer
    });

    // Call the emberd-side sender. Returns the open UnixStream after
    // the handshake frame is flushed.
    let mut stream = send_spawn_directive(&socket_path, directive)
        .await
        .expect("send_spawn_directive should succeed");

    // Prove the returned stream is still open + writable: write one
    // trailer byte and flush. If the connection were closed, write_all
    // would error with BrokenPipe.
    stream.write_all(&[0x42]).await.expect("trailer write_all");
    stream.flush().await.expect("trailer flush");
    drop(stream); // EOF the connection so the mock drain returns

    // Reap the mock; assert the trailer arrived intact and the only
    // post-frame byte on the wire is the test-side trailer.
    let trailer = tokio::time::timeout(Duration::from_secs(5), mock_handle)
        .await
        .expect("mock task timeout")
        .expect("mock task panicked");
    assert_eq!(
        trailer,
        vec![0x42],
        "expected exactly one trailer byte; got {trailer:?}",
    );
}

#[tokio::test]
async fn test_send_spawn_directive_refuses_nonexistent_socket() {
    // Path validation must fire BEFORE connect — a dangling path
    // produces ExecSocketInvalid (typed error), NOT a vague
    // ECONNREFUSED. This is the trust-boundary invariant: the daemon
    // must never send credentials to an unverified inode.
    let tmp = TempDir::new().expect("tempdir");
    let missing = tmp.path().join("does-not-exist.sock");

    let directive = SpawnDirective {
        binary_path: "/bin/sh".to_string(),
        argv: vec!["sh".to_string()],
        env_allowlist: vec![],
        credential_env: vec![],
        target_uid: 0,
        target_gid: 0,
        content_hash_expected: "0".repeat(64),
    };
    let err = send_spawn_directive(&missing, directive)
        .await
        .expect_err("nonexistent socket must refuse");
    let msg = format!("{err}");
    assert!(
        msg.contains("invalid"),
        "expected ExecSocketInvalid-shaped error; got {msg:?}",
    );
}

#[tokio::test]
async fn test_send_spawn_directive_refuses_non_socket_path() {
    // A regular file at the configured path is NOT a UDS — the
    // validation gate must reject it before connect.
    let tmp = TempDir::new().expect("tempdir");
    let regular = tmp.path().join("not-a-socket.txt");
    std::fs::write(&regular, b"definitely not a socket").expect("write file");

    let directive = SpawnDirective {
        binary_path: "/bin/sh".to_string(),
        argv: vec!["sh".to_string()],
        env_allowlist: vec![],
        credential_env: vec![],
        target_uid: 0,
        target_gid: 0,
        content_hash_expected: "0".repeat(64),
    };
    let err = send_spawn_directive(&regular, directive)
        .await
        .expect_err("regular file at socket path must refuse");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a unix-domain socket") || msg.contains("invalid"),
        "expected ExecSocketInvalid-shaped error; got {msg:?}",
    );
}
