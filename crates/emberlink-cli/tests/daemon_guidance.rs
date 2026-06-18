//! T2 integration coverage for shared daemon-guidance mapping.
//!
//! Exercises `emberlink_cli::call_daemon_method` against a fake Unix socket
//! daemon so the library is compiled in normal mode (`cfg(not(test))` for the
//! library itself). This pins the operator-facing contract for a locked vault.
//!
//! ADR 206 slice 4 C retired the forgeable native/managed vault-unlock ceremony
//! (and the client-side auto-unlock retry). So:
//!
//! - the RPC returns a locked-session daemon error
//! - `call_daemon_method` does NOT retry with `vault_unlock_begin` — it surfaces
//!   the daemon's guidance directly
//! - the surfaced `ValidationError` must contain guidance, not the raw daemon
//!   payload

use std::io::{BufRead, Write as _};
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::Duration;

fn accept_with_timeout(
    listener: &UnixListener,
    timeout: Duration,
) -> std::os::unix::net::UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking on listener");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("restore blocking on accepted stream");
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    panic!("listener.accept() timed out after {timeout:?}");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("listener.accept() error: {e}"),
        }
    }
}

#[test]
fn call_daemon_method_locked_vault_surfaces_guidance_without_retry() {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let socket_path = tmp.path().join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            // ADR 206 slice 4 C: exactly ONE request — the client no longer
            // retries with `vault_unlock_begin`. The locked-vault error is
            // surfaced as guidance directly.
            let mut stream = accept_with_timeout(&listener, Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("create_persona"));

            let response = serde_json::json!({
                "id": request["id"],
                "error": {
                    "code": -32030,
                    "message": "create_persona denied: session is locked; same-daemon operator-uid reopen is disabled to avoid legacy login-keychain prompts. Supported lanes: managed separate-uid biometric unlock (`vault_unlock_begin/vault_unlock_complete`), a fresh daemon bootstrap via `EMBER_VAULT_PASSPHRASE` for dev probes, or future broker-mediated browser auth",
                }
            });

            let mut encoded =
                serde_json::to_string(&response).expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let err = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": "needs-guidance"}),
    )
    .expect_err("locked vault should surface guidance");

    let msg = err.to_string();
    assert!(
        msg.contains("operator presence"),
        "expected operator-presence guidance, got: {msg}"
    );
    assert!(
        msg.contains("managed separate-uid biometric unlock"),
        "expected unlock hint, got: {msg}"
    );
    assert!(
        msg.contains("EMBER_VAULT_PASSPHRASE"),
        "expected bootstrap hint, got: {msg}"
    );

    server.join().expect("fake daemon thread");
}
