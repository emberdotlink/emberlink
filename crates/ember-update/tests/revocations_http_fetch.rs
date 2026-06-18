//! Integration test for the revocations HTTP fetch client.
//!
//! Spawns a single-shot HTTP server on `127.0.0.1:0`, returns a canned
//! signed `revocations/current.json` body, and asserts the
//! [`RevocationsFetcher`] → [`RevocationsPoller`] chain produces the
//! expected [`RevocationAction`]. Mirrors the
//! `core-broker::cloudflare` mock-server pattern (TcpListener +
//! thread) to avoid pulling a new test-dep (`wiremock`/`httpmock`)
//! into the workspace for one test file.
// CLASSIFICATION: PUBLIC

use ed25519_dalek::{SigningKey, VerifyingKey};
use ember_update::in_toto;
use ember_update::revocations::{
    RevocationAction, RevocationDocument, RevocationEntry, RevocationFetchError,
    RevocationPollError, RevocationSeverity, RevocationsFetcher, RevocationsPoller,
    revocation_statement,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fixture_keys() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::from_bytes(&[77u8; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn signed_doc(sk: &SigningKey, doc: RevocationDocument) -> String {
    let signed = in_toto::sign(revocation_statement(doc), sk).expect("sign doc");
    serde_json::to_string(&signed).expect("serialize signed doc")
}

/// Bind on 127.0.0.1:0, accept ONE connection, drain the request
/// headers, write back `canned_body` with a 200 OK status. The thread
/// joins when the test's local handle is dropped.
fn spawn_one_shot(canned_body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        // Drain request headers; body is empty for GET.
        loop {
            let mut hline = String::new();
            let n = reader.read_line(&mut hline).expect("read header");
            if n == 0 || hline.trim().is_empty() {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            canned_body.len(),
            canned_body
        );
        stream.write_all(response.as_bytes()).expect("write");
    });
    (base, handle)
}

#[tokio::test]
async fn t2_fetch_and_poll_critical_revocation_round_trip() {
    let now = now_unix();
    let (sk, vk) = fixture_keys();
    let canned = signed_doc(
        &sk,
        RevocationDocument {
            revocations: vec![RevocationEntry {
                digest: "sha256:fakecritical".to_string(),
                severity: RevocationSeverity::Critical,
                reason: "revocations HTTP fetch client fixture".to_string(),
            }],
            issued_at_unix_secs: now,
        },
    );
    let (base_url, handle) = spawn_one_shot(canned);

    let fetcher = RevocationsFetcher::with_timeout(base_url, 5).expect("build fetcher");
    let bytes = fetcher.fetch().await.expect("fetch ok");

    let poller = RevocationsPoller::with_trusted_signer(vk);
    let decisions = poller.poll(&bytes).expect("poll ok");

    assert_eq!(decisions.len(), 1, "one decision for one revocation entry");
    assert_eq!(
        decisions[0].action,
        RevocationAction::IsolateDrainKill,
        "fresh critical revocation must produce IsolateDrainKill via the HTTP path"
    );
    assert_eq!(decisions[0].entry.digest, "sha256:fakecritical");

    handle.join().expect("server thread");
}

#[tokio::test]
async fn t1_fetch_and_poll_stale_doc_fails_closed() {
    // Document issued 35 minutes ago — exceeds 30-minute stale threshold.
    // Acceptance: stale-doc detector fails closed via the HTTP fetch path,
    // not only via the in-process `evaluate()` API.
    let stale_issued_at = now_unix().saturating_sub(35 * 60);
    let (sk, vk) = fixture_keys();
    let canned = signed_doc(
        &sk,
        RevocationDocument {
            revocations: vec![RevocationEntry {
                digest: "sha256:stale".to_string(),
                severity: RevocationSeverity::Critical,
                reason: "stale-doc fail-closed test".to_string(),
            }],
            issued_at_unix_secs: stale_issued_at,
        },
    );
    let (base_url, handle) = spawn_one_shot(canned);

    let fetcher = RevocationsFetcher::with_timeout(base_url, 5).expect("build fetcher");
    let bytes = fetcher.fetch().await.expect("fetch ok");

    let poller = RevocationsPoller::with_trusted_signer(vk);
    let err = poller
        .poll(&bytes)
        .expect_err("stale signed document must fail closed");

    assert!(
        matches!(err, RevocationPollError::StaleDocument { .. }),
        "stale document via HTTP fetch must fail closed, got {err:?}"
    );

    handle.join().expect("server thread");
}

#[tokio::test]
async fn fetch_returns_status_error_for_non_2xx() {
    // Bind a one-shot server that returns 503.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        loop {
            let mut hline = String::new();
            let n = reader.read_line(&mut hline).expect("read");
            if n == 0 || hline.trim().is_empty() {
                break;
            }
        }
        let body = "endpoint down";
        let response = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).expect("write");
    });

    let fetcher = RevocationsFetcher::with_timeout(base, 5).expect("build");
    let err = fetcher.fetch().await.expect_err("expected 503 to error");
    match err {
        RevocationFetchError::Status { status, .. } => assert_eq!(status, 503),
        other => panic!("expected Status(503), got {other:?}"),
    }

    server.join().expect("server thread");
}
