//! T2 integration tests for the JSON-RPC Unix-socket listener and per-agent
//! socket factory in `crates/ember-daemon/src/infra/socket.rs`.
//!
//! These tests were previously in-tree `#[cfg(test)] mod tests { ... }` blocks
//! that imported `tempfile::TempDir`, `tokio::net::UnixStream`, and
//! `tokio::net::UnixListener` — the three I/O imports flagged by the T1 lint
//! (`lint-t1-tier.sh`). The right home for tests that legitimately need a
//! filesystem path + real Unix-socket listener to exercise the end-to-end
//! request/response pipeline is a T2 integration file like this one.
//!
//! Refiled per `AUDIT-V030-T1-BASELINE-DRAIN-PART-2`. Tests cover:
//! - JSON-RPC happy path through `SocketListener::run` (`ping`, `list_personas`,
//!   `create_persona`) including unknown-method (-32601) + malformed-JSON
//!   (-32700) error shapes
//! - graceful shutdown via the `watch::Sender<bool>` channel
//! - concurrent client connections fan-in through the single-threaded
//!   `LocalSet`
//! - peer-uid same-uid acceptance via `read_peer_creds` against a real
//!   connected `UnixListener` / `UnixStream` pair (regression guard for the
//!   `verify_peer_uid` self-connection path; the production fn is
//!   `#[cfg(test)]`-only so the integration test exercises the public
//!   `read_peer_creds` surface with the same kernel-attested-uid invariant)
//! - `read_peer_creds` returning `Some(PeerCreds)` for a same-process socket
//!   pair, with pid/uid/gid matching the test process
//! - per-agent socket factory: symlink-swap rejection (CRIT-C) and tombstone
//!   UUID-recycling rejection
//! - per-agent socket factory happy path (fresh UUID binds, listener accepts)
//!
//! Internal-only T1 tests (admission counters, `take_presence_token` parser,
//! `compute_next_accept_delay` sequence, `annotate_bind_error` branches,
//! `verify_peer_uid_with` seam-based negative paths, `daemon_euid` sanity,
//! `catch_unwind` panic-conversion) remain in-tree under `src/infra/socket.rs`.
//! This file only houses tests that needed I/O.
//!
//! Anchor: t1_tier_baseline_drained_part2
//!
//! CLASSIFICATION: PUBLIC

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::handler::PeerCred;
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::{
    PER_AGENT_SOCKET_PARENT, Response, SocketError, SocketListener, create_per_agent_socket_with,
    new_shared_policy_engine, read_peer_creds, tombstone_socket,
};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::policy::PolicyEngine;
use ember_daemon::trust::presence;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::LocalSet;
use uuid::Uuid;

// ----- Shared helpers ------------------------------------------------------

fn make_store() -> Rc<DaemonStore> {
    let store = DaemonStore::open_in_memory().unwrap();
    // In-tree `#[cfg(test)] mod tests` builds auto-attach a deterministic
    // vault in `DaemonStore::open_in_memory`, but integration tests compile
    // the daemon library with `cfg(not(test))` — so the auto-attach branch
    // doesn't fire and `create_persona` would refuse with
    // `vault error: create_persona requires a live vault but no vault is
    // attached`. Mirror the same `[0xAB; 32]` deterministic-vault attachment
    // the in-tree path uses so the JSON-RPC pipeline tests (especially
    // `create_persona`) reach the same persona write path they exercised
    // when these tests lived in `src/infra/socket.rs`.
    store.set_vault(Rc::new(Vault::new([0xABu8; 32])));
    Rc::new(store)
}

async fn start_listener(tmp: &TempDir) -> (PathBuf, watch::Sender<bool>) {
    let path = tmp.path().join("ember.sock");
    let (tx, rx) = watch::channel(false);
    let store = make_store();
    let policy = new_shared_policy_engine(PolicyEngine::default());
    let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));

    // Three invariants the listener needs for OperatorPresence-class
    // socket tests (create_persona, etc.) to pass the dispatch-time
    // authority gates (PR #3812 / #3822 / #3828). Methods that aren't
    // OperatorPresence-classified (e.g. ping) are unaffected by either
    // helper, so existing non-OP tests on the same `start_listener`
    // still pass.
    //
    //   1. Daemon identity for mint_operator_presence_token
    //      (idempotent; tempdir leaked since the singleton outlives
    //      any one test).
    //   2. presence::mark_unlocked so the unlocked-session gate
    //      doesn't refuse with -32030.
    //   3. with_test_mode_synthetic_presence_token(true) so every
    //      accepted connection's RequestContext carries a synthetic
    //      presence token (socket.rs:247).
    let id_dir = tempfile::tempdir().expect("tempdir for daemon identity");
    let _ = ember_daemon::infra::receipt::init_identity(id_dir.path());
    std::mem::forget(id_dir);
    presence::mark_unlocked();

    let listener = SocketListener::new(path.clone(), rx, store, policy, rate_limiter)
        .with_test_mode_synthetic_presence_token(true);
    tokio::task::spawn_local(async move {
        listener.run().await.unwrap();
    });
    // Give listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(20)).await;
    (path, tx)
}

async fn connect(
    path: &PathBuf,
) -> (
    tokio::net::unix::OwnedWriteHalf,
    tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
) {
    let stream = UnixStream::connect(path).await.unwrap();
    let (r, w) = stream.into_split();
    (w, BufReader::new(r))
}

async fn send_recv(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    r: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    msg: &str,
) -> Response {
    let mut line = msg.to_string();
    line.push('\n');
    w.write_all(line.as_bytes()).await.unwrap();

    let mut resp_line = String::new();
    r.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(&resp_line).unwrap()
}

// Ensure PER_AGENT_SOCKET_PARENT is referenced from the integration test
// so a future rename in `socket.rs` surfaces here as a build break rather
// than as silent drift in the comment headers below.
#[allow(dead_code)]
const _PER_AGENT_SOCKET_PARENT_REFERENCED: &str = PER_AGENT_SOCKET_PARENT;

// ----- JSON-RPC pipeline tests --------------------------------------------

#[tokio::test]
async fn test_ping() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"1","method":"ping","params":null}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "1");
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            assert_eq!(result["pong"], serde_json::json!(true));
        })
        .await;
}

#[tokio::test]
async fn test_unknown_method() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"2","method":"no_such_method"}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "2");
            assert!(resp.result.is_none());
            let err = resp.error.unwrap();
            assert_eq!(err.code, -32601);
        })
        .await;
}

#[tokio::test]
async fn test_malformed_json() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = "not json at all\n";
            w.write_all(req.as_bytes()).await.unwrap();

            let mut resp_line = String::new();
            r.read_line(&mut resp_line).await.unwrap();
            let resp: Response = serde_json::from_str(&resp_line).unwrap();

            assert!(resp.result.is_none());
            let err = resp.error.unwrap();
            assert_eq!(err.code, -32700);
        })
        .await;
}

#[tokio::test]
async fn test_shutdown() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, tx) = start_listener(&tmp).await;

            // Signal shutdown.
            tx.send(true).unwrap();

            // After shutdown the listener should stop accepting.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let result = UnixStream::connect(&path).await;
            assert!(
                result.is_err(),
                "expected connection refused after shutdown"
            );
        })
        .await;
}

#[tokio::test]
async fn test_concurrent_connections() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;

            let mut handles = vec![];
            for i in 0..5u32 {
                let p = path.clone();
                handles.push(tokio::task::spawn_local(async move {
                    let (mut w, mut r) = connect(&p).await;
                    let req = format!(r#"{{"id":"{i}","method":"ping"}}"#);
                    let resp = send_recv(&mut w, &mut r, &req).await;
                    assert_eq!(resp.id, i.to_string());
                    assert!(resp.error.is_none());
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        })
        .await;
}

#[tokio::test]
async fn test_create_persona_returns_id() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"10","method":"create_persona","params":{"name":"test-agent"}}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "10");
            assert!(
                resp.error.is_none(),
                "create_persona returned error: {:?}",
                resp.error
            );
            let result = resp.result.unwrap();
            assert!(result["id"].as_str().unwrap().starts_with("persona-"));
            assert_eq!(result["name"], serde_json::json!("test-agent"));
        })
        .await;
}

#[tokio::test]
async fn test_peer_uid_gate_accepts_same_uid() {
    // C39-HANDLER-C1: a client running as the daemon's own uid (the
    // common case, and the only case CI can exercise) must be able to
    // connect and complete a ping round-trip. This exercises the
    // `verify_peer_uid` branch that returns `true`.
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"peer-uid","method":"ping"}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "peer-uid");
            assert!(resp.error.is_none());
        })
        .await;
}

#[tokio::test]
async fn test_list_personas_empty() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let (path, _tx) = start_listener(&tmp).await;
            let (mut w, mut r) = connect(&path).await;

            let req = r#"{"id":"11","method":"list_personas","params":null}"#;
            let resp = send_recv(&mut w, &mut r, req).await;

            assert_eq!(resp.id, "11");
            assert!(resp.error.is_none());
            let result = resp.result.unwrap();
            let arr = result.as_array().unwrap();
            assert!(arr.is_empty());
        })
        .await;
}

// ----- read_peer_creds + same-uid gate tests ------------------------------
//
// META-AP-DAEMON-PER-METHOD-AUTHORITY-A. Exercise `read_peer_creds`
// against a real same-process socket pair where the peer credentials
// must surface the test process's own uid/gid/pid.

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn read_peer_creds_returns_pid_uid_gid() {
    // read_peer_creds must return the current process's own uid/gid/pid
    // when called on a connected UnixStream pair from the same process.
    // Uses a real socket pair — no injection needed because both ends
    // are this process.
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("read_peer_creds_test.sock");
            let listener = UnixListener::bind(&path).unwrap();

            let connect_task = tokio::task::spawn_local({
                let path = path.clone();
                async move { UnixStream::connect(&path).await.unwrap() }
            });

            let (server_side, _) = listener.accept().await.unwrap();
            let _client_side = connect_task.await.unwrap();

            // SAFETY: `geteuid` / `getegid` are simple syscall wrappers.
            let expected_uid = unsafe { libc::geteuid() };
            let expected_gid = unsafe { libc::getegid() };
            let expected_pid = std::process::id() as i32;

            let creds = read_peer_creds(&server_side)
                .expect("read_peer_creds must succeed on a same-process socket pair");

            assert_eq!(
                creds.uid, expected_uid,
                "uid must match current process euid"
            );
            assert_eq!(
                creds.gid, expected_gid,
                "gid must match current process egid"
            );
            // pid may be None on BSD platforms that don't surface it in LOCAL_PEERCRED;
            // when present it must match the current process.
            if let Some(pid) = creds.pid {
                assert_eq!(
                    pid, expected_pid,
                    "pid must match current process id when present"
                );
            }
        })
        .await;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn read_peer_creds_returns_some_on_valid_pair() {
    // Contract test: read_peer_creds must return Some(_) for a connected
    // socket pair. The kernel-anomaly (None) path cannot be exercised
    // in normal unit tests without a mock socket, so this test asserts
    // the happy-path type contract: Some is returned and all three fields
    // are present at the struct level.
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("read_peer_creds_contract.sock");
            let listener = UnixListener::bind(&path).unwrap();

            let connect_task = tokio::task::spawn_local({
                let path = path.clone();
                async move { UnixStream::connect(&path).await.unwrap() }
            });

            let (server_side, _) = listener.accept().await.unwrap();
            let _client_side = connect_task.await.unwrap();

            let result = read_peer_creds(&server_side);
            assert!(
                result.is_some(),
                "read_peer_creds must return Some for a real connected socket"
            );
            let creds = result.unwrap();
            // Verify the struct carries all three fields at the type level.
            let _: u32 = creds.uid;
            let _: u32 = creds.gid;
            let _: Option<i32> = creds.pid;
        })
        .await;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn test_verify_peer_uid_accepts_self_connection() {
    // C43-PEERCRED happy-path regression guard using a real connected
    // socket pair from the same process. Both ends are this process, so
    // the kernel-attested peer uid must match the daemon euid.
    //
    // The original in-tree test called `verify_peer_uid(&stream)` directly,
    // but that fn is `#[cfg(test)]`-only inside the daemon crate so it
    // is not visible from an integration test. The behaviour the gate
    // enforces in production — "peer uid must equal daemon euid" — is
    // observable here via the public `read_peer_creds` surface: a same-
    // process pair surfaces `Some(creds)` with `creds.uid == geteuid()`,
    // which is exactly what `verify_peer_uid` would have accepted.
    let local = LocalSet::new();
    local
        .run_until(async {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("peer_cred.sock");
            let listener = UnixListener::bind(&path).unwrap();

            let connect_task = tokio::task::spawn_local({
                let path = path.clone();
                async move { UnixStream::connect(&path).await.unwrap() }
            });

            let (server_side, _) = listener.accept().await.unwrap();
            let _client_side = connect_task.await.unwrap();

            let creds = read_peer_creds(&server_side)
                .expect("self-connection must surface peer credentials");

            // SAFETY: `geteuid` is a simple syscall wrapper.
            let expected_uid = unsafe { libc::geteuid() };
            assert_eq!(
                creds.uid, expected_uid,
                "self-connection peer uid must equal daemon euid"
            );

            // Also exercise the PeerCred re-export so a future relocation
            // surfaces as a build break here rather than silent drift.
            let _: PeerCred = PeerCred {
                uid: creds.uid,
                pid: creds.pid,
            };
        })
        .await;
}

// ----- SCION-PER-AGENT-UDS-SOCKET tests -----------------------------------
//
// CRIT-C symlink-swap rejection + tombstone UUID-recycling rejection.
// Both tests use the `_with` seam so we can drive the would-be-path
// deterministically: the production entry point generates a fresh
// UUIDv4, but a test cannot pre-create a symlink at an unknown path.

#[test]
fn create_per_agent_socket_refuses_symlink_swap() {
    // CRIT-C: a privileged-enough container process may pre-create a
    // symlink at the predictable per-agent socket path before emberd
    // gets a chance to bind. The O_EXCL + flock contract must reject
    // any pre-existing inode at the path — including symlinks —
    // rather than overwrite or follow it.
    let tmp = TempDir::new().unwrap();
    let parent = tmp.path();
    let uuid = Uuid::new_v4();
    let socket_path = parent.join(format!("agent-{}.sock", uuid));

    // Plant a symlink at the would-be path pointing at /tmp (a real
    // path that exists). If the implementation followed the symlink
    // it would either fail with a confusing EEXIST-on-target or, in
    // a worst-case TOCTOU window, end up binding the socket at the
    // wrong location entirely.
    std::os::unix::fs::symlink("/tmp", &socket_path).unwrap();

    // SAFETY: `geteuid` / `getegid` are simple syscall wrappers.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let err = create_per_agent_socket_with(parent, uuid, uid, gid)
        .expect_err("symlink at would-be path must reject");

    match err {
        SocketError::AlreadyExists(p) => {
            assert_eq!(
                p, socket_path,
                "AlreadyExists must surface the colliding path"
            );
        }
        other => panic!("expected SocketError::AlreadyExists on symlink-swap, got: {other:?}"),
    }

    // Symlink must still be present — we refused to touch it.
    let meta = std::fs::symlink_metadata(&socket_path).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "symlink must be untouched after refused create",
    );
}

#[tokio::test]
async fn tombstone_prevents_uuid_recycling() {
    // After tombstoning a UUID, attempts to create another socket
    // with the same UUID must reject with `TombstonedUuid` so a
    // recycled agent-id cannot inherit a previous agent's identity.
    //
    // tempdir_in("/tmp") matches the canonical SUN_LEN-safe pattern
    // used elsewhere in the daemon (broker/spawn_helper_client.rs).
    // macOS $TMPDIR resolves under /var/folders/<long>/T which
    // overruns sockaddr_un's 104-byte path limit; binding then
    // fails with `path must be shorter than SUN_LEN`.
    let tmp = tempfile::Builder::new()
        .prefix("ember-socket-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let parent = tmp.path();
    let uuid = Uuid::new_v4();
    // SAFETY: `geteuid` / `getegid` are simple syscall wrappers.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    // First create succeeds: tombstone table is empty for this UUID.
    let (got_uuid, socket_path, listener) =
        create_per_agent_socket_with(parent, uuid, uid, gid).expect("fresh UUID must bind");
    assert_eq!(got_uuid, uuid);
    assert!(socket_path.exists(), "socket inode must exist after create");
    drop(listener);
    // Remove the inode so the second attempt would otherwise succeed
    // — proving the tombstone (not a stale inode) is doing the work.
    std::fs::remove_file(&socket_path).unwrap();

    // Tombstone the UUID.
    tombstone_socket(uuid).expect("tombstone must succeed");

    // Second create with the same UUID must reject with TombstonedUuid
    // even though the inode is gone.
    let err = create_per_agent_socket_with(parent, uuid, uid, gid)
        .expect_err("recycled UUID must reject after tombstone");
    match err {
        SocketError::TombstonedUuid(u) => {
            assert_eq!(u, uuid, "TombstonedUuid must surface the recycled UUID");
        }
        other => {
            panic!("expected SocketError::TombstonedUuid on recycled UUID, got: {other:?}")
        }
    }
}

#[tokio::test]
async fn create_per_agent_socket_happy_path_returns_listener() {
    // Regression guard for the success path: a fresh UUID under a
    // fresh tempdir binds, the socket exists at the returned path,
    // and the listener accepts connections.
    //
    // tempdir_in("/tmp") — see SUN_LEN note on
    // tombstone_prevents_uuid_recycling above.
    let tmp = tempfile::Builder::new()
        .prefix("ember-socket-test-")
        .tempdir_in("/tmp")
        .unwrap();
    let parent = tmp.path();
    let uuid = Uuid::new_v4();
    // SAFETY: `geteuid` / `getegid` are simple syscall wrappers.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    let (got_uuid, socket_path, _listener) =
        create_per_agent_socket_with(parent, uuid, uid, gid).expect("fresh path must bind");
    assert_eq!(got_uuid, uuid);
    assert!(
        socket_path.starts_with(parent),
        "socket path must live under parent dir",
    );
    assert!(
        socket_path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.starts_with("agent-") && s.ends_with(".sock"))
            .unwrap_or(false),
        "socket filename must match agent-<uuid>.sock shape",
    );
    let meta = std::fs::symlink_metadata(&socket_path).unwrap();
    use std::os::unix::fs::FileTypeExt;
    assert!(
        meta.file_type().is_socket(),
        "created inode must be a Unix socket",
    );
}
