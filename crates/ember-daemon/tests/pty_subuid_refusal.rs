//!
//! design Path A — broker_exec PTY + subuid combo refusal (-32031).
//!
//! ## Test scope
//!
//! These tests exercise the handler-side refusal that fires before the
//! daemon attempts to forkpty under a subuid pool. The combo is
//! structurally broken in v0.3 because `forkpty_exec_and_bridge` calls
//! `setresuid` on the host side which requires CAP_SETUID — the daemon
//! has no host CAP_SETUID under a subuid pool, and the child exits 127
//! with a cryptic stderr. Refusing cleanly at the handler boundary
//! gives the operator an actionable error instead of a post-spawn
//! mystery exit.
//!
//! Sibling-test seam: this test binary calls
//! `uid_alloc::init_subuid_pool_for_test()` to install a subuid-flagged
//! test pool in this binary's process address space. The pool's
//! `test_mode = true` bypasses the Finding-14 refusal so the test
//! process's own uid can be checked out.
//!
//! implementation-note-167 — follow-up task name for the
//! future state where PTY constructs ARE routed through the
//! user-namespace primitive; until then the refusal here is the
//! correct behavior.

#![cfg(target_os = "linux")]

use ember_daemon::broker::handler::handle_broker_exec;
use ember_daemon::broker::uid_alloc;
use ember_daemon::infra::store::DaemonStore;

/// T2 — broker_exec with `pty_socket_path = Some(_)` AND a subuid-
/// flagged global pool refuses with JSON-RPC code -32031 and a clear
/// operator-facing message naming the follow-up task.
///
/// The refusal fires BEFORE any forkpty so the daemon never enters the
/// cryptic-stderr failure mode that a real subuid + forkpty combo
/// would produce.
#[tokio::test]
async fn pty_subuid_routing_refused_with_clear_error() {
    // Install a subuid-flagged test pool. This is process-global via
    // OnceLock so it must be the first uid_pool init in this binary —
    // the integration test binary is independent from
    // `broker_exec_per_spawn_uid.rs`'s process so there's no cross-
    // binary collision.
    uid_alloc::init_subuid_pool_for_test();
    let pool = uid_alloc::global_pool().expect("subuid test pool installed");
    assert!(
        pool.is_subuid(),
        "subuid test pool must carry is_subuid=true; got is_subuid=false"
    );

    // Construct a broker_exec request with pty_socket_path set to a
    // dummy path. The refusal fires on the predicate alone — the
    // socket doesn't need to exist or be listening because the daemon
    // never reaches the forkpty step.
    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let req = serde_json::json!({
        "binary": "/usr/bin/true",
        "argv": [],
        "cwd": null,
        "env_passthrough": [],
        "pty_socket_path": "/tmp/ember-test-nonexistent-pty.sock",
    });

    let result = handle_broker_exec(None, &store, &req).await;
    let (code, msg) = result.expect_err("PTY + subuid combo must refuse");

    assert_eq!(
        code, -32031,
        "expected -32031 (PTY+subuid combo refusal), got {code}: {msg}"
    );
    assert!(
        msg.contains("PTY constructs not yet routed"),
        "error must explain PTY-not-yet-routed: got {msg}"
    );
    assert!(
        msg.contains("implementation-note-167"),
        "error must name the follow-up task: got {msg}"
    );
    assert!(
        msg.contains("non-PTY mode") || msg.contains("omit"),
        "error must surface the actionable remediation: got {msg}"
    );
}
