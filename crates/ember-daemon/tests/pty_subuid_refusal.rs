//! CLASSIFICATION: PUBLIC
//!
//! ADR 155 Path A — broker_exec PTY + subuid combo refusal (-32031).
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
//! META-EXEC-DOMAIN-PTY-SUBUID-ROUTING — follow-up task name for the
//! future state where PTY constructs ARE routed through the
//! user-namespace primitive; until then the refusal here is the
//! correct behavior.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use core_event_types::{ActionRef, ExecutionContract};
use ember_daemon::broker::handler::handle_broker_exec;
use ember_daemon::broker::uid_alloc;
use ember_daemon::infra::store::DaemonStore;
use uuid::Uuid;

fn write_runner_manifest(home: &Path, tool_name: &str, binary_path: &Path) -> PathBuf {
    let manifest_dir = home.join(".ember/binaries");
    std::fs::create_dir_all(&manifest_dir).expect("mkdir manifest dir");
    let manifest_path = manifest_dir.join("manifest.toml");
    let manifest_body = format!(
        "\
[[entries]]
tool_name = \"{tool_name}\"
version = \"1.0.0\"
content_hash = \"blake3:test\"
absolute_path = \"{}\"
installed_at = 1735689600
publisher = \"did:emberlink\"
channel = \"bundled\"
",
        binary_path.display()
    );
    std::fs::write(&manifest_path, manifest_body).expect("write runner manifest");
    manifest_path
}

fn write_managed_worktree(home: &Path, runtime_id: &str) -> PathBuf {
    let worktree_path = home.join("repo/.ember/worktrees/demo");
    std::fs::create_dir_all(worktree_path.join(".git")).expect("mkdir worktree git dir");
    std::fs::write(
        worktree_path.join(".agent-session"),
        format!(
            "runtime_id: {runtime_id}\nworktree_path: {}\n",
            worktree_path.display()
        ),
    )
    .expect("write managed worktree metadata");
    worktree_path
}

struct HomeGuard {
    previous_home: Option<std::ffi::OsString>,
    previous_manifest_path: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn set(home: &Path, manifest_path: &Path) -> Self {
        let previous_home = std::env::var_os("HOME");
        let previous_manifest_path = std::env::var_os("EMBER_MANIFEST_PATH");
        unsafe {
            std::env::set_var("HOME", home);
            std::env::set_var("EMBER_MANIFEST_PATH", manifest_path);
        }
        Self {
            previous_home,
            previous_manifest_path,
        }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        match self.previous_home.take() {
            Some(home) => unsafe {
                std::env::set_var("HOME", home);
            },
            None => unsafe {
                std::env::remove_var("HOME");
            },
        }
        match self.previous_manifest_path.take() {
            Some(path) => unsafe {
                std::env::set_var("EMBER_MANIFEST_PATH", path);
            },
            None => unsafe {
                std::env::remove_var("EMBER_MANIFEST_PATH");
            },
        }
    }
}

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
    let home = tempfile::tempdir().expect("tempdir");
    let fake_gh = home.path().join("bin/ember-gh");
    std::fs::create_dir_all(fake_gh.parent().expect("parent")).expect("mkdir bin dir");
    if std::os::unix::fs::symlink("/usr/bin/true", &fake_gh).is_err() {
        std::fs::write(&fake_gh, b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n").expect("write fake gh");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&fake_gh).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_gh, perms).expect("chmod fake gh");
    }
    let manifest_path = write_runner_manifest(home.path(), "ember-gh", &fake_gh);
    let _home_guard = HomeGuard::set(home.path(), &manifest_path);
    let runtime_id = format!("rt-{}", Uuid::new_v4().simple());
    write_managed_worktree(home.path(), &runtime_id);

    let store = DaemonStore::open_in_memory().expect("in-memory store");
    let action_ref = ActionRef::new(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_merge",
        "v1",
    );
    let workspace_ref = format!("managed_worktree:{runtime_id}");
    let mut execution_contract = ExecutionContract::new(action_ref.clone());
    execution_contract.workspace_ref = Some(workspace_ref.clone());
    let req = serde_json::json!({
        "execution_contract": execution_contract,
        "argv": ["pr", "merge", "123"],
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
        msg.contains("META-EXEC-DOMAIN-PTY-SUBUID-ROUTING"),
        "error must name the follow-up task: got {msg}"
    );
    assert!(
        msg.contains("non-PTY mode") || msg.contains("omit"),
        "error must surface the actionable remediation: got {msg}"
    );
}
