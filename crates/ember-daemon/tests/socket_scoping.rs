//! CLASSIFICATION: PUBLIC
//!
//! META-T3-USER-SOCKET-LEAK-GUARD subtask A — positive test that
//! `DaemonConfig::for_test(&tmpdir)` scopes every path-bearing field
//! under `tmpdir`, so a T3 test cannot accidentally bind the operator's
//! real `~/.ember/run/daemon.sock`.
//!
//! Scar: 2026-05-12 leaked T3 test daemon PID 89035 ran for 25+ hours
//! bound to the user's real socket; root cause was the `Default` impl
//! returning user-home paths under `..Default::default()` partial-
//! override syntax. This test pins the substrate that closes that
//! failure mode at the type level (full closure ships with subtask B's
//! Default-removal + caller migration).

use ember_daemon::infra::config::DaemonConfig;

#[test]
fn for_test_scopes_all_paths_under_tmpdir() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let cfg = DaemonConfig::for_test(tmp.path());

    for (name, p) in [
        ("socket_dir", &cfg.socket_dir),
        ("data_dir", &cfg.data_dir),
        ("pid_file", &cfg.pid_file),
        ("policy_file", &cfg.policy_file),
    ] {
        assert!(
            p.starts_with(tmp.path()),
            "{name} {} not under tmpdir {}",
            p.display(),
            tmp.path().display()
        );
    }
}

#[test]
fn for_test_disables_dashboard_and_proxies_by_default() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let cfg = DaemonConfig::for_test(tmp.path());
    assert!(
        cfg.dashboard_addr.is_none(),
        "for_test must disable dashboard"
    );
    assert!(
        cfg.git_proxy_addr.is_none(),
        "for_test must disable git proxy"
    );
    assert!(
        cfg.llm_proxy_addr.is_none(),
        "for_test must disable llm proxy"
    );
}
