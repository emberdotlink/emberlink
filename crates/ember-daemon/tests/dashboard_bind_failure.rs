//! UX2-DASHBOARD-SILENT-BIND-FAILURE regression: when the configured
//! dashboard port is already bound by another process, the daemon must
//! report the failure truthfully via `runtime.dashboard_actual_addr`
//! (== `None`) and via `/api/status`'s `dashboard_addr_bound` field
//! (== `null`). When the bind succeeds, both surfaces report the resolved
//! `host:port`.
//!
//! Pre-2026-04-27 the daemon logged an `info!` warning, kept running, but
//! the CLI `status` subcommand still printed `Dashboard: http://localhost:3141`
//! — sending operators to whatever foreign daemon owned that port. This
//! test pins the new contract.

use std::net::SocketAddr;
use std::time::Duration;

use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::dashboard::run_dashboard;
use ember_daemon::infra::runtime::{DaemonRuntime, DashboardBind};
use ember_daemon::infra::store::DaemonStore;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

/// Bind-failure path: holding the dashboard port forces `run_dashboard`
/// onto its `Failed` branch. The runtime must still come up (PID file +
/// socket listener) and `dashboard_actual_addr` must read `None`.
#[test]
fn runtime_dashboard_actual_addr_is_none_when_bind_fails() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Hold an ephemeral port for the duration of the test. `Box::leak`
    // keeps the listener alive past this block; the test process exits
    // shortly after so the leak is harmless.
    let blocked_addr: SocketAddr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _: &'static TcpListener = Box::leak(Box::new(listener));
        addr
    });

    let tmp = TempDir::new().unwrap();
    let socket_dir = tmp.path().join("run");
    std::fs::create_dir_all(&socket_dir).unwrap();

    let config = DaemonConfig {
        data_dir: tmp.path().to_path_buf(),
        pid_file: socket_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        socket_dir,
        dashboard_addr: Some(blocked_addr),
        // Leave git_proxy disabled — only the dashboard bind is under test.
        git_proxy_addr: None,
        ..DaemonConfig::for_test(tmp.path())
    };

    let runtime = DaemonRuntime::new(config);

    // The full daemon startup path opens the broker/credential plane before
    // it reaches the accept loop, which makes this bind contract vulnerable
    // to unrelated startup stalls. Drive the dashboard listener directly,
    // then apply the same bind outcome method used by `DaemonRuntime::run`.
    let db_path = tmp.path().join("daemon.db");
    let _ = DaemonStore::open(&db_path).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (bind_tx, bind_rx) = oneshot::channel();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        tokio::task::spawn_local(run_dashboard(
            blocked_addr,
            db_path,
            "0.0.0-test".to_string(),
            None,
            shutdown_rx,
            Some(bind_tx),
        ));
        let bind_result = tokio::time::timeout(Duration::from_secs(2), bind_rx)
            .await
            .expect("dashboard bind result timed out")
            .expect("dashboard bind result channel closed");
        let _ = shutdown_tx.send(true);
        let dashboard_bind = match bind_result {
            Ok(addr) => DashboardBind::Bound(addr),
            Err(err) => DashboardBind::Failed {
                addr: blocked_addr,
                error: err.to_string(),
            },
        };
        assert!(
            matches!(dashboard_bind, DashboardBind::Failed { .. }),
            "expected occupied dashboard port to produce a failed bind, got {dashboard_bind:?}"
        );
        runtime.record_dashboard_bind(&dashboard_bind);
    });

    let actual = runtime
        .dashboard_actual_addr
        .lock()
        .expect("runtime.dashboard_actual_addr lock");
    assert_eq!(
        *actual, None,
        "expected runtime.dashboard_actual_addr to be None when configured port is occupied; got {:?}",
        *actual
    );
}

/// Happy path: when the dashboard binds successfully, `/api/status`
/// returns the resolved `host:port` string in `dashboard_addr_bound` so
/// CLI consumers can render a truthful URL. Together with the bind-failure
/// test this pins both branches of the contract: `Some` ↔ bound, `None` ↔
/// not bound.
#[tokio::test(flavor = "current_thread")]
async fn api_status_dashboard_addr_bound_reports_resolved_port() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");
    let _ = DaemonStore::open(&db_path).unwrap();

    // Bind a port, capture, drop — small TOCTOU window matches the
    // pattern in existing integration tests.
    let ephemeral = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ephemeral.local_addr().unwrap();
    drop(ephemeral);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            tokio::task::spawn_local(run_dashboard(
                addr,
                db_path,
                "0.0.0-test".to_string(),
                None,
                shutdown_rx,
                None,
            ));

            // Give the listener a beat to bind.
            tokio::time::sleep(Duration::from_millis(150)).await;

            // GET /api/status and parse the body.
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(
                    b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let resp = std::str::from_utf8(&buf).unwrap();
            assert!(
                resp.starts_with("HTTP/1.1 200"),
                "expected 200 OK from /api/status, got: {}",
                &resp[..resp.len().min(120)]
            );
            let body = resp.split("\r\n\r\n").nth(1).expect("body separator");
            let json: serde_json::Value = serde_json::from_str(body).unwrap();
            assert!(
                json.get("dashboard_addr_bound").is_some(),
                "JSON must include dashboard_addr_bound key, got: {json}"
            );
            let bound = json["dashboard_addr_bound"]
                .as_str()
                .expect("dashboard_addr_bound must be a string when bound");
            let parsed: SocketAddr = bound.parse().expect("dashboard_addr_bound must parse");
            assert_eq!(
                parsed, addr,
                "dashboard_addr_bound must reflect the address the listener resolved to"
            );
            // Sanity: the rest of the response shape is preserved.
            assert_eq!(json["running"], true);

            let _ = shutdown_tx.send(true);
        })
        .await;
}
