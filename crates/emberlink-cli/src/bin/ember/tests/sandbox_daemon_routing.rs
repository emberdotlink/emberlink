use super::*;

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_create_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_create"));
            assert_eq!(request["params"]["name"], serde_json::json!("codebox"));
            assert_eq!(
                request["params"]["image"],
                serde_json::json!("ubuntu:24.04")
            );
            assert_eq!(
                request["params"]["workspace_from"],
                serde_json::json!("https://example.test/repo.git")
            );
            assert_eq!(
                request["params"]["extra_env"],
                serde_json::json!([["FOO", "bar"]])
            );
            assert_eq!(
                request["params"]["owner_persona_id"],
                serde_json::json!("persona-owner")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "sandbox": {
                        "id": "sandbox-123",
                        "name": "codebox",
                        "persona_id": "persona-sandbox",
                        "owner_persona_id": "persona-owner",
                        "container_id": null,
                        "image": "ubuntu:24.04",
                        "status": "created",
                        "created_at": "2026-05-18T00:00:00Z",
                        "workspace_path": "/tmp/ws"
                    },
                    "container_id": "container-123",
                    "start_error": null
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let opts = SandboxCreateOpts {
        name: "codebox".to_string(),
        image: "ubuntu:24.04".to_string(),
        workspace_from: Some("https://example.test/repo.git".to_string()),
        extra_env: vec![("FOO".to_string(), "bar".to_string())],
        owner_persona_id: Some("persona-owner".to_string()),
        ..SandboxCreateOpts::default()
    };
    let (dispatch, created) = run_sandbox_create(&config, &opts).expect("sandbox create");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(created.sandbox.id, "sandbox-123");
    assert_eq!(created.container_id.as_deref(), Some("container-123"));
    server.join().expect("fake daemon thread");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_list_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_list"));

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": [{
                    "id": "sandbox-1",
                    "name": "alpha",
                    "persona_id": "persona-a",
                    "owner_persona_id": "persona-owner",
                    "container_id": "container-a",
                    "image": "ubuntu:24.04",
                    "status": "running",
                    "created_at": "2026-05-18T00:00:00Z",
                    "workspace_path": null
                }],
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, sandboxes) = run_sandbox_list(&config).expect("sandbox list");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(sandboxes.len(), 1);
    assert_eq!(sandboxes[0].name, "alpha");
    server.join().expect("fake daemon thread");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_stop_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_stop"));
            assert_eq!(
                request["params"]["id_or_name"],
                serde_json::json!("sandbox-1")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"resolved_id": "sandbox-1", "stopped": true},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, resolved_id) = run_sandbox_stop(&config, "sandbox-1").expect("sandbox stop");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(resolved_id, "sandbox-1");
    server.join().expect("fake daemon thread");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_delete_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_delete"));
            assert_eq!(
                request["params"]["id_or_name"],
                serde_json::json!("codebox")
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"resolved_id": "sandbox-1", "already_absent": false},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, deleted) = run_sandbox_delete(&config, "codebox").expect("sandbox delete");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(deleted.resolved_id.as_deref(), Some("sandbox-1"));
    assert!(!deleted.already_absent);
    server.join().expect("fake daemon thread");
}
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_exec_routes_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::tempdir().expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_exec"));
            assert_eq!(
                request["params"]["id_or_name"],
                serde_json::json!("sandbox-1")
            );
            assert_eq!(
                request["params"]["caller_persona_id"],
                serde_json::json!("persona-owner")
            );
            assert_eq!(
                request["params"]["command"],
                serde_json::json!(["echo", "hello"])
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {"resolved_id": "sandbox-1", "output": "hello\n"},
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let (dispatch, output) = run_sandbox_exec(
        &config,
        "sandbox-1",
        Some("persona-owner".to_string()),
        &["echo".to_string(), "hello".to_string()],
    )
    .expect("sandbox exec");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(output, "hello\n");
    server.join().expect("fake daemon thread");
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "local macOS sandbox forbids fake daemon UDS bind"
)]
fn sandbox_run_routes_orchestration_through_daemon_when_socket_exists() {
    use std::io::{BufRead, Write as _};
    use std::os::unix::net::UnixListener;

    let tmp = tempfile::Builder::new()
        .prefix("esb")
        .tempdir()
        .expect("tempdir");
    let config = DaemonConfig::for_test(tmp.path());
    std::fs::create_dir_all(&config.socket_dir).expect("create socket dir");
    let socket_path = config.socket_dir.join("daemon.sock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn({
        let socket_path = socket_path.clone();
        move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).expect("bind fake daemon");
            ready_tx.send(()).expect("signal ready");

            let mut stream = accept_with_timeout(&listener, std::time::Duration::from_secs(10));
            let mut reader =
                std::io::BufReader::new(stream.try_clone().expect("clone fake daemon stream"));
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read fake daemon request");
            let request: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse fake daemon request");
            assert_eq!(request["method"], serde_json::json!("sandbox_run"));
            assert_eq!(
                request["params"]["sandbox"]["name"],
                serde_json::json!("codebox")
            );
            assert_eq!(
                request["params"]["sandbox"]["image"],
                serde_json::json!("ubuntu:24.04")
            );
            assert_eq!(
                request["params"]["credential_resource"],
                serde_json::json!("obj-github-token")
            );
            assert_eq!(request["params"]["ttl_secs"], serde_json::json!(1800));
            assert_eq!(
                request["params"]["statements"]
                    .as_array()
                    .expect("statements array")
                    .len(),
                3
            );

            let mut encoded = serde_json::to_string(&serde_json::json!({
                "id": request["id"],
                "result": {
                    "sandbox": {
                        "id": "sandbox-123",
                        "name": "codebox",
                        "persona_id": "persona-sandbox",
                        "owner_persona_id": "persona-owner",
                        "container_id": null,
                        "image": "ubuntu:24.04",
                        "status": "created",
                        "created_at": "2026-05-18T00:00:00Z",
                        "workspace_path": null
                    },
                    "container_id": "container-123",
                    "start_error": null,
                    "grant": {
                        "PendingApproval": {
                            "approval_id": "approval-123"
                        }
                    }
                },
            }))
            .expect("encode fake daemon response");
            encoded.push('\n');
            stream
                .write_all(encoded.as_bytes())
                .expect("write fake daemon response");
        }
    });

    ready_rx.recv().expect("wait for fake daemon ready");
    let opts = SandboxCreateOpts {
        name: "codebox".to_string(),
        image: "ubuntu:24.04".to_string(),
        owner_persona_id: Some("persona-owner".to_string()),
        ..SandboxCreateOpts::default()
    };
    let statements =
        build_composite_grant_statements(Some("obj-github-token"), Some(42), None, Some(1800));
    let (dispatch, prepared) = run_sandbox_run(
        &config,
        &opts,
        &statements,
        Some(1800),
        Some("obj-github-token"),
    )
    .expect("sandbox run via daemon");
    assert_eq!(dispatch, SandboxActionDispatch::DaemonRpc);
    assert_eq!(prepared.sandbox.id, "sandbox-123");
    assert_eq!(prepared.container_id.as_deref(), Some("container-123"));
    match prepared.grant {
        SandboxRunGrantDisposition::PendingApproval { approval_id } => {
            assert_eq!(approval_id, "approval-123");
        }
        other => panic!("expected pending approval, got {other:?}"),
    }
    server.join().expect("fake daemon thread");
}
