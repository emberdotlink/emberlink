use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ember_daemon::infra::dashboard::run_dashboard;
use ember_daemon::infra::rate_limit::RateLimiter;
use ember_daemon::infra::socket::SocketListener;
use ember_daemon::infra::store::{DaemonStore, StoreError};
use ember_daemon::infra::vault::Vault;
use ember_daemon::trust::approval::ApprovalOutcome;
use ember_daemon::trust::policy::{
    ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel,
};
use tempfile::TempDir;
use tokio::sync::watch;

/// Permissive policy engine for socket-level integration tests.
///
/// development milestone closed the `force: true` socket bypass, so socket tests
/// can no longer skip the policy engine via the wire. This engine mirrors
/// the shape of `PolicyEngine::default()` (so `deploy.staging` still
/// auto-approves etc.) AND adds an auto-approve rule for
/// `credential.access.*` so existing lifecycle tests can mint grants
/// without going through the approval loop. It does NOT auto-approve
/// `*` — that would mask the policy gate entirely.
fn permissive_test_policy() -> PolicyEngine {
    PolicyEngine::new(PolicyConfig {
        rules: vec![
            PolicyRule {
                action: "credential.access.*".to_string(),
                risk: RiskLevel::Low,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
            PolicyRule {
                action: "credential.access".to_string(),
                risk: RiskLevel::Low,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
            PolicyRule {
                action: "git.push.main".to_string(),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            },
            PolicyRule {
                action: "git.push.*".to_string(),
                risk: RiskLevel::Medium,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
            PolicyRule {
                action: "deploy.production".to_string(),
                risk: RiskLevel::Critical,
                requirement: ApprovalRequirement::Required,
                tier: None,
            },
            PolicyRule {
                action: "deploy.staging".to_string(),
                risk: RiskLevel::Medium,
                requirement: ApprovalRequirement::Auto,
                tier: None,
            },
        ],
        default_requirement: ApprovalRequirement::Required,
        default_risk: RiskLevel::Medium,
    })
}

/// Spawn the daemon listener on a dedicated single-threaded runtime in its own
/// OS thread. Returns the socket path and a shutdown sender. This avoids
/// LocalSet/spawn_blocking interaction issues: the listener owns its thread,
/// and the sync SocketTransport client can be called from spawn_blocking on the
/// test's multi-threaded runtime.
fn spawn_listener_thread(tmp: &TempDir) -> (std::path::PathBuf, watch::Sender<bool>) {
    let socket_path = tmp.path().join("test.sock");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let path_for_thread = socket_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open_in_memory().unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            // V0 schema: persona-secret writes require an attached vault.
            store.set_vault(Rc::clone(&vault));
            let policy = Rc::new(permissive_test_policy());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));
            let listener =
                SocketListener::new(path_for_thread, shutdown_rx, store, policy, rate_limiter);
            listener.run().await.unwrap();
        });
    });

    (socket_path, shutdown_tx)
}

#[tokio::test]
async fn full_grant_lifecycle_via_socket() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);

    // Give listener time to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        use emberlink_agent::socket_transport::SocketTransport;

        let mut t = SocketTransport::connect(&path).unwrap();

        // 1. Ping
        let ping_result = t.send("ping", serde_json::Value::Null).unwrap();
        assert_eq!(ping_result["pong"], serde_json::json!(true));

        // 2. Create persona
        let p = t
            .send("create_persona", serde_json::json!({"name": "e2e-agent"}))
            .unwrap();
        let pid = p["id"].as_str().unwrap().to_string();
        assert!(pid.starts_with("persona-"), "persona id: {pid}");

        // 3. Add credential to vault
        t.send(
            "vault_add",
            serde_json::json!({"name": "test-key", "value": "secret123"}),
        )
        .unwrap();

        // 4. Create grant with TTL — relies on `permissive_test_policy`
        // auto-approving credential.access.* (force is no longer wire-honored
        // post development milestone).
        let g = t
            .send(
                "create_grant",
                serde_json::json!({
                    "persona_id": pid,
                    "credential_name": "test-key",
                    "scope": "read",
                    "ttl_secs": 3600,
                }),
            )
            .unwrap();
        let gid = g["id"].as_str().unwrap().to_string();
        assert!(gid.starts_with("grant-"), "grant id: {gid}");

        // 5. Use credential — should succeed while grant is active
        let c = t
            .send(
                "use_credential",
                serde_json::json!({
                    "persona_id": pid,
                    "credential_name": "test-key",
                }),
            )
            .unwrap();
        assert_eq!(c["credential"], "secret123");

        // 6. Check audit log — at least one entry from the credential access above
        let audit = t
            .send("audit_query", serde_json::json!({"limit": 10}))
            .unwrap();
        let entries = audit.as_array().unwrap();
        assert!(!entries.is_empty(), "audit log should not be empty");

        // 7. Revoke grant
        t.send("revoke_grant", serde_json::json!({"id": gid}))
            .unwrap();

        // 8. Use credential should now fail (grant revoked)
        let err = t.send(
            "use_credential",
            serde_json::json!({
                "persona_id": pid,
                "credential_name": "test-key",
            }),
        );
        assert!(
            err.is_err(),
            "use_credential should fail after grant revocation"
        );

        // 9. Request access via policy — low-risk action should auto-approve
        let access = t
            .send(
                "request_access",
                serde_json::json!({
                    "persona_id": pid,
                    "credential_name": "test-key",
                    "scope": "read",
                    "action": "deploy.staging",
                }),
            )
            .unwrap();
        assert_eq!(
            access["decision"], "auto_approve",
            "expected auto_approve, got: {access}"
        );

        "passed"
    })
    .await
    .unwrap();

    assert_eq!(result, "passed");
    shutdown_tx.send(true).unwrap();
}

#[tokio::test]
async fn full_demo_flow() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);

    // Give listener time to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        use emberlink_agent::socket_transport::SocketTransport;
        use serde_json::json;

        let mut t = SocketTransport::connect(&path).unwrap();

        // 1. Ping — verify daemon is alive
        let ping = t.send("ping", json!(null)).unwrap();
        assert_eq!(ping["pong"], json!(true));

        // 2. Create persona "demo-agent"
        let p = t
            .send("create_persona", json!({"name": "demo-agent"}))
            .unwrap();
        let persona_id = p["id"].as_str().unwrap().to_string();
        assert!(
            persona_id.starts_with("persona-"),
            "persona id: {persona_id}"
        );
        assert_eq!(p["name"], json!("demo-agent"));

        // 3. Add credential to vault
        let vault_resp = t
            .send(
                "vault_add",
                json!({"name": "github-token", "value": "ghp_demo123"}),
            )
            .unwrap();
        assert_eq!(vault_resp["name"], json!("github-token"));

        // 4. Create grant with TTL and rate limit — permissive policy
        // auto-approves; socket API no longer honors `force`.
        let g = t
            .send(
                "create_grant",
                json!({
                    "persona_id": persona_id,
                    "credential_name": "github-token",
                    "scope": "read",
                    "ttl_secs": 3600,
                    "max_uses_per_hour": 10,
                }),
            )
            .unwrap();
        let grant_id = g["id"].as_str().unwrap().to_string();
        assert!(grant_id.starts_with("grant-"), "grant id: {grant_id}");
        assert_eq!(g["conditions"]["max_uses_per_hour"], json!(10));

        // 5. Use credential — should succeed with active grant
        let c = t
            .send(
                "use_credential",
                json!({
                    "persona_id": persona_id,
                    "credential_name": "github-token",
                }),
            )
            .unwrap();
        assert_eq!(c["credential"], json!("ghp_demo123"));

        // 6. Audit query — verify the access event was logged
        let audit = t.send("audit_query", json!({"limit": 10})).unwrap();
        let entries = audit.as_array().unwrap();
        assert!(!entries.is_empty(), "audit log should not be empty");
        let access_entry = entries
            .iter()
            .find(|e| e["action"] == "credential.access")
            .expect("should have a credential.access audit entry");
        assert_eq!(access_entry["outcome"], json!("allowed"));
        assert_eq!(access_entry["credential"], json!("github-token"));

        // 7. Grant summary — verify summary shows the grant
        let summary = t.send("grant_summary", json!(null)).unwrap();
        assert!(
            summary["active"].as_u64().unwrap() >= 1,
            "should have at least 1 active grant, got: {summary}"
        );

        // 8. List grants — verify the grant is listed (persona_id now required)
        let grants = t
            .send("list_grants", json!({"persona_id": persona_id}))
            .unwrap();
        let grant_list = grants.as_array().unwrap();
        assert!(
            !grant_list.is_empty(),
            "should have at least one active grant"
        );
        let our_grant = grant_list
            .iter()
            .find(|g| g["id"] == grant_id.as_str())
            .expect("our grant should be in the list");
        assert_eq!(our_grant["persona_id"], json!(persona_id));
        assert_eq!(our_grant["credential_name"], json!("github-token"));
        assert_eq!(our_grant["scope"], json!("read"));

        // 9. Submit approval request
        let approval = t
            .send(
                "submit_approval",
                json!({
                    "persona_id": persona_id,
                    "credential_name": "github-token",
                    "scope": "write",
                    "action": "deploy.production",
                    "risk_level": "high",
                    "ttl_secs": 1800,
                }),
            )
            .unwrap();
        let approval_id = approval["id"].as_str().unwrap().to_string();
        assert_eq!(approval["status"], json!("pending"));

        // 10. List pending approvals — verify it appears
        let pending = t.send("list_pending_approvals", json!(null)).unwrap();
        let pending_list = pending.as_array().unwrap();
        let our_approval = pending_list
            .iter()
            .find(|a| a["id"] == approval_id.as_str())
            .expect("our approval should be in the pending list");
        assert_eq!(our_approval["persona_id"], json!(persona_id));
        assert_eq!(our_approval["action"], json!("deploy.production"));
        assert_eq!(our_approval["risk_level"], json!("high"));

        // 11. Revoke the grant
        t.send("revoke_grant", json!({"id": grant_id})).unwrap();

        // 12. Use credential again — should fail (grant revoked)
        let err = t.send(
            "use_credential",
            json!({
                "persona_id": persona_id,
                "credential_name": "github-token",
            }),
        );
        assert!(
            err.is_err(),
            "use_credential should fail after grant revocation"
        );

        // 13. Grant summary after revocation — revoked count should increase
        let summary_after = t.send("grant_summary", json!(null)).unwrap();
        assert!(
            summary_after["revoked"].as_u64().unwrap() >= 1,
            "should have at least 1 revoked grant, got: {summary_after}"
        );

        // 14. Vault list — verify credential is still in vault
        let vault_list = t.send("vault_list", json!(null)).unwrap();
        let creds = vault_list.as_array().unwrap();
        assert!(
            creds.iter().any(|c| c["name"] == "github-token"),
            "github-token should still be in vault"
        );

        "passed"
    })
    .await
    .unwrap();

    assert_eq!(result, "passed");
    shutdown_tx.send(true).unwrap();
}

/// Verify that grant lifecycle events (issuance and revocation) are written to
/// the audit log.  This exercises task 69E.10 acceptance criteria 1-3.
#[tokio::test]
async fn grant_lifecycle_audits_issuance_and_revoke() {
    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        use emberlink_agent::socket_transport::SocketTransport;
        use serde_json::json;

        let mut t = SocketTransport::connect(&path).unwrap();

        // Create persona
        let p = t
            .send("create_persona", json!({"name": "audit-test-agent"}))
            .unwrap();
        let pid = p["id"].as_str().unwrap().to_string();

        // Add credential to vault
        t.send(
            "vault_add",
            json!({"name": "audit-key", "value": "secretval"}),
        )
        .unwrap();

        // Create grant (policy auto-approves credential.access.*).
        let g = t
            .send(
                "create_grant",
                json!({
                    "persona_id": pid,
                    "credential_name": "audit-key",
                    "scope": "read",
                    "ttl_secs": 3600,
                }),
            )
            .unwrap();
        let gid = g["id"].as_str().unwrap().to_string();
        assert!(gid.starts_with("grant-"), "grant id: {gid}");

        // Query audit log — must contain a grant.issued entry
        let audit = t.send("audit_query", json!({"limit": 20})).unwrap();
        let entries = audit.as_array().unwrap();
        let issued = entries
            .iter()
            .find(|e| e["action"] == "grant.issued")
            .expect("audit log must contain a grant.issued entry");
        assert_eq!(issued["outcome"], json!("allowed"));
        assert_eq!(issued["credential"], json!("audit-key"));

        // Revoke the grant
        t.send("revoke_grant", json!({"id": gid})).unwrap();

        // Query audit log again — must now also contain a grant.revoked entry
        let audit2 = t.send("audit_query", json!({"limit": 20})).unwrap();
        let entries2 = audit2.as_array().unwrap();
        let revoked = entries2
            .iter()
            .find(|e| e["action"] == "grant.revoked")
            .expect("audit log must contain a grant.revoked entry");
        assert_eq!(revoked["outcome"], json!("allowed"));
        assert_eq!(revoked["credential"], json!("audit-key"));

        "passed"
    })
    .await
    .unwrap();

    assert_eq!(result, "passed");
    shutdown_tx.send(true).unwrap();
}

/// Two clients connect to the daemon. Client A creates a persona, a vault
/// entry, and a grant. Client B connects afterward and passively reads lines
/// from its socket. When Client A revokes the grant, Client B must receive a
/// `grant_revoked` notification within 1 second.
///
/// Exercises the full daemon-side broadcast path: handler publishes →
/// broadcast channel fans out → per-connection forwarder writes a JSON-RPC
/// notification → client reads it from the socket.
#[tokio::test]
async fn revocation_notification_reaches_connected_client() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    let tmp = TempDir::new().unwrap();
    let (socket_path, shutdown_tx) = spawn_listener_thread(&tmp);

    // Give listener time to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let path = socket_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        use emberlink_agent::socket_transport::SocketTransport;
        use serde_json::json;

        // --- Client A: issues commands via the synchronous transport. ---
        let mut client_a = SocketTransport::connect(&path).unwrap();

        // Set up persona + vault + grant.
        let p = client_a
            .send("create_persona", json!({"name": "revocation-agent"}))
            .unwrap();
        let pid = p["id"].as_str().unwrap().to_string();

        client_a
            .send(
                "vault_add",
                json!({"name": "revoke-key", "value": "hunter2"}),
            )
            .unwrap();

        let g = client_a
            .send(
                "create_grant",
                json!({
                    "persona_id": pid,
                    "credential_name": "revoke-key",
                    "scope": "read",
                }),
            )
            .unwrap();
        let gid = g["id"].as_str().unwrap().to_string();

        // --- Client B: raw unix socket; read lines to observe notifications.
        let stream_b = UnixStream::connect(&path).unwrap();
        stream_b
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        let mut reader_b = BufReader::new(stream_b.try_clone().unwrap());
        let mut writer_b = stream_b;

        // Handshake so the daemon registers this connection in its select
        // loop on both request and event branches.
        writer_b
            .write_all(b"{\"id\":\"b-ping\",\"method\":\"ping\",\"params\":null}\n")
            .unwrap();
        let mut pong = String::new();
        reader_b.read_line(&mut pong).unwrap();
        assert!(pong.contains("b-ping"));

        // --- Client A revokes the grant. ---
        let _ = client_a.send("revoke_grant", json!({"id": gid})).unwrap();

        // --- Client B must receive a grant_revoked notification. ---
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut got_notification = false;
        while Instant::now() < deadline {
            let mut line = String::new();
            match reader_b.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let v: serde_json::Value = match serde_json::from_str(line.trim_end()) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v["method"] == "grant_revoked" {
                        assert_eq!(v["params"]["grant_id"].as_str().unwrap(), gid);
                        assert_eq!(v["params"]["persona_id"].as_str().unwrap(), pid);
                        // Must NOT leak scope / credential name / timestamp.
                        let params_obj = v["params"].as_object().unwrap();
                        assert_eq!(params_obj.len(), 2);
                        got_notification = true;
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => panic!("read error: {e}"),
            }
        }

        // Keep writer alive until the assertion fires so the daemon side
        // doesn't treat the connection as gone mid-test.
        drop(writer_b);
        drop(reader_b);

        assert!(got_notification, "expected grant_revoked within 1s");
        "passed"
    })
    .await
    .unwrap();

    assert_eq!(result, "passed");
    shutdown_tx.send(true).unwrap();
}

/// Start the dashboard HTTP listener on an ephemeral port, make a GET / request,
/// and assert a 200 response with HTML in the body.
#[tokio::test]
async fn dashboard_tcp_listener_serves_html() {
    use tokio::net::TcpListener;

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");

    // Pre-create the database so the dashboard can open it.
    let _ = DaemonStore::open(&db_path).unwrap();

    // Bind to port 0 to get an ephemeral port, then release so run_dashboard can bind it.
    // Small TOCTOU window is acceptable in tests.
    let ephemeral = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ephemeral.local_addr().unwrap();
    drop(ephemeral);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let db = db_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &rt,
            run_dashboard(addr, db, "0.0.0-test".to_string(), None, shutdown_rx, None),
        );
    });

    // Give the listener time to bind.
    tokio::time::sleep(Duration::from_millis(150)).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response_str = std::str::from_utf8(&response).unwrap();

    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "expected 200 OK, got: {}",
        &response_str[..response_str.len().min(120)]
    );
    assert!(
        response_str.contains("<!DOCTYPE html>"),
        "expected HTML body, got: {}",
        &response_str[..response_str.len().min(500)]
    );

    shutdown_tx.send(true).unwrap();
}

/// End-to-end CSRF protection: POST without the X-Ember-CSRF-Token header
/// must return 403. HTML GET must contain a rendered (non-placeholder) token.
/// POST with the correct token must pass the CSRF check (reaching the store).
#[tokio::test]
async fn dashboard_csrf_protects_post_endpoints() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");
    let _ = DaemonStore::open(&db_path).unwrap();

    let ephemeral = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ephemeral.local_addr().unwrap();
    drop(ephemeral);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let db = db_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &rt,
            run_dashboard(addr, db, "0.0.0-test".to_string(), None, shutdown_rx, None),
        );
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // 1. GET / returns HTML containing CSRF_TOKEN constant (and no placeholder).
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        body_str.contains("const CSRF_TOKEN ="),
        "HTML must define CSRF_TOKEN"
    );
    assert!(
        !body_str.contains("{{CSRF_TOKEN}}"),
        "template placeholder must be replaced"
    );

    // Extract the token from the HTML (parsed from `const CSRF_TOKEN = "...";`).
    let marker = "const CSRF_TOKEN = \"";
    let start = body_str.find(marker).unwrap() + marker.len();
    let rest = &body_str[start..];
    let end = rest.find('"').unwrap();
    let token = &rest[..end];
    assert_eq!(token.len(), 64, "token must be 64 hex chars");

    // 2. POST without header -> 403.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"POST /api/approvals/fake-id/approve HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp).unwrap();
    assert!(
        resp_str.starts_with("HTTP/1.1 403"),
        "expected 403 without CSRF header, got: {}",
        &resp_str[..resp_str.len().min(120)]
    );

    // 3. POST with wrong header -> 403.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"POST /api/approvals/fake-id/approve HTTP/1.1\r\nHost: localhost\r\nX-Ember-CSRF-Token: wrong\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp).unwrap();
    assert!(
        resp_str.starts_with("HTTP/1.1 403"),
        "expected 403 with wrong CSRF header, got: {}",
        &resp_str[..resp_str.len().min(120)]
    );

    // 4. POST with correct CSRF header AND matching Origin -> passes both checks,
    //    fails downstream. implementation-note-91: with the WebAuthn gate active
    //    (no `EMBER_DISABLE_BIO=1`), an empty body reaches the gate and gets
    //    401 "missing webauthn challenge_id". Without the gate, the legacy
    //    path reaches the store and gets 400 "approval not found". Either
    //    code is fine — what we're asserting here is that the CSRF + Origin
    //    check let the request through; the downstream behaviour is owned
    //    by other tests.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /api/approvals/fake-id/approve HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nX-Ember-CSRF-Token: {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp).unwrap();
    assert!(
        resp_str.starts_with("HTTP/1.1 400") || resp_str.starts_with("HTTP/1.1 401"),
        "expected 400 (legacy store error) or 401 (webauthn gate refusal) — both prove CSRF+origin passed; got: {}",
        &resp_str[..resp_str.len().min(120)]
    );

    // 5. GET endpoints still work without the header.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let resp_str = std::str::from_utf8(&resp).unwrap();
    assert!(
        resp_str.starts_with("HTTP/1.1 200"),
        "GET should not require CSRF, got: {}",
        &resp_str[..resp_str.len().min(120)]
    );

    shutdown_tx.send(true).unwrap();
}

/// When the dashboard port is already held, the unix socket must still bind and
/// serve requests. This test occupies an ephemeral port, starts both the dashboard
/// (which fails to bind) and the socket listener (which must succeed) on the same
/// local set, then asserts the socket is reachable and the dashboard bind result
/// is `Err`.
#[tokio::test]
async fn socket_still_works_when_dashboard_port_occupied() {
    use std::net::SocketAddr;
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::sync::oneshot;

    let tmp = TempDir::new().unwrap();
    let socket_path = tmp.path().join("daemon.sock");
    let db_path = tmp.path().join("daemon.db");

    // Pre-create the database.
    let _ = DaemonStore::open(&db_path).unwrap();

    // Hold a port so the dashboard cannot bind it.
    let blocker = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr: SocketAddr = blocker.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx_dash) = watch::channel(false);
    let shutdown_rx_sock = shutdown_tx.subscribe();
    let (bind_tx, bind_rx) = oneshot::channel::<Result<SocketAddr, std::io::Error>>();

    let sock_path = socket_path.clone();
    let db = db_path.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            let store = Rc::new(DaemonStore::open(&db).unwrap());
            let vault = Rc::new(Vault::new([42u8; 32]));
            // V0 schema: persona-secret writes require an attached vault.
            store.set_vault(Rc::clone(&vault));
            let policy = Rc::new(PolicyEngine::default());
            let rate_limiter = Rc::new(RefCell::new(RateLimiter::default()));

            // Spawn the failing dashboard.
            tokio::task::spawn_local(run_dashboard(
                blocked_addr,
                db,
                "0.0.0-test".to_string(),
                None,
                shutdown_rx_dash,
                Some(bind_tx),
            ));

            // Run the socket listener until shutdown.
            let listener =
                SocketListener::new(sock_path, shutdown_rx_sock, store, policy, rate_limiter);
            let _ = listener.run().await;
        });
    });

    // The dashboard bind should fail quickly (port is held).
    let bind_result = tokio::time::timeout(Duration::from_secs(5), bind_rx)
        .await
        .expect("bind_tx result did not arrive within 5s")
        .expect("bind_tx sender dropped without sending");
    assert!(
        bind_result.is_err(),
        "expected dashboard bind to fail when port is occupied"
    );

    // Give the socket listener a moment to start.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The unix socket must be reachable.
    let path = socket_path.clone();
    let ping_result = tokio::task::spawn_blocking(move || {
        use emberlink_agent::socket_transport::SocketTransport;
        let mut t = SocketTransport::connect(&path)?;
        t.send("ping", serde_json::Value::Null)
    })
    .await
    .unwrap();
    assert!(
        ping_result.is_ok(),
        "unix socket must accept connections even when dashboard port is occupied"
    );
    assert_eq!(ping_result.unwrap()["pong"], serde_json::json!(true));

    drop(blocker);
    let _ = shutdown_tx.send(true);
}

/// Verify that when a port is already held by another process, `run_dashboard`
/// sends `Err` on the bind_tx channel rather than silently discarding the failure.
///
/// This test avoids port 3141 to stay CI-safe: it binds an ephemeral port first
/// (the "port blocker"), then tries to run the dashboard on the same port, and
/// asserts that the bind result is `Err`.
#[tokio::test]
async fn dashboard_bind_failure_surfaced_via_channel() {
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("daemon.db");

    // Pre-create the database.
    let _ = DaemonStore::open(&db_path).unwrap();

    // Bind port X and hold it — this is the "port already in use" blocker.
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (bind_tx, bind_rx) = oneshot::channel();

    let db = db_path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(
            &rt,
            run_dashboard(
                blocked_addr,
                db,
                "0.0.0-test".to_string(),
                None,
                shutdown_rx,
                Some(bind_tx),
            ),
        );
    });

    // The bind should fail quickly because the port is held by `blocker`.
    let result = tokio::time::timeout(Duration::from_secs(5), bind_rx)
        .await
        .expect("bind result did not arrive within 5s")
        .expect("bind_tx sender dropped without sending");

    // Assert the bind failed — port was already in use.
    assert!(
        result.is_err(),
        "expected bind failure when port is already held, got: Ok({:?})",
        result.ok()
    );

    // Clean up: drop the blocker and signal shutdown (dashboard already exited but be tidy).
    drop(blocker);
    let _ = shutdown_tx.send(true);
}

// ---------------------------------------------------------------------------
// implementation-note-296 — auto-unseal vault from keyring on daemon startup.
//
// The bug: `qember.sh demo up` finished, then `grant create` failed with
// "persona '<id>' secret is vault-sealed but no vault is attached" because
// the in-process call path opened the SQLite store directly and never
// attached a vault. Fix: a documented `try_auto_unseal_from_keyring` helper
// that the daemon (`runtime.rs`) and the CLI direct-DB paths
// (`bin/ember.rs::open_store`) both call.
//
// These tests exercise the helper + the runtime audit event end-to-end.
// They share a single mutex so env-variable manipulation does not race
// across the parallel test runner — `EMBER_VAULT_PASSPHRASE` and
// `EMBER_VAULT_TEST_KEYRING_PRESENT` are process-global, so two tests
// flipping them simultaneously would interfere.
// ---------------------------------------------------------------------------

/// Serialize all implementation-note-296 tests that mutate process-global env vars
/// (`EMBER_VAULT_PASSPHRASE`, `EMBER_VAULT_TEST_KEYRING_PRESENT`). Without
/// this, the parallel cargo test runner can interleave env writes between
/// tests and cause spurious `Unsealed` / `NoKeyringEntry` flips.
fn demo_ux_8_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[test]
fn auto_unseal_returns_no_keyring_entry_when_none_configured() {
    use ember_daemon::infra::config::DaemonConfig;
    use ember_daemon::infra::vault::{AutoUnsealOutcome, try_auto_unseal_from_keyring};

    let _guard = demo_ux_8_env_lock();

    // Failure-mode acceptance criterion: keyring entry absent → helper returns
    // NoKeyringEntry, daemon can still start (caller falls back to
    // provisioning path).
    // SAFETY: tests holding `_guard` are serialized for env-var access.
    unsafe {
        std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT");
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
    }

    let tmp = TempDir::new().unwrap();
    let config = DaemonConfig {
        data_dir: tmp.path().to_path_buf(),
        ..DaemonConfig::for_test(tmp.path())
    };

    match try_auto_unseal_from_keyring(&config) {
        AutoUnsealOutcome::NoKeyringEntry => {}
        AutoUnsealOutcome::Unsealed(_) => {
            panic!("expected NoKeyringEntry, got Unsealed (test gate misconfigured?)")
        }
        AutoUnsealOutcome::Error(e) => {
            panic!("expected NoKeyringEntry, got Error: {e}")
        }
    }
}

#[test]
fn auto_unseal_returns_unsealed_when_keyring_entry_present() {
    use ember_daemon::infra::config::DaemonConfig;
    use ember_daemon::infra::store::DaemonStore;
    use ember_daemon::infra::vault::{AutoUnsealOutcome, try_auto_unseal_from_keyring};
    use std::rc::Rc;

    let _guard = demo_ux_8_env_lock();

    // Happy path: the test-keyring-present gate signals "as if the keyring
    // had a passphrase". Auto-unseal should succeed, the returned vault
    // should attach to the store, and `create_persona` should succeed —
    // which is the contract that `qember.sh demo up` + `grant create` needs.
    // SAFETY: tests holding `_guard` are serialized for env-var access.
    unsafe {
        std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1");
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
    }

    let tmp = TempDir::new().unwrap();
    let config = DaemonConfig {
        data_dir: tmp.path().to_path_buf(),
        ..DaemonConfig::for_test(tmp.path())
    };

    let outcome = try_auto_unseal_from_keyring(&config);

    // Re-clear so other tests see a clean slate even if this one panics later.
    unsafe {
        std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT");
    }

    let vault = match outcome {
        AutoUnsealOutcome::Unsealed(v) => v,
        AutoUnsealOutcome::NoKeyringEntry => {
            panic!(
                "expected Unsealed; got NoKeyringEntry — test gate not honoring EMBER_VAULT_TEST_KEYRING_PRESENT"
            )
        }
        AutoUnsealOutcome::Error(e) => panic!("expected Unsealed; got Error: {e}"),
    };

    // Round-trip: attach to store, create a persona, retrieve its keypair.
    // This is the precise call sequence that `grant create` triggers and the
    // path that was failing in implementation-note-296. If this works end-to-end, the
    // demo-blocking bug is fixed.
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(Rc::new(vault));
    let persona = store.create_persona("demo-ux-8-root").unwrap();
    let _kp = store
        .persona_root_keypair(&persona.id)
        .expect("persona_root_keypair must succeed when vault is attached");
}

#[test]
fn daemon_run_logs_vault_auto_unseal_audit_event() {
    use ember_daemon::infra::audit::AuditFilter;
    use ember_daemon::infra::config::DaemonConfig;
    use ember_daemon::infra::runtime::DaemonRuntime;
    use ember_daemon::infra::store::DaemonStore;

    let _guard = demo_ux_8_env_lock();

    // Drive `DaemonRuntime::run()` long enough for the explicit bridge
    // bootstrap path to attach the vault and emit the
    // `vault.auto_unseal_from_keyring` audit event, then drop the runtime
    // task to shut it down. We don't go through the full socket loop here —
    // the audit row is written before the listener accepts.
    //
    // Test gate: signal "keyring entry exists" so the helper returns Unsealed
    // and the audit event is labeled `auto_unseal_from_keyring`.
    // SAFETY: tests holding `_guard` are serialized for env-var access.
    unsafe {
        std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1");
        std::env::remove_var("EMBER_VAULT_PASSPHRASE");
    }

    let tmp = TempDir::new().unwrap();
    let socket_dir = tmp.path().join("run");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let config = DaemonConfig {
        data_dir: tmp.path().to_path_buf(),
        pid_file: socket_dir.join("emberd.pid"),
        policy_file: tmp.path().join("policy.toml"),
        socket_dir,
        // Disable dashboard so the runtime startup is purely about vault attach.
        dashboard_addr: None,
        // Explicit bridge opt-in keeps this test on the bootstrap-open path.
        bridge_bind: Some("127.0.0.1:8443".parse().unwrap()),
        ..DaemonConfig::for_test(tmp.path())
    };

    let runtime = DaemonRuntime::new(config.clone());
    let db_path = config.data_dir.join("daemon.db");

    // Run the runtime on a single-threaded tokio runtime in this thread,
    // racing against a 1.5-second timer so the test always terminates.
    // The audit-event write happens within the first few hundred ms of
    // `run()` — well before any external traffic could arrive.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        tokio::select! {
            res = runtime.run(None) => { let _ = res; }
            _ = tokio::time::sleep(Duration::from_millis(1500)) => {}
        }
    });

    // Drop env gate before any panic-on-assertion.
    unsafe {
        std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT");
    }

    let store = DaemonStore::open(&db_path).unwrap();
    let entries = store
        .query_audit(&AuditFilter {
            action: Some("vault.auto_unseal_from_keyring".to_string()),
            ..Default::default()
        })
        .unwrap();

    assert!(
        !entries.is_empty(),
        "expected at least one vault.auto_unseal_from_keyring audit row, found 0 — \
         the daemon startup path must emit this audit event so `audit show` reflects \
         when (and how) the vault came online"
    );
    assert_eq!(entries[0].action, "vault.auto_unseal_from_keyring");
    assert_eq!(
        entries[0].outcome, "auto_unseal_from_keyring",
        "outcome should label the success branch when keyring entry is present"
    );
}

// ---------------------------------------------------------------------------
// BEGIN IMMEDIATE serializes concurrent authorize+materialize pairs
// ---------------------------------------------------------------------------

/// Ten concurrent callers each open their own DaemonStore connection to the
/// same on-disk SQLite file and simultaneously call resolve_approval(Approved)
/// for the same pending request.
///
/// The BEGIN IMMEDIATE transaction inside resolve_approval acquires a write
/// lock before the status re-read, so the authorize (status == 'pending'
/// check) and the materialize (grant mint + UPDATE) run atomically. Exactly
/// one caller wins; the other nine see status != 'pending' and return
/// AlreadyResolved.
#[test]
fn ten_concurrent_approve_calls_mint_exactly_one_grant() {
    use std::sync::{Arc, Barrier};

    const THREAD_COUNT: usize = 10;
    const VAULT_KEY: [u8; 32] = [0xCCu8; 32];

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("sec19.db");

    // Bootstrap: one store creates the persona and the pending approval.
    let request_id = {
        let store = DaemonStore::open(&db_path).unwrap();
        store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
        store.create_persona("sec19-agent").unwrap();
        let pid = store
            .list_personas()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .id;
        let req = store
            .submit_approval(&pid, "sec19-key", "read", None, "credential.access", "high")
            .unwrap();
        req.id
    };

    // All threads synchronize on this barrier to maximize dispatch overlap.
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));

    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|_| {
            let db_path = db_path.clone();
            let req_id = request_id.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = DaemonStore::open(&db_path).unwrap();
                store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
                barrier.wait();
                store.resolve_approval(&req_id, &ApprovalOutcome::Approved)
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    let already_resolved_count = results
        .iter()
        .filter(|r| matches!(r, Err(StoreError::AlreadyResolved)))
        .count();

    // All results must be either Ok or AlreadyResolved — no unexpected errors.
    for r in &results {
        match r {
            Ok(()) | Err(StoreError::AlreadyResolved) => {}
            Err(e) => panic!("unexpected error from resolve_approval: {e}"),
        }
    }

    assert_eq!(
        ok_count, 1,
        "BEGIN IMMEDIATE must allow exactly one approve to succeed; got {ok_count}"
    );
    assert_eq!(
        already_resolved_count,
        THREAD_COUNT - 1,
        "the other {} callers must return AlreadyResolved; got {already_resolved_count}",
        THREAD_COUNT - 1
    );

    // Verify exactly one grant was minted across all concurrent attempts.
    let verify_store = DaemonStore::open(&db_path).unwrap();
    verify_store.set_vault(Rc::new(Vault::new(VAULT_KEY)));
    let grants = verify_store.list_grants().unwrap();
    assert_eq!(
        grants.len(),
        1,
        "exactly one grant must be minted; got {}",
        grants.len()
    );
    assert_eq!(grants[0].credential_name, "sec19-key");

    let resolved = verify_store.get_approval(&request_id).unwrap();
    assert_eq!(resolved.status, "approved");
    assert!(
        resolved.result_grant_id.is_some(),
        "winning approval must record the minted grant_id"
    );
}
