use super::*;
use crate::infra::store::DaemonStore;

// Display-time unit tests for generic string action rendering. Mirror
// tests exist in the JS-side `displayActionKey` (inlined via
// COMPOSITE_STATEMENTS_JS); both surfaces must agree so composite
// statements do not drift between server and client render paths.

#[test]
fn display_action_key_leaves_non_construct_strings_unchanged() {
    assert_eq!(
        display_action_key("did:web:hashicorp.com:terraform.apply"),
        "did:web:hashicorp.com:terraform.apply"
    );
    assert_eq!(
        display_action_key("credential.access.github-token"),
        "credential.access.github-token"
    );
}

#[test]
fn display_action_key_leaves_bare_strings_unchanged() {
    assert_eq!(display_action_key("gh.pr_create"), "gh.pr_create");
    assert_eq!(display_action_key("read"), "read");
    assert_eq!(display_action_key("github:push"), "github:push");
    assert_eq!(
        display_action_key("docker.push.dockerhub"),
        "docker.push.dockerhub"
    );
}

const TEST_CSRF_TOKEN: &str = "test-csrf-token-0123456789abcdef";
const TEST_EXPECTED_ORIGIN: &str = "http://127.0.0.1:3141";

fn make_state() -> Arc<DashboardState> {
    let store = DaemonStore::open_in_memory().unwrap();
    Arc::new(DashboardState {
        store: Arc::new(store),
        version: "0.0.0-test".to_string(),
        csrf_token: TEST_CSRF_TOKEN.to_string(),
        started_at: std::time::Instant::now(),
        expected_origin: TEST_EXPECTED_ORIGIN.to_string(),
        // Default to a well-known
        // localhost addr so most tests see a "bound" dashboard; tests
        // that exercise the "not bound" branch override directly.
        dashboard_actual_addr: Some("127.0.0.1:3141".parse().expect("test addr parse")),
        data_dir: std::path::PathBuf::from("/tmp/.ember-test/data"),
        // Tests don't construct a gate; the
        // approval handler falls back to the legacy
        // `{biometric: bool}` body field when this is `None`.
        #[cfg(feature = "webauthn")]
        webauthn: None,
    })
}

// Test-accessible wrapper that accepts any body type.
async fn call(state: Arc<DashboardState>, path: &str) -> Response<Full<Bytes>> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://localhost{path}"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    handle_dashboard_boxed(state, req).await
}

async fn call_post(state: Arc<DashboardState>, path: &str) -> Response<Full<Bytes>> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://localhost{path}"))
        .header("origin", TEST_EXPECTED_ORIGIN)
        .header(CSRF_HEADER, TEST_CSRF_TOKEN)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    handle_dashboard_boxed(state, req).await
}

async fn call_post_no_csrf(state: Arc<DashboardState>, path: &str) -> Response<Full<Bytes>> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://localhost{path}"))
        .header("origin", TEST_EXPECTED_ORIGIN)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    handle_dashboard_boxed(state, req).await
}

async fn call_post_wrong_csrf(state: Arc<DashboardState>, path: &str) -> Response<Full<Bytes>> {
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://localhost{path}"))
        .header("origin", TEST_EXPECTED_ORIGIN)
        .header(CSRF_HEADER, "not-the-real-token")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    handle_dashboard_boxed(state, req).await
}

async fn handle_dashboard_boxed(
    state: Arc<DashboardState>,
    req: Request<impl hyper::body::Body + 'static>,
) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let headers = req.headers().clone();

    match (method.clone(), path.as_str()) {
        (Method::GET, "/") | (Method::GET, "/index.html") => {
            let html = DASHBOARD_HTML
                .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
                .replace("{{CSRF_TOKEN}}", &state.csrf_token);
            let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
            dashboard_etag_response(if_none_match, html)
        }

        (Method::GET, "/api/status") => {
            let active_grants = state.store.list_active_grants().unwrap_or_default().len();
            let pending_approvals = state
                .store
                .list_pending_approvals()
                .unwrap_or_default()
                .len();
            let audit_events = state.store.audit_count().unwrap_or(0);
            let active_agents = state
                .store
                .list_personas()
                .unwrap_or_default()
                .iter()
                .filter(|p| p.status == "active")
                .count();
            // Mirror the production
            // handler so `api_status_*` tests cover the new field shape.
            let dashboard_addr_bound = state.dashboard_actual_addr.map(|a| a.to_string());
            let body = serde_json::json!({
                "running": true,
                "version": state.version,
                "active_agents": active_agents,
                "active_grants": active_grants,
                "pending_approvals": pending_approvals,
                "audit_events": audit_events,
                "dashboard_addr_bound": dashboard_addr_bound,
            });
            json_response(StatusCode::OK, &body)
        }

        (Method::GET, "/api/grants") => {
            let grants = state.store.list_active_grants().unwrap_or_default();
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = grants
                .iter()
                .map(|g| {
                    // Test handler mirrors
                    // production: emit the per-Statement array under
                    // `statements` (the canonical name from
                    // grant_to_json_with_store) so JS callers no longer
                    // need a `g.statements || g.composite_statements`
                    // fallback.
                    let mut val = grant_to_json_with_store(g, &state.store);
                    if let Some(obj) = val.as_object_mut() {
                        // add persona_name (production path adds this too)
                        obj.insert(
                            "persona_name".into(),
                            serde_json::json!(names.get(&g.persona_id).cloned()),
                        );
                        obj.insert("paused".into(), serde_json::json!(g.paused));
                    }
                    val
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/api/anomalies") => {
            let anomalies = state.store.detect_anomalies().unwrap_or_default();
            let body = serde_json::to_value(&anomalies).unwrap_or(serde_json::Value::Array(vec![]));
            json_response(StatusCode::OK, &body)
        }

        (Method::GET, "/api/approvals") => {
            let approvals = state.store.list_pending_approvals().unwrap_or_default();
            let body: Vec<serde_json::Value> = approvals
                .iter()
                .map(|a| serde_json::json!({"id": a.id}))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        _ if method == Method::GET
            && path.starts_with("/api/approvals/")
            && !path.ends_with("/approve")
            && !path.ends_with("/deny") =>
        {
            let id = path.strip_prefix("/api/approvals/").unwrap_or("");
            match state.store.get_approval(id) {
                Ok(a) => {
                    // Surface persona.name for the
                    // approval-detail render path (test handler mirrors
                    // production).
                    let persona_name = state.store.get_persona(&a.persona_id).ok().map(|p| p.name);
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "id": a.id,
                            "persona_id": a.persona_id,
                            "persona_name": persona_name,
                            "credential_name": a.credential_name,
                            "scope": a.scope,
                            "ttl_secs": a.ttl_secs,
                            "action": a.action,
                            "risk_level": a.risk_level,
                            "status": a.status,
                            "reason": a.reason,
                            "created_at": a.created_at,
                            // Mirrors production handler so
                            // the polled /api/approvals/{id} response carries the
                            // composite_statements array; the page JS calls
                            // renderBreakdown(data.composite_statements) on each poll.
                            "composite_statements": a.composite_statements,
                            "result_grant_id": a.result_grant_id,
                        }),
                    )
                }
                Err(_) => error_response(404, "approval not found"),
            }
        }

        (Method::GET, "/api/audit") => {
            use crate::infra::audit::AuditFilter;
            // Mirror the production handler's
            // `?include_internal=1` toggle and `?action_filter=<prefix>`
            // so test coverage reflects the same operator-audit semantics.
            let (include_internal, action_filter) = req
                .uri()
                .query()
                .map(|q| {
                    let mut include = false;
                    let mut filter: Option<String> = None;
                    for kv in q.split('&') {
                        let mut parts = kv.splitn(2, '=');
                        let k = parts.next().unwrap_or("");
                        let v = parts.next().unwrap_or("");
                        if k == "include_internal" && (v == "1" || v == "true") {
                            include = true;
                        }
                        if k == "action_filter" && !v.is_empty() {
                            filter = Some(v.to_string());
                        }
                    }
                    (include, filter)
                })
                .unwrap_or((false, None));
            let entries = state
                .store
                .query_audit(&AuditFilter {
                    limit: Some(100),
                    action_prefix: action_filter,
                    ..Default::default()
                })
                .unwrap_or_default();
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = entries
                .iter()
                .filter(|e| include_internal || !is_internal_audit_action(&e.action))
                .map(|e| {
                    let persona_name = e.agent_id.as_deref().and_then(|id| names.get(id).cloned());
                    serde_json::json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "agent_id": e.agent_id,
                        "persona_name": persona_name,
                        "action": e.action,
                        "credential": e.credential,
                        "outcome": e.outcome,
                        "details": e.details,
                    })
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/api/maturation/candidates") => {
            let conn = state.store.conn();
            let mut stmt = match conn.prepare(
                "SELECT action, credential, COUNT(*) as freq, MAX(timestamp) as last_seen \
                 FROM audit_log GROUP BY action, credential \
                 HAVING freq > 2 ORDER BY freq DESC LIMIT 20",
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "maturation candidates query prepare failed");
                    return json_response(StatusCode::OK, &serde_json::json!([]));
                }
            };
            let rows: Vec<serde_json::Value> = stmt.query_map([], |row| {
                Ok(serde_json::json!({
                    "pattern": format!("{}+{}", row.get::<_, String>(0).unwrap_or_default(), row.get::<_, Option<String>>(1).unwrap_or_default().unwrap_or_default()),
                    "action": row.get::<_, String>(0).unwrap_or_default(),
                    "credential": row.get::<_, Option<String>>(1).ok().flatten(),
                    "frequency": row.get::<_, i64>(2).unwrap_or(0),
                    "last_seen": row.get::<_, Option<String>>(3).ok().flatten(),
                }))
            }).map(|iter| iter.flatten().collect()).unwrap_or_default();
            json_response(StatusCode::OK, &serde_json::json!(rows))
        }

        (Method::GET, "/api/autopilot/snapshot") => {
            let output = std::process::Command::new("internal-automation")
                .args(["status", "--json"])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    match serde_json::from_slice::<serde_json::Value>(&o.stdout) {
                        Ok(val) => json_response(StatusCode::OK, &val),
                        Err(_) => json_response(
                            StatusCode::OK,
                            &serde_json::json!({"running": false, "inflight": [], "queue_head": [], "last_events": []}),
                        ),
                    }
                }
                _ => json_response(
                    StatusCode::OK,
                    &serde_json::json!({"running": false, "inflight": [], "queue_head": [], "last_events": []}),
                ),
            }
        }

        (Method::GET, "/api/personas") => {
            let personas = state.store.list_personas().unwrap_or_default();
            let body: Vec<serde_json::Value> = personas
                .iter()
                .map(|p| serde_json::json!({"id": p.id, "name": p.name}))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/health") | (Method::GET, "/api/health") => {
            let uptime = state.started_at.elapsed().as_secs();
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": uptime,
            });
            json_response(StatusCode::OK, &body)
        }

        // ADR212-TELEMETRY-EXPORTER — mirror of the production `/metrics` arm
        // (kept byte-identical to `handle_dashboard_request` so the boxed
        // test router exercises the same route).
        (Method::GET, "/metrics") => match crate::infra::telemetry::render_exposition() {
            Some(body) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", ember_telemetry::METRICS_CONTENT_TYPE)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
            None => error_response(503, "telemetry not initialized"),
        },

        // /grants/{id} — HTML grant-detail page
        (Method::GET, p)
            if p.starts_with("/grants/")
                && !p.contains("/pause")
                && !p.contains("/unpause")
                && !p.contains("/extend")
                && !p.contains("/revoke") =>
        {
            let id = p.strip_prefix("/grants/").unwrap_or("");
            if id.is_empty() {
                error_response(400, "missing grant id")
            } else {
                match state.store.get_grant(id) {
                    Ok(g) => {
                        let chain = state.store.get_access_grant(&g.id).ok();
                        let html = build_grant_detail_html(&g, &state.csrf_token, chain.as_ref());
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(html)))
                            .unwrap()
                    }
                    Err(_) => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from("not found")))
                        .unwrap(),
                }
            }
        }

        (Method::GET, p) if p.starts_with("/approvals/") => {
            let id = p.strip_prefix("/approvals/").unwrap_or("");
            match state.store.get_approval(id) {
                Ok(a) => {
                    let persona_name = state.store.get_persona(&a.persona_id).ok().map(|p| p.name);
                    let html = render_approval_page(
                        &state.csrf_token,
                        &a,
                        persona_name.as_deref(),
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap()
                }
                Err(_) => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(
                        "<!DOCTYPE html><html><head><title>ember</title></head><body>Approval not found or already resolved.</body></html>",
                    )))
                    .unwrap(),
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/revoke-statement") =>
        {
            // Test handler mirrors
            // the production per-statement revoke route.
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/revoke-statement")
                    .unwrap()
                    .to_string();
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let sid = params["sid"].as_str().unwrap_or("");
                if sid.is_empty() {
                    error_response(400, "missing 'sid' field")
                } else {
                    match state.store.revoke_grant_statement(&id, sid) {
                        Ok(()) => json_response(
                            StatusCode::OK,
                            &serde_json::json!({
                                "revoked": true,
                                "grant_id": id,
                                "statement_sid": sid,
                            }),
                        ),
                        Err(e) => error_response(400, &e.to_string()),
                    }
                }
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/revoke") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/revoke")
                    .unwrap();
                match state.store.revoke_grant(id) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"revoked": true})),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/approvals/")
            && path.ends_with("/approve-always") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/approvals/")
                    .unwrap()
                    .strip_suffix("/approve-always")
                    .unwrap()
                    .to_string();
                // standing_grant_expires_at_capped: see sibling fix at
                // dashboard.rs:3074 for the rationale (strict RFC-3339
                // + 29 days to stay safely inside MAX_GRANT_TTL_SECS).
                let expires_at = {
                    let twenty_nine_days = chrono::Utc::now() + chrono::Duration::days(29);
                    Some(twenty_nine_days.to_rfc3339())
                };
                resolve_approval_via_dashboard(
                    state,
                    req,
                    id,
                    ApprovalOutcome::Always {
                        scope: None,
                        expires_at,
                    },
                    "approved",
                    true,
                )
                .await
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/approvals/")
            && path.ends_with("/approve") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/approvals/")
                    .unwrap()
                    .strip_suffix("/approve")
                    .unwrap();
                match state.store.resolve_approval(id, &ApprovalOutcome::Approved) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"approved": true})),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/approvals/")
            && path.ends_with("/deny") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/approvals/")
                    .unwrap()
                    .strip_suffix("/deny")
                    .unwrap();
                match state.store.resolve_approval(
                    id,
                    &ApprovalOutcome::Denied {
                        reason: "denied via dashboard".to_string(),
                    },
                ) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"denied": true})),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        _ if method == Method::POST && path == "/api/webauthn/auth/complete" => {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                webauthn_auth_complete_not_shipped_response()
            }
        }

        // Dismiss (test handler)
        _ if method == Method::POST
            && path.starts_with("/api/approvals/")
            && path.ends_with("/dismiss") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/approvals/")
                    .unwrap()
                    .strip_suffix("/dismiss")
                    .unwrap();
                match state.store.dismiss_approval(id) {
                    Ok(()) => {
                        json_response(StatusCode::OK, &serde_json::json!({"dismissed": true}))
                    }
                    Err(crate::infra::store::StoreError::NotFound) => {
                        error_response(404, "approval not found")
                    }
                    Err(crate::infra::store::StoreError::AlreadyResolved) => {
                        error_response(409, "approval already resolved")
                    }
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // 69K.7: hard pause toggle
        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/pause") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/pause")
                    .unwrap();
                match state.store.pause_grant(id) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": true})),
                    Err(crate::infra::store::StoreError::NotFound) => {
                        error_response(404, "grant not found")
                    }
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/unpause") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/unpause")
                    .unwrap();
                match state.store.resume_grant(id) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": false})),
                    Err(crate::infra::store::StoreError::NotFound) => {
                        error_response(404, "grant not found")
                    }
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // 69K.7: extend — body not read in test helper (empty body → None params)
        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/extend") =>
        {
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/extend")
                    .unwrap();
                // Test helper: empty body → no deltas; just call extend with None
                match state.store.extend_grant(id, None, None, None) {
                    Ok(g) => json_response(StatusCode::OK, &grant_to_json(&g)),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // 69K.7: all grants including terminated — must come before the detail guard
        (Method::GET, "/api/grants/all") => {
            let grants = state.store.list_all_grants().unwrap_or_default();
            let body: Vec<serde_json::Value> = grants.iter().map(grant_to_json).collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        // 69K.7: grant detail
        // Test handler mirrors
        // production by routing through `grant_to_json_with_store`, so
        // /api/grants/{id} emits the canonical `statements` array (same
        // shape as /api/grants and /api/grants/all).
        _ if method == Method::GET
            && path.starts_with("/api/grants/")
            && !path.ends_with("/revoke")
            && !path.ends_with("/pause")
            && !path.ends_with("/unpause")
            && !path.ends_with("/extend") =>
        {
            let id = path.strip_prefix("/api/grants/").unwrap_or("");
            if id.is_empty() || id.contains('/') {
                error_response(400, "missing or invalid grant id")
            } else {
                match state.store.get_grant(id) {
                    Ok(g) => {
                        json_response(StatusCode::OK, &grant_to_json_with_store(&g, &state.store))
                    }
                    Err(_) => error_response(404, "grant not found"),
                }
            }
        }

        // 69K.7: receipt viewer
        (Method::GET, p) if p.starts_with("/receipts/") => {
            let id = p.strip_prefix("/receipts/").unwrap_or("");
            let accept = req
                .headers()
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let format_param = req.uri().query().and_then(|q| {
                q.split('&').find_map(|kv| {
                    let mut parts = kv.splitn(2, '=');
                    if parts.next() == Some("format") {
                        parts.next()
                    } else {
                        None
                    }
                })
            });
            let want_json = format_param == Some("json")
                || (accept.contains("application/json") && !accept.contains("text/html"));

            if let Ok(signed) = state.store.get_receipt(id) {
                if want_json {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header(
                            "content-disposition",
                            format!("attachment; filename=\"{id}.json\""),
                        )
                        .body(Full::new(Bytes::from(
                            serde_json::to_vec_pretty(&signed).unwrap_or_default(),
                        )))
                        .unwrap()
                } else {
                    let html = build_signed_receipt_html(&signed);
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap()
                }
            } else if let Ok(raw) = state.store.get_receipt_v2_envelope_json(id) {
                if want_json {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header(
                            "content-disposition",
                            format!("attachment; filename=\"{id}.json\""),
                        )
                        .body(Full::new(Bytes::from(raw.clone())))
                        .unwrap()
                } else if let Ok(envelope) =
                    serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
                {
                    let html = build_signed_receipt_v2_html(&envelope, None);
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap()
                } else {
                    error_response(404, "receipt not found")
                }
            } else {
                match state.store.get_grant(id) {
                    Ok(g) => {
                        if let Ok(mut v2_receipts) =
                            state.store.list_receipts_v2_envelopes(&[g.id.clone()])
                            && let Some((rid, _kind, grant_id, envelope)) = v2_receipts.pop()
                        {
                            if want_json {
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .header(
                                        "content-disposition",
                                        format!("attachment; filename=\"{rid}.json\""),
                                    )
                                    .body(Full::new(Bytes::from(
                                        serde_json::to_vec_pretty(&envelope).unwrap_or_default(),
                                    )))
                                    .unwrap()
                            } else {
                                let html = build_signed_receipt_v2_html(&envelope, Some(&grant_id));
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "text/html; charset=utf-8")
                                    .body(Full::new(Bytes::from(html)))
                                    .unwrap()
                            }
                        } else if want_json {
                            let receipt = build_receipt_json(&g);
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .header(
                                    "content-disposition",
                                    format!("attachment; filename=\"receipt-{id}.json\""),
                                )
                                .body(Full::new(Bytes::from(
                                    serde_json::to_vec_pretty(&receipt).unwrap_or_default(),
                                )))
                                .unwrap()
                        } else {
                            let chain = state.store.get_access_grant(&g.id).ok();
                            let html = build_receipt_html(&g, &state.csrf_token, chain.as_ref());
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/html; charset=utf-8")
                                .body(Full::new(Bytes::from(html)))
                                .unwrap()
                        }
                    }
                    Err(_) => error_response(404, "grant not found"),
                }
            }
        }

        // 69K.7: SSE
        (Method::GET, p) if p.starts_with("/sse/grants/") => {
            let grant_id = p.strip_prefix("/sse/grants/").unwrap_or("");
            if grant_id.is_empty() {
                error_response(400, "missing grant id")
            } else {
                match state.store.get_grant(grant_id) {
                    Ok(g) => {
                        let data = serde_json::to_string(&grant_to_json(&g)).unwrap_or_default();
                        let body = format!("retry: 5000\nevent: usage_update\ndata: {data}\n\n");
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/event-stream")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap()
                    }
                    Err(_) => error_response(404, "grant not found"),
                }
            }
        }

        // Test handler for `/api/receipts/stream`.
        // Mirrors the production single-shot SSE snapshot so route
        // tests can assert content-type + framing without spinning
        // up a real listener.
        (Method::GET, "/api/receipts/stream") => {
            use crate::infra::receipt::ReceiptFilter;
            let filter = ReceiptFilter {
                limit: Some(50),
                ..Default::default()
            };
            let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
            let mut body = String::with_capacity(256);
            body.push_str("retry: 1000\n");
            for r in rows.iter().rev() {
                let data = receipt_stream_payload(&state.store, r);
                let payload = serde_json::to_string(&data).unwrap_or_default();
                body.push_str("event: receipt\ndata: ");
                body.push_str(&payload);
                body.push_str("\n\n");
            }
            if rows.is_empty() {
                body.push_str("event: ping\ndata: {}\n\n");
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        // GET /api/receipts — test handler mirrors production filter logic.
        // AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD: supports ?view=rollup|raw.
        (Method::GET, "/api/receipts") => {
            use crate::infra::receipt::ReceiptFilter;
            let (persona_id, signed_only, since_iso, view) = req
                .uri()
                .query()
                .map(|q| {
                    let mut pid: Option<String> = None;
                    let mut signed = false;
                    let mut since: Option<String> = None;
                    let mut view = "rollup".to_string();
                    for kv in q.split('&') {
                        let mut parts = kv.splitn(2, '=');
                        let k = parts.next().unwrap_or("");
                        let v = parts.next().unwrap_or("");
                        match k {
                            "persona_id" if !v.is_empty() => pid = Some(v.to_string()),
                            "signed_only" if v == "true" || v == "1" => signed = true,
                            "view" if !v.is_empty() => view = v.to_string(),
                            "since" => {
                                let now = chrono::Utc::now();
                                since = match v {
                                    "24h" => Some((now - chrono::Duration::hours(24)).to_rfc3339()),
                                    "7d" => Some((now - chrono::Duration::days(7)).to_rfc3339()),
                                    _ => None,
                                };
                            }
                            _ => {}
                        }
                    }
                    (pid, signed, since, view)
                })
                .unwrap_or((None, false, None, "rollup".to_string()));
            let filter = ReceiptFilter {
                persona_id,
                signed_only: false,
                since_iso,
                limit: Some(100),
                kind: None,
                grant_id: None,
                resource: None,
            };
            if view == "raw" {
                let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
                let names = persona_name_map(&state.store);
                let body: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|r| receipt_row_raw_payload(&state.store, r, names.get(&r.actor).cloned()))
                    .filter(|r| !signed_only || r["signed"].as_bool().unwrap_or(false))
                    .collect();
                json_response(StatusCode::OK, &serde_json::Value::Array(body))
            } else {
                let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
                let body = rollup_view(&rows);
                json_response(StatusCode::OK, &body)
            }
        }

        // Test handler mirrors the
        // production `/api/receipts/search` route so `searchReceipts`-
        // style tests can assert filter behavior without spinning up a
        // real listener.
        (Method::GET, "/api/receipts/search") => {
            use crate::infra::receipt::ReceiptFilter;
            let (persona, scope, grant_id, resource) = req
                .uri()
                .query()
                .map(|q| {
                    let mut p: Option<String> = None;
                    let mut s: Option<String> = None;
                    let mut g: Option<String> = None;
                    let mut r: Option<String> = None;
                    for kv in q.split('&') {
                        let mut parts = kv.splitn(2, '=');
                        let k = parts.next().unwrap_or("");
                        let v = parts.next().unwrap_or("");
                        if v.is_empty() {
                            continue;
                        }
                        match k {
                            "persona" => p = Some(v.to_string()),
                            "scope" => s = Some(v.to_string()),
                            "grant_id" => g = Some(v.to_string()),
                            "resource" => r = Some(v.to_string()),
                            _ => {}
                        }
                    }
                    (p, s, g, r)
                })
                .unwrap_or((None, None, None, None));

            let filter = ReceiptFilter {
                persona_id: persona,
                signed_only: false,
                since_iso: None,
                limit: Some(100),
                grant_id,
                kind: None,
                resource: scope.clone().or(resource.clone()),
            };
            let rows = match state.store.list_receipt_rows(&filter) {
                Ok(r) => r,
                Err(_) => return error_response(500, "search failed"),
            };
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| receipt_row_raw_payload(&state.store, r, names.get(&r.actor).cloned()))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/settings/passkeys") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(PASSKEYS_SETTINGS_HTML)))
            .unwrap(),

        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    }
}

#[tokio::test]
async fn dashboard_root_returns_html() {
    let state = make_state();
    let resp = call(state, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"));
}

#[tokio::test]
async fn api_status_returns_json_with_running_true() {
    let state = make_state();
    let resp = call(state, "/api/status").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["running"], true);
}

#[tokio::test]
async fn api_grants_empty_returns_array() {
    let state = make_state();
    let resp = call(state, "/api/grants").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn api_approvals_empty_returns_array() {
    let state = make_state();
    let resp = call(state, "/api/approvals").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
}

#[tokio::test]
async fn api_audit_empty_returns_array() {
    let state = make_state();
    let resp = call(state, "/api/audit").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let state = make_state();
    let resp = call(state, "/api/unknown").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// The old `/api/webauthn/challenge` stub
// (returns random bytes the client claims it signed) is gone;
// the new flow is `/api/webauthn/{register,auth}/{begin,complete}`
// with real signature verification at finish time. The new flow's
// happy path can't be exercised in pure-rust tests (it needs a
// platform authenticator); coverage is on the `_logs_audit_fields`
// store-level test below plus runtime smoke via
// `qember.sh demo headless` (which uses the CLI biometric path
// that also honors `EMBER_DISABLE_BIO=1`).

/// `resolve_approval_with_biometric` records the
/// biometric flag + credential_id in the audit log so an auditor can
/// distinguish hardware-attested approvals from click-throughs.
#[tokio::test]
async fn resolve_approval_with_biometric_logs_audit_fields() {
    use crate::trust::approval::ApprovalOutcome;
    let state = make_state();
    let persona = state.store.create_persona("agent-bio").unwrap();
    let req = state
        .store
        .submit_approval(
            &persona.id,
            "stripe-key",
            "read",
            None,
            "credential:read",
            "low",
        )
        .unwrap();

    state
        .store
        .resolve_approval_with_biometric(
            &req.id,
            &ApprovalOutcome::Approved,
            true,
            Some("touchid:enrollment-abcdef"),
        )
        .unwrap();

    // Walk the audit log and confirm the new biometric fields landed
    // on at least one event tied to this approval. We expect both a
    // grant.issued (legacy event) and an approval.approved (new
    // dedicated event) to carry the fields.
    use crate::infra::audit::AuditFilter;
    let entries = state
        .store
        .query_audit(&AuditFilter {
            limit: Some(50),
            ..Default::default()
        })
        .unwrap();
    let bio_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.details
                .as_deref()
                .map(|d| d.contains("\"biometric\":true"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !bio_entries.is_empty(),
        "expected biometric=true in at least one audit event detail"
    );
    let credential_logged = bio_entries.iter().any(|e| {
        e.details
            .as_deref()
            .map(|d| d.contains("touchid:enrollment-abcdef"))
            .unwrap_or(false)
    });
    assert!(
        credential_logged,
        "expected credential_id=touchid:... in audit detail"
    );
}

#[tokio::test]
async fn api_grants_returns_created_grant() {
    let state = make_state();
    let persona = state.store.create_persona("test-agent").unwrap();
    state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let resp = call(state, "/api/grants").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["persona_id"], persona.id);
}

/// /api/grants list must include the
/// per-Statement array under the canonical field name `statements`
/// (matching grant_to_json_with_store / /api/grants/all / /api/grants/{id})
/// so the dashboard JS can render real scope + budget for multi-statement
/// grants without a `g.statements || g.composite_statements` fallback.
#[tokio::test]
async fn api_grants_list_includes_statements_for_composite_grant() {
    use core_grant_types::{Action, StatementId};
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

    let state = make_state();
    let persona = state.store.create_persona("cstmt-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    // Overwrite blocks_json with a 2-statement composite chain.
    let stmts = vec![
        Statement {
            sid: StatementId::from("SA"),
            resource_type: ResourceType::Credential,
            actions: vec![Action::from("read")],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(2_000),
                ..Default::default()
            }),
            usage: Usage {
                cents: 412,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: StatementId::from("SB"),
            resource_type: ResourceType::Session,
            actions: vec![Action::from("create")],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
    ];
    let root = state.store.persona_root_keypair(&persona.id).unwrap();
    let chain = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        &persona.id,
        "api-key",
        stmts,
        0,
        Some(9_999_999_999),
        &root,
    )
    .unwrap();
    let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        )
        .unwrap();

    let resp = call(Arc::clone(&state), "/api/grants").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);

    let stmts_field = arr[0]["statements"]
        .as_array()
        .expect("statements must be an array");
    assert_eq!(stmts_field.len(), 2, "should have 2 statements");

    // Assert the legacy
    // `composite_statements` field is gone from /api/grants. The list
    // endpoint must align on `statements` (the canonical name used by
    // /api/grants/all and /api/grants/{id}).
    assert!(
        arr[0].get("composite_statements").is_none(),
        "/api/grants must not emit legacy `composite_statements` — \
         field name is canonical `statements`"
    );

    // SA has a cents budget — the demo gauge needs to read it.
    let sa = stmts_field
        .iter()
        .find(|s| s["sid"] == "SA")
        .expect("SA statement must be present");
    assert_eq!(sa["budget"]["cents"], 2_000, "SA budget.cents must be 2000");
    assert_eq!(sa["usage"]["cents"], 412, "SA usage.cents must be 412");

    // SB has no budget.
    let sb = stmts_field
        .iter()
        .find(|s| s["sid"] == "SB")
        .expect("SB statement must be present");
    assert!(sb["budget"].is_null(), "SB budget must be null");
}

/// /api/grants list and
/// /api/grants/{id} detail must emit the per-Statement array under the
/// same field name (`statements`). Without this, dashboard JS callers
/// have to fall back through `g.statements || g.composite_statements`
/// and the two endpoints drift.
#[tokio::test]
async fn api_grants_list_and_detail_field_shapes_match() {
    use core_grant_types::{Action, StatementId};
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

    let state = make_state();
    let persona = state.store.create_persona("parity-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let stmts = vec![Statement {
        sid: StatementId::from("SX"),
        resource_type: ResourceType::Credential,
        actions: vec![Action::from("read")],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            cents: Some(1_000),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    }];
    let root = state.store.persona_root_keypair(&persona.id).unwrap();
    let chain = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        &persona.id,
        "api-key",
        stmts,
        0,
        Some(9_999_999_999),
        &root,
    )
    .unwrap();
    let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        )
        .unwrap();

    // 1. List endpoint /api/grants
    let list_resp = call(Arc::clone(&state), "/api/grants").await;
    let list_body = http_body_util::BodyExt::collect(list_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let list_json: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
    let list_arr = list_json.as_array().expect("/api/grants returns an array");
    let list_entry = list_arr
        .iter()
        .find(|e| e["id"] == grant.id)
        .expect("list endpoint must include the test grant");

    // 2. Detail endpoint /api/grants/{id}
    let detail_resp = call(Arc::clone(&state), &format!("/api/grants/{}", grant.id)).await;
    let detail_body = http_body_util::BodyExt::collect(detail_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let detail_json: serde_json::Value = serde_json::from_slice(&detail_body).unwrap();

    // Parity: both must emit `statements` as an array; neither must
    // emit `composite_statements`.
    assert!(
        list_entry["statements"].is_array(),
        "/api/grants must emit `statements` as an array"
    );
    assert!(
        detail_json["statements"].is_array(),
        "/api/grants/{{id}} must emit `statements` as an array"
    );

    // dashboard_agent_tree_view_promoted
    // Slice A: list + detail must both expose parent_persona_id,
    // parent_persona_name, and revoked_sids so the Active Agents tile
    // can render the delegation tree + inline revoke without a
    // follow-up detail fetch.
    for field in ["parent_persona_id", "parent_persona_name", "revoked_sids"] {
        assert!(
            list_entry.get(field).is_some(),
            "/api/grants must emit field {field:?}; got keys: {:?}",
            list_entry
                .as_object()
                .map(|m| m.keys().collect::<Vec<_>>())
                .unwrap_or_default()
        );
        assert!(
            detail_json.get(field).is_some(),
            "/api/grants/{{id}} must emit field {field:?}; got keys: {:?}",
            detail_json
                .as_object()
                .map(|m| m.keys().collect::<Vec<_>>())
                .unwrap_or_default()
        );
    }
    // For a root grant (no parent), parent_persona_id is null.
    assert!(
        list_entry["parent_persona_id"].is_null(),
        "root grant must emit parent_persona_id as null on list endpoint"
    );
    assert!(
        detail_json["parent_persona_id"].is_null(),
        "root grant must emit parent_persona_id as null on detail endpoint"
    );
    // revoked_sids defaults to empty array (no revocations yet).
    assert!(
        list_entry["revoked_sids"].is_array(),
        "revoked_sids must be an array on list endpoint"
    );
    assert!(
        detail_json["revoked_sids"].is_array(),
        "revoked_sids must be an array on detail endpoint"
    );
    assert!(
        list_entry.get("composite_statements").is_none(),
        "/api/grants must not emit legacy `composite_statements` field"
    );
    assert!(
        detail_json.get("composite_statements").is_none(),
        "/api/grants/{{id}} must not emit legacy `composite_statements` field"
    );

    // Same length and same per-statement shape.
    let list_stmts = list_entry["statements"].as_array().unwrap();
    let detail_stmts = detail_json["statements"].as_array().unwrap();
    assert_eq!(
        list_stmts.len(),
        detail_stmts.len(),
        "list + detail statements arrays must have the same length"
    );
    // Per-Statement field shape parity — list and detail must emit the
    // exact same per-Statement shape (sid, block_index, resource_type,
    // actions, resource, budget, usage, conditions).
    for (list_s, detail_s) in list_stmts.iter().zip(detail_stmts.iter()) {
        for field in [
            "sid",
            "block_index",
            "resource_type",
            "actions",
            "resource",
            "budget",
            "usage",
            "conditions",
        ] {
            assert_eq!(
                list_s[field], detail_s[field],
                "statements[].{field} must match across /api/grants and /api/grants/{{id}}"
            );
        }
    }
}

#[tokio::test]
async fn api_status_counts_reflect_store_state() {
    let state = make_state();
    let persona = state.store.create_persona("agent-x").unwrap();
    state
        .store
        .create_grant(&persona.id, "key", "read", None)
        .unwrap();
    state
        .store
        .submit_approval(&persona.id, "key2", "write", None, "access", "high")
        .unwrap();
    state
        .store
        .log_event(Some(&persona.id), "test.event", None, "ok", None)
        .unwrap();

    let resp = call(Arc::clone(&state), "/api/status").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active_grants"], 1);
    assert_eq!(json["pending_approvals"], 1);
    // create_grant now emits a grant.minted event plus the explicit test.event = 2
    assert_eq!(json["audit_events"], 2);
    assert_eq!(json["active_agents"], 1);
}

#[tokio::test]
async fn post_revoke_nonexistent_grant_returns_error() {
    let state = make_state();
    let resp = call_post(state, "/api/grants/nonexistent/revoke").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn post_approve_nonexistent_approval_returns_error() {
    let state = make_state();
    let resp = call_post(state, "/api/approvals/nonexistent/approve").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
}

#[tokio::test]
async fn post_revoke_grant_succeeds() {
    let state = make_state();
    let persona = state.store.create_persona("agent-r").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "key", "read", None)
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/revoke", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["revoked"], true);
}

#[tokio::test]
async fn post_approve_approval_succeeds() {
    let state = make_state();
    let persona = state.store.create_persona("agent-a").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/approve", req.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["approved"], true);
}

#[tokio::test]
async fn post_deny_approval_succeeds() {
    let state = make_state();
    let persona = state.store.create_persona("agent-d").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/deny", req.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["denied"], true);
}

#[tokio::test]
async fn api_anomalies_empty_returns_array() {
    let state = make_state();
    let resp = call(state, "/api/anomalies").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn api_grants_includes_conditions_field() {
    let state = make_state();
    let persona = state.store.create_persona("agent-cond").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    // Set rate_limit and time_window conditions directly in the store.
    state.store.conn().execute(
        "UPDATE grants SET max_uses_per_hour = 10, allowed_hours_start = 9, allowed_hours_end = 17 WHERE id = ?1",
        rusqlite::params![grant.id],
    ).unwrap();

    let resp = call(state, "/api/grants").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let conditions = &arr[0]["conditions"];
    assert!(
        conditions.is_object(),
        "conditions should be an object when grant has conditions"
    );
    assert_eq!(conditions["rate_limit"], "10/hour");
    assert_eq!(conditions["time_window"], "9:00-17:00 UTC");
}

#[tokio::test]
async fn api_anomalies_detects_high_denial_rate() {
    let state = make_state();
    for _ in 0..4 {
        state
            .store
            .log_event(
                Some("agent-flagged"),
                "credential.access",
                None,
                "denied",
                None,
            )
            .unwrap();
    }
    let resp = call(state, "/api/anomalies").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["agent_id"], "agent-flagged");
    assert_eq!(arr[0]["severity"], "medium");
}

#[tokio::test]
async fn api_health_returns_200_with_status_ok() {
    let state = make_state();
    let resp = call(state, "/api/health").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    // uptime_secs must reflect elapsed time since state construction, not Unix epoch.
    let uptime = json["uptime_secs"]
        .as_u64()
        .expect("uptime_secs must be a u64");
    assert!(
        uptime < 10,
        "uptime_secs={uptime} looks like Unix epoch, not elapsed seconds"
    );
}

// --- CSRF protection tests ---

#[tokio::test]
async fn html_contains_csrf_token() {
    let state = make_state();
    let resp = call(state, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains(&format!("const CSRF_TOKEN = \"{}\";", TEST_CSRF_TOKEN)),
        "expected CSRF_TOKEN constant in HTML"
    );
    // Placeholder must be fully substituted.
    assert!(
        !s.contains("{{CSRF_TOKEN}}"),
        "placeholder should be replaced"
    );
    assert!(
        s.contains("href=\"/receipts/'+encodeURIComponent(String(r.id||''))+'\""),
        "live receipts panel should deep-link streamed rows to receipt detail pages"
    );
    assert!(
        s.contains(
            "const receiptLink=`<a href=\"/receipts/${encodeURIComponent(String(r.id||''))}\""
        ),
        "receipts table rows should deep-link summaries to receipt detail pages"
    );
    assert!(
        s.contains("href=\"/receipts/${encodeURIComponent(String(s.receipt_hash||''))}\""),
        "rollup sub-receipt rows should deep-link hashes to receipt detail pages"
    );
    assert!(
        s.contains("function _renderRawReceiptRow(r){"),
        "raw/search tables should share one receipt row renderer"
    );
    assert!(
        s.contains("function _receiptReasonLabel(v){"),
        "raw/search tables should normalize terminal reason copy"
    );
    assert!(
        s.contains("const kindBadge=`<span class=\"badge\""),
        "raw/search tables should surface receipt kind badges"
    );
}

#[tokio::test]
async fn generate_csrf_token_is_64_hex_chars() {
    let t = generate_csrf_token().expect("rng should work");
    assert_eq!(t.len(), 64);
    assert!(
        t.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // Two consecutive calls must differ (randomness sanity check).
    let t2 = generate_csrf_token().expect("rng should work");
    assert_ne!(t, t2);
}

#[tokio::test]
async fn post_approve_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/approvals/fake-id/approve").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("csrf"));
}

#[tokio::test]
async fn post_approve_with_wrong_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_wrong_csrf(state, "/api/approvals/fake-id/approve").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_deny_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/approvals/fake-id/deny").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_revoke_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/grants/fake-id/revoke").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_approve_with_valid_csrf_passes_csrf_check() {
    // With a valid token but a non-existent approval id we expect 400 (store
    // error), NOT 403 — proving the CSRF guard allowed the request through.
    let state = make_state();
    let resp = call_post(state, "/api/approvals/fake-id/approve").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn webauthn_auth_complete_returns_501_and_no_presence_token() {
    let state = make_state();
    let resp = call_post(Arc::clone(&state), "/api/webauthn/auth/complete").await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not a shipped daemon presence-token surface"),
        "error should explain that browser auth-complete is disabled as a daemon token surface"
    );
    assert!(
        json.get("presence_token").is_none(),
        "fail-closed response must not include a presence token"
    );
}

#[tokio::test]
async fn webauthn_auth_complete_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/webauthn/auth/complete").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// --- /approvals/<id> deep-link route tests ---

#[tokio::test]
async fn approval_deep_link_returns_200_with_approve_button() {
    let state = make_state();
    let persona = state.store.create_persona("agent-deep").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "my-key", "read", None, "access", "high")
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"));
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(s.contains("Approve"), "page should contain Approve button");
    assert!(s.contains("Deny"), "page should contain Deny button");
    assert!(s.contains(&req.id), "page should embed approval id for JS");
    assert!(s.contains("access"), "page should show action");
    assert!(s.contains("my-key"), "page should show credential");
}

#[tokio::test]
async fn approval_deep_link_unknown_id_returns_404() {
    let state = make_state();
    let resp = call(state, "/approvals/approval-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("not found") || s.contains("resolved"),
        "404 page should explain the state"
    );
}

#[tokio::test]
async fn approval_deep_link_embeds_csrf_token() {
    let state = make_state();
    let persona = state.store.create_persona("agent-csrf-check").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "k", "read", None, "access", "low")
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains(&format!("const CSRF_TOKEN = \"{}\";", TEST_CSRF_TOKEN)),
        "deep-link page must embed CSRF token"
    );
}

#[tokio::test]
async fn approval_deep_link_approve_via_post_respects_csrf() {
    let state = make_state();
    let persona = state.store.create_persona("agent-dl-approve").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "k", "read", None, "access", "low")
        .unwrap();

    // POST approve with valid CSRF — should succeed (200, approved: true)
    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/approve", req.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["approved"], true);

    // After resolution, the deep-link page still returns 200 (record exists but is resolved).
    // The JS on that page handles showing the resolved state after the action buttons fire.
    let resp2 = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp2.status(), StatusCode::OK);
}

#[tokio::test]
async fn approval_deep_link_approve_without_csrf_returns_403() {
    let state = make_state();
    let persona = state.store.create_persona("agent-dl-nocsrf").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "k", "read", None, "access", "low")
        .unwrap();

    let resp = call_post_no_csrf(state, &format!("/api/approvals/{}/approve", req.id)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approval_deep_link_renders_composite_breakdown_inline() {
    // The dedicated /approvals/{id} page must
    // surface the full per-statement breakdown inline, never gated
    // behind a "Show details" disclosure. The operator must never be
    // one click away from approving authority chains they cannot see.
    // Asserts:
    //   1. The legacy <details class="composite-disclosure"> wrapper
    //      is gone — replaced by an always-rendered statements section
    //      that JS unhides as soon as the first poll returns the
    //      composite_statements list.
    //   2. The flat Credential and Scope rows have ids so the same JS
    //      poll can hide them (the row's flat columns are statement
    //      0's projection — misleading for a multi-statement chain).
    //   3. The shared renderCompositeStatements helper is present so
    //      the dashboard card and this page never drift.
    let state = make_state();
    let persona = state.store.create_persona("agent-composite").unwrap();
    let req = state
        .store
        .submit_approval(
            &persona.id,
            "github-key",
            "composite",
            None,
            "credential.access",
            "high",
        )
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();

    // Legacy disclosure must NOT appear — that was the UX bug.
    assert!(
        !s.contains(r#"composite-disclosure"#),
        "legacy `composite-disclosure` block must be removed — breakdown is always inline now",
    );
    assert!(
        !s.contains("<summary>Show details</summary>"),
        "legacy `Show details` disclosure summary must be removed",
    );

    // The new always-visible statements section must be present (and
    // hidden until JS confirms composite_statements actually exist;
    // single-statement approvals leave it hidden permanently).
    assert!(
        s.contains(r#"id="statements-section""#),
        "always-rendered statements section must be present",
    );
    assert!(
        s.contains(r#"id="composite-breakdown""#),
        "composite-breakdown container must be present so JS can populate it",
    );

    // The flat Credential and Scope rows must be tagged with ids so
    // the renderBreakdown JS can hide them on composite approvals.
    assert!(
        s.contains(r#"id="credential-row""#),
        "Credential row must be tagged so JS can hide it for composite approvals",
    );
    assert!(
        s.contains(r#"id="scope-row""#),
        "Scope row must be tagged so JS can hide it for composite approvals",
    );

    // Shared helper baked in (single source of truth with dashboard card).
    assert!(
        s.contains("function renderCompositeStatements"),
        "shared renderCompositeStatements helper must be present in the page"
    );
    // Approve/Deny must be the leading decision.
    assert!(s.contains("Approve"));
    assert!(s.contains("Deny"));
}

// --- composite render polish ---

#[tokio::test]
async fn composite_statements_js_handles_internally_tagged_resource_selector() {
    // Regression for the dashboard render bug where `ResourceSelector`
    // is serde-serialized as `{kind:"exact",value:"..."}` (internally
    // tagged) but the JS checked `'Exact' in s.resource` (externally
    // tagged), so every resource fell through to `*`. Assert the
    // shipped JS now reads the `kind` discriminant directly.
    let state = make_state();
    let resp = call(state, "/").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("function renderResourceSelector"),
        "JS must expose the renderResourceSelector helper",
    );
    assert!(
        s.contains("r.kind === 'exact'") && s.contains("r.kind === 'glob'"),
        "JS must read the serde internally-tagged enum format \
         (`kind: 'exact'|'glob'`); the legacy `'Exact' in r` shape \
         always falls through to `*`",
    );
}

#[tokio::test]
async fn dashboard_escapes_agent_controlled_innerhtml() {
    // D21 — agent-controlled fields (anomaly description/agent_id, persona
    // names, credential names, scopes, action keys, rollup outcome/denial
    // reason) are rendered into innerHTML. Without HTML-escaping, a string
    // like `<img src=x onerror=...>` in any of those fields is stored XSS
    // against the operator viewing the dashboard. Assert the served page
    // exposes a module-scope escaper and routes the agent-controlled sinks
    // through it.
    let state = make_state();
    let resp = call(state, "/").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    // Module-scope escaper present in the served (assembled) page.
    assert!(
        s.contains("function escapeHtml("),
        "served dashboard must define the module-scope escapeHtml helper",
    );
    // Anomaly card sinks (the named D21 site).
    assert!(
        s.contains("escapeHtml(a.description") && s.contains("escapeHtml(a.agent_id"),
        "anomaly agent_id/description must be HTML-escaped",
    );
    // Rollup receipt view sinks (previously escaped nothing).
    assert!(
        s.contains("escapeHtml(r.persona") && s.contains("escapeHtml(r.outcome"),
        "rollup persona/outcome must be HTML-escaped",
    );
    // Helper boundaries that fan out to many call sites.
    assert!(
        s.contains("${escapeHtml(cls)}") && s.contains("escapeHtml(name)"),
        "badge() and personaLabel() must HTML-escape their agent-controlled inputs",
    );
    // Regression: _renderRawReceiptRow previously called a `safe()` that
    // was only in scope inside the live-stream IIFE — a latent
    // ReferenceError on the raw/searched receipt view. It must now use the
    // module-scope escaper.
    assert!(
        s.contains("escapeHtml(r.kind||'receipt')"),
        "raw receipt row must escape via the in-scope module escaper",
    );
    assert!(
        !s.contains("${safe(r.kind"),
        "raw receipt row must not reference the out-of-scope IIFE-local safe()",
    );
    // JS-string-inside-HTML-attribute sinks (onclick) carry agent-controlled
    // data (maturation c.action; rollup materialization_id). JSON.stringify
    // alone guards the JS layer but its `"` breaks the double-quoted
    // attribute → attribute-breakout XSS. Must be escapeHtml(JSON.stringify()).
    assert!(
        s.contains("escapeHtml(JSON.stringify(c.action||''))"),
        "maturation Scaffold onclick must HTML-escape the JSON-encoded action",
    );
    assert!(
        s.contains("_toggleRollupDetail(${escapeHtml(JSON.stringify(mid))})"),
        "rollup toggle onclick must HTML-escape the JSON-encoded materialization id",
    );
    assert!(
        !s.contains("_toggleRollupDetail('${mid}')"),
        "rollup toggle must not interpolate raw mid into the onclick JS string",
    );
}

#[test]
fn approval_page_escapes_agent_controlled_fields() {
    // Server-side stored XSS regression: render_approval_page substitutes
    // agent-supplied credential_name / scope / action / skill_ref / persona
    // name into HTML. An agent picks those when requesting approval; the
    // operator's approval page holds the CSRF token + drives the Touch-ID
    // ceremony, so script execution there defeats the human approval gate.
    let a: crate::trust::approval::ApprovalRequestInfo =
        serde_json::from_value(serde_json::json!({
            "id": "appr-xss-1",
            "persona_id": "persona-abc123",
            "credential_name": "<img src=x onerror=alert('cred')>",
            "scope": "repo:\"><script>alert('scope')</script>",
            "action": "gh.pr_create<script>alert('action')</script>",
            "risk_level": "high",
            "status": "pending",
            "created_at": "2026-05-31T00:00:00Z",
            "skill_ref": "<script>alert('skill')</script>",
        }))
        .expect("fixture approval deserializes");
    let html = render_approval_page("csrf-tok", &a, Some("Bad<script>alert('name')</script>"));
    // No raw agent payload survives into the page.
    assert!(
        !html.contains("<script>alert("),
        "no unescaped <script> from agent fields may reach the approval page",
    );
    assert!(
        !html.contains("<img src=x onerror="),
        "no unescaped event-handler markup from credential_name",
    );
    // The escaped forms are present (proves the values rendered, escaped).
    assert!(
        html.contains("&lt;script&gt;alert(&#39;action&#39;)")
            && html.contains("&lt;img src=x onerror="),
        "agent fields must render HTML-escaped",
    );
}

#[tokio::test]
async fn dashboard_card_template_routes_composite_through_detail_review() {
    // Composite approvals are multi-statement
    // chains; the dashboard pending-approvals card only shows the
    // summary ("composite (N statements)"), not the breakdown. The
    // operator must never approve a chain they cannot see, so the
    // card's button strip for composite approvals is
    // "Review & Approve" + "Deny" only — the Approve / Approve
    // Always buttons live on the detail page where the full
    // breakdown renders inline.
    //
    // Single-statement approvals keep the inline Approve buttons
    // because all the info is on the card.
    //
    // We can't directly test the JS rendering output, but we can
    // assert the rendered HTML inlines the conditional: a `stmts`
    // ternary that picks Review-and-Approve for composites.
    let state = make_state();
    let resp = call(state, "/").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("Review &amp; Approve"),
        "composite cards must surface a `Review & Approve` button so the operator clicks through to the breakdown",
    );
    assert!(
        !s.contains(r#"<button class="btn-dismiss""#),
        "Dismiss (X) button must be removed — operators decide via Approve / Deny / Review, not a vague third option",
    );
}

#[tokio::test]
async fn composite_statement_render_drops_on_star_for_any_resource() {
    // `time:wall_clock on * · 90s` reads as
    // technical noise; time isn't bound to a resource. When the
    // selector resolves to wildcard, the JS render now elides the
    // `on *` clause. Assert the shipped helper contains the elision
    // logic (the runtime behavior is JS, but we can verify the
    // helper's source ships with the guard).
    let state = make_state();
    let resp = call(state, "/").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("(resource === '*')"),
        "JS must check resource === '*' to elide the noisy `on *` clause",
    );
}

#[tokio::test]
async fn composite_summary_does_not_advertise_click_to_review_on_detail_page() {
    // The detail page shows the breakdown in an inline disclosure on
    // the same surface, so "click to review" is misleading once the
    // disclosure is open. compositeSummary now returns the bare
    // statement count; the dashboard card's anchor styling indicates
    // it is clickable.
    let state = make_state();
    let resp = call(state, "/").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        !s.contains("click to review"),
        "compositeSummary must not advertise 'click to review' — the affordance is the link styling, not the label",
    );
}

#[tokio::test]
async fn approval_detail_page_renders_composite_action_label() {
    // For composite approvals, the row's flat `action` column is
    // statement 0's verb, which misrepresents a multi-verb chain
    // (e.g. an Anthropic+budget+session bundle showing as
    // "credential.access"). Assert the dedicated /approvals/{id}
    // page renders an honest "composite (N statements)" label.
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
    let state = make_state();
    let persona = state.store.create_persona("agent-render-action").unwrap();
    let stmts = vec![
        Statement {
            sid: "s0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".into()],
            resource: ResourceSelector::Exact { value: "k".into() },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "s1".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Glob {
                pattern: "*".into(),
            },
            budget: Some(Budget {
                tokens: Some(1),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
    ];
    let req = state
        .store
        .propose_grant(
            &persona.id,
            "k",
            "composite",
            Some(60),
            "credential.access",
            "low",
            stmts,
        )
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("composite (2 statements)"),
        "composite Action field must read 'composite (N statements)', not the row's flat action verb",
    );
    assert!(
        !s.contains(">credential.access<"),
        "the legacy `credential.access` flat-action label must not leak into the composite Action field",
    );
}

#[tokio::test]
async fn approval_detail_page_renders_persona_name_with_identifier() {
    // Persona field shows "<name> <identifier>"
    // so the operator sees both the human-friendly handle (e.g.
    // `qa`) and the unique persona-id suffix used in audit logs
    // and grant chains. The previous "name only" rendering hid the
    // disambiguator that's necessary when multiple personas share
    // a friendly name.
    let state = make_state();
    let persona = state.store.create_persona("qa").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "k", "read", None, "credential.access", "low")
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    // Both the friendly name and the truncated UUID must be present.
    assert!(
        s.contains("qa <span class=\"persona-id\">persona-"),
        "Persona field must show name + identifier as `<name> <span class=persona-id>persona-...</span>`",
    );
}

#[tokio::test]
async fn dashboard_html_inlines_shared_composite_helper() {
    // The dashboard pending-approvals card and
    // the dedicated /approvals/{id} page share a single JS helper for
    // rendering the composite-statement breakdown. Assert the helper is
    // baked into the dashboard HTML so the two surfaces cannot drift.
    let state = make_state();
    let resp = call(state, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("function renderCompositeStatements"),
        "dashboard must inline the shared renderCompositeStatements helper"
    );
    // The placeholder must be substituted, not left raw.
    assert!(
        !s.contains("{{COMPOSITE_STATEMENTS_JS}}"),
        "COMPOSITE_STATEMENTS_JS placeholder must be replaced"
    );
}

// --- GET /api/approvals/<id> per-approval JSON endpoint tests ---

#[tokio::test]
async fn api_approval_by_id_returns_200_with_json_body() {
    let state = make_state();
    let persona = state.store.create_persona("agent-poll").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "poll-key", "read", None, "access", "low")
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/api/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("application/json"));
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], req.id);
    assert_eq!(json["status"], "pending");
    assert_eq!(json["credential_name"], "poll-key");
}

#[tokio::test]
async fn api_approval_by_id_reflects_resolved_status() {
    let state = make_state();
    let persona = state.store.create_persona("agent-poll-resolved").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "k", "read", None, "access", "low")
        .unwrap();

    // Resolve via approve
    state
        .store
        .resolve_approval(&req.id, &ApprovalOutcome::Approved)
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/api/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "approved");
}

#[tokio::test]
async fn api_approval_by_nonexistent_id_returns_404() {
    let state = make_state();
    let resp = call(state, "/api/approvals/approval-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().is_some());
}

#[tokio::test]
async fn api_approvals_approve_always_endpoint_works() {
    let state = make_state();
    let persona = state.store.create_persona("agent-always").unwrap();
    let req = state
        .store
        .submit_approval(
            &persona.id,
            "key",
            "read",
            None,
            "credential.access.github-token",
            "low",
        )
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/approve-always", req.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["approved"], true);
    assert_eq!(json["standing_grant_created"], true);
    assert_eq!(
        json["biometric"], false,
        "test fixture has no WebAuthn gate, but approve-always must still route through the shared approval helper"
    );
    assert_eq!(json["credential_id"], serde_json::Value::Null);

    // Approval should be resolved
    let resolved = state.store.get_approval(&req.id).unwrap();
    assert_eq!(resolved.status, "approved");

    // A standing grant should exist for the action
    let standing = state.store.list_standing_grants().unwrap();
    assert_eq!(standing.len(), 1);
    assert_eq!(
        standing[0].action_selector,
        core_event_types::ActionSelector::named("credential.access.github-token")
    );
    assert_eq!(standing[0].persona_id, persona.id);
    // Standing grant should have a future expires_at (30 days from now)
    assert!(standing[0].expires_at.is_some());
}

#[tokio::test]
async fn api_approvals_approve_always_without_csrf_returns_403() {
    let state = make_state();
    let persona = state.store.create_persona("agent-always-nocsrf").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();

    let resp = call_post_no_csrf(state, &format!("/api/approvals/{}/approve-always", req.id)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// --- 69K.7: budget gauge, pause/extend, receipt viewer tests ---

#[tokio::test]
async fn api_grants_pause_toggles_paused_flag() {
    let state = make_state();
    let persona = state.store.create_persona("agent-pause").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    // Verify initially not paused
    let g0 = state.store.get_grant(&grant.id).unwrap();
    assert!(!g0.paused);
    assert_eq!(g0.status, "active");

    // Pause via endpoint — hard pause sets status='paused'
    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/pause", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["paused"], true);

    // Verify store state: status is 'paused' and paused flag is set
    let g1 = state.store.get_grant(&grant.id).unwrap();
    assert!(g1.paused);
    assert_eq!(g1.status, "paused");

    // Unpause — restores status='active'
    let resp2 = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/unpause", grant.id),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let g2 = state.store.get_grant(&grant.id).unwrap();
    assert!(!g2.paused);
    assert_eq!(g2.status, "active");
}

#[tokio::test]
async fn api_grants_extend_calls_extend_grant_method() {
    let state = make_state();
    let persona = state.store.create_persona("agent-extend").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", Some(3600))
        .unwrap();
    let original_expires = grant.expires_at.clone();

    // Call extend with empty body (test helper applies no deltas, just re-fetches)
    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/extend", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], grant.id);
    // With no deltas the expires_at should be unchanged
    assert_eq!(json["expires_at"].as_str(), original_expires.as_deref());
}

#[tokio::test]
async fn dashboard_renders_budget_gauge_when_grant_has_budget() {
    let state = make_state();
    let persona = state.store.create_persona("agent-gauge").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "*:read", None)
        .unwrap();
    // Set budget + usage on the first-statement of the chain. V0
    // schema: the envelope-level `budget` / `usage` fields are gone;
    // consumers read from the `statements` array. Block 0 must be
    // re-signed after the mutation or `verify_chain` rejects on read.
    let mut chain = state.store.get_access_grant(&grant.id).unwrap();
    if let Some(block) = chain.blocks.first_mut()
        && let Some(stmt) = block.block.statements.first_mut()
    {
        stmt.budget = Some(core_grant_types::Budget {
            tokens: Some(20_000),
            ..Default::default()
        });
        stmt.usage = core_grant_types::Usage {
            tokens: 5_000,
            ..Default::default()
        };
    }
    if let Some(first) = chain.blocks.first_mut() {
        let root = state.store.persona_root_keypair(&persona.id).unwrap();
        let resigned = core_crypto::grant_chain::sign_block_zero(&root, &first.block).unwrap();
        *first = resigned.signed;
    }
    let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        )
        .unwrap();

    // Get grant from API — budget + usage live on `statements[0]`.
    let resp = call(Arc::clone(&state), "/api/grants").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["statements"][0]["budget"]["tokens"], 20000);
    assert_eq!(arr[0]["statements"][0]["usage"]["tokens"], 5000);
}

#[tokio::test]
async fn dashboard_renders_view_receipt_link_when_grant_terminal() {
    let state = make_state();
    let persona = state.store.create_persona("agent-receipt").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    // Revoke to make it terminal
    state.store.revoke_grant(&grant.id).unwrap();

    // /api/grants/all should include the revoked grant
    let resp = call(Arc::clone(&state), "/api/grants/all").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    let revoked = arr
        .iter()
        .find(|g| g["id"] == grant.id)
        .expect("revoked grant in list");
    assert_eq!(revoked["status"], "revoked");

    // Receipt viewer returns HTML
    let resp2 = call(Arc::clone(&state), &format!("/receipts/{}", grant.id)).await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = http_body_util::BodyExt::collect(resp2.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body2).unwrap();
    assert!(
        s.contains("Grant Receipt"),
        "receipt page should have title"
    );
    assert!(s.contains(&grant.id), "receipt page should embed grant id");
    assert!(
        s.contains("Download JSON"),
        "receipt page should have download button"
    );
}

#[tokio::test]
async fn sse_endpoint_returns_event_stream() {
    let state = make_state();
    let persona = state.store.create_persona("agent-sse").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let resp = call(state, &format!("/sse/grants/{}", grant.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "SSE endpoint must return event-stream content-type"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(s.contains("event:"), "SSE body should contain event type");
    assert!(s.contains("data:"), "SSE body should contain data field");
}

#[tokio::test]
async fn sse_endpoint_unknown_grant_returns_404() {
    let state = make_state();
    let resp = call(state, "/sse/grants/grant-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// `/api/receipts/stream` is the live receipts panel
// SSE feed. Empty-store path must still return 200 + event-stream
// content-type so the EventSource client transitions to `open`.
#[tokio::test]
async fn receipts_stream_endpoint_returns_event_stream() {
    let state = make_state();
    let resp = call(state, "/api/receipts/stream").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "receipts stream must return event-stream content-type, got {ct}"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(s.contains("retry:"), "SSE body should carry a retry hint");
    assert!(
        s.contains("event:"),
        "SSE body should contain at least one event (ping when empty)"
    );
}

#[tokio::test]
async fn receipts_stream_includes_segmented_claim_summary_fields_for_session_receipts() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("stream-session").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    let _receipt_id = store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(state, "/api/receipts/stream").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("\"kind\":\"session.composite_grant\""),
        "got:\n{s}"
    );
    assert!(s.contains("\"claim_count_total\":9"), "got:\n{s}");
    assert!(s.contains("\"claim_segment_count\":2"), "got:\n{s}");
    assert!(s.contains("\"claim_events_truncated\":true"), "got:\n{s}");
}

#[tokio::test]
async fn pause_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/grants/fake-id/pause").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn extend_without_csrf_returns_403() {
    let state = make_state();
    let resp = call_post_no_csrf(state, "/api/grants/fake-id/extend").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn receipt_viewer_nonexistent_grant_returns_404() {
    let state = make_state();
    let resp = call(state, "/receipts/grant-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn receipt_viewer_renders_v2_session_receipt_by_receipt_id() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("session-viewer").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    let receipt_id = store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(Arc::clone(&state), &format!("/receipts/{receipt_id}")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("Session Receipt"), "got:\n{html}");
    assert!(html.contains("session.composite_grant"), "got:\n{html}");
    assert!(html.contains("Claim Rollup"), "got:\n{html}");
    assert!(html.contains("Claim count total"), "got:\n{html}");
    assert!(html.contains("emberd-development"), "got:\n{html}");
    assert!(html.contains("budget exhausted"), "got:\n{html}");
}

#[tokio::test]
async fn receipt_viewer_returns_v2_session_receipt_json_by_grant_id() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("session-viewer-json").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    let _receipt_id = store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(
        Arc::clone(&state),
        &format!("/receipts/{}?format=json", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["kind"], "session.composite_grant");
    assert_eq!(json["body"]["claim_count_total"], 9);
    assert_eq!(json["body"]["claim_events_truncated"], true);
}

/// Pure-function test: render_statement_gauges emits exactly one wrapper
/// div per statement, shows the SID, and uses "unbounded" when no budget.
#[test]
fn render_statement_gauges_emits_one_div_per_statement() {
    use core_grant_types::{Action, StatementId};
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

    let s0 = Statement {
        sid: StatementId::from("S0"),
        resource_type: ResourceType::Credential,
        actions: vec![Action::from("read")],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            tokens: Some(10_000),
            ..Default::default()
        }),
        usage: Usage {
            tokens: 3_000,
            ..Default::default()
        },
        conditions: vec![],
        can_delegate: None,
    };
    let s1 = Statement {
        sid: StatementId::from("S1"),
        resource_type: ResourceType::Session,
        actions: vec![Action::from("create")],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            cents: Some(500),
            ..Default::default()
        }),
        usage: Usage {
            cents: 125,
            ..Default::default()
        },
        conditions: vec![],
        can_delegate: None,
    };
    let s2 = Statement {
        sid: StatementId::from("S2"),
        resource_type: ResourceType::Credential,
        actions: vec![],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: vec![],
        can_delegate: None,
    };

    let pairs: Vec<(usize, &Statement)> = vec![(0, &s0), (0, &s1), (0, &s2)];
    let html = render_statement_gauges(&pairs);

    // Three wrapper divs — use the unique inline style from render_statement_gauges.
    assert_eq!(
        html.matches(r#"padding:14px;margin-bottom:12px"#).count(),
        3,
        "should emit one wrapper div per statement"
    );

    // SIDs are present
    assert!(html.contains("S0"), "html should contain SID S0");
    assert!(html.contains("S1"), "html should contain SID S1");
    assert!(html.contains("S2"), "html should contain SID S2");

    // S0 has a token gauge
    assert!(html.contains("tokens"), "S0 should render tokens gauge");

    // S1 has a cost gauge
    assert!(html.contains("cost"), "S1 should render cost gauge");

    // S2 is unbounded
    let s2_start = html.rfind("S2").expect("S2 in output");
    let s2_section = &html[s2_start..];
    assert!(
        s2_section.contains("unbounded"),
        "S2 with no budget should say unbounded"
    );
}

/// Integration test: /receipts/{id} shows per-Statement gauges for a
/// 3-statement composite grant.
#[tokio::test]
async fn receipt_html_shows_per_statement_gauges_for_composite_grant() {
    use core_grant_types::{Action, StatementId};
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

    let state = make_state();
    let persona = state.store.create_persona("p-3stmt").unwrap();
    // Start with a single-statement grant so we have a valid row.
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", Some(3600))
        .unwrap();

    // Build a 3-statement composite chain and overwrite blocks_json.
    let stmts = vec![
        Statement {
            sid: StatementId::from("S0"),
            resource_type: ResourceType::Credential,
            actions: vec![Action::from("read")],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(20_000),
                ..Default::default()
            }),
            usage: Usage {
                tokens: 5_000,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: StatementId::from("S1"),
            resource_type: ResourceType::Session,
            actions: vec![Action::from("create")],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(1_000),
                ..Default::default()
            }),
            usage: Usage {
                cents: 250,
                ..Default::default()
            },
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: StatementId::from("S2"),
            resource_type: ResourceType::Credential,
            actions: vec![],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
    ];
    let root = state.store.persona_root_keypair(&persona.id).unwrap();
    let chain = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        &persona.id,
        "api-key",
        stmts,
        0,
        Some(9_999_999_999),
        &root,
    )
    .unwrap();
    let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        )
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/receipts/{}", grant.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();

    // Three statement wrapper divs (one per statement). Each uses the
    // unique padding:14px;margin-bottom:12px inline style from render_statement_gauges.
    assert_eq!(
        html.matches(r#"padding:14px;margin-bottom:12px"#).count(),
        3,
        "receipt page should render one gauge block per statement"
    );
    assert!(html.contains("S0"), "should show SID S0");
    assert!(html.contains("S1"), "should show SID S1");
    assert!(html.contains("S2"), "should show SID S2");
    assert!(
        html.contains("unbounded"),
        "S2 with no budget should render as unbounded"
    );
    assert!(
        html.contains("Statements"),
        "card title should say Statements"
    );
}

// --- /grants/{id} detail page tests ---

#[tokio::test]
async fn grant_detail_page_returns_200_for_active_grant() {
    let state = make_state();
    let persona = state.store.create_persona("detail-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("text/html"));
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("Grant Detail"),
        "page should have Grant Detail title"
    );
    assert!(html.contains(&grant.id), "page should embed grant id");
    assert!(
        html.contains("Pause"),
        "active grant should show Pause button"
    );
    assert!(
        html.contains("Extend"),
        "active grant should show Extend button"
    );
    assert!(
        html.contains("Revoke"),
        "active grant should show Revoke button"
    );
}

#[tokio::test]
async fn grant_detail_page_shows_resume_when_paused() {
    let state = make_state();
    let persona = state.store.create_persona("detail-paused").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    state.store.pause_grant(&grant.id).unwrap();

    let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("Resume"),
        "paused grant should show Resume button"
    );
    assert!(
        !html.contains(">Pause<"),
        "paused grant should not show Pause button"
    );
    assert!(html.contains("paused"), "page should indicate paused state");
}

#[tokio::test]
async fn grant_detail_page_shows_receipt_link_for_terminal_grant() {
    let state = make_state();
    let persona = state.store.create_persona("detail-terminal").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("View Receipt"),
        "terminal grant page should have View Receipt link"
    );
    assert!(
        !html.contains(">Pause<"),
        "terminal grant should not show Pause button"
    );
    assert!(
        !html.contains(">Revoke<"),
        "terminal grant should not show Revoke button"
    );
}

#[tokio::test]
async fn grant_detail_page_unknown_id_returns_404() {
    let state = make_state();
    let resp = call(state, "/grants/grant-does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pause_hard_sets_status_and_blocks_evaluate() {
    let state = make_state();
    let persona = state.store.create_persona("hard-pause-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/pause", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Status must be 'paused', not just the advisory flag.
    let g = state.store.get_grant(&grant.id).unwrap();
    assert_eq!(g.status, "paused");
    assert!(g.paused);

    // evaluate_grant must not return the grant (proxy-blocking).
    let eval = state.store.evaluate_grant(&persona.id, "api-key");
    assert!(
        eval.is_err(),
        "paused grant must not be returned by evaluate_grant"
    );
}

#[tokio::test]
async fn unpause_restores_status_to_active() {
    let state = make_state();
    let persona = state.store.create_persona("unpause-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "api-key", "read", None)
        .unwrap();

    call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/pause", grant.id),
    )
    .await;
    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/grants/{}/unpause", grant.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let g = state.store.get_grant(&grant.id).unwrap();
    assert_eq!(g.status, "active");
    assert!(!g.paused);

    // evaluate_grant should work again.
    assert!(state.store.evaluate_grant(&persona.id, "api-key").is_ok());
}

#[tokio::test]
async fn pause_nonexistent_grant_returns_404() {
    let state = make_state();
    // Well-formed but unknown grant id — must reach the DB lookup so the
    // handler maps StoreError::NotFound to 404 rather than mapping the
    // upstream parse failure to a 400.
    let unknown_id = format!("grant-{}", uuid::Uuid::new_v4());
    let resp = call_post(state, &format!("/api/grants/{unknown_id}/pause")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn truncate_persona_id_normal() {
    let full = "persona-368a0fc5-809a-4539-abcd-ef0123456789";
    let got = truncate_persona_id(full);
    assert_eq!(
        got, "persona-368a0fc5-809",
        "should keep 12 UUID chars after persona- prefix"
    );
}

#[test]
fn truncate_persona_id_short_does_not_panic() {
    let short = "persona-abc";
    let got = truncate_persona_id(short);
    assert_eq!(
        got, "persona-abc",
        "short UUID portion should not panic or over-reach"
    );
}

#[test]
fn truncate_persona_id_missing_prefix_returns_as_is() {
    let no_prefix = "368a0fc5";
    let got = truncate_persona_id(no_prefix);
    assert_eq!(
        got, "368a0fc5",
        "missing persona- prefix should return as-is"
    );
}

#[test]
fn truncate_persona_id_exact_boundary() {
    // Exactly 12 UUID chars after "persona-" — returned unchanged (no ellipsis added).
    let exactly_12 = "persona-368a0fc5-809";
    let got = truncate_persona_id(exactly_12);
    assert_eq!(
        got, "persona-368a0fc5-809",
        "exactly-12-char UUID portion should be returned as-is"
    );
}

// --- Origin/Referer header checks ---

fn make_headers_with_origin(origin: &str) -> hyper::HeaderMap {
    let mut h = hyper::HeaderMap::new();
    h.insert("origin", origin.parse().unwrap());
    h
}

fn make_headers_with_referer(referer: &str) -> hyper::HeaderMap {
    let mut h = hyper::HeaderMap::new();
    h.insert("referer", referer.parse().unwrap());
    h
}

fn make_empty_headers() -> hyper::HeaderMap {
    hyper::HeaderMap::new()
}

#[test]
fn origin_ok_matching_origin_passes() {
    let h = make_headers_with_origin("http://127.0.0.1:3141");
    assert!(origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_mismatched_origin_fails() {
    let h = make_headers_with_origin("http://evil.example.com");
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_missing_origin_and_referer_fails() {
    let h = make_empty_headers();
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_matching_referer_passes() {
    let h = make_headers_with_referer("http://127.0.0.1:3141/some/path?q=1");
    assert!(origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_mismatched_referer_fails() {
    let h = make_headers_with_referer("http://attacker.example.com/steal");
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
}

// --- loopback aliases ---
// The dashboard binds to 127.0.0.1, but the WebAuthn rp_id is pinned to
// `localhost`, so a browser following the WebAuthn flow sends
// `Origin: http://localhost:<port>`. Both forms are the same loopback
// socket and must be accepted symmetrically.

#[test]
fn origin_ok_localhost_origin_matches_loopback_bind() {
    let h = make_headers_with_origin("http://localhost:3141");
    assert!(origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_loopback_origin_matches_localhost_bind() {
    let h = make_headers_with_origin("http://127.0.0.1:3141");
    assert!(origin_ok(&h, "http://localhost:3141"));
}

#[test]
fn origin_ok_localhost_referer_matches_loopback_bind() {
    let h = make_headers_with_referer("http://localhost:3141/settings/passkeys");
    assert!(origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_loopback_alias_does_not_widen_to_other_hosts() {
    // The alias only swaps localhost↔127.0.0.1 on the *bound* loopback
    // pair. A non-loopback origin like 0.0.0.0 or an external host must
    // still be rejected.
    let h = make_headers_with_origin("http://0.0.0.0:3141");
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
    let h = make_headers_with_origin("http://localhost.evil.com:3141");
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn origin_ok_loopback_alias_respects_port() {
    // Aliasing is only between loopback hostnames at the *same* port.
    let h = make_headers_with_origin("http://localhost:9999");
    assert!(!origin_ok(&h, "http://127.0.0.1:3141"));
}

#[test]
fn loopback_origin_aliases_for_127_0_0_1_includes_localhost() {
    let aliases = loopback_origin_aliases("http://127.0.0.1:3141");
    assert!(aliases.iter().any(|a| a == "http://127.0.0.1:3141"));
    assert!(aliases.iter().any(|a| a == "http://localhost:3141"));
}

#[test]
fn loopback_origin_aliases_for_localhost_includes_127_0_0_1() {
    let aliases = loopback_origin_aliases("http://localhost:3141");
    assert!(aliases.iter().any(|a| a == "http://localhost:3141"));
    assert!(aliases.iter().any(|a| a == "http://127.0.0.1:3141"));
}

#[test]
fn loopback_origin_aliases_for_non_loopback_is_singleton() {
    // A non-loopback expected_origin (e.g. tailnet IP) gets no alias —
    // we don't want to silently widen what counts as same-origin for
    // any future bind addresses.
    let aliases = loopback_origin_aliases("http://10.0.0.5:3141");
    assert_eq!(aliases.len(), 1);
    assert_eq!(aliases[0], "http://10.0.0.5:3141");
}

// Integration tests: POST endpoints reject requests without matching Origin.

#[tokio::test]
async fn post_revoke_without_origin_returns_403() {
    let state = make_state();
    let persona = state.store.create_persona("no-origin-agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "key", "read", None)
        .unwrap();
    // Build POST with valid CSRF but no Origin/Referer.
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://localhost/api/grants/{}/revoke", grant.id))
        .header(CSRF_HEADER, TEST_CSRF_TOKEN)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = handle_dashboard_boxed(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_approve_with_wrong_origin_returns_403() {
    let state = make_state();
    let persona = state.store.create_persona("wrong-origin-agent").unwrap();
    let req_a = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();
    // Build POST with valid CSRF but mismatched Origin.
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/approvals/{}/approve",
            req_a.id
        ))
        .header("origin", "http://evil.example.com")
        .header(CSRF_HEADER, TEST_CSRF_TOKEN)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = handle_dashboard_boxed(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_approve_with_matching_referer_only_passes_origin_check() {
    let state = make_state();
    let persona = state.store.create_persona("referer-agent").unwrap();
    let req_a = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();
    // Build POST with valid CSRF and matching Referer (no Origin).
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "http://localhost/api/approvals/{}/approve",
            req_a.id
        ))
        .header(
            "referer",
            format!("{TEST_EXPECTED_ORIGIN}/approvals/{}", req_a.id),
        )
        .header(CSRF_HEADER, TEST_CSRF_TOKEN)
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = handle_dashboard_boxed(state, req).await;
    // Origin check passes; CSRF passes; store resolves OK → 200.
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- dismiss endpoint ---

#[tokio::test]
async fn dismiss_approval_returns_200_and_removes_from_pending() {
    let state = make_state();
    let persona = state.store.create_persona("dismiss-agent").unwrap();
    let approval = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();

    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/dismiss", approval.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["dismissed"], true);

    // Approval should no longer appear in pending list.
    let pending = state.store.list_pending_approvals().unwrap();
    assert!(
        pending.iter().all(|a| a.id != approval.id),
        "dismissed approval must not appear in pending"
    );

    // Status must be 'dismissed'.
    let resolved = state.store.get_approval(&approval.id).unwrap();
    assert_eq!(resolved.status, "dismissed");
}

#[tokio::test]
async fn dismiss_approval_double_dismiss_returns_409() {
    let state = make_state();
    let persona = state.store.create_persona("dismiss-double").unwrap();
    let approval = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();

    call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/dismiss", approval.id),
    )
    .await;
    let resp = call_post(
        Arc::clone(&state),
        &format!("/api/approvals/{}/dismiss", approval.id),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn dismiss_approval_nonexistent_returns_404() {
    let state = make_state();
    let resp = call_post(state, "/api/approvals/does-not-exist/dismiss").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dismiss_approval_without_csrf_returns_403() {
    let state = make_state();
    let persona = state.store.create_persona("dismiss-nocsrf").unwrap();
    let approval = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();
    let resp = call_post_no_csrf(state, &format!("/api/approvals/{}/dismiss", approval.id)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// --- audit action_filter query param ---

#[tokio::test]
async fn audit_action_filter_returns_only_matching_prefix() {
    let state = make_state();
    state
        .store
        .log_event(None, "grant.create", None, "ok", None)
        .unwrap();
    state
        .store
        .log_event(None, "approval.dismissed", None, "ok", None)
        .unwrap();
    state
        .store
        .log_event(None, "broker.materialization", None, "ok", None)
        .unwrap();

    let resp = call(Arc::clone(&state), "/api/audit?action_filter=grant.").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "only grant.* actions should be returned");
    assert_eq!(arr[0]["action"], "grant.create");
}

#[tokio::test]
async fn audit_action_filter_empty_returns_all() {
    let state = make_state();
    state
        .store
        .log_event(None, "grant.create", None, "ok", None)
        .unwrap();
    state
        .store
        .log_event(None, "approval.dismissed", None, "ok", None)
        .unwrap();

    let resp = call(Arc::clone(&state), "/api/audit?action_filter=").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2, "empty filter returns all events");
}

// --- /api/receipts endpoint ---

/// Ensure the receipts singleton identity is active (mirrors receipt.rs
/// test helper) so revoke_grant can emit signed receipts.
fn ensure_receipt_identity() -> &'static crate::infra::receipt::DaemonPersona {
    use once_cell::sync::OnceCell;
    static INIT_DIR: OnceCell<tempfile::TempDir> = OnceCell::new();
    let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    let _ = crate::infra::receipt::init_identity(dir.path());
    crate::infra::receipt::current_identity().expect("identity was just initialised")
}

fn store_fixture_session_composite_receipt(
    store: &crate::infra::store::DaemonStore,
    grant_id: &str,
    persona_id: &str,
    delegation_template: &str,
    claim_count_total: u64,
    claim_events_truncated: bool,
    claim_segment_count: usize,
) -> String {
    use core_events::receipt::body::{ClaimEvent, ClaimKind, ClaimSegmentDigest, ReceiptBody};
    use core_events::receipt::cohort_a::{
        ClaudeCodeBody, RECEIPT_KIND_COMPOSITE_GRANT, TerminationReason,
    };
    use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};

    let receipt_id = format!("rct-session-{grant_id}");
    let claim_segments: Vec<ClaimSegmentDigest> = (0..claim_segment_count)
        .map(|idx| ClaimSegmentDigest {
            segment_no: idx as u64,
            first_scope_seq: (idx as u64) + 1,
            last_scope_seq: (idx as u64) + 1,
            claim_count: 1,
            started_at: "2026-05-22T12:00:00Z".to_string(),
            ended_at: "2026-05-22T12:00:30Z".to_string(),
            merkle_root: format!("root-{idx}"),
        })
        .collect();
    let body = ClaudeCodeBody {
        base: ReceiptBody {
            claim_events: vec![ClaimEvent {
                ts: "2026-05-22T12:00:00Z".to_string(),
                kind: ClaimKind::CredentialVended,
                tool: "Claude".to_string(),
                action_ref: None,
                input_hash: "hash-1".to_string(),
                input_redacted: serde_json::json!({"prompt": "deploy"}),
                resolved: serde_json::json!({"allowed": true}),
            }],
            claim_count_total: Some(claim_count_total),
            claim_events_truncated,
            claim_segment_summaries: claim_segments,
            claim_history_merkle_root: "history-root".to_string(),
            delegation_template: Some(delegation_template.to_string()),
            ..Default::default()
        },
        audit_gaps: vec![],
        termination_reason: Some(TerminationReason::ExhaustedByBudget),
        last_heartbeat_at: None,
        pid_alive_at_check: None,
    };
    let envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_COMPOSITE_GRANT.to_string(),
        receipt_id: receipt_id.clone(),
        daemon_root_id: "root-test".to_string(),
        traceparent: None,
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body: serde_json::to_value(body).expect("serialize body"),
        signature: Some("deadbeef".repeat(16)),
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };
    store
        .store_session_receipt_v2(&envelope, grant_id, persona_id)
        .expect("store session receipt");
    receipt_id
}

#[tokio::test]
async fn api_receipts_empty_returns_array() {
    let state = make_state();
    // ?view=rollup (default) returns empty rollup array.
    let resp = call(state, "/api/receipts").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "receipts response must be an array");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn api_receipts_raw_empty_returns_array() {
    let state = make_state();
    let resp = call(state, "/api/receipts?view=raw").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "raw receipts response must be an array");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn api_receipts_returns_signed_status_field() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-receipt-signed").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "gh-token", "push", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    // Use ?view=raw to test the raw per-receipt shape.
    let resp = call(Arc::clone(&state), "/api/receipts?view=raw").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(
        arr.iter().any(|r| r["grant_id"] == grant.id),
        "revoked grant should surface at least one raw receipt row"
    );
    assert!(
        arr.iter().all(|r| r["signed"].is_boolean()),
        "signed field must be boolean on every raw row"
    );
    assert!(
        arr.iter().any(|r| r["signed"].as_bool().unwrap_or(false)),
        "at least one receipt should be signed by daemon identity"
    );
    assert!(arr.iter().all(|r| r["action_summary"].is_string()));
    assert!(arr.iter().all(|r| r["persona_id"].is_string()));
}

#[tokio::test]
async fn api_receipts_raw_includes_signed_session_composite_rows() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-session-raw").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    let _receipt_id = store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(
        Arc::clone(&state),
        "/api/receipts?view=raw&signed_only=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "signed_only should retain signed session receipt"
    );
    assert_eq!(arr[0]["grant_id"], grant.id);
    assert_eq!(arr[0]["persona_id"], persona.id);
    assert_eq!(arr[0]["signed"], true);
    assert_eq!(arr[0]["claim_count_total"], 9);
    assert_eq!(arr[0]["claim_segment_count"], 2);
    assert_eq!(arr[0]["claim_events_truncated"], true);
}

#[tokio::test]
async fn api_receipts_persona_filter_isolates_results() {
    ensure_receipt_identity();
    let state = make_state();
    let a = state.store.create_persona("agent-rcpt-a").unwrap();
    let b = state.store.create_persona("agent-rcpt-b").unwrap();
    let g1 = state.store.create_grant(&a.id, "cred", "r", None).unwrap();
    let g2 = state.store.create_grant(&b.id, "cred", "r", None).unwrap();
    state.store.revoke_grant(&g1.id).unwrap();
    state.store.revoke_grant(&g2.id).unwrap();

    let url = format!("/api/receipts?view=raw&persona_id={}", a.id);
    let resp = call(Arc::clone(&state), &url).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "persona filter must return receipts for that persona"
    );
    assert!(arr.iter().all(|r| r["persona_id"] == a.id.as_str()));
}

#[tokio::test]
async fn receipts_search_persona_isolates_rows() {
    // `/api/receipts/search?persona=`
    // must surface only receipts whose persona_id matches.
    ensure_receipt_identity();
    let state = make_state();
    let a = state.store.create_persona("agent-search-a").unwrap();
    let b = state.store.create_persona("agent-search-b").unwrap();
    let g1 = state.store.create_grant(&a.id, "cred", "r", None).unwrap();
    let g2 = state.store.create_grant(&b.id, "cred", "r", None).unwrap();
    state.store.revoke_grant(&g1.id).unwrap();
    state.store.revoke_grant(&g2.id).unwrap();

    let url = format!("/api/receipts/search?persona={}", a.id);
    let resp = call(Arc::clone(&state), &url).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("search response must be an array");
    assert!(
        !arr.is_empty(),
        "persona filter must isolate to at least one receipt row"
    );
    assert!(arr.iter().all(|r| r["persona_id"] == a.id.as_str()));
}

#[tokio::test]
async fn receipts_search_scope_matches_session_delegation_template() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-search-session").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    let _receipt_id = store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(
        Arc::clone(&state),
        "/api/receipts/search?scope=emberd-development",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().expect("search response must be an array");
    assert_eq!(
        arr.len(),
        1,
        "delegation template search should find the session receipt"
    );
    assert_eq!(arr[0]["grant_id"], grant.id);
    assert_eq!(arr[0]["persona_id"], persona.id);
}

#[tokio::test]
async fn api_receipts_signed_only_excludes_unsigned() {
    // Seed one receipt that is unsigned (signer_pubkey='') via direct store
    // insert to simulate a pre-identity-key receipt, then one real signed one.
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-rcpt-so").unwrap();
    let g_signed = state
        .store
        .create_grant(&persona.id, "cred", "r", None)
        .unwrap();
    state.store.revoke_grant(&g_signed.id).unwrap();

    // Manually insert an unsigned receipt row.
    use core_grant_types::grant_receipt::{
        Evidence, GrantReceipt, Lifecycle, ReceiptSummary, TerminalReason,
    };
    let unsigned = GrantReceipt {
        id: "rct-unsigned-test".to_string(),
        grant_id: "grant-unsigned-test".to_string(),
        summary: ReceiptSummary {
            human_owner: "test".to_string(),
            persona_id: persona.id.clone(),
            agent_id: "test".to_string(),
            service: "test".to_string(),
            resource: "r".to_string(),
        },
        approved_chain: vec![],
        per_statement_usage: vec![],
        approval_chain: vec![],
        actions_observed: vec![],
        lifecycle: Lifecycle {
            issued_at: 0,
            last_used_at: None,
            terminated_at: 0,
            terminal_reason: TerminalReason::Expired,
        },
        attestation: Default::default(),
        dev_mode_active: false,
        evidence: Evidence::default(), // all-zero placeholder → unsigned
    };
    state.store.store_receipt(&unsigned).unwrap();

    // Without filter (raw view): both receipts visible.
    let resp_all = call(Arc::clone(&state), "/api/receipts?view=raw").await;
    let body_all = http_body_util::BodyExt::collect(resp_all.into_body())
        .await
        .unwrap()
        .to_bytes();
    let all: serde_json::Value = serde_json::from_slice(&body_all).unwrap();
    let all_arr = all.as_array().unwrap();
    assert!(
        all_arr.iter().any(|r| r["id"] == "rct-unsigned-test"),
        "unfiltered view must include the manually inserted unsigned receipt"
    );

    // With signed_only=true (raw view): only the signed receipt.
    let resp_signed = call(
        Arc::clone(&state),
        "/api/receipts?view=raw&signed_only=true",
    )
    .await;
    let body_signed = http_body_util::BodyExt::collect(resp_signed.into_body())
        .await
        .unwrap()
        .to_bytes();
    let signed: serde_json::Value = serde_json::from_slice(&body_signed).unwrap();
    let signed_arr = signed.as_array().unwrap();
    assert_eq!(
        signed_arr.len() + 1,
        all_arr.len(),
        "signed_only=true must exclude exactly the one unsigned receipt"
    );
    assert!(signed_arr.iter().all(|r| r["signed"].as_bool().unwrap()));
    assert!(
        signed_arr.iter().all(|r| r["id"] != "rct-unsigned-test"),
        "signed_only=true must exclude the manual unsigned receipt"
    );
}

#[tokio::test]
async fn api_receipts_includes_persona_name() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("My Test Agent").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "key", "r", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    let resp = call(Arc::clone(&state), "/api/receipts?view=raw").await;
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(
        arr.iter().all(|r| r["persona_name"] == "My Test Agent"),
        "persona_name must be resolved from store"
    );
}

#[tokio::test]
async fn api_receipts_raw_surfaces_session_composite_claim_rollup_fields() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("session-composite-ui").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        9,
        true,
        2,
    );

    let resp = call(Arc::clone(&state), "/api/receipts?view=raw").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["kind"], "session.composite_grant");
    assert_eq!(arr[0]["claim_count_total"], 9);
    assert_eq!(arr[0]["claim_events_truncated"], true);
    assert_eq!(arr[0]["claim_segment_count"], 2);
    assert_eq!(arr[0]["signed"], true);
    assert!(
        arr[0]["action_summary"]
            .as_str()
            .unwrap_or_default()
            .contains("emberd-development")
    );
}

#[tokio::test]
async fn api_receipts_signed_only_keeps_signed_session_composite_receipts() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state
        .store
        .create_persona("session-composite-signed")
        .unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "anthropic", "chat", None)
        .unwrap();
    store_fixture_session_composite_receipt(
        &state.store,
        &grant.id,
        &persona.id,
        "emberd-development",
        3,
        false,
        1,
    );

    let resp = call(
        Arc::clone(&state),
        "/api/receipts?view=raw&signed_only=true",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "signed session envelope must survive signed_only filter"
    );
    assert_eq!(arr[0]["kind"], "session.composite_grant");
}

// AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD — T1 unit tests for rollup_view
// and T2 integration tests for ?view=rollup endpoint.

#[test]
fn rollup_view_empty_rows_returns_empty_array() {
    let rows: Vec<crate::infra::receipt::ReceiptRow> = vec![];
    let val = rollup_view(&rows);
    assert!(val.is_array(), "rollup_view must return JSON array");
    assert_eq!(
        val.as_array().unwrap().len(),
        0,
        "empty rows → empty rollup"
    );
}

#[test]
fn rollup_view_groups_rows_by_grant_id() {
    use crate::infra::receipt::ReceiptRow;
    let rows = vec![
        ReceiptRow {
            id: "rct-1".to_string(),
            kind: "grant".to_string(),
            actor: "persona-a".to_string(),
            resource: "github.com/org/repo".to_string(),
            action_ref: None,
            contract_id: None,
            workspace_ref: None,
            caller_ref: None,
            authority_ref: None,
            grant_id: "grant-abc".to_string(),
            materialized_at: "2026-05-05T13:00:00Z".to_string(),
            terminal_reason: "revoked".to_string(),
            requested_scope: None,
            granted_scope: None,
            signed: true,
            delegation_template: None,
            claim_count_total: None,
            claim_events_truncated: false,
            claim_segment_count: None,
            claim_history_merkle_root: None,
        },
        ReceiptRow {
            id: "rct-2".to_string(),
            kind: "grant".to_string(),
            actor: "persona-b".to_string(),
            resource: "anthropic.com/api".to_string(),
            action_ref: None,
            contract_id: None,
            workspace_ref: None,
            caller_ref: None,
            authority_ref: None,
            grant_id: "grant-xyz".to_string(),
            materialized_at: "2026-05-05T14:00:00Z".to_string(),
            terminal_reason: "expired".to_string(),
            requested_scope: None,
            granted_scope: None,
            signed: true,
            delegation_template: None,
            claim_count_total: None,
            claim_events_truncated: false,
            claim_segment_count: None,
            claim_history_merkle_root: None,
        },
    ];
    let val = rollup_view(&rows);
    let arr = val.as_array().unwrap();
    assert_eq!(arr.len(), 2, "two distinct grant_ids → two rollup rows");
    // Each row must have the required fields.
    for item in arr {
        assert!(item["materialization_id"].is_string());
        assert!(item["receipt_count"].is_number());
        assert!(item["outcome"].is_string());
        assert!(item["sub_receipts"].is_array());
    }
}

#[test]
fn rollup_view_denied_outcome_inlines_denial_reason() {
    use crate::infra::receipt::ReceiptRow;
    let rows = vec![ReceiptRow {
        id: "rct-denied".to_string(),
        kind: "broker_materialization".to_string(),
        actor: "persona-deny".to_string(),
        resource: "gh".to_string(),
        action_ref: None,
        contract_id: None,
        workspace_ref: None,
        caller_ref: None,
        authority_ref: None,
        grant_id: String::new(),
        materialized_at: "2026-05-05T12:00:00Z".to_string(),
        terminal_reason: "rate_limited".to_string(),
        requested_scope: None,
        granted_scope: None,
        signed: true,
        delegation_template: None,
        claim_count_total: None,
        claim_events_truncated: false,
        claim_segment_count: None,
        claim_history_merkle_root: None,
    }];
    let val = rollup_view(&rows);
    let arr = val.as_array().unwrap();
    // broker_materialization without a revocation → Incomplete outcome.
    // Key check: denial_reason field must be present (possibly null).
    assert!(
        arr[0].get("denial_reason").is_some(),
        "denial_reason field must be present"
    );
    assert!(
        arr[0]["sub_receipts"].is_array(),
        "sub_receipts field must be present"
    );
}

#[test]
fn rollup_view_surfaces_singleton_session_receipt_claim_summary() {
    use crate::infra::receipt::ReceiptRow;
    let rows = vec![ReceiptRow {
        id: "rct-session".to_string(),
        kind: "session.composite_grant".to_string(),
        actor: "persona-session".to_string(),
        resource: "emberd-development".to_string(),
        action_ref: None,
        contract_id: None,
        workspace_ref: None,
        caller_ref: None,
        authority_ref: None,
        grant_id: "grant-session".to_string(),
        materialized_at: "2026-05-22T12:00:00Z".to_string(),
        terminal_reason: "exhausted_by_budget".to_string(),
        requested_scope: None,
        granted_scope: None,
        signed: true,
        delegation_template: Some("emberd-development".to_string()),
        claim_count_total: Some(9),
        claim_events_truncated: true,
        claim_segment_count: Some(2),
        claim_history_merkle_root: Some("history-root".to_string()),
    }];
    let val = rollup_view(&rows);
    let arr = val.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["outcome"], "success");
    assert_eq!(arr[0]["claim_count_total"], 9);
    assert_eq!(arr[0]["claim_events_truncated"], true);
    assert_eq!(arr[0]["claim_segment_count"], 2);
    assert_eq!(arr[0]["sub_receipts"][0]["claim_count_total"], 9);
}

#[test]
fn receipt_row_action_summary_prefers_structured_action_ref() {
    use crate::infra::receipt::ReceiptRow;

    let row = ReceiptRow {
        id: "rct-action".to_string(),
        kind: "grant".to_string(),
        actor: "persona-a".to_string(),
        resource: "repo:acme/project".to_string(),
        action_ref: Some(core_event_types::ActionRef::new(
            "registry.ember.systems/ember-systems/ember-gh",
            "pr_list",
            "v1",
        )),
        contract_id: Some("contract-123".to_string()),
        workspace_ref: Some("rt-horchata".to_string()),
        caller_ref: Some("persona-a".to_string()),
        authority_ref: Some("grant-abc".to_string()),
        grant_id: "grant-abc".to_string(),
        materialized_at: "2026-05-05T12:00:00Z".to_string(),
        terminal_reason: "revoked".to_string(),
        requested_scope: Some("repo:read".to_string()),
        granted_scope: Some("repo:read".to_string()),
        signed: true,
        delegation_template: None,
        claim_count_total: None,
        claim_events_truncated: false,
        claim_segment_count: None,
        claim_history_merkle_root: None,
    };

    let summary = receipt_row_action_summary(&row);
    assert!(summary.contains("repo:read"));
    assert!(summary.contains("registry.ember.systems/ember-systems/ember-gh/pr_list@v1"));
}

#[tokio::test]
async fn api_receipts_rollup_view_returns_rollup_envelope() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-rollup-test").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "gh-token", "push", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    // Default view=rollup.
    let resp = call(Arc::clone(&state), "/api/receipts").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "one revoked grant → one rollup row");
    let row = &arr[0];
    assert!(
        row["materialization_id"].is_string(),
        "must have materialization_id"
    );
    assert!(row["receipt_count"].is_number(), "must have receipt_count");
    assert!(row["outcome"].is_string(), "must have outcome field");
    assert!(
        row["sub_receipts"].is_array(),
        "must have sub_receipts for click-through detail"
    );
    assert!(
        row.get("denial_reason").is_some(),
        "denial_reason must be present (null or string)"
    );
}

#[tokio::test]
async fn api_receipts_view_rollup_explicit_param_works() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-rollup-explicit").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    let resp = call(Arc::clone(&state), "/api/receipts?view=rollup").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "?view=rollup must return array");
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "one grant → one rollup row");
}

#[tokio::test]
async fn api_receipts_view_raw_preserves_legacy_shape() {
    ensure_receipt_identity();
    let state = make_state();
    let persona = state.store.create_persona("agent-raw-shape").unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "cred", "read", None)
        .unwrap();
    state.store.revoke_grant(&grant.id).unwrap();

    let resp = call(Arc::clone(&state), "/api/receipts?view=raw").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty(), "?view=raw must return per-receipt list");
    // Legacy shape must have grant_id, persona_id, signed fields.
    assert!(arr.iter().all(|r| r["grant_id"].is_string()));
    assert!(arr.iter().all(|r| r["persona_id"].is_string()));
    assert!(arr.iter().all(|r| r["signed"].is_boolean()));
}

#[tokio::test]
async fn dashboard_html_contains_receipts_section() {
    let state = make_state();
    let resp = call(state, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("Grant Receipts"),
        "dashboard must contain Grant Receipts section heading"
    );
    assert!(
        s.contains("receipts-body"),
        "dashboard must contain receipts table body element"
    );
    assert!(
        s.contains("receipt-signed-filter"),
        "dashboard must contain signed filter control"
    );
    assert!(
        s.contains("receipt-since-filter"),
        "dashboard must contain since filter control"
    );
    assert!(
        s.contains("function loadReceipts"),
        "dashboard must contain loadReceipts JS function"
    );
}

/// DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — fresh-daemon dashboard ships
/// the zero-state panel checkpoint + first-grant CLI command + Receipt
/// explainer + /verify-receipt link, plus the JS hook that hides it
/// once a grant or receipt populates.
#[tokio::test]
async fn dashboard_html_contains_zero_state_first_receipt_panel() {
    let state = make_state();
    let resp = call(state, "/").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        s.contains("dashboard-empty-state-first-receipt"),
        "zero-state checkpoint class missing from dashboard"
    );
    assert!(
        s.contains("zero-state-panel"),
        "zero-state panel element id missing from dashboard"
    );
    assert!(
        s.contains("ember grant create --to"),
        "zero-state must include copy-paste 'ember grant create' command"
    );
    assert!(
        s.contains("/verify-receipt"),
        "zero-state must link to /verify-receipt"
    );
    assert!(
        s.contains("_updateZeroStatePanel"),
        "JS toggle hook _updateZeroStatePanel missing — empty state would never hide once populated"
    );
}

#[tokio::test]
async fn approval_page_no_longer_has_narrow_button() {
    // The disabled Narrow button was removed for clean screenshots.
    let state = make_state();
    let persona = state.store.create_persona("agent-narrow-check").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "low")
        .unwrap();
    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let s = std::str::from_utf8(&body).unwrap();
    assert!(
        !s.contains("btn-narrow"),
        "Narrow button must have been removed from approval page"
    );
    assert!(
        !s.contains("Narrow"),
        "Narrow text must not appear on approval page"
    );
}

/// `/settings/passkeys` returns the enrollment page with
/// expected content so operators can register their platform authenticator.
#[tokio::test]
async fn settings_passkeys_returns_enrollment_page() {
    let state = make_state();
    let resp = call(state, "/settings/passkeys").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("Register Passkey"),
        "enrollment button missing"
    );
    assert!(
        html.contains("navigator.credentials.create"),
        "WebAuthn create call missing"
    );
    assert!(
        html.contains("/api/webauthn/register/begin"),
        "register begin endpoint reference missing"
    );
    assert!(
        html.contains("/api/webauthn/register/complete"),
        "register complete endpoint reference missing"
    );
    assert!(
        html.contains("Enrolled Passkeys"),
        "enrolled passkeys section missing"
    );
}

/// The `/approvals/{id}` page wires the real
/// auth/begin → navigator.credentials.get → POST/<action> ceremony
/// into the resolve() function so Approve/Deny calls carry a verified
/// WebAuthn assertion (same as the main dashboard cards).
#[tokio::test]
async fn approval_page_resolve_calls_webauthn_ceremony() {
    let state = make_state();
    let persona = state.store.create_persona("agent-bio-page").unwrap();
    let req = state
        .store
        .submit_approval(&persona.id, "key", "read", None, "access", "high")
        .unwrap();
    let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(
        html.contains("/api/webauthn/auth/begin"),
        "/approvals/{{id}} page must hit auth/begin before POSTing"
    );
    assert!(
        html.contains("navigator.credentials.get"),
        "/approvals/{{id}} page must include WebAuthn get call"
    );
    assert!(
        html.contains("challenge_id"),
        "/approvals/{{id}} page must forward the challenge_id from auth/begin"
    );
    assert!(
        html.contains(
            "const needsBio = action === 'approve' || action === 'deny' || action === 'approve-always';"
        ),
        "/approvals/{{id}} page must require WebAuthn before approve-always creates a standing grant"
    );
}

#[test]
fn dashboard_approve_always_uses_webauthn_ceremony() {
    assert!(
        DASHBOARD_HTML.contains("if(await approveOrDeny(id, 'approve-always')) loadDashboard();"),
        "main dashboard approve-always must use the same WebAuthn ceremony as approve/deny"
    );
    assert!(
        !DASHBOARD_HTML.contains(
            "fetch(`/api/approvals/${id}/approve-always`,{method:'POST',headers:CSRF_HEADERS})"
        ),
        "approve-always must not bypass the WebAuthn helper with a bare CSRF-only POST"
    );
}

/// The `/approvals/{id}` dedicated page must
/// expose composite_statements via the polled JSON AND embed the shared
/// renderCompositeStatements helper so the breakdown renders identically
/// to the main dashboard card. This is the P1 YC-partner deep-link path.
///
/// Anchor: composite-statements  render_composite_statements  3 statements
#[tokio::test]
async fn approvals_id_renders_composite_breakdown_when_multi_statement() {
    use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

    let state = make_state();
    let persona = state.store.create_persona("agent-composite-page").unwrap();

    // Build a 3-statement composite envelope (same shape as the demo flow).
    let stmts = vec![
        Statement {
            sid: "s0-credential".to_string(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: "github-token".to_string(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "s1-session".to_string(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".to_string(),
            },
            budget: Some(Budget {
                tokens: Some(20_000),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
        Statement {
            sid: "s2-time".to_string(),
            resource_type: ResourceType::Time,
            actions: vec!["time:wall_clock".to_string()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(1800),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
            can_delegate: None,
        },
    ];

    let req = state
        .store
        .propose_grant(
            &persona.id,
            "github-token",
            "composite",
            Some(300),
            "credential.access",
            "high",
            stmts,
        )
        .unwrap();

    // 1. The polled JSON endpoint must return all 3 statements so the
    //    page JS has data to call renderBreakdown(data.composite_statements).
    let api_resp = call(Arc::clone(&state), &format!("/api/approvals/{}", req.id)).await;
    assert_eq!(api_resp.status(), StatusCode::OK);
    let api_body = http_body_util::BodyExt::collect(api_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&api_body).unwrap();
    let stmts_json = json["composite_statements"]
        .as_array()
        .expect("composite_statements must be an array in /api/approvals/{id} response");
    assert_eq!(
        stmts_json.len(),
        3,
        "/api/approvals/{{id}} must return all 3 statements so the page JS can render composite-statements"
    );
    // Verify statement identity round-trips correctly.
    assert_eq!(stmts_json[0]["sid"], "s0-credential");
    assert_eq!(stmts_json[1]["sid"], "s1-session");
    assert_eq!(stmts_json[2]["sid"], "s2-time");

    // 2. The HTML page must embed the shared renderCompositeStatements helper
    //    (single source of truth with the dashboard card — both surfaces call
    //    the same function so they can never drift).
    let page_resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
    assert_eq!(page_resp.status(), StatusCode::OK);
    let page_body = http_body_util::BodyExt::collect(page_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let html = std::str::from_utf8(&page_body).unwrap();
    assert!(
        html.contains("function renderCompositeStatements"),
        "/approvals/{{id}} page must embed the shared renderCompositeStatements helper"
    );
    // 3 statements label surfaced via JS — the CSS class must be defined so
    // the rendered block matches the dashboard card appearance.
    assert!(
        html.contains("composite-statements"),
        "/approvals/{{id}} page must define the composite-statements CSS class"
    );
    // Disclosure container present (JS reveals it when composite_statements arrives).
    assert!(
        html.contains(r#"id="composite-breakdown""#),
        "/approvals/{{id}} page must contain composite-breakdown container for JS to populate"
    );
    // Approve/Deny lead the page — composite detail is secondary.
    assert!(html.contains("Approve"), "Approve button must be present");
    assert!(html.contains("Deny"), "Deny button must be present");
}

#[tokio::test]
async fn maturation_candidates_returns_empty_array_with_no_data() {
    let state = make_state();
    let resp = call(state, "/api/maturation/candidates").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.is_array(),
        "maturation candidates response must be a JSON array"
    );
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "empty store yields no candidates"
    );
}

#[tokio::test]
async fn autopilot_snapshot_returns_running_false_when_binary_missing() {
    let state = make_state();
    let resp = call(state, "/api/autopilot/snapshot").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.is_object(),
        "autopilot snapshot response must be a JSON object"
    );
    // When internal-automation is missing or returns non-zero, running must be false
    // (it may also be a valid snapshot if internal-automation is present on PATH)
    if json.get("running").and_then(|v| v.as_bool()) == Some(false) {
        assert!(
            json.get("inflight").map(|v| v.is_array()).unwrap_or(false),
            "inflight must be an array"
        );
        assert!(
            json.get("queue_head")
                .map(|v| v.is_array())
                .unwrap_or(false),
            "queue_head must be an array"
        );
        assert!(
            json.get("last_events")
                .map(|v| v.is_array())
                .unwrap_or(false),
            "last_events must be an array"
        );
    }
}

// ADR212-TELEMETRY-EXPORTER — T2: the `/metrics` route renders the
// broker-materialization families through the shared `ember-telemetry`
// exposition handler, and the rendered text never carries a per-principal
// label (the trust-boundary check from ADR 212 §5).
#[tokio::test]
async fn metrics_route_renders_registered_family_without_per_principal_label() {
    // Install the process-global telemetry (idempotent; other tests in this
    // process may have already done so) and record one materialization so the
    // family is non-empty. `record_broker_materialization` is the REAL exporter
    // path the broker hot-path calls.
    crate::infra::telemetry::init("127.0.0.1:0", "testsha");
    crate::infra::telemetry::record_broker_materialization(
        core_metrics::ReceiptKindLabel::BrokerMint,
        core_metrics::OutcomeLabel::Ok,
        0.0123,
        "mat-metrics-route-test",
    );

    let state = make_state();
    let resp = call(state, "/metrics").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some(ember_telemetry::METRICS_CONTENT_TYPE)
    );

    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let text = String::from_utf8(body.to_vec()).expect("utf8 exposition");

    // The receipt-kind/outcome series are present (acceptance item 4).
    assert!(
        text.contains("ember_broker_materialization_total"),
        "missing outcome counter series:\n{text}"
    );
    assert!(
        text.contains("ember_broker_materialization_duration_seconds"),
        "missing latency histogram series:\n{text}"
    );
    assert!(
        text.contains("receipt_kind=\"broker_mint\""),
        "missing receipt_kind label:\n{text}"
    );
    assert!(
        text.contains("outcome=\"ok\""),
        "missing outcome label:\n{text}"
    );

    // TRUST BOUNDARY (ADR 212 §5): no per-principal identifier as a label.
    assert!(
        !text.contains("persona_id"),
        "exposition leaked persona_id:\n{text}"
    );
    assert!(
        !text.contains("grant_id"),
        "exposition leaked grant_id:\n{text}"
    );
    assert!(
        !text.contains("session_id"),
        "exposition leaked session_id:\n{text}"
    );
}

// ADR212-TELEMETRY-EXPORTER — exercise the `forbidden_label_value` gate
// (via `ember_telemetry::guard_label_value`) on the exporter path: a
// credential-shaped value is rejected before it can become a label, while a
// bounded label value passes. Acceptance item 4 (forbidden gate exercised).
#[test]
fn forbidden_label_gate_rejects_credential_on_exporter_path() {
    // A safe, bounded value passes the gate unchanged.
    assert_eq!(
        ember_telemetry::guard_label_value("broker_mint"),
        Ok("broker_mint")
    );
    // A credential-shaped value trips the gate with a named leak class, so it
    // never reaches the registry.
    assert_eq!(
        ember_telemetry::guard_label_value("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Err("github_token_prefix")
    );
    // And the underlying `core-metrics` gate (the source of truth) agrees.
    assert_eq!(
        core_metrics::forbidden_label_value("hvs.SECRETTOKEN"),
        Some("vault_token_prefix")
    );
}
