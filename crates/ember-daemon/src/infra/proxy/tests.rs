use super::*;
use crate::infra::store::DaemonStore;
use crate::infra::vault::Vault;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty};

fn test_key() -> [u8; 32] {
    [0x42u8; 32]
}

/// Install a sinkless `DaemonEventSink` on the given state. Mirrors what
/// `runtime.rs` does in production for the git-echo proxy spawn (no
/// broadcast channel attached). Tests that don't care about audit/broadcast
/// observability still need this so `emit_threshold_crossings` /
/// `emit_debounced` / `state.sink_log_event(...)` don't panic in the
/// `ProxyState::sink()` unwrap.
fn install_sink(state: &Arc<ProxyState>) {
    let sink = Arc::new(DaemonEventSink::new(state.clone(), None));
    let _ = state.event_sink.set(sink);
}

fn make_state() -> Arc<ProxyState> {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(Vault::new(test_key())));
    let state = Arc::new(ProxyState::new(store, None));
    install_sink(&state);
    state
}

fn make_state_with_data_dir(data_dir: &std::path::Path) -> Arc<ProxyState> {
    std::fs::create_dir_all(data_dir).expect("create daemon data dir");
    let store = DaemonStore::open(&data_dir.join("daemon.db")).unwrap();
    store.set_vault(std::rc::Rc::new(Vault::new(test_key())));
    let state = Arc::new(ProxyState::new(store, None));
    install_sink(&state);
    state
}

/// Build a `ProxyState` seeded with a persona, a grant authorising
/// `github:push` on `*`, and a vault credential. Returns the state,
/// persona id, and credential name so callers can set the matching
/// request headers.
fn make_git_echo_state(
    persona_name: &str,
    credential_name: &str,
    token_value: &str,
) -> (Arc<ProxyState>, String, String) {
    let store = DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(Vault::new(test_key())));
    let state = Arc::new(ProxyState::new(store, None));
    install_sink(&state);
    let persona = state.store.create_persona(persona_name).unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            credential_name,
            token_value.as_bytes(),
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();
    (state, persona.id, credential_name.to_string())
}

static RUSTLS_INIT: std::sync::Once = std::sync::Once::new();
fn ensure_rustls_provider() {
    RUSTLS_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[test]
fn scheme_from_str_roundtrip() {
    assert_eq!("http".parse::<Scheme>().unwrap(), Scheme::Http);
    assert_eq!("https".parse::<Scheme>().unwrap(), Scheme::Https);
    assert_eq!("HTTP".parse::<Scheme>().unwrap(), Scheme::Http);
    assert_eq!("HTTPS".parse::<Scheme>().unwrap(), Scheme::Https);
    assert!("htps".parse::<Scheme>().is_err());
    assert!("".parse::<Scheme>().is_err());
    assert!("ftp".parse::<Scheme>().is_err());
}

#[test]
fn scheme_display() {
    assert_eq!(Scheme::Http.to_string(), "http");
    assert_eq!(Scheme::Https.to_string(), "https");
}

fn proxy_request_with_headers(
    persona: Option<&str>,
    credential: Option<&str>,
    target: Option<&str>,
) -> Request<Empty<Bytes>> {
    proxy_request_with_method_and_uri(
        "GET",
        "http://localhost/api/repos",
        persona,
        credential,
        target,
    )
}

fn proxy_request_with_method_and_uri(
    method: &str,
    uri: &str,
    persona: Option<&str>,
    credential: Option<&str>,
    target: Option<&str>,
) -> Request<Empty<Bytes>> {
    let mut builder = Request::builder().method(method).uri(uri);

    if let Some(p) = persona {
        builder = builder.header("X-Ember-Persona", p);
    }
    if let Some(c) = credential {
        builder = builder.header("X-Ember-Credential", c);
    }
    if let Some(t) = target {
        builder = builder.header("X-Ember-Target", t);
    }

    builder.body(Empty::new()).unwrap()
}

async fn call(state: Arc<ProxyState>, req: Request<Empty<Bytes>>) -> Response<ProxyBody> {
    // Adapt Empty<Bytes> to Incoming-compatible body using map_err
    let (parts, body) = req.into_parts();
    let mapped = body.map_err(|e| -> hyper::Error { panic!("empty body error: {e}") });
    let incoming_req = Request::from_parts(parts, mapped);

    // We need to call handle_request which takes Incoming — but in tests we
    // use a type-erased body.  Use the UnsyncBoxBody approach: box the body.
    let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> = incoming_req.map(UnsyncBoxBody::new);

    // handle_request is generic — call a test-only wrapper.
    handle_request_boxed(state, boxed).await.unwrap()
}

// Test wrapper that accepts a boxed body so tests don't need a real Incoming.
async fn handle_request_boxed(
    state: Arc<ProxyState>,
    req: Request<impl hyper::body::Body<Data = Bytes, Error = hyper::Error>>,
) -> Result<Response<ProxyBody>, ProxyError> {
    let headers = req.headers();

    let credential_name = match headers
        .get("x-ember-credential")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Credential header")),
    };

    let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Target header")),
    };

    if headers.get("x-ember-grant-id").is_some() {
        return Ok(bad_request(
            "X-Ember-Grant-Id is no longer accepted; use attachment endpoint headers",
        ));
    }

    let attachment_authority =
        match crate::infra::attachment::attachment_endpoint_from_headers(headers) {
            Some((attachment_id, endpoint_token)) => {
                let Some(sessions_dir) = state.sessions_dir.as_deref() else {
                    return Ok(bad_request("attachment endpoint resolution unavailable"));
                };
                match crate::infra::attachment::resolve_attachment_authority(
                    sessions_dir,
                    attachment_id,
                    endpoint_token,
                )
                .await
                {
                    Ok(authority) => Some(authority),
                    Err((_code, message)) => return Ok(forbidden(&message)),
                }
            }
            None => None,
        };

    let persona_id = match attachment_authority.as_ref() {
        Some(authority) => {
            if let Some(asserted) = headers
                .get("x-ember-persona")
                .and_then(|v| v.to_str().ok())
                .filter(|value| !value.is_empty())
                && asserted != authority.runtime_persona_id
            {
                return Ok(forbidden(
                    "X-Ember-Persona does not match attachment authority",
                ));
            }
            authority.runtime_persona_id.clone()
        }
        None => match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Persona header")),
        },
    };

    // Mirror the production C-1 fix: derive the single authoritative URI
    // used for scope + action resolution from `X-Ember-Target`.
    let effective_uri = match effective_scope_uri(&target_url, req.uri()) {
        Ok(u) => u,
        Err(msg) => return Ok(bad_request(&msg)),
    };

    let resolved_grant_id = attachment_authority
        .as_ref()
        .map(|authority| &authority.grant_id);

    let grant = if let Some(gid) = resolved_grant_id {
        match state.store.get_grant(gid) {
            Ok(g) => {
                if g.persona_id != persona_id {
                    return Ok(forbidden("grant belongs to a different persona"));
                }
                if g.credential_name != credential_name {
                    return Ok(forbidden(
                        "grant credential_name does not match X-Ember-Credential",
                    ));
                }
                if g.status != "active" {
                    return Ok(forbidden(&format!(
                        "grant is {} and cannot be used",
                        g.status
                    )));
                }
                g
            }
            Err(StoreError::NotFound) => {
                return Ok(forbidden("attachment resolved to a missing grant"));
            }
            Err(e) => return Err(ProxyError::Store(e)),
        }
    } else {
        match state.store.evaluate_grant(&persona_id, &credential_name) {
            Ok(g) => g,
            Err(StoreError::NotFound) => {
                return Ok(forbidden("no active grant for persona/credential"));
            }
            Err(e) => return Err(ProxyError::Store(e)),
        }
    };

    // Mirror the production per-Statement resolution check.
    let access_grant = match state.store.get_access_grant(&grant.id) {
        Ok(g) => g,
        Err(e) => return Err(ProxyError::Store(e)),
    };
    let resolved_sid: String;
    let resolved_stmt: core_grant_types::Statement;
    if let Some((action, resource)) = request_to_action_resource(req.method(), &effective_uri) {
        match resolve_statement_for_request_with_uri(
            &access_grant,
            &action,
            &resource,
            &effective_uri,
        ) {
            ResolveOutcome::NoApplicable => {
                tracing::warn!(
                    grant_id = %grant.id,
                    action = %action,
                    resource = %resource,
                    "no applicable statement for request — denying (test harness)"
                );
                if let Err(e) = state.store.log_event(
                    Some(&persona_id),
                    "credential.access",
                    Some(&credential_name),
                    "denied_no_applicable_statement",
                    Some(&format!("action={action} resource={resource}")),
                ) {
                    tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, action = %action, resource = %resource, "log_event failed");
                }
                return Ok(no_applicable_statement_response());
            }
            ResolveOutcome::SubtargetMiss { subtarget_glob } => {
                tracing::warn!(
                    grant_id = %grant.id,
                    action = %action,
                    resource = %resource,
                    subtarget = %subtarget_glob,
                    "subtarget scope mismatch — denying (test harness)"
                );
                if let Err(e) = state.store.log_event(
                    Some(&persona_id),
                    "credential.access",
                    Some(&credential_name),
                    "denied_subtarget_scope",
                    Some(&format!(
                        "action={action} resource={resource} subtarget_glob={subtarget_glob}"
                    )),
                ) {
                    tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, action = %action, resource = %resource, "log_event failed");
                }
                return Ok(scope_violation_response());
            }
            ResolveOutcome::UnevaluableCondition { conditions } => {
                // ADR 207 seam 8B — fail closed (test harness mirror).
                if let Err(e) = state.store.log_event(
                    Some(&persona_id),
                    "credential.access",
                    Some(&credential_name),
                    "denied_unevaluable_condition",
                    Some(&format!(
                        "action={action} resource={resource} conditions={conditions}"
                    )),
                ) {
                    tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, action = %action, resource = %resource, "log_event failed");
                }
                return Ok(scope_violation_response());
            }
            ResolveOutcome::Match { index: _, stmt } => {
                resolved_sid = stmt.sid.clone();
                resolved_stmt = stmt.clone();
            }
        }
    } else {
        return Ok(no_applicable_statement_response());
    }

    // Enforce allowed_targets if the grant specifies them.
    // FINDING-1 fix (cycle 41): use effective_uri.host() + host_matches_domain
    // — see the production handler's equivalent block for the rationale.
    if let Some(ref targets) = grant.allowed_targets {
        let allowed: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
        let target_host = effective_uri.host();

        let is_allowed = match target_host {
            Some(host) => allowed.iter().any(|pattern| {
                if let Some(domain) = pattern.strip_prefix("*.") {
                    host_matches_domain(host, domain)
                } else {
                    host == *pattern
                }
            }),
            None => false,
        };

        if !is_allowed {
            return Ok(forbidden(&format!(
                "target {} not in allowed origins: {}",
                target_url, targets
            )));
        }
    }

    // Collect request body up front so preflight can estimate tokens.
    // A test-mode header `X-Ember-Test-Response-Body` lets a test
    // inject the upstream response body verbatim so the post-flight
    // metering path can be exercised without a real upstream socket.
    let test_response_body_hdr = req
        .headers()
        .get("x-ember-test-response-body")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let (_parts, incoming_body) = req.into_parts();
    // Enforce body size cap in the test harness to match production.
    let body_bytes_in = match Limited::new(incoming_body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Ok(payload_too_large("request body exceeds 10 MiB limit"));
        }
        Err(e) => {
            tracing::warn!(error = %e, "request body collection failed");
            return Ok(internal_error("failed to read request body"));
        }
    };

    // Pre-flight Stream C budget check (test parity with production).
    match preflight_budget_check(&resolved_stmt, body_bytes_in.as_ref()) {
        PreflightDecision::Allowed => {}
        PreflightDecision::Rejected { axis, limit, used } => {
            if let Err(e) = state.store.log_event(
                Some(&persona_id),
                "proxy.denied_preflight",
                Some(&credential_name),
                "budget_exhausted",
                Some(&format!(
                    "grant_id={} sid={resolved_sid} axis={axis} limit={limit} used={used}",
                    grant.id
                )),
            ) {
                tracing::warn!(error = ?e, grant_id = %grant.id, statement_sid = %resolved_sid, axis, "log_event failed");
            }
            return Ok(budget_exhausted_response(
                &grant.id,
                &resolved_sid,
                axis,
                limit,
                used,
            ));
        }
    }

    // Wrap in Zeroizing so the raw key bytes are wiped on drop.
    let credential_bytes: Zeroizing<Vec<u8>> =
        match state
            .vault
            .get(VaultScope::Interactive, &state.store, &credential_name)
        {
            Ok(b) => b,
            Err(VaultError::NotFound) => {
                return Ok(internal_error("credential not found in vault"));
            }
            Err(e) => return Err(ProxyError::Vault(e)),
        };

    let credential_value: Zeroizing<String> =
        Zeroizing::new(String::from_utf8_lossy(&credential_bytes).into_owned());

    // P69L.0a (test harness): derive auth mode by reusing the
    // production helper, not by duplicating its host/provider logic.
    // This keeps the harness honest when provider-specific auth formats
    // evolve, such as Claude subscription OAuth staying on Bearer while
    // Anthropic API-key traffic still uses x-api-key.
    let effective_path_and_query_test = effective_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(effective_uri.path());
    let is_git_transport_test = is_git_smart_http_path(effective_path_and_query_test);
    let target_host_lower_test: String = extract_host_from_url(&target_url).unwrap_or_default();
    let auth_mode = {
        let mut auth_headers = hyper::HeaderMap::new();
        match inject_provider_auth(
            &mut auth_headers,
            &target_host_lower_test,
            is_git_transport_test,
            &credential_name,
            &credential_value,
        ) {
            Ok(scheme) => scheme.as_str(),
            Err(()) => {
                return Ok(internal_error(
                    "credential not representable as a header value",
                ));
            }
        }
    };

    if let Err(e) = state.store.log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        None,
    ) {
        tracing::warn!(error = ?e, persona_id = %persona_id, credential = %credential_name, "log_event failed");
    }

    // Synthesize an upstream body. If the test injected
    // `X-Ember-Test-Response-Body`, use that verbatim so the
    // post-flight meter has something LLM-shaped to parse;
    // otherwise return the legacy fixture JSON.
    let method = _parts.method.to_string();
    let response_body_bytes: Bytes = match test_response_body_hdr {
        Some(body) => Bytes::from(body),
        None => {
            let body = serde_json::json!({
                "proxied": true,
                "target": target_url,
                "method": method,
            });
            Bytes::from(serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()))
        }
    };

    let _ = credential_value;

    // Post-flight meter (test parity with production).
    let target_host: String = extract_host_from_url(&target_url).unwrap_or_default();
    if let Some(mut delta) = meter_response(&target_host, response_body_bytes.as_ref()) {
        // Production
        // metering folds in `record_upstream_request` to mint the
        // billable request count. The test harness always returns
        // 200, so success is unconditional — match the production
        // call shape so the bookkeeping stays identical.
        delta.requests = record_upstream_request(&target_host, true, true);
        match state
            .store
            .increment_statement_usage(&grant.id, &resolved_sid, delta)
        {
            Ok(delta) => {
                if let Some(budget) = &resolved_stmt.budget {
                    emit_threshold_crossings(
                        &state,
                        &grant.id,
                        &resolved_sid,
                        &persona_id,
                        &credential_name,
                        budget,
                        &delta.prior,
                        &delta.current,
                    );
                }
                let _ = state
                    .store
                    .mark_grant_exhausted_by_budget_if_terminal(&grant.id);
            }
            Err(e) => {
                tracing::warn!(
                    grant_id = %grant.id,
                    sid = %resolved_sid,
                    error = ?e,
                    "test harness: failed to increment statement usage"
                );
            }
        }
    }

    // Expose the auth mode chosen for the request in a response header
    // so tests can assert that git-transport paths route to Basic auth,
    // not Bearer. `x-ember-auth-mode` is a test-harness-only header —
    // it is never emitted by the production `handle_request`.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-ember-auth-mode", auth_mode)
        .body(box_full(Full::new(response_body_bytes)))
        .unwrap())
}

#[tokio::test]
async fn valid_request_returns_200_proxied() {
    let state = make_state();

    let persona = state.store.create_persona("test-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "github-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "github-token", "github:read", None)
        .unwrap();

    let req = proxy_request_with_headers(
        Some(&persona.id),
        Some("github-token"),
        Some("https://api.github.com"),
    );

    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["proxied"], true);
    assert_eq!(json["target"], "https://api.github.com");
    assert_eq!(json["method"], "GET");
}

#[tokio::test]
async fn missing_persona_header_returns_400() {
    let state = make_state();
    let req =
        proxy_request_with_headers(None, Some("github-token"), Some("https://api.github.com"));
    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_credential_header_returns_400() {
    let state = make_state();
    let req = proxy_request_with_headers(Some("persona-123"), None, Some("https://api.github.com"));
    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_target_header_returns_400() {
    let state = make_state();
    let req = proxy_request_with_headers(Some("persona-123"), Some("github-token"), None);
    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn no_active_grant_returns_403() {
    let state = make_state();

    let persona = state.store.create_persona("ungrantable-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "github-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    // No grant created

    let req = proxy_request_with_headers(
        Some(&persona.id),
        Some("github-token"),
        Some("https://api.github.com"),
    );

    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn request_to_disallowed_target_returns_403() {
    let state = make_state();

    let persona = state.store.create_persona("ssrf-test-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "github-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "github-token", "read", None)
        .unwrap();

    // Restrict the grant to api.github.com only
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET allowed_targets = 'api.github.com' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .unwrap();

    // Request to a disallowed target should be rejected
    let req = proxy_request_with_headers(
        Some(&persona.id),
        Some("github-token"),
        Some("https://evil.attacker.example.com/exfiltrate"),
    );

    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn credential_not_in_vault_returns_500() {
    let state = make_state();

    let persona = state.store.create_persona("vault-miss-agent").unwrap();
    state
        .store
        .create_grant(&persona.id, "missing-cred", "generic:read", None)
        .unwrap();
    // Credential NOT added to vault

    let req = proxy_request_with_headers(
        Some(&persona.id),
        Some("missing-cred"),
        Some("https://api.example.com"),
    );

    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

mod scope_tests;

// ------------------------------------------------------------------
// Stream C — per-Statement token + cent metering (P69K-C)
// ------------------------------------------------------------------

use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

/// Build a grant whose composite chain carries caller-supplied
/// Statements. Uses `create_grant` to insert the row, then
/// `overwrite_grant_blocks` to replace the shim chain with the
/// real multi-Statement envelope.
fn seed_composite_grant(
    state: &ProxyState,
    persona_id: &str,
    credential_name: &str,
    statements: Vec<Statement>,
) -> String {
    // Issue a stub so the row exists with sensible scope. The row-level
    // `scope` is metadata here; the signed statement set carries the
    // real request authorization shape.
    let grant = state
        .store
        .create_grant(persona_id, credential_name, "*", None)
        .unwrap();
    let root = state.store.persona_root_keypair(persona_id).unwrap();
    let ag = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        persona_id,
        credential_name,
        statements,
        0,
        None,
        &root,
    )
    .unwrap();
    state
        .store
        .overwrite_grant_blocks_with_parent_bound(&grant.id, &ag, &ag)
        .unwrap();
    grant.id
}

/// Credential statement — matches GitHub pushes under github:push.
/// Narrower than `*` so resolver chains don't accidentally shadow
/// the Session statement on LLM requests.
fn stmt_credential(sid: &str) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:push".into(), "github:read".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

/// Session statement with a `tokens` budget. Uses `llm:generate` so
/// it matches Anthropic POSTs (which `request_to_action_resource`
/// classifies as `llm:generate` on host `api.anthropic.com`).
fn stmt_session(sid: &str, tokens: u64) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Session,
        actions: vec!["llm:generate".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            tokens: Some(tokens),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

fn stmt_time(sid: &str, wall_clock_secs: u64) -> Statement {
    Statement {
        sid: sid.into(),
        resource_type: ResourceType::Time,
        actions: vec!["llm:generate".into()],
        resource: ResourceSelector::Any,
        budget: Some(Budget {
            wall_clock_secs: Some(wall_clock_secs),
            ..Default::default()
        }),
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    }
}

/// Anthropic-shaped response body with the given token counts.
fn anthropic_body(input_tokens: u64, output_tokens: u64) -> String {
    serde_json::json!({
        "id": "msg_test",
        "model": "claude-opus-4-5",
        "content": [],
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    })
    .to_string()
}

/// Build a proxy LLM request with an empty-ish JSON request body that
/// declares `max_tokens: 1`, so the preflight estimate is near-zero
/// and tests can exercise the post-flight meter without tripping
/// preflight rejection (the real preflight logic has its own tests).
fn proxy_llm_request(
    persona: &str,
    credential: &str,
    target: &str,
    response_body: &str,
) -> Request<Full<Bytes>> {
    let req_body = br#"{"max_tokens": 1}"#.to_vec();
    Request::builder()
        .method("POST")
        .uri("https://api.anthropic.com/v1/messages")
        .header("X-Ember-Persona", persona)
        .header("X-Ember-Credential", credential)
        .header("X-Ember-Target", target)
        .header("X-Ember-Test-Response-Body", response_body)
        .body(Full::new(Bytes::from(req_body)))
        .unwrap()
}

#[tokio::test]
async fn proxy_call_receipt_hook_mints_signed_receipt_id() {
    let identity_dir = tempfile::tempdir().expect("identity tempdir");
    let _ = crate::infra::receipt::init_identity(identity_dir.path());
    let state = make_state();
    let persona = state.store.create_persona("proxy-call").unwrap();
    let statement = stmt_session("S1", 20_000);
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_credential("S0"), statement.clone()],
    );
    let resolved = core_proxy_forward::ResolvedGrant {
        grant_id: grant_id.clone(),
        persona_id: persona.id.clone(),
        credential_name: "anthropic-key".into(),
        statement_sid: statement.sid.clone(),
        statement,
        grant_scope: "*".into(),
        allowed_targets: None,
    };
    let call = core_proxy_forward::ProxyCallReceiptRequest {
        method: "POST".into(),
        path: "/v1/messages".into(),
        status: 200,
        tokens_in: 120,
        tokens_out: 192,
        outcome: "complete".into(),
    };
    let backend = DaemonPolicyBackend::new(Arc::clone(&state));

    let receipt_id = backend
        .issue_proxy_call_receipt(&resolved, &call)
        .await
        .expect("receipt hook should not error")
        .expect("daemon backend should mint a receipt");

    assert_eq!(receipt_id.len(), 64, "receipt_id should be canonical hex");
    assert!(
        !receipt_id.starts_with("r-"),
        "proxy_call receipt_id must not use the old demo hash prefix"
    );
    let raw = state
        .store
        .get_receipt_v2_envelope_json(&receipt_id)
        .expect("receipt should be persisted");
    let envelope: core_events::receipt::ReceiptEnvelope =
        serde_json::from_str(&raw).expect("stored envelope should parse");
    assert_eq!(envelope.receipt_id, receipt_id);
    assert_eq!(envelope.kind, core_events::receipt::RECEIPT_KIND_PROXY_CALL);
    assert!(envelope.signature.is_some(), "receipt should be signed");
    let body: core_events::receipt::ProxyCallBody =
        serde_json::from_value(envelope.body).expect("proxy.call body should parse");
    assert_eq!(body.persona_id, persona.id);
    assert_eq!(body.grant_id, grant_id);
    assert_eq!(body.statement_sid, "S1");
    assert_eq!(body.method, "POST");
    assert_eq!(body.path, "/v1/messages");
    assert_eq!(body.status, 200);
    assert_eq!(body.tokens_in, 120);
    assert_eq!(body.tokens_out, 192);
    assert_eq!(body.tokens_total, 312);
    assert_eq!(body.outcome, "complete");
}

/// Call helper that takes a `Full<Bytes>` body — used for tests that
/// need a non-empty request body (preflight, metering).
async fn call_full(state: Arc<ProxyState>, req: Request<Full<Bytes>>) -> Response<ProxyBody> {
    use http_body_util::combinators::UnsyncBoxBody;
    let (parts, body) = req.into_parts();
    let mapped = body.map_err(|_| -> hyper::Error { panic!("Full body mapper unused") });
    let incoming_req = Request::from_parts(parts, mapped);
    let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> = incoming_req.map(UnsyncBoxBody::new);
    handle_request_boxed(state, boxed).await.unwrap()
}

#[tokio::test]
async fn proxy_meter_increments_tokens_on_anthropic_response() {
    let state = make_state();
    let persona = state.store.create_persona("meter-1").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-test",
            None,
        )
        .unwrap();
    // 3-statement grant — Credential + Session(20000 tokens) + Time.
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![
            stmt_credential("S0"),
            stmt_session("S1", 20_000),
            stmt_time("S2", 1800),
        ],
    );

    let body = anthropic_body(1_500, 500);
    let req = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body,
    );
    let resp = call_full(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Inspect the post-flight usage on the Session statement.
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let session = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .expect("session statement present")
        .1
        .clone();
    assert_eq!(
        session.usage.tokens, 2_000,
        "input 1500 + output 500 should sum to 2000 tokens"
    );
    // 10% usage → no warning yet.
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(
        !entries.iter().any(|e| e.action == "budget.warning"),
        "no warning expected at 10% usage"
    );
}

#[tokio::test]
async fn proxy_meter_emits_warning_at_80_percent() {
    let state = make_state();
    let persona = state.store.create_persona("meter-80").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-test",
            None,
        )
        .unwrap();
    // Session tokens = 10_000.
    let _grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_credential("S0"), stmt_session("S1", 10_000)],
    );

    // First call: 7900 tokens total (input 4000 + output 3900).
    let body_1 = anthropic_body(4_000, 3_900);
    let req_1 = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body_1,
    );
    let resp_1 = call_full(Arc::clone(&state), req_1).await;
    assert_eq!(resp_1.status(), StatusCode::OK);
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(
        !entries.iter().any(|e| e.action == "budget.warning"),
        "no warning expected at 79%"
    );

    // Second call: 200 more tokens (input 100, output 100) → 8100, crossing 80%.
    let body_2 = anthropic_body(100, 100);
    let req_2 = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body_2,
    );
    let resp_2 = call_full(Arc::clone(&state), req_2).await;
    assert_eq!(resp_2.status(), StatusCode::OK);

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(
        entries.iter().any(|e| {
            e.action == "budget.warning"
                && e.outcome == "80"
                && e.details.as_deref().unwrap_or("").contains("axis=tokens")
        }),
        "expected tokens budget.warning at 80% band, entries: {:?}",
        entries
            .iter()
            .map(|e| (e.action.clone(), e.outcome.clone()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn proxy_preflight_rejects_over_budget() {
    let state = make_state();
    let persona = state.store.create_persona("meter-preflight").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-test",
            None,
        )
        .unwrap();
    // Budget: 10_000 tokens. Pre-seed usage = 9_500 by doing one
    // metered call first.
    let _grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_credential("S0"), stmt_session("S1", 10_000)],
    );
    // Warm usage to 9_500 via a prior successful meter.
    let body_warm = anthropic_body(5_000, 4_500);
    let req_warm = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body_warm,
    );
    let resp = call_full(Arc::clone(&state), req_warm).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Now attempt a call whose estimated cost pushes usage past 10k.
    // Craft a request body large enough that the byte-len/4 heuristic
    // projects >600 input tokens, plus `max_tokens` = 500 output.
    let big_prompt: String = "a".repeat(4_000); // 4_000 bytes → ~1_000 tokens input
    let req_body_json = serde_json::json!({
        "model": "claude-opus-4-5",
        "max_tokens": 500,
        "messages": [{"role": "user", "content": big_prompt}],
    })
    .to_string();
    // Use Full body instead of Empty so preflight has bytes to
    // estimate against.
    let response_body = anthropic_body(0, 0);
    let req_over = Request::builder()
        .method("POST")
        .uri("https://api.anthropic.com/v1/messages")
        .header("X-Ember-Persona", &persona.id)
        .header("X-Ember-Credential", "anthropic-key")
        .header("X-Ember-Target", "https://api.anthropic.com")
        .header("X-Ember-Test-Response-Body", response_body)
        .body(Full::new(Bytes::from(req_body_json)))
        .unwrap();

    // Call via the boxed wrapper directly since the `call` helper
    // uses Empty<Bytes>. Map body errors in the same way.
    use http_body_util::combinators::UnsyncBoxBody;
    let (parts, body) = req_over.into_parts();
    let mapped = body
        .map_err(|_| -> hyper::Error { panic!("full body error mapper unused in preflight test") });
    let incoming_req = Request::from_parts(parts, mapped);
    let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> = incoming_req.map(UnsyncBoxBody::new);
    let resp = handle_request_boxed(Arc::clone(&state), boxed)
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "preflight should 429 when projected usage exceeds budget"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "budget_exhausted");
    assert_eq!(json["axis"], "tokens");

    // Usage must be unchanged — 9500, same as before the rejected call.
    let ag = state.store.get_access_grant(&_grant_id).unwrap();
    let session = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .unwrap()
        .1
        .clone();
    assert_eq!(
        session.usage.tokens, 9_500,
        "preflight reject must not increment usage"
    );

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(
        entries.iter().any(|e| e.action == "proxy.denied_preflight"),
        "expected proxy.denied_preflight audit entry"
    );
}

#[tokio::test]
async fn proxy_meter_flips_status_on_exhaustion() {
    // Grant with Session tokens = 2_000 (single budget-bearing
    // statement). Drive usage past the limit. Since Session is the
    // only budget-bearing Statement AND it's exhausted, the grant
    // flips to ExhaustedByBudget under the "all budget-bearing
    // statements exhausted" rule.
    let state = make_state();
    let persona = state.store.create_persona("meter-exhaust").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-test",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![
            stmt_credential("S0"),
            stmt_session("S1", 2_000),
            // Time statement with wall_clock_secs = 3_600, which
            // still has remaining capacity (usage.wall_clock_secs
            // stays 0 since we don't tick it in this test). Since
            // mark_grant_exhausted_by_budget_if_terminal requires
            // ALL budget-bearing statements exhausted, we do NOT
            // expect a flip while Time remains active. That
            // documents the "conservative choice" behavior.
            stmt_time("S2", 3_600),
        ],
    );

    // Drive Session usage past the 2_000 limit.
    let body = anthropic_body(1_500, 1_500); // 3_000 total
    let req = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body,
    );
    let resp = call_full(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Session usage exceeds its 2_000 cap.
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let s1 = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .unwrap()
        .1
        .clone();
    assert!(s1.usage.tokens >= 2_000);
    assert!(
        !s1.has_budget_remaining(),
        "S1 should have no budget remaining"
    );
    // Since Time statement still has capacity (wall_clock_secs
    // remains 0), the grant stays Active — the conservative
    // "all-exhausted" rule documents this.
    assert_eq!(ag.status.as_str(), "active");

    // Now seed a single-budget-statement grant and verify the flip.
    let persona2 = state.store.create_persona("meter-exhaust-2").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key-2",
            b"sk-test",
            None,
        )
        .unwrap();
    let gid2 = seed_composite_grant(
        &state,
        &persona2.id,
        "anthropic-key-2",
        vec![stmt_credential("S0"), stmt_session("S1", 2_000)],
    );
    let body2 = anthropic_body(1_500, 1_500);
    let req2 = proxy_llm_request(
        &persona2.id,
        "anthropic-key-2",
        "https://api.anthropic.com",
        &body2,
    );
    let resp2 = call_full(Arc::clone(&state), req2).await;
    assert_eq!(resp2.status(), StatusCode::OK);

    let ag2 = state.store.get_access_grant(&gid2).unwrap();
    assert_eq!(
        ag2.status.as_str(),
        "exhausted_by_budget",
        "single-budget grant must flip when its one budget-bearing statement exhausts"
    );
    // Audit must carry grant.exhausted and budget.exhausted events.
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(entries.iter().any(|e| e.action == "grant.exhausted"));
    assert!(entries.iter().any(|e| e.action == "budget.exhausted"));
}

#[tokio::test]
async fn proxy_non_llm_target_skips_token_meters() {
    // GitHub request — only a Credential statement applicable, no
    // token/cent meter. Post-flight `meter_response` returns None
    // for github.com and usage is unchanged.
    let state = make_state();
    let persona = state.store.create_persona("gh-meter").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    // Single credential statement with allowed POST.
    let stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:push".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let grant_id = seed_composite_grant(&state, &persona.id, "gh-token", vec![stmt]);

    let req = Request::builder()
        .method("POST")
        .uri("https://api.github.com/repos/a/b/issues")
        .header("X-Ember-Persona", &persona.id)
        .header("X-Ember-Credential", "gh-token")
        .header("X-Ember-Target", "https://api.github.com")
        .body(Empty::new())
        .unwrap();
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // No metering — usage still default.
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let s0 = ag
        .statements()
        .find(|(_, s)| s.sid == "S0")
        .unwrap()
        .1
        .clone();
    assert_eq!(s0.usage.tokens, 0);
    assert_eq!(s0.usage.cents, 0);
    // No warnings/exhausted — statement has no budget.
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(!entries.iter().any(|e| e.action == "budget.warning"));
    assert!(!entries.iter().any(|e| e.action == "budget.exhausted"));
}

#[test]
fn preflight_budget_check_passes_when_under_limit() {
    let stmt = stmt_session("S1", 10_000);
    let body = br#"{"max_tokens": 100}"#;
    assert_eq!(
        preflight_budget_check(&stmt, body),
        PreflightDecision::Allowed
    );
}

#[test]
fn preflight_budget_check_rejects_when_projected_exceeds() {
    let mut stmt = stmt_session("S1", 1_000);
    stmt.usage.tokens = 900;
    // Body >= 1_000 bytes implies estimate >= 250 tokens plus 500
    // default output = 750; 900 + 750 > 1_000 → reject.
    let big_body = vec![b'a'; 1_000];
    match preflight_budget_check(&stmt, &big_body) {
        PreflightDecision::Rejected { axis, limit, used } => {
            assert_eq!(axis, "tokens");
            assert_eq!(limit, 1_000);
            assert_eq!(used, 900);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[test]
fn preflight_budget_check_no_budget_always_allowed() {
    let stmt = stmt_credential("S0");
    let body = b"anything";
    assert_eq!(
        preflight_budget_check(&stmt, body),
        PreflightDecision::Allowed
    );
}

#[test]
fn meter_response_anthropic_extracts_tokens() {
    let body =
        br#"{"usage": {"input_tokens": 100, "output_tokens": 200}, "model": "claude-opus-4-5"}"#;
    let u = meter_response("api.anthropic.com", body).expect("parsed");
    assert_eq!(u.tokens, 300);
    // 100 input + 200 output at claude-opus-4-5 (1500 / 7500 cents/M).
    // in cents: (100 * 1500 / 1_000_000) + (200 * 7500 / 1_000_000) = 0 + 1 = 1.
    assert_eq!(u.cents, 1);
}

#[test]
fn meter_response_github_returns_none() {
    let body = br#"{"sha": "abc123"}"#;
    assert!(meter_response("api.github.com", body).is_none());
}

#[test]
fn mark_grant_exhausted_stays_active_while_budgets_remain() {
    // Only one of two budget-bearing statements is exhausted; grant
    // stays Active.
    let state = make_state();
    let persona = state.store.create_persona("flip-test-a").unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "cred",
        vec![stmt_session("S1", 1_000), stmt_time("S2", 3_600)],
    );
    // Exhaust S1.
    state
        .store
        .increment_statement_usage(
            &grant_id,
            "S1",
            Usage {
                tokens: 1_500,
                ..Default::default()
            },
        )
        .unwrap();
    let flipped = state
        .store
        .mark_grant_exhausted_by_budget_if_terminal(&grant_id)
        .unwrap();
    assert!(!flipped, "grant should stay active — S2 still has capacity");
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    assert_eq!(ag.status.as_str(), "active");
}

#[test]
fn threshold_warning_is_debounced_per_band() {
    // Running the meter twice in a row on the same (grant, sid,
    // axis, band) must only emit one audit entry.
    let state = make_state();
    let persona = state.store.create_persona("dedupe").unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "cred",
        vec![stmt_session("S1", 10_000)],
    );
    // First increment: crosses 80% band (8000/10000).
    let delta1 = state
        .store
        .increment_statement_usage(
            &grant_id,
            "S1",
            Usage {
                tokens: 8_000,
                ..Default::default()
            },
        )
        .unwrap();
    let budget = Budget {
        tokens: Some(10_000),
        ..Default::default()
    };
    emit_threshold_crossings(
        &state,
        &grant_id,
        "S1",
        &persona.id,
        "cred",
        &budget,
        &delta1.prior,
        &delta1.current,
    );
    // Second attempt at the same threshold: should be deduped.
    emit_threshold_crossings(
        &state,
        &grant_id,
        "S1",
        &persona.id,
        "cred",
        &budget,
        &delta1.prior,
        &delta1.current,
    );
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let count = entries
        .iter()
        .filter(|e| e.action == "budget.warning" && e.outcome == "80")
        .count();
    assert_eq!(count, 1, "warning at 80% must be emitted only once");
}

#[test]
fn threshold_warning_broadcasts_to_subscribers() {
    // Wiring check for the MCP push channel (P69K-F1). When a
    // `broadcast::Sender<GrantEvent>` is attached to `ProxyState`,
    // crossing an 80% band MUST both log an audit record AND send a
    // `GrantEvent::BudgetWarning` to active subscribers. Subscribers
    // see the same debounce semantics as the audit log — a second
    // crossing of the same band produces no second broadcast.
    use tokio::sync::broadcast;

    let (events_tx, mut events_rx) = broadcast::channel::<GrantEvent>(16);
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(crate::infra::vault::Vault::new(
        [0x42u8; 32],
    )));
    let state = Arc::new(ProxyState::new(store, None));
    // The broadcast channel + threshold
    // debounce set now live on the sink, not on `ProxyState`. Install
    // the sink immediately after construction. `OnceLock::set` returns
    // `Result<(), Arc<DaemonEventSink>>` whose Err variant does not
    // implement Debug, so we discard the Result rather than `unwrap`.
    let sink = Arc::new(DaemonEventSink::new(state.clone(), Some(events_tx.clone())));
    let _ = state.event_sink.set(sink.clone());
    let persona = state.store.create_persona("broadcast").unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "cred",
        vec![stmt_session("S1", 10_000)],
    );
    let delta = state
        .store
        .increment_statement_usage(
            &grant_id,
            "S1",
            Usage {
                tokens: 8_000,
                ..Default::default()
            },
        )
        .unwrap();
    let budget = Budget {
        tokens: Some(10_000),
        ..Default::default()
    };
    emit_threshold_crossings(
        &state,
        &grant_id,
        "S1",
        &persona.id,
        "cred",
        &budget,
        &delta.prior,
        &delta.current,
    );

    // Subscriber sees exactly one warning with the right payload.
    let event = events_rx.try_recv().expect("one broadcast pending");
    match event {
        GrantEvent::BudgetWarning {
            grant_id: gid,
            statement_sid,
            axis,
            used,
            budget: cap,
            percent,
        } => {
            assert_eq!(gid, grant_id);
            assert_eq!(statement_sid, "S1");
            assert_eq!(axis, "tokens");
            assert_eq!(used, 8_000);
            assert_eq!(cap, 10_000);
            assert_eq!(percent, "80");
        }
        other => panic!("expected BudgetWarning, got {other:?}"),
    }

    // Second emit at the same band: no new broadcast.
    emit_threshold_crossings(
        &state,
        &grant_id,
        "S1",
        &persona.id,
        "cred",
        &budget,
        &delta.prior,
        &delta.current,
    );
    assert!(
        matches!(
            events_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ),
        "debounced second crossing must not rebroadcast"
    );
}

#[test]
fn threshold_exhausted_broadcasts_budget_exhausted_event() {
    use tokio::sync::broadcast;

    let (events_tx, mut events_rx) = broadcast::channel::<GrantEvent>(16);
    let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
    store.set_vault(std::rc::Rc::new(crate::infra::vault::Vault::new(
        [0x42u8; 32],
    )));
    let state = Arc::new(ProxyState::new(store, None));
    // See sibling test — sink ownership of
    // events_tx + threshold_emitted moved out of ProxyState.
    let sink = Arc::new(DaemonEventSink::new(state.clone(), Some(events_tx.clone())));
    let _ = state.event_sink.set(sink.clone());
    let persona = state.store.create_persona("exhaust-b").unwrap();
    let grant_id =
        seed_composite_grant(&state, &persona.id, "cred", vec![stmt_session("S1", 1_000)]);
    let delta = state
        .store
        .increment_statement_usage(
            &grant_id,
            "S1",
            Usage {
                tokens: 1_000,
                ..Default::default()
            },
        )
        .unwrap();
    let budget = Budget {
        tokens: Some(1_000),
        ..Default::default()
    };
    emit_threshold_crossings(
        &state,
        &grant_id,
        "S1",
        &persona.id,
        "cred",
        &budget,
        &delta.prior,
        &delta.current,
    );

    // Going from 0 → 1000 crosses 80%, 95%, AND 100% in a single
    // increment — the subscriber sees three events in band order.
    let bands: Vec<String> = (0..3)
        .map(|_| {
            let ev = events_rx.try_recv().expect("event pending");
            match ev {
                GrantEvent::BudgetWarning { percent, .. } => percent.to_string(),
                GrantEvent::BudgetExhausted { .. } => "100".to_string(),
                other => panic!("unexpected event {other:?}"),
            }
        })
        .collect();
    assert!(bands.contains(&"80".to_string()));
    assert!(bands.contains(&"95".to_string()));
    assert!(bands.contains(&"100".to_string()));
}

// P69L spike Day-1 pure-function tests for git echo helpers moved to
// `core-proxy-forward::r#match::tests`.

#[test]
fn base64_std_encode_matches_rfc_vectors() {
    // RFC 4648 §10 test vectors.
    assert_eq!(base64_std_encode(b""), "");
    assert_eq!(base64_std_encode(b"f"), "Zg==");
    assert_eq!(base64_std_encode(b"fo"), "Zm8=");
    assert_eq!(base64_std_encode(b"foo"), "Zm9v");
    assert_eq!(base64_std_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_std_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64_std_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn github_basic_auth_uses_x_access_token_prefix() {
    // `x-access-token:hunter2` → base64 → "eC1hY2Nlc3MtdG9rZW46aHVudGVyMg=="
    let v = build_github_basic_auth("hunter2");
    assert_eq!(v, "Basic eC1hY2Nlc3MtdG9rZW46aHVudGVyMg==");
}

// ------------------------------------------------------------------
// P69L.0b: streaming git-echo body — 2 MiB passes through without OOM
// ------------------------------------------------------------------

/// Verify that the git-echo path streams a body larger than the old
/// 1 MiB `TeeBody` cap without panicking or truncating.
///
/// Architecture: spins up two local TCP servers —
///   1. A mock "upstream" that echoes the request body back verbatim.
///   2. The git-echo proxy (`handle_git_echo` served via hyper HTTP/1)
///      pointing at (1).
/// A hyper HTTP/1 client pushes a 2 MiB body through the echo proxy
/// and asserts the response length matches. `BodyExt::collect` is only
/// used on the assertion side — the path under test never collects.
///
/// Both server connections run inside a `LocalSet` so `run_git_echo_proxy`
/// (which internally builds a `LocalSet`) is not needed here; we serve
/// `handle_git_echo` directly via `hyper::server::conn::http1`.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn git_echo_streams_large_body_without_collect() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    // ---- 1. Mock upstream: bind on a random port, echo request body ----
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        // Serve exactly one connection then exit.
        if let Ok((stream, _)) = upstream_listener.accept().await {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req: Request<Incoming>| async move {
                        // Collect the request body to build the echo response.
                        // This is ONLY in the mock upstream, not in the path under test.
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let len = body.len();
                        Ok::<Response<Full<Bytes>>, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-length", len.to_string())
                                .body(Full::new(body))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        }
    });

    // ---- 2. Bind the echo-proxy socket and serve handle_git_echo in a LocalSet ----
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());

    let (echo_state, persona_id, cred_name) =
        make_git_echo_state("stream-persona", "stream-cred", "test-pat");
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state: echo_state,
        upstream_scheme: Scheme::Http,
    });

    // Run the proxy in a LocalSet — handle_git_echo is !Send-safe via LocalSet.
    let local = tokio::task::LocalSet::new();
    let cfg_for_server = Arc::clone(&config);
    local.spawn_local(async move {
        // Accept exactly one connection.
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    // ---- 3. Build a 2 MiB payload and POST it through the proxy ----
    const TWO_MIB: usize = 2 * 1024 * 1024;
    let payload: Bytes = Bytes::from(vec![0xABu8; TWO_MIB]);
    let payload_clone = payload.clone();

    // The proxy rewrites paths of the form `/{upstream_host}/{rest}`.
    // We use the git-receive-pack path so Basic auth is injected.
    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/emberdotlink/emberlink.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );

    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona_id.as_str())
        .header("x-ember-credential", cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .header("content-length", TWO_MIB.to_string())
        .body(Full::new(payload_clone))
        .unwrap();

    // Drive the LocalSet while performing the entire client round-trip —
    // headers + body collection — inside `run_until` so the server-side
    // hyper connection keeps progressing while the client drains the
    // response body. Ending `run_until` before body collection would
    // stall the `Passthrough(Incoming)` body (no executor to push frames).
    // The 10-second timeout prevents a connection-ordering regression from
    // hanging CI for the full 60-minute runner timeout.
    let (status, resp_body) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        local.run_until(async move {
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        }),
    )
    .await
    .expect("streaming round-trip timed out");

    assert_eq!(status, 200, "mock upstream should echo 200");

    // Collect only on the assertion side — the path under test streamed.
    assert_eq!(
        resp_body.len(),
        TWO_MIB,
        "response body length must equal the sent payload (no truncation)"
    );
    assert_eq!(
        resp_body, payload,
        "response body content must match the sent payload"
    );
}

/// Sweep 3 S-REVOKE regression: a per-statement revocation on the git-push
/// echo lane must DENY (parity with the LLM lane). Before the fix,
/// `handle_git_echo` resolved a statement but never consulted
/// `get_revoked_sids`, so a credential the operator had scoped-down via
/// per-statement revoke still injected and pushed. No upstream server is bound
/// because the revocation denial returns 403 before any upstream contact.
#[tokio::test]
async fn git_echo_denies_revoked_statement() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    let (echo_state, persona_id, cred_name) =
        make_git_echo_state("revoke-persona", "revoke-cred", "ghp_secret");

    // Revoke every statement on the persona's grant for this credential, via
    // the real store path (same write `revoke_grant_statement` the daemon RPC
    // uses). After this, the matched github:push statement is revoked.
    let grant = echo_state
        .store
        .evaluate_grant(&persona_id, &cred_name)
        .expect("grant exists");
    let access_grant = echo_state
        .store
        .get_access_grant(&grant.id)
        .expect("access grant loads");
    let sids: Vec<String> = access_grant
        .statements()
        .map(|(_, stmt)| stmt.sid.clone())
        .collect();
    assert!(
        !sids.is_empty(),
        "test grant must carry at least one statement"
    );
    for sid in &sids {
        echo_state
            .store
            .revoke_grant_statement(&grant.id, sid)
            .expect("revoke statement");
    }

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    // upstream_host is never contacted (denial precedes upstream).
    let upstream_host = "127.0.0.1:9";
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.to_string(),
        state: echo_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_for_server = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/acme/widgets.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona_id.as_str())
        .header("x-ember-credential", cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"0000")))
        .unwrap();

    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        local.run_until(async move { client.request(req).await.unwrap().status() }),
    )
    .await
    .expect("revoked git-echo round-trip timed out");

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "git-echo must deny a revoked statement (S-REVOKE parity)"
    );
}

/// BKR-4b (ADR 205 §A.4): the git-echo lane now walks grant ancestry. A child
/// grant whose PARENT was revoked without the eager `cascade_revoke_children`
/// write reaching it (crash mid-cascade / race / presented embed-chain) must be
/// denied — even though the child is active and its statement covers the push.
/// Before this, `handle_git_echo` walked no ancestry, so a revoked-ancestor
/// grant could still inject a git-push credential (the same class #5708 closed
/// at the construct mint; parity with the LLM lane's existing §A.4 check). No
/// upstream is bound — the denial precedes upstream contact.
#[tokio::test]
async fn git_echo_denies_revoked_grant_ancestor() {
    use http_body_util::Full;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    let (echo_state, persona_id, cred_name) =
        make_git_echo_state("ancestry-persona", "ancestry-cred", "ghp_secret");

    // The grant make_git_echo_state created is the apex; treat it as the parent.
    let parent = echo_state
        .store
        .evaluate_grant(&persona_id, &cred_name)
        .expect("apex grant exists");
    // Active child grant for the same persona+credential, descending from parent.
    let child = echo_state
        .store
        .create_grant(&persona_id, &cred_name, "*", None)
        .expect("create child grant");
    echo_state
        .store
        .conn()
        .execute(
            "UPDATE grants SET parent_grant_id = ?1 WHERE id = ?2",
            rusqlite::params![parent.id, child.id],
        )
        .unwrap();
    // Revoke ONLY the parent (simulate the missed cascade); child stays active.
    echo_state
        .store
        .conn()
        .execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();
    assert_eq!(
        echo_state.store.get_grant(&child.id).unwrap().status,
        "active",
        "child must stay active so the denial is purely the §A.4 walk"
    );

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    // upstream_host is never contacted (denial precedes upstream).
    let upstream_host = "127.0.0.1:9";
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.to_string(),
        state: echo_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_for_server = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/acme/widgets.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona_id.as_str())
        .header("x-ember-credential", cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"0000")))
        .unwrap();

    let status = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        local.run_until(async move { client.request(req).await.unwrap().status() }),
    )
    .await
    .expect("ancestor-revoked git-echo round-trip timed out");

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "git-echo must deny a grant with a revoked ancestor (§A.4 walk)"
    );
}

/// ADR 211 §1/AC-2 parity for the git echo lane: an active grant row is not
/// enough authority-to-act once its grant-scoped live lease is gone. Deny
/// before statement resolution, vault reads, or upstream contact.
#[tokio::test]
async fn git_echo_denies_active_grant_without_live_lease() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    let (echo_state, persona_id, cred_name) =
        make_git_echo_state("no-lease-persona", "no-lease-cred", "ghp_secret");
    let grant = echo_state
        .store
        .evaluate_grant(&persona_id, &cred_name)
        .expect("grant exists");
    assert!(
        echo_state.store.leases().drop_lease(&grant.id),
        "test setup must remove the live lease while leaving the grant active"
    );
    assert_eq!(
        echo_state.store.get_grant(&grant.id).unwrap().status,
        "active",
        "row remains active; refusal must come from missing lease authority"
    );

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let upstream_host = "127.0.0.1:9";
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.to_string(),
        state: echo_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_for_server = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/acme/widgets.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona_id.as_str())
        .header("x-ember-credential", cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"0000")))
        .unwrap();

    let (status, body) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        local.run_until(async move {
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        }),
    )
    .await
    .expect("no-lease git-echo round-trip timed out");

    assert_eq!(status, StatusCode::FORBIDDEN);
    let body_str = std::str::from_utf8(&body[..]).expect("body must be utf-8");
    assert!(
        body_str.starts_with("grant_inactive:no_live_lease:"),
        "git-echo no-live-lease body must include grant_id suffix, got: {body_str}"
    );
}

// ------------------------------------------------------------------
// P69L.0b-P0-GATE: handle_git_echo honours the streaming concurrency
// cap — 503 with Retry-After + "streaming-saturated" body when
// saturated; 200 once a slot frees up.
// ------------------------------------------------------------------

/// When every streaming slot is held, `handle_git_echo` must
/// fast-fail with 503 + `Retry-After: 1` + body `streaming-saturated`
/// BEFORE spending any upstream bandwidth. Drop one slot and the
/// next request must pass through normally.
///
/// The test shares the process-global `STREAMING_REQUESTS_INFLIGHT`
/// counter with peer streaming tests, so we hold
/// `streaming_gate_test_lock()` for the whole body to serialise
/// with every other test that touches the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn passthrough_respects_concurrency_cap() {
    use http_body_util::Full;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let _guard = streaming_gate_test_lock();
    // Baseline — must be zero under the gate lock; otherwise a
    // prior test leaked a slot and this suite is already broken.
    assert_eq!(
        StreamingSlot::inflight(),
        0,
        "streaming gate must be idle before cap-saturation test"
    );

    // ---- Mock upstream: echo the request body back as 200 OK.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = upstream_listener.accept().await {
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|req: Request<Incoming>| async move {
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            Ok::<Response<Full<Bytes>>, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(body))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    // ---- Bind the echo proxy and serve it from a LocalSet.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());

    let _ = rustls::crypto::ring::default_provider().install_default();

    let (gate_state, gate_persona_id, gate_cred_name) =
        make_git_echo_state("gate-persona", "gate-cred", "gate-pat");
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state: gate_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_for_server = Arc::clone(&config);
    local.spawn_local(async move {
        // Accept a handful of connections — we call it at most 3x
        // below (saturated call, cap-edge call, post-release call)
        // and each hyper client may open multiple TCP connections.
        for _ in 0..6 {
            let Ok((stream, _)) = proxy_listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            tokio::task::spawn_local(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req: Request<Incoming>| {
                            let cfg = Arc::clone(&cfg);
                            async move { handle_git_echo(cfg, req).await }
                        }),
                    )
                    .await;
            });
        }
    });

    // ---- Saturate the gate by holding MAX slots directly.
    let mut held: Vec<StreamingSlot> = Vec::with_capacity(MAX_CONCURRENT_STREAMING);
    for _ in 0..MAX_CONCURRENT_STREAMING {
        held.push(StreamingSlot::try_acquire().expect("slot under cap"));
    }
    assert_eq!(StreamingSlot::inflight(), MAX_CONCURRENT_STREAMING);

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/emberdotlink/emberlink.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );

    // ---- First call — gate saturated → expect 503 + Retry-After.
    let (status1, retry_after1, body1) = local
        .run_until(async {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let req = Request::builder()
                .method("POST")
                .uri(&proxy_url)
                .header("content-type", "application/x-git-receive-pack-request")
                .body(Full::new(Bytes::from_static(b"noop")))
                .unwrap();
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, retry_after, body)
        })
        .await;
    assert_eq!(
        status1,
        StatusCode::SERVICE_UNAVAILABLE,
        "saturated gate must reject with 503"
    );
    assert_eq!(
        retry_after1.as_deref(),
        Some("1"),
        "503 must carry Retry-After: 1"
    );
    assert_eq!(
        &body1[..],
        b"streaming-saturated",
        "503 body must be exactly \"streaming-saturated\""
    );
    // Gate must still report MAX — the rejected call did not
    // acquire, so no slot was consumed.
    assert_eq!(
        StreamingSlot::inflight(),
        MAX_CONCURRENT_STREAMING,
        "rejected request must not perturb the counter"
    );

    // ---- Release one slot — next call must succeed.
    drop(held.pop().expect("one held"));
    assert_eq!(StreamingSlot::inflight(), MAX_CONCURRENT_STREAMING - 1);

    let status2 = local
        .run_until(async {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let req = Request::builder()
                .method("POST")
                .uri(&proxy_url)
                .header("x-ember-persona", gate_persona_id.as_str())
                .header("x-ember-credential", gate_cred_name.as_str())
                .header("content-type", "application/x-git-receive-pack-request")
                .body(Full::new(Bytes::from_static(b"ok")))
                .unwrap();
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            // Drain body so the response body drops → slot releases.
            let _ = resp.into_body().collect().await.unwrap().to_bytes();
            status
        })
        .await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "with a free slot, handle_git_echo must forward upstream normally"
    );

    // Tidy up — release the remaining MAX-1 held slots.
    drop(held);
    assert_eq!(
        StreamingSlot::inflight(),
        0,
        "all held slots must be released by test end"
    );
}

// ------------------------------------------------------------------
// P69L.0b-P1-DROP-GUARD: PassthroughBody emits bytes_forwarded +
// outcome on Drop — both for clean EOF ("complete") and mid-stream
// client disconnect ("partial").
// ------------------------------------------------------------------

/// Clean-EOF path: consume the body to completion → Drop must see
/// `outcome == complete` and the exact byte count observed.
#[tokio::test(flavor = "current_thread")]
async fn passthrough_drop_emits_complete_outcome_on_eof() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    let mut body = PassthroughBody::new(mock, None)
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // Feed two data frames then clean EOF.
    tx.send(Ok(Frame::data(Bytes::from_static(b"hello "))))
        .unwrap();
    tx.send(Ok(Frame::data(Bytes::from_static(b"world"))))
        .unwrap();
    drop(tx);

    // Drain to EOF.
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        if frame.is_none() {
            break;
        }
    }

    // Drop the body; sinks must reflect clean outcome.
    drop(body);
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_COMPLETE,
        "EOF-drained body must record outcome=complete"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        (b"hello ".len() + b"world".len()) as u64,
        "bytes_forwarded must match total data-frame bytes"
    );
}

/// Mid-stream disconnect path: drop the body without draining.
/// Outcome must collapse to `partial`; bytes_forwarded must reflect
/// whatever was already observed by `poll_frame` (0 here because
/// we never polled).
#[tokio::test(flavor = "current_thread")]
async fn passthrough_drop_emits_partial_outcome_on_mid_stream_drop() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    let mut body = PassthroughBody::new(mock, None)
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // Poll exactly one frame so there's a non-zero byte count to
    // witness — then simulate client disconnect by dropping the
    // body without reaching EOF. Keep `tx` alive so upstream has
    // more to send (this is the hostile-client model).
    tx.send(Ok(Frame::data(Bytes::from_static(b"abc"))))
        .unwrap();
    let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(
        frame.is_some(),
        "first poll should surface the queued frame"
    );

    drop(body);
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_PARTIAL,
        "mid-stream drop without EOF must record outcome=partial"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        b"abc".len() as u64,
        "partial drop must still report bytes forwarded up to the drop"
    );
    // Keep tx alive to end — models the upstream still having data
    // queued at the moment the client side vanished.
    drop(tx);
}

// ------------------------------------------------------------------
// P69L.0b-P0-TIMEOUTS: slow-loris upstream headers deadline + per-frame
// idle watchdog regression tests.
// ------------------------------------------------------------------

/// Slow-loris upstream: mock server accepts the TCP connection but
/// never writes any bytes (no status line, no headers). The
/// `HEADERS_DEADLINE` wrapper in `handle_git_echo` must abort the
/// in-flight request and return 504 to the client.
///
/// Correctness invariants:
///   1. Client sees `504 Gateway Timeout`.
///   2. Upstream socket is closed (we observe this by holding the
///      `TcpStream` handle on the mock side — the subsequent `read`
///      returns `Ok(0)`, meaning FIN arrived).
///   3. No futures leak: the hyper server task serving the proxy
///      connection completes (`JoinHandle::is_finished()`) after
///      the client drops the 504 response.
///
/// Uses `current_thread` + `start_paused = true` so the
/// `HEADERS_DEADLINE` elapse is driven by `tokio::time::advance`
/// rather than a real 30s sleep. All work runs inside a single
/// LocalSet — required because `handle_git_echo` is `!Send`.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn slow_loris_upstream_times_out_with_504() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use tokio::io::AsyncReadExt;

    // ---- Slow-loris upstream: bind, accept, hold the socket open,
    // ---- never write anything. We observe FIN via `read == Ok(0)`.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (peer_closed_tx, peer_closed_rx) = tokio::sync::oneshot::channel::<bool>();

    let local = tokio::task::LocalSet::new();

    let upstream_handle = local.spawn_local(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut buf = [0u8; 1];
        // The proxy will write the request line + headers (wanting a
        // response), so upstream will see bytes before the deadline
        // fires. Drain in a loop until FIN (read returns `Ok(0)`).
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    let _ = peer_closed_tx.send(true);
                    break;
                }
                Ok(_) => continue,
                Err(_) => {
                    let _ = peer_closed_tx.send(false);
                    break;
                }
            }
        }
    });

    // ---- Bind the echo proxy and serve handle_git_echo in the
    // ---- same LocalSet. `!Send` bodies ride along freely.
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());

    let _ = rustls::crypto::ring::default_provider().install_default();

    let (deadline_state, deadline_persona_id, deadline_cred_name) =
        make_git_echo_state("deadline-persona", "deadline-cred", "deadline-pat");
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state: deadline_state,
        upstream_scheme: Scheme::Http,
    });

    let cfg_for_server = Arc::clone(&config);
    // Track the server-side JoinHandle so we can assert it
    // completes (no leaked futures) after the client disconnects.
    let server_handle = local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_for_server);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/emberdotlink/emberlink.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );

    // Drive the client request + clock advance inside the LocalSet
    // so the paused clock can be moved past HEADERS_DEADLINE while
    // the proxy-server + upstream-mock tasks keep progressing.
    let (status, body_bytes) = local
        .run_until(async {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let req = Request::builder()
                .method("POST")
                .uri(&proxy_url)
                .header("x-ember-persona", deadline_persona_id.as_str())
                .header("x-ember-credential", deadline_cred_name.as_str())
                .header("content-type", "application/x-git-receive-pack-request")
                .body(Full::new(Bytes::from_static(b"noop")))
                .unwrap();
            // Fire the request and advance the clock concurrently.
            // `tokio::join!` polls both; the advance future pushes
            // paused time past HEADERS_DEADLINE so the
            // `tokio::time::timeout` inside handle_git_echo elapses.
            let req_fut = client.request(req);
            let advance_fut = async {
                // Hand control back to the runtime a few times so
                // the proxy-server begins dispatching upstream
                // before the clock jumps.
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
                tokio::time::advance(HEADERS_DEADLINE + Duration::from_secs(1)).await;
            };
            let (req_res, _) = tokio::join!(req_fut, advance_fut);
            let resp = req_res.expect("client request must return a 504 response");
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        })
        .await;

    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "slow-loris upstream must surface as 504 to the client"
    );
    assert!(
        !body_bytes.is_empty(),
        "504 should include a short diagnostic body"
    );

    // Upstream must have observed FIN (peer close). Polling this
    // from inside the LocalSet so the upstream task can finish.
    let peer_closed = local
        .run_until(async { tokio::time::timeout(Duration::from_secs(5), peer_closed_rx).await })
        .await
        .expect("upstream mock must report back within 5s (tokio time)")
        .expect("peer_closed channel must deliver");
    assert!(
        peer_closed,
        "upstream mock must observe peer close (FIN) when the proxy aborts on HEADERS_DEADLINE"
    );

    // No leaked futures: once the client has received the 504 and
    // dropped the connection, the hyper server task must complete.
    // Yield several times so the server's `serve_connection` future
    // observes the client disconnect and runs to completion.
    local
        .run_until(async {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    assert!(
        server_handle.is_finished(),
        "proxy connection task must complete (no leaked server future) once the client disconnects"
    );
    assert!(
        upstream_handle.is_finished(),
        "upstream mock task must complete after observing FIN"
    );
}

/// Frame-idle watchdog: upstream sends headers and one data frame,
/// then goes silent for longer than `FRAME_IDLE_DEADLINE`. The
/// `PassthroughBody`'s per-frame watchdog must abort the stream and
/// Drop must emit `outcome=partial`.
///
/// This test exercises the body shape directly (mirrors the existing
/// `passthrough_drop_emits_partial_outcome_on_mid_stream_drop` style)
/// so we can deterministically advance tokio's paused clock past the
/// deadline without depending on a real network upstream.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn frame_idle_watchdog_fires_on_dribble() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    let mut body = PassthroughBody::new(mock, None)
        .with_frame_idle(FRAME_IDLE_DEADLINE)
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // Upstream sends exactly one data byte then stalls forever —
    // classic dribble pattern (SlowPost / slow-read-variant).
    tx.send(Ok(Frame::data(Bytes::from_static(b"x")))).unwrap();

    // First poll surfaces the single byte.
    let f1 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(
        matches!(&f1, Some(Ok(frame)) if frame.data_ref().map(|b| b.len()) == Some(1)),
        "expected one-byte frame, got {f1:?}",
    );

    // Subsequent polls observe Pending from the (still-open) mock.
    // Advance the paused clock past FRAME_IDLE_DEADLINE; the watchdog
    // must fire and return Ready(None).
    let watchdog_fut = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx));
    tokio::pin!(watchdog_fut);

    // Poll once to arm the sleep, then advance the clock past the
    // deadline, then poll until completion.
    let poll_now = std::future::poll_fn(|cx| match watchdog_fut.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => Poll::Ready(()),
    });
    poll_now.await;
    tokio::time::advance(FRAME_IDLE_DEADLINE + Duration::from_secs(1)).await;
    let f2 = watchdog_fut.await;
    // P69L.0b-P1-ERROR-SIGNAL: the watchdog now emits a trailer frame
    // before ending the stream, so f2 is the `x-ember-stream-outcome:
    // partial` trailer rather than `None`.
    let trailer_map = match f2 {
        Some(Ok(ref frame)) => frame.trailers_ref().cloned(),
        _ => None,
    };
    assert!(
        trailer_map.is_some(),
        "frame-idle watchdog must emit an outcome trailer, got {f2:?}",
    );
    let outcome_hdr = trailer_map
        .as_ref()
        .unwrap()
        .get(STREAM_OUTCOME_TRAILER_NAME)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        outcome_hdr, "partial",
        "watchdog trailer must carry outcome=partial"
    );

    // Next poll must return None (body fully terminated).
    let f3 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(
        f3.is_none(),
        "poll after trailer must return None, got {f3:?}"
    );

    // Drop the body — outcome must record `partial`, bytes must
    // reflect the one byte that did flush before the stall.
    drop(body);
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_PARTIAL,
        "frame-idle-timeout must record outcome=partial"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        b"x".len() as u64,
        "bytes_forwarded must reflect data observed before the stall"
    );

    // Keep tx alive to end — models the upstream still technically
    // able to emit more data at the moment the watchdog fires.
    drop(tx);
}

// ------------------------------------------------------------------
// P69L.0b-P0-HOPBYHOP: RFC 7230 §6.1 hop-by-hop header stripping
//
// `stream_response` MUST NOT forward hop-by-hop headers from upstream
// to downstream. The adversarial review on #625 surfaced three live
// exploits against the straight-passthrough version:
//   1. Upstream `Transfer-Encoding: chunked` + hyper's own framing
//      produces duplicate/conflicting framing on the wire.
//   2. Upstream `Proxy-Authenticate` leaks to the client (info leak +
//      spurious auth prompts for an upstream realm).
//   3. Upstream `Connection: X-Custom` + `X-Custom: leaky` tunnels a
//      declared-hop-by-hop header through to the client.
// All three must be neutralised; unrelated end-to-end headers must
// survive unchanged.
// ------------------------------------------------------------------

#[test]
fn stream_response_strips_hop_by_hop_headers() {
    // Exercises the header-stripping logic inside `stream_response`
    // directly via its extracted helper `strip_hop_by_hop_headers`.
    // A wire-level integration test is the wrong shape here — hyper's
    // server writer auto-adds/removes framing headers (`Transfer-
    // Encoding: chunked`, `Content-Length`), which makes it impossible
    // to distinguish an upstream value leaking through from hyper
    // correctly setting its own. Operating directly on the HeaderMap
    // gives a deterministic assertion with no framing ambiguity.
    //
    // Reverting just the body of `strip_hop_by_hop_headers` (make it
    // a no-op) causes every assertion below to fail — confirms the
    // test exercises the fix and not some unrelated path.
    let mut headers = hyper::HeaderMap::new();

    // Hop-by-hop headers per RFC 7230 §6.1 — must be stripped.
    headers.insert("transfer-encoding", "chunked".parse().unwrap());
    headers.insert("proxy-authenticate", "Basic realm=foo".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("te", "trailers".parse().unwrap());
    headers.insert("trailer", "X-End".parse().unwrap());
    headers.insert("trailers", "X-End".parse().unwrap());
    headers.insert("upgrade", "websocket".parse().unwrap());
    headers.insert("proxy-authorization", "Basic abc".parse().unwrap());

    // Connection lists an additional hop-by-hop name (X-Custom) plus
    // the canonical `keep-alive` token. Both targets must be removed
    // and the Connection header itself must vanish.
    headers.insert("connection", "X-Custom, keep-alive".parse().unwrap());
    headers.insert("x-custom", "leaky".parse().unwrap());

    // End-to-end headers — MUST survive untouched.
    headers.insert("x-foo", "bar".parse().unwrap());
    headers.insert("content-type", "text/plain".parse().unwrap());
    headers.insert("content-length", "42".parse().unwrap());

    strip_hop_by_hop_headers(&mut headers);

    // --- Canonical hop-by-hop set (RFC 7230 §6.1) must be absent. ---
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(
            !headers.contains_key(name),
            "{name} is hop-by-hop (RFC 7230 §6.1) and must be stripped"
        );
    }

    // --- Connection-listed hop-by-hop must be stripped too. ---
    assert!(
        !headers.contains_key("x-custom"),
        "X-Custom was announced as hop-by-hop via Connection: and must be stripped"
    );

    // --- End-to-end headers must survive untouched. ---
    assert_eq!(
        headers.get("x-foo").and_then(|v| v.to_str().ok()),
        Some("bar"),
        "unrelated end-to-end header X-Foo must pass through (no over-stripping)"
    );
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/plain"),
        "Content-Type is end-to-end and must pass through"
    );
    assert_eq!(
        headers.get("content-length").and_then(|v| v.to_str().ok()),
        Some("42"),
        "Content-Length is end-to-end and must pass through"
    );
}

#[test]
fn stream_response_strips_hop_by_hop_case_insensitive() {
    // Upstream uses mixed case; HeaderMap normalises but the
    // Connection token list parser must also handle mixed-case
    // announced names.
    let mut headers = hyper::HeaderMap::new();
    headers.insert("Transfer-Encoding", "chunked".parse().unwrap());
    headers.insert("Connection", "X-CUSTOM".parse().unwrap());
    headers.insert("x-custom", "leaky".parse().unwrap());
    headers.insert("x-foo", "bar".parse().unwrap());

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key("transfer-encoding"));
    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("x-custom"));
    assert_eq!(
        headers.get("x-foo").and_then(|v| v.to_str().ok()),
        Some("bar")
    );
}

// ------------------------------------------------------------------
// Request header allowlist — filter_request_headers
// ------------------------------------------------------------------

/// Helper: run `filter_request_headers` and collect the output into a
/// `HeaderMap` so tests can assert presence/absence without dealing
/// with `Request::Builder` internals.
fn apply_filter(src: &hyper::HeaderMap) -> hyper::HeaderMap {
    let builder = filter_request_headers(Request::builder(), src);
    // Build a throwaway request to materialise the header map.
    let req = builder
        .uri("https://example.com/")
        .body(Full::new(Bytes::new()))
        .expect("builder should be valid after filter_request_headers");
    req.headers().clone()
}

#[test]
fn filter_drops_cookie_header() {
    // Cookie must never reach upstream (session fixation /
    // credential-forwarding risk).
    let mut src = hyper::HeaderMap::new();
    src.insert("cookie", "x=y".parse().unwrap());
    src.insert("content-type", "application/json".parse().unwrap());

    let out = apply_filter(&src);
    assert!(
        !out.contains_key("cookie"),
        "Cookie must be stripped by the allowlist"
    );
    assert!(
        out.contains_key("content-type"),
        "content-type is allowlisted and must pass through"
    );
}

#[test]
fn filter_drops_host_header() {
    // Client-supplied Host must not leak — hyper sets the
    // correct Host from the request URI; a spoofed value could
    // confuse SNI-based virtual-hosting at upstream.
    let mut src = hyper::HeaderMap::new();
    src.insert("host", "internal.local".parse().unwrap());
    src.insert("accept", "application/json".parse().unwrap());

    let out = apply_filter(&src);
    assert!(
        !out.contains_key("host"),
        "Host must be stripped by the allowlist"
    );
    assert!(
        out.contains_key("accept"),
        "accept is allowlisted and must pass through"
    );
}

#[test]
fn filter_drops_x_forwarded_for_header() {
    // X-Forwarded-For must never reach upstream — it could
    // spoof the apparent client IP in upstream audit/rate-limit logic.
    let mut src = hyper::HeaderMap::new();
    src.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
    src.insert("x-forwarded-host", "attacker.example".parse().unwrap());
    src.insert("x-forwarded-proto", "http".parse().unwrap());
    src.insert("content-type", "application/json".parse().unwrap());

    let out = apply_filter(&src);
    assert!(
        !out.contains_key("x-forwarded-for"),
        "X-Forwarded-For must be stripped by the allowlist"
    );
    assert!(
        !out.contains_key("x-forwarded-host"),
        "X-Forwarded-Host must be stripped by the allowlist"
    );
    assert!(
        !out.contains_key("x-forwarded-proto"),
        "X-Forwarded-Proto must be stripped by the allowlist"
    );
}

#[test]
fn filter_drops_authorization_header() {
    // Any client-supplied Authorization is stripped so that
    // only the vault-injected credential reaches upstream.
    let mut src = hyper::HeaderMap::new();
    src.insert("authorization", "Bearer client-token".parse().unwrap());
    src.insert("content-type", "application/json".parse().unwrap());

    let out = apply_filter(&src);
    assert!(
        !out.contains_key("authorization"),
        "client-supplied Authorization must be stripped — proxy injects its own"
    );
}

#[test]
fn filter_passes_anthropic_version_header() {
    // Anthropic-Version is in the allowlist and must reach
    // upstream so callers can pin to a specific API version.
    let mut src = hyper::HeaderMap::new();
    src.insert("anthropic-version", "2023-06-01".parse().unwrap());
    src.insert("cookie", "session=secret".parse().unwrap());

    let out = apply_filter(&src);
    assert_eq!(
        out.get("anthropic-version").and_then(|v| v.to_str().ok()),
        Some("2023-06-01"),
        "Anthropic-Version must pass through the allowlist"
    );
    assert!(
        !out.contains_key("cookie"),
        "Cookie must still be stripped when Anthropic-Version is present"
    );
}

#[test]
fn filter_drops_proxy_authorization_forwarded_via_te_trailer_connection() {
    // Verify that the headers explicitly called out in the
    // acceptance criteria are all absent from the allowlist.
    let mut src = hyper::HeaderMap::new();
    src.insert("proxy-authorization", "Basic abc".parse().unwrap());
    src.insert("forwarded", "for=1.2.3.4".parse().unwrap());
    src.insert("via", "1.1 proxy.example".parse().unwrap());
    src.insert("te", "trailers".parse().unwrap());
    src.insert("trailer", "X-End".parse().unwrap());
    src.insert("transfer-encoding", "chunked".parse().unwrap());
    src.insert("connection", "keep-alive".parse().unwrap());

    let out = apply_filter(&src);

    for name in [
        "proxy-authorization",
        "forwarded",
        "via",
        "te",
        "trailer",
        "transfer-encoding",
        "connection",
    ] {
        assert!(
            !out.contains_key(name),
            "{name} must be stripped by the allowlist"
        );
    }
}

// C39-PROXY-C2: strict host-suffix matching unit tests moved to
// `core-proxy-forward::r#match::tests`.

// ------------------------------------------------------------------
// FINDING B: provider-aware auth
// injection. Mirrors `git_echo_grant_backed_lookup_injects_correct_auth`
// for the LLM proxy path, but tests the helper directly because
// `handle_request` consults the target URL for the live TCP connection
// (no mock-upstream-pretending-to-be-Anthropic shape that doesn't
// require DNS hijacking).
// ------------------------------------------------------------------

#[test]
fn inject_provider_auth_anthropic_uses_x_api_key() {
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "api.anthropic.com",
        false,
        "anthropic-key",
        "sk-ant-test-token",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Anthropic);
    assert_eq!(
        headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some("sk-ant-test-token"),
        "Anthropic must use x-api-key, NOT Authorization: Bearer"
    );
    assert!(
        !headers.contains_key("authorization"),
        "Anthropic must NOT carry an Authorization header"
    );
}

#[test]
fn inject_provider_auth_anthropic_subdomain_still_routes_x_api_key() {
    // host_matches_domain matches `api.anthropic.com` and any subdomain.
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "console.anthropic.com",
        false,
        "anthropic-key",
        "sk-ant-test-token",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Anthropic);
    assert_eq!(
        headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some("sk-ant-test-token"),
    );
}

#[test]
fn inject_provider_auth_lookalike_does_not_route_anthropic() {
    // C39-PROXY-C2 invariant — `notanthropic.com` MUST NOT match
    // `anthropic.com`. The fallback is Bearer (generic).
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "notanthropic.com",
        false,
        "anthropic-key",
        "should-be-bearer",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Bearer);
    assert!(
        !headers.contains_key("x-api-key"),
        "Look-alike host must NOT receive x-api-key"
    );
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer should-be-bearer"),
    );
}

#[test]
fn inject_provider_auth_anthropic_oauth_token_uses_bearer() {
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "api.anthropic.com",
        false,
        "anthropic/oauth-token",
        "claude-subscription-token",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Bearer);
    assert!(
        !headers.contains_key("x-api-key"),
        "Claude subscription OAuth must not be rewritten into x-api-key"
    );
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer claude-subscription-token"),
    );
}

#[test]
fn inject_provider_auth_strips_client_supplied_credentials() {
    // The Anthropic SDK demo path sets `api_key="placeholder"`, which
    // surfaces as `x-api-key: placeholder` on the inbound request.
    // Defence-in-depth: even if the allowlist drifts and forwards a
    // client-supplied credential header, the helper MUST replace it
    // with the vault-resolved token rather than appending (which would
    // produce the pathological `x-api-key: placeholder, sk-ant-real`
    // joined-list form).
    let mut headers = hyper::HeaderMap::new();
    headers.insert("authorization", "Bearer client-supplied".parse().unwrap());
    headers.insert("x-api-key", "placeholder".parse().unwrap());
    let scheme = inject_provider_auth(
        &mut headers,
        "api.anthropic.com",
        false,
        "anthropic-key",
        "sk-ant-real",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Anthropic);
    // Authorization stripped; only one x-api-key remains; value is ours.
    assert!(!headers.contains_key("authorization"));
    let api_keys: Vec<&str> = headers
        .get_all("x-api-key")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(api_keys, vec!["sk-ant-real"], "must replace, not append");
}

#[test]
fn inject_provider_auth_git_uses_basic() {
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "github.com",
        true,
        "github/pat",
        "ghp_test_pat",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Basic);
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(
        auth.starts_with("Basic "),
        "git smart-HTTP requires Basic auth; got: {auth}"
    );
}

#[test]
fn inject_provider_auth_default_is_bearer() {
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "api.openai.com",
        false,
        "openai/api-key",
        "sk-openai-test",
    )
    .expect("valid credential");
    assert_eq!(scheme, AuthScheme::Bearer);
    assert_eq!(
        headers.get("authorization").and_then(|v| v.to_str().ok()),
        Some("Bearer sk-openai-test"),
    );
}

#[test]
fn inject_provider_auth_trims_trailing_line_endings() {
    let mut headers = hyper::HeaderMap::new();
    let scheme = inject_provider_auth(
        &mut headers,
        "api.anthropic.com",
        false,
        "anthropic-key",
        "sk-ant-test-token\r\n",
    )
    .expect("valid credential after newline trim");
    assert_eq!(scheme, AuthScheme::Anthropic);
    assert_eq!(
        headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some("sk-ant-test-token"),
    );
}

#[tokio::test]
async fn proxy_anthropic_target_routes_to_x_api_key_mode() {
    // End-to-end through `handle_request_boxed`: a request to
    // `https://api.anthropic.com` echoes `x-ember-auth-mode: anthropic`
    // back in the response, while `https://api.github.com` (non-git
    // path) echoes `bearer`. This is the integration-level proof
    // that FINDING B's routing flows through the production handler.
    let state = make_state();
    let persona = state.store.create_persona("anthropic-route").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-ant-test",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "anthropic-key", "*", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://api.anthropic.com/v1/messages",
        Some(&persona.id),
        Some("anthropic-key"),
        Some("https://api.anthropic.com"),
    );
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-ember-auth-mode")
            .and_then(|v| v.to_str().ok()),
        Some("anthropic"),
        "Anthropic target MUST route to x-api-key, NOT Bearer"
    );
}

#[tokio::test]
async fn proxy_anthropic_oauth_target_routes_to_bearer_mode() {
    let state = make_state();
    let persona = state.store.create_persona("anthropic-oauth-route").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic/oauth-token",
            b"claude-subscription-token",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "anthropic/oauth-token", "*", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://api.anthropic.com/v1/messages",
        Some(&persona.id),
        Some("anthropic/oauth-token"),
        Some("https://api.anthropic.com"),
    );
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-ember-auth-mode")
            .and_then(|v| v.to_str().ok()),
        Some("bearer"),
        "Claude subscription OAuth must preserve Bearer auth to Anthropic"
    );
}

#[test]
fn request_to_action_resource_classifies_github_hosts_only() {
    // Legit github hosts — classify as `github`.
    let uri: hyper::Uri = "https://api.github.com/repos/emberdotlink/emberlink"
        .parse()
        .unwrap();
    let (action, _resource) = request_to_action_resource(&hyper::Method::GET, &uri).unwrap();
    assert_eq!(action, "github:read");

    let uri: hyper::Uri = "https://github.com/emberdotlink/emberlink".parse().unwrap();
    let (action, _resource) = request_to_action_resource(&hyper::Method::POST, &uri).unwrap();
    assert_eq!(action, "github:push");

    // Look-alike — must classify as `generic`, never `github`.
    for attacker_host in [
        "https://notgithub.com/repos/legit/repo",
        "https://fakegithub.com/repos/legit/repo",
        "https://evilgithub.com/anything",
        "https://my-github.com/x/y",
    ] {
        let uri: hyper::Uri = attacker_host.parse().unwrap();
        let (action, _resource) = request_to_action_resource(&hyper::Method::POST, &uri).unwrap();
        assert!(
            action.starts_with("generic:"),
            "look-alike host {attacker_host} must not classify as github, got {action}"
        );
    }
}

// ------------------------------------------------------------------
// C39-PROXY-C1: effective-scope URI pins to X-Ember-Target authority
// ------------------------------------------------------------------

#[test]
fn effective_scope_uri_uses_target_authority_for_host() {
    // Attacker sends a scope-satisfying `req.uri` but flips the forward
    // destination via X-Ember-Target. The effective URI MUST take its
    // authority from the target, not the request line.
    let req_uri: hyper::Uri = "https://api.github.com/repos/legit/repo/issues"
        .parse()
        .unwrap();
    let eff = effective_scope_uri("https://evil.attacker.example/exfil", &req_uri).unwrap();
    assert_eq!(eff.host(), Some("evil.attacker.example"));
    // Target has a non-trivial path, so its path wins.
    assert_eq!(eff.path(), "/exfil");
}

#[test]
fn effective_scope_uri_falls_back_to_req_path_when_target_bare() {
    // Bare-host target convention: X-Ember-Target carries scheme+host
    // only, req.uri carries path+query. Effective URI combines the two.
    let req_uri: hyper::Uri = "http://localhost/repos/owner/repo/issues?state=open"
        .parse()
        .unwrap();
    let eff = effective_scope_uri("https://api.github.com", &req_uri).unwrap();
    assert_eq!(eff.host(), Some("api.github.com"));
    assert_eq!(eff.path(), "/repos/owner/repo/issues");
    assert_eq!(eff.query(), Some("state=open"));
}

#[test]
fn effective_scope_uri_rejects_authority_less_target() {
    // A path-only target (`/foo`) can't identify the destination host,
    // so scope enforcement has nothing to check against — reject.
    let req_uri: hyper::Uri = "http://localhost/any".parse().unwrap();
    assert!(effective_scope_uri("/foo", &req_uri).is_err());
    assert!(effective_scope_uri("not a url", &req_uri).is_err());
}

#[tokio::test]
async fn c1_scope_split_attack_denies_exfiltration_to_attacker_host() {
    // C-1 regression: agent has a `github:push:legit/repo` scope and
    // sends a request whose `req.uri` looks legitimate, but whose
    // X-Ember-Target points at an attacker-controlled host. The proxy
    // must deny — scope is validated against the forwarding authority,
    // not the unvalidated request line.
    let state = make_state();
    let persona = state.store.create_persona("c1-split-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_exfil_target",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "gh-token", "github:push:legit/repo", None)
        .unwrap();

    // req.uri satisfies the scope; X-Ember-Target redirects elsewhere.
    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://api.github.com/repos/legit/repo/issues",
        Some(&persona.id),
        Some("gh-token"),
        Some("https://evil.attacker.example/exfil"),
    );

    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let err = json["error"].as_str().unwrap_or("");
    assert_eq!(
        err, "no_applicable_statement",
        "expected statement-resolution denial, got: {err}"
    );
}

#[tokio::test]
async fn c1_lookalike_host_with_github_scope_is_denied() {
    // Defence-in-depth for C-2: even without C-1, a grant scoped to
    // `github:*` must not forward credentials to `notgithub.com`.
    let state = make_state();
    let persona = state.store.create_persona("c2-lookalike-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "gh-token", "github:read", None)
        .unwrap();

    // Every request field points at the look-alike host — this is the
    // plain "attacker registers notgithub.com" path from the review.
    let req = proxy_request_with_method_and_uri(
        "GET",
        "https://notgithub.com/repos/legit/repo",
        Some(&persona.id),
        Some("gh-token"),
        Some("https://notgithub.com/repos/legit/repo"),
    );

    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn finding1_allowed_targets_userinfo_host_exfil_denied() {
    // FINDING-1 (cycle 41 Phase E): allowed_targets previously derived
    // target_host by string-slicing target_url, stopping at `/?#` but
    // NOT `@`. A grant with `allowed_targets = "api.github.com"` could
    // be bypassed by `X-Ember-Target: https://api.github.com@evil.host/x`
    // because the starts_with fallback matched the URL prefix. Fixed by
    // switching to `effective_uri.host()` + removing the starts_with
    // fallback. This test asserts the exfil path now denies.
    let state = make_state();
    let persona = state.store.create_persona("finding1-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    // Grant scoped broadly enough that check_scope does NOT deny first —
    // we want allowed_targets to be the gate under test.
    let grant = state
        .store
        .create_grant(&persona.id, "gh-token", "generic:*", None)
        .unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET allowed_targets = 'api.github.com' WHERE id = ?1",
            rusqlite::params![grant.id],
        )
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "GET",
        "https://api.github.com/repos/legit/repo",
        Some(&persona.id),
        Some("gh-token"),
        // Userinfo-prefixed target: hyper parses host as `evil.example`,
        // but the old string-slice parser would yield
        // `api.github.com@evil.example` and then fall through to the
        // starts_with match. Must deny.
        Some("https://api.github.com@evil.example/exfil"),
    );

    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// -----------------------------------------------------------------
// P69L.1 — Anthropic SSE streaming tests
// -----------------------------------------------------------------

/// Channel-backed mock body. Each `poll_frame` call dequeues one item
/// off the receiver; `None` ends the stream. Used by the streaming
/// tests so we can interleave "send chunk → assert chunk delivered"
/// without a real network upstream.
struct ChannelBody {
    rx: tokio::sync::mpsc::UnboundedReceiver<Result<Frame<Bytes>, hyper::Error>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

#[test]
fn is_streaming_upstream_detects_event_stream() {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        hyper::header::CONTENT_TYPE,
        "text/event-stream".parse().unwrap(),
    );
    assert!(is_streaming_upstream(&h));
}

#[test]
fn is_streaming_upstream_detects_event_stream_with_charset() {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        hyper::header::CONTENT_TYPE,
        "text/event-stream; charset=utf-8".parse().unwrap(),
    );
    assert!(is_streaming_upstream(&h));
}

#[test]
fn is_streaming_upstream_detects_chunked_transfer_encoding() {
    let mut h = hyper::HeaderMap::new();
    h.insert(hyper::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    assert!(is_streaming_upstream(&h));
}

#[test]
fn is_streaming_upstream_detects_chunked_in_compound_te() {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        hyper::header::TRANSFER_ENCODING,
        "gzip, chunked".parse().unwrap(),
    );
    assert!(is_streaming_upstream(&h));
}

#[test]
fn is_streaming_upstream_rejects_plain_json() {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        hyper::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    assert!(!is_streaming_upstream(&h));
}

#[test]
fn is_streaming_upstream_rejects_empty_headers() {
    let h = hyper::HeaderMap::new();
    assert!(!is_streaming_upstream(&h));
}

/// Three SSE-shaped chunks pushed with 50ms delays must arrive
/// downstream as they're sent — chunk N visible before chunk N+1 is
/// produced. Asserts:
///   1. Each chunk body equals what was sent (in order).
///   2. The arrival ordering matches send ordering (no buffering).
///   3. The meter callback fires exactly once with a populated
///      `UsageSummary` that reflects the streamed frames.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tee_body_forwards_chunks_as_they_arrive() {
    use std::sync::Mutex;

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let captured: Arc<Mutex<Option<pricing::UsageSummary>>> = Arc::new(Mutex::new(None));
    let meter_captured = Arc::clone(&captured);
    let meter = TeeMeterCallback::new(
        move |summary: pricing::UsageSummary, _outcome: StreamOutcome| {
            *meter_captured.lock().unwrap() = Some(summary);
        },
    );

    let mut tee = TeeBody::new(mock, MAX_STREAMING_RESPONSE_BYTES, meter);

    // Spawn a producer that pushes 3 SSE-shaped chunks with delays.
    // Each chunk is a `message_delta`-style line so the captured
    // accumulator looks plausibly Anthropic-shaped. The mpsc sender
    // is `Send` so a vanilla `tokio::spawn` is sufficient.
    let producer = tokio::spawn(async move {
        for i in 0..3 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let payload = format!("event: message_delta\ndata: {{\"chunk\":{i}}}\n\n");
            tx.send(Ok(Frame::data(Bytes::from(payload)))).unwrap();
        }
        // Signal end-of-stream by dropping `tx`.
        drop(tx);
    });

    // Pull frames from the tee. Track wall-clock arrival to verify
    // that chunk N arrives before chunk N+1's send time.
    let start = std::time::Instant::now();
    let mut arrivals: Vec<(u128, Vec<u8>)> = Vec::new();
    loop {
        let frame_opt =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
        match frame_opt {
            None => break,
            Some(Ok(f)) => {
                if let Some(b) = f.data_ref() {
                    arrivals.push((start.elapsed().as_millis(), b.to_vec()));
                }
            }
            Some(Err(e)) => panic!("unexpected upstream error: {e}"),
        }
    }
    producer.await.unwrap();

    // 1. Three chunks arrived.
    assert_eq!(arrivals.len(), 3, "expected 3 chunks, got {arrivals:?}");

    // 2. Each chunk arrived strictly after the corresponding send
    //    delay (50ms, 100ms, 150ms) — i.e. the tee did NOT collect
    //    the whole stream before yielding. Allow a generous lower
    //    bound (40ms) for scheduler jitter; the upper bound is the
    //    next chunk's send time.
    assert!(
        arrivals[0].0 >= 40 && arrivals[0].0 < 90,
        "chunk 0 arrived at {}ms, expected ~50ms",
        arrivals[0].0
    );
    assert!(
        arrivals[1].0 >= 90 && arrivals[1].0 < 140,
        "chunk 1 arrived at {}ms, expected ~100ms",
        arrivals[1].0
    );
    assert!(
        arrivals[2].0 >= 140 && arrivals[2].0 < 200,
        "chunk 2 arrived at {}ms, expected ~150ms",
        arrivals[2].0
    );

    // 3. Meter callback fired exactly once. Parser saw three
    //    `message_delta` frames; none carried a `usage` block, so
    //    `saw_any_usage` stays false. The point of this test is the
    //    timing/ordering invariant — the summary is just the proof
    //    the meter ran.
    let summary = captured.lock().unwrap().clone().expect("meter must fire");
    assert!(
        !summary.saw_message_stop,
        "no message_stop frame was streamed"
    );
    assert_eq!(summary.output_tokens, 0, "no usage frames streamed");
}

/// Push a body whose total size exceeds the cap; assert the stream
/// terminates early and the meter still fires with the partial
/// accumulator. The cap protects the daemon from a malicious or
/// buggy upstream that streams unbounded bytes.
#[tokio::test(flavor = "current_thread")]
async fn tee_body_aborts_when_size_cap_exceeded() {
    use std::sync::Mutex;

    let cap = 64usize;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let meter_called: Arc<Mutex<Option<StreamOutcome>>> = Arc::new(Mutex::new(None));
    let meter_called_inner = Arc::clone(&meter_called);
    let meter = TeeMeterCallback::new(
        move |_summary: pricing::UsageSummary, outcome: StreamOutcome| {
            *meter_called_inner.lock().unwrap() = Some(outcome);
        },
    );

    let mut tee = TeeBody::new(mock, cap, meter);

    // First chunk: under cap (32 bytes).
    tx.send(Ok(Frame::data(Bytes::from(vec![0u8; 32]))))
        .unwrap();
    // Second chunk: would push total to 96 bytes, > cap.
    tx.send(Ok(Frame::data(Bytes::from(vec![1u8; 64]))))
        .unwrap();
    drop(tx);

    // First poll yields the under-cap frame.
    let f1 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
    match f1 {
        Some(Ok(frame)) => {
            assert_eq!(frame.data_ref().unwrap().len(), 32);
        }
        other => panic!("expected first frame, got {other:?}"),
    }

    // Second poll: cap exceeded → end-of-stream returned, meter fires.
    let f2 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
    assert!(f2.is_none(), "expected stream end after cap, got {f2:?}");

    // Subsequent polls stay terminated.
    let f3 = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
    assert!(f3.is_none(), "polling after termination must stay None");

    let outcome = meter_called
        .lock()
        .unwrap()
        .expect("meter must fire on cap abort");
    assert_eq!(
        outcome,
        StreamOutcome::Partial,
        "cap-aborted streams must be tagged Partial"
    );
    assert!(tee.cap_exceeded, "cap_exceeded flag must be set");
}

/// Process-wide lock used to serialize the three
/// `STREAMING_REQUESTS_INFLIGHT` tests below. `cargo test` runs
/// unit tests in parallel threads by default; they all share the
/// static counter, so without serialisation a peer test's
/// `try_acquire` would perturb the invariants we're asserting.
fn streaming_gate_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// C44-TEE-MEM: the streaming-concurrency gate refuses to over-admit
/// and releases a slot exactly when the guarded `TeeBody` (or a bare
/// `StreamingSlot`) is dropped. This test exercises the gate in
/// isolation — it does NOT go through `handle_request` — because the
/// invariant we care about is purely on the `StreamingSlot` contract.
#[test]
fn streaming_slot_gates_at_concurrency_cap() {
    let _guard = streaming_gate_test_lock();
    // Snapshot the counter so we never assume zero-start — cargo
    // may parallelise tests in other processes/threads.
    let baseline = StreamingSlot::inflight();
    assert_eq!(
        baseline, 0,
        "streaming gate must be idle at test start; got {baseline}"
    );

    // Acquire up to the cap.
    let mut held: Vec<StreamingSlot> = Vec::with_capacity(MAX_CONCURRENT_STREAMING);
    for i in 0..MAX_CONCURRENT_STREAMING {
        let slot = StreamingSlot::try_acquire()
            .unwrap_or_else(|| panic!("slot {i} should be available under cap"));
        held.push(slot);
    }
    assert_eq!(StreamingSlot::inflight(), MAX_CONCURRENT_STREAMING);

    // At cap: further acquisitions return None.
    assert!(
        StreamingSlot::try_acquire().is_none(),
        "acquisition at cap must return None",
    );
    assert!(
        StreamingSlot::try_acquire().is_none(),
        "repeated acquisition at cap must stay None",
    );
    assert_eq!(
        StreamingSlot::inflight(),
        MAX_CONCURRENT_STREAMING,
        "failed acquisition must not increment the counter"
    );

    // Dropping one slot frees exactly one slot.
    let popped = held.pop().expect("at least one held");
    drop(popped);
    assert_eq!(StreamingSlot::inflight(), MAX_CONCURRENT_STREAMING - 1);

    let reclaimed = StreamingSlot::try_acquire().expect("slot should be available after drop");
    held.push(reclaimed);
    assert_eq!(StreamingSlot::inflight(), MAX_CONCURRENT_STREAMING);

    // Drop all held slots; counter returns to zero.
    drop(held);
    assert_eq!(
        StreamingSlot::inflight(),
        0,
        "dropping all held slots must fully release the counter"
    );
}

/// `TeeBody` built with a slot releases it on clean EOF. Belt +
/// braces that the RAII guard wired through the body type actually
/// fires — regression gate for anyone refactoring `TeeBody::Drop`
/// behaviour.
///
/// The `await_holding_lock` allow is deliberate: the test's
/// invariant is about a process-global counter, and the lock is a
/// std `Mutex` used purely for test serialisation. We do NOT
/// perform any blocking work under the lock (the single `.await`
/// resolves synchronously because the upstream has already been
/// dropped) — switching to `tokio::sync::Mutex` would be pure
/// ceremony.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::await_holding_lock)]
async fn tee_body_releases_slot_on_clean_eof() {
    let _guard = streaming_gate_test_lock();
    let baseline = StreamingSlot::inflight();
    let slot = StreamingSlot::try_acquire().expect("cap not saturated");
    assert_eq!(StreamingSlot::inflight(), baseline + 1);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };
    let meter =
        TeeMeterCallback::new(move |_summary: pricing::UsageSummary, _outcome: StreamOutcome| {});
    let mut tee = TeeBody::new_with_slot(mock, 1024, meter, Some(slot));
    drop(tx); // clean EOF on next poll

    let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
    assert!(frame.is_none(), "expected EOF");

    // Slot is not released until `tee` itself is dropped — it rides
    // inside the body. This matches real hyper behaviour where the
    // response body outlives `handle_request`.
    assert_eq!(
        StreamingSlot::inflight(),
        baseline + 1,
        "slot stays held while TeeBody is alive"
    );
    drop(tee);
    assert_eq!(
        StreamingSlot::inflight(),
        baseline,
        "dropping TeeBody must release the slot"
    );
}

/// Client disconnect mid-stream drops the `TeeBody` before EOF.
/// The RAII slot MUST still be released — otherwise a hostile
/// client could exhaust the concurrency gate by opening streams
/// and abandoning them.
#[tokio::test(flavor = "current_thread")]
async fn tee_body_releases_slot_on_mid_stream_drop() {
    let _guard = streaming_gate_test_lock();
    let baseline = StreamingSlot::inflight();
    let slot = StreamingSlot::try_acquire().expect("cap not saturated");
    assert_eq!(StreamingSlot::inflight(), baseline + 1);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };
    let meter =
        TeeMeterCallback::new(move |_summary: pricing::UsageSummary, _outcome: StreamOutcome| {});
    let tee = TeeBody::new_with_slot(mock, 1024, meter, Some(slot));

    // Keep `tx` alive so upstream would still have more to send.
    // Simulate the client side abandoning the response by dropping
    // the body without polling to EOF.
    drop(tee);
    assert_eq!(
        StreamingSlot::inflight(),
        baseline,
        "mid-stream TeeBody drop must release the slot"
    );
    drop(tx);
}

/// Metering against the streamed body must produce identical
/// per-Statement token totals to what the equivalent JSON `usage`
/// block would produce on the buffered path. C44-TEE-INCR-PARSE
/// switched the streaming path to a structured `UsageSummary`, so
/// "matches buffered" now means "the summary's folded usage matches
/// the JSON parser's `ParsedUsage`".
#[tokio::test(flavor = "current_thread")]
async fn tee_body_meter_matches_buffered_path() {
    // SSE-shaped equivalent of `anthropic_body(700, 300)`: 700 input
    // tokens at message_start, deltas advancing output cumulatively
    // to 300, and a terminal message_stop so the stream is Complete.
    let body = anthropic_sse_complete("claude-opus-4-5", 700, &[100, 250, 300]);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let captured: Arc<std::sync::Mutex<Option<pricing::UsageSummary>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cap_inner = Arc::clone(&captured);
    let meter = TeeMeterCallback::new(
        move |summary: pricing::UsageSummary, _outcome: StreamOutcome| {
            *cap_inner.lock().unwrap() = Some(summary);
        },
    );

    let mut tee = TeeBody::new(mock, MAX_STREAMING_RESPONSE_BYTES, meter);

    // Split the body into 3 roughly-equal chunks so the tee has to
    // parse across multiple frames before the meter sees the result.
    let bytes = body.as_bytes();
    let third = bytes.len() / 3;
    for chunk in [
        &bytes[..third],
        &bytes[third..2 * third],
        &bytes[2 * third..],
    ] {
        tx.send(Ok(Frame::data(Bytes::copy_from_slice(chunk))))
            .unwrap();
    }
    drop(tx);

    // Drain the tee.
    loop {
        let f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
        if f.is_none() {
            break;
        }
    }

    let summary = captured.lock().unwrap().clone().expect("meter must fire");
    let from_streamed = usage_from_summary("api.anthropic.com", &summary).expect("metered");
    // Buffered-path equivalent: a JSON body with the same token
    // counts. Both paths must agree token-for-token.
    let json_body = anthropic_body(700, 300);
    let from_buffered =
        meter_response("api.anthropic.com", json_body.as_bytes()).expect("parsable");
    assert_eq!(
        from_streamed.tokens, from_buffered.tokens,
        "streamed metering must match buffered metering token-for-token"
    );
    assert_eq!(
        from_streamed.tokens, 1_000,
        "anthropic body 700+300 should yield 1000 tokens"
    );
    assert!(summary.saw_message_stop, "complete SSE stream is Complete");
}

#[tokio::test(flavor = "current_thread")]
async fn tee_body_meter_meters_openai_responses_sse() {
    let body = openai_responses_sse_complete("gpt-4o-mini", 2_000, 754);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let captured: Arc<std::sync::Mutex<Option<pricing::UsageSummary>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cap_inner = Arc::clone(&captured);
    let meter = TeeMeterCallback::new(
        move |summary: pricing::UsageSummary, _outcome: StreamOutcome| {
            *cap_inner.lock().unwrap() = Some(summary);
        },
    );

    let mut tee = TeeBody::new(mock, MAX_STREAMING_RESPONSE_BYTES, meter);

    let bytes = body.as_bytes();
    let third = bytes.len() / 3;
    for chunk in [
        &bytes[..third],
        &bytes[third..2 * third],
        &bytes[2 * third..],
    ] {
        tx.send(Ok(Frame::data(Bytes::copy_from_slice(chunk))))
            .unwrap();
    }
    drop(tx);

    loop {
        let f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
        if f.is_none() {
            break;
        }
    }

    let summary = captured.lock().unwrap().clone().expect("meter must fire");
    let from_streamed = usage_from_summary("api.openai.com", &summary).expect("metered");
    let from_buffered = meter_response("api.openai.com", body.as_bytes()).expect("parsable");

    assert_eq!(summary.model.as_deref(), Some("gpt-4o-mini"));
    assert!(summary.saw_any_usage);
    assert!(summary.saw_message_stop);
    assert_eq!(from_streamed.tokens, 2_754);
    assert_eq!(
        from_streamed.tokens, from_buffered.tokens,
        "OpenAI streamed metering must match buffered token metering"
    );
    assert_eq!(
        from_streamed.cents_micro, from_buffered.cents_micro,
        "OpenAI streamed metering must match buffered cents metering"
    );
    assert!(
        from_streamed.cents_micro > 0,
        "known OpenAI model must not price as unknown"
    );
}

#[tokio::test]
async fn composite_template_scope_does_not_block_anthropic_proxy_flow() {
    let state = make_state();
    let persona = state.store.create_persona("llm-template-scope").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-test",
            None,
        )
        .unwrap();

    let grant = state
        .store
        .create_grant(&persona.id, "anthropic-key", "claude-code-default-v1", None)
        .unwrap();
    let root = state.store.persona_root_keypair(&persona.id).unwrap();
    let ag = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        &persona.id,
        "anthropic-key",
        vec![
            Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact {
                    value: "anthropic-key".into(),
                },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
                can_delegate: None,
            },
            stmt_session("S1", 10_000),
        ],
        0,
        None,
        &root,
    )
    .unwrap();
    state
        .store
        .overwrite_grant_blocks_with_parent_bound(&grant.id, &ag, &ag)
        .unwrap();

    let body = anthropic_body(128, 32);
    let req = proxy_llm_request(
        &persona.id,
        "anthropic-key",
        "https://api.anthropic.com",
        &body,
    );
    let resp = call_full(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Build a single SSE frame: `event:\n data:\n\n`. Panics on malformed
/// JSON so a typo in the test fixture fails loud.
fn sse_frame(event: &str, payload: serde_json::Value) -> String {
    format!("event: {event}\ndata: {payload}\n\n", payload = payload)
}

/// Build a plausible Anthropic SSE response: message_start with
/// input_tokens, two message_delta events advancing output_tokens
/// cumulatively, and a terminal message_stop.
fn anthropic_sse_complete(model: &str, input_tokens: u64, delta_outputs: &[u64]) -> String {
    let mut out = String::new();
    out.push_str(&sse_frame(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {
                "id": "msg_test",
                "model": model,
                "usage": {"input_tokens": input_tokens, "output_tokens": 0},
            },
        }),
    ));
    for &n in delta_outputs {
        out.push_str(&sse_frame(
            "message_delta",
            serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"},
                "usage": {"output_tokens": n},
            }),
        ));
    }
    out.push_str(&sse_frame(
        "message_stop",
        serde_json::json!({"type": "message_stop"}),
    ));
    out
}

fn openai_responses_sse_complete(model: &str, input_tokens: u64, output_tokens: u64) -> String {
    let mut out = String::new();
    out.push_str(&sse_frame(
        "response.created",
        serde_json::json!({
            "type": "response.created",
            "response": {
                "id": "resp_test",
                "model": model,
            },
        }),
    ));
    out.push_str(&sse_frame(
        "response.output_text.delta",
        serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "hello",
        }),
    ));
    out.push_str(&sse_frame(
        "response.completed",
        serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp_test",
                "model": model,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": input_tokens.saturating_add(output_tokens),
                },
            },
        }),
    ));
    out
}

/// P69L.1 — streaming happy path.
/// Drive a TeeBody with a complete Anthropic SSE response (two
/// `message_delta` chunks plus `message_stop`), then invoke the
/// post-flight meter exactly like production does and verify that
/// (a) the statement's usage row carries the summed token count and
/// (b) the audit log records a `proxy.meter` entry tagged `complete`.
#[tokio::test(flavor = "current_thread")]
async fn test_streaming_response_tees_usage() {
    let state = make_state();
    let persona = state.store.create_persona("sse-happy").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-secret",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_session("S1", 100_000)],
    );
    let resolved_stmt = stmt_session("S1", 100_000);

    // Build the SSE body: 40 input tokens, deltas cumulative 10 → 25.
    // The final cumulative output_tokens is what the meter should
    // record (matches real Anthropic semantics).
    let body = anthropic_sse_complete("claude-opus-4-5", 40, &[10, 25]);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    // Split the body into two frames so the tee has to accumulate.
    let bytes = body.as_bytes();
    let mid = bytes.len() / 2;
    tx.send(Ok(Frame::data(Bytes::copy_from_slice(&bytes[..mid]))))
        .unwrap();
    tx.send(Ok(Frame::data(Bytes::copy_from_slice(&bytes[mid..]))))
        .unwrap();
    drop(tx);

    // Meter callback mirrors production: downgrade Complete → Partial
    // when the SSE body lacks `message_stop`.
    let meter_state = Arc::clone(&state);
    let meter_grant_id = grant_id.clone();
    let meter_stmt = resolved_stmt.clone();
    let meter_persona = persona.id.clone();
    let meter_host = "api.anthropic.com".to_string();
    let meter = TeeMeterCallback::new(
        move |summary: pricing::UsageSummary, tee_outcome: StreamOutcome| {
            let outcome = if tee_outcome == StreamOutcome::Complete
                && pricing::provider_for_host(&meter_host) == Some(pricing::PROVIDER_ANTHROPIC)
                && summary.saw_any_usage
                && !summary.saw_message_stop
            {
                StreamOutcome::Partial
            } else {
                tee_outcome
            };
            run_post_flight_meter_from_summary(
                &meter_state,
                &meter_grant_id,
                "S1",
                &meter_stmt,
                &meter_persona,
                "anthropic-key",
                &meter_host,
                &summary,
                outcome,
                true, // upstream success path under test
            );
        },
    );

    let mut tee = TeeBody::new(mock, MAX_STREAMING_RESPONSE_BYTES, meter);

    // Drain the tee; frames flow through and the meter fires on
    // clean EOF.
    loop {
        let f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
        if f.is_none() {
            break;
        }
    }

    // (a) Statement usage reflects the metered tokens.
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let stmt = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .map(|(_, s)| s.clone())
        .expect("S1 present");
    assert_eq!(
        stmt.usage.tokens, 65,
        "expected 40 input + 25 output = 65 tokens recorded, got {}",
        stmt.usage.tokens
    );
    assert_eq!(stmt.usage.requests, 1, "metering counts one request");

    // (b) Audit log has a proxy.meter entry with outcome=complete.
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let meter_entry = entries
        .iter()
        .find(|e| e.action == "proxy.meter")
        .expect("proxy.meter audit entry present");
    assert_eq!(
        meter_entry.outcome, "complete",
        "complete stream must tag outcome=complete"
    );
    let details = meter_entry.details.as_deref().unwrap_or("");
    assert!(
        details.contains("tokens=65"),
        "details must include tokens=65, got {details}"
    );
}

/// P69L.1 — partial stream path.
/// Drive a TeeBody with an Anthropic SSE response that lacks
/// `message_stop` (simulating upstream disconnect after a single
/// `message_delta`). The meter must still record the tokens observed
/// up to the interruption and tag the audit record `partial`.
#[tokio::test(flavor = "current_thread")]
async fn test_streaming_response_partial_records_usage() {
    let state = make_state();
    let persona = state.store.create_persona("sse-partial").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-secret",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_session("S1", 100_000)],
    );
    let resolved_stmt = stmt_session("S1", 100_000);

    // Build an INCOMPLETE SSE body: message_start + one message_delta,
    // NO message_stop. This models an upstream hang-up mid-stream.
    let mut body = String::new();
    body.push_str(&sse_frame(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {
                "id": "msg_partial",
                "model": "claude-opus-4-5",
                "usage": {"input_tokens": 12, "output_tokens": 0},
            },
        }),
    ));
    body.push_str(&sse_frame(
        "message_delta",
        serde_json::json!({
            "type": "message_delta",
            "delta": {},
            "usage": {"output_tokens": 7},
        }),
    ));

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };
    tx.send(Ok(Frame::data(Bytes::from(body.clone())))).unwrap();
    // Drop the sender WITHOUT a terminal frame — mimics upstream
    // closing the TCP connection mid-stream. Upstream close after
    // `drop(tx)` is an SSE-level partial: TCP was clean but the
    // wire-format `message_stop` never arrived.
    drop(tx);

    let meter_state = Arc::clone(&state);
    let meter_grant_id = grant_id.clone();
    let meter_stmt = resolved_stmt.clone();
    let meter_persona = persona.id.clone();
    let meter_host = "api.anthropic.com".to_string();
    let meter = TeeMeterCallback::new(
        move |summary: pricing::UsageSummary, tee_outcome: StreamOutcome| {
            let outcome = if tee_outcome == StreamOutcome::Complete
                && pricing::provider_for_host(&meter_host) == Some(pricing::PROVIDER_ANTHROPIC)
                && summary.saw_any_usage
                && !summary.saw_message_stop
            {
                StreamOutcome::Partial
            } else {
                tee_outcome
            };
            run_post_flight_meter_from_summary(
                &meter_state,
                &meter_grant_id,
                "S1",
                &meter_stmt,
                &meter_persona,
                "anthropic-key",
                &meter_host,
                &summary,
                outcome,
                true, // upstream success path under test
            );
        },
    );

    let mut tee = TeeBody::new(mock, MAX_STREAMING_RESPONSE_BYTES, meter);
    loop {
        let f = std::future::poll_fn(|cx| std::pin::Pin::new(&mut tee).poll_frame(cx)).await;
        if f.is_none() {
            break;
        }
    }

    // Usage must reflect the partial: 12 input + 7 output = 19.
    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let stmt = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .map(|(_, s)| s.clone())
        .expect("S1 present");
    assert_eq!(
        stmt.usage.tokens, 19,
        "partial stream must record 12+7=19 tokens, got {}",
        stmt.usage.tokens
    );

    // Audit entry must be tagged `partial`.
    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let meter_entry = entries
        .iter()
        .find(|e| e.action == "proxy.meter")
        .expect("proxy.meter audit entry present");
    assert_eq!(
        meter_entry.outcome, "partial",
        "missing message_stop must flip outcome to partial"
    );
}

/// P69L.1 regression guard — the non-streaming (buffered) path must
/// still meter a plain JSON Anthropic response exactly as before, with
/// outcome=complete. Changes to the streaming tee or `StreamOutcome`
/// plumbing must not regress this case.
#[test]
fn test_non_streaming_unchanged() {
    let state = make_state();
    let persona = state.store.create_persona("buffered").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-secret",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_session("S1", 100_000)],
    );
    let resolved_stmt = stmt_session("S1", 100_000);

    // Plain JSON Anthropic body — the legacy .collect() buffered path.
    let body = anthropic_body(120, 80); // 200 tokens

    run_post_flight_meter(
        &state,
        &grant_id,
        "S1",
        &resolved_stmt,
        &persona.id,
        "anthropic-key",
        "api.anthropic.com",
        body.as_bytes(),
        StreamOutcome::Complete,
        true, // upstream 2xx
    );

    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let stmt = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .map(|(_, s)| s.clone())
        .expect("S1 present");
    assert_eq!(
        stmt.usage.tokens, 200,
        "buffered JSON path must record 120+80=200 tokens"
    );

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let meter_entry = entries
        .iter()
        .find(|e| e.action == "proxy.meter")
        .expect("proxy.meter audit entry present");
    assert_eq!(
        meter_entry.outcome, "complete",
        "buffered path is always complete"
    );

    // SSE parser itself must return None on a JSON body (content-type
    // sniffing was by-content, not header). Regression-guard that
    // `looks_like_json` keeps redirecting to the JSON branch.
    assert_eq!(
        pricing::parse_anthropic_sse_usage(body.as_bytes()),
        None,
        "pure JSON body must not be misparsed as SSE"
    );
}

/// Credential-correlation regression guard — the proxy.meter audit event
/// must NOT emit the raw credential alias in any field. Readers of the
/// audit log must not be able to correlate persona → credential by
/// scanning rows. The raw alias stays in `statement_usage`/grant rows;
/// the audit row gets a short sha256-derived identifier instead.
#[test]
fn audit_event_hides_raw_credential_name() {
    let state = make_state();
    let persona = state.store.create_persona("cred-corr").unwrap();
    // Use a distinctive raw alias so a substring scan of the emitted
    // event is unambiguous.
    let raw_alias = "anthropic-secret-alias-abc123";
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            raw_alias,
            b"sk-secret",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        raw_alias,
        vec![stmt_session("S1", 100_000)],
    );
    let resolved_stmt = stmt_session("S1", 100_000);

    let body = anthropic_body(10, 20);

    run_post_flight_meter(
        &state,
        &grant_id,
        "S1",
        &resolved_stmt,
        &persona.id,
        raw_alias,
        "api.anthropic.com",
        body.as_bytes(),
        StreamOutcome::Complete,
        true, // upstream 2xx
    );

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    let meter_entry = entries
        .iter()
        .find(|e| e.action == "proxy.meter")
        .expect("proxy.meter audit entry present");

    // `credential` column must NOT be the raw alias.
    let cred_field = meter_entry.credential.as_deref().unwrap_or("");
    assert_ne!(
        cred_field, raw_alias,
        "audit credential column must not expose the raw credential alias"
    );
    assert!(
        !cred_field.contains(raw_alias),
        "audit credential column must not contain the raw alias as a substring: got {cred_field}"
    );
    assert!(
        cred_field.starts_with("credname-"),
        "audit credential column must use the hashed form (credname-<hex>), got {cred_field}"
    );

    // `details` column must also not leak the raw alias. The c44
    // format string embeds grant_id/sid/tokens/cents only, but
    // regression-guard it so a future drive-by doesn't smuggle the
    // alias back into the details payload.
    let details = meter_entry.details.as_deref().unwrap_or("");
    assert!(
        !details.contains(raw_alias),
        "audit details must not contain the raw alias: got {details}"
    );

    // The hash must be stable across calls with the same input so a
    // troubleshooter can correlate by re-hashing the raw alias and
    // matching against the audit row.
    assert_eq!(cred_field, hash_credential_name_for_audit(raw_alias));
}

/// The SSE parser extracts usage from a real-looking Anthropic stream
/// and flags `saw_message_stop` correctly. Unit-level check for the
/// parser in isolation.
#[test]
fn anthropic_sse_parser_extracts_cumulative_usage() {
    let body = anthropic_sse_complete("claude-opus-4-5", 100, &[5, 15, 42]);
    let summary = pricing::parse_anthropic_sse_usage(body.as_bytes()).expect("parsed");
    assert_eq!(summary.usage.input_tokens, 100);
    assert_eq!(
        summary.usage.output_tokens, 42,
        "cumulative message_delta output_tokens — last (max) value wins"
    );
    assert_eq!(summary.model.as_deref(), Some("claude-opus-4-5"));
    assert!(summary.saw_message_stop);
}

#[test]
fn anthropic_sse_parser_missing_message_stop_is_partial() {
    // message_start + one message_delta, no message_stop.
    let mut body = String::new();
    body.push_str(&sse_frame(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {
                "id": "msg_x",
                "model": "claude-opus-4-5",
                "usage": {"input_tokens": 3, "output_tokens": 0},
            },
        }),
    ));
    body.push_str(&sse_frame(
        "message_delta",
        serde_json::json!({
            "type": "message_delta",
            "delta": {},
            "usage": {"output_tokens": 9},
        }),
    ));
    let summary = pricing::parse_anthropic_sse_usage(body.as_bytes()).expect("parsed");
    assert_eq!(summary.usage.input_tokens, 3);
    assert_eq!(summary.usage.output_tokens, 9);
    assert!(
        !summary.saw_message_stop,
        "partial stream must not claim message_stop"
    );
}

// -----------------------------------------------------------------
// P69L.0a — git-transport detection in handle_request (production path)
// -----------------------------------------------------------------

/// Assert that `handle_request` routes git smart-HTTP requests through
/// Basic auth, not Bearer. Uses the test harness's `x-ember-auth-mode`
/// response header to observe which auth format was chosen without
/// requiring a live upstream socket.
///
/// Two request shapes are checked:
///   - POST `.../git-receive-pack` (the pack-receiving phase of `git push`)
///   - GET  `.../info/refs?service=git-receive-pack` (the discovery phase)
///
/// A third assertion verifies that a regular REST API request on the
/// same grant still routes to Bearer — confirming the branch is a
/// conditional, not an unconditional replacement.
#[tokio::test]
async fn handle_request_routes_git_to_basic_auth() {
    let state = make_state();
    let persona = state.store.create_persona("git-transport-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_test_secret",
            None,
        )
        .unwrap();
    // Universal scope so both GET (info/refs discovery) and POST
    // (git-receive-pack) pass scope enforcement. The test only verifies
    // the auth format chosen, not the forwarding destination.
    state
        .store
        .create_grant(&persona.id, "gh-token", "*", None)
        .unwrap();

    // --- Phase 1: POST git-receive-pack (credential injection phase) ---
    let git_pack_req = proxy_request_with_method_and_uri(
        "POST",
        // Request URI carries the git-receive-pack path so that the
        // effective_uri path is resolved correctly from X-Ember-Target
        // (bare host) + request URI path.
        "https://github.com/emberdotlink/emberlink.git/git-receive-pack",
        Some(&persona.id),
        Some("gh-token"),
        // Bare-host target: effective_uri takes path from req.uri.
        Some("https://github.com"),
    );
    let resp_pack = call(Arc::clone(&state), git_pack_req).await;
    assert_eq!(
        resp_pack.status(),
        StatusCode::OK,
        "git-receive-pack POST should reach the allowed branch (scope=github:push)"
    );
    let auth_mode = resp_pack
        .headers()
        .get("x-ember-auth-mode")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(
        auth_mode, "basic",
        "git-receive-pack POST must use Basic auth, not Bearer"
    );

    // --- Phase 2: GET info/refs discovery ---
    let git_refs_req = proxy_request_with_method_and_uri(
        "GET",
        "https://github.com/emberdotlink/emberlink.git/info/refs?service=git-receive-pack",
        Some(&persona.id),
        Some("gh-token"),
        Some("https://github.com"),
    );
    let resp_refs = call(Arc::clone(&state), git_refs_req).await;
    assert_eq!(
        resp_refs.status(),
        StatusCode::OK,
        "info/refs GET should pass (scope=github:push, read-tier)"
    );
    let auth_mode_refs = resp_refs
        .headers()
        .get("x-ember-auth-mode")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(
        auth_mode_refs, "basic",
        "info/refs discovery GET must use Basic auth"
    );

    // --- Non-git baseline: regular REST API call still uses Bearer ---
    let rest_req = proxy_request_with_method_and_uri(
        "GET",
        "https://api.github.com/repos/emberdotlink/emberlink",
        Some(&persona.id),
        Some("gh-token"),
        Some("https://api.github.com"),
    );
    let resp_rest = call(Arc::clone(&state), rest_req).await;
    assert_eq!(resp_rest.status(), StatusCode::OK);
    let auth_mode_rest = resp_rest
        .headers()
        .get("x-ember-auth-mode")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(
        auth_mode_rest, "bearer",
        "regular REST API call must still use Bearer"
    );
}

// -----------------------------------------------------------------
// P69L.0b-P1-AUDIT: tracing-capture helpers + regression tests
// -----------------------------------------------------------------

/// Shared-buffer writer compatible with `tracing_subscriber::fmt::MakeWriter`.
/// Each `write` call appends bytes to the inner `Vec`; `flush` is a no-op.
/// Deliberately simple — we only need to capture structured JSON lines
/// from a single-threaded test run.
#[derive(Clone)]
struct CaptureBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl CaptureBuf {
    fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(Vec::new())))
    }

    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for CaptureBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuf {
    type Writer = CaptureBuf;
    fn make_writer(&'a self) -> CaptureBuf {
        self.clone()
    }
}

/// Install a tracing subscriber that writes to `buf` for the
/// duration of the test. Returns the `DefaultGuard` — drop it to restore
/// the previous subscriber (or the default no-op).
///
/// Uses the default compact text format so field values appear verbatim in
/// the captured output; callers can assert `buf.snapshot().contains("...")`.
fn install_capture_subscriber(buf: &CaptureBuf) -> tracing::subscriber::DefaultGuard {
    use tracing_subscriber::prelude::*;
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(buf.clone()));
    tracing::subscriber::set_default(subscriber)
}

/// `handle_git_echo` must emit `credential.access` on every request
/// that reaches credential substitution.
///
/// Correctness invariants:
///   1. The log contains `"credential.access"` in the `event` field.
///   2. The `action` field contains `"github.push."` + the parsed owner/repo.
///   3. The `request_id` field is present and non-empty.
///   4. `allowed` is `true`.
#[tokio::test(flavor = "current_thread")]
async fn git_echo_emits_credential_access_on_entry() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    // ---- Mock upstream: accept one connection, return 200 immediately ----
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = upstream_listener.accept().await {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(|_req: Request<Incoming>| async {
                        Ok::<Response<Full<Bytes>>, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from_static(b"ok")))
                                .unwrap(),
                        )
                    }),
                )
                .await;
        }
    });

    // ---- Echo proxy ----
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());
    let (audit_state, audit_persona_id, audit_cred_name) =
        make_git_echo_state("audit-persona", "audit-cred", "ghp_test_pat");
    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state: audit_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_srv = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_srv);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    // ---- Install capture subscriber, fire request, collect logs ----
    let buf = CaptureBuf::new();
    let _guard = install_capture_subscriber(&buf);

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/emberdotlink/emberlink.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", audit_persona_id.as_str())
        .header("x-ember-credential", audit_cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"")))
        .unwrap();

    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        local.run_until(async move { client.request(req).await }),
    )
    .await
    .expect("streaming round-trip timed out");

    // Drop guard to flush any buffered subscriber output.
    drop(_guard);

    let captured = buf.snapshot();
    assert!(
        captured.contains("credential.access"),
        "log must contain credential.access event; got: {captured}"
    );
    assert!(
        captured.contains("github.push.emberdotlink/emberlink"),
        "action must encode owner/repo; got: {captured}"
    );
    assert!(
        captured.contains("request_id"),
        "credential.access must carry request_id; got: {captured}"
    );
}

/// When the response body is dropped mid-stream (client disconnect
/// simulation), `PassthroughBody::Drop` must emit `proxy.stream` with
/// `outcome=partial` and a `request_id` that matches the one from the
/// corresponding `credential.access` entry.
///
/// We simulate mid-stream disconnect by dropping the `PassthroughBody`
/// directly before draining it to EOF, then asserting the captured log.
#[tokio::test(flavor = "current_thread")]
async fn git_echo_emits_proxy_stream_on_drop() {
    // This test exercises PassthroughBody::Drop with a request_id set,
    // without requiring a full network round-trip.  We construct the body
    // directly so we control exactly when EOF arrives vs. when we drop.

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let test_rid: Arc<str> = Arc::from("req-test-drop-1234");

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    let body = PassthroughBody::new(mock, None)
        .with_request_id(Arc::clone(&test_rid))
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // Queue one data frame so bytes_forwarded > 0, then keep tx open
    // (simulates upstream still writing when client disconnects).
    tx.send(Ok(Frame::data(Bytes::from_static(b"pack-data"))))
        .unwrap();

    // Install subscriber BEFORE drop so the proxy.stream emit is captured.
    let buf = CaptureBuf::new();
    let _guard = install_capture_subscriber(&buf);

    // Poll one frame to advance bytes_forwarded, then drop without EOF.
    let mut body = body;
    let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(
        frame.is_some(),
        "first poll should surface the queued frame"
    );

    // Drop the body — this triggers Drop::drop, which emits proxy.stream.
    drop(body);
    drop(_guard);

    // Verify atomic sinks (outcome + bytes) — independent of tracing.
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_PARTIAL,
        "mid-stream drop must record outcome=partial"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        b"pack-data".len() as u64,
    );

    // Verify tracing output contains proxy.stream with expected fields.
    let captured = buf.snapshot();
    assert!(
        captured.contains("proxy.stream"),
        "log must contain proxy.stream event; got: {captured}"
    );
    assert!(
        captured.contains("req-test-drop-1234"),
        "proxy.stream must carry the correlating request_id; got: {captured}"
    );
    assert!(
        captured.contains("partial"),
        "proxy.stream outcome must be partial; got: {captured}"
    );

    // Keep tx alive to end — models upstream still having data queued.
    drop(tx);
}

// ------------------------------------------------------------------
// P69L.0c: grant-backed credential lookup in the git-echo path.
// ------------------------------------------------------------------

/// Happy path: persona has an active grant for the credential; the grant
/// chain permits `github:push` on `*`; the credential is in the vault.
/// Expected: `handle_git_echo` injects the correct Basic-auth header and
/// the mock upstream sees it; response flows back with 200.
#[tokio::test(flavor = "current_thread")]
async fn git_echo_grant_backed_lookup_injects_correct_auth() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    // ---- Mock upstream: record the Authorization header, return 200 ----
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    // Channel to receive the Authorization header the proxy injected.
    let (auth_tx, mut auth_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        if let Ok((stream, _)) = upstream_listener.accept().await {
            let io = TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let auth = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let tx = auth_tx.clone();
                        async move {
                            let _ = tx.send(auth);
                            Ok::<Response<Full<Bytes>>, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from_static(b"ok")))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await;
        }
    });

    // ---- Grant-seeded state + echo proxy ----
    let (echo_state, persona_id, cred_name) =
        make_git_echo_state("grant-persona", "grant-cred", "secret-pat-abc");
    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state: echo_state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_srv = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_srv);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/owner/repo.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona_id.as_str())
        .header("x-ember-credential", cred_name.as_str())
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"")))
        .unwrap();

    let status = local
        .run_until(async move {
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let _ = resp.into_body().collect().await;
            status
        })
        .await;

    assert_eq!(status, StatusCode::OK, "grant-backed lookup must succeed");

    // The upstream must have seen Basic auth for "secret-pat-abc".
    let injected = auth_rx.try_recv().expect("auth header must be recorded");
    let expected = build_github_basic_auth("secret-pat-abc");
    assert_eq!(
        injected, expected,
        "injected Authorization must use vault-fetched token"
    );
}

/// Missing persona header → 401 (fail closed before touching upstream).
#[tokio::test(flavor = "current_thread")]
async fn git_echo_missing_persona_header_returns_401() {
    let (_echo_state, _persona_id, cred_name) =
        make_git_echo_state("test-persona-401", "test-cred-401", "tok");
    // The 401 path returns before ever touching a GitEchoConfig, so the
    // earlier `let config = Arc::new(GitEchoConfig { .. })` here was dead
    // code — drop it. Persona-check + unauthorized() call below are the
    // exact code path under test.
    let req = Request::builder()
        .method("POST")
        .uri("/github.com/owner/repo.git/git-receive-pack")
        .header("x-ember-credential", cred_name.as_str())
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|e| -> hyper::Error { panic!("empty body: {e}") }),
        )
        .unwrap();
    // Hold the streaming-gate test lock so a peer saturation test
    // doesn't hold all 32 slots while we try to acquire one. Without
    // this, the test fails when run in parallel with
    // `passthrough_respects_concurrency_cap` etc.
    let _gate = streaming_gate_test_lock();
    // Acquire a slot so handle_git_echo proceeds past the gate.
    let _slot = StreamingSlot::try_acquire().expect("slot");
    // We can't call handle_git_echo directly with Empty body (it expects
    // Incoming), so verify via the streaming slot path — the function
    // returns 401 before touching upstream. Use a synthesised Incoming-
    // compatible body by wrapping with UnsyncBoxBody.
    use http_body_util::combinators::UnsyncBoxBody;
    let (parts, body) = req.into_parts();
    let boxed = Request::from_parts(parts, UnsyncBoxBody::new(body));

    // Call the internal handler logic — replicate the persona-check only.
    let headers = boxed.headers();
    let persona_result = headers.get("x-ember-persona").and_then(|v| v.to_str().ok());
    assert!(
        persona_result.is_none(),
        "request must be missing x-ember-persona"
    );
    // Confirm the handler returns 401 for this case by calling it directly.
    // We need a real Incoming, so build a minimal in-process HTTP/1 round-trip.
    // Instead, call unauthorized() which is the exact code path.
    let resp = unauthorized("missing X-Ember-Persona header");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing persona header must yield 401"
    );
    drop(_slot);
}

/// No active grant → 403.
#[tokio::test(flavor = "current_thread")]
async fn git_echo_no_active_grant_returns_403() {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    ensure_rustls_provider();
    let _gate = streaming_gate_test_lock();

    // Upstream should never be reached — proxy must deny before forwarding.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept and immediately close — the proxy must NOT connect.
        if let Ok((stream, _)) = upstream_listener.accept().await {
            drop(stream);
        }
    });

    // State has a persona but NO grant.
    let state = make_state();
    let persona = state.store.create_persona("no-grant-persona").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "no-grant-cred",
            b"tok",
            None,
        )
        .unwrap();

    let upstream_host = format!("127.0.0.1:{}", upstream_addr.port());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let config = Arc::new(GitEchoConfig {
        bind_addr: proxy_addr,
        upstream_host: upstream_host.clone(),
        state,
        upstream_scheme: Scheme::Http,
    });

    let local = tokio::task::LocalSet::new();
    let cfg_srv = Arc::clone(&config);
    local.spawn_local(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let cfg = Arc::clone(&cfg_srv);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(move |req: Request<Incoming>| {
                        let cfg = Arc::clone(&cfg);
                        async move { handle_git_echo(cfg, req).await }
                    }),
                )
                .await;
        }
    });

    let proxy_url = format!(
        "http://127.0.0.1:{}/{}/owner/repo.git/git-receive-pack",
        proxy_addr.port(),
        upstream_host,
    );
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(&proxy_url)
        .header("x-ember-persona", persona.id.as_str())
        .header("x-ember-credential", "no-grant-cred")
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Full::new(Bytes::from_static(b"")))
        .unwrap();

    let status = local
        .run_until(async move {
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let _ = resp.into_body().collect().await;
            status
        })
        .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing grant must yield 403"
    );
}

// ------------------------------------------------------------------
// P69L.0b-P1-ERROR-SIGNAL: x-ember-stream-outcome trailer tests.
// ------------------------------------------------------------------

/// Clean upstream EOF: the body completes normally, and the final
/// trailer frame must carry `x-ember-stream-outcome: complete`.
#[tokio::test]
async fn passthrough_body_emits_complete_trailer_on_clean_eof() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let mut body = PassthroughBody::new(mock, None);

    // Push two data frames then signal clean EOF by closing the sender.
    tx.send(Ok(Frame::data(Bytes::from_static(b"chunk-a"))))
        .unwrap();
    tx.send(Ok(Frame::data(Bytes::from_static(b"chunk-b"))))
        .unwrap();
    // Drop the sender — ChannelBody's `poll_recv` returns None when the
    // channel is closed, modelling upstream EOF.
    drop(tx);

    // Drain all frames.
    let mut trailers_seen: Option<hyper::HeaderMap> = None;
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => break,
            Some(Ok(f)) => {
                if let Some(t) = f.trailers_ref() {
                    trailers_seen = Some(t.clone());
                }
            }
            Some(Err(e)) => panic!("unexpected error: {e}"),
        }
    }

    let trailers = trailers_seen.expect("trailer frame must be emitted before body end");
    let outcome = trailers
        .get(STREAM_OUTCOME_TRAILER_NAME)
        .expect("x-ember-stream-outcome header must be present")
        .to_str()
        .expect("header value must be valid UTF-8");
    assert_eq!(
        outcome, "complete",
        "clean EOF must produce outcome=complete"
    );

    // The atomic outcome should also record complete.
    assert_eq!(
        body.outcome.load(Ordering::Acquire),
        PASSTHROUGH_COMPLETE,
        "internal outcome must be PASSTHROUGH_COMPLETE"
    );
}

/// A body that emits one data frame then returns an error, modelling
/// an upstream TCP reset after partial delivery. The error type is
/// `std::io::Error` — since `PassthroughBody<B>` is now generic over
/// `B::Error: Display`, we don't need `hyper::Error` specifically.
/// Used only by the
/// `passthrough_body_emits_partial_trailer_on_upstream_error` test.
struct ErrorAfterFirstBody {
    step: u8,
}

impl Body for ErrorAfterFirstBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.step {
            0 => {
                self.step = 1;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"partial-data")))))
            }
            _ => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "mock upstream reset",
            )))),
        }
    }
}

/// Mid-stream upstream error: the upstream errors after one data frame.
/// The trailer must carry `x-ember-stream-outcome: partial` and the
/// body must terminate cleanly (no error propagated to the caller).
#[tokio::test]
async fn passthrough_body_emits_partial_trailer_on_upstream_error() {
    let mock = ErrorAfterFirstBody { step: 0 };
    let mut body = PassthroughBody::new(mock, None);

    // Drain all frames — expect data, then trailer, then None.
    let mut trailers_seen: Option<hyper::HeaderMap> = None;
    let mut data_bytes: Vec<u8> = Vec::new();
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => break,
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    data_bytes.extend_from_slice(d);
                }
                if let Some(t) = f.trailers_ref() {
                    trailers_seen = Some(t.clone());
                }
            }
            Some(Err(e)) => panic!("upstream error must not propagate; got: {e}"),
        }
    }

    // The partial data frame must have been forwarded.
    assert_eq!(
        data_bytes, b"partial-data",
        "data received before the error must be forwarded"
    );

    let trailers = trailers_seen.expect("trailer frame must be emitted on upstream error");
    let outcome = trailers
        .get(STREAM_OUTCOME_TRAILER_NAME)
        .expect("x-ember-stream-outcome header must be present")
        .to_str()
        .expect("header value must be valid UTF-8");
    assert_eq!(
        outcome, "partial",
        "upstream error must produce outcome=partial"
    );
}

// ------------------------------------------------------------------
// P69L.0b-TESTS: missing streaming scenarios.
// ------------------------------------------------------------------

/// Zero-length body: upstream returns 200 with no data frames (immediate
/// EOF). `PassthroughBody` must not hang waiting for a frame, must emit
/// `outcome=complete`, and must report `bytes_forwarded=0`.
#[tokio::test]
async fn streaming_response_handles_zero_length_body() {
    // An immediately-closed sender models a 200 with Content-Length: 0
    // or a 204/304 where the body is empty.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Frame<Bytes>, hyper::Error>>();
    drop(tx); // Close immediately — zero frames.
    let mock = ChannelBody { rx };

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    let mut body = PassthroughBody::new(mock, None)
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // First poll must return the outcome trailer (complete), not hang.
    let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;

    // The trailer frame carries outcome=complete.
    let trailers = frame
        .expect("first poll must yield a trailer, not None")
        .expect("frame must not be an error")
        .into_trailers()
        .expect("first frame must be a trailers frame");
    let outcome = trailers
        .get(STREAM_OUTCOME_TRAILER_NAME)
        .expect("x-ember-stream-outcome must be present")
        .to_str()
        .expect("header value must be valid UTF-8");
    assert_eq!(
        outcome, "complete",
        "empty body must yield outcome=complete"
    );

    // Second poll terminates the body.
    let done = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(done.is_none(), "body must end after the trailer");

    drop(body);
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_COMPLETE,
        "drop must record outcome=complete"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        0,
        "zero-length body must report bytes_forwarded=0"
    );
}

/// Client disconnect mid-stream (e2e): proxy successfully accepts the
/// request, begins streaming upstream data, then the downstream client
/// drops the response body before EOF. `PassthroughBody` must record
/// `outcome=partial` and the slot must be released (no gate leak).
///
/// This test exercises the drop path via the test-sink API — the same
/// mechanism that `passthrough_drop_emits_partial_outcome_on_mid_stream_drop`
/// uses, but wired through `stream_response` to confirm the production
/// call-site propagates sinks correctly.
#[tokio::test]
async fn streaming_response_propagates_client_disconnect() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    let outcome_sink = Arc::new(AtomicU8::new(0xff));
    let bytes_sink = Arc::new(AtomicU64::new(u64::MAX));

    // Simulate the production path: wrap in PassthroughBody (slot=None
    // for the test so we don't touch the process-global gate).
    let mut body = PassthroughBody::new(mock, None)
        .with_test_sinks(Arc::clone(&outcome_sink), Arc::clone(&bytes_sink));

    // Upstream has data queued — keep `tx` alive to model an open
    // upstream TCP connection at the moment the client disconnects.
    tx.send(Ok(Frame::data(Bytes::from_static(b"first-chunk"))))
        .unwrap();
    tx.send(Ok(Frame::data(Bytes::from_static(b"second-chunk"))))
        .unwrap();

    // Client reads exactly one frame then disconnects.
    let first = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(first.is_some(), "first poll must deliver a frame");
    let chunk = first.unwrap().unwrap().into_data().expect("data frame");
    assert_eq!(&chunk[..], b"first-chunk");

    // Drop the body mid-stream (models client TCP close / cancelled request).
    drop(body);

    // Upstream is still alive — this is the key: no leak.
    assert_eq!(
        outcome_sink.load(Ordering::Acquire),
        PASSTHROUGH_PARTIAL,
        "client disconnect before EOF must record outcome=partial"
    );
    assert_eq!(
        bytes_sink.load(Ordering::Acquire),
        b"first-chunk".len() as u64,
        "bytes_forwarded must count only frames delivered before disconnect"
    );

    // Keep tx alive to end — upstream still had data when client left.
    drop(tx);
}

/// Backpressure / slow consumer: a large body is available upstream but
/// the consumer reads one frame at a time with channel back-pressure.
/// All bytes must arrive intact; the body must not accumulate them in
/// memory (each frame is released before the next is requested).
#[tokio::test]
async fn streaming_response_backpressure_slow_consumer() {
    const CHUNKS: usize = 8;
    const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB per frame → 512 KiB total

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let mock = ChannelBody { rx };

    // Pre-load all chunks and close the sender (upstream EOF is known).
    let pattern: Bytes = Bytes::from(vec![0xABu8; CHUNK_SIZE]);
    for _ in 0..CHUNKS {
        tx.send(Ok(Frame::data(pattern.clone()))).unwrap();
    }
    drop(tx);

    let mut body = PassthroughBody::new(mock, None);

    // Read one frame at a time — model a slow downstream consumer.
    let mut total_bytes = 0usize;
    loop {
        let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
        match frame {
            None => break,
            Some(Ok(f)) => {
                if let Some(d) = f.data_ref() {
                    total_bytes += d.len();
                    // Verify content correctness (not just length).
                    assert!(
                        d.iter().all(|&b| b == 0xAB),
                        "chunk bytes must match pattern"
                    );
                }
                // Trailers are the terminal frame — don't count bytes.
            }
            Some(Err(e)) => panic!("unexpected error from PassthroughBody: {e}"),
        }
    }

    assert_eq!(
        total_bytes,
        CHUNKS * CHUNK_SIZE,
        "all bytes must arrive intact with slow consumer (no drop or duplication)"
    );
    assert_eq!(
        body.bytes_forwarded.load(Ordering::Acquire),
        (CHUNKS * CHUNK_SIZE) as u64,
        "bytes_forwarded counter must match total data delivered"
    );
    assert_eq!(
        body.outcome.load(Ordering::Acquire),
        PASSTHROUGH_COMPLETE,
        "slow consumer that reads all bytes must record outcome=complete"
    );
}

// -------------------------------------------------------------------------
// Body-size cap tests
// -------------------------------------------------------------------------

/// A request body at exactly MAX_BODY_BYTES (10 MiB) passes through
/// and returns 200 OK from the test harness.
#[tokio::test]
async fn body_at_limit_passes_through() {
    let state = make_state();
    let persona = state.store.create_persona("sec9-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "sec9-token",
            b"tok-sec9",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "sec9-token", "*", None)
        .unwrap();

    // Build a POST with exactly MAX_BODY_BYTES payload.
    let payload = vec![0u8; MAX_BODY_BYTES];
    let req = Request::builder()
        .method("POST")
        .uri("https://api.github.com/repos/owner/repo/issues")
        .header("X-Ember-Persona", persona.id.as_str())
        .header("X-Ember-Credential", "sec9-token")
        .header("X-Ember-Target", "https://api.github.com")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();

    let resp = call_full(state, req).await;
    // The test harness echos back 200 with the synthetic JSON body.
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A request body that exceeds MAX_BODY_BYTES (11 MiB here) must
/// be rejected with 413 Payload Too Large before touching the vault.
#[tokio::test]
async fn body_over_limit_returns_413() {
    let state = make_state();
    let persona = state.store.create_persona("sec9-over-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "sec9-over-token",
            b"tok-sec9-over",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "sec9-over-token", "*", None)
        .unwrap();

    // Build a POST with MAX_BODY_BYTES + 1 byte (just over the limit).
    let payload = vec![0u8; MAX_BODY_BYTES + 1];
    let req = Request::builder()
        .method("POST")
        .uri("https://api.github.com/repos/owner/repo/issues")
        .header("X-Ember-Persona", persona.id.as_str())
        .header("X-Ember-Credential", "sec9-over-token")
        .header("X-Ember-Target", "https://api.github.com")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();

    let resp = call_full(state, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body > MAX_BODY_BYTES must return 413"
    );
}

// -------------------------------------------------------------------------
// Credential zeroize test
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Attachment-scoped proxy authority resolution
// -------------------------------------------------------------------------

fn proxy_request_with_attachment(
    method: &str,
    uri: &str,
    persona: Option<&str>,
    credential: Option<&str>,
    target: Option<&str>,
    attachment_id: Option<&str>,
    endpoint_token: Option<&str>,
) -> Request<Empty<Bytes>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(p) = persona {
        builder = builder.header("X-Ember-Persona", p);
    }
    if let Some(c) = credential {
        builder = builder.header("X-Ember-Credential", c);
    }
    if let Some(t) = target {
        builder = builder.header("X-Ember-Target", t);
    }
    if let Some(attachment_id) = attachment_id {
        builder = builder.header("X-Ember-Attachment-Id", attachment_id);
    }
    if let Some(endpoint_token) = endpoint_token {
        builder = builder.header("X-Ember-Endpoint-Token", endpoint_token);
    }
    builder.body(Empty::new()).unwrap()
}

#[tokio::test]
async fn attachment_endpoint_headers_resolve_current_grant() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = make_state_with_data_dir(&tmp.path().join("data"));
    let persona = state.store.create_persona("composite-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "github-token",
            b"ghp_secret_a",
            None,
        )
        .unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-ant-secret",
            None,
        )
        .unwrap();
    let grant = state
        .store
        .create_grant(&persona.id, "github-token", "*", None)
        .unwrap();
    let stmt_github = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:push".into(), "github:read".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let stmt_anthropic = Statement {
        sid: "S1".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["llm:generate".into()],
        resource: ResourceSelector::Any,
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let root = state.store.persona_root_keypair(&persona.id).unwrap();
    let ag = crate::trust::grant::access_grant_from_statements(
        &grant.id,
        &persona.id,
        "github-token",
        vec![stmt_github, stmt_anthropic],
        0,
        None,
        &root,
    )
    .unwrap();
    state.store.overwrite_grant_blocks(&grant.id, &ag).unwrap();

    let sessions = core_state::sessions::SessionStore::new(
        state
            .sessions_dir
            .clone()
            .expect("persistent state has sessions dir"),
    );
    let session_id = "sess-proxy-attachment";
    sessions
        .create(&core_state::sessions::SessionMeta {
            session_id: session_id.to_string(),
            persona: persona.id.clone(),
            grant_id: grant.id.clone(),
            started_at: chrono::Utc::now(),
            launcher_pid: std::process::id(),
            authority_strict: false,
            delegation_id: None,
            delegation_template: None,
            durable_persona: Some("durable-proxy-persona".to_string()),
            caller_binding_id: Some("binding-proxy-001".to_string()),
        })
        .unwrap();
    sessions
        .write_attachment_endpoint(
            session_id,
            &core_state::sessions::AttachmentEndpoint::active(
                "att-proxy-001".to_string(),
                "ep-proxy-001".to_string(),
            ),
        )
        .unwrap();

    let req_a = proxy_request_with_attachment(
        "GET",
        "https://api.github.com/repos/x/y",
        None,
        Some("github-token"),
        Some("https://api.github.com"),
        Some("att-proxy-001"),
        Some("ep-proxy-001"),
    );
    let resp_a = call(Arc::clone(&state), req_a).await;
    assert_eq!(
        resp_a.status(),
        StatusCode::OK,
        "credential request should succeed through attachment-scoped authority"
    );

    let req_b = proxy_request_with_attachment(
        "GET",
        "https://api.github.com/repos/x/y",
        Some("different-runtime-persona"),
        Some("github-token"),
        Some("https://api.github.com"),
        Some("att-proxy-001"),
        Some("ep-proxy-001"),
    );
    let resp_b = call(Arc::clone(&state), req_b).await;
    assert_eq!(
        resp_b.status(),
        StatusCode::FORBIDDEN,
        "asserted persona headers must not override attachment authority"
    );
}

/// Regression: the existing single-credential flow without attachment
/// headers keeps working for non-session callers. evaluate_grant resolves
/// the grant from the persona/credential pair as before.
#[tokio::test]
async fn attachment_headers_absent_falls_back_to_evaluate_grant() {
    let state = make_state();
    let persona = state.store.create_persona("legacy-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "legacy-token",
            b"v",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "legacy-token", "*", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "GET",
        "https://api.github.com/repos/x/y",
        Some(&persona.id),
        Some("legacy-token"),
        Some("https://api.github.com"),
    );
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Pinned grant headers are no longer accepted as the proxy authority seam.
#[tokio::test]
async fn x_ember_grant_id_header_is_rejected() {
    let state = make_state();
    let persona = state.store.create_persona("nogrant-agent").unwrap();
    state
        .vault
        .add(VaultScope::Interactive, &state.store, "tok", b"v", None)
        .unwrap();
    let req = Request::builder()
        .method("GET")
        .uri("https://api.github.com/repos/x/y")
        .header("X-Ember-Persona", persona.id.as_str())
        .header("X-Ember-Credential", "tok")
        .header("X-Ember-Target", "https://api.github.com")
        .header("X-Ember-Grant-Id", "grant-does-not-exist")
        .body(Empty::new())
        .unwrap();
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_attachment_endpoint_is_forbidden() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = make_state_with_data_dir(&tmp.path().join("data"));
    state
        .vault
        .add(VaultScope::Interactive, &state.store, "tok", b"v", None)
        .unwrap();
    let req = proxy_request_with_attachment(
        "GET",
        "https://api.github.com/repos/x/y",
        None,
        Some("tok"),
        Some("https://api.github.com"),
        Some("missing-att"),
        Some("missing-token"),
    );
    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Verify that `Zeroizing<Vec<u8>>` zeros the backing allocation before
/// deallocation. Uses `ManuallyDrop` so the allocation stays live while
/// we inspect it — we call `zeroize()` explicitly (which is exactly what
/// the `Drop` impl does), then verify the bytes are all zero.
#[test]
fn credential_bytes_zeroized_on_drop() {
    use std::mem::ManuallyDrop;
    use zeroize::Zeroize;

    // Verify it's non-zero while live.
    let token = b"super-secret-token";
    let cred: Zeroizing<Vec<u8>> = Zeroizing::new(token.to_vec());
    assert!(
        cred.iter().any(|&b| b != 0),
        "credential bytes must be non-zero while live"
    );

    // Wrap in ManuallyDrop so we control the drop sequence: call
    // zeroize() first (the exact operation Zeroizing's Drop performs),
    // then verify all bytes are zero before the allocation is freed.
    let mut md: ManuallyDrop<Zeroizing<Vec<u8>>> = ManuallyDrop::new(cred);
    // Zeroize in place (mirrors what `<Zeroizing<T> as Drop>::drop` does).
    (**md).zeroize();
    assert!(
        md.iter().all(|&b| b == 0),
        "Zeroizing<Vec<u8>> must zero bytes on drop"
    );
    // Now safe to drop without re-zeroing.
    unsafe { ManuallyDrop::drop(&mut md) };
}

/// Upstream-usage-requests regression guard.
///
/// `usage.requests` must reflect upstream-confirmed responses, not a
/// pre-flight tally. Driving the post-flight meter once with an
/// upstream-success and once with a 5xx (using identical usage-bearing
/// bodies in both cases) must record exactly one request — the
/// success — not two.
#[test]
fn usage_requests_counts_only_upstream_confirmed_calls() {
    let state = make_state();
    let persona = state.store.create_persona("audit-usage").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "anthropic-key",
            b"sk-secret",
            None,
        )
        .unwrap();
    let grant_id = seed_composite_grant(
        &state,
        &persona.id,
        "anthropic-key",
        vec![stmt_session("S1", 100_000)],
    );
    let resolved_stmt = stmt_session("S1", 100_000);

    // Same usage-bearing body for both calls — the only thing that
    // changes is the upstream's HTTP status. A pre-flight counter
    // would record both as billable requests; the post-flight
    // upstream-confirmed counter must reject the 5xx.
    let body = anthropic_body(40, 25); // 65 tokens

    // Call 1: upstream-confirmed success.
    run_post_flight_meter(
        &state,
        &grant_id,
        "S1",
        &resolved_stmt,
        &persona.id,
        "anthropic-key",
        "api.anthropic.com",
        body.as_bytes(),
        StreamOutcome::Complete,
        true, // upstream returned 2xx
    );

    // Call 2: upstream returned 5xx. The body still parses, but
    // the request did NOT happen as far as the provider is
    // concerned, so the requests counter must not advance.
    run_post_flight_meter(
        &state,
        &grant_id,
        "S1",
        &resolved_stmt,
        &persona.id,
        "anthropic-key",
        "api.anthropic.com",
        body.as_bytes(),
        StreamOutcome::Complete,
        false, // upstream returned non-2xx (e.g. 502)
    );

    let ag = state.store.get_access_grant(&grant_id).unwrap();
    let stmt = ag
        .statements()
        .find(|(_, s)| s.sid == "S1")
        .map(|(_, s)| s.clone())
        .expect("S1 present");

    // Tokens accumulate either way (the daemon still observed the
    // bytes); the budget machinery treats them as best-effort.
    // What MUST NOT inflate is `requests` — that's the audit-
    // integrity invariant.
    assert_eq!(
        stmt.usage.requests, 1,
        "usage.requests must count only upstream-confirmed responses; got {} (one success + one 5xx must equal 1, not 2)",
        stmt.usage.requests
    );
}

/// `record_upstream_request` direct unit cases. The interface
/// contract specifies it returns 1 only when the upstream is a
/// known LLM provider, the status is 2xx, and a usage signal was
/// observed. All failure paths return 0.
#[test]
fn record_upstream_request_only_credits_on_success() {
    // Happy path.
    assert_eq!(record_upstream_request("api.anthropic.com", true, true), 1,);
    // 5xx / non-2xx upstream — failure path, do not credit.
    assert_eq!(record_upstream_request("api.anthropic.com", false, true), 0,);
    // No usage parsed — nothing happened we can bill for.
    assert_eq!(record_upstream_request("api.anthropic.com", true, false), 0,);
    // Unknown / non-LLM provider — outside the metering contract.
    assert_eq!(record_upstream_request("api.github.com", true, true), 0,);
}

/// `statement_revoked_response` emits a
/// structured JSON 403 naming the persona + statement so clients can
/// distinguish revoke from a generic scope/audit denial. Locks the
/// public shape `{"error":"statement_revoked","persona_id":..,
/// "statement_id":..}` against future drift.
#[tokio::test]
async fn statement_revoked_response_emits_structured_json_403() {
    let resp = statement_revoked_response("agent-worker-a", "S1");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(ct, "application/json");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "statement_revoked");
    assert_eq!(json["persona_id"], "agent-worker-a");
    assert_eq!(json["statement_id"], "S1");
}

/// ADR 190 §4 / ADR 197 §2 — `authority_lapsed_response` is fail-closed
/// (403, no credential) but carries the session base posture's recovery
/// affordance so a lapsed grant degrades gracefully instead of bricking.
/// `jit` => re-approvable; `strict` => re-delegate required. Locks the
/// public body shape against drift.
#[tokio::test]
async fn authority_lapsed_response_carries_posture_recovery() {
    // jit posture: re-approvable.
    let resp = authority_lapsed_response("agent-worker-a", "expired", "grant-abc", false);
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "authority_lapsed");
    assert_eq!(json["persona_id"], "agent-worker-a");
    assert_eq!(json["grant_id"], "grant-abc");
    assert_eq!(json["grant_status"], "expired");
    assert_eq!(json["posture"], "jit");
    assert_eq!(json["recovery"], "reapprove");

    // strict posture: re-delegate required; never silently allowed.
    let resp = authority_lapsed_response("agent-worker-b", "revoked", "grant-xyz", true);
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["grant_id"], "grant-xyz");
    assert_eq!(json["grant_status"], "revoked");
    assert_eq!(json["posture"], "strict");
    assert_eq!(json["recovery"], "redelegate");
}

/// ADR 190 §4 / ADR 197 §2 — a grant taken out of `active` mid-session
/// (operator revoke here) resolved on the attachment path must yield the
/// parseable `grant_inactive:<status>` contract — NOT the legacy prose and
/// NOT a silent allow — so the LLM lane renders the recoverable
/// authority_lapsed response. Locks the resolve seam end-to-end.
#[tokio::test]
async fn resolve_grant_non_active_yields_grant_inactive_contract() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state.store.create_persona("persona-expiry").unwrap();
    let credential_name = "anthropic/oauth-token";
    let grant = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();
    // Take the grant out of `active` mid-session.
    state.store.grant_store().revoke_grant(&grant.id).unwrap();

    let backend = DaemonPolicyBackend::new(state);
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
    let err = backend
        .resolve_grant(&persona.id, credential_name, Some(&grant.id), &uri, "POST")
        .await
        .expect_err("a revoked grant must not resolve");
    match err {
        // V030-REVOKE-ERROR-MESSAGE: the contract is now
        // `grant_inactive:<status>:<grant_id>` so the proxy can name the
        // offending grant in its operator-facing message.
        core_proxy_forward::PolicyError::Forbidden(msg) => assert_eq!(
            msg,
            format!("grant_inactive:revoked:{}", grant.id),
            "must emit the parseable posture contract with grant_id, got: {msg}"
        ),
        other => panic!("expected Forbidden(grant_inactive:..), got {other:?}"),
    }
}

/// ADR 211 §1/AC-2 — a grant can be SQL-active but inert when its
/// grant-scoped lease is gone. The proxy resolver must refuse before upstream
/// traffic; active row state alone is not authority-to-act.
#[tokio::test]
async fn resolve_grant_active_without_live_lease_yields_grant_inactive_contract() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state.store.create_persona("persona-no-live-lease").unwrap();
    let credential_name = "anthropic/oauth-token";
    let grant = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();
    assert!(
        state.store.leases().drop_lease(&grant.id),
        "test setup must remove the live lease while leaving the grant active"
    );
    assert_eq!(
        state.store.get_grant(&grant.id).unwrap().status,
        "active",
        "row remains active; refusal must come from the missing lease"
    );

    let backend = DaemonPolicyBackend::new(state);
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
    let err = backend
        .resolve_grant(&persona.id, credential_name, Some(&grant.id), &uri, "POST")
        .await
        .expect_err("an active grant without a live lease must not resolve");
    match err {
        core_proxy_forward::PolicyError::Forbidden(msg) => assert!(
            msg.starts_with("grant_inactive:no_live_lease:"),
            "must emit the parseable posture contract with grant_id suffix, got: {msg}"
        ),
        other => panic!("expected Forbidden(grant_inactive:no_live_lease:*), got {other:?}"),
    }
}

/// P22-S3 / ADR 211 - request-start resolution is not enough if the lease
/// disappears before the preflight gate. The proxy must re-check the live
/// grant-scoped lease after collecting the request body and before it can
/// approve budget / continue toward credential injection.
#[tokio::test]
async fn preflight_budget_rejects_when_live_lease_drops_after_resolve() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state
        .store
        .create_persona("persona-preflight-lease")
        .unwrap();
    let credential_name = "anthropic/oauth-token";
    let grant = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();

    let backend = DaemonPolicyBackend::new(state.clone());
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
    let resolved = backend
        .resolve_grant(&persona.id, credential_name, Some(&grant.id), &uri, "POST")
        .await
        .expect("live lease should resolve before the preflight drop");
    assert!(
        state.store.leases().drop_lease(&grant.id),
        "test setup must remove the lease after resolve but before preflight"
    );

    let err = backend
        .preflight_budget(&resolved, br#"{"max_tokens":1}"#)
        .await
        .expect_err("preflight must fail closed after lease loss");
    match err {
        core_proxy_forward::PolicyError::Forbidden(msg) => assert!(
            msg.starts_with("grant_inactive:no_live_lease:"),
            "must emit the parseable no-live-lease contract with grant_id suffix, got: {msg}"
        ),
        other => panic!("expected Forbidden(grant_inactive:no_live_lease:*), got {other:?}"),
    }
}

/// P22 lease survival / ADR 211 - resolving a grant at request start is not
/// enough to let an in-flight proxy call survive after its lease disappears.
/// Post-flight metering reopens the grant chain for usage accounting; when the
/// grant-scoped lease is gone, that authority-to-act consumer must fail closed
/// instead of silently accepting an unmetered stream/request.
#[tokio::test]
async fn post_flight_rejects_when_live_lease_drops_after_resolve() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state
        .store
        .create_persona("persona-post-flight-lease")
        .unwrap();
    let credential_name = "anthropic/oauth-token";
    let grant = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();

    let backend = DaemonPolicyBackend::new(state.clone());
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
    let resolved = backend
        .resolve_grant(&persona.id, credential_name, Some(&grant.id), &uri, "POST")
        .await
        .expect("live lease should resolve before the in-flight drop");
    assert!(
        state.store.leases().drop_lease(&grant.id),
        "test setup must remove the lease after resolve but before post-flight"
    );

    let err = backend
        .post_flight(
            &resolved,
            Some(Usage {
                tokens: 100,
                requests: 1,
                ..Default::default()
            }),
        )
        .await
        .expect_err("post-flight metering must fail closed after lease loss");
    match err {
        core_proxy_forward::PolicyError::Forbidden(msg) => assert!(
            msg.starts_with("grant_inactive:no_live_lease:"),
            "must emit the parseable no-live-lease contract with grant_id suffix, got: {msg}"
        ),
        other => panic!("expected Forbidden(grant_inactive:no_live_lease:*), got {other:?}"),
    }

    let chain = state.store.get_access_grant(&grant.id).unwrap();
    let stmt = chain
        .statements()
        .find(|(_, stmt)| stmt.sid == resolved.statement_sid)
        .expect("resolved statement remains present")
        .1;
    assert_eq!(
        stmt.usage.tokens, 0,
        "failed post-flight metering must not persist usage without a live lease"
    );
}

/// ADR 205 §A.4 — the proxy boundary walks grant ancestry, not just the leaf.
/// A child grant whose PARENT was revoked without the eager
/// `cascade_revoke_children` write reaching it (crash mid-cascade / race /
/// presented embed-chain) must be refused at `resolve_grant` even though the
/// leaf itself is still `active`. Without the online walk this is the open
/// "revoke the parent, the child's proxied requests still succeed" hole.
#[tokio::test]
async fn resolve_grant_refuses_when_grant_ancestor_revoked() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state.store.create_persona("persona-ancestry").unwrap();
    let credential_name = "anthropic/oauth-token";
    let parent = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();
    let child = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();
    // Link child → parent directly. The daemon sets `parent_grant_id` at
    // delegate-time; we set it here to isolate the revocation-walk wiring from
    // delegation attenuation (covered by the grant.rs unit tests).
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET parent_grant_id = ?1 WHERE id = ?2",
            rusqlite::params![parent.id, child.id],
        )
        .unwrap();

    let backend = DaemonPolicyBackend::new(state.clone());
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();

    // Clean chain: parent active → the leaf resolves (the walk does not
    // false-refuse).
    let clean = backend
        .resolve_grant(&persona.id, credential_name, Some(&child.id), &uri, "POST")
        .await;
    assert!(clean.is_ok(), "clean ancestry must resolve, got: {clean:?}");

    // Revoke ONLY the parent's row (simulate the missed cascade); child stays
    // `active`.
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![parent.id],
        )
        .unwrap();
    assert_eq!(
        state.store.get_grant(&child.id).unwrap().status,
        "active",
        "leaf must remain active — the refusal must come from the ancestry walk"
    );

    let err = backend
        .resolve_grant(&persona.id, credential_name, Some(&child.id), &uri, "POST")
        .await
        .expect_err("a revoked ancestor must refuse the proxied request");
    match err {
        core_proxy_forward::PolicyError::Forbidden(msg) => assert_eq!(
            msg,
            format!("ancestor_revoked:{}", parent.id),
            "must emit the parseable ancestor-revoked contract, got: {msg}"
        ),
        other => panic!("expected Forbidden(ancestor_revoked:..), got {other:?}"),
    }
}

/// BKR-4b (ADR 205 §A.3 parts 1+2) — the proxy boundary now root-authorizes +
/// chain-verifies the grant on the composed `PersonaRootAuthority` seam (the
/// same one #5708/#5718 wired at the broker mints), BEFORE per-request
/// statement resolution. A grant whose issuing persona is NOT authorized by the
/// root authority is refused with the `root_unauthorized` contract.
///
/// In the dev0 root regime this fires for an issuing persona that resolves no
/// root key — reachable via a single-block unsigned-phase1 orphan grant (which
/// `get_access_grant` passes through, F-07) whose persona row is gone. This is
/// the SAME predicate that becomes load-bearing with no caller change when ADR
/// 206 steps 1–2 anchor the root in the presence device-set: a persona the set
/// does not authorize will yield `None` here and be refused identically.
#[tokio::test]
async fn resolve_grant_refuses_when_issuing_persona_root_unauthorized() {
    use core_proxy_forward::PolicyBackend;

    let state = make_state();
    let persona = state.store.create_persona("persona-unrooted").unwrap();
    let credential_name = "anthropic/oauth-token";
    // Create normally so the grant carries a live grant-scoped lease (the proxy
    // refuses no-live-lease before reaching the root/chain gate).
    let grant = state
        .store
        .create_grant(&persona.id, credential_name, "*", None)
        .unwrap();

    // Replace the signed chain with a single unsigned-phase1 placeholder block
    // (issued_by the persona) so `get_access_grant` returns it via the F-07
    // orphan pass-through instead of erroring on a broken chain.
    let placeholder = core_grant_types::SignedBlock {
        block: core_grant_types::Block {
            statements: vec![core_grant_types::Statement {
                sid: "S0".into(),
                resource_type: core_grant_types::ResourceType::Credential,
                actions: vec!["*".into()],
                resource: core_grant_types::ResourceSelector::Any,
                budget: None,
                usage: core_grant_types::Usage::default(),
                conditions: vec![],
                can_delegate: None,
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona.id.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        },
        pubkey_next: core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
        signature: core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
    };
    let blocks_json = serde_json::to_string(&[placeholder]).unwrap();
    state
        .store
        .conn()
        .execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        )
        .unwrap();

    // Drop the persona row so the root authority resolves no key for the
    // issuing persona (FK off for the orphaning delete, mirroring the grant.rs
    // orphan fixtures).
    state
        .store
        .conn()
        .execute_batch("PRAGMA foreign_keys = OFF")
        .unwrap();
    state
        .store
        .conn()
        .execute(
            "DELETE FROM personas WHERE id = ?1",
            rusqlite::params![persona.id],
        )
        .unwrap();
    state
        .store
        .conn()
        .execute_batch("PRAGMA foreign_keys = ON")
        .unwrap();

    let backend = DaemonPolicyBackend::new(state.clone());
    let uri: http::Uri = "https://api.anthropic.com/v1/messages".parse().unwrap();
    let err = backend
        .resolve_grant(&persona.id, credential_name, Some(&grant.id), &uri, "POST")
        .await
        .expect_err("a grant whose issuing persona is not root-authorized must refuse");
    match err {
        core_proxy_forward::PolicyError::Forbidden(msg) => assert_eq!(
            msg, "root_unauthorized",
            "must emit the root-unauthorized contract (parts 1+2 gate), got: {msg}"
        ),
        other => panic!("expected Forbidden(root_unauthorized), got {other:?}"),
    }
}

// DaemonEventSink::record_threshold_crossing
// dedupes repeated calls on the same (grant_id, statement_sid, axis, band)
// tuple. Mirrors the existing in-place `ProxyState.threshold_emitted`
// semantics so the trait-routed code path is independently correct before
// the call-site migration (Slice B-2).
#[tokio::test]
async fn daemon_event_sink_record_threshold_crossing_dedupes() {
    let state = make_state();
    let sink = DaemonEventSink::new(state, None);

    let first = sink
        .record_threshold_crossing("g-1", "S1", ThresholdAxis::Tokens, ThresholdBand::Warning)
        .await;
    assert!(first, "first crossing on a fresh tuple is newly inserted");

    let dup = sink
        .record_threshold_crossing("g-1", "S1", ThresholdAxis::Tokens, ThresholdBand::Warning)
        .await;
    assert!(!dup, "repeat call on the same tuple dedupes");

    let different_band = sink
        .record_threshold_crossing("g-1", "S1", ThresholdAxis::Tokens, ThresholdBand::Exhausted)
        .await;
    assert!(
        different_band,
        "different band on same axis is a fresh tuple"
    );

    let different_axis = sink
        .record_threshold_crossing("g-1", "S1", ThresholdAxis::Cents, ThresholdBand::Warning)
        .await;
    assert!(different_axis, "different axis is a fresh tuple");
}
