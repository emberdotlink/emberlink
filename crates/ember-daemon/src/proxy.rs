use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::pricing;
use crate::store::StoreError;
use crate::vault::VaultError;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("client error: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("vault error: {0}")]
    Vault(VaultError),
}

impl From<VaultError> for ProxyError {
    fn from(e: VaultError) -> Self {
        ProxyError::Vault(e)
    }
}

pub struct ProxyConfig {
    pub bind_addr: std::net::SocketAddr,
}

pub struct ProxyState {
    pub store: crate::store::DaemonStore,
    pub vault: crate::vault::Vault,
    /// In-memory debounce set for threshold-crossing audit events. Entries
    /// are `(grant_id, statement_sid, axis, band)` — adding to this set
    /// before emission guarantees `budget.warning` is never logged twice
    /// for the same threshold. The set resets on daemon restart, which is
    /// acceptable: a restarted daemon re-emitting a warning is a
    /// defensive duplicate, not a missed alert.
    ///
    /// The outer `RefCell` is safe because proxy connections run on a
    /// `LocalSet` (see `run_proxy`) — the single-threaded runtime gives
    /// us non-Sync interior mutability for free without a Mutex.
    threshold_emitted: RefCell<HashSet<(String, String, &'static str, &'static str)>>,
}

impl ProxyState {
    pub fn new(store: crate::store::DaemonStore, vault: crate::vault::Vault) -> Self {
        Self {
            store,
            vault,
            threshold_emitted: RefCell::new(HashSet::new()),
        }
    }
}

pub async fn run_proxy(
    config: ProxyConfig,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(config.bind_addr).await?;

    // Use a LocalSet so that Arc<ProxyState> (which contains rusqlite's !Sync
    // Connection) does not need to cross thread boundaries.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            loop {
                tokio::select! {
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, _addr)) => {
                                let state = Arc::clone(&state);
                                let io = TokioIo::new(stream);
                                tokio::task::spawn_local(async move {
                                    let svc = hyper::service::service_fn(move |req| {
                                        let state = Arc::clone(&state);
                                        async move { handle_request(state, req).await }
                                    });
                                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, svc)
                                        .await
                                    {
                                        tracing::warn!(error = %e, "proxy connection error");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "proxy accept error");
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
        .await;

    Ok(())
}

pub async fn handle_request(
    state: Arc<ProxyState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let headers = req.headers();

    let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Persona header")),
    };

    let credential_name = match headers.get("x-ember-credential").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Credential header")),
    };

    let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Ok(bad_request("missing X-Ember-Target header")),
    };

    // Evaluate grant
    let grant = match state.store.evaluate_grant(&persona_id, &credential_name) {
        Ok(g) => g,
        Err(StoreError::NotFound) => {
            return Ok(forbidden("no active grant for persona/credential"));
        }
        Err(e) => return Err(ProxyError::Store(e)),
    };

    // Per-Statement resolution (design). If the composite chain has no
    // Statement applicable to the request's (action, resource), deny with
    // `no_applicable_statement` and NEVER fall back to grant-level
    // enforcement — that is the entire point of the composite-grant shape.
    let access_grant = match state.store.get_access_grant(&grant.id) {
        Ok(g) => g,
        Err(e) => return Err(ProxyError::Store(e)),
    };
    // Clone the resolved Statement so we can meter against it post-flight
    // without re-resolving (the request body is consumed during forward).
    let resolved_sid: String;
    let resolved_stmt: core_types::Statement;
    if let Some((action, resource)) = request_to_action_resource(req.method(), req.uri()) {
        match resolve_statement_for_request(&access_grant, &action, &resource) {
            None => {
                tracing::warn!(
                    grant_id = %grant.id,
                    persona_id = %persona_id,
                    credential = %credential_name,
                    action = %action,
                    resource = %resource,
                    "no applicable statement for request — denying"
                );
                let _ = state.store.log_event(
                    Some(&persona_id),
                    "credential.access",
                    Some(&credential_name),
                    "denied_no_applicable_statement",
                    Some(&format!("action={action} resource={resource}")),
                );
                return Ok(no_applicable_statement_response());
            }
            Some((_i, stmt)) => {
                resolved_sid = stmt.sid.clone();
                resolved_stmt = stmt.clone();
            }
        }
    } else {
        // Unknown HTTP method — already a hard deny in check_scope, but
        // emit the same signal here so the composite path doesn't silently
        // bypass on e.g. CONNECT.
        tracing::warn!(
            grant_id = %grant.id,
            method = %req.method(),
            "unsupported method — denying"
        );
        return Ok(no_applicable_statement_response());
    }

    // Enforce grant.scope against request method + URI. Fail closed on any
    // unknown or ambiguous scope format. Do NOT leak the scope string to the
    // client — log it internally and return a generic 403.
    if let Err(violation) = check_scope(&grant.scope, req.method(), req.uri()) {
        tracing::warn!(
            grant_id = %grant.id,
            persona_id = %persona_id,
            credential = %credential_name,
            method = %req.method(),
            uri = %req.uri(),
            scope = %grant.scope,
            detail = %violation.0,
            "scope violation: denying request"
        );
        let _ = state.store.log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "denied_scope",
            Some(&violation.0),
        );
        return Ok(scope_violation_response());
    }

    // Enforce allowed_targets if the grant specifies them
    if let Some(ref targets) = grant.allowed_targets {
        let allowed: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
        let target_host = target_url
            .find("://")
            .map(|i| &target_url[i + 3..])
            .map(|after_scheme| {
                let end = after_scheme
                    .find(['/', '?', '#'])
                    .unwrap_or(after_scheme.len());
                &after_scheme[..end]
            });

        let is_allowed = match target_host {
            Some(host) => allowed.iter().any(|pattern| {
                if pattern.starts_with("*.") {
                    host.ends_with(&pattern[1..])
                } else {
                    host == *pattern || target_url.starts_with(pattern)
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

    // Collect the incoming body up front so the Stream C pre-flight
    // budget check has something to estimate against. `body_bytes_in` is
    // then forwarded unchanged.
    let (parts, incoming_body) = req.into_parts();
    let body_bytes_in = incoming_body
        .collect()
        .await
        .map_err(ProxyError::Hyper)?
        .to_bytes();

    // Pre-flight Stream C budget check. When the resolved Statement has a
    // `budget.tokens` or `budget.cents` set, estimate the call cost and
    // 429 if it would exceed the remaining allowance. Statements without
    // a budget (TTL-only, credential grants) pass through unchanged.
    match preflight_budget_check(&resolved_stmt, body_bytes_in.as_ref()) {
        PreflightDecision::Allowed => {}
        PreflightDecision::Rejected { axis, limit, used } => {
            tracing::warn!(
                grant_id = %grant.id,
                statement_sid = %resolved_sid,
                axis,
                limit,
                used,
                "budget pre-flight rejection"
            );
            let _ = state.store.log_event(
                Some(&persona_id),
                "proxy.denied_preflight",
                Some(&credential_name),
                "budget_exhausted",
                Some(&format!(
                    "grant_id={} sid={resolved_sid} axis={axis} limit={limit} used={used}",
                    grant.id
                )),
            );
            return Ok(budget_exhausted_response(
                &grant.id,
                &resolved_sid,
                axis,
                limit,
                used,
            ));
        }
    }

    // Decrypt credential from vault
    let credential_bytes = match state.vault.get(&state.store, &credential_name) {
        Ok(b) => b,
        Err(VaultError::NotFound) => {
            return Ok(internal_error("credential not found in vault"));
        }
        Err(e) => return Err(ProxyError::Vault(e)),
    };

    let credential_value = String::from_utf8_lossy(&credential_bytes).into_owned();

    // Log the access
    let _ = state.store.log_event(
        Some(&persona_id),
        "credential.access",
        Some(&credential_name),
        "allowed",
        None,
    );

    // Build an HTTPS-capable client using rustls with system WebPKI roots.
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(https);

    // Build the outgoing request to the target URL.
    let mut outgoing = Request::builder()
        .method(parts.method.clone())
        .uri(&target_url);

    // Forward original headers, injecting the credential as Authorization.
    for (name, value) in &parts.headers {
        // Drop the ember-specific proxy headers.
        let lower = name.as_str();
        if lower.starts_with("x-ember-") {
            continue;
        }
        outgoing = outgoing.header(name, value);
    }

    let outgoing_req = outgoing
        .header("authorization", format!("Bearer {credential_value}"))
        .body(Full::new(body_bytes_in))
        .map_err(|e| {
            tracing::warn!(error = %e, "failed to build outgoing request");
            ProxyError::Http(e)
        })?;

    let upstream_resp = client
        .request(outgoing_req)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "upstream request failed");
            ProxyError::Client(e)
        })?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = upstream_resp
        .into_body()
        .collect()
        .await
        .map_err(ProxyError::Hyper)?
        .to_bytes();

    // Stream C post-flight meter. Resolve the upstream host and parse
    // the response for token + cent usage. If the target isn't an LLM
    // provider we have pricing for, `meter_response` returns `None` and
    // we skip the increment — the request still forwards unchanged.
    let target_host: String = extract_host_from_url(&target_url).unwrap_or_default();
    if let Some(delta) = meter_response(&target_host, resp_body.as_ref()) {
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
                // After the increment, check whether the grant is now
                // budget-terminal across all budget-bearing Statements
                // and flip status to `exhausted_by_budget` if so.
                let _ = state
                    .store
                    .mark_grant_exhausted_by_budget_if_terminal(&grant.id);
            }
            Err(e) => {
                tracing::warn!(
                    grant_id = %grant.id,
                    sid = %resolved_sid,
                    error = ?e,
                    "failed to increment statement usage (metering skipped)"
                );
            }
        }
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }

    Ok(builder
        .body(Full::new(resp_body))
        .unwrap())
}

/// Extract the host from a URL string (e.g. `https://api.anthropic.com/v1`).
/// Returns `None` if the URL is malformed.
fn extract_host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());
    Some(after_scheme[..end].to_ascii_lowercase())
}

/// Reason a request was rejected by scope enforcement.
///
/// Held as a separate type (rather than `String`) so callers can't
/// accidentally render it into the HTTP response body — scope details are
/// sensitive and should only hit `tracing` + the audit table.
#[derive(Debug)]
pub(crate) struct ScopeViolation(pub(crate) String);

/// Map an HTTP (method, URI) pair to the composite-grant (action, resource)
/// tuple used by `Statement.applicable_to`.
///
/// Actions are colon-delimited IAM verbs (`github:read`, `github:push`,
/// `generic:read`, `generic:write`). Resources are the request URI's path,
/// potentially prefixed with the host when the provider is host-scoped.
///
/// This is the authoritative bridge between the legacy method-tier scope
/// grammar and the composite-grant selector model. New callers (dashboard
/// streaming, approval flow, standing-grant matcher) share this mapping so
/// the selector a request is checked against is identical across paths.
pub(crate) fn request_to_action_resource(
    method: &hyper::Method,
    uri: &hyper::Uri,
) -> Option<(String, String)> {
    let tier = method_tier(method)?;
    let host = uri.host().unwrap_or("");
    let path = uri.path();

    let (provider, action) = if host.ends_with("github.com") || host == "api.github.com" {
        (
            "github",
            match tier {
                MethodTier::Read => "read",
                MethodTier::Write => "push",
            },
        )
    } else {
        (
            "generic",
            match tier {
                MethodTier::Read => "read",
                MethodTier::Write => "write",
            },
        )
    };

    // Resource string: for github, strip leading "/repos/" so the path matches
    // a selector like `emberdotlink/ember-daemon`. For generic, the full path
    // is the resource.
    let resource = if provider == "github" {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        trimmed.strip_prefix("repos/").unwrap_or(trimmed).to_string()
    } else {
        path.to_string()
    };

    Some((format!("{provider}:{action}"), resource))
}

/// Resolve the applicable `Statement` for a request (action, resource) pair
/// against a composite grant chain.
///
/// Walks every `(block_index, statement)` pair in chain order and returns
/// the first whose `applicable_to` predicate holds. When the chain has zero
/// applicable statements the caller MUST deny with
/// `no_applicable_statement_response()` — the authorization primitive never
/// falls back to grant-level enforcement. See design § "Allow-only" and
/// SESSION-composite-plan.md §Risks.
///
/// Matching is tolerant of legacy bare-action forms:
/// - `"read"` on a Statement matches request action `"github:read"` and
///   `"generic:read"` (the colon-delimited form is a superset of the bare
///   form, used by new composite grants; the bare form is carried forward
///   by `scope_to_actions_and_selector` in grant.rs for legacy scopes).
/// - `"*"` on a Statement matches any request action.
///
/// Resource matching follows `Statement.resource.covers(resource)`. When a
/// grant's selector is an `Exact` match on the credential name (the fallback
/// for credential-type grants where `scope` has no `:target` tail) we also
/// accept the request iff the Statement's action agrees — effectively
/// treating credential-fallback selectors as `Any` because the request's
/// resource is a URI, not a credential name.
pub fn resolve_statement_for_request<'a>(
    grant: &'a core_types::AccessGrant,
    action: &str,
    resource: &str,
) -> Option<(usize, &'a core_types::Statement)> {
    use core_types::ResourceSelector;

    // Bare-action tail: `"github:read"` → `"read"`, `"read"` → `"read"`.
    let bare_action = action.rsplit(':').next().unwrap_or(action);

    grant.statements().find(|(_, stmt)| {
        let action_ok = stmt.actions.iter().any(|a| {
            a == action
                || a == bare_action
                || a == "*"
                || {
                    // Stmt action may be a bare "read"/"push"/"write" while
                    // the request is "github:read". Accept when the trailing
                    // verb matches.
                    let stmt_bare = a.rsplit(':').next().unwrap_or(a);
                    stmt_bare == bare_action
                }
        });
        if !action_ok {
            return false;
        }

        // Legacy credential-fallback: if the selector is an Exact match
        // on the credential name, the resource match is effectively
        // Any (because the request URI will never equal a credential
        // name). This is a transitional compat branch — once every
        // call site emits fully-qualified selectors, this collapses to
        // pure Statement.resource.covers() matching.
        match &stmt.resource {
            ResourceSelector::Exact { value } if !value.contains('/') && !value.starts_with('/') => {
                // Heuristic: a bare ident without path separators looks
                // like a credential name (e.g. "github-token", "api-key").
                // Treat as Any for HTTP resource matching.
                true
            }
            other => other.covers(resource),
        }
    })
}

/// Outcome of `preflight_budget_check`. `Allowed` → forward upstream;
/// `Rejected { axis, limit, used }` → 429 with budget-exhausted body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightDecision {
    Allowed,
    Rejected { axis: &'static str, limit: u64, used: u64 },
}

/// Pre-flight budget check for a resolved Statement.
///
/// Given the Statement the request resolved to and the request body (used
/// to estimate tokens via `pricing::estimate_call_tokens`), return
/// `Allowed` when the projected token usage plus current usage fits under
/// the Statement's budget, or `Rejected` naming the first exhausted axis.
///
/// Cents are NOT estimated pre-flight because we don't know the model
/// pricing without the response (the `model` field in the request body is
/// advisory; the upstream can substitute). The post-flight meter handles
/// cents. Token estimation uses the byte-length / 4 heuristic from
/// `pricing.rs` which biases conservatively — a request that just fits
/// will pass preflight and the real post-flight math may nudge usage up
/// against the budget.
///
/// Statements without a `budget` (TTL-only) always pass.
pub fn preflight_budget_check(stmt: &core_types::Statement, request_body: &[u8]) -> PreflightDecision {
    let Some(budget) = &stmt.budget else {
        return PreflightDecision::Allowed;
    };
    if let Some(cap) = budget.tokens {
        let estimated = pricing::estimate_call_tokens(request_body);
        let projected = stmt.usage.tokens.saturating_add(estimated);
        if projected > cap {
            return PreflightDecision::Rejected {
                axis: "tokens",
                limit: cap,
                used: stmt.usage.tokens,
            };
        }
    }
    // Cents preflight: only block when the existing usage ALREADY exceeds
    // the cents cap (post-flight cents tick can nudge usage over budget
    // between calls). We don't estimate cents up front — see doc above.
    if let Some(cap) = budget.cents
        && stmt.usage.cents >= cap
    {
        return PreflightDecision::Rejected {
            axis: "cents",
            limit: cap,
            used: stmt.usage.cents,
        };
    }
    PreflightDecision::Allowed
}

/// 429 denial body for a budget-exhausted pre-flight. The body names
/// `axis`, `limit`, and `used` so the agent can back off intelligently
/// without probing. Emitting a structured shape matches the `Error`
/// schema used by Stream D receipts; no secret is leaked because the
/// agent already knows the grant's budget (they've minted/received it).
pub(crate) fn budget_exhausted_response(
    grant_id: &str,
    statement_sid: &str,
    axis: &str,
    limit: u64,
    used: u64,
) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "budget_exhausted",
        "grant_id": grant_id,
        "statement_sid": statement_sid,
        "axis": axis,
        "limit": limit,
        "used": used,
    });
    let bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"budget_exhausted\"}".to_vec());
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

/// Compute the (token, cents) usage delta from an upstream LLM response
/// body. Returns `None` if the body isn't a recognizable JSON LLM
/// response — the caller should skip metering rather than fail the
/// request (e.g. GitHub + non-LLM providers return here with `None`).
///
/// Provider is resolved from the target host (`api.anthropic.com`,
/// `api.openai.com`); an unknown host returns `None` even if the body
/// looks like JSON — we only meter providers we have a pricing table
/// for.
pub fn meter_response(
    target_host: &str,
    response_body: &[u8],
) -> Option<core_types::Usage> {
    let provider = pricing::provider_for_host(target_host)?;
    let parsed = pricing::parse_usage(provider, response_body)?;
    let model =
        pricing::extract_model(provider, response_body).unwrap_or_default();
    let cents = pricing::cents_for(
        &model,
        provider,
        parsed.input_tokens,
        parsed.output_tokens,
    );
    Some(core_types::Usage {
        tokens: parsed.input_tokens.saturating_add(parsed.output_tokens),
        cents,
        requests: 1,
        workload_hours: 0,
        wall_clock_secs: 0,
        last_updated: 0,
    })
}

/// Emit threshold-crossing audit events for a metering update.
///
/// Looks at (prior, current, budget) on each axis (tokens, cents) and
/// emits a `budget.warning` at each band (80%, 95%) the update crossed
/// — never twice for the same (grant, sid, axis, band) in the lifetime
/// of the daemon process (debounce set on `ProxyState`). When `current`
/// meets or exceeds `budget`, emits a `budget.exhausted` audit record
/// (debounced the same way, band = `"100"`).
///
/// The caller is responsible for passing the Statement's current
/// resolved `budget` — this function does no read-back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_threshold_crossings(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    persona_id: &str,
    credential_name: &str,
    budget: &core_types::Budget,
    prior: &core_types::Usage,
    current: &core_types::Usage,
) {
    let axes: [(&'static str, Option<u64>, u64, u64); 2] = [
        ("tokens", budget.tokens, prior.tokens, current.tokens),
        ("cents", budget.cents, prior.cents, current.cents),
    ];
    for (axis, cap, before, after) in axes.iter() {
        let Some(cap) = cap else { continue };
        if *cap == 0 {
            continue;
        }
        for &(band_label, band_frac) in &[("80", 0.80f64), ("95", 0.95f64)] {
            let threshold = (*cap as f64 * band_frac) as u64;
            if *before < threshold && *after >= threshold {
                emit_debounced(
                    state,
                    grant_id,
                    statement_sid,
                    axis,
                    band_label,
                    persona_id,
                    credential_name,
                    "budget.warning",
                    &format!(
                        "axis={axis} used={after} limit={cap} percent={band_label}"
                    ),
                );
            }
        }
        if *before < *cap && *after >= *cap {
            emit_debounced(
                state,
                grant_id,
                statement_sid,
                axis,
                "100",
                persona_id,
                credential_name,
                "budget.exhausted",
                &format!("axis={axis} used={after} limit={cap}"),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_debounced(
    state: &ProxyState,
    grant_id: &str,
    statement_sid: &str,
    axis: &'static str,
    band_label: &'static str,
    persona_id: &str,
    credential_name: &str,
    action: &str,
    details: &str,
) {
    let key = (
        grant_id.to_string(),
        statement_sid.to_string(),
        axis,
        band_label,
    );
    if !state.threshold_emitted.borrow_mut().insert(key) {
        return;
    }
    let _ = state.store.log_event(
        Some(persona_id),
        action,
        Some(credential_name),
        band_label,
        Some(details),
    );
}

/// 403 denial when zero statements match a request. Never names the
/// statement set — same rationale as `scope_violation_response` (leaking
/// the selector shape is a probe vector). The cause is logged + audited.
pub(crate) fn no_applicable_statement_response() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "no_applicable_statement",
    });
    let bytes = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"no_applicable_statement\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

/// Check a grant's `scope` string against the request method and URI.
///
/// Scope grammar (fail closed on anything else):
///
/// ```text
///   <scope> := "*"                       // universal
///            | <action>                  // legacy bare action: "read", "push", "*"
///            | <provider> ":" <action>
///            | <provider> ":" <action> ":" <target>
///            | <provider> ":" <action> ":" <target> ":" <subtarget>
///
///   <provider>  := "github" | "generic" | "*"
///   <action>    := "read" | "push" | "write" | "*"
///   <target>    := owner "/" repo        // for github
///                | <path-prefix>         // for generic
///                | "*"
///   <subtarget> := <glob>                // branch pattern; enforced via
///                                        //  URI-path matching for GitHub
///                                        //  branch endpoints. Git
///                                        //  smart-http body-sniffing is
///                                        //  still deferred.
/// ```
///
/// HTTP method → action bucket:
///
/// * `GET`, `HEAD`, `OPTIONS` → `read` (also allowed by `*`)
/// * `POST`, `PUT`, `PATCH`, `DELETE` → `push`/`write` (also allowed by `*`)
/// * anything else → denied
///
/// `write` is treated as a synonym of `push` for legacy grants.
///
/// This function **never widens** a scope: a missing, empty, or
/// unrecognised scope is a denial, and an unknown action never satisfies a
/// write-tier method.
pub(crate) fn check_scope(
    scope: &str,
    method: &hyper::Method,
    uri: &hyper::Uri,
) -> Result<(), ScopeViolation> {
    let scope = scope.trim();
    if scope.is_empty() {
        return Err(ScopeViolation("empty scope".to_string()));
    }

    // Classify the method first; an unknown method is a hard deny so new
    // HTTP verbs can't sneak past the enforcement table.
    let method_tier = method_tier(method)
        .ok_or_else(|| ScopeViolation(format!("unsupported method: {method}")))?;

    // "*" alone is the universal scope.
    if scope == "*" {
        return Ok(());
    }

    // Split into at most 4 components. Reject anything with empty segments
    // (e.g. "::", "github::push") so typos fail closed.
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(ScopeViolation(format!("malformed scope: '{scope}'")));
    }
    if parts.len() > 4 {
        return Err(ScopeViolation(format!(
            "scope has too many segments: '{scope}'"
        )));
    }

    // Legacy bare-action form: "read", "push", "write", "*".
    let (provider, action, target, subtarget) = match parts.as_slice() {
        [action] => ("*", *action, "*", None),
        [provider, action] => (*provider, *action, "*", None),
        [provider, action, target] => (*provider, *action, *target, None),
        [provider, action, target, subtarget] => (*provider, *action, *target, Some(*subtarget)),
        _ => {
            return Err(ScopeViolation(format!(
                "malformed scope: '{scope}'"
            )));
        }
    };

    // Validate provider against a closed set. Anything else is a deny.
    match provider {
        "github" => {
            let host = uri.host().unwrap_or("");
            if host != "api.github.com" && host != "github.com" {
                return Err(ScopeViolation(format!(
                    "scope restricts to github but host is '{host}'"
                )));
            }
        }
        "generic" | "*" => {}
        other => {
            return Err(ScopeViolation(format!(
                "unknown scope provider: '{other}'"
            )));
        }
    }

    // Validate action against the method tier. `write` is accepted as a
    // legacy synonym of `push`.
    let action_allows_method = matches!(
        (action, method_tier),
        ("*", _)
            | ("read", MethodTier::Read)
            | ("push", MethodTier::Write)
            | ("write", MethodTier::Write)
    );
    if !action_allows_method {
        return Err(ScopeViolation(format!(
            "scope action '{action}' does not permit {method} requests"
        )));
    }

    // Validate target. For github this is "owner/repo" (optionally
    // containing `*` wildcards). For generic this is treated as a path
    // prefix with `*` wildcards. `*` alone always matches.
    if target != "*" {
        let path = uri.path();
        let target_ok = match provider {
            "github" => github_target_matches(target, path),
            // generic + * fall through to path-prefix globbing
            _ => wildcard_match(target, path),
        };
        if !target_ok {
            return Err(ScopeViolation(format!(
                "scope target '{target}' does not match request path"
            )));
        }
    }

    // Validate subtarget (branch pattern) when present.
    // Enforced via URI-path matching for GitHub branch endpoints.
    // Git smart-http body-sniffing (/git-receive-pack) is still deferred.
    if let Some(st) = subtarget {
        subtarget_matches(st, uri, provider)?;
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MethodTier {
    Read,
    Write,
}

fn method_tier(method: &hyper::Method) -> Option<MethodTier> {
    match *method {
        hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS => {
            Some(MethodTier::Read)
        }
        hyper::Method::POST
        | hyper::Method::PUT
        | hyper::Method::PATCH
        | hyper::Method::DELETE => Some(MethodTier::Write),
        _ => None,
    }
}

/// Match a github target (`owner/repo`, possibly with `*` wildcards) against
/// the URI path of a GitHub API request. We recognise the common
/// `/repos/{owner}/{repo}/...` and `/{owner}/{repo}` shapes; anything else
/// fails closed.
fn github_target_matches(target: &str, path: &str) -> bool {
    // Split target into owner/repo; targets without a slash are invalid.
    let (t_owner, t_repo) = match target.split_once('/') {
        Some((o, r)) if !o.is_empty() && !r.is_empty() => (o, r),
        _ => return false,
    };

    // Strip a leading "/repos" if present, then leading "/".
    let rest = path.strip_prefix('/').unwrap_or(path);
    let rest = rest.strip_prefix("repos/").unwrap_or(rest);

    let mut segments = rest.split('/');
    let owner = segments.next().unwrap_or("");
    let repo = segments.next().unwrap_or("");
    if owner.is_empty() || repo.is_empty() {
        return false;
    }

    wildcard_match(t_owner, owner) && wildcard_match(t_repo, repo)
}

/// Check that a scope's subtarget (branch glob) is satisfied by the request URI.
///
/// For `provider == "github"` we extract the branch name from these path shapes:
///   - `/repos/{owner}/{repo}/branches/{branch}[/...]`
///   - `/repos/{owner}/{repo}/git/refs/heads/{branch}[/...]`
///
/// If neither pattern matches we fail closed: we cannot prove which branch is
/// targeted so we deny.  Git smart-http body-sniffing (`/git-receive-pack`) is
/// explicitly out of scope and remains deferred.
///
/// For providers other than `github` (including `generic`/`*`) subtarget
/// enforcement is not defined; we fail closed there too.
fn subtarget_matches(subtarget_glob: &str, uri: &hyper::Uri, provider: &str) -> Result<(), ScopeViolation> {
    if provider != "github" {
        return Err(ScopeViolation(format!(
            "scope subtarget is only supported for provider 'github', not '{provider}'"
        )));
    }

    let path = uri.path();

    // Try to extract a branch from either URI shape.
    let branch = extract_github_branch(path);

    match branch {
        Some(b) => {
            if wildcard_match(subtarget_glob, &b) {
                Ok(())
            } else {
                Err(ScopeViolation(format!(
                    "scope subtarget '{subtarget_glob}' does not match branch '{b}'"
                )))
            }
        }
        None => Err(ScopeViolation(
            "scope subtarget requires branch in URI path but path does not contain \
             /branches/ or /git/refs/heads/"
                .to_string(),
        )),
    }
}

/// Known single-word sub-resource suffixes that appear after a branch name in
/// the GitHub REST API path.  These are stripped when extracting the branch
/// from a `/branches/{branch}/{sub-resource}` path.
const GITHUB_BRANCH_SUBRESOURCES: &[&str] = &["protection", "rename"];

/// Extract the branch name from a GitHub API URI path that explicitly encodes
/// the branch.
///
/// Recognised shapes:
///   - `.../branches/{branch}[/sub-resource]`
///     The tail after `branches/` is the branch name.  If the last segment of
///     that tail is a known single-word sub-resource (`protection`, `rename`)
///     it is stripped, leaving just the branch.  This handles both simple
///     branches (`main`) and slash-containing branches (`feat/foo`).
///   - `.../git/refs/heads/{branch}` — the entire tail after `/heads/` is the
///     branch name, which may contain `/` (e.g. `feat/foo`).
///
/// The raw path is percent-decoded before matching so that a branch delivered
/// as `feat%2Ffoo` (a valid GitHub API percent-encoding) compares equal to the
/// glob `feat/*` rather than failing to match `%2F` against `/`.
///
/// Returns `None` if the path doesn't match either shape.
fn extract_github_branch(path: &str) -> Option<String> {
    use percent_encoding::percent_decode_str;

    // Decode the whole path once up front.  percent_decode on a plain path
    // (no `%XX` sequences) is a no-op and returns a borrowed Cow, so this is
    // cheap in the common case.
    let decoded = percent_decode_str(path).decode_utf8_lossy().into_owned();
    let path = decoded.as_str();

    // Shape 1: .../branches/{branch}[/sub-resource]
    // Find the byte offset of "/branches/" and take everything after it.
    const BRANCHES: &str = "/branches/";
    if let Some(idx) = path.find(BRANCHES) {
        let tail = path[idx + BRANCHES.len()..].trim_end_matches('/');
        if tail.is_empty() {
            return None;
        }
        // Strip a known single-word sub-resource from the end if present.
        let branch = if let Some(last_slash) = tail.rfind('/') {
            let last_seg = &tail[last_slash + 1..];
            if GITHUB_BRANCH_SUBRESOURCES.contains(&last_seg) {
                &tail[..last_slash]
            } else {
                tail
            }
        } else {
            tail
        };
        return if branch.is_empty() { None } else { Some(branch.to_owned()) };
    }

    // Shape 2: .../git/refs/heads/{branch}
    // The entire tail after "/heads/" is the branch name (may contain '/').
    const HEADS: &str = "/git/refs/heads/";
    if let Some(idx) = path.find(HEADS) {
        let tail = path[idx + HEADS.len()..].trim_end_matches('/');
        return if tail.is_empty() { None } else { Some(tail.to_owned()) };
    }

    None
}

/// Tiny glob matcher supporting `*` as "any run of characters". No `?`, no
/// character classes, no escaping. Used for owner/repo/path matching where
/// `*` wildcards are the only thing we claim to support. Falls back to a
/// prefix-match for the final `*` so that `"emberdotlink/*"` matches any
/// repo.
fn wildcard_match(pattern: &str, s: &str) -> bool {
    // Fast path: no wildcard at all means literal equality.
    if !pattern.contains('*') {
        return pattern == s;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut cursor = 0usize;

    // Anchor the first literal fragment to the start.
    let first = parts[0];
    if !s[cursor..].starts_with(first) {
        return false;
    }
    cursor += first.len();

    // Middle fragments: find each in turn.
    for frag in &parts[1..parts.len() - 1] {
        if frag.is_empty() {
            continue;
        }
        match s[cursor..].find(frag) {
            Some(idx) => cursor += idx + frag.len(),
            None => return false,
        }
    }

    // Anchor the final literal to the end of the input.
    let last = parts[parts.len() - 1];
    s[cursor..].ends_with(last)
}

/// Return a generic 403 for scope violations. The body deliberately does
/// NOT include the grant's scope string — leaking it would let an attacker
/// probe for narrower scopes. The detail is in the daemon log and audit.
fn scope_violation_response() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "scope violation",
    });
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"scope violation\"}".to_vec());
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn bad_request(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

fn forbidden(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

fn internal_error(msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from(msg.to_string())))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DaemonStore;
    use crate::vault::Vault;
    use http_body_util::{BodyExt, Empty};

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_state() -> Arc<ProxyState> {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Vault::new(test_key());
        Arc::new(ProxyState::new(store, vault))
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

    async fn call(
        state: Arc<ProxyState>,
        req: Request<Empty<Bytes>>,
    ) -> Response<Full<Bytes>> {
        // Adapt Empty<Bytes> to Incoming-compatible body using map_err
        let (parts, body) = req.into_parts();
        let mapped = body.map_err(|e| -> hyper::Error { panic!("empty body error: {e}") });
        let incoming_req = Request::from_parts(parts, mapped);

        // We need to call handle_request which takes Incoming — but in tests we
        // use a type-erased body.  Use the UnsyncBoxBody approach: box the body.
        use http_body_util::combinators::UnsyncBoxBody;
        let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> = incoming_req
            .map(|b| UnsyncBoxBody::new(b));

        // handle_request is generic — call a test-only wrapper.
        handle_request_boxed(state, boxed).await.unwrap()
    }

    // Test wrapper that accepts a boxed body so tests don't need a real Incoming.
    async fn handle_request_boxed(
        state: Arc<ProxyState>,
        req: Request<impl hyper::body::Body<Data = Bytes, Error = hyper::Error>>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let headers = req.headers();

        let persona_id = match headers.get("x-ember-persona").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Persona header")),
        };

        let credential_name = match headers.get("x-ember-credential").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Credential header")),
        };

        let target_url = match headers.get("x-ember-target").and_then(|v| v.to_str().ok()) {
            Some(v) => v.to_string(),
            None => return Ok(bad_request("missing X-Ember-Target header")),
        };

        let grant = match state.store.evaluate_grant(&persona_id, &credential_name) {
            Ok(g) => g,
            Err(StoreError::NotFound) => {
                return Ok(forbidden("no active grant for persona/credential"));
            }
            Err(e) => return Err(ProxyError::Store(e)),
        };

        // Mirror the production per-Statement resolution check.
        let access_grant = match state.store.get_access_grant(&grant.id) {
            Ok(g) => g,
            Err(e) => return Err(ProxyError::Store(e)),
        };
        let resolved_sid: String;
        let resolved_stmt: core_types::Statement;
        if let Some((action, resource)) = request_to_action_resource(req.method(), req.uri()) {
            match resolve_statement_for_request(&access_grant, &action, &resource) {
                None => {
                    tracing::warn!(
                        grant_id = %grant.id,
                        action = %action,
                        resource = %resource,
                        "no applicable statement for request — denying (test harness)"
                    );
                    let _ = state.store.log_event(
                        Some(&persona_id),
                        "credential.access",
                        Some(&credential_name),
                        "denied_no_applicable_statement",
                        Some(&format!("action={action} resource={resource}")),
                    );
                    return Ok(no_applicable_statement_response());
                }
                Some((_i, stmt)) => {
                    resolved_sid = stmt.sid.clone();
                    resolved_stmt = stmt.clone();
                }
            }
        } else {
            return Ok(no_applicable_statement_response());
        }

        // Mirror the production scope check so tests exercise it end-to-end.
        if let Err(violation) = check_scope(&grant.scope, req.method(), req.uri()) {
            tracing::warn!(
                grant_id = %grant.id,
                persona_id = %persona_id,
                credential = %credential_name,
                method = %req.method(),
                uri = %req.uri(),
                scope = %grant.scope,
                detail = %violation.0,
                "scope violation: denying request"
            );
            let _ = state.store.log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "denied_scope",
                Some(&violation.0),
            );
            return Ok(scope_violation_response());
        }

        // Enforce allowed_targets if the grant specifies them
        if let Some(ref targets) = grant.allowed_targets {
            let allowed: Vec<&str> = targets.split(',').map(|s| s.trim()).collect();
            let target_host = target_url
                .find("://")
                .map(|i| &target_url[i + 3..])
                .map(|after_scheme| {
                    let end = after_scheme
                        .find(['/', '?', '#'])
                        .unwrap_or(after_scheme.len());
                    &after_scheme[..end]
                });

            let is_allowed = match target_host {
                Some(host) => allowed.iter().any(|pattern| {
                    if pattern.starts_with("*.") {
                        host.ends_with(&pattern[1..])
                    } else {
                        host == *pattern || target_url.starts_with(pattern)
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
        let body_bytes_in = incoming_body
            .collect()
            .await
            .map_err(ProxyError::Hyper)?
            .to_bytes();

        // Pre-flight Stream C budget check (test parity with production).
        match preflight_budget_check(&resolved_stmt, body_bytes_in.as_ref()) {
            PreflightDecision::Allowed => {}
            PreflightDecision::Rejected { axis, limit, used } => {
                let _ = state.store.log_event(
                    Some(&persona_id),
                    "proxy.denied_preflight",
                    Some(&credential_name),
                    "budget_exhausted",
                    Some(&format!(
                        "grant_id={} sid={resolved_sid} axis={axis} limit={limit} used={used}",
                        grant.id
                    )),
                );
                return Ok(budget_exhausted_response(
                    &grant.id,
                    &resolved_sid,
                    axis,
                    limit,
                    used,
                ));
            }
        }

        let credential_bytes = match state.vault.get(&state.store, &credential_name) {
            Ok(b) => b,
            Err(VaultError::NotFound) => {
                return Ok(internal_error("credential not found in vault"));
            }
            Err(e) => return Err(ProxyError::Vault(e)),
        };

        let credential_value = String::from_utf8_lossy(&credential_bytes).into_owned();

        let _ = state.store.log_event(
            Some(&persona_id),
            "credential.access",
            Some(&credential_name),
            "allowed",
            None,
        );

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
        if let Some(delta) = meter_response(&target_host, response_body_bytes.as_ref()) {
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

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(response_body_bytes))
            .unwrap())
    }

    #[tokio::test]
    async fn valid_request_returns_200_proxied() {
        let state = make_state();

        let persona = state.store.create_persona("test-agent").unwrap();
        state
            .vault
            .add(&state.store, "github-token", b"ghp_secret", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "github-token", "read", None)
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
        let req = proxy_request_with_headers(None, Some("github-token"), Some("https://api.github.com"));
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
            .add(&state.store, "github-token", b"ghp_secret", None)
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
            .add(&state.store, "github-token", b"ghp_secret", None)
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
            .create_grant(&persona.id, "missing-cred", "read", None)
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

    // ------------------------------------------------------------------
    // Scope enforcement tests (69E.5)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn scope_read_denies_post() {
        let state = make_state();

        let persona = state.store.create_persona("scope-read-post").unwrap();
        state
            .vault
            .add(&state.store, "gh-token", b"ghp_secret", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "gh-token", "read", None)
            .unwrap();

        let req = proxy_request_with_method_and_uri(
            "POST",
            "https://api.github.com/repos/emberdotlink/emberlink/issues",
            Some(&persona.id),
            Some("gh-token"),
            Some("https://api.github.com"),
        );

        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Per design a POST to a github endpoint under a read-only
        // statement has zero applicable statements (the statement's
        // action is "read", the request's action is "github:push"),
        // so this denies at the composite layer, not the legacy scope
        // layer. Either denial shape is acceptable as long as the body
        // never leaks the selector string.
        let err = json["error"].as_str().unwrap_or("");
        assert!(
            err == "no_applicable_statement" || err == "scope violation",
            "unexpected error shape: {err}"
        );
        // The response must NOT leak the scope string.
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            !body_str.contains("read"),
            "response body leaked scope detail: {body_str}"
        );
    }

    #[tokio::test]
    async fn scope_read_allows_get() {
        // The check function itself is the load-bearing piece; the full
        // forward path doesn't need to work in tests.
        let uri: hyper::Uri = "https://api.github.com/repos/emberdotlink/emberlink"
            .parse()
            .unwrap();
        assert!(check_scope("read", &hyper::Method::GET, &uri).is_ok());
        assert!(check_scope("read", &hyper::Method::HEAD, &uri).is_ok());
    }

    #[tokio::test]
    async fn scope_github_push_specific_repo() {
        // Allowed: push to the exact repo.
        let ok_uri: hyper::Uri =
            "https://api.github.com/repos/emberdotlink/emberlink/issues"
                .parse()
                .unwrap();
        assert!(check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &ok_uri
        )
        .is_ok());

        // Denied: push to a different repo.
        let bad_uri: hyper::Uri =
            "https://api.github.com/repos/other/repo/issues".parse().unwrap();
        assert!(check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &bad_uri
        )
        .is_err());

        // Also denied: the host isn't github.
        let wrong_host: hyper::Uri =
            "https://api.example.com/repos/emberdotlink/emberlink/issues"
                .parse()
                .unwrap();
        assert!(check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &wrong_host
        )
        .is_err());

        // Also denied: a read-tier method with a push-only scope.
        assert!(check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::GET,
            &ok_uri
        )
        .is_err());
    }

    #[tokio::test]
    async fn scope_wildcard_allows_anything() {
        let uri: hyper::Uri = "https://api.example.com/anything".parse().unwrap();
        assert!(check_scope("*", &hyper::Method::GET, &uri).is_ok());
        assert!(check_scope("*", &hyper::Method::POST, &uri).is_ok());
        assert!(check_scope("*:*", &hyper::Method::DELETE, &uri).is_ok());
        assert!(check_scope("*:*:*", &hyper::Method::PATCH, &uri).is_ok());
    }

    #[tokio::test]
    async fn scope_unknown_format_denies() {
        let uri: hyper::Uri = "https://api.github.com/repos/a/b".parse().unwrap();

        // Empty scope.
        assert!(check_scope("", &hyper::Method::GET, &uri).is_err());
        // Whitespace-only.
        assert!(check_scope("   ", &hyper::Method::GET, &uri).is_err());
        // Trailing/double colons (empty segments).
        assert!(check_scope("garbled::::", &hyper::Method::GET, &uri).is_err());
        assert!(check_scope("github::push", &hyper::Method::POST, &uri).is_err());
        // Too many segments.
        assert!(
            check_scope("a:b:c:d:e", &hyper::Method::GET, &uri).is_err()
        );
        // Unknown provider.
        assert!(
            check_scope("quux:read", &hyper::Method::GET, &uri).is_err()
        );
        // Unknown action.
        assert!(
            check_scope("github:frobnicate", &hyper::Method::POST, &uri).is_err()
        );
        // Unknown HTTP method (CONNECT/TRACE etc.) fails closed even under "*".
        assert!(
            check_scope("*", &hyper::Method::CONNECT, &uri).is_err()
        );
    }

    #[tokio::test]
    async fn scope_read_denies_post_e2e_logs_denial() {
        // End-to-end: denial also writes an audit entry with outcome=denied_scope.
        let state = make_state();
        let persona = state.store.create_persona("scope-audit").unwrap();
        state
            .vault
            .add(&state.store, "tok", b"s", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "tok", "read", None)
            .unwrap();

        let req = proxy_request_with_method_and_uri(
            "POST",
            "https://api.github.com/repos/a/b/issues",
            Some(&persona.id),
            Some("tok"),
            Some("https://api.github.com"),
        );

        let resp = call(Arc::clone(&state), req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let entries = state
            .store
            .query_audit(&crate::audit::AuditFilter::default())
            .unwrap();
        // Either the legacy scope-violation denial or the composite
        // no-applicable-statement denial satisfies the audit requirement.
        assert!(entries.iter().any(|e| e.action == "credential.access"
            && (e.outcome == "denied_scope"
                || e.outcome == "denied_no_applicable_statement")));
    }

    #[tokio::test]
    async fn successful_request_logs_audit_event() {
        let state = make_state();

        let persona = state.store.create_persona("audit-agent").unwrap();
        state
            .vault
            .add(&state.store, "audit-token", b"tok_secret", None)
            .unwrap();
        state
            .store
            .create_grant(&persona.id, "audit-token", "read", None)
            .unwrap();

        let req = proxy_request_with_headers(
            Some(&persona.id),
            Some("audit-token"),
            Some("https://api.example.com"),
        );

        let resp = call(Arc::clone(&state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let entries = state
            .store
            .query_audit(&crate::audit::AuditFilter::default())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "credential.access");
        assert_eq!(entries[0].outcome, "allowed");
        assert_eq!(entries[0].credential.as_deref(), Some("audit-token"));
    }

    // ------------------------------------------------------------------
    // Subtarget (branch-pattern) enforcement tests (69E.5b)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn scope_subtarget_branches_path_glob_match() {
        // feat/* glob matches feat/foo branch.
        let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/feat/foo"
            .parse()
            .unwrap();
        assert!(
            check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
            "feat/* should match feat/foo via /branches/ path"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_branches_path_glob_mismatch() {
        // feat/* glob does NOT match main.
        let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
            .parse()
            .unwrap();
        assert!(
            check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_err(),
            "feat/* should not match main branch"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_git_refs_heads_glob_match() {
        // feat/* glob matches feat/anything via /git/refs/heads/.
        let uri: hyper::Uri =
            "https://api.github.com/repos/x/y/git/refs/heads/feat/anything"
                .parse()
                .unwrap();
        assert!(
            check_scope("github:push:x/y:feat/*", &hyper::Method::PATCH, &uri).is_ok(),
            "feat/* should match feat/anything via /git/refs/heads/"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_non_branch_path_denied() {
        // Path has no branch in it — should fail closed.
        let uri: hyper::Uri = "https://api.github.com/repos/x/y/issues"
            .parse()
            .unwrap();
        let result = check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri);
        assert!(
            result.is_err(),
            "scope with subtarget must fail closed when path has no /branches/ or /git/refs/heads/"
        );
        let err_msg = result.unwrap_err().0;
        assert!(
            err_msg.contains("/branches/") || err_msg.contains("/git/refs/heads/"),
            "error message should explain why: {err_msg}"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_exact_match() {
        let main_uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
            .parse()
            .unwrap();
        let dev_uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/develop"
            .parse()
            .unwrap();

        // Exact match succeeds.
        assert!(
            check_scope("github:push:x/y:main", &hyper::Method::DELETE, &main_uri).is_ok(),
            "exact subtarget 'main' should match /branches/main"
        );
        // Exact match fails on a different branch.
        assert!(
            check_scope("github:push:x/y:main", &hyper::Method::DELETE, &dev_uri).is_err(),
            "exact subtarget 'main' should not match /branches/develop"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_empty_segment_rejected() {
        // A trailing colon (empty subtarget) must be rejected as a malformed scope.
        let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
            .parse()
            .unwrap();
        let result = check_scope("github:push:x/y:", &hyper::Method::POST, &uri);
        assert!(
            result.is_err(),
            "empty subtarget segment (trailing colon) must be rejected"
        );
        let err_msg = result.unwrap_err().0;
        assert!(
            err_msg.contains("malformed"),
            "error should say malformed: {err_msg}"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_protection_subresource() {
        // /branches/{branch}/protection — branch is still the segment after /branches/.
        let uri: hyper::Uri =
            "https://api.github.com/repos/x/y/branches/main/protection"
                .parse()
                .unwrap();
        assert!(
            check_scope("github:push:x/y:main", &hyper::Method::PUT, &uri).is_ok(),
            "subtarget 'main' should match /branches/main/protection"
        );
    }

    // ------------------------------------------------------------------
    // Percent-encoded branch name tests (adversarial review finding)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn scope_subtarget_percent_encoded_slash_in_branch() {
        // feat%2Ffoo in the URI path should match the glob feat/* after decoding.
        // hyper parses the raw path; `%2F` is NOT decoded to `/` by `uri.path()`.
        // We must decode it ourselves before matching.
        let uri: hyper::Uri =
            "https://api.github.com/repos/x/y/branches/feat%2Ffoo"
                .parse()
                .unwrap();
        assert!(
            check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
            "feat/* should match branch feat/foo delivered as feat%2Ffoo in path"
        );
    }

    #[tokio::test]
    async fn scope_subtarget_heavily_percent_encoded_branch() {
        // %66eat%2Fbar decodes to feat/bar, which should match feat/*.
        let uri: hyper::Uri =
            "https://api.github.com/repos/x/y/branches/%66eat%2Fbar"
                .parse()
                .unwrap();
        assert!(
            check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
            "feat/* should match branch feat/bar delivered as %66eat%2Fbar in path"
        );
    }

    // ------------------------------------------------------------------
    // Per-Statement resolution tests (design / P69K-A2)
    // ------------------------------------------------------------------

    #[test]
    fn resolve_statement_picks_first_applicable() {
        use core_types::{
            AccessGrant, AttestationBinding, Block, GrantMode, GrantStatus,
            PresentationAudienceKind, RecipientProfile, ResourceSelector, ResourceType,
            SignedBlock, Statement, Usage,
        };
        let stmt_read = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Glob { pattern: "emberdotlink/*".into() },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
        };
        let stmt_push = Statement {
            sid: "S1".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["push".into()],
            resource: ResourceSelector::Exact { value: "emberdotlink/widgets".into() },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
        };
        let block = Block {
            statements: vec![stmt_read, stmt_push],
            nbf: None,
            expires_at: None,
            issued_by: "persona-a".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant-x".into(),
            version: 1,
            issuing_persona_id: "persona-a".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "x".into(),
                signature: "x".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };
        // github:read matches stmt_read via glob.
        let hit = resolve_statement_for_request(&grant, "github:read", "emberdotlink/ember");
        assert!(hit.is_some(), "github:read should match stmt_read");
        assert_eq!(hit.unwrap().1.sid, "S0");
        // github:push on the exact resource matches stmt_push.
        let hit =
            resolve_statement_for_request(&grant, "github:push", "emberdotlink/widgets");
        assert!(hit.is_some(), "github:push on widgets should match stmt_push");
        assert_eq!(hit.unwrap().1.sid, "S1");
        // github:push to a different repo matches nothing — read glob is
        // action=read only and push selector is exact.
        let hit = resolve_statement_for_request(&grant, "github:push", "emberdotlink/other");
        assert!(hit.is_none(), "other repo with push must have no match");
    }

    #[tokio::test]
    async fn per_statement_denies_unmatched_action() {
        // A read-scoped grant with a path-style selector. POST under
        // read action produces no applicable statement → deny.
        let state = make_state();
        let persona = state.store.create_persona("per-stmt-1").unwrap();
        state.vault.add(&state.store, "tok", b"s", None).unwrap();
        state
            .store
            .create_grant(&persona.id, "tok", "generic:read:/api/foo", None)
            .unwrap();

        let req = proxy_request_with_method_and_uri(
            "POST",
            "https://example.com/api/foo",
            Some(&persona.id),
            Some("tok"),
            Some("https://example.com"),
        );
        let resp = call(state, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "no_applicable_statement");
    }

    // ------------------------------------------------------------------
    // Stream C — per-Statement token + cent metering (P69K-C)
    // ------------------------------------------------------------------

    use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};

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
        // Issue a stub so the row exists with sensible scope. Scope of
        // `*` means the grant-level `check_scope` is a no-op; the
        // per-Statement resolution carries the real shape.
        let grant = state
            .store
            .create_grant(persona_id, credential_name, "*", None)
            .unwrap();
        let root = state.store.persona_root_keypair(persona_id).unwrap();
        let ag = crate::grant::access_grant_from_statements(
            &grant.id,
            persona_id,
            credential_name,
            statements,
            0,
            None,
            &root,
        )
        .unwrap();
        state.store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
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
        }
    }

    /// Session statement with a `tokens` budget. Uses `generic:write` so
    /// it matches Anthropic POSTs (which have action `generic:write`).
    fn stmt_session(sid: &str, tokens: u64) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: ResourceType::Session,
            actions: vec!["generic:write".into(), "generic:read".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(tokens),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
        }
    }

    fn stmt_time(sid: &str, wall_clock_secs: u64) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: ResourceType::Time,
            actions: vec!["generic:write".into(), "generic:read".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(wall_clock_secs),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
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

    /// Call helper that takes a `Full<Bytes>` body — used for tests that
    /// need a non-empty request body (preflight, metering).
    async fn call_full(
        state: Arc<ProxyState>,
        req: Request<Full<Bytes>>,
    ) -> Response<Full<Bytes>> {
        use http_body_util::combinators::UnsyncBoxBody;
        let (parts, body) = req.into_parts();
        let mapped = body.map_err(|_| -> hyper::Error {
            panic!("Full body mapper unused")
        });
        let incoming_req = Request::from_parts(parts, mapped);
        let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> =
            incoming_req.map(UnsyncBoxBody::new);
        handle_request_boxed(state, boxed).await.unwrap()
    }

    #[tokio::test]
    async fn proxy_meter_increments_tokens_on_anthropic_response() {
        let state = make_state();
        let persona = state.store.create_persona("meter-1").unwrap();
        state
            .vault
            .add(&state.store, "anthropic-key", b"sk-test", None)
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
            .query_audit(&crate::audit::AuditFilter::default())
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
            .add(&state.store, "anthropic-key", b"sk-test", None)
            .unwrap();
        // Session tokens = 10_000.
        let _grant_id = seed_composite_grant(
            &state,
            &persona.id,
            "anthropic-key",
            vec![
                stmt_credential("S0"),
                stmt_session("S1", 10_000),
            ],
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
            .query_audit(&crate::audit::AuditFilter::default())
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
            .query_audit(&crate::audit::AuditFilter::default())
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
            .add(&state.store, "anthropic-key", b"sk-test", None)
            .unwrap();
        // Budget: 10_000 tokens. Pre-seed usage = 9_500 by doing one
        // metered call first.
        let _grant_id = seed_composite_grant(
            &state,
            &persona.id,
            "anthropic-key",
            vec![
                stmt_credential("S0"),
                stmt_session("S1", 10_000),
            ],
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
        let mapped = body.map_err(|_| -> hyper::Error {
            panic!("full body error mapper unused in preflight test")
        });
        let incoming_req = Request::from_parts(parts, mapped);
        let boxed: Request<UnsyncBoxBody<Bytes, hyper::Error>> =
            incoming_req.map(UnsyncBoxBody::new);
        let resp = handle_request_boxed(Arc::clone(&state), boxed).await.unwrap();
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
            .query_audit(&crate::audit::AuditFilter::default())
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
            .add(&state.store, "anthropic-key", b"sk-test", None)
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
        let s1 = ag.statements().find(|(_, s)| s.sid == "S1").unwrap().1.clone();
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
            .add(&state.store, "anthropic-key-2", b"sk-test", None)
            .unwrap();
        let gid2 = seed_composite_grant(
            &state,
            &persona2.id,
            "anthropic-key-2",
            vec![
                stmt_credential("S0"),
                stmt_session("S1", 2_000),
            ],
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
            .query_audit(&crate::audit::AuditFilter::default())
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
            .add(&state.store, "gh-token", b"ghp_secret", None)
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
        };
        let grant_id = seed_composite_grant(
            &state,
            &persona.id,
            "gh-token",
            vec![stmt],
        );

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
        let s0 = ag.statements().find(|(_, s)| s.sid == "S0").unwrap().1.clone();
        assert_eq!(s0.usage.tokens, 0);
        assert_eq!(s0.usage.cents, 0);
        // No warnings/exhausted — statement has no budget.
        let entries = state
            .store
            .query_audit(&crate::audit::AuditFilter::default())
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
        let body = br#"{"usage": {"input_tokens": 100, "output_tokens": 200}, "model": "claude-opus-4-5"}"#;
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
            vec![
                stmt_session("S1", 1_000),
                stmt_time("S2", 3_600),
            ],
        );
        // Exhaust S1.
        state
            .store
            .increment_statement_usage(
                &grant_id,
                "S1",
                Usage { tokens: 1_500, ..Default::default() },
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
                Usage { tokens: 8_000, ..Default::default() },
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
            .query_audit(&crate::audit::AuditFilter::default())
            .unwrap();
        let count = entries
            .iter()
            .filter(|e| e.action == "budget.warning" && e.outcome == "80")
            .count();
        assert_eq!(count, 1, "warning at 80% must be emitted only once");
    }
}
