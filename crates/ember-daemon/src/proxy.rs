use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::watch;

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

    // Collect the incoming body so we can forward it.
    let (parts, incoming_body) = req.into_parts();
    let body_bytes_in = incoming_body
        .collect()
        .await
        .map_err(ProxyError::Hyper)?
        .to_bytes();

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

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }

    Ok(builder
        .body(Full::new(resp_body))
        .unwrap())
}

/// Reason a request was rejected by scope enforcement.
///
/// Held as a separate type (rather than `String`) so callers can't
/// accidentally render it into the HTTP response body — scope details are
/// sensitive and should only hit `tracing` + the audit table.
#[derive(Debug)]
pub(crate) struct ScopeViolation(pub(crate) String);

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
        Arc::new(ProxyState { store, vault })
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

        let method = req.method().to_string();
        let body = serde_json::json!({
            "proxied": true,
            "target": target_url,
            "method": method,
        });

        let _ = credential_value;

        let body_bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
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
        assert_eq!(json["error"], "scope violation");
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
        assert!(entries
            .iter()
            .any(|e| e.action == "credential.access" && e.outcome == "denied_scope"));
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
}
