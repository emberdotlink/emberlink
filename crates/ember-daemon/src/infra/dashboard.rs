use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use crate::infra::store::{DaemonStore, LiveVaultSlot};
use crate::trust::approval::ApprovalOutcome;

/// Actions hidden from the operator audit timeline by
/// default. Internal bookkeeping events (vault unseal, lifecycle plumbing)
/// leak implementation detail and clutter screenshots; the dashboard exposes
/// a `[show internal events]` toggle that re-fetches with `?include_internal=1`
/// to surface them when needed.
///
/// `is_internal_audit_action` returns true when an action is either a known
/// internal event (`vault.auto_unseal_from_keyring`) or follows the
/// `*.internal.*` namespace convention. Marker grep: `hide.*auto_unseal` /
/// `filter.*internal`.
fn is_internal_audit_action(action: &str) -> bool {
    // Known one-off internal action — vault auto-unseal at daemon startup.
    if action == "vault.auto_unseal_from_keyring" {
        return true;
    }
    // Generic `.internal.` namespace marker — any future internal lifecycle
    // event that includes a `.internal.` segment is hidden by default.
    action.contains(".internal.")
}

/// Build a `persona_id -> persona.name` map from the store. Used by the
/// dashboard JSON endpoints to surface real display names alongside the
/// raw persona id. Falls back to an empty map on
/// store error so endpoints stay live; consumers must treat missing keys
/// as "no name available" and render the id instead.
fn persona_name_map(store: &DaemonStore) -> HashMap<String, String> {
    store
        .list_personas()
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.id, p.name))
        .collect()
}

/// Default persona for the dashboard's
/// single-tenant flows (passkey enrollment, credential listing).
/// Returns the first persona ordered by `list_personas()` — the QA
/// daemon ships exactly one, so this is unambiguous; production
/// daemons with multiple personas will eventually need explicit
/// per-request scoping but that's beyond the May 3 demo.
pub(crate) fn default_persona_id(store: &DaemonStore) -> Option<String> {
    store
        .list_personas()
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|p| p.id)
}

/// Header name clients must send on state-mutating (POST) dashboard requests.
/// 69K.7: live budget gauge + pause/extend buttons + receipt viewer.
const CSRF_HEADER: &str = "X-Ember-CSRF-Token";

// The legacy `base64url_encode` helper used by
// the now-deleted `/api/webauthn/challenge` stub was removed. The
// new flow returns webauthn-rs's `CreationChallengeResponse` /
// `RequestChallengeResponse` types directly via `serde_json::to_value`,
// which carry their own base64url-encoded byte fields.

/// Generate a fresh 32-byte random CSRF token, hex-encoded. Called once per
/// dashboard startup. Returns `None` if the OS RNG fails to fill the buffer —
/// callers should refuse to start the dashboard rather than run unprotected.
fn generate_csrf_token() -> Option<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).ok()?;
    // Hex encode: 32 bytes -> 64 chars. No external dep; simple lookup.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in buf {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    Some(out)
}

/// Check whether the request carries a valid CSRF token matching `expected`.
///
/// For a localhost-only dashboard the timing-attack surface is negligible (a
/// local attacker who can measure microsecond timing can also read memory);
/// a plain `==` on two equal-length hex strings is acceptable.
fn csrf_ok(req_headers: &hyper::HeaderMap, expected: &str) -> bool {
    match req_headers.get(CSRF_HEADER) {
        Some(v) => match v.to_str() {
            Ok(s) => s == expected,
            Err(_) => false,
        },
        None => false,
    }
}

/// Loopback aliases for `expected_origin`. The dashboard binds to `127.0.0.1`
/// but the WebAuthn `rp_id` is pinned to `localhost`, so a browser that follows
/// the WebAuthn instructions sends `Origin: http://localhost:<port>` while the
/// bound address yields `http://127.0.0.1:<port>`. Both refer to the same
/// loopback socket; `WebauthnGate::new` already accepts both via
/// `WebauthnBuilder::append_allowed_origin`. Mirror that here so the HTTP
/// CSRF guard and the WebAuthn ceremony agree on what's same-origin.
fn loopback_origin_aliases(expected_origin: &str) -> Vec<String> {
    let mut aliases = vec![expected_origin.to_string()];
    if let Some(rest) = expected_origin.strip_prefix("http://127.0.0.1:") {
        aliases.push(format!("http://localhost:{rest}"));
    } else if let Some(rest) = expected_origin.strip_prefix("http://localhost:") {
        aliases.push(format!("http://127.0.0.1:{rest}"));
    }
    aliases
}

/// Defense-in-depth origin check for POST endpoints.
///
/// Reads the `Origin` header first; if present it must equal `expected_origin`
/// (or its loopback alias — see `loopback_origin_aliases`) exactly. If `Origin`
/// is absent, falls back to `Referer` — parses its URL and compares
/// scheme + host + port. If neither header is present the request is rejected
/// (403).
///
/// `expected_origin` is derived from the actual bound dashboard address at
/// startup, never from user input.
fn origin_ok(headers: &hyper::HeaderMap, expected_origin: &str) -> bool {
    let allowed = loopback_origin_aliases(expected_origin);
    // Primary: check Origin header.
    if let Some(origin_val) = headers.get("origin") {
        return match origin_val.to_str() {
            Ok(o) => allowed.iter().any(|a| a == o),
            Err(_) => false,
        };
    }
    // Fallback: parse Referer and compare scheme+host+port.
    if let Some(referer_val) = headers.get("referer")
        && let Ok(referer_str) = referer_val.to_str()
    {
        // Parse just enough: find "://" then find the next "/" after that
        // to extract the origin component.
        if let Some(after_scheme) = referer_str.find("://") {
            let rest = &referer_str[after_scheme + 3..];
            let authority_end = rest.find('/').unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            let scheme = &referer_str[..after_scheme];
            let candidate = format!("{scheme}://{authority}");
            return allowed.iter().any(|a| a == &candidate);
        }
    }
    // Neither header present — reject.
    false
}

/// Bind a TCP listener on `addr` and serve the dashboard handler until `shutdown` fires.
///
/// Opens its own read-write connection to `db_path` so it does not need to share the
/// daemon's primary `Rc<DaemonStore>`. SQLite serialises concurrent writers at the
/// library level, so dashboard writes (approve/deny/revoke) are safe alongside the
/// main daemon connection.
///
/// `vault` is the master key the main daemon already opened (via keyring auto-unseal
/// or fallback `Vault::open_from_config`). The dashboard's separate store needs the
/// same vault attached so the biometric-attested approve path can read vault-sealed
/// persona secrets when minting composite-grant chains. Before the real-biometric
/// path landed, the dashboard approve path never touched persona secrets, so the omission was
/// invisible; the WebAuthn-attested path triggers `mint_composite_chain_for_grant`
/// which reads the persona signing key. Mirrors the git-echo proxy pattern in
/// `runtime.rs`. `None` is the test-only escape hatch.
///
/// `bind_tx` is sent exactly once, immediately after the `TcpListener::bind` call, with
/// either `Ok(bound_addr)` or `Err(io_error)`. This lets callers observe the bind
/// outcome before the serve loop starts (useful for surfacing port-conflict errors to
/// the CLI banner). If `bind_tx` is `Some`, it is always consumed before returning.
///
/// If the port is already in use, a warning is logged, `bind_tx` carries the error,
/// and the function returns without starting the listener — the daemon continues
/// without the dashboard.
pub async fn run_dashboard(
    addr: SocketAddr,
    db_path: PathBuf,
    version: String,
    // The dashboard shares the daemon's
    // live-vault slot instead of owning a private `Rc<Vault>`. Explicit
    // lock can therefore cut off dashboard-side persona-secret access
    // without restarting the dashboard task.
    vault_slot: Option<LiveVaultSlot>,
    mut shutdown: watch::Receiver<bool>,
    bind_tx: Option<oneshot::Sender<Result<SocketAddr, std::io::Error>>>,
) {
    // Generate a cryptographically random CSRF token ONCE per dashboard process.
    // If the OS RNG fails (should be impossible in practice), refuse to start
    // the dashboard rather than run without CSRF protection.
    let csrf_token = match generate_csrf_token() {
        Some(t) => t,
        None => {
            tracing::warn!(
                "dashboard could not generate CSRF token from OS RNG, refusing to start"
            );
            return;
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => {
            // Resolve the actual local address (port 0 binds assign an ephemeral port).
            let local_addr = l.local_addr().unwrap_or(addr);
            if let Some(tx) = bind_tx {
                // Ignore send error — caller may have timed out and dropped the receiver.
                let _ = tx.send(Ok(local_addr));
            }
            l
        }
        Err(e) => {
            // P69E.8b: replace the opaque `AddrInUse` log with an actionable
            // hint (lsof + daemon stop commands) so the user knows what to
            // do without diffing the source. Same kind, richer message body.
            let annotated = crate::infra::socket::annotate_bind_error(e, &addr.to_string());
            tracing::warn!(addr = %addr, error = %annotated, "dashboard failed to bind, continuing without dashboard");
            if let Some(tx) = bind_tx {
                let _ = tx.send(Err(annotated));
            }
            return;
        }
    };

    // Derive the expected origin from the actual bound address (handles port 0).
    let local_addr = listener.local_addr().unwrap_or(addr);
    let expected_origin = format!("http://{local_addr}");

    // Arc<DaemonStore> is !Send because rusqlite::Connection is !Send.
    // This is intentional: the Arc is used only within the LocalSet (single thread).
    #[allow(clippy::arc_with_non_send_sync)]
    let store = match DaemonStore::open(&db_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(error = %e, "dashboard store open failed, continuing without dashboard");
            return;
        }
    };

    // Attach the same vault the main daemon
    // opened so the WebAuthn-attested approve path can read vault-sealed
    // persona secrets when minting composite chains. Pre-WebAuthn the
    // dashboard approve path never touched persona secrets, so the omission
    // was invisible; once `resolve_approval_with_biometric` triggers
    // `mint_composite_chain_for_grant` (which reads the persona signing
    // key) a missing vault surfaces as
    // `"persona '<id>' secret is vault-sealed but no vault is attached"`.
    if let Some(slot) = vault_slot {
        store.replace_vault_slot(slot);
    }

    // Build the WebAuthn relying-party gate.
    // `None` is the documented escape hatch for unit tests that
    // construct DashboardState directly; in the production daemon
    // path we always have a configured gate so the dashboard
    // approval surface is fail-closed.
    #[cfg(feature = "webauthn")]
    #[allow(clippy::arc_with_non_send_sync)]
    let webauthn = match crate::webauthn::WebauthnGate::new(&expected_origin, Arc::clone(&store)) {
        Ok(gate) => Some(Arc::new(gate)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "webauthn gate failed to initialize; dashboard approvals will refuse without bypass"
            );
            None
        }
    };
    #[cfg(not(feature = "webauthn"))]
    let webauthn: Option<()> = None;

    // Deliberately do NOT log the CSRF token. Only log that it was generated.
    tracing::info!(addr = %addr, "dashboard listening (CSRF protection enabled)");

    let started_at = std::time::Instant::now();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _peer)) => {
                        // Arc<DashboardState> is !Send — used only within the LocalSet.
                        #[allow(clippy::arc_with_non_send_sync)]
                        let state = Arc::new(DashboardState {
                            store: Arc::clone(&store),
                            version: version.clone(),
                            csrf_token: csrf_token.clone(),
                            started_at,
                            expected_origin: expected_origin.clone(),
                            // The listener
                            // is alive at this point — propagate the resolved
                            // local_addr so `/api/status` reports it instead
                            // of relying on the configured (pre-bind) port.
                            dashboard_actual_addr: Some(local_addr),
                            // Derive data_dir from
                            // db_path parent so snapshot blobs can be served.
                            data_dir: db_path.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
                            // Per-connection clone of
                            // the gate handle. Cheap (Arc bump). The gate
                            // itself owns the Webauthn config + Store ref.
                            #[cfg(feature = "webauthn")]
                            webauthn: webauthn.as_ref().map(Arc::clone),
                        });
                        let io = TokioIo::new(stream);
                        tokio::task::spawn_local(async move {
                            let svc = service_fn(move |req| {
                                let s = Arc::clone(&state);
                                async move { handle_dashboard_request(s, req).await }
                            });
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await
                            {
                                tracing::warn!(error = %e, "dashboard connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "dashboard accept error");
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
}

/// Display helper for action strings on generic grant surfaces.
///
/// Structured construct identity renders through `action_ref`; this helper is
/// only for the remaining stringly action fields on composite/legacy grant
/// surfaces. Per ADR 186 the dashboard must not synthesize flat DID-prefixed
/// action keys on read, so the string is rendered as-is.
pub fn display_action_key(action: &str) -> String {
    action.to_string()
}

mod assets;
mod spa;

use assets::PASSKEYS_SETTINGS_HTML;
pub use assets::{APPROVAL_HTML_TEMPLATE, COMPOSITE_STATEMENTS_JS, DASHBOARD_HTML};

/// Compute the ETag for the dashboard HTML using the compile-time git SHA.
/// Returns the ETag value in the form `"<sha>"` (with surrounding quotes as
/// required by RFC 7232). If `if_none_match` equals the current ETag the
/// caller should return 304 Not Modified.
fn dashboard_etag() -> &'static str {
    // Static — the ETag is fixed for the lifetime of the process (the binary
    // doesn't change at runtime). Wrapped in quotes per RFC 7232 §2.3.
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ETAG.get_or_init(|| format!("\"{}\"", env!("EMBERLINK_GIT_SHA")))
}

/// Build the correct response for a dashboard HTML request given the
/// `If-None-Match` header value from the browser.
///
/// * If `if_none_match` matches the current ETag → 304 Not Modified (no body).
/// * Otherwise → 200 OK with the full HTML body, `ETag`, and
///   `Cache-Control: no-cache` (allows the browser to cache but requires
///   revalidation before serving from cache — NOT `no-store`).
fn dashboard_etag_response(if_none_match: Option<&str>, html: String) -> Response<Full<Bytes>> {
    let etag = dashboard_etag();
    let matched = if_none_match
        .map(|v| v.trim() == etag || v.trim() == "*")
        .unwrap_or(false);
    if matched {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("etag", etag)
            .header("cache-control", "no-cache")
            .body(Full::new(Bytes::new()))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .header("etag", etag)
            .header("cache-control", "no-cache")
            .body(Full::new(Bytes::from(html)))
            .unwrap()
    }
}

pub struct DashboardState {
    pub store: Arc<DaemonStore>,
    pub version: String,
    /// Random hex-encoded CSRF token. Required on POST requests via the
    /// `X-Ember-CSRF-Token` header. Must never be logged or exposed via a
    /// read-only endpoint — it is only baked into the dashboard HTML served
    /// to the same origin, which the browser's same-origin policy protects
    /// from cross-origin reads.
    pub csrf_token: String,
    /// Monotonic instant captured once at daemon startup. Used to compute
    /// `uptime_secs` in the `/health` response. `Instant` is preferred over
    /// `SystemTime` because it is monotonic and cannot produce a negative
    /// duration due to clock skew.
    pub started_at: std::time::Instant,
    /// Expected `Origin` for POST requests (defense-in-depth).
    ///
    /// Set to `http://127.0.0.1:<port>` derived from the actual bound address
    /// at dashboard startup. Every POST handler checks that the incoming
    /// `Origin` (or `Referer` origin component) matches this value before the
    /// CSRF token check. Mismatches are rejected with 403.
    ///
    /// Defaults to `"http://127.0.0.1:3141"` for backwards-compat with tests
    /// that construct `DashboardState` without an explicit origin.
    pub expected_origin: String,
    /// The address the dashboard actually
    /// bound to, surfaced via `/api/status` as `dashboard_addr_bound`. Always
    /// `Some` when the dashboard is serving traffic (you can't reach this
    /// state otherwise) but the field is `Option<>` so test fixtures can
    /// model the "not bound" case to verify the JSON contract returns `null`.
    /// Resolved from `TcpListener::local_addr()` after a successful bind so
    /// port-0 ephemeral assignments are reflected truthfully.
    pub dashboard_actual_addr: Option<SocketAddr>,
    /// Daemon data directory — used to serve
    /// cluster-snapshot blobs from `<data_dir>/snapshots/`.
    pub data_dir: std::path::PathBuf,
    /// Server-side WebAuthn relying party.
    ///
    /// `Some` when the daemon's `webauthn` cargo feature is on AND
    /// the gate initialized successfully. The dashboard's
    /// `/api/approvals/<id>/{approve,deny}` handler routes through
    /// the gate when this is `Some`: a verified `PublicKeyCredential`
    /// is required (or `EMBER_DISABLE_BIO=1` is set) before the
    /// approval state flips. When `None` (test fixture or feature
    /// off) the handler falls back to the legacy
    /// `{biometric: bool}` body field — kept around for tests but
    /// production daemons always have `Some`.
    #[cfg(feature = "webauthn")]
    pub webauthn: Option<Arc<crate::webauthn::WebauthnGate>>,
}

pub async fn handle_dashboard_request(
    state: Arc<DashboardState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let headers = req.headers().clone();

    let resp = match (method.clone(), path.as_str()) {
        (Method::GET, "/") | (Method::GET, "/index.html") => {
            // ETag-based revalidation: the ETag is the compile-time git SHA so
            // any rebuilt binary serves a new ETag, invalidating browser caches
            // on upgrade. `Cache-Control: no-cache` (NOT `no-store`) lets the
            // browser cache the document but requires revalidation before use —
            // a 304 path avoids re-transmitting the full HTML on every load
            // while still guaranteeing staleness never survives a daemon upgrade.
            let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());
            // ADR 221 §D5: when the Warden Console SPA is embedded in this
            // binary it IS the dashboard at this origin; otherwise serve the
            // legacy hand-written HTML (zero regression on builds without a
            // frontend bundle).
            if let Some(resp) = spa::serve(path.as_str(), &state.csrf_token) {
                resp
            } else {
                let html = DASHBOARD_HTML
                    .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
                    .replace("{{CSRF_TOKEN}}", &state.csrf_token);
                dashboard_etag_response(if_none_match, html)
            }
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
            // Stringify the bound address
            // (or `null`) so the CLI `status` subcommand stops printing the
            // configured-but-not-bound port. Field shape: `Option<String>` →
            // `null` when the dashboard isn't bound, full `host:port` when it is.
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

        // GET /daemon/identity.json — publish the daemon's long-lived
        // Ed25519 identity pubkey used to sign Grant Receipts. Always
        // returns a well-shaped JSON document even if the identity is
        // not initialised (empty pubkey). Receipt verifiers should
        // cache this value as their trust anchor.
        (Method::GET, "/daemon/identity.json") | (Method::GET, "/api/daemon/identity") => {
            let (pubkey, canonical_version) = match crate::infra::receipt::current_identity() {
                Some(id) => (id.pubkey_hex(), crate::infra::receipt::CANONICAL_VERSION),
                None => (String::new(), crate::infra::receipt::CANONICAL_VERSION),
            };
            let body = serde_json::json!({
                "pubkey": pubkey,
                "algorithm": "ed25519",
                "canonical_version": canonical_version,
                "generated_at": chrono::Utc::now().timestamp(),
            });
            json_response(StatusCode::OK, &body)
        }

        // GET /api/receipts — list receipts, most-recent first.
        // Query params (all optional):
        //   view=rollup|raw   — response shape (default: rollup)
        //   signed_only=true  — exclude receipts with empty signer_pubkey
        //   persona_id=<id>   — restrict to one persona
        //   since=24h|7d|all  — lower bound on created_at (default: all)
        //   limit=N           — cap (default 100)
        //
        // AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD:
        //   ?view=rollup (default) — calls rollup_view(), returns rollup envelope
        //   ?view=raw              — original per-receipt list (backwards-compat)
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
                grant_id: None,
                kind: None,
                resource: None,
            };

            if view == "raw" {
                // ?view=raw — original per-receipt list shape (backwards-compat).
                let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
                let names = persona_name_map(&state.store);
                let body: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|r| receipt_row_raw_payload(&state.store, r, names.get(&r.actor).cloned()))
                    .filter(|r| !signed_only || r["signed"].as_bool().unwrap_or(false))
                    .collect();
                json_response(StatusCode::OK, &serde_json::Value::Array(body))
            } else {
                // ?view=rollup (default) — rollup envelope via compute_rollups.
                let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
                let body = rollup_view(&rows);
                json_response(StatusCode::OK, &body)
            }
        }

        // Server-Sent Events stream feeding the live
        // receipts panel on the dashboard. Mirrors the single-shot
        // snapshot pattern used by `/sse/grants/{id}`: emit the latest
        // 50 receipt rows as individual `data:` events, set the
        // `retry: 1000` hint so EventSource reconnects every second,
        // and let the client deduplicate by row id. This avoids the
        // long-lived streaming-body complexity that hyper 1.x's
        // `Full<Bytes>` response type would otherwise impose, while
        // still surfacing every new receipt within ~1s end-to-end —
        // ample for "this product built itself, here are the receipts."
        (Method::GET, "/api/receipts/stream") => {
            use crate::infra::receipt::ReceiptFilter;
            let filter = ReceiptFilter {
                limit: Some(50),
                ..Default::default()
            };
            let rows = state.store.list_receipt_rows(&filter).unwrap_or_default();
            let mut body = String::with_capacity(256 + rows.len() * 256);
            // EventSource reconnect hint: 1000ms — combined with the
            // single-shot snapshot this gives ~1Hz polling. The 5-minute
            // server-side timeout requested by the spec is achieved
            // implicitly: every reconnect is a fresh snapshot, so a
            // long-running tab simply keeps re-fetching without holding
            // the connection open.
            body.push_str("retry: 1000\n");
            // Oldest-first emission so the client's prepend-on-message
            // semantics leave the newest row at the top of the list.
            for r in rows.iter().rev() {
                let data = receipt_stream_payload(&state.store, r);
                let payload = serde_json::to_string(&data).unwrap_or_default();
                body.push_str("event: receipt\n");
                body.push_str("data: ");
                body.push_str(&payload);
                body.push_str("\n\n");
            }
            if rows.is_empty() {
                // Always send at least one event so EventSource transitions
                // to `open` and the client's status dot turns green.
                body.push_str("event: ping\ndata: {}\n\n");
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .header("connection", "keep-alive")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        // Cross-receipt search panel.
        // GET /api/receipts/search — query receipts by persona / scope /
        // grant_id / resource. Empty result is `[]` (200); store error
        // returns 500 with `{"error": "search failed"}`.
        //
        // Query params (all optional):
        //   persona=<persona-id>  — exact-match persona_id
        //   scope=<prefix>        — substring filter on summary.resource
        //                           (post-fetch, mirrors ReceiptFilter.resource)
        //   grant_id=<id>         — exact-match grant_id (post-fetch since
        //                           list_receipts_filtered does not bind it)
        //   resource=<prefix>     — alias for scope (kept for callers that
        //                           prefer the existing ReceiptFilter naming)
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
                grant_id: grant_id.clone(),
                kind: None,
                resource: scope.clone().or(resource.clone()),
            };
            match state.store.list_receipt_rows(&filter) {
                Err(_) => error_response(500, "search failed"),
                Ok(rows) => {
                    let names = persona_name_map(&state.store);
                    let body: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|r| {
                            receipt_row_raw_payload(&state.store, r, names.get(&r.actor).cloned())
                        })
                        .collect();
                    json_response(StatusCode::OK, &serde_json::Value::Array(body))
                }
            }
        }

        (Method::GET, "/api/personas") => {
            let personas = state.store.list_personas().unwrap_or_default();
            let body: Vec<serde_json::Value> = personas
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "id": p.id,
                        "name": p.name,
                        "public_key": p.public_key,
                        "created_at": p.created_at,
                        "status": p.status,
                    })
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/api/grants") => {
            let grants = state.store.list_active_grants().unwrap_or_default();
            // Surface persona.name alongside persona_id
            // so the dashboard can render real display names instead of UUID
            // prefixes. Lookup is rendering-layer only; raw persona_id is
            // unchanged, contract additive.
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = grants
                .iter()
                .map(|g| {
                    let mut conds = serde_json::Map::new();
                    if let Some(rate) = g.max_uses_per_hour {
                        conds.insert(
                            "rate_limit".to_string(),
                            serde_json::json!(format!("{}/hour", rate)),
                        );
                    }
                    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
                        conds.insert(
                            "time_window".to_string(),
                            serde_json::json!(format!("{}:00-{}:00 UTC", start, end)),
                        );
                    }
                    if let Some(ref targets) = g.allowed_targets {
                        // Surface allowed_targets to the UI as a real JSON
                        // array of host patterns
                        // (`allowed_targets_storage_and_parse_one_encoding`)
                        // — the stored encoding is a JSON-array string;
                        // serialising the raw string would give the UI a
                        // stringified blob and break the `length`-driven
                        // badge in `dashboard/assets.rs`.
                        let entries = core_proxy_forward::parse_allowed_targets(targets);
                        conds.insert("allowed_targets".to_string(), serde_json::json!(entries));
                    }
                    if let Some(limit) = g.spending_limit_cents {
                        conds.insert(
                            "spending_limit".to_string(),
                            serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)),
                        );
                    }
                    if let Some(depth) = g.max_delegation_depth {
                        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
                    }
                    let conditions = if conds.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::Object(conds)
                    };

                    // (budget_persists_on_simple_grant) —
                    // surface the projected budget + usage so the dashboard's
                    // BUDGET column and live gauge JS can render the operator-
                    // configured ceilings. `g.budget` projects from the signed
                    // chain's first-statement budget; `g.usage` is the running
                    // tally. Both stay omitted when no axis was set so existing
                    // consumers (and tests) see the same shape they did pre-fix.
                    // dashboard_agent_tree_view_promoted — list endpoint
                    // mirrors `grant_to_json_with_store`'s parent-persona +
                    // revoked-sids fields so the Active Agents tile can
                    // render "delegated by <parent>" + per-statement revoke
                    // without a follow-up detail fetch. The list path keeps
                    // its batch `persona_name_map` optimisation; the
                    // parent-persona lookup is per-grant (only fires when
                    // parent_grant_id is Some), so the cost is bounded by
                    // delegated-grant count not total grant count.
                    let (parent_persona_id, parent_persona_name): (Option<String>, Option<String>) =
                        match g.parent_grant_id.as_deref() {
                            Some(pgid) => match state.store.get_grant(pgid) {
                                Ok(parent_grant) => {
                                    let pname = names.get(&parent_grant.persona_id).cloned();
                                    (Some(parent_grant.persona_id), pname)
                                }
                                Err(_) => (None, None),
                            },
                            None => (None, None),
                        };
                    let revoked_sids = state.store.get_revoked_sids(&g.id).unwrap_or_default();

                    let mut entry = serde_json::Map::new();
                    entry.insert("id".into(), serde_json::json!(g.id));
                    entry.insert("persona_id".into(), serde_json::json!(g.persona_id));
                    entry.insert(
                        "persona_name".into(),
                        serde_json::json!(names.get(&g.persona_id).cloned()),
                    );
                    entry.insert(
                        "parent_persona_id".into(),
                        serde_json::json!(parent_persona_id),
                    );
                    entry.insert(
                        "parent_persona_name".into(),
                        serde_json::json!(parent_persona_name),
                    );
                    entry.insert(
                        "credential_name".into(),
                        serde_json::json!(g.credential_name),
                    );
                    entry.insert("scope".into(), serde_json::json!(g.scope));
                    entry.insert("created_at".into(), serde_json::json!(g.created_at));
                    entry.insert("expires_at".into(), serde_json::json!(g.expires_at));
                    entry.insert("status".into(), serde_json::json!(g.status));
                    entry.insert("conditions".into(), conditions);
                    entry.insert("revoked_sids".into(), serde_json::json!(revoked_sids));
                    if let Some(b) = g.budget.as_ref().filter(|b| !b.is_none_set()) {
                        entry.insert(
                            "budget".into(),
                            serde_json::to_value(b).unwrap_or(serde_json::Value::Null),
                        );
                        entry.insert(
                            "usage".into(),
                            serde_json::to_value(&g.usage).unwrap_or(serde_json::Value::Null),
                        );
                    }
                    // Emit the per-Statement
                    // array under `statements` to match `grant_to_json_with_store`
                    // (the canonical serializer used by /api/grants/all and
                    // /api/grants/{id}). Previously this list endpoint emitted
                    // the same data under `composite_statements`, forcing JS
                    // callers into `g.statements || g.composite_statements`
                    // fallbacks that cemented the divergence.
                    //
                    // Silently dropping the
                    // get_access_grant error means the dashboard rendered
                    // BUDGET=`—` for fully-valid grants whenever chain
                    // verification failed (or transiently failed during the
                    // narrow mint window before blocks_json settles). The
                    // operator spotted it: budget appeared only after pause
                    // because the next 5s loadDashboard tick re-hit the API
                    // after the chain stabilized. Log the error so the next
                    // diagnosis isn't blind.
                    let statements: serde_json::Value = match state.store.get_access_grant(&g.id) {
                        Ok(chain) => {
                            let arr: Vec<serde_json::Value> = chain
                                .statements()
                                .map(|(block_index, s)| {
                                    // Per-Statement shape mirrors
                                    // grant_to_json_with_store so the
                                    // list and detail endpoints emit
                                    // the same fields (incl. conditions).
                                    serde_json::json!({
                                        "sid": s.sid,
                                        "block_index": block_index,
                                        "resource_type": s.resource_type.as_str(),
                                        "actions": s.actions,
                                        "resource": s.resource,
                                        "budget": s.budget,
                                        "usage": s.usage,
                                        "conditions": s.conditions,
                                    })
                                })
                                .collect();
                            serde_json::Value::Array(arr)
                        }
                        Err(e) => {
                            tracing::warn!(
                                grant_id = %g.id,
                                persona_id = %g.persona_id,
                                status = %g.status,
                                error = %e,
                                "/api/grants: get_access_grant failed; \
                                 rendering empty statements array (BUDGET cell will show `—`)"
                            );
                            serde_json::Value::Array(Vec::new())
                        }
                    };
                    entry.insert("statements".into(), statements);
                    entry.insert("paused".into(), serde_json::json!(g.paused));
                    serde_json::Value::Object(entry)
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
            // `persona.name` lookup for the approval card.
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = approvals
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "persona_id": a.persona_id,
                        "persona_name": names.get(&a.persona_id).cloned(),
                        "credential_name": a.credential_name,
                        "scope": a.scope,
                        "ttl_secs": a.ttl_secs,
                        "action": a.action,
                        "risk_level": a.risk_level,
                        "status": a.status,
                        "reason": a.reason,
                        "created_at": a.created_at,
                        // Composite envelopes (sandbox-run 3-statement
                        // bundle) surface as a single approval entry whose
                        // statements array drives the per-statement card UI.
                        "composite_statements": a.composite_statements,
                        "result_grant_id": a.result_grant_id,
                        "skill_ref": a.skill_ref,
                    })
                })
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
                    // Additive `persona_name` lookup.
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
                            // Surface composite statements + minted grant ID.
                            "composite_statements": a.composite_statements,
                            "result_grant_id": a.result_grant_id,
                            "skill_ref": a.skill_ref,
                        }),
                    )
                }
                Err(_) => error_response(404, "approval not found"),
            }
        }

        (Method::GET, "/api/audit") => {
            use crate::infra::audit::AuditFilter;
            // Operator audit timeline hides internal
            // bookkeeping events (vault.auto_unseal_from_keyring + the
            // generic `*.internal.*` namespace) by default. The dashboard
            // toggle re-fetches with `?include_internal=1` so internal
            // events are reachable without hand-editing URLs.
            // `?action_filter=<prefix>` further narrows to one action family
            // (e.g. `grant.`, `approval.`, `broker.`). Both are rendering-
            // layer only — store rows are unchanged.
            //
            // Additional query params:
            //   ?persona_filter=<persona-id> — exact-match agent_id column
            //   ?scope_filter=<prefix>       — credential LIKE prefix%
            //   ?since=<unix-ms>             — inclusive lower-bound timestamp
            //   ?before=<unix-ms>            — inclusive upper-bound timestamp
            let (
                include_internal,
                action_filter,
                persona_filter,
                scope_filter,
                since_ms,
                before_ms,
            ) = req
                .uri()
                .query()
                .map(|q| {
                    let mut include = false;
                    let mut a_filter: Option<String> = None;
                    let mut p_filter: Option<String> = None;
                    let mut s_filter: Option<String> = None;
                    let mut since: Option<i64> = None;
                    let mut before: Option<i64> = None;
                    for kv in q.split('&') {
                        let mut parts = kv.splitn(2, '=');
                        let k = parts.next().unwrap_or("");
                        let v = parts.next().unwrap_or("");
                        if k == "include_internal" && (v == "1" || v == "true") {
                            include = true;
                        }
                        if k == "action_filter" && !v.is_empty() {
                            a_filter = Some(v.to_string());
                        }
                        if k == "persona_filter" && !v.is_empty() {
                            p_filter = Some(v.to_string());
                        }
                        if k == "scope_filter" && !v.is_empty() {
                            s_filter = Some(v.to_string());
                        }
                        if k == "since" && !v.is_empty() {
                            since = v.parse::<i64>().ok();
                        }
                        if k == "before" && !v.is_empty() {
                            before = v.parse::<i64>().ok();
                        }
                    }
                    (include, a_filter, p_filter, s_filter, since, before)
                })
                .unwrap_or((false, None, None, None, None, None));
            let entries = state
                .store
                .query_audit(&AuditFilter {
                    limit: Some(100),
                    action_prefix: action_filter,
                    persona_id: persona_filter,
                    scope: scope_filter,
                    since_ms,
                    before_ms,
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
                    return Ok(json_response(StatusCode::OK, &serde_json::json!([])));
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

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/revoke-statement") =>
        {
            // Per-statement revoke
            // wired through the dashboard. Body: `{"sid": "S0"}`.
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
                // Default 30-day TTL per design spec.
                // standing_grant_expires_at_capped: emit strict RFC-3339
                // (with TZ) so `create_standing_grant`'s parser accepts it.
                // 29 days keeps the value safely inside MAX_GRANT_TTL_SECS
                // (30 days) — by the time the store sees it, sub-second
                // drift from now-to-resolve would not push it past the cap.
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
                    .unwrap()
                    .to_string();
                resolve_approval_via_dashboard(
                    state,
                    req,
                    id,
                    ApprovalOutcome::Approved,
                    "approved",
                    false,
                )
                .await
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
                    .unwrap()
                    .to_string();
                resolve_approval_via_dashboard(
                    state,
                    req,
                    id,
                    ApprovalOutcome::Denied {
                        reason: "denied via dashboard".to_string(),
                    },
                    "denied",
                    false,
                )
                .await
            }
        }

        // WebAuthn registration ceremony — begin.
        //
        // Body: optional `{persona_id}`. Defaults to the daemon's
        // first persona (single-tenant local dashboard). Returns
        // `{challenge_id, options}` where `options` is the spec
        // `PublicKeyCredentialCreationOptions` JSON the browser feeds
        // to `navigator.credentials.create()`. `challenge_id` is
        // opaque to the browser — pass it back unchanged on the
        // matching `/complete` call so the daemon can re-load the
        // ceremony state.
        //
        // The ceremony state itself is persisted server-side in the
        // `webauthn_challenges` table; the browser never sees it.
        // This is what makes the gate fail-closed: a malicious
        // actor with no ceremony cannot synthesize a finish call.
        _ if method == Method::POST && path == "/api/webauthn/register/begin" => {
            #[cfg(feature = "webauthn")]
            {
                if !origin_ok(&headers, &state.expected_origin) {
                    return Ok(error_response(
                        403,
                        "origin or referer header missing or mismatched",
                    ));
                }
                if !csrf_ok(&headers, &state.csrf_token) {
                    return Ok(error_response(403, "csrf token missing or mismatched"));
                }
                let Some(gate) = state.webauthn.as_ref() else {
                    return Ok(error_response(503, "webauthn gate unavailable"));
                };
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let persona_id = match params["persona_id"].as_str() {
                    Some(p) if !p.is_empty() => p.to_string(),
                    _ => match default_persona_id(&state.store) {
                        Some(p) => p,
                        None => {
                            return Ok(error_response(409, "no persona registered yet"));
                        }
                    },
                };
                match gate.start_register(&persona_id) {
                    Ok((challenge_id, ccr)) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "challenge_id": challenge_id,
                            "persona_id": persona_id,
                            "options": ccr,
                        }),
                    ),
                    Err(e) => error_response(500, &e.to_string()),
                }
            }
            #[cfg(not(feature = "webauthn"))]
            {
                let _ = req;
                error_response(503, "webauthn feature disabled at build time")
            }
        }

        // WebAuthn registration ceremony — finish.
        //
        // Body: `{challenge_id, credential}` where `credential` is the
        // `RegisterPublicKeyCredential` JSON the browser produced from
        // `navigator.credentials.create()`. The daemon re-loads the
        // ceremony state by `challenge_id`, calls
        // `webauthn_rs::finish_passkey_registration` (origin check,
        // attestation parsing, signature check), persists the verified
        // `Passkey` in `webauthn_credentials`, and returns the
        // base64url credential id.
        _ if method == Method::POST && path == "/api/webauthn/register/complete" => {
            #[cfg(feature = "webauthn")]
            {
                if !origin_ok(&headers, &state.expected_origin) {
                    return Ok(error_response(
                        403,
                        "origin or referer header missing or mismatched",
                    ));
                }
                if !csrf_ok(&headers, &state.csrf_token) {
                    return Ok(error_response(403, "csrf token missing or mismatched"));
                }
                let Some(gate) = state.webauthn.as_ref() else {
                    return Ok(error_response(503, "webauthn gate unavailable"));
                };
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                #[derive(serde::Deserialize)]
                struct CompleteBody {
                    challenge_id: String,
                    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
                }
                let body: CompleteBody = match serde_json::from_slice(&body_bytes) {
                    Ok(b) => b,
                    Err(e) => return Ok(error_response(400, &format!("body parse: {e}"))),
                };
                match gate.finish_register(&body.challenge_id, body.credential) {
                    Ok(cred_id) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({"credential_id": cred_id}),
                    ),
                    Err(crate::webauthn::WebauthnError::UnknownChallenge)
                    | Err(crate::webauthn::WebauthnError::ChallengeMismatch) => {
                        error_response(401, "challenge expired or mismatched")
                    }
                    Err(crate::webauthn::WebauthnError::VerifyFailed(why)) => {
                        error_response(401, &format!("registration did not verify: {why}"))
                    }
                    Err(e) => error_response(500, &e.to_string()),
                }
            }
            #[cfg(not(feature = "webauthn"))]
            {
                let _ = req;
                error_response(503, "webauthn feature disabled at build time")
            }
        }

        // WebAuthn authentication ceremony — begin.
        //
        // Body: `{approval_id}`. The daemon looks up the approval to
        // determine the persona, loads that persona's enrolled
        // credentials, and starts an auth ceremony. Returns
        // `{challenge_id, options}` for `navigator.credentials.get()`.
        // The approval_id is bound into the persisted ceremony state
        // — replaying an assertion against a different approval
        // fails at finish time (`ChallengeMismatch`).
        _ if method == Method::POST && path == "/api/webauthn/auth/begin" => {
            #[cfg(feature = "webauthn")]
            {
                if !origin_ok(&headers, &state.expected_origin) {
                    return Ok(error_response(
                        403,
                        "origin or referer header missing or mismatched",
                    ));
                }
                if !csrf_ok(&headers, &state.csrf_token) {
                    return Ok(error_response(403, "csrf token missing or mismatched"));
                }
                let Some(gate) = state.webauthn.as_ref() else {
                    return Ok(error_response(503, "webauthn gate unavailable"));
                };
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let approval_id = match params["approval_id"].as_str() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => return Ok(error_response(400, "missing approval_id")),
                };
                let persona_id = match state.store.get_approval(&approval_id) {
                    Ok(info) => info.persona_id,
                    Err(_) => return Ok(error_response(404, "approval not found")),
                };
                match gate.start_auth(&persona_id, &approval_id) {
                    Ok((challenge_id, rcr)) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "challenge_id": challenge_id,
                            "options": rcr,
                        }),
                    ),
                    Err(crate::webauthn::WebauthnError::NotEnrolled) => {
                        error_response(409, "no passkey enrolled — visit /settings/passkeys")
                    }
                    Err(e) => error_response(500, &e.to_string()),
                }
            }
            #[cfg(not(feature = "webauthn"))]
            {
                let _ = req;
                error_response(503, "webauthn feature disabled at build time")
            }
        }

        // Browser-side daemon presence-token minting is intentionally disabled.
        // The shipped dashboard WebAuthn flows are passkey enrollment and
        // approval confirmation. This route previously minted a wildcard token
        // with a fake uid and a local stub signer; that misrepresented the
        // actual trust boundary, so the surface now fails closed until it can
        // bind to real runtime-backed operator state.
        _ if method == Method::POST && path == "/api/webauthn/auth/complete" => {
            let _ = req;
            if !origin_ok(&headers, &state.expected_origin) {
                error_response(403, "origin or referer header missing or mismatched")
            } else if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                webauthn_auth_complete_not_shipped_response()
            }
        }

        // List enrolled credentials for a persona.
        // Used by the `/settings/passkeys` page to render the list.
        _ if method == Method::GET && path.starts_with("/api/webauthn/credentials") => {
            #[cfg(feature = "webauthn")]
            {
                let Some(gate) = state.webauthn.as_ref() else {
                    return Ok(error_response(503, "webauthn gate unavailable"));
                };
                let query = req.uri().query().unwrap_or("");
                let persona_id = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("persona_id="))
                    .map(|s| s.to_string())
                    .or_else(|| default_persona_id(&state.store));
                let Some(persona_id) = persona_id else {
                    return Ok(error_response(409, "no persona registered yet"));
                };
                match gate.list_credential_ids(&persona_id) {
                    Ok(ids) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "persona_id": persona_id,
                            "credential_ids": ids,
                        }),
                    ),
                    Err(e) => error_response(500, &e.to_string()),
                }
            }
            #[cfg(not(feature = "webauthn"))]
            {
                let _ = req;
                error_response(503, "webauthn feature disabled at build time")
            }
        }

        // Delete an enrolled credential. Body
        // `{persona_id, credential_id}`. Used by the settings page's
        // Remove button.
        _ if method == Method::POST && path == "/api/webauthn/credentials/delete" => {
            #[cfg(feature = "webauthn")]
            {
                if !origin_ok(&headers, &state.expected_origin) {
                    return Ok(error_response(
                        403,
                        "origin or referer header missing or mismatched",
                    ));
                }
                if !csrf_ok(&headers, &state.csrf_token) {
                    return Ok(error_response(403, "csrf token missing or mismatched"));
                }
                let Some(gate) = state.webauthn.as_ref() else {
                    return Ok(error_response(503, "webauthn gate unavailable"));
                };
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let persona_id = params["persona_id"].as_str().map(|s| s.to_string());
                let credential_id = params["credential_id"].as_str().map(|s| s.to_string());
                let (Some(p), Some(c)) = (persona_id, credential_id) else {
                    return Ok(error_response(400, "missing persona_id or credential_id"));
                };
                match gate.delete_credential(&p, &c) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"deleted": true})),
                    Err(e) => error_response(500, &e.to_string()),
                }
            }
            #[cfg(not(feature = "webauthn"))]
            {
                let _ = req;
                error_response(503, "webauthn feature disabled at build time")
            }
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

        // ADR212-TELEMETRY-EXPORTER — emberd's per-process Prometheus pull
        // endpoint, mounted on this existing dashboard listener (ADR 212 §4:
        // no new listener). The registry is the process-global daemon
        // telemetry installed at startup; a scrape before that init returns
        // `503` so Prometheus records a clean "not ready" rather than an empty
        // exposition. NO central aggregation — this endpoint reports only this
        // process's series (ADR 212 §2).
        (Method::GET, "/metrics") => match crate::infra::telemetry::render_exposition() {
            Some(body) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", ember_telemetry::METRICS_CONTENT_TYPE)
                .body(Full::new(Bytes::from(body)))
                .unwrap(),
            None => error_response(503, "telemetry not initialized"),
        },

        // GET /api/cluster-snapshot/latest
        // Returns the most recent snapshot_id from the local snapshots dir.
        // The puller on the operator's daemon calls this to discover the latest
        // snapshot before fetching the full blob.
        (Method::GET, "/api/cluster-snapshot/latest") => {
            let snapshots_dir = state.data_dir.join("snapshots");
            // Find the manifest file with the newest mtime.
            match std::fs::read_dir(&snapshots_dir) {
                Err(_) => error_response(404, "no snapshots available"),
                Ok(entries) => {
                    let mut best: Option<(std::time::SystemTime, String)> = None;
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.ends_with(".manifest.json") {
                            continue;
                        }
                        // Read the manifest to get the canonical snapshot_id.
                        if let Ok(bytes) = std::fs::read(entry.path())
                            && let Ok(manifest) = serde_json::from_slice::<
                                core_grant_types::grant_receipt::SnapshotManifest,
                            >(&bytes)
                        {
                            let mtime = entry
                                .metadata()
                                .and_then(|m| m.modified())
                                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                            if best.as_ref().is_none_or(|(t, _)| mtime > *t) {
                                best = Some((mtime, manifest.snapshot_id));
                            }
                        }
                    }
                    match best {
                        None => error_response(404, "no snapshots available"),
                        Some((_, snapshot_id)) => json_response(
                            StatusCode::OK,
                            &serde_json::json!({
                                "snapshot_id": snapshot_id,
                            }),
                        ),
                    }
                }
            }
        }

        // GET /api/cluster-snapshot/{id}
        // Returns { manifest, encrypted_blob_hex } for the given snapshot_id prefix.
        // The puller fetches this after discovering the latest snapshot_id.
        _ if method == Method::GET && path.starts_with("/api/cluster-snapshot/") => {
            let id_param = path.strip_prefix("/api/cluster-snapshot/").unwrap_or("");
            if id_param.is_empty() || id_param == "latest" {
                error_response(400, "missing snapshot id")
            } else {
                // snapshot_id may be the full sha256 hex (64 chars) or a prefix.
                // Files are keyed by the first 16 chars.
                let prefix = if id_param.len() >= 16 {
                    &id_param[..16]
                } else {
                    id_param
                };
                let snapshots_dir = state.data_dir.join("snapshots");
                let manifest_path = snapshots_dir.join(format!("{prefix}.manifest.json"));
                let blob_path = snapshots_dir.join(format!("{prefix}.blob.bin"));

                match (std::fs::read(&manifest_path), std::fs::read(&blob_path)) {
                    (Ok(manifest_bytes), Ok(blob_bytes)) => {
                        match serde_json::from_slice::<serde_json::Value>(&manifest_bytes) {
                            Ok(manifest_json) => {
                                let body = serde_json::json!({
                                    "manifest": manifest_json,
                                    "encrypted_blob_hex": hex::encode(&blob_bytes),
                                });
                                json_response(StatusCode::OK, &body)
                            }
                            Err(_) => error_response(500, "corrupt snapshot manifest"),
                        }
                    }
                    _ => error_response(404, "snapshot not found"),
                }
            }
        }

        // GET /api/grants — now includes all grants (active + terminal) with budget/usage fields
        (Method::GET, "/api/grants/all") => {
            let grants = state.store.list_all_grants().unwrap_or_default();
            let body: Vec<serde_json::Value> = grants
                .iter()
                .map(|g| grant_to_json_with_store(g, &state.store))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        // GET /api/grants/{id} — single grant detail with budget/usage + statements
        _ if method == Method::GET
            && path.starts_with("/api/grants/")
            && !path.ends_with("/revoke")
            && !path.ends_with("/revoke-statement")
            && !path.ends_with("/pause")
            && !path.ends_with("/unpause")
            && !path.ends_with("/extend") =>
        {
            let id = path.strip_prefix("/api/grants/").unwrap_or("");
            if id.is_empty() {
                error_response(400, "missing grant id")
            } else {
                match state.store.get_grant(id) {
                    Ok(g) => {
                        json_response(StatusCode::OK, &grant_to_json_with_store(&g, &state.store))
                    }
                    Err(_) => error_response(404, "grant not found"),
                }
            }
        }

        // POST /api/grants/{id}/pause  — hard pause: sets status='paused', proxy rejects
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

        // POST /api/grants/{id}/unpause — resumes a paused grant
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

        // POST /api/grants/{id}/extend  — extend budget and/or TTL
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

                // Read body bytes then parse JSON
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let tokens_delta = params["tokens_delta"].as_u64();
                let cents_delta = params["cents_delta"].as_u64();
                let ttl_extension_secs = params["ttl_extension_secs"].as_u64();

                match state
                    .store
                    .extend_grant(id, tokens_delta, cents_delta, ttl_extension_secs)
                {
                    Ok(g) => json_response(StatusCode::OK, &grant_to_json(&g)),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // POST /api/approvals/{id}/dismiss — stale-approval cleanup.
        // Operator-initiated dismiss. Sets status to 'dismissed', records
        // `approval.dismissed` audit event, removes the card from the dashboard.
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

        // GET /grants/{id} — HTML grant-detail page with Pause/Extend buttons.
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
                        let revoked_sids = state.store.get_revoked_sids(&g.id).unwrap_or_default();
                        let html = build_grant_detail_html_with_revoked(
                            &g,
                            &state.csrf_token,
                            chain.as_ref(),
                            &revoked_sids,
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
                            "<!DOCTYPE html><html><head><title>ember</title></head><body style=\"font-family:monospace;background:#0a0a0f;color:#6b6b7b;display:flex;align-items:center;justify-content:center;height:100vh;margin:0\"><p>Grant not found. <a href=\"/\" style=\"color:#e85d26\">Back to dashboard</a></p></body></html>",
                        )))
                        .unwrap(),
                }
            }
        }

        // GET /receipts/{id} — Grant Receipt viewer.
        //
        // `id` may be either a receipt id (`rct-…`) or a grant id (back-
        // compat for dashboard links that point at the grant row). When
        // the id resolves to a persisted signed receipt we return it
        // verbatim; otherwise we fall back to the unsigned draft view
        // of the grant row so active grants remain viewable.
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

            // Fast path: signed receipt by receipt id.
            if let Ok(signed) = state.store.get_receipt(id) {
                if want_json {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header(
                            "content-disposition",
                            format!("attachment; filename=\"{id}.json\""),
                        )
                        .body(Full::new(Bytes::from(
                            serde_json::to_vec_pretty(&signed).unwrap_or_default(),
                        )))
                        .unwrap());
                }
                let html = build_signed_receipt_html(&signed);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(html)))
                    .unwrap());
            }

            // Next: signed v2 receipt by receipt id.
            if let Ok(raw) = state.store.get_receipt_v2_envelope_json(id)
                && let Ok(envelope) =
                    serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
            {
                if want_json {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header(
                            "content-disposition",
                            format!("attachment; filename=\"{id}.json\""),
                        )
                        .body(Full::new(Bytes::from(raw)))
                        .unwrap());
                }
                let html = build_signed_receipt_v2_html(&envelope, None);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(html)))
                    .unwrap());
            }

            // Next: by grant id — fetch the grant's linked receipt if any.
            let grant_result = state.store.get_grant(id);
            if let Ok(g) = grant_result {
                if let Some(rid) = g.receipt_id.as_deref()
                    && let Ok(signed) = state.store.get_receipt(rid)
                {
                    if want_json {
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .header(
                                "content-disposition",
                                format!("attachment; filename=\"{rid}.json\""),
                            )
                            .body(Full::new(Bytes::from(
                                serde_json::to_vec_pretty(&signed).unwrap_or_default(),
                            )))
                            .unwrap());
                    }
                    let html = build_signed_receipt_html(&signed);
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap());
                }
                if let Ok(mut v2_receipts) = state
                    .store
                    .list_receipts_v2_envelopes(std::slice::from_ref(&g.id))
                    && let Some((rid, _kind, grant_id, envelope)) = v2_receipts.pop()
                {
                    if want_json {
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .header(
                                "content-disposition",
                                format!("attachment; filename=\"{rid}.json\""),
                            )
                            .body(Full::new(Bytes::from(
                                serde_json::to_vec_pretty(&envelope).unwrap_or_default(),
                            )))
                            .unwrap());
                    }
                    let html = build_signed_receipt_v2_html(&envelope, Some(&grant_id));
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(html)))
                        .unwrap());
                }
                // Fall back to legacy draft view for grants without a receipt.
                if want_json {
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
            } else {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(
                        "<!DOCTYPE html><html><head><title>ember</title></head><body style=\"font-family:monospace;background:#0a0a0f;color:#6b6b7b;display:flex;align-items:center;justify-content:center;height:100vh;margin:0\"><p>Receipt not found. <a href=\"/\" style=\"color:#e85d26\">Back to dashboard</a></p></body></html>",
                    )))
                    .unwrap()
            }
        }

        // GET /sse/grants/{id} — Server-Sent Events stream for live budget gauge
        (Method::GET, p) if p.starts_with("/sse/grants/") => {
            let grant_id = p.strip_prefix("/sse/grants/").unwrap_or("").to_string();
            if grant_id.is_empty() {
                return Ok(error_response(400, "missing grant id"));
            }
            // Verify grant exists
            if state.store.get_grant(&grant_id).is_err() {
                return Ok(error_response(404, "grant not found"));
            }
            // Build SSE response: send a snapshot now, then poll every 500ms
            // For this implementation we return a single snapshot as an SSE event.
            // A production impl would use a long-lived streaming body; hyper 1.x
            // requires an async body type which adds complexity. We use a simpler
            // approach: emit events for the current state as a complete SSE response,
            // and let the client reconnect on EventSource's automatic retry timer.
            let grant = state.store.get_grant(&grant_id).unwrap_or_else(|_| {
                // should not happen — we checked above
                unreachable!()
            });
            let data = serde_json::to_string(&grant_to_json(&grant)).unwrap_or_default();
            let event_type = if grant.status != "active" {
                "grant_terminated"
            } else if grant.paused {
                "paused"
            } else if let Some(bt) = grant.budget.as_ref().and_then(|b| b.tokens) {
                let tokens_used = grant.usage.tokens;
                let pct = tokens_used * 100 / bt.max(1);
                if pct >= 100 {
                    "budget_exhausted"
                } else if pct >= 95 {
                    "budget_warning"
                } else {
                    "usage_update"
                }
            } else {
                "usage_update"
            };
            // retry: 5000ms — client will reconnect after 5 seconds
            let body = format!("retry: 5000\nevent: {event_type}\ndata: {data}\n\n");
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .header("connection", "keep-alive")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
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
                        "<!DOCTYPE html><html><head><title>ember</title></head><body style=\"font-family:monospace;background:#0a0a0f;color:#6b6b7b;display:flex;align-items:center;justify-content:center;height:100vh;margin:0\"><p>Approval not found or already resolved. <a href=\"/\" style=\"color:#e85d26\">Back to dashboard</a></p></body></html>",
                    )))
                    .unwrap(),
            }
        }

        // First-run passkey enrollment page.
        // Explains how to register the operator's platform authenticator
        // (Touch ID on macOS, Windows Hello on Windows) so the dashboard
        // Approve button raises the OS biometric sheet.
        (Method::GET, "/settings/passkeys") => {
            // Substitute the per-process CSRF token
            // so the page can issue authenticated POSTs to
            // /api/webauthn/{register,credentials/delete}.
            let html = PASSKEYS_SETTINGS_HTML.replace("{{CSRF_TOKEN}}", &state.csrf_token);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap()
        }

        // ADR 221 §D5: any other GET is a Warden Console SPA asset or a
        // client-side route. `spa::serve` returns the embedded asset (or
        // index.html for extensionless routes), and `None` for `/api`/`/sse`,
        // a concrete missing file, or when no SPA is embedded → 404 below.
        _ if method == Method::GET => {
            match spa::serve(path.as_str(), &state.csrf_token) {
                Some(resp) => resp,
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("content-type", "text/plain")
                    .body(Full::new(Bytes::from("not found")))
                    .unwrap(),
            }
        }

        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    };

    Ok(resp)
}

/// Serialize a `GrantInfo` to the JSON shape used by dashboard API endpoints.
///
/// TODO: this function and its siblings (grant_to_json,
/// build_receipt_json, and the inline lambdas at lines ~4192/4200/4562) all take
/// &GrantInfo because the dashboard needs credential_name, scope (String),
/// created_at, expires_at (String), status, paused, max_uses_per_hour, etc.
/// Migrate to walk AccessGrant.blocks[].statements[] natively once the scalar
/// columns are dropped from the SQLite schema.
///
/// Post-composite-port (ADR 073): emits a `statements` array with per-
/// Statement `sid`, `resource_type`, `actions`, `resource`, `budget`, and
/// `usage`. Dashboard / receipt views render per-Statement meters from
/// this field — there is no envelope-level `budget`/`usage` projection
/// under the V0 schema.
fn grant_to_json_with_store(
    g: &crate::trust::grant::GrantInfo,
    store: &crate::infra::store::DaemonStore,
) -> serde_json::Value {
    let mut conds = serde_json::Map::new();
    if let Some(rate) = g.max_uses_per_hour {
        conds.insert(
            "rate_limit".to_string(),
            serde_json::json!(format!("{}/hour", rate)),
        );
    }
    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
        conds.insert(
            "time_window".to_string(),
            serde_json::json!(format!("{}:00-{}:00 UTC", start, end)),
        );
    }
    if let Some(ref targets) = g.allowed_targets {
        // See `allowed_targets_storage_and_parse_one_encoding` — surface as
        // a real array, not the raw JSON-encoded string.
        let entries = core_proxy_forward::parse_allowed_targets(targets);
        conds.insert("allowed_targets".to_string(), serde_json::json!(entries));
    }
    if let Some(limit) = g.spending_limit_cents {
        conds.insert(
            "spending_limit".to_string(),
            serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)),
        );
    }
    if let Some(depth) = g.max_delegation_depth {
        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
    }
    let conditions = if conds.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(conds)
    };

    let statements: serde_json::Value = match store.get_access_grant(&g.id) {
        Ok(chain) => {
            let arr: Vec<serde_json::Value> = chain
                .statements()
                .map(|(block_index, s)| {
                    serde_json::json!({
                        "sid": s.sid,
                        "block_index": block_index,
                        "resource_type": s.resource_type.as_str(),
                        "actions": s.actions,
                        "resource": s.resource,
                        "budget": s.budget,
                        "usage": s.usage,
                        "conditions": s.conditions,
                    })
                })
                .collect();
            serde_json::Value::Array(arr)
        }
        Err(e) => {
            tracing::warn!(
                grant_id = %g.id,
                persona_id = %g.persona_id,
                status = %g.status,
                error = %e,
                "grant_to_json_with_store: get_access_grant failed; \
                 rendering empty statements array"
            );
            serde_json::Value::Array(Vec::new())
        }
    };

    // Additive `persona_name` lookup so the dashboard
    // can render the persona's display name as the primary label.
    let persona_name = store.get_persona(&g.persona_id).ok().map(|p| p.name);

    // dashboard_agent_tree_view_promoted
    // Slice A (backend). Surface parent persona id+name when this grant was
    // minted via delegate (g.parent_grant_id is Some). The Active Agents
    // tile renders "delegated by <parent_alias>" above the credential list.
    // When parent_grant_id is None (root grant), both fields stay null.
    let (parent_persona_id, parent_persona_name): (Option<String>, Option<String>) =
        match g.parent_grant_id.as_deref() {
            Some(pgid) => match store.get_grant(pgid) {
                Ok(parent_grant) => {
                    let pname = store
                        .get_persona(&parent_grant.persona_id)
                        .ok()
                        .map(|p| p.name);
                    (Some(parent_grant.persona_id), pname)
                }
                Err(_) => (None, None),
            },
            None => (None, None),
        };

    // Surface seconds-remaining
    // alongside the absolute timestamp so the dashboard JS can render a
    // tick-down counter without re-parsing RFC3339 in every browser.
    // `null` when the grant has no TTL or the timestamp is unparseable.
    let expires_in_secs: Option<i64> = g.expires_at.as_deref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| (dt.timestamp() - chrono::Utc::now().timestamp()).max(0))
    });

    let revoked_sids = store.get_revoked_sids(&g.id).unwrap_or_default();

    serde_json::json!({
        "id": g.id,
        "persona_id": g.persona_id,
        "persona_name": persona_name,
        "parent_persona_id": parent_persona_id,
        "parent_persona_name": parent_persona_name,
        "credential_name": g.credential_name,
        "scope": g.scope,
        "created_at": g.created_at,
        "expires_at": g.expires_at,
        "expires_in_secs": expires_in_secs,
        "status": g.status,
        "conditions": conditions,
        "statements": statements,
        "revoked_sids": revoked_sids,
        "paused": g.paused,
        "receipt_id": g.receipt_id,
    })
}

/// Back-compat shim for callers that don't need the `statements` array.
/// Forwards to `grant_to_json_with_store` but omits the array.
fn grant_to_json(g: &crate::trust::grant::GrantInfo) -> serde_json::Value {
    let mut conds = serde_json::Map::new();
    if let Some(rate) = g.max_uses_per_hour {
        conds.insert(
            "rate_limit".to_string(),
            serde_json::json!(format!("{}/hour", rate)),
        );
    }
    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
        conds.insert(
            "time_window".to_string(),
            serde_json::json!(format!("{}:00-{}:00 UTC", start, end)),
        );
    }
    if let Some(ref targets) = g.allowed_targets {
        // See `allowed_targets_storage_and_parse_one_encoding` — surface as
        // a real array, not the raw JSON-encoded string.
        let entries = core_proxy_forward::parse_allowed_targets(targets);
        conds.insert("allowed_targets".to_string(), serde_json::json!(entries));
    }
    if let Some(limit) = g.spending_limit_cents {
        conds.insert(
            "spending_limit".to_string(),
            serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)),
        );
    }
    if let Some(depth) = g.max_delegation_depth {
        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
    }
    let conditions = if conds.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(conds)
    };
    serde_json::json!({
        "id": g.id,
        "persona_id": g.persona_id,
        "credential_name": g.credential_name,
        "scope": g.scope,
        "created_at": g.created_at,
        "expires_at": g.expires_at,
        "status": g.status,
        "conditions": conditions,
        "paused": g.paused,
        "receipt_id": g.receipt_id,
    })
}

/// Render a persisted, Ed25519-signed `GrantReceipt` as HTML.
///
/// Presents the receipt as a read-only artifact: chain snapshot, per-
/// Statement usage, approval chain, actions observed, lifecycle, and
/// evidence block. A download button serves the verbatim signed JSON.
fn build_signed_receipt_html(r: &core_grant_types::grant_receipt::GrantReceipt) -> String {
    let json = serde_json::to_string_pretty(r).unwrap_or_default();
    let escaped = json.replace('<', "&lt;").replace('>', "&gt;");
    let terminal = &r.lifecycle.terminal_reason;
    let reason_label = match terminal {
        core_grant_types::grant_receipt::TerminalReason::Expired => "expired".to_string(),
        core_grant_types::grant_receipt::TerminalReason::Revoked { by, reason } => {
            let actor = match by {
                core_grant_types::grant_receipt::RevokeActor::Operator => "operator",
                core_grant_types::grant_receipt::RevokeActor::Agent => "agent",
                core_grant_types::grant_receipt::RevokeActor::ParentCascade => "parent cascade",
            };
            if reason.is_empty() {
                format!("revoked by {actor}")
            } else {
                format!("revoked by {actor}: {reason}")
            }
        }
        core_grant_types::grant_receipt::TerminalReason::Abandoned { reason } => {
            if reason.is_empty() {
                "abandoned".to_string()
            } else {
                format!("abandoned: {reason}")
            }
        }
        core_grant_types::grant_receipt::TerminalReason::ExhaustedByBudget {
            statement_sid,
            axis,
        } => format!("exhausted_by_budget on {statement_sid} ({axis:?})"),
        core_grant_types::grant_receipt::TerminalReason::ParentCascadeRevoked {
            parent_grant_id,
        } => format!("parent_cascade_revoked from {parent_grant_id}"),
    };

    let statements_rows: String = r
        .per_statement_usage
        .iter()
        .map(|(sid, u)| {
            format!(
                r#"<tr><td>{sid}</td><td>{} tokens</td><td>{} cents</td><td>{} req</td><td>{} s</td></tr>"#,
                u.tokens, u.cents, u.requests, u.wall_clock_secs
            )
        })
        .collect();
    let statements_table = if statements_rows.is_empty() {
        "<p style=\"color:var(--text-muted);font-size:12px\">No statements recorded.</p>"
            .to_string()
    } else {
        format!(
            r#"<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr style="color:var(--text-muted);text-align:left"><th>SID</th><th>Tokens</th><th>Cents</th><th>Requests</th><th>Wall-clock</th></tr></thead><tbody>{statements_rows}</tbody></table>"#
        )
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember · grant receipt</title>
<style>
:root{{--bg-primary:#0a0a0f;--bg-card:#12121a;--bg-hover:#1a1a2a;--accent:#e85d26;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--border:#1e1e2e;--success:#22c55e;--danger:#ef4444}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'JetBrains Mono',ui-monospace,monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px}}
a{{color:var(--accent);text-decoration:none}}
#header{{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card)}}
#header .logo{{font-size:20px;font-weight:700;color:var(--accent)}}
main{{padding:20px 24px;max-width:960px;margin:0 auto}}
.card{{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
.card-title{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:14px}}
.field{{display:flex;justify-content:space-between;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)}}
.field:last-child{{border-bottom:none}}
.field-label{{color:var(--text-muted);font-size:11px}}
.field-val{{color:var(--text-primary);font-size:12px;text-align:right;word-break:break-all;max-width:65%}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;background:rgba(239,68,68,.15);color:var(--danger)}}
pre{{background:var(--bg-hover);border:1px solid var(--border);border-radius:6px;padding:14px;overflow-x:auto;font-size:11px;white-space:pre-wrap;word-break:break-all}}
.btn{{display:inline-flex;align-items:center;padding:6px 14px;border-radius:4px;font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:rgba(107,107,123,.15);color:var(--text-muted);text-decoration:none}}
.btn:hover{{opacity:.8}}
.actions{{display:flex;gap:8px;margin-top:14px}}
table td,table th{{padding:6px 10px;border-bottom:1px solid var(--border)}}
/* DEMO-MAY3-IDENTITY-ANCHOR: Signed-by card. Foreground treatment for
   the trust anchor — this is the moment the viewer's eye is on the
   receipt artifact, perfect time to bind pubkey↔receipt visually. */
.signed-block{{padding:16px 18px;background:rgba(232,93,38,.05);border:1px solid rgba(232,93,38,.22);border-radius:6px;margin-bottom:14px}}
.signed-fingerprint{{font-size:18px;font-weight:600;color:var(--accent);letter-spacing:1px;margin-bottom:10px;font-family:'JetBrains Mono',ui-monospace,monospace}}
.signed-pubkey-row{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.signed-pubkey-full{{flex:1;color:var(--text-muted);font-size:11px;word-break:break-all;font-family:'JetBrains Mono',ui-monospace,monospace;line-height:1.5}}
.btn-copy{{padding:5px 12px;border-radius:4px;border:1px solid var(--border);background:rgba(107,107,123,.15);color:var(--text-primary);font-family:inherit;font-size:10px;font-weight:600;cursor:pointer;text-transform:uppercase;letter-spacing:.6px;flex-shrink:0;transition:background .15s ease-out,color .15s ease-out,border-color .15s ease-out}}
.btn-copy:hover{{background:rgba(232,93,38,.15);color:var(--accent);border-color:rgba(232,93,38,.4)}}
.btn-copy.copied{{background:rgba(34,197,94,.15);color:var(--success);border-color:rgba(34,197,94,.4)}}
.signed-helper{{color:var(--text-dim);font-size:11px;line-height:1.55}}
.signed-helper code{{color:var(--text-muted);background:var(--bg-hover);padding:2px 6px;border-radius:3px;font-size:10px;font-family:'JetBrains Mono',ui-monospace,monospace}}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
</div>
<main>
  <div style="margin-bottom:16px">
    <span style="font-size:18px;font-weight:700">Grant Receipt</span>
    <span class="badge" style="margin-left:10px">{reason_label}</span>
  </div>

  <div class="card">
    <div class="card-title">Summary</div>
    <div class="field"><span class="field-label">Receipt ID</span><span class="field-val">{receipt_id}</span></div>
    <div class="field"><span class="field-label">Grant ID</span><span class="field-val">{grant_id}</span></div>
    <div class="field"><span class="field-label">Persona</span><span class="field-val">{persona}</span></div>
    <div class="field"><span class="field-label">Human owner</span><span class="field-val">{owner}</span></div>
    <div class="field"><span class="field-label">Service</span><span class="field-val">{service}</span></div>
    <div class="field"><span class="field-label">Resource</span><span class="field-val">{resource}</span></div>
  </div>

  <div class="card">
    <div class="card-title">Lifecycle</div>
    <div class="field"><span class="field-label">Issued</span><span class="field-val">epoch {issued}</span></div>
    <div class="field"><span class="field-label">Last used</span><span class="field-val">{last_used}</span></div>
    <div class="field"><span class="field-label">Terminated</span><span class="field-val">epoch {terminated}</span></div>
    <div class="field"><span class="field-label">Terminal reason</span><span class="field-val">{reason_label}</span></div>
  </div>

  <div class="card">
    <div class="card-title">Per-Statement usage</div>
    {statements_table}
  </div>

  <div class="card">
    <div class="card-title">Signed by</div>
    <div class="signed-block">
      <div class="signed-fingerprint">{signer_fingerprint}</div>
      <div class="signed-pubkey-row">
        <code class="signed-pubkey-full" id="signed-pubkey-full">{signer_pubkey}</code>
        <button class="btn-copy" id="copy-pubkey-btn" data-pubkey="{signer_pubkey}" type="button">Copy</button>
      </div>
      <div class="signed-helper">Pass this pubkey to <code>ember receipt verify --file &lt;path&gt; --pubkey &lt;hex&gt;</code> to verify offline. The daemon does not need to be running.</div>
    </div>
    <div class="field"><span class="field-label">Algorithm</span><span class="field-val">Ed25519</span></div>
    <div class="field"><span class="field-label">Hash</span><span class="field-val">{hash}</span></div>
    <div class="field"><span class="field-label">Signature</span><span class="field-val">{sig}</span></div>
    <div class="field"><span class="field-label">Canonical version</span><span class="field-val">v{canonical}</span></div>
  </div>

  <div class="card">
    <div class="card-title">Raw Signed JSON</div>
    <pre>{escaped}</pre>
  </div>

  <div class="actions">
    <a href="/receipts/{receipt_id}?format=json" class="btn">Download JSON</a>
    <a href="/" class="btn">Back</a>
  </div>
</main>
<script>
(function(){{
  var btn = document.getElementById('copy-pubkey-btn');
  if(!btn) return;
  btn.addEventListener('click', async function(){{
    var pk = btn.dataset.pubkey || '';
    if(!pk) return;
    try{{
      await navigator.clipboard.writeText(pk);
      var orig = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      setTimeout(function(){{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1400);
    }}catch(e){{
      console.warn('clipboard write failed:', e);
      btn.textContent = 'Copy failed';
      setTimeout(function(){{ btn.textContent = 'Copy'; }}, 1400);
    }}
  }});
}})();
</script>
</body>
</html>"#,
        reason_label = reason_label,
        receipt_id = r.id,
        grant_id = r.grant_id,
        persona = r.summary.persona_id,
        owner = r.summary.human_owner,
        service = r.summary.service,
        resource = r.summary.resource,
        issued = r.lifecycle.issued_at,
        last_used = r
            .lifecycle
            .last_used_at
            .map(|t| format!("epoch {t}"))
            .unwrap_or_else(|| "—".into()),
        terminated = r.lifecycle.terminated_at,
        statements_table = statements_table,
        signer_pubkey = r.evidence.signer_pubkey,
        signer_fingerprint = pubkey_fingerprint(&r.evidence.signer_pubkey),
        hash = r.evidence.hash,
        sig = r.evidence.sig,
        canonical = r.evidence.canonical_version,
        escaped = escaped,
    )
}

/// HTML-entity escaper for agent/external-controlled values substituted into
/// server-rendered dashboard HTML (escapes `& < > " '`, covering text and
/// quoted-attribute contexts). Hoisted to module scope so every `render_*`
/// page can use it; the signed-receipt and approval renderers both rely on it.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn build_signed_receipt_v2_html(
    envelope: &core_events::receipt::ReceiptEnvelope,
    grant_id_hint: Option<&str>,
) -> String {
    fn normalize_terminal_reason_label(raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return "-".to_string();
        }
        let cleaned = trimmed
            .replace('_', " ")
            .chars()
            .enumerate()
            .flat_map(|(idx, ch)| {
                if idx > 0 && ch.is_uppercase() {
                    vec![' ', ch]
                } else {
                    vec![ch]
                }
            })
            .collect::<String>()
            .split_whitespace()
            .map(|word| word.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        match cleaned.as_str() {
            "exhausted by budget" => "budget exhausted".to_string(),
            "parent cascade revoked" => "parent revoked".to_string(),
            _ => cleaned,
        }
    }

    let escaped = escape_html(&serde_json::to_string_pretty(envelope).unwrap_or_default());
    let delegation_template = envelope
        .body
        .get("delegation_template")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let terminal_reason = envelope
        .body
        .get("termination_reason")
        .and_then(|v| v.as_str())
        .map(normalize_terminal_reason_label)
        .unwrap_or_else(|| "-".to_string());
    let claim_count_total = envelope
        .body
        .get("claim_count_total")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let claim_segment_count = envelope
        .body
        .get("claim_segment_summaries")
        .and_then(|v| v.as_array())
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "-".to_string());
    let truncated = envelope
        .body
        .get("claim_events_truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let claim_history_merkle_root = envelope
        .body
        .get("claim_history_merkle_root")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let receipt_id = escape_html(&envelope.receipt_id);
    let grant_id = escape_html(grant_id_hint.unwrap_or("-"));
    let signature = escape_html(envelope.signature.as_deref().unwrap_or("-"));
    let body_claim_events = envelope
        .body
        .get("claim_events")
        .and_then(|v| v.as_array())
        .map(|v| v.len().to_string())
        .unwrap_or_else(|| "0".to_string());
    let title = if envelope.kind.starts_with("session.") {
        "Session Receipt"
    } else {
        "Receipt v2"
    };
    let kind = escape_html(&envelope.kind);
    let delegation_template = escape_html(delegation_template);
    let terminal_reason = escape_html(&terminal_reason);
    let termination_authority = escape_html(
        &serde_json::to_string(&envelope.termination_authority)
            .unwrap_or_else(|_| "\"unknown\"".to_string()),
    );
    let claim_count_total = escape_html(&claim_count_total);
    let claim_segment_count = escape_html(&claim_segment_count);
    let claim_history_merkle_root = escape_html(claim_history_merkle_root);
    let daemon_root_id = escape_html(&envelope.daemon_root_id);
    format!(
        r#"<!DOCTYPE html>
<html><head><title>ember</title><meta charset="utf-8">
<style>
body{{background:#0a0a0f;color:#f5f5f7;font-family:'JetBrains Mono',ui-monospace,monospace;margin:0}}
#header{{padding:28px 36px 0}}
.logo{{color:#e85d26;text-decoration:none;font-size:42px;font-weight:700}}
main{{max-width:1100px;margin:24px auto 48px;padding:0 28px}}
.card{{background:#12131a;border:1px solid rgba(107,107,123,.28);border-radius:10px;padding:18px 20px;margin-bottom:16px}}
.card-title{{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:#8f90a6;margin-bottom:12px}}
.field{{display:flex;gap:18px;padding:6px 0;border-bottom:1px solid rgba(107,107,123,.16)}}
.field:last-child{{border-bottom:none}}
.field-label{{width:220px;color:#8f90a6;flex-shrink:0}}
.field-val{{color:#f5f5f7;word-break:break-all}}
.badge{{display:inline-block;padding:6px 10px;border-radius:999px;background:rgba(232,93,38,.12);border:1px solid rgba(232,93,38,.28);color:#ff9468;font-size:11px;text-transform:uppercase;letter-spacing:.8px}}
.btn{{display:inline-block;padding:8px 14px;border-radius:6px;background:#e85d26;color:#fff;text-decoration:none;margin-right:8px}}
pre{{white-space:pre-wrap;word-break:break-word;color:#d8d8df}}
</style></head>
<body>
<div id="header"><a class="logo" href="/">ember</a></div>
<main>
  <div style="margin-bottom:16px">
    <span style="font-size:18px;font-weight:700">{title}</span>
    <span class="badge" style="margin-left:10px">{kind}</span>
  </div>
  <div class="card">
    <div class="card-title">Summary</div>
    <div class="field"><span class="field-label">Receipt ID</span><span class="field-val">{receipt_id}</span></div>
    <div class="field"><span class="field-label">Grant ID</span><span class="field-val">{grant_id}</span></div>
    <div class="field"><span class="field-label">Delegation template</span><span class="field-val">{delegation_template}</span></div>
    <div class="field"><span class="field-label">Termination reason</span><span class="field-val">{terminal_reason}</span></div>
    <div class="field"><span class="field-label">Termination authority</span><span class="field-val">{termination_authority}</span></div>
  </div>
  <div class="card">
    <div class="card-title">Claim Rollup</div>
    <div class="field"><span class="field-label">Inline claim events</span><span class="field-val">{body_claim_events}</span></div>
    <div class="field"><span class="field-label">Claim count total</span><span class="field-val">{claim_count_total}</span></div>
    <div class="field"><span class="field-label">Claim segment count</span><span class="field-val">{claim_segment_count}</span></div>
    <div class="field"><span class="field-label">Truncated tail</span><span class="field-val">{truncated}</span></div>
    <div class="field"><span class="field-label">Claim history Merkle root</span><span class="field-val">{claim_history_merkle_root}</span></div>
  </div>
  <div class="card">
    <div class="card-title">Signature</div>
    <div class="field"><span class="field-label">Daemon root id</span><span class="field-val">{daemon_root_id}</span></div>
    <div class="field"><span class="field-label">Signature</span><span class="field-val">{signature}</span></div>
  </div>
  <div class="card">
    <div class="card-title">Raw Signed JSON</div>
    <pre>{escaped}</pre>
  </div>
  <div><a href="/receipts/{receipt_id}?format=json" class="btn">Download JSON</a><a href="/" class="btn">Back</a></div>
</main></body></html>"#,
        title = title,
        kind = kind,
        receipt_id = receipt_id,
        grant_id = grant_id,
        delegation_template = delegation_template,
        terminal_reason = terminal_reason,
        termination_authority = termination_authority,
        body_claim_events = body_claim_events,
        claim_count_total = claim_count_total,
        claim_segment_count = claim_segment_count,
        truncated = truncated,
        claim_history_merkle_root = claim_history_merkle_root,
        daemon_root_id = daemon_root_id,
        signature = signature,
        escaped = escaped,
    )
}

fn receipt_stream_payload(
    store: &DaemonStore,
    row: &crate::infra::receipt::ReceiptRow,
) -> serde_json::Value {
    let mut data = serde_json::json!({
        "id": row.id,
        "kind": row.kind,
        "actor": row.actor,
        "resource": row.resource,
        "grant_id": row.grant_id,
        "materialized_at": row.materialized_at,
        "terminal_reason": row.terminal_reason,
        "claim_count_total": serde_json::Value::Null,
        "claim_events_truncated": false,
        "claim_segment_count": serde_json::Value::Null,
        "claim_history_merkle_root": serde_json::Value::Null,
    });
    if row.kind.contains('.')
        && let Ok(raw) = store.get_receipt_v2_envelope_json(&row.id)
        && let Ok(envelope) = serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
    {
        data["claim_count_total"] = envelope
            .body
            .get("claim_count_total")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        data["claim_events_truncated"] = serde_json::json!(
            envelope
                .body
                .get("claim_events_truncated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        );
        data["claim_segment_count"] = serde_json::json!(
            envelope
                .body
                .get("claim_segment_summaries")
                .and_then(|v| v.as_array())
                .map(|v| v.len())
        );
        data["claim_history_merkle_root"] = envelope
            .body
            .get("claim_history_merkle_root")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
    }
    data
}

fn receipt_row_raw_payload(
    store: &DaemonStore,
    row: &crate::infra::receipt::ReceiptRow,
    persona_name: Option<String>,
) -> serde_json::Value {
    let mut signed = false;
    let mut claim_count_total = serde_json::Value::Null;
    let mut claim_events_truncated = serde_json::Value::Bool(false);
    let mut claim_segment_count = serde_json::Value::Null;
    let mut claim_history_merkle_root = serde_json::Value::Null;

    if row.kind.contains('.') {
        if let Ok(raw) = store.get_receipt_v2_envelope_json(&row.id)
            && let Ok(envelope) =
                serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
        {
            signed = envelope
                .signature
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            claim_count_total = envelope
                .body
                .get("claim_count_total")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            claim_events_truncated = serde_json::json!(
                envelope
                    .body
                    .get("claim_events_truncated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            );
            claim_segment_count = serde_json::json!(
                envelope
                    .body
                    .get("claim_segment_summaries")
                    .and_then(|v| v.as_array())
                    .map(|v| v.len())
            );
            claim_history_merkle_root = envelope
                .body
                .get("claim_history_merkle_root")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
        }
    } else if row.kind == "grant" {
        if let Ok(receipt) = store.get_receipt(&row.id) {
            signed = receipt.evidence.signer_pubkey != "0".repeat(64)
                && receipt.evidence.sig != "0".repeat(128)
                && !receipt.evidence.signer_pubkey.is_empty();
        }
    } else {
        signed = true;
    }

    let action_summary = receipt_row_action_summary(row);
    let created_at_epoch = chrono::DateTime::parse_from_rfc3339(&row.materialized_at)
        .ok()
        .map(|dt| dt.timestamp())
        .unwrap_or_default();

    serde_json::json!({
        "id": row.id,
        "kind": row.kind,
        "grant_id": row.grant_id,
        "persona_id": row.actor,
        "persona_name": persona_name,
        "action_ref": row.action_ref,
        "action_summary": action_summary,
        "contract_id": row.contract_id,
        "workspace_ref": row.workspace_ref,
        "caller_ref": row.caller_ref,
        "authority_ref": row.authority_ref,
        "terminal_reason": row.terminal_reason,
        "created_at_epoch": created_at_epoch,
        "signed": signed,
        "claim_count_total": claim_count_total,
        "claim_events_truncated": claim_events_truncated,
        "claim_segment_count": claim_segment_count,
        "claim_history_merkle_root": claim_history_merkle_root,
    })
}

/// Render a 64-hex Ed25519 pubkey as a
/// short SSH-style fingerprint (`4a5d:a587:dd36:53b2`) using the first
/// 8 bytes / 16 hex chars. Decorative only — the full pubkey is the
/// actual trust anchor. Returns `—` for placeholder / empty inputs so
/// the receipt detail page never renders a half-formed string.
fn pubkey_fingerprint(pubkey_hex: &str) -> String {
    let trimmed = pubkey_hex.trim();
    if trimmed.len() < 16 || trimmed.chars().all(|c| c == '0') {
        return "—".to_string();
    }
    let head = &trimmed[..16];
    let mut out = String::with_capacity(19);
    for (i, ch) in head.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(':');
        }
        out.push(ch);
    }
    out
}

/// Build the signed-receipt JSON for a grant (for download / display).
fn build_receipt_json(g: &crate::trust::grant::GrantInfo) -> serde_json::Value {
    let terminal = matches!(
        g.status.as_str(),
        "revoked" | "abandoned" | "expired" | "expired_by_budget" | "parent_cascade_revoked"
    );
    serde_json::json!({
        "grant_receipt": {
            "id": g.receipt_id.as_deref().unwrap_or(&format!("receipt-{}", g.id)),
            "grant_id": g.id,
            "persona_id": g.persona_id,
            "credential": g.credential_name,
            "scope": g.scope,
            "budget": g.budget,
            "usage": g.usage,
            "lifecycle": {
                "issued_at": g.created_at,
                "expired_at": if terminal { g.expires_at.as_deref() } else { None },
                "terminal_status": g.status,
            },
            "evidence": {
                "signed": false,
                "note": "append-only audit log — cryptographic signing Phase 2"
            }
        }
    })
}

/// Render per-Statement gauge cards for a composite grant chain.
///
/// For each statement, renders: SID header, resource_type + actions summary,
/// and one progress bar per budget axis that has a limit set. Statements with
/// no budget show an "unbounded" note.
///
/// Pure function of the statement slice — testable without a running server.
/// Per-Statement gauges with an
/// inline "Revoke" button per row. `revoked_sids` is the slice of sids that
/// have already been revoked (struck through, button hidden). Wires to
/// `POST /api/grants/{id}/revoke-statement` via the page's JS handler.
// Terminal grants suppress per-Statement Revoke
pub(crate) fn render_statement_gauges_with_revoke(
    grant_id: &str,
    statements: &[(usize, &core_grant_types::Statement)],
    revoked_sids: &[String],
    is_terminal: bool,
) -> String {
    if statements.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (block_idx, stmt) in statements {
        let is_revoked = revoked_sids.iter().any(|s| s == &stmt.sid);
        // Stringly statement actions are still rendered directly here; the
        // structured construct path uses `action_ref` on the receipt/rollup
        // surfaces instead of synthesizing flat keys.
        let actions: Vec<String> = stmt.actions.iter().map(|a| display_action_key(a)).collect();
        let actions_str = if actions.is_empty() {
            "—".to_string()
        } else {
            actions.join(", ")
        };
        let row_style = if is_revoked {
            "border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px;opacity:.55;text-decoration:line-through"
        } else {
            "border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px"
        };
        out.push_str(&format!(r#"<div style="{row_style}">"#));
        let revoke_btn = if is_revoked {
            r#"<span style="font-size:11px;color:var(--danger);font-weight:600;text-decoration:none">REVOKED</span>"#.to_string()
        } else if is_terminal {
            // Grant has reached a terminal state — per-statement revoke is meaningless.
            r#"<span style="font-size:11px;color:var(--text-muted);font-weight:600">FINAL</span>"#
                .to_string()
        } else {
            format!(
                r#"<button class="btn btn-danger" style="padding:2px 8px;font-size:10px" data-revoke-sid="{sid}" data-grant-id="{gid}">Revoke</button>"#,
                sid = stmt.sid,
                gid = grant_id,
            )
        };
        out.push_str(&format!(
            r#"<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:12px;font-weight:600;color:var(--text-primary)">{sid}</span><span style="display:flex;align-items:center;gap:10px"><span style="font-size:11px;color:var(--text-muted)">block {block_idx} · {rt} · {actions_str}</span>{revoke_btn}</span></div>"#,
            sid = stmt.sid,
            rt = stmt.resource_type.as_str(),
        ));
        let has_budget = stmt
            .budget
            .as_ref()
            .map(|b| !b.is_none_set())
            .unwrap_or(false);
        if !has_budget {
            out.push_str(r#"<div style="color:var(--text-dim);font-size:12px">unbounded</div>"#);
        } else if let Some(b) = &stmt.budget {
            let u = &stmt.usage;
            if let Some(cap) = b.tokens {
                let pct = (u.tokens * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>tokens</span><span>{used} / {cap} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.tokens,
                ));
            }
            if let Some(cap) = b.cents {
                let pct = (u.cents * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                let used_fmt = format!("${:.2}", u.cents as f64 / 100.0);
                let cap_fmt = format!("${:.2}", cap as f64 / 100.0);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>cost</span><span>{used_fmt} / {cap_fmt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                ));
            }
            if let Some(cap) = b.requests {
                let pct = (u.requests * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>requests</span><span>{used} / {cap} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.requests,
                ));
            }
            if let Some(cap) = b.wall_clock_secs {
                let pct = (u.wall_clock_secs * 100)
                    .checked_div(cap)
                    .unwrap_or(100)
                    .min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>wall-clock</span><span>{used}s / {cap}s ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.wall_clock_secs,
                ));
            }
        }
        out.push_str("</div>");
    }
    out
}

pub(crate) fn render_statement_gauges(
    statements: &[(usize, &core_grant_types::Statement)],
) -> String {
    if statements.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (block_idx, stmt) in statements {
        // Keep generic statement actions honest on read; do not synthesize
        // flat DID-prefixed keys for operator display.
        let actions: Vec<String> = stmt.actions.iter().map(|a| display_action_key(a)).collect();
        let actions_str = if actions.is_empty() {
            "—".to_string()
        } else {
            actions.join(", ")
        };
        out.push_str(r#"<div style="border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:12px">"#);
        out.push_str(&format!(
            r#"<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:12px;font-weight:600;color:var(--text-primary)">{sid}</span><span style="font-size:11px;color:var(--text-muted)">block {block_idx} · {rt} · {actions_str}</span></div>"#,
            sid = stmt.sid,
            rt = stmt.resource_type.as_str(),
        ));
        let has_budget = stmt
            .budget
            .as_ref()
            .map(|b| !b.is_none_set())
            .unwrap_or(false);
        if !has_budget {
            out.push_str(r#"<div style="color:var(--text-dim);font-size:12px">unbounded</div>"#);
        } else if let Some(b) = &stmt.budget {
            let u = &stmt.usage;
            if let Some(cap) = b.tokens {
                let pct = (u.tokens * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>tokens</span><span>{used} / {cap} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.tokens,
                ));
            }
            if let Some(cap) = b.cents {
                let pct = (u.cents * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                let used_fmt = format!("${:.2}", u.cents as f64 / 100.0);
                let cap_fmt = format!("${:.2}", cap as f64 / 100.0);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>cost</span><span>{used_fmt} / {cap_fmt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                ));
            }
            if let Some(cap) = b.requests {
                let pct = (u.requests * 100).checked_div(cap).unwrap_or(100).min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>requests</span><span>{used} / {cap} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.requests,
                ));
            }
            if let Some(cap) = b.wall_clock_secs {
                let pct = (u.wall_clock_secs * 100)
                    .checked_div(cap)
                    .unwrap_or(100)
                    .min(100);
                let color = gauge_color(pct);
                out.push_str(&format!(
                    r#"<div class="gauge-label"><span>wall-clock</span><span>{used}s / {cap}s ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
                    used = u.wall_clock_secs,
                ));
            }
        }
        out.push_str("</div>");
    }
    out
}

#[inline]
fn gauge_color(pct: u64) -> &'static str {
    if pct >= 95 {
        "var(--danger)"
    } else if pct >= 80 {
        "var(--warning)"
    } else {
        "var(--success)"
    }
}

/// Render the `/grants/{id}` HTML detail page.
///
/// Shows grant metadata, per-Statement budget gauges, and action buttons:
/// Pause (or Resume if already paused), Extend, Revoke, View Receipt.
/// Terminal grants show a read-only view with only the receipt link.
#[allow(dead_code)]
fn build_grant_detail_html(
    g: &crate::trust::grant::GrantInfo,
    csrf_token: &str,
    access_grant: Option<&core_grant_types::AccessGrant>,
) -> String {
    build_grant_detail_html_with_revoked(g, csrf_token, access_grant, &[])
}

fn build_grant_detail_html_with_revoked(
    g: &crate::trust::grant::GrantInfo,
    csrf_token: &str,
    access_grant: Option<&core_grant_types::AccessGrant>,
    revoked_sids: &[String],
) -> String {
    let status_class = match g.status.as_str() {
        "active" => "active",
        "paused" => "paused",
        "revoked" | "abandoned" | "parent_cascade_revoked" => "revoked",
        "expired" | "expired_by_budget" | "exhausted_by_budget" => "revoked",
        _ => "pending",
    };

    let is_terminal = matches!(
        g.status.as_str(),
        "revoked"
            | "abandoned"
            | "expired"
            | "expired_by_budget"
            | "exhausted_by_budget"
            | "parent_cascade_revoked"
    );

    let budget_section = if let Some(chain) = access_grant {
        let stmts: Vec<(usize, &core_grant_types::Statement)> = chain.statements().collect();
        let gauges = render_statement_gauges_with_revoke(&g.id, &stmts, revoked_sids, is_terminal);
        if gauges.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="card"><div class="card-title">Statements &amp; Budget</div>{gauges}</div>"#
            )
        }
    } else {
        String::new()
    };

    let paused_badge = if g.paused || g.status == "paused" {
        r#"<span class="paused-badge">paused</span>"#
    } else {
        ""
    };

    let action_buttons = if is_terminal {
        format!(
            r#"<a href="/receipts/{id}" class="btn btn-neutral">View Receipt</a>
<a href="/" class="btn btn-neutral">Back</a>"#,
            id = g.id,
        )
    } else if g.status == "paused" {
        format!(
            r#"<form method="POST" action="/grants/{id}/unpause" style="display:inline">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="btn btn-warn" onclick="return confirm('Resume this grant?')">Resume</button>
</form>
<button class="btn btn-neutral" onclick="openExtend('{id}')">Extend</button>
<form method="POST" action="/grants/{id}/revoke" style="display:inline">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="btn btn-danger" onclick="return confirm('Revoke this grant? This cannot be undone.')">Revoke</button>
</form>
<a href="/" class="btn btn-neutral">Back</a>"#,
            id = g.id,
            csrf = csrf_token,
        )
    } else {
        format!(
            r#"<form method="POST" action="/grants/{id}/pause" style="display:inline">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="btn btn-warn" onclick="return confirm('Pause this grant? Proxy requests will be rejected until resumed.')">Pause</button>
</form>
<button class="btn btn-neutral" onclick="openExtend('{id}')">Extend</button>
<form method="POST" action="/grants/{id}/revoke" style="display:inline">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" class="btn btn-danger" onclick="return confirm('Revoke this grant? This cannot be undone.')">Revoke</button>
</form>
<a href="/receipts/{id}" class="btn btn-neutral">Receipt</a>
<a href="/" class="btn btn-neutral">Back</a>"#,
            id = g.id,
            csrf = csrf_token,
        )
    };

    // The Pause/Resume/Revoke buttons use form POSTs. The server reads the
    // CSRF token from the `X-Ember-CSRF-Token` header (set via JS on the
    // dashboard main page). For the detail page, we use a fetch()-based JS
    // wrapper for CSRF-sensitive actions to keep the header protocol
    // consistent with the main dashboard. The form `action` attributes are
    // used as the URL targets; JS intercepts submit events.
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember · grant {id}</title>
<style>
:root{{--bg-primary:#0a0a0f;--bg-card:#12121a;--bg-hover:#1a1a2a;--accent:#e85d26;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--text-dim:#3a3a4a;--border:#1e1e2e;--success:#22c55e;--warning:#eab308;--danger:#ef4444}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'JetBrains Mono',ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px}}
a{{color:var(--accent);text-decoration:none}}
#header{{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card)}}
#header .logo{{font-size:20px;font-weight:700;color:var(--accent)}}
#header .nav{{display:flex;gap:16px;align-items:center;color:var(--text-muted);font-size:12px}}
main{{padding:20px 24px;max-width:900px;margin:0 auto}}
.card{{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
.card-title{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:14px}}
.field{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)}}
.field:last-child{{border-bottom:none;margin-bottom:0;padding-bottom:0}}
.field-label{{color:var(--text-muted);font-size:11px}}
.field-val{{color:var(--text-primary);font-size:12px;text-align:right;word-break:break-all;max-width:65%}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.badge.active{{background:rgba(34,197,94,.15);color:var(--success)}}
.badge.paused{{background:rgba(234,179,8,.15);color:var(--warning)}}
.badge.revoked{{background:rgba(239,68,68,.15);color:var(--danger)}}
.badge.pending{{background:rgba(234,179,8,.15);color:var(--warning)}}
.paused-badge{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;background:rgba(234,179,8,.15);color:var(--warning);border:1px solid rgba(234,179,8,.3);margin-left:8px}}
.gauge-label{{display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;margin-top:10px}}
.gauge-track{{width:100%;height:6px;background:var(--bg-hover);border-radius:3px;overflow:hidden}}
.gauge-fill{{height:100%;border-radius:3px;transition:width .3s}}
.btn{{display:inline-flex;align-items:center;padding:6px 14px;border-radius:4px;font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:opacity .1s;text-decoration:none}}
.btn:hover{{opacity:.8}}
.btn-danger{{background:rgba(239,68,68,.15);color:var(--danger);border-color:rgba(239,68,68,.3)}}
.btn-warn{{background:rgba(234,179,8,.15);color:var(--warning);border-color:rgba(234,179,8,.3)}}
.btn-neutral{{background:rgba(107,107,123,.15);color:var(--text-muted);border-color:var(--border)}}
.btn-success{{background:rgba(34,197,94,.15);color:var(--success);border-color:rgba(34,197,94,.3)}}
.actions{{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}}
.modal-overlay{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}}
.modal-overlay.open{{display:flex}}
.modal{{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:24px;width:380px;max-width:95vw}}
.modal-title{{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:16px}}
.modal-field{{margin-bottom:12px}}
.modal-field label{{display:block;font-size:11px;color:var(--text-muted);margin-bottom:4px}}
.modal-field input{{width:100%;background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text-primary);font-family:inherit;font-size:12px}}
.modal-field input:focus{{outline:none;border-color:var(--accent)}}
.quick-picks{{display:flex;gap:6px;margin-top:6px}}
.quick-pick{{padding:3px 8px;border-radius:3px;font-family:inherit;font-size:10px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg-hover);color:var(--text-muted)}}
.quick-pick:hover{{border-color:var(--accent);color:var(--accent)}}
.modal-actions{{display:flex;gap:8px;margin-top:16px}}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
</div>
<main>
  <div style="margin-bottom:16px;display:flex;align-items:center;gap:10px">
    <span style="font-size:18px;font-weight:700;color:var(--text-primary)">Grant Detail</span>
    <span class="badge {status_class}">{status}</span>
    {paused_badge}
  </div>

  <div class="card">
    <div class="card-title">Grant Details</div>
    <div class="field"><span class="field-label">Grant ID</span><span class="field-val">{id}</span></div>
    <div class="field"><span class="field-label">Persona</span><span class="field-val">{persona_id}</span></div>
    <div class="field"><span class="field-label">Credential</span><span class="field-val">{credential_name}</span></div>
    <div class="field"><span class="field-label">Scope</span><span class="field-val">{scope}</span></div>
    <div class="field"><span class="field-label">Issued</span><span class="field-val">{created_at}</span></div>
    <div class="field"><span class="field-label">Expires</span><span class="field-val"><span id="expires-at-abs">{expires_at}</span><span id="expires-at-tick" style="margin-left:8px;font-size:11px;color:var(--text-muted)"></span></span></div>
    <div class="field"><span class="field-label">Status</span><span class="field-val"><span class="badge {status_class}">{status}</span></span></div>
    {parent_row}
  </div>

  {budget_section}

  <div class="card">
    <div class="card-title">Actions</div>
    <div class="actions">{action_buttons}</div>
  </div>
</main>

<div class="modal-overlay" id="extend-modal">
  <div class="modal">
    <div class="modal-title">Extend Grant</div>
    <div class="modal-field">
      <label>Additional Tokens</label>
      <input type="number" id="extend-tokens" min="0" placeholder="e.g. 10000">
    </div>
    <div class="modal-field">
      <label>Additional Budget (USD)</label>
      <input type="number" id="extend-cents-usd" min="0" step="0.01" placeholder="e.g. 0.50">
    </div>
    <div class="modal-field">
      <label>TTL Extension</label>
      <input type="number" id="extend-ttl-secs" min="0" placeholder="seconds">
      <div class="quick-picks">
        <button class="quick-pick" onclick="setTTL(900)">15m</button>
        <button class="quick-pick" onclick="setTTL(3600)">1h</button>
        <button class="quick-pick" onclick="setTTL(86400)">24h</button>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-success" onclick="submitExtend()">Extend</button>
      <button class="btn btn-neutral" onclick="closeExtend()">Cancel</button>
    </div>
  </div>
</div>
<script>
const CSRF_TOKEN="{csrf_token}";
const GRANT_ID="{id}";
const CSRF_HEADERS={{'X-Ember-CSRF-Token':CSRF_TOKEN}};
function openExtend(){{document.getElementById('extend-modal').classList.add('open');}}
function closeExtend(){{document.getElementById('extend-modal').classList.remove('open');}}
function setTTL(s){{document.getElementById('extend-ttl-secs').value=s;}}
async function submitExtend(){{
  const tokens=parseInt(document.getElementById('extend-tokens').value)||undefined;
  const centsUsd=parseFloat(document.getElementById('extend-cents-usd').value);
  const cents=isNaN(centsUsd)?undefined:Math.round(centsUsd*100);
  const ttl=parseInt(document.getElementById('extend-ttl-secs').value)||undefined;
  const body={{}};
  if(tokens)body.tokens_delta=tokens;
  if(cents)body.cents_delta=cents;
  if(ttl)body.ttl_extension_secs=ttl;
  const resp=await fetch(`/api/grants/${{GRANT_ID}}/extend`,{{method:'POST',headers:{{...CSRF_HEADERS,'content-type':'application/json'}},body:JSON.stringify(body)}});
  closeExtend();
  if(!resp.ok){{const e=await resp.json().catch(()=>({{error:'failed'}}));alert('Extend failed: '+(e.error||resp.status));}}
  else{{window.location.reload();}}
}}
document.querySelectorAll('form[action$="/pause"],form[action$="/unpause"],form[action$="/revoke"]').forEach(form=>{{
  form.addEventListener('submit',async e=>{{
    e.preventDefault();
    if(!confirm(form.querySelector('button[type=submit]')?.title||'Confirm?'))return;
    const resp=await fetch(form.action,{{method:'POST',headers:CSRF_HEADERS}});
    if(resp.ok){{window.location.href='/';}}
    else{{const err=await resp.json().catch(()=>({{error:'request failed'}}));alert('Error: '+(err.error||resp.status));}}
  }});
}});

// DEMO-MAY3-COMPOSITE-DASHBOARD-COUNTDOWN — per-statement revoke buttons.
document.querySelectorAll('button[data-revoke-sid]').forEach(btn=>{{
  btn.addEventListener('click',async e=>{{
    e.preventDefault();
    const sid=btn.getAttribute('data-revoke-sid');
    const gid=btn.getAttribute('data-grant-id');
    if(!confirm(`Revoke statement ${{sid}}? Other statements on this grant will keep working.`))return;
    const resp=await fetch(`/api/grants/${{gid}}/revoke-statement`,{{
      method:'POST',
      headers:{{...CSRF_HEADERS,'content-type':'application/json'}},
      body:JSON.stringify({{sid}}),
    }});
    if(resp.ok){{window.location.reload();}}
    else{{const err=await resp.json().catch(()=>({{error:'request failed'}}));alert('Error: '+(err.error||resp.status));}}
  }});
}});

// DEMO-MAY3-COMPOSITE-DASHBOARD-COUNTDOWN — live tick-down. Computes
// time-remaining from `expires_at` once per second; flips the status
// badge to EXPIRED at the boundary. The server-side `expire_stale_grants`
// sweep is the source of truth for the audit `grant.expired` event;
// the JS tick is purely cosmetic.
const EXPIRES_AT_RAW="{expires_at_raw}";
function renderTimeRemaining(){{
  if(!EXPIRES_AT_RAW||EXPIRES_AT_RAW==="never"){{return;}}
  const target=Date.parse(EXPIRES_AT_RAW);
  if(isNaN(target))return;
  const now=Date.now();
  const remaining=Math.max(0,Math.floor((target-now)/1000));
  const tickEl=document.getElementById('expires-at-tick');
  if(!tickEl)return;
  if(remaining<=0){{
    tickEl.textContent='(EXPIRED)';
    tickEl.style.color='var(--danger)';
    // Best-effort badge swap on the page header.
    document.querySelectorAll('.badge.active').forEach(b=>{{b.classList.remove('active');b.classList.add('revoked');b.textContent='expired';}});
    return;
  }}
  const h=Math.floor(remaining/3600);
  const m=Math.floor((remaining%3600)/60);
  const s=remaining%60;
  let txt;
  if(h>0)txt=`(${{h}}h ${{m}}m ${{s}}s)`;
  else if(m>0)txt=`(${{m}}m ${{s}}s)`;
  else txt=`(${{s}}s)`;
  tickEl.textContent=txt;
}}
renderTimeRemaining();
setInterval(renderTimeRemaining,1000);

// grant detail page uses /sse/grants/{id} not setInterval(tickUsageGauges)
//
// Subscribe to the SSE stream for live per-statement gauge updates.
// Mirrors the summary page connectSSE pattern (sseConnections keyed by
// grant id). Drops the former /api/grants/{id} poll every 2s.
//
// ARCH-RECEIPT-WALL-CLOCK-USAGE: wall-clock gauge reads server-computed
// usage.wall_clock_secs from SSE events; tickWallClockGauge removed.
// ARCH-DASHBOARD-API-FIELD-PARITY — statements array name is canonical.
function applyUsageGauges(stmts){{
  if(!Array.isArray(stmts))return;
  document.querySelectorAll('span').forEach(sidSpan=>{{
    const sid=sidSpan.textContent.trim();
    if(!/^s\d+-/.test(sid))return;
    const card=sidSpan.closest('div[style*="border-radius"]');
    if(!card)return;
    const stmt=stmts.find(s=>s.sid===sid);
    if(!stmt||!stmt.budget||!stmt.usage)return;
    card.querySelectorAll('.gauge-label').forEach(label=>{{
      const spans=label.querySelectorAll('span');
      if(spans.length<2)return;
      const axis=spans[0].textContent;
      let used,cap,txt,pct;
      if(axis==='tokens'&&stmt.budget.tokens!=null){{
        used=stmt.usage.tokens||0; cap=stmt.budget.tokens;
        pct=Math.min(100,Math.round((used*100)/cap));
        txt=`${{used}} / ${{cap}} (${{pct}}%)`;
      }}else if(axis==='cost'&&stmt.budget.cents!=null){{
        used=stmt.usage.cents||0; cap=stmt.budget.cents;
        pct=Math.min(100,Math.round((used*100)/cap));
        const uf='$'+(used/100).toFixed(2); const cf='$'+(cap/100).toFixed(2);
        txt=`${{uf}} / ${{cf}} (${{pct}}%)`;
      }}else if(axis==='wall-clock'&&stmt.budget.wall_clock_secs!=null){{
        used=stmt.usage.wall_clock_secs||0; cap=stmt.budget.wall_clock_secs;
        pct=Math.min(100,Math.round((used*100)/cap));
        txt=`${{used}}s / ${{cap}}s (${{pct}}%)`;
      }}else return;
      spans[1].textContent=txt;
      const track=label.nextElementSibling;
      if(!track||!track.classList.contains('gauge-track'))return;
      const fill=track.querySelector('.gauge-fill');
      if(!fill)return;
      fill.style.width=pct+'%';
      const color=pct>=95?'var(--danger)':pct>=80?'var(--warning)':'var(--success)';
      fill.style.background=color;
    }});
  }});
}}
(function(){{
  const es=new EventSource(`/sse/grants/${{GRANT_ID}}`);
  function onUsage(e){{
    try{{
      const g=JSON.parse(e.data);
      if(g&&g.statements)applyUsageGauges(g.statements);
    }}catch(_){{}}
  }}
  es.addEventListener('usage_update',onUsage);
  es.addEventListener('budget_warning',onUsage);
  es.addEventListener('budget_exhausted',e=>{{
    onUsage(e);
    es.close();
    // Reload so the status badge reflects budget-exhausted state.
    setTimeout(()=>window.location.reload(),500);
  }});
  es.addEventListener('grant_terminated',()=>{{
    es.close();
    setTimeout(()=>window.location.reload(),500);
  }});
  es.onerror=()=>es.close();
  window.addEventListener('unload',()=>es.close());
}})();
</script>
</body>
</html>"#,
        id = g.id,
        persona_id = truncate_persona_id(&g.persona_id),
        credential_name = g.credential_name,
        scope = g.scope,
        created_at = g.created_at,
        expires_at = g.expires_at.as_deref().unwrap_or("never"),
        expires_at_raw = g.expires_at.as_deref().unwrap_or("never"),
        status = g.status,
        status_class = status_class,
        paused_badge = paused_badge,
        budget_section = budget_section,
        action_buttons = action_buttons,
        csrf_token = csrf_token,
        parent_row = g.parent_grant_id.as_deref().map(|pid| format!(
            r#"<div class="field"><span class="field-label">Parent Grant</span><span class="field-val"><a href="/grants/{pid}">{pid}</a></span></div>"#
        )).unwrap_or_default(),
    )
}

fn build_receipt_html(
    g: &crate::trust::grant::GrantInfo,
    _csrf_token: &str,
    access_grant: Option<&core_grant_types::AccessGrant>,
) -> String {
    let receipt_json = serde_json::to_string_pretty(&build_receipt_json(g)).unwrap_or_default();

    // Per-Statement gauges (composite path) — preferred when the chain is available.
    let budget_section = if let Some(chain) = access_grant {
        let stmts: Vec<(usize, &core_grant_types::Statement)> = chain.statements().collect();
        let gauges = render_statement_gauges(&stmts);
        format!(
            r#"<div class="card"><div class="card-title">Statements &amp; Budget</div>{gauges}</div>"#
        )
    } else {
        // Legacy fallback: single aggregate gauge from GrantInfo scalar columns.
        let budget_tokens = g.budget.as_ref().and_then(|b| b.tokens);
        let budget_cents = g.budget.as_ref().and_then(|b| b.cents);
        let tokens_used = g.usage.tokens;
        let cents_used = g.usage.cents;
        let token_pct =
            budget_tokens.map(|bt| (tokens_used * 100).checked_div(bt).unwrap_or(100u64));
        let cents_pct = budget_cents.map(|bc| (cents_used * 100).checked_div(bc).unwrap_or(100u64));
        let token_gauge = if let (Some(bt), Some(pct)) = (budget_tokens, token_pct) {
            let color = gauge_color(pct);
            format!(
                r#"<div class="gauge-label"><span>Tokens</span><span>{tokens_used} / {bt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#
            )
        } else {
            String::new()
        };
        let cents_gauge = if let (Some(bc), Some(pct)) = (budget_cents, cents_pct) {
            let color = gauge_color(pct);
            let used_fmt = format!("${:.2}", cents_used as f64 / 100.0);
            let budget_fmt = format!("${:.2}", bc as f64 / 100.0);
            format!(
                r#"<div class="gauge-label"><span>Cost</span><span>{used_fmt} / {budget_fmt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#
            )
        } else {
            String::new()
        };
        let no_budget_msg = if budget_tokens.is_none() && budget_cents.is_none() {
            r#"<div style="color:var(--text-dim);font-size:12px;padding:8px 0">No budget set (TTL-only grant)</div>"#
        } else {
            ""
        };
        format!(
            r#"<div class="card"><div class="card-title">Budget &amp; Usage</div>{token_gauge}{cents_gauge}{no_budget_msg}</div>"#
        )
    };

    let status_class = match g.status.as_str() {
        "active" => "active",
        "revoked" | "abandoned" | "parent_cascade_revoked" => "revoked",
        "expired" | "expired_by_budget" => "revoked",
        _ => "pending",
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember · grant receipt</title>
<style>
:root{{--bg-primary:#0a0a0f;--bg-card:#12121a;--bg-hover:#1a1a2a;--accent:#e85d26;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--text-dim:#3a3a4a;--border:#1e1e2e;--success:#22c55e;--warning:#eab308;--danger:#ef4444}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'JetBrains Mono',ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px}}
a{{color:var(--accent);text-decoration:none}}
#header{{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card)}}
#header .logo{{font-size:20px;font-weight:700;color:var(--accent)}}
#header .nav{{display:flex;gap:16px;align-items:center;color:var(--text-muted);font-size:12px}}
main{{padding:20px 24px;max-width:900px;margin:0 auto}}
.card{{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}}
.card-title{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:14px}}
.field{{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)}}
.field:last-child{{border-bottom:none;margin-bottom:0;padding-bottom:0}}
.field-label{{color:var(--text-muted);font-size:11px}}
.field-val{{color:var(--text-primary);font-size:12px;text-align:right;word-break:break-all;max-width:65%}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
.badge.active{{background:rgba(34,197,94,.15);color:var(--success)}}
.badge.revoked{{background:rgba(239,68,68,.15);color:var(--danger)}}
.badge.pending{{background:rgba(234,179,8,.15);color:var(--warning)}}
.gauge-label{{display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:4px;margin-top:10px}}
.gauge-track{{width:100%;height:6px;background:var(--bg-hover);border-radius:3px;overflow:hidden}}
.gauge-fill{{height:100%;border-radius:3px;transition:width .3s}}
.tabs{{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px}}
.tab{{padding:8px 16px;font-size:11px;text-transform:uppercase;letter-spacing:.6px;cursor:pointer;border-bottom:2px solid transparent;color:var(--text-muted);background:none;border-top:none;border-left:none;border-right:none;font-family:inherit}}
.tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.tab-panel{{display:none}}.tab-panel.active{{display:block}}
pre{{background:var(--bg-hover);border:1px solid var(--border);border-radius:6px;padding:14px;overflow-x:auto;font-size:11px;color:var(--text-primary);white-space:pre-wrap;word-break:break-all}}
.btn{{display:inline-flex;align-items:center;padding:6px 14px;border-radius:4px;font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:opacity .1s;text-decoration:none}}
.btn:hover{{opacity:.8}}
.btn-neutral{{background:rgba(107,107,123,.15);color:var(--text-muted);border-color:var(--border)}}
.actions{{display:flex;gap:8px;margin-top:14px}}
.evidence-note{{font-size:11px;color:var(--text-muted);margin-top:8px;padding:8px 12px;background:rgba(234,179,8,.07);border:1px solid rgba(234,179,8,.2);border-radius:4px}}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
</div>
<main>
  <div style="margin-bottom:16px">
    <span style="font-size:18px;font-weight:700;color:var(--text-primary)">Grant Receipt</span>
    <span class="badge {status_class}" style="margin-left:10px">{status}</span>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('summary')">Summary</button>
    <button class="tab" onclick="showTab('evidence')">Evidence (JSON)</button>
  </div>

  <div id="tab-summary" class="tab-panel active">
    <div class="card">
      <div class="card-title">Grant Details</div>
      <div class="field"><span class="field-label">Grant ID</span><span class="field-val">{id}</span></div>
      <div class="field"><span class="field-label">Persona</span><span class="field-val">{persona_id}</span></div>
      <div class="field"><span class="field-label">Credential</span><span class="field-val">{credential_name}</span></div>
      <div class="field"><span class="field-label">Scope</span><span class="field-val">{scope}</span></div>
      <div class="field"><span class="field-label">Issued</span><span class="field-val">{created_at}</span></div>
      <div class="field"><span class="field-label">Expires / Expired</span><span class="field-val">{expires_at}</span></div>
      <div class="field"><span class="field-label">Terminal Status</span><span class="field-val"><span class="badge {status_class}">{status}</span></span></div>
    </div>

    {budget_section}

    <div class="actions">
      <a href="/receipts/{id}?format=json" class="btn btn-neutral">Download JSON</a>
      <a href="/" class="btn btn-neutral">Back to Dashboard</a>
    </div>
  </div>

  <div id="tab-evidence" class="tab-panel">
    <div class="card">
      <div class="card-title">Raw Receipt JSON</div>
      <pre id="receipt-json">{receipt_json_escaped}</pre>
      <div class="evidence-note">This receipt is derived from the append-only audit log. Cryptographic signing ships in Phase 2.</div>
    </div>
    <div class="actions">
      <a href="/receipts/{id}?format=json" class="btn btn-neutral">Download JSON</a>
    </div>
  </div>
</main>
<script>
function showTab(name){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelectorAll('.tab')[name==='summary'?0:1].classList.add('active');
}}
</script>
</body>
</html>"#,
        status_class = status_class,
        status = g.status,
        id = g.id,
        persona_id = truncate_persona_id(&g.persona_id),
        credential_name = g.credential_name,
        scope = g.scope,
        created_at = g.created_at,
        expires_at = g.expires_at.as_deref().unwrap_or("—"),
        budget_section = budget_section,
        receipt_json_escaped = receipt_json.replace('<', "&lt;").replace('>', "&gt;"),
    )
}

// AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD — rollup view helpers.
//
// Adapts the dashboard's `ReceiptRow` store type to the `RollupReceiptView`
// trait so `core_events::rollup::compute_rollups` can collapse sub-receipts
// into per-materialization rollup rows. For grant receipts the `grant_id`
// doubles as the materialization join key (one grant = one invocation chain).
// Broker receipts carry their own `materialization_id` in the JSON body.

/// Dashboard-local receipt adapter that implements `RollupReceiptView` over
/// the flat `ReceiptRow` returned by `list_receipt_rows`.
struct DashboardRollupRow {
    materialization_id: Option<String>,
    kind: String,
    ts: String,
    receipt_hash: String,
    persona: Option<String>,
    action: Option<String>,
    action_ref: Option<core_event_types::ActionRef>,
    exit_code: Option<i32>,
    denied_reason: Option<String>,
    claim_count_total: Option<u64>,
    claim_events_truncated: bool,
    claim_segment_count: Option<u64>,
    claim_history_merkle_root: Option<String>,
}

impl core_events::rollup::RollupReceiptView for DashboardRollupRow {
    fn materialization_id(&self) -> Option<&str> {
        self.materialization_id.as_deref()
    }
    fn kind(&self) -> &str {
        &self.kind
    }
    fn ts(&self) -> &str {
        &self.ts
    }
    fn receipt_hash(&self) -> &str {
        &self.receipt_hash
    }
    fn persona(&self) -> Option<&str> {
        self.persona.as_deref()
    }
    fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }
    fn action_ref(&self) -> Option<&core_event_types::ActionRef> {
        self.action_ref.as_ref()
    }
    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
    fn denied_reason(&self) -> Option<&str> {
        self.denied_reason.as_deref()
    }
}

/// Build a `DashboardRollupRow` from a `ReceiptRow`. For grant receipts the
/// `grant_id` is used as the `materialization_id`. For broker receipts the
/// `materialization_id` is extracted from the raw JSON in the row's
/// `grant_id` field if present, otherwise falls back to the row id.
fn receipt_row_to_rollup(r: &crate::infra::receipt::ReceiptRow) -> DashboardRollupRow {
    // Map the stored kind discriminator to the dot-path form expected by
    // the rollup algorithm (matches the `events.jsonl` shape used by the
    // CLI verb).
    let rollup_kind = match r.kind.as_str() {
        "broker_materialization" => "broker.materialization".to_string(),
        "broker_revocation" => "broker.revocation".to_string(),
        "kms_wrap" => "broker.resolution".to_string(),
        "grant" => "session.construct_invocation".to_string(),
        other => other.to_string(),
    };
    // For grant receipts, use the grant_id as the materialization join key.
    // For broker receipts the real materialization_id lives in the body JSON
    // but is not surfaced in ReceiptRow; fall back to the row id to avoid
    // merging unrelated rows.
    let materialization_id = if r.grant_id.is_empty() {
        Some(r.id.clone())
    } else {
        Some(r.grant_id.clone())
    };
    DashboardRollupRow {
        materialization_id,
        kind: rollup_kind,
        ts: r.materialized_at.clone(),
        receipt_hash: r.id.clone(),
        persona: if r.actor.is_empty() {
            None
        } else {
            Some(r.actor.clone())
        },
        action_ref: r.action_ref.clone(),
        action: if r.resource.is_empty() {
            None
        } else {
            Some(r.resource.clone())
        },
        exit_code: None,
        denied_reason: None,
        claim_count_total: r.claim_count_total,
        claim_events_truncated: r.claim_events_truncated,
        claim_segment_count: r.claim_segment_count,
        claim_history_merkle_root: r.claim_history_merkle_root.clone(),
    }
}

/// Compute the rollup envelope from a slice of receipt rows and serialise it
/// to a `serde_json::Value` array. Each element carries the fields the
/// dashboard rollup table renders: `materialization_id`, `action`, `persona`,
/// `started_at`, `ended_at`, `outcome`, `denial_reason`, `receipt_count`,
/// and a `sub_receipts` array for click-through expand-detail.
///
/// This is the function named by `target_state_anchor = "fn rollup_view"`.
fn rollup_view(rows: &[crate::infra::receipt::ReceiptRow]) -> serde_json::Value {
    use core_events::rollup::{RollupOutcome, compute_rollups};

    let adapted: Vec<DashboardRollupRow> = rows.iter().map(receipt_row_to_rollup).collect();
    let mut session_groups: std::collections::BTreeMap<String, Vec<&DashboardRollupRow>> =
        std::collections::BTreeMap::new();
    for row in adapted.iter().filter(|r| r.kind.starts_with("session.")) {
        let key = row
            .materialization_id
            .clone()
            .unwrap_or_else(|| row.receipt_hash.clone());
        session_groups.entry(key).or_default().push(row);
    }
    let mut session_singletons: Vec<serde_json::Value> = session_groups
        .into_values()
        .map(|mut group| {
            group.sort_by(|a, b| a.ts.cmp(&b.ts));
            let first = group.first().expect("session group should not be empty");
            let last = group.last().expect("session group should not be empty");
            let action_ref = group.iter().rev().find_map(|r| r.action_ref.clone());
            let action = group.iter().rev().find_map(|r| r.action.clone());
            let persona = group.iter().find_map(|r| r.persona.clone());
            let claim_count_total = group.iter().rev().find_map(|r| r.claim_count_total);
            let claim_events_truncated = group.iter().any(|r| r.claim_events_truncated);
            let claim_segment_count = group.iter().rev().find_map(|r| r.claim_segment_count);
            let claim_history_merkle_root = group
                .iter()
                .rev()
                .find_map(|r| r.claim_history_merkle_root.clone());
            let sub_receipts: Vec<serde_json::Value> = group
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "kind": r.kind,
                        "ts": r.ts,
                        "receipt_hash": r.receipt_hash,
                        "claim_count_total": r.claim_count_total,
                        "claim_events_truncated": r.claim_events_truncated,
                        "claim_segment_count": r.claim_segment_count,
                        "claim_history_merkle_root": r.claim_history_merkle_root,
                    })
                })
                .collect();
            serde_json::json!({
                "materialization_id": first.materialization_id,
                "action_ref": action_ref,
                "action": action,
                "persona": persona,
                "started_at": first.ts,
                "ended_at": last.ts,
                "outcome": "success",
                "denial_reason": serde_json::Value::Null,
                "receipt_count": group.len(),
                "claim_count_total": claim_count_total,
                "claim_events_truncated": claim_events_truncated,
                "claim_segment_count": claim_segment_count,
                "claim_history_merkle_root": claim_history_merkle_root,
                "sub_receipts": sub_receipts,
            })
        })
        .collect();
    let construct_adapted: Vec<DashboardRollupRow> = adapted
        .into_iter()
        .filter(|r| !r.kind.starts_with("session."))
        .collect();
    let rollups = compute_rollups(&construct_adapted);
    // type alias would cross no other-file boundaries, but the tuple value is local plumbing — allow for the lint-clear
    #[allow(clippy::type_complexity)]
    let extras_by_hash: std::collections::BTreeMap<
        String,
        (Option<u64>, bool, Option<u64>, Option<String>),
    > = construct_adapted
        .iter()
        .map(|r| {
            (
                r.receipt_hash.clone(),
                (
                    r.claim_count_total,
                    r.claim_events_truncated,
                    r.claim_segment_count,
                    r.claim_history_merkle_root.clone(),
                ),
            )
        })
        .collect();

    let mut items: Vec<serde_json::Value> = rollups
        .into_iter()
        .map(|r| {
            let (outcome_str, denial_reason) = match &r.outcome {
                RollupOutcome::Success => ("success".to_string(), None),
                RollupOutcome::Denied { reason } => ("denied".to_string(), Some(reason.clone())),
                RollupOutcome::Errored { exit_code } => (
                    "errored".to_string(),
                    Some(format!("exit_code={exit_code}")),
                ),
                RollupOutcome::InFlight => ("in_flight".to_string(), None),
                RollupOutcome::Incomplete => ("incomplete".to_string(), None),
            };
            let sub_receipts: Vec<serde_json::Value> = r
                .sub_receipts
                .iter()
                .map(|s| {
                    let (
                        claim_count_total,
                        claim_events_truncated,
                        claim_segment_count,
                        claim_history_merkle_root,
                    ) = extras_by_hash
                        .get(&s.receipt_hash)
                        .cloned()
                        .unwrap_or((None, false, None, None));
                    serde_json::json!({
                        "kind": s.kind,
                        "ts": s.ts,
                        "receipt_hash": s.receipt_hash,
                        "claim_count_total": claim_count_total,
                        "claim_events_truncated": claim_events_truncated,
                        "claim_segment_count": claim_segment_count,
                        "claim_history_merkle_root": claim_history_merkle_root,
                    })
                })
                .collect();
            serde_json::json!({
                "materialization_id": r.materialization_id,
                "action_ref": r.action_ref,
                "action": r.action,
                "persona": r.persona,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "outcome": outcome_str,
                "denial_reason": denial_reason,
                "receipt_count": r.receipt_count,
                "sub_receipts": sub_receipts,
            })
        })
        .collect();
    items.append(&mut session_singletons);
    items.sort_by(|a, b| {
        let ak = a.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        let bk = b.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
        bk.cmp(ak)
    });

    serde_json::Value::Array(items)
}

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn receipt_row_action_summary(r: &crate::infra::receipt::ReceiptRow) -> String {
    let action_target = r
        .action_ref
        .as_ref()
        .map(ToString::to_string)
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| r.resource.chars().take(40).collect::<String>());
    match r.kind.as_str() {
        "grant" => format!(
            "{} · {}",
            r.requested_scope
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("grant"),
            if action_target.is_empty() {
                "grant".to_string()
            } else {
                action_target
            }
        ),
        kind if kind.starts_with("session.") => {
            let label = r
                .delegation_template
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(r.resource.as_str());
            format!("{kind} · {label}")
        }
        _ => {
            if action_target.is_empty() {
                r.kind.clone()
            } else {
                format!("{} · {}", r.kind, action_target)
            }
        }
    }
}

// currently unused; retained as a sibling JSON projector — allow for the lint-clear (reversible)
#[allow(dead_code)]
fn receipt_row_json(
    r: &crate::infra::receipt::ReceiptRow,
    persona_name: Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "kind": r.kind,
        "grant_id": r.grant_id,
        "persona_id": r.actor,
        "persona_name": persona_name,
        "action_ref": r.action_ref,
        "action_summary": receipt_row_action_summary(r),
        "contract_id": r.contract_id,
        "workspace_ref": r.workspace_ref,
        "caller_ref": r.caller_ref,
        "authority_ref": r.authority_ref,
        "terminal_reason": r.terminal_reason,
        "created_at": r.materialized_at,
        "signed": r.signed,
        "claim_count_total": r.claim_count_total,
        "claim_events_truncated": r.claim_events_truncated,
        "claim_segment_count": r.claim_segment_count,
        "claim_history_merkle_root": r.claim_history_merkle_root,
    })
}

fn error_response(status: u16, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({"error": msg});
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

/// The dashboard's shipped WebAuthn surfaces are passkey enrollment and
/// per-approval confirmation. Browser-side daemon presence-token minting is
/// intentionally disabled until this module can bind assertions to a real
/// runtime-backed operator identity and signer.
fn webauthn_auth_complete_not_shipped_response() -> Response<Full<Bytes>> {
    error_response(
        501,
        "dashboard webauthn auth-complete is not a shipped daemon presence-token surface; use approval routes or local daemon presence_token_mint",
    )
}

/// Truncate a persona ID for UI display. Keeps the 12-char UUID prefix after "persona-".
/// Render the dedicated `/approvals/{id}` page HTML for a given approval
/// record, with all `{{TOKEN}}` placeholders substituted.
///
/// The page leads with the high-level
/// Approve/Deny decision; the per-statement breakdown for composite
/// approvals is rendered client-side from the polled JSON behind a
/// "Show details" disclosure (collapsed-by-default). Both the dashboard
/// pending-approvals card and this page share the same
/// `renderCompositeStatements` helper via `COMPOSITE_STATEMENTS_JS`,
/// so the two surfaces cannot drift.
/// Shared dashboard handler for approve + deny.
///
/// Verifies a WebAuthn assertion against the persona's enrolled
/// credentials before flipping approval state. Refuses the state
/// transition with `401` if no challenge_id + credential are
/// supplied, or if the assertion fails to verify.
///
/// ## Bypass policy
///
/// 1. **Production daemon (gate present):** the body MUST carry
///    `{challenge_id, credential}` and the gate MUST verify. No
///    other bypass.
/// 2. **Operator opt-out** via `EMBER_DISABLE_BIO=1` env: legacy
///    `{biometric, credential_id}` path is honored. Same gate the
///    CLI honors. Production deployments that explicitly disable
///    biometric prompting (CI, headless boxes) opt in here.
/// 3. **Tests** (gate absent): legacy path. Only reachable when
///    DashboardState is constructed without a gate, which the
///    production `run_dashboard` never does.
async fn resolve_approval_via_dashboard<B>(
    state: Arc<DashboardState>,
    req: Request<B>,
    approval_id: String,
    outcome: ApprovalOutcome,
    success_key: &'static str,
    standing_grant_created: bool,
) -> Response<Full<Bytes>>
where
    B: hyper::body::Body + 'static,
    B::Data: bytes::Buf,
{
    use http_body_util::BodyExt as _;
    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => Bytes::new(),
    };
    let params: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

    // Decide which path: real WebAuthn vs legacy claim.
    #[cfg(feature = "webauthn")]
    let use_real_webauthn = state.webauthn.is_some() && std::env::var("EMBER_DISABLE_BIO").is_err();
    #[cfg(not(feature = "webauthn"))]
    let use_real_webauthn = false;

    if use_real_webauthn {
        #[cfg(feature = "webauthn")]
        {
            let gate = state.webauthn.as_ref().expect("checked above");
            let challenge_id = match params["challenge_id"].as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => {
                    return error_response(
                        401,
                        "missing webauthn challenge_id — visit /settings/passkeys to enroll a passkey first, then retry",
                    );
                }
            };
            let credential: webauthn_rs::prelude::PublicKeyCredential =
                match serde_json::from_value(params["credential"].clone()) {
                    Ok(c) => c,
                    Err(e) => {
                        return error_response(401, &format!("invalid webauthn credential: {e}"));
                    }
                };
            let verified = match gate.finish_auth(&challenge_id, &approval_id, credential) {
                Ok(v) => v,
                Err(crate::webauthn::WebauthnError::UnknownChallenge)
                | Err(crate::webauthn::WebauthnError::ChallengeMismatch) => {
                    return error_response(401, "challenge expired or mismatched — retry");
                }
                Err(crate::webauthn::WebauthnError::VerifyFailed(why)) => {
                    return error_response(401, &format!("assertion did not verify: {why}"));
                }
                Err(crate::webauthn::WebauthnError::NotEnrolled) => {
                    return error_response(
                        409,
                        "no passkey enrolled — visit /settings/passkeys to enroll first",
                    );
                }
                Err(e) => return error_response(500, &e.to_string()),
            };
            // Verified. Flip state with the verified credential id.
            match state.store.resolve_approval_with_biometric(
                &approval_id,
                &outcome,
                /* biometric = */ true,
                Some(&verified.credential_id),
            ) {
                Ok(()) => json_response(
                    StatusCode::OK,
                    &approval_success_body(
                        success_key,
                        true,
                        Some(&verified.credential_id),
                        standing_grant_created,
                    ),
                ),
                Err(e) => error_response(400, &e.to_string()),
            }
        }
        #[cfg(not(feature = "webauthn"))]
        unreachable!()
    } else {
        // Legacy path. Tests + opt-out operators only.
        let biometric = params["biometric"].as_bool().unwrap_or(false);
        let credential_id = params["credential_id"].as_str();
        match state.store.resolve_approval_with_biometric(
            &approval_id,
            &outcome,
            biometric,
            credential_id,
        ) {
            Ok(()) => json_response(
                StatusCode::OK,
                &approval_success_body(
                    success_key,
                    biometric,
                    credential_id,
                    standing_grant_created,
                ),
            ),
            Err(e) => error_response(400, &e.to_string()),
        }
    }
}

fn approval_success_body(
    success_key: &'static str,
    biometric: bool,
    credential_id: Option<&str>,
    standing_grant_created: bool,
) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert(success_key.to_string(), serde_json::Value::Bool(true));
    body.insert("biometric".to_string(), serde_json::Value::Bool(biometric));
    body.insert(
        "credential_id".to_string(),
        credential_id
            .map(|id| serde_json::Value::String(id.to_string()))
            .unwrap_or(serde_json::Value::Null),
    );
    if standing_grant_created {
        body.insert(
            "standing_grant_created".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    serde_json::Value::Object(body)
}

pub fn render_approval_page(
    csrf_token: &str,
    approval: &crate::trust::approval::ApprovalRequestInfo,
    persona_name: Option<&str>,
) -> String {
    // For composite approvals, the row's flat `action`
    // column is the verb of statement 0; that misrepresents a multi-verb
    // chain on the operator-facing card (e.g. an Anthropic+budget+session
    // bundle showing as "credential.access"). Render an honest summary
    // instead. Single-statement approvals keep the legacy projection.
    let action_label = if let Some(stmts) = approval.composite_statements.as_ref() {
        format!("composite ({} statements)", stmts.len())
    } else {
        approval.action.clone()
    };
    // Show "name <identifier>" so the operator
    // sees both the human-friendly handle (e.g. `qa`) and the unique
    // persona-id suffix used in audit logs and grant chains. The
    // identifier-only fallback covers personas that lack a name.
    // persona_label is intentional HTML (wraps the id in a span), so escape the
    // agent-controlled `name` and the id INSIDE the markup — not the whole
    // string — to avoid stored XSS while keeping the layout.
    let persona_label = match persona_name.filter(|n| !n.is_empty()) {
        Some(name) => format!(
            "{} <span class=\"persona-id\">{}</span>",
            escape_html(name),
            escape_html(&truncate_persona_id(&approval.persona_id))
        ),
        None => escape_html(&truncate_persona_id(&approval.persona_id)),
    };
    // COMPOSITE-PR6-TESTS-DASHBOARD — render skill_ref row when present on the
    // proposal; hidden (empty string) when None so the card stays clean for
    // legacy approvals that predate the skill_ref field.
    let skill_ref_row = match approval.skill_ref.as_deref().filter(|s| !s.is_empty()) {
        Some(sr) => format!(
            "<div class=\"field\" id=\"skill-ref-row\"><span class=\"field-label\">Skill</span><span class=\"field-val\">{}</span></div>",
            escape_html(sr)
        ),
        None => String::new(),
    };
    APPROVAL_HTML_TEMPLATE
        .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
        .replace("{{CSRF_TOKEN}}", csrf_token)
        .replace("{{APPROVAL_ID}}", &approval.id)
        .replace("{{ACTION}}", &escape_html(&action_label))
        .replace("{{SKILL_REF_ROW}}", &skill_ref_row)
        .replace("{{CREDENTIAL}}", &escape_html(&approval.credential_name))
        .replace("{{SCOPE}}", &escape_html(&approval.scope))
        .replace("{{RISK_LEVEL}}", &escape_html(&approval.risk_level))
        .replace("{{PERSONA_PREFIX}}", &persona_label)
        .replace("{{CREATED_AT}}", &escape_html(&approval.created_at))
}

fn truncate_persona_id(persona_id: &str) -> String {
    const PREFIX: &str = "persona-";
    const UUID_CHARS: usize = 12;
    if let Some(uuid_part) = persona_id.strip_prefix(PREFIX) {
        let taken: String = uuid_part.chars().take(UUID_CHARS).collect();
        format!("{PREFIX}{taken}")
    } else {
        persona_id.to_string()
    }
}

#[cfg(test)]
mod tests;
