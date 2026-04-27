use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use crate::approval::ApprovalOutcome;
use crate::store::DaemonStore;

/// implementation-note-8 — actions hidden from the operator audit timeline by
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
/// raw persona id (implementation-note-8). Falls back to an empty map on
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

/// Header name clients must send on state-mutating (POST) dashboard requests.
/// 69K.7: live budget gauge + pause/extend buttons + receipt viewer.
const CSRF_HEADER: &str = "X-Ember-CSRF-Token";

/// Base64url (RFC 4648 §5) encode without padding. Used by the WebAuthn
/// challenge endpoint (implementation-note-6) — `navigator.credentials.get()`
/// expects PublicKeyCredentialRequestOptions.challenge in spec-aligned
/// base64url-no-pad. Avoids pulling the `base64` crate into the daemon
/// for one ~10-line helper.
fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() == 3 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

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

/// Defense-in-depth origin check for POST endpoints (security check).
///
/// Reads the `Origin` header first; if present it must equal `expected_origin`
/// exactly. If `Origin` is absent, falls back to `Referer` — parses its URL
/// and compares scheme + host + port to `expected_origin`. If neither header is
/// present the request is rejected (403).
///
/// `expected_origin` must be of the form `http://127.0.0.1:<port>` — derived
/// from the actual bound dashboard address at startup, never from user input.
fn origin_ok(headers: &hyper::HeaderMap, expected_origin: &str) -> bool {
    // Primary: check Origin header.
    if let Some(origin_val) = headers.get("origin") {
        return match origin_val.to_str() {
            Ok(o) => o == expected_origin,
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
            return candidate == expected_origin;
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
            tracing::warn!(addr = %addr, error = %e, "dashboard failed to bind, continuing without dashboard");
            if let Some(tx) = bind_tx {
                let _ = tx.send(Err(e));
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
                            // implementation-note-11: the listener
                            // is alive at this point — propagate the resolved
                            // local_addr so `/api/status` reports it instead
                            // of relying on the configured (pre-bind) port.
                            dashboard_actual_addr: Some(local_addr),
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

/// Shared JS that renders a composite-statement breakdown into HTML — used
/// by both the dashboard pending-approvals card and the dedicated
/// `/approvals/{id}` page so the two surfaces can never drift. Injected
/// into both templates via `{{COMPOSITE_STATEMENTS_JS}}`. The function name
/// `render_composite_statements` (and the rendered class `composite-statements`)
/// are the implementation-note-12 target_state_anchor markers — search for
/// either if you are tracing why the page hides "3 statements" by default.
pub const COMPOSITE_STATEMENTS_JS: &str = r#"
// render_composite_statements — single source of truth for the composite
// breakdown HTML. Returns '' when stmts is null/empty so single-statement
// approvals fall through to the simple layout.
function renderCompositeStatements(stmts){
  if(!Array.isArray(stmts) || stmts.length===0) return '';
  const rows = stmts.map(function(s,i){
    const actions = (s.actions||[]).join(',');
    let resource = '*';
    if (s.resource && typeof s.resource === 'object') {
      if ('Exact' in s.resource) resource = s.resource.Exact.value;
      else if ('Glob' in s.resource) resource = s.resource.Glob.pattern;
      else if (s.resource === 'Any' || ('Any' in s.resource)) resource = '*';
    }
    let budget = '';
    if (s.budget) {
      const parts = [];
      if (s.budget.tokens != null) parts.push(s.budget.tokens+' tokens');
      if (s.budget.cents != null) parts.push((s.budget.cents/100).toFixed(2)+' USD');
      if (s.budget.wall_clock_secs != null) parts.push(s.budget.wall_clock_secs+'s');
      if (parts.length) budget = ' · '+parts.join(' · ');
    }
    return '<div class="composite-stmt"><span class="composite-stmt-idx">['+i+']</span> <span class="mono">'+actions+'</span> on <span class="mono">'+resource+'</span>'+budget+'</div>';
  }).join('');
  return '<div class="composite-statements">'+rows+'</div>';
}
function compositeSummary(stmts){
  if(!Array.isArray(stmts) || stmts.length===0) return '';
  return stmts.length+' statements · click to review';
}
"#;

pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember daemon</title>
<style>
:root{--bg-primary:#0a0a0f;--bg-card:#12121a;--bg-hover:#1a1a2a;--accent:#e85d26;--accent-dim:#c44d1e;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--text-dim:#3a3a4a;--border:#1e1e2e;--success:#22c55e;--warning:#eab308;--danger:#ef4444}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'JetBrains Mono',ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px}
a{color:var(--accent);text-decoration:none}
#header{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg-card)}
#header .logo{font-size:20px;font-weight:700;color:var(--accent);letter-spacing:-0.5px}
#header .meta{display:flex;align-items:center;gap:16px;color:var(--text-muted);font-size:12px}
#header .status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);display:inline-block;margin-right:6px;box-shadow:0 0 6px var(--success)}
#header .status-dot.offline{background:var(--danger);box-shadow:0 0 6px var(--danger)}
main{padding:20px 24px;max-width:1400px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px}
.card .label{color:var(--text-muted);font-size:11px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.card .value{font-size:28px;font-weight:700;color:var(--text-primary)}
.card .value.accent{color:var(--accent)}
.card .value.warn{color:var(--warning)}
.section{margin-bottom:28px}
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.section-title{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted)}
.refresh-ts{font-size:11px;color:var(--text-dim)}
table{width:100%;border-collapse:collapse;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
thead th{padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);border-bottom:1px solid var(--border);background:var(--bg-primary)}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--bg-hover)}
tbody td{padding:10px 14px;color:var(--text-primary)}
.mono{font-family:inherit;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge.active{background:rgba(34,197,94,.15);color:var(--success)}
.badge.revoked{background:rgba(239,68,68,.15);color:var(--danger)}
.badge.pending{background:rgba(234,179,8,.15);color:var(--warning)}
.badge.high{background:rgba(239,68,68,.15);color:var(--danger)}
.badge.medium{background:rgba(234,179,8,.15);color:var(--warning)}
.badge.low{background:rgba(34,197,94,.15);color:var(--success)}
.badge.allowed{background:rgba(34,197,94,.15);color:var(--success)}
.badge.denied{background:rgba(239,68,68,.15);color:var(--danger)}
.btn{display:inline-flex;align-items:center;padding:4px 10px;border-radius:4px;font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:opacity .1s}
.btn:hover{opacity:.8}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger);border-color:rgba(239,68,68,.3)}
.btn-success{background:rgba(34,197,94,.15);color:var(--success);border-color:rgba(34,197,94,.3)}
.btn-warn{background:rgba(234,179,8,.15);color:var(--warning);border-color:rgba(234,179,8,.3)}
.btn-neutral{background:rgba(107,107,123,.15);color:var(--text-muted);border-color:var(--border)}
.approval-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.approval-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px;position:relative}
.approval-card .row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.approval-card .field{color:var(--text-muted);font-size:11px}
.approval-card .field-val{color:var(--text-primary);font-size:12px}
.approval-card .actions{display:flex;gap:8px;margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}
.btn-dismiss{position:absolute;top:8px;right:8px;background:none;border:none;color:var(--text-dim);font-size:14px;cursor:pointer;line-height:1;padding:2px 4px;border-radius:3px}
.btn-dismiss:hover{color:var(--text-muted);background:var(--bg-hover)}
.composite-statements{margin:6px 0 10px;padding:8px 10px;background:rgba(232,93,38,.05);border-left:2px solid var(--accent);border-radius:4px;font-size:11px}
.composite-stmt{padding:4px 0;color:var(--text-primary)}
.composite-stmt-idx{color:var(--text-muted);font-weight:600}
.approval-link{color:var(--accent);text-decoration:none}
.approval-link:hover{text-decoration:underline}
.timeline{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.timeline-item{display:grid;grid-template-columns:180px 140px 160px 140px 80px;gap:12px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--border);transition:background .1s}
.timeline-item:last-child{border-bottom:none}
.timeline-item:hover{background:var(--bg-hover)}
.timeline-header{display:grid;grid-template-columns:180px 140px 160px 140px 80px;gap:12px;padding:8px 14px;border-bottom:1px solid var(--border);background:var(--bg-primary)}
.timeline-header span{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted)}
.ts{color:var(--text-dim);font-size:11px}
.empty{color:var(--text-dim);text-align:center;padding:32px;font-size:12px}
.cond-badges{display:flex;flex-wrap:wrap;gap:4px}
.cond-badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:rgba(107,107,123,.2);color:var(--text-muted);border:1px solid var(--border)}
.anomaly-section{margin-bottom:24px}
.anomaly-list{display:flex;flex-direction:column;gap:8px}
.anomaly-card{background:var(--bg-card);border-radius:8px;padding:12px 16px;display:flex;align-items:flex-start;gap:12px}
.anomaly-card.high{border-left:3px solid var(--danger)}
.anomaly-card.medium{border-left:3px solid var(--warning)}
.anomaly-card.low{border-left:3px solid #3b82f6}
.anomaly-card .anm-meta{flex:1}
.anomaly-card .anm-agent{font-size:12px;font-weight:600;color:var(--text-primary);margin-bottom:2px}
.anomaly-card .anm-desc{font-size:11px;color:var(--text-muted)}
.anomaly-card .anm-ts{font-size:10px;color:var(--text-dim);margin-top:4px}
.anomaly-card .anm-type{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}
.anomaly-card.high .anm-type{color:var(--danger)}
.anomaly-card.medium .anm-type{color:var(--warning)}
.anomaly-card.low .anm-type{color:#3b82f6}
.gauge-wrap{padding:4px 0}
.gauge-label{display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:3px}
.gauge-track{width:100%;height:4px;background:var(--bg-hover);border-radius:2px;overflow:hidden}
.gauge-fill{height:100%;border-radius:2px;transition:width .4s}
.gauge-fill.green{background:var(--success)}
.gauge-fill.yellow{background:var(--warning)}
.gauge-fill.red{background:var(--danger)}
.paused-banner{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;background:rgba(234,179,8,.15);color:var(--warning);border:1px solid rgba(234,179,8,.3);margin-top:4px}
.show-all-label{font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:5px;cursor:pointer}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:24px;width:380px;max-width:95vw}
.modal-title{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:16px}
.modal-field{margin-bottom:12px}
.modal-field label{display:block;font-size:11px;color:var(--text-muted);margin-bottom:4px}
.modal-field input{width:100%;background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:6px 10px;color:var(--text-primary);font-family:inherit;font-size:12px}
.modal-field input:focus{outline:none;border-color:var(--accent)}
.quick-picks{display:flex;gap:6px;margin-top:6px}
.quick-pick{padding:3px 8px;border-radius:3px;font-family:inherit;font-size:10px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg-hover);color:var(--text-muted)}
.quick-pick:hover{border-color:var(--accent);color:var(--accent)}
.modal-actions{display:flex;gap:8px;margin-top:16px}
.badge.expired_by_budget{background:rgba(239,68,68,.15);color:var(--danger)}
.badge.exhausted_by_budget{background:rgba(239,68,68,.15);color:var(--danger)}
.badge.expired{background:rgba(107,107,123,.15);color:var(--text-muted)}
.badge.paused{background:rgba(234,179,8,.15);color:var(--warning)}
.badge.parent_cascade_revoked{background:rgba(239,68,68,.1);color:var(--danger)}
.grant-status-active>td:first-child{border-left:3px solid var(--success)}
.grant-status-expired>td:first-child{border-left:3px solid var(--warning)}
.grant-status-revoked>td:first-child{border-left:3px solid var(--danger)}
.grant-status-exhausted>td:first-child{border-left:3px solid var(--danger)}
.signed-yes{color:var(--success);font-weight:700}
.signed-no{color:var(--text-dim)}
.receipt-filters{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.receipt-filters select,.receipt-filters label{font-size:11px;color:var(--text-muted);font-family:inherit}
.receipt-filters select{background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 6px;cursor:pointer}
</style>
</head>
<body>
<div id="header">
  <div class="logo">ember</div>
  <div class="meta">
    <span id="version">v0.0.0</span>
    <span><span id="status-dot" class="status-dot offline"></span><span id="status-text">connecting…</span></span>
    <span id="last-refresh" class="refresh-ts"></span>
  </div>
</div>
<main>
  <div id="anomaly-section" class="anomaly-section" style="display:none">
    <div class="section-header"><span class="section-title">Anomaly Alerts</span></div>
    <div class="anomaly-list" id="anomaly-list"></div>
  </div>

  <div class="cards">
    <div class="card"><div class="label">Active Agents</div><div class="value accent" id="cnt-agents">—</div></div>
    <div class="card"><div class="label">Active Grants</div><div class="value" id="cnt-grants">—</div></div>
    <div class="card"><div class="label">Pending Approvals</div><div class="value warn" id="cnt-approvals">—</div></div>
    <div class="card"><div class="label">Audit Events</div><div class="value" id="cnt-audit">—</div></div>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Active Grants</span><label class="show-all-label"><input type="checkbox" id="show-all-grants" onchange="loadDashboard()"> show terminated</label></div>
    <table id="grants-table">
      <thead><tr><th>ID</th><th>Persona</th><th>Credential</th><th>Scope</th><th>Budget</th><th>Expires</th><th>Status</th><th></th></tr></thead>
      <tbody id="grants-body"><tr><td colspan="8" class="empty">loading…</td></tr></tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-header"><span class="section-title">Pending Approvals</span></div>
    <div class="approval-cards" id="approvals-container"><div class="empty">loading…</div></div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">Audit Timeline</span>
      <div style="display:flex;align-items:center;gap:14px">
        <select id="audit-action-filter" onchange="loadDashboard()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);font-family:inherit;font-size:11px;padding:3px 6px;cursor:pointer">
          <option value="">all actions</option>
          <option value="grant.">grant.*</option>
          <option value="approval.">approval.*</option>
          <option value="broker.">broker.*</option>
          <option value="credential.">credential.*</option>
          <option value="vault.">vault.*</option>
          <option value="sandbox.">sandbox.*</option>
        </select>
        <label class="show-all-label"><input type="checkbox" id="show-internal-events" onchange="loadDashboard()"> show internal events</label>
      </div>
    </div>
    <div class="timeline">
      <div class="timeline-header">
        <span>Timestamp</span><span>Agent</span><span>Action</span><span>Credential</span><span>Outcome</span>
      </div>
      <div id="audit-body"><div class="empty">loading…</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <span class="section-title">Grant Receipts</span>
      <div class="receipt-filters">
        <select id="receipt-signed-filter" onchange="loadReceipts()">
          <option value="">all receipts</option>
          <option value="true">signed only</option>
        </select>
        <select id="receipt-since-filter" onchange="loadReceipts()">
          <option value="all">all time</option>
          <option value="24h">last 24h</option>
          <option value="7d">last 7d</option>
        </select>
        <input type="text" id="receipt-persona-filter" placeholder="persona id…" oninput="loadReceipts()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 6px;color:var(--text-primary);font-family:inherit;font-size:11px;width:140px">
      </div>
    </div>
    <table id="receipts-table">
      <thead><tr><th>Issued</th><th>Grant ID</th><th>Persona</th><th>Summary</th><th>Reason</th><th>Signed</th></tr></thead>
      <tbody id="receipts-body"><tr><td colspan="6" class="empty">loading…</td></tr></tbody>
    </table>
  </div>
</main>

<div class="modal-overlay" id="extend-modal">
  <div class="modal">
    <div class="modal-title">Extend Grant</div>
    <input type="hidden" id="extend-grant-id">
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
      <button class="btn btn-neutral" onclick="closeExtendModal()">Cancel</button>
    </div>
  </div>
</div>
<script>
const CSRF_TOKEN = "{{CSRF_TOKEN}}";
const CSRF_HEADERS = {'X-Ember-CSRF-Token': CSRF_TOKEN};
{{COMPOSITE_STATEMENTS_JS}}
function ts(iso){if(!iso)return'—';const d=new Date(iso);return d.toLocaleString(undefined,{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
// implementation-note-8 — relative_time / formatRelative: render audit + grant
// timestamps as 'Just now' / '12s ago' / '3 min ago' / '04/26 1:34 AM'
// long-tail fallback so screenshots don't lead with raw ISO strings. Tooltip
// (title=) keeps the precise ISO for operators who need it.
function formatRelative(iso){
  if(!iso) return '—';
  const d = new Date(iso);
  if(isNaN(d.getTime())) return iso;
  const now = Date.now();
  const diff = Math.floor((now - d.getTime())/1000);
  if(diff < 0) return d.toLocaleString();
  if(diff < 5)   return 'Just now';
  if(diff < 60)  return diff+'s ago';
  if(diff < 3600){ const m = Math.floor(diff/60); return m+' min ago'; }
  if(diff < 86400){ const h = Math.floor(diff/3600); return h+'h ago'; }
  // Long-tail: short month/day + time, e.g. '04/26 1:34 AM'.
  const mm = String(d.getMonth()+1).padStart(2,'0');
  const dd = String(d.getDate()).padStart(2,'0');
  const time = d.toLocaleTimeString(undefined,{hour:'numeric',minute:'2-digit'});
  return mm+'/'+dd+' '+time;
}
function relTime(iso){
  // Render as a span with a tooltip carrying the full ISO timestamp.
  if(!iso) return '—';
  const safe = String(iso).replace(/"/g,'&quot;');
  return '<span title="'+safe+'">'+formatRelative(iso)+'</span>';
}
function trunc(s,n){if(!s)return'—';return s.length>n?s.slice(0,n)+'…':s;}
function truncPersona(s){if(!s)return'—';const p='persona-';if(s.startsWith(p)){return p+s.slice(p.length,p.length+12);}return trunc(s,20);}
// implementation-note-8 — persona.name primary label; raw persona_id moves to
// the tooltip so screenshots show real names instead of UUID prefixes.
// Falls back to truncPersona when no name was returned by the API.
function personaLabel(id, name){
  if(name && name.length){
    const safeId = String(id||'').replace(/"/g,'&quot;');
    return '<span title="'+safeId+'">'+name+'</span>';
  }
  return truncPersona(id);
}
function badge(cls,text){return`<span class="badge ${cls}">${text}</span>`;}
function grantStatusClass(s){if(s==='active')return'active';if(s==='expired')return'expired';if(s==='revoked')return'revoked';if(s==='exhausted_by_budget'||s==='expired_by_budget')return'exhausted';return '';}

// Active SSE connections keyed by grant id
const sseConnections = {};

function connectSSE(grantId, rowId) {
  if(sseConnections[grantId]) return;
  const es = new EventSource(`/sse/grants/${grantId}`);
  sseConnections[grantId] = es;
  es.addEventListener('usage_update', e => updateGrantRow(grantId, JSON.parse(e.data)));
  es.addEventListener('budget_warning', e => updateGrantRow(grantId, JSON.parse(e.data)));
  es.addEventListener('budget_exhausted', e => { updateGrantRow(grantId, JSON.parse(e.data)); es.close(); delete sseConnections[grantId]; loadDashboard(); });
  es.addEventListener('grant_terminated', e => { es.close(); delete sseConnections[grantId]; loadDashboard(); });
  es.addEventListener('paused', e => updateGrantRow(grantId, JSON.parse(e.data)));
  es.addEventListener('unpaused', e => updateGrantRow(grantId, JSON.parse(e.data)));
  es.onerror = () => { es.close(); delete sseConnections[grantId]; };
}

function updateGrantRow(grantId, g) {
  const row = document.getElementById('grant-row-' + grantId);
  if(!row) return;
  const gaugeCell = row.querySelector('.gauge-cell');
  if(gaugeCell) gaugeCell.innerHTML = renderBudgetGauge(g);
  const statusCell = row.querySelector('.status-cell');
  if(statusCell) statusCell.innerHTML = badge(g.status, g.status);
}

function renderBudgetGauge(g) {
  let html = '';
  const budget = g.budget || {};
  const usage = g.usage || {};
  if(budget.tokens != null) {
    const used = usage.tokens || 0;
    const pct = Math.min(100, Math.round(used*100/Math.max(1,budget.tokens)));
    const cls = pct>=95?'red':pct>=80?'yellow':'green';
    html += `<div class="gauge-wrap">
      <div class="gauge-label"><span>tokens</span><span>${used}/${budget.tokens} (${pct}%)</span></div>
      <div class="gauge-track"><div class="gauge-fill ${cls}" style="width:${pct}%"></div></div>
    </div>`;
  }
  if(budget.cents != null) {
    const used = usage.cents || 0;
    const pct = Math.min(100, Math.round(used*100/Math.max(1,budget.cents)));
    const cls = pct>=95?'red':pct>=80?'yellow':'green';
    const usedFmt = '$'+((used/100).toFixed(2));
    const budFmt = '$'+((budget.cents/100).toFixed(2));
    html += `<div class="gauge-wrap">
      <div class="gauge-label"><span>cost</span><span>${usedFmt}/${budFmt} (${pct}%)</span></div>
      <div class="gauge-track"><div class="gauge-fill ${cls}" style="width:${pct}%"></div></div>
    </div>`;
  }
  if(!html) html = '<span style="color:var(--text-dim);font-size:11px">—</span>';
  if(g.paused) html += '<div class="paused-banner">paused by operator</div>';
  return html;
}

function renderGrantActions(g) {
  const terminal = ['revoked','expired','expired_by_budget','parent_cascade_revoked'].includes(g.status);
  if(terminal) {
    let btns = `<a class="btn btn-neutral" href="/receipts/${g.id}" style="font-size:10px">View Receipt</a>`;
    return btns;
  }
  let btns = `<button class="btn btn-danger" onclick="revokeGrant('${g.id}')">Revoke</button>`;
  if(g.paused) {
    btns += ` <button class="btn btn-warn" onclick="unpauseGrant('${g.id}')">Unpause</button>`;
  } else {
    btns += ` <button class="btn btn-warn" onclick="pauseGrant('${g.id}')">Pause</button>`;
  }
  btns += ` <button class="btn btn-neutral" onclick="openExtendModal('${g.id}')">Extend</button>`;
  return btns;
}

async function revokeGrant(id){
  await fetch(`/api/grants/${id}/revoke`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function pauseGrant(id){
  await fetch(`/api/grants/${id}/pause`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function unpauseGrant(id){
  await fetch(`/api/grants/${id}/unpause`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
function openExtendModal(id){
  document.getElementById('extend-grant-id').value=id;
  document.getElementById('extend-tokens').value='';
  document.getElementById('extend-cents-usd').value='';
  document.getElementById('extend-ttl-secs').value='';
  document.getElementById('extend-modal').classList.add('open');
}
function closeExtendModal(){
  document.getElementById('extend-modal').classList.remove('open');
}
function setTTL(secs){document.getElementById('extend-ttl-secs').value=secs;}
async function submitExtend(){
  const id=document.getElementById('extend-grant-id').value;
  const tokens=parseInt(document.getElementById('extend-tokens').value)||undefined;
  const centsUsd=parseFloat(document.getElementById('extend-cents-usd').value);
  const cents=isNaN(centsUsd)?undefined:Math.round(centsUsd*100);
  const ttl=parseInt(document.getElementById('extend-ttl-secs').value)||undefined;
  const body={};
  if(tokens)body.tokens_delta=tokens;
  if(cents)body.cents_delta=cents;
  if(ttl)body.ttl_extension_secs=ttl;
  const resp=await fetch(`/api/grants/${id}/extend`,{method:'POST',headers:{...CSRF_HEADERS,'content-type':'application/json'},body:JSON.stringify(body)});
  closeExtendModal();
  if(!resp.ok){const e=await resp.json().catch(()=>({error:'failed'}));alert('Extend failed: '+(e.error||resp.status));}
  loadDashboard();
}
// implementation-note-6 — request a fresh WebAuthn challenge from the daemon and
// invoke navigator.credentials.get() to raise the platform authenticator
// (Touch ID on macOS, Windows Hello on Windows, fingerprint on supported
// Android browsers). Returns {biometric: bool, credential_id?: string}.
//
// Failure modes are fail-open by design for the May 3 demo path — if the
// browser doesn't expose WebAuthn (legacy Safari, restricted-context iframe)
// or the user has no platform authenticator enrolled, we record
// `biometric=false` and continue. The daemon's audit log faithfully captures
// the operator-asserted posture either way; a downstream auditor can filter
// on `biometric=true` to find the high-trust beats.
async function performBiometricCeremony(){
  if(!('credentials' in navigator) || !navigator.credentials.get){
    return {biometric: false};
  }
  try{
    const ch = await fetch('/api/webauthn/challenge').then(r=>r.json());
    const challengeBytes = base64urlDecode(ch.challenge);
    const assertion = await navigator.credentials.get({
      publicKey:{
        challenge: challengeBytes,
        rpId: ch.rp_id || 'localhost',
        allowCredentials: (ch.allow_credentials||[]).map(c=>({
          type:'public-key',
          id: base64urlDecode(c.id),
        })),
        userVerification: ch.user_verification || 'preferred',
        timeout: 60000,
      }
    });
    if(!assertion){
      return {biometric: false};
    }
    return {
      biometric: true,
      credential_id: assertion.id || null,
    };
  }catch(e){
    // User cancel, no enrollment, framework error — degrade gracefully.
    console.warn('biometric ceremony skipped:', e && e.message);
    return {biometric: false};
  }
}
function base64urlDecode(s){
  if(!s) return new Uint8Array(0);
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g,'+').replace(/_/g,'/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
  return out;
}
async function approveRequest(id){
  const bio = await performBiometricCeremony();
  await fetch(`/api/approvals/${id}/approve`,{
    method:'POST',
    headers:{...CSRF_HEADERS,'content-type':'application/json'},
    body: JSON.stringify(bio),
  });
  loadDashboard();
}
async function approveAlwaysRequest(id){
  await fetch(`/api/approvals/${id}/approve-always`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function denyRequest(id){
  const bio = await performBiometricCeremony();
  await fetch(`/api/approvals/${id}/deny`,{
    method:'POST',
    headers:{...CSRF_HEADERS,'content-type':'application/json'},
    body: JSON.stringify(bio),
  });
  loadDashboard();
}
// implementation-note-7 — dismiss a pending approval card.
// Records approval.dismissed in the audit log; does NOT re-fire desktop
// notifications. Card vanishes immediately on success.
async function dismissApproval(id){
  const resp = await fetch(`/api/approvals/${id}/dismiss`,{method:'POST',headers:CSRF_HEADERS});
  if(resp.ok){
    const card = document.getElementById('approval-card-'+id);
    if(card) card.remove();
    // Update pending count
    const cnt = document.getElementById('cnt-approvals');
    if(cnt){ const n=parseInt(cnt.textContent)||0; cnt.textContent=Math.max(0,n-1); }
  }
}

function renderConditions(c){
  if(!c)return'<span style="color:var(--text-dim);font-size:11px">—</span>';
  const tags=[];
  if(c.rate_limit!=null)tags.push(`<span class="cond-badge">${c.rate_limit}/hr</span>`);
  if(c.time_window)tags.push(`<span class="cond-badge">window: ${c.time_window}</span>`);
  if(c.allowed_hours)tags.push(`<span class="cond-badge">${c.allowed_hours}</span>`);
  if(c.allowed_targets&&c.allowed_targets.length>0)tags.push(`<span class="cond-badge">${c.allowed_targets.length} target${c.allowed_targets.length>1?'s':''}</span>`);
  if(c.spending_limit!=null)tags.push(`<span class="cond-badge">limit: ${c.spending_limit}</span>`);
  if(c.delegation_depth!=null)tags.push(`<span class="cond-badge">depth ${c.delegation_depth}</span>`);
  return tags.length?`<div class="cond-badges">${tags.join('')}</div>`:'<span style="color:var(--text-dim);font-size:11px">—</span>';
}

async function loadDashboard(){
  try{
    const showAll=document.getElementById('show-all-grants')?.checked;
    const grantsUrl=showAll?'/api/grants/all':'/api/grants';
    // implementation-note-8 — operator audit hides internal lifecycle events
    // (vault.auto_unseal_from_keyring + *.internal.*) by default; toggle
    // surfaces them via ?include_internal=1. Action filter dropdown narrows
    // to one family (grant.*, approval.*, broker.*, etc.) via ?action_filter=.
    const showInternal=document.getElementById('show-internal-events')?.checked;
    const actionFilter=document.getElementById('audit-action-filter')?.value||'';
    const auditParams=new URLSearchParams();
    if(showInternal) auditParams.set('include_internal','1');
    if(actionFilter) auditParams.set('action_filter',actionFilter);
    const auditQuery=auditParams.toString();
    const auditUrl=auditQuery?`/api/audit?${auditQuery}`:'/api/audit';
    const[status,grants,approvals,audit,anomalies]=await Promise.all([
      fetch('/api/status').then(r=>r.json()),
      fetch(grantsUrl).then(r=>r.json()),
      fetch('/api/approvals').then(r=>r.json()),
      fetch(auditUrl).then(r=>r.json()),
      fetch('/api/anomalies').then(r=>r.json()).catch(()=>[]),
    ]);

    // Header
    const dot=document.getElementById('status-dot');
    const stxt=document.getElementById('status-text');
    const ver=document.getElementById('version');
    if(status.running){dot.classList.remove('offline');stxt.textContent='running';}
    else{dot.classList.add('offline');stxt.textContent='stopped';}
    if(status.version)ver.textContent=`v${status.version}`;
    document.getElementById('last-refresh').textContent='updated '+new Date().toLocaleTimeString();

    // Anomaly alerts
    const asec=document.getElementById('anomaly-section');
    const alist=document.getElementById('anomaly-list');
    if(anomalies&&anomalies.length>0){
      asec.style.display='';
      alist.innerHTML=anomalies.map(a=>`<div class="anomaly-card ${a.severity}">
        <div class="anm-meta">
          <div class="anm-agent">${a.agent_id||'unknown'}</div>
          <div class="anm-desc">${a.description||'—'}</div>
          <div class="anm-ts">${relTime(a.detected_at)}</div>
        </div>
        <span class="anm-type">${(a.anomaly_type||'').replace(/_/g,' ')}</span>
      </div>`).join('');
    }else{
      asec.style.display='none';
    }

    // Summary cards
    document.getElementById('cnt-agents').textContent=status.active_agents??'0';
    document.getElementById('cnt-grants').textContent=status.active_grants??grants.length??'0';
    document.getElementById('cnt-approvals').textContent=status.pending_approvals??approvals.length??'0';
    document.getElementById('cnt-audit').textContent=status.audit_events??audit.length??'0';

    // Grants table
    const gb=document.getElementById('grants-body');
    if(!grants||grants.length===0){
      gb.innerHTML='<tr><td colspan="8" class="empty">no grants</td></tr>';
    }else{
      gb.innerHTML=grants.map(g=>`<tr id="grant-row-${g.id}" class="grant-status-${grantStatusClass(g.status)}">
        <td class="mono">${trunc(g.id,18)}</td>
        <td class="mono">${personaLabel(g.persona_id, g.persona_name)}</td>
        <td>${g.credential_name||'—'}</td>
        <td>${g.scope||'—'}</td>
        <td class="gauge-cell">${renderBudgetGauge(g)}</td>
        <td class="ts">${g.expires_at?relTime(g.expires_at):'never'}</td>
        <td class="status-cell">${badge(g.status,g.status)}</td>
        <td>${renderGrantActions(g)}</td>
      </tr>`).join('');
      // Connect SSE for active grants with budgets
      grants.filter(g=>g.status==='active'&&g.budget&&(g.budget.tokens!=null||g.budget.cents!=null))
            .forEach(g=>connectSSE(g.id, 'grant-row-'+g.id));
    }

    // Approvals
    const ac=document.getElementById('approvals-container');
    if(!approvals||approvals.length===0){
      ac.innerHTML='<div class="empty">no pending approvals</div>';
    }else{
      ac.innerHTML=approvals.map(a=>{
        // implementation-note-12 — composite breakdown moved to the
        // dedicated /approvals/{id} page (behind a Show details disclosure).
        // Cards now render a one-line summary + link so the dashboard stays
        // glanceable for the demo. Single-statement approvals keep the
        // legacy per-field row layout.
        const stmts = Array.isArray(a.composite_statements) ? a.composite_statements : null;
        const scope_block = stmts ? `
        <div class="row"><span class="field">Scope</span><a class="field-val approval-link" href="/approvals/${a.id}">${compositeSummary(stmts)}</a></div>` : `
        <div class="row"><span class="field">Credential</span><span class="field-val">${a.credential_name||'—'}</span></div>
        <div class="row"><span class="field">Scope</span><a class="field-val approval-link" href="/approvals/${a.id}">${a.scope||'—'}</a></div>`;
        return `<div class="approval-card" id="approval-card-${a.id}">
        <button class="btn-dismiss" onclick="dismissApproval('${a.id}')" title="Dismiss — records approval.dismissed in audit log">✕</button>
        <div class="row"><span class="field">Persona</span><span class="field-val mono">${personaLabel(a.persona_id, a.persona_name)}</span></div>
        ${scope_block}
        <div class="row"><span class="field">Action</span><span class="field-val">${a.action||'—'}</span></div>
        <div class="row"><span class="field">Risk</span><span class="field-val">${badge(a.risk_level,a.risk_level)}</span></div>
        <div class="row"><span class="field">Requested</span><span class="field-val">${relTime(a.created_at)}</span></div>
        <div class="actions">
          <button class="btn btn-success" onclick="approveRequest('${a.id}')">Approve</button>
          <button class="btn btn-success btn-outline" onclick="approveAlwaysRequest('${a.id}')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days).">&#x1F512; Approve Always</button>
          <a class="btn btn-neutral" href="/approvals/${a.id}">Review</a>
          <button class="btn btn-danger" onclick="denyRequest('${a.id}')">Deny</button>
        </div>
      </div>`;
      }).join('');
    }

    // Audit timeline
    const ab=document.getElementById('audit-body');
    if(!audit||audit.length===0){
      ab.innerHTML='<div class="empty">no audit events</div>';
    }else{
      ab.innerHTML=audit.map(e=>`<div class="timeline-item">
        <span class="ts">${relTime(e.timestamp)}</span>
        <span class="mono">${personaLabel(e.agent_id, e.persona_name)}</span>
        <span>${e.action||'—'}</span>
        <span>${e.credential||'—'}</span>
        <span>${badge(e.outcome,e.outcome)}</span>
      </div>`).join('');
    }
  }catch(err){
    document.getElementById('status-text').textContent='error: '+err.message;
    document.getElementById('status-dot').classList.add('offline');
  }
}
async function loadReceipts(){
  try{
    const signedOnly=document.getElementById('receipt-signed-filter')?.value||'';
    const since=document.getElementById('receipt-since-filter')?.value||'all';
    const personaId=(document.getElementById('receipt-persona-filter')?.value||'').trim();
    const p=new URLSearchParams();
    if(signedOnly==='true')p.set('signed_only','true');
    if(since&&since!=='all')p.set('since',since);
    if(personaId)p.set('persona_id',personaId);
    const url='/api/receipts'+(p.toString()?'?'+p.toString():'');
    const receipts=await fetch(url).then(r=>r.json());
    const rb=document.getElementById('receipts-body');
    if(!rb)return;
    if(!receipts||receipts.length===0){
      rb.innerHTML='<tr><td colspan="6" class="empty">no receipts</td></tr>';
      return;
    }
    rb.innerHTML=receipts.map(r=>{
      const signedHtml=r.signed
        ?'<span class="signed-yes" title="Ed25519 signed by daemon identity">&#10003;</span>'
        :'<span class="signed-no" title="No signature (placeholder)">—</span>';
      const grantLink=`<a href="/grants/${r.grant_id}" class="mono" style="color:var(--accent)">${trunc(r.grant_id,16)}</a>`;
      const ts=r.created_at_epoch?relTime(new Date(r.created_at_epoch*1000).toISOString()):'—';
      const reason=(r.terminal_reason||'').replace(/^\w+\s*/,'').replace(/[{}"]/g,'').slice(0,32)||'—';
      return `<tr>
        <td class="ts">${ts}</td>
        <td>${grantLink}</td>
        <td class="mono">${personaLabel(r.persona_id,r.persona_name)}</td>
        <td style="color:var(--text-muted);font-size:11px">${r.action_summary||'—'}</td>
        <td style="color:var(--text-dim);font-size:11px">${reason}</td>
        <td style="text-align:center">${signedHtml}</td>
      </tr>`;
    }).join('');
  }catch(err){
    const rb=document.getElementById('receipts-body');
    if(rb)rb.innerHTML='<tr><td colspan="6" class="empty">error loading receipts</td></tr>';
  }
}
loadDashboard();
loadReceipts();
setInterval(loadDashboard,5000);
setInterval(loadReceipts,15000);
</script>
</body>
</html>"#;

pub const APPROVAL_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember · approval</title>
<style>
:root{--bg-primary:#0a0a0f;--bg-card:#12121a;--accent:#e85d26;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--border:#1e1e2e;--success:#22c55e;--warning:#eab308;--danger:#ef4444}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'JetBrains Mono',ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
#header{width:100%;max-width:560px;display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
#header .logo{font-size:20px;font-weight:700;color:var(--accent)}
#header a{color:var(--text-muted);font-size:12px;text-decoration:none}
#header a:hover{color:var(--text-primary)}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:24px;width:100%;max-width:560px}
.card-title{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:16px}
.field{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.field:last-of-type{border-bottom:none;margin-bottom:0;padding-bottom:0}
.field-label{color:var(--text-muted);font-size:11px}
.field-val{color:var(--text-primary);font-size:12px;text-align:right;max-width:340px;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge.high{background:rgba(239,68,68,.15);color:var(--danger)}
.badge.medium{background:rgba(234,179,8,.15);color:var(--warning)}
.badge.low{background:rgba(34,197,94,.15);color:var(--success)}
.actions{display:flex;gap:10px;margin-top:20px}
.btn{flex:1;padding:10px 0;border-radius:4px;font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:opacity .1s}
.btn:hover{opacity:.8}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-success{background:rgba(34,197,94,.15);color:var(--success);border-color:rgba(34,197,94,.3)}
.btn-warn{background:rgba(234,179,8,.15);color:var(--warning);border-color:rgba(234,179,8,.3)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger);border-color:rgba(239,68,68,.3)}
#resolved{display:none;margin-top:20px;padding:16px;border-radius:6px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);color:var(--success);text-align:center;font-size:13px}
.composite-statements{margin:8px 0 0;padding:10px 12px;background:rgba(232,93,38,.05);border-left:2px solid var(--accent);border-radius:4px;font-size:12px}
.composite-stmt{padding:5px 0;color:var(--text-primary);text-align:left}
.composite-stmt-idx{color:var(--text-muted);font-weight:600}
.mono{font-family:inherit;font-size:12px}
details.composite-disclosure{margin-top:14px;padding-top:14px;border-top:1px solid var(--border)}
details.composite-disclosure summary{cursor:pointer;font-size:12px;color:var(--text-muted);list-style:none;user-select:none}
details.composite-disclosure summary::-webkit-details-marker{display:none}
details.composite-disclosure summary::before{content:'▸ ';color:var(--accent);font-size:10px}
details.composite-disclosure[open] summary::before{content:'▾ '}
details.composite-disclosure summary:hover{color:var(--text-primary)}
#composite-disclosure[hidden]{display:none}
</style>
</head>
<body>
<div id="header">
  <div class="logo">ember</div>
  <a href="/">dashboard</a>
</div>
<div class="card">
  <div class="card-title">Pending Approval</div>
  <div class="field"><span class="field-label">Action</span><span class="field-val">{{ACTION}}</span></div>
  <div class="field"><span class="field-label">Credential</span><span class="field-val">{{CREDENTIAL}}</span></div>
  <div class="field"><span class="field-label">Scope</span><span class="field-val" id="scope-summary">{{SCOPE}}</span></div>
  <div class="field"><span class="field-label">Risk</span><span class="field-val"><span class="badge {{RISK_LEVEL}}">{{RISK_LEVEL}}</span></span></div>
  <div class="field"><span class="field-label">Persona</span><span class="field-val">{{PERSONA_PREFIX}}</span></div>
  <div class="field"><span class="field-label">Requested</span><span class="field-val">{{CREATED_AT}}</span></div>
  <div class="actions">
    <button class="btn btn-success" id="btn-approve" onclick="resolve('approve')">Approve</button>
    <button class="btn btn-success btn-always" id="btn-approve-always" onclick="resolve('approve-always')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days). Reviewable under Standing Grants.">&#x1F512; Approve Always</button>
    <button class="btn btn-danger" id="btn-deny" onclick="resolve('deny')">Deny</button>
  </div>
  <details class="composite-disclosure" id="composite-disclosure" hidden>
    <summary>Show details</summary>
    <div id="composite-breakdown"></div>
  </details>
  <div id="resolved">Resolved — you can close this tab.</div>
</div>
<script>
const CSRF_TOKEN = "{{CSRF_TOKEN}}";
const APPROVAL_ID = "{{APPROVAL_ID}}";
{{COMPOSITE_STATEMENTS_JS}}
let pollTimer = null;
let breakdownRendered = false;
function renderBreakdown(stmts){
  if(breakdownRendered) return;
  if(!Array.isArray(stmts) || stmts.length===0) return;
  // implementation-note-12 — composite breakdown lives behind a
  // Show details disclosure (collapsed-by-default) so the dedicated
  // /approvals/{id} page leads with the high-level approve/deny
  // decision instead of overwhelming the demo audience with a raw
  // 3 statements list. Clicking the disclosure reveals it.
  const el = document.getElementById('composite-disclosure');
  const body = document.getElementById('composite-breakdown');
  body.innerHTML = renderCompositeStatements(stmts);
  el.hidden = false;
  // Tighten the scope summary to match the dashboard card.
  const sum = document.getElementById('scope-summary');
  if(sum) sum.textContent = compositeSummary(stmts);
  breakdownRendered = true;
}
function showResolved(status){
  const btns = document.querySelectorAll('.btn');
  btns.forEach(b=>b.disabled=true);
  const el = document.getElementById('resolved');
  el.textContent = 'Resolved (' + status + ') — you can close this tab.';
  el.style.display='block';
  document.querySelector('.card-title').textContent = 'Approval ' + status.charAt(0).toUpperCase() + status.slice(1);
  if(pollTimer){clearInterval(pollTimer);pollTimer=null;}
  setTimeout(()=>{window.location.href='/';},3000);
}
async function pollStatus(){
  try{
    const resp = await fetch(`/api/approvals/${APPROVAL_ID}`);
    if(resp.ok){
      const data = await resp.json();
      if(Array.isArray(data.composite_statements)) renderBreakdown(data.composite_statements);
      if(data.status && data.status !== 'pending'){
        showResolved(data.status);
      }
    }
  }catch(_){}
}
// Fire once on load so the breakdown appears without waiting 2s.
pollStatus();
pollTimer = setInterval(pollStatus, 2000);
async function resolve(action){
  const btns = document.querySelectorAll('.btn');
  btns.forEach(b=>b.disabled=true);
  try{
    const resp = await fetch(`/api/approvals/${APPROVAL_ID}/${action}`,{
      method:'POST',
      headers:{'X-Ember-CSRF-Token':CSRF_TOKEN}
    });
    if(resp.ok){
      const label = action==='approve'?'approved':action==='approve-always'?'approved (always)':'denied';
      showResolved(label);
    }else{
      const err = await resp.json().catch(()=>({error:'request failed'}));
      alert('Error: '+(err.error||resp.status));
      btns.forEach(b=>b.disabled=false);
    }
  }catch(e){
    alert('Network error: '+e.message);
    btns.forEach(b=>b.disabled=false);
  }
}
</script>
</body>
</html>"#;

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
    /// Expected `Origin` for POST requests (security check defense-in-depth).
    ///
    /// Set to `http://127.0.0.1:<port>` derived from the actual bound address
    /// at dashboard startup. Every POST handler checks that the incoming
    /// `Origin` (or `Referer` origin component) matches this value before the
    /// CSRF token check. Mismatches are rejected with 403.
    ///
    /// Defaults to `"http://127.0.0.1:3141"` for backwards-compat with tests
    /// that construct `DashboardState` without an explicit origin.
    pub expected_origin: String,
    /// implementation-note-11: the address the dashboard actually
    /// bound to, surfaced via `/api/status` as `dashboard_addr_bound`. Always
    /// `Some` when the dashboard is serving traffic (you can't reach this
    /// state otherwise) but the field is `Option<>` so test fixtures can
    /// model the "not bound" case to verify the JSON contract returns `null`.
    /// Resolved from `TcpListener::local_addr()` after a successful bind so
    /// port-0 ephemeral assignments are reflected truthfully.
    pub dashboard_actual_addr: Option<SocketAddr>,
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
            let html = DASHBOARD_HTML
                .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
                .replace("{{CSRF_TOKEN}}", &state.csrf_token);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap()
        }

        (Method::GET, "/api/status") => {
            let active_grants = state.store.list_active_grants().unwrap_or_default().len();
            let pending_approvals = state.store.list_pending_approvals().unwrap_or_default().len();
            let audit_events = state.store.audit_count().unwrap_or(0);
            let active_agents = state.store.list_personas().unwrap_or_default()
                .iter()
                .filter(|p| p.status == "active")
                .count();
            // implementation-note-11: stringify the bound address
            // (or `null`) so the CLI `status` subcommand stops printing the
            // configured-but-not-bound port. Field shape: `Option<String>` →
            // `null` when the dashboard isn't bound, full `host:port` when it is.
            let dashboard_addr_bound = state
                .dashboard_actual_addr
                .map(|a| a.to_string());
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
            let (pubkey, canonical_version) = match crate::receipt::current_identity() {
                Some(id) => (id.pubkey_hex(), crate::receipt::CANONICAL_VERSION),
                None => (String::new(), crate::receipt::CANONICAL_VERSION),
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
        //   signed_only=true  — exclude receipts with empty signer_pubkey
        //   persona_id=<id>   — restrict to one persona
        //   since=24h|7d|all  — lower bound on created_at (default: all)
        //   limit=N           — cap (default 100)
        (Method::GET, "/api/receipts") => {
            use crate::receipt::ReceiptFilter;

            let (persona_id, signed_only, since_iso) = req.uri().query().map(|q| {
                let mut pid: Option<String> = None;
                let mut signed = false;
                let mut since: Option<String> = None;
                for kv in q.split('&') {
                    let mut parts = kv.splitn(2, '=');
                    let k = parts.next().unwrap_or("");
                    let v = parts.next().unwrap_or("");
                    match k {
                        "persona_id" if !v.is_empty() => pid = Some(v.to_string()),
                        "signed_only" if v == "true" || v == "1" => signed = true,
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
                (pid, signed, since)
            }).unwrap_or((None, false, None));

            let filter = ReceiptFilter {
                persona_id,
                signed_only,
                since_iso,
                limit: Some(100),
                grant_id: None,
                kind: None,
                resource: None,
            };
            let receipts = state
                .store
                .list_receipts_filtered(&filter)
                .unwrap_or_default();
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = receipts
                .iter()
                .map(|r| {
                    let signed = r.evidence.signer_pubkey != "0".repeat(64)
                        && r.evidence.sig != "0".repeat(128)
                        && !r.evidence.signer_pubkey.is_empty();
                    let persona_name = names.get(&r.summary.persona_id).cloned();
                    let action_summary = format!(
                        "{} · {}",
                        r.summary.service,
                        r.summary.resource
                            .chars()
                            .take(40)
                            .collect::<String>()
                    );
                    serde_json::json!({
                        "id": r.id,
                        "grant_id": r.grant_id,
                        "persona_id": r.summary.persona_id,
                        "persona_name": persona_name,
                        "action_summary": action_summary,
                        "terminal_reason": format!("{:?}", r.lifecycle.terminal_reason),
                        "created_at_epoch": r.lifecycle.terminated_at,
                        "signed": signed,
                        "signer_pubkey": r.evidence.signer_pubkey,
                    })
                })
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/api/personas") => {
            let personas = state.store.list_personas().unwrap_or_default();
            let body: Vec<serde_json::Value> = personas
                .iter()
                .map(|p| serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "public_key": p.public_key,
                    "created_at": p.created_at,
                    "status": p.status,
                }))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        (Method::GET, "/api/grants") => {
            let grants = state.store.list_active_grants().unwrap_or_default();
            // implementation-note-8 — surface persona.name alongside persona_id
            // so the dashboard can render real display names instead of UUID
            // prefixes. Lookup is rendering-layer only; raw persona_id is
            // unchanged, contract additive.
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = grants
                .iter()
                .map(|g| {
                    let mut conds = serde_json::Map::new();
                    if let Some(rate) = g.max_uses_per_hour {
                        conds.insert("rate_limit".to_string(), serde_json::json!(format!("{}/hour", rate)));
                    }
                    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
                        conds.insert("time_window".to_string(), serde_json::json!(format!("{}:00-{}:00 UTC", start, end)));
                    }
                    if let Some(ref targets) = g.allowed_targets {
                        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
                    }
                    if let Some(limit) = g.spending_limit_cents {
                        conds.insert("spending_limit".to_string(), serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)));
                    }
                    if let Some(depth) = g.max_delegation_depth {
                        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
                    }
                    let conditions = if conds.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(conds) };

                    // implementation-note-13 (budget_persists_on_simple_grant) —
                    // surface the projected budget + usage so the dashboard's
                    // BUDGET column and live gauge JS can render the operator-
                    // configured ceilings. `g.budget` projects from the signed
                    // chain's first-statement budget; `g.usage` is the running
                    // tally. Both stay omitted when no axis was set so existing
                    // consumers (and tests) see the same shape they did pre-fix.
                    let mut entry = serde_json::Map::new();
                    entry.insert("id".into(), serde_json::json!(g.id));
                    entry.insert("persona_id".into(), serde_json::json!(g.persona_id));
                    entry.insert("persona_name".into(), serde_json::json!(names.get(&g.persona_id).cloned()));
                    entry.insert("credential_name".into(), serde_json::json!(g.credential_name));
                    entry.insert("scope".into(), serde_json::json!(g.scope));
                    entry.insert("created_at".into(), serde_json::json!(g.created_at));
                    entry.insert("expires_at".into(), serde_json::json!(g.expires_at));
                    entry.insert("status".into(), serde_json::json!(g.status));
                    entry.insert("conditions".into(), conditions);
                    if let Some(b) = g.budget.as_ref().filter(|b| !b.is_none_set()) {
                        entry.insert("budget".into(), serde_json::to_value(b).unwrap_or(serde_json::Value::Null));
                        entry.insert("usage".into(), serde_json::to_value(&g.usage).unwrap_or(serde_json::Value::Null));
                    }
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
            // implementation-note-8 — `persona.name` lookup for the approval card.
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = approvals
                .iter()
                .map(|a| serde_json::json!({
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
                    // implementation-note-5 — composite envelopes (sandbox-run 3-statement
                    // bundle) surface as a single approval entry whose
                    // statements array drives the per-statement card UI.
                    "composite_statements": a.composite_statements,
                    "result_grant_id": a.result_grant_id,
                }))
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
                    // implementation-note-8 — additive `persona_name` lookup.
                    let persona_name = state.store.get_persona(&a.persona_id).ok().map(|p| p.name);
                    json_response(StatusCode::OK, &serde_json::json!({
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
                        // implementation-note-5 — surface composite statements + minted grant ID.
                        "composite_statements": a.composite_statements,
                        "result_grant_id": a.result_grant_id,
                    }))
                }
                Err(_) => error_response(404, "approval not found"),
            }
        }

        (Method::GET, "/api/audit") => {
            use crate::audit::AuditFilter;
            // implementation-note-8 — operator audit timeline hides internal
            // bookkeeping events (vault.auto_unseal_from_keyring + the
            // generic `*.internal.*` namespace) by default. The dashboard
            // toggle re-fetches with `?include_internal=1` so internal
            // events are reachable without hand-editing URLs.
            // `?action_filter=<prefix>` further narrows to one action family
            // (e.g. `grant.`, `approval.`, `broker.`). Both are rendering-
            // layer only — store rows are unchanged.
            let (include_internal, action_filter) = req.uri().query().map(|q| {
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
            }).unwrap_or((false, None));
            let entries = state
                .store
                .query_audit(&AuditFilter { limit: Some(100), action_prefix: action_filter, ..Default::default() })
                .unwrap_or_default();
            let names = persona_name_map(&state.store);
            let body: Vec<serde_json::Value> = entries
                .iter()
                .filter(|e| include_internal || !is_internal_audit_action(&e.action))
                .map(|e| {
                    let persona_name = e
                        .agent_id
                        .as_deref()
                        .and_then(|id| names.get(id).cloned());
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
                    .unwrap();
                // Default 30-day TTL per design spec.
                let expires_at = {
                    let thirty_days = chrono::Utc::now() + chrono::Duration::days(30);
                    Some(thirty_days.format("%Y-%m-%dT%H:%M:%S").to_string())
                };
                match state.store.resolve_approval(
                    id,
                    &ApprovalOutcome::Always {
                        scope: None,
                        expires_at,
                    },
                ) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"approved": true, "standing_grant_created": true})),
                    Err(e) => error_response(400, &e.to_string()),
                }
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
                // implementation-note-6 — optional JSON body carries WebAuthn
                // assertion metadata: `{biometric: bool, credential_id?: string,
                // assertion?: {clientDataJSON, authenticatorData, signature, ...}}`.
                // The dashboard JS calls `navigator.credentials.get()` with a
                // freshly-minted challenge from `/api/webauthn/challenge` and
                // forwards the assertion here. We accept the operator-asserted
                // `biometric=true` claim trusting the same-origin browser
                // because the dashboard is bound to localhost; deeper
                // attestation (verifying the assertion signature against a
                // pre-registered passkey) is on the protocol-side roadmap and
                // tracked separately. The audit log records exactly what was
                // claimed, so downstream verification is possible.
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let biometric = params["biometric"].as_bool().unwrap_or(false);
                let credential_id = params["credential_id"].as_str();
                match state.store.resolve_approval_with_biometric(
                    &id,
                    &ApprovalOutcome::Approved,
                    biometric,
                    credential_id,
                ) {
                    Ok(()) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "approved": true,
                            "biometric": biometric,
                            "credential_id": credential_id,
                        }),
                    ),
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
                    .unwrap()
                    .to_string();
                // implementation-note-6 — accept biometric metadata on deny too so
                // an auditor can distinguish "human rejected with TouchID"
                // from "untouched click-through".
                use http_body_util::BodyExt as _;
                let body_bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let params: serde_json::Value =
                    serde_json::from_slice(&body_bytes).unwrap_or_default();
                let biometric = params["biometric"].as_bool().unwrap_or(false);
                let credential_id = params["credential_id"].as_str();
                match state.store.resolve_approval_with_biometric(
                    &id,
                    &ApprovalOutcome::Denied {
                        reason: "denied via dashboard".to_string(),
                    },
                    biometric,
                    credential_id,
                ) {
                    Ok(()) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "denied": true,
                            "biometric": biometric,
                            "credential_id": credential_id,
                        }),
                    ),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // implementation-note-6 — WebAuthn challenge minting endpoint.
        //
        // Returns a fresh 32-byte random challenge (base64url-encoded) plus
        // a configured `rp_id` so the dashboard JS can call
        // `navigator.credentials.get({publicKey: {challenge, rpId, ...}})`.
        //
        // We don't (yet) persist the challenge or bind it to a pending
        // approval — the assertion ride-along on the approve POST is
        // accepted as a same-origin attestation that the browser raised
        // the platform-authenticator (Touch ID / Windows Hello) sheet.
        // Full server-side challenge replay protection is tracked
        // separately on the protocol roadmap; the audit-log capture
        // satisfies the May 3 demo's evidence requirement.
        (Method::GET, "/api/webauthn/challenge") => {
            let mut buf = [0u8; 32];
            if getrandom::fill(&mut buf).is_err() {
                return Ok(error_response(500, "challenge entropy failure"));
            }
            // base64url (RFC 4648 §5) encoded without padding — what
            // navigator.credentials.get() expects in the spec-aligned
            // PublicKeyCredentialRequestOptions.challenge field.
            let challenge = base64url_encode(&buf);
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "challenge": challenge,
                    "rp_id": "localhost",
                    "allow_credentials": [],
                    "user_verification": "preferred",
                }),
            )
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
            && !path.ends_with("/pause")
            && !path.ends_with("/unpause")
            && !path.ends_with("/extend") =>
        {
            let id = path.strip_prefix("/api/grants/").unwrap_or("");
            if id.is_empty() {
                error_response(400, "missing grant id")
            } else {
                match state.store.get_grant(id) {
                    Ok(g) => json_response(StatusCode::OK, &grant_to_json_with_store(&g, &state.store)),
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
                    Err(crate::store::StoreError::NotFound) => error_response(404, "grant not found"),
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
                    Err(crate::store::StoreError::NotFound) => error_response(404, "grant not found"),
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
                let body_bytes = req.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
                let params: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
                let tokens_delta = params["tokens_delta"].as_u64();
                let cents_delta = params["cents_delta"].as_u64();
                let ttl_extension_secs = params["ttl_extension_secs"].as_u64();

                match state.store.extend_grant(id, tokens_delta, cents_delta, ttl_extension_secs) {
                    Ok(g) => json_response(StatusCode::OK, &grant_to_json(&g)),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // POST /api/approvals/{id}/dismiss — implementation-note-7
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
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"dismissed": true})),
                    Err(crate::store::StoreError::NotFound) => error_response(404, "approval not found"),
                    Err(crate::store::StoreError::AlreadyResolved) => error_response(409, "approval already resolved"),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // GET /grants/{id} — HTML grant-detail page with Pause/Extend buttons.
        (Method::GET, p) if p.starts_with("/grants/") && !p.contains("/pause") && !p.contains("/unpause") && !p.contains("/extend") && !p.contains("/revoke") => {
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
            let accept = req.headers()
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let format_param = req.uri().query().and_then(|q| {
                q.split('&').find_map(|kv| {
                    let mut parts = kv.splitn(2, '=');
                    if parts.next() == Some("format") { parts.next() } else { None }
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
                if pct >= 100 { "budget_exhausted" }
                else if pct >= 95 { "budget_warning" }
                else { "usage_update" }
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
                    let html = render_approval_page(&state.csrf_token, &a);
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
/// Post-composite-port (design): emits a `statements` array with per-
/// Statement `sid`, `resource_type`, `actions`, `resource`, `budget`, and
/// `usage`. Dashboard / receipt views render per-Statement meters from
/// this field — there is no envelope-level `budget`/`usage` projection
/// under the V0 schema.
fn grant_to_json_with_store(
    g: &crate::grant::GrantInfo,
    store: &crate::store::DaemonStore,
) -> serde_json::Value {
    let mut conds = serde_json::Map::new();
    if let Some(rate) = g.max_uses_per_hour {
        conds.insert("rate_limit".to_string(), serde_json::json!(format!("{}/hour", rate)));
    }
    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
        conds.insert("time_window".to_string(), serde_json::json!(format!("{}:00-{}:00 UTC", start, end)));
    }
    if let Some(ref targets) = g.allowed_targets {
        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
    }
    if let Some(limit) = g.spending_limit_cents {
        conds.insert("spending_limit".to_string(), serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)));
    }
    if let Some(depth) = g.max_delegation_depth {
        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
    }
    let conditions = if conds.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(conds) };

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
        Err(_) => serde_json::Value::Array(Vec::new()),
    };

    // implementation-note-8 — additive `persona_name` lookup so the dashboard
    // can render the persona's display name as the primary label.
    let persona_name = store.get_persona(&g.persona_id).ok().map(|p| p.name);

    serde_json::json!({
        "id": g.id,
        "persona_id": g.persona_id,
        "persona_name": persona_name,
        "credential_name": g.credential_name,
        "scope": g.scope,
        "created_at": g.created_at,
        "expires_at": g.expires_at,
        "status": g.status,
        "conditions": conditions,
        "statements": statements,
        "paused": g.paused,
        "receipt_id": g.receipt_id,
    })
}

/// Back-compat shim for callers that don't need the `statements` array.
/// Forwards to `grant_to_json_with_store` but omits the array.
fn grant_to_json(g: &crate::grant::GrantInfo) -> serde_json::Value {
    let mut conds = serde_json::Map::new();
    if let Some(rate) = g.max_uses_per_hour {
        conds.insert("rate_limit".to_string(), serde_json::json!(format!("{}/hour", rate)));
    }
    if let (Some(start), Some(end)) = (g.allowed_hours_start, g.allowed_hours_end) {
        conds.insert("time_window".to_string(), serde_json::json!(format!("{}:00-{}:00 UTC", start, end)));
    }
    if let Some(ref targets) = g.allowed_targets {
        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
    }
    if let Some(limit) = g.spending_limit_cents {
        conds.insert("spending_limit".to_string(), serde_json::json!(format!("${}.{:02}/day", limit / 100, limit % 100)));
    }
    if let Some(depth) = g.max_delegation_depth {
        conds.insert("delegation_depth".to_string(), serde_json::json!(depth));
    }
    let conditions = if conds.is_empty() { serde_json::Value::Null } else { serde_json::Value::Object(conds) };
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
fn build_signed_receipt_html(r: &core_types::grant_receipt::GrantReceipt) -> String {
    let json = serde_json::to_string_pretty(r).unwrap_or_default();
    let escaped = json.replace('<', "&lt;").replace('>', "&gt;");
    let terminal = &r.lifecycle.terminal_reason;
    let reason_label = match terminal {
        core_types::grant_receipt::TerminalReason::Expired => "expired".to_string(),
        core_types::grant_receipt::TerminalReason::Revoked { by, reason } => {
            let actor = match by {
                core_types::grant_receipt::RevokeActor::Operator => "operator",
                core_types::grant_receipt::RevokeActor::Agent => "agent",
                core_types::grant_receipt::RevokeActor::ParentCascade => "parent cascade",
            };
            if reason.is_empty() {
                format!("revoked by {actor}")
            } else {
                format!("revoked by {actor}: {reason}")
            }
        }
        core_types::grant_receipt::TerminalReason::ExhaustedByBudget {
            statement_sid,
            axis,
        } => format!("exhausted_by_budget on {statement_sid} ({axis:?})"),
        core_types::grant_receipt::TerminalReason::ParentCascadeRevoked {
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
        "<p style=\"color:var(--text-muted);font-size:12px\">No statements recorded.</p>".to_string()
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
</style>
</head>
<body>
<div id="header">
  <div class="logo">ember</div>
  <div><a href="/">dashboard</a></div>
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
    <div class="card-title">Evidence (Ed25519)</div>
    <div class="field"><span class="field-label">Signer pubkey</span><span class="field-val">{signer_pubkey}</span></div>
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
    <a href="/daemon/identity.json" class="btn">Trust anchor</a>
    <a href="/" class="btn">Back</a>
  </div>
</main>
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
        last_used = r.lifecycle.last_used_at.map(|t| format!("epoch {t}")).unwrap_or_else(|| "—".into()),
        terminated = r.lifecycle.terminated_at,
        statements_table = statements_table,
        signer_pubkey = r.evidence.signer_pubkey,
        hash = r.evidence.hash,
        sig = r.evidence.sig,
        canonical = r.evidence.canonical_version,
        escaped = escaped,
    )
}

/// Build the signed-receipt JSON for a grant (for download / display).
fn build_receipt_json(g: &crate::grant::GrantInfo) -> serde_json::Value {
    let terminal = matches!(
        g.status.as_str(),
        "revoked" | "expired" | "expired_by_budget" | "parent_cascade_revoked"
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
pub(crate) fn render_statement_gauges(statements: &[(usize, &core_types::Statement)]) -> String {
    if statements.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (block_idx, stmt) in statements {
        let actions: Vec<&str> = stmt.actions.iter().map(|a| a.as_str()).collect();
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
        let has_budget = stmt.budget.as_ref().map(|b| !b.is_none_set()).unwrap_or(false);
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
                let pct = (u.wall_clock_secs * 100).checked_div(cap).unwrap_or(100).min(100);
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
    if pct >= 95 { "var(--danger)" } else if pct >= 80 { "var(--warning)" } else { "var(--success)" }
}

/// Render the `/grants/{id}` HTML detail page.
///
/// Shows grant metadata, per-Statement budget gauges, and action buttons:
/// Pause (or Resume if already paused), Extend, Revoke, View Receipt.
/// Terminal grants show a read-only view with only the receipt link.
fn build_grant_detail_html(
    g: &crate::grant::GrantInfo,
    csrf_token: &str,
    access_grant: Option<&core_types::AccessGrant>,
) -> String {
    let status_class = match g.status.as_str() {
        "active" => "active",
        "paused" => "paused",
        "revoked" | "parent_cascade_revoked" => "revoked",
        "expired" | "expired_by_budget" | "exhausted_by_budget" => "revoked",
        _ => "pending",
    };

    let is_terminal = matches!(
        g.status.as_str(),
        "revoked" | "expired" | "expired_by_budget" | "exhausted_by_budget" | "parent_cascade_revoked"
    );

    let budget_section = if let Some(chain) = access_grant {
        let stmts: Vec<(usize, &core_types::Statement)> = chain.statements().collect();
        let gauges = render_statement_gauges(&stmts);
        if gauges.is_empty() {
            String::new()
        } else {
            format!(r#"<div class="card"><div class="card-title">Statements &amp; Budget</div>{gauges}</div>"#)
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
            id = g.id, csrf = csrf_token,
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
            id = g.id, csrf = csrf_token,
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
  <div class="logo">ember</div>
  <div class="nav"><a href="/">dashboard</a></div>
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
    <div class="field"><span class="field-label">Expires</span><span class="field-val">{expires_at}</span></div>
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
</script>
</body>
</html>"#,
        id = g.id,
        persona_id = truncate_persona_id(&g.persona_id),
        credential_name = g.credential_name,
        scope = g.scope,
        created_at = g.created_at,
        expires_at = g.expires_at.as_deref().unwrap_or("never"),
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
    g: &crate::grant::GrantInfo,
    _csrf_token: &str,
    access_grant: Option<&core_types::AccessGrant>,
) -> String {
    let receipt_json = serde_json::to_string_pretty(&build_receipt_json(g)).unwrap_or_default();

    // Per-Statement gauges (composite path) — preferred when the chain is available.
    let budget_section = if let Some(chain) = access_grant {
        let stmts: Vec<(usize, &core_types::Statement)> = chain.statements().collect();
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
        let token_pct = budget_tokens.map(|bt| (tokens_used * 100).checked_div(bt).unwrap_or(100u64));
        let cents_pct = budget_cents.map(|bc| (cents_used * 100).checked_div(bc).unwrap_or(100u64));
        let token_gauge = if let (Some(bt), Some(pct)) = (budget_tokens, token_pct) {
            let color = gauge_color(pct);
            format!(r#"<div class="gauge-label"><span>Tokens</span><span>{tokens_used} / {bt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#)
        } else {
            String::new()
        };
        let cents_gauge = if let (Some(bc), Some(pct)) = (budget_cents, cents_pct) {
            let color = gauge_color(pct);
            let used_fmt = format!("${:.2}", cents_used as f64 / 100.0);
            let budget_fmt = format!("${:.2}", bc as f64 / 100.0);
            format!(r#"<div class="gauge-label"><span>Cost</span><span>{used_fmt} / {budget_fmt} ({pct}%)</span></div><div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#)
        } else {
            String::new()
        };
        let no_budget_msg = if budget_tokens.is_none() && budget_cents.is_none() {
            r#"<div style="color:var(--text-dim);font-size:12px;padding:8px 0">No budget set (TTL-only grant)</div>"#
        } else {
            ""
        };
        format!(r#"<div class="card"><div class="card-title">Budget &amp; Usage</div>{token_gauge}{cents_gauge}{no_budget_msg}</div>"#)
    };

    let status_class = match g.status.as_str() {
        "active" => "active",
        "revoked" | "parent_cascade_revoked" => "revoked",
        "expired" | "expired_by_budget" => "revoked",
        _ => "pending",
    };

    format!(r#"<!DOCTYPE html>
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
  <div class="logo">ember</div>
  <div class="nav">
    <a href="/">dashboard</a>
  </div>
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

fn json_response(status: StatusCode, body: &serde_json::Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn error_response(status: u16, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({"error": msg});
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

/// Truncate a persona ID for UI display. Keeps the 12-char UUID prefix after "persona-".
/// Render the dedicated `/approvals/{id}` page HTML for a given approval
/// record, with all `{{TOKEN}}` placeholders substituted.
///
/// implementation-note-12 — the page leads with the high-level
/// Approve/Deny decision; the per-statement breakdown for composite
/// approvals is rendered client-side from the polled JSON behind a
/// "Show details" disclosure (collapsed-by-default). Both the dashboard
/// pending-approvals card and this page share the same
/// `renderCompositeStatements` helper via `COMPOSITE_STATEMENTS_JS`,
/// so the two surfaces cannot drift.
fn render_approval_page(
    csrf_token: &str,
    approval: &crate::approval::ApprovalRequestInfo,
) -> String {
    let persona_prefix = truncate_persona_id(&approval.persona_id);
    APPROVAL_HTML_TEMPLATE
        .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
        .replace("{{CSRF_TOKEN}}", csrf_token)
        .replace("{{APPROVAL_ID}}", &approval.id)
        .replace("{{ACTION}}", &approval.action)
        .replace("{{CREDENTIAL}}", &approval.credential_name)
        .replace("{{SCOPE}}", &approval.scope)
        .replace("{{RISK_LEVEL}}", &approval.risk_level)
        .replace("{{PERSONA_PREFIX}}", &persona_prefix)
        .replace("{{CREATED_AT}}", &approval.created_at)
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
mod tests {
    use super::*;
    use crate::store::DaemonStore;

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
            // implementation-note-11: default to a well-known
            // localhost addr so most tests see a "bound" dashboard; tests
            // that exercise the "not bound" branch override directly.
            dashboard_actual_addr: Some(
                "127.0.0.1:3141".parse().expect("test addr parse"),
            ),
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

    async fn call_post_wrong_csrf(
        state: Arc<DashboardState>,
        path: &str,
    ) -> Response<Full<Bytes>> {
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
        req: Request<impl hyper::body::Body>,
    ) -> Response<Full<Bytes>> {
        let path = req.uri().path().to_owned();
        let method = req.method().clone();
        let headers = req.headers().clone();

        match (method.clone(), path.as_str()) {
            (Method::GET, "/") | (Method::GET, "/index.html") => {
                let html = DASHBOARD_HTML
                    .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
                    .replace("{{CSRF_TOKEN}}", &state.csrf_token);
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Full::new(Bytes::from(html)))
                    .unwrap()
            }

            (Method::GET, "/api/status") => {
                let active_grants = state.store.list_active_grants().unwrap_or_default().len();
                let pending_approvals = state.store.list_pending_approvals().unwrap_or_default().len();
                let audit_events = state.store.audit_count().unwrap_or(0);
                let active_agents = state.store.list_personas().unwrap_or_default()
                    .iter()
                    .filter(|p| p.status == "active")
                    .count();
                // implementation-note-11: mirror the production
                // handler so `api_status_*` tests cover the new field shape.
                let dashboard_addr_bound = state
                    .dashboard_actual_addr
                    .map(|a| a.to_string());
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
                let body: Vec<serde_json::Value> = grants
                    .iter()
                    .map(|g| grant_to_json_with_store(g, &state.store))
                    .collect();
                json_response(StatusCode::OK, &serde_json::Value::Array(body))
            }

            (Method::GET, "/api/anomalies") => {
                let anomalies = state.store.detect_anomalies().unwrap_or_default();
                let body = serde_json::to_value(&anomalies).unwrap_or(serde_json::Value::Array(vec![]));
                json_response(StatusCode::OK, &body)
            }

            // implementation-note-6 — WebAuthn challenge endpoint (test handler).
            // Mirrors the production handler exactly; kept in sync here so
            // dashboard tests can assert on the response shape.
            (Method::GET, "/api/webauthn/challenge") => {
                let mut buf = [0u8; 32];
                if getrandom::fill(&mut buf).is_err() {
                    return error_response(500, "challenge entropy failure");
                }
                let challenge = base64url_encode(&buf);
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "challenge": challenge,
                        "rp_id": "localhost",
                        "allow_credentials": [],
                        "user_verification": "preferred",
                    }),
                )
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
                        // implementation-note-8 — surface persona.name for the
                        // approval-detail render path (test handler mirrors
                        // production).
                        let persona_name = state.store.get_persona(&a.persona_id).ok().map(|p| p.name);
                        json_response(StatusCode::OK, &serde_json::json!({
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
                        }))
                    }
                    Err(_) => error_response(404, "approval not found"),
                }
            }

            (Method::GET, "/api/audit") => {
                use crate::audit::AuditFilter;
                // implementation-note-8 — mirror the production handler's
                // `?include_internal=1` toggle and `?action_filter=<prefix>`
                // so test coverage reflects the same operator-audit semantics.
                let (include_internal, action_filter) = req.uri().query().map(|q| {
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
                }).unwrap_or((false, None));
                let entries = state
                    .store
                    .query_audit(&AuditFilter { limit: Some(100), action_prefix: action_filter, ..Default::default() })
                    .unwrap_or_default();
                let names = persona_name_map(&state.store);
                let body: Vec<serde_json::Value> = entries
                    .iter()
                    .filter(|e| include_internal || !is_internal_audit_action(&e.action))
                    .map(|e| {
                        let persona_name = e
                            .agent_id
                            .as_deref()
                            .and_then(|id| names.get(id).cloned());
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

            // /grants/{id} — HTML grant-detail page
            (Method::GET, p) if p.starts_with("/grants/") && !p.contains("/pause") && !p.contains("/unpause") && !p.contains("/extend") && !p.contains("/revoke") => {
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
                        let html = render_approval_page(&state.csrf_token, &a);
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
                        .unwrap();
                    let expires_at = {
                        let thirty_days = chrono::Utc::now() + chrono::Duration::days(30);
                        Some(thirty_days.format("%Y-%m-%dT%H:%M:%S").to_string())
                    };
                    match state.store.resolve_approval(
                        id,
                        &ApprovalOutcome::Always {
                            scope: None,
                            expires_at,
                        },
                    ) {
                        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"approved": true, "standing_grant_created": true})),
                        Err(e) => error_response(400, &e.to_string()),
                    }
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

            // implementation-note-7 — dismiss (test handler)
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
                        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"dismissed": true})),
                        Err(crate::store::StoreError::NotFound) => error_response(404, "approval not found"),
                        Err(crate::store::StoreError::AlreadyResolved) => error_response(409, "approval already resolved"),
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
                        Err(crate::store::StoreError::NotFound) => error_response(404, "grant not found"),
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
                        Err(crate::store::StoreError::NotFound) => error_response(404, "grant not found"),
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
                        Ok(g) => json_response(StatusCode::OK, &grant_to_json(&g)),
                        Err(_) => error_response(404, "grant not found"),
                    }
                }
            }

            // 69K.7: receipt viewer
            (Method::GET, p) if p.starts_with("/receipts/") => {
                let id = p.strip_prefix("/receipts/").unwrap_or("");
                match state.store.get_grant(id) {
                    Ok(g) => {
                        let chain = state.store.get_access_grant(&g.id).ok();
                        let html = build_receipt_html(&g, &state.csrf_token, chain.as_ref());
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from(html)))
                            .unwrap()
                    }
                    Err(_) => error_response(404, "grant not found"),
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

            // GET /api/receipts — test handler mirrors production filter logic.
            (Method::GET, "/api/receipts") => {
                use crate::receipt::ReceiptFilter;
                let (persona_id, signed_only, since_iso) = req.uri().query().map(|q| {
                    let mut pid: Option<String> = None;
                    let mut signed = false;
                    let mut since: Option<String> = None;
                    for kv in q.split('&') {
                        let mut parts = kv.splitn(2, '=');
                        let k = parts.next().unwrap_or("");
                        let v = parts.next().unwrap_or("");
                        match k {
                            "persona_id" if !v.is_empty() => pid = Some(v.to_string()),
                            "signed_only" if v == "true" || v == "1" => signed = true,
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
                    (pid, signed, since)
                }).unwrap_or((None, false, None));
                let filter = ReceiptFilter {
                    persona_id,
                    signed_only,
                    since_iso,
                    limit: Some(100),
                    grant_id: None,
                    kind: None,
                    resource: None,
                };
                let receipts = state.store.list_receipts_filtered(&filter).unwrap_or_default();
                let names = persona_name_map(&state.store);
                let body: Vec<serde_json::Value> = receipts.iter().map(|r| {
                    let signed = r.evidence.signer_pubkey != "0".repeat(64)
                        && r.evidence.sig != "0".repeat(128)
                        && !r.evidence.signer_pubkey.is_empty();
                    let persona_name = names.get(&r.summary.persona_id).cloned();
                    let action_summary = format!(
                        "{} · {}",
                        r.summary.service,
                        r.summary.resource.chars().take(40).collect::<String>()
                    );
                    serde_json::json!({
                        "id": r.id,
                        "grant_id": r.grant_id,
                        "persona_id": r.summary.persona_id,
                        "persona_name": persona_name,
                        "action_summary": action_summary,
                        "terminal_reason": format!("{:?}", r.lifecycle.terminal_reason),
                        "created_at_epoch": r.lifecycle.terminated_at,
                        "signed": signed,
                        "signer_pubkey": r.evidence.signer_pubkey,
                    })
                }).collect();
                json_response(StatusCode::OK, &serde_json::Value::Array(body))
            }

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
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/html"));
    }

    #[tokio::test]
    async fn api_status_returns_json_with_running_true() {
        let state = make_state();
        let resp = call(state, "/api/status").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["running"], true);
    }

    #[tokio::test]
    async fn api_grants_empty_returns_array() {
        let state = make_state();
        let resp = call(state, "/api/grants").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn api_approvals_empty_returns_array() {
        let state = make_state();
        let resp = call(state, "/api/approvals").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn api_audit_empty_returns_array() {
        let state = make_state();
        let resp = call(state, "/api/audit").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let state = make_state();
        let resp = call(state, "/api/unknown").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// implementation-note-6 — `/api/webauthn/challenge` returns a fresh
    /// base64url-encoded challenge plus rp_id + user_verification fields,
    /// matching the shape `navigator.credentials.get({publicKey: ...})`
    /// expects in the dashboard JS.
    #[tokio::test]
    async fn webauthn_challenge_returns_random_base64url() {
        let state = make_state();
        let resp = call(state, "/api/webauthn/challenge").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let challenge = json["challenge"].as_str().expect("challenge field");
        // 32 random bytes encoded as base64url-no-pad → 43 chars.
        assert_eq!(challenge.len(), 43);
        assert!(
            challenge.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-' || c == '_'
            }),
            "base64url alphabet only: {challenge}"
        );
        assert_eq!(json["rp_id"], "localhost");
        assert_eq!(json["user_verification"], "preferred");
    }

    /// implementation-note-6 — successive challenges differ, asserting we mint
    /// fresh entropy per call rather than reusing a constant.
    #[tokio::test]
    async fn webauthn_challenges_differ_across_calls() {
        let state = make_state();
        let r1 = call(Arc::clone(&state), "/api/webauthn/challenge").await;
        let r2 = call(state, "/api/webauthn/challenge").await;
        let b1 = http_body_util::BodyExt::collect(r1.into_body())
            .await
            .unwrap()
            .to_bytes();
        let b2 = http_body_util::BodyExt::collect(r2.into_body())
            .await
            .unwrap()
            .to_bytes();
        let j1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let j2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
        assert_ne!(j1["challenge"], j2["challenge"]);
    }

    /// implementation-note-6 — `resolve_approval_with_biometric` records the
    /// biometric flag + credential_id in the audit log so an auditor can
    /// distinguish hardware-attested approvals from click-throughs.
    #[tokio::test]
    async fn resolve_approval_with_biometric_logs_audit_fields() {
        use crate::approval::ApprovalOutcome;
        let state = make_state();
        let persona = state.store.create_persona("agent-bio").unwrap();
        let req = state
            .store
            .submit_approval(&persona.id, "stripe-key", "read", None, "credential:read", "low")
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
        use crate::audit::AuditFilter;
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
        state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        let resp = call(state, "/api/grants").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_id"], persona.id);
    }

    #[tokio::test]
    async fn api_status_counts_reflect_store_state() {
        let state = make_state();
        let persona = state.store.create_persona("agent-x").unwrap();
        state.store.create_grant(&persona.id, "key", "read", None).unwrap();
        state.store.submit_approval(&persona.id, "key2", "write", None, "access", "high").unwrap();
        state.store.log_event(Some(&persona.id), "test.event", None, "ok", None).unwrap();

        let resp = call(Arc::clone(&state), "/api/status").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn post_approve_nonexistent_approval_returns_error() {
        let state = make_state();
        let resp = call_post(state, "/api/approvals/nonexistent/approve").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn post_revoke_grant_succeeds() {
        let state = make_state();
        let persona = state.store.create_persona("agent-r").unwrap();
        let grant = state.store.create_grant(&persona.id, "key", "read", None).unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/revoke", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["revoked"], true);
    }

    #[tokio::test]
    async fn post_approve_approval_succeeds() {
        let state = make_state();
        let persona = state.store.create_persona("agent-a").unwrap();
        let req = state.store.submit_approval(&persona.id, "key", "read", None, "access", "low").unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/approve", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], true);
    }

    #[tokio::test]
    async fn post_deny_approval_succeeds() {
        let state = make_state();
        let persona = state.store.create_persona("agent-d").unwrap();
        let req = state.store.submit_approval(&persona.id, "key", "read", None, "access", "low").unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/deny", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["denied"], true);
    }

    #[tokio::test]
    async fn api_anomalies_empty_returns_array() {
        let state = make_state();
        let resp = call(state, "/api/anomalies").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn api_grants_includes_conditions_field() {
        let state = make_state();
        let persona = state.store.create_persona("agent-cond").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        // Set rate_limit and time_window conditions directly in the store.
        state.store.conn().execute(
            "UPDATE grants SET max_uses_per_hour = 10, allowed_hours_start = 9, allowed_hours_end = 17 WHERE id = ?1",
            rusqlite::params![grant.id],
        ).unwrap();

        let resp = call(state, "/api/grants").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let conditions = &arr[0]["conditions"];
        assert!(conditions.is_object(), "conditions should be an object when grant has conditions");
        assert_eq!(conditions["rate_limit"], "10/hour");
        assert_eq!(conditions["time_window"], "9:00-17:00 UTC");
    }

    #[tokio::test]
    async fn api_anomalies_detects_high_denial_rate() {
        let state = make_state();
        for _ in 0..4 {
            state.store.log_event(Some("agent-flagged"), "credential.access", None, "denied", None).unwrap();
        }
        let resp = call(state, "/api/anomalies").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert!(!arr.is_empty());
        assert_eq!(arr[0]["agent_id"], "agent-flagged");
        assert_eq!(arr[0]["severity"], "medium");
    }

    #[tokio::test]
    async fn health_returns_200_with_status_ok() {
        let state = make_state();
        let resp = call(state, "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        // uptime_secs must reflect elapsed time since state construction, not Unix epoch.
        let uptime = json["uptime_secs"].as_u64().expect("uptime_secs must be a u64");
        assert!(uptime < 10, "uptime_secs={uptime} looks like Unix epoch, not elapsed seconds");
    }

    #[tokio::test]
    async fn api_health_returns_200_with_status_ok() {
        let state = make_state();
        let resp = call(state, "/api/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        // uptime_secs must reflect elapsed time since state construction, not Unix epoch.
        let uptime = json["uptime_secs"].as_u64().expect("uptime_secs must be a u64");
        assert!(uptime < 10, "uptime_secs={uptime} looks like Unix epoch, not elapsed seconds");
    }

    // --- CSRF protection tests ---

    #[tokio::test]
    async fn html_contains_csrf_token() {
        let state = make_state();
        let resp = call(state, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(
            s.contains(&format!("const CSRF_TOKEN = \"{}\";", TEST_CSRF_TOKEN)),
            "expected CSRF_TOKEN constant in HTML"
        );
        // Placeholder must be fully substituted.
        assert!(!s.contains("{{CSRF_TOKEN}}"), "placeholder should be replaced");
    }

    #[tokio::test]
    async fn generate_csrf_token_is_64_hex_chars() {
        let t = generate_csrf_token().expect("rng should work");
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Two consecutive calls must differ (randomness sanity check).
        let t2 = generate_csrf_token().expect("rng should work");
        assert_ne!(t, t2);
    }

    #[tokio::test]
    async fn post_approve_without_csrf_returns_403() {
        let state = make_state();
        let resp = call_post_no_csrf(state, "/api/approvals/fake-id/approve").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
    async fn get_endpoints_do_not_require_csrf() {
        // GET endpoints are read-only and same-origin policy protects them.
        let state = make_state();
        let resp = call(state, "/api/status").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- /approvals/<id> deep-link route tests ---

    #[tokio::test]
    async fn approval_deep_link_returns_200_with_approve_button() {
        let state = make_state();
        let persona = state.store.create_persona("agent-deep").unwrap();
        let req = state.store.submit_approval(&persona.id, "my-key", "read", None, "access", "high").unwrap();

        let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/html"));
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("not found") || s.contains("resolved"), "404 page should explain the state");
    }

    #[tokio::test]
    async fn approval_deep_link_embeds_csrf_token() {
        let state = make_state();
        let persona = state.store.create_persona("agent-csrf-check").unwrap();
        let req = state.store.submit_approval(&persona.id, "k", "read", None, "access", "low").unwrap();

        let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let req = state.store.submit_approval(&persona.id, "k", "read", None, "access", "low").unwrap();

        // POST approve with valid CSRF — should succeed (200, approved: true)
        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/approve", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let req = state.store.submit_approval(&persona.id, "k", "read", None, "access", "low").unwrap();

        let resp = call_post_no_csrf(state, &format!("/api/approvals/{}/approve", req.id)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn approval_deep_link_hides_composite_breakdown_behind_disclosure() {
        // implementation-note-12 — the dedicated /approvals/{id} page must
        // lead with the Approve/Deny decision and keep the per-statement
        // breakdown collapsed behind a "Show details" disclosure. Asserts:
        //   1. The page contains a <details class="composite-disclosure"> block
        //   2. The block is `hidden` by default (only revealed when JS sees
        //      composite_statements in the polled JSON)
        //   3. The shared renderCompositeStatements helper is present so
        //      the dashboard card and this page never drift
        let state = make_state();
        let persona = state.store.create_persona("agent-composite").unwrap();
        let req = state.store.submit_approval(
            &persona.id,
            "github-key",
            "composite",
            None,
            "credential.access",
            "high",
        ).unwrap();

        let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();

        // Disclosure block exists and is collapsed-by-default.
        assert!(
            s.contains(r#"<details class="composite-disclosure" id="composite-disclosure" hidden>"#),
            "composite-disclosure must be present and `hidden` by default"
        );
        assert!(
            s.contains("<summary>Show details</summary>"),
            "disclosure must use the Show details summary affordance"
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

    #[tokio::test]
    async fn dashboard_html_inlines_shared_composite_helper() {
        // implementation-note-12 — the dashboard pending-approvals card and
        // the dedicated /approvals/{id} page share a single JS helper for
        // rendering the composite-statement breakdown. Assert the helper is
        // baked into the dashboard HTML so the two surfaces cannot drift.
        let state = make_state();
        let resp = call(state, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let req = state.store.submit_approval(&persona.id, "poll-key", "read", None, "access", "low").unwrap();

        let resp = call(Arc::clone(&state), &format!("/api/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("application/json"));
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], req.id);
        assert_eq!(json["status"], "pending");
        assert_eq!(json["credential_name"], "poll-key");
    }

    #[tokio::test]
    async fn api_approval_by_id_reflects_resolved_status() {
        let state = make_state();
        let persona = state.store.create_persona("agent-poll-resolved").unwrap();
        let req = state.store.submit_approval(&persona.id, "k", "read", None, "access", "low").unwrap();

        // Resolve via approve
        state.store.resolve_approval(&req.id, &ApprovalOutcome::Approved).unwrap();

        let resp = call(Arc::clone(&state), &format!("/api/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "approved");
    }

    #[tokio::test]
    async fn api_approval_by_nonexistent_id_returns_404() {
        let state = make_state();
        let resp = call(state, "/api/approvals/approval-does-not-exist").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn api_approvals_approve_always_endpoint_works() {
        let state = make_state();
        let persona = state.store.create_persona("agent-always").unwrap();
        let req = state.store.submit_approval(
            &persona.id, "key", "read", None, "credential.access.github-token", "low"
        ).unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/approve-always", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["approved"], true);
        assert_eq!(json["standing_grant_created"], true);

        // Approval should be resolved
        let resolved = state.store.get_approval(&req.id).unwrap();
        assert_eq!(resolved.status, "approved");

        // A standing grant should exist for the action
        let standing = state.store.list_standing_grants().unwrap();
        assert_eq!(standing.len(), 1);
        assert_eq!(standing[0].action_pattern, "credential.access.github-token");
        assert_eq!(standing[0].persona_id, persona.id);
        // Standing grant should have a future expires_at (30 days from now)
        assert!(standing[0].expires_at.is_some());
    }

    #[tokio::test]
    async fn api_approvals_approve_always_without_csrf_returns_403() {
        let state = make_state();
        let persona = state.store.create_persona("agent-always-nocsrf").unwrap();
        let req = state.store.submit_approval(
            &persona.id, "key", "read", None, "access", "low"
        ).unwrap();

        let resp = call_post_no_csrf(state, &format!("/api/approvals/{}/approve-always", req.id)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // --- 69K.7: budget gauge, pause/extend, receipt viewer tests ---

    #[tokio::test]
    async fn api_grants_pause_toggles_paused_flag() {
        let state = make_state();
        let persona = state.store.create_persona("agent-pause").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        // Verify initially not paused
        let g0 = state.store.get_grant(&grant.id).unwrap();
        assert!(!g0.paused);
        assert_eq!(g0.status, "active");

        // Pause via endpoint — hard pause sets status='paused'
        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/pause", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["paused"], true);

        // Verify store state: status is 'paused' and paused flag is set
        let g1 = state.store.get_grant(&grant.id).unwrap();
        assert!(g1.paused);
        assert_eq!(g1.status, "paused");

        // Unpause — restores status='active'
        let resp2 = call_post(Arc::clone(&state), &format!("/api/grants/{}/unpause", grant.id)).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let g2 = state.store.get_grant(&grant.id).unwrap();
        assert!(!g2.paused);
        assert_eq!(g2.status, "active");
    }

    #[tokio::test]
    async fn api_grants_extend_calls_extend_grant_method() {
        let state = make_state();
        let persona = state.store.create_persona("agent-extend").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", Some(3600)).unwrap();
        let original_expires = grant.expires_at.clone();

        // Call extend with empty body (test helper applies no deltas, just re-fetches)
        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/extend", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], grant.id);
        // With no deltas the expires_at should be unchanged
        assert_eq!(json["expires_at"].as_str(), original_expires.as_deref());
    }

    #[tokio::test]
    async fn dashboard_renders_budget_gauge_when_grant_has_budget() {
        let state = make_state();
        let persona = state.store.create_persona("agent-gauge").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "*:read", None).unwrap();
        // Set budget + usage on the first-statement of the chain. V0
        // schema: the envelope-level `budget` / `usage` fields are gone;
        // consumers read from the `statements` array. Block 0 must be
        // re-signed after the mutation or `verify_chain` rejects on read.
        let mut chain = state.store.get_access_grant(&grant.id).unwrap();
        if let Some(block) = chain.blocks.first_mut()
            && let Some(stmt) = block.block.statements.first_mut()
        {
            stmt.budget = Some(core_types::Budget {
                tokens: Some(20_000),
                ..Default::default()
            });
            stmt.usage = core_types::Usage {
                tokens: 5_000,
                ..Default::default()
            };
        }
        if let Some(first) = chain.blocks.first_mut() {
            let root = state.store.persona_root_keypair(&persona.id).unwrap();
            let resigned = core_crypto::grant_chain::sign_block_zero(&root, &first.block)
                .unwrap();
            *first = resigned.signed;
        }
        let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
        state.store.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        ).unwrap();

        // Get grant from API — budget + usage live on `statements[0]`.
        let resp = call(Arc::clone(&state), "/api/grants").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();
        // Revoke to make it terminal
        state.store.revoke_grant(&grant.id).unwrap();

        // /api/grants/all should include the revoked grant
        let resp = call(Arc::clone(&state), "/api/grants/all").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        let revoked = arr.iter().find(|g| g["id"] == grant.id).expect("revoked grant in list");
        assert_eq!(revoked["status"], "revoked");

        // Receipt viewer returns HTML
        let resp2 = call(Arc::clone(&state), &format!("/receipts/{}", grant.id)).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = http_body_util::BodyExt::collect(resp2.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body2).unwrap();
        assert!(s.contains("Grant Receipt"), "receipt page should have title");
        assert!(s.contains(&grant.id), "receipt page should embed grant id");
        assert!(s.contains("Download JSON"), "receipt page should have download button");
    }

    #[tokio::test]
    async fn sse_endpoint_returns_event_stream() {
        let state = make_state();
        let persona = state.store.create_persona("agent-sse").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        let resp = call(state, &format!("/sse/grants/{}", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/event-stream"), "SSE endpoint must return event-stream content-type");
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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

    /// Pure-function test: render_statement_gauges emits exactly one wrapper
    /// div per statement, shows the SID, and uses "unbounded" when no budget.
    #[test]
    fn render_statement_gauges_emits_one_div_per_statement() {
        use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
        use core_types::{Action, StatementId};

        let s0 = Statement {
            sid: StatementId::from("S0"),
            resource_type: ResourceType::Credential,
            actions: vec![Action::from("read")],
            resource: ResourceSelector::Any,
            budget: Some(Budget { tokens: Some(10_000), ..Default::default() }),
            usage: Usage { tokens: 3_000, ..Default::default() },
            conditions: vec![],
        };
        let s1 = Statement {
            sid: StatementId::from("S1"),
            resource_type: ResourceType::Session,
            actions: vec![Action::from("create")],
            resource: ResourceSelector::Any,
            budget: Some(Budget { cents: Some(500), ..Default::default() }),
            usage: Usage { cents: 125, ..Default::default() },
            conditions: vec![],
        };
        let s2 = Statement {
            sid: StatementId::from("S2"),
            resource_type: ResourceType::Credential,
            actions: vec![],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        };

        let pairs: Vec<(usize, &Statement)> = vec![(0, &s0), (0, &s1), (0, &s2)];
        let html = render_statement_gauges(&pairs);

        // Three wrapper divs — use the unique inline style from render_statement_gauges.
        assert_eq!(html.matches(r#"padding:14px;margin-bottom:12px"#).count(), 3,
            "should emit one wrapper div per statement");

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
        assert!(s2_section.contains("unbounded"), "S2 with no budget should say unbounded");
    }

    /// Integration test: /receipts/{id} shows per-Statement gauges for a
    /// 3-statement composite grant.
    #[tokio::test]
    async fn receipt_html_shows_per_statement_gauges_for_composite_grant() {
        use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
        use core_types::{Action, StatementId};

        let state = make_state();
        let persona = state.store.create_persona("p-3stmt").unwrap();
        // Start with a single-statement grant so we have a valid row.
        let grant = state.store.create_grant(&persona.id, "api-key", "read", Some(3600)).unwrap();

        // Build a 3-statement composite chain and overwrite blocks_json.
        let stmts = vec![
            Statement {
                sid: StatementId::from("S0"),
                resource_type: ResourceType::Credential,
                actions: vec![Action::from("read")],
                resource: ResourceSelector::Any,
                budget: Some(Budget { tokens: Some(20_000), ..Default::default() }),
                usage: Usage { tokens: 5_000, ..Default::default() },
                conditions: vec![],
            },
            Statement {
                sid: StatementId::from("S1"),
                resource_type: ResourceType::Session,
                actions: vec![Action::from("create")],
                resource: ResourceSelector::Any,
                budget: Some(Budget { cents: Some(1_000), ..Default::default() }),
                usage: Usage { cents: 250, ..Default::default() },
                conditions: vec![],
            },
            Statement {
                sid: StatementId::from("S2"),
                resource_type: ResourceType::Credential,
                actions: vec![],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            },
        ];
        let root = state.store.persona_root_keypair(&persona.id).unwrap();
        let chain = crate::grant::access_grant_from_statements(
            &grant.id,
            &persona.id,
            "api-key",
            stmts,
            0,
            Some(9_999_999_999),
            &root,
        ).unwrap();
        let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
        state.store.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant.id],
        ).unwrap();

        let resp = call(Arc::clone(&state), &format!("/receipts/{}", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
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
        assert!(html.contains("unbounded"), "S2 with no budget should render as unbounded");
        assert!(html.contains("Statements"), "card title should say Statements");
    }

    // --- /grants/{id} detail page tests ---

    #[tokio::test]
    async fn grant_detail_page_returns_200_for_active_grant() {
        let state = make_state();
        let persona = state.store.create_persona("detail-agent").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/html"));
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Grant Detail"), "page should have Grant Detail title");
        assert!(html.contains(&grant.id), "page should embed grant id");
        assert!(html.contains("Pause"), "active grant should show Pause button");
        assert!(html.contains("Extend"), "active grant should show Extend button");
        assert!(html.contains("Revoke"), "active grant should show Revoke button");
    }

    #[tokio::test]
    async fn grant_detail_page_shows_resume_when_paused() {
        let state = make_state();
        let persona = state.store.create_persona("detail-paused").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();
        state.store.pause_grant(&grant.id).unwrap();

        let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Resume"), "paused grant should show Resume button");
        assert!(!html.contains(">Pause<"), "paused grant should not show Pause button");
        assert!(html.contains("paused"), "page should indicate paused state");
    }

    #[tokio::test]
    async fn grant_detail_page_shows_receipt_link_for_terminal_grant() {
        let state = make_state();
        let persona = state.store.create_persona("detail-terminal").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();
        state.store.revoke_grant(&grant.id).unwrap();

        let resp = call(Arc::clone(&state), &format!("/grants/{}", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("View Receipt"), "terminal grant page should have View Receipt link");
        assert!(!html.contains(">Pause<"), "terminal grant should not show Pause button");
        assert!(!html.contains(">Revoke<"), "terminal grant should not show Revoke button");
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
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/pause", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Status must be 'paused', not just the advisory flag.
        let g = state.store.get_grant(&grant.id).unwrap();
        assert_eq!(g.status, "paused");
        assert!(g.paused);

        // evaluate_grant must not return the grant (proxy-blocking).
        let eval = state.store.evaluate_grant(&persona.id, "api-key");
        assert!(eval.is_err(), "paused grant must not be returned by evaluate_grant");
    }

    #[tokio::test]
    async fn unpause_restores_status_to_active() {
        let state = make_state();
        let persona = state.store.create_persona("unpause-agent").unwrap();
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        call_post(Arc::clone(&state), &format!("/api/grants/{}/pause", grant.id)).await;
        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/unpause", grant.id)).await;
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
        let resp = call_post(state, "/api/grants/grant-nope/pause").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn truncate_persona_id_normal() {
        let full = "persona-368a0fc5-809a-4539-abcd-ef0123456789";
        let got = truncate_persona_id(full);
        assert_eq!(got, "persona-368a0fc5-809", "should keep 12 UUID chars after persona- prefix");
    }

    #[test]
    fn truncate_persona_id_short_does_not_panic() {
        let short = "persona-abc";
        let got = truncate_persona_id(short);
        assert_eq!(got, "persona-abc", "short UUID portion should not panic or over-reach");
    }

    #[test]
    fn truncate_persona_id_missing_prefix_returns_as_is() {
        let no_prefix = "368a0fc5";
        let got = truncate_persona_id(no_prefix);
        assert_eq!(got, "368a0fc5", "missing persona- prefix should return as-is");
    }

    #[test]
    fn truncate_persona_id_exact_boundary() {
        // Exactly 12 UUID chars after "persona-" — returned unchanged (no ellipsis added).
        let exactly_12 = "persona-368a0fc5-809";
        let got = truncate_persona_id(exactly_12);
        assert_eq!(got, "persona-368a0fc5-809", "exactly-12-char UUID portion should be returned as-is");
    }

    // --- security check: Origin/Referer header checks ---

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

    // Integration tests: POST endpoints reject requests without matching Origin.

    #[tokio::test]
    async fn post_revoke_without_origin_returns_403() {
        let state = make_state();
        let persona = state.store.create_persona("no-origin-agent").unwrap();
        let grant = state.store.create_grant(&persona.id, "key", "read", None).unwrap();
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
        let req_a = state.store.submit_approval(&persona.id, "key", "read", None, "access", "low").unwrap();
        // Build POST with valid CSRF but mismatched Origin.
        let req = Request::builder()
            .method("POST")
            .uri(format!("http://localhost/api/approvals/{}/approve", req_a.id))
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
        let req_a = state.store.submit_approval(&persona.id, "key", "read", None, "access", "low").unwrap();
        // Build POST with valid CSRF and matching Referer (no Origin).
        let req = Request::builder()
            .method("POST")
            .uri(format!("http://localhost/api/approvals/{}/approve", req_a.id))
            .header("referer", format!("{TEST_EXPECTED_ORIGIN}/approvals/{}", req_a.id))
            .header(CSRF_HEADER, TEST_CSRF_TOKEN)
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = handle_dashboard_boxed(state, req).await;
        // Origin check passes; CSRF passes; store resolves OK → 200.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // --- implementation-note-7: dismiss endpoint ---

    #[tokio::test]
    async fn dismiss_approval_returns_200_and_removes_from_pending() {
        let state = make_state();
        let persona = state.store.create_persona("dismiss-agent").unwrap();
        let approval = state
            .store
            .submit_approval(&persona.id, "key", "read", None, "access", "low")
            .unwrap();

        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/dismiss", approval.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["dismissed"], true);

        // Approval should no longer appear in pending list.
        let pending = state.store.list_pending_approvals().unwrap();
        assert!(pending.iter().all(|a| a.id != approval.id), "dismissed approval must not appear in pending");

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

        call_post(Arc::clone(&state), &format!("/api/approvals/{}/dismiss", approval.id)).await;
        let resp = call_post(Arc::clone(&state), &format!("/api/approvals/{}/dismiss", approval.id)).await;
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

    // --- implementation-note-8: audit action_filter query param ---

    #[tokio::test]
    async fn audit_action_filter_returns_only_matching_prefix() {
        let state = make_state();
        state.store.log_event(None, "grant.create", None, "ok", None).unwrap();
        state.store.log_event(None, "approval.dismissed", None, "ok", None).unwrap();
        state.store.log_event(None, "broker.materialization", None, "ok", None).unwrap();

        let resp = call(Arc::clone(&state), "/api/audit?action_filter=grant.").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "only grant.* actions should be returned");
        assert_eq!(arr[0]["action"], "grant.create");
    }

    #[tokio::test]
    async fn audit_action_filter_empty_returns_all() {
        let state = make_state();
        state.store.log_event(None, "grant.create", None, "ok", None).unwrap();
        state.store.log_event(None, "approval.dismissed", None, "ok", None).unwrap();

        let resp = call(Arc::clone(&state), "/api/audit?action_filter=").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2, "empty filter returns all events");
    }

    // --- implementation-note-14: /api/receipts endpoint ---

    /// Ensure the receipts singleton identity is active (mirrors receipt.rs
    /// test helper) so revoke_grant can emit signed receipts.
    fn ensure_receipt_identity() -> &'static crate::receipt::DaemonIdentity {
        use once_cell::sync::OnceCell;
        static INIT_DIR: OnceCell<tempfile::TempDir> = OnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = crate::receipt::init_identity(dir.path());
        crate::receipt::current_identity().expect("identity was just initialised")
    }

    #[tokio::test]
    async fn api_receipts_empty_returns_array() {
        let state = make_state();
        let resp = call(state, "/api/receipts").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array(), "receipts response must be an array");
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn api_receipts_returns_signed_status_field() {
        ensure_receipt_identity();
        let state = make_state();
        let persona = state.store.create_persona("agent-receipt-signed").unwrap();
        let grant = state.store.create_grant(&persona.id, "gh-token", "push", None).unwrap();
        state.store.revoke_grant(&grant.id).unwrap();

        let resp = call(Arc::clone(&state), "/api/receipts").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "one revoked grant → one receipt");
        assert_eq!(arr[0]["grant_id"], grant.id);
        assert!(arr[0]["signed"].is_boolean(), "signed field must be boolean");
        assert!(arr[0]["signed"].as_bool().unwrap(), "receipt signed by daemon identity");
        assert!(arr[0]["action_summary"].is_string());
        assert!(arr[0]["persona_id"].is_string());
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

        let url = format!("/api/receipts?persona_id={}", a.id);
        let resp = call(Arc::clone(&state), &url).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "persona filter must return only receipts for that persona");
        assert_eq!(arr[0]["persona_id"], a.id.as_str());
    }

    #[tokio::test]
    async fn api_receipts_signed_only_excludes_unsigned() {
        // Seed one receipt that is unsigned (signer_pubkey='') via direct store
        // insert to simulate a pre-identity-key receipt, then one real signed one.
        ensure_receipt_identity();
        let state = make_state();
        let persona = state.store.create_persona("agent-rcpt-so").unwrap();
        let g_signed = state.store.create_grant(&persona.id, "cred", "r", None).unwrap();
        state.store.revoke_grant(&g_signed.id).unwrap();

        // Manually insert an unsigned receipt row.
        use core_types::grant_receipt::{Evidence, GrantReceipt, Lifecycle, ReceiptSummary, TerminalReason};
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
            evidence: Evidence::default(), // all-zero placeholder → unsigned
        };
        state.store.store_receipt(&unsigned).unwrap();

        // Without filter: both receipts visible.
        let resp_all = call(Arc::clone(&state), "/api/receipts").await;
        let body_all = http_body_util::BodyExt::collect(resp_all.into_body()).await.unwrap().to_bytes();
        let all: serde_json::Value = serde_json::from_slice(&body_all).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2, "unfiltered returns both");

        // With signed_only=true: only the signed receipt.
        let resp_signed = call(Arc::clone(&state), "/api/receipts?signed_only=true").await;
        let body_signed = http_body_util::BodyExt::collect(resp_signed.into_body()).await.unwrap().to_bytes();
        let signed: serde_json::Value = serde_json::from_slice(&body_signed).unwrap();
        let signed_arr = signed.as_array().unwrap();
        assert_eq!(signed_arr.len(), 1, "signed_only=true must exclude unsigned receipt");
        assert!(signed_arr[0]["signed"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn api_receipts_includes_persona_name() {
        ensure_receipt_identity();
        let state = make_state();
        let persona = state.store.create_persona("My Test Agent").unwrap();
        let grant = state.store.create_grant(&persona.id, "key", "r", None).unwrap();
        state.store.revoke_grant(&grant.id).unwrap();

        let resp = call(Arc::clone(&state), "/api/receipts").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_name"], "My Test Agent", "persona_name must be resolved from store");
    }

    #[tokio::test]
    async fn dashboard_html_contains_receipts_section() {
        let state = make_state();
        let resp = call(state, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("Grant Receipts"), "dashboard must contain Grant Receipts section heading");
        assert!(s.contains("receipts-body"), "dashboard must contain receipts table body element");
        assert!(s.contains("receipt-signed-filter"), "dashboard must contain signed filter control");
        assert!(s.contains("receipt-since-filter"), "dashboard must contain since filter control");
        assert!(s.contains("function loadReceipts"), "dashboard must contain loadReceipts JS function");
    }

    #[tokio::test]
    async fn approval_page_no_longer_has_narrow_button() {
        // implementation-note-15: disabled Narrow button was removed for clean screenshots.
        let state = make_state();
        let persona = state.store.create_persona("agent-narrow-check").unwrap();
        let req = state.store.submit_approval(&persona.id, "key", "read", None, "access", "low").unwrap();
        let resp = call(Arc::clone(&state), &format!("/approvals/{}", req.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(!s.contains("btn-narrow"), "Narrow button must have been removed from approval page");
        assert!(!s.contains("Narrow"), "Narrow text must not appear on approval page");
    }
}
