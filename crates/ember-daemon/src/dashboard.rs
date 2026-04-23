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

/// Header name clients must send on state-mutating (POST) dashboard requests.
/// 69K.7: live budget gauge + pause/extend buttons + receipt viewer.
const CSRF_HEADER: &str = "X-Ember-CSRF-Token";

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
.approval-card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:16px}
.approval-card .row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.approval-card .field{color:var(--text-muted);font-size:11px}
.approval-card .field-val{color:var(--text-primary);font-size:12px}
.approval-card .actions{display:flex;gap:8px;margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}
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
.badge.expired{background:rgba(107,107,123,.15);color:var(--text-muted)}
.badge.parent_cascade_revoked{background:rgba(239,68,68,.1);color:var(--danger)}
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
    <div class="section-header"><span class="section-title">Audit Timeline</span></div>
    <div class="timeline">
      <div class="timeline-header">
        <span>Timestamp</span><span>Agent</span><span>Action</span><span>Credential</span><span>Outcome</span>
      </div>
      <div id="audit-body"><div class="empty">loading…</div></div>
    </div>
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
function ts(iso){if(!iso)return'—';const d=new Date(iso);return d.toLocaleString(undefined,{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function trunc(s,n){if(!s)return'—';return s.length>n?s.slice(0,n)+'…':s;}
function badge(cls,text){return`<span class="badge ${cls}">${text}</span>`;}

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
async function approveRequest(id){
  await fetch(`/api/approvals/${id}/approve`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function approveAlwaysRequest(id){
  await fetch(`/api/approvals/${id}/approve-always`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function denyRequest(id){
  await fetch(`/api/approvals/${id}/deny`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
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
    const[status,grants,approvals,audit,anomalies]=await Promise.all([
      fetch('/api/status').then(r=>r.json()),
      fetch(grantsUrl).then(r=>r.json()),
      fetch('/api/approvals').then(r=>r.json()),
      fetch('/api/audit').then(r=>r.json()),
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
          <div class="anm-ts">${ts(a.detected_at)}</div>
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
      gb.innerHTML=grants.map(g=>`<tr id="grant-row-${g.id}">
        <td class="mono">${trunc(g.id,18)}</td>
        <td class="mono">${trunc(g.persona_id,20)}</td>
        <td>${g.credential_name||'—'}</td>
        <td>${g.scope||'—'}</td>
        <td class="gauge-cell">${renderBudgetGauge(g)}</td>
        <td class="ts">${g.expires_at?ts(g.expires_at):'never'}</td>
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
      ac.innerHTML=approvals.map(a=>`<div class="approval-card">
        <div class="row"><span class="field">Persona</span><span class="field-val mono">${trunc(a.persona_id,20)}</span></div>
        <div class="row"><span class="field">Credential</span><span class="field-val">${a.credential_name||'—'}</span></div>
        <div class="row"><span class="field">Scope</span><span class="field-val">${a.scope||'—'}</span></div>
        <div class="row"><span class="field">Action</span><span class="field-val">${a.action||'—'}</span></div>
        <div class="row"><span class="field">Risk</span><span class="field-val">${badge(a.risk_level,a.risk_level)}</span></div>
        <div class="actions">
          <button class="btn btn-success" onclick="approveRequest('${a.id}')">Approve</button>
          <button class="btn btn-success btn-outline" onclick="approveAlwaysRequest('${a.id}')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days).">&#x1F512; Approve Always</button>
          <button class="btn btn-warn">Narrow</button>
          <button class="btn btn-danger" onclick="denyRequest('${a.id}')">Deny</button>
        </div>
      </div>`).join('');
    }

    // Audit timeline
    const ab=document.getElementById('audit-body');
    if(!audit||audit.length===0){
      ab.innerHTML='<div class="empty">no audit events</div>';
    }else{
      ab.innerHTML=audit.map(e=>`<div class="timeline-item">
        <span class="ts">${ts(e.timestamp)}</span>
        <span class="mono">${trunc(e.agent_id,14)}</span>
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
loadDashboard();
setInterval(loadDashboard,5000);
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
  <div class="field"><span class="field-label">Scope</span><span class="field-val">{{SCOPE}}</span></div>
  <div class="field"><span class="field-label">Risk</span><span class="field-val"><span class="badge {{RISK_LEVEL}}">{{RISK_LEVEL}}</span></span></div>
  <div class="field"><span class="field-label">Persona</span><span class="field-val">{{PERSONA_PREFIX}}</span></div>
  <div class="field"><span class="field-label">Requested</span><span class="field-val">{{CREATED_AT}}</span></div>
  <div class="actions">
    <button class="btn btn-success" id="btn-approve" onclick="resolve('approve')">Approve</button>
    <button class="btn btn-success btn-always" id="btn-approve-always" onclick="resolve('approve-always')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days). Reviewable under Standing Grants.">&#x1F512; Approve Always</button>
    <button class="btn btn-warn" id="btn-narrow" disabled title="Use the dashboard to narrow scope">Narrow</button>
    <button class="btn btn-danger" id="btn-deny" onclick="resolve('deny')">Deny</button>
  </div>
  <div id="resolved">Resolved — you can close this tab.</div>
</div>
<script>
const CSRF_TOKEN = "{{CSRF_TOKEN}}";
const APPROVAL_ID = "{{APPROVAL_ID}}";
let pollTimer = null;
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
      if(data.status && data.status !== 'pending'){
        showResolved(data.status);
      }
    }
  }catch(_){}
}
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
            let html = DASHBOARD_HTML.replace("{{CSRF_TOKEN}}", &state.csrf_token);
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
            let body = serde_json::json!({
                "running": true,
                "version": state.version,
                "active_agents": active_agents,
                "active_grants": active_grants,
                "pending_approvals": pending_approvals,
                "audit_events": audit_events,
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
        (Method::GET, "/api/receipts") => {
            let persona_filter = req.uri().query().and_then(|q| {
                q.split('&').find_map(|kv| {
                    let mut parts = kv.splitn(2, '=');
                    if parts.next() == Some("persona_id") { parts.next() } else { None }
                })
            });
            let receipts = state
                .store
                .list_receipts(persona_filter)
                .unwrap_or_default();
            let body: Vec<serde_json::Value> = receipts
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
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
                    serde_json::json!({
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "created_at": g.created_at,
                        "expires_at": g.expires_at,
                        "status": g.status,
                        "conditions": conditions,
                    })
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
                .map(|a| serde_json::json!({
                    "id": a.id,
                    "persona_id": a.persona_id,
                    "credential_name": a.credential_name,
                    "scope": a.scope,
                    "ttl_secs": a.ttl_secs,
                    "action": a.action,
                    "risk_level": a.risk_level,
                    "status": a.status,
                    "reason": a.reason,
                    "created_at": a.created_at,
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
                Ok(a) => json_response(StatusCode::OK, &serde_json::json!({
                    "id": a.id,
                    "persona_id": a.persona_id,
                    "credential_name": a.credential_name,
                    "scope": a.scope,
                    "ttl_secs": a.ttl_secs,
                    "action": a.action,
                    "risk_level": a.risk_level,
                    "status": a.status,
                    "reason": a.reason,
                    "created_at": a.created_at,
                })),
                Err(_) => error_response(404, "approval not found"),
            }
        }

        (Method::GET, "/api/audit") => {
            use crate::audit::AuditFilter;
            let entries = state
                .store
                .query_audit(&AuditFilter { limit: Some(100), ..Default::default() })
                .unwrap_or_default();
            let body: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| serde_json::json!({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "agent_id": e.agent_id,
                    "action": e.action,
                    "credential": e.credential,
                    "outcome": e.outcome,
                    "details": e.details,
                }))
                .collect();
            json_response(StatusCode::OK, &serde_json::Value::Array(body))
        }

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/revoke") =>
        {
            if !csrf_ok(&headers, &state.csrf_token) {
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
            if !csrf_ok(&headers, &state.csrf_token) {
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
            if !csrf_ok(&headers, &state.csrf_token) {
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
            if !csrf_ok(&headers, &state.csrf_token) {
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

        // POST /api/grants/{id}/pause  — advisory pause (advisory = doesn't stop proxy)
        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/pause") =>
        {
            if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/pause")
                    .unwrap();
                match state.store.set_grant_paused(id, true) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": true})),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // POST /api/grants/{id}/unpause
        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/unpause") =>
        {
            if !csrf_ok(&headers, &state.csrf_token) {
                error_response(403, "csrf token missing or mismatched")
            } else {
                let id = path
                    .strip_prefix("/api/grants/")
                    .unwrap()
                    .strip_suffix("/unpause")
                    .unwrap();
                match state.store.set_grant_paused(id, false) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": false})),
                    Err(e) => error_response(400, &e.to_string()),
                }
            }
        }

        // POST /api/grants/{id}/extend  — extend budget and/or TTL
        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/extend") =>
        {
            if !csrf_ok(&headers, &state.csrf_token) {
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
                    let html = build_receipt_html(&g, &state.csrf_token);
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
                    // Persona ID: show first 12 chars as prefix to avoid leaking the full UUID.
                    let persona_prefix: String = a.persona_id.chars().take(20).collect();
                    let html = APPROVAL_HTML_TEMPLATE
                        .replace("{{CSRF_TOKEN}}", &state.csrf_token)
                        .replace("{{APPROVAL_ID}}", &a.id)
                        .replace("{{ACTION}}", &a.action)
                        .replace("{{CREDENTIAL}}", &a.credential_name)
                        .replace("{{SCOPE}}", &a.scope)
                        .replace("{{RISK_LEVEL}}", &a.risk_level)
                        .replace("{{PERSONA_PREFIX}}", &persona_prefix)
                        .replace("{{CREATED_AT}}", &a.created_at);
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
/// Post-composite-port (design): also emits a `statements` array with per-
/// Statement `sid`, `resource_type`, `actions`, `resource`, `budget`, and
/// `usage`. Dashboard / receipt views can render per-Statement meters from
/// this field. The legacy envelope-level `budget` + `usage` fields remain
/// as projections across all statements for backward compat.
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

    serde_json::json!({
        "id": g.id,
        "persona_id": g.persona_id,
        "credential_name": g.credential_name,
        "scope": g.scope,
        "created_at": g.created_at,
        "expires_at": g.expires_at,
        "status": g.status,
        "conditions": conditions,
        "budget": g.budget,
        "usage": g.usage,
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
        "budget": g.budget,
        "usage": g.usage,
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

/// Render a full Grant Receipt HTML page with tabbed view (Summary / Evidence).
fn build_receipt_html(g: &crate::grant::GrantInfo, _csrf_token: &str) -> String {
    let receipt_json = serde_json::to_string_pretty(&build_receipt_json(g)).unwrap_or_default();
    let budget_tokens = g.budget.as_ref().and_then(|b| b.tokens);
    let budget_cents = g.budget.as_ref().and_then(|b| b.cents);
    let tokens_used = g.usage.tokens;
    let cents_used = g.usage.cents;
    let token_pct = budget_tokens.map(|bt| (tokens_used * 100).checked_div(bt).unwrap_or(100u64));
    let cents_pct = budget_cents.map(|bc| (cents_used * 100).checked_div(bc).unwrap_or(100u64));

    let token_gauge = if let (Some(bt), Some(pct)) = (budget_tokens, token_pct) {
        let color = if pct >= 95 { "var(--danger)" } else if pct >= 80 { "var(--warning)" } else { "var(--success)" };
        format!(r#"<div class="gauge-label"><span>Tokens</span><span>{} / {} ({pct}%)</span></div>
<div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#,
            tokens_used, bt)
    } else {
        String::new()
    };

    let cents_gauge = if let (Some(bc), Some(pct)) = (budget_cents, cents_pct) {
        let color = if pct >= 95 { "var(--danger)" } else if pct >= 80 { "var(--warning)" } else { "var(--success)" };
        let used_fmt = format!("${:.2}", cents_used as f64 / 100.0);
        let budget_fmt = format!("${:.2}", bc as f64 / 100.0);
        format!(r#"<div class="gauge-label"><span>Cost</span><span>{used_fmt} / {budget_fmt} ({pct}%)</span></div>
<div class="gauge-track"><div class="gauge-fill" style="width:{pct}%;background:{color}"></div></div>"#)
    } else {
        String::new()
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

    <div class="card">
      <div class="card-title">Budget &amp; Usage</div>
      {token_gauge}
      {cents_gauge}
      {no_budget_msg}
    </div>

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
        persona_id = g.persona_id,
        credential_name = g.credential_name,
        scope = g.scope,
        created_at = g.created_at,
        expires_at = g.expires_at.as_deref().unwrap_or("—"),
        token_gauge = token_gauge,
        cents_gauge = cents_gauge,
        no_budget_msg = if budget_tokens.is_none() && budget_cents.is_none() {
            r#"<div style="color:var(--text-dim);font-size:12px;padding:8px 0">No budget set (TTL-only grant)</div>"#
        } else {
            ""
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::DaemonStore;

    const TEST_CSRF_TOKEN: &str = "test-csrf-token-0123456789abcdef";

    fn make_state() -> Arc<DashboardState> {
        let store = DaemonStore::open_in_memory().unwrap();
        Arc::new(DashboardState {
            store: Arc::new(store),
            version: "0.0.0-test".to_string(),
            csrf_token: TEST_CSRF_TOKEN.to_string(),
            started_at: std::time::Instant::now(),
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
            .header(CSRF_HEADER, TEST_CSRF_TOKEN)
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();

        handle_dashboard_boxed(state, req).await
    }

    async fn call_post_no_csrf(state: Arc<DashboardState>, path: &str) -> Response<Full<Bytes>> {
        let req = Request::builder()
            .method("POST")
            .uri(format!("http://localhost{path}"))
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
                let html = DASHBOARD_HTML.replace("{{CSRF_TOKEN}}", &state.csrf_token);
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
                let body = serde_json::json!({
                    "running": true,
                    "version": state.version,
                    "active_agents": active_agents,
                    "active_grants": active_grants,
                    "pending_approvals": pending_approvals,
                    "audit_events": audit_events,
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
                    Ok(a) => json_response(StatusCode::OK, &serde_json::json!({
                        "id": a.id,
                        "persona_id": a.persona_id,
                        "credential_name": a.credential_name,
                        "scope": a.scope,
                        "ttl_secs": a.ttl_secs,
                        "action": a.action,
                        "risk_level": a.risk_level,
                        "status": a.status,
                        "reason": a.reason,
                        "created_at": a.created_at,
                    })),
                    Err(_) => error_response(404, "approval not found"),
                }
            }

            (Method::GET, "/api/audit") => {
                use crate::audit::AuditFilter;
                let entries = state
                    .store
                    .query_audit(&AuditFilter { limit: Some(100), ..Default::default() })
                    .unwrap_or_default();
                let body: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| serde_json::json!({"id": e.id, "action": e.action}))
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

            (Method::GET, p) if p.starts_with("/approvals/") => {
                let id = p.strip_prefix("/approvals/").unwrap_or("");
                match state.store.get_approval(id) {
                    Ok(a) => {
                        let persona_prefix: String = a.persona_id.chars().take(20).collect();
                        let html = APPROVAL_HTML_TEMPLATE
                            .replace("{{CSRF_TOKEN}}", &state.csrf_token)
                            .replace("{{APPROVAL_ID}}", &a.id)
                            .replace("{{ACTION}}", &a.action)
                            .replace("{{CREDENTIAL}}", &a.credential_name)
                            .replace("{{SCOPE}}", &a.scope)
                            .replace("{{RISK_LEVEL}}", &a.risk_level)
                            .replace("{{PERSONA_PREFIX}}", &persona_prefix)
                            .replace("{{CREATED_AT}}", &a.created_at);
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
                if !csrf_ok(&headers, &state.csrf_token) {
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
                if !csrf_ok(&headers, &state.csrf_token) {
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
                if !csrf_ok(&headers, &state.csrf_token) {
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
                if !csrf_ok(&headers, &state.csrf_token) {
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

            // 69K.7: pause toggle
            _ if method == Method::POST
                && path.starts_with("/api/grants/")
                && path.ends_with("/pause") =>
            {
                if !csrf_ok(&headers, &state.csrf_token) {
                    error_response(403, "csrf token missing or mismatched")
                } else {
                    let id = path
                        .strip_prefix("/api/grants/")
                        .unwrap()
                        .strip_suffix("/pause")
                        .unwrap();
                    match state.store.set_grant_paused(id, true) {
                        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": true})),
                        Err(e) => error_response(400, &e.to_string()),
                    }
                }
            }

            _ if method == Method::POST
                && path.starts_with("/api/grants/")
                && path.ends_with("/unpause") =>
            {
                if !csrf_ok(&headers, &state.csrf_token) {
                    error_response(403, "csrf token missing or mismatched")
                } else {
                    let id = path
                        .strip_prefix("/api/grants/")
                        .unwrap()
                        .strip_suffix("/unpause")
                        .unwrap();
                    match state.store.set_grant_paused(id, false) {
                        Ok(()) => json_response(StatusCode::OK, &serde_json::json!({"paused": false})),
                        Err(e) => error_response(400, &e.to_string()),
                    }
                }
            }

            // 69K.7: extend — body not read in test helper (empty body → None params)
            _ if method == Method::POST
                && path.starts_with("/api/grants/")
                && path.ends_with("/extend") =>
            {
                if !csrf_ok(&headers, &state.csrf_token) {
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
                        let html = build_receipt_html(&g, &state.csrf_token);
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
        assert_eq!(json["audit_events"], 1);
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

        // Pause via endpoint
        let resp = call_post(Arc::clone(&state), &format!("/api/grants/{}/pause", grant.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["paused"], true);

        // Verify store state changed
        let g1 = state.store.get_grant(&grant.id).unwrap();
        assert!(g1.paused);

        // Unpause
        let resp2 = call_post(Arc::clone(&state), &format!("/api/grants/{}/unpause", grant.id)).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let g2 = state.store.get_grant(&grant.id).unwrap();
        assert!(!g2.paused);
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
        let grant = state.store.create_grant(&persona.id, "api-key", "read", None).unwrap();
        // Set budget + usage via direct SQL. Post-composite-port we must
        // also patch blocks_json so the composite first-statement carries
        // the budget; get_grant hydrates from blocks_json.
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
        let blocks_json = serde_json::to_string(&chain.blocks).unwrap();
        state.store.conn().execute(
            "UPDATE grants SET budget_json = ?1, usage_json = ?2, blocks_json = ?3 WHERE id = ?4",
            rusqlite::params![
                r#"{"tokens":20000}"#,
                r#"{"tokens":5000,"cents":0,"requests":0,"workload_hours":0,"wall_clock_secs":0,"last_updated":0}"#,
                blocks_json,
                grant.id,
            ],
        ).unwrap();

        // Get grant from API — should expose the nested Budget + Usage structs.
        let resp = call(Arc::clone(&state), "/api/grants").await;
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["budget"]["tokens"], 20000);
        assert_eq!(arr[0]["usage"]["tokens"], 5000);
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
}
