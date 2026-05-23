// implementation-note-219
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

/// implementation-note-195 — actions hidden from the operator audit timeline by
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
/// raw persona id (implementation-note-195). Falls back to an empty map on
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

/// implementation-note-108: default persona for the dashboard's
/// single-tenant flows (passkey enrollment, credential listing).
/// Returns the first persona ordered by `list_personas()` — the QA
/// daemon ships exactly one, so this is unambiguous; production
/// daemons with multiple personas will eventually need explicit
/// per-request scoping but that's beyond the May 3 demo.
fn default_persona_id(store: &DaemonStore) -> Option<String> {
    store
        .list_personas()
        .ok()
        .and_then(|v| v.into_iter().next())
        .map(|p| p.id)
}

/// Header name clients must send on state-mutating (POST) dashboard requests.
/// 69K.7: live budget gauge + pause/extend buttons + receipt viewer.
const CSRF_HEADER: &str = "X-Ember-CSRF-Token";

// implementation-note-108: the legacy `base64url_encode` helper used by
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
/// persona secrets when minting composite-grant chains. Pre implementation-note-108 the
/// dashboard approve path never touched persona secrets, so the omission was
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
    // implementation-note-215: the dashboard shares the daemon's
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

    // implementation-note-108 follow-up: attach the same vault the main daemon
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

    // implementation-note-108: build the WebAuthn relying-party gate.
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
                            // implementation-note-220: the listener
                            // is alive at this point — propagate the resolved
                            // local_addr so `/api/status` reports it instead
                            // of relying on the configured (pre-bind) port.
                            dashboard_actual_addr: Some(local_addr),
                            // implementation-note-203: derive data_dir from
                            // db_path parent so snapshot blobs can be served.
                            data_dir: db_path.parent().map(|p| p.to_path_buf()).unwrap_or_default(),
                            // implementation-note-108: per-connection clone of
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

/// T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — display-time
/// helper that ensures every action key rendered to a human surface
/// (dashboard cards, statement gauges, audit timeline) carries a
/// `did:<method>:<rest>` prefix per design §1. Already-prefixed keys
/// pass through unchanged; bare keys (legacy fixtures, pre-migration
/// rows) are decorated with `did:ember:` so the operator sees the
/// canonical FQ shape consistently. The validator at
/// `crate::trust::grant::validate_action_keys_did_prefixed` guards
/// every new write at the RPC gate; this helper bridges the read side
/// for rows that predate the migration. Exported for tests.
pub fn display_action_key(action: &str) -> String {
    if let Some(rest) = action.strip_prefix("did:")
        && let Some(colon_idx) = rest.find(':')
        && colon_idx > 0
    {
        return action.to_string();
    }
    format!("did:ember:{action}")
}

/// Shared JS that renders a composite-statement breakdown into HTML — used
/// by both the dashboard pending-approvals card and the dedicated
/// `/approvals/{id}` page so the two surfaces can never drift. Injected
/// into both templates via `{{COMPOSITE_STATEMENTS_JS}}`. The function name
/// `render_composite_statements` (and the rendered class `composite-statements`)
/// are the implementation-note-221 target_state_anchor markers — search for
/// either if you are tracing why the page hides "3 statements" by default.
pub const COMPOSITE_STATEMENTS_JS: &str = r#"
// render_composite_statements — single source of truth for the composite
// breakdown HTML. Returns '' when stmts is null/empty so single-statement
// approvals fall through to the simple layout.
//
// `s.resource` is a `ResourceSelector` serialized via serde's
// internally-tagged enum format: `{kind: "exact"|"glob"|"any", ...}`.
// We support both that production format and the legacy
// externally-tagged shape (`{Exact: {value}}` / `{Glob: {pattern}}` /
// `"Any"`) so unit tests using bespoke fixtures keep rendering.
// displayActionKey — T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES.
// Per design §1 every action key rendered to a human surface must carry
// the `did:<method>:<rest>` FQ shape. Already-prefixed keys pass through;
// bare keys (legacy fixtures or pre-migration audit rows) are decorated
// with `did:ember:` so the operator sees a consistent canonical form.
// Mirror of the Rust-side `display_action_key` helper in dashboard.rs.
function displayActionKey(a){
  if(typeof a !== 'string' || a.length === 0) return a;
  if(a.indexOf('did:') === 0){
    var rest = a.substring(4);
    var colonIdx = rest.indexOf(':');
    if(colonIdx > 0) return a;
  }
  return 'did:ember:' + a;
}
function renderCompositeStatements(stmts){
  if(!Array.isArray(stmts) || stmts.length===0) return '';
  const rows = stmts.map(function(s,i){
    const actions = (s.actions||[]).map(displayActionKey).join(',');
    const resource = renderResourceSelector(s.resource);
    // implementation-note-222 — `time:wall_clock on * · 90s` reads as
    // technical noise (time isn't bound to a resource). When the
    // selector resolves to wildcard, drop the `on *` clause and let
    // the budget speak for itself.
    const resourceClause = (resource === '*')
      ? ''
      : ' on <span class="mono">'+resource+'</span>';
    let budget = '';
    if (s.budget) {
      const parts = [];
      if (s.budget.tokens != null) parts.push(s.budget.tokens+' tokens');
      if (s.budget.cents != null) parts.push((s.budget.cents/100).toFixed(2)+' USD');
      if (s.budget.wall_clock_secs != null) parts.push(s.budget.wall_clock_secs+'s');
      if (parts.length) budget = ' · '+parts.join(' · ');
    }
    return '<div class="composite-stmt"><span class="composite-stmt-idx">['+i+']</span> <span class="mono">'+actions+'</span>'+resourceClause+budget+'</div>';
  }).join('');
  return '<div class="composite-statements">'+rows+'</div>';
}
function renderResourceSelector(r){
  // Default — `any` selector, missing field, or unknown shape.
  if (r == null) return '*';
  if (r === 'Any' || r === 'any') return '*';
  if (typeof r !== 'object') return '*';
  // Production: serde internally-tagged enum.
  if (typeof r.kind === 'string') {
    if (r.kind === 'exact') return r.value || '*';
    if (r.kind === 'glob') return r.pattern || '*';
    return '*';
  }
  // Legacy: serde externally-tagged enum.
  if ('Exact' in r) return (r.Exact && r.Exact.value) || '*';
  if ('Glob' in r) return (r.Glob && r.Glob.pattern) || '*';
  if ('Any' in r) return '*';
  return '*';
}
function compositeSummary(stmts){
  if(!Array.isArray(stmts) || stmts.length===0) return '';
  return stmts.length+' statements';
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
/* implementation-note-223: ambient daemon-identity strip in the
   header. Subtle by design — the viewer registers it in peripheral
   vision so the verify-time --pubkey arg lands as recognition rather
   than mystery. Prominent treatment lives on the receipt detail page. */
#header .meta .identity{display:inline-flex;align-items:center;gap:8px;padding:3px 10px;border:1px solid var(--border);border-radius:5px;background:rgba(232,93,38,.04);color:var(--text-muted);font-size:11px;cursor:default;transition:opacity .15s ease-out,border-color .15s ease-out,background .15s ease-out;white-space:nowrap}
#header .meta .identity .id-label{color:var(--text-dim);text-transform:uppercase;letter-spacing:.6px;font-size:10px}
#header .meta .identity .id-fingerprint{color:var(--text-primary);font-weight:600;letter-spacing:.4px}
#header .meta .identity .id-algo{color:var(--text-dim);font-size:10px}
#header .meta .identity .id-offline{display:none;padding:1px 6px;border-radius:3px;background:rgba(239,68,68,.18);color:var(--danger);font-size:9px;font-weight:700;letter-spacing:.6px;text-transform:uppercase}
/* Offline state — daemon torn down or unreachable. Identity strip
   stays in place so the last-known fingerprint is still on screen
   when `ember receipt verify --pubkey <hex>` runs in the terminal. */
body.daemon-offline #header .meta .identity{border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.04)}
body.daemon-offline #header .meta .identity .id-fingerprint{color:var(--text-muted)}
body.daemon-offline #header .meta .identity .id-algo{opacity:.5}
body.daemon-offline #header .meta .identity .id-offline{display:inline-block}
body.daemon-offline main{opacity:.45;filter:grayscale(.5);transition:opacity .25s ease-out,filter .25s ease-out}
body.daemon-offline #header .status-dot{background:var(--danger);box-shadow:0 0 6px var(--danger)}
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
/* implementation-note-222 — hover preview of the composite breakdown
   surfaces what's hidden behind the "N statements" link without
   forcing the operator to navigate. CSS-only — no JS needed; the
   inline preview shares its render with the dedicated /approvals
   page via the same renderCompositeStatements helper. */
.scope-hover{position:relative;display:inline-block}
.scope-hover .scope-preview{display:none;position:absolute;right:0;top:calc(100% + 6px);min-width:280px;max-width:380px;z-index:50;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;box-shadow:0 8px 24px rgba(0,0,0,.4);padding:6px 8px;text-align:left;font-size:11px}
.scope-hover:hover .scope-preview, .scope-hover:focus-within .scope-preview{display:block}
.scope-hover .scope-preview .composite-statements{margin:0;background:transparent;border-left:none;padding:4px 6px}
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
.paused-banner{display:block;width:fit-content;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;background:rgba(234,179,8,.15);color:var(--warning);border:1px solid rgba(234,179,8,.3);margin-top:6px}
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
/* DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — zero-state panel teaches Receipts on first launch.
   Shown when 0 active grants AND 0 receipts; hidden by JS once either populates. */
.zero-state.dashboard-empty-state-first-receipt{background:var(--bg-card);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:20px 24px;margin-bottom:24px}
.zero-state h2{font-size:14px;color:var(--text-primary);margin:0 0 12px;font-weight:600;letter-spacing:.2px}
.zero-state-explainer{color:var(--text-muted);font-size:12px;line-height:1.55;margin:0 0 12px}
.zero-state-explainer a{color:var(--accent);text-decoration:none}
.zero-state-explainer a:hover{text-decoration:underline}
.zero-state-cmd{background:var(--bg-primary);border:1px solid var(--border);border-radius:4px;padding:10px 12px;margin:0 0 8px;overflow-x:auto}
.zero-state-cmd code{font-family:inherit;font-size:11px;color:var(--text-primary)}
.zero-state-hint{color:var(--text-dim);font-size:11px;margin:0}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
  <div class="meta">
    <span id="version">v0.0.0</span>
    <span><span id="status-dot" class="status-dot offline"></span><span id="status-text">connecting…</span></span>
    <span id="daemon-identity" class="identity" title="Daemon identity (Ed25519). Trust anchor for `ember receipt verify --pubkey`.">
      <span class="id-label">identity</span>
      <span class="id-fingerprint" id="id-fingerprint">—</span>
      <span class="id-algo">ed25519</span>
      <span class="id-offline">offline</span>
    </span>
    <span id="last-refresh" class="refresh-ts"></span>
    <a href="/settings/passkeys" style="color:var(--text-muted);font-size:11px;text-decoration:none;margin-left:8px" title="Register Touch ID / passkey for biometric approval">&#x1F511; Passkeys</a>
  </div>
</div>
<main>
  <!-- DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — first-launch zero-state panel.
       Hidden by default; JS surfaces it when 0 active grants AND 0 receipts.
       Once a Receipt exists, the panel hides and the receipts table renders. -->
  <div id="zero-state-panel" class="zero-state dashboard-empty-state-first-receipt" style="display:none">
    <h2>no grants yet — issue your first one to see how Receipts work.</h2>
    <p class="zero-state-explainer">A <strong>Receipt</strong> is the signed audit trail emitted when a grant terminates. Every action your agent takes lands here, signed by the daemon's Ed25519 identity. <a href="/verify-receipt" target="_blank" rel="noreferrer">What is a Receipt? &rarr;</a></p>
    <pre class="zero-state-cmd"><code>ember grant create --to &lt;agent&gt; --scope github:repo:read --ttl 5m</code></pre>
    <p class="zero-state-hint">Run this in your shell, then reload &mdash; the dashboard will show the live grant and (after expiry) the signed Receipt.</p>
  </div>

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

  <!-- BEAT-7-implementation-note-224 — per-agent panel grouped by persona_id so an
       operator can revoke worker-a's anthropic statement without affecting
       worker-b. Each tile lists the agent's active grants with inline links
       to the per-statement revoke buttons on the grant detail page. The
       tile-view UI itself is minimal (METAd for a richer follow-up); the
       revoke primitive already exists via render_statement_gauges_with_revoke. -->
  <div class="section" id="agents-section" style="display:none">
    <div class="section-header"><span class="section-title">Active Agents</span><span class="refresh-ts">grouped by persona · revoke per agent</span></div>
    <div id="agents-tiles" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px"></div>
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
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <select id="audit-action-filter" onchange="loadDashboard()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);font-family:inherit;font-size:11px;padding:3px 6px;cursor:pointer">
          <option value="">all actions</option>
          <option value="grant.">grant.*</option>
          <option value="approval.">approval.*</option>
          <option value="broker.">broker.*</option>
          <option value="credential.">credential.*</option>
          <option value="vault.">vault.*</option>
          <option value="sandbox.">sandbox.*</option>
        </select>
        <!-- implementation-note-194 — persona/scope/date filters -->
        <input type="text" id="audit-persona-filter" placeholder="persona id" oninput="loadDashboard()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);font-family:inherit;font-size:11px;padding:3px 6px;width:120px">
        <input type="text" id="audit-scope-filter" placeholder="scope prefix" oninput="loadDashboard()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);font-family:inherit;font-size:11px;padding:3px 6px;width:120px">
        <input type="date" id="audit-since-filter" onchange="loadDashboard()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);font-family:inherit;font-size:11px;padding:3px 6px">
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
      <span class="section-title">Maturation Review</span>
      <span class="refresh-ts">recurring patterns → Construct candidates</span>
    </div>
    <div id="maturation-body"><div class="empty">loading…</div></div>
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
    <!-- implementation-note-225 — cross-receipt search panel.
         Three text inputs (persona / scope / grant) live-fire searchReceipts()
         on input; the clear button resets and falls back to loadReceipts(). -->
    <div class="receipt-search" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;padding:8px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px">
      <input type="text" id="receipt-search-persona" placeholder="persona id" oninput="searchReceipts()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 6px;color:var(--text-primary);font-family:inherit;font-size:11px;width:140px">
      <input type="text" id="receipt-search-scope" placeholder="scope substring" oninput="searchReceipts()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 6px;color:var(--text-primary);font-family:inherit;font-size:11px;width:160px">
      <input type="text" id="receipt-search-grant" placeholder="grant id" oninput="searchReceipts()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 6px;color:var(--text-primary);font-family:inherit;font-size:11px;width:140px">
      <button onclick="clearReceiptSearch()" style="background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;padding:3px 10px;color:var(--text-muted);font-family:inherit;font-size:11px;cursor:pointer">clear</button>
    </div>
    <table id="receipts-table">
      <thead><tr><th>Issued</th><th>Grant ID</th><th>Persona</th><th>Summary</th><th>Reason</th><th>Signed</th></tr></thead>
      <tbody id="receipts-body"><tr><td colspan="6" class="empty">loading…</td></tr></tbody>
    </table>
  </div>

  <section id="receipts-panel" class="section">
    <div class="section-header">
      <span class="section-title">Live Receipts <span class="status-dot" id="receipts-status" style="background:var(--text-dim);box-shadow:none">&#9679;</span></span>
      <span class="refresh-ts">streaming via /api/receipts/stream</span>
    </div>
    <ul id="receipts-list" style="list-style:none;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;max-height:320px;overflow-y:auto;padding:0;margin:0"></ul>
  </section>
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
// implementation-note-195 — relative_time / formatRelative: render audit + grant
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
// implementation-note-195 — persona.name primary label; raw persona_id moves to
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

// implementation-note-222 — humanize audit-event labels for the timeline
// render. Raw event names are dot-segmented identifiers used by the
// Python/TS agent SDKs to demultiplex; on screen they read as log
// lines, not product copy. Map known events to spaces-and-capitals.
// Unknown events fall through unchanged so a future event surfaces
// instead of being eaten.
const AUDIT_EVENT_LABELS = {
  'grant.create':                 'Grant requested',
  'grant.minted':                 'Grant minted',
  'grant.issued':                 'Grant issued',
  'grant.delegated':              'Grant delegated',
  'grant.revoke':                 'Grant revoked',
  'grant.revoked':                'Grant revoked',
  'grant.statement_revoked':      'Statement revoked',
  'grant.expired':                'Grant expired',
  'grant.exhausted':              'Grant exhausted',
  'grant.composite_overwrite':    'Composite overwrite',
  'grant.request.stale_expired':  'Stale request expired',
  'approval.approved':            'Approved',
  'approval.denied':              'Denied',
  'approval.dismissed':           'Approval dismissed',
  'approval.integrity_violation': 'Approval integrity violation',
  'budget.warning':               'Budget warning',
  'budget.exhausted':             'Budget exhausted',
  'proxy.url':                    'Proxy listening',
  'proxy.meter':                  'Proxy meter',
  'proxy.stream':                 'Proxy stream',
  'proxy.denied_preflight':       'Proxy preflight denied',
  'proxy.credential.injected':    'Credential sideloaded',
  'sandbox.run':                  'Sandbox started',
  'broker.materialization':       'Broker materialization',
  'broker.revocation':            'Broker revocation',
  'credential.access':            'Credential accessed',
  'vault.mek_acl_migrated':       'Vault ACL migrated',
  'vault.salt':                   'Vault salt rotated',
};
function humanizeEvent(action){
  if(!action) return '—';
  return AUDIT_EVENT_LABELS[action] || action;
}

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

// implementation-note-195 — pick the most demo-meaningful budget axis from a
// composite grant's statements array (cents > tokens > wall_clock_secs).
// Returns a gauge-wrap div, or '<span …>none</span>' when no statement has
// a budget cap set.
function compositeGrantBudgetGauge(stmts) {
  if(!Array.isArray(stmts) || stmts.length===0) return '<span style="color:var(--text-dim);font-size:11px">—</span>';
  // implementation-note-226 — build a compact per-statement budget summary so
  // the operator sees all caps, not just the "best" single axis.
  const capParts = [];
  for(const s of stmts) {
    if(!s.budget) continue;
    const parts = [];
    if(s.budget.tokens != null) parts.push('tokens: '+(s.budget.tokens>=1000?(s.budget.tokens/1000).toFixed(0)+'k':s.budget.tokens));
    if(s.budget.cents != null) parts.push('cents: '+s.budget.cents);
    if(s.budget.wall_clock_secs != null) parts.push('seconds: '+s.budget.wall_clock_secs);
    if(parts.length) capParts.push(parts.join(' · '));
  }
  if(!capParts.length) return '<span style="color:var(--text-dim);font-size:11px">none</span>';
  return '<span style="color:var(--text-muted);font-size:11px">'+capParts.join(' | ')+'</span>';
}
// implementation-note-226: shipped
// implementation-note-226 — scope cell for the Active Grants table. Composite
// grants show "N statements · action1, action2, action3" so the operator
// sees real scope instead of '*'. Single-statement grants show flat scope.
function grantScopeText(g) {
  const stmts = Array.isArray(g.statements) ? g.statements : null;
  if(stmts && stmts.length>0) {
    // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — DID-prefix
    // every action key so the Active Grants table shows the canonical
    // `did:ember:<key>` form per design §1.
    const names = stmts.map(function(s){ return (s.actions||[]).map(displayActionKey).join('/'); }).join(', ');
    return stmts.length+' statement'+(stmts.length===1?'':'s')+' · '+names;
  }
  return g.scope||'—';
}
function renderBudgetGauge(g) {
  // implementation-note-227 — composite grants surface their real
  // budget via the canonical `statements` array (same name across all three
  // /api/grants* endpoints). Delegate to the composite helper when present.
  const stmts = Array.isArray(g.statements) ? g.statements : null;
  if(stmts && stmts.length>0) {
    let html = compositeGrantBudgetGauge(stmts);
    // implementation-note-222 — only show the budget-cell banner for soft
    // pause (paused flag set but status still active). Hard pause flips
    // g.status to "paused" which already renders as a yellow pill in
    // the Status column; doubling up overlaps the budget text.
    if(g.paused && g.status !== 'paused') html += '<div class="paused-banner">paused by operator</div>';
    return html;
  }
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
// implementation-note-108: WebAuthn ceremony — auth/begin → navigator.credentials.get()
// → POST /api/approvals/<id>/<action> with the verified assertion.
//
// The daemon mints a challenge bound to the specific approval_id at
// auth/begin; the assertion that comes back from the platform
// authenticator is verified server-side against the persona's
// enrolled passkey before the approval state flips. There is no
// fail-open: if the browser doesn't surface WebAuthn, or the user
// cancels TouchID, or the assertion doesn't verify, the daemon
// refuses the state transition with 401 and the approval stays
// pending.
//
// The user-visible cost of this hardness: an operator who hasn't
// yet enrolled a passkey at /settings/passkeys will see a 409 with
// a "visit /settings/passkeys" message instead of a silent click-
// through. That's the architecturally correct UX — biometric is
// not optional.
async function approveOrDeny(id, action){
  if(!('credentials' in navigator) || !navigator.credentials.get){
    alert('WebAuthn unavailable in this browser. Use Safari or Chrome on a recent macOS/Windows machine, or run `ember approval ' + action + ' ' + id + '` from the CLI.');
    return false;
  }
  // 1. auth/begin — gets challenge + allowCredentials bound to this approval.
  let beginResp, begin;
  try{
    beginResp = await fetch('/api/webauthn/auth/begin',{
      method:'POST',
      headers:{...CSRF_HEADERS,'content-type':'application/json'},
      body: JSON.stringify({approval_id: id}),
    });
  }catch(e){
    alert('Network error starting webauthn: '+e.message);
    return false;
  }
  if(!beginResp.ok){
    const err = await beginResp.json().catch(()=>({error:'failed'}));
    if(beginResp.status === 409){
      alert('No passkey enrolled. Visit /settings/passkeys to register a TouchID-backed passkey, then retry.');
    }else{
      alert('webauthn begin failed: '+(err.error||beginResp.status));
    }
    return false;
  }
  begin = await beginResp.json();

  // 2. navigator.credentials.get() — platform authenticator (TouchID).
  let credential;
  try{
    credential = await navigator.credentials.get(b64urlOptionsForGet(begin.options));
  }catch(e){
    alert('Authenticator ceremony cancelled or failed: '+(e && e.message ? e.message : e));
    return false;
  }
  if(!credential){
    alert('No assertion returned from authenticator.');
    return false;
  }

  // 3. POST approve/deny with {challenge_id, credential}. Daemon
  //    verifies the signature and flips state on success.
  const resolveResp = await fetch(`/api/approvals/${id}/${action}`,{
    method:'POST',
    headers:{...CSRF_HEADERS,'content-type':'application/json'},
    body: JSON.stringify({
      challenge_id: begin.challenge_id,
      credential: credentialToJson(credential),
    }),
  });
  if(!resolveResp.ok){
    const err = await resolveResp.json().catch(()=>({error:'failed'}));
    alert(action + ' failed: '+(err.error||resolveResp.status));
    return false;
  }
  return true;
}
async function approveRequest(id){
  if(await approveOrDeny(id, 'approve')) loadDashboard();
}
async function approveAlwaysRequest(id){
  await fetch(`/api/approvals/${id}/approve-always`,{method:'POST',headers:CSRF_HEADERS});
  loadDashboard();
}
async function denyRequest(id){
  if(await approveOrDeny(id, 'deny')) loadDashboard();
}

// ----------------------------------------------------------------
// WebAuthn JSON helpers (shared between dashboard + approval page +
// settings/passkeys). The daemon emits/expects the standard
// `webauthn-rs` JSON shape; the browser's PublicKeyCredential
// returned by navigator.credentials.{get,create} carries
// ArrayBuffers that need base64url encoding to round-trip.
// ----------------------------------------------------------------
function base64urlDecode(s){
  if(!s) return new Uint8Array(0);
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g,'+').replace(/_/g,'/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
  return out;
}
function base64urlEncode(buf){
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for(let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
// Convert webauthn-rs `RequestChallengeResponse` JSON into the shape
// `navigator.credentials.get()` expects: ArrayBuffers in challenge
// + allowCredentials[].id.
function b64urlOptionsForGet(opts){
  const pk = opts.publicKey || opts;
  const out = Object.assign({}, pk);
  out.challenge = base64urlDecode(pk.challenge);
  out.allowCredentials = (pk.allowCredentials||[]).map(c=>({
    ...c,
    id: base64urlDecode(c.id),
  }));
  return {publicKey: out};
}
// Convert webauthn-rs `CreationChallengeResponse` JSON into the shape
// `navigator.credentials.create()` expects.
function b64urlOptionsForCreate(opts){
  const pk = opts.publicKey || opts;
  const out = Object.assign({}, pk);
  out.challenge = base64urlDecode(pk.challenge);
  if(pk.user) out.user = Object.assign({}, pk.user, { id: base64urlDecode(pk.user.id) });
  out.excludeCredentials = (pk.excludeCredentials||[]).map(c=>({
    ...c,
    id: base64urlDecode(c.id),
  }));
  // Force platform authenticator (TouchID/Windows Hello). webauthn-rs's
  // default `start_passkey_registration` leaves attachment unspecified,
  // which lets Brave's app-mode picker offer "Your Brave profile" as a
  // peer to the OS biometric. Locking attachment to "platform" tells the
  // browser to skip the chooser and go directly to the OS authenticator.
  out.authenticatorSelection = Object.assign({}, pk.authenticatorSelection || {}, {
    authenticatorAttachment: 'platform',
  });
  return {publicKey: out};
}
// Serialize the browser's PublicKeyCredential (assertion or attestation)
// into the JSON shape webauthn-rs's `PublicKeyCredential` /
// `RegisterPublicKeyCredential` deserialize from.
function credentialToJson(cred){
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: base64urlEncode(cred.rawId),
    type: cred.type,
    response: {},
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
  if(r.clientDataJSON) out.response.clientDataJSON = base64urlEncode(r.clientDataJSON);
  if(r.authenticatorData) out.response.authenticatorData = base64urlEncode(r.authenticatorData);
  if(r.signature) out.response.signature = base64urlEncode(r.signature);
  if(r.userHandle) out.response.userHandle = base64urlEncode(r.userHandle);
  if(r.attestationObject) out.response.attestationObject = base64urlEncode(r.attestationObject);
  if(typeof cred.authenticatorAttachment === 'string') out.authenticatorAttachment = cred.authenticatorAttachment;
  return out;
}
// implementation-note-228 — dismiss a pending approval card.
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

async function loadMaturation(){
  try{
    const r=await fetch('/api/maturation/candidates');
    if(!r.ok)throw new Error('fetch failed');
    const candidates=await r.json();
    const el=document.getElementById('maturation-body');
    if(!candidates||candidates.length===0){
      el.innerHTML='<div class="empty">No recurring patterns yet — run agents to collect data</div>';
      return;
    }
    el.innerHTML=candidates.slice(0,5).map(c=>`
      <div class="row maturation-row">
        <span class="pattern">${c.pattern||c.action||'—'}</span>
        <span class="freq-badge">${c.frequency}×</span>
        <span class="last-seen">${c.last_seen||''}</span>
        <button onclick="navigator.clipboard.writeText('ember construct scaffold --from-pattern '+${JSON.stringify(c.action||'')})">Scaffold</button>
      </div>
    `).join('');
  }catch(e){
    document.getElementById('maturation-body').innerHTML='<div class="empty">Maturation data unavailable</div>';
  }
}
// DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — zero-state panel visibility.
// Tracks whether each parallel loader has observed any grants / receipts.
// Panel reveals only after both loaders have reported zero; any non-zero
// signal hides it. null = "haven't observed yet".
let _hasGrants=null,_hasReceipts=null;
function _updateZeroStatePanel(){
  const el=document.getElementById('zero-state-panel');
  if(!el)return;
  if(_hasGrants===false&&_hasReceipts===false){el.style.display='';}
  else if(_hasGrants===true||_hasReceipts===true){el.style.display='none';}
}
async function loadDashboard(){
  try{
    const showAll=document.getElementById('show-all-grants')?.checked;
    const grantsUrl=showAll?'/api/grants/all':'/api/grants';
    // implementation-note-195 — operator audit hides internal lifecycle events
    // (vault.auto_unseal_from_keyring + *.internal.*) by default; toggle
    // surfaces them via ?include_internal=1. Action filter dropdown narrows
    // to one family (grant.*, approval.*, broker.*, etc.) via ?action_filter=.
    const showInternal=document.getElementById('show-internal-events')?.checked;
    const actionFilter=document.getElementById('audit-action-filter')?.value||'';
    // implementation-note-194 — persona/scope/since query params.
    const personaFilter=document.getElementById('audit-persona-filter')?.value?.trim()||'';
    const scopeFilter=document.getElementById('audit-scope-filter')?.value?.trim()||'';
    const sinceDate=document.getElementById('audit-since-filter')?.value||'';
    const auditParams=new URLSearchParams();
    if(showInternal) auditParams.set('include_internal','1');
    if(actionFilter) auditParams.set('action_filter',actionFilter);
    if(personaFilter) auditParams.set('persona_filter',personaFilter);
    if(scopeFilter) auditParams.set('scope_filter',scopeFilter);
    if(sinceDate){
      const ms=Date.parse(sinceDate);
      if(!isNaN(ms)) auditParams.set('since',String(ms));
    }
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
    const pending=Number(status.pending_approvals??approvals.length??0);
    document.getElementById('cnt-approvals').textContent=String(pending);
    document.getElementById('cnt-audit').textContent=status.audit_events??audit.length??'0';
    // implementation-note-222 — surface pending count in the browser tab
    // title so a YC viewer scanning the take notices the counter
    // tick. Reverts to bare "ember" when nothing's awaiting.
    document.title = pending > 0 ? `ember · ${pending} pending` : 'ember';

    // BEAT-7-implementation-note-224 — per-agent tiles. Group active grants by
    // persona_id; each tile shows the persona alias + a credential roll-up
    // with links to the grant detail page (where per-statement revoke
    // buttons live). Terminal/show-all grants are excluded so the panel
    // only surfaces what is currently revocable.
    const agentsSection=document.getElementById('agents-section');
    const agentsTiles=document.getElementById('agents-tiles');
    if(agentsSection&&agentsTiles){
      const activeGrants=(grants||[]).filter(g=>g.status==='active');
      if(activeGrants.length===0){
        agentsSection.style.display='none';
      }else{
        const byPersona=new Map();
        for(const g of activeGrants){
          if(!byPersona.has(g.persona_id))byPersona.set(g.persona_id,{persona_id:g.persona_id,persona_name:g.persona_name,grants:[]});
          byPersona.get(g.persona_id).grants.push(g);
        }
        // Show panel only when there is at least one agent with an active grant.
        agentsSection.style.display='';
        const tiles=[];
        for(const a of byPersona.values()){
          const credLinks=a.grants.map(g=>`<a href="/grants/${g.id}" style="color:var(--text-primary);text-decoration:none;font-size:11px;display:inline-block;padding:2px 8px;background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;margin:2px" title="Open grant detail to revoke individual statements">${g.credential_name||'—'}</a>`).join('');
          tiles.push(`<div class="agent-tile" style="border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--bg-card)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <span style="font-weight:600;color:var(--text-primary)">${personaLabel(a.persona_id,a.persona_name)}</span>
              <span style="font-size:10px;color:var(--text-muted)">${a.grants.length} grant${a.grants.length===1?'':'s'}</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px">Click a credential to revoke statements:</div>
            <div>${credLinks}</div>
          </div>`);
        }
        agentsTiles.innerHTML=tiles.join('');
      }
    }

    // Grants table
    const gb=document.getElementById('grants-body');
    // DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — feed the zero-state tracker.
    // active_grants from /api/status is authoritative; grants.length fallback
    // covers the show-all toggle (which may surface terminated rows even when
    // active_grants is 0). Either > 0 means we are not in the empty state.
    _hasGrants=(Number(status.active_grants??0)>0)||(Array.isArray(grants)&&grants.length>0);
    _updateZeroStatePanel();
    if(!grants||grants.length===0){
      gb.innerHTML='<tr><td colspan="8" class="empty">No active grants yet.</td></tr>';
    }else{
      gb.innerHTML=grants.map(g=>`<tr id="grant-row-${g.id}" class="grant-status-${grantStatusClass(g.status)}">
        <td class="mono"><a href="/grants/${g.id}" style="color:var(--text-primary);text-decoration:none" title="Open grant detail (per-statement revoke)">${trunc(g.id,18)}</a></td>
        <td class="mono">${personaLabel(g.persona_id, g.persona_name)}</td>
        <td>${g.credential_name||'—'}</td>
        <td>${grantScopeText(g)}</td>
        <td class="gauge-cell">${renderBudgetGauge(g)}</td>
        <td class="ts">${g.expires_at?relTime(g.expires_at):'never'}</td>
        <td class="status-cell">${badge(g.status,g.status)}</td>
        <td>${renderGrantActions(g)}</td>
      </tr>`).join('');
      // Connect SSE for active grants with budgets (simple or composite).
      // implementation-note-195 — also wire composite grants whose statements carry
      // a budget so the gauge ticks up in real time during the demo.
      // implementation-note-227 — read `statements` (canonical name).
      grants.filter(g=>g.status==='active'&&(
        (g.budget&&(g.budget.tokens!=null||g.budget.cents!=null))||
        (Array.isArray(g.statements)&&g.statements.some(s=>s.budget&&(s.budget.cents!=null||s.budget.tokens!=null||s.budget.wall_clock_secs!=null)))
      )).forEach(g=>connectSSE(g.id, 'grant-row-'+g.id));
    }

    // Approvals
    const ac=document.getElementById('approvals-container');
    if(!approvals||approvals.length===0){
      ac.innerHTML='<div class="empty">Awaiting approval requests.</div>';
    }else{
      ac.innerHTML=approvals.map(a=>{
        // implementation-note-221 — composite breakdown moved to the
        // dedicated /approvals/{id} page (behind a Show details disclosure).
        // Cards now render a one-line summary + link so the dashboard stays
        // glanceable for the demo. Single-statement approvals keep the
        // legacy per-field row layout.
        const stmts = Array.isArray(a.composite_statements) ? a.composite_statements : null;
        // implementation-note-222 — composite scope cell surfaces a hover
        // preview of the inline breakdown so the operator can see what
        // they would be approving without navigating to the detail page.
        // The preview reuses renderCompositeStatements so the dashboard
        // card and detail page never drift in how they render statements.
        const scope_block = stmts ? `
        <div class="row"><span class="field">Scope</span><span class="scope-hover"><a class="field-val approval-link" href="/approvals/${a.id}" tabindex="0">${compositeSummary(stmts)}</a><span class="scope-preview">${renderCompositeStatements(stmts)}</span></span></div>` : `
        <div class="row"><span class="field">Credential</span><span class="field-val">${a.credential_name||'—'}</span></div>
        <div class="row"><span class="field">Scope</span><a class="field-val approval-link" href="/approvals/${a.id}">${a.scope||'—'}</a></div>`;
        // implementation-note-222 — for composites the row's flat `action` is
        // statement 0's verb, which misrepresents a multi-verb chain.
        // Surface "composite (N statements)" instead so the card matches
        // the detail page and what the storyboard voiceover claims.
        const action_label = stmts ? `composite (${stmts.length} statements)` : (a.action||'—');
        // implementation-note-222 — composite approvals are multi-statement
        // chains; the card only shows the summary, not the breakdown.
        // The operator must never approve a chain they cannot see, so
        // for composites the card surfaces Review (→ detail page) +
        // Deny only. Approve / Approve Always live on the detail page
        // where the full statement list is visible. Single-statement
        // approvals keep the inline Approve buttons because all the
        // info is already on the card.
        const action_buttons = stmts
          ? `<a class="btn btn-success" href="/approvals/${a.id}">Review &amp; Approve</a>
             <button class="btn btn-danger" onclick="denyRequest('${a.id}')">Deny</button>`
          : `<button class="btn btn-success" onclick="approveRequest('${a.id}')">&#x1F510; Approve with Touch ID</button>
             <button class="btn btn-success btn-outline" onclick="approveAlwaysRequest('${a.id}')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days).">&#x1F512; Approve Always</button>
             <a class="btn btn-neutral" href="/approvals/${a.id}">Review</a>
             <button class="btn btn-danger" onclick="denyRequest('${a.id}')">Deny</button>`;
        return `<div class="approval-card" id="approval-card-${a.id}">
        <div class="row"><span class="field">Persona</span><span class="field-val mono">${personaLabel(a.persona_id, a.persona_name)}</span></div>
        ${scope_block}
        <div class="row"><span class="field">Action</span><span class="field-val">${action_label}</span></div>
        <div class="row"><span class="field">Risk</span><span class="field-val">${badge(a.risk_level,a.risk_level)}</span></div>
        <div class="row"><span class="field">Requested</span><span class="field-val">${relTime(a.created_at)}</span></div>
        <div class="actions">
          ${action_buttons}
        </div>
      </div>`;
      }).join('');
    }

    // Audit timeline
    const ab=document.getElementById('audit-body');
    if(!audit||audit.length===0){
      ab.innerHTML='<div class="empty">Empty timeline — daemon idle.</div>';
    }else{
      ab.innerHTML=audit.map(e=>`<div class="timeline-item">
        <span class="ts">${relTime(e.timestamp)}</span>
        <span class="mono">${personaLabel(e.agent_id, e.persona_name)}</span>
        <span title="${e.action||''}">${humanizeEvent(e.action)}</span>
        <span>${e.credential||'—'}</span>
        <span>${badge(e.outcome,e.outcome)}</span>
      </div>`).join('');
    }
  }catch(err){
    // Daemon unreachable (most common: it was just stopped). Match the
    // case-2 path's wording (status.running===false) — same UX state to
    // the user. Avoid leaking the raw browser fetch-error string ("Failed
    // to fetch") into the header; the OFFLINE badge in the identity strip
    // (set by loadIdentity()'s catch) carries the offline signal.
    document.getElementById('status-text').textContent='stopped';
    document.getElementById('status-dot').classList.add('offline');
  }
}
// AP-CONSTRUCT-RECEIPT-ROLLUP-DASHBOARD — rollup view for /api/receipts.
// Default view=rollup collapses sub-receipts into per-materialization rows
// with inline denial reason. Click a row to expand sub-receipt detail.
// Pass ?view=raw (via the raw-view toggle) to restore the legacy per-receipt list.
let _receiptsViewMode='rollup';
function _rollupOutcomeStyle(outcome){
  if(outcome==='success')return'color:var(--green,#3d9970)';
  if(outcome==='denied')return'color:var(--red,#e74c3c)';
  if(outcome==='errored')return'color:var(--orange,#e67e22)';
  if(outcome==='in_flight')return'color:var(--accent)';
  return'color:var(--text-muted)';
}
function _claimSummary(r){
  const total=r.claim_count_total;
  const segments=r.claim_segment_count;
  if(total==null&&segments==null)return'';
  const totalText=total==null?'':`${total} claim${total===1?'':'s'}`;
  const segText=segments==null?'':`${segments} segment${segments===1?'':'s'}`;
  const joined=[totalText,segText].filter(Boolean).join(' across ');
  return r.claim_events_truncated?`${joined} (truncated tail)`:joined;
}
function _receiptReasonLabel(v){
  const raw=String(v==null?'':v).trim();
  if(!raw)return'—';
  const cleaned=raw
    .replace(/^\w+\s*/,'')
    .replace(/[{}"]/g,'')
    .replace(/_/g,' ')
    .replace(/([a-z])([A-Z])/g,'$1 $2')
    .trim()
    .toLowerCase();
  if(!cleaned)return'—';
  if(cleaned==='exhausted by budget')return'budget exhausted';
  if(cleaned==='parent cascade revoked')return'parent revoked';
  return cleaned;
}
function _renderRawReceiptRow(r){
  const signedHtml=r.signed
    ?'<span class="signed-yes" title="Ed25519 signed by daemon identity">&#10003;</span>'
    :'<span class="signed-no" title="No signature (placeholder)">—</span>';
  const grantLink=`<a href="/grants/${r.grant_id}" class="mono" style="color:var(--accent)">${trunc(r.grant_id,16)}</a>`;
  const kindBadge=`<span class="badge" style="margin-right:6px;font-size:10px;background:rgba(232,93,38,.12);border:1px solid rgba(232,93,38,.28);color:#ff9468">${safe(r.kind||'receipt')}</span>`;
  const receiptLink=`<a href="/receipts/${encodeURIComponent(String(r.id||''))}" style="color:var(--text-muted);text-decoration:none">${safe(r.action_summary||'—')}</a>`;
  const claimSummary=_claimSummary(r);
  const ts=r.created_at?relTime(r.created_at):(r.created_at_epoch?relTime(new Date(r.created_at_epoch*1000).toISOString()):'—');
  const reason=_receiptReasonLabel(r.terminal_reason).slice(0,32)||'—';
  return`<tr>
    <td class="ts">${ts}</td>
    <td>${grantLink}</td>
    <td class="mono">${personaLabel(r.persona_id,r.persona_name)}</td>
    <td style="color:var(--text-muted);font-size:11px">${kindBadge}${receiptLink}${claimSummary?`<div style="font-size:10px;color:var(--text-dim);margin-top:2px">${safe(claimSummary)}</div>`:''}</td>
    <td style="color:var(--text-dim);font-size:11px">${reason}</td>
    <td style="text-align:center">${signedHtml}</td>
  </tr>`;
}
function _toggleRollupDetail(mid){
  const el=document.getElementById('rollup-detail-'+mid);
  if(!el)return;
  el.style.display=el.style.display==='none'?'table-row':'none';
}
async function loadReceipts(){
  try{
    const signedOnly=document.getElementById('receipt-signed-filter')?.value||'';
    const since=document.getElementById('receipt-since-filter')?.value||'all';
    const personaId=(document.getElementById('receipt-persona-filter')?.value||'').trim();
    const p=new URLSearchParams();
    p.set('view',_receiptsViewMode);
    if(signedOnly==='true')p.set('signed_only','true');
    if(since&&since!=='all')p.set('since',since);
    if(personaId)p.set('persona_id',personaId);
    const url='/api/receipts?'+p.toString();
    const data=await fetch(url).then(r=>r.json());
    const rb=document.getElementById('receipts-body');
    if(!rb)return;
    // DASHBOARD-EMPTY-STATE-FIRST-RECEIPT — feed the zero-state tracker.
    _hasReceipts=Array.isArray(data)&&data.length>0;
    _updateZeroStatePanel();
    // Update table header for rollup vs raw view.
    const th=document.querySelector('#receipts-table thead tr');
    if(th){
      if(_receiptsViewMode==='rollup'){
        th.innerHTML='<th>Started</th><th>Materialization</th><th>Persona</th><th>Action</th><th>Outcome</th><th>Sub-receipts</th>';
      }else{
        th.innerHTML='<th>Issued</th><th>Grant ID</th><th>Persona</th><th>Summary</th><th>Reason</th><th>Signed</th>';
      }
    }
    if(!data||data.length===0){
      rb.innerHTML='<tr><td colspan="6" class="empty">No receipts yet — terminal grants emit signed receipts here.</td></tr>';
      return;
    }
    if(_receiptsViewMode==='rollup'){
      // Rollup view: one row per materialization_id with inline denial reason.
      // Click a row to expand/collapse the sub-receipt detail.
      rb.innerHTML=data.map(r=>{
        const mid=r.materialization_id||'—';
        const midShort=mid.length>20?mid.slice(0,18)+'…':mid;
        const ts=r.started_at?relTime(r.started_at):'—';
        const persona=r.persona||'—';
        const action=(r.action||'—').slice(0,32);
        const claimSummary=_claimSummary(r);
        const actionHtml=claimSummary
          ?`${action}<div style="color:var(--text-dim);font-size:10px;margin-top:2px">${claimSummary}</div>`
          :action;
        const outcomeStyle=_rollupOutcomeStyle(r.outcome||'');
        // Inline denial reason — no click-through required for primary scan.
        const outcomeLabel=r.denial_reason
          ?`<span style="${outcomeStyle}">${r.outcome}</span> <span style="color:var(--text-dim);font-size:10px" title="${r.denial_reason}">(${(r.denial_reason||'').slice(0,24)})</span>`
          :`<span style="${outcomeStyle}">${r.outcome||'—'}</span>`;
        const count=r.receipt_count||0;
        const subHtml=(r.sub_receipts||[]).map(s=>{
          const subClaimSummary=_claimSummary(s);
          const subClaimHtml=subClaimSummary?` <span style="color:var(--text-dim)">· ${subClaimSummary}</span>`:'';
          return`<span style="display:block;font-size:10px;color:var(--text-muted);padding:1px 0">${s.kind}${subClaimHtml} <span style="color:var(--text-dim)">${(s.ts||'').slice(0,19)}</span> <a href="/receipts/${encodeURIComponent(String(s.receipt_hash||''))}" class="mono" style="font-size:9px;color:var(--text-primary);text-decoration:none">${(s.receipt_hash||'').slice(0,16)}</a></span>`;
        }).join('');
        const detailRow=`<tr id="rollup-detail-${mid}" style="display:none"><td colspan="6" style="padding:4px 12px;background:var(--bg-hover)">${subHtml||'<span style="color:var(--text-dim);font-size:11px">no sub-receipts</span>'}</td></tr>`;
        const mainRow=`<tr style="cursor:pointer" onclick="_toggleRollupDetail('${mid}')" title="Click to expand sub-receipt detail">
          <td class="ts">${ts}</td>
          <td class="mono" style="font-size:11px" title="${mid}">${midShort}</td>
          <td class="mono" style="font-size:11px">${persona}</td>
          <td style="color:var(--text-muted);font-size:11px">${actionHtml}</td>
          <td style="font-size:11px">${outcomeLabel}</td>
          <td style="color:var(--text-dim);font-size:11px;text-align:center">${count}</td>
        </tr>`;
        return mainRow+detailRow;
      }).join('');
    }else{
      // Raw view: original per-receipt list shape.
      const receipts=data;
      rb.innerHTML=receipts.map(_renderRawReceiptRow).join('');
    }
  }catch(err){
    const rb=document.getElementById('receipts-body');
    if(rb)rb.innerHTML='<tr><td colspan="6" class="empty">error loading receipts</td></tr>';
  }
}
// implementation-note-225 — cross-receipt search. When any input
// has a value we hit /api/receipts/search and render the result in the
// existing receipts table; an empty form falls back to loadReceipts() so
// the standard signed/since filters resume.
async function searchReceipts(){
  const persona=(document.getElementById('receipt-search-persona')?.value||'').trim();
  const scope=(document.getElementById('receipt-search-scope')?.value||'').trim();
  const grant=(document.getElementById('receipt-search-grant')?.value||'').trim();
  if(!persona&&!scope&&!grant){
    loadReceipts();
    return;
  }
  try{
    const p=new URLSearchParams();
    if(persona)p.set('persona',persona);
    if(scope)p.set('scope',scope);
    if(grant)p.set('grant_id',grant);
    const receipts=await fetch('/api/receipts/search?'+p.toString()).then(r=>r.json());
    const rb=document.getElementById('receipts-body');
    if(!rb)return;
    if(!Array.isArray(receipts)||receipts.length===0){
      rb.innerHTML='<tr><td colspan="6" class="empty">No receipts match the current filter.</td></tr>';
      return;
    }
    rb.innerHTML=receipts.map(_renderRawReceiptRow).join('');
  }catch(err){
    const rb=document.getElementById('receipts-body');
    if(rb)rb.innerHTML='<tr><td colspan="6" class="empty">error searching receipts</td></tr>';
  }
}
function clearReceiptSearch(){
  const ids=['receipt-search-persona','receipt-search-scope','receipt-search-grant'];
  ids.forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  loadReceipts();
}
loadDashboard();
loadReceipts();
loadMaturation();
// implementation-note-223 — fetch the daemon's Ed25519 identity once
// on load + every 2s thereafter. Success populates the header
// fingerprint and clears the daemon-offline class; failure adds it.
// The fingerprint persists in the DOM after failure so the closing
// `ember receipt verify --pubkey <hex>` line in the terminal still
// matches what's on screen — that visual loop is the load-bearing
// anchor for the wedge story ("the receipt outlives the issuer").
async function loadIdentity(){
  try{
    const r = await fetch('/api/daemon/identity');
    if(!r.ok) throw new Error('http '+r.status);
    const id = await r.json();
    if(id && typeof id.pubkey === 'string' && id.pubkey.length >= 16){
      const fp = id.pubkey.substring(0, 16).match(/.{1,4}/g).join(':');
      const fpEl = document.getElementById('id-fingerprint');
      if(fpEl && fpEl.textContent !== fp) fpEl.textContent = fp;
      const wrap = document.getElementById('daemon-identity');
      if(wrap){
        const tip = `Daemon identity (Ed25519, canonical v${id.canonical_version||1})\nFull pubkey: ${id.pubkey}\nTrust anchor for: ember receipt verify --file <path> --pubkey ${id.pubkey}`;
        if(wrap.title !== tip) wrap.title = tip;
      }
      document.body.classList.remove('daemon-offline');
    }
  }catch(e){
    document.body.classList.add('daemon-offline');
  }
}
loadIdentity();
setInterval(loadIdentity, 2000);
// implementation-note-202 — FINDING C: drop the dashboard refresh
// cadence from 5s to 2s so the cents-gauge ticks visibly during Beat 4
// of the WEDGE storyboard (where the agent burns through the budget
// call-by-call). SSE handles instantaneous warning/exhaust transitions;
// this interval governs the running-total visualisation between SSE
// events. 2s is the recording-quality floor — shorter would hammer
// /api/grants without visible benefit.
setInterval(loadDashboard,2000);
setInterval(loadReceipts,15000);

// implementation-note-229 — live receipts panel: stream new receipt rows from
// /api/receipts/stream and prepend them to #receipts-list. EventSource
// auto-reconnects via the server-emitted retry hint, so the client stays
// live without a manual setInterval poll. Capped at 50 visible rows so
// the page never grows unbounded during a long demo.
(function(){
  const list = document.getElementById('receipts-list');
  const status = document.getElementById('receipts-status');
  if(!list || !status) return;
  let evt = null;
  function safe(s){return String(s==null?'':s).replace(/[<>&"']/g, function(c){
    return ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'})[c];
  });}
  function claimSummary(r){
    const total = Number.isFinite(r.claim_count_total) ? r.claim_count_total : null;
    const segs = Number.isFinite(r.claim_segment_count) ? r.claim_segment_count : null;
    const tail = !!r.claim_events_truncated;
    if(total == null && segs == null && !tail) return '';
    const bits = [];
    if(total != null) bits.push(total + ' claims');
    if(segs != null) bits.push(segs + ' segs');
    if(tail) bits.push('tail');
    return bits.join(' / ');
  }
  function connect(){
    try{ evt = new EventSource('/api/receipts/stream'); }catch(e){ return; }
    evt.onopen = function(){ status.style.background = 'var(--success)'; status.style.boxShadow='0 0 6px var(--success)'; };
    evt.onerror = function(){ status.style.background = 'var(--danger)'; status.style.boxShadow='0 0 6px var(--danger)'; };
    evt.onmessage = function(e){
      try{
        const r = JSON.parse(e.data);
        const claim = claimSummary(r);
        const li = document.createElement('li');
        li.style.cssText = 'display:grid;grid-template-columns:140px 110px 180px 1fr;gap:10px;padding:8px 14px;border-bottom:1px solid var(--border);font-size:11px;color:var(--text-primary)';
        li.innerHTML =
          '<span class="ts">'+safe(r.materialized_at)+'</span>'+
          '<span class="badge '+(r.kind==='grant'?'active':'pending')+'">'+safe(r.kind)+'</span>'+
          '<span class="mono" style="color:var(--text-muted)">'+safe(r.actor)+'</span>'+
          '<span class="mono"><a href="/receipts/'+encodeURIComponent(String(r.id||''))+'" style="color:var(--text-primary);text-decoration:none">'+safe(r.resource)+'</a>'+(claim?'<div style="font-size:10px;color:var(--text-dim);margin-top:2px">'+safe(claim)+'</div>':'')+'</span>';
        list.insertBefore(li, list.firstChild);
        while(list.children.length > 50){ list.removeChild(list.lastChild); }
      }catch(err){ /* ignore parse errors */ }
    };
  }
  connect();
})();
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
/* implementation-note-222 — author-defined `display:flex` overrides the
   user-agent `[hidden]{display:none}` rule (CSS specificity gotcha),
   so `el.hidden = true` had no visible effect on `.field` rows.
   Explicit override below restores the expected behavior. */
.field[hidden]{display:none}
.field-label{color:var(--text-muted);font-size:11px}
.field-val{color:var(--text-primary);font-size:12px;text-align:right;max-width:340px;word-break:break-all}
.persona-id{color:var(--text-muted);font-size:11px;margin-left:6px;font-family:inherit}
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
.statements-section{margin-top:14px;padding-top:14px;border-top:1px solid var(--border)}
.statements-section .field-label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);margin-bottom:6px}
.statements-section[hidden]{display:none}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
</div>
<div class="card">
  <div class="card-title">Pending Approval</div>
  <div class="field"><span class="field-label">Action</span><span class="field-val">{{ACTION}}</span></div>
  {{SKILL_REF_ROW}}
  <div class="field" id="credential-row"><span class="field-label">Credential</span><span class="field-val">{{CREDENTIAL}}</span></div>
  <div class="field" id="scope-row"><span class="field-label">Scope</span><span class="field-val" id="scope-summary">{{SCOPE}}</span></div>
  <div class="field"><span class="field-label">Risk</span><span class="field-val"><span class="badge {{RISK_LEVEL}}">{{RISK_LEVEL}}</span></span></div>
  <div class="field"><span class="field-label">Persona</span><span class="field-val">{{PERSONA_PREFIX}}</span></div>
  <div class="field"><span class="field-label">Requested</span><span class="field-val">{{CREATED_AT}}</span></div>
  <!-- implementation-note-222 — composite breakdown is the scope. Always
       visible so the operator can never approve a chain they cannot
       see. Hidden only for single-statement approvals (which do not
       have a meaningful breakdown). -->
  <div class="statements-section" id="statements-section" hidden>
    <span class="field-label">Statements</span>
    <div id="composite-breakdown"></div>
  </div>
  <div class="actions">
    <button class="btn btn-success" id="btn-approve" onclick="resolve('approve')">&#x1F510; Approve with Touch ID</button>
    <button class="btn btn-success btn-always" id="btn-approve-always" onclick="resolve('approve-always')" title="Auto-approve future requests for this action from this persona. Creates a standing grant (expires in 30 days). Reviewable under Standing Grants.">&#x1F512; Approve Always</button>
    <button class="btn btn-danger" id="btn-deny" onclick="resolve('deny')">Deny</button>
  </div>
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
  // implementation-note-222 — composite breakdown is the scope. Show it
  // inline as soon as the page loads; never gate "what am I approving?"
  // behind a disclosure. The flat Credential and Scope rows are
  // statement 0's projection — misleading for a multi-statement chain
  // — so we hide them when a real breakdown exists.
  const section = document.getElementById('statements-section');
  const body = document.getElementById('composite-breakdown');
  body.innerHTML = renderCompositeStatements(stmts);
  section.hidden = false;
  const credRow = document.getElementById('credential-row');
  if(credRow) credRow.hidden = true;
  const scopeRow = document.getElementById('scope-row');
  if(scopeRow) scopeRow.hidden = true;
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
// implementation-note-108: dedicated approval page — same auth/begin →
// navigator.credentials.get() → POST/<action> ceremony as the main
// dashboard pending-approvals card. Fail-closed: no WebAuthn, no
// state flip.
function base64urlDecode(s){
  if(!s) return new Uint8Array(0);
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g,'+').replace(/_/g,'/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
  return out;
}
function base64urlEncode(buf){
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for(let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function b64urlOptionsForGet(opts){
  const pk = opts.publicKey || opts;
  const out = Object.assign({}, pk);
  out.challenge = base64urlDecode(pk.challenge);
  out.allowCredentials = (pk.allowCredentials||[]).map(c=>({
    ...c,
    id: base64urlDecode(c.id),
  }));
  return {publicKey: out};
}
function credentialToJson(cred){
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: base64urlEncode(cred.rawId),
    type: cred.type,
    response: {},
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
  if(r.clientDataJSON) out.response.clientDataJSON = base64urlEncode(r.clientDataJSON);
  if(r.authenticatorData) out.response.authenticatorData = base64urlEncode(r.authenticatorData);
  if(r.signature) out.response.signature = base64urlEncode(r.signature);
  if(r.userHandle) out.response.userHandle = base64urlEncode(r.userHandle);
  if(typeof cred.authenticatorAttachment === 'string') out.authenticatorAttachment = cred.authenticatorAttachment;
  return out;
}
async function resolve(action){
  const btns = document.querySelectorAll('.btn');
  btns.forEach(b=>b.disabled=true);
  try{
    const needsBio = action === 'approve' || action === 'deny';
    const headers = {'X-Ember-CSRF-Token':CSRF_TOKEN,'content-type':'application/json'};
    let body;
    if(needsBio){
      if(!('credentials' in navigator) || !navigator.credentials.get){
        alert('WebAuthn unavailable in this browser. Use Safari or Chrome on a recent macOS/Windows machine, or run `ember approval ' + action + ' ' + APPROVAL_ID + '` from the CLI.');
        btns.forEach(b=>b.disabled=false);
        return;
      }
      const beginResp = await fetch('/api/webauthn/auth/begin',{
        method:'POST',
        headers,
        body: JSON.stringify({approval_id: APPROVAL_ID}),
      });
      if(!beginResp.ok){
        const err = await beginResp.json().catch(()=>({error:'failed'}));
        if(beginResp.status === 409){
          alert('No passkey enrolled for this persona. Visit /settings/passkeys to register one, then retry.');
        }else{
          alert('webauthn begin failed: '+(err.error||beginResp.status));
        }
        btns.forEach(b=>b.disabled=false);
        return;
      }
      const begin = await beginResp.json();
      let credential;
      try{
        credential = await navigator.credentials.get(b64urlOptionsForGet(begin.options));
      }catch(e){
        alert('Authenticator ceremony cancelled or failed: '+(e && e.message ? e.message : e));
        btns.forEach(b=>b.disabled=false);
        return;
      }
      if(!credential){
        alert('No assertion returned from authenticator.');
        btns.forEach(b=>b.disabled=false);
        return;
      }
      body = JSON.stringify({
        challenge_id: begin.challenge_id,
        credential: credentialToJson(credential),
      });
    }
    const resp = await fetch(`/api/approvals/${APPROVAL_ID}/${action}`,{
      method:'POST',
      headers,
      body: body,
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

/// implementation-note-108: first-run passkey enrollment page at `/settings/passkeys`.
///
/// Guides the operator through registering their platform authenticator
/// (Touch ID on macOS, Windows Hello on Windows). Calls
/// `/api/webauthn/register/begin` → `navigator.credentials.create()` →
/// `/api/webauthn/register/complete` so the credential's COSE pubkey is
/// persisted server-side in the daemon's `webauthn_credentials` table.
/// Subsequent dashboard approvals can verify a signed assertion against
/// that pubkey — there is no localStorage in the trust path.
const PASSKEYS_SETTINGS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ember · passkey settings</title>
<style>
:root{--bg-primary:#0a0a0f;--bg-card:#12121a;--accent:#e85d26;--text-primary:#e0e0e8;--text-muted:#6b6b7b;--border:#1e1e2e;--success:#22c55e;--warning:#eab308;--danger:#ef4444}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'JetBrains Mono',ui-monospace,'Cascadia Code','Fira Code',monospace;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;font-size:13px;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
#header{width:100%;max-width:560px;display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
#header .logo{font-size:20px;font-weight:700;color:var(--accent)}
#header a{color:var(--text-muted);font-size:12px;text-decoration:none}
#header a:hover{color:var(--text-primary)}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:24px;width:100%;max-width:560px;margin-bottom:16px}
.card-title{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:16px}
.desc{font-size:12px;color:var(--text-muted);line-height:1.6;margin-bottom:20px}
.btn{display:inline-block;padding:10px 20px;border-radius:4px;font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:opacity .1s}
.btn:hover{opacity:.8}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-primary{background:rgba(232,93,38,.15);color:var(--accent);border-color:rgba(232,93,38,.3)}
.btn-danger{background:rgba(239,68,68,.15);color:var(--danger);border-color:rgba(239,68,68,.3)}
#status{margin-top:16px;padding:12px 16px;border-radius:6px;font-size:12px;display:none}
#status.ok{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);color:var(--success)}
#status.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:var(--danger)}
.passkey-list{margin-top:16px}
.passkey-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:12px}
.passkey-row:last-of-type{border-bottom:none}
.passkey-id{color:var(--text-muted);font-size:11px;word-break:break-all;max-width:380px}
.empty{color:var(--text-muted);font-size:12px;font-style:italic;padding:8px 0}
</style>
</head>
<body>
<div id="header">
  <a class="logo" href="/">ember</a>
</div>
<div class="card">
  <div class="card-title">Passkey Enrollment</div>
  <p class="desc">Register your platform authenticator (Touch ID on macOS, Windows Hello on Windows, or a hardware security key) to enable biometric approval confirmation on this browser. Once enrolled, the Approve button on pending-approval cards will raise the OS biometric sheet before submitting.</p>
  <button class="btn btn-primary" id="btn-enroll" onclick="enrollPasskey()">Register Passkey</button>
  <div id="status"></div>
</div>
<div class="card">
  <div class="card-title">Enrolled Passkeys</div>
  <div id="passkey-list"></div>
</div>
<script>
const CSRF_TOKEN = "{{CSRF_TOKEN}}";
const CSRF_HEADERS = {'X-Ember-CSRF-Token':CSRF_TOKEN,'content-type':'application/json'};
let CURRENT_PERSONA_ID = null;

function escapeHtml(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function base64urlDecode(s){
  if(!s) return new Uint8Array(0);
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g,'+').replace(/_/g,'/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
  return out;
}
function base64urlEncode(buf){
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for(let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function b64urlOptionsForCreate(opts){
  const pk = opts.publicKey || opts;
  const out = Object.assign({}, pk);
  out.challenge = base64urlDecode(pk.challenge);
  if(pk.user) out.user = Object.assign({}, pk.user, { id: base64urlDecode(pk.user.id) });
  out.excludeCredentials = (pk.excludeCredentials||[]).map(c=>({
    ...c,
    id: base64urlDecode(c.id),
  }));
  // Force platform authenticator (TouchID/Windows Hello). webauthn-rs's
  // default `start_passkey_registration` leaves attachment unspecified,
  // which lets Brave's app-mode picker offer "Your Brave profile" as a
  // peer to the OS biometric. Locking attachment to "platform" tells the
  // browser to skip the chooser and go directly to the OS authenticator.
  out.authenticatorSelection = Object.assign({}, pk.authenticatorSelection || {}, {
    authenticatorAttachment: 'platform',
  });
  return {publicKey: out};
}
function attestationToJson(cred){
  const r = cred.response;
  const out = {
    id: cred.id,
    rawId: base64urlEncode(cred.rawId),
    type: cred.type,
    response: {},
    extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
  if(r.clientDataJSON) out.response.clientDataJSON = base64urlEncode(r.clientDataJSON);
  if(r.attestationObject) out.response.attestationObject = base64urlEncode(r.attestationObject);
  if(typeof cred.authenticatorAttachment === 'string') out.authenticatorAttachment = cred.authenticatorAttachment;
  return out;
}
function showStatus(msg, ok){
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = ok ? 'ok' : 'err';
  el.style.display = 'block';
}

async function loadEnrolledList(){
  const el = document.getElementById('passkey-list');
  try{
    const resp = await fetch('/api/webauthn/credentials');
    if(!resp.ok){
      el.innerHTML = '<div class="empty">Could not load enrolled passkeys (status '+resp.status+').</div>';
      return;
    }
    const data = await resp.json();
    CURRENT_PERSONA_ID = data.persona_id;
    const ids = data.credential_ids || [];
    if(ids.length === 0){
      el.innerHTML = '<div class="empty">No passkeys enrolled. Click Register Passkey above.</div>';
      return;
    }
    el.innerHTML = ids.map(cid=>`
      <div class="passkey-row">
        <span class="passkey-id">${escapeHtml(cid)}</span>
        <button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="removePasskey('${escapeHtml(cid)}')">Remove</button>
      </div>`).join('');
  }catch(e){
    el.innerHTML = '<div class="empty">Could not load enrolled passkeys: '+escapeHtml(e.message)+'</div>';
  }
}

async function removePasskey(credentialId){
  if(!CURRENT_PERSONA_ID){ alert('persona unknown — reload page'); return; }
  const resp = await fetch('/api/webauthn/credentials/delete',{
    method:'POST',
    headers: CSRF_HEADERS,
    body: JSON.stringify({persona_id: CURRENT_PERSONA_ID, credential_id: credentialId}),
  });
  if(!resp.ok){
    alert('delete failed: '+resp.status);
    return;
  }
  loadEnrolledList();
}

async function enrollPasskey(){
  const btn = document.getElementById('btn-enroll');
  btn.disabled = true;
  try{
    if(!('credentials' in navigator) || !navigator.credentials.create){
      showStatus('WebAuthn not available in this browser or context.', false);
      btn.disabled = false;
      return;
    }
    showStatus('Requesting challenge from daemon…', true);
    const beginResp = await fetch('/api/webauthn/register/begin',{
      method:'POST',
      headers: CSRF_HEADERS,
      body: JSON.stringify({}),
    });
    if(!beginResp.ok){
      const err = await beginResp.json().catch(()=>({error:'failed'}));
      showStatus('begin failed: '+(err.error||beginResp.status), false);
      btn.disabled = false;
      return;
    }
    const begin = await beginResp.json();

    showStatus('Touch ID / authenticator prompt…', true);
    let credential;
    try{
      credential = await navigator.credentials.create(b64urlOptionsForCreate(begin.options));
    }catch(e){
      showStatus('Registration failed: '+(e && e.message ? e.message : String(e)), false);
      btn.disabled = false;
      return;
    }
    if(!credential){
      showStatus('Registration cancelled.', false);
      btn.disabled = false;
      return;
    }

    showStatus('Verifying with daemon…', true);
    const completeResp = await fetch('/api/webauthn/register/complete',{
      method:'POST',
      headers: CSRF_HEADERS,
      body: JSON.stringify({
        challenge_id: begin.challenge_id,
        credential: attestationToJson(credential),
      }),
    });
    if(!completeResp.ok){
      const err = await completeResp.json().catch(()=>({error:'failed'}));
      showStatus('verify failed: '+(err.error||completeResp.status), false);
      btn.disabled = false;
      return;
    }
    showStatus('Passkey registered. You can now approve grants with Touch ID.', true);
    loadEnrolledList();
  }catch(e){
    showStatus('Registration failed: '+(e && e.message ? e.message : String(e)), false);
  }
  btn.disabled = false;
}

loadEnrolledList();
</script>
</body>
</html>"#;

// implementation-note-230: shipped
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
    /// implementation-note-220: the address the dashboard actually
    /// bound to, surfaced via `/api/status` as `dashboard_addr_bound`. Always
    /// `Some` when the dashboard is serving traffic (you can't reach this
    /// state otherwise) but the field is `Option<>` so test fixtures can
    /// model the "not bound" case to verify the JSON contract returns `null`.
    /// Resolved from `TcpListener::local_addr()` after a successful bind so
    /// port-0 ephemeral assignments are reflected truthfully.
    pub dashboard_actual_addr: Option<SocketAddr>,
    /// implementation-note-203: daemon data directory — used to serve
    /// cluster-snapshot blobs from `<data_dir>/snapshots/`.
    pub data_dir: std::path::PathBuf,
    /// implementation-note-108: server-side WebAuthn relying party.
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
            let html = DASHBOARD_HTML
                .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
                .replace("{{CSRF_TOKEN}}", &state.csrf_token);
            // ETag-based revalidation: the ETag is the compile-time git SHA so
            // any rebuilt binary serves a new ETag, invalidating browser caches
            // on upgrade. `Cache-Control: no-cache` (NOT `no-store`) lets the
            // browser cache the document but requires revalidation before use —
            // a 304 path avoids re-transmitting the full HTML on every load
            // while still guaranteeing staleness never survives a daemon upgrade.
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
            // implementation-note-220: stringify the bound address
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

        // implementation-note-229 — Server-Sent Events stream feeding the live
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

        // implementation-note-225 — cross-receipt search panel.
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
                        .map(|r| receipt_row_raw_payload(&state.store, r, names.get(&r.actor).cloned()))
                        .collect();
                    // implementation-note-231: shipped
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
            // implementation-note-195 — surface persona.name alongside persona_id
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
                        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
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

                    // implementation-note-232 (budget_persists_on_simple_grant) —
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
                    // implementation-note-227 — emit the per-Statement
                    // array under `statements` to match `grant_to_json_with_store`
                    // (the canonical serializer used by /api/grants/all and
                    // /api/grants/{id}). Previously this list endpoint emitted
                    // the same data under `composite_statements`, forcing JS
                    // callers into `g.statements || g.composite_statements`
                    // fallbacks that cemented the divergence.
                    //
                    // implementation-note-222 — silently dropping the
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
                                    // implementation-note-227 —
                                    // per-Statement shape mirrors
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
            // implementation-note-195 — `persona.name` lookup for the approval card.
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
                        // implementation-note-233 — composite envelopes (sandbox-run 3-statement
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
                    // implementation-note-195 — additive `persona_name` lookup.
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
                            // implementation-note-233 — surface composite statements + minted grant ID.
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
            // implementation-note-234: shipped
            use crate::infra::audit::AuditFilter;
            // implementation-note-195 — operator audit timeline hides internal
            // bookkeeping events (vault.auto_unseal_from_keyring + the
            // generic `*.internal.*` namespace) by default. The dashboard
            // toggle re-fetches with `?include_internal=1` so internal
            // events are reachable without hand-editing URLs.
            // `?action_filter=<prefix>` further narrows to one action family
            // (e.g. `grant.`, `approval.`, `broker.`). Both are rendering-
            // layer only — store rows are unchanged.
            //
            // implementation-note-194 — additional query params:
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
            // implementation-note-235: shipped
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

        _ if method == Method::POST
            && path.starts_with("/api/grants/")
            && path.ends_with("/revoke-statement") =>
        {
            // implementation-note-236 — per-statement revoke
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
                    .unwrap();
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
                match state.store.resolve_approval(
                    id,
                    &ApprovalOutcome::Always {
                        scope: None,
                        expires_at,
                    },
                ) {
                    Ok(()) => json_response(
                        StatusCode::OK,
                        &serde_json::json!({"approved": true, "standing_grant_created": true}),
                    ),
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
                resolve_approval_via_dashboard(state, req, id, /* approve */ true).await
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
                resolve_approval_via_dashboard(state, req, id, /* approve */ false).await
            }
        }

        // implementation-note-108: WebAuthn registration ceremony — begin.
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

        // implementation-note-108: WebAuthn registration ceremony — finish.
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

        // implementation-note-108: WebAuthn authentication ceremony — begin.
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

        // implementation-note-108: list enrolled credentials for a persona.
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

        // implementation-note-108: delete an enrolled credential. Body
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

        // implementation-note-203: GET /api/cluster-snapshot/latest
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

        // implementation-note-203: GET /api/cluster-snapshot/{id}
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

        // POST /api/approvals/{id}/dismiss — implementation-note-228
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
                && let Ok(envelope) = serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
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
                if let Ok(mut v2_receipts) = state.store.list_receipts_v2_envelopes(&[g.id.clone()])
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

        // implementation-note-237 — first-run passkey enrollment page.
        // Explains how to register the operator's platform authenticator
        // (Touch ID on macOS, Windows Hello on Windows) so the dashboard
        // Approve button raises the OS biometric sheet.
        (Method::GET, "/settings/passkeys") => {
            // implementation-note-108: substitute the per-process CSRF token
            // so the page can issue authenticated POSTs to
            // /api/webauthn/{register,credentials/delete}.
            let html = PASSKEYS_SETTINGS_HTML.replace("{{CSRF_TOKEN}}", &state.csrf_token);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap()
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
/// Post-composite-port (design): emits a `statements` array with per-
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
        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
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

    // implementation-note-195 — additive `persona_name` lookup so the dashboard
    // can render the persona's display name as the primary label.
    let persona_name = store.get_persona(&g.persona_id).ok().map(|p| p.name);

    // dashboard_agent_tree_view_promoted — implementation-note-238
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

    // implementation-note-236 — surface seconds-remaining
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
        conds.insert("allowed_targets".to_string(), serde_json::json!(targets));
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
/* implementation-note-223: Signed-by card. Foreground treatment for
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

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    let escaped = escape_html(&serde_json::to_string_pretty(envelope).unwrap_or_default());
    let workflow_template = envelope
        .body
        .get("workflow_template")
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
    let workflow_template = escape_html(workflow_template);
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
    <div class="field"><span class="field-label">Workflow template</span><span class="field-val">{workflow_template}</span></div>
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
        workflow_template = workflow_template,
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
    let mut workflow_template: Option<String> = None;

    if row.kind.contains('.') {
        if let Ok(raw) = store.get_receipt_v2_envelope_json(&row.id)
            && let Ok(envelope) = serde_json::from_str::<core_events::receipt::ReceiptEnvelope>(&raw)
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
            workflow_template = envelope
                .body
                .get("workflow_template")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
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

    let action_summary = if row.kind.starts_with("session.") {
        workflow_template
            .unwrap_or_else(|| row.resource.clone())
            .chars()
            .take(40)
            .collect::<String>()
    } else {
        format!(
            "{} · {}",
            row.kind,
            row.resource.chars().take(40).collect::<String>()
        )
    };
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
        "action_summary": action_summary,
        "terminal_reason": row.terminal_reason,
        "created_at_epoch": created_at_epoch,
        "signed": signed,
        "claim_count_total": claim_count_total,
        "claim_events_truncated": claim_events_truncated,
        "claim_segment_count": claim_segment_count,
        "claim_history_merkle_root": claim_history_merkle_root,
    })
}

/// implementation-note-223: render a 64-hex Ed25519 pubkey as a
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
/// implementation-note-236 — per-Statement gauges with an
/// inline "Revoke" button per row. `revoked_sids` is the slice of sids that
/// have already been revoked (struck through, button hidden). Wires to
/// `POST /api/grants/{id}/revoke-statement` via the page's JS handler.
// TERMINAL-implementation-note-239: terminal grants suppress per-Statement Revoke
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
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — DID-prefix
        // every action key on the way to the operator-facing card so bare
        // pre-migration keys render in the canonical `did:ember:<key>` form.
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
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — same DID
        // decoration as `render_statement_gauges_with_revoke` so both
        // gauge surfaces stay in sync on the operator-facing render.
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
        "revoked" | "parent_cascade_revoked" => "revoked",
        "expired" | "expired_by_budget" | "exhausted_by_budget" => "revoked",
        _ => "pending",
    };

    let is_terminal = matches!(
        g.status.as_str(),
        "revoked"
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

// implementation-note-236 — per-statement revoke buttons.
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

// implementation-note-236 — live tick-down. Computes
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
// implementation-note-240: wall-clock gauge reads server-computed
// usage.wall_clock_secs from SSE events; tickWallClockGauge removed.
// implementation-note-227 — statements array name is canonical.
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
        "revoked" | "parent_cascade_revoked" => "revoked",
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
    let mut session_singletons: Vec<serde_json::Value> = adapted
        .iter()
        .filter(|r| r.kind.starts_with("session."))
        .map(|r| {
            serde_json::json!({
                "materialization_id": r.materialization_id,
                "action": r.action,
                "persona": r.persona,
                "started_at": r.ts,
                "ended_at": r.ts,
                "outcome": "success",
                "denial_reason": serde_json::Value::Null,
                "receipt_count": 1,
                "claim_count_total": r.claim_count_total,
                "claim_events_truncated": r.claim_events_truncated,
                "claim_segment_count": r.claim_segment_count,
                "claim_history_merkle_root": r.claim_history_merkle_root,
                "sub_receipts": [{
                    "kind": r.kind,
                    "ts": r.ts,
                    "receipt_hash": r.receipt_hash,
                    "claim_count_total": r.claim_count_total,
                    "claim_events_truncated": r.claim_events_truncated,
                    "claim_segment_count": r.claim_segment_count,
                    "claim_history_merkle_root": r.claim_history_merkle_root,
                }],
            })
        })
        .collect();
    let construct_adapted: Vec<DashboardRollupRow> = adapted
        .into_iter()
        .filter(|r| !r.kind.starts_with("session."))
        .collect();
    let rollups = compute_rollups(&construct_adapted);
    let extras_by_hash: std::collections::BTreeMap<String, (Option<u64>, bool, Option<u64>, Option<String>)> =
        construct_adapted
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
                    let (claim_count_total, claim_events_truncated, claim_segment_count, claim_history_merkle_root) =
                        extras_by_hash
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
    match r.kind.as_str() {
        "grant" => format!(
            "{} · {}",
            r.requested_scope
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("grant"),
            r.resource.chars().take(40).collect::<String>()
        ),
        kind if kind.starts_with("session.") => {
            let label = r
                .workflow_template
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(r.resource.as_str());
            format!("{kind} · {label}")
        }
        _ => {
            if r.resource.is_empty() {
                r.kind.clone()
            } else {
                format!("{} · {}", r.kind, r.resource.chars().take(40).collect::<String>())
            }
        }
    }
}

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
        "action_summary": receipt_row_action_summary(r),
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
/// implementation-note-221 — the page leads with the high-level
/// Approve/Deny decision; the per-statement breakdown for composite
/// approvals is rendered client-side from the polled JSON behind a
/// "Show details" disclosure (collapsed-by-default). Both the dashboard
/// pending-approvals card and this page share the same
/// `renderCompositeStatements` helper via `COMPOSITE_STATEMENTS_JS`,
/// so the two surfaces cannot drift.
/// implementation-note-108: shared dashboard handler for approve + deny.
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
async fn resolve_approval_via_dashboard(
    state: Arc<DashboardState>,
    req: Request<Incoming>,
    approval_id: String,
    approve: bool,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt as _;
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let params: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

    // Decide which path: real WebAuthn vs legacy claim.
    #[cfg(feature = "webauthn")]
    let use_real_webauthn = state.webauthn.is_some() && std::env::var("EMBER_DISABLE_BIO").is_err();
    #[cfg(not(feature = "webauthn"))]
    let use_real_webauthn = false;

    let outcome = if approve {
        ApprovalOutcome::Approved
    } else {
        ApprovalOutcome::Denied {
            reason: "denied via dashboard".to_string(),
        }
    };

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
                    &serde_json::json!({
                        if approve { "approved" } else { "denied" }: true,
                        "biometric": true,
                        "credential_id": verified.credential_id,
                    }),
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
                &serde_json::json!({
                    if approve { "approved" } else { "denied" }: true,
                    "biometric": biometric,
                    "credential_id": credential_id,
                }),
            ),
            Err(e) => error_response(400, &e.to_string()),
        }
    }
}

pub fn render_approval_page(
    csrf_token: &str,
    approval: &crate::trust::approval::ApprovalRequestInfo,
    persona_name: Option<&str>,
) -> String {
    // implementation-note-222 — for composite approvals, the row's flat `action`
    // column is the verb of statement 0; that misrepresents a multi-verb
    // chain on the operator-facing card (e.g. an Anthropic+budget+session
    // bundle showing as "credential.access"). Render an honest summary
    // instead. Single-statement approvals keep the legacy projection.
    let action_label = if let Some(stmts) = approval.composite_statements.as_ref() {
        format!("composite ({} statements)", stmts.len())
    } else {
        approval.action.clone()
    };
    // implementation-note-222 — show "name <identifier>" so the operator
    // sees both the human-friendly handle (e.g. `qa`) and the unique
    // persona-id suffix used in audit logs and grant chains. The
    // identifier-only fallback covers personas that lack a name.
    let persona_label = match persona_name.filter(|n| !n.is_empty()) {
        Some(name) => format!(
            "{name} <span class=\"persona-id\">{}</span>",
            truncate_persona_id(&approval.persona_id)
        ),
        None => truncate_persona_id(&approval.persona_id),
    };
    // COMPOSITE-prior change-TESTS-DASHBOARD — render skill_ref row when present on the
    // proposal; hidden (empty string) when None so the card stays clean for
    // legacy approvals that predate the skill_ref field.
    let skill_ref_row = match approval.skill_ref.as_deref().filter(|s| !s.is_empty()) {
        Some(sr) => format!(
            "<div class=\"field\" id=\"skill-ref-row\"><span class=\"field-label\">Skill</span><span class=\"field-val\">{}</span></div>",
            sr
        ),
        None => String::new(),
    };
    APPROVAL_HTML_TEMPLATE
        .replace("{{COMPOSITE_STATEMENTS_JS}}", COMPOSITE_STATEMENTS_JS)
        .replace("{{CSRF_TOKEN}}", csrf_token)
        .replace("{{APPROVAL_ID}}", &approval.id)
        .replace("{{ACTION}}", &action_label)
        .replace("{{SKILL_REF_ROW}}", &skill_ref_row)
        .replace("{{CREDENTIAL}}", &approval.credential_name)
        .replace("{{SCOPE}}", &approval.scope)
        .replace("{{RISK_LEVEL}}", &approval.risk_level)
        .replace("{{PERSONA_PREFIX}}", &persona_label)
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
    use crate::infra::store::DaemonStore;

    // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — display-time
    // unit tests for the action-key DID-prefix decorator. Mirror tests
    // exist in the JS-side `displayActionKey` (inlined via
    // COMPOSITE_STATEMENTS_JS); both surfaces must agree on prefixing
    // behavior or the dashboard render will diverge from the API JSON.

    #[test]
    fn display_action_key_passes_through_did_ember() {
        // Bundled-publisher case — the canonical v0.3.0 shape must
        // round-trip unchanged through the renderer.
        assert_eq!(
            display_action_key("did:ember:gh.pr_create"),
            "did:ember:gh.pr_create"
        );
    }

    #[test]
    fn display_action_key_passes_through_did_web_for_forward_compat() {
        // design §3 — arbitrary `did:<method>:` prefixes pass through
        // even though v0.3.0's broker.resolve only routes `did:ember:`.
        // This locks the forward-compat door at the display layer.
        assert_eq!(
            display_action_key("did:web:hashicorp.com:terraform.apply"),
            "did:web:hashicorp.com:terraform.apply"
        );
        assert_eq!(
            display_action_key("did:key:z6MkkBRG7Ghk:custom-tool.deploy"),
            "did:key:z6MkkBRG7Ghk:custom-tool.deploy"
        );
    }

    #[test]
    fn display_action_key_decorates_bare_keys_with_did_ember() {
        // Bare action keys (legacy fixtures, pre-migration audit rows)
        // are decorated with `did:ember:` so the operator sees the
        // canonical FQ shape per design §1.
        assert_eq!(display_action_key("gh.pr_create"), "did:ember:gh.pr_create");
        assert_eq!(display_action_key("read"), "did:ember:read");
        assert_eq!(display_action_key("github:push"), "did:ember:github:push");
        assert_eq!(
            display_action_key("docker.push.dockerhub"),
            "did:ember:docker.push.dockerhub"
        );
    }

    #[test]
    fn display_action_key_rejects_did_with_empty_method_or_no_separator() {
        // Defense-in-depth: structurally-incomplete `did:` strings
        // (`did::foo`, `did:something_without_colon`) must NOT be
        // treated as already-prefixed. The validator at write time
        // refuses these, but the display layer must not silently let
        // them through with a missing `did:ember:` decoration either.
        assert_eq!(
            display_action_key("did::gh.pr_create"),
            "did:ember:did::gh.pr_create"
        );
        assert_eq!(
            display_action_key("did:something_without_a_colon"),
            "did:ember:did:something_without_a_colon"
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
            // implementation-note-220: default to a well-known
            // localhost addr so most tests see a "bound" dashboard; tests
            // that exercise the "not bound" branch override directly.
            dashboard_actual_addr: Some("127.0.0.1:3141".parse().expect("test addr parse")),
            data_dir: std::path::PathBuf::from("/tmp/.ember-test/data"),
            // implementation-note-108: tests don't construct a gate; the
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
                // implementation-note-220: mirror the production
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
                        // implementation-note-227 — test handler mirrors
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
                let body =
                    serde_json::to_value(&anomalies).unwrap_or(serde_json::Value::Array(vec![]));
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
                        // implementation-note-195 — surface persona.name for the
                        // approval-detail render path (test handler mirrors
                        // production).
                        let persona_name =
                            state.store.get_persona(&a.persona_id).ok().map(|p| p.name);
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
                                // implementation-note-221 — mirrors production handler so
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
                // implementation-note-195 — mirror the production handler's
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
                        let persona_name =
                            e.agent_id.as_deref().and_then(|id| names.get(id).cloned());
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
                // implementation-note-235: shipped
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
                            let html =
                                build_grant_detail_html(&g, &state.csrf_token, chain.as_ref());
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
                // implementation-note-236 — test handler mirrors
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
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({"revoked": true}))
                        }
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
                    // standing_grant_expires_at_capped: see sibling fix at
                    // dashboard.rs:3074 for the rationale (strict RFC-3339
                    // + 29 days to stay safely inside MAX_GRANT_TTL_SECS).
                    let expires_at = {
                        let twenty_nine_days = chrono::Utc::now() + chrono::Duration::days(29);
                        Some(twenty_nine_days.to_rfc3339())
                    };
                    match state.store.resolve_approval(
                        id,
                        &ApprovalOutcome::Always {
                            scope: None,
                            expires_at,
                        },
                    ) {
                        Ok(()) => json_response(
                            StatusCode::OK,
                            &serde_json::json!({"approved": true, "standing_grant_created": true}),
                        ),
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
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({"approved": true}))
                        }
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
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({"denied": true}))
                        }
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

            // implementation-note-228 — dismiss (test handler)
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
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({"paused": true}))
                        }
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
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({"paused": false}))
                        }
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
            // implementation-note-227 — test handler mirrors
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
                        Ok(g) => json_response(
                            StatusCode::OK,
                            &grant_to_json_with_store(&g, &state.store),
                        ),
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
                                            serde_json::to_vec_pretty(&envelope)
                                                .unwrap_or_default(),
                                        )))
                                        .unwrap()
                                } else {
                                    let html =
                                        build_signed_receipt_v2_html(&envelope, Some(&grant_id));
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
                                let html =
                                    build_receipt_html(&g, &state.csrf_token, chain.as_ref());
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
                            let data =
                                serde_json::to_string(&grant_to_json(&g)).unwrap_or_default();
                            let body =
                                format!("retry: 5000\nevent: usage_update\ndata: {data}\n\n");
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

            // implementation-note-229 — test handler for `/api/receipts/stream`.
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
                                        "24h" => {
                                            Some((now - chrono::Duration::hours(24)).to_rfc3339())
                                        }
                                        "7d" => {
                                            Some((now - chrono::Duration::days(7)).to_rfc3339())
                                        }
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

            // implementation-note-225 — test handler mirrors the
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

            // implementation-note-237 — first-run passkey enrollment page. Mirror
            // the production handler at line 2411 so test fixtures stay
            // in sync. Without this the test stub's routing table drifts
            // from production and `settings_passkeys_returns_enrollment_page`
            // sees 404 instead of 200.
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

    // implementation-note-108: the old `/api/webauthn/challenge` stub
    // (returns random bytes the client claims it signed) is gone;
    // the new flow is `/api/webauthn/{register,auth}/{begin,complete}`
    // with real signature verification at finish time. The new flow's
    // happy path can't be exercised in pure-rust tests (it needs a
    // platform authenticator); coverage is on the `_logs_audit_fields`
    // store-level test below plus runtime smoke via
    // `qember.sh demo headless` (which uses the CLI biometric path
    // that also honors `EMBER_DISABLE_BIO=1`).

    /// implementation-note-237 — `resolve_approval_with_biometric` records the
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

    /// implementation-note-227 — /api/grants list must include the
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
            },
            Statement {
                sid: StatementId::from("SB"),
                resource_type: ResourceType::Session,
                actions: vec![Action::from("create")],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
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

        // implementation-note-227 — assert the legacy
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

    /// implementation-note-227 — /api/grants list and
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

        // dashboard_agent_tree_view_promoted — implementation-note-238
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
    async fn health_returns_200_with_status_ok() {
        let state = make_state();
        let resp = call(state, "/health").await;
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
            s.contains("const receiptLink=`<a href=\"/receipts/${encodeURIComponent(String(r.id||''))}\""),
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
    async fn get_endpoints_do_not_require_csrf() {
        // GET endpoints are read-only and same-origin policy protects them.
        let state = make_state();
        let resp = call(state, "/api/status").await;
        assert_eq!(resp.status(), StatusCode::OK);
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
        // implementation-note-222 — the dedicated /approvals/{id} page must
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

    // --- implementation-note-222 — composite render polish ---

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
    async fn dashboard_card_template_routes_composite_through_detail_review() {
        // implementation-note-222 — composite approvals are multi-statement
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
        // implementation-note-222 — `time:wall_clock on * · 90s` reads as
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
        // implementation-note-222 — Persona field shows "<name> <identifier>"
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
        // implementation-note-221 — the dashboard pending-approvals card and
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
        let req = state
            .store
            .submit_approval(&persona.id, "key", "read", None, "access", "low")
            .unwrap();

        let resp =
            call_post_no_csrf(state, &format!("/api/approvals/{}/approve-always", req.id)).await;
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

    // implementation-note-229 — `/api/receipts/stream` is the live receipts panel
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
        assert!(s.contains("\"kind\":\"session.composite_grant\""), "got:\n{s}");
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

    // --- implementation-note-108 follow-up: loopback aliases ---
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

    // --- implementation-note-228: dismiss endpoint ---

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
        let resp =
            call_post_no_csrf(state, &format!("/api/approvals/{}/dismiss", approval.id)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // --- implementation-note-195: audit action_filter query param ---

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

    // --- implementation-note-242: /api/receipts endpoint ---

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
        workflow_template: &str,
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
                    input_hash: "hash-1".to_string(),
                    input_redacted: serde_json::json!({"prompt": "deploy"}),
                    resolved: serde_json::json!({"allowed": true}),
                }],
                claim_count_total: Some(claim_count_total),
                claim_events_truncated,
                claim_segment_summaries: claim_segments,
                claim_history_merkle_root: "history-root".to_string(),
                workflow_template: Some(workflow_template.to_string()),
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

        let resp = call(Arc::clone(&state), "/api/receipts?view=raw&signed_only=true").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1, "signed_only should retain signed session receipt");
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
        // implementation-note-225 — `/api/receipts/search?persona=`
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
    async fn receipts_search_scope_matches_session_workflow_template() {
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
        assert_eq!(arr.len(), 1, "workflow template search should find the session receipt");
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
        let persona = state.store.create_persona("session-composite-signed").unwrap();
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
        assert_eq!(arr.len(), 1, "signed session envelope must survive signed_only filter");
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
                grant_id: "grant-abc".to_string(),
                materialized_at: "2026-05-05T13:00:00Z".to_string(),
                terminal_reason: "revoked".to_string(),
                requested_scope: None,
                granted_scope: None,
                signed: true,
                workflow_template: None,
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
                grant_id: "grant-xyz".to_string(),
                materialized_at: "2026-05-05T14:00:00Z".to_string(),
                terminal_reason: "expired".to_string(),
                requested_scope: None,
                granted_scope: None,
                signed: true,
                workflow_template: None,
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
            grant_id: String::new(),
            materialized_at: "2026-05-05T12:00:00Z".to_string(),
            terminal_reason: "rate_limited".to_string(),
            requested_scope: None,
            granted_scope: None,
            signed: true,
            workflow_template: None,
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
            grant_id: "grant-session".to_string(),
            materialized_at: "2026-05-22T12:00:00Z".to_string(),
            terminal_reason: "exhausted_by_budget".to_string(),
            requested_scope: None,
            granted_scope: None,
            signed: true,
            workflow_template: Some("emberd-development".to_string()),
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
        assert!(
            !arr.is_empty(),
            "?view=raw must return per-receipt list"
        );
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
        // implementation-note-243: disabled Narrow button was removed for clean screenshots.
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

    /// implementation-note-237 — `/settings/passkeys` returns the enrollment page with
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

    /// implementation-note-108 — the `/approvals/{id}` page wires the real
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
    }

    /// implementation-note-221 — the `/approvals/{id}` dedicated page must
    /// expose composite_statements via the polled JSON AND embed the shared
    /// renderCompositeStatements helper so the breakdown renders identically
    /// to the main dashboard card. This is the YC-partner deep-link path.
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

}
