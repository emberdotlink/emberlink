/// Shared JS that renders a composite-statement breakdown into HTML — used
/// by both the dashboard pending-approvals card and the dedicated
/// `/approvals/{id}` page so the two surfaces can never drift. Injected
/// into both templates via `{{COMPOSITE_STATEMENTS_JS}}`. The function name
/// `render_composite_statements` (and the rendered class `composite-statements`)
/// are the target_state_anchor markers — search for
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
// escapeHtml — module-scope HTML-entity escaper for agent-controlled values
// that land in dashboard/approval innerHTML. COMPOSITE_STATEMENTS_JS is
// spliced at the top of both the dashboard and approval scripts, so every
// render helper below (and in DASHBOARD_HTML) can rely on this being in
// scope. Mirrors the escaper on the passkeys settings page. NEVER interpolate
// agent-controlled strings (persona/credential names, descriptions, scopes,
// action keys, resource selectors, anomaly fields) into innerHTML without it.
function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
// displayActionKey mirrors the Rust-side `display_action_key` helper.
// Generic grant-statement action strings render as-is; structured construct
// identity renders through `displayActionRef`. Output is HTML-escaped because
// callers embed it directly into innerHTML.
function displayActionKey(a){
  if(typeof a !== 'string' || a.length === 0) return a;
  return escapeHtml(a);
}
function displayActionRef(ref, fallback){
  if(ref && typeof ref === 'object' && ref.plugin_address && ref.action_key && ref.action_version){
    return ref.plugin_address + '/' + ref.action_key + '@' + ref.action_version;
  }
  return fallback || '—';
}
function renderCompositeStatements(stmts){
  if(!Array.isArray(stmts) || stmts.length===0) return '';
  const rows = stmts.map(function(s,i){
    const actions = (s.actions||[]).map(displayActionKey).join(',');
    const resource = renderResourceSelector(s.resource);
    // DEMO-MAY3-POLISH-3 — `time:wall_clock on * · 90s` reads as
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
    if (r.kind === 'exact') return escapeHtml(r.value || '*');
    if (r.kind === 'glob') return escapeHtml(r.pattern || '*');
    return '*';
  }
  // Legacy: serde externally-tagged enum.
  if ('Exact' in r) return escapeHtml((r.Exact && r.Exact.value) || '*');
  if ('Glob' in r) return escapeHtml((r.Glob && r.Glob.pattern) || '*');
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
/* DEMO-MAY3-IDENTITY-ANCHOR: ambient daemon-identity strip in the
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
/* DEMO-MAY3-POLISH-3 — hover preview of the composite breakdown
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
.badge.abandoned{background:rgba(239,68,68,.12);color:var(--danger)}
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

  <!-- BEAT-7-SCION-2026-05-15 — per-agent panel grouped by persona_id so an
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
        <!-- ARCH-DASHBOARD-WEDGE-SURFACES-1 — persona/scope/date filters -->
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

  <div class="section" id="autopilot-section">
    <div class="section-header">
      <span class="section-title">Autopilot</span>
      <span class="refresh-ts" id="autopilot-ts">polling every 2s</span>
    </div>
    <div id="autopilot-body"><div class="empty">not running</div></div>
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
    <!-- ARCH-DASHBOARD-WEDGE-SURFACES-2 — cross-receipt search panel.
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
// DEMO-MAY3-POLISH — relative_time / formatRelative: render audit + grant
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
function truncPersona(s){if(!s)return'—';const p='persona-';if(s.startsWith(p)){return escapeHtml(p+s.slice(p.length,p.length+12));}return escapeHtml(trunc(s,20));}
// DEMO-MAY3-POLISH — persona.name primary label; raw persona_id moves to
// the tooltip so screenshots show real names instead of UUID prefixes.
// Falls back to truncPersona when no name was returned by the API.
function personaLabel(id, name){
  if(name && name.length){
    return '<span title="'+escapeHtml(id||'')+'">'+escapeHtml(name)+'</span>';
  }
  return truncPersona(id);
}
function badge(cls,text){return`<span class="badge ${escapeHtml(cls)}">${escapeHtml(text)}</span>`;}
function grantStatusClass(s){if(s==='active')return'active';if(s==='expired')return'expired';if(s==='revoked'||s==='abandoned')return'revoked';if(s==='exhausted_by_budget'||s==='expired_by_budget')return'exhausted';return '';}

// DEMO-MAY3-POLISH-3 — humanize audit-event labels for the timeline
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
  // Known events map to fixed copy; unknown events fall through escaped
  // because the raw action string is agent-controlled and rendered as HTML.
  return AUDIT_EVENT_LABELS[action] || escapeHtml(action);
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

// DEMO-MAY3-POLISH — pick the most demo-meaningful budget axis from a
// composite grant's statements array (cents > tokens > wall_clock_secs).
// Returns a gauge-wrap div, or '<span …>none</span>' when no statement has
// a budget cap set.
function compositeGrantBudgetGauge(stmts) {
  if(!Array.isArray(stmts) || stmts.length===0) return '<span style="color:var(--text-dim);font-size:11px">—</span>';
  // DEMO-MAY3-POLISH-2 — build a compact per-statement budget summary so
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
// DEMO-MAY3-POLISH-2: shipped
// DEMO-MAY3-POLISH-2 — scope cell for the Active Grants table. Composite
// grants show "N statements · action1, action2, action3" so the operator
// sees real scope instead of '*'. Single-statement grants show flat scope.
function grantScopeText(g) {
  const stmts = Array.isArray(g.statements) ? g.statements : null;
  if(stmts && stmts.length>0) {
    // Composite statement summaries render generic action strings as stored.
    const names = stmts.map(function(s){ return (s.actions||[]).map(displayActionKey).join('/'); }).join(', ');
    // names is already escaped via displayActionKey; the count prefix is numeric.
    return stmts.length+' statement'+(stmts.length===1?'':'s')+' · '+names;
  }
  return escapeHtml(g.scope||'—');
}
function renderBudgetGauge(g) {
  // ARCH-DASHBOARD-API-FIELD-PARITY — composite grants surface their real
  // budget via the canonical `statements` array (same name across all three
  // /api/grants* endpoints). Delegate to the composite helper when present.
  const stmts = Array.isArray(g.statements) ? g.statements : null;
  if(stmts && stmts.length>0) {
    let html = compositeGrantBudgetGauge(stmts);
    // DEMO-MAY3-POLISH-3 — only show the budget-cell banner for soft
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
  const terminal = ['revoked','abandoned','expired','expired_by_budget','parent_cascade_revoked'].includes(g.status);
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
// DEMO-MAY3-BIO-REAL: WebAuthn ceremony — auth/begin → navigator.credentials.get()
// → POST /api/approvals/<id>/<action> with the verified assertion.
//
// The daemon mints a challenge bound to the specific approval_id at
// auth/begin; the assertion that comes back from the platform
// authenticator is verified server-side against the persona's
// enrolled passkey before the approval state flips. Approve Always
// uses this same path before creating a standing grant. There is no
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
  if(await approveOrDeny(id, 'approve-always')) loadDashboard();
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
// DEMO-MAY3-STALE-APPROVAL-CLEANUP — dismiss a pending approval card.
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
        <span class="pattern">${escapeHtml(c.pattern||c.action||'—')}</span>
        <span class="freq-badge">${c.frequency}×</span>
        <span class="last-seen">${escapeHtml(c.last_seen||'')}</span>
        <button onclick="navigator.clipboard.writeText('ember construct scaffold --from-pattern '+${escapeHtml(JSON.stringify(c.action||''))})">Scaffold</button>
      </div>
    `).join('');
  }catch(e){
    document.getElementById('maturation-body').innerHTML='<div class="empty">Maturation data unavailable</div>';
  }
}
let _autopilotInterval = null;
async function pollAutopilot() {
  try {
    const r = await fetch('/api/autopilot/snapshot');
    if (!r.ok) throw new Error('http error');
    const snap = await r.json();
    const body = document.getElementById('autopilot-body');
    if (!snap || snap.running === false) {
      body.innerHTML = '<div class="empty">autopilot not running</div>';
      return;
    }
    const inflight = (snap.inflight || []).slice(0, 4).map(w => `
      <div class="row">
        <span class="worker-id">${escapeHtml((w.agent_id || w.worker_id || '').slice(0, 8))}</span>
        <span class="task-id">${escapeHtml(w.task_id || '')}</span>
        <span class="elapsed">${w.elapsed_seconds || w.elapsed_s || 0}s</span>
      </div>
    `).join('');
    const queue = (snap.queue_head || []).slice(0, 3).map(p => `<span class="queue-pick">${escapeHtml(p.id || p)}</span>`).join(' · ');
    const events = (snap.last_events || []).slice(0, 3).map(e => `<div class="event-row">${escapeHtml(e.event || JSON.stringify(e).slice(0, 80))}</div>`).join('');
    body.innerHTML = `<div class="inflight">${inflight || '<div class="empty">no workers</div>'}</div><div class="queue-head">${queue}</div><div class="events">${events}</div>`;
  } catch (e) {
    document.getElementById('autopilot-body').innerHTML = '<div class="empty">snapshot unavailable</div>';
  }
}
function startAutopilotPolling() {
  if (_autopilotInterval) return;
  pollAutopilot();
  _autopilotInterval = setInterval(pollAutopilot, 2000);
}
function stopAutopilotPolling() {
  if (_autopilotInterval) { clearInterval(_autopilotInterval); _autopilotInterval = null; }
}
document.addEventListener('visibilitychange', () => { document.hidden ? stopAutopilotPolling() : startAutopilotPolling(); });
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
    // DEMO-MAY3-POLISH — operator audit hides internal lifecycle events
    // (vault.auto_unseal_from_keyring + *.internal.*) by default; toggle
    // surfaces them via ?include_internal=1. Action filter dropdown narrows
    // to one family (grant.*, approval.*, broker.*, etc.) via ?action_filter=.
    const showInternal=document.getElementById('show-internal-events')?.checked;
    const actionFilter=document.getElementById('audit-action-filter')?.value||'';
    // ARCH-DASHBOARD-WEDGE-SURFACES-1 — persona/scope/since query params.
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
      alist.innerHTML=anomalies.map(a=>`<div class="anomaly-card ${escapeHtml(a.severity)}">
        <div class="anm-meta">
          <div class="anm-agent">${escapeHtml(a.agent_id||'unknown')}</div>
          <div class="anm-desc">${escapeHtml(a.description||'—')}</div>
          <div class="anm-ts">${relTime(a.detected_at)}</div>
        </div>
        <span class="anm-type">${escapeHtml((a.anomaly_type||'').replace(/_/g,' '))}</span>
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
    // DEMO-MAY3-POLISH-3 — surface pending count in the browser tab
    // title so a YC viewer scanning the take notices the counter
    // tick. Reverts to bare "ember" when nothing's awaiting.
    document.title = pending > 0 ? `ember · ${pending} pending` : 'ember';

    // BEAT-7-SCION-2026-05-15 — per-agent tiles. Group active grants by
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
          const credLinks=a.grants.map(g=>`<a href="/grants/${g.id}" style="color:var(--text-primary);text-decoration:none;font-size:11px;display:inline-block;padding:2px 8px;background:var(--bg-hover);border:1px solid var(--border);border-radius:4px;margin:2px" title="Open grant detail to revoke individual statements">${escapeHtml(g.credential_name||'—')}</a>`).join('');
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
        <td>${escapeHtml(g.credential_name||'—')}</td>
        <td>${grantScopeText(g)}</td>
        <td class="gauge-cell">${renderBudgetGauge(g)}</td>
        <td class="ts">${g.expires_at?relTime(g.expires_at):'never'}</td>
        <td class="status-cell">${badge(g.status,g.status)}</td>
        <td>${renderGrantActions(g)}</td>
      </tr>`).join('');
      // Connect SSE for active grants with budgets (simple or composite).
      // DEMO-MAY3-POLISH — also wire composite grants whose statements carry
      // a budget so the gauge ticks up in real time during the demo.
      // ARCH-DASHBOARD-API-FIELD-PARITY — read `statements` (canonical name).
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
        // DEMO-MAY3-COMPOSITE-PAGE — composite breakdown moved to the
        // dedicated /approvals/{id} page (behind a Show details disclosure).
        // Cards now render a one-line summary + link so the dashboard stays
        // glanceable for the demo. Single-statement approvals keep the
        // legacy per-field row layout.
        const stmts = Array.isArray(a.composite_statements) ? a.composite_statements : null;
        // DEMO-MAY3-POLISH-3 — composite scope cell surfaces a hover
        // preview of the inline breakdown so the operator can see what
        // they would be approving without navigating to the detail page.
        // The preview reuses renderCompositeStatements so the dashboard
        // card and detail page never drift in how they render statements.
        const scope_block = stmts ? `
        <div class="row"><span class="field">Scope</span><span class="scope-hover"><a class="field-val approval-link" href="/approvals/${a.id}" tabindex="0">${compositeSummary(stmts)}</a><span class="scope-preview">${renderCompositeStatements(stmts)}</span></span></div>` : `
        <div class="row"><span class="field">Credential</span><span class="field-val">${escapeHtml(a.credential_name||'—')}</span></div>
        <div class="row"><span class="field">Scope</span><a class="field-val approval-link" href="/approvals/${a.id}">${escapeHtml(a.scope||'—')}</a></div>`;
        // DEMO-MAY3-POLISH-3 — for composites the row's flat `action` is
        // statement 0's verb, which misrepresents a multi-verb chain.
        // Surface "composite (N statements)" instead so the card matches
        // the detail page and what the storyboard voiceover claims.
        const action_label = stmts ? `composite (${stmts.length} statements)` : escapeHtml(a.action||'—');
        // DEMO-MAY3-POLISH-3 — composite approvals are multi-statement
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
        <span title="${escapeHtml(e.action||'')}">${humanizeEvent(e.action)}</span>
        <span>${escapeHtml(e.credential||'—')}</span>
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
  const kindBadge=`<span class="badge" style="margin-right:6px;font-size:10px;background:rgba(232,93,38,.12);border:1px solid rgba(232,93,38,.28);color:#ff9468">${escapeHtml(r.kind||'receipt')}</span>`;
  const receiptLink=`<a href="/receipts/${encodeURIComponent(String(r.id||''))}" style="color:var(--text-muted);text-decoration:none">${escapeHtml(r.action_summary||'—')}</a>`;
  const claimSummary=_claimSummary(r);
  const ts=r.created_at?relTime(r.created_at):(r.created_at_epoch?relTime(new Date(r.created_at_epoch*1000).toISOString()):'—');
  const reason=_receiptReasonLabel(r.terminal_reason).slice(0,32)||'—';
  return`<tr>
    <td class="ts">${ts}</td>
    <td>${grantLink}</td>
    <td class="mono">${personaLabel(r.persona_id,r.persona_name)}</td>
    <td style="color:var(--text-muted);font-size:11px">${kindBadge}${receiptLink}${claimSummary?`<div style="font-size:10px;color:var(--text-dim);margin-top:2px">${escapeHtml(claimSummary)}</div>`:''}</td>
    <td style="color:var(--text-dim);font-size:11px">${escapeHtml(reason)}</td>
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
      rb.innerHTML='<tr><td colspan="6" class="empty">No receipts yet — terminal authority events emit signed receipts here.</td></tr>';
      return;
    }
    if(_receiptsViewMode==='rollup'){
      // Rollup view: one row per materialization_id with inline denial reason.
      // Click a row to expand/collapse the sub-receipt detail.
      rb.innerHTML=data.map(r=>{
        const mid=r.materialization_id||'—';
        const midShort=mid.length>20?mid.slice(0,18)+'…':mid;
        const ts=r.started_at?relTime(r.started_at):'—';
        const persona=escapeHtml(r.persona||'—');
        const action=escapeHtml(displayActionRef(r.action_ref, r.action).slice(0,32));
        const claimSummary=_claimSummary(r);
        const actionHtml=claimSummary
          ?`${action}<div style="color:var(--text-dim);font-size:10px;margin-top:2px">${claimSummary}</div>`
          :action;
        const outcomeStyle=_rollupOutcomeStyle(r.outcome||'');
        // Inline denial reason — no click-through required for primary scan.
        const outcomeLabel=r.denial_reason
          ?`<span style="${outcomeStyle}">${escapeHtml(r.outcome)}</span> <span style="color:var(--text-dim);font-size:10px" title="${escapeHtml(r.denial_reason)}">(${escapeHtml((r.denial_reason||'').slice(0,24))})</span>`
          :`<span style="${outcomeStyle}">${escapeHtml(r.outcome||'—')}</span>`;
        const count=r.receipt_count||0;
        const subHtml=(r.sub_receipts||[]).map(s=>{
          const subClaimSummary=_claimSummary(s);
          const subClaimHtml=subClaimSummary?` <span style="color:var(--text-dim)">· ${subClaimSummary}</span>`:'';
          return`<span style="display:block;font-size:10px;color:var(--text-muted);padding:1px 0">${escapeHtml(s.kind)}${subClaimHtml} <span style="color:var(--text-dim)">${escapeHtml((s.ts||'').slice(0,19))}</span> <a href="/receipts/${encodeURIComponent(String(s.receipt_hash||''))}" class="mono" style="font-size:9px;color:var(--text-primary);text-decoration:none">${escapeHtml((s.receipt_hash||'').slice(0,16))}</a></span>`;
        }).join('');
        // `mid` lands in three contexts: an HTML id attribute, a JS-string
        // argument inside an onclick attribute, and visible text. escapeHtml
        // covers the attribute/text layers; for the JS-string-in-attribute the
        // robust encoding is escapeHtml(JSON.stringify(...)) — JSON makes a
        // valid JS literal, escapeHtml neutralizes the HTML-attribute layer.
        // getElementById in the handler reconstructs `rollup-detail-`+mid from
        // the decoded raw value, which matches the (HTML-decoded) id attribute.
        const detailRow=`<tr id="rollup-detail-${escapeHtml(mid)}" style="display:none"><td colspan="6" style="padding:4px 12px;background:var(--bg-hover)">${subHtml||'<span style="color:var(--text-dim);font-size:11px">no sub-receipts</span>'}</td></tr>`;
        const mainRow=`<tr style="cursor:pointer" onclick="_toggleRollupDetail(${escapeHtml(JSON.stringify(mid))})" title="Click to expand sub-receipt detail">
          <td class="ts">${ts}</td>
          <td class="mono" style="font-size:11px" title="${escapeHtml(mid)}">${escapeHtml(midShort)}</td>
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
// ARCH-DASHBOARD-WEDGE-SURFACES-2 — cross-receipt search. When any input
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
startAutopilotPolling();
// DEMO-MAY3-IDENTITY-ANCHOR — fetch the daemon's Ed25519 identity once
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
// DEMO-MAY3-LLM-PROXY-WIRE-UP — FINDING C: drop the dashboard refresh
// cadence from 5s to 2s so the cents-gauge ticks visibly during Beat 4
// of the WEDGE storyboard (where the agent burns through the budget
// call-by-call). SSE handles instantaneous warning/exhaust transitions;
// this interval governs the running-total visualisation between SSE
// events. 2s is the recording-quality floor — shorter would hammer
// /api/grants without visible benefit.
setInterval(loadDashboard,2000);
setInterval(loadReceipts,15000);

// DEMO-RECEIPTS — live receipts panel: stream new receipt rows from
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
/* DEMO-MAY3-POLISH-3 — author-defined `display:flex` overrides the
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
  <!-- DEMO-MAY3-POLISH-3 — composite breakdown is the scope. Always
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
  // DEMO-MAY3-POLISH-3 — composite breakdown is the scope. Show it
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
// DEMO-MAY3-BIO-REAL: dedicated approval page — same auth/begin →
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
    const needsBio = action === 'approve' || action === 'deny' || action === 'approve-always';
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

/// First-run passkey enrollment page at `/settings/passkeys`.
///
/// Guides the operator through registering their platform authenticator
/// (Touch ID on macOS, Windows Hello on Windows). Calls
/// `/api/webauthn/register/begin` → `navigator.credentials.create()` →
/// `/api/webauthn/register/complete` so the credential's COSE pubkey is
/// persisted server-side in the daemon's `webauthn_credentials` table.
/// Subsequent dashboard approvals can verify a signed assertion against
/// that pubkey — there is no localStorage in the trust path.
pub(super) const PASSKEYS_SETTINGS_HTML: &str = r#"<!DOCTYPE html>
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
