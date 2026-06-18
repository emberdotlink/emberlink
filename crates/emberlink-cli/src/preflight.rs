//! CLASSIFICATION: PUBLIC
//! P10-S3 — `ember preflight` authority coverage surface.
//!
//! Answers the before-launch question for the interactive `ember claude` /
//! `ember codex` lane: for each action the agent might take, is it already
//! `covered`, will it `prompt`, will it `deny`, or is a prerequisite `missing`?
//!
//! The daemon (authority root) owns the verdict. This module only enumerates
//! the static catalog action set (no authority decision) and renders the
//! daemon's result. It is the interactive sibling of `ember headless preflight`.

use std::io::IsTerminal;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// CLI arguments for `ember preflight`.
#[derive(Debug, Clone, Default)]
pub struct PreflightArgs {
    /// Service name or plugin address to scope the check. `None` = all
    /// installed bundled services.
    pub service: Option<String>,
    /// Persona to evaluate against. `None` = all active grants (dev0).
    pub persona: Option<String>,
    /// Preview the strict lane (out-of-scope actions deny instead of prompting).
    pub strict: bool,
    /// Preview the unattended/headless lane (cannot prompt).
    pub headless: bool,
    /// Emit JSON instead of the human-readable table.
    pub json: bool,
}

/// One coverage row, mirroring the daemon's `preflight_authority_coverage`
/// result shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightRow {
    pub service: String,
    #[serde(default)]
    pub action_ref: Option<String>,
    pub status: String,
    pub reason: String,
    #[serde(default)]
    pub material_summary: Option<String>,
    #[serde(default)]
    pub next_action: Option<String>,
    #[serde(default)]
    pub access_resolution_plan: Option<Value>,
}

#[derive(Debug)]
pub enum PreflightCliError {
    ServiceNotFound(String),
    NoServices,
    Daemon(String),
    Protocol(String),
    /// Invalid planner input (bad posture, ambient + --save, …). Rendered
    /// verbatim — it is operator-facing guidance, not a decode failure.
    Invalid(String),
}

impl std::fmt::Display for PreflightCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightCliError::ServiceNotFound(q) => write!(f, "service not found: {q}"),
            PreflightCliError::NoServices => write!(f, "no bundled services installed"),
            PreflightCliError::Daemon(m) => write!(f, "{m}"),
            PreflightCliError::Protocol(m) => write!(f, "decode preflight result: {m}"),
            PreflightCliError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for PreflightCliError {}

/// Resolve a friendly service query to a bundled service. Accepts the exact
/// `plugin_address`/`name` (`catalog::find_service`), the wrapped binary
/// (`gh` → `ember-gh`), or the bare name without the `ember-` prefix.
fn resolve_service(query: &str) -> Option<crate::catalog::BundledService> {
    if let Some(service) = crate::catalog::find_service(query) {
        return Some(service);
    }
    let prefixed = format!("ember-{query}");
    crate::catalog::bundled_services()
        .into_iter()
        .find(|s| s.name == prefixed || s.wraps_binary.as_deref() == Some(query))
}

/// Build the normalized planned-action set from the catalog projection for the
/// requested service(s). Static manifest facts only — no authority decision.
fn build_planned_actions(service_filter: Option<&str>) -> Result<Vec<Value>, PreflightCliError> {
    let services = match service_filter {
        Some(q) => vec![
            resolve_service(q).ok_or_else(|| PreflightCliError::ServiceNotFound(q.to_string()))?,
        ],
        None => crate::catalog::bundled_services(),
    };
    if services.is_empty() {
        return Err(PreflightCliError::NoServices);
    }

    let mut planned: Vec<Value> = Vec::new();
    for service in &services {
        project_service_actions(service, &[], &mut planned);
    }
    Ok(planned)
}

/// Project one service's actions into the normalized planned-action JSON the
/// daemon's `preflight_authority_coverage` consumes. When `action_filter` is
/// non-empty only actions whose key or structured ref matches an entry are
/// included. Static manifest facts only — no authority decision.
fn project_service_actions(
    service: &crate::catalog::BundledService,
    action_filter: &[String],
    out: &mut Vec<Value>,
) {
    let authority_refs: Vec<&str> = service.all_authority_refs();
    for action in &service.actions {
        let action_ref = service.action_ref_for(action).map(|r| r.to_string());
        if !action_filter.is_empty() {
            let matches = action_filter
                .iter()
                .any(|f| f == &action.key || action_ref.as_deref().is_some_and(|r| r.ends_with(f)));
            if !matches {
                continue;
            }
        }
        out.push(json!({
            "service": service.name,
            "action_ref": action_ref,
            "plugin_address": service.plugin_address,
            "default_policy": action.default_policy,
            "authority_refs": authority_refs,
        }));
    }
}

/// Build the planned-action set for an explicit list of services (the
/// `ember catalog plan --service ...` form), optionally filtered to specific
/// action keys/refs. Errors if any named service is unknown.
fn build_planned_actions_for_services(
    services: &[String],
    action_filter: &[String],
) -> Result<Vec<Value>, PreflightCliError> {
    if services.is_empty() {
        return Err(PreflightCliError::NoServices);
    }
    let mut planned: Vec<Value> = Vec::new();
    for query in services {
        let service = resolve_service(query)
            .ok_or_else(|| PreflightCliError::ServiceNotFound(query.clone()))?;
        project_service_actions(&service, action_filter, &mut planned);
    }
    Ok(planned)
}

/// The friendly planning postures locked by ADR 194 §4. Each maps onto a point
/// in the `jit|strict` × `ambient|delegated` matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanPosture {
    /// `jit + ambient` — no standing delegated authority; prompt when needed.
    Ambient,
    /// `jit + delegated` — attach a delegated envelope, JIT fallback on misses.
    Elastic,
    /// `strict + delegated` — attach a delegated envelope, fail closed on misses.
    Bounded,
}

impl PlanPosture {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ambient" => Some(Self::Ambient),
            "elastic" => Some(Self::Elastic),
            "bounded" => Some(Self::Bounded),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::Elastic => "elastic",
            Self::Bounded => "bounded",
        }
    }

    /// The underlying posture-matrix point this friendly choice maps to.
    fn underlying(self) -> &'static str {
        match self {
            Self::Ambient => "jit + ambient",
            Self::Elastic => "jit + delegated",
            Self::Bounded => "strict + delegated",
        }
    }

    /// Delegated postures attach an envelope, so the planner passes the plan's
    /// proposed scope inline for lane-effective (parent ∩ scope) coverage.
    fn is_delegated(self) -> bool {
        matches!(self, Self::Elastic | Self::Bounded)
    }

    /// Strict postures deny out-of-scope actions instead of prompting.
    fn is_strict(self) -> bool {
        matches!(self, Self::Bounded)
    }

    /// Posture-derived default TTL ceiling for a saved artifact (ADR 194 §9).
    /// TTL is not one of the four planning dimensions, so it falls out of the
    /// posture's operational intent rather than being a separate input: a
    /// fail-closed `bounded` lane gets a firmer ceiling than a forgiving
    /// `elastic` working session. `ambient` has no delegated envelope to save.
    /// Magnitudes match the bundled templates (`emberd-development` 4h,
    /// `read-only` 8h).
    fn default_ttl(self) -> Option<&'static str> {
        match self {
            Self::Ambient => None,
            Self::Elastic => Some("8h"),
            Self::Bounded => Some("4h"),
        }
    }

    /// One-line answer to the QC question "what happens if it needs more?".
    fn fallback_summary(self) -> &'static str {
        match self {
            Self::Ambient => "out-of-scope actions prompt for approval at first use",
            Self::Elastic => "out-of-scope actions fall back to a JIT approval prompt",
            Self::Bounded => "out-of-scope actions fail closed (deny) — no prompt",
        }
    }
}

/// CLI arguments for `ember catalog plan` (ADR 194).
#[derive(Debug, Clone, Default)]
pub struct PlanArgs {
    /// One or more services by buyer-facing identity (name or plugin address).
    pub services: Vec<String>,
    /// Restrict the plan to specific action keys/refs. Empty = every action.
    pub actions: Vec<String>,
    /// Planner posture: `ambient` | `elastic` | `bounded`.
    pub posture: String,
    /// Persona to evaluate against. `None` = all active grants (dev0).
    pub persona: Option<String>,
    /// Save the plan as a reusable delegated artifact under this name (ADR 194
    /// §5 output 3). Only valid for delegated postures (`elastic`/`bounded`).
    pub save: Option<String>,
    /// Advanced TTL override for `--save` (e.g. `4h`). Defaults to a
    /// posture-derived ceiling when omitted.
    pub ttl: Option<String>,
    /// Emit JSON instead of the human-readable preview.
    pub json: bool,
}

/// `ember catalog plan` — the service-first delegation planning preview (ADR
/// 194). Composes service/action/material/posture and renders the lane-effective
/// authority answer by reusing the daemon's `preflight_authority_coverage`
/// evaluator (P10-S3). Preview-first: never mutates authority.
pub fn cmd_catalog_plan(socket_path: &Path, args: PlanArgs) -> Result<(), PreflightCliError> {
    let posture = PlanPosture::parse(&args.posture).ok_or_else(|| {
        PreflightCliError::Invalid(format!(
            "unknown posture '{}': expected ambient | elastic | bounded",
            args.posture
        ))
    })?;

    // Saving an artifact only makes sense for a delegated posture — the saved
    // artifact IS the delegated envelope, and ambient has none. Reject before
    // touching the daemon so the operator gets a fast, clear error.
    if args.save.is_some() && !posture.is_delegated() {
        return Err(PreflightCliError::Invalid(format!(
            "--save needs a delegated posture (the saved artifact is the delegated envelope); \
             the '{}' posture has none — choose --posture elastic or --posture bounded",
            posture.label()
        )));
    }

    let planned = build_planned_actions_for_services(&args.services, &args.actions)?;
    if planned.is_empty() {
        return Err(PreflightCliError::NoServices);
    }

    // The plan's proposed scope: the structured action_refs it selected. Used
    // both for delegated lane-effective coverage and as the saved envelope.
    let inline_scope: Vec<String> = planned
        .iter()
        .filter_map(|a| {
            a.get("action_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect();

    let mut params = json!({
        "posture": {
            "fallback": if posture.is_strict() { "strict" } else { "jit" },
            "context": "interactive",
        },
        "actions": planned.clone(),
    });
    if let Some(p) = &args.persona {
        params["persona"] = json!(p);
    }
    // Delegated postures shape an envelope from the plan's own actions; pass them
    // inline so the daemon runs delegable-parent ∩ scope (it has no saved
    // template for a plan). Ambient has no delegated envelope.
    if posture.is_delegated() {
        params["inline_template_scope"] = json!(inline_scope);
    }

    let result = crate::call_daemon_rpc(socket_path, "preflight_authority_coverage", &params)
        .map_err(|e| PreflightCliError::Daemon(e.to_string()))?;
    let rows: Vec<PreflightRow> =
        serde_json::from_value(result).map_err(|e| PreflightCliError::Protocol(e.to_string()))?;

    // Perform the save (the planner's one mutation) AFTER coverage is computed,
    // so the operator sees what the lane can do before it is persisted.
    let saved = match &args.save {
        Some(name) => Some(save_plan_artifact(
            socket_path,
            name,
            posture,
            &inline_scope,
            &args.services,
            args.ttl.as_deref(),
        )?),
        None => None,
    };

    if args.json {
        let counts = CoverageCounts::tally(&rows);
        let mut payload = json!({
            "posture": posture.label(),
            "underlying": posture.underlying(),
            "persona": args.persona,
            "rows": rows,
            "summary": {
                "covered": counts.covered,
                "prompt": counts.prompt,
                "deny": counts.deny,
                "missing": counts.missing,
            },
        });
        if let (Some(name), Some(saved)) = (&args.save, &saved) {
            payload["saved"] = saved.clone();
            payload["launch"] = json!(launch_bridge_line(name, posture));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print!("{}", render_plan(posture, args.persona.as_deref(), &rows));
        match (&args.save, &saved) {
            (Some(name), Some(saved)) => {
                let path = saved
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(overlay)");
                let ttl = saved.get("ttl").and_then(|v| v.as_str()).unwrap_or("-");
                println!(
                    "\n  saved delegated plan '{name}' ({ttl}, {} actions) → {path}",
                    inline_scope.len()
                );
                println!("  launch it: {}", launch_bridge_line(name, posture));
            }
            _ => {
                if let Some(hint) = save_hint_line(posture) {
                    println!("  {hint}");
                }
            }
        }
    }
    Ok(())
}

/// Persist the plan as a reusable delegated artifact (ADR 194 §5 output 3) by
/// brokering the write through the daemon's `save_delegation_template` RPC. The
/// daemon writes to its OWN overlay dir so a separate-uid managed daemon (ADR
/// 131) can read it at launch — a CLI-side write to the operator's home would
/// be unreadable to that daemon. Returns the daemon's
/// `{ name, path, ttl, scope_count }` result.
fn save_plan_artifact(
    socket_path: &Path,
    name: &str,
    posture: PlanPosture,
    scopes: &[String],
    services: &[String],
    ttl_override: Option<&str>,
) -> Result<Value, PreflightCliError> {
    let ttl = ttl_override
        .map(str::to_string)
        .or_else(|| posture.default_ttl().map(str::to_string))
        .ok_or_else(|| {
            // Unreachable: cmd_catalog_plan rejects ambient + save earlier.
            PreflightCliError::Invalid(
                "ambient posture has no delegated envelope to save".to_string(),
            )
        })?;
    let description = format!(
        "Saved by ember catalog plan ({}) for {}",
        posture.label(),
        services.join(", ")
    );
    let params = json!({
        "name": name,
        "ttl": ttl,
        "scopes": scopes,
        "description": description,
    });
    crate::call_daemon_rpc(socket_path, "save_delegation_template", &params)
        .map_err(|e| PreflightCliError::Daemon(e.to_string()))
}

/// The launcher invocation that consumes a saved plan (ADR 194 §5 output 4).
/// Launchers consume plans; they do not become planners (§6), so this is the
/// existing `--delegated <name>` opt-in plus `--strict` for the fail-closed
/// `bounded` posture — no new launcher flags.
pub fn launch_bridge_line(template_name: &str, posture: PlanPosture) -> String {
    let strict = if posture.is_strict() { " --strict" } else { "" };
    format!("ember claude --delegated {template_name}{strict}")
}

/// Hint under a delegated preview that was not saved, pointing at the
/// save-then-launch path. `None` for ambient (nothing to persist).
fn save_hint_line(posture: PlanPosture) -> Option<String> {
    posture.is_delegated().then(|| {
        "to make this lane reusable: re-run with --save <name>, then launch with \
         ember claude --delegated <name>"
            .to_string()
    })
}

/// Render the service-first planning preview. Pure so the shape is unit-testable
/// without a daemon. Answers the four QC questions ADR 194 §3 names: who acts,
/// what the lane can do now, what happens if it needs more, how to tighten later.
pub fn render_plan(posture: PlanPosture, persona: Option<&str>, rows: &[PreflightRow]) -> String {
    let mut buf = String::new();
    buf.push_str(&format!(
        "ember catalog plan: {} ({})\n",
        posture.label(),
        posture.underlying()
    ));
    buf.push_str(&format!(
        "  who acts: {}\n\n",
        persona.unwrap_or("all active grants")
    ));

    if rows.is_empty() {
        buf.push_str("no actions to evaluate (no matching service actions)\n");
        return buf;
    }

    let labels: Vec<String> = rows
        .iter()
        .map(|r| short_action_label(r.action_ref.as_deref()))
        .collect();
    let svc_w = rows
        .iter()
        .map(|r| r.service.len())
        .max()
        .unwrap_or(0)
        .max("SERVICE".len());
    let act_w = labels
        .iter()
        .map(|l| l.len())
        .max()
        .unwrap_or(0)
        .max("ACTION".len());

    buf.push_str(&format!(
        "  {:svc_w$}  {:act_w$}  {:<8}  MATERIAL\n",
        "SERVICE",
        "ACTION",
        "STATUS",
        svc_w = svc_w,
        act_w = act_w
    ));
    for (row, label) in rows.iter().zip(labels.iter()) {
        let status_cell = format!("{:<8}", row.status);
        let status_cell =
            if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
                status_cell
            } else {
                status_cell.replacen(&row.status, &colorize(&row.status), 1)
            };
        buf.push_str(&format!(
            "  {:svc_w$}  {:act_w$}  {}  {}\n",
            row.service,
            label,
            status_cell,
            row.material_summary.as_deref().unwrap_or("-"),
            svc_w = svc_w,
            act_w = act_w
        ));
    }

    let counts = CoverageCounts::tally(rows);
    buf.push_str(&format!(
        "\n  covered: {} · prompt: {} · deny: {} · missing: {}\n",
        counts.covered, counts.prompt, counts.deny, counts.missing
    ));
    buf.push_str(&format!(
        "  if it needs more: {}\n",
        posture.fallback_summary()
    ));
    buf.push_str("  tighten later: ember grant revoke <id>\n");
    if let Some(hint) = rows
        .iter()
        .find(|r| r.status != "covered")
        .and_then(|r| r.next_action.clone())
    {
        buf.push_str(&format!("  next: {hint}\n"));
    }
    buf
}

/// `ember preflight [SERVICE] [--persona <id>] [--strict] [--headless] [--json]`.
pub fn cmd_preflight(socket_path: &Path, args: PreflightArgs) -> Result<(), PreflightCliError> {
    let actions = build_planned_actions(args.service.as_deref())?;

    let mut params = json!({
        "posture": {
            "fallback": if args.strict { "strict" } else { "jit" },
            "context": if args.headless { "headless" } else { "interactive" },
        },
        "actions": actions,
    });
    if let Some(persona) = &args.persona {
        params["persona"] = json!(persona);
    }

    let result = crate::call_daemon_rpc(socket_path, "preflight_authority_coverage", &params)
        .map_err(|e| PreflightCliError::Daemon(e.to_string()))?;
    let rows: Vec<PreflightRow> =
        serde_json::from_value(result).map_err(|e| PreflightCliError::Protocol(e.to_string()))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        print!("{}", render_preflight_table(&rows, &args));
    }
    Ok(())
}

/// Last path/version segment of a structured action ref — `pr_create@v1` from
/// `registry.ember.systems/ember-systems/ember-gh/pr_create@v1`.
fn short_action_label(action_ref: Option<&str>) -> String {
    match action_ref {
        Some(r) => r.rsplit('/').next().unwrap_or(r).to_string(),
        None => "-".to_string(),
    }
}

fn colorize(status: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
        return status.to_string();
    }
    let code = match status {
        "covered" => "\x1b[32m",          // green
        "prompt" => "\x1b[33m",           // yellow
        "deny" | "missing" => "\x1b[31m", // red
        _ => return status.to_string(),
    };
    format!("{code}{status}\x1b[0m")
}

/// Render the four-category result as a compact fixed-width table plus a
/// one-line summary. Public so callers can snapshot the output for tests.
pub fn render_preflight_table(rows: &[PreflightRow], args: &PreflightArgs) -> String {
    let mut buf = String::new();
    let posture = format!(
        "{} + {}",
        if args.strict { "strict" } else { "jit" },
        if args.headless {
            "headless"
        } else {
            "interactive"
        },
    );
    let persona = args.persona.as_deref().unwrap_or("all active grants");
    buf.push_str("ember preflight: authority coverage\n");
    buf.push_str(&format!("  persona: {persona}\n"));
    buf.push_str(&format!("  posture: {posture}\n\n"));

    if rows.is_empty() {
        buf.push_str("no actions to evaluate (service has no declared actions)\n");
        return buf;
    }

    let labels: Vec<String> = rows
        .iter()
        .map(|r| short_action_label(r.action_ref.as_deref()))
        .collect();
    let svc_w = rows
        .iter()
        .map(|r| r.service.len())
        .max()
        .unwrap_or(0)
        .max("SERVICE".len());
    let act_w = labels
        .iter()
        .map(|l| l.len())
        .max()
        .unwrap_or(0)
        .max("ACTION".len());

    buf.push_str(&format!(
        "{:svc_w$}  {:act_w$}  {:<8}  REASON\n",
        "SERVICE",
        "ACTION",
        "STATUS",
        svc_w = svc_w,
        act_w = act_w
    ));
    let (mut covered, mut prompt, mut deny, mut missing) = (0, 0, 0, 0);
    for (row, label) in rows.iter().zip(labels.iter()) {
        match row.status.as_str() {
            "covered" => covered += 1,
            "prompt" => prompt += 1,
            "deny" => deny += 1,
            "missing" => missing += 1,
            _ => {}
        }
        // Pad the plain status to width, then colorize — ANSI codes must not
        // count toward the column width.
        let status_cell = format!("{:<8}", row.status);
        let status_cell =
            if std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
                status_cell
            } else {
                status_cell.replacen(&row.status, &colorize(&row.status), 1)
            };
        buf.push_str(&format!(
            "{:svc_w$}  {:act_w$}  {}  {}\n",
            row.service,
            label,
            status_cell,
            row.reason,
            svc_w = svc_w,
            act_w = act_w
        ));
    }

    buf.push_str(&format!(
        "\ncovered: {covered} · prompt: {prompt} · deny: {deny} · missing: {missing}\n"
    ));

    // Surface the first actionable next step for an uncovered row so the
    // operator has an obvious move without scanning every line.
    if let Some(hint) = rows
        .iter()
        .find(|r| r.status != "covered")
        .and_then(|r| r.next_action.clone())
    {
        buf.push_str(&format!("next: {hint}\n"));
    }
    if let Some(line) = rows.iter().find_map(resolve_access_line) {
        buf.push_str(&format!("{line}\n"));
    }

    buf
}

fn resolve_access_line(row: &PreflightRow) -> Option<String> {
    let plan = row.access_resolution_plan.as_ref()?;
    let eligible = plan
        .get("collapse_eligibility")
        .and_then(|v| v.get("eligible"))
        .and_then(|v| v.as_bool())
        == Some(true);
    let action = short_action_label(Some(
        plan.get("denied_action")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| row.action_ref.as_deref().unwrap_or("-")),
    ));
    let repo = plan
        .get("target")
        .and_then(|v| v.get("repo"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown repo");
    let branch = plan
        .get("target")
        .and_then(|v| v.get("branch"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown branch");
    if eligible {
        return Some(format!(
            "Resolve Access: one confirmation for {action} on {repo} ({branch}); credential stays daemon-side until approval"
        ));
    }

    let steps = plan.get("steps").and_then(|v| v.as_array());
    let mut rendered = Vec::new();
    let mut has_service_readiness_step = false;
    for step in steps.into_iter().flatten() {
        match step.get("kind").and_then(|v| v.as_str()) {
            Some("install_service") => {
                let service = step
                    .get("service_ref")
                    .and_then(|v| v.get("display_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Service");
                rendered.push(format!("install {service}"));
                has_service_readiness_step = true;
            }
            Some("connect_service") => {
                let connection = step
                    .get("envelope")
                    .and_then(|v| v.get("service_connection"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Service Connection");
                rendered.push(format!("connect {connection}"));
                has_service_readiness_step = true;
            }
            Some("issue_grant") => {
                rendered.push(format!("approve {action} on {repo} ({branch})"));
            }
            _ => {}
        }
    }
    if has_service_readiness_step && !rendered.is_empty() {
        return Some(format!(
            "Resolve Access: {}; credential stays daemon-side until approval",
            rendered.join("; ")
        ));
    }

    let reason = plan
        .get("collapse_eligibility")
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("Action, Target, Grant, Service, or Policy proof is incomplete");
    Some(format!(
        "Resolve Access: separate review required for {action} on {repo} ({branch}); {reason}"
    ))
}

/// Aggregate coverage counts over a planned-action set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageCounts {
    pub covered: usize,
    pub prompt: usize,
    pub deny: usize,
    pub missing: usize,
}

impl CoverageCounts {
    pub fn total(&self) -> usize {
        self.covered + self.prompt + self.deny + self.missing
    }
    /// Actions that will fail closed in this lane (deny + missing).
    pub fn blocking(&self) -> usize {
        self.deny + self.missing
    }
    fn tally(rows: &[PreflightRow]) -> Self {
        let mut c = CoverageCounts::default();
        for r in rows {
            match r.status.as_str() {
                "covered" => c.covered += 1,
                "prompt" => c.prompt += 1,
                "deny" => c.deny += 1,
                "missing" => c.missing += 1,
                _ => {}
            }
        }
        c
    }
}

/// Best-effort coverage rollup over every installed service for a lane.
/// Returns `None` on any error so callers (the launcher) can fall back to a
/// plain pointer instead of failing the launch.
pub fn lane_coverage_counts(
    socket_path: &Path,
    persona: Option<&str>,
    strict: bool,
    headless: bool,
    delegation_template: Option<&str>,
) -> Option<CoverageCounts> {
    let actions = build_planned_actions(None).ok()?;
    if actions.is_empty() {
        return None;
    }
    let mut params = json!({
        "posture": {
            "fallback": if strict { "strict" } else { "jit" },
            "context": if headless { "headless" } else { "interactive" },
        },
        "actions": actions,
    });
    if let Some(p) = persona {
        params["persona"] = json!(p);
    }
    // A delegated lane passes the delegation template so the daemon computes
    // lane-effective (parent delegable grant ∩ template) coverage instead of the
    // durable persona's full standing-grant rollup, which would over-count.
    if let Some(template) = delegation_template {
        params["delegation_template"] = json!(template);
    }
    let result =
        crate::call_daemon_rpc(socket_path, "preflight_authority_coverage", &params).ok()?;
    let rows: Vec<PreflightRow> = serde_json::from_value(result).ok()?;
    Some(CoverageCounts::tally(&rows))
}

/// Compact one-line strict-lane coverage summary for the launch confirmation.
/// Pure formatter so the message shape is unit-testable without a daemon.
fn format_lane_coverage_line(
    launcher_label: &str,
    counts: Option<CoverageCounts>,
    delegated: bool,
) -> String {
    // A delegated lane narrows the durable persona's delegable grant by the
    // delegation template; the daemon computes that intersection so the count here
    // is the lane-effective answer, not the durable-persona rollup.
    let lane = if delegated {
        "delegated strict lane"
    } else {
        "strict lane"
    };
    match counts {
        Some(c) if c.blocking() > 0 => format!(
            "{launcher_label}: coverage — {}/{} catalog actions covered; {} will deny in this {lane} — run `ember preflight --strict` for the list",
            c.covered,
            c.total(),
            c.blocking(),
        ),
        Some(c) => format!(
            "{launcher_label}: coverage — all {} catalog actions covered for this {lane}",
            c.total(),
        ),
        None => format!(
            "{launcher_label}: coverage — run `ember preflight --strict` to preview what will deny before you start"
        ),
    }
}

/// Fetch + format the strict-lane coverage line. Best-effort: a daemon error
/// degrades to the plain `ember preflight --strict` pointer.
///
/// `delegation_template` is the delegated lane's template name (the launcher knows
/// it). When `delegated`, it is threaded to the daemon so coverage is the
/// parent-delegable-grant ∩ template intersection — the authority the minted
/// session grant will actually carry.
pub fn strict_lane_coverage_line(
    socket_path: &Path,
    launcher_label: &str,
    durable_persona: Option<&str>,
    delegated: bool,
    delegation_template: Option<&str>,
) -> String {
    let counts = lane_coverage_counts(
        socket_path,
        durable_persona,
        true,
        false,
        if delegated { delegation_template } else { None },
    );
    format_lane_coverage_line(launcher_label, counts, delegated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(service: &str, action_ref: Option<&str>, status: &str) -> PreflightRow {
        PreflightRow {
            service: service.to_string(),
            action_ref: action_ref.map(str::to_string),
            status: status.to_string(),
            reason: format!("{status} reason"),
            material_summary: None,
            next_action: (status != "covered").then(|| "ember grant ...".to_string()),
            access_resolution_plan: None,
        }
    }

    fn row_with_resolve_access() -> PreflightRow {
        PreflightRow {
            access_resolution_plan: Some(json!({
                "denied_action": "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
                "target": {
                    "kind": "github_repository_branch",
                    "provider": "github",
                    "repo": "emberdotlink/emberlink-dev",
                    "branch": "feat/resolve-access",
                },
                "collapse_eligibility": {
                    "eligible": true,
                    "reason": "core-vetted GitHub PR creation with one concrete repository and exact feature branch target evidence",
                },
                "steps": [{
                    "kind": "issue_grant",
                    "grant_delta": {
                        "ttl_secs": 14400,
                        "delegation": null,
                        "statements": [],
                    },
                }],
                "reasons": ["credential materialization remains daemon-side until approval"],
            })),
            ..row(
                "ember-gh",
                Some("registry.ember.systems/ember-systems/ember-gh/pr_create@v1"),
                "prompt",
            )
        }
    }

    fn row_with_blocked_resolve_access() -> PreflightRow {
        PreflightRow {
            access_resolution_plan: Some(json!({
                "denied_action": "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
                "target": {
                    "kind": "github_repository_branch",
                    "provider": "github",
                    "repo": "emberdotlink/emberlink-dev",
                    "branch": "main",
                },
                "collapse_eligibility": {
                    "eligible": false,
                    "reason": "Target is a protected or production branch and needs separate review",
                },
                "steps": [{
                    "kind": "issue_grant",
                    "grant_delta": {
                        "ttl_secs": 14400,
                        "delegation": null,
                        "statements": [],
                    },
                }],
                "reasons": ["Target is a protected or production branch and needs separate review"],
            })),
            ..row(
                "ember-gh",
                Some("registry.ember.systems/ember-systems/ember-gh/pr_create@v1"),
                "prompt",
            )
        }
    }

    fn row_with_missing_service_resolve_access() -> PreflightRow {
        PreflightRow {
            access_resolution_plan: Some(json!({
                "denied_action": "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
                "target": {
                    "kind": "github_repository_branch",
                    "provider": "github",
                    "repo": "emberdotlink/emberlink-dev",
                    "branch": "feat/resolve-access",
                },
                "collapse_eligibility": {
                    "eligible": false,
                    "reason": "GitHub Service must be installed before this Resolve Access plan can collapse",
                },
                "steps": [
                    {
                        "kind": "install_service",
                        "service_ref": {
                            "name": "ember-gh",
                            "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
                            "display_name": "GitHub Service",
                        },
                        "publisher_trust": {
                            "trusted": true,
                            "provenance": "bundled Ember Systems Service manifest",
                            "reason": "bundled Service manifests are core-vetted before advisory discovery",
                        },
                    },
                    {
                        "kind": "connect_service",
                        "service_ref": {
                            "name": "ember-gh",
                            "plugin_address": "registry.ember.systems/ember-systems/ember-gh",
                            "display_name": "GitHub Service",
                        },
                        "envelope": {
                            "service_connection": "GitHub Service Connection",
                            "readiness": "missing",
                            "reason": "connect the GitHub Service before Ember can mint a scoped credential",
                        },
                    },
                    {
                        "kind": "issue_grant",
                        "grant_delta": {
                            "ttl_secs": 14400,
                            "delegation": null,
                            "statements": [],
                        },
                    },
                ],
                "reasons": [
                    "Available Service Index matched the bundled GitHub Service from non-secret action metadata"
                ],
            })),
            ..row("github", None, "missing")
        }
    }

    #[test]
    fn build_planned_actions_for_known_service() {
        let actions = build_planned_actions(Some("ember-gh")).expect("gh service present");
        assert!(!actions.is_empty());
        assert!(
            actions
                .iter()
                .all(|a| a["service"].as_str() == Some("ember-gh"))
        );
        assert!(actions.iter().any(|a| {
            a["action_ref"]
                .as_str()
                .is_some_and(|r| r.contains("pr_create"))
        }));
    }

    #[test]
    fn resolve_service_accepts_friendly_names() {
        assert!(resolve_service("gh").is_some(), "bare wrapped-binary 'gh'");
        assert!(resolve_service("ember-gh").is_some(), "full service name");
        assert_eq!(resolve_service("gh").unwrap().name, "ember-gh");
        assert!(resolve_service("nope").is_none());
    }

    #[test]
    fn build_planned_actions_unknown_service_errors() {
        let err = build_planned_actions(Some("does-not-exist")).unwrap_err();
        assert!(matches!(err, PreflightCliError::ServiceNotFound(_)));
    }

    #[test]
    fn short_action_label_extracts_key_version() {
        assert_eq!(
            short_action_label(Some(
                "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
            )),
            "pr_create@v1"
        );
        assert_eq!(short_action_label(None), "-");
    }

    #[test]
    fn table_renders_summary_counts() {
        let rows = vec![
            row("ember-gh", Some("a/b/pr_create@v1"), "covered"),
            row("ember-gh", Some("a/b/pr_merge@v1"), "prompt"),
            row("ember-git", Some("a/b/git.push@v1"), "deny"),
        ];
        let out = render_preflight_table(&rows, &PreflightArgs::default());
        assert!(out.contains("covered: 1 · prompt: 1 · deny: 1 · missing: 0"));
        assert!(out.contains("pr_create@v1"));
        assert!(out.contains("next: ember grant ..."));
    }

    #[test]
    fn table_renders_collapsed_resolve_access_copy() {
        let out = render_preflight_table(&[row_with_resolve_access()], &PreflightArgs::default());
        assert!(out.contains("Resolve Access: one confirmation"));
        assert!(out.contains("pr_create@v1"));
        assert!(out.contains("emberdotlink/emberlink-dev"));
        assert!(out.contains("feat/resolve-access"));
        assert!(out.contains("credential stays daemon-side until approval"));
        assert!(!out.contains("issue_grant"));
        assert!(!out.contains("InstallService"));
        assert!(!out.contains("ConnectService"));
    }

    #[test]
    fn table_renders_blocked_resolve_access_copy() {
        let out = render_preflight_table(
            &[row_with_blocked_resolve_access()],
            &PreflightArgs::default(),
        );
        assert!(out.contains("Resolve Access: separate review required"));
        assert!(out.contains("pr_create@v1"));
        assert!(out.contains("emberdotlink/emberlink-dev"));
        assert!(out.contains("main"));
        assert!(out.contains("protected or production branch"));
        assert!(!out.contains("issue_grant"));
        assert!(!out.contains("InstallService"));
        assert!(!out.contains("ConnectService"));
    }

    #[test]
    fn table_renders_missing_service_resolve_access_copy() {
        let out = render_preflight_table(
            &[row_with_missing_service_resolve_access()],
            &PreflightArgs::default(),
        );
        assert!(out.contains("Resolve Access: install GitHub Service"));
        assert!(out.contains("connect GitHub Service Connection"));
        assert!(out.contains("approve pr_create@v1"));
        assert!(out.contains("emberdotlink/emberlink-dev"));
        assert!(out.contains("feat/resolve-access"));
        assert!(out.contains("credential stays daemon-side until approval"));
        assert!(!out.contains("Provider"));
        assert!(!out.contains("InstallService"));
        assert!(!out.contains("ConnectService"));
        assert!(!out.contains("issue_grant"));
    }

    #[test]
    fn table_handles_empty_rows() {
        let out = render_preflight_table(&[], &PreflightArgs::default());
        assert!(out.contains("no actions to evaluate"));
    }

    #[test]
    fn coverage_counts_tally() {
        let rows = vec![
            row("s", Some("a/b/x@v1"), "covered"),
            row("s", Some("a/b/y@v1"), "deny"),
            row("s", Some("a/b/z@v1"), "missing"),
        ];
        let c = CoverageCounts::tally(&rows);
        assert_eq!((c.covered, c.deny, c.missing, c.total()), (1, 1, 1, 3));
        assert_eq!(c.blocking(), 2);
    }

    #[test]
    fn lane_line_warns_on_blocking_actions() {
        let c = CoverageCounts {
            covered: 8,
            prompt: 0,
            deny: 3,
            missing: 1,
        };
        let line = format_lane_coverage_line("claude", Some(c), false);
        assert!(line.contains("8/12 catalog actions covered"));
        assert!(line.contains("4 will deny"));
        assert!(line.contains("ember preflight --strict"));
    }

    #[test]
    fn lane_line_all_covered() {
        let c = CoverageCounts {
            covered: 12,
            ..Default::default()
        };
        let line = format_lane_coverage_line("claude", Some(c), false);
        assert!(line.contains("all 12 catalog actions covered"));
    }

    #[test]
    fn lane_line_delegated_shows_lane_effective_counts() {
        // Delegated lanes now print real numbers (parent ∩ template), computed by
        // the daemon, instead of punting to the detail command.
        let c = CoverageCounts {
            covered: 5,
            prompt: 0,
            deny: 2,
            missing: 0,
        };
        let line = format_lane_coverage_line("claude", Some(c), true);
        assert!(line.contains("5/7 catalog actions covered"));
        assert!(line.contains("2 will deny"));
        assert!(line.contains("delegated strict lane"));
    }

    #[test]
    fn lane_line_delegated_all_covered_names_the_lane() {
        let c = CoverageCounts {
            covered: 4,
            ..Default::default()
        };
        let line = format_lane_coverage_line("claude", Some(c), true);
        assert!(line.contains("all 4 catalog actions covered"));
        assert!(line.contains("delegated strict lane"));
    }

    #[test]
    fn lane_line_degrades_to_pointer_on_no_counts() {
        let line = format_lane_coverage_line("claude", None, false);
        assert!(line.contains("run `ember preflight --strict`"));
    }

    // --- ember catalog plan (ADR 194) ---

    #[test]
    fn plan_posture_parse_and_mapping() {
        assert_eq!(PlanPosture::parse("ambient"), Some(PlanPosture::Ambient));
        assert_eq!(PlanPosture::parse("elastic"), Some(PlanPosture::Elastic));
        assert_eq!(PlanPosture::parse("bounded"), Some(PlanPosture::Bounded));
        assert_eq!(PlanPosture::parse("strict"), None);

        assert!(!PlanPosture::Ambient.is_delegated());
        assert!(PlanPosture::Elastic.is_delegated());
        assert!(PlanPosture::Bounded.is_delegated());

        assert!(!PlanPosture::Elastic.is_strict());
        assert!(PlanPosture::Bounded.is_strict());

        assert_eq!(PlanPosture::Bounded.underlying(), "strict + delegated");
    }

    #[test]
    fn build_planned_actions_for_services_filters_by_action() {
        let all = build_planned_actions_for_services(&["ember-gh".to_string()], &[]).unwrap();
        assert!(all.len() > 1, "ember-gh should expose several actions");

        let filtered = build_planned_actions_for_services(
            &["ember-gh".to_string()],
            &["pr_create".to_string()],
        )
        .unwrap();
        assert!(!filtered.is_empty());
        assert!(
            filtered.iter().all(|a| {
                a["action_ref"]
                    .as_str()
                    .is_some_and(|r| r.contains("pr_create"))
            }),
            "action filter must keep only the requested action"
        );
        assert!(filtered.len() < all.len(), "filter should narrow the set");
    }

    #[test]
    fn build_planned_actions_for_services_unknown_service_errors() {
        let err =
            build_planned_actions_for_services(&["does-not-exist".to_string()], &[]).unwrap_err();
        assert!(matches!(err, PreflightCliError::ServiceNotFound(_)));
    }

    #[test]
    fn build_planned_actions_for_services_requires_a_service() {
        let err = build_planned_actions_for_services(&[], &[]).unwrap_err();
        assert!(matches!(err, PreflightCliError::NoServices));
    }

    #[test]
    fn render_plan_shows_posture_persona_and_counts() {
        let rows = vec![
            row("ember-gh", Some("a/b/pr_create@v1"), "covered"),
            row("ember-gh", Some("a/b/repo_delete@v1"), "deny"),
        ];
        let out = render_plan(PlanPosture::Bounded, Some("dev0"), &rows);
        assert!(out.contains("ember catalog plan: bounded (strict + delegated)"));
        assert!(out.contains("who acts: dev0"));
        assert!(out.contains("covered: 1 · prompt: 0 · deny: 1 · missing: 0"));
        assert!(
            out.contains("fail closed"),
            "bounded must explain deny-on-miss"
        );
        assert!(out.contains("ember grant revoke"));
        assert!(!out.contains("ember delegation revoke"));
    }

    #[test]
    fn render_plan_ambient_explains_prompt_fallback() {
        let rows = vec![row("ember-gh", Some("a/b/pr_create@v1"), "prompt")];
        let out = render_plan(PlanPosture::Ambient, None, &rows);
        assert!(out.contains("who acts: all active grants"));
        assert!(out.contains("prompt"));
    }

    #[test]
    fn render_plan_handles_no_actions() {
        let out = render_plan(PlanPosture::Elastic, None, &[]);
        assert!(out.contains("no actions to evaluate"));
    }

    // --- ember catalog plan --save / launch bridge (ADR 194 §5 outputs 3 & 4) ---

    #[test]
    fn posture_default_ttl_is_posture_derived() {
        // TTL falls out of posture intent (ADR 194 §9): a fail-closed bounded
        // lane gets a firmer ceiling than a forgiving elastic working session;
        // ambient has no delegated envelope to save.
        assert_eq!(PlanPosture::Ambient.default_ttl(), None);
        assert_eq!(PlanPosture::Elastic.default_ttl(), Some("8h"));
        assert_eq!(PlanPosture::Bounded.default_ttl(), Some("4h"));
    }

    #[test]
    fn launch_bridge_adds_strict_only_for_bounded() {
        assert_eq!(
            launch_bridge_line("release-proof", PlanPosture::Bounded),
            "ember claude --delegated release-proof --strict"
        );
        assert_eq!(
            launch_bridge_line("landing-edits", PlanPosture::Elastic),
            "ember claude --delegated landing-edits"
        );
    }

    #[test]
    fn save_hint_only_for_delegated_postures() {
        assert!(save_hint_line(PlanPosture::Ambient).is_none());
        assert!(
            save_hint_line(PlanPosture::Elastic)
                .unwrap()
                .contains("--save")
        );
        assert!(
            save_hint_line(PlanPosture::Bounded)
                .unwrap()
                .contains("ember claude --delegated")
        );
    }
}
