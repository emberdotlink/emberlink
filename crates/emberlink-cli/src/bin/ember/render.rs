use super::*;
use std::cell::Cell;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CliRenderTone {
    Brand,
    Subtle,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CliRenderTheme {
    pub(super) color: bool,
}

thread_local! {
    static CLI_RENDER_THEME: Cell<Option<CliRenderTheme>> = const { Cell::new(None) };
}

impl Default for CliRenderTheme {
    fn default() -> Self {
        Self {
            color: detect_color_auto(),
        }
    }
}

impl CliRenderTheme {
    pub(super) fn from_choice(choice: CliColorChoice) -> Self {
        Self {
            color: resolve_color_enabled(choice),
        }
    }

    pub(super) fn title(self, text: &str, tone: Option<CliRenderTone>) -> String {
        match tone {
            Some(tone) => self.paint(text, tone, true, false),
            None => self.plain_bold(text),
        }
    }

    pub(super) fn section_heading(self, text: &str) -> String {
        self.paint(text, CliRenderTone::Subtle, true, false)
    }

    pub(super) fn action_heading(self, text: &str) -> String {
        self.paint(text, CliRenderTone::Brand, true, false)
    }

    pub(super) fn table_heading(self, text: &str) -> String {
        self.plain_bold(text)
    }

    pub(super) fn plain_bold(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[1m{text}\x1b[0m")
    }

    pub(super) fn dim(self, text: &str) -> String {
        if !self.color {
            return text.to_string();
        }
        format!("\x1b[2m{text}\x1b[0m")
    }

    pub(super) fn command(self, text: &str) -> String {
        self.plain_bold(text)
    }

    pub(super) fn detail_label(self, text: &str) -> String {
        self.plain_bold(text)
    }

    pub(super) fn warning_label(self, text: &str) -> String {
        self.paint(text, CliRenderTone::Warning, true, false)
    }

    pub(super) fn error_label(self, text: &str) -> String {
        self.paint(text, CliRenderTone::Danger, true, false)
    }

    fn paint(self, text: &str, tone: CliRenderTone, bold: bool, dim: bool) -> String {
        if !self.color {
            return text.to_string();
        }

        let mut out = String::new();
        if bold {
            out.push_str("\x1b[1m");
        }
        if dim {
            out.push_str("\x1b[2m");
        }
        out.push_str(match tone {
            CliRenderTone::Brand => "\x1b[38;2;217;106;29m",
            CliRenderTone::Subtle => "\x1b[38;2;111;106;99m",
            CliRenderTone::Success => "\x1b[32m",
            CliRenderTone::Warning => "\x1b[33m",
            CliRenderTone::Danger => "\x1b[31m",
        });
        out.push_str(text);
        out.push_str("\x1b[0m");
        out
    }
}

pub(super) fn current_cli_render_theme() -> CliRenderTheme {
    CLI_RENDER_THEME.with(|theme| theme.get().unwrap_or_default())
}

pub(super) fn set_cli_render_theme(theme: CliRenderTheme) {
    CLI_RENDER_THEME.with(|slot| slot.set(Some(theme)));
}

#[cfg(test)]
pub(super) fn with_test_cli_render_theme<T>(theme: CliRenderTheme, f: impl FnOnce() -> T) -> T {
    CLI_RENDER_THEME.with(|slot| {
        let previous = slot.get();
        slot.set(Some(theme));
        let result = f();
        slot.set(previous);
        result
    })
}

fn detect_color_auto() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn resolve_color_enabled(choice: CliColorChoice) -> bool {
    match choice {
        CliColorChoice::Always => true,
        CliColorChoice::Never => false,
        CliColorChoice::Auto => detect_color_auto(),
    }
}

fn parse_cli_color_choice(value: &str) -> Option<CliColorChoice> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(CliColorChoice::Auto),
        "always" => Some(CliColorChoice::Always),
        "never" => Some(CliColorChoice::Never),
        _ => None,
    }
}

pub(super) fn resolve_cli_render_theme_from_raw_args(raw_args: &[String]) -> CliRenderTheme {
    let mut choice = CliColorChoice::Auto;
    let mut raw_iter = raw_args.iter();
    while let Some(arg) = raw_iter.next() {
        if let Some(value) = arg.strip_prefix("--color=") {
            if let Some(parsed) = parse_cli_color_choice(value) {
                choice = parsed;
            }
            continue;
        }
        if arg == "--color"
            && let Some(value) = raw_iter.next()
            && let Some(parsed) = parse_cli_color_choice(value)
        {
            choice = parsed;
        }
    }
    CliRenderTheme::from_choice(choice)
}

pub(super) fn tone_for_card_title(title: &str) -> Option<CliRenderTone> {
    let normalized = title.trim().to_ascii_lowercase();
    if normalized == "ready" || normalized.ends_with(" ready") {
        return Some(CliRenderTone::Success);
    }
    if normalized.contains("blocked") || normalized.contains("quarantined") {
        return Some(CliRenderTone::Danger);
    }
    if normalized.contains("needs attention") || normalized.contains("not set up") {
        return Some(CliRenderTone::Warning);
    }
    None
}

pub(super) fn style_section_heading(heading: &str) -> String {
    current_cli_render_theme().action_heading(heading)
}

pub(super) fn style_detail_line(line: &str) -> String {
    let Some((label, rest)) = line.split_once(':') else {
        return line.to_string();
    };
    if label.trim().is_empty() || label.len() > 24 {
        return line.to_string();
    }
    format!(
        "{}:{}",
        current_cli_render_theme().detail_label(label),
        rest
    )
}

pub(super) fn style_section_line(line: &str) -> String {
    if line.contains("\x1b[") {
        return line.to_string();
    }

    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return line.to_string();
    }

    if trimmed.starts_with("ember ")
        || trimmed.starts_with("sudo ember ")
        || trimmed.starts_with("codex ")
        || trimmed.starts_with("docs/")
    {
        let indent_width = line.len() - trimmed.len();
        let indent = &line[..indent_width];
        return format!("{indent}{}", current_cli_render_theme().command(trimmed));
    }

    line.to_string()
}

fn tone_for_inline_badge(value: &str) -> Option<CliRenderTone> {
    match value.trim().to_ascii_lowercase().as_str() {
        "active" | "ready" | "healthy" | "approved" | "open" | "attached" => {
            Some(CliRenderTone::Success)
        }
        "pending" | "paused" | "medium" | "degraded" | "expiring" => Some(CliRenderTone::Warning),
        "denied" | "blocked" | "critical" | "high" | "error" => Some(CliRenderTone::Danger),
        _ => None,
    }
}

pub(super) fn style_inline_badge(value: &str) -> String {
    let theme = current_cli_render_theme();
    match value.trim().to_ascii_lowercase().as_str() {
        "revoked" => return theme.title(value, Some(CliRenderTone::Brand)),
        "expired" | "exhausted" => return theme.dim(value),
        _ => {}
    }
    match tone_for_inline_badge(value) {
        Some(tone) => theme.title(value, Some(tone)),
        None => theme.plain_bold(value),
    }
}

pub(super) fn style_receipt_reason_badge(value: &str) -> String {
    let theme = current_cli_render_theme();
    match value.trim().to_ascii_lowercase().as_str() {
        "revoked" => theme.title(value, Some(CliRenderTone::Brand)),
        "expired" | "exhausted" => theme.dim(value),
        "cascaded" => theme.plain_bold(value),
        _ => theme.plain_bold(value),
    }
}

pub(super) fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

pub(super) fn compact_timeish(value: &str, max: usize) -> String {
    if value == "never" {
        return value.to_string();
    }
    if let Some((date, rest)) = value.split_once('T') {
        let time = rest.chars().take(5).collect::<String>();
        let compact = format!("{date} {time}");
        return truncate(&compact, max);
    }
    truncate(value, max)
}

pub(super) fn format_default_yes_prompt(prompt: &str) -> String {
    let theme = current_cli_render_theme();
    if !theme.color {
        return format!("{prompt} [Y/n]");
    }

    format!("{prompt} [{}/n]", theme.action_heading("Y"))
}

pub(super) fn style_explain_text(text: &str) -> String {
    let theme = current_cli_render_theme();
    let mut out = String::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            let _ = writeln!(out, "{}", theme.title(line, tone_for_card_title(line)));
            continue;
        }
        if line.is_empty() {
            let _ = writeln!(out);
            continue;
        }
        if !line.starts_with(' ') {
            let _ = writeln!(out, "{}", style_section_heading(line));
            continue;
        }

        let trimmed = line.trim_start();
        if trimmed.starts_with("ember ")
            || trimmed.starts_with("codex ")
            || trimmed.starts_with("docs/")
        {
            let indent_width = line.len() - trimmed.len();
            let indent = &line[..indent_width];
            let _ = writeln!(out, "{indent}{}", theme.command(trimmed));
            continue;
        }

        let _ = writeln!(out, "{line}");
    }
    out.trim_end().to_string()
}

pub(super) fn render_compact_card(
    title: &str,
    summary: &str,
    details: &[String],
    sections: &[UiSection],
) -> String {
    let theme = current_cli_render_theme();
    let mut out = String::new();
    let _ = writeln!(out, "{}", theme.title(title, tone_for_card_title(title)));
    let _ = writeln!(out, "{summary}");
    for detail in details {
        let _ = writeln!(out, "{}", style_detail_line(detail));
    }
    for section in sections {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", style_section_heading(section.heading));
        for line in &section.lines {
            for (index, segment) in line.lines().enumerate() {
                let indent = if index == 0 { "  " } else { "    " };
                let _ = writeln!(out, "{indent}{}", style_section_line(segment));
            }
        }
    }
    out.trim_end().to_string()
}

pub(super) fn display_launcher_path_text(path: &Path) -> String {
    if path.file_name().is_some_and(|name| name == "ember") {
        return "ember".to_string();
    }
    path.display().to_string()
}

pub(super) fn display_command_text(command: &str) -> String {
    if let Some(rest) = command.strip_prefix("sudo /")
        && let Some((_, tail)) = rest.rsplit_once("/ember ")
    {
        return format!("sudo ember {tail}");
    }
    if let Some(rest) = command.strip_prefix('/')
        && let Some((_, tail)) = rest.rsplit_once("/ember ")
    {
        return format!("ember {tail}");
    }
    command.to_string()
}

pub(super) fn command_row(command: impl Into<String>, detail: impl Into<String>) -> String {
    let command = command.into();
    let detail = detail.into();
    let display = display_command_text(&command);
    format!(
        "{}\n{}",
        current_cli_render_theme().command(&display),
        detail
    )
}

pub(super) fn render_persona_list_text(personas: &[serde_json::Value]) -> String {
    let active = personas
        .iter()
        .filter(|persona| persona.get("status").and_then(|v| v.as_str()) != Some("revoked"))
        .count();
    let revoked = personas.len().saturating_sub(active);
    let summary = if personas.is_empty() {
        "No personas are enrolled on this machine yet.".to_string()
    } else if revoked == 0 {
        format!(
            "{} available for grants and delegated-authority lanes.",
            pluralize(personas.len(), "persona", "personas")
        )
    } else {
        format!(
            "{} available: {} active, {} revoked.",
            pluralize(personas.len(), "persona", "personas"),
            active,
            revoked
        )
    };

    let mut sections = Vec::new();
    if personas.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember persona create <name>",
                    "Create a persona for a new agent lane",
                ),
                command_row(
                    "ember explain persona",
                    "Read how personas anchor grants and delegated authority",
                ),
            ],
        });
    } else {
        let mut lines = vec![
            current_cli_render_theme()
                .table_heading(&format!("{:<28} {:<24} STATE", "NAME", "PERSONA")),
        ];
        for persona in personas {
            let name = truncate(
                persona
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unnamed>"),
                28,
            );
            let id = truncate(
                persona
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<unknown>"),
                24,
            );
            let status = persona
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            lines.push(format!(
                "{name:<28} {id:<24} {}",
                style_inline_badge(status)
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember grant create --persona <id> --credential <name> --scope <scope> --ttl 30m",
                    "Issue authority to the persona you just inspected",
                ),
                command_row(
                    "ember persona revoke <id>",
                    "Stop a persona from receiving future authority",
                ),
            ],
        });
    }

    render_compact_card("Personas", &summary, &[], &sections)
}

pub(super) fn render_vault_list_text(
    entries: &[serde_json::Value],
    prefix: Option<&str>,
) -> String {
    let metadata_count = entries
        .iter()
        .filter(|entry| {
            entry
                .get("metadata")
                .and_then(|value| value.as_str())
                .is_some_and(|value| !value.trim().is_empty())
        })
        .count();
    let summary = match (entries.is_empty(), prefix.filter(|value| !value.is_empty())) {
        (true, Some(prefix)) => {
            format!("No credential names match the `{prefix}` prefix on this lane.")
        }
        (true, None) => "No credential names are visible on this lane.".to_string(),
        (false, Some(prefix)) => format!(
            "{} match the `{prefix}` prefix on the current lane.",
            pluralize(entries.len(), "credential name", "credential names")
        ),
        (false, None) => format!(
            "{} visible: {} with operator notes attached.",
            pluralize(entries.len(), "credential name", "credential names"),
            metadata_count
        ),
    };

    let mut sections = Vec::new();
    if entries.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember vault add <name> --stdin",
                    "Store the first credential without leaking it into shell history",
                ),
                command_row(
                    "ember explain vault",
                    "Read how the managed vault lane handles storage and unlock posture",
                ),
            ],
        });
    } else {
        let mut lines =
            vec![current_cli_render_theme().table_heading(&format!("{:<34} DETAIL", "NAME"))];
        for entry in entries {
            let name = truncate(
                entry
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("-"),
                34,
            );
            let metadata = entry
                .get("metadata")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .map(|value| truncate(value, 28));
            let detail = if entry
                .get("requires_biometric")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                metadata
                    .map(|value| format!("biometric; {value}"))
                    .unwrap_or_else(|| "biometric".to_string())
            } else {
                metadata.unwrap_or_else(|| "stored".to_string())
            };
            lines.push(format!("{name:<34} {detail}"));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember vault get <name>",
                    "Read one stored credential by name when you need to inspect or export it",
                ),
                command_row(
                    "ember vault lock",
                    "Re-lock the managed vault lane after a high-risk credential operation",
                ),
                command_row(
                    "ember vault add <name> --stdin",
                    "Add another credential without exposing the value on argv",
                ),
            ],
        });
    }

    render_compact_card("Vault credentials", &summary, &[], &sections)
}

pub(super) fn render_grant_list_text(list: &[serde_json::Value], active_only: bool) -> String {
    let active = list
        .iter()
        .filter(|grant| grant.get("status").and_then(|v| v.as_str()) == Some("active"))
        .count();
    let inactive = list.len().saturating_sub(active);
    let title = if active_only {
        "Active grants"
    } else {
        "Grants"
    };
    let summary = if list.is_empty() {
        if active_only {
            "No active grants are visible on the current lane.".to_string()
        } else {
            "No grants are visible on the current lane.".to_string()
        }
    } else if active_only {
        format!(
            "{} visible on the current authority lane.",
            pluralize(list.len(), "active grant", "active grants")
        )
    } else {
        format!(
            "{} visible: {} active, {} inactive.",
            pluralize(list.len(), "grant", "grants"),
            active,
            inactive
        )
    };

    let mut sections = Vec::new();
    if list.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember grant create --persona <id> --credential <name> --scope <scope> --ttl 30m",
                    "Issue the first grant on this lane",
                ),
                command_row(
                    "ember explain grant",
                    "Read the grant and delegation model before issuing authority",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<22} {:<22} {:<20} {:<16} STATE",
            "GRANT", "PERSONA", "CREDENTIAL", "EXPIRES"
        ))];
        for grant in list {
            let id = truncate(grant.get("id").and_then(|v| v.as_str()).unwrap_or("-"), 22);
            let persona = truncate(
                grant
                    .get("persona_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                22,
            );
            let credential = truncate(
                grant
                    .get("credential_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                20,
            );
            let expires = compact_timeish(
                grant
                    .get("expires_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("never"),
                16,
            );
            let status = grant
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            lines.push(format!(
                "{id:<22} {persona:<22} {credential:<20} {expires:<16} {}",
                style_inline_badge(status)
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember receipt list",
                    "Review the signed witnesses emitted by recent grant lifecycles",
                ),
                command_row(
                    "ember approval list",
                    "Return to pending requests that may mint the next grant",
                ),
            ],
        });
    }

    render_compact_card(title, &summary, &[], &sections)
}

pub(super) fn format_cents_display(cents: Option<u64>) -> String {
    cents
        .map(|value| format!("${:.2}", value as f64 / 100.0))
        .unwrap_or_else(|| "—".to_string())
}

pub(super) fn render_spend_grant_list_text(
    rows: &[SpendGrantListRow],
    active_only: bool,
) -> String {
    let active = rows.iter().filter(|row| row.status == "active").count();
    let inactive = rows.len().saturating_sub(active);
    let summary = if rows.is_empty() {
        "No spend grants are visible on the current lane.".to_string()
    } else if active_only {
        format!(
            "{} visible on the current authority lane.",
            pluralize(rows.len(), "spend grant", "spend grants")
        )
    } else {
        format!(
            "{} visible: {} active, {} inactive.",
            pluralize(rows.len(), "spend grant", "spend grants"),
            active,
            inactive
        )
    };

    let mut sections = Vec::new();
    if rows.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember grant create --persona <id> --kind spend --vendor <name> --max-cents <N> --window 24h",
                    "Issue the first spend grant on this lane",
                ),
                command_row(
                    "ember grant evaluate --grant <id> --attempt attempt.toml",
                    "Preflight a spend attempt before wiring a live rail",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<22} {:<18} {:<16} {:<10} {:<10} {:<10} STATE",
            "GRANT", "PERSONA", "VENDOR", "THRESH", "CAP", "RESERVED"
        ))];
        for row in rows {
            lines.push(format!(
                "{:<22} {:<18} {:<16} {:<10} {:<10} {:<10} {}",
                truncate(&row.id, 22),
                truncate(&row.persona_id, 18),
                truncate(&row.vendor, 16),
                truncate(&format_cents_display(row.threshold_cents), 10),
                truncate(&format_cents_display(row.hard_cap_cents), 10),
                truncate(&format_cents_display(Some(row.reserved_cents)), 10),
                style_inline_badge(&row.status)
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember grant show <id>",
                    "Inspect one spend grant with vendor, threshold, usage, and reserved posture",
                ),
                command_row(
                    "ember grant evaluate --grant <id> --attempt attempt.toml",
                    "Preflight one spend attempt against the selected grant",
                ),
            ],
        });
    }

    render_compact_card("Spend grants", &summary, &[], &sections)
}

pub(super) fn render_spend_grant_show_text(view: &GrantStatusView) -> String {
    let Some(stmt) = payment_statement_from_status(view) else {
        return render_grant_budget_from_status(&GrantBudgetStatusView {
            id: view.id.clone(),
            persona_id: view.persona_id.clone(),
            status: view.status.clone(),
            expires_at: view.expires_at.clone(),
            statements: view
                .statements
                .iter()
                .map(|stmt| GrantBudgetStatusStatementView {
                    sid: stmt.sid.clone(),
                    resource_type: stmt.resource_type.clone(),
                    resource: stmt.resource.clone(),
                    budget: stmt.budget.clone(),
                    usage: stmt.usage.clone(),
                })
                .collect(),
        });
    };

    let mut out = String::new();
    let _ = writeln!(out, "Spend grant {}", view.id);
    let _ = writeln!(out, "  Persona:   {}", view.persona_id);
    let _ = writeln!(out, "  Vendor:    {}", payment_vendor_display(stmt));
    let _ = writeln!(out, "  Status:    {}", view.status);
    let _ = writeln!(
        out,
        "  Expires:   {}",
        view.expires_at.as_deref().unwrap_or("never")
    );
    let _ = writeln!(
        out,
        "  Threshold: {}",
        format_cents_display(payment_threshold_cents(stmt))
    );
    let _ = writeln!(
        out,
        "  Hard cap:  {}",
        format_cents_display(stmt.budget.as_ref().and_then(|budget| budget.cents))
    );
    let _ = writeln!(
        out,
        "  Used:      {}",
        format_cents_display(Some(stmt.usage.cents))
    );
    let _ = writeln!(
        out,
        "  Reserved:  {}",
        format_cents_display(Some(stmt.reserved_cents))
    );
    let _ = writeln!(
        out,
        "  Action:    {}",
        stmt.actions
            .first()
            .cloned()
            .unwrap_or_else(|| "payment:charge".to_string())
    );
    let _ = writeln!(out, "  Statement: {}", stmt.sid);
    out.trim_end().to_string()
}

pub(super) fn render_grant_evaluate_text(decision: &serde_json::Value) -> String {
    let permit = decision
        .get("permit")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let reason = decision
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or(if permit { "allowed" } else { "denied" });
    let grant_id = decision
        .get("grant_id")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let emitted = decision
        .get("emitted_event_id")
        .and_then(|value| value.as_str())
        .unwrap_or("-");
    let approval = decision
        .get("await_approval_request_id")
        .and_then(|value| value.as_str());

    let mut out = String::new();
    let _ = writeln!(out, "Grant evaluate");
    let _ = writeln!(
        out,
        "  Decision:  {}",
        if permit { "permit" } else { "deny" }
    );
    let _ = writeln!(out, "  Reason:    {reason}");
    let _ = writeln!(out, "  Grant:     {grant_id}");
    let _ = writeln!(out, "  Event:     {emitted}");
    if let Some(approval_id) = approval {
        let _ = writeln!(out, "  Approval:  {approval_id}");
    }
    out.trim_end().to_string()
}

pub(super) fn approval_target_summary(
    request: &ember_daemon::trust::approval::ApprovalRequestInfo,
) -> String {
    if let Some(summary) = request.target_summary.as_deref() {
        return truncate(summary, 20);
    }
    if let Some(tool) = request.tool_name.as_deref() {
        if let Some(host) = request.target_host.as_deref() {
            return truncate(&format!("{tool}@{host}"), 20);
        }
        return truncate(tool, 20);
    }
    truncate(&request.credential_name, 20)
}

pub(super) fn render_approval_list_text(
    requests: &[ember_daemon::trust::approval::ApprovalRequestInfo],
) -> String {
    let summary = if requests.is_empty() {
        "No approval requests are waiting for operator input.".to_string()
    } else {
        format!(
            "{} waiting for operator input.",
            pluralize(requests.len(), "approval request", "approval requests")
        )
    };

    let mut sections = Vec::new();
    if requests.is_empty() {
        sections.push(UiSection {
            heading: "More",
            lines: vec![command_row(
                "ember explain approval",
                "Read how approvals turn proposed access into a grant",
            )],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<18} {:<18} {:<20} {:<18} RISK",
            "REQUEST", "PERSONA", "TARGET", "ACTION"
        ))];
        for request in requests {
            let action = if let Some(statements) = request.composite_statements.as_ref() {
                truncate(
                    &format!("{} · {} stmt", request.action, statements.len()),
                    18,
                )
            } else {
                truncate(&request.action, 18)
            };
            lines.push(format!(
                "{:<18} {:<18} {:<20} {:<18} {}",
                truncate(&request.id, 18),
                truncate(&request.persona_id, 18),
                approval_target_summary(request),
                action,
                style_inline_badge(&request.risk_level)
            ));
        }
        sections.push(UiSection {
            heading: "Queue",
            lines,
        });
        sections.push(UiSection {
            heading: "Resolve",
            lines: vec![
                command_row(
                    "ember approval approve <id>",
                    "Approve the exact request and mint the proposed authority",
                ),
                command_row(
                    "ember approval narrow <id>",
                    "Approve with reduced access instead of the full request",
                ),
                command_row("ember approval deny <id>", "Reject the request outright"),
            ],
        });
    }

    render_compact_card("Pending approvals", &summary, &[], &sections)
}

pub(super) fn render_sandbox_list_text(sandboxes: &[SandboxInfo]) -> String {
    let running = sandboxes
        .iter()
        .filter(|sandbox| sandbox.status == "running")
        .count();
    let summary = if sandboxes.is_empty() {
        "No sandboxes are registered on this machine yet.".to_string()
    } else if running == sandboxes.len() {
        format!(
            "{} running on the current machine.",
            pluralize(sandboxes.len(), "sandbox", "sandboxes")
        )
    } else {
        format!(
            "{} visible: {} running, {} inactive.",
            pluralize(sandboxes.len(), "sandbox", "sandboxes"),
            running,
            sandboxes.len().saturating_sub(running)
        )
    };

    let mut sections = Vec::new();
    if sandboxes.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember sandbox create --name <name> --image ubuntu:24.04",
                    "Create a bounded execution lane for agent work",
                ),
                command_row(
                    "ember explain sandbox",
                    "Read how sandboxes relate to grants, containers, and scoped execution",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<18} {:<18} {:<20} {:<16} STATE",
            "NAME", "PERSONA", "IMAGE", "OWNER"
        ))];
        for sandbox in sandboxes {
            lines.push(format!(
                "{:<18} {:<18} {:<20} {:<16} {}",
                truncate(&sandbox.name, 18),
                truncate(&sandbox.persona_id, 18),
                truncate(&sandbox.image, 20),
                truncate(sandbox.owner_persona_id.as_deref().unwrap_or("-"), 16),
                style_inline_badge(&sandbox.status)
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember sandbox exec <id> -- <cmd>",
                    "Run one bounded command inside a named sandbox deliberately",
                ),
                command_row(
                    "ember sandbox stop <id>",
                    "Pause a running sandbox without deleting its tracked state",
                ),
                command_row(
                    "ember sandbox delete <id>",
                    "Remove a sandbox that should stop existing entirely",
                ),
            ],
        });
    }

    render_compact_card("Sandboxes", &summary, &[], &sections)
}

pub(super) fn receipt_reason_badge(
    reason: &core_grant_types::grant_receipt::TerminalReason,
) -> &'static str {
    match reason {
        core_grant_types::grant_receipt::TerminalReason::Expired => "expired",
        core_grant_types::grant_receipt::TerminalReason::Revoked { .. } => "revoked",
        core_grant_types::grant_receipt::TerminalReason::Abandoned { .. } => "abandoned",
        core_grant_types::grant_receipt::TerminalReason::ExhaustedByBudget { .. } => "exhausted",
        core_grant_types::grant_receipt::TerminalReason::ParentCascadeRevoked { .. } => "cascaded",
    }
}

pub(super) fn render_receipt_list_text(
    receipts: &[core_grant_types::grant_receipt::GrantReceipt],
) -> String {
    let summary = if receipts.is_empty() {
        "No signed receipts are visible on this machine yet.".to_string()
    } else {
        format!(
            "{} available for audit, export, and trust verification.",
            pluralize(receipts.len(), "receipt", "receipts")
        )
    };

    let mut sections = Vec::new();
    if receipts.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember grant list",
                    "Inspect active authority before expecting new lifecycle witnesses",
                ),
                command_row(
                    "ember explain receipt",
                    "Read why receipts are the durable signed witness lane",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<22} {:<22} {:<20} REASON",
            "RECEIPT", "GRANT", "PERSONA"
        ))];
        for receipt in receipts {
            lines.push(format!(
                "{:<22} {:<22} {:<20} {}",
                truncate(&receipt.id, 22),
                truncate(&receipt.grant_id, 22),
                truncate(&receipt.summary.persona_id, 20),
                style_receipt_reason_badge(receipt_reason_badge(
                    &receipt.lifecycle.terminal_reason
                ))
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember receipt show <id>",
                    "Inspect one receipt in full, including chain and observed actions",
                ),
                command_row(
                    "ember receipt export --latest --format md",
                    "Export the latest signed witness in a shareable format",
                ),
                command_row(
                    "ember receipt verify <id>",
                    "Verify one witness against the current trust roots",
                ),
            ],
        });
    }

    render_compact_card("Receipts", &summary, &[], &sections)
}

pub(super) fn render_receipt_artifact_list_text(receipts: &[serde_json::Value]) -> String {
    let parsed_v1: Result<Vec<_>, _> = receipts
        .iter()
        .cloned()
        .map(serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>)
        .collect();
    if let Ok(v1_receipts) = parsed_v1 {
        return render_receipt_list_text(&v1_receipts);
    }

    let summary = if receipts.is_empty() {
        "No signed receipts are visible on this machine yet.".to_string()
    } else {
        format!(
            "{} available for audit, export, and trust verification.",
            pluralize(receipts.len(), "receipt", "receipts")
        )
    };

    let mut sections = Vec::new();
    if receipts.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember grant list",
                    "Inspect active authority before expecting new lifecycle witnesses",
                ),
                command_row(
                    "ember explain receipt",
                    "Read why receipts are the durable signed witness lane",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<22} {:<28} {:<8} {:<20} {:<22} DETAIL",
            "RECEIPT", "KIND", "VERSION", "PERSONA", "GRANT"
        ))];
        for receipt in receipts {
            lines.push(format!(
                "{:<22} {:<28} {:<8} {:<20} {:<22} {}",
                truncate(&receipt_artifact_id_label(receipt), 22),
                truncate(&receipt_artifact_kind_label(receipt), 28),
                truncate(&receipt_artifact_version_label(receipt), 8),
                truncate(&receipt_artifact_persona_label(receipt), 20),
                truncate(&receipt_artifact_grant_label(receipt), 22),
                truncate(&receipt_artifact_detail_label(receipt), 80),
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember receipt show <id>",
                    "Inspect one receipt in full, including envelope body fields",
                ),
                command_row(
                    "ember receipt export --latest --format json",
                    "Export the latest signed artifact as stored",
                ),
                command_row(
                    "ember receipt verify <id>",
                    "Verify one witness against the current trust roots",
                ),
            ],
        });
    }

    render_compact_card("Receipts", &summary, &[], &sections)
}

pub(super) fn render_receipt_artifact_summary_text(receipt: &serde_json::Value) -> String {
    let title = format!("Receipt {}", receipt_artifact_id_label(receipt));
    let summary = format!(
        "{} {} receipt artifact.",
        receipt_artifact_version_label(receipt),
        receipt_artifact_kind_label(receipt)
    );

    let mut facts = vec![
        format!("Kind: {}", receipt_artifact_kind_label(receipt)),
        format!("Version: {}", receipt_artifact_version_label(receipt)),
    ];
    let persona = receipt_artifact_persona_label(receipt);
    if persona != "-" {
        facts.push(format!("Persona: {persona}"));
    }
    let grant = receipt_artifact_grant_label(receipt);
    if grant != "-" {
        facts.push(format!("Grant: {grant}"));
    }
    if let Some(daemon_root) = receipt
        .get("daemon_root_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
    {
        facts.push(format!("Daemon root: {daemon_root}"));
    }
    if let Some(termination_authority) = receipt
        .get("termination_authority")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
    {
        facts.push(format!("Termination authority: {termination_authority}"));
    }

    let mut sections = Vec::new();
    let detail = receipt_artifact_detail_label(receipt);
    if detail != "-" {
        sections.push(UiSection {
            heading: "Body",
            lines: vec![detail],
        });
    }
    sections.push(UiSection {
        heading: "Inspect",
        lines: vec![
            command_row(
                "ember receipt show <id> --json",
                "Print the raw signed artifact as stored",
            ),
            command_row(
                "ember receipt verify <id>",
                "Verify the artifact against the current trust roots",
            ),
        ],
    });

    render_compact_card(&title, &summary, &facts, &sections)
}

fn receipt_artifact_id_label(receipt: &serde_json::Value) -> String {
    receipt
        .get("receipt_id")
        .or_else(|| receipt.get("id"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("-")
        .to_string()
}

fn receipt_artifact_kind_label(receipt: &serde_json::Value) -> String {
    if serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>(receipt.clone())
        .is_ok()
    {
        return "grant".to_string();
    }
    receipt
        .get("kind")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn receipt_artifact_version_label(receipt: &serde_json::Value) -> String {
    if serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>(receipt.clone())
        .is_ok()
    {
        return "v1".to_string();
    }
    match receipt.get("version") {
        Some(serde_json::Value::String(value)) if !value.is_empty() => format!("v{value}"),
        Some(serde_json::Value::Number(value)) => format!("v{value}"),
        _ => "unknown".to_string(),
    }
}

fn receipt_artifact_persona_label(receipt: &serde_json::Value) -> String {
    if let Ok(v1) =
        serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>(receipt.clone())
    {
        return v1.summary.persona_id;
    }
    string_at(receipt, &["persona_id"])
        .or_else(|| string_at(receipt, &["principal_id"]))
        .or_else(|| string_at(receipt, &["body", "persona_id"]))
        .or_else(|| string_at(receipt, &["body", "principal_id"]))
        .or_else(|| string_at(receipt, &["body", "operator_principal_id"]))
        .unwrap_or_else(|| "-".to_string())
}

fn receipt_artifact_grant_label(receipt: &serde_json::Value) -> String {
    if let Ok(v1) =
        serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>(receipt.clone())
    {
        return v1.grant_id;
    }
    string_at(receipt, &["grant_id"])
        .or_else(|| string_at(receipt, &["body", "grant_id"]))
        .or_else(|| string_at(receipt, &["body", "issued_grant_id"]))
        .or_else(|| string_at(receipt, &["body", "subject_grant_id"]))
        .or_else(|| string_at(receipt, &["body", "parent_grant_id"]))
        .unwrap_or_else(|| "-".to_string())
}

fn receipt_artifact_detail_label(receipt: &serde_json::Value) -> String {
    if let Ok(v1) =
        serde_json::from_value::<core_grant_types::grant_receipt::GrantReceipt>(receipt.clone())
    {
        return style_receipt_reason_badge(receipt_reason_badge(&v1.lifecycle.terminal_reason));
    }

    let mut parts = Vec::new();
    for path in [
        &["body", "issued_grant_id"][..],
        &["body", "subject_grant_id"],
        &["body", "device_id"],
        &["body", "signing_device_id"],
        &["body", "operation"],
        &["body", "provider"],
        &["body", "scope_template"],
        &["body", "termination_cause"],
        &["body", "operator_principal_id"],
        &["body", "resource"],
        &["body", "action"],
        &["body", "action_key"],
    ] {
        if let Some(value) = scalar_at(receipt, path) {
            parts.push(format!("{}={value}", path[path.len() - 1]));
        }
        if parts.len() >= 4 {
            break;
        }
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(", ")
    }
}

fn string_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    value_at(value, path)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn scalar_at(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    match value_at(value, path)? {
        serde_json::Value::String(value) if !value.is_empty() => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_at<'a>(mut value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    for key in path {
        value = value.get(*key)?;
    }
    Some(value)
}

pub(super) fn receipt_row_action_label(row: &ember_daemon::infra::receipt::ReceiptRow) -> String {
    row.action_ref
        .as_ref()
        .map(ToString::to_string)
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| {
            if row.resource.is_empty() {
                row.kind.clone()
            } else {
                row.resource.clone()
            }
        })
}

pub(super) fn render_receipt_query_text(
    rows: &[ember_daemon::infra::receipt::ReceiptRow],
) -> String {
    if rows.is_empty() {
        return "No receipts match the supplied filters.".to_string();
    }

    let h_kind = "KIND";
    let h_persona = "PERSONA";
    let h_action = "ACTION";
    let h_grant = "GRANT";
    let h_at = "MATERIALIZED_AT";
    let h_reason = "REASON";

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{h_kind:<10} {h_persona:<22} {h_action:<48} {h_grant:<22} {h_at:<28} {h_reason}"
    );
    for row in rows {
        let reason_short: String = row.terminal_reason.chars().take(40).collect();
        let action = receipt_row_action_label(row);
        let _ = writeln!(
            out,
            "{:<10} {:<22} {:<48} {:<22} {:<28} {}",
            truncate(&row.kind, 10),
            truncate(&row.actor, 22),
            action,
            truncate(&row.grant_id, 22),
            truncate(&row.materialized_at, 28),
            reason_short,
        );
    }
    out.trim_end().to_string()
}

pub(super) fn render_audit_show_text(entries: &[ember_daemon::infra::audit::AuditEntry]) -> String {
    let summary = if entries.is_empty() {
        "No operator-visible audit events matched the current filter.".to_string()
    } else {
        format!(
            "{} visible in the current audit window.",
            pluralize(entries.len(), "audit event", "audit events")
        )
    };

    let mut sections = Vec::new();
    if entries.is_empty() {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    "ember audit verify",
                    "Verify chain integrity before assuming the history is complete",
                ),
                command_row(
                    "ember receipt list",
                    "Inspect signed grant witnesses that should align with the audit trail",
                ),
            ],
        });
    } else {
        let mut lines = vec![current_cli_render_theme().table_heading(&format!(
            "{:<16} {:<16} {:<20} {:<18} OUTCOME",
            "TIME", "PERSONA", "ACTION", "CREDENTIAL"
        ))];
        for entry in entries {
            let time = compact_timeish(&entry.timestamp, 16);
            let persona = truncate(entry.agent_id.as_deref().unwrap_or("-"), 16);
            let action = truncate(&entry.action, 20);
            let credential = truncate(entry.credential.as_deref().unwrap_or("-"), 18);
            lines.push(format!(
                "{time:<16} {persona:<16} {action:<20} {credential:<18} {}",
                style_inline_badge(&entry.outcome)
            ));
        }
        sections.push(UiSection {
            heading: "Current set",
            lines,
        });
        sections.push(UiSection {
            heading: "Inspect",
            lines: vec![
                command_row(
                    "ember audit explain <id>",
                    "Drill into one audit decision with current-state context",
                ),
                command_row(
                    "ember audit verify",
                    "Verify the audit chain if anything here looks inconsistent",
                ),
            ],
        });
    }

    render_compact_card("Audit events", &summary, &[], &sections)
}

pub(super) fn vault_unlock_command_with_ember_command(ember_cmd: &str) -> String {
    format!("{ember_cmd} vault unlock")
}

pub(super) fn vault_lane_requires_unlock(vault_session: Option<&VaultStatusView>) -> bool {
    vault_session.is_some_and(|session| !session.live_vault_attached)
}

pub(super) fn render_actionable_error(
    code: &str,
    title: &str,
    why: &str,
    do_this: &[String],
    more: &[String],
) -> String {
    let theme = current_cli_render_theme();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        theme.title(
            &format!("error[{code}]: {title}"),
            Some(CliRenderTone::Danger)
        )
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", theme.error_label("Why this blocks you:"));
    let _ = writeln!(out, "  {why}");
    if !do_this.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", theme.warning_label("Do this:"));
        for step in do_this {
            let _ = writeln!(out, "  {}", style_section_line(step));
        }
    }
    if !more.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", theme.section_heading("More:"));
        for line in more {
            let _ = writeln!(out, "  {}", style_section_line(line));
        }
    }
    out.trim_end().to_string()
}

pub(super) fn render_status_collection_failure_text(error: &str, ember_cmd: &str) -> String {
    let status_json_cmd = format!("{ember_cmd} status --json");
    let doctor_cmd = format!("{ember_cmd} doctor");
    let explain_status_cmd = format!("{ember_cmd} explain status");

    render_compact_card(
        "Needs attention",
        "Ember could not inspect the current machine posture.",
        &[error.to_string()],
        &[
            UiSection {
                heading: "Fix now",
                lines: vec![command_row(doctor_cmd, "Open the deeper diagnosis lane")],
            },
            UiSection {
                heading: "Inspect",
                lines: vec![
                    command_row(
                        status_json_cmd,
                        "Emit the machine-readable posture contract",
                    ),
                    command_row(explain_status_cmd, "Read the posture and repair model"),
                ],
            },
        ],
    )
}

pub(super) fn render_launcher_actionable_error(surface: &str, err: &str) -> (String, i32) {
    let (surface_title, init_cmd, launch_cmd, explain_cmd) = match surface {
        "claude" => (
            "Claude",
            "ember init --for claude",
            "ember claude",
            "ember explain claude",
        ),
        "codex" => (
            "Codex",
            "ember init --for codex",
            "ember codex",
            "ember explain codex",
        ),
        "cursor" => (
            "Cursor",
            "ember init --for cursor",
            "ember cursor",
            "ember explain cursor",
        ),
        _ => ("Launcher", "ember init", "ember", "ember explain"),
    };
    let help_cmd = format!("{launch_cmd} --help");
    let code_prefix = surface.to_ascii_uppercase();

    if err.contains("managed worktree already has a live owner") {
        return (
            render_actionable_error(
                &format!("E-{code_prefix}-WORKTREE-BUSY"),
                "Managed worktree is already in use",
                err,
                &[
                    "Use a different `--worktree <name>` for a new launch.".to_string(),
                    "Wait for the current owner to exit before reusing this worktree.".to_string(),
                ],
                &[help_cmd, explain_cmd.to_string()],
            ),
            1,
        );
    }

    if err.contains("worktree dev CLI missing") {
        return (
            render_actionable_error(
                &format!("E-{code_prefix}-DEV-CLI-MISSING"),
                &format!("{surface_title} dev runtime is not installed"),
                "The requested `--dev` launch depends on a repo-local contributor runtime, and that runtime is missing.",
                &[
                    format!(
                        "Retry `{launch_cmd}` without `--dev` to use the managed product runtime."
                    ),
                    "If you intentionally need a contributor worktree runtime, use the repo-local contributor tooling for this checkout.".to_string(),
                ],
                &[err.to_string(), explain_cmd.to_string()],
            ),
            1,
        );
    }

    if err.contains("no cohort-A persona found") || err.contains("no Codex persona found") {
        return (
            render_actionable_error(
                &format!("E-{code_prefix}-NOT-INITIALIZED"),
                &format!("{surface_title} is not set up yet"),
                "The required persona and session wiring do not exist on this machine.",
                &[
                    format!("Run `{init_cmd}`."),
                    "Run `ember status` to confirm readiness.".to_string(),
                ],
                &[err.to_string(), explain_cmd.to_string()],
            ),
            1,
        );
    }

    if surface == "codex" && err.contains("could not resolve `codex` on PATH") {
        return (
            render_actionable_error(
                "E-CODEX-BINARY-NOT-FOUND",
                "Codex is not installed on this host",
                "Ember could not find the `codex` executable on PATH.",
                &[
                    "Install Codex or add it to PATH.".to_string(),
                    "Re-run `ember codex` after the host binary is available.".to_string(),
                ],
                &[err.to_string(), explain_cmd.to_string()],
            ),
            1,
        );
    }

    if surface == "codex" && (err.contains("auth.json") || err.contains("codex login")) {
        return (
            render_actionable_error(
                "E-CODEX-AUTH-NOT-READY",
                "Codex host auth is missing",
                "Isolated Codex launch needs host Codex auth state before Ember can forward the session.",
                &[
                    "Run `codex login` on the host first.".to_string(),
                    "Run `ember codex --host` if you want the host lane right now.".to_string(),
                ],
                &[err.to_string(), explain_cmd.to_string()],
            ),
            1,
        );
    }

    if err.contains("choose exactly one placement override")
        || err.contains("backend hints and presets only apply")
        || err.contains("require `--worktree`")
        || err.contains("managed worktree launch is host-only")
        || err.contains("not wired yet")
    {
        return (
            render_actionable_error(
                &format!("E-{code_prefix}-USAGE"),
                &format!("{surface_title} launch request is invalid"),
                err,
                &[
                    format!("Run `{help_cmd}` to review the launch flags."),
                    format!("Run `{explain_cmd}` for the launch model."),
                ],
                &[],
            ),
            2,
        );
    }

    (
        render_actionable_error(
            &format!("E-{code_prefix}-LAUNCH"),
            &format!("{surface_title} could not start"),
            err,
            &[
                "Run `ember status` to inspect current posture.".to_string(),
                "Run `ember doctor` if the blocker is not obvious.".to_string(),
            ],
            &[explain_cmd.to_string()],
        ),
        1,
    )
}
