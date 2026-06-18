use core_grant_types::grant_receipt::{
    ApprovalActor, ApprovalEvent, AuditEntry, BudgetAxis, GrantReceipt, RevokeActor, TerminalReason,
};

fn iso8601_from_epoch(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("epoch+{secs}s"))
}

fn format_terminal_reason(reason: &TerminalReason) -> String {
    match reason {
        TerminalReason::Expired => "expired".to_string(),
        TerminalReason::Revoked { by, reason } => {
            let actor = match by {
                RevokeActor::Operator => "operator",
                RevokeActor::Agent => "agent",
                RevokeActor::ParentCascade => "parent_cascade",
            };
            format!("revoked (by {actor}: {reason})")
        }
        TerminalReason::Abandoned { reason } => format!("abandoned ({reason})"),
        TerminalReason::ExhaustedByBudget {
            statement_sid,
            axis,
        } => {
            let axis_str = match axis {
                BudgetAxis::Tokens => "tokens",
                BudgetAxis::Cents => "cents",
                BudgetAxis::Requests => "requests",
                BudgetAxis::WallClockSecs => "wall_clock_secs",
            };
            format!("exhausted_by_budget ({axis_str} on {statement_sid})")
        }
        TerminalReason::ParentCascadeRevoked { parent_grant_id } => {
            format!("parent_cascade_revoked ({parent_grant_id})")
        }
    }
}

fn format_approval_actor(actor: &ApprovalActor) -> &'static str {
    match actor {
        ApprovalActor::HumanDashboard => "human (dashboard)",
        ApprovalActor::HumanCli => "human (cli)",
        ApprovalActor::Policy => "policy",
        ApprovalActor::StandingGrant => "standing_grant",
    }
}

fn render_approval_chain(events: &[ApprovalEvent]) -> String {
    let mut out = format!("## Approval chain ({} events)\n\n", events.len());
    out.push_str("| When | Actor | Outcome | Reason |\n");
    out.push_str("|---|---|---|---|\n");
    for ev in events {
        let when = iso8601_from_epoch(ev.at);
        let actor = format_approval_actor(&ev.actor);
        let outcome = format!("{:?}", ev.outcome);
        let reason = ev.reason.as_deref().unwrap_or("-");
        out.push_str(&format!("| {when} | {actor} | {outcome} | {reason} |\n"));
    }
    out
}

fn render_actions_observed(entries: &[AuditEntry]) -> String {
    let mut out = format!("## Actions observed ({})\n\n", entries.len());
    out.push_str("| When | Event | Action | Resource | Outcome |\n");
    out.push_str("|---|---|---|---|---|\n");
    for entry in entries {
        let when = iso8601_from_epoch(entry.at);
        let action = entry.action.as_deref().unwrap_or("-");
        let resource = entry.resource.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "| {when} | {} | {action} | {resource} | {} |\n",
            entry.event, entry.outcome
        ));
    }
    out
}

/// Render a [`GrantReceipt`] as a markdown string suitable for Slack/iMessage paste.
///
/// Per ADR 120 §7: output targets <80 lines for a typical receipt.
///
/// The `raw` parameter is reserved for ADR 118 v2 sidecar compatibility and is
/// a no-op today. When the v2 schema lands (COHORT-A-7), `raw = true` will
/// include the full sidecar tier-mapping and tool-aware redaction fields.
pub fn render_receipt_markdown(receipt: &GrantReceipt, _raw: bool) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!("# Grant Receipt {}\n\n", receipt.id));
    out.push_str(&format!("**Grant:** {}\n", receipt.grant_id));
    out.push_str(&format!(
        "**Persona:** {}  → **Agent:** {}\n",
        receipt.summary.persona_id, receipt.summary.agent_id
    ));
    out.push_str(&format!(
        "**Service:** {} · **Resource:** {}\n",
        receipt.summary.service, receipt.summary.resource
    ));
    out.push_str(&format!("**Owner:** {}\n", receipt.summary.human_owner));
    out.push('\n');

    // Lifecycle
    out.push_str("## Lifecycle\n\n");
    out.push_str("| Field | Value |\n");
    out.push_str("|---|---|\n");
    out.push_str(&format!(
        "| Issued | {} |\n",
        iso8601_from_epoch(receipt.lifecycle.issued_at)
    ));
    let last_used = receipt
        .lifecycle
        .last_used_at
        .map(iso8601_from_epoch)
        .unwrap_or_else(|| "never".to_string());
    out.push_str(&format!("| Last used | {last_used} |\n"));
    out.push_str(&format!(
        "| Terminated | {} |\n",
        iso8601_from_epoch(receipt.lifecycle.terminated_at)
    ));
    out.push_str(&format!(
        "| Reason | {} |\n",
        format_terminal_reason(&receipt.lifecycle.terminal_reason)
    ));
    out.push('\n');

    // Approval chain
    out.push_str(&render_approval_chain(&receipt.approval_chain));
    out.push('\n');

    // Actions observed
    out.push_str(&render_actions_observed(&receipt.actions_observed));
    out.push('\n');

    // Per-statement usage
    out.push_str("## Per-statement usage\n\n");
    out.push_str("| Statement | Usage |\n");
    out.push_str("|---|---|\n");
    for (sid, usage) in &receipt.per_statement_usage {
        out.push_str(&format!("| {sid} | {usage:?} |\n"));
    }
    out.push('\n');

    // Signature
    out.push_str("## Signature\n\n");
    out.push_str("| Field | Value |\n");
    out.push_str("|---|---|\n");
    out.push_str(&format!(
        "| Hash (sha256) | `{}` |\n",
        receipt.evidence.hash
    ));
    out.push_str(&format!(
        "| Signer pubkey | `{}` |\n",
        receipt.evidence.signer_pubkey
    ));
    out.push_str(&format!(
        "| Canonical version | {} |\n",
        receipt.evidence.canonical_version
    ));
    out.push('\n');
    out.push_str(&format!(
        "Verify with: `ember receipt verify --file <path> --pubkey {}`\n\n",
        receipt.evidence.signer_pubkey
    ));
    out.push_str("---\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grant_types::grant_receipt::{
        ApprovalActor, ApprovalEvent, ApprovalOutcome, AuditEntry, Evidence, GrantReceipt,
        Lifecycle, ReceiptSummary, TerminalReason,
    };
    use core_grant_types::{AttestationBinding, StatementId};

    fn fixture() -> GrantReceipt {
        GrantReceipt {
            id: "rct_fixture".to_string(),
            grant_id: "grt_fixture".to_string(),
            summary: ReceiptSummary {
                human_owner: "alice@example.com".to_string(),
                persona_id: "persona-prof".to_string(),
                agent_id: "claude-code".to_string(),
                service: "github".to_string(),
                resource: "emberdotlink/emberlink".to_string(),
            },
            approved_chain: vec![],
            per_statement_usage: vec![],
            approval_chain: vec![ApprovalEvent {
                at: 1714492800,
                actor: ApprovalActor::HumanCli,
                outcome: ApprovalOutcome::Approved,
                reason: Some("initial issuance".to_string()),
            }],
            actions_observed: vec![AuditEntry {
                at: 1714492900,
                event: "tool_call_attempt".to_string(),
                action: Some("Bash".to_string()),
                resource: Some("cargo build".to_string()),
                outcome: "allowed".to_string(),
            }],
            lifecycle: Lifecycle {
                issued_at: 1714492800,
                last_used_at: Some(1714493000),
                terminated_at: 1714493600,
                terminal_reason: TerminalReason::Expired,
            },
            attestation: AttestationBinding::default(),
            dev_mode_active: false,
            evidence: Evidence::default(),
        }
    }

    #[test]
    fn renders_grant_receipt_id() {
        let md = render_receipt_markdown(&fixture(), false);
        assert!(md.contains("rct_fixture"), "should include receipt id");
        assert!(md.contains("grt_fixture"), "should include grant id");
    }

    #[test]
    fn renders_iso8601_timestamps() {
        let md = render_receipt_markdown(&fixture(), false);
        // 1714492800 = 2024-04-30T16:00:00Z
        assert!(
            md.contains("2024-04-30T16:00:00Z"),
            "should render ISO-8601: {md}"
        );
    }

    #[test]
    fn renders_terminal_reason_expired() {
        let md = render_receipt_markdown(&fixture(), false);
        assert!(md.contains("expired") || md.contains("Expired"));
    }

    #[test]
    fn renders_signature_section() {
        let md = render_receipt_markdown(&fixture(), false);
        assert!(md.contains("Signature"));
        assert!(md.contains("ember receipt verify"));
    }

    #[test]
    fn renders_under_80_lines_for_minimal_receipt() {
        let md = render_receipt_markdown(&fixture(), false);
        let lines = md.lines().count();
        assert!(
            lines < 80,
            "minimal receipt rendered to {lines} lines (target <80)"
        );
    }

    #[test]
    fn raw_flag_currently_noop() {
        // ADR 118 v2 sidecar lands in COHORT-A-7; today the flag is parsed
        // but the rendering is identical regardless of value.
        let md_default = render_receipt_markdown(&fixture(), false);
        let md_raw = render_receipt_markdown(&fixture(), true);
        assert_eq!(md_default, md_raw);
    }

    #[test]
    fn renders_revoked_terminal_reason() {
        let mut f = fixture();
        f.lifecycle.terminal_reason = TerminalReason::Revoked {
            by: RevokeActor::Operator,
            reason: "demo teardown".to_string(),
        };
        let md = render_receipt_markdown(&f, false);
        assert!(md.contains("revoked"), "expected 'revoked' in: {md}");
        assert!(md.contains("operator"), "expected 'operator' in: {md}");
        assert!(md.contains("demo teardown"), "expected reason in: {md}");
    }

    /// Invariant H10: `ember receipt export --latest --format md` must render
    /// a friendly-readable markdown receipt that (1) starts with the
    /// grant-receipt header, (2) carries the grant-summary line, and (3) stays
    /// under 100 lines for a *typical* session — not just the minimal fixture.
    /// These are the exact properties `scripts/agent/v030-rc-postflight.sh`
    /// asserts on the exported `latest-receipt.md`; pinning them here on the
    /// same `render_receipt_markdown` the CLI `export --format md` path
    /// dispatches to means a render regression fails on the recurring lane
    /// before it reaches the host postflight. (The live `--latest` daemon
    /// round-trip stays a T4 postflight concern; this is the deterministic
    /// no-daemon coverage.)
    #[test]
    fn h10_markdown_export_typical_session_under_100_lines_with_header_and_grant() {
        let mut f = fixture();
        // Grow the fixture to a representative session: a short approval chain
        // plus ~20 observed tool calls. The renderer emits one markdown row
        // per entry, so this exercises the realistic upper end of a "typical
        // session" receipt rather than the trivially small minimal fixture.
        f.approval_chain = vec![
            ApprovalEvent {
                at: 1714492800,
                actor: ApprovalActor::HumanCli,
                outcome: ApprovalOutcome::Approved,
                reason: Some("initial issuance".to_string()),
            },
            ApprovalEvent {
                at: 1714492850,
                actor: ApprovalActor::HumanDashboard,
                outcome: ApprovalOutcome::Approved,
                reason: Some("scope confirmed".to_string()),
            },
        ];
        f.actions_observed = (0..20u64)
            .map(|i| AuditEntry {
                at: 1714492900 + i,
                event: "tool_call_attempt".to_string(),
                action: Some("Bash".to_string()),
                resource: Some(format!("cmd-{i}")),
                outcome: "allowed".to_string(),
            })
            .collect();

        let md = render_receipt_markdown(&f, false);

        assert!(!md.trim().is_empty(), "markdown export must be non-empty");
        assert!(
            md.starts_with("# Grant Receipt "),
            "must start with the grant-receipt header, got first line: {}",
            md.lines().next().unwrap_or_default()
        );
        assert!(
            md.contains("\n**Grant:** "),
            "must carry the grant-summary line, got: {md}"
        );
        let lines = md.lines().count();
        assert!(
            lines < 100,
            "typical-session receipt rendered to {lines} lines (H10 bound: <100)"
        );
    }

    #[test]
    fn renders_exhausted_by_budget() {
        let mut f = fixture();
        f.lifecycle.terminal_reason = TerminalReason::ExhaustedByBudget {
            statement_sid: "SessionTokens".to_string() as StatementId,
            axis: BudgetAxis::Tokens,
        };
        let md = render_receipt_markdown(&f, false);
        assert!(
            md.contains("exhausted_by_budget"),
            "expected exhausted variant: {md}"
        );
        assert!(md.contains("tokens"), "expected axis: {md}");
    }
}
