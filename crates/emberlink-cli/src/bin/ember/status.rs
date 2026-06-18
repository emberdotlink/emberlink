use super::*;

pub(super) fn collect_status_overview(config: &DaemonConfig) -> Result<StatusOverview, String> {
    let runtime = DaemonRuntime::new(config.clone());
    let runtime_status = runtime.status().ok();
    let daemon_running = runtime_status.as_ref().is_some_and(|status| status.running);
    let (status_dispatch, live_daemon, summary) =
        run_status_summary(config, daemon_running).map_err(|e| e.to_string())?;

    let (vault_backend, vault_addr) = match config.credential_store.as_ref() {
        None => ("local".to_string(), "local-encrypted".to_string()),
        Some(cs) if cs.backend == "local" => ("local".to_string(), "local-encrypted".to_string()),
        Some(cs) => (
            cs.backend.clone(),
            cs.addr
                .clone()
                .unwrap_or_else(|| "<addr-not-configured>".to_string()),
        ),
    };
    let vault_session = if status_dispatch == StatusActionDispatch::DaemonRpc {
        match runtime_status {
            Some(ref status) if status.running => {
                run_vault_status(config).ok().map(|(_, status)| status)
            }
            _ => None,
        }
    } else {
        None
    };
    let banner = build_status_banner(
        config,
        runtime_status.as_ref(),
        live_daemon.as_ref(),
        vault_backend.clone(),
        vault_addr.clone(),
        vault_session.clone(),
    );
    let github_status = if status_dispatch == StatusActionDispatch::DaemonRpc {
        run_github_provider_status(config).ok()
    } else {
        None
    };
    let launcher_issue = detect_default_installed_launcher_issue();
    let current_launcher_lane = detect_current_launcher_lane();
    let managed_daemon_issue = detect_managed_daemon_issue(current_launcher_lane.as_ref());
    let delegation_template_issue =
        detect_delegation_template_install_issue(current_launcher_lane.as_ref());
    let ember_initialized = is_ember_initialized(config);
    let (daemon_running, daemon_pid, daemon_socket) =
        live_daemon_identity(runtime_status.as_ref(), live_daemon.as_ref());

    Ok(StatusOverview {
        dispatch: status_dispatch,
        banner,
        summary,
        github_status,
        ember_initialized,
        launcher_issue,
        current_launcher_lane,
        managed_daemon_issue,
        delegation_template_issue,
        daemon_running,
        daemon_pid,
        daemon_socket,
        vault_backend,
        vault_addr,
        vault_session,
    })
}

pub(super) fn status_counts_line(summary: &ember_daemon::infra::status::StatusSummary) -> String {
    let active_personas = summary
        .personas
        .iter()
        .filter(|persona| persona.status == "active")
        .count();
    let running_sandboxes = summary
        .sandboxes
        .iter()
        .filter(|sandbox| sandbox.status == "running")
        .count();
    format!(
        "{} active persona(s), {} grant(s), {} sandbox(es) running, {} approval(s) waiting.",
        active_personas,
        summary.grants.len(),
        running_sandboxes,
        summary.approvals.len()
    )
}

pub(super) fn detect_claude_runtime_auth_truth(
    summary: &ember_daemon::infra::status::StatusSummary,
) -> ClaudeRuntimeAuthTruth {
    let active_claude_grants: Vec<_> = summary
        .grants
        .iter()
        .filter(|grant| {
            grant.scope == CLAUDE_CODE_DEFAULT_SCOPE
                && summary_grant_has_live_lease(summary, &grant.id)
        })
        .collect();

    if let Some(grant) = active_claude_grants.iter().find(|grant| {
        claude_code_anthropic_runtime_credential_kind_from_name(&grant.credential_name)
            == Some(AnthropicRuntimeCredentialKind::OAuthToken)
    }) {
        return ClaudeRuntimeAuthTruth::GovernedOauth {
            grant_id: grant.id.clone(),
            credential_name: grant.credential_name.clone(),
        };
    }

    if let Some(grant) = active_claude_grants.iter().find(|grant| {
        claude_code_anthropic_runtime_credential_kind_from_name(&grant.credential_name)
            == Some(AnthropicRuntimeCredentialKind::ApiKey)
    }) {
        return ClaudeRuntimeAuthTruth::GovernedApiKeyFallback {
            grant_id: grant.id.clone(),
            credential_name: grant.credential_name.clone(),
        };
    }

    if let Some(grant) = active_claude_grants.first() {
        return ClaudeRuntimeAuthTruth::GovernedOther {
            grant_id: grant.id.clone(),
            credential_name: grant.credential_name.clone(),
        };
    }

    ClaudeRuntimeAuthTruth::NoActiveBrokeredGrant
}

pub(super) fn detect_codex_runtime_auth_truth(
    summary: &ember_daemon::infra::status::StatusSummary,
) -> CodexRuntimeAuthTruth {
    if let Some(grant) = summary.grants.iter().find(|grant| {
        grant.scope == CODEX_DEFAULT_SCOPE && summary_grant_has_live_lease(summary, &grant.id)
    }) {
        return CodexRuntimeAuthTruth::BrokeredResponsesProxyActive {
            grant_id: grant.id.clone(),
            credential_name: grant.credential_name.clone(),
        };
    }

    CodexRuntimeAuthTruth::NoActiveBrokeredSession
}

pub(super) fn detect_cursor_runtime_auth_truth(
    summary: &ember_daemon::infra::status::StatusSummary,
) -> CursorRuntimeAuthTruth {
    if let Some(grant) = cursor_launch_ready_grant(summary) {
        return CursorRuntimeAuthTruth::LaunchReadyGrant {
            grant_id: grant.id.clone(),
            credential_name: grant.credential_name.clone(),
        };
    }

    CursorRuntimeAuthTruth::NoLaunchReadyGrant
}

fn summary_grant_has_live_lease(
    summary: &ember_daemon::infra::status::StatusSummary,
    grant_id: &str,
) -> bool {
    summary
        .grant_live_leases
        .iter()
        .any(|live_grant_id| live_grant_id == grant_id)
}

fn summary_grant_supports_runtime_persona_delegation(
    grant: &ember_daemon::trust::grant::GrantInfo,
) -> bool {
    grant.max_delegation_depth.unwrap_or(0) > 0
}

fn active_persona_id_by_name<'a>(
    summary: &'a ember_daemon::infra::status::StatusSummary,
    name: &str,
) -> Option<&'a str> {
    summary
        .personas
        .iter()
        .find(|persona| persona.name == name && persona.status == "active")
        .map(|persona| persona.id.as_str())
}

fn cursor_launch_ready_grant(
    summary: &ember_daemon::infra::status::StatusSummary,
) -> Option<&ember_daemon::trust::grant::GrantInfo> {
    let cursor_persona_id = active_persona_id_by_name(summary, "cursor-default")?;
    summary.grants.iter().find(|grant| {
        grant.persona_id == cursor_persona_id
            && grant.status == "active"
            && grant.scope == CURSOR_DEFAULT_SCOPE
            && grant.credential_name == CURSOR_DEFAULT_SCOPE
            && summary_grant_supports_runtime_persona_delegation(grant)
            && summary_grant_has_live_lease(summary, &grant.id)
    })
}

pub(super) fn runtime_auth_section(
    summary: &ember_daemon::infra::status::StatusSummary,
) -> UiSection {
    let claude = detect_claude_runtime_auth_truth(summary);
    let codex = detect_codex_runtime_auth_truth(summary);
    let cursor = detect_cursor_runtime_auth_truth(summary);
    UiSection {
        heading: "Auth",
        lines: vec![
            claude.status_line(),
            codex.status_line(),
            cursor.status_line(),
        ],
    }
}

pub(super) fn status_json_value(overview: &StatusOverview) -> serde_json::Value {
    let claude_auth = detect_claude_runtime_auth_truth(&overview.summary);
    let codex_auth = detect_codex_runtime_auth_truth(&overview.summary);
    let cursor_auth = detect_cursor_runtime_auth_truth(&overview.summary);
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "daemon": {
            "running": overview.daemon_running,
            "pid": overview.daemon_pid,
            "socket": overview.daemon_socket,
        },
        "launcher_issue": launcher_issue_json(overview.launcher_issue.as_ref()),
        "managed_daemon_issue": managed_daemon_issue_json(overview.managed_daemon_issue.as_ref()),
        "delegation_template_issue": delegation_template_issue_json(overview.delegation_template_issue.as_ref()),
        "personas": overview.summary.personas.iter().filter(|persona| persona.status == "active").count(),
        "grants": { "active": overview.summary.grants.len(), "expired_sweep_interval_sec": 60 },
        "approvals": { "pending": overview.summary.approvals.len() },
        "standing_grants": overview.summary.standing_grants,
        "audit_events": overview.summary.audit_events_total,
        "quarantined": overview.summary.quarantined,
        "quarantine_authority": overview.summary.quarantine_authority,
        "auth": {
            "claude": claude_auth.json_value(),
            "codex": codex_auth.json_value(),
            "cursor": cursor_auth.json_value(),
        },
        "lanes": status_lanes_json(overview),
        "vault": {
            "backend": overview.vault_backend,
            "addr": overview.vault_addr,
            "session": overview.vault_session.as_ref().map(|status| serde_json::json!({
                "posture": status.posture,
                "unlocked": status.unlocked,
                "live_vault_attached": status.live_vault_attached,
                "session_pin_count": status.session_pin_count,
                "grace_window_secs": status.grace_window_secs,
                "grace_remaining_secs": status.grace_remaining_secs,
                "grace_lock_pending": status.grace_lock_pending,
                "grace_zero_due": status.grace_zero_due,
                "idle_secs": status.idle_secs,
                "idle_timeout_secs": status.idle_timeout_secs,
                "quiet_hours_start": status.quiet_hours_start,
                "quiet_hours_end": status.quiet_hours_end,
            })),
        },
    })
}

pub(super) fn primary_status_action(overview: &StatusOverview) -> PrimaryAction {
    let ember_cmd = ember_command_prefix_for_launcher_lane(overview.current_launcher_lane.as_ref());
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let doctor_cmd = format!("{ember_cmd} doctor");
    let github_setup_cmd = github_setup_command_with_ember_command(&ember_cmd);
    let vault_unlock_cmd = vault_unlock_command_with_ember_command(&ember_cmd);

    if !overview.ember_initialized {
        return PrimaryAction {
            kind: PrimaryActionKind::Start,
            command: format!("{ember_cmd} init --for claude"),
        };
    }

    if overview.launcher_issue.is_some() {
        return PrimaryAction {
            kind: PrimaryActionKind::FixNow,
            command: doctor_cmd,
        };
    }

    if overview.managed_daemon_issue.is_some() {
        return PrimaryAction {
            kind: PrimaryActionKind::FixNow,
            command: daemon_install_cmd,
        };
    }

    if overview.delegation_template_issue.is_some() {
        return PrimaryAction {
            kind: PrimaryActionKind::FixNow,
            command: doctor_cmd,
        };
    }

    match &overview.banner {
        DaemonStatusBanner::StalePid { .. } | DaemonStatusBanner::NotRunning => {
            return PrimaryAction {
                kind: PrimaryActionKind::FixNow,
                command: daemon_install_cmd,
            };
        }
        DaemonStatusBanner::Running { .. } => {}
    }

    if overview.summary.quarantined {
        return PrimaryAction {
            kind: PrimaryActionKind::FixNow,
            command: doctor_cmd,
        };
    }

    if vault_lane_requires_unlock(overview.vault_session.as_ref()) {
        return PrimaryAction {
            kind: PrimaryActionKind::FixNow,
            command: vault_unlock_cmd,
        };
    }

    if let Some(github_status) = overview.github_status.as_ref() {
        match github_status.lane.as_str() {
            "none" | "mock" | "pat" | "broken" => {
                return PrimaryAction {
                    kind: PrimaryActionKind::FixNow,
                    command: github_setup_cmd,
                };
            }
            _ => {}
        }
    }

    PrimaryAction {
        kind: PrimaryActionKind::Next,
        command: format!("{ember_cmd} claude"),
    }
}

/// A single onboarding lane's at-a-glance state for the `ember status`
/// checklist (F8: "can't see Claude ✓ Codex ✗ GitHub ⚠ anywhere"). Maps the
/// per-lane signals already collected in `StatusOverview` into the OSCAR
/// teardown §4 mock shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatusLaneMark {
    Ok,
    Warn,
    Fail,
}

impl StatusLaneMark {
    pub(super) fn glyph(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Warn => "⚠",
            Self::Fail => "✗",
        }
    }

    pub(super) fn json(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatusLane {
    pub(super) name: &'static str,
    pub(super) mark: StatusLaneMark,
    pub(super) detail: String,
    /// The one command that advances this lane, if it is not already ✓.
    pub(super) next_action: Option<String>,
}

/// Compute the per-lane onboarding checklist from the already-gathered
/// `StatusOverview`. Pure — no I/O — so the whole at-a-glance matrix is
/// unit-testable. Lane order matches OSCAR's mock plus the Cursor launcher
/// lane: Daemon, Presence, Claude, Codex, Cursor, GitHub, Shadow PATH.
pub(super) fn compute_status_lanes(overview: &StatusOverview) -> Vec<StatusLane> {
    let ember_cmd = ember_command_prefix_for_launcher_lane(overview.current_launcher_lane.as_ref());
    let daemon_install = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let github_setup = github_setup_command_with_ember_command(&ember_cmd);
    let vault_unlock = vault_unlock_command_with_ember_command(&ember_cmd);
    let doctor = format!("{ember_cmd} doctor");

    let mut lanes = Vec::with_capacity(7);

    // 1. Daemon ----------------------------------------------------------
    lanes.push(match &overview.banner {
        DaemonStatusBanner::Running { .. } if overview.managed_daemon_issue.is_some() => {
            StatusLane {
                name: "Daemon",
                mark: StatusLaneMark::Warn,
                detail: "running, but the managed daemon is older than this launcher".to_string(),
                next_action: Some(daemon_install.clone()),
            }
        }
        DaemonStatusBanner::Running { .. } => StatusLane {
            name: "Daemon",
            mark: StatusLaneMark::Ok,
            detail: "running (separate-uid)".to_string(),
            next_action: None,
        },
        DaemonStatusBanner::StalePid { .. } | DaemonStatusBanner::NotRunning => StatusLane {
            name: "Daemon",
            mark: StatusLaneMark::Fail,
            detail: "not running".to_string(),
            next_action: Some(daemon_install.clone()),
        },
    });

    // 2. Presence custody ------------------------------------------------
    lanes.push(match overview.vault_session.as_ref() {
        Some(session) if session.unlocked => StatusLane {
            name: "Presence",
            mark: StatusLaneMark::Ok,
            detail: "authority custody open".to_string(),
            next_action: None,
        },
        Some(_) => StatusLane {
            name: "Presence",
            mark: StatusLaneMark::Warn,
            detail: "custody locked — opens with one Touch ID at launch".to_string(),
            next_action: Some(vault_unlock.clone()),
        },
        None => StatusLane {
            name: "Presence",
            mark: StatusLaneMark::Warn,
            detail: "custody state unknown (daemon offline?)".to_string(),
            next_action: None,
        },
    });

    // 3. Claude model-auth ----------------------------------------------
    lanes.push(match detect_claude_runtime_auth_truth(&overview.summary) {
        ClaudeRuntimeAuthTruth::GovernedOauth { .. } => StatusLane {
            name: "Claude",
            mark: StatusLaneMark::Ok,
            detail: "governed plan lane".to_string(),
            next_action: None,
        },
        ClaudeRuntimeAuthTruth::GovernedApiKeyFallback { .. } => StatusLane {
            name: "Claude",
            mark: StatusLaneMark::Ok,
            detail: "governed API-key lane".to_string(),
            next_action: None,
        },
        ClaudeRuntimeAuthTruth::GovernedOther { .. } => StatusLane {
            name: "Claude",
            mark: StatusLaneMark::Warn,
            detail: "governed (non-standard credential)".to_string(),
            next_action: None,
        },
        ClaudeRuntimeAuthTruth::NoActiveBrokeredGrant => StatusLane {
            name: "Claude",
            mark: StatusLaneMark::Fail,
            detail: "no brokered runtime grant".to_string(),
            next_action: Some(format!("{ember_cmd} init --for claude")),
        },
    });

    // 4. Codex model-auth (symmetric with Claude per ADR 197 §9) --------
    lanes.push(match detect_codex_runtime_auth_truth(&overview.summary) {
        CodexRuntimeAuthTruth::BrokeredResponsesProxyActive { .. } => StatusLane {
            name: "Codex",
            mark: StatusLaneMark::Ok,
            detail: "governed plan lane".to_string(),
            next_action: None,
        },
        CodexRuntimeAuthTruth::NoActiveBrokeredSession => StatusLane {
            name: "Codex",
            mark: StatusLaneMark::Fail,
            detail: "no brokered runtime grant".to_string(),
            next_action: Some(format!("{ember_cmd} init --for codex")),
        },
    });

    // 5. Cursor launcher/session governance -----------------------------
    lanes.push(match detect_cursor_runtime_auth_truth(&overview.summary) {
        CursorRuntimeAuthTruth::LaunchReadyGrant { .. } => StatusLane {
            name: "Cursor",
            mark: StatusLaneMark::Ok,
            detail: "launch grant ready; model auth Cursor-owned".to_string(),
            next_action: None,
        },
        CursorRuntimeAuthTruth::NoLaunchReadyGrant => StatusLane {
            name: "Cursor",
            mark: StatusLaneMark::Fail,
            detail: "no launch-ready grant; model auth Cursor-owned".to_string(),
            next_action: Some(format!("{ember_cmd} init --for cursor")),
        },
    });

    // 6. GitHub ----------------------------------------------------------
    lanes.push(match overview.github_status.as_ref() {
        Some(github) => match github.lane.as_str() {
            "pat" => StatusLane {
                name: "GitHub",
                mark: StatusLaneMark::Warn,
                detail: "degraded PAT fallback".to_string(),
                next_action: Some(github_setup.clone()),
            },
            "none" | "mock" | "broken" => StatusLane {
                name: "GitHub",
                mark: StatusLaneMark::Fail,
                detail: github
                    .detail
                    .clone()
                    .unwrap_or_else(|| "App lane setup needed".to_string()),
                next_action: Some(github_setup.clone()),
            },
            _ => StatusLane {
                name: "GitHub",
                mark: StatusLaneMark::Ok,
                detail: "App lane ready".to_string(),
                next_action: None,
            },
        },
        None => StatusLane {
            name: "GitHub",
            mark: StatusLaneMark::Warn,
            detail: "status unknown (daemon offline?)".to_string(),
            next_action: None,
        },
    });

    // 7. Shadow PATH / launcher -----------------------------------------
    lanes.push(match overview.launcher_issue.as_ref() {
        Some(issue) => StatusLane {
            name: "Shadow PATH",
            mark: StatusLaneMark::Warn,
            detail: issue.detail(),
            next_action: Some(doctor.clone()),
        },
        None => StatusLane {
            name: "Shadow PATH",
            mark: StatusLaneMark::Ok,
            detail: "git/gh wrapped via managed shadow PATH".to_string(),
            next_action: None,
        },
    });

    lanes
}

/// JSON projection of the per-lane checklist — keeps `ember status --json`
/// grep/jq-scriptable for the same lane state the text checklist shows.
pub(super) fn status_lanes_json(overview: &StatusOverview) -> serde_json::Value {
    serde_json::Value::Array(
        compute_status_lanes(overview)
            .into_iter()
            .map(|lane| {
                serde_json::json!({
                    "name": lane.name,
                    "mark": lane.mark.json(),
                    "detail": lane.detail,
                    "next_action": lane.next_action,
                })
            })
            .collect(),
    )
}

/// Render the read-only per-lane onboarding checklist (F8 / proposal:
/// "`ember status` is the read-only per-lane checklist"). Shown beneath the
/// focused status card so the operator gets both the single next action and
/// every lane's state at a glance.
pub(super) fn render_status_lane_checklist(overview: &StatusOverview) -> String {
    let lanes = compute_status_lanes(overview);
    let mut out = String::new();
    let _ = writeln!(out, "{}", style_section_heading("Onboarding lanes"));
    for lane in &lanes {
        let mut row = format!("  {} {:<12} {}", lane.mark.glyph(), lane.name, lane.detail);
        if lane.mark != StatusLaneMark::Ok
            && let Some(action) = lane.next_action.as_ref()
        {
            let _ = write!(row, "  → {action}");
        }
        let _ = writeln!(out, "{row}");
    }
    let action = primary_status_action(overview);
    let label = match action.kind {
        PrimaryActionKind::Start | PrimaryActionKind::Next => "Next",
        PrimaryActionKind::FixNow => "Fix",
    };
    let _ = write!(out, "  → {label}: {}", action.command);
    out
}

pub(super) fn render_status_overview_text(overview: &StatusOverview) -> String {
    let ember_cmd = ember_command_prefix_for_launcher_lane(overview.current_launcher_lane.as_ref());
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let status_json_cmd = format!("{ember_cmd} status --json");
    let doctor_cmd = format!("{ember_cmd} doctor");
    let github_setup_cmd = github_setup_command_with_ember_command(&ember_cmd);
    let vault_unlock_cmd = vault_unlock_command_with_ember_command(&ember_cmd);
    let claude_cmd = format!("{ember_cmd} claude");
    let codex_cmd = format!("{ember_cmd} codex");
    let cursor_cmd = format!("{ember_cmd} cursor");
    let trust_list_cmd = format!("{ember_cmd} trust list");
    let counts = status_counts_line(&overview.summary);

    if !overview.ember_initialized {
        return render_compact_card(
            "Not set up yet",
            "Ember is not initialized on this machine. Start with one managed agent lane.",
            &[counts],
            &[
                UiSection {
                    heading: "Start",
                    lines: vec![format!(
                        "{}",
                        command_row(
                            format!("{ember_cmd} init --for claude"),
                            "Set up Claude as the first managed lane"
                        )
                    )],
                },
                UiSection {
                    heading: "Also",
                    lines: vec![
                        command_row(format!("{ember_cmd} status"), "Check current posture"),
                        command_row("ember explain init", "Read the deeper setup flow"),
                    ],
                },
            ],
        );
    }

    if let Some(issue) = overview.launcher_issue.as_ref() {
        return render_compact_card(
            "Needs attention",
            "The installed Ember launcher is out of sync with the runtime surface on this host.",
            &[issue.detail(), counts],
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        doctor_cmd.clone(),
                        "Diagnose the launcher and repair path",
                    )],
                },
                UiSection {
                    heading: "Learn",
                    lines: vec![
                        issue.repair_guidance(),
                        command_row("ember explain status", "Read the posture and repair model"),
                    ],
                },
            ],
        );
    }

    if let Some(issue) = overview.managed_daemon_issue.as_ref() {
        return render_compact_card(
            "Needs attention",
            "The current repo-built launcher is newer than the managed daemon on this host.",
            &[issue.detail(), counts],
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        daemon_install_cmd.clone(),
                        "Refresh the managed daemon",
                    )],
                },
                UiSection {
                    heading: "Diagnose",
                    lines: vec![command_row(
                        doctor_cmd.clone(),
                        "Open the deeper diagnosis lane",
                    )],
                },
            ],
        );
    }

    if let Some(issue) = overview.delegation_template_issue.as_ref() {
        return render_compact_card(
            "Needs attention",
            "The managed delegation-template bundle is incomplete on this machine.",
            &[issue.detail(), counts],
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        doctor_cmd.clone(),
                        "Open the deeper diagnosis lane",
                    )],
                },
                UiSection {
                    heading: "Learn",
                    lines: vec![
                        issue.repair_guidance(),
                        command_row("ember explain status", "Read the posture and repair model"),
                    ],
                },
            ],
        );
    }

    match &overview.banner {
        DaemonStatusBanner::StalePid { pid } => {
            return render_compact_card(
                "Needs attention",
                "The managed daemon is not running cleanly.",
                &[
                    format!("Stale daemon pid file still points at {pid}."),
                    "Daemon-backed features are unavailable; local summary only.".to_string(),
                    counts,
                ],
                &[
                    UiSection {
                        heading: "Fix now",
                        lines: vec![command_row(
                            daemon_install_cmd,
                            "Install or repair the managed daemon",
                        )],
                    },
                    UiSection {
                        heading: "Diagnose",
                        lines: vec![
                            command_row(doctor_cmd, "Open the deeper diagnosis lane"),
                            command_row(
                                status_json_cmd,
                                "Emit the machine-readable status contract",
                            ),
                        ],
                    },
                ],
            );
        }
        DaemonStatusBanner::NotRunning => {
            return render_compact_card(
                "Needs attention",
                "The managed daemon is not running.",
                &[
                    "Daemon-backed features are unavailable; local summary only.".to_string(),
                    counts,
                ],
                &[
                    UiSection {
                        heading: "Fix now",
                        lines: vec![command_row(
                            daemon_install_cmd,
                            "Install or repair the managed daemon",
                        )],
                    },
                    UiSection {
                        heading: "Diagnose",
                        lines: vec![
                            command_row(doctor_cmd, "Open the deeper diagnosis lane"),
                            command_row(
                                status_json_cmd,
                                "Emit the machine-readable status contract",
                            ),
                        ],
                    },
                ],
            );
        }
        DaemonStatusBanner::Running { .. } => {}
    }

    if overview.summary.quarantined {
        let authority = overview
            .summary
            .quarantine_authority
            .as_deref()
            .unwrap_or("unknown");
        return render_compact_card(
            "Running (quarantined)",
            "Audit-chain repair is required before write-class actions can continue.",
            &[format!("Quarantine authority: {authority}"), counts],
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        doctor_cmd,
                        "Open the deep diagnosis and repair router",
                    )],
                },
                UiSection {
                    heading: "Inspect",
                    lines: vec![
                        command_row(status_json_cmd, "Emit the machine-readable status contract"),
                        command_row(
                            format!("{ember_cmd} explain error E-DAEMON-NOT-INSTALLED"),
                            "Read the repair contract and recovery model",
                        ),
                    ],
                },
                runtime_auth_section(&overview.summary),
            ],
        );
    }

    if vault_lane_requires_unlock(overview.vault_session.as_ref()) {
        let mut details = vec![
            "Managed daemon running. The next launch needs operator presence on the daemon-managed vault lane.".to_string(),
            counts,
        ];
        if let Some(vault_session) = overview.vault_session.as_ref() {
            details.push(format!("Vault lane: {}", vault_session.summary_line()));
        }
        return render_compact_card(
            "Needs attention",
            "Operator presence is still locked on this machine.",
            &details,
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        vault_unlock_cmd,
                        "Unlock the managed vault lane",
                    )],
                },
                UiSection {
                    heading: "After unlock",
                    lines: vec![
                        command_row(claude_cmd, "Open the managed Claude session"),
                        command_row(codex_cmd, "Open the managed Codex session"),
                        command_row(cursor_cmd, "Open the Cursor host baseline path"),
                    ],
                },
                UiSection {
                    heading: "Also",
                    lines: vec![
                        command_row(doctor_cmd, "Open the deeper diagnosis lane"),
                        command_row(trust_list_cmd, "Confirm trust roots are readable"),
                    ],
                },
                runtime_auth_section(&overview.summary),
            ],
        );
    }

    if let Some(github_status) = overview.github_status.as_ref() {
        match github_status.lane.as_str() {
            "none" | "mock" => {
                return render_compact_card(
                    "Needs attention",
                    "GitHub App setup is not complete on this machine.",
                    &[
                        "GitHub-brokered actions will fail until the App lane is configured."
                            .to_string(),
                        counts,
                    ],
                    &[
                        UiSection {
                            heading: "Fix now",
                            lines: vec![command_row(
                                github_setup_cmd,
                                "Configure the GitHub App lane",
                            )],
                        },
                        UiSection {
                            heading: "Diagnose",
                            lines: vec![
                                command_row(doctor_cmd, "Open the deeper diagnosis lane"),
                                command_row(
                                    "ember explain github setup",
                                    "Read the setup contract",
                                ),
                            ],
                        },
                        runtime_auth_section(&overview.summary),
                    ],
                );
            }
            "pat" => {
                return render_compact_card(
                    "Needs attention",
                    "GitHub is still running on the degraded PAT fallback lane.",
                    &[
                        "The App lane is the preferred operator path for v0.3.0.".to_string(),
                        counts,
                    ],
                    &[
                        UiSection {
                            heading: "Fix now",
                            lines: vec![command_row(github_setup_cmd, "Upgrade to the App lane")],
                        },
                        UiSection {
                            heading: "Diagnose",
                            lines: vec![command_row(doctor_cmd, "Open the deeper diagnosis lane")],
                        },
                        runtime_auth_section(&overview.summary),
                    ],
                );
            }
            "broken" => {
                return render_compact_card(
                    "Needs attention",
                    "The local GitHub App configuration is present but broken.",
                    &[
                        github_status.detail.clone().unwrap_or_else(|| {
                            "Stored App credentials failed validation.".to_string()
                        }),
                        counts,
                    ],
                    &[
                        UiSection {
                            heading: "Fix now",
                            lines: vec![command_row(
                                github_setup_cmd,
                                "Repair or replace the App triple",
                            )],
                        },
                        UiSection {
                            heading: "Diagnose",
                            lines: vec![command_row(doctor_cmd, "Open the deeper diagnosis lane")],
                        },
                        runtime_auth_section(&overview.summary),
                    ],
                );
            }
            _ => {}
        }
    }

    let mut details = vec![
        "Managed daemon running. GitHub App ready. Launcher path ready.".to_string(),
        counts,
    ];
    if let DaemonStatusBanner::Running {
        pid,
        socket,
        dashboard,
        vault_backend,
        vault_addr,
        vault_session,
        ..
    } = &overview.banner
    {
        details.push(format!("Daemon: pid {pid} on {socket}"));
        details.push(format!("Dashboard: {dashboard}"));
        details.push(format!("Vault: {vault_backend} ({vault_addr})"));
        if let Some(vault_session) = vault_session.as_ref() {
            details.push(format!("Vault lane: {}", vault_session.summary_line()));
        }
    }
    render_compact_card(
        "Ready",
        "Launch through Ember, use your normal tools, then verify the receipt.",
        &details,
        &[
            UiSection {
                heading: "Next",
                lines: vec![command_row(claude_cmd, "Open the managed Claude session")],
            },
            runtime_auth_section(&overview.summary),
            UiSection {
                heading: "Also",
                lines: vec![
                    command_row(codex_cmd, "Open the managed Codex session"),
                    command_row(cursor_cmd, "Open the Cursor host baseline path"),
                    command_row(trust_list_cmd, "Confirm trust roots are readable"),
                    command_row("ember explain init", "Read the setup and launch story"),
                ],
            },
        ],
    )
}

pub(super) fn render_uninitialized_home_screen() -> String {
    render_compact_card(
        "Not set up yet",
        "Ember is not initialized on this machine. Start with one managed agent lane.",
        &[],
        &[
            UiSection {
                heading: "Start",
                lines: vec![command_row(
                    "ember init --for claude",
                    "Set up Claude as the first managed lane",
                )],
            },
            UiSection {
                heading: "Also",
                lines: vec![
                    command_row("ember status", "Check readiness and repair steps"),
                    command_row("ember codex", "Open Codex with Ember wiring"),
                    command_row("ember explain init", "Read the full setup flow"),
                ],
            },
            UiSection {
                heading: "Command map",
                lines: vec!["ember --help".to_string()],
            },
        ],
    )
}

pub(super) fn render_home_screen(config: &DaemonConfig) -> String {
    if !is_ember_initialized(config) {
        return render_uninitialized_home_screen();
    }

    match collect_status_overview(config) {
        Ok(overview) => {
            let theme = current_cli_render_theme();
            format!(
                "{}\n\n{}\n  {}",
                render_status_overview_text(&overview),
                style_section_heading("Command map"),
                theme.command("ember --help"),
            )
        }
        Err(error) => render_compact_card(
            "Needs attention",
            "Ember could not inspect the current machine posture.",
            &[error],
            &[
                UiSection {
                    heading: "Fix now",
                    lines: vec![command_row(
                        "ember doctor",
                        "Open the deeper diagnosis lane",
                    )],
                },
                UiSection {
                    heading: "Learn",
                    lines: vec![
                        command_row("ember explain status", "Read the posture model"),
                        "ember --help".to_string(),
                    ],
                },
            ],
        ),
    }
}

pub(super) fn doctor_summary_source_text(dispatch: StatusActionDispatch) -> &'static str {
    match dispatch {
        StatusActionDispatch::DaemonRpc => "daemon RPC (live socket)",
        StatusActionDispatch::LocalFallback => {
            "local fallback (daemon unavailable or socket missing)"
        }
    }
}

pub(super) fn doctor_daemon_probe_text(overview: &StatusOverview) -> String {
    match &overview.banner {
        DaemonStatusBanner::Running { .. } if overview.summary.quarantined => {
            "socket + status RPC reachable, but write-class methods are quarantined".to_string()
        }
        DaemonStatusBanner::Running { .. }
            if overview.dispatch == StatusActionDispatch::DaemonRpc =>
        {
            "socket + status RPC healthy".to_string()
        }
        DaemonStatusBanner::Running { .. } => {
            "PID file says running, but the status socket/RPC path was unavailable".to_string()
        }
        DaemonStatusBanner::StalePid { .. } => "stale PID file; daemon is not healthy".to_string(),
        DaemonStatusBanner::NotRunning => "not running".to_string(),
    }
}

pub(super) fn doctor_github_https_text(overview: &StatusOverview) -> String {
    match overview.github_status.as_ref().map(github_https_lane) {
        Some(GithubHttpsLane::ConfiguredApp) => "real App lane ready".to_string(),
        Some(GithubHttpsLane::ConfiguredPat) => "degraded PAT fallback active".to_string(),
        Some(GithubHttpsLane::ConfiguredMock) => "mock-only App registration".to_string(),
        Some(GithubHttpsLane::Broken) => "local App config is present but broken".to_string(),
        Some(GithubHttpsLane::NotConfigured) => "not configured".to_string(),
        None => "unavailable from this status path".to_string(),
    }
}

pub(super) fn render_doctor_text(overview: &StatusOverview) -> String {
    let theme = current_cli_render_theme();
    let ember_cmd = ember_command_prefix_for_launcher_lane(overview.current_launcher_lane.as_ref());
    let status_json_cmd = format!("{ember_cmd} status --json");
    let trust_list_cmd = format!("{ember_cmd} trust list");
    let audit_show_cmd = format!("{ember_cmd} audit show --limit 20");
    let audit_verify_cmd = format!("{ember_cmd} audit verify");
    let github_status_cmd = github_status_command_with_ember_command(&ember_cmd);
    let github_setup_cmd = github_setup_command_with_ember_command(&ember_cmd);
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let daemon_diagnose_cmd = format!("{ember_cmd} daemon diagnose");
    let vault_unlock_cmd = vault_unlock_command_with_ember_command(&ember_cmd);
    let claude_cmd = format!("{ember_cmd} claude");
    let codex_cmd = format!("{ember_cmd} codex");
    let cursor_cmd = format!("{ember_cmd} cursor");
    let receipt_export_cmd = format!("{ember_cmd} receipt export --latest --format md");
    let counts = status_counts_line(&overview.summary);

    let (card_title, card_summary) = if !overview.ember_initialized {
        (
            "Not set up yet",
            "Ember is not initialized on this machine.",
        )
    } else if overview.launcher_issue.is_some() {
        (
            "Needs attention",
            "The installed Ember launcher is out of sync with the runtime surface on this host.",
        )
    } else if overview.managed_daemon_issue.is_some() {
        (
            "Needs attention",
            "The current repo-built launcher is newer than the managed daemon on this host.",
        )
    } else if overview.delegation_template_issue.is_some() {
        (
            "Needs attention",
            "The managed delegation-template bundle is incomplete on this machine.",
        )
    } else {
        match &overview.banner {
            DaemonStatusBanner::StalePid { .. } => (
                "Needs attention",
                "The managed daemon is not running cleanly.",
            ),
            DaemonStatusBanner::NotRunning => {
                ("Needs attention", "The managed daemon is not running.")
            }
            DaemonStatusBanner::Running { .. } if overview.summary.quarantined => (
                "Running (quarantined)",
                "Audit-chain repair is required before write-class actions can continue.",
            ),
            DaemonStatusBanner::Running { .. }
                if vault_lane_requires_unlock(overview.vault_session.as_ref()) =>
            {
                (
                    "Needs attention",
                    "Operator presence is still locked on this machine.",
                )
            }
            DaemonStatusBanner::Running { .. } => match overview.github_status.as_ref() {
                Some(status) if matches!(status.lane.as_str(), "none" | "mock") => (
                    "Needs attention",
                    "GitHub App setup is not complete on this machine.",
                ),
                Some(status) if status.lane == "pat" => (
                    "Needs attention",
                    "GitHub is still running on the degraded PAT fallback lane.",
                ),
                Some(status) if status.lane == "broken" => (
                    "Needs attention",
                    "The local GitHub App configuration is present but broken.",
                ),
                _ => (
                    "Ready",
                    "Launch through Ember, use your normal tools, then verify the receipt.",
                ),
            },
        }
    };

    let mut details = vec![counts];
    match &overview.banner {
        DaemonStatusBanner::Running {
            pid,
            socket,
            dashboard,
            vault_backend,
            vault_addr,
            vault_session,
        } => {
            details.insert(
                0,
                if vault_lane_requires_unlock(overview.vault_session.as_ref()) {
                    "Managed daemon running. Unlock the managed vault lane before launching work."
                        .to_string()
                } else {
                    "Managed daemon running. GitHub posture and launcher state are summarized below."
                        .to_string()
                },
            );
            details.push(format!("Daemon: pid {pid} on {socket}"));
            details.push(format!("Dashboard: {dashboard}"));
            details.push(format!("Vault: {vault_backend} ({vault_addr})"));
            if let Some(vault_session) = vault_session.as_ref() {
                details.push(format!("Vault lane: {}", vault_session.summary_line()));
            }
        }
        DaemonStatusBanner::StalePid { pid } => {
            details.insert(0, format!("Stale daemon pid file still points at {pid}."));
        }
        DaemonStatusBanner::NotRunning => {
            details.insert(
                0,
                "Daemon-backed features are unavailable until the managed daemon comes back."
                    .to_string(),
            );
        }
    }

    if let Some(issue) = overview.launcher_issue.as_ref() {
        details.push(issue.detail());
    }
    if let Some(issue) = overview.managed_daemon_issue.as_ref() {
        details.push(issue.detail());
    }
    if let Some(issue) = overview.delegation_template_issue.as_ref() {
        details.push(issue.detail());
    }
    if let Some(detail) = overview
        .github_status
        .as_ref()
        .and_then(|status| status.detail.as_ref())
    {
        details.push(format!("GitHub detail: {detail}"));
    }

    let mut sections = Vec::new();
    if !overview.ember_initialized {
        sections.push(UiSection {
            heading: "Do this",
            lines: vec![command_row(
                format!("{ember_cmd} init --for claude"),
                "Set up Claude as the first managed lane",
            )],
        });
    } else if overview.launcher_issue.is_some() {
        sections.push(UiSection {
            heading: "Do this",
            lines: vec![
                "Repair the installed host launcher before trusting this runtime surface."
                    .to_string(),
                command_row(
                    "ember explain status",
                    "Review the launcher boundary and repair model",
                ),
            ],
        });
    } else if overview.managed_daemon_issue.is_some() {
        sections.push(UiSection {
            heading: "Do this",
            lines: vec![command_row(
                daemon_install_cmd.clone(),
                "Refresh the managed daemon to match this launcher",
            )],
        });
        sections.push(UiSection {
            heading: "Then",
            lines: vec![command_row(
                format!("{ember_cmd} status"),
                "Re-check posture after the managed daemon refresh",
            )],
        });
    } else if let Some(issue) = overview.delegation_template_issue.as_ref() {
        sections.push(UiSection {
            heading: "Do this",
            lines: vec![
                issue.repair_guidance(),
                command_row(
                    "ember explain status",
                    "Review the launcher boundary and repair model",
                ),
            ],
        });
        sections.push(UiSection {
            heading: "Then",
            lines: vec![command_row(
                format!("{ember_cmd} status"),
                "Re-check posture after the managed bundle is restored",
            )],
        });
    } else {
        match &overview.banner {
            DaemonStatusBanner::StalePid { .. } | DaemonStatusBanner::NotRunning => {
                sections.push(UiSection {
                    heading: "Do this",
                    lines: vec![command_row(
                        daemon_install_cmd.clone(),
                        "Install or repair the managed daemon",
                    )],
                });
                sections.push(UiSection {
                    heading: "Then",
                    lines: vec![command_row(
                        daemon_diagnose_cmd,
                        "Inspect the daemon branch if it still refuses to start",
                    )],
                });
            }
            DaemonStatusBanner::Running { .. } if overview.summary.quarantined => {
                sections.push(UiSection {
                    heading: "Do this",
                    lines: vec![command_row(
                        audit_verify_cmd,
                        "Inspect the raw audit-chain state during repair",
                    )],
                });
            }
            DaemonStatusBanner::Running { .. }
                if vault_lane_requires_unlock(overview.vault_session.as_ref()) =>
            {
                sections.push(UiSection {
                    heading: "Do this",
                    lines: vec![command_row(
                        vault_unlock_cmd,
                        "Restore operator presence on the managed vault lane",
                    )],
                });
                sections.push(UiSection {
                    heading: "After unlock",
                    lines: vec![
                        command_row(claude_cmd.clone(), "Open the managed Claude session"),
                        command_row(codex_cmd, "Open the managed Codex session"),
                        command_row(cursor_cmd.clone(), "Open the Cursor host baseline path"),
                    ],
                });
            }
            DaemonStatusBanner::Running { .. } => match overview.github_status.as_ref() {
                Some(status)
                    if matches!(status.lane.as_str(), "none" | "mock" | "pat" | "broken") =>
                {
                    sections.push(UiSection {
                        heading: "Do this",
                        lines: vec![command_row(
                            github_setup_cmd,
                            "Repair or complete the GitHub App lane",
                        )],
                    });
                    sections.push(UiSection {
                        heading: "Then",
                        lines: vec![command_row(
                            github_status_cmd,
                            "Confirm the GitHub App lane is ready",
                        )],
                    });
                }
                _ => {
                    sections.push(UiSection {
                        heading: "Next",
                        lines: vec![command_row(
                            claude_cmd.clone(),
                            "Open the managed Claude session",
                        )],
                    });
                    sections.push(UiSection {
                        heading: "Also",
                        lines: vec![command_row(
                            cursor_cmd.clone(),
                            "Open the Cursor host baseline path",
                        )],
                    });
                }
            },
        }
    }

    let mut diagnosis_lines = vec![format!(
        "Summary source: {}",
        doctor_summary_source_text(overview.dispatch)
    )];
    if let Some(lane) = overview.current_launcher_lane.as_ref() {
        diagnosis_lines.push(format!("Current lane: {}", lane.human_detail()));
    }
    diagnosis_lines.push(format!(
        "Daemon probe: {}",
        doctor_daemon_probe_text(overview)
    ));
    diagnosis_lines.push(format!(
        "GitHub HTTPS: {}",
        doctor_github_https_text(overview)
    ));
    if let Some(authority) = overview.summary.quarantine_authority.as_deref() {
        diagnosis_lines.push(format!("Quarantine: {authority}"));
    }
    sections.push(UiSection {
        heading: "Diagnosis",
        lines: diagnosis_lines,
    });
    sections.push(runtime_auth_section(&overview.summary));

    let mut inspect_lines = vec![command_row(
        status_json_cmd,
        "Emit the machine-readable posture contract",
    )];
    if matches!(
        overview.github_status.as_ref().map(github_https_lane),
        Some(GithubHttpsLane::ConfiguredApp)
    ) && !vault_lane_requires_unlock(overview.vault_session.as_ref())
    {
        inspect_lines.push(command_row(
            receipt_export_cmd,
            "Export the latest signed receipt after the first brokered action",
        ));
    }
    inspect_lines.push(command_row(
        trust_list_cmd,
        "Confirm trust roots are readable",
    ));
    inspect_lines.push(command_row(
        audit_show_cmd,
        "Inspect recent operator-visible events",
    ));
    sections.push(UiSection {
        heading: "Inspect",
        lines: inspect_lines,
    });

    let mut out = String::new();
    let _ = writeln!(out, "{}", theme.title("Doctor", None));
    let _ = writeln!(
        out,
        "Deep diagnosis and repair guidance for the current machine."
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        render_compact_card(card_title, card_summary, &details, &sections)
    );
    out.trim_end().to_string()
}

#[cfg(test)]
pub(super) fn render_status_text(
    banner: DaemonStatusBanner,
    summary: &ember_daemon::infra::status::StatusSummary,
    launcher_issue: Option<&InstalledLauncherIssue>,
    current_launcher_lane: Option<&CurrentLauncherLane>,
    managed_daemon_issue: Option<&ManagedDaemonIssue>,
) -> String {
    let personas = &summary.personas;
    let active = personas.iter().filter(|p| p.status == "active").count();
    let revoked = personas.iter().filter(|p| p.status == "revoked").count();
    let grants = &summary.grants;
    let sandboxes = &summary.sandboxes;
    let running = sandboxes.iter().filter(|s| s.status == "running").count();
    let approvals = &summary.approvals;
    let entries = &summary.recent_activity;
    let total = summary.audit_events_total;
    let ember_cmd = ember_command_prefix_for_launcher_lane(current_launcher_lane);
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let doctor_cmd = format!("{ember_cmd} doctor");

    let mut out = String::new();
    match banner {
        DaemonStatusBanner::Running {
            pid,
            socket,
            dashboard,
            vault_backend,
            vault_addr,
            vault_session,
        } => {
            let _ = writeln!(out, "DAEMON             running (PID {pid})");
            let _ = writeln!(out, "  Socket:    {socket}");
            let _ = writeln!(out, "  Dashboard: {dashboard}");
            let _ = writeln!(out, "  Vault:     {vault_backend} ({vault_addr})");
            if let Some(vault_session) = &vault_session {
                let _ = writeln!(out, "  Vault lane: {}", vault_session.summary_line());
            }
            if summary.quarantined {
                let authority = summary.quarantine_authority.as_deref().unwrap_or("unknown");
                let _ = writeln!(out, "  Quarantine: {authority}");
                let _ = writeln!(
                    out,
                    "  Impact:     write-class commands are blocked until audit repair"
                );
                let _ = writeln!(out, "  Repair:     {doctor_cmd}");
            }
            push_status_launcher_issue_note(&mut out, launcher_issue);
            push_status_managed_daemon_issue_note(&mut out, managed_daemon_issue);
            let _ = writeln!(out);

            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            for p in personas {
                let st = if p.status == "revoked" {
                    "revoked"
                } else {
                    "active "
                };
                let _ = writeln!(out, "  {:<18} {}  {}", p.name, st, p.id);
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            for g in grants {
                let exp = g.expires_at.as_deref().unwrap_or("never");
                let _ = writeln!(
                    out,
                    "  {} {} → {} ({}) expires {}",
                    g.id, g.persona_id, g.credential_name, g.scope, exp
                );
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "SANDBOXES          {} running", running);
            for s in sandboxes.iter().filter(|s| s.status == "running") {
                let cid = s.container_id.as_deref().unwrap_or("-");
                let _ = writeln!(out, "  {} {} container={}", s.id, s.name, cid);
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            for r in approvals {
                let _ = writeln!(
                    out,
                    "  {} {} → {} ({}) [{}]",
                    r.id, r.persona_id, r.credential_name, r.action, r.risk_level
                );
            }
            let _ = writeln!(out);

            let _ = writeln!(out, "RECENT ACTIVITY    (last {})", entries.len());
            for e in entries {
                let ag = e.agent_id.as_deref().unwrap_or("-");
                let cr = e.credential.as_deref().unwrap_or("-");
                let _ = writeln!(
                    out,
                    "  {} {} {} {} {}",
                    e.timestamp, ag, e.action, cr, e.outcome
                );
            }
            let _ = writeln!(out);
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
        DaemonStatusBanner::StalePid { pid } => {
            let _ = writeln!(out, "DAEMON             stopped (stale PID {pid})");
            let _ = writeln!(out, "  Repair:    {daemon_install_cmd}");
            let _ = writeln!(
                out,
                "  Note:      daemon-backed features are unavailable; showing local store summary only"
            );
            push_status_launcher_issue_note(&mut out, launcher_issue);
            push_status_managed_daemon_issue_note(&mut out, managed_daemon_issue);
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            let _ = writeln!(out, "SANDBOXES          {} running", running);
            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            let _ = writeln!(out, "RECENT ACTIVITY    {} entries", entries.len());
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
        DaemonStatusBanner::NotRunning => {
            let _ = writeln!(out, "DAEMON             not running");
            let _ = writeln!(out, "  Repair:    {daemon_install_cmd}");
            let _ = writeln!(
                out,
                "  Note:      daemon-backed features are unavailable; showing local store summary only"
            );
            push_status_launcher_issue_note(&mut out, launcher_issue);
            push_status_managed_daemon_issue_note(&mut out, managed_daemon_issue);
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "PERSONAS           {} active, {} revoked",
                active, revoked
            );
            let _ = writeln!(out, "ACTIVE GRANTS      {}", grants.len());
            let _ = writeln!(out, "SANDBOXES          {} running", running);
            let _ = writeln!(out, "PENDING APPROVALS  {}", approvals.len());
            let _ = writeln!(out, "RECENT ACTIVITY    {} entries", entries.len());
            let _ = write!(out, "AUDIT TOTAL        {} events", total);
        }
    }
    out
}

#[cfg(test)]
pub(super) fn push_status_launcher_issue_note(
    out: &mut String,
    launcher_issue: Option<&InstalledLauncherIssue>,
) {
    if let Some(issue) = launcher_issue {
        let _ = writeln!(out, "  Host launcher: {}", issue.detail());
        let _ = writeln!(out, "  Attention:     {}", issue.repair_guidance());
    }
}

#[cfg(test)]
pub(super) fn push_status_managed_daemon_issue_note(
    out: &mut String,
    managed_daemon_issue: Option<&ManagedDaemonIssue>,
) {
    if let Some(issue) = managed_daemon_issue {
        let _ = writeln!(out, "  Host daemon:   {}", issue.detail());
        let _ = writeln!(out, "  Attention:     {}", issue.repair_guidance());
    }
}

// Troubleshoot-text rendering aggregates many independent status inputs — structurally many params.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_status_troubleshoot_text(
    banner: &DaemonStatusBanner,
    summary: &ember_daemon::infra::status::StatusSummary,
    dispatch: StatusActionDispatch,
    github_status: Option<&GithubProviderStatusView>,
    ember_initialized: bool,
    launcher_issue: Option<&InstalledLauncherIssue>,
    current_launcher_lane: Option<&CurrentLauncherLane>,
    managed_daemon_issue: Option<&ManagedDaemonIssue>,
    delegation_template_issue: Option<&DelegationTemplateInstallIssue>,
) -> String {
    let mut out = String::new();
    let ember_cmd = ember_command_prefix_for_launcher_lane(current_launcher_lane);
    let status_cmd = format!("{ember_cmd} status");
    let doctor_cmd = format!("{ember_cmd} doctor");
    let audit_verify_cmd = format!("{ember_cmd} audit verify");
    let github_status_cmd = github_status_command_with_ember_command(&ember_cmd);
    let github_setup_cmd = github_setup_command_with_ember_command(&ember_cmd);
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(&ember_cmd);
    let daemon_diagnose_cmd = format!("{ember_cmd} daemon diagnose");
    let trust_list_cmd = format!("{ember_cmd} trust list");
    let audit_show_cmd = format!("{ember_cmd} audit show --limit 20");
    let init_claude_cmd =
        init_command_with_ember_command(&ember_cmd, Some(OnboardingTarget::Claude));
    let claude_cmd = format!("{ember_cmd} claude");
    let receipt_export_cmd = format!("{ember_cmd} receipt export --latest --format md");
    let summary_source = match dispatch {
        StatusActionDispatch::DaemonRpc => "daemon RPC (live socket)",
        StatusActionDispatch::LocalFallback => {
            "local fallback (daemon unavailable or socket missing)"
        }
    };

    let _ = writeln!(out, "{}", style_section_heading("Troubleshoot"));
    let _ = writeln!(out, "  Summary source: {summary_source}");
    if let Some(lane) = current_launcher_lane {
        let _ = writeln!(out, "  Current lane:   {}", lane.detail());
    }
    if let Some(issue) = managed_daemon_issue {
        let _ = writeln!(out, "  Managed drift:  {}", issue.detail());
        let _ = writeln!(out, "  Attention:      {}", issue.repair_guidance());
    }
    if let Some(issue) = delegation_template_issue {
        let _ = writeln!(out, "  Delegation bundle: {}", issue.detail());
        let _ = writeln!(out, "  Attention:       {}", issue.repair_guidance());
    }

    match banner {
        DaemonStatusBanner::Running { .. } => {
            if dispatch == StatusActionDispatch::DaemonRpc {
                if summary.quarantined {
                    let _ = writeln!(
                        out,
                        "  Daemon probe:   socket + status RPC reachable, but write-class methods are quarantined"
                    );
                    if let Some(authority) = summary.quarantine_authority.as_deref() {
                        let _ = writeln!(out, "  Quarantine:     {authority}");
                    }
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(out, "  1. Run `{doctor_cmd}` to diagnose the repair path.");
                    let _ = writeln!(
                        out,
                        "  2. Use `{audit_verify_cmd}` if you need the raw audit-chain view during repair."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Repair the daemon and audit chain before retrying write-class commands."
                    );
                    let _ = writeln!(
                        out,
                        "  4. Re-run `{status_cmd}` to confirm quarantine is gone."
                    );
                    let _ = writeln!(
                        out,
                        "  5. Only then continue with `{github_status_cmd}` and `{claude_cmd}`."
                    );
                    return out;
                }
                let _ = writeln!(out, "  Daemon probe:   socket + status RPC healthy");
            } else {
                let _ = writeln!(
                    out,
                    "  Daemon probe:   PID file says running, but the status socket/RPC path was unavailable"
                );
            }

            if let Some(issue) = delegation_template_issue {
                let _ = writeln!(out);
                let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                let _ = writeln!(out, "  1. {}", issue.repair_guidance());
                let _ = writeln!(
                    out,
                    "  2. Run `{status_cmd}` to confirm the managed bundle is restored."
                );
                let _ = writeln!(
                    out,
                    "  3. Run `{doctor_cmd}` if launcher or daemon posture still looks wrong after reinstall."
                );
                let _ = writeln!(
                    out,
                    "  4. After repair, continue with `{github_status_cmd}` and `{claude_cmd}`."
                );
                return out;
            }

            match github_status.map(github_https_lane) {
                Some(GithubHttpsLane::ConfiguredApp) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   real App lane ready");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(
                        out,
                        "  1. Launch `{claude_cmd}` for the canonical friendly session path."
                    );
                    let _ = writeln!(
                        out,
                        "  2. After the first brokered action, run `{receipt_export_cmd}`."
                    );
                }
                Some(GithubHttpsLane::ConfiguredPat) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   degraded PAT fallback active");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(
                        out,
                        "  1. Run `{github_setup_cmd}` to upgrade from PAT fallback to the App lane."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Until then, gh/git will attribute through your GitHub identity."
                    );
                    let _ = writeln!(
                        out,
                        "  3. If you intentionally stay on this degraded lane, verify it with `{receipt_export_cmd}` after the first brokered action."
                    );
                }
                Some(GithubHttpsLane::ConfiguredMock) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   mock-only App registration");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(
                        out,
                        "  1. Run `{github_setup_cmd}` with a real App credential triple."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Have these ready: private key PEM, App ID, installation URL or ID, and App slug."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Then run `{github_status_cmd}` to confirm the App lane is ready."
                    );
                }
                Some(GithubHttpsLane::Broken) => {
                    let _ = writeln!(
                        out,
                        "  GitHub HTTPS:   local App config is present but broken"
                    );
                    if let Some(detail) = github_status.and_then(|status| status.detail.as_deref())
                    {
                        let _ = writeln!(out, "  GitHub detail:  {detail}");
                    }
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(
                        out,
                        "  1. Run `{github_setup_cmd}` to repair or replace the local App credential triple."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Then run `{github_status_cmd}` to confirm the App lane is ready."
                    );
                }
                Some(GithubHttpsLane::NotConfigured) => {
                    let _ = writeln!(out, "  GitHub HTTPS:   not configured");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
                    let _ = writeln!(
                        out,
                        "  1. Run `{github_setup_cmd}` to register local App credentials for the HTTPS/App lane."
                    );
                    let _ = writeln!(
                        out,
                        "  2. Have these ready: private key PEM, App ID, installation URL or ID, and App slug."
                    );
                    let _ = writeln!(
                        out,
                        "  3. Then run `{github_status_cmd}` to confirm the App lane is ready."
                    );
                }
                None => {
                    let _ = writeln!(out, "  GitHub HTTPS:   unavailable from this status path");
                    let _ = writeln!(out);
                    let _ = writeln!(out, "Next steps:");
                    let _ = writeln!(out, "  1. Run `{github_status_cmd}` for GitHub posture.");
                }
            }

            if dispatch == StatusActionDispatch::LocalFallback {
                let _ = writeln!(
                    out,
                    "  3. Run `{daemon_diagnose_cmd}` if the daemon should be up but the socket still does not answer."
                );
            }
            let _ = writeln!(
                out,
                "  4. Run `{trust_list_cmd}` to confirm trust roots are readable."
            );
            let _ = writeln!(
                out,
                "  5. Run `{audit_show_cmd}` for recent operator-visible events."
            );
        }
        DaemonStatusBanner::StalePid { .. } => {
            let _ = writeln!(
                out,
                "  Daemon probe:   stale PID file; daemon is not healthy"
            );
            let _ = writeln!(
                out,
                "  Local state:    {}",
                if ember_initialized {
                    "daemon.db present"
                } else {
                    "daemon.db missing"
                }
            );
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  Install path:   {}", issue.detail());
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
            let mut next_step = 1;
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
            }
            if let Some(issue) = delegation_template_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{status_cmd}` to confirm the managed bundle is restored."
                );
                next_step += 1;
            }
            let _ = writeln!(
                out,
                "  {next_step}. Run `{daemon_install_cmd}` to repair the managed separate-uid daemon."
            );
            next_step += 1;
            if ember_initialized {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{daemon_diagnose_cmd}` before deeper surgery; this usually means state exists but the daemon did not come back cleanly."
                );
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Once the daemon is back, run `{github_status_cmd}` before launching Claude Code."
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{init_claude_cmd}` after the daemon is back."
                );
            }
        }
        DaemonStatusBanner::NotRunning => {
            let _ = writeln!(out, "  Daemon probe:   not running");
            let _ = writeln!(
                out,
                "  Local state:    {}",
                if ember_initialized {
                    "daemon.db present"
                } else {
                    "daemon.db missing"
                }
            );
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  Install path:   {}", issue.detail());
            }
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", style_section_heading("Next steps:"));
            let mut next_step = 1;
            if let Some(issue) = launcher_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
            }
            if let Some(issue) = delegation_template_issue {
                let _ = writeln!(out, "  {next_step}. {}", issue.repair_guidance());
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{status_cmd}` to confirm the managed bundle is restored."
                );
                next_step += 1;
            }
            let _ = writeln!(
                out,
                "  {next_step}. Run `{daemon_install_cmd}` to install or repair the managed separate-uid daemon."
            );
            next_step += 1;
            if ember_initialized {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{daemon_diagnose_cmd}` if the daemon still refuses to start; this preserves the MEK/state branch instead of reinstalling blindly."
                );
                next_step += 1;
                let _ = writeln!(
                    out,
                    "  {next_step}. Once the daemon is back, run `{github_status_cmd}` before launching Claude Code."
                );
            } else {
                let _ = writeln!(
                    out,
                    "  {next_step}. Run `{init_claude_cmd}` after the daemon is up."
                );
            }
        }
    }

    // ADR 161 §Component 3 — append the F-code symptom-check appendix.
    // The appendix runs every registered `Symptom` in `recover::symptoms`
    // against a `HealthSnapshot` derived from the bounded signals this
    // function already holds, so the operator gets one [verdict] line
    // per F-code with the canonical recovery command underneath.
    let snapshot = build_troubleshoot_snapshot(
        banner,
        summary,
        dispatch,
        github_status,
        ember_initialized,
    );
    let _ = writeln!(out);
    out.push_str(&emberlink_cli::status::troubleshoot::render_troubleshoot_appendix(
        &snapshot, &ember_cmd,
    ));

    out
}

/// Translate the bounded set of signals `render_status_troubleshoot_text`
/// already holds into the `HealthSnapshot` shape the F-code symptom
/// registry consumes. Signals the bin-level renderer does not measure
/// stay `None`; the per-F-code check functions then surface them as
/// `warn` per ADR 161 R4 (conservative on uncertain).
fn build_troubleshoot_snapshot(
    banner: &DaemonStatusBanner,
    summary: &ember_daemon::infra::status::StatusSummary,
    dispatch: StatusActionDispatch,
    github_status: Option<&GithubProviderStatusView>,
    ember_initialized: bool,
) -> emberlink_cli::recover::symptoms::HealthSnapshot {
    use emberlink_cli::status::troubleshoot::{TroubleshootProbes, snapshot_from_probes};

    // Daemon reachability: `Running` with `DaemonRpc` dispatch = the
    // socket+RPC path is live. `Running` with `LocalFallback` = PID file
    // says running but the socket did not answer; treat as unreachable.
    // `StalePid` / `NotRunning` = unreachable.
    let daemon_socket_reachable = Some(matches!(
        (banner, dispatch),
        (DaemonStatusBanner::Running { .. }, StatusActionDispatch::DaemonRpc)
    ));

    // Stale socket: PID file claims running AND we fell back to local —
    // the canonical stale-socket symptom (F-DAEMON-2). Otherwise we know
    // it is not stale.
    let daemon_socket_stale = Some(matches!(
        (banner, dispatch),
        (
            DaemonStatusBanner::Running { .. } | DaemonStatusBanner::StalePid { .. },
            StatusActionDispatch::LocalFallback
        )
    ));

    // DB health: when the daemon is up, infer healthy. Otherwise we did
    // not run integrity-check this session; leave `None` → warn.
    let daemon_db_healthy = match banner {
        DaemonStatusBanner::Running { .. } if dispatch == StatusActionDispatch::DaemonRpc => {
            Some(true)
        }
        _ => None,
    };

    // Shadow path: probe the canonical location at render time. The
    // appendix derives `shadow_path_present` from the path's existence
    // automatically.
    let shadow_path = dirs_next::home_dir().map(|home| home.join(".ember").join("shadow"));

    // GitHub broker credential: a `Broken` lane signals broker.resolve
    // saw a credential failure recently. `ConfiguredApp` / `ConfiguredPat`
    // / `ConfiguredMock` are OK from a credential-validity view (the App
    // and PAT lanes authenticated upstream; mock-only is its own F-code).
    let broker_github_credential_invalid = github_status.map(|gs| {
        matches!(github_https_lane(gs), GithubHttpsLane::Broken)
    });

    // Mock broker trust on the prod daemon — captured in the daemon
    // status summary when it is exposed; today the StatusSummary does
    // not expose a mock-only flag, so leave `None` (warn) and let the
    // check fall back to conservative.
    let mock_brokers_trusted: Option<bool> = None;
    let daemon_lane_is_prod: Option<bool> = None;

    // Audit store usage — not surfaced through this renderer today;
    // `summary.quarantined` is the proxy signal we DO have, but it
    // overlaps with multiple F-codes. Leave `None` so the symptom
    // returns `warn` instead of guessing the wrong root cause.
    let audit_store_usage_ratio: Option<f32> = None;

    // Install manifest signature: when the daemon refuses to start
    // because of a signature mismatch, it reports through the banner.
    // We do not surface that distinct error here, so leave `None`.
    let install_manifest_signature_valid: Option<bool> = match banner {
        DaemonStatusBanner::Running { .. } => Some(true),
        _ => None,
    };

    // `ember_initialized` + `summary.quarantined` are already surfaced
    // in the next-steps section above; the per-F-code checks would only
    // duplicate them. Keep the appendix focused on the bounded set.
    let _ = (ember_initialized, summary);

    snapshot_from_probes(TroubleshootProbes {
        daemon_socket_reachable,
        daemon_socket_stale,
        daemon_db_healthy,
        shadow_path,
        broker_github_credential_invalid,
        audit_store_usage_ratio,
        mock_brokers_trusted,
        daemon_lane_is_prod,
        install_manifest_signature_valid,
    })
}

/// Independent socket diagnostic that runs when `collect_status_overview` fails.
/// Probes the socket file, permissions, group membership, and raw connectivity
/// without going through the full status RPC — so `ember doctor` can report
/// useful information even when the daemon rejects the connection.
pub(super) fn diagnose_daemon_socket(config: &DaemonConfig) -> String {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixStream;

    let mut out = String::new();
    let socket_path = config.socket_dir.join("daemon.sock");
    let ember_cmd = ember_command_prefix_for_current_launcher();

    let _ = writeln!(out, "{}", style_section_heading("Socket diagnostics"));
    let _ = writeln!(out, "  Path: {}", socket_path.display());

    let meta = match std::fs::metadata(&socket_path) {
        Ok(m) => {
            let mode = m.mode();
            let uid = m.uid();
            let gid = m.gid();
            let _ = writeln!(out, "  Exists: yes");
            let _ = writeln!(
                out,
                "  Mode: {:04o}  Owner UID: {}  GID: {}",
                mode & 0o7777,
                uid,
                gid
            );
            Some((mode, uid, gid))
        }
        Err(e) => {
            let _ = writeln!(out, "  Exists: NO — {e}");
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  The socket file is missing. The daemon may not be running or \
                 the socket directory may be wrong."
            );
            let _ = writeln!(
                out,
                "  Repair: `sudo {ember_cmd} daemon install` to (re)install the managed daemon."
            );
            None
        }
    };

    let my_uid = unsafe { libc::getuid() };
    let my_gid = unsafe { libc::getgid() };
    let _ = writeln!(out, "  Caller UID: {}  Primary GID: {}", my_uid, my_gid);

    let in_ember_clients = is_user_in_ember_clients_group(my_uid);
    let _ = writeln!(
        out,
        "  In `ember-clients`: {}",
        if in_ember_clients { "yes" } else { "NO" }
    );

    match UnixStream::connect(&socket_path) {
        Ok(_stream) => {
            let _ = writeln!(out, "  Raw connect: success");
        }
        Err(e) => {
            let _ = writeln!(out, "  Raw connect: FAILED — {e}");
        }
    }

    let _ = writeln!(out);
    if meta.is_none() {
        // Already printed guidance above.
    } else if !in_ember_clients {
        let _ = writeln!(out, "{}", style_section_heading("Diagnosis"));
        let _ = writeln!(
            out,
            "  This user (uid {my_uid}) is NOT a member of `ember-clients`. \
             The daemon socket requires group membership for access."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "  Fix:");
        let _ = writeln!(
            out,
            "    1. `sudo dseditgroup -o edit -a $USER -t user ember-clients`"
        );
        let _ = writeln!(
            out,
            "    2. Start a fresh login shell (Terminal.app > Shell > New Window)"
        );
        let _ = writeln!(
            out,
            "    3. Verify with `dseditgroup -o checkmember -m $USER ember-clients`"
        );
    } else {
        let _ = writeln!(out, "{}", style_section_heading("Diagnosis"));
        let stale_shell = is_stale_group_membership(my_uid, my_gid, &meta);
        if stale_shell {
            let _ = writeln!(
                out,
                "  The user IS in `ember-clients`, but this shell session may be using \
                 stale group credentials (the group was added after this shell started)."
            );
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  Fix: start a fresh login shell (Terminal.app > Shell > New Window)."
            );
        } else {
            let _ = writeln!(
                out,
                "  Group membership looks correct. The socket error may be transient \
                 or caused by a daemon version mismatch."
            );
            let _ = writeln!(
                out,
                "  Repair: `sudo {ember_cmd} daemon install` to reinstall the managed daemon."
            );
        }
    }
    out
}

fn is_user_in_ember_clients_group(uid: u32) -> bool {
    let output = std::process::Command::new("dseditgroup")
        .args(["-o", "checkmember", "-m"])
        .arg(username_for_uid(uid))
        .arg("ember-clients")
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => {
            let output = std::process::Command::new("id").arg("-Gn").output();
            match output {
                Ok(o) => {
                    let groups = String::from_utf8_lossy(&o.stdout);
                    groups.split_whitespace().any(|g| g == "ember-clients")
                }
                Err(_) => false,
            }
        }
    }
}

fn username_for_uid(uid: u32) -> String {
    let output = std::process::Command::new("id").args(["-un"]).output();
    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => uid.to_string(),
    }
}

/// Heuristic: if the user is in ember-clients but the socket's GID doesn't match
/// any of the caller's effective supplementary groups, the shell is stale.
fn is_stale_group_membership(_uid: u32, _primary_gid: u32, meta: &Option<(u32, u32, u32)>) -> bool {
    let Some((_mode, _owner_uid, socket_gid)) = meta else {
        return false;
    };
    let mut groups = vec![0u32; 64];
    let mut ngroups: libc::c_int = groups.len() as libc::c_int;
    let ret = unsafe { libc::getgroups(ngroups, groups.as_mut_ptr() as *mut libc::gid_t) };
    if ret < 0 {
        return false;
    }
    ngroups = ret;
    let effective_groups = &groups[..ngroups as usize];
    !effective_groups.contains(socket_gid)
}
