use super::*;

pub(super) fn run_github_provider_status(
    config: &DaemonConfig,
) -> Result<GithubProviderStatusView, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "broker.github_status",
        &serde_json::json!({}),
    )?;
    serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("broker github status: {e}")))
}

pub(super) fn github_https_lane(status: &GithubProviderStatusView) -> GithubHttpsLane {
    match status.lane.as_str() {
        "app" => GithubHttpsLane::ConfiguredApp,
        "pat" => GithubHttpsLane::ConfiguredPat,
        "mock" => GithubHttpsLane::ConfiguredMock,
        "broken" => GithubHttpsLane::Broken,
        _ => GithubHttpsLane::NotConfigured,
    }
}

pub(super) fn github_onboarding_posture(
    config: &DaemonConfig,
) -> emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    match run_github_provider_status(config) {
        Ok(status) => match github_https_lane(&status) {
            GithubHttpsLane::ConfiguredApp => GitHubOnboardingPosture::AppConfiguredReal,
            GithubHttpsLane::ConfiguredPat => GitHubOnboardingPosture::PatConfigured,
            GithubHttpsLane::ConfiguredMock => GitHubOnboardingPosture::AppConfiguredMock,
            GithubHttpsLane::Broken => {
                GitHubOnboardingPosture::AppBroken(status.detail.unwrap_or_else(|| {
                    "local GitHub App authority is configured, but loading failed".to_string()
                }))
            }
            GithubHttpsLane::NotConfigured => GitHubOnboardingPosture::AppNotConfigured,
        },
        Err(e) => {
            eprintln!("warning: could not inspect GitHub broker posture: {e}");
            GitHubOnboardingPosture::AppNotConfigured
        }
    }
}

pub(super) fn github_status_json_payload(
    status: &GithubProviderStatusView,
    launcher_issue: Option<&InstalledLauncherIssue>,
) -> serde_json::Value {
    serde_json::json!({
        "https_app_lane": match github_https_lane(status) {
            GithubHttpsLane::ConfiguredApp => "configured_app",
            GithubHttpsLane::ConfiguredPat => "configured_pat",
            GithubHttpsLane::ConfiguredMock => "configured_mock",
            GithubHttpsLane::Broken => "broken",
            GithubHttpsLane::NotConfigured => "not_configured",
        },
        "detail": status.detail,
        "app_id": status.app_id,
        "installation_id": status.installation_id,
        "ssh_lane": "substrate_exists_not_launcher_wired",
        "pat_lane": "degraded_brokered_fallback",
        "launcher_issue": launcher_issue_json(launcher_issue),
    })
}

#[cfg(test)]
pub(super) fn render_github_status_text(
    status: &GithubProviderStatusView,
    launcher_issue: Option<&InstalledLauncherIssue>,
) -> String {
    render_github_status_text_with_ember_command(status, launcher_issue, "ember")
}

pub(super) fn render_github_status_text_with_ember_command(
    status: &GithubProviderStatusView,
    launcher_issue: Option<&InstalledLauncherIssue>,
    ember_cmd: &str,
) -> String {
    let mut details = Vec::new();
    if let Some(app_id) = status.app_id.as_deref() {
        details.push(format!("App ID: {app_id}"));
    }
    if let Some(installation_id) = status.installation_id.as_deref() {
        details.push(format!("Installation: {installation_id}"));
    }
    if let Some(detail) = status.detail.as_deref() {
        details.push(format!("Detail: {detail}"));
    }
    let mut sections = Vec::new();

    let (title, summary) = match github_https_lane(status) {
        GithubHttpsLane::ConfiguredApp => {
            sections.push(UiSection {
                heading: "Next",
                lines: vec![command_row(
                    format!("{ember_cmd} init --for claude"),
                    "Keep the App-first path while wiring Claude",
                )],
            });
            sections.push(UiSection {
                heading: "More",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} status"),
                        "Check overall Ember readiness",
                    ),
                    command_row(
                        "ember explain github setup",
                        "Read how the GitHub App lane works",
                    ),
                ],
            });
            (
                "GitHub ready",
                "The GitHub App lane is configured for Ember's HTTPS/API path.",
            )
        }
        GithubHttpsLane::ConfiguredPat => {
            details.push(
                "gh/git will attribute through your GitHub identity until the App lane is restored."
                    .to_string(),
            );
            sections.push(UiSection {
                heading: "Fix now",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup"),
                    "Upgrade from PAT fallback to the App lane",
                )],
            });
            sections.push(UiSection {
                heading: "More",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} init --for claude"),
                        "Keep moving if the degraded lane is acceptable for now",
                    ),
                    command_row("ember explain github setup", "Read the App setup contract"),
                ],
            });
            (
                "GitHub needs attention",
                "The degraded PAT fallback lane is active on this machine.",
            )
        }
        GithubHttpsLane::Broken => {
            sections.push(UiSection {
                heading: "Fix now",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup"),
                    "Repair or replace the local App credential triple",
                )],
            });
            sections.push(UiSection {
                heading: "More",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} doctor"),
                        "Open the deeper diagnosis surface",
                    ),
                    command_row("ember explain github setup", "Read the App setup contract"),
                ],
            });
            (
                "GitHub needs attention",
                "The local GitHub App triple is present but broken.",
            )
        }
        GithubHttpsLane::ConfiguredMock | GithubHttpsLane::NotConfigured => {
            details.push(
                "Need: private key PEM, App ID, installation ID or post-install URL, and App slug."
                    .to_string(),
            );
            sections.push(UiSection {
                heading: "Start",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup"),
                    "Configure the GitHub App lane",
                )],
            });
            sections.push(UiSection {
                heading: "More",
                lines: vec![
                    command_row("ember explain github setup", "Read the App setup contract"),
                    command_row(
                        format!("{ember_cmd} status"),
                        "Check broader Ember readiness",
                    ),
                ],
            });
            (
                "GitHub not set up",
                "The GitHub App lane is not configured on this machine.",
            )
        }
    };

    if let Some(issue) = launcher_issue {
        sections.push(UiSection {
            heading: "Boundary",
            lines: vec![
                format!("Install path: {}", issue.detail()),
                issue.repair_guidance(),
            ],
        });
    }

    render_compact_card(title, summary, &details, &sections)
}

#[cfg(test)]
pub(super) fn github_setup_command() -> &'static str {
    "ember github setup"
}

pub(super) fn github_setup_command_with_ember_command(ember_cmd: &str) -> String {
    format!("{ember_cmd} github setup")
}

pub(super) fn github_status_command_with_ember_command(ember_cmd: &str) -> String {
    format!("{ember_cmd} github status")
}

pub(super) fn init_command_with_ember_command(
    ember_cmd: &str,
    for_target: Option<OnboardingTarget>,
) -> String {
    match for_target {
        Some(OnboardingTarget::Claude) => format!("{ember_cmd} init --for claude"),
        Some(OnboardingTarget::Codex) => format!("{ember_cmd} init --for codex"),
        Some(OnboardingTarget::Cursor) => format!("{ember_cmd} init --for cursor"),
        Some(OnboardingTarget::Gemini) => format!("{ember_cmd} init --for gemini"),
        None => format!("{ember_cmd} init"),
    }
}

pub(super) fn sudo_daemon_install_command_with_ember_command(ember_cmd: &str) -> String {
    format!("sudo {ember_cmd} daemon install")
}

pub(super) fn rewrite_status_and_daemon_install_mentions(text: &str, ember_cmd: &str) -> String {
    if ember_cmd == "ember" {
        return text.to_string();
    }

    let status_cmd = format!("{ember_cmd} status");
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(ember_cmd);
    text.replace("`ember status`", &format!("`{status_cmd}`"))
        .replace("'ember status'", &format!("'{status_cmd}'"))
        .replace(
            "`sudo ember daemon install`",
            &format!("`{daemon_install_cmd}`"),
        )
        .replace(
            "'sudo ember daemon install'",
            &format!("'{daemon_install_cmd}'"),
        )
}

pub(super) fn render_github_app_manifest_launcher_note(ember_cmd: &str) -> Option<String> {
    (ember_cmd != "ember").then(|| {
        format!(
            "Launcher note:\n  You are running a repo-built launcher. In the embedded reference below, replace bare `ember ...` examples with `{ember_cmd} ...` while dogfooding this build.\n\n"
        )
    })
}

pub(super) fn render_github_setup_prelude(install_url: &str, ember_cmd: &str) -> String {
    render_compact_card(
        "GitHub App setup",
        "Store the local credential triple Ember needs for the HTTPS/App lane.",
        &["Need: private key PEM, App ID, installation ID or post-install URL, and App slug."
            .to_string()],
        &[
            UiSection {
                heading: "Reference",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} github app install-url"),
                        "Open the GitHub installation page",
                    ),
                    format!("Install URL: {install_url}"),
                    command_row(
                        format!("{ember_cmd} github app show"),
                        "Show the local reference manifest",
                    ),
                ],
            },
            UiSection {
                heading: "Tips",
                lines: vec![
                    "Paste the full install URL if needed; setup extracts `/installations/<ID>` automatically.".to_string(),
                    "Paste the App URL if needed; setup normalizes the slug automatically.".to_string(),
                ],
            },
        ],
    )
}

pub(super) enum GithubSetupDaemonFollowup {
    Reloaded { old_pid: u32, new_pid: Option<u32> },
    NeedsManualReload,
}

pub(super) fn try_reload_daemon_after_github_setup(
    config: &DaemonConfig,
) -> Result<GithubSetupDaemonFollowup, daemon_agent::AgentError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let pid_file = config.pid_file.clone();
    if !daemon_agent::is_managed_service() {
        return Ok(GithubSetupDaemonFollowup::NeedsManualReload);
    }
    let outcome = daemon_agent::reload_daemon(&pid_file, &socket_path, Duration::from_secs(10))?;
    Ok(GithubSetupDaemonFollowup::Reloaded {
        old_pid: outcome.old_pid,
        new_pid: outcome.new_pid,
    })
}

pub(super) fn render_github_setup_success_text(
    followup: GithubSetupDaemonFollowup,
    launcher_issue: Option<&InstalledLauncherIssue>,
    ember_cmd: &str,
) -> String {
    let github_status_cmd = format!("{ember_cmd} github status");
    let init_claude_cmd = format!("{ember_cmd} init --for claude");
    let claude_cmd = format!("{ember_cmd} claude");
    let receipt_cmd = format!("{ember_cmd} receipt export --latest --format md");
    let daemon_reload_cmd = format!("{ember_cmd} daemon reload");
    let mut details = Vec::new();
    let mut sections = Vec::new();
    let (title, summary) = match followup {
        GithubSetupDaemonFollowup::Reloaded { old_pid, new_pid } => {
            details.push(format!(
                "Daemon reloaded: {old_pid} -> {}",
                new_pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ));
            sections.push(UiSection {
                heading: "Next",
                lines: vec![
                    command_row(github_status_cmd, "Confirm the App lane is ready"),
                    command_row(init_claude_cmd, "Use this if you are still wiring Claude"),
                    command_row(claude_cmd, "Use this if setup is already complete"),
                ],
            });
            sections.push(UiSection {
                heading: "Verify",
                lines: vec![command_row(
                    receipt_cmd,
                    "Inspect the latest signed proof after the first brokered action",
                )],
            });
            (
                "GitHub ready",
                "The App credential triple was stored and the daemon reloaded.",
            )
        }
        GithubSetupDaemonFollowup::NeedsManualReload => {
            sections.push(UiSection {
                heading: "Fix now",
                lines: vec![
                    command_row(daemon_reload_cmd, "Reload the running daemon"),
                    command_row(github_status_cmd, "Confirm the App lane afterward"),
                ],
            });
            sections.push(UiSection {
                heading: "Also",
                lines: vec![
                    command_row(init_claude_cmd, "Use this if you are still wiring Claude"),
                    command_row(claude_cmd, "Use this if setup is already complete"),
                    command_row(
                        receipt_cmd,
                        "Inspect the latest signed proof after the first brokered action",
                    ),
                ],
            });
            (
                "GitHub staged",
                "The App credential triple was stored, but the daemon still needs a reload.",
            )
        }
    };

    if let Some(issue) = launcher_issue {
        sections.push(UiSection {
            heading: "Boundary",
            lines: vec![issue.detail(), issue.repair_guidance()],
        });
    }

    render_compact_card(title, summary, &details, &sections)
}

pub(super) fn render_github_setup_retry_hint(
    err: &GithubSetupError,
    ember_cmd: &str,
) -> Option<String> {
    let msg = err.to_string();
    if msg.contains("managed separate-uid biometric unlock")
        || msg.contains("EMBER_VAULT_PASSPHRASE")
    {
        let github_setup_cmd = github_setup_command_with_ember_command(ember_cmd);
        return Some(format!(
            "use the managed separate-uid biometric unlock flow if available, or restart the daemon with `EMBER_VAULT_PASSPHRASE`, then rerun `{github_setup_cmd}`."
        ));
    }
    if msg.contains("already exists;") && msg.contains("--replace") {
        let github_setup_cmd = github_setup_command_with_ember_command(ember_cmd);
        return Some(format!(
            "stored App credentials already exist for this slug + installation; rerun `{github_setup_cmd} --replace` if you intend to overwrite them."
        ));
    }
    if msg.contains("--allow-unverified-slug") && msg.contains("canonicalization") {
        let github_setup_cmd = github_setup_command_with_ember_command(ember_cmd);
        return Some(format!(
            "if GitHub is unreachable, the app is suspended, or you only need the local staged triple first, retry with `{github_setup_cmd} --allow-unverified-slug`."
        ));
    }
    None
}

pub(super) fn render_github_setup_error_guidance(
    err: &GithubSetupError,
    launcher_issue: Option<&InstalledLauncherIssue>,
    ember_cmd: &str,
) -> String {
    let github_status_cmd = format!("{ember_cmd} github status");
    let github_setup_cmd = github_setup_command_with_ember_command(ember_cmd);
    let mut do_this = vec![
        format!("Run `{github_status_cmd}` to inspect the current posture."),
        format!("Run `{github_setup_cmd}` to retry interactively."),
    ];
    if let Some(hint) = render_github_setup_retry_hint(err, ember_cmd) {
        do_this.insert(0, hint);
    }
    let mut more = Vec::new();
    if let Some(issue) = launcher_issue {
        more.push(format!("Install path: {}", issue.detail()));
        more.push(issue.repair_guidance());
    }
    render_actionable_error(
        "E-GITHUB-SETUP",
        "GitHub App setup failed",
        &err.to_string(),
        &do_this,
        &more,
    )
}

pub(super) fn render_github_status_retry_hint(
    err: &core_types::ValidationError,
    ember_cmd: &str,
) -> Option<String> {
    let msg = err.to_string();
    if msg.contains("managed separate-uid biometric unlock")
        || msg.contains("EMBER_VAULT_PASSPHRASE")
    {
        let github_status_cmd = github_status_command_with_ember_command(ember_cmd);
        return Some(format!(
            "use the managed separate-uid biometric unlock flow if available, or restart the daemon with `EMBER_VAULT_PASSPHRASE`, then rerun `{github_status_cmd}`."
        ));
    }
    None
}

pub(super) fn render_github_status_error_guidance(
    err: &core_types::ValidationError,
    launcher_issue: Option<&InstalledLauncherIssue>,
    ember_cmd: &str,
) -> String {
    if let Some(hint) = render_github_status_retry_hint(err, ember_cmd) {
        return render_actionable_error(
            "E-GITHUB-STATUS",
            "GitHub status could not inspect the current lane",
            &err.to_string(),
            &[hint],
            &[],
        );
    }

    let status_cmd = format!("{ember_cmd} status");
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(ember_cmd);
    let mut do_this = Vec::new();
    if let Some(issue) = launcher_issue {
        do_this.push(issue.repair_guidance());
        do_this.push(format!("Run `{status_cmd}` to inspect daemon posture."));
        do_this.push(format!(
            "Run `{daemon_install_cmd}` to repair the managed daemon."
        ));
        return render_actionable_error(
            "E-GITHUB-STATUS",
            "GitHub status could not inspect the current lane",
            &err.to_string(),
            &do_this,
            &[format!("Install path: {}", issue.detail())],
        );
    } else {
        do_this.push(format!("Run `{status_cmd}` to inspect daemon posture."));
        do_this.push(format!(
            "Run `{daemon_install_cmd}` to repair the managed daemon."
        ));
    }
    render_actionable_error(
        "E-GITHUB-STATUS",
        "GitHub status could not inspect the current lane",
        &err.to_string(),
        &do_this,
        &[],
    )
}

pub(super) fn prompt_github_setup_field(
    prompt: &str,
    default: Option<&str>,
) -> Result<String, String> {
    loop {
        match default {
            Some(value) => eprint!("{prompt} [{value}]: "),
            None => eprint!("{prompt}: "),
        }
        let _ = io::stderr().flush();
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| format!("read {prompt}: {e}"))?;
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
        if let Some(value) = default {
            return Ok(value.to_string());
        }
        eprintln!("  value required");
    }
}

pub(super) fn normalize_github_installation_id_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("installation ID is required".to_string());
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(trimmed.to_string());
    }

    let segments = trimmed
        .split(['/', '?', '#'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if let Some(last_numeric) = segments
        .iter()
        .rev()
        .find(|segment| segment.chars().all(|c| c.is_ascii_digit()))
    {
        return Ok((*last_numeric).to_string());
    }

    Err(format!(
        "could not extract numeric installation ID from `{trimmed}`"
    ))
}

pub(super) fn normalize_github_slug_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("GitHub App slug is required".to_string());
    }
    if let Some((_, slug)) = trimmed.split_once("/apps/") {
        let slug = slug
            .split(['/', '?', '#'])
            .find(|segment| !segment.is_empty())
            .ok_or_else(|| format!("could not extract GitHub App slug from `{trimmed}`"))?;
        return Ok(slug.to_string());
    }
    if let Some((_, slug)) = trimmed.split_once("/settings/apps/") {
        let slug = slug
            .split(['/', '?', '#'])
            .find(|segment| !segment.is_empty())
            .ok_or_else(|| format!("could not extract GitHub App slug from `{trimmed}`"))?;
        return Ok(slug.to_string());
    }
    Ok(trimmed.to_string())
}

pub(super) fn github_setup_has_direct_inputs(args: &GithubSetupArgs) -> bool {
    args.pem_file.is_some()
        || args.app_id.is_some()
        || args.installation_id.is_some()
        || args.slug.is_some()
}

pub(super) fn github_setup_should_use_manifest_flow(
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
) -> bool {
    args.from_manifest || (stdin_is_terminal && !github_setup_has_direct_inputs(args))
}

pub(super) fn resolve_github_setup_args(
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
    ember_cmd: &str,
) -> Result<GithubAppRegisterArgs, core_types::ValidationError> {
    let complete = args.pem_file.is_some()
        && args.app_id.is_some()
        && args.installation_id.is_some()
        && args.slug.is_some();
    if complete {
        return Ok(GithubAppRegisterArgs {
            pem_file: args.pem_file.clone().expect("checked"),
            app_id: args.app_id.clone().expect("checked"),
            installation_id: normalize_github_installation_id_input(
                args.installation_id.as_deref().expect("checked"),
            )
            .map_err(core_types::ValidationError::new)?,
            slug: normalize_github_slug_input(args.slug.as_deref().expect("checked"))
                .map_err(core_types::ValidationError::new)?,
            allow_unverified_slug: args.allow_unverified_slug,
            replace: args.replace,
        });
    }

    if !stdin_is_terminal {
        return Err(core_types::ValidationError::new(format!(
            "missing GitHub App setup inputs; rerun `{}` interactively or pass --pem-file, --app-id, --installation-id, and --slug",
            github_setup_command_with_ember_command(ember_cmd)
        )));
    }

    eprint!(
        "{}",
        render_github_setup_prelude(
            &emberlink_cli::onboarding::github_app::print_install_url(),
            ember_cmd,
        )
    );
    eprintln!();

    let pem_file = match args.pem_file.clone() {
        Some(path) => path,
        None => PathBuf::from(
            prompt_github_setup_field("Private key PEM path", None)
                .map_err(core_types::ValidationError::new)?,
        ),
    };
    let app_id = match args.app_id.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub App ID", None)
            .map_err(core_types::ValidationError::new)?,
    };
    let installation_id = match args.installation_id.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub installation ID or post-install URL", None)
            .map_err(core_types::ValidationError::new)?,
    };
    let slug = match args.slug.clone() {
        Some(value) => value,
        None => prompt_github_setup_field("GitHub App slug or app URL", None)
            .map_err(core_types::ValidationError::new)?,
    };

    Ok(GithubAppRegisterArgs {
        pem_file,
        app_id,
        installation_id: normalize_github_installation_id_input(&installation_id)
            .map_err(core_types::ValidationError::new)?,
        slug: normalize_github_slug_input(&slug).map_err(core_types::ValidationError::new)?,
        allow_unverified_slug: args.allow_unverified_slug,
        replace: args.replace,
    })
}

pub(super) enum GithubSetupError {
    Validation(core_types::ValidationError),
    Broker(emberlink_cli::broker::BrokerCliError),
    Manifest { message: String, exit_code: i32 },
}

impl std::fmt::Display for GithubSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(err) => err.fmt(f),
            Self::Broker(err) => err.fmt(f),
            Self::Manifest { message, .. } => f.write_str(message),
        }
    }
}

impl GithubSetupError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Validation(_) => 2,
            Self::Broker(err) => err.exit_code(),
            Self::Manifest { exit_code, .. } => *exit_code,
        }
    }
}

pub(super) fn register_github_from_setup_args(
    config: &DaemonConfig,
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
    json_out: bool,
    ember_cmd: &str,
) -> Result<(), GithubSetupError> {
    let register_args = resolve_github_setup_args(args, stdin_is_terminal, ember_cmd)
        .map_err(GithubSetupError::Validation)?;
    let socket_path = config.socket_dir.join("daemon.sock");
    let opts = emberlink_cli::broker::GlobalOpts { socket_path };
    emberlink_cli::broker::register_github(
        &opts,
        &register_args.pem_file,
        &register_args.app_id,
        &register_args.installation_id,
        &register_args.slug,
        register_args.allow_unverified_slug,
        register_args.replace,
        json_out,
    )
    .map_err(GithubSetupError::Broker)
}

pub(super) fn github_setup_args_from_app_register(args: &GithubAppRegisterArgs) -> GithubSetupArgs {
    GithubSetupArgs {
        from_manifest: false,
        pem_file: Some(args.pem_file.clone()),
        app_id: Some(args.app_id.clone()),
        installation_id: Some(args.installation_id.clone()),
        slug: Some(args.slug.clone()),
        allow_unverified_slug: args.allow_unverified_slug,
        replace: args.replace,
    }
}

pub(super) fn manifest_setup_error(message: impl Into<String>, exit_code: i32) -> GithubSetupError {
    GithubSetupError::Manifest {
        message: message.into(),
        exit_code,
    }
}

pub(super) fn write_manifest_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub(super) fn manifest_setup_success_page() -> &'static str {
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Emberlink GitHub App setup</title></head><body><h1>Emberlink received the GitHub App callback</h1><p>You can return to the terminal.</p></body></html>"
}

pub(super) fn manifest_setup_error_page(message: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Emberlink GitHub App setup</title></head><body><h1>GitHub App setup did not complete</h1><p>{}</p></body></html>",
        message
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    )
}

pub(super) fn handle_manifest_http_request(
    mut stream: TcpStream,
    state: &str,
    manifest: &serde_json::Value,
) -> Result<Option<String>, GithubSetupError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| manifest_setup_error(format!("set callback read timeout: {e}"), 1))?;
    let mut buf = [0_u8; 8192];
    let n = stream
        .read(&mut buf)
        .map_err(|e| manifest_setup_error(format!("read callback request: {e}"), 1))?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let first = request
        .lines()
        .next()
        .ok_or_else(|| manifest_setup_error("empty callback request", 2))?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        let body = manifest_setup_error_page("Only GET requests are accepted on this callback.");
        let _ = write_manifest_http_response(
            &mut stream,
            "405 Method Not Allowed",
            "text/html; charset=utf-8",
            &body,
        );
        return Ok(None);
    }

    if target == "/" || target == "/start" {
        let body =
            emberlink_cli::onboarding::github_app::manifest_registration_form_html(manifest, state)
                .map_err(|e| manifest_setup_error(format!("render manifest form: {e}"), 1))?;
        write_manifest_http_response(&mut stream, "200 OK", "text/html; charset=utf-8", &body)
            .map_err(|e| manifest_setup_error(format!("write manifest form: {e}"), 1))?;
        return Ok(None);
    }

    if target.starts_with("/callback") {
        match emberlink_cli::onboarding::github_app::parse_manifest_callback_target(target, state) {
            Ok(code) => {
                write_manifest_http_response(
                    &mut stream,
                    "200 OK",
                    "text/html; charset=utf-8",
                    manifest_setup_success_page(),
                )
                .map_err(|e| {
                    manifest_setup_error(format!("write callback success page: {e}"), 1)
                })?;
                return Ok(Some(code));
            }
            Err(e) => {
                let body = manifest_setup_error_page(&e);
                let _ = write_manifest_http_response(
                    &mut stream,
                    "400 Bad Request",
                    "text/html; charset=utf-8",
                    &body,
                );
                return Err(manifest_setup_error(e, 2));
            }
        }
    }

    let body = manifest_setup_error_page("This setup server only serves /start and /callback.");
    write_manifest_http_response(
        &mut stream,
        "404 Not Found",
        "text/html; charset=utf-8",
        &body,
    )
    .map_err(|e| manifest_setup_error(format!("write callback 404: {e}"), 1))?;
    Ok(None)
}

pub(super) fn wait_for_github_manifest_code(
    listener: TcpListener,
    state: &str,
    manifest: &serde_json::Value,
) -> Result<String, GithubSetupError> {
    listener
        .set_nonblocking(true)
        .map_err(|e| manifest_setup_error(format!("set callback listener nonblocking: {e}"), 1))?;
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(code) = handle_manifest_http_request(stream, state, manifest)? {
                    return Ok(code);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(manifest_setup_error(format!("accept callback: {e}"), 1)),
        }
    }
    Err(manifest_setup_error(
        "GitHub App manifest callback timed out after 5 minutes; rerun `ember github setup --from-manifest` to retry",
        2,
    ))
}

pub(super) fn exchange_github_manifest_code(
    code: &str,
) -> Result<emberlink_cli::onboarding::github_app::ManifestConversion, GithubSetupError> {
    let url = format!("https://api.github.com/app-manifests/{code}/conversions");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = agent
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "ember-cli/github-manifest")
        .send_empty()
        .map_err(|e| manifest_setup_error(format!("POST {url}: transport error: {e}"), 1))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.body_mut().read_to_string().unwrap_or_default();
        return Err(manifest_setup_error(
            format!("POST {url}: unexpected status {}: {body}", status.as_u16()),
            1,
        ));
    }
    let conversion: emberlink_cli::onboarding::github_app::ManifestConversion =
        response.body_mut().read_json().map_err(|e| {
            manifest_setup_error(format!("POST {url}: response JSON parse failed: {e}"), 1)
        })?;
    if !conversion.pem_present() {
        return Err(manifest_setup_error(
            "GitHub manifest conversion response did not include a private key PEM",
            1,
        ));
    }
    Ok(conversion)
}

/// Render the "App created but not installed yet" interstitial.
///
/// Reached when the manifest flow created the App but the installation poll
/// did not resolve an installation before its budget ran out (or stdin was
/// not a terminal so the flow could not wait interactively). The App exists on
/// GitHub; the operator just has not finished — or an org admin has not
/// approved — the install. Org installs in particular sit in this state until
/// approved.
pub(super) fn render_github_manifest_setup_result(
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    ember_cmd: &str,
) -> String {
    let install_url = conversion.installation_url();
    let mut details = vec![
        format!("App ID: {}", conversion.id),
        format!("Slug: {}", conversion.slug),
        format!("Install URL: {install_url}"),
    ];
    if let Some(url) = conversion.html_url.as_deref() {
        details.push(format!("App URL: {url}"));
    }

    let mut next = vec![command_row(
        install_url.clone(),
        "Install the App on the account and repositories Emberlink should act on",
    )];
    if let Some(url) = conversion.html_url.as_deref() {
        next.push(command_row(
            url.to_string(),
            "App settings — generate a fresh private key here if you resume setup in a new session",
        ));
    }
    next.push(command_row(
        format!("{ember_cmd} github setup --from-manifest"),
        "Rerun the manifest flow if the in-memory App key was lost before install",
    ));

    render_compact_card(
        "GitHub App created, not installed yet",
        "The App exists on GitHub but is not installed on any account, so Emberlink could not resolve an installation id. An organization install can also sit here until an admin approves the request.",
        &details,
        &[
            UiSection {
                heading: "Next",
                lines: next,
            },
            UiSection {
                heading: "Secret handling",
                lines: vec![
                    "The private key PEM stayed in memory and was not printed or written to disk."
                        .to_string(),
                    "P16-S3 wires automatic vault provisioning from this in-process bundle."
                        .to_string(),
                ],
            },
        ],
    )
}

/// Render the install drive-out shown before polling begins.
pub(super) fn render_github_install_drive_out(
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    install_url: &str,
) -> String {
    render_compact_card(
        "Install the GitHub App",
        "The App was created. Install it on the account and repositories Emberlink should act on; the installation is then detected automatically — no installation id to copy by hand.",
        &[
            format!("App: {} (id {})", conversion.slug, conversion.id),
            format!("Install URL: {install_url}"),
        ],
        &[UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    install_url.to_string(),
                    "Open in a browser signed in to GitHub and confirm the install",
                ),
                "Leave this command running — Emberlink polls GitHub until the install appears."
                    .to_string(),
            ],
        }],
    )
}

/// Render the success card once an installation is resolved.
pub(super) fn render_github_install_resolved(
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    resolved: &emberlink_cli::onboarding::github_app::ResolvedInstallation,
    ember_cmd: &str,
) -> String {
    let mut details = vec![
        format!("App ID: {}", conversion.id),
        format!("Slug: {}", conversion.slug),
        format!("Installation ID: {}", resolved.installation_id),
    ];
    if let Some(account) = resolved.account_login.as_deref() {
        details.push(format!("Installed on: {account}"));
    }
    if let Some(selection) = resolved.repository_selection.as_deref() {
        details.push(format!("Repository selection: {selection}"));
    }

    render_compact_card(
        "GitHub App installed",
        "Emberlink resolved the installation automatically. Automatic vault provisioning lands in the next setup step (P16-S3).",
        &details,
        &[
            UiSection {
                heading: "Next",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup --from-manifest"),
                    "Rerun after P16-S3 vault provisioning lands to complete the App lane",
                )],
            },
            UiSection {
                heading: "Secret handling",
                lines: vec![
                    "The private key PEM and the App JWT stayed in memory and were not printed or written to disk.".to_string(),
                ],
            },
        ],
    )
}

/// Attempts in one automated installation-poll round before the flow either
/// waits for an interactive recheck or surfaces the not-installed interstitial.
const INSTALL_POLL_ATTEMPTS_PER_ROUND: u32 = 10;
const INSTALL_POLL_INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const INSTALL_POLL_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Block until the operator presses Enter (recheck) or stdin reaches EOF
/// (stop). Returns `true` to poll again, `false` to stop waiting.
pub(super) fn wait_for_install_recheck(prompt: &str) -> bool {
    eprint!("{prompt}: ");
    let _ = io::stderr().flush();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .map(|n| n > 0)
        .unwrap_or(false)
}

/// Poll `GET /app/installations` with the App JWT for one bounded round,
/// backing off between attempts. Returns the first installation found, or
/// `Ok(None)` when the round's attempt budget is exhausted without one
/// appearing (the "created but not installed yet" state).
///
/// The JWT is re-minted per attempt so a long interactive wait never sends an
/// expired token. The JWT and PEM stay in memory and are never logged.
pub(super) fn poll_github_installations_round(
    app_id: u64,
    pem: &str,
) -> Result<Option<emberlink_cli::onboarding::github_app::ResolvedInstallation>, GithubSetupError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let url = "https://api.github.com/app/installations";
    let mut backoff = INSTALL_POLL_INITIAL_BACKOFF;

    for attempt in 0..INSTALL_POLL_ATTEMPTS_PER_ROUND {
        let jwt = emberlink_cli::onboarding::github_app::build_app_jwt(app_id, pem)
            .map_err(|e| manifest_setup_error(format!("App JWT mint failed: {e}"), 1))?;

        let mut response = agent
            .get(url)
            .header("Authorization", &format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "ember-cli/github-manifest")
            .call()
            .map_err(|e| manifest_setup_error(format!("GET {url}: transport error: {e}"), 1))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.body_mut().read_to_string().unwrap_or_default();
            return Err(manifest_setup_error(
                format!("GET {url}: unexpected status {}: {body}", status.as_u16()),
                1,
            ));
        }

        let body: serde_json::Value = response.body_mut().read_json().map_err(|e| {
            manifest_setup_error(format!("GET {url}: response JSON parse failed: {e}"), 1)
        })?;
        let installations = emberlink_cli::onboarding::github_app::parse_installations(&body)
            .map_err(|e| manifest_setup_error(format!("GET {url}: {e}"), 1))?;
        if let Some(first) = installations.into_iter().next() {
            return Ok(Some(first));
        }

        if attempt + 1 < INSTALL_POLL_ATTEMPTS_PER_ROUND {
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(INSTALL_POLL_MAX_BACKOFF);
        }
    }

    Ok(None)
}

/// Drive the operator to the App install URL and resolve the installation.
///
/// Runs one automated poll round first. If nothing is installed yet and stdin
/// is a terminal, it offers an in-process recheck loop so the operator can
/// finish the browser step (or wait for an org admin) without re-running the
/// manifest flow — keeping the in-memory PEM alive. Returns `Ok(None)` when
/// the installation is still not resolved, so the caller renders the
/// not-installed interstitial.
///
/// A cross-process `--resume-install <staged-token>` path is intentionally
/// NOT implemented: resuming after the process exits would require persisting
/// the App PEM to disk, which violates the PEM-never-on-disk guardrail. The
/// in-process recheck loop is the defensible default; cross-process resume is
/// a operator design decision (stage the PEM in vault vs. regenerate a key)
/// deferred to P16-S3 / a future ADR.
pub(super) fn drive_github_install_and_poll(
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    stdin_is_terminal: bool,
    json_out: bool,
) -> Result<Option<emberlink_cli::onboarding::github_app::ResolvedInstallation>, GithubSetupError> {
    let install_url = conversion.installation_url();
    if !json_out {
        eprintln!(
            "{}",
            render_github_install_drive_out(conversion, &install_url)
        );
    }

    if let Some(found) = poll_github_installations_round(conversion.id, &conversion.pem)? {
        return Ok(Some(found));
    }

    // Interactive in-process recheck: the App key stays in memory, so the
    // operator can install (or wait for org approval) and recheck without
    // re-running the manifest flow. Non-interactive callers fall straight
    // through to the interstitial.
    if stdin_is_terminal && !json_out {
        loop {
            if !wait_for_install_recheck(
                "Install not detected yet — press Enter to check again (Ctrl-C to stop)",
            ) {
                break;
            }
            if let Some(found) = poll_github_installations_round(conversion.id, &conversion.pem)? {
                return Ok(Some(found));
            }
        }
    }

    Ok(None)
}

/// Build the `--json` payload for the manifest-flow result, including resolved
/// installation metadata when present. Pure so the shape can be unit-tested.
pub(super) fn github_manifest_flow_json(
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    resolved: Option<&emberlink_cli::onboarding::github_app::ResolvedInstallation>,
) -> serde_json::Value {
    serde_json::json!({
        "app_id": conversion.id,
        "slug": conversion.slug,
        "html_url": conversion.html_url,
        "installation_url": conversion.installation_url(),
        "pem_received": conversion.pem_present(),
        "installed": resolved.is_some(),
        "installation_id": resolved.map(|r| r.installation_id),
        "account_login": resolved.and_then(|r| r.account_login.clone()),
        "repository_selection": resolved.and_then(|r| r.repository_selection.clone()),
        "stored": false,
    })
}

pub(super) fn run_github_manifest_setup_flow(
    config: &DaemonConfig,
    replace: bool,
    stdin_is_terminal: bool,
    json_out: bool,
    ember_cmd: &str,
) -> Result<(), GithubSetupError> {
    let state = emberlink_cli::onboarding::github_app::generate_manifest_state()
        .map_err(|e| manifest_setup_error(e, 1))?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| manifest_setup_error(format!("bind loopback callback: {e}"), 1))?;
    let port = listener
        .local_addr()
        .map_err(|e| manifest_setup_error(format!("read loopback callback address: {e}"), 1))?
        .port();
    let start_url = format!("http://127.0.0.1:{port}/start");
    let redirect_url = format!("http://127.0.0.1:{port}/callback");
    let manifest = emberlink_cli::onboarding::github_app::build_manifest_body(&redirect_url);

    eprintln!(
        "{}",
        render_compact_card(
            "GitHub App manifest flow",
            "Open the local setup URL in a browser signed in to GitHub.",
            &[format!("Setup URL: {start_url}")],
            &[UiSection {
                heading: "Waiting",
                lines: vec![
                    "The listener is bound to 127.0.0.1 only and will time out after 5 minutes."
                        .to_string(),
                    "The callback must return the matching manifest-flow state token.".to_string(),
                ],
            }],
        )
    );

    let code = wait_for_github_manifest_code(listener, &state, &manifest)?;
    let conversion = exchange_github_manifest_code(&code)?;
    let resolved = drive_github_install_and_poll(&conversion, stdin_is_terminal, json_out)?;

    let Some(installation) = resolved else {
        // App created but not installed yet — nothing to provision. Surface the
        // interstitial so the operator knows the App exists and what comes next.
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&github_manifest_flow_json(&conversion, None))
                    .unwrap_or_default()
            );
        } else {
            println!(
                "{}",
                render_github_manifest_setup_result(&conversion, ember_cmd)
            );
        }
        return Ok(());
    };

    if !json_out {
        eprintln!(
            "{}",
            render_github_install_resolved(&conversion, &installation, ember_cmd)
        );
    }

    // Provision the resolved credential triple from the in-memory PEM. The
    // bytes go straight to the daemon's vault_add RPC; the PEM never lands on
    // disk. register_github_with_pem prints its own confirmation (json/human),
    // mirroring the operator-direct `register_github` path.
    provision_github_from_manifest(config, &conversion, &installation, replace, json_out)?;

    // Mirror run_github_registration_flow: reload the daemon and show the
    // standard success copy in human mode (json mode ends on the provisioning
    // output above).
    if !json_out {
        match try_reload_daemon_after_github_setup(config) {
            Ok(followup) => {
                let launcher_issue = detect_default_installed_launcher_issue();
                println!(
                    "{}",
                    render_github_setup_success_text(followup, launcher_issue.as_ref(), ember_cmd)
                );
            }
            Err(e) => {
                println!(
                    "{}",
                    render_github_setup_success_text(
                        GithubSetupDaemonFollowup::NeedsManualReload,
                        detect_default_installed_launcher_issue().as_ref(),
                        ember_cmd,
                    )
                );
                eprintln!("warning: daemon reload failed after GitHub setup: {e}");
            }
        }
    }
    Ok(())
}

/// Provision the manifest-flow credential triple into the daemon vault.
///
/// Routes the in-memory PEM, App ID, resolved installation id, and canonical
/// slug straight to `register_github_with_pem` — the same daemon vault
/// data-plane the operator-direct `ember github setup` path uses. The PEM
/// never touches disk. The slug is canonical (it came from GitHub's
/// `/conversions` response), so `allow_unverified_slug = true` skips the
/// `GET /app` round-trip.
pub(super) fn provision_github_from_manifest(
    config: &DaemonConfig,
    conversion: &emberlink_cli::onboarding::github_app::ManifestConversion,
    installation: &emberlink_cli::onboarding::github_app::ResolvedInstallation,
    replace: bool,
    json_out: bool,
) -> Result<(), GithubSetupError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let opts = emberlink_cli::broker::GlobalOpts { socket_path };
    emberlink_cli::broker::register_github_with_pem(
        &opts,
        &conversion.pem,
        &conversion.id.to_string(),
        &installation.installation_id.to_string(),
        &conversion.slug,
        true,
        replace,
        json_out,
    )
    .map_err(GithubSetupError::Broker)
}

pub(super) fn run_github_registration_flow(
    config: &DaemonConfig,
    args: &GithubSetupArgs,
    stdin_is_terminal: bool,
    json_out: bool,
) -> Result<(), i32> {
    let ember_cmd = ember_command_prefix_for_current_launcher();
    if args.from_manifest && github_setup_has_direct_inputs(args) {
        eprintln!(
            "{}",
            render_github_setup_error_guidance(
                &manifest_setup_error(
                    "--from-manifest cannot be combined with --pem-file, --app-id, --installation-id, or --slug",
                    2,
                ),
                detect_default_installed_launcher_issue().as_ref(),
                &ember_cmd,
            )
        );
        return Err(2);
    }
    if github_setup_should_use_manifest_flow(args, stdin_is_terminal) {
        if let Err(e) = run_github_manifest_setup_flow(
            config,
            args.replace,
            stdin_is_terminal,
            json_out,
            &ember_cmd,
        ) {
            eprintln!(
                "{}",
                render_github_setup_error_guidance(
                    &e,
                    detect_default_installed_launcher_issue().as_ref(),
                    &ember_cmd,
                )
            );
            return Err(e.exit_code());
        }
        return Ok(());
    }

    if let Err(e) =
        register_github_from_setup_args(config, args, stdin_is_terminal, json_out, &ember_cmd)
    {
        let launcher_issue = detect_default_installed_launcher_issue();
        eprintln!(
            "{}",
            render_github_setup_error_guidance(&e, launcher_issue.as_ref(), &ember_cmd)
        );
        return Err(e.exit_code());
    }

    if !json_out {
        match try_reload_daemon_after_github_setup(config) {
            Ok(followup) => {
                let launcher_issue = detect_default_installed_launcher_issue();
                println!(
                    "{}",
                    render_github_setup_success_text(followup, launcher_issue.as_ref(), &ember_cmd)
                );
            }
            Err(e) => {
                println!(
                    "{}",
                    render_github_setup_success_text(
                        GithubSetupDaemonFollowup::NeedsManualReload,
                        detect_default_installed_launcher_issue().as_ref(),
                        &ember_cmd,
                    )
                );
                eprintln!("warning: daemon reload failed after GitHub setup: {e}");
            }
        }
    }

    Ok(())
}

pub(super) fn should_offer_inline_github_setup(
    posture: emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture,
    non_interactive: bool,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    matches!(
        posture,
        GitHubOnboardingPosture::AppNotConfigured
            | GitHubOnboardingPosture::AppConfiguredMock
            | GitHubOnboardingPosture::AppBroken(_)
    ) && !non_interactive
        && stdin_is_terminal
        && stderr_is_terminal
}
