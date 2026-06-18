use super::*;

pub(super) fn daemon_install_launcher_boundary_note() -> &'static str {
    "`sudo ember daemon install` refreshes daemon/runtime sidecars, but it does not rebuild `/usr/local/lib/ember.app` or refresh `/usr/local/bin/ember`. Reinstall the managed CLI artifact or release package if the host launcher changed."
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InstalledLauncherIssue {
    BrokenRepoBuildSymlink {
        path: PathBuf,
        target: PathBuf,
    },
    BrokenSymlink {
        path: PathBuf,
        target: PathBuf,
    },
    StaleManagedInstall {
        path: PathBuf,
        target: PathBuf,
        newer_components: Vec<PathBuf>,
    },
}

impl InstalledLauncherIssue {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::BrokenRepoBuildSymlink { .. } => "broken_repo_build_symlink",
            Self::BrokenSymlink { .. } => "broken_symlink",
            Self::StaleManagedInstall { .. } => "stale_managed_install",
        }
    }

    pub(super) fn detail(&self) -> String {
        match self {
            Self::BrokenRepoBuildSymlink { path, target } => format!(
                "{} -> {} (missing repo build artifact)",
                path.display(),
                target.display()
            ),
            Self::BrokenSymlink { path, target } => format!(
                "{} -> {} (missing target)",
                path.display(),
                target.display()
            ),
            Self::StaleManagedInstall {
                path,
                target,
                newer_components,
            } => format!(
                "{} -> {} (older than managed runtime surface: {})",
                path.display(),
                target.display(),
                newer_components
                    .iter()
                    .map(|component| component.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    pub(super) fn repair_guidance(&self) -> String {
        match self {
            Self::BrokenRepoBuildSymlink { path, target } => format!(
                "Repair the installed `ember` launcher path first: {} points at missing repo build artifact {}. Reinstall the managed CLI artifact or stop pointing the host launcher at `target/...` outputs.",
                path.display(),
                target.display()
            ),
            Self::BrokenSymlink { path, target } => format!(
                "Repair the installed `ember` launcher path first: {} points at missing target {}. Reinstall or relink the managed CLI artifact before treating this as a daemon/product failure.",
                path.display(),
                target.display()
            ),
            Self::StaleManagedInstall { path, .. } => format!(
                "Repair the installed `ember` launcher path first: {} is older than the managed daemon/construct binaries on this host. Reinstall the managed CLI artifact or release package so `/usr/local/bin/ember` matches the runtime surface. `sudo ember daemon install` refreshes daemon/runtime sidecars, but it does not rebuild `/usr/local/lib/ember.app`.",
                path.display()
            ),
        }
    }
}

pub(super) fn launcher_issue_json(
    launcher_issue: Option<&InstalledLauncherIssue>,
) -> serde_json::Value {
    match launcher_issue {
        Some(
            issue @ InstalledLauncherIssue::BrokenRepoBuildSymlink { path, target }
            | issue @ InstalledLauncherIssue::BrokenSymlink { path, target },
        ) => serde_json::json!({
            "kind": issue.kind(),
            "path": path,
            "target": target,
            "detail": issue.detail(),
            "repair_guidance": issue.repair_guidance(),
            "newer_components": serde_json::Value::Null,
        }),
        Some(
            issue @ InstalledLauncherIssue::StaleManagedInstall {
                path,
                target,
                newer_components,
            },
        ) => serde_json::json!({
            "kind": issue.kind(),
            "path": path,
            "target": target,
            "detail": issue.detail(),
            "repair_guidance": issue.repair_guidance(),
            "newer_components": newer_components,
        }),
        None => serde_json::Value::Null,
    }
}

pub(super) const PROD_EMBER_LAUNCHER_PATH: &str = "/usr/local/bin/ember";
pub(super) const PROD_EMBER_APP_PATH: &str = "/usr/local/lib/ember.app/Contents/MacOS/ember";
pub(super) const PROD_EMBER_DAEMON_PATH: &str = "/usr/local/bin/emberd";
pub(super) const PROD_EMBER_GH_PATH: &str = "/usr/local/lib/ember/binaries/ember-gh";
pub(super) const PROD_EMBER_GIT_PATH: &str = "/usr/local/lib/ember/binaries/ember-git";
pub(super) const PROD_EMBER_KUBECTL_PATH: &str = "/usr/local/lib/ember/binaries/ember-kubectl";
pub(super) const PROD_EMBER_DELEGATION_TEMPLATES_DIR: &str =
    "/usr/local/lib/ember/delegation-templates";
pub(super) const INSTALLED_LAUNCHER_DRIFT_THRESHOLD: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CurrentLauncherLane {
    InstalledHost { path: PathBuf },
    RepoBuild { path: PathBuf },
    Other { path: PathBuf },
}

impl CurrentLauncherLane {
    pub(super) fn detail(&self) -> String {
        match self {
            Self::InstalledHost { path } => {
                format!("installed host (human dogfood lane) via {}", path.display())
            }
            Self::RepoBuild { path } => {
                format!("repo build (no-sudo proof lane) via {}", path.display())
            }
            Self::Other { path } => format!("other binary via {}", path.display()),
        }
    }

    pub(super) fn human_detail(&self) -> String {
        match self {
            Self::InstalledHost { path } => {
                format!(
                    "installed host (human dogfood lane) via {}",
                    display_launcher_path_text(path)
                )
            }
            Self::RepoBuild { path } => {
                format!(
                    "repo build (no-sudo proof lane) via {}",
                    display_launcher_path_text(path)
                )
            }
            Self::Other { path } => {
                format!("other binary via {}", display_launcher_path_text(path))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ManagedDaemonIssue {
    pub(super) launcher_path: PathBuf,
    pub(super) daemon_path: PathBuf,
}

impl ManagedDaemonIssue {
    pub(super) fn detail(&self) -> String {
        format!(
            "{} is newer than managed daemon {}",
            self.launcher_path.display(),
            self.daemon_path.display()
        )
    }

    pub(super) fn repair_guidance(&self) -> String {
        format!(
            "Refresh the managed daemon with `{}` before trusting launcher or unlock behavior from this repo build.",
            sudo_daemon_install_command(&self.launcher_path)
        )
    }
}

pub(super) fn sudo_daemon_install_command(launcher_path: &Path) -> String {
    format!("sudo {} daemon install", shell_quote(launcher_path))
}

pub(super) fn shell_quote(path: &Path) -> String {
    let rendered = path.display().to_string();
    let safe = rendered
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '=' | ':'));
    if safe {
        rendered
    } else {
        format!("'{}'", rendered.replace('\'', "'\\''"))
    }
}

pub(super) fn managed_daemon_issue_json(issue: Option<&ManagedDaemonIssue>) -> serde_json::Value {
    match issue {
        Some(issue) => serde_json::json!({
            "kind": "repo_build_newer_than_managed_daemon",
            "launcher_path": issue.launcher_path,
            "daemon_path": issue.daemon_path,
            "detail": issue.detail(),
            "repair_guidance": issue.repair_guidance(),
        }),
        None => serde_json::Value::Null,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DelegationTemplateInstallIssue {
    pub(super) templates_dir: PathBuf,
    pub(super) missing_templates: Vec<String>,
}

impl DelegationTemplateInstallIssue {
    pub(super) fn detail(&self) -> String {
        format!(
            "{} missing bundled delegation templates: {}",
            self.templates_dir.display(),
            self.missing_templates.join(", ")
        )
    }

    pub(super) fn repair_guidance(&self) -> String {
        format!(
            "Repair the managed delegation-template bundle: reinstall the managed CLI artifact or release package so `{}` contains the bundled delegation-template TOMLs. `sudo ember daemon install` refreshes daemon/runtime sidecars, but it does not rebuild `/usr/local/lib/ember.app` or repopulate the managed template directory.",
            self.templates_dir.display()
        )
    }
}

pub(super) fn delegation_template_issue_json(
    issue: Option<&DelegationTemplateInstallIssue>,
) -> serde_json::Value {
    match issue {
        Some(issue) => serde_json::json!({
            "kind": "missing_bundled_delegation_templates",
            "templates_dir": issue.templates_dir,
            "missing_templates": issue.missing_templates,
            "detail": issue.detail(),
            "repair_guidance": issue.repair_guidance(),
        }),
        None => serde_json::Value::Null,
    }
}

pub(super) fn detect_delegation_template_install_issue(
    current_launcher_lane: Option<&CurrentLauncherLane>,
) -> Option<DelegationTemplateInstallIssue> {
    if matches!(
        current_launcher_lane,
        Some(CurrentLauncherLane::RepoBuild { .. })
    ) {
        return None;
    }

    if !Path::new(PROD_EMBER_LAUNCHER_PATH).exists()
        && !Path::new(PROD_EMBER_APP_PATH).exists()
        && !Path::new(PROD_EMBER_GH_PATH).exists()
    {
        return None;
    }

    let templates_dir = PathBuf::from(PROD_EMBER_DELEGATION_TEMPLATES_DIR);
    let missing_templates =
        ember_construct::delegation_template_schema::BUNDLED_DELEGATION_TEMPLATE_TOMLS
            .iter()
            .map(|template| format!("{}.toml", template.name))
            .filter(|file_name| !templates_dir.join(file_name).is_file())
            .collect::<Vec<_>>();

    if missing_templates.is_empty() {
        None
    } else {
        Some(DelegationTemplateInstallIssue {
            templates_dir,
            missing_templates,
        })
    }
}

pub(super) fn detect_managed_daemon_issue(
    current_launcher_lane: Option<&CurrentLauncherLane>,
) -> Option<ManagedDaemonIssue> {
    let CurrentLauncherLane::RepoBuild { path } = current_launcher_lane? else {
        return None;
    };
    detect_repo_build_managed_daemon_issue_at(
        path,
        Path::new(PROD_EMBER_DAEMON_PATH),
        INSTALLED_LAUNCHER_DRIFT_THRESHOLD,
    )
}

pub(super) fn detect_repo_build_managed_daemon_issue_at(
    launcher_path: &Path,
    daemon_path: &Path,
    drift_threshold: Duration,
) -> Option<ManagedDaemonIssue> {
    let launcher_mtime = fs::metadata(launcher_path).ok()?.modified().ok()?;
    let daemon_mtime = fs::metadata(daemon_path).ok()?.modified().ok()?;
    let drift = launcher_mtime.duration_since(daemon_mtime).ok()?;
    (drift > drift_threshold).then(|| ManagedDaemonIssue {
        launcher_path: launcher_path.to_path_buf(),
        daemon_path: daemon_path.to_path_buf(),
    })
}

pub(super) fn detect_current_launcher_lane() -> Option<CurrentLauncherLane> {
    let exe = std::env::current_exe().ok()?;
    Some(classify_current_launcher_lane_at(&exe))
}

pub(super) fn classify_current_launcher_lane_at(path: &Path) -> CurrentLauncherLane {
    if path == Path::new(PROD_EMBER_LAUNCHER_PATH)
        || path == Path::new(PROD_EMBER_APP_PATH)
        || path.starts_with("/usr/local/lib/ember.app/")
    {
        return CurrentLauncherLane::InstalledHost {
            path: path.to_path_buf(),
        };
    }

    if path
        .components()
        .any(|component| component.as_os_str() == "target")
        && path.file_name().is_some_and(|name| name == "ember")
    {
        return CurrentLauncherLane::RepoBuild {
            path: path.to_path_buf(),
        };
    }

    CurrentLauncherLane::Other {
        path: path.to_path_buf(),
    }
}

pub(super) fn resolve_symlink_target(path: &Path, target: &Path) -> PathBuf {
    fn normalize_lexical(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if !normalized.pop() {
                        normalized.push(component.as_os_str());
                    }
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    }

    if target.is_absolute() {
        normalize_lexical(target.to_path_buf())
    } else {
        normalize_lexical(path.parent().unwrap_or_else(|| Path::new("/")).join(target))
    }
}

pub(super) fn path_looks_like_repo_build_artifact(target: &Path) -> bool {
    target
        .components()
        .any(|component| component.as_os_str() == "target")
}

pub(super) fn prod_managed_runtime_component_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from(PROD_EMBER_DAEMON_PATH),
        PathBuf::from(PROD_EMBER_GH_PATH),
        PathBuf::from(PROD_EMBER_GIT_PATH),
        PathBuf::from(PROD_EMBER_KUBECTL_PATH),
    ]
}

pub(super) fn detect_installed_launcher_issue_at_with_managed_components(
    path: &Path,
    managed_components: &[PathBuf],
    drift_threshold: Duration,
) -> Option<InstalledLauncherIssue> {
    let target = fs::read_link(path).ok()?;
    let resolved = resolve_symlink_target(path, &target);
    if !resolved.exists() {
        return Some(if path_looks_like_repo_build_artifact(&resolved) {
            InstalledLauncherIssue::BrokenRepoBuildSymlink {
                path: path.to_path_buf(),
                target: resolved,
            }
        } else {
            InstalledLauncherIssue::BrokenSymlink {
                path: path.to_path_buf(),
                target: resolved,
            }
        });
    }
    let launcher_mtime = fs::metadata(&resolved).ok()?.modified().ok()?;
    let newer_components: Vec<PathBuf> = managed_components
        .iter()
        .filter_map(|component| {
            let component_mtime = fs::metadata(component).ok()?.modified().ok()?;
            let drift = component_mtime.duration_since(launcher_mtime).ok()?;
            (drift > drift_threshold).then(|| component.clone())
        })
        .collect();
    if newer_components.is_empty() {
        None
    } else {
        Some(InstalledLauncherIssue::StaleManagedInstall {
            path: path.to_path_buf(),
            target: resolved,
            newer_components,
        })
    }
}

pub(super) fn detect_installed_launcher_issue_at(path: &Path) -> Option<InstalledLauncherIssue> {
    detect_installed_launcher_issue_at_with_managed_components(
        path,
        &prod_managed_runtime_component_paths(),
        INSTALLED_LAUNCHER_DRIFT_THRESHOLD,
    )
}

pub(super) fn detect_default_installed_launcher_issue() -> Option<InstalledLauncherIssue> {
    detect_installed_launcher_issue_at(Path::new(PROD_EMBER_LAUNCHER_PATH))
}
