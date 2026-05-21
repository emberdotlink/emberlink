//! Worktree-scoped dev runtime resolution.
//!
//! design moves internal dev away from one workstation-global mutable
//! runtime. This module derives a stable per-worktree runtime identity from
//! the workspace root so hidden `ember dev ...` / `ember claude-code --dev`
//! stop contending on shared sockets, manifests, shadows, and vault state.

use std::path::{Path, PathBuf};

const DEV_WORKTREE_ROOT_ENV: &str = "EMBER_DEV_WORKTREE_ROOT";
const DEV_ENVS_DIR_REL: &str = ".ember-dev/envs";
const DEV_SHARED_CONFIG_DIR_REL: &str = ".config/emberlink-dev";
const DEV_LABEL_PREFIX: &str = "sh.emberlink.daemon.dev";
const DEV_KEYRING_SERVICE_PREFIX: &str = "ember-daemon-dev";
const DEV_KEYRING_ACCOUNT: &str = "vault";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevRuntimeEnv {
    pub home: PathBuf,
    pub workspace_root: PathBuf,
    pub worktree_id: String,
    pub env_root: PathBuf,
    pub run_dir: PathBuf,
    pub socket_path: PathBuf,
    pub shadow_root: PathBuf,
    pub install_root: PathBuf,
    pub manifest_path: PathBuf,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub policy_file: PathBuf,
    pub pid_file: PathBuf,
    pub vault_dir: PathBuf,
    pub plist_label: String,
    pub plist_path: PathBuf,
    pub stderr_log_path: PathBuf,
    pub keyring_service: String,
    pub keyring_account: String,
    pub gh_app_env_path: PathBuf,
    pub gh_app_pem_path: PathBuf,
}

pub fn resolve_current_dev_runtime() -> Result<DevRuntimeEnv, String> {
    let workspace_root = resolve_workspace_root()?;
    resolve_dev_runtime_for_workspace_root(&workspace_root)
}

pub fn resolve_dev_runtime_for_workspace_root(workspace_root: &Path) -> Result<DevRuntimeEnv, String> {
    let home =
        dirs_next::home_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    Ok(derive_dev_runtime_env(&home, workspace_root))
}

pub fn resolve_workspace_root() -> Result<PathBuf, String> {
    if let Ok(root) = std::env::var(DEV_WORKTREE_ROOT_ENV) {
        let trimmed = root.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let cwd = std::env::current_dir().map_err(|e| format!("resolve current dir: {e}"))?;
    resolve_workspace_root_from(&cwd)
}

pub fn resolve_workspace_root_from(start: &Path) -> Result<PathBuf, String> {
    let mut candidate = start;
    loop {
        if candidate.join("Cargo.toml").exists() {
            return Ok(candidate.to_path_buf());
        }
        match candidate.parent() {
            Some(parent) => candidate = parent,
            None => {
                return Err(
                    "could not locate workspace Cargo.toml walking up from current directory"
                        .to_string(),
                );
            }
        }
    }
}

pub fn derive_dev_runtime_env(home: &Path, workspace_root: &Path) -> DevRuntimeEnv {
    let worktree_id = derive_worktree_id(workspace_root);
    let env_root = home.join(DEV_ENVS_DIR_REL).join(&worktree_id);
    let run_dir = env_root.join("run");
    let install_root = env_root.join("binaries");
    let shared_config_dir = home.join(DEV_SHARED_CONFIG_DIR_REL);

    DevRuntimeEnv {
        home: home.to_path_buf(),
        workspace_root: workspace_root.to_path_buf(),
        worktree_id: worktree_id.clone(),
        env_root: env_root.clone(),
        run_dir: run_dir.clone(),
        socket_path: run_dir.join("daemon.sock"),
        shadow_root: env_root.join("shadow"),
        install_root: install_root.clone(),
        manifest_path: install_root.join("manifest.toml"),
        config_path: env_root.join("config.toml"),
        data_dir: env_root.join("data"),
        policy_file: env_root.join("policy.toml"),
        pid_file: run_dir.join("emberd.pid"),
        vault_dir: env_root.join("vault"),
        plist_label: format!("{DEV_LABEL_PREFIX}.{worktree_id}"),
        plist_path: PathBuf::from("/Library/LaunchDaemons")
            .join(format!("{DEV_LABEL_PREFIX}.{worktree_id}.plist")),
        stderr_log_path: PathBuf::from("/var/log")
            .join(format!("emberd.dev.{worktree_id}.err")),
        keyring_service: format!("{DEV_KEYRING_SERVICE_PREFIX}-{worktree_id}"),
        keyring_account: DEV_KEYRING_ACCOUNT.to_string(),
        gh_app_env_path: shared_config_dir.join("github.env"),
        gh_app_pem_path: shared_config_dir.join("github-app.pem"),
    }
}

fn derive_worktree_id(workspace_root: &Path) -> String {
    let identity_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let slug = sanitize_component(
        identity_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("workspace"),
    );
    let hash = blake3::hash(identity_root.to_string_lossy().as_bytes());
    format!("{slug}-{}", &hex::encode(hash.as_bytes())[..12])
}

fn sanitize_component(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;

    for ch in raw.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' {
            if !prev_dash && !out.is_empty() {
                out.push('-');
            }
            prev_dash = true;
        } else {
            out.push(mapped);
            prev_dash = false;
        }
    }

    let trimmed = out.trim_matches('-');
    let collapsed = if trimmed.is_empty() {
        "workspace"
    } else {
        trimmed
    };
    collapsed.chars().take(24).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_workspace_produces_same_worktree_id() {
        let home = Path::new("/home/tester");
        let root = Path::new("/tmp/emberlink-dev/worktree-a");
        let a = derive_dev_runtime_env(home, root);
        let b = derive_dev_runtime_env(home, root);
        assert_eq!(a.worktree_id, b.worktree_id);
    }

    #[test]
    fn different_workspaces_produce_distinct_worktree_ids() {
        let home = Path::new("/home/tester");
        let a = derive_dev_runtime_env(home, Path::new("/tmp/emberlink-dev/worktree-a"));
        let b = derive_dev_runtime_env(home, Path::new("/tmp/emberlink-dev/worktree-b"));
        assert_ne!(a.worktree_id, b.worktree_id);
    }

    #[test]
    fn runtime_paths_live_under_worktree_env_root() {
        let env = derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        assert!(
            env.env_root
                .starts_with("/home/tester/.ember-dev/envs/"),
            "env root must live under ~/.ember-dev/envs: {}",
            env.env_root.display()
        );
        assert!(env.socket_path.starts_with(&env.env_root));
        assert!(env.shadow_root.starts_with(&env.env_root));
        assert!(env.install_root.starts_with(&env.env_root));
        assert!(env.vault_dir.starts_with(&env.env_root));
    }

    #[test]
    fn plist_label_and_keyring_service_include_worktree_id() {
        let env = derive_dev_runtime_env(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        assert!(env.plist_label.ends_with(&env.worktree_id));
        assert!(env.keyring_service.ends_with(&env.worktree_id));
    }
}
