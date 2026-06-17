//! Dev runtime selection and layout.
//!
//! The shared dev lane remains the fallback, but callers may opt into a
//! namespaced runtime via `EMBER_DEV_RUNTIME_ID` or by launching from a
//! validated Ember-managed worktree. We intentionally do not trust arbitrary
//! ancestor metadata files.

use std::path::{Path, PathBuf};

use crate::install_paths::{
    DEV_CREDS_DIR_REL, DEV_DAEMON_SOCKET_REL, DEV_INSTALL_ROOT, DEV_MANIFEST_PATH_REL,
    DEV_PLIST_LABEL,
};

pub const DEV_RUNTIME_ID_ENV: &str = "EMBER_DEV_RUNTIME_ID";
pub const SHARED_DEV_RUNTIME_ID: &str = "shared";

const DEV_ENVS_DIR_REL: &str = ".ember-dev/envs";
const DEV_SHARED_STATE_DIR_REL: &str = ".ember-dev";
const DEV_KEYRING_SERVICE_PREFIX: &str = "ember-daemon-dev";
const DEV_KEYRING_ACCOUNT: &str = "vault";
const DEV_WORKTREE_ROOT_ENV: &str = "EMBER_DEV_WORKTREE_ROOT";
const MANAGED_WORKTREE_ROOT_BASENAME: &str = ".ember";
const LEGACY_MANAGED_WORKTREE_ROOT_BASENAME: &str = ".claude";
const WORKTREE_DIR_BASENAME: &str = "worktrees";
const SESSION_META_FILE: &str = ".agent-session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSelectionSource {
    ExplicitEnv,
    ManagedWorktree,
    SharedDefault,
    PathDerived,
}

impl RuntimeSelectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitEnv => "explicit",
            Self::ManagedWorktree => "managed-worktree",
            Self::SharedDefault => "shared-default",
            Self::PathDerived => "path-derived",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevRuntimeEnv {
    pub home: PathBuf,
    pub workspace_root: PathBuf,
    pub worktree_id: String,
    pub runtime_label: String,
    pub selection_source: RuntimeSelectionSource,
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

impl DevRuntimeEnv {
    pub fn is_shared(&self) -> bool {
        self.worktree_id == SHARED_DEV_RUNTIME_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedWorktreeSelection {
    runtime_id: String,
    runtime_label: String,
    worktree_path: PathBuf,
}

pub fn compact_runtime_banner(runtime: &DevRuntimeEnv) -> String {
    format!(
        "{} [{} via {}]",
        runtime.runtime_label,
        runtime.worktree_id,
        runtime.selection_source.as_str()
    )
}

pub fn resolve_current_dev_runtime() -> Result<DevRuntimeEnv, String> {
    let home =
        dirs_next::home_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    resolve_current_dev_runtime_for_home(&home)
}

pub fn resolve_current_dev_runtime_for_home(home: &Path) -> Result<DevRuntimeEnv, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("resolve current dir: {e}"))?;
    resolve_dev_runtime_from_start(home, &cwd)
}

pub fn resolve_dev_runtime_for_workspace_root(
    workspace_root: &Path,
) -> Result<DevRuntimeEnv, String> {
    let home =
        dirs_next::home_dir().ok_or_else(|| "cannot determine home directory".to_string())?;
    resolve_dev_runtime_from_start(&home, workspace_root)
}

fn resolve_dev_runtime_from_start(home: &Path, start: &Path) -> Result<DevRuntimeEnv, String> {
    if let Some(explicit_runtime_id) = explicit_runtime_id_from_env()? {
        return Ok(derive_runtime_env_with_id(
            home,
            start,
            &explicit_runtime_id,
            explicit_runtime_id.clone(),
            RuntimeSelectionSource::ExplicitEnv,
        ));
    }

    if let Some(selection) = detect_runtime_selection_from_worktree(start)? {
        return Ok(derive_runtime_env_with_id(
            home,
            &selection.worktree_path,
            &selection.runtime_id,
            selection.runtime_label,
            RuntimeSelectionSource::ManagedWorktree,
        ));
    }

    Ok(shared_runtime_env(
        home,
        start,
        RuntimeSelectionSource::SharedDefault,
    ))
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
    let worktree_id = derive_runtime_id_for_path(workspace_root);
    derive_runtime_env_with_id(
        home,
        workspace_root,
        &worktree_id,
        worktree_id.clone(),
        RuntimeSelectionSource::PathDerived,
    )
}

fn derive_runtime_env_with_id(
    home: &Path,
    workspace_root: &Path,
    runtime_id: &str,
    runtime_label: String,
    selection_source: RuntimeSelectionSource,
) -> DevRuntimeEnv {
    if runtime_id == SHARED_DEV_RUNTIME_ID {
        return shared_runtime_env(home, workspace_root, selection_source);
    }

    let env_root = home.join(DEV_ENVS_DIR_REL).join(runtime_id);
    let run_dir = env_root.join("run");
    let install_root = env_root.join("binaries");
    let shared_config_dir = home.join(DEV_CREDS_DIR_REL);

    DevRuntimeEnv {
        home: home.to_path_buf(),
        workspace_root: workspace_root.to_path_buf(),
        worktree_id: runtime_id.to_string(),
        runtime_label,
        selection_source,
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
        plist_label: format!("{DEV_PLIST_LABEL}.{runtime_id}"),
        plist_path: PathBuf::from("/Library/LaunchDaemons")
            .join(format!("{DEV_PLIST_LABEL}.{runtime_id}.plist")),
        stderr_log_path: PathBuf::from("/var/log").join(format!("emberd.dev.{runtime_id}.err")),
        keyring_service: format!("{DEV_KEYRING_SERVICE_PREFIX}-{runtime_id}"),
        keyring_account: DEV_KEYRING_ACCOUNT.to_string(),
        gh_app_env_path: shared_config_dir.join("github.env"),
        gh_app_pem_path: shared_config_dir.join("github-app.pem"),
    }
}

fn shared_runtime_env(
    home: &Path,
    workspace_root: &Path,
    selection_source: RuntimeSelectionSource,
) -> DevRuntimeEnv {
    let shared_root = home.join(DEV_SHARED_STATE_DIR_REL);
    let run_dir = home.join(".ember/run");
    let shared_config_dir = home.join(DEV_CREDS_DIR_REL);

    DevRuntimeEnv {
        home: home.to_path_buf(),
        workspace_root: workspace_root.to_path_buf(),
        worktree_id: SHARED_DEV_RUNTIME_ID.to_string(),
        runtime_label: SHARED_DEV_RUNTIME_ID.to_string(),
        selection_source,
        env_root: shared_root.clone(),
        run_dir: run_dir.clone(),
        socket_path: home.join(DEV_DAEMON_SOCKET_REL),
        shadow_root: shared_root.join("shadow"),
        install_root: PathBuf::from(DEV_INSTALL_ROOT),
        manifest_path: home.join(DEV_MANIFEST_PATH_REL),
        config_path: shared_root.join("config.toml"),
        data_dir: shared_root.join("data"),
        policy_file: shared_root.join("policy.toml"),
        pid_file: run_dir.join("emberd-dev.pid"),
        vault_dir: shared_root.join("vault"),
        plist_label: DEV_PLIST_LABEL.to_string(),
        plist_path: PathBuf::from(format!("/Library/LaunchDaemons/{DEV_PLIST_LABEL}.plist")),
        stderr_log_path: PathBuf::from("/var/log/emberd.dev.err"),
        keyring_service: DEV_KEYRING_SERVICE_PREFIX.to_string(),
        keyring_account: DEV_KEYRING_ACCOUNT.to_string(),
        gh_app_env_path: shared_config_dir.join("github.env"),
        gh_app_pem_path: shared_config_dir.join("github-app.pem"),
    }
}

fn explicit_runtime_id_from_env() -> Result<Option<String>, String> {
    let Ok(raw) = std::env::var(DEV_RUNTIME_ID_ENV) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{DEV_RUNTIME_ID_ENV} is set but empty"));
    }
    parse_runtime_id(trimmed, DEV_RUNTIME_ID_ENV).map(Some)
}

fn parse_runtime_id(raw: &str, source: &str) -> Result<String, String> {
    let normalized = normalize_runtime_id(raw);
    if normalized.is_empty() {
        return Err(format!("{source} does not contain a valid runtime id"));
    }
    Ok(normalized)
}

fn normalize_runtime_id(raw: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;
    for ch in raw.chars().flat_map(char::to_lowercase) {
        let keep = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if keep {
            out.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.starts_with('-') {
        out.remove(0);
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn derive_runtime_id_for_path(path: &Path) -> String {
    let identity_root = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let hash = blake3::hash(identity_root.to_string_lossy().as_bytes());
    format!("rt-{}", &hex::encode(hash.as_bytes())[..8])
}

fn detect_runtime_selection_from_worktree(
    start: &Path,
) -> Result<Option<ManagedWorktreeSelection>, String> {
    for ancestor in start.ancestors() {
        if !looks_like_managed_worktree_root(ancestor) {
            continue;
        }
        let meta_path = ancestor.join(SESSION_META_FILE);
        if !meta_path.exists() {
            return Err(format!(
                "managed worktree at {} is missing {}",
                ancestor.display(),
                SESSION_META_FILE
            ));
        }
        let body = std::fs::read_to_string(&meta_path).map_err(|e| {
            format!(
                "failed to read managed worktree metadata at {}: {e}",
                meta_path.display()
            )
        })?;
        return Ok(Some(validate_managed_worktree_metadata(ancestor, &body)?));
    }
    Ok(None)
}

fn validate_managed_worktree_metadata(
    root: &Path,
    body: &str,
) -> Result<ManagedWorktreeSelection, String> {
    let declared_worktree_path = meta_value(body, "worktree_path").ok_or_else(|| {
        format!(
            "managed worktree metadata at {} is missing worktree_path",
            root.join(SESSION_META_FILE).display()
        )
    })?;
    let declared_worktree_path = PathBuf::from(declared_worktree_path);
    if declared_worktree_path != root {
        return Err(format!(
            "managed worktree metadata at {} points at {}, not {}",
            root.join(SESSION_META_FILE).display(),
            declared_worktree_path.display(),
            root.display()
        ));
    }
    if !root.join(".git").exists() {
        return Err(format!(
            "managed worktree metadata at {} is not rooted at a git worktree",
            root.join(SESSION_META_FILE).display()
        ));
    }

    let runtime_id = match meta_value(body, "runtime_id") {
        Some(value) => parse_runtime_id(value, "runtime_id")?,
        None => derive_runtime_id_for_path(root),
    };

    let runtime_label = meta_value(body, "session_name")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&runtime_id)
                .to_string()
        });

    Ok(ManagedWorktreeSelection {
        runtime_id,
        runtime_label,
        worktree_path: root.to_path_buf(),
    })
}

fn looks_like_managed_worktree_root(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(grandparent) = parent.parent() else {
        return false;
    };
    parent
        .file_name()
        .is_some_and(|name| name == WORKTREE_DIR_BASENAME)
        && grandparent.file_name().is_some_and(|name| {
            name == MANAGED_WORKTREE_ROOT_BASENAME || name == LEGACY_MANAGED_WORKTREE_ROOT_BASENAME
        })
}

fn meta_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    body.lines().find_map(|line| line.strip_prefix(&prefix))
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
            env.env_root.starts_with("/home/tester/.ember-dev/envs/"),
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

    #[test]
    fn shared_runtime_matches_existing_paths() {
        let runtime = shared_runtime_env(
            Path::new("/home/tester"),
            Path::new("/home/tester/repos/emberlink-dev"),
            RuntimeSelectionSource::SharedDefault,
        );
        assert_eq!(runtime.worktree_id, SHARED_DEV_RUNTIME_ID);
        assert_eq!(
            runtime.install_root,
            PathBuf::from("/usr/local/lib/ember-dev")
        );
        assert_eq!(
            runtime.socket_path,
            PathBuf::from("/home/tester/.ember/run/daemon.dev.sock")
        );
        assert_eq!(
            runtime.manifest_path,
            PathBuf::from("/home/tester/.ember-dev/binaries/manifest.toml")
        );
        assert_eq!(runtime.plist_label, "sh.emberlink.daemon.dev");
    }

    #[test]
    fn compact_banner_includes_label_id_and_source() {
        let runtime = derive_runtime_env_with_id(
            Path::new("/home/tester"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
            "rt-1234abcd",
            "auth posture".to_string(),
            RuntimeSelectionSource::ManagedWorktree,
        );
        assert_eq!(
            compact_runtime_banner(&runtime),
            "auth posture [rt-1234abcd via managed-worktree]"
        );
    }

    #[test]
    fn explicit_runtime_id_rejects_empty_env_value() {
        unsafe { std::env::set_var(DEV_RUNTIME_ID_ENV, "   ") };
        let err = explicit_runtime_id_from_env().expect_err("must reject empty");
        assert!(err.contains("empty"), "unexpected error: {err}");
        unsafe { std::env::remove_var(DEV_RUNTIME_ID_ENV) };
    }

    #[test]
    fn detects_runtime_selection_from_validated_managed_worktree_metadata() {
        let tmp = tempfile::tempdir().expect("tmp");
        let worktree = tmp.path().join(".ember/worktrees/auth-posture");
        let nested = worktree.join("crates/emberlink-cli");
        std::fs::create_dir_all(&nested).expect("nested dir");
        std::fs::write(worktree.join(".git"), "gitdir: /tmp/fake\n").expect(".git");
        std::fs::write(
            worktree.join(".agent-session"),
            format!(
                "session_name: Codex Auth Posture\nruntime_id: rt-1234abcd\nharness: codex\nworktree_path: {}\n",
                worktree.display()
            ),
        )
        .expect("session meta");

        let selection = detect_runtime_selection_from_worktree(&nested)
            .expect("detection")
            .expect("selection");
        assert_eq!(selection.runtime_id, "rt-1234abcd");
        assert_eq!(selection.runtime_label, "Codex Auth Posture");
    }

    #[test]
    fn managed_worktree_metadata_without_runtime_id_derives_opaque_id_from_path() {
        let tmp = tempfile::tempdir().expect("tmp");
        let worktree = tmp.path().join(".ember/worktrees/release-proof");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(worktree.join(".git"), "gitdir: /tmp/fake\n").expect(".git");
        let selection = validate_managed_worktree_metadata(
            &worktree,
            &format!(
                "session_name: Human Friendly Name\nworktree_path: {}\n",
                worktree.display()
            ),
        )
        .expect("valid metadata");
        assert!(selection.runtime_id.starts_with("rt-"));
        assert_eq!(selection.runtime_label, "Human Friendly Name");
    }

    #[test]
    fn managed_worktree_metadata_must_match_actual_worktree_path() {
        let tmp = tempfile::tempdir().expect("tmp");
        let worktree = tmp.path().join(".ember/worktrees/auth-posture");
        std::fs::create_dir_all(&worktree).expect("worktree");
        std::fs::write(worktree.join(".git"), "gitdir: /tmp/fake\n").expect(".git");
        let err = validate_managed_worktree_metadata(
            &worktree,
            "session_name: Codex Auth Posture\nruntime_id: rt-1234abcd\nworktree_path: /tmp/elsewhere\n",
        )
        .expect_err("mismatched worktree_path must fail");
        assert!(err.contains("points at"), "unexpected error: {err}");
    }

    #[test]
    fn managed_worktree_metadata_requires_git_root() {
        let tmp = tempfile::tempdir().expect("tmp");
        let worktree = tmp.path().join(".ember/worktrees/auth-posture");
        std::fs::create_dir_all(&worktree).expect("worktree");
        let err = validate_managed_worktree_metadata(
            &worktree,
            &format!(
                "session_name: Codex Auth Posture\nruntime_id: rt-1234abcd\nworktree_path: {}\n",
                worktree.display()
            ),
        )
        .expect_err("non-git worktree must fail");
        assert!(err.contains("git worktree"), "unexpected error: {err}");
    }
}
