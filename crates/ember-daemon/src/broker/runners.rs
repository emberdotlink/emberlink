use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use core_event_types::{ActionRef, ExecutionContract, RunnerClass, RunnerPolicy};
use once_cell::sync::OnceCell;

use crate::binary_manifest::BinaryManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerBinarySource {
    ActionRef,
    WrappedBinary,
}

impl RunnerBinarySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ActionRef => "action_ref",
            Self::WrappedBinary => "wrapped_binary",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerCwdSource {
    WorkspaceRef,
    CompatibilityCwd,
}

impl RunnerCwdSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceRef => "workspace_ref",
            Self::CompatibilityCwd => "compatibility_cwd",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunnerDispatchResolution {
    pub(crate) runner_class: RunnerClass,
    pub(crate) binary: String,
    pub(crate) binary_source: RunnerBinarySource,
    pub(crate) cwd: Option<String>,
    pub(crate) cwd_source: Option<RunnerCwdSource>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RunnerDispatchError {
    #[error("runner_unavailable: no_runner_policy")]
    NoRunnerPolicy,
    #[error("runner_unavailable: no_enrolled_adapter for runner classes [{classes}]")]
    NoEnrolledAdapter { classes: String },
    #[error("{0}")]
    InvalidParams(String),
}

impl RunnerDispatchError {
    pub(crate) fn into_rpc_error(self) -> (i32, String) {
        match self {
            Self::NoRunnerPolicy | Self::NoEnrolledAdapter { .. } => (-32024, self.to_string()),
            Self::InvalidParams(message) => (-32602, message),
        }
    }
}

pub(crate) trait RunnerAdapter: Send + Sync {
    fn class(&self) -> RunnerClass;

    fn resolve_binary(
        &self,
        action_ref: &ActionRef,
    ) -> Result<(String, RunnerBinarySource), String>;

    fn resolve_exec(
        &self,
        contract: &ExecutionContract,
        compatibility_cwd: Option<&str>,
        workspace_path_hint: Option<&Path>,
    ) -> Result<RunnerDispatchResolution, String>;
}

pub(crate) fn runner_class_as_str(class: RunnerClass) -> &'static str {
    match class {
        RunnerClass::LocalTrusted => "local_trusted",
        RunnerClass::IsolatedLocal => "isolated_local",
        RunnerClass::InternalOnly => "internal_only",
        RunnerClass::TeeRequired => "tee_required",
        RunnerClass::VendorBound => "vendor_bound",
        RunnerClass::CheapTrustless => "cheap_trustless",
    }
}

pub(crate) fn dispatch_runner_for_resolve(
    contract: &ExecutionContract,
) -> Result<RunnerDispatchResolution, RunnerDispatchError> {
    let adapter = select_runner_adapter(&contract.runner_policy)?;
    let (binary, binary_source) = adapter
        .resolve_binary(&contract.action_ref)
        .map_err(RunnerDispatchError::InvalidParams)?;
    Ok(RunnerDispatchResolution {
        runner_class: adapter.class(),
        binary,
        binary_source,
        cwd: None,
        cwd_source: None,
    })
}

pub(crate) fn dispatch_runner_for_exec_with_workspace_path(
    contract: &ExecutionContract,
    compatibility_cwd: Option<&str>,
    workspace_path_hint: Option<&Path>,
) -> Result<RunnerDispatchResolution, RunnerDispatchError> {
    select_runner_adapter(&contract.runner_policy)?
        .resolve_exec(contract, compatibility_cwd, workspace_path_hint)
        .map_err(RunnerDispatchError::InvalidParams)
}

fn select_runner_adapter(
    runner_policy: &RunnerPolicy,
) -> Result<&'static dyn RunnerAdapter, RunnerDispatchError> {
    let candidate_order = runner_candidate_order(runner_policy);
    if candidate_order.is_empty() {
        return Err(RunnerDispatchError::NoRunnerPolicy);
    }

    for class in &candidate_order {
        if let Some(adapter) = enrolled_adapter(*class) {
            return Ok(adapter);
        }
    }

    Err(RunnerDispatchError::NoEnrolledAdapter {
        classes: candidate_order
            .iter()
            .map(|class| runner_class_as_str(*class))
            .collect::<Vec<_>>()
            .join(", "),
    })
}

fn runner_candidate_order(runner_policy: &RunnerPolicy) -> Vec<RunnerClass> {
    if runner_policy.preferred.is_empty() {
        return runner_policy.allowed.clone();
    }

    let mut order = runner_policy.preferred.clone();
    for class in &runner_policy.allowed {
        if !order.contains(class) {
            order.push(*class);
        }
    }
    order
}

fn enrolled_adapter(class: RunnerClass) -> Option<&'static dyn RunnerAdapter> {
    match class {
        RunnerClass::LocalTrusted => Some(&LOCAL_TRUSTED_RUNNER),
        RunnerClass::IsolatedLocal
        | RunnerClass::InternalOnly
        | RunnerClass::TeeRequired
        | RunnerClass::VendorBound
        | RunnerClass::CheapTrustless => None,
    }
}

struct LocalTrustedRunner;

static LOCAL_TRUSTED_RUNNER: LocalTrustedRunner = LocalTrustedRunner;

impl RunnerAdapter for LocalTrustedRunner {
    fn class(&self) -> RunnerClass {
        RunnerClass::LocalTrusted
    }

    fn resolve_binary(
        &self,
        action_ref: &ActionRef,
    ) -> Result<(String, RunnerBinarySource), String> {
        resolve_binary_from_action_ref(action_ref)
            .map(|path| {
                (
                    path.to_string_lossy().into_owned(),
                    RunnerBinarySource::ActionRef,
                )
            })
            .map_err(|err| {
                format!(
                    "runner-owned binary resolution failed for action_ref {}: {}",
                    action_ref, err
                )
            })
    }

    fn resolve_exec(
        &self,
        contract: &ExecutionContract,
        compatibility_cwd: Option<&str>,
        workspace_path_hint: Option<&Path>,
    ) -> Result<RunnerDispatchResolution, String> {
        let (binary, binary_source) = self.resolve_binary(&contract.action_ref)?;
        let (cwd, cwd_source) = resolve_runner_cwd_with_workspace_path(
            contract.workspace_ref.as_deref(),
            compatibility_cwd,
            workspace_path_hint,
        )?;
        Ok(RunnerDispatchResolution {
            runner_class: self.class(),
            binary,
            binary_source,
            cwd: Some(cwd),
            cwd_source: Some(cwd_source),
        })
    }
}

static MANAGED_WORKTREE_CACHE: OnceCell<Mutex<HashMap<String, PathBuf>>> = OnceCell::new();
const MANAGED_WORKTREE_SCAN_MAX_DEPTH: usize = 6;
const STARTUP_BINARY_MANIFEST_ENV: &str = "EMBER_MANIFEST_PATH";

fn runner_resolution_manifest_path() -> PathBuf {
    if let Some(path) = std::env::var_os(STARTUP_BINARY_MANIFEST_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.exists())
    {
        return path;
    }

    let bundled = crate::binary_manifest::bundled_install_dir().join("manifest.toml");
    if bundled.exists() {
        return bundled;
    }

    bundled
}

fn runner_resolution_manifest() -> Option<BinaryManifest> {
    if let Some(manifest) = crate::broker::handler::current_manifest() {
        return Some((*manifest).clone());
    }
    let manifest_path = runner_resolution_manifest_path();
    crate::binary_manifest::load_manifest(&manifest_path).ok()
}

pub(crate) fn resolve_binary_from_action_ref_with_manifest(
    manifest: &BinaryManifest,
    action_ref: &ActionRef,
) -> Result<PathBuf, String> {
    let tool_name = action_ref
        .plugin_address
        .rsplit('/')
        .next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("action_ref {} has no plugin-local tool segment", action_ref))?;
    let entry = crate::binary_manifest::lookup_construct(manifest, tool_name)
        .map_err(|e| format!("manifest lookup for {tool_name}: {e}"))?;
    Ok(entry.absolute_path.clone())
}

pub(crate) fn resolve_binary_from_action_ref(action_ref: &ActionRef) -> Result<PathBuf, String> {
    let manifest = runner_resolution_manifest()
        .ok_or_else(|| "no binary manifest is installed for runner-owned resolution".to_string())?;
    resolve_binary_from_action_ref_with_manifest(&manifest, action_ref)
}

fn workspace_meta_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}: ");
    body.lines().find_map(|line| line.strip_prefix(&prefix))
}

fn parse_managed_worktree_meta(meta_path: &Path) -> Option<(String, PathBuf)> {
    let body = std::fs::read_to_string(meta_path).ok()?;
    let workspace_ref = workspace_meta_value(&body, "workspace_ref")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            workspace_meta_value(&body, "runtime_id")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|runtime_id| format!("managed_worktree:{runtime_id}"))
        })?;
    let worktree_path = workspace_meta_value(&body, "worktree_path")?.trim();
    if worktree_path.is_empty() {
        return None;
    }
    Some((workspace_ref, PathBuf::from(worktree_path)))
}

fn normalize_existing_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn declared_worktree_path_matches(
    managed_root: &Path,
    declared_worktree_path: &Path,
    actual_worktree_path: &Path,
) -> bool {
    let declared = if declared_worktree_path.is_absolute() {
        declared_worktree_path.to_path_buf()
    } else {
        managed_root
            .parent()
            .unwrap_or(managed_root)
            .join(declared_worktree_path)
    };
    normalize_existing_path(&declared) == normalize_existing_path(actual_worktree_path)
}

fn should_prune_managed_worktree_scan(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".cargo" | ".rustup" | ".cache" | "Library" | "node_modules" | "target"
    )
}

fn lookup_runtime_id_in_managed_worktree_root(root: &Path, runtime_id: &str) -> Option<PathBuf> {
    let worktrees_dir = root.join("worktrees");
    let entries = std::fs::read_dir(worktrees_dir).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let worktree_path = entry.path();
        let meta_path = worktree_path.join(".agent-session");
        let Some((found_workspace_ref, declared_worktree_path)) =
            parse_managed_worktree_meta(&meta_path)
        else {
            continue;
        };
        if found_workspace_ref == format!("managed_worktree:{runtime_id}")
            && declared_worktree_path_matches(root, &declared_worktree_path, &worktree_path)
            && worktree_path.join(".git").exists()
        {
            return Some(worktree_path);
        }
    }
    None
}

fn scan_home_for_managed_worktree_runtime_id(
    root: &Path,
    runtime_id: &str,
    depth: usize,
) -> Option<PathBuf> {
    if depth > MANAGED_WORKTREE_SCAN_MAX_DEPTH {
        return None;
    }
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".ember" || name == ".claude" {
            if let Some(found) = lookup_runtime_id_in_managed_worktree_root(&path, runtime_id) {
                return Some(found);
            }
            continue;
        }
        if name.starts_with('.') || should_prune_managed_worktree_scan(&name) {
            continue;
        }
        if let Some(found) = scan_home_for_managed_worktree_runtime_id(&path, runtime_id, depth + 1)
        {
            return Some(found);
        }
    }
    None
}

pub(crate) fn resolve_workspace_ref_to_path_from_home(
    home: &Path,
    workspace_ref: &str,
) -> Result<PathBuf, String> {
    let runtime_id = workspace_ref
        .strip_prefix("managed_worktree:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("unsupported workspace_ref {workspace_ref:?}"))?;

    let cache = MANAGED_WORKTREE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .expect("managed-worktree cache mutex")
        .get(runtime_id)
        .cloned()
    {
        return Ok(cached);
    }

    let path = scan_home_for_managed_worktree_runtime_id(home, runtime_id, 0).ok_or_else(|| {
        format!(
            "managed worktree runtime_id {runtime_id} not found under {}",
            home.display()
        )
    })?;
    cache
        .lock()
        .expect("managed-worktree cache mutex")
        .insert(runtime_id.to_string(), path.clone());
    Ok(path)
}

#[cfg(test)]
pub(crate) fn resolve_runner_cwd(
    workspace_ref: Option<&str>,
    compatibility_cwd: Option<&str>,
) -> Result<(String, RunnerCwdSource), String> {
    resolve_runner_cwd_with_workspace_path(workspace_ref, compatibility_cwd, None)
}

pub(crate) fn resolve_runner_cwd_with_workspace_path(
    workspace_ref: Option<&str>,
    compatibility_cwd: Option<&str>,
    workspace_path_hint: Option<&Path>,
) -> Result<(String, RunnerCwdSource), String> {
    if let Some(workspace_ref) = workspace_ref {
        if let Some(workspace_path) = workspace_path_hint {
            let path = workspace_path.canonicalize().map_err(|e| {
                format!(
                    "registered workspace path for {} is not reachable at {}: {}",
                    workspace_ref,
                    workspace_path.display(),
                    e
                )
            })?;
            if !path.join(".git").exists() {
                return Err(format!(
                    "registered workspace path for {} is not a git worktree: {}",
                    workspace_ref,
                    path.display()
                ));
            }
            return Ok((
                path.to_string_lossy().into_owned(),
                RunnerCwdSource::WorkspaceRef,
            ));
        }
        return dirs_next::home_dir()
            .ok_or_else(|| {
                format!(
                    "runner-owned workspace resolution failed for {}: home directory unavailable",
                    workspace_ref
                )
            })
            .and_then(|home| {
                resolve_workspace_ref_to_path_from_home(&home, workspace_ref).map_err(|e| {
                    format!(
                        "runner-owned workspace resolution failed for {}: {}",
                        workspace_ref, e
                    )
                })
            })
            .map(|path| {
                (
                    path.to_string_lossy().into_owned(),
                    RunnerCwdSource::WorkspaceRef,
                )
            });
    }

    if let Some(cwd) = compatibility_cwd {
        return Path::new(cwd)
            .canonicalize()
            .map_err(|e| format!("compatibility broker_exec cwd fallback failed for {cwd:?}: {e}"))
            .map(|path| {
                (
                    path.to_string_lossy().into_owned(),
                    RunnerCwdSource::CompatibilityCwd,
                )
            });
    }

    Err("broker_exec requires execution_contract.workspace_ref or workspace_ref".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.previous.take() {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn runner_resolution_manifest_path_prefers_explicit_existing_manifest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_path = tmp.path().join("explicit-manifest.toml");
        std::fs::write(&manifest_path, b"# manifest").expect("write manifest");
        let _manifest_guard = EnvGuard::set(STARTUP_BINARY_MANIFEST_ENV, &manifest_path);

        assert_eq!(runner_resolution_manifest_path(), manifest_path);
    }

    #[test]
    fn runner_resolution_manifest_path_ignores_home_manifest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_dir = tmp.path().join(".ember/binaries");
        std::fs::create_dir_all(&manifest_dir).expect("mkdir manifest dir");
        let home_manifest = manifest_dir.join("manifest.toml");
        std::fs::write(&home_manifest, b"# legacy manifest").expect("write manifest");
        let _home_guard = EnvGuard::set("HOME", tmp.path());

        assert_ne!(runner_resolution_manifest_path(), home_manifest);
    }

    #[test]
    fn resolve_workspace_ref_accepts_launcher_relative_worktree_metadata() {
        let home = tempfile::tempdir().expect("home");
        let repo = home.path().join("repos/emberlink-dev");
        let worktree = repo.join(".ember/worktrees/yankee");
        std::fs::create_dir_all(&worktree).expect("create worktree");
        std::fs::write(
            worktree.join(".git"),
            "gitdir: ../../../.git/worktrees/yankee\n",
        )
        .expect("write git file");
        std::fs::write(
            worktree.join(".agent-session"),
            "session_name: yankee\nruntime_id: rt-relative-yankee\nworktree_path: .ember/worktrees/yankee\n",
        )
        .expect("write metadata");

        let resolved = resolve_workspace_ref_to_path_from_home(
            home.path(),
            "managed_worktree:rt-relative-yankee",
        )
        .expect("resolve workspace ref");

        assert_eq!(resolved, worktree);
    }
}
