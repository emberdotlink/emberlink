//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 runtime-config seam for `ember dev install`.
//!
//! Writes the managed dev daemon config consumed by the separate-uid
//! LaunchDaemon path. ADR 179 amends the dev lane so config lands under the
//! current worktree's derived runtime root instead of one workstation-global
//! `.ember-dev` tree.

use std::fs;

use crate::dev_runtime::DevRuntimeEnv;

const DEFAULT_DEV_POLICY_TOML: &str = "\
# Ember daemon policy
# Rules evaluated in order — first match wins.

default_requirement = \"required\"
default_risk = \"medium\"

[[rules]]
action = \"git.push.main\"
risk = \"critical\"
requirement = \"denied\"

[[rules]]
action = \"git.push.*\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"deploy.production\"
risk = \"critical\"
requirement = \"required\"

[[rules]]
action = \"deploy.staging\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"credential.access\"
risk = \"high\"
requirement = \"required\"
";

fn escape_toml_string(path: &std::path::Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub fn render_dev_config(runtime: &DevRuntimeEnv) -> String {
    let socket_dir = escape_toml_string(&runtime.run_dir);
    let data_dir = escape_toml_string(&runtime.data_dir);
    let pid_file = escape_toml_string(&runtime.pid_file);
    let policy_file = escape_toml_string(&runtime.policy_file);

    format!(
        "\
# ember dev install — managed dev daemon config

[daemon]
socket_dir = \"{socket_dir}\"
data_dir = \"{data_dir}\"
pid_file = \"{pid_file}\"
policy_file = \"{policy_file}\"
log_level = \"info\"
tier = \"dev0\"

[keyring]
service = \"{service}\"
account = \"{account}\"
",
        service = runtime.keyring_service,
        account = runtime.keyring_account,
    )
}

fn sync_dev_runtime_files_for(runtime: &DevRuntimeEnv) -> Result<DevRuntimeEnv, String> {
    if let Some(parent) = runtime.config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create dev config dir {}: {e}", parent.display()))?;
    }
    if let Some(parent) = runtime.policy_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create dev policy dir {}: {e}", parent.display()))?;
    }
    fs::create_dir_all(&runtime.data_dir)
        .map_err(|e| format!("create dev data dir {}: {e}", runtime.data_dir.display()))?;
    fs::create_dir_all(&runtime.run_dir)
        .map_err(|e| format!("create dev run dir {}: {e}", runtime.run_dir.display()))?;
    fs::create_dir_all(&runtime.install_root).map_err(|e| {
        format!(
            "create dev install root {}: {e}",
            runtime.install_root.display()
        )
    })?;
    fs::create_dir_all(&runtime.vault_dir)
        .map_err(|e| format!("create dev vault dir {}: {e}", runtime.vault_dir.display()))?;

    fs::write(&runtime.config_path, render_dev_config(runtime))
        .map_err(|e| format!("write dev config {}: {e}", runtime.config_path.display()))?;

    if !runtime.policy_file.exists() {
        fs::write(&runtime.policy_file, DEFAULT_DEV_POLICY_TOML)
            .map_err(|e| format!("write dev policy {}: {e}", runtime.policy_file.display()))?;
    }

    Ok(runtime.clone())
}

pub fn sync_dev_runtime_files() -> Result<DevRuntimeEnv, String> {
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    sync_dev_runtime_files_for(&runtime)
}

pub fn sync_dev_runtime_files_with(runtime: &DevRuntimeEnv) -> Result<DevRuntimeEnv, String> {
    sync_dev_runtime_files_for(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_runtime::derive_dev_runtime_env;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn render_dev_config_uses_worktree_specific_paths_and_keyring() {
        let runtime = derive_dev_runtime_env(
            Path::new("/home/test-operator"),
            Path::new("/tmp/emberlink-dev/worktree-a"),
        );
        let rendered = render_dev_config(&runtime);

        assert!(
            rendered.contains(&format!("socket_dir = \"{}\"", runtime.run_dir.display())),
            "socket_dir must point at worktree-scoped run dir"
        );
        assert!(
            rendered.contains(&format!("data_dir = \"{}\"", runtime.data_dir.display())),
            "data_dir must point at worktree-scoped data dir"
        );
        assert!(
            rendered.contains(&format!("pid_file = \"{}\"", runtime.pid_file.display())),
            "pid_file must be worktree-scoped"
        );
        assert!(
            rendered.contains(&format!(
                "policy_file = \"{}\"",
                runtime.policy_file.display()
            )),
            "policy_file must be worktree-scoped"
        );
        assert!(
            rendered.contains(&format!("service = \"{}\"", runtime.keyring_service)),
            "config must isolate the keyring service"
        );
    }

    #[test]
    fn sync_dev_runtime_files_writes_config_and_policy() {
        let tmp = TempDir::new().unwrap();
        let runtime =
            derive_dev_runtime_env(tmp.path(), Path::new("/tmp/emberlink-dev/worktree-a"));
        let synced = sync_dev_runtime_files_with(&runtime).expect("sync runtime files");

        let config_text = fs::read_to_string(&synced.config_path).expect("read dev config");
        assert!(
            config_text.contains("# ember dev install — managed dev daemon config"),
            "managed config header missing"
        );
        assert!(
            synced.policy_file.exists(),
            "policy file must be created when absent"
        );
        assert!(synced.run_dir.exists(), "run dir must be created");
        assert!(synced.vault_dir.exists(), "vault dir must be created");

        let policy_text = fs::read_to_string(&synced.policy_file).expect("read dev policy");
        assert!(
            policy_text.contains("default_requirement = \"required\""),
            "default policy seed missing"
        );
    }
}
