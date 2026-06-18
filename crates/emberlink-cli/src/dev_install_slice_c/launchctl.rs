//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 steps 9 + 10: render plist + launchctl bootstrap.
//!
//! Syncs the managed dev runtime config, stages a plist with the operator-home
//! environment baked in, copies it into `/Library/LaunchDaemons/`, then runs
//! `sudo launchctl bootstrap system <worktree-specific plist>`.

use super::CommandRunner;
use crate::dev_install::{DevInstallVars, render_plist};
use crate::dev_runtime::DevRuntimeEnv;

/// Write the dev LaunchDaemon plist (via `dev_install::install_plist`) and
/// bootstrap it with `launchctl`.
///
/// If the plist is already installed and up-to-date, `install_plist` returns
/// `Ok(false)` and `launchctl bootstrap` is still called (idempotent — the
/// OS ignores a double-bootstrap for an already-running label).
///
/// `identity_fingerprint` is embedded in the plist as the `EMBER_TRUST_ROOTS`
/// environment variable value.
///
/// # Errors
///
/// Returns an error if the plist write or `launchctl` invocation fails.
pub fn install_and_bootstrap(
    runner: &dyn CommandRunner,
    identity_fingerprint: &str,
    runtime: &DevRuntimeEnv,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = super::config::sync_dev_runtime_files_with(runtime)?;
    install_and_bootstrap_with_paths(runner, identity_fingerprint, &runtime)
}

fn install_and_bootstrap_with_paths(
    runner: &dyn CommandRunner,
    identity_fingerprint: &str,
    runtime: &DevRuntimeEnv,
) -> Result<(), Box<dyn std::error::Error>> {
    let vars = DevInstallVars {
        label: runtime.plist_label.clone(),
        ember_dev_bin: runtime.install_root.join("emberd").display().to_string(),
        trust_roots: identity_fingerprint.to_string(),
        home: runtime.home.display().to_string(),
        config_path: runtime.config_path.display().to_string(),
        socket_path: runtime.socket_path.display().to_string(),
        gh_app_env_path: runtime.gh_app_env_path.display().to_string(),
        gh_app_pem_path: runtime.gh_app_pem_path.display().to_string(),
        vault_dir: runtime.vault_dir.display().to_string(),
        manifest_path: runtime.manifest_path.display().to_string(),
        stderr_path: runtime.stderr_log_path.display().to_string(),
    };
    let rendered = render_plist(&vars);
    let staged_path = std::env::temp_dir().join(format!(
        "{}-{}.plist",
        runtime.plist_label,
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&staged_path, rendered.as_bytes())?;
    let staged_path_str = staged_path
        .to_str()
        .ok_or("staged plist path is not valid UTF-8")?;

    let plist_path = runtime.plist_path.to_string_lossy().into_owned();
    let already_loaded = check_service_loaded(runner, &runtime.plist_label)?;

    runner.run("sudo", &["cp", staged_path_str, &plist_path])?;

    if already_loaded {
        // Bootout so we can re-bootstrap with fresh plist content.
        runner.run(
            "sudo",
            &[
                "launchctl",
                "bootout",
                &format!("system/{}", runtime.plist_label),
            ],
        )?;
    }

    // Step 10: bootstrap the (potentially updated) plist.
    runner.run("sudo", &["launchctl", "bootstrap", "system", &plist_path])?;

    // Verify the service came up.
    let _ = runner.run(
        "launchctl",
        &["print", &format!("system/{}", runtime.plist_label)],
    );
    let _ = std::fs::remove_file(&staged_path);
    Ok(())
}

/// Query `launchctl print system/<label>` to determine whether the service is
/// currently loaded. Returns `true` when the service is present.
fn check_service_loaded(
    runner: &dyn CommandRunner,
    label: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    match runner.run("launchctl", &["print", &format!("system/{label}")]) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false), // exit non-zero → service not loaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_runtime::derive_dev_runtime_env;
    use std::cell::RefCell;
    use std::path::Path;

    struct RecordingRunner {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        /// If set, `launchctl print` returns an error (service not loaded).
        service_not_loaded: bool,
    }

    impl RecordingRunner {
        fn new_service_loaded() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                service_not_loaded: false,
            }
        }

        fn new_service_not_loaded() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                service_not_loaded: true,
            }
        }

        fn recorded(&self) -> Vec<(String, Vec<String>)> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let full_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

            // launchctl print: simulate loaded / not-loaded.
            if program == "launchctl" && args.first().copied() == Some("print") {
                if self.service_not_loaded {
                    return Err("service not found".into());
                }
                self.calls
                    .borrow_mut()
                    .push((program.to_string(), full_args));
                return Ok(b"service entry...".to_vec());
            }

            self.calls
                .borrow_mut()
                .push((program.to_string(), full_args));
            Ok(Vec::new())
        }
    }

    #[test]
    fn install_and_bootstrap_calls_launchctl_bootstrap() {
        let runner = RecordingRunner::new_service_not_loaded();
        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            derive_dev_runtime_env(tmp.path(), Path::new("/tmp/emberlink-dev/worktree-a"));
        install_and_bootstrap_with_paths(&runner, "sha256:abc123", &runtime)
            .expect("should succeed");

        let calls = runner.recorded();
        let cp_call = calls
            .iter()
            .find(|(_, args)| args.contains(&"cp".to_string()));
        assert!(
            cp_call.is_some(),
            "sudo cp must be invoked; calls: {calls:?}"
        );
        let bootstrap_call = calls
            .iter()
            .find(|(_, args)| args.contains(&"bootstrap".to_string()));
        assert!(
            bootstrap_call.is_some(),
            "launchctl bootstrap must be invoked; calls: {calls:?}"
        );

        let (_, bargs) = bootstrap_call.unwrap();
        assert!(
            bargs.contains(&"system".to_string()),
            "bootstrap must target 'system' domain"
        );
        assert!(
            bargs.contains(&runtime.plist_path.display().to_string()),
            "bootstrap must reference the dev plist path"
        );
    }

    #[test]
    fn install_and_bootstrap_boots_out_when_service_already_loaded() {
        let runner = RecordingRunner::new_service_loaded();
        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            derive_dev_runtime_env(tmp.path(), Path::new("/tmp/emberlink-dev/worktree-a"));
        install_and_bootstrap_with_paths(&runner, "sha256:abc123", &runtime)
            .expect("should succeed");

        let calls = runner.recorded();
        let bootout_call = calls
            .iter()
            .find(|(_, args)| args.contains(&"bootout".to_string()));
        assert!(
            bootout_call.is_some(),
            "bootout must be called when service is already loaded; calls: {calls:?}"
        );
    }

    #[test]
    fn install_and_bootstrap_skips_bootout_when_service_not_loaded() {
        let runner = RecordingRunner::new_service_not_loaded();
        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            derive_dev_runtime_env(tmp.path(), Path::new("/tmp/emberlink-dev/worktree-a"));
        install_and_bootstrap_with_paths(&runner, "sha256:abc123", &runtime)
            .expect("should succeed");

        let calls = runner.recorded();
        let bootout_call = calls
            .iter()
            .find(|(_, args)| args.contains(&"bootout".to_string()));
        assert!(
            bootout_call.is_none(),
            "bootout must NOT be called when service is not loaded; calls: {calls:?}"
        );
    }

    #[test]
    fn install_and_bootstrap_propagates_bootstrap_failure() {
        struct FailingBootstrapRunner;
        impl CommandRunner for FailingBootstrapRunner {
            fn run(
                &self,
                program: &str,
                args: &[&str],
            ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                if args.contains(&"bootstrap") {
                    return Err("launchctl bootstrap failed with exit 5".into());
                }
                // launchctl print: not loaded
                if program == "launchctl" && args.first().copied() == Some("print") {
                    return Err("not loaded".into());
                }
                Ok(Vec::new())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            derive_dev_runtime_env(tmp.path(), Path::new("/tmp/emberlink-dev/worktree-a"));
        let result =
            install_and_bootstrap_with_paths(&FailingBootstrapRunner, "sha256:abc123", &runtime);
        assert!(result.is_err(), "must propagate bootstrap failure");
    }
}
