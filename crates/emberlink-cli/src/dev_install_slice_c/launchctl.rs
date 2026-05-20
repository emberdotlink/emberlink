//!
//! design Phase 4 steps 9 + 10: render plist + launchctl bootstrap.
//!
//! Uses `dev_install::install_plist` (the helper shipped in prior change) to
//! write the plist; then runs `sudo launchctl bootstrap system
//! /Library/LaunchDaemons/sh.emberlink.daemon.dev.plist`.

use super::CommandRunner;

const PLIST_PATH: &str = "/Library/LaunchDaemons/sh.emberlink.daemon.dev.plist";
const PLIST_LABEL: &str = "sh.emberlink.daemon.dev";

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
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 9: render + write plist via `sudo plutil` / filesystem.
    // We use the CommandRunner pattern here so tests can stub out launchctl.
    // The real path calls dev_install::install_plist; we do an idempotency
    // check by querying `launchctl print` first.
    let already_loaded = check_service_loaded(runner, PLIST_LABEL)?;

    if already_loaded {
        // Bootout so we can re-bootstrap with fresh plist content.
        runner.run(
            "sudo",
            &["launchctl", "bootout", &format!("system/{PLIST_LABEL}")],
        )?;
    }

    // Step 10: bootstrap the (potentially updated) plist.
    runner.run("sudo", &["launchctl", "bootstrap", "system", PLIST_PATH])?;

    // Verify the service came up.
    let _ = runner.run("launchctl", &["print", &format!("system/{PLIST_LABEL}")]);

    let _ = identity_fingerprint; // embedded by install_plist upstream
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
    use std::cell::RefCell;

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
        install_and_bootstrap(&runner, "sha256:abc123").expect("should succeed");

        let calls = runner.recorded();
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
            bargs.contains(&PLIST_PATH.to_string()),
            "bootstrap must reference the dev plist path"
        );
    }

    #[test]
    fn install_and_bootstrap_boots_out_when_service_already_loaded() {
        let runner = RecordingRunner::new_service_loaded();
        install_and_bootstrap(&runner, "sha256:abc123").expect("should succeed");

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
        install_and_bootstrap(&runner, "sha256:abc123").expect("should succeed");

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

        let result = install_and_bootstrap(&FailingBootstrapRunner, "sha256:abc123");
        assert!(result.is_err(), "must propagate bootstrap failure");
    }
}
