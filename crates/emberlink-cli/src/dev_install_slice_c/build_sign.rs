//! CLASSIFICATION: PUBLIC
//!
//! ADR 157 Phase 4 steps 5 + 6: cargo release build + code-sign.
//!
//! Build is `cargo build --release -p emberlink-cli -p ember-daemon -p
//! ember-construct`.
//! Sign uses the operator's Developer ID Application cert (resolved via
//! `security find-identity -p codesigning`). No notarization (dev only).
//!
//! Anchor: `dev_prod_parity_ember_dev_install_slice_c_landed`

use std::path::PathBuf;

use super::CommandRunner;
use crate::dev_runtime_artifacts::{DevRuntimeArtifactKind, build_packages, runtime_artifacts};

/// Output of a successful build + sign cycle.
#[derive(Debug)]
pub struct BuildSignResult {
    /// Path to the signed ember CLI (`target/release/ember`).
    pub cli_signed_path: PathBuf,
    /// Path to the signed emberd binary (`target/release/emberd`).
    pub daemon_signed_path: PathBuf,
    /// Paths to any additional signed construct binaries.
    pub construct_signed_paths: Vec<PathBuf>,
}

impl BuildSignResult {
    pub fn signed_paths(&self) -> impl Iterator<Item = &PathBuf> + '_ {
        std::iter::once(&self.cli_signed_path)
            .chain(std::iter::once(&self.daemon_signed_path))
            .chain(self.construct_signed_paths.iter())
    }
}

/// Build the worktree dev runtime (`ember`, `emberd`, and the construct
/// bundle) in release mode, then code-sign each binary with the operator's
/// Developer ID Application cert.
///
/// # Errors
///
/// Returns a boxed error if `cargo build` fails, if no suitable signing
/// identity is found via `security find-identity`, or if `codesign` fails for
/// any binary.
pub fn build_and_sign(
    runner: &dyn CommandRunner,
) -> Result<BuildSignResult, Box<dyn std::error::Error>> {
    // Phase 5: cargo build --release
    let mut cargo_args = vec!["build", "--release"];
    for package in build_packages() {
        cargo_args.push("-p");
        cargo_args.push(package);
    }
    runner.run("cargo", &cargo_args)?;

    let cli_path = PathBuf::from("target/release/ember");
    let daemon_path = PathBuf::from("target/release/emberd");
    let construct_paths: Vec<PathBuf> = runtime_artifacts()
        .into_iter()
        .filter(|artifact| artifact.kind == DevRuntimeArtifactKind::Construct)
        .map(|artifact| PathBuf::from("target/release").join(artifact.binary_name))
        .collect();

    // Phase 6: resolve signing identity + codesign each binary.
    let identity = resolve_signing_identity(runner)?;

    codesign_binary(runner, &cli_path, &identity)?;
    codesign_binary(runner, &daemon_path, &identity)?;
    for p in &construct_paths {
        codesign_binary(runner, p, &identity)?;
    }

    Ok(BuildSignResult {
        cli_signed_path: cli_path,
        daemon_signed_path: daemon_path,
        construct_signed_paths: construct_paths,
    })
}

/// Resolve the operator's Developer ID Application signing identity by querying
/// the macOS keychain via `security find-identity -p codesigning -v`.
///
/// Returns the first identity whose description contains
/// `"Developer ID Application"`.
///
/// # Errors
///
/// Returns an error if no such identity exists in the keychain or if the
/// `security` command fails.
fn resolve_signing_identity(
    runner: &dyn CommandRunner,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = runner.run("security", &["find-identity", "-p", "codesigning", "-v"])?;
    let text = String::from_utf8_lossy(&output);

    for line in text.lines() {
        if line.contains("Developer ID Application") {
            // Lines look like:
            //   1) HASH "Developer ID Application: Acme Corp (XXXXXXXXXX)"
            // Extract the quoted identity string.
            if let Some(start) = line.find('"')
                && let Some(end) = line.rfind('"')
                && end > start
            {
                return Ok(line[start + 1..end].to_string());
            }
        }
    }

    Err("no Developer ID Application cert found in keychain (run: security find-identity -p codesigning -v)".into())
}

/// Code-sign a single binary at `bin` with `identity` using
/// `codesign --sign <identity> --force --timestamp <bin>`.
///
/// # Errors
///
/// Returns an error if `codesign` exits non-zero.
fn codesign_binary(
    runner: &dyn CommandRunner,
    bin: &std::path::Path,
    identity: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let bin_str = bin
        .to_str()
        .ok_or_else(|| format!("binary path is not valid UTF-8: {}", bin.display()))?;
    runner.run(
        "codesign",
        &["--sign", identity, "--force", "--timestamp", bin_str],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct RecordingRunner {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        /// When set, the runner returns this error for commands whose program
        /// matches the given string.
        fail_on: Option<String>,
        /// Fake output to return from `security find-identity`.
        identity_output: Vec<u8>,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_on: None,
                identity_output: b"1) AABBCCDD \"Developer ID Application: Acme Corp (X1234567)\""
                    .to_vec(),
            }
        }

        fn recorded(&self) -> Vec<(String, Vec<String>)> {
            self.calls.borrow().clone()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            if let Some(ref fail) = self.fail_on
                && program == fail.as_str()
            {
                return Err(format!("simulated failure in {program}").into());
            }
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            if program == "security" {
                return Ok(self.identity_output.clone());
            }
            Ok(Vec::new())
        }
    }

    #[test]
    fn build_and_sign_issues_cargo_build_with_expected_args() {
        let runner = RecordingRunner::new();
        let result = build_and_sign(&runner);
        assert!(
            result.is_ok(),
            "build_and_sign should succeed: {:?}",
            result.err()
        );

        let calls = runner.recorded();
        let cargo_call = calls.iter().find(|(p, _)| p == "cargo");
        assert!(cargo_call.is_some(), "cargo must be invoked");

        let (_, args) = cargo_call.unwrap();
        assert!(args.contains(&"build".to_string()), "must pass 'build'");
        assert!(
            args.contains(&"--release".to_string()),
            "must pass '--release'"
        );
        assert!(args.contains(&"-p".to_string()), "must pass '-p'");
        assert!(
            args.contains(&"emberlink-cli".to_string()),
            "must target emberlink-cli"
        );
        assert!(
            args.contains(&"ember-daemon".to_string()),
            "must target ember-daemon"
        );
        assert!(
            args.contains(&"ember-construct".to_string()),
            "must target ember-construct"
        );
    }

    #[test]
    fn build_and_sign_invokes_codesign_for_each_binary() {
        let runner = RecordingRunner::new();
        let result = build_and_sign(&runner);
        assert!(
            result.is_ok(),
            "build_and_sign should succeed: {:?}",
            result.err()
        );

        let calls = runner.recorded();
        let codesign_calls: Vec<_> = calls.iter().filter(|(p, _)| p == "codesign").collect();
        assert!(
            !codesign_calls.is_empty(),
            "codesign must be invoked at least once"
        );
        let expected_codesign_calls = 2 + runtime_artifacts()
            .iter()
            .filter(|artifact| artifact.kind == DevRuntimeArtifactKind::Construct)
            .count();
        assert_eq!(
            codesign_calls.len(),
            expected_codesign_calls,
            "codesign count must match staged dev-runtime binaries"
        );

        // Every codesign call must pass --sign and --force.
        for (_, args) in &codesign_calls {
            assert!(
                args.contains(&"--sign".to_string()),
                "codesign must use --sign"
            );
            assert!(
                args.contains(&"--force".to_string()),
                "codesign must use --force"
            );
        }
    }

    #[test]
    fn build_and_sign_propagates_cargo_failure() {
        let mut runner = RecordingRunner::new();
        runner.fail_on = Some("cargo".to_string());
        let result = build_and_sign(&runner);
        assert!(result.is_err(), "must propagate cargo build failure");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("simulated failure in cargo"),
            "error message must name cargo: {msg}"
        );
    }

    #[test]
    fn resolve_signing_identity_extracts_quoted_identity() {
        // Provide multi-line output as the keychain might return.
        let output = b"    1) AABBCCDD \"Developer ID Application: Acme Corp (XYZW1234)\"\n    2) EEFF9900 \"Apple Development: dev@example.com\"\n".to_vec();

        struct FakeRunner(Vec<u8>);
        impl CommandRunner for FakeRunner {
            fn run(&self, _: &str, _: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                Ok(self.0.clone())
            }
        }

        let runner = FakeRunner(output);
        // Call via build_and_sign; check no error on identity resolution step.
        // (We do this indirectly — cargo will "succeed" too with empty output.)
        // Direct call: resolve_signing_identity is private; test through build_and_sign.
        // Instead, we verify via the codesign call that the right identity was passed.
        struct CheckingRunner {
            identity_out: Vec<u8>,
            codesign_args: RefCell<Vec<String>>,
        }
        impl CommandRunner for CheckingRunner {
            fn run(
                &self,
                program: &str,
                args: &[&str],
            ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                if program == "security" {
                    return Ok(self.identity_out.clone());
                }
                if program == "codesign" {
                    self.codesign_args
                        .borrow_mut()
                        .extend(args.iter().map(|s| s.to_string()));
                }
                Ok(Vec::new())
            }
        }

        let r = CheckingRunner {
            identity_out: runner.0,
            codesign_args: RefCell::new(Vec::new()),
        };
        build_and_sign(&r).expect("should succeed");
        let args = r.codesign_args.borrow();
        // The identity passed to --sign must be the Developer ID Application string.
        let sign_idx = args
            .iter()
            .position(|a| a == "--sign")
            .expect("--sign must appear");
        let identity_used = &args[sign_idx + 1];
        assert!(
            identity_used.contains("Developer ID Application"),
            "must use Developer ID Application cert; got: {identity_used}"
        );
    }

    #[test]
    fn build_and_sign_fails_when_no_developer_id_cert() {
        struct NoIdentityRunner;
        impl CommandRunner for NoIdentityRunner {
            fn run(
                &self,
                program: &str,
                _args: &[&str],
            ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                if program == "security" {
                    // No Developer ID Application entry.
                    return Ok(b"    1) AABB \"Apple Development: dev@example.com\"".to_vec());
                }
                Ok(Vec::new())
            }
        }
        let result = build_and_sign(&NoIdentityRunner);
        assert!(
            result.is_err(),
            "must fail when no Developer ID cert present"
        );
    }
}
