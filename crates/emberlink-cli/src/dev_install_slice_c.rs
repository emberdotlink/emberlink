//! CLASSIFICATION: PUBLIC
//!
//! ember dev install — phases 5-11 helper modules (ADR 157 §Component 4).
//!
//! This crate-level module declares the five helper submodules that now back
//! phases 5-11 of `ember dev install`.
//!
//! Anchor: `dev_prod_parity_ember_dev_install_slice_c_landed`

/// Mockable command-execution abstraction used by all phase helpers in this
/// slice. Mirrors the `CommandRunner` pattern introduced in Slice B.
///
/// Each method receives the program name and a slice of arguments and returns
/// the captured stdout on success or a boxed error on failure.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// Real (production) `CommandRunner` — shells out via `std::process::Command`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = std::process::Command::new(program).args(args).output()?;
        if !output.status.success() {
            let code = output.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("`{program}` exited {code}: {stderr}").into());
        }
        Ok(output.stdout)
    }
}

#[path = "dev_install_slice_c/build_sign.rs"]
pub mod build_sign;

#[path = "dev_install_slice_c/config.rs"]
pub mod config;

#[path = "dev_install_slice_c/install_binaries.rs"]
pub mod install_binaries;

#[path = "dev_install_slice_c/manifest.rs"]
pub mod manifest;

#[path = "dev_install_slice_c/launchctl.rs"]
pub mod launchctl;

#[path = "dev_install_slice_c/verify.rs"]
pub mod verify;
