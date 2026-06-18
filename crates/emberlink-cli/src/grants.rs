//! `ember grants ...` CLI subcommand handlers.
//!
//! Currently exposes `validate <file>` — wraps
//! [`core_grants_toml::GrantsManifest::validate`] for commit-time + dispatch-time
//! + broker-call-time three-gate validation per ADR 094.

use std::path::PathBuf;
use std::process::ExitCode;

use core_grants_toml::GrantsManifest;

/// Dispatch entry point — called from `ember.rs` when the user runs
/// `ember grants <subcommand>`. `rest` is the args after `grants`.
pub fn dispatch(rest: &[String]) -> ExitCode {
    match rest.first().map(String::as_str) {
        Some("validate") => match rest.get(1) {
            Some(path) => validate(PathBuf::from(path)),
            None => {
                eprintln!("usage: ember grants validate <path-to-grants.toml>");
                ExitCode::from(2)
            }
        },
        Some(other) => {
            eprintln!("ember grants: unknown subcommand {other:?}");
            eprintln!("known subcommands: validate");
            ExitCode::from(2)
        }
        None => {
            eprintln!("usage: ember grants <subcommand>");
            eprintln!("known subcommands: validate <path>");
            ExitCode::from(2)
        }
    }
}

fn validate(path: PathBuf) -> ExitCode {
    let toml_str = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ember grants validate: read {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };

    let manifest = match GrantsManifest::from_toml(&toml_str) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ember grants validate: parse {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };

    match manifest.validate() {
        Ok(()) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for err in errors {
                eprintln!("{err}");
            }
            ExitCode::from(1)
        }
    }
}
