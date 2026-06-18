//! `ember dev info` / `ember dev status` — verify the dev install state.
//!
//! Read-only post-install diagnostic for ADR 157 / ADR 163. Reports the
//! current dev install state without minting new key material: IdentityRoot,
//! GitHub App provisioning, socket/plist/install paths, daemon PID, manifest
//! fingerprint, registered broker count, and trust roots.
//!
//! CLASSIFICATION: PUBLIC

use super::{gh_app, identity_root};
use crate::dev_runtime_artifacts::{DevRuntimeArtifactKind, runtime_artifacts};

/// Run `ember dev info`.
pub fn run() -> Result<(), String> {
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    let artifacts = runtime_artifacts();
    let mut issues = Vec::new();
    let installed_artifacts: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact.installed_path(&runtime).exists())
        .collect();
    let missing_artifacts: Vec<_> = artifacts
        .iter()
        .filter(|artifact| !artifact.installed_path(&runtime).exists())
        .map(|artifact| artifact.binary_name.clone())
        .collect();
    let construct_total = artifacts
        .iter()
        .filter(|artifact| artifact.kind == DevRuntimeArtifactKind::Construct)
        .count();
    let construct_installed = installed_artifacts
        .iter()
        .filter(|artifact| artifact.kind == DevRuntimeArtifactKind::Construct)
        .count();

    println!("ember dev install state");
    println!(
        "  runtime:        {}",
        crate::dev_runtime::compact_runtime_banner(&runtime)
    );
    println!("  install root:   {}", runtime.install_root.display());
    println!(
        "  ember cli:      {}",
        runtime.install_root.join("ember").display()
    );
    println!("  plist label:    {}", runtime.plist_label);
    println!("  socket:         {}", runtime.socket_path.display());
    println!("  shadow root:    {}", runtime.shadow_root.display());
    println!("  keychain label: {}", identity_root::KEYCHAIN_LABEL);
    println!(
        "  binaries:       {}/{} present (constructs: {}/{})",
        installed_artifacts.len(),
        artifacts.len(),
        construct_installed,
        construct_total
    );

    if !missing_artifacts.is_empty() {
        issues.push(format!(
            "runtime binaries missing from install root: {}",
            missing_artifacts.join(", ")
        ));
    }

    match identity_root::read_existing_dev_identity_root() {
        Ok(Some(handle)) => {
            println!(
                "  identity root:  {} (loaded from keychain)",
                handle.fingerprint
            );
        }
        Ok(None) => {
            println!("  identity root:  <missing>");
            issues.push("dev IdentityRoot missing".to_string());
        }
        Err(e) => {
            println!("  identity root:  <error> ({e})");
            issues.push(format!("dev IdentityRoot unreadable: {e}"));
        }
    }

    match gh_app::read_existing_gh_app() {
        Ok(Some(record)) => {
            println!(
                "  github app:     {} ({})",
                record.app_id,
                record.pem_path.display()
            );
        }
        Ok(None) => {
            println!("  github app:     <missing>");
            issues.push("GitHub App not provisioned".to_string());
        }
        Err(e) => {
            println!("  github app:     <error> ({e})");
            issues.push(format!("GitHub App config unreadable: {e}"));
        }
    }

    match crate::dev_install_slice_c::verify::verify_dev_install_for(&runtime) {
        Ok(report) => {
            println!("  daemon pid:     {:?}", report.daemon_pid);
            println!("  manifest sig:   {:?}", report.manifest_fingerprint);
            println!("  brokers:        {:?}", report.registered_broker_count);
            println!("  trust roots:    {:?}", report.trust_roots);
            issues.extend(crate::dev_install_slice_c::verify::readiness_issues(
                &report,
            ));
        }
        Err(e) => {
            println!("  verify:         <error> ({e})");
            issues.push(format!("post-install verify failed: {e}"));
        }
    }

    if issues.is_empty() {
        println!("  readiness:      READY");
    } else {
        println!("  readiness:      INCOMPLETE");
        for issue in issues {
            println!("  gap:            {issue}");
        }
    }

    Ok(())
}
