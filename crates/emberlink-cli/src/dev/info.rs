//! `ember dev info` / `ember dev status` — verify the dev install state.
//!
//! Read-only post-install diagnostic for design / design. Reports the
//! current dev install state without minting new key material: IdentityRoot,
//! GitHub App provisioning, socket/plist/install paths, daemon PID, manifest
//! fingerprint, registered broker count, and trust roots.
//!

use super::{gh_app, identity_root};

/// Run `ember dev info`.
pub fn run() -> Result<(), String> {
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;
    let mut issues = Vec::new();

    println!("ember dev install state");
    println!("  workspace root: {}", runtime.workspace_root.display());
    println!("  worktree id:    {}", runtime.worktree_id);
    println!("  install root:   {}", runtime.install_root.display());
    println!("  plist label:    {}", runtime.plist_label);
    println!("  socket:         {}", runtime.socket_path.display());
    println!("  shadow root:    {}", runtime.shadow_root.display());
    println!("  keychain label: {}", identity_root::KEYCHAIN_LABEL);

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
