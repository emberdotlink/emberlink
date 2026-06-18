//! `ember dev install` — worktree dev runtime install flow (ADR 157 Phase 4).
//!
//! This file ships the full ADR 157 Phase 4 dev-install path: dev
//! IdentityRoot generation, GH App provisioning, uid/group provisioning,
//! release build + signing, runtime binary install, manifest signing,
//! launchctl bootstrap, and post-install verify.
//!
//! CLASSIFICATION: PUBLIC

use super::gh_app;
use super::identity_root;
use super::uids;

/// Run `ember dev install`.
///
/// Phase 1: generate the dev IdentityRoot keypair and stash the private key
///   in Keychain. Idempotent — re-running loads the existing key.
/// Phase 2: GH App interactive provisioning (idempotent).
/// Phase 3: `_ember_dev` system user via dscl (idempotent).
/// Phase 4: `_ember_clients_dev` group via dscl + operator membership (idempotent).
pub fn run() -> Result<(), String> {
    let mut completion_issues = Vec::new();
    let runtime = crate::dev_runtime::resolve_current_dev_runtime()?;

    println!("worktree dev runtime:");
    println!(
        "  runtime:        {}",
        crate::dev_runtime::compact_runtime_banner(&runtime)
    );
    println!("  install root:   {}", runtime.install_root.display());
    println!("  plist label:    {}", runtime.plist_label);
    println!("  socket:         {}", runtime.socket_path.display());
    println!();

    // Phase 1: dev IdentityRoot key generation.
    eprintln!("[ember dev install] phase 1: dev IdentityRoot key generation");
    let handle = identity_root::ensure_dev_identity_root()?;
    println!("dev IdentityRoot fingerprint: {}", handle.fingerprint);
    println!("  keychain label: {}", identity_root::KEYCHAIN_LABEL);

    // Phase 2: GH App provisioning.
    eprintln!("[ember dev install] phase 2: GH App provisioning");
    match gh_app::ensure_gh_app() {
        Ok(record) => {
            println!("  GH App ID: {}", record.app_id);
            println!("  PEM: {}", record.pem_path.display());
        }
        Err(e) => {
            eprintln!("  warning: GH App provisioning incomplete: {e}");
            eprintln!(
                "  Run 'ember dev install' again after setting EMBER_DEV_GH_APP_ID + EMBER_DEV_GH_APP_PEM"
            );
            completion_issues.push(format!("GitHub App provisioning incomplete: {e}"));
        }
    }

    // Phase 3: `_ember_dev` system user.
    eprintln!("[ember dev install] phase 3: _ember_dev system user");
    uids::ensure_dev_daemon_user_real().map_err(|e| format!("phase 3 failed: {e}"))?;
    println!("  _ember_dev user: OK (UID {})", uids::DEV_DAEMON_UID);

    // Phase 4: `_ember_clients_dev` group.
    eprintln!("[ember dev install] phase 4: _ember_clients_dev group + operator membership");
    uids::ensure_clients_dev_group_real().map_err(|e| format!("phase 4 failed: {e}"))?;
    println!(
        "  _ember_clients_dev group: OK (GID {})",
        uids::CLIENTS_DEV_GID
    );

    // Phases 5-11: build/sign/install/bootstrap/verify via slice-C helpers.
    use crate::dev_install_slice_c::{
        RealCommandRunner, build_sign, install_binaries, launchctl, manifest, verify,
    };

    let runner = RealCommandRunner;

    // Phase 5+6: cargo build --release + code-sign with operator's Developer ID.
    eprintln!("[ember dev install] phase 5+6: cargo build --release + code-sign");
    let build =
        build_sign::build_and_sign(&runner).map_err(|e| format!("phase 5+6 failed: {e}"))?;
    println!(
        "  built + signed: {} (cli), {} (daemon), {} construct binaries",
        build.cli_signed_path.display(),
        build.daemon_signed_path.display(),
        build.construct_signed_paths.len()
    );

    // Phase 7: copy signed binaries to install root (idempotent via SHA-256 diff).
    eprintln!("[ember dev install] phase 7: install binaries");
    let changed = install_binaries::install_binaries(&runner, &build, &runtime.install_root)
        .map_err(|e| format!("phase 7 failed: {e}"))?;
    println!("  binaries copied: {} changed", changed.len());

    // Phase 7b: install the `claude` shadow shim — bare `claude` inside a
    // launcher-managed agent shell auto-routes through `ember claude-code`
    // (META-DEV-PROD-PARITY-BARE-CLAUDE-INSTALL-WIRING). The shim is the
    // unconditional half of the hybrid; the opt-in shell-init wrap is
    // prompted by the interactive install wizard.
    // Anchor: dev_prod_parity_bare_claude_install_wiring_landed.
    let shadow_dir = crate::launcher::core::resolve_shadow_dir();
    let installed_ember = runtime.install_root.join("ember");
    match install_binaries::install_claude_shadow_shim(&shadow_dir, &installed_ember) {
        Ok(true) => println!(
            "  claude shadow shim: written at {}",
            shadow_dir.join("bin/claude").display(),
        ),
        Ok(false) => println!(
            "  claude shadow shim: already up-to-date at {}",
            shadow_dir.join("bin/claude").display(),
        ),
        Err(e) => {
            eprintln!("  warning: claude shadow shim install failed: {e}");
            completion_issues.push(format!("claude shadow shim install failed: {e}"));
        }
    }

    // Phase 8: generate + sign manifest with dev IdentityRoot.
    eprintln!("[ember dev install] phase 8: manifest generation + signing");
    let entries =
        manifest::scan_tool_binaries(&runner).map_err(|e| format!("phase 8 (scan) failed: {e}"))?;
    let toml_str = manifest::render_manifest(&entries);
    let signing_key = identity_root::ensure_dev_identity_root_signing_key()?;
    let dest_dir = manifest::manifest_dest_dir(&runtime.manifest_path).ok_or_else(|| {
        "phase 8 failed: manifest dest dir not resolvable (no $HOME?)".to_string()
    })?;
    eprintln!(
        "  manifest target dir: {}; signing with dev IdentityRoot {}",
        dest_dir.display(),
        handle.fingerprint
    );
    let signature = manifest::sign_manifest(toml_str.as_bytes(), &signing_key)
        .map_err(|e| format!("phase 8 (sign) failed: {e}"))?;
    manifest::write_manifest(&toml_str, &signature, &dest_dir)
        .map_err(|e| format!("phase 8 (write) failed: {e}"))?;
    println!(
        "  manifest written: {} entr{} -> {}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        dest_dir.join("manifest.toml").display()
    );

    // Phase 9+10: render dev LaunchDaemon plist + launchctl bootstrap.
    eprintln!("[ember dev install] phase 9+10: plist install + launchctl bootstrap");
    launchctl::install_and_bootstrap(&runner, &handle.fingerprint, &runtime)
        .map_err(|e| format!("phase 9+10 failed: {e}"))?;
    println!("  dev daemon: bootstrapped");

    // Phase 11: post-install verify.
    eprintln!("[ember dev install] phase 11: verify");
    match verify::verify_dev_install_for(&runtime) {
        Ok(report) => {
            println!(
                "  verify: pid={:?} manifest_fp={:?} brokers={:?} trust_roots={:?} runtime_missing={:?}",
                report.daemon_pid,
                report.manifest_fingerprint,
                report.registered_broker_count,
                report.trust_roots,
                report.missing_runtime_artifacts,
            );
            completion_issues.extend(verify::readiness_issues(&report));
        }
        Err(e) => {
            eprintln!("  verify: WARN — {e}");
            completion_issues.push(format!("post-install verify failed: {e}"));
        }
    }

    if !completion_issues.is_empty() {
        eprintln!();
        eprintln!("ember dev install: incomplete");
        for issue in &completion_issues {
            eprintln!("  - {issue}");
        }
        eprintln!(
            "  Inspect `ember dev status` and re-run `ember dev install` after fixing the gaps above."
        );
        return Err("install did not reach ready state".to_string());
    }

    println!();
    println!("ember dev install: complete (ADR 157 §Component 4 all 11 phases wired)");
    Ok(())
}
