use super::*;

/// Resolve the credential value for `ember vault add` / `ember vault put`
/// from the safe input flags (`--stdin`, `--file <path>`, terminal prompt).
///
/// Returns `Ok(bytes)` on success, or `Err(exit_code)` after emitting a
/// human-readable error to stderr (1 for runtime failures, 2 for input
/// validation refusals like `--file` under `~/Downloads`).
pub(super) fn resolve_credential_input(
    stdin: bool,
    file: Option<&Path>,
    delete_source: bool,
    from_downloads: bool,
) -> Result<Vec<u8>, i32> {
    if stdin {
        let mut buf = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut buf) {
            eprintln!("error: failed to read stdin: {e}");
            return Err(1);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            eprintln!("error: --stdin received empty value");
            return Err(1);
        }
        return Ok(buf);
    }
    if let Some(path) = file {
        let downloads_dir = dirs_next::download_dir();
        if !from_downloads
            && let Some(dl) = downloads_dir.as_ref()
            && path.starts_with(dl)
        {
            eprintln!(
                "error: --file refuses paths under ~/Downloads ({}) — \
                 Downloads is a known cleartext-credential leak surface.",
                dl.display()
            );
            eprintln!(
                "       Move the file to a non-Downloads path, or pass \
                 --from-downloads to acknowledge the risk."
            );
            return Err(2);
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: failed to read --file {}: {e}", path.display());
                return Err(1);
            }
        };
        if bytes.is_empty() {
            eprintln!("error: --file {} is empty", path.display());
            return Err(1);
        }
        if delete_source {
            // Best-effort overwrite-then-unlink; matches the existing
            // `ember vault add` behavior. fsync is omitted intentionally.
            let zeros = vec![0u8; bytes.len()];
            if let Err(e) = std::fs::write(path, &zeros) {
                eprintln!(
                    "warn: --delete-source: failed to zero {}: {e}",
                    path.display()
                );
            }
            if let Err(e) = std::fs::remove_file(path) {
                eprintln!(
                    "warn: --delete-source: failed to unlink {}: {e}",
                    path.display()
                );
            }
        }
        return Ok(bytes);
    }
    if io::stdin().is_terminal() {
        return match rpassword::prompt_password("Paste credential value: ") {
            Ok(s) if s.is_empty() => {
                eprintln!("error: empty value");
                Err(1)
            }
            Ok(s) => Ok(s.into_bytes()),
            Err(e) => {
                eprintln!("error: failed to read prompt: {e}");
                Err(1)
            }
        };
    }
    eprintln!(
        "error: no value source. Pass --stdin (pipe or terminal) or \
         --file <path>; --value is refused (leaks via shell history)."
    );
    Err(2)
}

fn zero_and_unlink_source(path: &Path, len: usize) {
    let zeros = vec![0u8; len];
    if let Err(e) = std::fs::write(path, &zeros) {
        eprintln!(
            "warn: --delete-source: failed to zero {}: {e}",
            path.display()
        );
    }
    if let Err(e) = std::fs::remove_file(path) {
        eprintln!(
            "warn: --delete-source: failed to unlink {}: {e}",
            path.display()
        );
    }
}

fn recovery_passphrase_flag_set(flag: &Option<Option<String>>) -> bool {
    match flag {
        None => false,
        Some(None) => true,
        Some(Some(value)) if value.is_empty() => true,
        Some(Some(_)) => refuse_value_in_argv("recovery-passphrase"),
    }
}

fn passphrase_from_bytes(mut bytes: Vec<u8>) -> Result<zeroize::Zeroizing<String>, i32> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        eprintln!("error: recovery passphrase is empty");
        return Err(1);
    }
    let passphrase = String::from_utf8(bytes).map_err(|e| {
        eprintln!("error: recovery passphrase must be valid UTF-8: {e}");
        1
    })?;
    Ok(zeroize::Zeroizing::new(passphrase))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VaultLockDispatch {
    DaemonRpc,
    SecureEnclave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VaultUnlockRoute {
    DaemonRpc,
    SecureEnclaveNoop,
    SecureEnclavePrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VaultActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VaultStatusView {
    pub(super) posture: String,
    pub(super) unlocked: bool,
    pub(super) live_vault_attached: bool,
    pub(super) session_pin_count: usize,
    pub(super) grace_window_secs: u64,
    pub(super) grace_remaining_secs: u64,
    pub(super) grace_lock_pending: bool,
    pub(super) grace_zero_due: bool,
    pub(super) idle_secs: Option<u64>,
    pub(super) idle_timeout_secs: u64,
    pub(super) quiet_hours_start: Option<u8>,
    pub(super) quiet_hours_end: Option<u8>,
}

impl VaultStatusView {
    fn from_json(value: &serde_json::Value) -> Result<Self, core_types::ValidationError> {
        let posture = value["posture"]
            .as_str()
            .ok_or_else(|| core_types::ValidationError::new("vault_status: missing posture"))?
            .to_string();
        let unlocked = value["unlocked"]
            .as_bool()
            .ok_or_else(|| core_types::ValidationError::new("vault_status: missing unlocked"))?;
        let live_vault_attached = value["live_vault_attached"].as_bool().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing live_vault_attached")
        })?;
        let session_pin_count = value["session_pin_count"].as_u64().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing session_pin_count")
        })? as usize;
        let grace_window_secs = value["grace_window_secs"].as_u64().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing grace_window_secs")
        })?;
        let grace_remaining_secs = value["grace_remaining_secs"].as_u64().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing grace_remaining_secs")
        })?;
        let grace_lock_pending = value["grace_lock_pending"].as_bool().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing grace_lock_pending")
        })?;
        let grace_zero_due = value["grace_zero_due"].as_bool().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing grace_zero_due")
        })?;
        let idle_timeout_secs = value["idle_timeout_secs"].as_u64().ok_or_else(|| {
            core_types::ValidationError::new("vault_status: missing idle_timeout_secs")
        })?;
        let quiet_hours_start =
            if value.get("quiet_hours_start").is_some() && !value["quiet_hours_start"].is_null() {
                Some(value["quiet_hours_start"].as_u64().ok_or_else(|| {
                    core_types::ValidationError::new("vault_status: invalid quiet_hours_start")
                })? as u8)
            } else {
                None
            };
        let quiet_hours_end =
            if value.get("quiet_hours_end").is_some() && !value["quiet_hours_end"].is_null() {
                Some(value["quiet_hours_end"].as_u64().ok_or_else(|| {
                    core_types::ValidationError::new("vault_status: invalid quiet_hours_end")
                })? as u8)
            } else {
                None
            };
        let idle_secs = if value.get("idle_secs").is_some() && !value["idle_secs"].is_null() {
            Some(value["idle_secs"].as_u64().ok_or_else(|| {
                core_types::ValidationError::new("vault_status: invalid idle_secs")
            })?)
        } else {
            None
        };
        Ok(Self {
            posture,
            unlocked,
            live_vault_attached,
            session_pin_count,
            grace_window_secs,
            grace_remaining_secs,
            grace_lock_pending,
            grace_zero_due,
            idle_secs,
            idle_timeout_secs,
            quiet_hours_start,
            quiet_hours_end,
        })
    }

    fn local_fallback() -> Self {
        Self {
            posture: "hard-locked".to_string(),
            unlocked: false,
            live_vault_attached: false,
            session_pin_count: 0,
            grace_window_secs: 0,
            grace_remaining_secs: 0,
            grace_lock_pending: false,
            grace_zero_due: false,
            idle_secs: None,
            idle_timeout_secs: 0,
            quiet_hours_start: None,
            quiet_hours_end: None,
        }
    }

    pub(super) fn summary_line(&self) -> String {
        match self.posture.as_str() {
            "interactive-unlocked" => format!(
                "interactive-unlocked (live vault attached; {} session pin{})",
                self.session_pin_count,
                if self.session_pin_count == 1 { "" } else { "s" }
            ),
            "presence-locked-vault-pinned" => format!(
                "presence-locked (live vault still attached; {} session pin{})",
                self.session_pin_count,
                if self.session_pin_count == 1 { "" } else { "s" }
            ),
            "presence-locked-vault-attached" if self.grace_lock_pending => format!(
                "presence-locked (live vault still attached; {}s grace remaining)",
                self.grace_remaining_secs
            ),
            "presence-locked-vault-attached" => {
                "presence-locked (live vault still attached)".to_string()
            }
            "hard-locked" => "hard-locked (live vault detached)".to_string(),
            other => other.to_string(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn render_vault_status_text(view: &VaultStatusView) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "VAULT LANE         {}", view.summary_line());
    let _ = writeln!(
        out,
        "  Presence:  {}",
        if view.unlocked { "unlocked" } else { "locked" }
    );
    let _ = writeln!(
        out,
        "  Live MEK:   {}",
        if view.live_vault_attached {
            "attached"
        } else {
            "detached"
        }
    );
    let _ = writeln!(out, "  Session pins: {}", view.session_pin_count);
    if let Some(idle_secs) = view.idle_secs {
        let _ = writeln!(
            out,
            "  Idle:      {}s / {}s",
            idle_secs, view.idle_timeout_secs
        );
    } else if view.idle_timeout_secs > 0 {
        let _ = writeln!(out, "  Idle:      locked / {}s", view.idle_timeout_secs);
    }
    if view.grace_lock_pending {
        let _ = writeln!(
            out,
            "  Grace:     active ({}s remaining)",
            view.grace_remaining_secs
        );
    } else if view.grace_zero_due {
        let _ = writeln!(out, "  Grace:     due (awaiting hard-lock cleanup)");
    } else if view.grace_window_secs > 0 {
        let _ = writeln!(
            out,
            "  Grace:     inactive ({}s window)",
            view.grace_window_secs
        );
    }
    match (view.quiet_hours_start, view.quiet_hours_end) {
        (Some(start), Some(end)) => {
            let _ = writeln!(out, "  Quiet hrs: {}:00-{}:00 UTC", start, end);
        }
        _ => {
            let _ = writeln!(out, "  Quiet hrs: off");
        }
    }
    out.trim_end().to_string()
}

pub(super) struct VaultStoreResult {
    pub(super) dispatch: VaultActionDispatch,
    pub(super) id: String,
    pub(super) name: String,
}

/// Lock the live vault on the current authority surface.
///
/// `ember vault lock` must act on the daemon's shared in-process state rather
/// than only this CLI process. Without a daemon socket there is no authoritative
/// live vault session to lock.
pub(super) fn run_vault_lock(
    config: &DaemonConfig,
) -> Result<VaultLockDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        emberlink_cli::call_daemon_method(&socket_path, "vault_lock", &serde_json::Value::Null)?;
        Ok(VaultLockDispatch::DaemonRpc)
    } else {
        Err(vault_control_daemon_required("lock"))
    }
}

/// Re-open the live vault on the current authority surface.
///
/// On the installed daemon-backed path this exercises the explicit
/// non-session reopen seam. Without a daemon socket there is no authoritative
/// live vault session to unlock.
pub(super) fn run_vault_unlock(
    config: &DaemonConfig,
) -> Result<VaultLockDispatch, core_types::ValidationError> {
    let current_launcher_lane = detect_current_launcher_lane();
    let managed_daemon_issue = detect_managed_daemon_issue(current_launcher_lane.as_ref());
    run_vault_unlock_with_managed_daemon_issue(config, managed_daemon_issue.as_ref())
}

pub(super) fn run_vault_unlock_with_managed_daemon_issue(
    config: &DaemonConfig,
    managed_daemon_issue: Option<&ManagedDaemonIssue>,
) -> Result<VaultLockDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        if let Some(issue) = managed_daemon_issue {
            return Err(core_types::ValidationError::new(format!(
                "vault unlock refused until the managed daemon is refreshed: {}. {}",
                issue.detail(),
                issue.repair_guidance()
            )));
        }
        match detect_vault_unlock_route(config) {
            VaultUnlockRoute::DaemonRpc => {
                emberlink_cli::call_daemon_method(
                    &socket_path,
                    "vault_unlock",
                    &serde_json::Value::Null,
                )?;
                Ok(VaultLockDispatch::DaemonRpc)
            }
            VaultUnlockRoute::SecureEnclaveNoop => Ok(VaultLockDispatch::SecureEnclave),
            VaultUnlockRoute::SecureEnclavePrompt => {
                run_vault_se_unlock(DEFAULT_OPERATOR_PRESENCE_SE_LABEL, None, false)?;
                Ok(VaultLockDispatch::SecureEnclave)
            }
        }
    } else {
        Err(vault_control_daemon_required("unlock"))
    }
}

pub(super) fn plan_vault_unlock_route(state: SeCustodyState) -> VaultUnlockRoute {
    if !state.se_backend_real || !state.presence_device_enrolled || !state.kek_wrap_present {
        return VaultUnlockRoute::DaemonRpc;
    }
    if state.authority_window_open {
        VaultUnlockRoute::SecureEnclaveNoop
    } else {
        VaultUnlockRoute::SecureEnclavePrompt
    }
}

#[cfg(target_os = "macos")]
fn detect_vault_unlock_route(config: &DaemonConfig) -> VaultUnlockRoute {
    plan_vault_unlock_route(detect_se_custody_state(
        config,
        DEFAULT_OPERATOR_PRESENCE_SE_LABEL,
    ))
}

#[cfg(not(target_os = "macos"))]
fn detect_vault_unlock_route(_config: &DaemonConfig) -> VaultUnlockRoute {
    VaultUnlockRoute::DaemonRpc
}

/// ADR 206 §4 — shared core that provisions presence-as-decryption custody
/// (macOS). Generate the operator authority scope KEK, `se_wrap` it to this
/// device's ECIES recipient key (public-key op, no Touch ID), and register the
/// wrapped blob + the KEK (for the current window) with the daemon via the
/// `vault.se_provision` RPC (shipped in #5179).
///
/// This is the single seam called from BOTH the standalone `ember vault
/// se-provision` command and the auto-provision step of `ember device enroll
/// --secure-enclave` — there is exactly one place that drives the RPC, so the
/// two paths can never drift on derivations or method name. On the non-JSON
/// path it prints the shared `device_id` / `ecies_key_id` block; each caller
/// owns its own follow-up notice line. The §4 provision is a clean-break
/// re-point of any prior custody (dev0 sole-operator cutover; intended).
#[cfg(target_os = "macos")]
pub(super) fn provision_vault_se_scope_kek(
    se_label: &str,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    if !se::se_backend_is_real() {
        return Err(core_types::ValidationError::new(
            "ember vault se-provision: this binary lacks real Secure Enclave support \
             (unsigned / no se-real). Refusing to provision §4 custody with a software key.",
        ));
    }

    // Signing key → device_id; ECIES key → ecies_key_id. Derivations MUST match
    // the daemon's operator_identity (device-operator-<pk>, key-operator-ecies-<pk>).
    let sign_key = se::find_secure_enclave_key(se_label).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember vault se-provision: signing SE key '{se_label}' not found (enroll first): {e}"
        ))
    })?;
    let sign_pub = se::se_pubkey_bytes(&sign_key).map_err(|e| {
        core_types::ValidationError::new(format!("ember vault se-provision: signing pubkey: {e}"))
    })?;
    let device_id = format!("device-operator-{}", hex::encode(&sign_pub));

    let ecies_label = format!("{se_label}-ecies");
    let ecies_key = se::find_secure_enclave_key(&ecies_label).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember vault se-provision: ECIES SE key '{ecies_label}' not found (enroll first): {e}"
        ))
    })?;
    let ecies_pub = se::se_pubkey_bytes(&ecies_key).map_err(|e| {
        core_types::ValidationError::new(format!("ember vault se-provision: ECIES pubkey: {e}"))
    })?;
    let ecies_key_id = format!("key-operator-ecies-{}", hex::encode(&ecies_pub));

    // Generate KEK_s from OS entropy and wrap it to the ECIES recipient (public-
    // key op — no presence prompt). KEK_s is best-effort scrubbed after; it
    // transits the socket at provision/unlock (the §4 honesty clause accepts this
    // at dev0 — eviction is the load-bearing control).
    let mut kek = [0u8; 32];
    getrandom::fill(&mut kek).map_err(|e| {
        core_types::ValidationError::new(format!("ember vault se-provision: OS entropy: {e}"))
    })?;
    let ecies_role = se::EciesKeyLabel::from_provisioned(ecies_label);
    let wrapped = se::se_wrap(&ecies_role, &kek).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember vault se-provision: se_wrap to ECIES recipient failed: {e}"
        ))
    })?;

    let socket_path = emberlink_cli::daemon_socket_path();
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_provision",
        &serde_json::json!({
            "device_id": device_id,
            "ecies_key_id": ecies_key_id,
            "wrapped_kek": hex::encode(&wrapped),
            "scope_kek": hex::encode(kek),
        }),
    );
    kek.fill(0); // best-effort scrub
    let result = result?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }
    println!("Provisioned ADR 206 §4 presence-as-decryption custody.");
    println!("  device_id:     {device_id}");
    println!("  ecies_key_id:  {ecies_key_id}");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn provision_vault_se_scope_kek(
    _se_label: &str,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember vault se-provision (ADR 206 §4) is only available on macOS",
    ))
}

/// ADR 206 §4 — standalone `ember vault se-provision` command. A thin wrapper
/// over the shared `provision_vault_se_scope_kek` core (the same seam the
/// `device enroll --secure-enclave` auto-provision uses), kept for explicit
/// re-cutover of §4 custody.
#[cfg(target_os = "macos")]
pub(super) fn run_vault_se_provision(
    se_label: &str,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    provision_vault_se_scope_kek(se_label, json_output)?;
    if !json_output {
        println!("Run `ember vault se-unlock` (one Touch ID tap) to open authority custody.");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn run_vault_se_provision(
    _se_label: &str,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember vault se-provision (ADR 206 §4) is only available on macOS",
    ))
}

/// ADR 206 §6 — unlock the authority scope with a printed `age` recovery code
/// instead of a presence tap (used after device loss). Cross-platform: pure
/// software `age` decrypt of the stored recovery wrap + the daemon unlock RPCs.
/// The daemon NEVER sees the code (finding C3) — it is used only locally here.
fn run_recovery_code_unlock(
    code: &str,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    // Derive the recipient from the code to locate ITS stored wrap (one recovery
    // code ⇒ one `key-recovery-ecies-<age1…>` recipient).
    let recovery_pub = core_crypto::recovery_public_from_secret(code).map_err(|e| {
        core_types::ValidationError::new(format!("ember vault se-unlock --recovery-code: {e}"))
    })?;
    let ecies_key_id = format!("key-recovery-ecies-{recovery_pub}");

    let socket_path = emberlink_cli::daemon_socket_path();
    let begin = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_unlock_begin",
        &serde_json::Value::Null,
    )?;
    let wraps = begin
        .get("wraps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let wrapped_hex = wraps
        .iter()
        .find(|w| w.get("ecies_key_id").and_then(|v| v.as_str()) == Some(ecies_key_id.as_str()))
        .and_then(|w| w.get("wrapped_kek").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            core_types::ValidationError::new(format!(
                "ember vault se-unlock --recovery-code: no recovery wrap registered for this code \
                 (ecies_key_id={ecies_key_id}). Was it enrolled with `ember vault enroll-recovery`?"
            ))
        })?;

    let mut kek = core_crypto::unwrap_secret_with_identity(code, wrapped_hex).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember vault se-unlock --recovery-code: failed to decrypt KEK_s with this code: {e}"
        ))
    })?;
    if kek.len() != 32 {
        kek.iter_mut().for_each(|b| *b = 0);
        return Err(core_types::ValidationError::new(format!(
            "ember vault se-unlock --recovery-code: recovered KEK_s is {} bytes, expected 32",
            kek.len()
        )));
    }
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_unlock_complete",
        &serde_json::json!({ "scope_kek": hex::encode(&kek) }),
    );
    kek.iter_mut().for_each(|b| *b = 0); // best-effort scrub
    let result = result?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }
    println!("Authority custody unlocked via recovery code (ADR 206 §6).");
    println!(
        "⚠  Treat this recovery code as SPENT: enroll a fresh one with \
         `ember vault enroll-recovery` and discard the old."
    );
    Ok(())
}

/// Unwrap THIS device's authority scope `KEK_s` via its Secure-Enclave ECIES key
/// (the presence tap). Shared by `se-unlock` and `enroll-recovery` (which needs
/// `KEK_s` cleartext to wrap it to the new recovery recipient). Returns the 32-byte
/// `KEK_s`; the caller MUST scrub it after use.
#[cfg(target_os = "macos")]
fn unwrap_this_device_scope_kek(
    se_label: &str,
    touch_id_reason: &str,
) -> Result<Vec<u8>, core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    let ecies_label = format!("{se_label}-ecies");
    let ecies_key = se::find_secure_enclave_key(&ecies_label).map_err(|e| {
        core_types::ValidationError::new(format!("ECIES SE key '{ecies_label}' not found: {e}"))
    })?;
    let ecies_pub = se::se_pubkey_bytes(&ecies_key)
        .map_err(|e| core_types::ValidationError::new(format!("ECIES pubkey: {e}")))?;
    let ecies_key_id = format!("key-operator-ecies-{}", hex::encode(&ecies_pub));

    let socket_path = emberlink_cli::daemon_socket_path();
    let begin = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_unlock_begin",
        &serde_json::Value::Null,
    )?;
    let wraps = begin
        .get("wraps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let wrapped_hex = wraps
        .iter()
        .find(|w| w.get("ecies_key_id").and_then(|v| v.as_str()) == Some(ecies_key_id.as_str()))
        .and_then(|w| w.get("wrapped_kek").and_then(|v| v.as_str()))
        .ok_or_else(|| {
            core_types::ValidationError::new(format!(
                "no wrapped scope KEK registered for this device (ecies_key_id={ecies_key_id}). \
                 Run `ember vault se-provision` first."
            ))
        })?;
    let wrapped = hex::decode(wrapped_hex)
        .map_err(|e| core_types::ValidationError::new(format!("bad wrapped_kek hex: {e}")))?;

    println!("{touch_id_reason}");
    let ecies_role = se::EciesKeyLabel::from_provisioned(ecies_label);
    let kek = se::se_unwrap(&ecies_role, &wrapped).map_err(|e| {
        core_types::ValidationError::new(format!(
            "se_unwrap failed (Touch ID declined or key unavailable): {e}"
        ))
    })?;
    if kek.len() != 32 {
        let mut k = kek;
        k.iter_mut().for_each(|b| *b = 0);
        return Err(core_types::ValidationError::new(
            "unwrapped scope KEK is not 32 bytes",
        ));
    }
    Ok(kek)
}

/// ADR 206 §4 — unlock authority custody with a presence tap (macOS), OR with a
/// printed recovery code (`--recovery-code`, ADR 206 §6, cross-platform). Fetch
/// the daemon's stored wrapped scope KEK, `se_unwrap` it (the Touch ID gesture),
/// and hand the unwrapped KEK back to the daemon. The daemon never touches the
/// presence-gated SE key nor the recovery secret.
#[cfg(target_os = "macos")]
pub(super) fn run_vault_se_unlock(
    se_label: &str,
    recovery_code: Option<&str>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    if let Some(code) = recovery_code {
        return run_recovery_code_unlock(code, json_output);
    }

    if !se::se_backend_is_real() {
        return Err(core_types::ValidationError::new(
            "ember vault se-unlock: this binary lacks real Secure Enclave support (unsigned / no se-real)",
        ));
    }

    let mut kek = unwrap_this_device_scope_kek(
        se_label,
        "Touch ID required: unwrapping the authority scope key on the Secure Enclave…",
    )
    .map_err(|e| core_types::ValidationError::new(format!("ember vault se-unlock: {e}")))?;

    let socket_path = emberlink_cli::daemon_socket_path();
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_unlock_complete",
        &serde_json::json!({ "scope_kek": hex::encode(&kek) }),
    );
    kek.iter_mut().for_each(|b| *b = 0); // best-effort scrub
    let result = result?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }
    println!("Authority custody unlocked (ADR 206 §4 presence-as-decryption).");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn run_vault_se_unlock(
    _se_label: &str,
    recovery_code: Option<&str>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    // The recovery-code path is pure software (age) + daemon RPCs, so it works
    // off-macOS too — important for recovering on a fresh non-Mac host.
    if let Some(code) = recovery_code {
        return run_recovery_code_unlock(code, json_output);
    }
    Err(core_types::ValidationError::new(
        "ember vault se-unlock (ADR 206 §4) is only available on macOS \
         (use --recovery-code on other platforms)",
    ))
}

/// ADR 206 §6 — enroll an off-host recovery recipient (printed `age` code). The
/// operator's existing presence SE key AUTHORIZES the enrollment (one tap) and
/// then unwraps `KEK_s` (a second tap) so it can be sealed to the new recipient.
/// The daemon never holds the recovery secret (finding C3); it is shown ONCE here.
#[cfg(target_os = "macos")]
pub(super) fn run_vault_enroll_recovery(
    se_label: &str,
    label: &str,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    run_recovery_enroll_shared(se_label, label, json_output, RecoveryEnrollOrigin::Vault)
}

/// Distinguishes the `ember vault enroll-recovery` and `ember device enroll
/// --recovery-code` surfaces in the shared implementation. The flow is
/// identical (same daemon RPCs, same age-recipient generation, same KEK_s
/// seal) — only the framing diverges (program name in error messages, AC-2
/// card emission on the device surface).
#[cfg(target_os = "macos")]
pub(super) enum RecoveryEnrollOrigin<'a> {
    /// `ember vault enroll-recovery` — the original consumer-side verb.
    Vault,
    /// `ember device enroll --recovery-code` — the device-tree surface that
    /// additionally emits an AC-2 confirmation card.
    Device {
        ac2_emit: &'a dyn Fn(
            /* enroll_result */ &serde_json::Value,
            /* recovery_pub */ &str,
            /* device_label */ &str,
        ) -> Result<(), core_types::ValidationError>,
    },
}

#[cfg(target_os = "macos")]
fn run_recovery_enroll_shared(
    se_label: &str,
    label: &str,
    json_output: bool,
    origin: RecoveryEnrollOrigin<'_>,
) -> Result<(), core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    let program_label = match origin {
        RecoveryEnrollOrigin::Vault => "ember vault enroll-recovery",
        RecoveryEnrollOrigin::Device { .. } => "ember device enroll --recovery-code",
    };

    if !se::se_backend_is_real() {
        return Err(core_types::ValidationError::new(format!(
            "{program_label}: this binary lacks real Secure Enclave support \
             (unsigned / no se-real); cannot authorize the enrollment.",
        )));
    }

    // AUTHORITY = the operator's existing presence SIGNING key.
    let raw_sign = se::find_secure_enclave_key(se_label).map_err(|e| {
        core_types::ValidationError::new(format!(
            "{program_label}: presence signing key '{se_label}' not found \
             (enroll a presence device first via `ember device enroll`): {e}"
        ))
    })?;
    let sign_pub = se::se_pubkey_bytes(&raw_sign).map_err(|e| {
        core_types::ValidationError::new(format!("{program_label}: signing pubkey: {e}"))
    })?;
    let authority_device_key = format!("p256:{}", hex::encode(&sign_pub));
    let sign_key = se::SignKeyHandle::from_provisioned(raw_sign);

    // Generate the recovery identity in THIS session (the daemon never sees it).
    let (secret, recovery_pub) = core_crypto::generate_recovery_identity();

    let socket_path = emberlink_cli::daemon_socket_path();

    // PREPARE: the DeviceEnrolled(Recovery) bytes the authority must sign.
    let prepared = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.recovery.enroll",
        &serde_json::json!({
            "recovery_pubkey": recovery_pub,
            "label": label,
            "authority_device_key": authority_device_key,
        }),
    )?;
    let to_sign = prepared
        .get("to_sign")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if to_sign.is_empty() {
        return Err(core_types::ValidationError::new(format!(
            "{program_label}: daemon returned an empty signing plan",
        )));
    }
    let recovery_ecies_key_id = prepared
        .get("recovery_ecies_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new(format!(
                "{program_label}: daemon did not return recovery_ecies_key_id",
            ))
        })?
        .to_string();

    // SIGN the enrollment with the authority presence key (one tap).
    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(to_sign.len());
    for step in &to_sign {
        let bytes_hex = step
            .get("bytes_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    format!("{program_label}: malformed signing step",),
                )
            })?;
        let bytes = hex::decode(bytes_hex).map_err(|e| {
            core_types::ValidationError::new(format!("{program_label}: bad bytes_hex: {e}"))
        })?;
        messages.push(core_crypto::context_message(
            core_crypto::DOMAIN_EVENT,
            &bytes,
        ));
    }
    let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let signatures: Vec<String> = se::se_sign_batch(
        &sign_key,
        se::SingleIntent::new(&message_refs),
        "Authenticate to enroll a recovery code for your Emberlink identity",
    )
    .map_err(|e| {
        core_types::ValidationError::new(format!(
            "{program_label}: SE signing failed (Touch ID declined or key unavailable): {e}"
        ))
    })?
    .iter()
    .map(hex::encode)
    .collect();

    // COMMIT: append the DeviceEnrolled(Recovery) event.
    let committed = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.recovery.enroll",
        &serde_json::json!({
            "recovery_pubkey": recovery_pub,
            "label": label,
            "authority_device_key": authority_device_key,
            "signatures": signatures,
        }),
    )?;
    let device_id = committed
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Seal KEK_s to the recovery recipient: unwrap THIS device's KEK_s (second tap)
    // then age-wrap it to the recovery public half (software, public-key op).
    let mut kek = unwrap_this_device_scope_kek(
        se_label,
        "Touch ID required: unwrapping the authority scope key to seal it to the recovery code…",
    )
    .map_err(|e| core_types::ValidationError::new(format!("{program_label}: {e}")))?;
    let wrapped_hex = core_crypto::wrap_secret_to_recipient(&recovery_pub, &kek);
    kek.iter_mut().for_each(|b| *b = 0); // scrub regardless of outcome
    let wrapped_hex = wrapped_hex.map_err(|e| {
        core_types::ValidationError::new(format!("{program_label}: age-wrap KEK_s: {e}"))
    })?;
    emberlink_cli::call_daemon_method(
        &socket_path,
        "vault.se_add_recipient_wrap",
        &serde_json::json!({
            "device_id": device_id,
            "ecies_key_id": recovery_ecies_key_id,
            "wrapped_kek": wrapped_hex,
        }),
    )?;

    // AC-2 card (device origin only): bind the recovery recipient pubkey to
    // the operator root pubkey so an independent verifier can re-check the
    // recipient was enrolled under the same root as the presence device.
    if let RecoveryEnrollOrigin::Device { ac2_emit } = &origin {
        ac2_emit(&committed, &recovery_pub, label)?;
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "recovery_enrolled",
                "device_id": device_id,
                "recovery_ecies_key_id": recovery_ecies_key_id,
                "recovery_code": secret,
            }))
            .unwrap_or_default()
        );
        return Ok(());
    }
    println!("Recovery recipient enrolled (ADR 206 §6).");
    println!();
    println!("  ┌─ STORE THIS RECOVERY CODE SOMEWHERE SAFE — shown ONCE ──────────");
    println!("  │  {secret}");
    println!("  └─────────────────────────────────────────────────────────────────");
    println!();
    println!("Recover after device loss with:  ember vault se-unlock --recovery-code <CODE>");
    println!(
        "Anyone with this code AND access to this machine can recover your key — treat it like a password."
    );
    Ok(())
}

/// `ember device enroll --recovery-code` — same flow as
/// `run_vault_enroll_recovery` (shared implementation), plus emit an AC-2
/// confirmation card binding the recovery recipient to the operator root.
#[cfg(target_os = "macos")]
pub(super) fn run_device_recovery_code_enroll(
    se_label: &str,
    label: &str,
    ac2_card_path: Option<&std::path::Path>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    let ac2_emit = |enroll_result: &serde_json::Value,
                    recovery_pub: &str,
                    device_label: &str|
     -> Result<(), core_types::ValidationError> {
        // The operator root pubkey is recorded in the enroll result so the
        // verifier can re-derive the root id from it (ADR 200 AC-2).
        let operator_root_pubkey = enroll_result
            .get("operator_root_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "ember device enroll --recovery-code: daemon did not return operator_root_pubkey",
                )
            })?;
        let card = super::build_ac2_oob_confirmation_card_for_recovery(
            enroll_result,
            device_label,
            operator_root_pubkey,
            recovery_pub,
        )?;
        if let Some(path) = ac2_card_path {
            super::write_ac2_oob_confirmation_card(path, &card)?;
        }
        super::print_ac2_oob_confirmation_card(&card, ac2_card_path);
        Ok(())
    };
    run_recovery_enroll_shared(
        se_label,
        label,
        json_output,
        RecoveryEnrollOrigin::Device {
            ac2_emit: &ac2_emit,
        },
    )
}

#[cfg(not(target_os = "macos"))]
pub(super) fn run_vault_enroll_recovery(
    _se_label: &str,
    _label: &str,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember vault enroll-recovery (ADR 206 §6) is only available on macOS \
         (the authorizing presence device is a Secure Enclave key)",
    ))
}

/// ADR 206 §4 + ADR 158 — the canonical Secure Enclave keychain label for the
/// operator presence device. MUST match the `--se-label` default in `args.rs`
/// (used by `ember device enroll --secure-enclave`, `ember vault se-provision`,
/// `ember vault se-unlock`) so the front-loaded `ember init` custody bootstrap
/// and the standalone repair verbs derive the SAME `device_id` / `ecies_key_id`
/// and can never drift onto a second presence device.
pub(super) const DEFAULT_OPERATOR_PRESENCE_SE_LABEL: &str = "ember-operator-presence";

/// The single custody step the front-loading `ember init` bootstrap must drive
/// to move a host from "no presence custody" to "authority window open",
/// computed purely from detected host state. Keeping the branch decision in a
/// pure function lets it be unit-tested without a Secure Enclave or a daemon
/// (the I/O — SE key probes, the daemon wrap lookup, the vault-status read —
/// lives in `detect_se_custody_state` and the `ember.rs` executor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PresenceCustodyPlan {
    /// This binary has no real Secure Enclave (unsigned / built without
    /// `se-real`). §4 custody cannot be provisioned with a software key, so the
    /// bootstrap is a no-op and the rest of `init` proceeds — the daemon's
    /// non-§4 lanes still work on such hosts (dev builds, CI).
    SkipNoSecureEnclave,
    /// A presence tap would be required to finish, but the operator asked for
    /// `--non-interactive`. Skip and surface the manual provisioning ladder
    /// rather than half-provisioning custody we cannot then open.
    SkipNonInteractive,
    /// No presence device is enrolled on this host → run the full enroll
    /// ceremony (`device enroll --secure-enclave`, one tap), which auto-chains
    /// the §4 KEK provision, then open the unlock window.
    EnrollProvisionThenUnlock,
    /// A presence device is enrolled but no wrapped scope KEK is registered for
    /// it → provision the §4 KEK (a public-key wrap, no tap) then open the
    /// unlock window. This is the front-loaded fix for the gauntlet's
    /// `se-unlock → "run se-provision first"` dead-end.
    ProvisionThenUnlock,
    /// Custody is provisioned but the authority window is closed → open it with
    /// one presence tap (`se-unlock`).
    UnlockOnly,
    /// Custody is provisioned and the authority window is already open. No-op.
    AlreadyOpen,
}

/// Decide the single custody step `ember init` must drive, from detected host
/// state. Pure: encodes only the policy. The caller performs all I/O and runs
/// the resulting plan against the existing custody primitives.
///
/// `presence_device_enrolled` is keyed on the presence *signing* key existing
/// on the host — that key is only ever created by the enroll ceremony, so its
/// presence is the proxy for "this device was enrolled." We therefore never
/// re-run enroll on an already-enrolled host (which would risk a duplicate
/// enrollment), only provision/unlock.
pub(super) fn plan_presence_custody_bootstrap(
    se_backend_real: bool,
    non_interactive: bool,
    presence_device_enrolled: bool,
    kek_wrap_present: bool,
    authority_window_open: bool,
) -> PresenceCustodyPlan {
    if !se_backend_real {
        return PresenceCustodyPlan::SkipNoSecureEnclave;
    }
    let plan = if !presence_device_enrolled {
        PresenceCustodyPlan::EnrollProvisionThenUnlock
    } else if !kek_wrap_present {
        PresenceCustodyPlan::ProvisionThenUnlock
    } else if !authority_window_open {
        PresenceCustodyPlan::UnlockOnly
    } else {
        PresenceCustodyPlan::AlreadyOpen
    };
    // Every non-AlreadyOpen plan needs at least one presence tap to FINISH (the
    // enroll signing batch, or the se-unlock unwrap). `--non-interactive` cannot
    // tap, so defer to the manual ladder rather than leave custody half-built.
    if non_interactive && plan != PresenceCustodyPlan::AlreadyOpen {
        return PresenceCustodyPlan::SkipNonInteractive;
    }
    plan
}

/// Detected §4 presence-custody state for the front-loading `init` bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SeCustodyState {
    pub(super) se_backend_real: bool,
    pub(super) presence_device_enrolled: bool,
    pub(super) kek_wrap_present: bool,
    pub(super) authority_window_open: bool,
}

/// Probe this host's §4 presence-custody state without taking a presence tap.
/// All three signals are read-only: the signing-key probe is a keychain
/// lookup, the wrap lookup is the read-only `vault.se_unlock_begin` RPC (the
/// tap is the later `se_unwrap`, which we do NOT perform here), and the window
/// state comes from `vault_status`. On a host without a real Secure Enclave we
/// report `se_backend_real = false` and probe nothing else.
#[cfg(target_os = "macos")]
pub(super) fn detect_se_custody_state(config: &DaemonConfig, se_label: &str) -> SeCustodyState {
    use ember_broker::secure_enclave as se;

    if !se::se_backend_is_real() {
        return SeCustodyState {
            se_backend_real: false,
            presence_device_enrolled: false,
            kek_wrap_present: false,
            authority_window_open: false,
        };
    }

    let presence_device_enrolled = se::find_secure_enclave_key(se_label).is_ok();
    let authority_window_open = run_vault_status(config)
        .ok()
        .map(|(_, view)| view.unlocked)
        .unwrap_or(false);

    // A wrapped scope KEK can only be registered for an enrolled device's ECIES
    // recipient. Compute this device's `ecies_key_id` (same derivation as
    // `run_vault_se_unlock`) and look for a matching wrap. Any failure → treat
    // as "not provisioned" and let the bootstrap provision it.
    let ecies_label = format!("{se_label}-ecies");
    let kek_wrap_present = se::find_secure_enclave_key(&ecies_label)
        .ok()
        .and_then(|ecies_key| se::se_pubkey_bytes(&ecies_key).ok())
        .map(|ecies_pub| format!("key-operator-ecies-{}", hex::encode(&ecies_pub)))
        .map(|ecies_key_id| {
            let socket_path = emberlink_cli::daemon_socket_path();
            emberlink_cli::call_daemon_method(
                &socket_path,
                "vault.se_unlock_begin",
                &serde_json::Value::Null,
            )
            .ok()
            .and_then(|begin| {
                begin.get("wraps").and_then(|v| v.as_array()).map(|wraps| {
                    wraps.iter().any(|w| {
                        w.get("ecies_key_id").and_then(|v| v.as_str())
                            == Some(ecies_key_id.as_str())
                    })
                })
            })
            .unwrap_or(false)
        })
        .unwrap_or(false);

    SeCustodyState {
        se_backend_real: true,
        presence_device_enrolled,
        kek_wrap_present,
        authority_window_open,
    }
}

#[cfg(not(target_os = "macos"))]
pub(super) fn detect_se_custody_state(_config: &DaemonConfig, _se_label: &str) -> SeCustodyState {
    SeCustodyState {
        se_backend_real: false,
        presence_device_enrolled: false,
        kek_wrap_present: false,
        authority_window_open: false,
    }
}

pub(super) fn run_vault_status(
    config: &DaemonConfig,
) -> Result<(VaultActionDispatch, VaultStatusView), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "vault_status",
            &serde_json::Value::Null,
        )?;
        Ok((
            VaultActionDispatch::DaemonRpc,
            VaultStatusView::from_json(&result)?,
        ))
    } else if uses_managed_separate_uid_topology(config) {
        Err(managed_local_vault_fallback_refused())
    } else {
        Ok((
            VaultActionDispatch::LocalFallback,
            VaultStatusView::local_fallback(),
        ))
    }
}

/// List vault entries on the current authority surface.
pub(super) fn run_vault_list(
    config: &DaemonConfig,
    prefix: Option<&str>,
) -> Result<(VaultActionDispatch, Vec<serde_json::Value>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "vault_list",
            &serde_json::Value::Null,
        )?;
        let mut entries = result
            .as_array()
            .cloned()
            .ok_or_else(|| core_types::ValidationError::new("daemon vault_list: expected array"))?;
        if let Some(p) = prefix
            && !p.is_empty()
        {
            entries.retain(|entry| {
                entry
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|name| name.starts_with(p))
                    .unwrap_or(false)
            });
        }
        Ok((VaultActionDispatch::DaemonRpc, entries))
    } else if uses_managed_separate_uid_topology(config) {
        Err(managed_local_vault_fallback_refused())
    } else {
        let store = open_store(config);
        let vault = Vault::open_from_config(config, &store)
            .map_err(|e| core_types::ValidationError::new(format!("vault open: {e}")))?;
        let mut creds = vault
            .list(VaultScope::Interactive, &store)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        if let Some(p) = prefix
            && !p.is_empty()
        {
            creds.retain(|c| c.name.starts_with(p));
        }
        let entries = creds
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "name": c.name,
                    "metadata": c.metadata,
                    // Wire-compat field name (`requires_biometric`)
                    // preserved per the presence-policy unification;
                    // populated from the typed PresencePolicy on the row.
                    "requires_biometric": c.presence_policy.requires_fresh_presence(),
                })
            })
            .collect();
        Ok((VaultActionDispatch::LocalFallback, entries))
    }
}

/// Remove a vault entry via the daemon's `vault_remove` RPC.
///
/// vault_actions_migrated_to_rpc: under ADR 131's separate-uid posture the
/// daemon owns the SQLite DB; the prior `open_store(config)` local fallback
/// was silently-broken-by-design. Per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-VAULT
/// the fallback branch was removed; missing-socket errors surface clearly
/// through `call_daemon_method`.
pub(super) fn run_vault_remove(
    config: &DaemonConfig,
    name: &str,
) -> Result<VaultActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_remove",
        &serde_json::json!({ "name": name }),
    )?;
    Ok(VaultActionDispatch::DaemonRpc)
}

/// Fetch a vault entry via the daemon's `vault_get` RPC.
///
/// Local fallback removed per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-VAULT;
/// see the `vault_actions_migrated_to_rpc` note on [`run_vault_remove`].
pub(super) fn run_vault_get(
    config: &DaemonConfig,
    name: &str,
) -> Result<(VaultActionDispatch, Vec<u8>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_get",
        &serde_json::json!({ "name": name }),
    )?;
    if let Some(bytes) = result.get("value_bytes").and_then(|v| v.as_array()) {
        let mut out = Vec::with_capacity(bytes.len());
        for item in bytes {
            let byte = item.as_u64().ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon vault_get: value_bytes must be an array of integers",
                )
            })?;
            let byte = u8::try_from(byte).map_err(|_| {
                core_types::ValidationError::new(
                    "daemon vault_get: value_bytes entries must fit in u8",
                )
            })?;
            out.push(byte);
        }
        return Ok((VaultActionDispatch::DaemonRpc, out));
    }

    let value = result
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| core_types::ValidationError::new("daemon vault_get: missing value"))?;
    Ok((VaultActionDispatch::DaemonRpc, value.as_bytes().to_vec()))
}

/// Store a vault entry via the daemon's `vault_add` or `vault_put` RPC.
///
/// Local fallback removed per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-VAULT;
/// see the `vault_actions_migrated_to_rpc` note on [`run_vault_remove`].
pub(super) fn run_vault_store(
    config: &DaemonConfig,
    method: &str,
    name: &str,
    value: &[u8],
    metadata: Option<&str>,
    require_biometric: bool,
) -> Result<VaultStoreResult, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        method,
        &serde_json::json!({
            "name": name,
            "value_bytes": value,
            "metadata": metadata,
            "require_biometric": require_biometric,
        }),
    )?;
    let id = result
        .get("id")
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    let stored_name = result
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(name)
        .to_string();
    Ok(VaultStoreResult {
        dispatch: VaultActionDispatch::DaemonRpc,
        id,
        name: stored_name,
    })
}

/// Migrate MEK keyring ACL via the daemon's `vault_migrate_acl` RPC.
///
/// Per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-VAULT: routes through the
/// daemon so the operation lands in the daemon's audit log
/// (`vault.mek_acl_migrated`) and respects the separate-uid keyring scope
/// (ADR 131). The CLI's prior direct `migrate_mek_acl()` call bypassed
/// the audit trail. See the `vault_actions_migrated_to_rpc` checkpoint on
/// [`run_vault_remove`].
pub(super) fn run_vault_migrate_acl(
    config: &DaemonConfig,
) -> Result<serde_json::Value, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let service = resolve_keyring_service(&config.keyring);
    let account = resolve_keyring_account(&config.keyring);
    emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_migrate_acl",
        &serde_json::json!({
            "service": service,
            "account": account,
        }),
    )
}

/// Resolve the operator's age recipient public key for `ember vault export`.
///
/// Search order:
/// 1. Explicit `--recipient-key <path>` flag.
/// 2. `$XDG_CONFIG_HOME/emberlink/recipient.age` (or `~/.config/...`).
///
/// The file is expected to contain a single `age1...` recipient line; any
/// `#`-comment lines are ignored so operators can annotate their key.
fn resolve_recipient_key(explicit: Option<&Path>) -> Result<String, String> {
    let path: PathBuf = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let base = dirs_next::config_dir()
            .ok_or_else(|| "could not resolve XDG config directory".to_string())?;
        base.join("emberlink").join("recipient.age")
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read recipient key {}: {e}", path.display()))?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("age1") {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!(
        "no `age1...` recipient line found in {} (lines starting with `#` are skipped)",
        path.display()
    ))
}

/// Resolve the operator's age identity (private key) for `ember vault import`.
fn resolve_identity_key(explicit: Option<&Path>) -> Result<String, String> {
    let path: PathBuf = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let base = dirs_next::config_dir()
            .ok_or_else(|| "could not resolve XDG config directory".to_string())?;
        base.join("emberlink").join("identity.age")
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read identity key {}: {e}", path.display()))?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("AGE-SECRET-KEY-") {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!(
        "no `AGE-SECRET-KEY-...` identity line found in {} (lines starting with `#` are skipped)",
        path.display()
    ))
}

/// Drive the `ember vault export` flow: list every credential, encrypt each
/// value individually under the operator's age recipient, and emit a JSON
/// envelope to stdout (or `--output <path>` with mode 0600).
///
/// Returns `Err(exit_code)` if any step failed; the caller exits the
/// process with that code.
pub(super) fn run_vault_export(
    config: &DaemonConfig,
    json_global: bool,
    args: &VaultExportArgs,
) -> Result<(), i32> {
    if args.sealed {
        return run_vault_export_sealed(config, json_global, args);
    }
    if args.format != "json" {
        eprintln!(
            "error: unsupported --format {} (only `json` is supported)",
            args.format
        );
        return Err(2);
    }
    let recipient = match resolve_recipient_key(args.recipient_key.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(1);
        }
    };
    let (_, entries) = run_vault_list(config, None).map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let name = match entry.get("name").and_then(|v| v.as_str()) {
            Some(name) => name,
            None => {
                eprintln!("error: daemon/local vault list returned an entry without a string name");
                return Err(1);
            }
        };
        let (_, value) = run_vault_get(config, name).map_err(|e| {
            eprintln!("error: failed to read {name}: {e}");
            1
        })?;
        pairs.push((name.to_string(), value));
    }
    let envelope = emberlink_cli::vault_io::encode_export_envelope(
        &recipient,
        &pairs,
        chrono::Utc::now().to_rfc3339(),
    )
    .map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let serialized = serde_json::to_string_pretty(&envelope).map_err(|e| {
        eprintln!("error: failed to serialize envelope: {e}");
        1
    })?;
    if let Some(path) = args.output.as_deref() {
        // Write atomically with mode 0600 — same posture as
        // `ember vault add`'s --delete-source path.
        if let Err(e) = std::fs::write(path, &serialized) {
            eprintln!("error: failed to write {}: {e}", path.display());
            return Err(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                eprintln!("warn: failed to set 0600 on {}: {e}", path.display());
            }
        }
        if !json_global {
            eprintln!(
                "Exported {} credential(s) to {} (recipient {recipient}).",
                entries.len(),
                path.display()
            );
        }
    } else {
        println!("{serialized}");
    }
    Ok(())
}

fn run_vault_export_sealed(
    config: &DaemonConfig,
    _json_global: bool,
    args: &VaultExportArgs,
) -> Result<(), i32> {
    if !recovery_passphrase_flag_set(&args.recovery_passphrase) {
        eprintln!("error: --sealed export requires --recovery-passphrase");
        return Err(2);
    }
    if args.recipient_key.is_some() {
        eprintln!("error: --recipient-key is only valid for JSON credential export");
        return Err(2);
    }
    if !args.stdin && args.file.is_none() {
        eprintln!(
            "error: --sealed export requires a recovery passphrase source: --stdin or --file <path>"
        );
        return Err(2);
    }

    let passphrase_path = args.file.as_deref();
    let passphrase_bytes =
        resolve_credential_input(args.stdin, passphrase_path, false, args.from_downloads)?;
    let passphrase_source_len = passphrase_bytes.len();
    let passphrase = passphrase_from_bytes(passphrase_bytes)?;
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_export_sealed",
        &serde_json::json!({ "passphrase": passphrase.as_str() }),
    )
    .map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;
    let blob_b64 = result.get("blob").and_then(|v| v.as_str()).ok_or_else(|| {
        eprintln!("error: daemon vault_export_sealed: missing blob");
        1
    })?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .map_err(|e| {
            eprintln!("error: daemon vault_export_sealed returned invalid base64: {e}");
            1
        })?;

    if let Some(path) = args.output.as_deref() {
        if let Err(e) = std::fs::write(path, &blob) {
            eprintln!("error: failed to write {}: {e}", path.display());
            return Err(1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                eprintln!("warn: failed to set 0600 on {}: {e}", path.display());
            }
        }
    } else {
        let mut stdout = io::stdout();
        if let Err(e) = stdout.write_all(&blob).and_then(|_| stdout.flush()) {
            eprintln!("error: failed to write sealed blob to stdout: {e}");
            return Err(1);
        }
    }

    if let Some(path) = passphrase_path
        && args.delete_source
    {
        zero_and_unlink_source(path, passphrase_source_len);
    }

    if let Some(fp) = result.get("mek_fingerprint").and_then(|v| v.as_str()) {
        eprintln!("MEK fingerprint: {fp}");
    }
    if let Some(event_id) = result.get("audit_event_id").and_then(|v| v.as_i64()) {
        eprintln!("Audit event: vault.mek_sealed_exported#{event_id}");
    } else {
        eprintln!("Audit event: vault.mek_sealed_exported");
    }
    Ok(())
}

/// Drive the `ember vault import` flow: read the JSON envelope, decrypt
/// every entry first (so any failure aborts before any write), then `put`
/// each restored entry back into the vault.
pub(super) fn run_vault_import(config: &DaemonConfig, args: &VaultImportArgs) -> Result<(), i32> {
    if args.sealed {
        return run_vault_import_sealed(config, args);
    }
    if args.format != "json" {
        eprintln!(
            "error: unsupported --format {} (only `json` is supported)",
            args.format
        );
        return Err(2);
    }
    let Some(from) = args.from.as_ref() else {
        eprintln!("error: JSON vault import requires --from <path>");
        return Err(2);
    };
    let identity = match resolve_identity_key(args.identity_key.as_deref()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(1);
        }
    };
    let raw = std::fs::read_to_string(from).map_err(|e| {
        eprintln!("error: failed to read {}: {e}", from.display());
        1
    })?;
    let envelope: emberlink_cli::vault_io::VaultExportEnvelope = serde_json::from_str(&raw)
        .map_err(|e| {
            eprintln!("error: invalid JSON in {}: {e}", from.display());
            2
        })?;
    // Atomic decrypt — collect plaintext for every entry first; abort
    // before any vault write if any decryption fails.
    let decrypted =
        emberlink_cli::vault_io::decode_import_envelope(&identity, &envelope).map_err(|e| {
            eprintln!("error: {e}");
            1
        })?;
    // Every entry decrypted cleanly — commit them.
    let count = decrypted.len();
    for (name, value) in decrypted {
        run_vault_store(config, "vault_put", &name, &value, None, false).map_err(|e| {
            eprintln!("error: failed to put {name}: {e}");
            1
        })?;
    }
    eprintln!("Imported {count} credential(s) from {}.", from.display());
    Ok(())
}

fn run_vault_import_sealed(config: &DaemonConfig, args: &VaultImportArgs) -> Result<(), i32> {
    if !recovery_passphrase_flag_set(&args.recovery_passphrase) {
        eprintln!("error: --sealed import requires --recovery-passphrase");
        return Err(2);
    }
    if args.identity_key.is_some() {
        eprintln!("error: --identity-key is only valid for JSON credential import");
        return Err(2);
    }
    let Some(blob_path) = args.file.as_deref() else {
        eprintln!("error: --sealed import requires --file <blob-path>");
        return Err(2);
    };
    let Some(expected_fingerprint) = args.expected_fingerprint.as_deref() else {
        eprintln!("error: --sealed import requires --expected-fingerprint <hex>");
        return Err(2);
    };
    if expected_fingerprint.is_empty() {
        eprintln!("error: --expected-fingerprint must not be empty");
        return Err(2);
    }
    if !args.stdin {
        eprintln!("error: --sealed import requires --stdin for the recovery passphrase");
        return Err(2);
    }

    let blob = resolve_credential_input(false, Some(blob_path), false, args.from_downloads)?;
    let blob_source_len = blob.len();
    let passphrase = passphrase_from_bytes(resolve_credential_input(true, None, false, false)?)?;
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "vault_import_sealed",
        &serde_json::json!({
            "blob": blob_b64,
            "passphrase": passphrase.as_str(),
            "expected_fingerprint": expected_fingerprint,
        }),
    )
    .map_err(|e| {
        eprintln!("error: {e}");
        1
    })?;

    if args.delete_source {
        zero_and_unlink_source(blob_path, blob_source_len);
    }

    let fp = result
        .get("mek_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or(expected_fingerprint);
    eprintln!("Imported sealed MEK backup.");
    eprintln!("MEK fingerprint: {fp}");
    if let Some(event_id) = result.get("audit_event_id").and_then(|v| v.as_i64()) {
        eprintln!("Audit event: vault.mek_sealed_imported#{event_id}");
    } else {
        eprintln!("Audit event: vault.mek_sealed_imported");
    }
    Ok(())
}

/// Per ARCH-VAULT-ADD-NO-ARGV-VALUE: refuse `ember vault add --value <secret>`
/// argv form because it leaks the secret to shell history, `ps auxww`, and
/// transcript-capturing harnesses. Centralized so future credential-input
/// CLI surfaces can call it.
pub(super) fn refuse_value_in_argv(flag: &str) -> ! {
    eprintln!(
        "error: --{flag} is refused — passing secrets via argv leaks them to \
         shell history and `ps auxww`."
    );
    eprintln!("       Use one of:");
    eprintln!("         ember vault add --name <name> --stdin       # pipe or terminal input");
    eprintln!("         ember vault add --name <name> --file <path> # read from file");
    eprintln!(
        "       (--file pairs with --delete-source to zero+unlink after vault-encrypt; refuses \
         ~/Downloads paths without --from-downloads.)"
    );
    std::process::exit(2);
}
