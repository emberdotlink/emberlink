//! CLASSIFICATION: PUBLIC
//!
//! META-SE-PROBE-CODE-IDENTITY-VS-PRESENCE-VALIDATION-V1
//!
//! This probe is the reproducible answer to ADR 151's 2026-06-08
//! root-cause correction (signed code identity, not login session type,
//! gates DPK access) and ADR 206 §4's open question (whether a signed
//! launchd daemon at uid 450 can drive `.userPresence` SE keys via
//! cross-uid SecurityAgent). Must be runnable from a SIGNED production
//! binary in launchd context to be a valid probe; running from
//! `cargo run` or `cargo test` reproduces the unsigned-binary
//! errSecMissingEntitlement (-34018) false-negative.
//!
//! SE custody probe — answers the critical unknowns for ADR 211 §4
//! Option C and ADR 206 §4:
//!
//!   1. Headless arm: can a LaunchDaemon process (uid 450, sandbox-exec)
//!      create + use a `SeAccessPolicy::Headless` SE key without first
//!      unlocking a provisioned service-account login keychain? (Validated
//!      2026-06-08 — see memory `project_se_custody_probe_result`.)
//!
//!   2. UserPresence arm: can the same daemon drive a
//!      `SeAccessPolicy::UserPresence` SE key — whose every USE goes
//!      through `LAContext` and triggers a Touch ID sheet — from the
//!      LaunchDaemon's non-GUI session, by routing through cross-uid
//!      SecurityAgent to the GUI operator? Two in-code comments already
//!      assert this works (`crates/ember-broker/src/secure_enclave.rs:377`
//!      and `crates/ember-broker/src/ssh_agent_macos.rs:320`); this probe
//!      empirically validates those claims.
//!
//! Run under the actual daemon context (not SSH, not cargo test) via:
//! ```text
//! sudo launchctl kickstart -kp system/sh.emberlink.daemon.se-probe
//! ```
//! or the companion one-shot plist.
//!
//! ## CLI
//!
//! ```text
//! emberd se-probe                          # default: --policy headless
//! emberd se-probe --policy headless        # explicit current behavior
//! emberd se-probe --policy user-presence   # NEW: ADR 206 §4 validation
//! emberd se-probe --policy all             # runs headless then user-presence
//! ```

#[cfg(target_os = "macos")]
const HEADLESS_PROBE_LABEL: &str = "sh.emberlink.probe.se-test";
#[cfg(target_os = "macos")]
const UP_SIGN_PROBE_LABEL: &str = "sh.emberlink.probe.user-presence-sign-v1";
#[cfg(target_os = "macos")]
const UP_ECIES_PROBE_LABEL: &str = "sh.emberlink.probe.user-presence-ecies-v1";

/// Policy arms exposed by the probe CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbePolicy {
    Headless,
    UserPresence,
    All,
}

fn parse_policy(args: &[String]) -> Result<ProbePolicy, String> {
    let mut policy = ProbePolicy::Headless;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                if i >= args.len() {
                    return Err("--policy requires a value (headless|user-presence|all)".into());
                }
                policy = match args[i].as_str() {
                    "headless" => ProbePolicy::Headless,
                    "user-presence" => ProbePolicy::UserPresence,
                    "all" => ProbePolicy::All,
                    other => {
                        return Err(format!(
                            "unknown --policy value '{other}' (expected headless|user-presence|all)"
                        ));
                    }
                };
            }
            other => {
                return Err(format!("unknown argument '{other}'"));
            }
        }
        i += 1;
    }
    Ok(policy)
}

#[cfg(target_os = "macos")]
pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let policy = match parse_policy(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("se-probe: {e}");
            eprintln!(
                "usage: emberd se-probe [--policy headless|user-presence|all]\n  \
                 (default: headless)"
            );
            return 2;
        }
    };

    print_environment_report();

    if !ember_broker::secure_enclave::se_backend_is_real() {
        eprintln!(
            "ABORT: se-real feature is not compiled in — probe cannot test the real SE path."
        );
        eprintln!("Build with `cargo build -p ember-daemon --features se-real`.");
        return 2;
    }

    match policy {
        ProbePolicy::Headless => run_headless_arm(),
        ProbePolicy::UserPresence => run_user_presence_arm(),
        ProbePolicy::All => {
            let h = run_headless_arm();
            if h != 0 {
                return h;
            }
            eprintln!();
            run_user_presence_arm()
        }
    }
}

#[cfg(target_os = "macos")]
fn print_environment_report() {
    use ember_broker::secure_enclave::se_backend_is_real;
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let home = std::env::var("HOME").unwrap_or_else(|_| "(unset)".into());

    eprintln!("=== Ember SE Custody Probe ===");
    eprintln!("uid:     {uid}");
    eprintln!("euid:    {euid}");
    eprintln!("HOME:    {home}");
    eprintln!("se-real: {}", se_backend_is_real());
    eprintln!();
}

// ---------------------------------------------------------------------------
// Headless arm (ADR 151 / 211 Option C)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn run_headless_arm() -> i32 {
    use ember_broker::secure_enclave::{
        EciesKeyLabel, SeAccessPolicy, SeKeychainTarget, find_secure_enclave_key,
        generate_secure_enclave_key_with_policy, se_unwrap, se_wrap,
    };
    use security_framework::os::macos::keychain::SecKeychain;

    // ── Phase 1: Baseline — SE key without any keychain manipulation ────
    eprintln!("--- Phase 1: Baseline SE key lookup/create ---");
    let baseline_ok = match find_secure_enclave_key(HEADLESS_PROBE_LABEL) {
        Ok(_) => {
            eprintln!("PASS (find): SE key '{HEADLESS_PROBE_LABEL}' already exists in DPK");
            true
        }
        Err(find_err) => {
            eprintln!("find: {find_err}");
            eprintln!("  (expected in LaunchDaemon context without login keychain)");
            eprintln!("  attempting create...");
            match generate_secure_enclave_key_with_policy(
                HEADLESS_PROBE_LABEL,
                SeKeychainTarget::SystemKeychain,
                SeAccessPolicy::Headless,
            ) {
                Ok(_) => {
                    eprintln!("PASS (create): SE key '{HEADLESS_PROBE_LABEL}' created in DPK");
                    true
                }
                Err(gen_err) => {
                    eprintln!("FAIL (create): {gen_err}");
                    false
                }
            }
        }
    };
    eprintln!();

    // ── Phase 2: Keychain unlock (if env vars provided) ─────────────────
    let kc_path = std::env::var("EMBER_PROBE_KEYCHAIN_PATH").ok();
    let kc_password = std::env::var("EMBER_PROBE_KEYCHAIN_PASSWORD").ok();
    let mut post_unlock_ok = false;

    match (&kc_path, &kc_password) {
        (Some(path), Some(password)) => {
            eprintln!("--- Phase 2: Keychain unlock ---");
            eprintln!("path: {path}");

            match SecKeychain::open(path) {
                Ok(mut kc) => match kc.unlock(Some(password)) {
                    Ok(()) => eprintln!("PASS: keychain unlocked"),
                    Err(e) => {
                        eprintln!("FAIL: keychain unlock error: {e}");
                        return 1;
                    }
                },
                Err(e) => {
                    eprintln!("FAIL: keychain open error: {e}");
                    return 1;
                }
            }
            eprintln!();

            if !baseline_ok {
                eprintln!("--- Phase 2b: SE key lookup/create after keychain unlock ---");
                match find_secure_enclave_key(HEADLESS_PROBE_LABEL) {
                    Ok(_) => {
                        eprintln!(
                            "PASS (find): SE key '{HEADLESS_PROBE_LABEL}' found after unlock"
                        );
                        post_unlock_ok = true;
                    }
                    Err(find_err) => {
                        eprintln!("find after unlock: {find_err}");
                        eprintln!("  attempting create...");
                        match generate_secure_enclave_key_with_policy(
                            HEADLESS_PROBE_LABEL,
                            SeKeychainTarget::SystemKeychain,
                            SeAccessPolicy::Headless,
                        ) {
                            Ok(_) => {
                                eprintln!("PASS (create): SE key created after keychain unlock");
                                post_unlock_ok = true;
                            }
                            Err(gen_err) => {
                                eprintln!("FAIL (create after unlock): {gen_err}");
                            }
                        }
                    }
                }
                eprintln!();
            } else {
                post_unlock_ok = true;
            }
        }
        _ => {
            eprintln!("--- Phase 2: SKIPPED ---");
            eprintln!("  Set EMBER_PROBE_KEYCHAIN_PATH + EMBER_PROBE_KEYCHAIN_PASSWORD");
            eprintln!("  to test keychain-unlock-then-SE flow.");
            eprintln!();
            post_unlock_ok = baseline_ok;
        }
    }

    // ── Phase 3: ECIES wrap/unwrap roundtrip ────────────────────────────
    if !baseline_ok && !post_unlock_ok {
        eprintln!("--- Phase 3: SKIPPED (no SE key available) ---");
        eprintln!();
        eprintln!("=== RESULT: SE custody NOT available in this context ===");
        return 1;
    }

    eprintln!("--- Phase 3: ECIES wrap/unwrap roundtrip ---");
    let label = EciesKeyLabel::from_provisioned(HEADLESS_PROBE_LABEL);
    let test_plaintext = b"ADR-211-se-custody-probe-roundtrip-test-data";

    let wrapped = match se_wrap(&label, test_plaintext) {
        Ok(blob) => {
            eprintln!(
                "PASS (wrap): {} plaintext bytes → {} ciphertext bytes",
                test_plaintext.len(),
                blob.len()
            );
            blob
        }
        Err(e) => {
            eprintln!("FAIL (wrap): {e}");
            return 1;
        }
    };

    match se_unwrap(&label, &wrapped) {
        Ok(recovered) => {
            if recovered == test_plaintext {
                eprintln!(
                    "PASS (unwrap): roundtrip matches ({} bytes)",
                    recovered.len()
                );
            } else {
                eprintln!(
                    "FAIL (unwrap): roundtrip MISMATCH — got {} bytes, expected {}",
                    recovered.len(),
                    test_plaintext.len()
                );
                return 1;
            }
        }
        Err(e) => {
            eprintln!("FAIL (unwrap): {e}");
            return 1;
        }
    }

    eprintln!();
    if baseline_ok {
        eprintln!("=== RESULT: SE custody available WITHOUT keychain unlock ===");
        eprintln!("  (Option C may work without login-keychain provisioning)");
    } else {
        eprintln!("=== RESULT: SE custody available AFTER keychain unlock ===");
        eprintln!(
            "  (Option C requires login-keychain provisioning at install + unlock at startup)"
        );
    }
    0
}

// ---------------------------------------------------------------------------
// UserPresence arm (ADR 206 §4 open question)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn run_user_presence_arm() -> i32 {
    use ember_broker::secure_enclave::{
        EciesKeyLabel, SeAccessPolicy, SeKeychainTarget, SignKeyLabel, delete_secure_enclave_key,
        find_sign_key, generate_secure_enclave_key_with_policy, se_sign_with_touch_id_reason,
        se_unwrap, se_wrap,
    };
    use std::io::Write;

    let mut sign_ok = false;
    let mut ecies_keygen_ok = false;
    let mut overall = 0;

    // ── Phase 4: UserPresence sign key ─────────────────────────────────
    eprintln!("--- Phase 4: UserPresence sign key ---");
    let sign_keygen = generate_secure_enclave_key_with_policy(
        UP_SIGN_PROBE_LABEL,
        SeKeychainTarget::SystemKeychain,
        SeAccessPolicy::UserPresence,
    );
    let sign_label = SignKeyLabel::from_provisioned(UP_SIGN_PROBE_LABEL);

    match sign_keygen {
        Ok(_) => {
            eprintln!("keygen: PASS");
            eprintln!("TOUCH ID PROMPT EXPECTED — touch the sensor when the sheet appears.");
            // Flush so the operator reads the warning BEFORE the SecurityAgent
            // sheet appears (the SecKeyCreateSignature call below blocks).
            let _ = std::io::stderr().flush();

            match find_sign_key(&sign_label) {
                Ok(handle) => {
                    let intent = b"ADR-206-section-4-user-presence-sign-probe";
                    match se_sign_with_touch_id_reason(
                        &handle,
                        intent,
                        "Ember SE probe: validate cross-uid Touch ID for .userPresence sign key",
                    ) {
                        Ok(sig) => {
                            eprintln!("sign:   PASS ({} byte sig)", sig.len());
                            sign_ok = true;
                        }
                        Err(e) => {
                            eprintln!("sign:   FAIL {e}");
                            overall = 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("sign:   FAIL (sign-key lookup): {e}");
                    overall = 1;
                }
            }
        }
        Err(e) => {
            eprintln!("keygen: FAIL {e}");
            overall = 1;
        }
    }
    eprintln!();

    // ── Phase 5: UserPresence ECIES key ────────────────────────────────
    eprintln!("--- Phase 5: UserPresence ECIES key ---");
    let ecies_label = EciesKeyLabel::from_provisioned(UP_ECIES_PROBE_LABEL);
    let ecies_keygen = generate_secure_enclave_key_with_policy(
        UP_ECIES_PROBE_LABEL,
        SeKeychainTarget::SystemKeychain,
        SeAccessPolicy::UserPresence,
    );

    match ecies_keygen {
        Ok(_) => {
            eprintln!("keygen: PASS");
            ecies_keygen_ok = true;
            let plaintext = b"ADR-206-section-4-user-presence-ecies-probe";
            match se_wrap(&ecies_label, plaintext) {
                Ok(ct) => {
                    eprintln!("wrap:   PASS ({} bytes)", ct.len());
                    eprintln!(
                        "TOUCH ID PROMPT EXPECTED — touch the sensor when the sheet appears."
                    );
                    let _ = std::io::stderr().flush();
                    match se_unwrap(&ecies_label, &ct) {
                        Ok(recovered) => {
                            if recovered == plaintext {
                                eprintln!("unwrap: PASS (roundtrip matched)");
                            } else {
                                eprintln!(
                                    "unwrap: FAIL (roundtrip MISMATCH — got {} bytes, expected {})",
                                    recovered.len(),
                                    plaintext.len()
                                );
                                overall = 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("unwrap: FAIL {e}");
                            overall = 1;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("wrap:   FAIL {e}");
                    overall = 1;
                }
            }
        }
        Err(e) => {
            eprintln!("keygen: FAIL {e}");
            overall = 1;
        }
    }
    eprintln!();

    // ── Cleanup ────────────────────────────────────────────────────────
    eprintln!("--- Cleanup ---");
    let sign_del = delete_secure_enclave_key(UP_SIGN_PROBE_LABEL);
    match &sign_del {
        Ok(()) => eprintln!("delete user-presence-sign-v1: ok"),
        Err(e) => eprintln!("delete user-presence-sign-v1: err {e}"),
    }
    let ecies_del = delete_secure_enclave_key(UP_ECIES_PROBE_LABEL);
    match &ecies_del {
        Ok(()) => eprintln!("delete user-presence-ecies-v1: ok"),
        Err(e) => eprintln!("delete user-presence-ecies-v1: err {e}"),
    }
    eprintln!();

    // ── Result ─────────────────────────────────────────────────────────
    if sign_ok && ecies_keygen_ok && overall == 0 {
        eprintln!("=== RESULT: .userPresence SE custody available in LaunchDaemon context ===");
        eprintln!("  (cross-uid SecurityAgent reaches GUI operator; ADR 206 §4 unblocked)");
        0
    } else {
        eprintln!("=== RESULT: .userPresence SE custody FAILED in this context ===");
        eprintln!("  (review FAIL lines above; ADR 206 §4 needs alternative path)");
        1
    }
}

#[cfg(not(target_os = "macos"))]
pub fn run() -> i32 {
    let _ = parse_policy(&[]);
    eprintln!("se-probe: Secure Enclave is macOS-only");
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_defaults_to_headless() {
        assert_eq!(parse_policy(&[]).unwrap(), ProbePolicy::Headless);
    }

    #[test]
    fn parse_policy_explicit_headless() {
        let args = vec!["--policy".to_string(), "headless".to_string()];
        assert_eq!(parse_policy(&args).unwrap(), ProbePolicy::Headless);
    }

    #[test]
    fn parse_policy_user_presence() {
        let args = vec!["--policy".to_string(), "user-presence".to_string()];
        assert_eq!(parse_policy(&args).unwrap(), ProbePolicy::UserPresence);
    }

    #[test]
    fn parse_policy_all() {
        let args = vec!["--policy".to_string(), "all".to_string()];
        assert_eq!(parse_policy(&args).unwrap(), ProbePolicy::All);
    }

    #[test]
    fn parse_policy_rejects_unknown_value() {
        let args = vec!["--policy".to_string(), "biometric".to_string()];
        assert!(parse_policy(&args).is_err());
    }

    #[test]
    fn parse_policy_rejects_unknown_flag() {
        let args = vec!["--bogus".to_string()];
        assert!(parse_policy(&args).is_err());
    }

    #[test]
    fn parse_policy_rejects_missing_value() {
        let args = vec!["--policy".to_string()];
        assert!(parse_policy(&args).is_err());
    }
}
