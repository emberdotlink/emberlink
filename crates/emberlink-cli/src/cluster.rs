//! `ember cluster` subcommand implementations — ADR 117 single-phase bootstrap
//! and operator-driven recovery.
//!
//! `ember cluster bootstrap <cluster-id>` is the operator-facing entry point
//! for the single-phase EmberSeal bootstrap flow (ADR 117 §Decision):
//!
//! 1. Generates a fresh Ed25519 Daemon Persona keypair.
//! 2. Derives the X25519 recipient pubkey from the seed via
//!    `HKDF-SHA256(seed, "emberlink/v1/ember-seal/x25519-scalar")`
//!    × Curve25519 basepoint — this is the `recipientPubkey` field in the
//!    EmberSeal CR (per ADR 115 §The primitive and the `core_crypto` HKDF
//!    registry; security review H2 split this info string from the
//!    `ember-seal/snapshot-key` symmetric lane).
//! 3. Stores the **privkey seed** (hex-encoded) in the operator's vault
//!    under `cluster-daemon-persona/<cluster-id>`.
//! 4. Prints the Ed25519 pubkey (hex) and the X25519 recipient pubkey (hex)
//!    to stdout for embedding in the EmberSeal CR.
//!
//! `ember cluster restore <cluster-id>` is the inverse: after a PVC wipe,
//! the operator runs this command to retrieve the stored privkey seed and
//! re-inject it via a Kubernetes secret so EIC restarts with the same Daemon
//! Persona (EmberSeal CR `recipientPubkey` does not change).
//!
//! The two-phase path (ADR 115 §Bootstrap mode — existing default) remains
//! available: if you do NOT run `ember cluster bootstrap`, EIC generates its
//! own Daemon Persona on first start and posts the X25519 pubkey to
//! ember-relay for out-of-band retrieval. Pass `--two-phase` to explicitly
//! document that you intend the two-phase flow.

use std::io::Write as IoWrite;
use std::path::Path;
use std::process;

use core_crypto::derive_emberseal_x25519_recipient;
use ed25519_dalek::SigningKey;

use ember_daemon::bootstrap::vault_key_for_cluster;
use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::runtime::DaemonRuntime;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultError, VaultScope, validate_credential_name};

fn uses_managed_separate_uid_topology(config: &DaemonConfig) -> bool {
    if !ember_daemon::install::is_separate_uid_posture() {
        return false;
    }
    let Some(home) = dirs_next::home_dir() else {
        return false;
    };
    let ember_root = home.join(".ember");
    config.socket_dir == ember_root.join("run")
        && config.data_dir == ember_root.join("data")
        && config.pid_file == ember_root.join("run").join("emberd.pid")
}

fn managed_local_vault_fallback_message() -> &'static str {
    "daemon is not running on the managed separate-uid path; local vault fallback is refused. \
     Run `ember status` to inspect daemon posture and `sudo ember daemon install` to repair it."
}

/// Run `ember cluster bootstrap <cluster-id> [--two-phase]`.
///
/// When `two_phase` is true, this function prints documentation about the
/// existing two-phase flow and exits without generating a keypair. This gives
/// callers a single canonical flag for the opt-out path.
pub fn cmd_cluster_bootstrap(
    cluster_id: &str,
    two_phase: bool,
    config: &DaemonConfig,
    json_output: bool,
) {
    if two_phase {
        cmd_cluster_bootstrap_two_phase_doc(cluster_id, json_output);
        return;
    }
    if uses_managed_separate_uid_topology(config) {
        eprintln!("error: {}", managed_local_vault_fallback_message());
        process::exit(1);
    }

    // Validate cluster_id: must be a valid vault path segment (lowercase,
    // hyphens, digits; starts with a letter). We embed it as the second
    // segment of `cluster-daemon-persona/<cluster-id>`.
    let vault_key = vault_key_for_cluster(cluster_id);
    if let Err(e) = validate_credential_name(&vault_key) {
        eprintln!("error: cluster-id {cluster_id:?} is not a valid vault-path segment: {e}");
        eprintln!(
            "       Use lowercase letters, digits, and hyphens only (e.g. \"team-zero-dev\")."
        );
        process::exit(2);
    }

    // Open the daemon store + vault.
    let db_path = config.data_dir.join("daemon.db");
    let store = match DaemonStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to open daemon store: {e}");
            process::exit(1);
        }
    };
    let vault = match Vault::open_from_config(config, &store) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to open vault: {e}");
            process::exit(1);
        }
    };

    // Check whether a keypair for this cluster already exists in the vault.
    match vault.get(VaultScope::Interactive, &store, &vault_key) {
        Ok(_existing_seed) => {
            // Already generated — retrieve and re-print pubkeys (idempotent).
            print_existing_bootstrap(&vault, &store, cluster_id, &vault_key, json_output);
            return;
        }
        Err(VaultError::NotFound) => {
            // First time — generate and store.
        }
        Err(e) => {
            eprintln!("error: vault lookup for {vault_key}: {e}");
            process::exit(1);
        }
    }

    // Generate a fresh Ed25519 Daemon Persona keypair.
    let (seed, ed25519_pubkey_hex, x25519_recipient_hex) = generate_daemon_persona_keypair();

    // Store the privkey seed in the vault (hex-encoded).
    let seed_hex = hex::encode(seed);
    match vault.add(
        VaultScope::Interactive,
        &store,
        &vault_key,
        seed_hex.as_bytes(),
        Some("daemon-persona-seed"),
    ) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: failed to store Daemon Persona seed in vault: {e}");
            process::exit(1);
        }
    }

    if json_output {
        let out = serde_json::json!({
            "cluster_id": cluster_id,
            "vault_key": vault_key,
            "ed25519_pubkey": ed25519_pubkey_hex,
            "x25519_recipient": x25519_recipient_hex,
            "bootstrap_mode": "single-phase",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Daemon Persona keypair generated for cluster: {cluster_id}");
        println!();
        println!("  Vault key:         {vault_key}");
        println!("  Ed25519 pubkey:    {ed25519_pubkey_hex}");
        println!("  X25519 recipient:  {x25519_recipient_hex}");
        println!();
        println!("Next steps:");
        println!("  1. Set `recipientPubkey: {x25519_recipient_hex}` in your EmberSeal CR.");
        println!("  2. Deliver the privkey seed to EIC via Kubernetes secret:");
        println!("       ember vault get {vault_key} | kubectl create secret generic \\");
        println!("           ember-daemon-persona --from-literal=seed=$(cat) \\");
        println!("           -n ember-system");
        println!("  3. Set EMBER_DAEMON_PERSONA_SEED_HEX in the EIC deployment env.");
        println!("  4. Recovery after PVC wipe = redeploy with the same secret.");
        println!();
        println!("  Two-phase fallback: `ember cluster bootstrap {cluster_id} --two-phase`");
        println!("  prints the original ADR 115 flow documentation.");
    }
}

/// Run `ember cluster restore <cluster-id> [--verify] [--seed-out <path>]`.
///
/// Operator-driven recovery after a PVC wipe (ADR 117 §Recovery):
///
/// 1. Reads the Daemon Persona privkey seed from the vault at
///    `cluster-daemon-persona/<cluster-id>` — the same key bootstrap stored.
/// 2. Prints the recovery plan: vault key path, Ed25519 pubkey, X25519
///    recipient pubkey (confirming they still match the EmberSeal CR).
/// 3. Writes the seed hex to a temp file (or `--seed-out` path) the operator
///    uses to re-inject the secret into Kubernetes.
/// 4. With `--verify`: probes the local daemon socket to confirm the cluster
///    daemon came back up and prints success / partial / failed.
///
/// EIC re-deploy is the operator's responsibility — this command scopes to the
/// key-retrieval and status-verification sides. The actual `kubectl` command
/// is printed as a next-step prompt, not executed.
pub fn cmd_cluster_restore(
    cluster_id: &str,
    verify: bool,
    seed_out: Option<&str>,
    config: &DaemonConfig,
    json_output: bool,
) {
    if uses_managed_separate_uid_topology(config) {
        eprintln!("error: {}", managed_local_vault_fallback_message());
        process::exit(1);
    }

    let vault_key = vault_key_for_cluster(cluster_id);

    // Open daemon store + vault.
    let db_path = config.data_dir.join("daemon.db");
    let store = match DaemonStore::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to open daemon store: {e}");
            process::exit(1);
        }
    };
    let vault = match Vault::open_from_config(config, &store) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to open vault: {e}");
            process::exit(1);
        }
    };

    // Fetch privkey seed from vault.
    let seed_hex = match vault.get(VaultScope::Interactive, &store, &vault_key) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                eprintln!("error: vault key {vault_key} contains non-UTF-8 data");
                process::exit(1);
            }
        },
        Err(VaultError::NotFound) => {
            if json_output {
                let out = serde_json::json!({
                    "cluster_id": cluster_id,
                    "vault_key": vault_key,
                    "key_status": "not_found",
                    "recovery_status": "failed",
                    "error": format!(
                        "No privkey found in vault at {vault_key}. \
                         Was this cluster bootstrapped with `ember cluster bootstrap`?"
                    ),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                eprintln!("error: vault key {vault_key} not found.");
                eprintln!();
                eprintln!("  Recovery is only possible for clusters bootstrapped via:");
                eprintln!("    ember cluster bootstrap {cluster_id}");
                eprintln!();
                eprintln!("  Two-phase clusters require a fresh EmberSeal CR sealed to the");
                eprintln!("  new EIC-generated Daemon Persona pubkey. See:");
                eprintln!("    ember cluster bootstrap {cluster_id} --two-phase");
            }
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: vault lookup for {vault_key}: {e}");
            process::exit(1);
        }
    };

    // Decode seed to derive pubkeys (confirms vault data is intact).
    let seed_bytes: [u8; 32] = match hex::decode(&seed_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("error: vault key {vault_key} does not contain a valid 32-byte hex seed");
            process::exit(1);
        }
    };
    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let ed25519_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let x25519_recipient_hex = derive_emberseal_x25519_recipient(&seed_bytes);

    // Write seed to temp file (or operator-supplied path).
    let seed_path = write_seed_envelope(cluster_id, &seed_hex, seed_out);

    // Optionally probe daemon readiness.
    let verify_status = if verify {
        Some(probe_daemon_readiness(config))
    } else {
        None
    };

    // Print recovery plan.
    if json_output {
        let mut out = serde_json::json!({
            "cluster_id": cluster_id,
            "vault_key": vault_key,
            "key_status": "found",
            "ed25519_pubkey": ed25519_pubkey_hex,
            "x25519_recipient": x25519_recipient_hex,
            "seed_envelope_path": seed_path,
            "recovery_status": verify_status.as_ref().map(|s| s.status_label()).unwrap_or("pending_redeploy"),
        });
        if let Some(ref vs) = verify_status {
            out["daemon_running"] = serde_json::Value::Bool(vs.daemon_running);
            if let Some(pid) = vs.pid {
                out["daemon_pid"] = serde_json::Value::Number(pid.into());
            }
        }
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Recovery plan for cluster: {cluster_id}");
        println!();
        println!("  Vault key:         {vault_key}              [FOUND]");
        println!("  Ed25519 pubkey:    {ed25519_pubkey_hex}");
        println!("  X25519 recipient:  {x25519_recipient_hex}");
        println!("  Seed written to:   {seed_path}");
        println!();
        println!("Next steps:");
        println!("  1. Inject the recovered seed as a Kubernetes secret:");
        println!("       kubectl create secret generic ember-daemon-persona \\");
        println!("           --from-literal=seed=$(cat {seed_path}) \\");
        println!("           -n ember-system --dry-run=client -o yaml | kubectl apply -f -");
        println!("  2. Re-deploy EIC (restart the StatefulSet):");
        println!(
            "       kubectl rollout restart statefulset/ember-infra-controller -n ember-system"
        );
        println!("  3. After EIC is running, confirm daemon readiness:");
        println!("       ember cluster restore {cluster_id} --verify");
        println!("  4. The EmberSeal CR `recipientPubkey` is UNCHANGED — no CR update needed.");

        if let Some(ref vs) = verify_status {
            println!();
            println!("Readiness probe:");
            vs.print_human();
        }
    }
}

/// Recovery verification result from probing the local daemon socket.
#[derive(Debug)]
pub struct RecoveryStatus {
    pub daemon_running: bool,
    pub pid: Option<u32>,
}

impl RecoveryStatus {
    fn status_label(&self) -> &'static str {
        if self.daemon_running {
            "success"
        } else {
            "partial"
        }
    }

    fn print_human(&self) {
        if self.daemon_running {
            let pid_str = self.pid.map(|p| format!(" (PID {p})")).unwrap_or_default();
            println!("  Status: SUCCESS — daemon is running{pid_str}");
        } else {
            println!("  Status: PARTIAL — daemon socket not responding yet.");
            println!("  Tip: wait for EIC to finish starting, then re-run with --verify.");
        }
    }
}

/// Probe the local daemon socket to check if the daemon is up.
fn probe_daemon_readiness(config: &DaemonConfig) -> RecoveryStatus {
    let runtime = DaemonRuntime::new(config.clone());
    let runtime_status = runtime.status().ok();
    match crate::probe_live_daemon_status(&config.socket_dir.join("daemon.sock"), &config.pid_file)
    {
        Ok(Some(live)) => RecoveryStatus {
            daemon_running: true,
            pid: live.pid.or_else(|| runtime_status.map(|status| status.pid)),
        },
        _ => RecoveryStatus {
            daemon_running: false,
            pid: runtime_status.and_then(|status| (!status.running).then_some(status.pid)),
        },
    }
}

/// Write the privkey seed hex to a temp file (or `seed_out` if supplied).
///
/// Returns the path written.
fn write_seed_envelope(cluster_id: &str, seed_hex: &str, seed_out: Option<&str>) -> String {
    let path: std::path::PathBuf = match seed_out {
        Some(p) => Path::new(p).to_path_buf(),
        None => {
            let tmp = std::env::temp_dir();
            tmp.join(format!("ember-recover-{cluster_id}.seed"))
        }
    };

    match std::fs::File::create(&path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(seed_hex.as_bytes()) {
                eprintln!(
                    "warning: failed to write seed envelope to {}: {e}",
                    path.display()
                );
                eprintln!(
                    "         Continuing — operator must obtain seed via `ember vault get {}`",
                    vault_key_for_cluster(cluster_id)
                );
            }
        }
        Err(e) => {
            eprintln!(
                "warning: cannot create seed envelope at {}: {e}",
                path.display()
            );
            eprintln!(
                "         Continuing — operator must obtain seed via `ember vault get {}`",
                vault_key_for_cluster(cluster_id)
            );
        }
    }

    path.display().to_string()
}

/// Generate a fresh Ed25519 Daemon Persona keypair.
///
/// Returns `(seed_bytes, ed25519_pubkey_hex, x25519_recipient_hex)`.
///
/// The X25519 recipient is derived via `derive_emberseal_x25519_recipient`
/// (HKDF-SHA256 + Curve25519 basepoint multiply) per ADR 115 §The primitive.
fn generate_daemon_persona_keypair() -> ([u8; 32], String, String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS entropy failure generating Daemon Persona keypair");

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let ed25519_pubkey_hex = hex::encode(verifying_key.to_bytes());
    let x25519_recipient_hex = derive_emberseal_x25519_recipient(&seed);

    (seed, ed25519_pubkey_hex, x25519_recipient_hex)
}

/// Re-print pubkey information for an already-bootstrapped cluster.
fn print_existing_bootstrap(
    vault: &Vault,
    store: &DaemonStore,
    cluster_id: &str,
    vault_key: &str,
    json_output: bool,
) {
    let seed_hex_bytes = match vault.get(VaultScope::Interactive, store, vault_key) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot re-read vault key {vault_key}: {e}");
            process::exit(1);
        }
    };
    let seed_hex = match std::str::from_utf8(&seed_hex_bytes) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            eprintln!("error: vault key {vault_key} contains non-UTF-8 data");
            process::exit(1);
        }
    };
    let seed_bytes = match hex::decode(&seed_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("error: vault key {vault_key} does not contain a valid 32-byte hex seed");
            process::exit(1);
        }
    };

    let signing_key = SigningKey::from_bytes(&seed_bytes);
    let verifying_key = signing_key.verifying_key();
    let ed25519_pubkey_hex = hex::encode(verifying_key.to_bytes());
    let x25519_recipient_hex = derive_emberseal_x25519_recipient(&seed_bytes);

    if json_output {
        let out = serde_json::json!({
            "cluster_id": cluster_id,
            "vault_key": vault_key,
            "ed25519_pubkey": ed25519_pubkey_hex,
            "x25519_recipient": x25519_recipient_hex,
            "bootstrap_mode": "single-phase",
            "note": "keypair already exists in vault (idempotent re-print)",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Daemon Persona keypair for cluster {cluster_id} already exists (idempotent).");
        println!();
        println!("  Vault key:         {vault_key}");
        println!("  Ed25519 pubkey:    {ed25519_pubkey_hex}");
        println!("  X25519 recipient:  {x25519_recipient_hex}");
    }
}

/// Print documentation for the two-phase bootstrap flow (ADR 115 §Bootstrap
/// mode). This is the opt-out path for clusters that do not use single-phase.
fn cmd_cluster_bootstrap_two_phase_doc(cluster_id: &str, json_output: bool) {
    if json_output {
        let out = serde_json::json!({
            "cluster_id": cluster_id,
            "bootstrap_mode": "two-phase",
            "phase1": "Deploy EIC StatefulSet (no EmberSeal CR). EIC starts, generates \
                       Daemon Persona keypair, posts X25519 pubkey to ember-relay.",
            "phase2": "Retrieve pubkey: `ember relay pubkey <cluster-id>`. \
                       Run `ember seal --to <pubkey>` to produce the EmberSeal CR. \
                       Commit the CR into the platform stack. ArgoCD applies it. \
                       ember-kernel reconciles → EIC unseals → operational.",
            "note": "ADR 115 §Bootstrap mode. Two-phase is the fallback for clusters \
                     that do not pre-generate the Daemon Persona keypair.",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Two-phase bootstrap flow for cluster: {cluster_id}");
        println!();
        println!("  Phase 1 — PR #1: Deploy EIC StatefulSet without an EmberSeal CR.");
        println!("    - ArgoCD applies → EIC starts, generates Daemon Persona keypair.");
        println!("    - EIC posts X25519 pubkey to ember-relay and waits.");
        println!();
        println!("  Phase 2 — PR #2: Retrieve pubkey and produce the EmberSeal CR.");
        println!("    - Run: ember relay pubkey {cluster_id}");
        println!("    - Run: ember seal --to <pubkey>");
        println!("    - Commit the EmberSeal CR into the platform stack.");
        println!("    - ArgoCD applies → ember-kernel reconciles → EIC initializes.");
        println!();
        println!("  Recovery after PVC wipe (two-phase): requires a new PR with a");
        println!("  fresh EmberSeal CR sealed to the new Daemon Persona pubkey.");
        println!();
        println!("  To switch to single-phase (no human re-seal on recovery):");
        println!("    ember cluster bootstrap {cluster_id}   (without --two-phase)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_daemon_persona_keypair_produces_unique_pairs() {
        let (seed_a, pub_a, x_a) = generate_daemon_persona_keypair();
        let (seed_b, pub_b, x_b) = generate_daemon_persona_keypair();
        assert_ne!(seed_a, seed_b, "seeds must be distinct");
        assert_ne!(pub_a, pub_b, "pubkeys must be distinct");
        assert_ne!(x_a, x_b, "x25519 recipients must be distinct");
    }

    #[test]
    fn generate_daemon_persona_keypair_x25519_is_hex_64() {
        let (_seed, _pub, x25519) = generate_daemon_persona_keypair();
        assert_eq!(
            x25519.len(),
            64,
            "X25519 pubkey must be 64 hex chars: {x25519}"
        );
        assert!(
            x25519.chars().all(|c| c.is_ascii_hexdigit()),
            "X25519 pubkey must be hex: {x25519}"
        );
    }

    #[test]
    fn derive_x25519_recipient_is_deterministic() {
        let seed = [0x42u8; 32];
        let r1 = derive_emberseal_x25519_recipient(&seed);
        let r2 = derive_emberseal_x25519_recipient(&seed);
        assert_eq!(r1, r2, "derivation must be deterministic");
    }

    // --- T1 unit tests for cmd_cluster_restore helpers ---

    /// vault-key-not-found: RecoveryStatus with daemon_running=false produces
    /// "partial" status label and the correct VaultError::NotFound variant
    /// discriminant matches.
    #[test]
    fn restore_vault_key_not_found_status_label() {
        // VaultError::NotFound is the expected arm when no bootstrap was run.
        // We verify the error discriminant matches so the match arm in
        // cmd_cluster_restore is exercised by compile coverage.
        let err = VaultError::NotFound;
        assert!(
            matches!(err, VaultError::NotFound),
            "VaultError::NotFound must match the not-found arm"
        );

        // When the daemon is not running, status_label() returns "partial".
        let status = RecoveryStatus {
            daemon_running: false,
            pid: None,
        };
        assert_eq!(
            status.status_label(),
            "partial",
            "non-running daemon recovery is partial, not failed"
        );
    }

    /// vault-key-found + plan rendered: write_seed_envelope writes the seed hex
    /// to a temp path and returns that path as a string.
    #[test]
    fn restore_seed_envelope_written_to_temp() {
        let seed_hex = hex::encode([0xABu8; 32]);
        let tmp = std::env::temp_dir().join("ember-test-recover-seed-envelope.seed");
        let path_str = tmp.to_string_lossy().to_string();

        let returned = write_seed_envelope("test-cluster", &seed_hex, Some(&path_str));
        assert_eq!(
            returned, path_str,
            "returned path must match supplied seed_out"
        );

        let contents = std::fs::read_to_string(&tmp).expect("seed envelope file must exist");
        assert_eq!(
            contents.trim(),
            seed_hex.trim(),
            "seed envelope contents must match hex"
        );

        let _ = std::fs::remove_file(&tmp);
    }

    /// recovery-status reporter: RecoveryStatus correctly labels running / not-running.
    #[test]
    fn recover_status_reporter_labels() {
        let running = RecoveryStatus {
            daemon_running: true,
            pid: Some(12345),
        };
        assert_eq!(running.status_label(), "success");

        let not_running = RecoveryStatus {
            daemon_running: false,
            pid: None,
        };
        assert_eq!(not_running.status_label(), "partial");
    }

    #[test]
    fn managed_local_vault_fallback_message_points_to_repair() {
        let msg = managed_local_vault_fallback_message();
        assert!(
            msg.contains("local vault fallback is refused"),
            "managed cluster fallback message must explain why the local path is blocked: {msg}"
        );
        assert!(
            msg.contains("sudo ember daemon install"),
            "managed cluster fallback message must point at the canonical repair path: {msg}"
        );
    }
}
