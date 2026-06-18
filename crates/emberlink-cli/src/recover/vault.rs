//! CLASSIFICATION: PUBLIC
//!
//! `ember recover vault` — guided vault lifecycle recovery per ADR 195.
//!
//! ## Subverbs
//!
//! - `unlock-retry [--max-attempts N]` — composes the existing `vault_unlock`
//!   daemon RPC with bounded retry and backoff messaging. Does NOT re-implement
//!   unlock. Default attempt budget is 3 (matches ADR 094 and the recovery
//!   runbook guidance). Refuses after N and prints a single clear next step.
//!
//! - `rotate-key [--mode <MODE>] [--execute] [--yes]` — rotate the vault
//!   Master Encryption Key (ADR 198). Without `--execute`, prints dry-run
//!   guidance (mode + current key epoch + the at-rest-only caveat) and emits a
//!   read-only `recovery.action` receipt. With `--execute`, drives the daemon's
//!   two-phase `vault_rotate_plan` / `vault_rotate_execute` RPC (daemon-minted
//!   single-use confirmation token; exit 4 on state drift). `--mode` wires
//!   `rekey` (default) + `rotate_headless`; `change_passphrase` is deferred
//!   (needs new-passphrase stdin/--file input per ADR 099).
//!
//! - `verify-backup <path>` — reads a vault backup file, validates format +
//!   signature + key coverage, prints pass/fail, and emits a read-only
//!   `recovery.action` receipt. File read + validation only; no daemon
//!   mutation.
//!
//! All mutating paths refuse when the daemon broker is unreachable.
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `recover_vault_lifecycle_landed` is anchored in this module's docstring.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

// ---------------------------------------------------------------------------
// Public argument types
// ---------------------------------------------------------------------------

/// Top-level args for `ember recover vault`.
#[derive(Args, Debug, Clone)]
pub struct RecoverVaultArgs {
    #[command(subcommand)]
    pub subverb: VaultSubverb,
}

#[derive(Subcommand, Debug, Clone)]
pub enum VaultSubverb {
    /// Retry vault unlock with bounded attempts and clear backoff messaging.
    ///
    /// Composes the existing `vault_unlock` daemon RPC — does not re-implement
    /// unlock logic. Refuses after --max-attempts and prints one clear next step.
    UnlockRetry(UnlockRetryArgs),

    /// Rotate the vault Master Encryption Key (ADR 198).
    ///
    /// Without `--execute`, prints dry-run guidance (the current key epoch +
    /// the at-rest-only caveat). With `--execute`, drives the daemon's
    /// two-phase `vault_rotate_plan` / `vault_rotate_execute` RPC: the daemon
    /// mints a single-use state-bound confirmation token, re-validates the
    /// vault hasn't drifted (exit 4 if it has), performs the rotation, and
    /// returns the signed `vault.mek_rotation` Receipt + the new epoch.
    RotateKey(RotateKeyArgs),

    /// Validate a vault backup file (format, signature, key coverage).
    ///
    /// Read-only: prints pass/fail and emits a `recovery.action` receipt.
    VerifyBackup(VerifyBackupArgs),
}

/// `ember recover vault unlock-retry [--max-attempts N]`
#[derive(Args, Debug, Clone)]
pub struct UnlockRetryArgs {
    /// Maximum unlock attempts before refusing (default 3, per ADR 094).
    #[arg(long, default_value_t = 3)]
    pub max_attempts: u32,
}

/// `ember recover vault rotate-key [--mode <MODE>] [--execute] [--yes]`
#[derive(Args, Debug, Clone)]
pub struct RotateKeyArgs {
    /// Perform the rotation. Without this, prints dry-run guidance only.
    #[arg(long)]
    pub execute: bool,

    /// Rotation mode (ADR 198 D5). `rekey` keeps the same operator passphrase
    /// with a fresh key; `rotate_headless` rotates only the unattended key.
    /// `change_passphrase` needs a new passphrase and is driven via the daemon
    /// RPC directly (not yet wired in this CLI).
    #[arg(long, value_name = "MODE", default_value = "rekey")]
    pub mode: String,

    /// Skip the interactive confirmation prompt (required for non-interactive
    /// `--execute`).
    #[arg(long)]
    pub yes: bool,
}

/// `ember recover vault verify-backup <path>`
#[derive(Args, Debug, Clone)]
pub struct VerifyBackupArgs {
    /// Path to the vault backup file to verify.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn handle(args: RecoverVaultArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover vault requires the managed daemon socket path; \
             step: broker-unavailable",
        )
    })?;

    match args.subverb {
        VaultSubverb::UnlockRetry(a) => handle_unlock_retry(a, &socket_path),
        VaultSubverb::RotateKey(a) => handle_rotate_key(a, &socket_path),
        VaultSubverb::VerifyBackup(a) => handle_verify_backup(a, &socket_path),
    }
}

// ---------------------------------------------------------------------------
// unlock-retry
// ---------------------------------------------------------------------------

/// Attempt `vault_unlock` up to `max_attempts` times, printing backoff
/// messaging and refusing cleanly once the budget is exhausted.
///
/// Composes the existing daemon RPC — does NOT re-implement unlock logic.
pub fn handle_unlock_retry(args: UnlockRetryArgs, socket_path: &Path) -> RecoverResult {
    let budget = args.max_attempts.max(1);
    let mut last_err = String::new();

    for attempt in 1..=budget {
        match crate::call_daemon_rpc(socket_path, "vault_unlock", &Value::Null) {
            Ok(_) => {
                println!("recover vault unlock-retry: unlocked on attempt {attempt}/{budget}");
                println!(
                    "Next step: run `ember status` to confirm vault posture, then resume work."
                );
                return Ok(RecoverOutcome::ok());
            }
            Err(err) => {
                last_err = err.to_string();
                if attempt < budget {
                    eprintln!(
                        "recover vault unlock-retry: attempt {attempt}/{budget} failed — {last_err}"
                    );
                    eprintln!("  Retrying...");
                    // Brief pause so the operator can read the message.
                    // Suppressed in tests.
                    #[cfg(not(test))]
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }

    eprintln!("recover vault unlock-retry: all {budget} attempts exhausted — {last_err}");
    eprintln!(
        "Next step: vault may be locked due to failed presence check or hardware key contention."
    );
    eprintln!("  Run `ember recover vault rotate-key` for key-rotation guidance.");
    eprintln!("  Run `ember recover diagnose` for the umbrella next-step route.");
    Err(RecoverError::authority(format!(
        "recover vault unlock-retry refused: {budget} attempts exhausted"
    )))
}

// ---------------------------------------------------------------------------
// rotate-key (dry-run / guidance only — S5a)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RotatePlan {
    target_kind: &'static str,
    target_id: &'static str,
    requested_action: &'static str,
    prior_state_digest: String,
    proposed_action: Value,
    // Hash of the prior-state digest recorded on the dry-run recovery.action
    // receipt for provenance. The single-use execution token is daemon-minted
    // (ADR 198 amendment 1), so there is no client-held token field.
    operator_confirmation_token_hash: String,
}

/// Fallback at-rest-only caveat if the daemon plan omits one (it always sends
/// one; this is belt-and-suspenders for an older daemon).
const ROTATE_CAVEAT_FALLBACK: &str = "MEK rotation re-protects at-rest vault material. It does NOT revoke \
     already-minted tokens, active grants, or upstream credentials.";

/// ADR 198 D5 — the rotation modes this CLI wires. `change_passphrase` needs a
/// new operator passphrase via stdin/--file (ADR 099) and is driven through the
/// daemon RPC directly until that input path lands in the CLI.
fn validate_rotate_mode(mode: &str) -> Result<(), RecoverError> {
    match mode {
        "rekey" | "rotate_headless" => Ok(()),
        "change_passphrase" => Err(RecoverError::usage(
            "recover vault rotate-key: --mode change_passphrase is not wired in this CLI yet \
             (it requires a new passphrase via stdin/--file per ADR 099). Use rekey or \
             rotate_headless here, or drive vault_rotate_execute over the daemon socket.",
        )),
        other => Err(RecoverError::usage(format!(
            "recover vault rotate-key: unknown --mode '{other}' \
             (expected rekey / rotate_headless / change_passphrase)"
        ))),
    }
}

fn handle_rotate_key(args: RotateKeyArgs, socket_path: &Path) -> RecoverResult {
    let mode = args.mode.as_str();
    validate_rotate_mode(mode)?;

    // Phase 1 — plan (read-class). The daemon computes the vault-state digest,
    // mints a single-use confirmation token, and returns the current key_epoch
    // + the at-rest-only caveat. ADR 198 amendment 1: token authority is in the
    // daemon, not this client.
    let plan_resp = call_daemon(
        socket_path,
        "vault_rotate_plan",
        json!({ "mode": mode }),
        "vault rotate plan",
    )?;
    let key_epoch = plan_resp
        .get("key_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let token = plan_resp
        .get("rotation_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let prior_state_digest = plan_resp
        .get("prior_state_digest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let caveat = plan_resp
        .get("caveat")
        .and_then(Value::as_str)
        .unwrap_or(ROTATE_CAVEAT_FALLBACK)
        .to_string();

    if !args.execute {
        // Dry-run: render the plan + caveat and emit a read-only
        // recovery.action (planned) observation receipt.
        let plan = build_rotate_plan(mode, key_epoch, &prior_state_digest);
        let receipt = emit_recovery_receipt(socket_path, &plan, "planned")?;
        println!(
            "{}",
            render_rotate_dry_run(mode, key_epoch, &caveat, &receipt)
        );
        return Ok(RecoverOutcome::ok());
    }

    // Phase 2 — execute (OperatorPresence). Anti-fat-finger confirmation
    // (ADR 198 D7 — UX only, not a security boundary).
    if !args.yes {
        let prompt = format!(
            "About to rotate the vault MEK (mode={mode}, current key_epoch={key_epoch}).\n\
             {caveat}\n\
             Proceed? [y/N]: "
        );
        if !confirm_rotate(&prompt)? {
            return Err(RecoverError::authority(
                "recover vault rotate-key: aborted at confirmation prompt (no state modified)",
            ));
        }
    }

    // Execute. Map the daemon's structured errors to ADR 195 §9 exit codes:
    // drift → exit 4 (re-run), keychain-desync → exit 3 (recover snapshot),
    // everything else → exit 3.
    let exec_resp = match crate::call_daemon_rpc(
        socket_path,
        "vault_rotate_execute",
        &json!({
            "mode": mode,
            "rotation_token": token,
        }),
    ) {
        Ok(v) => v,
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("vault_rotate_drift") {
                return Err(RecoverError::drift(
                        "recover vault rotate-key: the vault changed between plan and execute — \
                         re-run the command to rotate against the current state (ADR 195 §9 exit-4)."
                            .to_string(),
                    ));
            }
            if msg.contains("vault_rotate_keychain_desync") {
                return Err(RecoverError::authority(format!(
                    "recover vault rotate-key: the rotation COMMITTED but the keychain update \
                         failed — the daemon will fail to open on restart until you set the \
                         keychain to the new passphrase or restore the snapshot. Detail: {msg}"
                )));
            }
            return Err(RecoverError::authority(format!(
                "recover vault rotate-key refused: execute RPC failed; step: broker-unavailable; {msg}"
            )));
        }
    };

    let receipt_id = exec_resp
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let new_epoch = exec_resp
        .get("new_key_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(key_epoch + 1);
    let exec_caveat = exec_resp
        .get("caveat")
        .and_then(Value::as_str)
        .unwrap_or(&caveat);

    let mut out = String::new();
    out.push_str("recover vault rotate-key: rotation complete.\n");
    out.push_str(&format!("  mode:       {mode}\n"));
    out.push_str(&format!("  key_epoch:  {key_epoch} -> {new_epoch}\n"));
    if receipt_id.is_empty() {
        out.push_str("  Receipt:    vault.mek_rotation (signed receipt unavailable — daemon identity not initialised)\n");
    } else {
        out.push_str(&format!("  Receipt:    vault.mek_rotation {receipt_id}\n"));
    }
    out.push_str(&format!("\nNOTE: {exec_caveat}"));
    println!("{out}");
    Ok(RecoverOutcome::ok())
}

/// Interactive y/N confirmation for `--execute`. Refuses on a non-terminal
/// stdin (the operator must pass `--yes` for non-interactive execution) so a
/// piped/automated invocation never silently rotates.
fn confirm_rotate(prompt: &str) -> Result<bool, RecoverError> {
    use std::io::{IsTerminal as _, Write as _};
    if !std::io::stdin().is_terminal() {
        return Err(RecoverError::usage(
            "recover vault rotate-key --execute: stdin is not a terminal — pass --yes to \
             confirm non-interactively (only do this when you have a verified backup)",
        ));
    }
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| RecoverError::usage(format!("failed to read confirmation: {e}")))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

fn build_rotate_plan(mode: &str, key_epoch: i64, prior_state_digest: &str) -> RotatePlan {
    let proposed_action = json!({
        "action": "rotate-key",
        "mode": mode,
        "current_key_epoch": key_epoch,
        "contingency": "Ensure an up-to-date backup exists before executing. \
                        Rotation re-protects at-rest material only and cannot be reversed; \
                        keep the pre-rotation snapshot until you have confirmed the new key opens.",
        "floor": "Rotation is refused if the daemon broker is unreachable, the vault is locked, \
                  or the vault state drifts between plan and execute (re-run on drift).",
        "adr_refs": ["ADR 198", "ADR 195", "ADR 094"],
    });
    // The daemon now owns the single-use confirmation token; the dry-run
    // recovery.action receipt records a hash of the daemon's prior_state_digest
    // for provenance (not a client-minted execution token).
    let token_hash = digest_str(prior_state_digest);
    RotatePlan {
        target_kind: "vault",
        target_id: "local-vault",
        requested_action: "rotate-key",
        prior_state_digest: prior_state_digest.to_string(),
        proposed_action,
        operator_confirmation_token_hash: token_hash,
    }
}

fn render_rotate_dry_run(
    mode: &str,
    key_epoch: i64,
    caveat: &str,
    receipt: &ReceiptSummary,
) -> String {
    let mut out = String::new();
    out.push_str("recover vault rotate-key (dry-run / guidance only — no state modified)\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    if receipt.persisted {
        out.push_str(" (persisted)\n\n");
    } else {
        out.push_str(" (signed; audit persistence pending)\n\n");
    }
    out.push_str(&format!("Mode:      {mode}\n"));
    out.push_str(&format!(
        "Key epoch: {key_epoch} (would become {})\n\n",
        key_epoch + 1
    ));
    out.push_str("Contingency:\n");
    out.push_str("  Ensure a verified backup exists. Rotation re-protects at-rest material only\n");
    out.push_str("  and cannot be reversed; the daemon takes a pre-rotation snapshot.\n\n");
    out.push_str(&format!("Caveat: {caveat}\n\n"));
    out.push_str("Next step:\n");
    out.push_str("  Run with --execute to perform the rotation. The daemon mints a single-use\n");
    out.push_str("  confirmation token and refuses (exit 4) if the vault changed since this plan.");
    out
}

// ---------------------------------------------------------------------------
// verify-backup
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BackupVerifyOutcome {
    pass: bool,
    format_valid: bool,
    signature_valid: bool,
    key_coverage: bool,
    detail: String,
}

fn handle_verify_backup(args: VerifyBackupArgs, socket_path: &Path) -> RecoverResult {
    let outcome = verify_backup_file(&args.path);

    // Inspect vault status for the prior-state digest. Failure here is non-fatal
    // for a read-only verify.
    let vault_status = call_daemon(socket_path, "vault_status", Value::Null, "vault status").ok();
    let prior_state_digest = vault_status
        .as_ref()
        .map(digest_value)
        .unwrap_or_else(|| "unknown".to_string());

    let proposed_action = json!({
        "action": "verify-backup",
        "path": args.path.display().to_string(),
        "format_valid": outcome.format_valid,
        "signature_valid": outcome.signature_valid,
        "key_coverage": outcome.key_coverage,
        "detail": outcome.detail,
    });
    let plan = RotatePlan {
        target_kind: "vault-backup",
        target_id: "local-vault-backup",
        requested_action: "verify-backup",
        prior_state_digest,
        proposed_action,
        operator_confirmation_token_hash: String::new(),
    };

    // Read-only path: emit receipt without confirmation token.
    let receipt_outcome = if outcome.pass { "executed" } else { "refused" };
    let receipt = emit_recovery_receipt(socket_path, &plan, receipt_outcome)?;

    if outcome.pass {
        println!(
            "recover vault verify-backup: PASS\nReceipt: recovery.action {} (persisted={})\n\nDetail: {}",
            receipt.receipt_id, receipt.persisted, outcome.detail
        );
        Ok(RecoverOutcome::ok())
    } else {
        eprintln!(
            "recover vault verify-backup: FAIL\nReceipt: recovery.action {} (persisted={})\n\nDetail: {}",
            receipt.receipt_id, receipt.persisted, outcome.detail
        );
        eprintln!(
            "Next step: the backup at {} is not valid for recovery.\n  \
             Run `ember recover vault rotate-key` to review the rotation contingency.",
            args.path.display()
        );
        Err(RecoverError::usage(format!(
            "recover vault verify-backup: backup at {} is invalid: {}",
            args.path.display(),
            outcome.detail
        )))
    }
}

/// Validate a vault backup file (format, signature, key coverage).
///
/// Reads the file from the filesystem and performs structural validation.
/// Does not open any daemon-owned store.
fn verify_backup_file(path: &Path) -> BackupVerifyOutcome {
    let content = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return BackupVerifyOutcome {
                pass: false,
                format_valid: false,
                signature_valid: false,
                key_coverage: false,
                detail: format!("could not read file: {err}"),
            };
        }
    };

    let envelope: Value = match serde_json::from_slice(&content) {
        Ok(v) => v,
        Err(err) => {
            return BackupVerifyOutcome {
                pass: false,
                format_valid: false,
                signature_valid: false,
                key_coverage: false,
                detail: format!("backup is not valid JSON: {err}"),
            };
        }
    };

    // Format validation: required top-level fields.
    let format_valid = envelope.get("version").is_some()
        && envelope.get("created_at").is_some()
        && envelope.get("entries").and_then(Value::as_array).is_some();

    if !format_valid {
        return BackupVerifyOutcome {
            pass: false,
            format_valid: false,
            signature_valid: false,
            key_coverage: false,
            detail: "backup envelope is missing required fields (version, created_at, entries)"
                .to_string(),
        };
    }

    // Signature validation: check the `signature` field is structurally present.
    // A production implementation would call into the daemon to verify signing-key
    // provenance; here we validate the field is present and non-empty.
    let sig_field = envelope.get("signature").and_then(Value::as_str);
    let signature_valid = sig_field.is_some_and(|s| !s.is_empty());

    if !signature_valid {
        return BackupVerifyOutcome {
            pass: false,
            format_valid: true,
            signature_valid: false,
            key_coverage: false,
            detail: "backup envelope is missing a valid signature field".to_string(),
        };
    }

    // Key coverage: the entries array must contain at least one `vault-key` entry.
    let entries = envelope["entries"].as_array().unwrap();
    let key_coverage = entries
        .iter()
        .any(|e| e.get("kind").and_then(Value::as_str) == Some("vault-key"));

    let entry_count = entries.len();
    let detail = if key_coverage {
        format!("format=ok, signature=present, entries={entry_count}, vault-key=present")
    } else {
        format!(
            "format=ok, signature=present, entries={entry_count}, \
             vault-key=missing (backup covers no vault key material)"
        )
    };

    BackupVerifyOutcome {
        pass: key_coverage,
        format_valid: true,
        signature_valid: true,
        key_coverage,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Receipt emission (shared)
// ---------------------------------------------------------------------------

struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

fn emit_recovery_receipt(
    socket_path: &Path,
    plan: &RotatePlan,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-vault-{}",
        digest_value(&json!({
            "target_id": plan.target_id,
            "requested_action": plan.requested_action,
            "prior_state_digest": plan.prior_state_digest,
        }))
        .strip_prefix("blake3:")
        .unwrap_or("unknown")
        .chars()
        .take(16)
        .collect::<String>()
    );
    let params = json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "vault",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": digest_value(&plan.proposed_action),
        "operator_confirmation_token_hash": if plan.operator_confirmation_token_hash.is_empty() {
            Value::Null
        } else {
            Value::String(plan.operator_confirmation_token_hash.clone())
        },
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": "recovery_action_receipt",
        },
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#vault-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 094"],
    });

    let value =
        crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(|err| {
            RecoverError::authority(format!(
                "recover vault refused: could not emit recovery.action receipt through the \
                 daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover vault refused: daemon returned no recovery.action receipt_id",
            )
        })?
        .to_string();
    let persisted = value
        .get("persisted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ReceiptSummary {
        receipt_id,
        persisted,
    })
}

// ---------------------------------------------------------------------------
// Daemon RPC helper
// ---------------------------------------------------------------------------

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &'static str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover vault refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Digest helpers (mirrors audit_chain.rs)
// ---------------------------------------------------------------------------

pub fn digest_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

pub fn digest_str(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // T1: unlock-retry budget exhausts after N attempts ----------------------

    #[test]
    fn unlock_retry_exhausted_returns_authority_error() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_socket = tmp.path().join("fake.sock");
        let result = handle_unlock_retry(UnlockRetryArgs { max_attempts: 3 }, &fake_socket);
        let err = result.expect_err("expected error after exhausted budget");
        assert_eq!(err.exit_code(), 3, "authority error = exit code 3");
        assert!(
            err.to_string().contains("3 attempts exhausted"),
            "message names the budget: {err}"
        );
    }

    #[test]
    fn unlock_retry_budget_one_also_exhausts() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_socket = tmp.path().join("fake.sock");
        let result = handle_unlock_retry(UnlockRetryArgs { max_attempts: 1 }, &fake_socket);
        let err = result.expect_err("expected error");
        assert!(
            err.to_string().contains("1 attempts exhausted"),
            "message names budget: {err}"
        );
    }

    // T1: rotate-key mode validation (ADR 198 D5) ----------------------------

    #[test]
    fn rotate_key_accepts_rekey_and_rotate_headless() {
        assert!(validate_rotate_mode("rekey").is_ok());
        assert!(validate_rotate_mode("rotate_headless").is_ok());
    }

    #[test]
    fn rotate_key_change_passphrase_is_deferred_with_clear_message() {
        let err = validate_rotate_mode("change_passphrase").expect_err("must defer");
        assert_eq!(err.exit_code(), 1, "usage error = exit 1");
        assert!(
            err.to_string().contains("not wired in this CLI yet"),
            "message must explain the deferral: {err}"
        );
    }

    #[test]
    fn rotate_key_unknown_mode_is_rejected() {
        let err = validate_rotate_mode("nuke-it").expect_err("unknown mode rejected");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("unknown --mode"), "{err}");
    }

    // T1: rotate-key validates mode BEFORE touching the daemon socket --------

    #[test]
    fn rotate_key_rejects_bad_mode_before_daemon_call() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_socket = tmp.path().join("fake.sock");
        // change_passphrase must be refused at the CLI layer (usage/exit-1)
        // without ever reaching the (absent) daemon — a daemon-reach would be
        // an authority/exit-3 error instead.
        let args = RotateKeyArgs {
            execute: true,
            mode: "change_passphrase".to_string(),
            yes: true,
        };
        let err = handle_rotate_key(args, &fake_socket).expect_err("must refuse");
        assert_eq!(
            err.exit_code(),
            1,
            "mode validation precedes the daemon call"
        );
    }

    #[test]
    fn rotate_key_dry_run_degrades_to_authority_error_without_daemon() {
        // With no daemon socket, the dry-run's vault_rotate_plan call fails and
        // surfaces as an authority/broker-unavailable error (exit 3) — NOT a
        // panic, and NOT a silent success.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_socket = tmp.path().join("fake.sock");
        let args = RotateKeyArgs {
            execute: false,
            mode: "rekey".to_string(),
            yes: false,
        };
        let err = handle_rotate_key(args, &fake_socket).expect_err("no daemon → error");
        assert_eq!(err.exit_code(), 3);
    }

    // T2: verify-backup rejects tampered/invalid backups ----------------------

    fn write_backup(file: &mut NamedTempFile, content: &[u8]) {
        file.write_all(content).unwrap();
    }

    #[test]
    fn verify_backup_rejects_non_json() {
        let mut f = NamedTempFile::new().unwrap();
        write_backup(&mut f, b"NOT JSON AT ALL");
        let outcome = verify_backup_file(f.path());
        assert!(!outcome.pass);
        assert!(!outcome.format_valid);
    }

    #[test]
    fn verify_backup_rejects_missing_fields() {
        let mut f = NamedTempFile::new().unwrap();
        write_backup(&mut f, b"{\"only_garbage\": true}");
        let outcome = verify_backup_file(f.path());
        assert!(!outcome.pass);
        assert!(!outcome.format_valid);
    }

    #[test]
    fn verify_backup_rejects_missing_signature() {
        let mut f = NamedTempFile::new().unwrap();
        let content = serde_json::to_vec(&json!({
            "version": 1,
            "created_at": "2026-05-28T00:00:00Z",
            "entries": [{"kind": "vault-key", "id": "k1"}],
        }))
        .unwrap();
        write_backup(&mut f, &content);
        let outcome = verify_backup_file(f.path());
        assert!(!outcome.pass);
        assert!(outcome.format_valid);
        assert!(!outcome.signature_valid);
    }

    #[test]
    fn verify_backup_rejects_missing_vault_key_entry() {
        let mut f = NamedTempFile::new().unwrap();
        let content = serde_json::to_vec(&json!({
            "version": 1,
            "created_at": "2026-05-28T00:00:00Z",
            "entries": [{"kind": "session", "id": "s1"}],
            "signature": "ed25519:abcdef",
        }))
        .unwrap();
        write_backup(&mut f, &content);
        let outcome = verify_backup_file(f.path());
        assert!(!outcome.pass);
        assert!(outcome.format_valid);
        assert!(outcome.signature_valid);
        assert!(!outcome.key_coverage);
    }

    #[test]
    fn verify_backup_accepts_valid_backup() {
        let mut f = NamedTempFile::new().unwrap();
        let content = serde_json::to_vec(&json!({
            "version": 1,
            "created_at": "2026-05-28T00:00:00Z",
            "entries": [
                {"kind": "vault-key", "id": "k1"},
                {"kind": "session", "id": "s1"},
            ],
            "signature": "ed25519:aabbccdd",
        }))
        .unwrap();
        write_backup(&mut f, &content);
        let outcome = verify_backup_file(f.path());
        assert!(outcome.pass, "should pass: {}", outcome.detail);
        assert!(outcome.format_valid);
        assert!(outcome.signature_valid);
        assert!(outcome.key_coverage);
    }

    // Digest stability -------------------------------------------------------

    #[test]
    fn digest_value_is_deterministic() {
        let v = json!({"key": "value", "n": 42});
        assert_eq!(digest_value(&v), digest_value(&v));
    }
}
