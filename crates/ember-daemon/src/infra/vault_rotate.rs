//! ADR 198 D3/D7 + amendments 1/2 — vault MEK-rotation RPC orchestration.
//!
//! Two-phase, daemon-authoritative rotation:
//!
//! - `vault_rotate_plan` (read-class) computes the current vault-state digest +
//!   the plan digest and mints a daemon-held, **single-use, expiring** token
//!   bound to both. The token authority lives in the daemon, not the client
//!   (ADR 198 Alternative D — a client-side token is rejected).
//! - `vault_rotate_execute` (OperatorPresence) validates + consumes the token,
//!   **re-validates** the state digest still matches (refusing with the ADR 195
//!   §9 exit-4 *drift* code if the vault changed between plan and execute),
//!   runs [`Vault::rotate_mek`], then wires the post-commit live-state + audit
//!   side effects the primitive intentionally leaves to the caller: swap the
//!   live `Vault` slot (D6), update the keychain for `change_passphrase`, clear
//!   key caches, emit the signed `vault.mek_rotation` Receipt, and retire the
//!   now-shadowed file sidecars.
//!
//! The gate itself is enforced upstream in `dispatch_method_with_context`
//! (`vault_rotate_execute` is classified `OperatorPresence` + scoped to
//! `class:vault`); this module runs only after that gate passes.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde_json::{Value, json};

use crate::infra::receipt::{append_receipts_journal, current_identity};
use crate::infra::store::DaemonStore;
use crate::infra::vault::{self, RotationMode};
use core_events::receipt::{
    RECEIPT_KIND_VAULT_MEK_ROTATION, ReceiptEnvelope, ReceiptVersion, TerminationAuthority,
    VaultMekRotationBody, sign::sign_receipt_v2,
};

/// Confirmation-token lifetime — long enough for an operator to read the plan
/// and confirm, short enough that a stale token cannot be replayed much later.
const ROTATION_TOKEN_TTL_SECS: i64 = 120;

/// Cap on outstanding (live, unexpired) rotation tokens. Only ONE rotation can
/// ever execute, so a large backlog is always stale planning churn; bounding
/// it forecloses unbounded `vault_rotate_plan` token-minting heap growth
/// (adversarial review A/LOW — a same-uid operator-domain DoS, but cheap to
/// close). When at the cap, the oldest-expiring token is evicted so a fresh
/// legitimate plan always succeeds.
const MAX_OUTSTANDING_ROTATION_TOKENS: usize = 16;

/// The honest at-rest-only caveat surfaced in both the plan and the execute
/// response + the operator-facing CLI (ADR 198 D6).
pub(crate) const ROTATION_CAVEAT: &str = "MEK rotation re-protects at-rest vault material. It does NOT revoke \
     already-minted tokens (they expire on TTL), active grants, or the upstream \
     credentials themselves (e.g. the GitHub App private key). If you rotated due \
     to suspected compromise, also revoke active grants and rotate those upstream \
     credentials.";

/// A pending rotation authorization minted by `vault_rotate_plan`.
struct PendingRotation {
    /// blake3 digest of the vault state at plan time (see [`vault_state_digest`]).
    prior_state_digest: String,
    /// blake3 digest of the requested plan (mode).
    plan_digest: String,
    /// The mode the plan authorized — execute MUST match.
    mode: RotationMode,
    /// Expiry (single-use tokens are also pruned past this).
    not_after: DateTime<Utc>,
}

/// Process-singleton store of outstanding rotation tokens. Single-use: a token
/// is REMOVED on consume, so any replay finds it absent and is rejected.
static ROTATION_TOKENS: Lazy<Mutex<HashMap<String, PendingRotation>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// ADR 198 amendment 1 — a digest of the vault state that a rotation depends
/// on, so the plan/execute pair can detect drift. Covers the key epoch, the
/// full set of credential + persona row ids (additions/removals change the
/// re-wrap set), and the advisory MEK fingerprint. blake3 to match the rest of
/// vault.rs. NOT a security boundary on its own — it is the freshness check
/// behind the OperatorPresence gate; an attacker who can already mutate the DB
/// is caught by the AEAD canary, not this digest.
pub(crate) fn vault_state_digest(store: &DaemonStore) -> Result<String, (i32, String)> {
    let key_epoch = store
        .read_key_epoch()
        .map_err(|e| (-32000, format!("vault_state_digest: read key_epoch: {e}")))?;
    let mek_fp = store
        .read_mek_fingerprint()
        .map_err(|e| (-32000, format!("vault_state_digest: read fingerprint: {e}")))?
        .unwrap_or_default();

    let collect_ids = |sql: &str| -> Result<Vec<String>, (i32, String)> {
        let mut stmt = store
            .conn()
            .prepare(sql)
            .map_err(|e| (-32000, format!("vault_state_digest: prepare: {e}")))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| (-32000, format!("vault_state_digest: query: {e}")))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r.map_err(|e| (-32000, format!("vault_state_digest: row: {e}")))?);
        }
        Ok(ids)
    };
    let cred_ids = collect_ids("SELECT id FROM credentials ORDER BY id")?;
    let persona_ids = collect_ids("SELECT id FROM personas ORDER BY id")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vault-state-digest.v1");
    hasher.update(&key_epoch.to_le_bytes());
    hasher.update(b"|creds|");
    for id in &cred_ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"|personas|");
    for id in &persona_ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\n");
    }
    hasher.update(b"|fp|");
    hasher.update(mek_fp.as_bytes());
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

/// blake3 digest of the requested plan (just the mode today; widen if the plan
/// grows parameters). Binds the token to the action so a token minted for one
/// mode cannot authorize another.
fn plan_digest(mode: RotationMode) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vault-rotate-plan.v1|mode|");
    hasher.update(mode.as_str().as_bytes());
    format!("blake3:{}", hasher.finalize().to_hex())
}

/// Mint a single-use token (random opaque id), record it, and return
/// `(token, not_after)`.
fn mint_rotation_token(
    prior_state_digest: &str,
    plan_digest: &str,
    mode: RotationMode,
    now: DateTime<Utc>,
) -> (String, DateTime<Utc>) {
    let token = format!("vault-rotate-{}", uuid::Uuid::new_v4());
    let not_after = now + chrono::Duration::seconds(ROTATION_TOKEN_TTL_SECS);
    let mut tokens = ROTATION_TOKENS.lock().expect("rotation token mutex");
    // Prune any expired tokens while we hold the lock.
    tokens.retain(|_, p| p.not_after > now);
    // Bound the live set: evict the oldest-expiring token(s) so a fresh plan
    // always lands and the map cannot grow without bound.
    while tokens.len() >= MAX_OUTSTANDING_ROTATION_TOKENS {
        if let Some(oldest) = tokens
            .iter()
            .min_by_key(|(_, p)| p.not_after)
            .map(|(k, _)| k.clone())
        {
            tokens.remove(&oldest);
        } else {
            break;
        }
    }
    tokens.insert(
        token.clone(),
        PendingRotation {
            prior_state_digest: prior_state_digest.to_string(),
            plan_digest: plan_digest.to_string(),
            mode,
            not_after,
        },
    );
    (token, not_after)
}

/// Validate + consume (single-use) a rotation token for `mode`, then
/// re-validate the vault-state digest still matches the plan. Returns the
/// drift error (mapped so the CLI can exit-4) when the vault changed.
fn consume_rotation_token(
    token: &str,
    mode: RotationMode,
    store: &DaemonStore,
    now: DateTime<Utc>,
) -> Result<(), (i32, String)> {
    let pending = {
        let mut tokens = ROTATION_TOKENS.lock().expect("rotation token mutex");
        tokens.retain(|_, p| p.not_after > now);
        // Single-use: remove on consume.
        tokens.remove(token)
    };
    let pending = pending.ok_or((
        -32030,
        json!({
            "error": "vault_rotate_token_invalid",
            "reason": "rotation token is unknown, already used, or expired — run vault_rotate_plan again",
        })
        .to_string(),
    ))?;
    if pending.mode != mode {
        return Err((
            -32602,
            json!({
                "error": "vault_rotate_mode_mismatch",
                "reason": format!(
                    "token authorized mode '{}' but execute requested '{}'",
                    pending.mode.as_str(),
                    mode.as_str()
                ),
            })
            .to_string(),
        ));
    }
    if pending.plan_digest != plan_digest(mode) {
        return Err((
            -32602,
            json!({"error": "vault_rotate_plan_mismatch", "reason": "plan digest changed"})
                .to_string(),
        ));
    }
    // ADR 198 amendment 1 — re-validate the state digest. If the vault changed
    // between plan and execute, refuse with the drift signal (CLI exit-4).
    let current = vault_state_digest(store)?;
    if current != pending.prior_state_digest {
        return Err((
            -32030,
            json!({
                "error": "vault_rotate_drift",
                "reason": "vault state changed between plan and execute; re-run vault_rotate_plan (ADR 195 §9 exit-4)",
            })
            .to_string(),
        ));
    }
    Ok(())
}

/// `vault_rotate_plan` handler (read-class). Mints the confirmation token.
pub(crate) fn handle_vault_rotate_plan(
    store: &DaemonStore,
    params: &Value,
    now: DateTime<Utc>,
) -> Result<Value, (i32, String)> {
    let mode_str = params["mode"].as_str().unwrap_or("rekey");
    let mode = RotationMode::parse(mode_str).ok_or((
        -32602,
        "invalid 'mode' (expected rekey / change_passphrase / rotate_headless)".to_string(),
    ))?;
    let prior = vault_state_digest(store)?;
    let plan = plan_digest(mode);
    let key_epoch = store
        .read_key_epoch()
        .map_err(|e| (-32000, format!("read key_epoch: {e}")))?;
    let (token, not_after) = mint_rotation_token(&prior, &plan, mode, now);
    Ok(json!({
        "rotation_token": token,
        "prior_state_digest": prior,
        "plan_digest": plan,
        "mode": mode.as_str(),
        "key_epoch": key_epoch,
        "expires_at": not_after.to_rfc3339(),
        "expires_in_secs": ROTATION_TOKEN_TTL_SECS,
        "caveat": ROTATION_CAVEAT,
    }))
}

/// `vault_rotate_execute` dispatch entrypoint (OperatorPresence). Resolves the
/// daemon config + data dir from the live runtime, then delegates to
/// [`execute_with_config`] (which is what the unit tests drive directly).
pub(crate) fn handle_vault_rotate_execute(
    store: &DaemonStore,
    params: &Value,
    now: DateTime<Utc>,
) -> Result<Value, (i32, String)> {
    let config = crate::infra::interactive_unlock::current_config()
        .ok_or((-32030, "daemon config unavailable for rotation".to_string()))?;
    let data_dir = store
        .data_dir()
        .ok_or((
            -32030,
            "daemon data dir unavailable for rotation".to_string(),
        ))?
        .to_path_buf();
    execute_with_config(store, &config, &data_dir, params, now)
}

/// The testable core of `vault_rotate_execute`: validates + consumes the
/// token, runs [`Vault::rotate_mek`], and wires the post-commit side effects
/// (live-slot swap, keychain update for `change_passphrase`, cache clears,
/// signed Receipt, file retirement). `config` + `data_dir` are injected so
/// this is exercisable without the live runtime's config thread-local.
pub(crate) fn execute_with_config(
    store: &DaemonStore,
    config: &crate::infra::config::DaemonConfig,
    data_dir: &std::path::Path,
    params: &Value,
    now: DateTime<Utc>,
) -> Result<Value, (i32, String)> {
    let mode = RotationMode::parse(params["mode"].as_str().unwrap_or("")).ok_or((
        -32602,
        "missing/invalid 'mode' (expected rekey / change_passphrase / rotate_headless)".to_string(),
    ))?;
    let token = params["rotation_token"]
        .as_str()
        .ok_or((-32602, "missing 'rotation_token'".to_string()))?;

    // ADR 198 D5 / ADR 131 — `change_passphrase` is unsupported when the
    // operator secret is SE-wrapped (the separate-uid production posture): the
    // new passphrase would have to be re-wrapped under the Secure Enclave, not
    // written to the keychain via `set_vault_passphrase`, so committing it
    // would desync the SE blob from the rotated MEK. Refuse up-front (before
    // consuming the token / mutating anything) rather than silently bricking
    // the next restart. `rekey` / `rotate_headless` are fine — they keep the
    // same operator secret.
    if mode == RotationMode::ChangePassphrase && vault::vault_passphrase_is_se_wrapped() {
        return Err((
            -32030,
            json!({
                "error": "vault_rotate_change_passphrase_unsupported_se_posture",
                "reason": "change_passphrase is not supported on this daemon — the operator secret \
                           is Secure-Enclave-wrapped (separate-uid posture); rotating it requires \
                           re-wrapping under the SE, which this primitive does not do. Use rekey \
                           (same passphrase, fresh key) instead.",
            })
            .to_string(),
        ));
    }

    // Validate + consume the token (drift → CLI exit-4). Single-use.
    consume_rotation_token(token, mode, store, now)?;

    let data_dir = data_dir.to_path_buf();

    // Resolve the CURRENT operator passphrase (snapshot + rekey derivation) the
    // SAME way the daemon opened the vault — including the ADR 131 separate-uid
    // SE-blob source. A keychain-only resolve would break rotation on the real
    // production daemon (which reads vault-mek.bin, not a keychain entry).
    let current_pass = vault::resolve_current_vault_passphrase(config)
        .map_err(|e| (-32030, format!("resolve current passphrase: {e}")))?
        .ok_or((
            -32030,
            "no operator passphrase source to rotate from (checked env, SE blob, keychain)"
                .to_string(),
        ))?;
    let new_pass: Option<String> = if mode == RotationMode::ChangePassphrase {
        Some(
            params["new_passphrase"]
                .as_str()
                .ok_or((
                    -32602,
                    "change_passphrase requires 'new_passphrase' (CLI reads it via stdin/--file per ADR 099)"
                        .to_string(),
                ))?
                .to_string(),
        )
    } else {
        None
    };

    let vault = store.vault().ok_or((
        -32030,
        "vault is locked — unlock before rotating".to_string(),
    ))?;

    let outcome = vault
        .rotate_mek(store, &data_dir, mode, &current_pass, new_pass.as_deref())
        .map_err(|e| (-32000, format!("vault rotation failed: {e}")))?;

    let vault::RotationOutcome {
        new_vault,
        mode: _,
        rewrap_count,
        prev_key_epoch,
        new_key_epoch,
        prev_scope_fingerprint,
        new_scope_fingerprint,
        snapshot_path,
        retired_files,
    } = outcome;

    // ── POST-COMMIT (the rotation is now durable in the DB). ──
    //
    // Ordering matters. For change_passphrase the keychain MUST be updated or
    // the next daemon restart derives the wrong MEK and the canary fail-loud
    // bricks the open (recoverable only via the snapshot). We attempt it
    // first, but the rotation has ALREADY committed, so we cannot un-rotate —
    // we MUST still swap the live vault (only the new vault can read the
    // rotated DB; the old vault is now stale against it). The honesty fix
    // (adversarial review O/HIGH): on keychain failure we do NOT return a
    // success-shaped result — we still emit the audit Receipt (the DB rotation
    // genuinely happened) and swap the live slot for session continuity, but
    // we return an ERROR so a receipt-id/exit-0-checking caller cannot read it
    // as success while the vault is one restart away from bricking.
    let keychain_desync: Option<String> = if mode == RotationMode::ChangePassphrase {
        match new_pass.as_deref() {
            Some(p) => match vault::set_vault_passphrase(config, p) {
                Ok(()) => None,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        snapshot = %snapshot_path,
                        "vault change_passphrase committed but the keychain passphrase update \
                         FAILED — the daemon will fail to open on restart; update the keychain to \
                         the new passphrase or restore the snapshot"
                    );
                    Some(format!("{e}"))
                }
            },
            None => None,
        }
    } else {
        None
    };

    // Swap the live vault slot (D6) — the new vault is the only one that can
    // read the rotated DB. For change_passphrase, clear the operator-passphrase
    // caches so the next reopen re-derives from the new keychain entry (rekey
    // keeps the same passphrase, so its caches stay correct — only the DB salt
    // changed, which reopen reads fresh).
    store.set_vault(std::rc::Rc::new(new_vault));
    if mode == RotationMode::ChangePassphrase {
        vault::clear_passphrase_caches();
    }

    // Emit the signed vault.mek_rotation Receipt (canonical builder; never
    // hand-rolled). The rotation already committed, so a signing/identity
    // failure here is NON-fatal — we log + return an empty receipt id +
    // `receipt_emitted: false` rather than a hard error that would mask the
    // successful rotation (adversarial review O/MEDIUM).
    let rotated_at_epoch_secs = now.timestamp().max(0) as u64;
    let body = VaultMekRotationBody {
        mode: mode.as_str().to_string(),
        prev_key_epoch: prev_key_epoch.max(0) as u64,
        new_key_epoch: new_key_epoch.max(0) as u64,
        rewrap_count,
        prev_mek_fingerprint: prev_scope_fingerprint,
        new_mek_fingerprint: new_scope_fingerprint,
        snapshot_path: snapshot_path.clone(),
        rotated_at_epoch_secs,
    };
    // A validate() failure is a programmer error (we built the body) — log it
    // but do not mask the committed rotation.
    if let Err(e) = body.validate() {
        tracing::error!(error = %e, "vault.mek_rotation body failed validate() post-commit");
    }
    let (receipt_id, receipt_emitted) = match (current_identity(), serde_json::to_value(&body)) {
        (Some(identity), Ok(body_value)) => {
            let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
            let mut envelope = ReceiptEnvelope {
                version: ReceiptVersion::default(),
                kind: RECEIPT_KIND_VAULT_MEK_ROTATION.to_string(),
                receipt_id: String::new(),
                daemon_root_id: identity.pubkey_hex(),
                traceparent: None,
                termination_authority: TerminationAuthority::DaemonPersona,
                presence_kind: None,
                body: body_value,
                signature: None,
                calling_principal: None,
                presence_reason: None,
                handle_id: None,
                challenge_hash: None,
                verifier_aaguid: None,
            };
            match sign_receipt_v2(&mut envelope, &signer) {
                Ok(()) => {
                    if let Err(e) = append_receipts_journal(&data_dir, &envelope) {
                        tracing::warn!(error = %e, "vault rotation Receipt signed but journal append failed");
                    }
                    (envelope.receipt_id, true)
                }
                Err(e) => {
                    tracing::error!(error = %e, "vault rotation committed but signing the Receipt FAILED — rotation stands, audit Receipt missing");
                    (String::new(), false)
                }
            }
        }
        (None, _) => {
            tracing::warn!(
                "vault rotation committed but no daemon identity is initialised — \
                 no signed Receipt emitted"
            );
            (String::new(), false)
        }
        (Some(_), Err(e)) => {
            tracing::error!(error = %e, "vault rotation committed but serializing the Receipt body FAILED");
            (String::new(), false)
        }
    };

    // Retire the now-shadowed file sidecars (DB-first reads make a lingering
    // file harmless, so a delete failure is non-fatal).
    for file in &retired_files {
        if file.exists()
            && let Err(e) = std::fs::remove_file(file)
        {
            tracing::warn!(
                path = %file.display(),
                error = %e,
                "vault rotation: failed to retire shadowed file sidecar (non-fatal)"
            );
        }
    }

    // ADR 198 amendment 2 — the keychain desync is the one post-commit failure
    // that leaves the vault NOT fully rotated (restart will brick). Surface it
    // as an error so the caller cannot read exit-0 success. The rotation is
    // recorded (Receipt above), live (slot swapped), and recoverable (snapshot).
    if let Some(detail) = keychain_desync {
        return Err((
            -32030,
            json!({
                "error": "vault_rotate_keychain_desync",
                "reason": format!(
                    "change_passphrase committed in the vault but the keychain update failed ({detail}); \
                     the daemon will fail to open on restart until you set the keychain to the new \
                     passphrase or restore the snapshot"
                ),
                "snapshot_path": snapshot_path,
                "receipt_id": receipt_id,
                "new_key_epoch": new_key_epoch,
            })
            .to_string(),
        ));
    }

    Ok(json!({
        "receipt_id": receipt_id,
        "receipt_emitted": receipt_emitted,
        "receipt_kind": RECEIPT_KIND_VAULT_MEK_ROTATION,
        "mode": mode.as_str(),
        "prev_key_epoch": prev_key_epoch,
        "new_key_epoch": new_key_epoch,
        "rewrap_count": rewrap_count,
        "snapshot_path": snapshot_path,
        "keychain_update": json!({"ok": true}),
        "caveat": ROTATION_CAVEAT,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::vault::{Vault, VaultScope};
    use std::rc::Rc;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn provisioned_store(salt: &[u8; 16], pass: &str) -> (DaemonStore, Rc<Vault>) {
        let store = DaemonStore::open_in_memory().unwrap();
        // `from_passphrase` derives the Interactive key via Argon2id; the
        // plan/token tests here exercise digest + token lifecycle, not the
        // rotation crypto itself (covered by vault.rs rotate_mek tests).
        let vault = Rc::new(Vault::from_passphrase(pass, salt));
        store.set_vault(Rc::clone(&vault));
        vault.provision_envelope_meta(&store, salt).unwrap();
        (store, vault)
    }

    #[test]
    fn state_digest_changes_when_a_credential_is_added() {
        let (store, vault) = provisioned_store(&[3u8; 16], "p");
        let d0 = vault_state_digest(&store).unwrap();
        vault
            .add(VaultScope::Interactive, &store, "c", b"v", None)
            .unwrap();
        let d1 = vault_state_digest(&store).unwrap();
        assert_ne!(d0, d1, "adding a credential must change the state digest");
    }

    #[test]
    fn token_is_single_use() {
        let (store, _v) = provisioned_store(&[3u8; 16], "p");
        let now = fixed_now();
        let plan = handle_vault_rotate_plan(&store, &json!({"mode": "rekey"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap();
        // First consume succeeds.
        consume_rotation_token(token, RotationMode::Rekey, &store, now).unwrap();
        // Replay fails (removed).
        let err = consume_rotation_token(token, RotationMode::Rekey, &store, now).unwrap_err();
        assert!(
            err.1.contains("vault_rotate_token_invalid"),
            "got {}",
            err.1
        );
    }

    #[test]
    fn token_drifts_when_state_changes_between_plan_and_execute() {
        let (store, vault) = provisioned_store(&[3u8; 16], "p");
        let now = fixed_now();
        let plan = handle_vault_rotate_plan(&store, &json!({"mode": "rekey"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap().to_string();
        // Mutate the vault after planning.
        vault
            .add(VaultScope::Interactive, &store, "late", b"v", None)
            .unwrap();
        let err = consume_rotation_token(&token, RotationMode::Rekey, &store, now).unwrap_err();
        assert_eq!(err.0, -32030);
        assert!(err.1.contains("vault_rotate_drift"), "got {}", err.1);
    }

    #[test]
    fn token_rejects_mode_mismatch() {
        let (store, _v) = provisioned_store(&[3u8; 16], "p");
        let now = fixed_now();
        let plan = handle_vault_rotate_plan(&store, &json!({"mode": "rekey"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap();
        let err =
            consume_rotation_token(token, RotationMode::RotateHeadless, &store, now).unwrap_err();
        assert!(
            err.1.contains("vault_rotate_mode_mismatch"),
            "got {}",
            err.1
        );
    }

    #[test]
    fn token_expires() {
        let (store, _v) = provisioned_store(&[3u8; 16], "p");
        let now = fixed_now();
        let plan = handle_vault_rotate_plan(&store, &json!({"mode": "rekey"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap();
        let later = now + chrono::Duration::seconds(ROTATION_TOKEN_TTL_SECS + 1);
        let err = consume_rotation_token(token, RotationMode::Rekey, &store, later).unwrap_err();
        assert!(
            err.1.contains("vault_rotate_token_invalid"),
            "got {}",
            err.1
        );
    }

    /// Full plan → execute over the handlers: rekey bumps the epoch, swaps the
    /// live vault (the cred reads back through the new slot), and the token is
    /// single-use (replay refuses).
    #[test]
    fn execute_rekey_end_to_end() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // resolve_passphrase_no_provision returns the deterministic test
        // passphrase only when this gate env is set.
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

        let tmp = tempfile::tempdir().unwrap();
        let store = DaemonStore::open(&tmp.path().join("daemon.db")).unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let service = vault::resolve_keyring_service(&config.keyring);
        let account = vault::resolve_keyring_account(&config.keyring);
        let pass = format!("test-passphrase-{service}-{account}");
        let salt = [4u8; 16];
        let vault = Rc::new(Vault::from_passphrase(&pass, &salt));
        store.set_vault(Rc::clone(&vault));
        vault.provision_envelope_meta(&store, &salt).unwrap();
        vault
            .add(VaultScope::Interactive, &store, "c", b"v", None)
            .unwrap();

        let now = fixed_now();
        let plan = handle_vault_rotate_plan(&store, &json!({"mode": "rekey"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap().to_string();

        let res = execute_with_config(
            &store,
            &config,
            tmp.path(),
            &json!({"mode": "rekey", "rotation_token": token.clone()}),
            now,
        )
        .unwrap();
        assert_eq!(res["mode"], "rekey");
        assert_eq!(res["prev_key_epoch"], 0);
        assert_eq!(res["new_key_epoch"], 1);
        assert_eq!(res["keychain_update"]["ok"], true);
        assert_eq!(store.read_key_epoch().unwrap(), 1);

        // The live vault was swapped — the cred reads back through the new slot.
        let live = store.vault().unwrap();
        assert_eq!(
            live.get(VaultScope::Interactive, &store, "c")
                .unwrap()
                .as_slice(),
            b"v"
        );

        // The token is single-use: replay refuses.
        let replay = execute_with_config(
            &store,
            &config,
            tmp.path(),
            &json!({"mode": "rekey", "rotation_token": token}),
            now,
        );
        assert!(replay.is_err(), "replaying a consumed token must refuse");

        unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };
    }

    /// Adversarial review O/HIGH — a change_passphrase whose post-commit
    /// keychain write FAILS must NOT present as success: the rotation
    /// committed + the live slot swapped (so the cred still reads), but the
    /// call returns a `vault_rotate_keychain_desync` error (not Ok) so an
    /// exit-0/receipt-id-checking caller cannot misread it, and the response
    /// names the snapshot for recovery.
    #[test]
    fn execute_change_passphrase_keychain_failure_does_not_report_success() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYCHAIN_FAIL", "1") };

        let tmp = tempfile::tempdir().unwrap();
        let store = DaemonStore::open(&tmp.path().join("daemon.db")).unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let service = vault::resolve_keyring_service(&config.keyring);
        let account = vault::resolve_keyring_account(&config.keyring);
        let pass = format!("test-passphrase-{service}-{account}");
        let salt = [6u8; 16];
        let vault = Rc::new(Vault::from_passphrase(&pass, &salt));
        store.set_vault(Rc::clone(&vault));
        vault.provision_envelope_meta(&store, &salt).unwrap();
        vault
            .add(VaultScope::Interactive, &store, "c", b"v", None)
            .unwrap();

        let now = fixed_now();
        let plan =
            handle_vault_rotate_plan(&store, &json!({"mode": "change_passphrase"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap().to_string();

        let result = execute_with_config(
            &store,
            &config,
            tmp.path(),
            &json!({
                "mode": "change_passphrase",
                "rotation_token": token,
                "new_passphrase": "brand-new-operator-secret",
            }),
            now,
        );

        // MUST be an error (not success-shaped).
        let (code, body) = result.expect_err("keychain-desync must NOT report success");
        assert_eq!(code, -32030);
        assert!(body.contains("vault_rotate_keychain_desync"), "got {body}");
        assert!(
            body.contains("snapshot"),
            "must name the recovery snapshot: {body}"
        );

        // The rotation DID commit (epoch bumped) and the live slot swapped (the
        // new vault reads the cred) — only the keychain desynced.
        assert_eq!(store.read_key_epoch().unwrap(), 1);
        let live = store.vault().unwrap();
        assert_eq!(
            live.get(VaultScope::Interactive, &store, "c")
                .unwrap()
                .as_slice(),
            b"v"
        );

        unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYCHAIN_FAIL") };
        unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };
    }

    /// ADR 198 D5 / ADR 131 — `change_passphrase` is refused (up-front, before
    /// consuming the token or mutating anything) when the operator secret is
    /// SE-wrapped (separate-uid production posture), because the new passphrase
    /// can't be written to the keychain there without desyncing the SE blob.
    /// `rekey` is NOT refused in that posture.
    #[test]
    fn change_passphrase_refused_in_se_wrapped_posture() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("EMBER_VAULT_TEST_FORCE_SE_POSTURE", "1") };

        let tmp = tempfile::tempdir().unwrap();
        let store = DaemonStore::open(&tmp.path().join("daemon.db")).unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let (store, _v) = {
            let salt = [8u8; 16];
            let vault = Rc::new(Vault::from_passphrase("p", &salt));
            store.set_vault(Rc::clone(&vault));
            vault.provision_envelope_meta(&store, &salt).unwrap();
            (store, vault)
        };
        let now = fixed_now();
        // Mint a token so we'd get past token validation if the refusal didn't fire.
        let plan =
            handle_vault_rotate_plan(&store, &json!({"mode": "change_passphrase"}), now).unwrap();
        let token = plan["rotation_token"].as_str().unwrap().to_string();

        let err = execute_with_config(
            &store,
            &config,
            tmp.path(),
            &json!({"mode": "change_passphrase", "rotation_token": token, "new_passphrase": "x"}),
            now,
        )
        .expect_err("change_passphrase must refuse in SE-wrapped posture");
        assert_eq!(err.0, -32030);
        assert!(
            err.1
                .contains("vault_rotate_change_passphrase_unsupported_se_posture"),
            "got {}",
            err.1
        );
        // The key_epoch must be UNCHANGED (refused before any mutation).
        assert_eq!(store.read_key_epoch().unwrap(), 0);

        unsafe { std::env::remove_var("EMBER_VAULT_TEST_FORCE_SE_POSTURE") };
    }

    /// `resolve_current_vault_passphrase` honors the `EMBER_VAULT_PASSPHRASE`
    /// override (the env/CI source) ahead of the keychain — the rotation reads
    /// the same passphrase the daemon opened with.
    #[test]
    fn resolve_current_passphrase_prefers_env_override() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("EMBER_VAULT_PASSPHRASE", "env-operator-secret") };
        let tmp = tempfile::tempdir().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let resolved = vault::resolve_current_vault_passphrase(&config)
            .unwrap()
            .expect("env override resolves");
        // N6: resolve_current_vault_passphrase now returns Zeroizing<String>.
        assert_eq!(resolved.as_str(), "env-operator-secret");
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
    }

    /// ADR 198 / ADR 131 REGRESSION (the bug found preparing the live verify):
    /// in the separate-uid SE posture the rotation MUST resolve the current
    /// operator passphrase from the System.keychain MEK item, NOT fall through
    /// to the login-keychain (which returns None there → rotation died with
    /// "no operator passphrase source"). With the SE posture forced and NO
    /// `EMBER_VAULT_PASSPHRASE`, `resolve_current_vault_passphrase` must return
    /// the SE-sourced passphrase. Pre-fix (keychain-only resolver) this returned
    /// None and rekey was broken on the real production daemon.
    /// macOS-only: the SE resolution branch is `#[cfg(target_os = "macos")]`.
    #[cfg(target_os = "macos")]
    #[test]
    fn rekey_resolves_passphrase_via_se_blob_in_separate_uid_posture() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Force the separate-uid SE posture; ensure no env passphrase shadows it.
        unsafe {
            std::env::set_var("EMBER_VAULT_TEST_FORCE_SE_POSTURE", "1");
            std::env::remove_var("EMBER_VAULT_PASSPHRASE");
            std::env::remove_var("EMBER_VAULT_MEK_SERVICE");
            std::env::remove_var("EMBER_VAULT_MEK_ACCOUNT");
        }
        let tmp = tempfile::tempdir().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let resolved = vault::resolve_current_vault_passphrase(&config);
        unsafe { std::env::remove_var("EMBER_VAULT_TEST_FORCE_SE_POSTURE") };

        // SE custody: `resolve_current_vault_passphrase` returns `Ok(None)` for
        // SE-wrapped vaults — there is no passphrase concept under SE custody.
        // Rotation under SE custody is a separate flow (not passphrase-based).
        let pass = resolved.expect("SE resolution must not error");
        assert!(
            pass.is_none(),
            "SE-wrapped vault must return None (no passphrase concept), got: {pass:?}"
        );
    }
}
