pub mod audit;
pub mod binary;
pub mod device;
// The Touch ID / LocalAuthentication FFI now lives in `ember-presence` so
// `internal-automation` shares it. Re-exported here as `crate::biometric` to keep
// existing `use crate::biometric::{…}` call sites unchanged.
pub use ember_presence::biometric;
// META-ARCH-DCC-7-EMBER-BIND-ADMIN-VERB — `ember bind …` admin path
// for credential bindings. See `bind.rs` doc-comment.
pub mod bind;
pub mod broker;
pub mod catalog;
pub mod cluster;
pub mod construct;
pub mod grants;
// HEADLESS-PREFLIGHT-LAYER2-GAPS — Phase 1 substrate. The
// `commands.rs` file is a single 300K-line module rather than a
// `commands/` directory; the `headless` substrate lands as a
// top-level sibling module per the brief's
// "(or wherever sibling commands are declared)" clause.
//
// PREFLIGHT-LAYER2-HISTORICAL
pub mod claude_code_launcher;
pub mod codex_launcher;
pub mod delegation_prompt;
pub mod demo;
pub mod dev;
pub mod dev_install;
pub mod dev_install_slice_c;
pub mod dev_runtime;
pub mod dev_runtime_artifacts;
pub mod headless;
pub mod install;
pub mod install_paths;
pub mod install_pipeline;
pub mod kms;
pub mod launcher;
pub mod onboarding;
pub mod orchestrator;
pub mod operator_paths;
pub mod output;
pub mod preflight;
pub mod receipt;
pub mod recover;
pub mod sandbox;
pub mod session;
// `ember status` library support — F-code symptom diagnostic appendix
// invoked by `ember status --troubleshoot` per ADR 161 §Component 3.
pub mod status;
// META-DEV-PROD-PARITY-ATTESTATION-SURFACE — `ember status --session`
// operator attestation that the current shell session IS brokered
// (ADR 157 follow-up). Anchor: `dev_prod_parity_attestation_surface_landed`.
pub mod status_session;
pub mod trust;
pub mod up;
pub mod v030_survey;
pub mod vault_io;

/// Test-only Mutex for serializing tests that mutate the `EMBER_PERSONA`
/// env var (or any process-global env var read by `resolve_persona_*`
/// helpers across modules). Without serialization, cargo's parallel test
/// runner can interleave a `set_var` from one test with a `remove_var`
/// from another, producing test-order-dependent failures.
///
/// Tests acquire via:
/// ```ignore
/// let _g = crate::EMBER_PERSONA_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
/// ```
///
/// Why this lives in `lib.rs`: `bind.rs::tests` and
/// `launcher/claude_code.rs::tests` both mutate the same env var; the
/// Mutex must be the same instance for the serialization to hold across
/// modules in the same test binary.
#[cfg(test)]
pub(crate) static EMBER_PERSONA_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only Mutex for serializing tests that mutate the
/// `EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS` env var. Two tests in
/// `onboarding/claude_code.rs::tests` race on this var:
/// `autostart_liveness_timeout_default_is_10` (remove) and
/// `autostart_liveness_timeout_honors_env` (set). Same pattern as
/// `EMBER_PERSONA_TEST_LOCK`.
#[cfg(test)]
pub(crate) static EMBER_DAEMON_AUTOSTART_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

/// Test-only Mutex for serializing tests that mutate process-wide cwd or env
/// vars outside narrower domain locks. Cwd is a single process-global pointer,
/// so modules that set it to a temporary directory must share one lock or a
/// parallel test can capture a directory that another test deletes on drop.
#[cfg(test)]
pub(crate) static PROCESS_ENV_CWD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use ember_broker::secure_enclave::{
    EciesKeyLabel, SignKeyHandle, SignKeyLabel, WideningGesture, find_sign_key, se_sign_and_unwrap,
    se_sign_with_touch_id_reason,
};
#[cfg(all(test, target_os = "macos"))]
use ember_broker::secure_enclave::{new_stub_key, se_register_stub_key};

use core_types::ValidationError;
use zeroize::Zeroizing;

pub fn default_data_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("emberlink")
}

#[cfg(not(test))]
fn default_data_file() -> PathBuf {
    default_data_dir().join("local-state.enc")
}

/// Public entry-point for callers (and integration tests) that need the
/// current local-state content key without going through a full client
/// bootstrap. Delegates to `resolve_encryption_key` — see its doc for the
/// full resolution order.
///
/// N6-deeper: returns `Zeroizing<String>` so the symmetric content key
/// zeroizes on drop at every consumer site. Hold as `Zeroizing<String>`
/// end-to-end; pass `&str` (via deref) at AEAD/HKDF use sites.
pub fn local_state_content_key() -> Result<Zeroizing<String>, ValidationError> {
    resolve_encryption_key()
}

const ENCRYPTED_MAGIC: &[u8] = b"EMBER_ENC\x01";

// `DaemonRpcError` + the plain UDS JSON-RPC client moved to `ember-presence`
// (shared with internal-automation). Re-exported so `crate::DaemonRpcError` paths and
// the 5 sibling modules that import it keep compiling.
pub use ember_presence::DaemonRpcError;

fn operator_presence_token_slot()
-> &'static std::sync::Mutex<Option<ember_daemon::auth::presence_token::PresenceToken>> {
    static SLOT: std::sync::OnceLock<
        std::sync::Mutex<Option<ember_daemon::auth::presence_token::PresenceToken>>,
    > = std::sync::OnceLock::new();
    SLOT.get_or_init(|| std::sync::Mutex::new(None))
}

fn cached_operator_presence_token() -> Option<ember_daemon::auth::presence_token::PresenceToken> {
    operator_presence_token_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn cached_operator_presence_token_for_method(
    method: &str,
) -> Option<ember_daemon::auth::presence_token::PresenceToken> {
    cached_operator_presence_token()
        .filter(|token| presence_token_scope_allows_method(token.scope.as_str(), method))
}

fn set_cached_operator_presence_token(
    token: Option<ember_daemon::auth::presence_token::PresenceToken>,
) {
    *operator_presence_token_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = token;
}

fn attach_presence_token(
    params: &serde_json::Value,
    token: &ember_daemon::auth::presence_token::PresenceToken,
) -> serde_json::Value {
    match params {
        serde_json::Value::Object(map) => {
            let mut map = map.clone();
            map.insert(
                "_presence_token".to_string(),
                serde_json::to_value(token).expect("serialize presence token"),
            );
            serde_json::Value::Object(map)
        }
        serde_json::Value::Null => serde_json::json!({
            "_presence_token": token
        }),
        other => other.clone(),
    }
}

fn presence_token_scope_allows_method(scope: &str, method: &str) -> bool {
    match scope {
        "*" => true,
        "class:vault" => matches!(
            method,
            "vault_unlock"
                | "vault_add"
                | "vault_put"
                | "vault_list"
                | "vault_remove"
                | "vault_get"
                | "vault_migrate_acl"
        ),
        "class:session-runtime" => matches!(
            method,
            "register_session"
                | "use_credential"
                | "evaluate_tool_call"
                | "broker_issue"
                | "broker_revoke"
                | "broker_list"
                | "broker_resolve"
                | "broker_exec"
                | "broker.mint_gh_token"
                | "broker_register_pid_watcher"
        ),
        exact => exact == method,
    }
}

fn maybe_cache_presence_token_from_result(
    result: &serde_json::Value,
) -> Result<(), DaemonRpcError> {
    let Some(token_value) = result.get("presence_token").cloned() else {
        return Ok(());
    };
    let token = serde_json::from_value(token_value).map_err(|e| {
        DaemonRpcError::Protocol(format!("invalid daemon presence_token payload: {e}"))
    })?;
    set_cached_operator_presence_token(Some(token));
    Ok(())
}

fn authority_error_reason(message: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(message)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
}

pub(crate) fn is_daemon_socket_permission_denied(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied || matches!(err.raw_os_error(), Some(1 | 13))
}

fn shell_quote_path(path: &Path) -> String {
    let rendered = path.display().to_string();
    let safe = rendered
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '=' | ':'));
    if safe {
        rendered
    } else {
        format!("'{}'", rendered.replace('\'', "'\\''"))
    }
}

fn repo_build_ember_command_for_path(path: &Path) -> Option<String> {
    if path.file_name() != Some(std::ffi::OsStr::new("ember")) {
        return None;
    }
    if !path
        .components()
        .any(|component| component.as_os_str() == "target")
    {
        return None;
    }
    Some(shell_quote_path(path))
}

pub(crate) fn current_repo_build_ember_command() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    repo_build_ember_command_for_path(&path)
}

pub(crate) fn rewrite_daemon_guidance_with_ember_command(
    text: &str,
    ember_cmd: Option<&str>,
) -> String {
    let Some(ember_cmd) = ember_cmd else {
        return text.to_string();
    };
    if ember_cmd == "ember" {
        return text.to_string();
    }

    let status_cmd = format!("{ember_cmd} status");
    let daemon_install_cmd = format!("sudo {ember_cmd} daemon install");
    text.replace("`ember status`", &format!("`{status_cmd}`"))
        .replace("'ember status'", &format!("'{status_cmd}'"))
        .replace(
            "`sudo ember daemon install`",
            &format!("`{daemon_install_cmd}`"),
        )
        .replace(
            "'sudo ember daemon install'",
            &format!("'{daemon_install_cmd}'"),
        )
}

fn format_daemon_socket_io_error_with_ember_command(
    err: &std::io::Error,
    ember_cmd: Option<&str>,
) -> String {
    if is_daemon_socket_permission_denied(err) {
        return rewrite_daemon_guidance_with_ember_command(
            &format!(
                "daemon socket access is denied for this shell ({err}). \
                 If the operator is already in `ember-clients`, start a fresh login shell \
                 (Terminal.app > Shell > New Window) so the new group takes effect, then retry. \
                 Otherwise run `sudo dseditgroup -o edit -a $USER -t user ember-clients`, \
                 start a fresh login shell, and retry. \
                 If the managed socket or daemon install drifted, repair with \
                 `sudo ember daemon install`. \
                 Run `ember doctor` for a deeper diagnosis.",
            ),
            ember_cmd,
        );
    }

    rewrite_daemon_guidance_with_ember_command(
        &format!(
            "daemon socket error: {err}. \
             Run `ember doctor` for a deeper diagnosis or repair with \
             `sudo ember daemon install`.",
        ),
        ember_cmd,
    )
}

pub(crate) fn format_daemon_socket_io_error(err: &std::io::Error) -> String {
    let ember_cmd = current_repo_build_ember_command();
    format_daemon_socket_io_error_with_ember_command(err, ember_cmd.as_deref())
}

fn format_daemon_unavailable_with_ember_command(
    socket_path: &std::path::Path,
    source: &std::io::Error,
    ember_cmd: Option<&str>,
) -> String {
    if is_daemon_socket_permission_denied(source) {
        return rewrite_daemon_guidance_with_ember_command(
            &format!(
                "daemon socket access is denied at {}. Confirm the operator is in the `ember-clients` group, start a fresh login shell (or relogin), and retry. If the managed socket or daemon install drifted, repair with `sudo ember daemon install`.",
                socket_path.display()
            ),
            ember_cmd,
        );
    }

    rewrite_daemon_guidance_with_ember_command(
        &format!(
            "daemon unavailable at {}: {} — run `ember status` to inspect posture or repair with `sudo ember daemon install`",
            socket_path.display(),
            source
        ),
        ember_cmd,
    )
}

pub fn format_daemon_unavailable(socket_path: &std::path::Path, source: &std::io::Error) -> String {
    let ember_cmd = current_repo_build_ember_command();
    format_daemon_unavailable_with_ember_command(socket_path, source, ember_cmd.as_deref())
}

fn call_daemon_rpc_once(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    // Attach a cached operator presence token when one is in scope for this
    // method (the CLI's interactive token-reuse optimization — the token type
    // lives in ember-daemon, which is why this wrapper stays in the CLI), then
    // delegate to the shared plain client in ember-presence.
    let request_params = match cached_operator_presence_token_for_method(method) {
        Some(token) => attach_presence_token(params, &token),
        None => params.clone(),
    };
    ember_presence::daemon_rpc_once(socket_path, method, &request_params)
}

pub fn call_daemon_rpc(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    // ADR 216 — double-envelope vault unlock (outermost retry layer). When
    // the daemon's vault is locked (no MEK in memory), the first RPC attempt
    // fails with -32030 "live vault is locked". The CLI peels the outer SE
    // envelope and relays the opaque inner blob to the daemon, then retries
    // the original RPC through the full §1/§4 retry stack.
    match call_daemon_rpc_with_presence(socket_path, method, params) {
        Err(DaemonRpcError::Rpc { code, ref message })
            if should_attempt_de_unlock(code, message) =>
        {
            match attempt_de_unlock(socket_path) {
                Ok(()) => call_daemon_rpc_with_presence(socket_path, method, params),
                Err(_de_err) => Err(DaemonRpcError::Rpc {
                    code,
                    message: message.clone(),
                }),
            }
        }
        other => other,
    }
}

fn call_daemon_rpc_with_presence(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    // ADR 206 §1 — authority-widening ops are gated by the daemon's fail-closed
    // presence chokepoint: the first attempt with no proof returns the chokepoint
    // refusal (-32030, "presence-Device signature"). Acquire a fresh nonce-bound
    // presence-Device signature and retry once with `_presence_proof` attached.
    // The proof'd retry runs the full inner path, so it still gets the
    // vault-unlock retry if the legacy OperatorPresence block needs it.
    let first = match call_daemon_rpc_inner(socket_path, method, params) {
        Err(DaemonRpcError::Rpc { code, message })
            if should_acquire_presence_proof(method, code, &message) =>
        {
            // ADR 206 §1 (Phase 3) — ONE-TAP widening. For a covered minting
            // widening op in an interactive SE-capable context, acquire the §1
            // proof AND the §4 KEK_s in a SINGLE batched gesture (one Touch ID
            // tap) and submit BOTH in the same retry. The daemon's transient-KEK
            // path (Phase 2) installs KEK_s for the op and evicts it after — no
            // separate unlock round-trip, no wasted re-sign. A non-covered /
            // non-interactive op falls back to the proof-only retry below (which
            // may then hit the §4 implicit-unlock retry as before).
            #[cfg(target_os = "macos")]
            if should_acquire_widening_gesture(method) {
                match acquire_widening_gesture(socket_path, method, params) {
                    Ok((proof, scope_kek_hex)) => {
                        let widened =
                            attach_presence_proof_and_scope_kek(params, &proof, &scope_kek_hex);
                        return call_daemon_rpc_inner(socket_path, method, &widened);
                    }
                    // The batched gesture was declined / unavailable — fall back
                    // to the proof-only path so the operator still gets the old
                    // two-step behavior (and a clean fail-closed if that also
                    // cannot satisfy a tap).
                    Err(_gesture_err) => {}
                }
            }
            let proof = acquire_presence_proof(socket_path, method, params)?;
            let proofed = attach_presence_proof(params, &proof);
            call_daemon_rpc_inner(socket_path, method, &proofed)
        }
        other => other,
    };

    // ADR 206 §4 — implicit just-in-time vault unlock. When the daemon's
    // fail-closed §4 gate refuses an authority op because the presence-as-
    // decryption unlock window is LOCKED (`-32001`, reason `"locked"`), tap the
    // operator's UserPresence Secure Enclave key to unwrap the scope KEK (the
    // real §4 `se_unwrap`, the daemon cannot forge it), then retry the original
    // RPC ONCE. The operator no longer has to pre-run `ember vault se-unlock`.
    //
    // This composes with the §1 proof retry above: the §4 gate is checked
    // AFTER scope/proof resolution, so a widening op that also needs a fresh
    // proof has already attached one by the time we land here, and we never
    // double-fire (the unlock attempt is bounded to ONE).
    //
    // It is strictly CLI-side convenience over the UNCHANGED secure daemon
    // gate: the only way the window opens is `vault.se_unlock_complete`
    // installing an operator-session-unwrapped KEK_s. If the tap is declined
    // or this context cannot satisfy a tap (headless / non-interactive / no
    // real Secure Enclave), the original `-32001` propagates UNCHANGED — fail
    // closed, never proceed without a real tap, never loop.
    match &first {
        Err(DaemonRpcError::Rpc { code, message })
            if should_attempt_se_unlock(method, *code, message) =>
        {
            match attempt_se_unlock_window(socket_path) {
                // Tap succeeded and the daemon installed the scope KEK — retry
                // the ORIGINAL call once. Re-run the full inner+proof path so a
                // widening op still attaches a proof if it needs one.
                Ok(()) => match call_daemon_rpc_inner(socket_path, method, params) {
                    Err(DaemonRpcError::Rpc { code, message })
                        if should_acquire_presence_proof(method, code, &message) =>
                    {
                        let proof = acquire_presence_proof(socket_path, method, params)?;
                        let proofed = attach_presence_proof(params, &proof);
                        call_daemon_rpc_inner(socket_path, method, &proofed)
                    }
                    other => other,
                },
                // The tap was declined or unavailable — fail closed by
                // propagating the daemon's original locked-window error, not the
                // unlock-machinery error. The caller's guidance still points at
                // `ember vault se-unlock`.
                Err(_unlock_err) => first,
            }
        }
        _ => first,
    }
}

/// True when a daemon error is the ADR 206 §4 fail-closed gate refusing an
/// authority op because the presence-as-decryption unlock window is LOCKED, AND
/// this context can actually satisfy a Secure Enclave presence tap.
///
/// The §4-window-locked signal is precisely `-32001` with the authority-error
/// body `{"error":"authority_class_not_met","reason":"locked"}` — emitted ONLY
/// by the daemon's §4 dispatch gate (`authority_error("locked")`), so it is
/// cleanly distinguishable from the widening chokepoint (`-32030`,
/// "presence-Device signature") and from every other `-32001` reason
/// (`missing` / `expired` / `uid-mismatch` / `sig-invalid` / `scope-mismatch` /
/// `identity-missing`), none of which a §4 tap would resolve.
///
/// The capability gate (`can_attempt_se_unlock`) keeps this from looping in
/// headless / non-interactive / no-real-Enclave contexts: there we propagate
/// the locked error with its existing `ember vault se-unlock` guidance instead.
fn should_attempt_se_unlock(method: &str, code: i32, message: &str) -> bool {
    // Never recurse on the §4 unlock or ADR 216 double-envelope RPCs.
    if matches!(
        method,
        "vault.se_unlock_begin"
            | "vault/se_unlock_begin"
            | "vault_se_unlock_begin"
            | "vault.se_unlock_complete"
            | "vault/se_unlock_complete"
            | "vault_se_unlock_complete"
            | "vault.se_provision"
            | "vault/se_provision"
            | "vault_se_provision"
            | "vault.de_unlock_begin"
            | "vault.de_unlock_complete"
            | "vault.de_provision_begin"
            | "vault.de_provision_outer"
    ) {
        return false;
    }
    if code != -32001 {
        return false;
    }
    if authority_error_reason(message).as_deref() != Some("locked") {
        return false;
    }
    can_attempt_se_unlock()
}

/// Whether this process can satisfy an interactive Secure Enclave presence tap
/// — the precondition for the §4 implicit-unlock retry. Requires macOS, a real
/// Secure Enclave backend (a signed build with `se-real`; the software stub is
/// NOT a presence factor), and an interactive context where the macOS Touch ID /
/// passcode dialog can be answered. Headless / piped / background invocations
/// (e.g. autopilot workers) must NOT auto-tap — they fail closed on the locked
/// window with the explicit `ember vault se-unlock` guidance.
/// Test-only override for the §4 implicit-unlock capability gate. In production
/// the gate consults the real Secure Enclave backend + terminal state; tests set
/// this to exercise BOTH the interactive/capable branch (auto-unlock + retry) and
/// the non-interactive branch (fail closed, no tap) without hardware or a TTY.
#[cfg(test)]
pub(crate) static SE_UNLOCK_CAPABLE_TEST_OVERRIDE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "macos")]
fn can_attempt_se_unlock() -> bool {
    #[cfg(test)]
    {
        // Tests drive the branch explicitly: the SE backend is a stub
        // (`se_backend_is_real()` is false) and stdin is rarely a TTY, so the
        // real production checks would always be false under test. The override
        // lets each test choose interactive-capable vs not.
        return SE_UNLOCK_CAPABLE_TEST_OVERRIDE.load(std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(not(test))]
    {
        use std::io::IsTerminal as _;
        // Require a real Secure Enclave (signed build, `se-real`; the software
        // stub is NOT a presence factor) AND an interactive context where the
        // macOS Touch ID / passcode dialog can actually be answered. Headless /
        // piped / background invocations (autopilot workers) fail closed on the
        // locked window with the explicit `ember vault se-unlock` guidance —
        // they must NOT auto-tap or loop.
        ember_broker::secure_enclave::se_backend_is_real()
            && std::io::stdin().is_terminal()
            && std::io::stderr().is_terminal()
    }
}

#[cfg(not(target_os = "macos"))]
fn can_attempt_se_unlock() -> bool {
    // Secure Enclave is macOS-only; non-macOS builds have no presence-tap path
    // for §4 unlock yet (YubiKey PIV is the planned cross-platform lane). Fail
    // closed on the locked window with the existing guidance.
    false
}

/// The presence-token-caching RPC path (everything `call_daemon_rpc` does except
/// the outer ADR 206 presence-proof acquisition layer AND the §4 implicit-unlock
/// retry layer, both of which wrap this).
///
/// ADR 206 slice 4 C retired the forgeable native/managed vault-unlock ceremony
/// (`perform_vault_unlock_ceremony`). This layer itself does NOT auto-unlock: a
/// locked §4 window surfaces as a `-32001` "locked" authority error here. The
/// implicit just-in-time unlock — riding the REAL §4 `se_unwrap` tap (the
/// daemon, separate-uid, cannot forge it) — lives in the `call_daemon_rpc`
/// wrapper, so probes that call this inner path (or
/// `call_daemon_method_without_unlock_retry`) still see the raw locked posture.
fn call_daemon_rpc_inner(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    let value = call_daemon_rpc_once(socket_path, method, params)?;
    maybe_cache_presence_token_from_result(&value)?;
    if matches!(method, "vault_lock" | "close_session") {
        set_cached_operator_presence_token(None);
    }
    Ok(value)
}

/// The default Secure Enclave label for the operator presence Device — matches
/// `ember device enroll --secure-enclave`'s `--se-label` default. Widening-proof
/// signing uses the same key the enrollment bound as the presence Device.
const OPERATOR_PRESENCE_SE_LABEL: &str = "ember-operator-presence";

/// True when a daemon error is the ADR 206 presence chokepoint refusing a
/// widening op for a *missing* proof — the signal to acquire one and retry once.
/// (A supplied-but-invalid proof produces a different chokepoint message and is
/// not retried; re-signing the same way would not help.)
fn should_acquire_presence_proof(method: &str, code: i32, message: &str) -> bool {
    // Never recurse on the nonce-acquisition RPC itself (it is not widening, but
    // guard anyway).
    if matches!(method, "presence/request_nonce" | "presence_request_nonce") {
        return false;
    }
    code == -32030 && message.contains("presence-Device signature")
}

/// Attach an acquired `_presence_proof` object onto a params value (clone).
fn attach_presence_proof(
    params: &serde_json::Value,
    proof: &serde_json::Value,
) -> serde_json::Value {
    let mut p = params.clone();
    if let serde_json::Value::Object(map) = &mut p {
        map.insert("_presence_proof".to_string(), proof.clone());
    }
    p
}

/// ADR 206 §1 (Phase 3) — attach BOTH the §1 `_presence_proof` and the §4
/// `scope_kek` (hex of the operator-session-unwrapped `KEK_s`) onto a params
/// value (clone), for the one-tap batched widening submission. The daemon's
/// transient-KEK path keys off the presence of `scope_kek`.
#[cfg(target_os = "macos")]
fn attach_presence_proof_and_scope_kek(
    params: &serde_json::Value,
    proof: &serde_json::Value,
    scope_kek_hex: &str,
) -> serde_json::Value {
    let mut p = attach_presence_proof(params, proof);
    if let serde_json::Value::Object(map) = &mut p {
        map.insert(
            "scope_kek".to_string(),
            serde_json::Value::String(scope_kek_hex.to_string()),
        );
    }
    p
}

/// A process-unique op id for a presence-intent nonce request. The daemon binds
/// the nonce to this id; the chokepoint re-checks it at consume.
fn new_presence_op_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("op-{}-{}-{}", std::process::id(), nanos, n)
}

/// Acquire a nonce-bound presence-Device signature for a widening `method`
/// (ADR 206 §1 — the operator-session signing driver). Requests a single-use
/// nonce from the daemon, signs the daemon-computed canonical intent bytes on the
/// enrolled presence Device's Secure Enclave key (one Touch ID tap, signed RAW —
/// the domain separator lives inside the canonical bytes), and returns the
/// `_presence_proof` object `{op_id, nonce, signature}` for the widening call.
/// Resolve the enrolled presence-Device Secure Enclave key. On a signed build
/// this is the real Touch-ID-gated Enclave key; under tests (where `se-real` may
/// be active and the lookup would hit the real keychain) it falls back to a stub
/// handle so the acquisition wiring is exercisable without hardware — mirroring
/// `load_or_create_native_vault_unlock_key`'s test affordance.
#[cfg(target_os = "macos")]
fn presence_device_se_key() -> Result<SignKeyHandle, DaemonRpcError> {
    // The operator presence Device key signs §1 proofs — sign-only role
    // (ADR 206 AC-3), carried in the type so it can never be used as a §4
    // ECIES recipient.
    #[cfg(test)]
    {
        if let Ok(handle) =
            find_sign_key(&SignKeyLabel::from_provisioned(OPERATOR_PRESENCE_SE_LABEL))
        {
            return Ok(handle);
        }
        let handle = new_stub_key(OPERATOR_PRESENCE_SE_LABEL);
        se_register_stub_key(OPERATOR_PRESENCE_SE_LABEL, &handle);
        Ok(SignKeyHandle::from_provisioned(handle))
    }
    #[cfg(not(test))]
    find_sign_key(&SignKeyLabel::from_provisioned(OPERATOR_PRESENCE_SE_LABEL)).map_err(|e| {
        DaemonRpcError::Protocol(format!(
            "no operator presence Device key (label '{OPERATOR_PRESENCE_SE_LABEL}'): {e}. \
             Enroll one with `ember device enroll --secure-enclave`."
        ))
    })
}

fn format_touch_id_key_use_error(context: &str, err: impl std::fmt::Display) -> String {
    let err = err.to_string();
    let mut message = format!("{context} (Touch ID declined or key unavailable): {err}");
    if touch_id_biometry_lockout(&err) {
        message.push_str(
            ". Touch ID is locked out; unlock this Mac with your account password, then rerun the command.",
        );
    }
    message
}

fn touch_id_biometry_lockout(err: &str) -> bool {
    let err = err.to_ascii_lowercase();
    err.contains("biometry") && err.contains("locked out")
}

#[cfg(target_os = "macos")]
fn acquire_presence_proof(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    let key = presence_device_se_key()?;

    // ADR 206 §1.3 / approval-laundering Finding 1 — bind the OBJECT. Compute the
    // canonical digest of the op's authority-relevant params (the SAME helper the
    // daemon recomputes at consume) and commit it in the nonce request.
    let params_digest = ember_daemon::auth::presence_gate::presence_params_digest(params)
        .map_err(|e| DaemonRpcError::Protocol(format!("presence: canonicalize params: {e}")))?;

    let op_id = new_presence_op_id();
    let nonce_resp = call_daemon_rpc_once(
        socket_path,
        "presence/request_nonce",
        &serde_json::json!({ "op_id": op_id, "method": method, "params_digest": params_digest }),
    )?;
    let nonce = nonce_resp
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DaemonRpcError::Protocol("request_nonce: missing nonce".to_string()))?
        .to_string();

    // F2 — re-derive the canonical intent bytes LOCALLY from the primitive fields
    // we hold (method, op_id, nonce, daemon_fingerprint, params_digest) and sign
    // THOSE, never the daemon-echoed blob. The daemon's `intent_bytes_hex` is
    // checked for agreement and the gesture refused on divergence — a compromised
    // daemon cannot make the SE sign bytes that differ from what we rendered.
    let local_intent =
        rederive_presence_intent_or_refuse(&nonce_resp, method, &op_id, &nonce, &params_digest)?;

    let reason = presence_touch_id_reason(method, params, &params_digest);
    let sig_der = se_sign_with_touch_id_reason(&key, &local_intent, &reason).map_err(|e| {
        DaemonRpcError::Protocol(format_touch_id_key_use_error(
            &format!("presence-Device signing failed for '{method}'"),
            e,
        ))
    })?;
    let signature = format!("p256sig:{}", hex::encode(sig_der));

    Ok(serde_json::json!({ "op_id": op_id, "nonce": nonce, "signature": signature }))
}

/// Non-macOS builds have no Secure Enclave presence Device driver yet (YubiKey
/// PIV is the planned cross-platform path). Widening ops fail closed with a clear
/// message rather than silently bypassing the daemon's presence chokepoint.
#[cfg(not(target_os = "macos"))]
fn acquire_presence_proof(
    _socket_path: &std::path::Path,
    method: &str,
    _params: &serde_json::Value,
) -> Result<serde_json::Value, DaemonRpcError> {
    Err(DaemonRpcError::Protocol(format!(
        "'{method}' requires an operator presence-Device signature, but this build has \
         no presence-Device signer (Secure Enclave is macOS-only; YubiKey PIV is not yet wired)."
    )))
}

/// ADR 206 H1 mitigation (Finding 2) — re-derive the canonical presence intent
/// bytes from the primitive fields the operator-session signer holds, and refuse
/// if the daemon-echoed `intent_bytes_hex` diverges. Returns the LOCALLY-derived
/// bytes (the ones to sign), so a compromised daemon can never make the Secure
/// Enclave sign a blob that differs from the rendered intent. The daemon's
/// `daemon_fingerprint` is read from the response (its own identity-root
/// fingerprint, which the verifier reconstructs the same way — it is not a
/// wire-claimed authority, only an input to the deterministic byte derivation).
#[cfg(target_os = "macos")]
fn rederive_presence_intent_or_refuse(
    nonce_resp: &serde_json::Value,
    method: &str,
    op_id: &str,
    nonce: &str,
    params_digest: &str,
) -> Result<Vec<u8>, DaemonRpcError> {
    let daemon_fingerprint = nonce_resp
        .get("daemon_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DaemonRpcError::Protocol("request_nonce: missing daemon_fingerprint".to_string())
        })?;
    let local = ember_daemon::auth::presence_gate::canonical_presence_intent_bytes(
        method,
        op_id,
        nonce,
        daemon_fingerprint,
        params_digest,
    );

    // Cross-check the daemon's echoed bytes against our independent derivation.
    let echoed_hex = nonce_resp
        .get("intent_bytes_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DaemonRpcError::Protocol("request_nonce: missing intent_bytes_hex".to_string())
        })?;
    let echoed = hex::decode(echoed_hex).map_err(|e| {
        DaemonRpcError::Protocol(format!("request_nonce: bad intent_bytes_hex: {e}"))
    })?;
    if echoed != local {
        return Err(DaemonRpcError::Protocol(format!(
            "presence: daemon-supplied intent bytes diverge from the locally re-derived \
             canonical intent for '{method}' — refusing to sign (ADR 206 H1). The daemon \
             may be misrepresenting the operation."
        )));
    }
    Ok(local)
}

/// Build the Touch ID reason string for a widening op. The reason is rendered
/// through the daemon-owned allowlist intent renderer so the human sees the
/// OBJECT they are authorizing (entry name, persona, scope, …) — never secret
/// param VALUES (ADR 206 §1.5 consent-legible; FINDING-A secret-leak fix).
///
/// `digest` is the full params digest actually being signed. We always append a
/// short tag of it so the human-visible reason is uniquely tied to what is
/// signed: the reason deliberately surfaces only non-secret allowlist fields, so
/// the tag is what closes the consent-legibility gap an adversarial review
/// flagged (render ⊊ signed) — two distinct param sets still produce DIFFERENT
/// reasons via the tag.
#[cfg(target_os = "macos")]
fn presence_touch_id_reason(method: &str, params: &serde_json::Value, digest: &str) -> String {
    // SECURITY (FINDING-A, 2026-06-07): build the operator-facing Touch ID
    // `localizedReason` from the daemon-owned ALLOWLIST renderer — never by
    // serializing the raw request params.
    //
    // The previous implementation serialized the whole params object into the
    // reason and stripped only a 3-field denylist (`_presence_proof` /
    // `scope_kek` / `_presence_token`). A denylist is structurally unsound for a
    // secret-bearing surface: any field NOT on the list leaks. `vault_add` /
    // `vault_put` carry the raw credential in `value` / `value_bytes`, so the
    // macOS prompt rendered e.g. `value_bytes=[...]` (decoding to an
    // `sk-ant-...` token) — and macOS persists `localizedReason` to the unified
    // log, making it a secret-at-rest leak, not merely shoulder-surfing.
    //
    // `unlock_prompt_intent` is the single daemon-owned operator-intent renderer
    // (ADR 206; "the daemon owns the operator intent once, adapters render it").
    // It is allowlist-by-construction: it surfaces only specific non-secret
    // fields (entry name, persona, scope, grant id, …) and, for unknown methods,
    // only the method name — param VALUES never reach the reason.
    let intent = ember_daemon::infra::prompt_intent::unlock_prompt_intent(method, params);
    // The digest is a blake3 hash of the (signed) params — safe to show, and it
    // lets the operator correlate the prompt with the authorized intent.
    let tag: String = digest.chars().take(15).collect(); // e.g. "b3:0a1b2c3d"
    let mut reason = intent.native_os_reason();
    for line in &intent.detail_lines {
        // detail_lines are allowlist-built (name/persona/scope/…), never values.
        reason.push_str(" · ");
        reason.push_str(line);
    }
    format!("{reason} [{tag}]")
}

#[cfg(all(test, target_os = "macos"))]
mod presence_touch_id_reason_tests {
    use super::*;

    // FINDING-A regression: the macOS Touch ID `localizedReason` must NEVER
    // contain a secret param VALUE. The reason is built from the daemon-owned
    // allowlist renderer, so raw values (vault `value` / `value_bytes`) cannot
    // reach it — proven here by feeding a recognizable credential and asserting
    // it is absent in both string and decimal-byte-array forms, while the
    // non-secret object identity (entry name) + digest tag remain legible.
    #[test]
    fn vault_add_reason_never_leaks_the_credential_value() {
        let secret = "sk-ant-oat01-THIS-MUST-NOT-LEAK";
        let params = serde_json::json!({
            "name": "anthropic/oauth-token",
            "value": secret,
            "value_bytes": secret.bytes().collect::<Vec<u8>>(),
        });
        let reason = presence_touch_id_reason("vault_add", &params, "b3:deadbeefcafef00d");

        assert!(
            !reason.contains(secret),
            "reason leaked the credential string: {reason}"
        );
        let byte_csv = secret
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            !reason.contains(&byte_csv),
            "reason leaked the value_bytes array: {reason}"
        );
        // Still consent-legible: safe verb + entry name + digest tag.
        assert!(
            reason.contains("Vault entry") && reason.contains("anthropic/oauth-token"),
            "reason should name the entry being stored: {reason}"
        );
        assert!(
            reason.contains("b3:deadbeef"),
            "digest tag missing: {reason}"
        );
    }

    // The allowlist holds even for a method the renderer does not special-case:
    // the fallback arm surfaces only the method name, never param values.
    #[test]
    fn unknown_method_reason_never_serializes_param_values() {
        let params = serde_json::json!({"api_token": "hunter2-DO-NOT-LEAK", "n": 1});
        let reason = presence_touch_id_reason(
            "some_future_widening_method",
            &params,
            "b3:00112233aabbccdd",
        );
        assert!(
            !reason.contains("hunter2-DO-NOT-LEAK"),
            "unknown-method reason leaked a param value: {reason}"
        );
        assert!(
            reason.contains("b3:00112233"),
            "digest tag missing: {reason}"
        );
    }
}

/// ADR 206 §1 — the covered minting widening ops that seal under `KEK_s` and
/// can ride the daemon's transient-KEK one-tap path (mirrors the daemon's
/// `widening_transient_kek_applies`). For these, the CLI acquires the §1 proof
/// AND the §4 `KEK_s` in ONE batched Secure Enclave gesture and submits both in
/// the SAME request, so the operator taps ONCE instead of the old
/// proof-tap → unlock-tap → wasted-resign sequence.
fn widening_transient_kek_applies(method: &str) -> bool {
    matches!(
        method,
        "create_persona"
            | "create_grant"
            | "create_composite_grant"
            | "create_standing_grant"
            | "propose_grant"
            | "save_delegation_template"
            | "resolve_approval"
            | "build_init_first_grant_receipt"
    )
}

/// ADR 206 §1 + §4 — the **unified widening gesture** (Phase 3): mint the §1
/// nonce AND fetch this device's wrapped `KEK_s`, then acquire BOTH the §1
/// authorization signature and the §4 unwrapped `KEK_s` under ONE Touch ID tap
/// via [`se_sign_and_unwrap`]. Returns `(_presence_proof, scope_kek_hex)` to
/// submit together in a SINGLE widening request — the daemon's transient-KEK
/// path (Phase 2) verifies the proof, installs `KEK_s` transiently, runs the op,
/// and evicts. No separate unlock round-trip, no wasted re-sign.
///
/// Fail-closed: a declined tap (or a decrypt failure) returns `Err` and the
/// caller propagates the daemon's original refusal — the op never proceeds
/// without a real gesture.
#[cfg(target_os = "macos")]
fn acquire_widening_gesture(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<(serde_json::Value, String), DaemonRpcError> {
    use ember_broker::secure_enclave as se;

    // (a) §1 sign key (sign-only role) + §4 ECIES recipient key (this device's).
    let sign_key = presence_device_se_key()?;
    let ecies_label = format!("{OPERATOR_PRESENCE_SE_LABEL}-ecies");
    let ecies_key = presence_ecies_se_key(&ecies_label)?;
    let ecies_pub = se::se_pubkey_bytes(&ecies_key)
        .map_err(|e| DaemonRpcError::Protocol(format!("widening gesture: ECIES pubkey: {e}")))?;
    let ecies_key_id = format!("key-operator-ecies-{}", hex::encode(&ecies_pub));

    // ADR 206 §1.3 / Finding 1 — bind the OBJECT: commit the canonical params
    // digest in the nonce request (recomputed by the daemon at consume).
    let params_digest = ember_daemon::auth::presence_gate::presence_params_digest(params)
        .map_err(|e| DaemonRpcError::Protocol(format!("presence: canonicalize params: {e}")))?;

    // (b) Mint the §1 nonce → re-derive the canonical intent bytes LOCALLY (F2).
    let op_id = new_presence_op_id();
    let nonce_resp = call_daemon_rpc_once(
        socket_path,
        "presence/request_nonce",
        &serde_json::json!({ "op_id": op_id, "method": method, "params_digest": params_digest }),
    )?;
    let nonce = nonce_resp
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DaemonRpcError::Protocol("request_nonce: missing nonce".to_string()))?
        .to_string();
    // F2 — sign the locally re-derived bytes, refusing if the daemon's echoed
    // bytes diverge from our independent derivation.
    let intent_bytes =
        rederive_presence_intent_or_refuse(&nonce_resp, method, &op_id, &nonce, &params_digest)?;

    // (c) Fetch THIS device's wrapped scope KEK (`vault.se_unlock_begin`).
    let begin = call_daemon_rpc_once(
        socket_path,
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
            DaemonRpcError::Protocol(format!(
                "widening gesture: no wrapped scope KEK registered for this device \
                 (ecies_key_id={ecies_key_id}). Run `ember vault se-provision` first."
            ))
        })?;
    let wrapped = hex::decode(wrapped_hex).map_err(|e| {
        DaemonRpcError::Protocol(format!("widening gesture: bad wrapped_kek hex: {e}"))
    })?;

    // (d) ONE tap: §1 sign (sign key) + §4 unwrap (ECIES key) under one presence
    // evaluation. The role separation is carried in the types.
    eprintln!("Touch ID required: authorizing {method} and opening its scope (ADR 206 §1)…");
    let ecies_role = EciesKeyLabel::from_provisioned(ecies_label);
    let reason = format!(
        "{} and open its scope",
        presence_touch_id_reason(method, params, &params_digest)
    );
    let (sig_der, kek) = se_sign_and_unwrap(
        &sign_key,
        &ecies_role,
        WideningGesture::new(&intent_bytes, &wrapped),
        &reason,
    )
    .map_err(|e| {
        DaemonRpcError::Protocol(format_touch_id_key_use_error(
            &format!("widening gesture for '{method}' failed"),
            e,
        ))
    })?;
    if kek.len() != 32 {
        return Err(DaemonRpcError::Protocol(format!(
            "widening gesture: unwrapped scope KEK is {} bytes, expected 32",
            kek.len()
        )));
    }
    let signature = format!("p256sig:{}", hex::encode(sig_der));
    let scope_kek_hex = hex::encode(&*kek); // `kek` is Zeroizing — dropped on scope exit

    let proof = serde_json::json!({ "op_id": op_id, "nonce": nonce, "signature": signature });
    Ok((proof, scope_kek_hex))
}

/// Whether the CLI should take the ADR 206 §1 ONE-TAP batched widening path for
/// `method` instead of the old two-tap proof-then-unlock sequence: the op must
/// be a covered transient-KEK widening op AND this context can actually satisfy
/// an interactive Secure Enclave tap (macOS + real SE backend + TTY). A
/// non-interactive context (autopilot worker / piped) keeps the old behavior
/// and ultimately fails closed on the locked window.
fn should_acquire_widening_gesture(method: &str) -> bool {
    widening_transient_kek_applies(method) && can_attempt_se_unlock()
}

/// Resolve THIS device's UserPresence ECIES Secure Enclave key (the §4 unwrap
/// recipient) by label. On a signed build this is the real Touch-ID-gated
/// Enclave key; under tests (where `se-real` may be active and the real
/// keychain lookup would miss) it falls back to a registered stub handle so the
/// implicit-unlock wiring is exercisable without hardware — mirroring
/// `presence_device_se_key`'s test affordance for the §1 signing key.
#[cfg(target_os = "macos")]
fn presence_ecies_se_key(
    ecies_label: &str,
) -> Result<ember_broker::secure_enclave::SeKeyHandle, DaemonRpcError> {
    use ember_broker::secure_enclave as se;
    #[cfg(test)]
    {
        // Prefer the real keychain lookup; if it misses (the common test case,
        // where `se-real` is active but no hardware key is enrolled), fall back
        // to the stub key the test registered under this label so the unwrap
        // recovers the exact KEK the test wrapped to it.
        if let Ok(handle) = se::find_secure_enclave_key(ecies_label) {
            return Ok(handle);
        }
        if let Some(handle) = se::stub_key_handle(ecies_label) {
            return Ok(handle);
        }
        let handle = new_stub_key(ecies_label);
        se_register_stub_key(ecies_label, &handle);
        return Ok(handle);
    }
    #[cfg(not(test))]
    se::find_secure_enclave_key(ecies_label).map_err(|e| {
        DaemonRpcError::Protocol(format!(
            "ADR 206 §4 implicit unlock: ECIES SE key '{ecies_label}' not found \
             (run `ember vault se-provision` first): {e}"
        ))
    })
}

/// ADR 206 §4 — perform the presence-as-decryption unlock from the operator
/// session: ask the daemon for THIS device's wrapped scope KEK
/// (`vault.se_unlock_begin`), `se_unwrap` it on the UserPresence Secure Enclave
/// key (THE TAP — the daemon, separate-uid, cannot touch this key), and hand the
/// unwrapped KEK back (`vault.se_unlock_complete`) so the daemon opens the §4
/// window. This is the SAME flow `ember vault se-unlock` runs; here it fires
/// implicitly when an authority op hits a locked window.
///
/// SECURITY INVARIANTS:
/// - The only way the window opens is a real `se_unwrap` (the tap). If the
///   operator declines the tap, `se_unwrap` errors and this returns `Err` —
///   the caller propagates the daemon's original locked-window error (fail
///   closed; the op never proceeds without a real tap).
/// - The unwrapped KEK is best-effort scrubbed after submission.
/// - Uses `call_daemon_rpc_once` for its own RPCs so the implicit-unlock layer
///   never recurses into itself.
#[cfg(target_os = "macos")]
fn attempt_se_unlock_window(socket_path: &std::path::Path) -> Result<(), DaemonRpcError> {
    use ember_broker::secure_enclave as se;

    // Identify THIS device's ECIES recipient key (default presence label; matches
    // `ember device enroll --secure-enclave` / `vault se-unlock`).
    let ecies_label = format!("{OPERATOR_PRESENCE_SE_LABEL}-ecies");
    let ecies_key = presence_ecies_se_key(&ecies_label)?;
    let ecies_pub = se::se_pubkey_bytes(&ecies_key).map_err(|e| {
        DaemonRpcError::Protocol(format!("ADR 206 §4 implicit unlock: ECIES pubkey: {e}"))
    })?;
    let ecies_key_id = format!("key-operator-ecies-{}", hex::encode(&ecies_pub));

    let begin = call_daemon_rpc_once(
        socket_path,
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
            DaemonRpcError::Protocol(format!(
                "ADR 206 §4 implicit unlock: no wrapped scope KEK registered for this device \
                 (ecies_key_id={ecies_key_id}). Run `ember vault se-provision` first."
            ))
        })?;
    let wrapped = hex::decode(wrapped_hex).map_err(|e| {
        DaemonRpcError::Protocol(format!(
            "ADR 206 §4 implicit unlock: bad wrapped_kek hex: {e}"
        ))
    })?;

    // THE TAP — UserPresence-gated SE ECDH decrypt. A decline errors here and we
    // fail closed (the caller propagates the locked-window error unchanged).
    eprintln!("Touch ID required: unlocking authority custody (ADR 206 §4)…");
    let ecies_role = se::EciesKeyLabel::from_provisioned(ecies_label);
    let mut kek = se::se_unwrap(&ecies_role, &wrapped).map_err(|e| {
        DaemonRpcError::Protocol(format_touch_id_key_use_error(
            "ADR 206 §4 implicit unlock: se_unwrap failed",
            e,
        ))
    })?;
    if kek.len() != 32 {
        kek.iter_mut().for_each(|b| *b = 0);
        return Err(DaemonRpcError::Protocol(format!(
            "ADR 206 §4 implicit unlock: unwrapped scope KEK is {} bytes, expected 32",
            kek.len()
        )));
    }

    let complete = call_daemon_rpc_once(
        socket_path,
        "vault.se_unlock_complete",
        &serde_json::json!({ "scope_kek": hex::encode(&kek) }),
    );
    kek.iter_mut().for_each(|b| *b = 0); // best-effort scrub
    complete.map(|_| ())
}

/// Non-macOS builds cannot perform the Secure Enclave presence tap; the §4
/// implicit-unlock retry never reaches here (`can_attempt_se_unlock()` is false
/// off macOS), but the symbol must exist so `call_daemon_rpc` compiles.
#[cfg(not(target_os = "macos"))]
fn attempt_se_unlock_window(_socket_path: &std::path::Path) -> Result<(), DaemonRpcError> {
    Err(DaemonRpcError::Protocol(
        "ADR 206 §4 implicit unlock requires a Secure Enclave (macOS-only).".to_string(),
    ))
}

/// ADR 216 — double-envelope vault unlock relay. When the daemon's vault is
/// locked (no MEK in memory), the CLI peels the outer SE ECIES envelope and
/// relays the opaque inner blob (DWK-wrapped MEK) to the daemon. Raw MEK
/// never enters uid=501 address space.
///
/// If the vault has never been provisioned (clean boot), this function runs
/// the provisioning flow first: daemon generates the raw MEK + DWK-wraps it,
/// CLI SE-wraps the inner blob, daemon stores the outer blob.
#[cfg(target_os = "macos")]
fn attempt_de_unlock(socket_path: &std::path::Path) -> Result<(), DaemonRpcError> {
    use ember_broker::secure_enclave as se;

    let ecies_label = format!("{OPERATOR_PRESENCE_SE_LABEL}-ecies");
    let ecies_role = se::EciesKeyLabel::from_provisioned(ecies_label);

    attempt_de_unlock_purpose(socket_path, &ecies_role, "vault_mek")?;
    attempt_de_unlock_purpose(socket_path, &ecies_role, "lease_kek")?;
    Ok(())
}

fn attempt_de_unlock_purpose(
    socket_path: &std::path::Path,
    ecies_role: &ember_broker::secure_enclave::EciesKeyLabel,
    purpose: &str,
) -> Result<(), DaemonRpcError> {
    use ember_broker::secure_enclave as se;

    let begin = call_daemon_rpc_once(
        socket_path,
        "vault.de_unlock_begin",
        &serde_json::json!({ "purpose": purpose }),
    )?;

    let status = begin.get("status").and_then(|v| v.as_str()).unwrap_or("");

    match status {
        "locked" => {
            let outer_hex = begin
                .get("outer_blob")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    DaemonRpcError::Protocol(format!(
                        "vault.de_unlock_begin({purpose}): status=locked but no outer_blob"
                    ))
                })?;
            let outer = hex::decode(outer_hex).map_err(|e| {
                DaemonRpcError::Protocol(format!("vault.de_unlock_begin({purpose}): bad hex: {e}"))
            })?;

            if purpose == "vault_mek" {
                eprintln!("Touch ID required: unlocking vault (ADR 216 double-envelope)…");
            }
            let inner = se::se_unwrap(ecies_role, &outer).map_err(|e| {
                DaemonRpcError::Protocol(format_touch_id_key_use_error(
                    &format!("ADR 216 double-envelope unlock ({purpose}): SE decrypt failed"),
                    e,
                ))
            })?;

            call_daemon_rpc_once(
                socket_path,
                "vault.de_unlock_complete",
                &serde_json::json!({
                    "inner_blob": hex::encode(&inner),
                    "purpose": purpose,
                }),
            )
            .map(|_| ())
        }
        "unprovisioned" => {
            if purpose == "vault_mek" {
                eprintln!(
                    "First boot: provisioning vault with double-envelope SE custody (ADR 216)…"
                );
            }
            let provision = call_daemon_rpc_once(
                socket_path,
                "vault.de_provision_begin",
                &serde_json::json!({ "purpose": purpose }),
            )?;
            let inner_hex = provision
                .get("inner_blob")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    DaemonRpcError::Protocol(format!(
                        "vault.de_provision_begin({purpose}): no inner_blob"
                    ))
                })?;
            let inner = hex::decode(inner_hex).map_err(|e| {
                DaemonRpcError::Protocol(format!(
                    "vault.de_provision_begin({purpose}): bad hex: {e}"
                ))
            })?;

            if purpose == "vault_mek" {
                eprintln!("Touch ID required: sealing vault key to Secure Enclave…");
            }
            let outer = se::se_wrap(ecies_role, &inner).map_err(|e| {
                DaemonRpcError::Protocol(format!(
                    "ADR 216 double-envelope provision ({purpose}): SE encrypt failed: {e}"
                ))
            })?;

            call_daemon_rpc_once(
                socket_path,
                "vault.de_provision_outer",
                &serde_json::json!({
                    "outer_blob": hex::encode(&outer),
                    "purpose": purpose,
                }),
            )
            .map(|_| ())
        }
        "unlocked" => Ok(()),
        other => Err(DaemonRpcError::Protocol(format!(
            "vault.de_unlock_begin({purpose}): unexpected status '{other}'"
        ))),
    }
}

#[cfg(not(target_os = "macos"))]
fn attempt_de_unlock(_socket_path: &std::path::Path) -> Result<(), DaemonRpcError> {
    Err(DaemonRpcError::Protocol(
        "ADR 216 double-envelope unlock requires a Secure Enclave (macOS-only).".to_string(),
    ))
}

/// True when the error signals that the vault is locked and a double-envelope
/// unlock via the CLI relay might succeed. The signal is -32030 with the
/// canonical `LiveVaultUnavailable` message ("live vault is locked").
fn should_attempt_de_unlock(code: i32, message: &str) -> bool {
    code == -32030 && message.contains("live vault is locked") && can_attempt_se_unlock()
}

fn daemon_rpc_guidance(method: &str, code: i32, message: &str) -> Option<String> {
    let presence_missing = code == -32001
        && authority_error_reason(message)
            .as_deref()
            .is_some_and(|reason| {
                matches!(
                    reason,
                    "missing"
                        | "expired"
                        | "uid-mismatch"
                        | "sig-invalid"
                        | "scope-mismatch"
                        | "identity-missing"
                )
            });
    // ADR 206 §4 — the presence-as-decryption unlock window is locked. In an
    // interactive macOS session `call_daemon_rpc` would have tapped to unlock
    // implicitly; reaching this guidance means the implicit tap was not possible
    // (headless / non-interactive / no real Secure Enclave) or was declined.
    // Point the operator at the explicit pre-warm command.
    let s4_window_locked =
        code == -32001 && authority_error_reason(message).as_deref() == Some("locked");
    let session_locked = code == -32030
        && (message.contains("session is locked")
            || message.contains("live vault is locked")
            || message.contains("vault unavailable")
            || message.contains("session auto-locked"));
    let live_vault_missing = code == -32000 && message.contains("no vault is attached");
    let vault_unlock_requires_managed_lane = method == "vault_unlock"
        && code == -32030
        && (message.contains(
            "vault_unlock_begin is only required on the separate-uid managed daemon path",
        ) || message.contains("same-daemon operator-uid reopen"));
    let daemon_quarantined =
        message.contains("daemon quarantined") && message.contains("write-class method");

    if daemon_quarantined {
        return Some(
            "this command is blocked because the daemon quarantined write-class methods after an audit-chain integrity failure. Run `ember doctor` to diagnose the repair path, then repair the daemon before retrying write operations."
                .to_string(),
        );
    }

    if vault_unlock_requires_managed_lane {
        return Some(
            "this command needs operator presence on the daemon-managed vault lane, but this daemon is not running in the managed separate-uid posture. The managed separate-uid biometric unlock flow only works on the true separate-uid daemon. If this is a dev probe lane, restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh bootstrap; otherwise run `sudo ember daemon install` to repair or start the managed service. same-daemon operator-uid reopen is intentionally disabled."
                .to_string(),
        );
    }

    if s4_window_locked {
        return Some(
            "this command needs authority custody unlocked (ADR 206 §4 presence-as-decryption), but the unlock window is locked and no presence tap could be performed here (headless / non-interactive / no Secure Enclave, or the Touch ID prompt was declined). Run `ember vault se-unlock` (one Touch ID tap) from an interactive macOS session to open the window, then retry."
                .to_string(),
        );
    }

    if method == "register_session" && presence_missing {
        return Some(
            "this session needs a session-runtime presence credential. The host launcher normally mints and caches that credential during `register_session` after the ADR 206 §4 Touch ID window opens; reaching this error means that handshake did not complete. Run `ember status` and `ember doctor`, then retry from an interactive signed host launcher."
                .to_string(),
        );
    }

    if method == "register_session" && (session_locked || live_vault_missing) {
        return Some(
            "this session needs authority custody unlocked (ADR 206 §4 presence-as-decryption). The host launcher normally performs this Touch ID unlock implicitly; reaching this error means the tap could not be completed here or the daemon is stale. Retry from an interactive signed host launcher. If you need to repair the custody window directly, run `ember vault se-unlock` once and retry."
                .to_string(),
        );
    }

    if presence_missing || session_locked || live_vault_missing {
        if method == "vault_unlock" {
            return Some(
                "this command needs operator presence on the daemon-managed vault lane, but this daemon is not running in the managed separate-uid posture. The managed separate-uid biometric unlock flow only works on the true separate-uid daemon. If this is a dev probe lane, restart the daemon with `EMBER_VAULT_PASSPHRASE` for a fresh bootstrap; otherwise run `sudo ember daemon install` to repair or start the managed service. same-daemon operator-uid reopen is intentionally disabled."
                    .to_string(),
            );
        }

        if method == "vault_lock" {
            return Some(
                "this command needs operator presence on the daemon-managed vault lane. \
                 Run `ember vault unlock` to invoke the managed separate-uid biometric \
                 unlock flow when available. If you are on a dev probe lane, restart \
                 the daemon with `EMBER_VAULT_PASSPHRASE`; same-daemon operator-uid \
                 reopen is intentionally disabled."
                    .to_string(),
            );
        }

        return Some(
            "this command needs operator presence on the daemon-managed vault lane. \
             Run `ember vault unlock` to invoke the managed separate-uid biometric unlock \
             flow when available. If you are on a dev probe lane, restart the daemon with \
             `EMBER_VAULT_PASSPHRASE`; same-daemon operator-uid reopen is intentionally \
             disabled."
                .to_string(),
        );
    }

    None
}

#[derive(Debug, Clone)]
pub struct LiveDaemonStatus {
    pub pid: Option<u32>,
    pub socket: std::path::PathBuf,
    pub summary: ember_daemon::infra::status::StatusSummary,
}

fn read_daemon_pid_hint(pid_file: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(pid_file)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// Probe whether the daemon is live on the socket/RPC seam.
///
/// This deliberately treats the daemon's own `status` RPC as the source of
/// truth once the socket path exists. Operator-facing posture/reporting should
/// not depend only on a PID-file race or launchd bookkeeping when the managed
/// daemon is already up and serving read-class methods.
pub fn probe_live_daemon_status(
    socket_path: &std::path::Path,
    pid_file: &std::path::Path,
) -> Result<Option<LiveDaemonStatus>, ValidationError> {
    if !socket_path.exists() {
        return Ok(None);
    }

    match call_daemon_rpc(socket_path, "status", &serde_json::Value::Null) {
        Ok(result) => {
            let summary = serde_json::from_value(result)
                .map_err(|e| ValidationError::new(format!("daemon status: {e}")))?;
            Ok(Some(LiveDaemonStatus {
                pid: read_daemon_pid_hint(pid_file),
                socket: socket_path.to_path_buf(),
                summary,
            }))
        }
        Err(DaemonRpcError::Unavailable(_)) => Ok(None),
        Err(DaemonRpcError::PermissionDenied(e)) => {
            Err(ValidationError::new(format_daemon_socket_io_error(&e)))
        }
        Err(DaemonRpcError::Io(e)) => Err(ValidationError::new(format_daemon_socket_io_error(&e))),
        Err(DaemonRpcError::Protocol(e)) => Err(ValidationError::new(format!(
            "daemon status RPC protocol error: {e}. \
                 The daemon may be starting up, hung, or running an incompatible version. \
                 Run `ember doctor` for a deeper diagnosis.",
        ))),
        Err(DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = daemon_rpc_guidance("status", code, &message) {
                return Err(ValidationError::new(guidance));
            }
            Err(ValidationError::new(format!("daemon rpc error: {message}")))
        }
    }
}

/// Resolve the daemon Unix-domain socket path.
///
/// Precedence (per ADR 218, operator-locked 2026-06-14):
///   1. `EMBER_SOCKET_PATH` env var (used by qember.sh + integration tests)
///   2. [`crate::install_paths::prod_daemon_socket_path`] — absolute
///      OS-conventional system path returned by
///      `ember_daemon::paths::DaemonPaths::system().socket_path`.
///      macOS: `/Library/Application Support/Emberlink/run/daemon.sock`.
///      Linux: `/run/ember/daemon.sock`.
///
/// The pre-ADR-218 `~/.ember/run/daemon.sock` operator-HOME path is
/// retired; the daemon no longer installs there.
#[cfg(not(test))]
pub fn daemon_socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("EMBER_SOCKET_PATH") {
        return std::path::PathBuf::from(p);
    }
    crate::install_paths::prod_daemon_socket_path()
}

/// Call a daemon JSON-RPC method over the Unix-domain socket. Returns the
/// `result` value on success or a `ValidationError` on any failure.
#[cfg(not(test))]
pub fn call_daemon_method(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, ValidationError> {
    match call_daemon_rpc(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(DaemonRpcError::Unavailable(_)) => Err(ValidationError::new(
            rewrite_daemon_guidance_with_ember_command(
                "daemon unavailable; run 'ember status' to inspect posture or repair with 'sudo ember daemon install'",
                current_repo_build_ember_command().as_deref(),
            ),
        )),
        Err(DaemonRpcError::PermissionDenied(e)) => {
            Err(ValidationError::new(format_daemon_socket_io_error(&e)))
        }
        Err(DaemonRpcError::Io(e)) => Err(ValidationError::new(format_daemon_socket_io_error(&e))),
        Err(DaemonRpcError::Protocol(e)) => Err(ValidationError::new(e)),
        Err(DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = daemon_rpc_guidance(method, code, &message) {
                return Err(ValidationError::new(guidance));
            }
            Err(ValidationError::new(format!("daemon rpc error: {message}")))
        }
    }
}

/// Call a daemon JSON-RPC method without the ADR 206 presence-proof acquisition
/// layer (the bare `call_daemon_rpc_once` path).
///
/// Used by optional/read-mostly probes where acquiring a fresh presence-Device
/// signature — OR firing the ADR 206 §4 implicit unlock tap — would be worse than
/// surfacing the locked-vault posture directly. `call_daemon_rpc` adds two retry
/// layers this path deliberately skips: the §1 widening presence-proof
/// acquisition and the §4 implicit `se_unwrap` unlock-and-retry.
pub fn call_daemon_method_without_unlock_retry(
    socket_path: &std::path::Path,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, ValidationError> {
    match call_daemon_rpc_once(socket_path, method, params) {
        Ok(result) => Ok(result),
        Err(DaemonRpcError::Unavailable(_)) => Err(ValidationError::new(
            rewrite_daemon_guidance_with_ember_command(
                "daemon unavailable; run 'ember status' to inspect posture or repair with 'sudo ember daemon install'",
                current_repo_build_ember_command().as_deref(),
            ),
        )),
        Err(DaemonRpcError::PermissionDenied(e)) => {
            Err(ValidationError::new(format_daemon_socket_io_error(&e)))
        }
        Err(DaemonRpcError::Io(e)) => Err(ValidationError::new(format_daemon_socket_io_error(&e))),
        Err(DaemonRpcError::Protocol(e)) => Err(ValidationError::new(e)),
        Err(DaemonRpcError::Rpc { code, message }) => {
            if let Some(guidance) = daemon_rpc_guidance(method, code, &message) {
                return Err(ValidationError::new(guidance));
            }
            Err(ValidationError::new(format!("daemon rpc error: {message}")))
        }
    }
}

/// Return the content key used to encrypt/decrypt local state.
///
/// Resolution order:
///   1. `EMBERLINK_KEY` env var (test bypass — accepts `ek1:<64 hex>` or
///      `xchacha20-key:<64 hex>` format).
///   2. In test builds: deterministic fixture key (avoids keychain/daemon I/O).
///   3. One-time migration: if the legacy keychain item
///      `com.emberlink/local-state-key` exists, ship it to the daemon via
///      `local_state_key_set` and delete the keychain copy (warn on delete
///      failure, do not abort).
///   4. Daemon socket `local_state_key_get` with `caller = "cli"`. The daemon
///      generates a fresh `xchacha20-key:…` content key on first call and
///      stores it in its vault under `local-state/cli`.
fn resolve_encryption_key() -> Result<Zeroizing<String>, ValidationError> {
    // Step 1 — env-var test bypass (preserved for CI and script usage).
    if let Ok(key) = std::env::var("EMBERLINK_KEY") {
        // Accept both the legacy ek1: prefix (4 chars + 64 hex = 68 total)
        // and the canonical xchacha20-key: prefix (14 chars + 64 hex = 78
        // total) so that daemon-sourced keys passed via env also work.
        let valid = (key.starts_with("ek1:") && key.len() == 68)
            || (key.starts_with("xchacha20-key:") && key.len() == 78);
        if valid {
            return Ok(Zeroizing::new(key));
        }
        return Err(ValidationError::new(
            "EMBERLINK_KEY must be a valid content key (ek1: prefix 68 chars, or xchacha20-key: prefix 78 chars)",
        ));
    }

    // Step 2 — deterministic fixture key in test builds.
    #[cfg(test)]
    {
        // N6-deeper: derive_content_key returns Zeroizing<String>; hand the
        // wrapper through unchanged so the symmetric key zeroizes on drop
        // end-to-end at every consumer site.
        Ok(core_crypto::derive_content_key(
            b"emberlink-test-key",
            b"test",
        ))
    }

    // Production path with adversarial-review CRIT-2 race-free migration.
    #[cfg(not(test))]
    {
        let socket_path = daemon_socket_path();
        let state_file = default_data_file();

        const LEGACY_SERVICE: &str = "com.emberlink";
        const LEGACY_USER: &str = "local-state-key";

        // Fetch daemon's current key (auto-generates if missing).
        let get_params = serde_json::json!({ "caller": "cli" });
        let result = call_daemon_method(&socket_path, "local_state_key_get", &get_params)?;
        // N6-deeper: wrap the daemon-supplied key in Zeroizing immediately so
        // the secret zeroizes on drop on every path out of this function.
        let daemon_key = Zeroizing::new(
            result
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ValidationError::new("daemon local_state_key_get: missing 'key' in response")
                })?
                .to_string(),
        );

        // Only touch the legacy keychain item if the daemon's key fails to
        // decrypt the current local-state file. Normal CLI launches should
        // stay entirely on the daemon-vault lane and never probe the old
        // `com.emberlink/local-state-key` item.
        let resolution =
            resolve_local_state_key_with_lazy_legacy_fallback(&state_file, daemon_key, || {
                let entry = keyring_core::Entry::new(LEGACY_SERVICE, LEGACY_USER).ok()?;
                let key = entry.get_password().ok()?;
                Some((entry, Zeroizing::new(key)))
            })?;

        match resolution {
            LocalStateKeyResolution::Daemon(key) => Ok(key),
            LocalStateKeyResolution::LegacyRecovered { legacy, key } => {
                let set_params = serde_json::json!({
                    "caller": "cli",
                    "key": &*key,
                    "force": true,
                });
                call_daemon_method(&socket_path, "local_state_key_set", &set_params).map_err(
                    |e| {
                        ValidationError::new(format!(
                            "race recovery: failed to force-overwrite daemon vault: {e}"
                        ))
                    },
                )?;
                if let Err(e) = legacy.delete_credential() {
                    tracing::warn!(
                        error = %e,
                        "keychain migration: delete legacy keychain item failed (non-fatal)"
                    );
                }
                Ok(key)
            }
        }
    }
}

/// Outcome of an attempt-decrypt-probe on the existing `local-state.enc`
/// using a candidate key. Used by the CRIT-2 race-free migration logic.
enum ProbeOutcome {
    DecryptOk,
    DecryptFailed,
    NoFile,
}

fn probe_decrypt(state_file: &Path, candidate_key: &str) -> ProbeOutcome {
    if !state_file.exists() {
        return ProbeOutcome::NoFile;
    }
    let bytes = match std::fs::read(state_file) {
        Ok(b) => b,
        Err(_) => return ProbeOutcome::DecryptFailed,
    };
    match decrypt_state(&bytes, candidate_key) {
        Ok(_) => ProbeOutcome::DecryptOk,
        Err(_) => ProbeOutcome::DecryptFailed,
    }
}

// N6-deeper: hold the candidate keys as Zeroizing<String> so the symmetric
// secret zeroizes on drop on every branch (DecryptFailed-with-no-legacy,
// LegacyRecovered hand-off, etc.).
enum LocalStateKeyResolution<L> {
    Daemon(Zeroizing<String>),
    LegacyRecovered { legacy: L, key: Zeroizing<String> },
}

fn resolve_local_state_key_with_lazy_legacy_fallback<L, F>(
    state_file: &Path,
    daemon_key: Zeroizing<String>,
    load_legacy: F,
) -> Result<LocalStateKeyResolution<L>, ValidationError>
where
    F: FnOnce() -> Option<(L, Zeroizing<String>)>,
{
    match probe_decrypt(state_file, &daemon_key) {
        ProbeOutcome::DecryptOk | ProbeOutcome::NoFile => {
            Ok(LocalStateKeyResolution::Daemon(daemon_key))
        }
        ProbeOutcome::DecryptFailed => match load_legacy() {
            Some((legacy, legacy_key))
                if matches!(
                    probe_decrypt(state_file, &legacy_key),
                    ProbeOutcome::DecryptOk
                ) =>
            {
                Ok(LocalStateKeyResolution::LegacyRecovered {
                    legacy,
                    key: legacy_key,
                })
            }
            _ => Err(ValidationError::new(format!(
                "local-state encryption-key recovery failed: daemon vault key does not decrypt {} and no legacy key matches. Manual recovery needed (export EMBERLINK_KEY).",
                state_file.display()
            ))),
        },
    }
}

#[cfg(test)]
mod local_state_key_resolution_tests {
    use super::*;

    #[test]
    fn daemon_key_short_circuits_legacy_loader_when_state_file_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let called = std::cell::Cell::new(false);
        let daemon_key =
            "xchacha20-key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let resolved = resolve_local_state_key_with_lazy_legacy_fallback(
            tmp.path().join("missing.enc").as_path(),
            Zeroizing::new(daemon_key.to_string()),
            || {
                called.set(true);
                Some(("legacy", Zeroizing::new("legacy-key".to_string())))
            },
        )
        .expect("resolve without legacy");

        match resolved {
            LocalStateKeyResolution::Daemon(key) => assert_eq!(key.as_str(), daemon_key),
            LocalStateKeyResolution::LegacyRecovered { .. } => {
                panic!("missing local-state file should keep daemon key")
            }
        }
        assert!(
            !called.get(),
            "legacy loader must stay lazy when the daemon key path is already valid"
        );
    }

    #[test]
    fn daemon_key_short_circuits_legacy_loader_when_state_decrypts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_file = tmp.path().join("local-state.enc");
        let daemon_key =
            "xchacha20-key:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let ciphertext = encrypt_state(br#"{"ok":true}"#, daemon_key).expect("encrypt state");
        std::fs::write(&state_file, ciphertext).expect("write state file");
        let called = std::cell::Cell::new(false);

        let resolved = resolve_local_state_key_with_lazy_legacy_fallback(
            &state_file,
            Zeroizing::new(daemon_key.to_string()),
            || {
                called.set(true);
                Some(("legacy", Zeroizing::new("legacy-key".to_string())))
            },
        )
        .expect("resolve with daemon key");

        match resolved {
            LocalStateKeyResolution::Daemon(key) => assert_eq!(key.as_str(), daemon_key),
            LocalStateKeyResolution::LegacyRecovered { .. } => {
                panic!("decryptable state should keep daemon key")
            }
        }
        assert!(
            !called.get(),
            "legacy loader must not run when the daemon key already decrypts the file"
        );
    }

    #[test]
    fn legacy_key_recovers_when_daemon_key_fails_to_decrypt() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_file = tmp.path().join("local-state.enc");
        let daemon_key =
            "xchacha20-key:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let legacy_key =
            "xchacha20-key:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let ciphertext = encrypt_state(br#"{"ok":true}"#, legacy_key).expect("encrypt state");
        std::fs::write(&state_file, ciphertext).expect("write state file");
        let called = std::cell::Cell::new(false);

        let resolved = resolve_local_state_key_with_lazy_legacy_fallback(
            &state_file,
            Zeroizing::new(daemon_key.to_string()),
            || {
                called.set(true);
                Some(("legacy-entry", Zeroizing::new(legacy_key.to_string())))
            },
        )
        .expect("resolve with legacy key");

        match resolved {
            LocalStateKeyResolution::LegacyRecovered { legacy, key } => {
                assert_eq!(legacy, "legacy-entry");
                assert_eq!(key.as_str(), legacy_key);
            }
            LocalStateKeyResolution::Daemon(_) => {
                panic!("daemon key should not decrypt legacy-encrypted state")
            }
        }
        assert!(
            called.get(),
            "legacy loader should run when daemon key cannot decrypt the state file"
        );
    }
}

#[cfg(test)]
fn encrypt_state(plaintext: &[u8], key: &str) -> Result<Vec<u8>, ValidationError> {
    let encrypted = core_crypto::encrypt_content(key, plaintext, b"emberlink-local-state")?;
    let nonce_bytes = core_types::hex_to_bytes(&encrypted.nonce_hex)?;
    let mut out =
        Vec::with_capacity(ENCRYPTED_MAGIC.len() + nonce_bytes.len() + encrypted.ciphertext.len());
    out.extend_from_slice(ENCRYPTED_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&encrypted.ciphertext);
    Ok(out)
}

fn decrypt_state(data: &[u8], key: &str) -> Result<Vec<u8>, ValidationError> {
    if data.len() < ENCRYPTED_MAGIC.len() + 24 {
        return Err(ValidationError::new("encrypted state file too short"));
    }
    if &data[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
        return Err(ValidationError::new(
            "not an encrypted state file (invalid magic header)",
        ));
    }
    let nonce_hex =
        core_types::bytes_to_hex(&data[ENCRYPTED_MAGIC.len()..ENCRYPTED_MAGIC.len() + 24]);
    let ciphertext = data[ENCRYPTED_MAGIC.len() + 24..].to_vec();
    let encrypted = core_crypto::EncryptedContent {
        nonce_hex,
        ciphertext,
    };
    core_crypto::decrypt_content(key, &encrypted, b"emberlink-local-state")
}

#[cfg(test)]
fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("local-state");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".{file_name}.{unique}.tmp"));

    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static TEMP_STATE_COUNTER: AtomicU64 = AtomicU64::new(0);
    #[path = "daemon_rpc_presence.rs"]
    mod daemon_rpc_presence;

    fn temp_state_file(tag: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_STATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("emberlink-app-{tag}-{timestamp}-{counter}.tsv"))
    }

    #[test]
    fn atomic_write_replaces_existing_file_without_leaving_temp_files() {
        let data_file = temp_state_file("atomic-write");
        let file_name = data_file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        atomic_write_bytes(&data_file, b"first").unwrap();
        atomic_write_bytes(&data_file, b"second").unwrap();

        assert_eq!(fs::read(&data_file).unwrap(), b"second");

        let tmp_prefix = format!(".{file_name}.");
        let leftovers: Vec<_> = fs::read_dir(data_file.parent().unwrap())
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let name = path.file_name()?.to_str()?;
                if name.starts_with(&tmp_prefix) && name.ends_with(".tmp") {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");

        let _ = fs::remove_file(&data_file);
    }
}
