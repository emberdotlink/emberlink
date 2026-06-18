// CLASSIFICATION: PUBLIC
//! `ember device revoke` — drive the daemon's `identity.device.revoke` RPC.
//!
//! Two lanes share the same daemon RPC; the operator picks via flags:
//!
//! 1. **SE-driven (default on macOS with a signed-SE binary).** The CLI runs
//!    the whole ceremony in one command:
//!    a. resolves the authority device key (`--authority-device-key` if
//!    supplied; otherwise inferred from the operator's
//!    `ember-operator-presence` SE signing key, with a clear error when
//!    2+ active presence Devices exist),
//!    b. calls `identity.device.revoke` (PREPARE) to fetch the canonical
//!    `DeviceRevoked` event bytes,
//!    c. signs those bytes with the SE key under one Touch ID prompt
//!    (`se_sign_batch` with a `SingleIntent` carrying the one event),
//!    d. calls `identity.device.revoke` (COMMIT) with the signature.
//!    No second invocation — same UX as `ember device enroll --secure-enclave`.
//!    The daemon never holds the presence-Device private key (G1 invariant
//!    preserved); the signature is verified at append time.
//!
//! 2. **`--external-signer` (off-host signer).** The two-call OOB flow for
//!    YubiKey PIV / PKCS#11 / `gpg` / `ssh-keygen -Y sign`. Run WITHOUT
//!    `--operator-signature-hex` to PREPARE (the daemon returns the exact
//!    bytes to sign); re-run with the signature to COMMIT. Requires
//!    `--authority-device-key` (the CLI cannot derive a YubiKey/PIV pubkey
//!    from local SE state).
//!
//! In both lanes the daemon enforces (a) cross-root signature check, (b)
//! last-presence-device guard, (c) V030-EMBER-DEVICE-REVOKE F4.1 race
//! serialization on COMMIT (YARA's `DaemonStore::identity_mutation_lock`).
//! Those structural guards remain intact: the SE-driven lane just collapses
//! PREPARE+sign+COMMIT into one operator step.
//!
#[cfg(not(test))]
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::device::list::DeviceView;
#[cfg(not(test))]
use crate::device::list::{DeviceListError, fetch_device_list};

/// One step of an out-of-band revoke signing plan: the deterministic event id
/// and the exact bytes the operator's presence Device must sign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokePrepareStep {
    /// What this event establishes (operator-facing display / audit).
    pub purpose: String,
    /// Deterministic event id — an external party can re-derive it.
    pub event_id: String,
    /// Hex-encoded canonical bytes to sign.
    pub bytes_hex: String,
}

/// The decoded body of an `identity.device.revoke` response in PREPARE mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevokePrepareResponse {
    /// Always `"prepare"` in PREPARE mode.
    pub mode: String,
    pub operator_root_id: String,
    pub device_id: String,
    pub authority_device_key: String,
    /// Single-element vector (one event = one signature).
    pub to_sign: Vec<RevokePrepareStep>,
}

/// The decoded body of an `identity.device.revoke` response in COMMIT mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevokeCommitResponse {
    /// Always `"committed"` in COMMIT mode.
    pub mode: String,
    pub device_id: String,
    pub reason: String,
    pub operator_root_id: String,
}

/// Errors surfaced by [`run`] / [`call_revoke`].
#[derive(Debug, thiserror::Error)]
pub enum DeviceRevokeError {
    #[error("daemon RPC error {code}: {message}")]
    DaemonRpc { code: i32, message: String },
    #[error("invalid daemon response: {0}")]
    Protocol(String),
    #[error("authority key inference: {0}")]
    AuthorityInference(String),
    #[error("Secure Enclave signing: {0}")]
    SecureEnclave(String),
    #[error("device list lookup: {0}")]
    DeviceList(String),
}

/// Parse the PREPARE response body. Separated from I/O so tests can exercise
/// the parser without a live daemon.
pub fn parse_prepare_response(
    body: &Value,
) -> Result<DeviceRevokePrepareResponse, DeviceRevokeError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        DeviceRevokeError::Protocol(format!("decode identity.device.revoke PREPARE: {e}"))
    })
}

/// Parse the COMMIT response body. Separated from I/O so tests can exercise
/// the parser without a live daemon.
pub fn parse_commit_response(
    body: &Value,
) -> Result<DeviceRevokeCommitResponse, DeviceRevokeError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        DeviceRevokeError::Protocol(format!("decode identity.device.revoke COMMIT: {e}"))
    })
}

/// Either a PREPARE response (no signature supplied) or a COMMIT response
/// (signature was supplied + daemon accepted it).
#[derive(Debug, Clone)]
pub enum DeviceRevokeResponse {
    Prepare(DeviceRevokePrepareResponse),
    Commit(DeviceRevokeCommitResponse),
}

/// Build the JSON-RPC params object for `identity.device.revoke`. Public so
/// tests can pin the on-wire shape.
///
/// `compromised` triggers the daemon's opt-in `KEK_s` rotation alongside the
/// always-on cascade-delete of the revoked Device's `presence_scope_kek` wraps.
/// Omitting the field on the wire (`false` is the daemon's default) preserves
/// the routine-revoke path: cascade-delete only, no rotation, no
/// `kek.rotation` receipt.
pub fn build_params(
    device_id: &str,
    authority_device_key: &str,
    reason: &str,
    signature_hex: Option<&str>,
    compromised: bool,
) -> Value {
    let mut params = json!({
        "device_id": device_id,
        "authority_device_key": authority_device_key,
        "reason": reason,
    });
    if compromised {
        params["compromised"] = json!(true);
    }
    if let Some(sig) = signature_hex {
        params["signatures"] = json!([sig]);
    }
    params
}

/// Call `identity.device.revoke` against the daemon and dispatch PREPARE vs
/// COMMIT by the `mode` field. Goes through the shared retry harness so the
/// §4 unlock window is acquired transparently if needed.
#[cfg(not(test))]
pub fn call_revoke(
    socket_path: &Path,
    device_id: &str,
    authority_device_key: &str,
    reason: &str,
    signature_hex: Option<&str>,
    compromised: bool,
) -> Result<DeviceRevokeResponse, DeviceRevokeError> {
    let params = build_params(
        device_id,
        authority_device_key,
        reason,
        signature_hex,
        compromised,
    );
    let body = crate::call_daemon_rpc(socket_path, "identity.device.revoke", &params).map_err(
        |e| match e {
            crate::DaemonRpcError::Rpc { code, message } => {
                DeviceRevokeError::DaemonRpc { code, message }
            }
            other => DeviceRevokeError::DaemonRpc {
                code: -32000,
                message: other.to_string(),
            },
        },
    )?;
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    match mode {
        "committed" => parse_commit_response(&body).map(DeviceRevokeResponse::Commit),
        "prepare" => parse_prepare_response(&body).map(DeviceRevokeResponse::Prepare),
        other => Err(DeviceRevokeError::Protocol(format!(
            "identity.device.revoke: unexpected mode {other:?}"
        ))),
    }
}

/// Resolve the authority device key the CLI will use to sign the revoke.
///
/// `explicit` wins (operator-provided). Otherwise we infer from the enrolled
/// active `presence`-class Device set: exactly ONE active presence Device →
/// use its `device_pubkey`; ZERO → error pointing at `device enroll`; 2+ →
/// error listing the candidates so the operator can pass
/// `--authority-device-key` to disambiguate. The CLI can't auto-pick when
/// multiple presence Devices exist because the SE only ever holds at most one
/// `ember-operator-presence` keypair locally; a second active presence Device
/// is on another host (or in another SE keychain) and the operator must
/// declare intent.
///
/// `presence` is the only class whose key may sign a `DeviceRevoked` event
/// (the daemon refuses other custody classes at append time); recovery
/// recipients, co-authority, etc. are filtered out.
pub fn resolve_authority_device_key(
    devices: &[DeviceView],
    explicit: Option<&str>,
) -> Result<String, DeviceRevokeError> {
    if let Some(k) = explicit {
        return Ok(k.to_string());
    }
    let active_presence: Vec<&DeviceView> = devices
        .iter()
        .filter(|d| d.class() == "presence" && d.status == "active")
        .collect();
    match active_presence.len() {
        0 => Err(DeviceRevokeError::AuthorityInference(
            "no active presence Device enrolled under the operator root — \
             enroll one with `ember device enroll` before revoking"
                .to_string(),
        )),
        1 => Ok(active_presence[0].device_pubkey.clone()),
        n => {
            let mut listing = String::new();
            for d in &active_presence {
                use std::fmt::Write as _;
                let _ = write!(
                    listing,
                    "\n  - {label} (device_id={id}, pubkey={pk})",
                    label = d.device_label,
                    id = d.device_id,
                    pk = d.device_pubkey,
                );
            }
            Err(DeviceRevokeError::AuthorityInference(format!(
                "{n} active presence Devices found — pass \
                 --authority-device-key <P256_PUBKEY> to pick which one signs:{listing}"
            )))
        }
    }
}

/// Fetch the operator's enrolled device list, mapped to the local error type.
#[cfg(not(test))]
fn fetch_devices(socket_path: &Path) -> Result<Vec<DeviceView>, DeviceRevokeError> {
    match fetch_device_list(socket_path) {
        Ok(resp) => Ok(resp.devices),
        Err(DeviceListError::DaemonRpc { code, message }) => {
            Err(DeviceRevokeError::DaemonRpc { code, message })
        }
        Err(other) => Err(DeviceRevokeError::DeviceList(other.to_string())),
    }
}

/// macOS-only: drive the SE-signing lane end-to-end. PREPARE → sign with the
/// `ember-operator-presence` SE key under one Touch ID prompt → COMMIT. The
/// daemon never holds the SE key (G1).
#[cfg(all(not(test), target_os = "macos"))]
fn run_se_driven_revoke(
    socket_path: &Path,
    device_id: &str,
    authority_device_key_explicit: Option<&str>,
    reason: &str,
    se_label: &str,
    compromised: bool,
) -> Result<DeviceRevokeCommitResponse, DeviceRevokeError> {
    use ember_broker::secure_enclave as se;

    // SAFETY GATE: never sign a real-revoke event with a software stub key.
    // Without the real SE backend the in-memory stub would let an unsigned
    // build forge the operator's revoke signature against the daemon's
    // append-time verifier (the daemon takes whatever P-256 signature the
    // CLI submits). Fail closed; the operator can fall back to
    // `--external-signer` with an off-host signer.
    if !se::se_backend_is_real() {
        return Err(DeviceRevokeError::SecureEnclave(
            "this binary lacks real Secure Enclave support (unsigned / no se-real). \
             Refusing the SE-driven revoke lane. Use a signed release build, \
             or pass --external-signer with --operator-signature-hex."
                .to_string(),
        ));
    }

    // Locate the SE signing key (created by `device enroll --secure-enclave`).
    let raw_sign = se::find_secure_enclave_key(se_label).map_err(|e| {
        DeviceRevokeError::SecureEnclave(format!(
            "SE signing key '{se_label}' not found — enroll a presence device first \
             via `ember device enroll --secure-enclave`: {e}"
        ))
    })?;
    let se_sign_pub = se::se_pubkey_bytes(&raw_sign)
        .map_err(|e| DeviceRevokeError::SecureEnclave(format!("read SE signing pubkey: {e}")))?;
    let se_authority_key = format!("p256:{}", hex::encode(&se_sign_pub));

    // Resolve the authority key the daemon will verify against. If the
    // operator passed --authority-device-key, honor it (and verify it
    // matches the SE pubkey — otherwise the SE-driven lane is signing
    // bytes the daemon will refuse). Otherwise infer from `device list`
    // when exactly one active presence Device exists.
    let devices = fetch_devices(socket_path)?;
    let resolved_authority = resolve_authority_device_key(&devices, authority_device_key_explicit)?;
    if !resolved_authority.eq_ignore_ascii_case(&se_authority_key) {
        return Err(DeviceRevokeError::AuthorityInference(format!(
            "--authority-device-key {resolved} does not match this host's SE signing key \
             {se_key}. The SE-driven lane signs with the local SE key only; either drop \
             --authority-device-key (let the CLI infer it from the SE key), or use \
             --external-signer on the host that holds the matching key.",
            resolved = resolved_authority,
            se_key = se_authority_key,
        )));
    }

    let sign_key = se::SignKeyHandle::from_provisioned(raw_sign);

    // PREPARE — fetch the exact canonical DeviceRevoked bytes. The
    // `compromised` flag is plumbed through both calls so the daemon's
    // PREPARE side can validate it parses without surprising the operator
    // at COMMIT (the actual rotation runs in COMMIT alongside the cascade-
    // delete).
    let prepare_params = build_params(device_id, &resolved_authority, reason, None, compromised);
    let prepare_body =
        crate::call_daemon_rpc(socket_path, "identity.device.revoke", &prepare_params).map_err(
            |e| match e {
                crate::DaemonRpcError::Rpc { code, message } => {
                    DeviceRevokeError::DaemonRpc { code, message }
                }
                other => DeviceRevokeError::DaemonRpc {
                    code: -32000,
                    message: other.to_string(),
                },
            },
        )?;
    let prepare = parse_prepare_response(&prepare_body)?;
    if prepare.to_sign.is_empty() {
        return Err(DeviceRevokeError::Protocol(
            "identity.device.revoke PREPARE returned an empty signing plan".to_string(),
        ));
    }

    // SIGN under one Touch ID prompt. `se_sign_batch` with a single-element
    // SingleIntent matches the byte-for-byte ceremony `device enroll
    // --secure-enclave` uses (domain-separated message via `context_message`).
    println!("Touch ID required: signing the device-revoke event on the Secure Enclave…");
    let bytes = hex::decode(&prepare.to_sign[0].bytes_hex)
        .map_err(|e| DeviceRevokeError::Protocol(format!("bad bytes_hex from daemon: {e}")))?;
    let message = core_crypto::context_message(core_crypto::DOMAIN_EVENT, &bytes);
    let message_refs: Vec<&[u8]> = vec![message.as_slice()];
    let signatures = se::se_sign_batch(
        &sign_key,
        se::SingleIntent::new(&message_refs),
        "Authenticate to revoke a device under your Emberlink operator root",
    )
    .map_err(|e| {
        DeviceRevokeError::SecureEnclave(format!(
            "SE signing failed (Touch ID declined or key unavailable): {e}"
        ))
    })?;
    let der_hex = hex::encode(&signatures[0]);

    // COMMIT — daemon verifies + appends. Last-presence-device guard + YARA's
    // F4.1 mutation-lock race serialization run on the daemon side. When
    // `compromised`, the daemon also rotates `KEK_s` per scope and emits a
    // `kek.rotation` receipt alongside the `DeviceRevoked` event.
    let commit_params = build_params(
        device_id,
        &resolved_authority,
        reason,
        Some(&der_hex),
        compromised,
    );
    let commit_body = crate::call_daemon_rpc(socket_path, "identity.device.revoke", &commit_params)
        .map_err(|e| match e {
            crate::DaemonRpcError::Rpc { code, message } => {
                DeviceRevokeError::DaemonRpc { code, message }
            }
            other => DeviceRevokeError::DaemonRpc {
                code: -32000,
                message: other.to_string(),
            },
        })?;
    let mode = commit_body
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if mode != "committed" {
        return Err(DeviceRevokeError::Protocol(format!(
            "identity.device.revoke COMMIT: expected mode=\"committed\", got {mode:?}"
        )));
    }
    parse_commit_response(&commit_body)
}

#[cfg(all(not(test), not(target_os = "macos")))]
fn run_se_driven_revoke(
    _socket_path: &Path,
    _device_id: &str,
    _authority_device_key_explicit: Option<&str>,
    _reason: &str,
    _se_label: &str,
    _compromised: bool,
) -> Result<DeviceRevokeCommitResponse, DeviceRevokeError> {
    Err(DeviceRevokeError::SecureEnclave(
        "the SE-driven revoke lane is only available on macOS. \
         Use --external-signer with --operator-signature-hex on other platforms."
            .to_string(),
    ))
}

/// Entry point for `ember device revoke`. Returns a non-zero exit code on
/// error so the binary can `process::exit`.
#[cfg(not(test))]
// CLI entry point — operator flags map 1:1 to params; bundling into a struct is out of scope.
#[allow(clippy::too_many_arguments)]
pub fn run(
    socket_path: &Path,
    device_id: &str,
    authority_device_key: Option<&str>,
    reason: &str,
    operator_signature_hex: Option<&str>,
    external_signer: bool,
    se_label: &str,
    compromised: bool,
    json_output: bool,
) -> i32 {
    // SE-driven lane: default on macOS with a real SE backend, no
    // --external-signer, and no operator-supplied signature. One Touch ID
    // prompt, single command.
    let use_se_lane =
        !external_signer && operator_signature_hex.is_none() && se_default_available();

    if use_se_lane {
        match run_se_driven_revoke(
            socket_path,
            device_id,
            authority_device_key,
            reason,
            se_label,
            compromised,
        ) {
            Ok(resp) => return print_commit(&resp, json_output),
            Err(err) => return print_error(&err),
        }
    }

    // External-signer lane: PREPARE / COMMIT off-host. --authority-device-key
    // is required (the CLI cannot derive it from a YubiKey/PIV key).
    let authority_key = match authority_device_key {
        Some(k) => k,
        None => {
            eprintln!(
                "ember device revoke: --authority-device-key is required with --external-signer \
                 (the CLI cannot derive an off-host signer's public key)."
            );
            return 2;
        }
    };

    match call_revoke(
        socket_path,
        device_id,
        authority_key,
        reason,
        operator_signature_hex,
        compromised,
    ) {
        Ok(DeviceRevokeResponse::Commit(resp)) => print_commit(&resp, json_output),
        Ok(DeviceRevokeResponse::Prepare(resp)) => print_prepare(&resp, json_output),
        Err(err) => print_error(&err),
    }
}

#[cfg(all(not(test), target_os = "macos"))]
fn se_default_available() -> bool {
    ember_broker::secure_enclave::se_backend_is_real()
}

#[cfg(all(not(test), not(target_os = "macos")))]
fn se_default_available() -> bool {
    false
}

#[cfg(not(test))]
fn print_commit(resp: &DeviceRevokeCommitResponse, json_output: bool) -> i32 {
    if json_output {
        match serde_json::to_string_pretty(resp) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("{{}}"),
        }
    } else {
        println!("Revoked {} (reason: {})", resp.device_id, resp.reason);
        println!("  operator_root_id: {}", resp.operator_root_id);
        println!();
        println!("Next: confirm the device dropped out of the authority set");
        println!("  ember device list");
    }
    0
}

#[cfg(not(test))]
fn print_prepare(resp: &DeviceRevokePrepareResponse, json_output: bool) -> i32 {
    if json_output {
        match serde_json::to_value(resp) {
            Ok(v) => println!(
                "{}",
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_string())
            ),
            Err(_) => println!("{{}}"),
        }
    } else {
        println!("PREPARE — sign the following bytes off-host with the");
        println!("authority device, then re-run with --operator-signature-hex:");
        println!();
        println!("  device_id:            {}", resp.device_id);
        println!("  operator_root_id:     {}", resp.operator_root_id);
        println!("  authority_device_key: {}", resp.authority_device_key);
        for step in &resp.to_sign {
            println!();
            println!("  step:       {}", step.purpose);
            println!("  event_id:   {}", step.event_id);
            println!("  bytes_hex:  {}", step.bytes_hex);
        }
        println!();
        println!("Sign these bytes with the authority device, then re-run:");
        println!(
            "  ember device revoke --device-id {} --authority-device-key {} --external-signer \\",
            resp.device_id, resp.authority_device_key,
        );
        println!("    --operator-signature-hex <DER_HEX>");
    }
    0
}

#[cfg(not(test))]
fn print_error(err: &DeviceRevokeError) -> i32 {
    match err {
        // -32032 is the structural last-presence-device guard refusal. Surface
        // the typed help instead of the generic "error <code>: <message>" line
        // so the operator sees the actionable next step (enroll a replacement
        // first) without re-parsing the daemon's message.
        DeviceRevokeError::DaemonRpc { code: -32032, message } => {
            eprintln!("ember device revoke: refused — {message}");
            eprintln!();
            eprintln!(
                "Enroll a replacement Device first via `ember device enroll --backup`, \
                 then retry the revoke."
            );
            2
        }
        DeviceRevokeError::DaemonRpc { code, message } => {
            eprintln!("ember device revoke: error {code}: {message}");
            2
        }
        other => {
            eprintln!("ember device revoke: {other}");
            2
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::list::DeviceView;

    fn presence_device(id: &str, pubkey_hex: &str, status: &str) -> DeviceView {
        DeviceView {
            device_id: id.to_string(),
            device_label: format!("Device {id}"),
            device_role: "presence".to_string(),
            device_class: "presence".to_string(),
            device_pubkey: format!("p256:{pubkey_hex}"),
            device_encryption_pubkey: format!("p256:{}", "ee".repeat(33)),
            enrolled_at: Some("2026-06-12T00:00:00Z".to_string()),
            status: status.to_string(),
            custody_class: "presence".to_string(),
            attestation_kind: "secure_enclave".to_string(),
            is_last_authority: false,
        }
    }

    fn recovery_device(id: &str) -> DeviceView {
        DeviceView {
            device_id: id.to_string(),
            device_label: format!("Recovery {id}"),
            device_role: "recovery".to_string(),
            device_class: "recovery".to_string(),
            device_pubkey: format!("age1{id}"),
            device_encryption_pubkey: format!("age1{id}"),
            enrolled_at: Some("2026-06-12T00:00:00Z".to_string()),
            status: "active".to_string(),
            custody_class: "recovery".to_string(),
            attestation_kind: "none".to_string(),
            is_last_authority: false,
        }
    }

    #[test]
    fn build_params_prepare_omits_signatures() {
        let p = build_params("device-x", "p256:aa", "test-revoke", None, false);
        assert_eq!(p["device_id"], "device-x");
        assert_eq!(p["authority_device_key"], "p256:aa");
        assert_eq!(p["reason"], "test-revoke");
        assert!(p.get("signatures").is_none());
        assert!(
            p.get("compromised").is_none(),
            "default routine revoke must not put `compromised` on the wire"
        );
    }

    #[test]
    fn build_params_commit_carries_single_signature() {
        let p = build_params(
            "device-x",
            "p256:aa",
            "test-revoke",
            Some("DEADBEEF"),
            false,
        );
        let sigs = p["signatures"].as_array().expect("signatures array");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0], "DEADBEEF");
    }

    /// `--compromised` plumbs through to the on-wire params as
    /// `compromised: true`. Default (routine revoke) MUST NOT include the
    /// field (the daemon defaults to `false`), so a server that hasn't shipped
    /// the flag yet still parses the routine-revoke shape unchanged.
    #[test]
    fn build_params_compromised_flag_appears_only_when_set() {
        let routine = build_params("device-x", "p256:aa", "retire", None, false);
        assert!(routine.get("compromised").is_none());

        let compromised = build_params("device-x", "p256:aa", "key leaked", None, true);
        assert_eq!(compromised["compromised"], serde_json::Value::Bool(true));
    }

    #[test]
    fn parse_prepare_round_trip() {
        let body = json!({
            "mode": "prepare",
            "operator_root_id": "root-operator-abc",
            "device_id": "device-operator-victim",
            "authority_device_key": "p256:cafef00d",
            "to_sign": [{
                "purpose": "operator-device-revoke",
                "event_id": "root-operator-abc/revoke/device-operator-victim",
                "bytes_hex": "deadbeef",
            }],
        });
        let resp = parse_prepare_response(&body).unwrap();
        assert_eq!(resp.mode, "prepare");
        assert_eq!(resp.device_id, "device-operator-victim");
        assert_eq!(resp.authority_device_key, "p256:cafef00d");
        assert_eq!(resp.to_sign.len(), 1);
        assert_eq!(resp.to_sign[0].purpose, "operator-device-revoke");
    }

    #[test]
    fn parse_commit_round_trip() {
        let body = json!({
            "mode": "committed",
            "device_id": "device-operator-victim",
            "reason": "key compromised",
            "operator_root_id": "root-operator-abc",
        });
        let resp = parse_commit_response(&body).unwrap();
        assert_eq!(resp.mode, "committed");
        assert_eq!(resp.device_id, "device-operator-victim");
        assert_eq!(resp.reason, "key compromised");
    }

    #[test]
    fn parse_prepare_rejects_missing_field() {
        let body = json!({
            "mode": "prepare",
            "operator_root_id": "root-x",
            // device_id omitted
            "authority_device_key": "p256:aa",
            "to_sign": [],
        });
        let err = parse_prepare_response(&body).unwrap_err();
        assert!(matches!(err, DeviceRevokeError::Protocol(_)));
    }

    // ── authority-key inference ──────────────────────────────────────────────

    /// T1 — explicit --authority-device-key wins regardless of enrolled set.
    #[test]
    fn resolve_authority_explicit_wins() {
        let devices = vec![
            presence_device("dev-1", &"aa".repeat(33), "active"),
            presence_device("dev-2", &"bb".repeat(33), "active"),
        ];
        let resolved = resolve_authority_device_key(&devices, Some("p256:explicit")).unwrap();
        assert_eq!(resolved, "p256:explicit");
    }

    /// T2 — exactly one active presence Device → infer its pubkey.
    #[test]
    fn resolve_authority_infers_single_presence() {
        let devices = vec![
            presence_device("dev-1", &"aa".repeat(33), "active"),
            recovery_device("dev-recovery"),
        ];
        let resolved = resolve_authority_device_key(&devices, None).unwrap();
        assert_eq!(resolved, format!("p256:{}", "aa".repeat(33)));
    }

    /// T3 — zero active presence Devices → clear error pointing at enroll.
    #[test]
    fn resolve_authority_zero_active_presence_errors() {
        let devices = vec![
            presence_device("dev-1", &"aa".repeat(33), "revoked"),
            recovery_device("dev-recovery"),
        ];
        let err = resolve_authority_device_key(&devices, None).unwrap_err();
        match err {
            DeviceRevokeError::AuthorityInference(msg) => {
                assert!(
                    msg.contains("no active presence Device"),
                    "expected helpful enroll hint, got: {msg}"
                );
                assert!(
                    msg.contains("ember device enroll"),
                    "expected enroll-command hint, got: {msg}"
                );
            }
            other => panic!("expected AuthorityInference, got {other:?}"),
        }
    }

    /// T4 — 2+ active presence Devices → error lists the candidates so the
    /// operator can disambiguate. Recovery devices are filtered out.
    #[test]
    fn resolve_authority_multi_presence_errors_with_candidates() {
        let pk_a = "aa".repeat(33);
        let pk_b = "bb".repeat(33);
        let devices = vec![
            presence_device("dev-1", &pk_a, "active"),
            presence_device("dev-2", &pk_b, "active"),
            recovery_device("dev-recovery"),
        ];
        let err = resolve_authority_device_key(&devices, None).unwrap_err();
        match err {
            DeviceRevokeError::AuthorityInference(msg) => {
                assert!(
                    msg.contains("2 active presence Devices"),
                    "expected count, got: {msg}"
                );
                assert!(msg.contains("--authority-device-key"), "got: {msg}");
                assert!(msg.contains("dev-1"), "candidate A missing in: {msg}");
                assert!(msg.contains("dev-2"), "candidate B missing in: {msg}");
                assert!(msg.contains(&pk_a), "candidate A pubkey missing in: {msg}");
                assert!(msg.contains(&pk_b), "candidate B pubkey missing in: {msg}");
                // Recovery devices MUST NOT appear in the candidate list —
                // they cannot sign a revoke. (The daemon-side authorizer
                // refuses non-presence signers; surfacing them as
                // candidates would mislead the operator.)
                assert!(
                    !msg.contains("dev-recovery"),
                    "recovery devices must NOT be candidates: {msg}"
                );
            }
            other => panic!("expected AuthorityInference, got {other:?}"),
        }
    }

    /// T5 — revoked / frozen / replaced presence Devices are not candidates.
    #[test]
    fn resolve_authority_ignores_non_active_presence() {
        let active_pk = "cc".repeat(33);
        let devices = vec![
            presence_device("dev-active", &active_pk, "active"),
            presence_device("dev-revoked", &"aa".repeat(33), "revoked"),
            presence_device("dev-frozen", &"bb".repeat(33), "frozen"),
            presence_device("dev-replaced", &"dd".repeat(33), "replaced"),
        ];
        let resolved = resolve_authority_device_key(&devices, None).unwrap();
        assert_eq!(
            resolved,
            format!("p256:{}", active_pk),
            "only the active presence Device should be inferred"
        );
    }
}
