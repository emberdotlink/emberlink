//! `ember trust rotate <principal-id-or-label> [--reason STRING]` —
//! unified Principal rotation flow.
//!
//! ## Flow
//!
//! Per ADR 200 (2026-06-15 amendment) + ADR 162 §Component 3 (amended):
//! the operator names the Principal (a `did:key:...` id or a label such
//! as `@workstation` / `@operator`); the CLI resolves the target into a
//! concrete rotation flow and dispatches.
//!
//! For v0.3.0 the resolved flows are:
//!
//! - `@workstation` (or transitional alias `dev-identity-root`) →
//!   rotate the workstation Durable Persona by re-keying the
//!   `sh.emberlink.dev-identity-root` keychain entry and registering
//!   the rotation with the daemon via `trust.rotate_dev_ir`. Same
//!   mechanics as PR #6019; only the operator-facing vocabulary
//!   changes.
//!
//! - `@operator` → reserved; rejected with a structured error pointing
//!   at the slice-E daemon signing-paths work.
//!
//! - `did:key:...` → reserved; rejected with a structured error
//!   pointing at the slice-B grant-types work which carries the
//!   Principal directory needed for did:key resolution.
//!
//! - Anything else → `UnknownPrincipalLabel` structured error with the
//!   accepted-vocabulary list.
//!
//! ## Workstation Durable Persona flow (today's wired path)
//!
//! 1. Read the existing workstation Durable Persona signing seed from
//!    Keychain (must exist; if absent, refuse — operator should run
//!    `ember dev install` first).
//! 2. Refuse if a `.v2` slot already holds a key — a previous rotation
//!    didn't complete; route the operator to
//!    `ember recover authority --scope identity-root`.
//! 3. Touch ID gate confirming the rotation + grace window.
//! 4. Generate a fresh Ed25519 keypair; stash the seed in Keychain at
//!    `sh.emberlink.dev-identity-root.v2`. The pre-rotation key remains
//!    at `sh.emberlink.dev-identity-root` (the `.v1` slot).
//! 5. Re-sign the dev binary manifest with the new key (best-effort —
//!    skipped with a warning if no manifest path is present on this
//!    workstation).
//! 6. Register the rotation with the daemon via `trust.rotate_dev_ir`.
//!    The daemon adds it to the rotation registry, schedules the
//!    grace-window timer, and (asynchronously) emits the
//!    `trust.rotation` Receipt.
//! 7. Print an operator-facing summary with the kickstart instructions:
//!    update plist `EMBER_TRUST_ROOTS` to include both fingerprints
//!    (additive), then `sudo launchctl kickstart -k system/<label>` to
//!    pick up the new key.
//!
//! The plist rewrite + `launchctl kickstart` are NOT executed
//! automatically by this CLI — they require `sudo` and a host
//! filesystem write that is not safe to perform without a deliberate
//! operator action. The summary gives the exact command lines.
//!
//! ## Failure recovery
//!
//! Each step fails loudly with a structured error. If the
//! Keychain-stash succeeded but the daemon RPC failed, the operator
//! can retry — the daemon refuses duplicate `trust.rotate_dev_ir`
//! requests for the same new fingerprint with `RotationError::Duplicate`,
//! making the CLI safe to re-run. If the recovery is more involved,
//! `ember recover authority --scope identity-root` is the entry point.
//!

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::biometric::{BiometricError, BiometricOutcome, require_biometric};
use crate::dev::identity_root::fingerprint_of;
use crate::trust::backup::KEYCHAIN_SERVICE;


/// Canonical macOS Keychain label for the pre-rotation workstation
/// Durable Persona signing seed. Same label as
/// `crate::dev::identity_root::KEYCHAIN_LABEL`; restated here so the
/// rotation surface owns a typed constant and stays self-contained if
/// the dev module renames its label later.
pub const DEV_IR_KEYCHAIN_LABEL: &str = "sh.emberlink.dev-identity-root";

/// Canonical macOS Keychain label for the rotation target (`.v2`
/// slot). Per ADR 162 §Component 3 step 1.
pub const DEV_IR_V2_KEYCHAIN_LABEL: &str = "sh.emberlink.dev-identity-root.v2";

/// Default grace window (7 days). Mirrors the daemon-side
/// `DEFAULT_GRACE_WINDOW_SECS` so the CLI doesn't need to round-trip
/// to the daemon just to learn the default.
pub const DEFAULT_GRACE_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// Minimum grace window (1 hour). Mirror of the daemon-side floor.
pub const MIN_GRACE_WINDOW_SECS: u64 = 60 * 60;

/// Resolved target of `ember trust rotate <principal-id-or-label>`.
/// The CLI parses the operator-supplied string into one of these
/// variants before driving any I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalTarget {
    /// Workstation Durable Persona — the only flow wired in v0.3.0.
    /// Carries `migration_hint` when the operator typed the
    /// transitional `dev-identity-root` token instead of `@workstation`,
    /// so the outer CLI can print a single-line nudge without changing
    /// the rotation outcome.
    WorkstationDurablePersona { migration_hint: Option<String> },
    /// Operator-role Durable Persona — reserved; rotation lands in
    /// the slice-E daemon signing-paths work.
    OperatorDurablePersona,
    /// Self-parented root Principal addressed by did:key — reserved;
    /// resolution requires the Principal directory shipping in slice B
    /// (the grant-types work).
    RootPrincipalById { did_key: String },
}

/// Errors surfaced by `ember trust rotate <principal-id-or-label>`.
#[derive(Debug, thiserror::Error)]
pub enum TrustRotateError {
    /// The operator-supplied target didn't match any accepted label or
    /// id form. Carries the typed value so the error message can echo
    /// it.
    #[error(
        "unknown Principal label or id: '{got}' — accepted: \
         @workstation, @operator, did:key:..., or the transitional \
         alias 'dev-identity-root' (mapped to @workstation)"
    )]
    UnknownPrincipalLabel { got: String },
    /// Target resolved to a Principal whose rotation flow is not yet
    /// wired. Carries the resolved target and a pointer to the slice
    /// that owns it.
    #[error("rotation flow for {target} is not wired yet: {detail}")]
    PrincipalRotationNotWired {
        target: &'static str,
        detail: String,
    },
    /// Pre-rotation workstation Durable Persona seed is not present in
    /// Keychain.
    #[error(
        "workstation Durable Persona seed not found at {0}: \
         run `ember dev install` first"
    )]
    MissingWorkstationPersona(String),
    /// `.v2` slot already populated — a previous rotation didn't
    /// complete. Operator should run
    /// `ember recover authority --scope identity-root`.
    #[error(
        "rotation already in flight ({slot} already populated); \
         run `ember recover authority --scope identity-root` to clear"
    )]
    RotationInFlight { slot: String },
    /// Keychain error other than NotFound.
    #[error("Keychain error: {0}")]
    Keychain(String),
    /// Touch ID prompt cancelled or unavailable.
    #[error("biometric refused: {0}")]
    Biometric(String),
    /// OS entropy source failed during keypair generation.
    #[error("entropy failure during keypair generation: {0}")]
    Entropy(String),
    /// Grace window argument below the daemon floor.
    #[error("grace window {got}s is below floor {min}s")]
    GraceWindowTooShort { got: u64, min: u64 },
    /// Daemon socket unreachable or returned an RPC error.
    #[error("daemon error ({step}): {detail}")]
    Daemon { step: &'static str, detail: String },
    /// I/O failure during the manifest re-sign step.
    #[error("manifest re-sign I/O error: {0}")]
    ManifestIo(String),
}

/// Result returned by [`run_rotate_workstation_durable_persona`]. The
/// outer CLI layer turns it into stdout text + drives any subsequent
/// shell hints.
#[derive(Debug, Clone)]
pub struct RotateOutcome {
    /// Resolved Principal kind that was rotated. Used by the renderer
    /// to label the output with Principal / Durable Persona vocabulary
    /// rather than the legacy "IdentityRoot" surface.
    pub principal_kind: &'static str,
    /// Hex-lowercase fingerprint of the old (pre-rotation) Principal
    /// key.
    pub old_fingerprint_hex: String,
    /// Hex-lowercase fingerprint of the new (post-rotation) Principal
    /// key.
    pub new_fingerprint_hex: String,
    /// 64-char hex pubkey of the new key, in the wire form
    /// `EMBER_TRUST_ROOTS` expects (`hex(public_key_bytes)`).
    pub new_pubkey_hex: String,
    /// Unix seconds at which the grace window ends. Mirrored from the
    /// daemon's `trust.rotate_dev_ir` response so the operator can
    /// build a calendar entry.
    pub grace_window_end_secs: u64,
    /// Whether the Touch ID prompt fired (false = skipped via test
    /// gate or `--no-biometric`).
    pub biometric_verified: bool,
    /// Whether the dev manifest was re-signed under the new key
    /// (false = no manifest configured on this workstation; warned in
    /// stdout).
    pub manifest_resigned: bool,
    /// Operator-supplied rationale, echoed back from the daemon for
    /// the operator's records.
    pub reason: Option<String>,
    /// One-line migration hint emitted when the operator typed the
    /// transitional `dev-identity-root` token. Renderer prints it on a
    /// dedicated line so the rotation output stays grep-stable.
    pub migration_hint: Option<String>,
}

/// CLI entry point. Resolves the operator-supplied target, dispatches
/// to the matching rotation flow, and returns an exit code.
///
/// Exit codes:
/// - `0` — rotation registered successfully.
/// - `1` — operator-correctable error (rotation-in-flight, weak grace
///   window, missing workstation Durable Persona seed, unknown
///   Principal label, or a target whose flow is not wired yet).
/// - `2` — everything else (Keychain, biometric, entropy, daemon,
///   manifest I/O).
pub fn run(
    socket_path: &Path,
    target: &str,
    manifest_path: Option<&Path>,
    reason: Option<String>,
    grace_window_secs: Option<u64>,
    no_biometric: bool,
) -> i32 {
    let resolved = match resolve_principal_target(target) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("ember trust rotate: {err}");
            return 1;
        }
    };

    match resolved {
        PrincipalTarget::WorkstationDurablePersona { migration_hint } => {
            match run_rotate_workstation_durable_persona(
                socket_path,
                manifest_path,
                reason,
                grace_window_secs,
                no_biometric,
                migration_hint,
            ) {
                Ok(outcome) => {
                    print!("{}", render_outcome(&outcome));
                    0
                }
                Err(err) => {
                    eprintln!("ember trust rotate: {err}");
                    match err {
                        TrustRotateError::RotationInFlight { .. }
                        | TrustRotateError::GraceWindowTooShort { .. }
                        | TrustRotateError::MissingWorkstationPersona(_) => 1,
                        _ => 2,
                    }
                }
            }
        }
        PrincipalTarget::OperatorDurablePersona => {
            eprintln!(
                "ember trust rotate: {}",
                TrustRotateError::PrincipalRotationNotWired {
                    target: "operator-role Durable Persona",
                    detail:
                        "lands in ARCH-IDENTITY-ROOT-PERSONA-UNIFICATION-DAEMON-SIGNING-PATHS"
                            .to_string(),
                }
            );
            1
        }
        PrincipalTarget::RootPrincipalById { did_key } => {
            eprintln!(
                "ember trust rotate: {}",
                TrustRotateError::PrincipalRotationNotWired {
                    target: "root Principal by did:key",
                    detail: format!(
                        "Principal directory resolves '{did_key}' in \
                         ARCH-IDENTITY-ROOT-PERSONA-UNIFICATION-GRANT-TYPES"
                    ),
                }
            );
            1
        }
    }
}

/// Resolve the operator-supplied `<principal-id-or-label>` argument to
/// a typed [`PrincipalTarget`].
///
/// Accepted vocabulary (canonical):
/// - `@workstation` / `workstation` → workstation Durable Persona
/// - `@operator` / `operator` → operator-role Durable Persona
/// - `did:key:...` → self-parented root Principal by id
///
/// Accepted vocabulary (transitional aliases, mapped with migration
/// hint):
/// - `dev-identity-root` → workstation Durable Persona
///   (PR #6019 surface; preserved so existing scripts don't break, but
///   the migration hint nudges the operator toward `@workstation`)
///
/// Anything else returns `UnknownPrincipalLabel`.
pub fn resolve_principal_target(input: &str) -> Result<PrincipalTarget, TrustRotateError> {
    let trimmed = input.trim();
    match trimmed {
        "@workstation" | "workstation" => Ok(PrincipalTarget::WorkstationDurablePersona {
            migration_hint: None,
        }),
        "dev-identity-root" => Ok(PrincipalTarget::WorkstationDurablePersona {
            migration_hint: Some(
                "note: 'dev-identity-root' is a transitional alias; \
                 prefer '@workstation' (the workstation Durable Persona)"
                    .to_string(),
            ),
        }),
        "@operator" | "operator" => Ok(PrincipalTarget::OperatorDurablePersona),
        other if other.starts_with("did:key:") => Ok(PrincipalTarget::RootPrincipalById {
            did_key: other.to_string(),
        }),
        other => Err(TrustRotateError::UnknownPrincipalLabel {
            got: other.to_string(),
        }),
    }
}

/// End-to-end rotation flow for the workstation Durable Persona. Same
/// mechanics as PR #6019's `run_rotate_dev_ir`; only the operator-facing
/// vocabulary changes. Pure-ish — Keychain reads/writes and the daemon
/// RPC are real I/O, but the manifest re-sign step is gated on
/// `manifest_path.is_some()` so unit tests can run the flow without a
/// disk path.
pub fn run_rotate_workstation_durable_persona(
    socket_path: &Path,
    manifest_path: Option<&Path>,
    reason: Option<String>,
    grace_window_secs: Option<u64>,
    no_biometric: bool,
    migration_hint: Option<String>,
) -> Result<RotateOutcome, TrustRotateError> {
    let grace_window = grace_window_secs.unwrap_or(DEFAULT_GRACE_WINDOW_SECS);
    if grace_window < MIN_GRACE_WINDOW_SECS {
        return Err(TrustRotateError::GraceWindowTooShort {
            got: grace_window,
            min: MIN_GRACE_WINDOW_SECS,
        });
    }

    // Step 1: read existing workstation Durable Persona seed.
    let old_signing = read_existing_workstation_persona()?;
    let old_pubkey: VerifyingKey = old_signing.verifying_key();
    let old_fingerprint = fingerprint_of(&old_pubkey);

    // Step 2: refuse if .v2 slot is already populated.
    if v2_slot_populated()? {
        return Err(TrustRotateError::RotationInFlight {
            slot: DEV_IR_V2_KEYCHAIN_LABEL.to_string(),
        });
    }

    // Step 3: Touch ID gate.
    let biometric_outcome = require_biometric(
        &format!(
            "Rotate workstation Durable Persona (old key remains valid for ~{} days during grace window)",
            grace_window / (24 * 60 * 60)
        ),
        no_biometric,
    )
    .map_err(|e: BiometricError| TrustRotateError::Biometric(e.to_string()))?;
    let biometric_verified = matches!(biometric_outcome, BiometricOutcome::Verified { .. });

    // Step 4: generate fresh keypair + stash in .v2 slot.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| TrustRotateError::Entropy(format!("getrandom: {e}")))?;
    let new_signing = SigningKey::from_bytes(&seed);
    let new_pubkey: VerifyingKey = new_signing.verifying_key();
    let new_fingerprint = fingerprint_of(&new_pubkey);
    write_v2_slot(&seed)?;

    // Step 5: best-effort re-sign manifest. Skipped (with warning) if
    // no manifest_path was supplied — host workstations without a
    // managed manifest land in this branch.
    let manifest_resigned = if let Some(path) = manifest_path {
        if path.exists() {
            resign_manifest(path, &new_signing)?;
            true
        } else {
            eprintln!(
                "  [warn] manifest path {} does not exist; skipping re-sign step",
                path.display()
            );
            false
        }
    } else {
        false
    };

    // Step 6: register with daemon. v0.3.0 keeps the existing
    // `trust.rotate_dev_ir` RPC method name — the slice-E daemon
    // signing-paths work owns any daemon-side method-name change. The CLI surface is
    // already principal-shaped; the wire name is implementation
    // detail.
    let registry_resp = call_trust_rotate_dev_ir(
        socket_path,
        &old_fingerprint,
        &new_fingerprint,
        grace_window,
        reason.as_deref(),
    )?;
    let grace_window_end_secs = registry_resp
        .get("grace_window_end_secs")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| TrustRotateError::Daemon {
            step: "register",
            detail: "daemon response missing grace_window_end_secs".to_string(),
        })?;
    let echoed_reason = registry_resp
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(RotateOutcome {
        principal_kind: "workstation Durable Persona",
        old_fingerprint_hex: old_fingerprint,
        new_fingerprint_hex: new_fingerprint,
        new_pubkey_hex: hex::encode(new_pubkey.to_bytes()),
        grace_window_end_secs,
        biometric_verified,
        manifest_resigned,
        reason: echoed_reason,
        migration_hint,
    })
}

/// Read the existing workstation Durable Persona signing key from
/// Keychain. Returns `MissingWorkstationPersona` when the canonical
/// entry is absent — the operator should run `ember dev install` first.
fn read_existing_workstation_persona() -> Result<SigningKey, TrustRotateError> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, DEV_IR_KEYCHAIN_LABEL)
        .map_err(|e| TrustRotateError::Keychain(format!("open workstation persona entry: {e}")))?;
    match entry.get_password() {
        Ok(hex_seed) => decode_hex_seed(&hex_seed).map(|seed| SigningKey::from_bytes(&seed)),
        Err(keyring_core::Error::NoEntry) => Err(TrustRotateError::MissingWorkstationPersona(
            DEV_IR_KEYCHAIN_LABEL.to_string(),
        )),
        Err(e) => Err(TrustRotateError::Keychain(format!(
            "read workstation persona seed: {e}"
        ))),
    }
}

/// Check whether the `.v2` slot is already populated. Returns true
/// when a previous rotation attempt left the slot dirty.
fn v2_slot_populated() -> Result<bool, TrustRotateError> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, DEV_IR_V2_KEYCHAIN_LABEL)
        .map_err(|e| TrustRotateError::Keychain(format!("open .v2 entry: {e}")))?;
    match entry.get_password() {
        Ok(_) => Ok(true),
        Err(keyring_core::Error::NoEntry) => Ok(false),
        Err(e) => Err(TrustRotateError::Keychain(format!(
            "probe .v2 slot: {e}"
        ))),
    }
}

/// Write the new seed to the `.v2` slot. Returns Keychain failure on
/// any error.
fn write_v2_slot(seed: &[u8; 32]) -> Result<(), TrustRotateError> {
    let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, DEV_IR_V2_KEYCHAIN_LABEL)
        .map_err(|e| TrustRotateError::Keychain(format!("open .v2 entry: {e}")))?;
    entry
        .set_password(&hex::encode(seed))
        .map_err(|e| TrustRotateError::Keychain(format!("stash .v2 seed: {e}")))?;
    Ok(())
}

fn decode_hex_seed(hex_seed: &str) -> Result<[u8; 32], TrustRotateError> {
    let bytes = hex::decode(hex_seed.trim())
        .map_err(|e| TrustRotateError::Keychain(format!("seed not hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(TrustRotateError::Keychain(format!(
            "seed has wrong length: {} (expected 32)",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Re-sign the dev binary manifest at `path` with the new workstation
/// Durable Persona key. Writes both the TOML body (preserved verbatim)
/// and a fresh `<path>.sig` JSON sidecar in the shape
/// `binary_manifest::verify_manifest_signature_with_trust_roots`
/// expects.
fn resign_manifest(path: &Path, signer: &SigningKey) -> Result<(), TrustRotateError> {
    use ed25519_dalek::Signer as _;

    let body = std::fs::read(path)
        .map_err(|e| TrustRotateError::ManifestIo(format!("read {}: {e}", path.display())))?;
    let sig = signer.sign(&body);
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        sig.to_bytes(),
    );
    let sidecar = json!({
        "schema_version": 1,
        "signature": format!("ed25519:{sig_b64}"),
        "signature_alg": "ed25519",
    });
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar)
        .map_err(|e| TrustRotateError::ManifestIo(format!("sidecar serialize: {e}")))?;
    let sidecar_path = path.with_extension("toml.sig");
    std::fs::write(&sidecar_path, &sidecar_bytes).map_err(|e| {
        TrustRotateError::ManifestIo(format!("write {}: {e}", sidecar_path.display()))
    })?;
    Ok(())
}

/// Issue the `trust.rotate_dev_ir` RPC to the daemon. Returns the
/// decoded response body on success; surfaces structured errors on
/// socket failure or RPC error.
///
/// The method name stays `trust.rotate_dev_ir` for v0.3.0; the slice-E
/// daemon signing-paths work owns the daemon-side rename. The CLI calls this only after
/// resolving the operator-supplied target to a workstation Durable
/// Persona, so the wire payload is already Principal-shaped at the
/// caller boundary.
fn call_trust_rotate_dev_ir(
    socket_path: &Path,
    old_fingerprint_hex: &str,
    new_fingerprint_hex: &str,
    grace_window_secs: u64,
    reason: Option<&str>,
) -> Result<Value, TrustRotateError> {
    let mut params = serde_json::Map::new();
    params.insert(
        "old_fingerprint_hex".into(),
        Value::String(old_fingerprint_hex.to_string()),
    );
    params.insert(
        "new_fingerprint_hex".into(),
        Value::String(new_fingerprint_hex.to_string()),
    );
    params.insert(
        "grace_window_secs".into(),
        Value::Number(serde_json::Number::from(grace_window_secs)),
    );
    if let Some(r) = reason {
        params.insert("reason".into(), Value::String(r.to_string()));
    }
    call_daemon(socket_path, "trust.rotate_dev_ir", &Value::Object(params))
}

/// Generic JSON-RPC client helper. Lifted from `trust/list.rs`; not
/// shared into a common helper yet because the trust surfaces still
/// differ slightly in error renderings.
fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: &Value,
) -> Result<Value, TrustRotateError> {
    let stream = std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
        TrustRotateError::Daemon {
            step: "connect",
            detail: format!("{}: {e}", socket_path.display()),
        }
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| TrustRotateError::Daemon {
            step: "clone socket",
            detail: e.to_string(),
        })?;
    let mut reader = BufReader::new(stream);

    let request = json!({
        "id": "1",
        "method": method,
        "params": params,
    });
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');

    writer
        .write_all(line.as_bytes())
        .map_err(|e| TrustRotateError::Daemon {
            step: "write request",
            detail: e.to_string(),
        })?;

    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| TrustRotateError::Daemon {
            step: "read response",
            detail: e.to_string(),
        })?;

    let response: Value = serde_json::from_str(response_line.trim()).map_err(|e| {
        TrustRotateError::Daemon {
            step: "parse response",
            detail: format!("invalid JSON-RPC: {e}"),
        }
    })?;

    if let Some(err) = response.get("error").filter(|v| !v.is_null()) {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32000);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error")
            .to_string();
        return Err(TrustRotateError::Daemon {
            step: "rpc",
            detail: format!("code {code}: {message}"),
        });
    }

    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

/// Render the outcome as operator-facing stdout. Mirrors the
/// `trust backup` / `trust restore` rendering convention.
pub fn render_outcome(outcome: &RotateOutcome) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Principal rotation registered ({}):\n",
        outcome.principal_kind
    ));
    out.push_str(&format!(
        "  Old fingerprint:    {}\n",
        outcome.old_fingerprint_hex
    ));
    out.push_str(&format!(
        "  New fingerprint:    {}\n",
        outcome.new_fingerprint_hex
    ));
    out.push_str(&format!(
        "  New pubkey hex:     {}\n",
        outcome.new_pubkey_hex
    ));
    out.push_str(&format!(
        "  Grace window ends:  {} (unix seconds)\n",
        outcome.grace_window_end_secs
    ));
    out.push_str(&format!(
        "  Biometric verified: {}\n",
        outcome.biometric_verified
    ));
    out.push_str(&format!(
        "  Manifest re-signed: {}\n",
        outcome.manifest_resigned
    ));
    if let Some(reason) = &outcome.reason {
        out.push_str(&format!("  Reason:             {reason}\n"));
    }
    if let Some(hint) = &outcome.migration_hint {
        out.push_str(&format!("  {hint}\n"));
    }
    out.push('\n');
    out.push_str("Next steps:\n");
    out.push_str(
        "  1. Update the daemon plist's EMBER_TRUST_ROOTS to include both fingerprints \
         (additive — old + new).\n",
    );
    out.push_str(
        "  2. sudo launchctl kickstart -k system/sh.emberlink.daemon.dev to pick up the \
         new trust set.\n",
    );
    out.push_str(
        "  3. After the grace window expires, the daemon emits a trust.rotation_complete \
         Receipt and drops the old Principal key.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..32 {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    #[test]
    fn render_outcome_includes_both_fingerprints_and_kickstart_hint() {
        let outcome = RotateOutcome {
            principal_kind: "workstation Durable Persona",
            old_fingerprint_hex: "old-fp".to_string(),
            new_fingerprint_hex: "new-fp".to_string(),
            new_pubkey_hex: fp(0xAB),
            grace_window_end_secs: 1_700_000_000,
            biometric_verified: true,
            manifest_resigned: true,
            reason: Some("monthly rotation".to_string()),
            migration_hint: None,
        };
        let rendered = render_outcome(&outcome);
        assert!(rendered.contains("old-fp"));
        assert!(rendered.contains("new-fp"));
        assert!(rendered.contains(&fp(0xAB)));
        assert!(rendered.contains("1700000000"));
        assert!(rendered.contains("launchctl kickstart"));
        assert!(rendered.contains("EMBER_TRUST_ROOTS"));
        assert!(rendered.contains("monthly rotation"));
        assert!(rendered.contains("Principal rotation registered"));
        assert!(rendered.contains("workstation Durable Persona"));
        // Vocabulary check: target type must not be advertised as
        // IdentityRoot in the operator-facing surface.
        assert!(
            !rendered.contains("IdentityRoot"),
            "render_outcome must use Principal/Durable Persona vocabulary, not IdentityRoot"
        );
    }

    #[test]
    fn render_outcome_without_reason_omits_reason_line() {
        let outcome = RotateOutcome {
            principal_kind: "workstation Durable Persona",
            old_fingerprint_hex: "old".to_string(),
            new_fingerprint_hex: "new".to_string(),
            new_pubkey_hex: "abc".to_string(),
            grace_window_end_secs: 1_700_000_000,
            biometric_verified: false,
            manifest_resigned: false,
            reason: None,
            migration_hint: None,
        };
        let rendered = render_outcome(&outcome);
        assert!(!rendered.contains("Reason:"));
    }

    #[test]
    fn render_outcome_emits_migration_hint_line_when_present() {
        let outcome = RotateOutcome {
            principal_kind: "workstation Durable Persona",
            old_fingerprint_hex: "old".to_string(),
            new_fingerprint_hex: "new".to_string(),
            new_pubkey_hex: "abc".to_string(),
            grace_window_end_secs: 1_700_000_000,
            biometric_verified: false,
            manifest_resigned: false,
            reason: None,
            migration_hint: Some(
                "note: 'dev-identity-root' is a transitional alias; \
                 prefer '@workstation' (the workstation Durable Persona)"
                    .to_string(),
            ),
        };
        let rendered = render_outcome(&outcome);
        assert!(rendered.contains("transitional alias"));
        assert!(rendered.contains("@workstation"));
    }

    #[test]
    fn decode_hex_seed_round_trips() {
        let seed = [0x5au8; 32];
        let encoded = hex::encode(seed);
        let decoded = decode_hex_seed(&encoded).expect("decode must succeed");
        assert_eq!(decoded, seed);
    }

    #[test]
    fn decode_hex_seed_rejects_short_seed() {
        let err = decode_hex_seed("ab").expect_err("short seed must fail");
        match err {
            TrustRotateError::Keychain(msg) => {
                assert!(msg.contains("wrong length"));
            }
            other => panic!("expected Keychain error, got {other:?}"),
        }
    }

    #[test]
    fn decode_hex_seed_rejects_non_hex() {
        let err = decode_hex_seed("not-hex").expect_err("non-hex must fail");
        match err {
            TrustRotateError::Keychain(msg) => {
                assert!(msg.contains("seed not hex"));
            }
            other => panic!("expected Keychain error, got {other:?}"),
        }
    }

    #[test]
    fn run_rotate_workstation_durable_persona_rejects_grace_window_below_floor() {
        let socket = std::path::PathBuf::from("/tmp/nonexistent-socket-for-test");
        let err = run_rotate_workstation_durable_persona(&socket, None, None, Some(60), true, None)
            .expect_err("short grace window must fail before any I/O");
        match err {
            TrustRotateError::GraceWindowTooShort { got, min } => {
                assert_eq!(got, 60);
                assert_eq!(min, MIN_GRACE_WINDOW_SECS);
            }
            other => panic!("expected GraceWindowTooShort, got {other:?}"),
        }
    }

    #[test]
    fn resign_manifest_writes_sidecar_in_expected_shape() {
        use ed25519_dalek::SigningKey;
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("manifest.toml");
        std::fs::write(&manifest_path, b"[[binary]]\nname = \"gh\"\n").unwrap();

        let seed = [0x77u8; 32];
        let signer = SigningKey::from_bytes(&seed);

        resign_manifest(&manifest_path, &signer).expect("resign must succeed");

        let sidecar_path = manifest_path.with_extension("toml.sig");
        assert!(sidecar_path.exists());
        let sidecar_bytes = std::fs::read(&sidecar_path).unwrap();
        let sidecar: Value = serde_json::from_slice(&sidecar_bytes).unwrap();
        assert_eq!(sidecar["schema_version"], 1);
        assert_eq!(sidecar["signature_alg"], "ed25519");
        let sig = sidecar["signature"].as_str().unwrap();
        assert!(sig.starts_with("ed25519:"));
    }


    #[test]
    fn trust_rotate_accepts_principal_id_or_label() {
        // @workstation → workstation Durable Persona
        let resolved =
            resolve_principal_target("@workstation").expect("@workstation must resolve");
        assert_eq!(
            resolved,
            PrincipalTarget::WorkstationDurablePersona {
                migration_hint: None
            }
        );

        // bare 'workstation' is also accepted
        let resolved =
            resolve_principal_target("workstation").expect("bare workstation must resolve");
        assert_eq!(
            resolved,
            PrincipalTarget::WorkstationDurablePersona {
                migration_hint: None
            }
        );

        // @operator → operator-role Durable Persona
        let resolved = resolve_principal_target("@operator").expect("@operator must resolve");
        assert_eq!(resolved, PrincipalTarget::OperatorDurablePersona);

        // did:key id → root Principal by id
        let did = concat!(
            "did:",
            "key:",
            "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
        );
        let resolved = resolve_principal_target(did).expect("did:key must resolve");
        assert_eq!(
            resolved,
            PrincipalTarget::RootPrincipalById {
                did_key: did.to_string()
            }
        );

        // Whitespace trimming
        let resolved =
            resolve_principal_target("  @workstation  ").expect("whitespace must trim");
        assert_eq!(
            resolved,
            PrincipalTarget::WorkstationDurablePersona {
                migration_hint: None
            }
        );
    }

    #[test]
    fn trust_rotate_maps_or_rejects_dev_identity_root_with_migration_hint() {
        // PR #6019's transitional `dev-identity-root` token must NOT
        // be the target vocabulary. We accept it as a back-compat
        // alias mapped to the workstation Durable Persona, but emit a
        // structured migration hint that names the canonical token.
        let resolved = resolve_principal_target("dev-identity-root")
            .expect("dev-identity-root must resolve as transitional alias");
        match resolved {
            PrincipalTarget::WorkstationDurablePersona { migration_hint } => {
                let hint = migration_hint
                    .expect("transitional alias must carry a migration hint");
                assert!(
                    hint.contains("@workstation"),
                    "migration hint must point at canonical @workstation token, got: {hint}"
                );
                assert!(
                    hint.contains("transitional"),
                    "migration hint must name the alias as transitional, got: {hint}"
                );
                // Vocabulary: must use Durable Persona, not
                // IdentityRoot.
                assert!(
                    hint.contains("Durable Persona"),
                    "migration hint must use Durable Persona vocabulary, got: {hint}"
                );
                assert!(
                    !hint.contains("IdentityRoot"),
                    "migration hint must NOT advertise IdentityRoot, got: {hint}"
                );
            }
            other => panic!(
                "dev-identity-root must map to workstation Durable Persona with hint, got {other:?}"
            ),
        }
    }

    #[test]
    fn trust_rotate_unknown_principal_label_fails_structured() {
        let err = resolve_principal_target("bogus-label").expect_err("unknown label must fail");
        match err {
            TrustRotateError::UnknownPrincipalLabel { ref got } => {
                assert_eq!(got, "bogus-label");
                // Error message must surface accepted vocabulary so the
                // operator can self-correct without reading source.
                let rendered = err.to_string();
                assert!(rendered.contains("@workstation"));
                assert!(rendered.contains("@operator"));
                assert!(rendered.contains("did:key:"));
                assert!(rendered.contains("dev-identity-root"));
            }
            other => panic!("expected UnknownPrincipalLabel, got {other:?}"),
        }
    }

    #[test]
    fn trust_rotate_operator_target_reports_not_wired_with_slice_pointer() {
        // The operator-role Durable Persona resolves cleanly, but its
        // rotation flow lives in slice E. The error must name the
        // slice so an operator who hits it can find the right task.
        let resolved = resolve_principal_target("@operator").expect("@operator must resolve");
        assert_eq!(resolved, PrincipalTarget::OperatorDurablePersona);

        // Build the error the run() dispatch arm would emit and check
        // its rendering.
        let err = TrustRotateError::PrincipalRotationNotWired {
            target: "operator-role Durable Persona",
            detail:
                "lands in ARCH-IDENTITY-ROOT-PERSONA-UNIFICATION-DAEMON-SIGNING-PATHS"
                    .to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("operator-role Durable Persona"));
        assert!(rendered.contains("ARCH-IDENTITY-ROOT-PERSONA-UNIFICATION-DAEMON-SIGNING-PATHS"));
    }
}
