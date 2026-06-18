//! `ember` CLI binary.
//!
//! open_store_mutator_audit_complete
//!
//! Audit of every `open_store(config)` call site in this file.
//! Under ADR 131
//! separate-uid posture (daemon=ember uid, operator=operator uid) the daemon
//! owns the SQLite DB and the operator cannot open it for writing — so
//! every direct-store *mutator* call site needs to route through the
//! daemon's JSON-RPC socket instead. Read-only paths are tolerable for
//! local-dev convenience but should also migrate in time.
//!
//! Classification key (search "open-store-audit" to find each site):
//!   * READ-ONLY: only invokes read methods on the store.
//!   * MUTATOR: invokes a store method that writes the DB AND the daemon
//!     already exposes an equivalent RPC.
//!   * MUTATOR-NO-RPC: invokes a store-write method with no existing
//!     daemon RPC; needs a daemon-side handler before the call site can
//!     migrate.
//!   * MUTATOR-MIXED: sub-action match where some arms are read-only and
//!     others mutate; migrate per-arm.
//!
//! Current migration state: `GrantAction::{Create,List,Revoke,Expire,Extend,Budget,Delegate}`,
//! daemon-present `VaultAction::{List,Get,Add,Put,Export,Import,Remove,Lock,Unlock}`,
//! installed-path `ReceiptAction::{List,Show,Export,Verify(id-mode)}`,
//! installed-path `AuditAction::Query`,
//! installed-path `ApprovalAction::{List,Approve,Deny,Narrow}`,
//! installed-path `Commands::Status`,
//! plain `ember init`, regular `SandboxAction::{Create,List,Stop,Delete,Exec}`,
//! and the daemon-owned sandbox/grant orchestration half of `SandboxAction::Run`
//! route through the daemon socket. The main remaining mixed operator surface is
//! the local prompt handoff in `SandboxAction::Run` and `SandboxAction::RunScion`.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, IsTerminal, Read, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use base64::Engine as _;
use clap::{Arg, ArgAction, Command as ClapCommand, CommandFactory, Parser, ValueEnum};
use core_grant_types::{
    AccessGrant, Budget, Condition, GrantProposal, ResourceSelector, ResourceType, Statement,
    StatementProposal,
};
use ember_daemon::infra::audit::{
    AuditFilter, RepairIntent, canonical_repair_intent_bytes, verify_repair_intent_signature,
};
use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::image_registry::ImageRegistry;
use ember_daemon::infra::runtime::{
    DaemonRuntime, DashboardBind, GitProxyBind, LlmProxyBind, StartupBinds,
};
use ember_daemon::infra::sandbox::{
    SandboxCreateOpts, SandboxCreateResult, SandboxDeleteResult, SandboxInfo,
    SandboxRunGrantDisposition, SandboxRunResult,
};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{
    DEFAULT_KEYRING_ACCOUNT, DEFAULT_KEYRING_SERVICE, Vault, VaultScope, resolve_keyring_account,
    resolve_keyring_service, validate_credential_name,
};
use ember_daemon::trust::approval::ApprovalOutcome;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[path = "ember/args.rs"]
mod args;
#[path = "daemon_agent.rs"]
mod daemon_agent;
#[path = "ember/github.rs"]
mod github;
#[path = "ember/grant.rs"]
mod grant;
#[path = "ember/help.rs"]
mod help;
#[path = "ember/launcher.rs"]
mod launcher;
#[path = "ember/render.rs"]
mod render;
#[path = "ember/sandbox.rs"]
mod sandbox;
#[path = "ember/status.rs"]
mod status;
#[path = "ember/vault.rs"]
mod vault;

use args::*;
use github::*;
use grant::*;
use help::*;
use launcher::*;
use render::*;
use sandbox::*;
use status::*;
use vault::*;

/// Render the version string consumed by `ember --version`, `ember -V`, and
/// `ember version`.
///
/// Format: `ember <semver> (<git-sha-or-(no-git)>) built <rfc3339-utc>`.
///
/// A prior vault AEAD-decrypt failure had its root cause in a
/// `v0.2.0` binary running against the `v0.2.17` codebase. Embedding the git
/// SHA + build timestamp at compile time makes "is the running binary
/// stale?" a five-second `--version` check.
fn print_version() -> String {
    format!(
        "ember {} ({}) built {}",
        env!("CARGO_PKG_VERSION"),
        env!("EMBERLINK_GIT_SHA"),
        env!("EMBERLINK_BUILD_TIMESTAMP"),
    )
}

fn is_top_level_version_request(raw_args: &[String]) -> bool {
    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--version" | "-V" => return true,
            "--json" | "--quiet" | "--verbose" | "--no-input" | "--yes" | "-y" => {
                i += 1;
            }
            "--config" | "--color" => {
                i += 2;
            }
            arg if arg.starts_with("--config=") || arg.starts_with("--color=") => {
                i += 1;
            }
            _ => return false,
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusActionDispatch {
    DaemonRpc,
    LocalFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GithubHttpsLane {
    ConfiguredApp,
    ConfiguredPat,
    ConfiguredMock,
    Broken,
    NotConfigured,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct GithubProviderStatusView {
    lane: String,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    app_id: Option<String>,
    #[serde(default)]
    installation_id: Option<String>,
}

/// `ember device enroll` — the operator-bootstrap ceremony (ADR 200 §5, §6).
///
/// Capability flows from the device class enrolled (ADR 200 amendment
/// 2026-06-12); there is no orthogonal `--presence` / `--recovery-only`
/// flag. The chosen subcommand/flag IS the capability declaration:
///
/// - `--secure-enclave` → `presence` class (signs + KEK_s recipient)
/// - `--external-signer` (legacy `--device-key`) → `presence` class
/// - `--recovery-code` → `recovery` class (KEK_s recipient only)
///
/// **Default behavior** (no flags): on macOS with a signed binary that
/// has real SE support, behaves as `--secure-enclave` (the dev0 floor —
/// secure path == convenient path). On non-macOS or unsigned builds, emits
/// a clear error pointing at `--secure-enclave` / `--external-signer` /
/// `--recovery-code`.
#[allow(clippy::too_many_arguments)]
fn run_device_enroll(
    device_key: Option<&str>,
    encryption_key: Option<&str>,
    label: &str,
    backup: bool,
    authority_device_key: Option<&str>,
    secure_enclave: bool,
    se_label: &str,
    no_provision: bool,
    ac2_card: Option<&Path>,
    operator_signature_hex: &[String],
    external_signer: bool,
    recovery_code: bool,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    if recovery_code {
        // Recovery class: KEK_s recipient only, no signing. Authorized by
        // the existing presence device. macOS-only at v0.3.0 because the
        // authorizer reads the operator's SE signing key (ADR 206 §6).
        return run_device_enroll_recovery_code(se_label, label, ac2_card, json_output);
    }
    if backup {
        let device_key = device_key.ok_or_else(|| {
            core_types::ValidationError::new(
                "ember device enroll --backup: --device-key is required for the backup device",
            )
        })?;
        let encryption_key = encryption_key.ok_or_else(|| {
            core_types::ValidationError::new(
                "ember device enroll --backup: --encryption-key is required for the backup device",
            )
        })?;
        if !external_signer && operator_signature_hex.is_empty() {
            if secure_enclave || se_default_available() {
                return run_device_enroll_backup_secure_enclave(
                    authority_device_key,
                    device_key,
                    encryption_key,
                    label,
                    se_label,
                    ac2_card,
                    json_output,
                );
            }
            return Err(core_types::ValidationError::new(
                "ember device enroll --backup: the default SE authority-signing lane is unavailable \
                 (unsigned/non-macOS build or no real Secure Enclave backend). Pass \
                 --external-signer with --authority-device-key and the prepared \
                 --operator-signature-hex from the existing presence device.",
            ));
        }
        let authority_device_key = authority_device_key.ok_or_else(|| {
            core_types::ValidationError::new(
                "ember device enroll --backup: --authority-device-key is required with \
                 --external-signer",
            )
        })?;
        return run_device_enroll_backup_manual(
            authority_device_key,
            device_key,
            encryption_key,
            label,
            ac2_card,
            operator_signature_hex,
            json_output,
        );
    }
    if secure_enclave && (device_key.is_some() || encryption_key.is_some()) {
        return Err(core_types::ValidationError::new(
            "ember device enroll --secure-enclave derives signing and encryption keys from \
             the Secure Enclave; do not pass --device-key or --encryption-key unless \
             enrolling a backup device or using --external-signer",
        ));
    }
    // Default-SE swap: bare `ember device enroll` on macOS with a signed
    // binary picks up `--secure-enclave` automatically. Operator-provided
    // `--external-signer` or `--device-key` opts out (explicit signer
    // selection wins over the convenience default).
    let want_se = secure_enclave
        || (device_key.is_none()
            && encryption_key.is_none()
            && operator_signature_hex.is_empty()
            && !external_signer
            && se_default_available());
    if want_se {
        return run_device_enroll_secure_enclave(
            label,
            se_label,
            no_provision,
            ac2_card,
            json_output,
        );
    }
    let device_key = device_key.ok_or_else(|| {
        core_types::ValidationError::new(
            "ember device enroll: --device-key is required in --external-signer mode; \
             pass --secure-enclave for the SE flow, --external-signer with --device-key \
             for an off-host signer, or --recovery-code to enroll a printed recovery code",
        )
    })?;
    let encryption_key = encryption_key.ok_or_else(|| {
        core_types::ValidationError::new(
            "ember device enroll: --encryption-key (the §4 ECIES recipient, distinct from \
             --device-key) is required in --external-signer mode",
        )
    })?;
    run_device_enroll_manual(
        device_key,
        encryption_key,
        label,
        ac2_card,
        operator_signature_hex,
        json_output,
    )
}

fn infer_device_enroll_external_signer(
    backup: bool,
    device_key_present: bool,
    operator_signature_present: bool,
    external_signer_flag: bool,
) -> bool {
    external_signer_flag || operator_signature_present || (!backup && device_key_present)
}

/// Return true if this binary can run `--secure-enclave` without explicit
/// opt-in (macOS + signed binary with real SE support). On unsigned builds
/// `se_backend_is_real()` returns false even on macOS, so the default-SE
/// swap silently falls through to the explicit-flag error — never binds a
/// software key as a presence device.
#[cfg(target_os = "macos")]
fn se_default_available() -> bool {
    ember_broker::secure_enclave::se_backend_is_real()
}

#[cfg(not(target_os = "macos"))]
fn se_default_available() -> bool {
    false
}

/// Current AC-2 card schema. v2 (2026-06-12) replaces `device_role` with
/// `device_class` — capabilities flow from custody class (presence / recovery /
/// co-authority / container), not an orthogonal primary/backup label. v1 cards
/// emitted before this change still verify under
/// `read_ac2_oob_confirmation_card` via the v1→v2 migration: `device_role:
/// "primary"|"backup"` maps to `device_class: "presence"`, and the original
/// digest is re-verified under the v1 digest input shape.
const AC2_OOB_CARD_SCHEMA_V2: &str = "emberlink.ac2_oob_confirmation.v2";
const AC2_OOB_CARD_SCHEMA_V1: &str = "emberlink.ac2_oob_confirmation.v1";
const AC2_OOB_CARD_SCHEMA: &str = AC2_OOB_CARD_SCHEMA_V2;
const AC2_PRESENCE_CEREMONY: &str = "identity.device.enroll";
const AC2_BACKUP_CEREMONY_LEGACY_V1: &str = "identity.device.enroll_backup";
const AC2_RECOVERY_CEREMONY: &str = "identity.recovery.enroll";

/// AC-2 OOB confirmation card (v2 schema).
///
/// **v2 (2026-06-12)** — `device_class` replaces `device_role`. Capabilities
/// flow from the custody class (per ADR 200 §1 + the 2026-06-12 amendment):
/// `presence` (signs + KEK_s recipient), `recovery` (KEK_s recipient only),
/// `co-authority` (co-authority lane signer; v0.3.1+), `container` (per-spawn
/// cert key). The v1 "primary"|"backup" naming is retired — both first and
/// additional presence devices carry `device_class: "presence"`.
///
/// **v1 → v2 migration** — `read_ac2_oob_confirmation_card` accepts both
/// schemas. A v1 card with `device_role: "primary"|"backup"` is mapped to
/// `device_class: "presence"`, the v1 digest is re-verified under its original
/// pre-image (`schema=v1`, `device_role=…`), and the in-memory representation
/// surfaces the migrated class. The on-disk file is NOT rewritten — operator
/// holds the artifact they keep — so an external verifier on either schema
/// continues to round-trip.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Ac2OobConfirmationCard {
    schema: String,
    ceremony: String,
    /// **v2 field** — `"presence"` | `"recovery"` | `"co-authority"` |
    /// `"container"`. Capability is intrinsic to the class.
    device_class: String,
    operator_root_id: String,
    operator_root_pubkey: String,
    device_id: String,
    device_label: String,
    device_pubkey: String,
    device_encryption_pubkey: String,
    confirmation_sha256: String,
}

fn operator_oob_ids_from_device_key(
    device_key: &str,
) -> Result<(String, String), core_types::ValidationError> {
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(device_key.to_string())) {
        return Err(core_types::ValidationError::new(
            "AC-2 confirmation card: device_key is not a valid p256:<sec1-hex> public key",
        ));
    }
    let pubkey_hex = device_key.strip_prefix("p256:").unwrap_or(device_key);
    Ok((
        format!("root-operator-{pubkey_hex}"),
        format!("device-operator-{pubkey_hex}"),
    ))
}

/// Build the v2 digest pre-image. v1 has its own pre-image generator
/// (`ac2_card_digest_input_v1`) used only for legacy verification.
// Digest pre-image builder — each field is a distinct signed input, structurally many params.
#[allow(clippy::too_many_arguments)]
fn ac2_card_digest_input(
    ceremony: &str,
    device_class: &str,
    operator_root_id: &str,
    operator_root_pubkey: &str,
    device_id: &str,
    device_label: &str,
    device_pubkey: &str,
    device_encryption_pubkey: &str,
) -> String {
    format!(
        "schema={AC2_OOB_CARD_SCHEMA_V2}\n\
         ceremony={ceremony}\n\
         device_class={device_class}\n\
         operator_root_id={operator_root_id}\n\
         operator_root_pubkey={operator_root_pubkey}\n\
         device_id={device_id}\n\
         device_label={device_label}\n\
         device_pubkey={device_pubkey}\n\
         device_encryption_pubkey={device_encryption_pubkey}\n"
    )
}

/// Build the v1 digest pre-image — used only to verify legacy v1 cards. The
/// v1 schema string and `device_role=` field are required to round-trip the
/// confirmation_sha256 the v1 builder originally produced.
// Digest pre-image builder — each field is a distinct signed input, structurally many params.
#[allow(clippy::too_many_arguments)]
fn ac2_card_digest_input_v1(
    ceremony: &str,
    device_role: &str,
    operator_root_id: &str,
    operator_root_pubkey: &str,
    device_id: &str,
    device_label: &str,
    device_pubkey: &str,
    device_encryption_pubkey: &str,
) -> String {
    format!(
        "schema={AC2_OOB_CARD_SCHEMA_V1}\n\
         ceremony={ceremony}\n\
         device_role={device_role}\n\
         operator_root_id={operator_root_id}\n\
         operator_root_pubkey={operator_root_pubkey}\n\
         device_id={device_id}\n\
         device_label={device_label}\n\
         device_pubkey={device_pubkey}\n\
         device_encryption_pubkey={device_encryption_pubkey}\n"
    )
}

/// Map a v2 `device_class` to the daemon ceremony the AC-2 card binds to.
/// Recovery cards bind the `identity.recovery.enroll` ceremony (ADR 206 §6);
/// presence cards bind `identity.device.enroll` (ADR 200 §5). co-authority and
/// container are reserved for v0.3.1+ — refused at build time today (no
/// v0.3.0 CLI verb mints them) but the verifier accepts them so a future card
/// is forward-compatible.
fn ac2_ceremony_for_class(device_class: &str) -> Result<&'static str, core_types::ValidationError> {
    match device_class {
        "presence" => Ok(AC2_PRESENCE_CEREMONY),
        "recovery" => Ok(AC2_RECOVERY_CEREMONY),
        _ => Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card: unsupported device_class {device_class}"
        ))),
    }
}

/// v1 → v2 device_class migration. v1 cards encoded `device_role` as one of
/// `"primary"|"backup"`; both correspond to a presence-class device in the v2
/// model. (Recovery cards did not exist in v1.) Returns the v1 ceremony so
/// the caller can re-verify the legacy digest.
fn ac2_v1_device_role_to_v2_class(
    device_role: &str,
) -> Result<(&'static str, &'static str), core_types::ValidationError> {
    match device_role {
        "primary" => Ok(("presence", AC2_PRESENCE_CEREMONY)),
        "backup" => Ok(("presence", AC2_BACKUP_CEREMONY_LEGACY_V1)),
        _ => Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card v1: unsupported device_role {device_role}"
        ))),
    }
}

/// Build a v2 AC-2 confirmation card. `device_class` is one of `"presence"` or
/// `"recovery"` at v0.3.0 (co-authority + container are reserved for v0.3.1+).
///
/// For `presence`, all three keys (`operator_root_pubkey`, `device_key`,
/// `encryption_key`) are p256 wire-form and `device_key != encryption_key`
/// (ADR 206 §4 sign/encrypt split). For `recovery`, `device_key == encryption_key`
/// (both record the same `age1…` recipient) and they are NOT p256 — the
/// recovery key never signs (ADR 206 §6), so we skip the p256 well-formedness
/// check on those slots and accept the `age1…` recipient as-is. The
/// `operator_root_pubkey` is still the operator-presence p256 root.
fn build_ac2_oob_confirmation_card(
    enroll_result: &serde_json::Value,
    device_class: &'static str,
    device_label: &str,
    operator_root_pubkey: &str,
    device_key: &str,
    encryption_key: &str,
) -> Result<Ac2OobConfirmationCard, core_types::ValidationError> {
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
        operator_root_pubkey.to_string(),
    )) {
        return Err(core_types::ValidationError::new(
            "AC-2 confirmation card: operator_root_pubkey is not a valid p256:<sec1-hex> public key",
        ));
    }
    match device_class {
        "presence" => {
            if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
                encryption_key.to_string(),
            )) {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: encryption_key is not a valid p256:<sec1-hex> public key",
                ));
            }
            if encryption_key.eq_ignore_ascii_case(device_key) {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: device_key and encryption_key must be distinct \
                     for presence devices (ADR 206 §4 sign/encrypt split)",
                ));
            }
        }
        "recovery" => {
            // Recovery cards record a single age x25519 recipient in both
            // `device_pubkey` and `device_encryption_pubkey` slots — the key
            // never signs (ADR 206 §6). The shape is `age1…`, not p256, so the
            // p256 well-formedness check above does not apply.
            if device_key != encryption_key {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: recovery class records the same age recipient \
                     in device_pubkey and device_encryption_pubkey (ADR 206 §6)",
                ));
            }
            if !device_key.starts_with("age1") {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: recovery class device_pubkey must be an age1… recipient",
                ));
            }
        }
        other => {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card: unsupported device_class {other} for v0.3.0 enrollment"
            )));
        }
    }
    let ceremony = ac2_ceremony_for_class(device_class)?;

    let (expected_root_id, _) = operator_oob_ids_from_device_key(operator_root_pubkey)?;
    let returned_root_id = enroll_result
        .get("operator_root_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "AC-2 confirmation card: enroll result missing operator_root_id",
            )
        })?;
    let returned_device_id = enroll_result
        .get("device_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "AC-2 confirmation card: enroll result missing device_id",
            )
        })?;
    if returned_root_id != expected_root_id {
        return Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card: daemon returned operator_root_id {returned_root_id}, \
             expected {expected_root_id} derived from the operator-held device pubkey"
        )));
    }
    // For presence, device_id is derived from the device's p256 pubkey;
    // for recovery, device_id is the daemon-side `operator_recovery_device_id`
    // built from the age recipient — we accept whatever the daemon returned
    // (it is bound into the digest, so substitution is still detected).
    let expected_device_id = if device_class == "presence" {
        let (_, derived) = operator_oob_ids_from_device_key(device_key)?;
        if returned_device_id != derived {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card: daemon returned device_id {returned_device_id}, \
                 expected {derived} derived from the operator-held device pubkey"
            )));
        }
        derived
    } else {
        returned_device_id.to_string()
    };

    let digest_input = ac2_card_digest_input(
        ceremony,
        device_class,
        &expected_root_id,
        operator_root_pubkey,
        &expected_device_id,
        device_label,
        device_key,
        encryption_key,
    );
    let confirmation_sha256 = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(digest_input.as_bytes()))
    };

    Ok(Ac2OobConfirmationCard {
        schema: AC2_OOB_CARD_SCHEMA.to_string(),
        ceremony: ceremony.to_string(),
        device_class: device_class.to_string(),
        operator_root_id: expected_root_id,
        operator_root_pubkey: operator_root_pubkey.to_string(),
        device_id: expected_device_id,
        device_label: device_label.to_string(),
        device_pubkey: device_key.to_string(),
        device_encryption_pubkey: encryption_key.to_string(),
        confirmation_sha256,
    })
}

/// One AC-2 card, normalized to the v2 representation, plus a stash of the
/// raw v1 fields (`schema` + `device_role`) so the legacy digest can be
/// re-verified against the original v1 pre-image. v2 cards have
/// `legacy_v1 = None` and round-trip directly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedAc2Card {
    card: Ac2OobConfirmationCard,
    /// `Some(device_role)` when the on-disk file was a v1 card; the verifier
    /// recomputes the v1 digest using that role + the v1 schema string. None
    /// for native v2 cards.
    legacy_v1_device_role: Option<String>,
}

/// Read an operator-held AC-2 confirmation card from disk.
///
/// The card is the operator-held artifact an independent verifier checks
/// against the daemon's enrollment receipt (ADR 200 §5 / AC-2). Accepts both
/// v1 (pre-2026-06-12) and v2 (current) schemas; v1 cards are migrated
/// in-memory to the v2 shape (`device_role: "primary"|"backup"` →
/// `device_class: "presence"`) but the on-disk file is NOT rewritten — the
/// operator's stored artifact remains the original v1 file. Every
/// load-bearing check lives in `verify_ac2_oob_confirmation_card`; the reader
/// itself is plain JSON deserialization so an external verifier re-running
/// the same logic does NOT rely on the file format being trusted.
fn read_ac2_oob_confirmation_card(
    path: &Path,
) -> Result<LoadedAc2Card, core_types::ValidationError> {
    let bytes = fs::read(path).map_err(|e| {
        core_types::ValidationError::new(format!(
            "AC-2 confirmation card: read {} failed: {e}",
            path.display()
        ))
    })?;
    parse_ac2_oob_confirmation_card_bytes(&bytes).map_err(|e| {
        core_types::ValidationError::new(format!(
            "AC-2 confirmation card: parse {} failed: {e}",
            path.display()
        ))
    })
}

/// Pure JSON parser for an AC-2 card. Extracted so unit tests can exercise
/// the v1/v2 migration without touching the filesystem.
fn parse_ac2_oob_confirmation_card_bytes(
    bytes: &[u8],
) -> Result<LoadedAc2Card, core_types::ValidationError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| core_types::ValidationError::new(format!("decode AC-2 card JSON: {e}")))?;
    let schema = raw.get("schema").and_then(|v| v.as_str()).ok_or_else(|| {
        core_types::ValidationError::new("AC-2 confirmation card: missing schema")
    })?;
    match schema {
        AC2_OOB_CARD_SCHEMA_V2 => {
            let card: Ac2OobConfirmationCard = serde_json::from_value(raw).map_err(|e| {
                core_types::ValidationError::new(format!("decode v2 AC-2 card: {e}"))
            })?;
            Ok(LoadedAc2Card {
                card,
                legacy_v1_device_role: None,
            })
        }
        AC2_OOB_CARD_SCHEMA_V1 => {
            // v1: `device_role` is the operative field; we map it to v2's
            // `device_class` ("primary" or "backup" → "presence") but keep the
            // v1 schema string + ceremony + role for the digest re-check.
            let device_role = raw
                .get("device_role")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    core_types::ValidationError::new(
                        "AC-2 confirmation card v1: missing device_role",
                    )
                })?
                .to_string();
            let (v2_class, _) = ac2_v1_device_role_to_v2_class(&device_role)?;
            let card = Ac2OobConfirmationCard {
                schema: AC2_OOB_CARD_SCHEMA_V1.to_string(),
                ceremony: raw
                    .get("ceremony")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_class: v2_class.to_string(),
                operator_root_id: raw
                    .get("operator_root_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                operator_root_pubkey: raw
                    .get("operator_root_pubkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_id: raw
                    .get("device_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_label: raw
                    .get("device_label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_pubkey: raw
                    .get("device_pubkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                device_encryption_pubkey: raw
                    .get("device_encryption_pubkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                confirmation_sha256: raw
                    .get("confirmation_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            Ok(LoadedAc2Card {
                card,
                legacy_v1_device_role: Some(device_role),
            })
        }
        other => Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card: unsupported schema {other} \
             (expected {AC2_OOB_CARD_SCHEMA_V2} or {AC2_OOB_CARD_SCHEMA_V1})",
        ))),
    }
}

/// Verify an AC-2 confirmation card is internally consistent against the
/// digest the operator-side `ember device enroll --ac2-card` builder would
/// have produced. This is the independent-verifier path (ADR 200 AC-1/AC-2).
///
/// All checks are reproducible from the card alone — no daemon state, no
/// network, no live keystore. A pubkey presented solely by the daemon is
/// NOT trusted; the digest binds `(schema, ceremony, device_class, ids,
/// pubkeys)` and is re-computed from those fields.
///
/// v1 cards are accepted via the legacy code path: the digest is recomputed
/// over the v1 pre-image (`schema=v1`, `device_role=…`), but the in-memory
/// shape exposes the migrated `device_class: "presence"`. This means an
/// independent verifier with the operator's pre-2026-06-12 cards continues to
/// validate after this change ships.
fn verify_ac2_oob_confirmation_card(
    loaded: &LoadedAc2Card,
) -> Result<(), core_types::ValidationError> {
    let card = &loaded.card;
    // ── Per-class shape checks (apply to both v1 and v2 cards). ─────────
    match card.device_class.as_str() {
        "presence" => {
            if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
                card.device_pubkey.clone(),
            )) {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: device_pubkey is not a valid p256:<sec1-hex> public key",
                ));
            }
            if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
                card.device_encryption_pubkey.clone(),
            )) {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: device_encryption_pubkey is not a valid p256:<sec1-hex> public key",
                ));
            }
            if card
                .device_pubkey
                .eq_ignore_ascii_case(&card.device_encryption_pubkey)
            {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: device_pubkey and device_encryption_pubkey must be distinct (ADR 206 §4 sign/encrypt split)",
                ));
            }
            let (_, expected_device_id) = operator_oob_ids_from_device_key(&card.device_pubkey)?;
            if card.device_id != expected_device_id {
                return Err(core_types::ValidationError::new(format!(
                    "AC-2 confirmation card: device_id {} does not match {expected_device_id} derived from device_pubkey",
                    card.device_id
                )));
            }
        }
        "recovery" => {
            if card.device_pubkey != card.device_encryption_pubkey {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: recovery class records the same age recipient \
                     in device_pubkey and device_encryption_pubkey (ADR 206 §6)",
                ));
            }
            if !card.device_pubkey.starts_with("age1") {
                return Err(core_types::ValidationError::new(
                    "AC-2 confirmation card: recovery class device_pubkey must be an age1… recipient",
                ));
            }
        }
        other => {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card: unsupported device_class {other}"
            )));
        }
    }
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
        card.operator_root_pubkey.clone(),
    )) {
        return Err(core_types::ValidationError::new(
            "AC-2 confirmation card: operator_root_pubkey is not a valid p256:<sec1-hex> public key",
        ));
    }
    let (expected_root_id, _) = operator_oob_ids_from_device_key(&card.operator_root_pubkey)?;
    if card.operator_root_id != expected_root_id {
        return Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card: operator_root_id {} does not match {expected_root_id} derived from operator_root_pubkey",
            card.operator_root_id
        )));
    }

    // ── Ceremony / digest checks branch on schema version. ──────────────
    let expected_digest = if let Some(v1_role) = loaded.legacy_v1_device_role.as_deref() {
        // Legacy v1 card. Verify against the v1 pre-image (schema=v1,
        // device_role=role) and the v1 ceremony→role mapping. We already
        // mapped the in-memory `device_class` to "presence" at parse time.
        let (_, expected_ceremony) = ac2_v1_device_role_to_v2_class(v1_role)?;
        if card.ceremony != expected_ceremony {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card v1: ceremony {} does not match expected {expected_ceremony} for device_role={v1_role}",
                card.ceremony
            )));
        }
        if card.schema != AC2_OOB_CARD_SCHEMA_V1 {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card v1: schema {} not {AC2_OOB_CARD_SCHEMA_V1}",
                card.schema
            )));
        }
        let digest_input = ac2_card_digest_input_v1(
            &card.ceremony,
            v1_role,
            &card.operator_root_id,
            &card.operator_root_pubkey,
            &card.device_id,
            &card.device_label,
            &card.device_pubkey,
            &card.device_encryption_pubkey,
        );
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(digest_input.as_bytes()))
    } else {
        if card.schema != AC2_OOB_CARD_SCHEMA_V2 {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card: schema {} does not match expected {AC2_OOB_CARD_SCHEMA_V2}",
                card.schema
            )));
        }
        let expected_ceremony = ac2_ceremony_for_class(&card.device_class)?;
        if card.ceremony != expected_ceremony {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card: ceremony {} does not match expected {expected_ceremony} for device_class={}",
                card.ceremony, card.device_class
            )));
        }
        let digest_input = ac2_card_digest_input(
            &card.ceremony,
            &card.device_class,
            &card.operator_root_id,
            &card.operator_root_pubkey,
            &card.device_id,
            &card.device_label,
            &card.device_pubkey,
            &card.device_encryption_pubkey,
        );
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(digest_input.as_bytes()))
    };
    if !card
        .confirmation_sha256
        .eq_ignore_ascii_case(&expected_digest)
    {
        return Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card: confirmation_sha256 {} does not match recomputed {expected_digest}",
            card.confirmation_sha256
        )));
    }
    Ok(())
}

/// Cross-check a pair of AC-2 cards (ADR 200 §5 / §6 C9): both must claim
/// the same operator root and carry distinct hardware/recipient keys.
///
/// **v2 semantics (capability-from-class):** at v0.3.0, the supported pair
/// shapes are (presence, presence) — the dev0 1-of-2 hardware floor — and
/// (presence, recovery) — one presence device + a recovery code. v1 cards
/// arrive normalized to `device_class: "presence"` regardless of their v1
/// primary/backup role, so a (v1-primary, v1-backup) load looks like
/// (presence, presence) here.
fn cross_check_ac2_oob_confirmation_card_pair(
    first: &Ac2OobConfirmationCard,
    second: &Ac2OobConfirmationCard,
) -> Result<(), core_types::ValidationError> {
    if first.operator_root_id != second.operator_root_id {
        return Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card pair: operator_root_id mismatch — first={} second={}",
            first.operator_root_id, second.operator_root_id
        )));
    }
    if first.operator_root_pubkey != second.operator_root_pubkey {
        return Err(core_types::ValidationError::new(format!(
            "AC-2 confirmation card pair: operator_root_pubkey mismatch — first={} second={}",
            first.operator_root_pubkey, second.operator_root_pubkey
        )));
    }
    match (first.device_class.as_str(), second.device_class.as_str()) {
        ("presence", "presence") | ("presence", "recovery") | ("recovery", "presence") => {}
        (a, b) => {
            return Err(core_types::ValidationError::new(format!(
                "AC-2 confirmation card pair: device_class pair ({a}, {b}) is not supported \
                 (expected presence+presence or presence+recovery)"
            )));
        }
    }
    if first.device_pubkey == second.device_pubkey {
        return Err(core_types::ValidationError::new(
            "AC-2 confirmation card pair: cards share device_pubkey — must be distinct hardware keys / recipients",
        ));
    }
    Ok(())
}

fn write_ac2_oob_confirmation_card(
    path: &Path,
    card: &Ac2OobConfirmationCard,
) -> Result<(), core_types::ValidationError> {
    let bytes = serde_json::to_vec_pretty(card).map_err(|e| {
        core_types::ValidationError::new(format!("AC-2 confirmation card: encode failed: {e}"))
    })?;
    fs::write(path, bytes).map_err(|e| {
        core_types::ValidationError::new(format!(
            "AC-2 confirmation card: write {} failed: {e}",
            path.display()
        ))
    })
}

/// Wrapper that builds a `device_class: "recovery"` AC-2 card for the
/// `ember device enroll --recovery-code` surface. The recovery recipient
/// pubkey (`age1…`) is recorded in BOTH the `device_pubkey` and
/// `device_encryption_pubkey` slots (ADR 206 §6).
fn build_ac2_oob_confirmation_card_for_recovery(
    enroll_result: &serde_json::Value,
    device_label: &str,
    operator_root_pubkey: &str,
    recovery_age_pubkey: &str,
) -> Result<Ac2OobConfirmationCard, core_types::ValidationError> {
    build_ac2_oob_confirmation_card(
        enroll_result,
        "recovery",
        device_label,
        operator_root_pubkey,
        recovery_age_pubkey,
        recovery_age_pubkey,
    )
}

fn print_ac2_oob_confirmation_card(card: &Ac2OobConfirmationCard, path: Option<&Path>) {
    println!();
    println!("AC-2 out-of-band confirmation card");
    if let Some(path) = path {
        println!("  path:                    {}", path.display());
    }
    println!("  schema:                  {}", card.schema);
    println!("  device_class:            {}", card.device_class);
    println!("  operator_root_id:        {}", card.operator_root_id);
    println!("  operator_root_pubkey:    {}", card.operator_root_pubkey);
    println!("  device_id:               {}", card.device_id);
    println!("  device_pubkey:           {}", card.device_pubkey);
    println!(
        "  device_encryption_pubkey: {}",
        card.device_encryption_pubkey
    );
    println!("  confirmation_sha256:     {}", card.confirmation_sha256);
    println!("  Store this outside daemon-controlled storage; a daemon-only copy is not AC-2.");
}

/// Verify one or two operator-held AC-2 confirmation cards against the
/// digest each card carries (ADR 200 AC-2 / §6 C9). Fail-closed on any
/// mismatch; on success, print a one-line confirmation per card.
///
/// Closes the V030-PRESENCE-AC2 buildout follow-up "decide whether to add a
/// standalone operator-facing 'verify AC-2 cards' command or keep card
/// verification as a operator-runbook/manual proof" (P23-S3 checkpoint
/// 2026-06-05, item 2).
fn run_device_verify_ac2_cards(
    paths: &[PathBuf],
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    if paths.is_empty() || paths.len() > 2 {
        return Err(core_types::ValidationError::new(
            "ember device verify-ac2-cards: supply one card (primary OR backup) or two cards (primary AND backup)",
        ));
    }
    let mut loaded: Vec<(PathBuf, LoadedAc2Card)> = Vec::with_capacity(paths.len());
    for path in paths {
        let card = read_ac2_oob_confirmation_card(path)?;
        verify_ac2_oob_confirmation_card(&card)?;
        loaded.push((path.clone(), card));
    }
    if loaded.len() == 2 {
        cross_check_ac2_oob_confirmation_card_pair(&loaded[0].1.card, &loaded[1].1.card)?;
    }

    if json_output {
        let mut entries: Vec<serde_json::Value> = Vec::with_capacity(loaded.len());
        for (path, loaded_card) in &loaded {
            let card = &loaded_card.card;
            entries.push(serde_json::json!({
                "path": path.display().to_string(),
                "schema": card.schema,
                "device_class": card.device_class,
                "operator_root_id": card.operator_root_id,
                "device_id": card.device_id,
                "confirmation_sha256": card.confirmation_sha256,
                "verified": true,
                "legacy_v1": loaded_card.legacy_v1_device_role.is_some(),
            }));
        }
        let pair_verified = loaded.len() == 2;
        let report = serde_json::json!({
            "schema": "emberlink.ac2_oob_verify.v1",
            "cards": entries,
            "pair_verified": pair_verified,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| {
                core_types::ValidationError::new(format!(
                    "verify-ac2-cards: encode JSON report failed: {e}"
                ))
            })?
        );
    } else {
        println!();
        for (path, loaded_card) in &loaded {
            let card = &loaded_card.card;
            let legacy_note = if loaded_card.legacy_v1_device_role.is_some() {
                " [legacy v1; migrated to device_class=presence in-memory]"
            } else {
                ""
            };
            println!(
                "OK {} ({}) device_id={} confirmation_sha256={}{legacy_note}",
                path.display(),
                card.device_class,
                card.device_id,
                card.confirmation_sha256
            );
        }
        if loaded.len() == 2 {
            println!(
                "OK pair operator_root_id={}",
                loaded[0].1.card.operator_root_id
            );
        } else {
            println!(
                "NOTE only one card verified; supply two cards (presence+presence, or presence+recovery) for the pair check"
            );
        }
    }
    Ok(())
}

/// PR #5684 companion — emit the canonical bytes the operator co-signs for
/// an `audit_repair_chain` intent (ADR 174 v2 §4 / ADR 200 §6). The bytes
/// are JCS-style (`canonical_repair_intent_bytes` is the daemon-side
/// trust path; this CLI helper just hex-prints what that function returns
/// so the operator can pipe them into off-host PIV/SE signing tools).
///
/// The companion ceremony lives in `docs/runbooks/ac2-oob-proof-ceremony.md`
/// (audit co-sign section).
fn run_audit_canonical_repair_intent(
    from_row: i64,
    tip_hash: &str,
    daemon_fingerprint: &str,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    if tip_hash.is_empty() {
        return Err(core_types::ValidationError::new(
            "audit canonical-repair-intent: --tip-hash must not be empty",
        ));
    }
    if daemon_fingerprint.is_empty() {
        return Err(core_types::ValidationError::new(
            "audit canonical-repair-intent: --daemon-fingerprint must not be empty",
        ));
    }
    let bytes = canonical_repair_intent_bytes(from_row, tip_hash, daemon_fingerprint);
    let hex_bytes = hex::encode(&bytes);
    let sha256_hex = {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    let blake3_hex = blake3::hash(&bytes).to_hex().to_string();

    if json_output {
        let report = serde_json::json!({
            "schema": "emberlink.audit_repair_intent_canonical.v1",
            "from_row_id": from_row,
            "current_chain_tip_hash": tip_hash,
            "daemon_identity_root_fingerprint": daemon_fingerprint,
            "canonical_bytes_hex": hex_bytes,
            "canonical_bytes_len": bytes.len(),
            "sha256_hex": sha256_hex,
            "blake3_hex": blake3_hex,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| {
                core_types::ValidationError::new(format!(
                    "audit canonical-repair-intent: encode JSON: {e}"
                ))
            })?
        );
    } else {
        println!();
        println!("Audit repair-intent canonical bytes");
        println!("  from_row_id:                      {from_row}");
        println!("  current_chain_tip_hash:           {tip_hash}");
        println!("  daemon_identity_root_fingerprint: {daemon_fingerprint}");
        println!("  canonical_bytes_len:              {}", bytes.len());
        println!("  canonical_bytes_hex:              {hex_bytes}");
        println!("  sha256_hex:                       {sha256_hex}");
        println!("  blake3_hex:                       {blake3_hex}");
        println!();
        println!("Sign these bytes off-host with the presence Device, e.g.:");
        println!("  printf %s {hex_bytes} | xxd -r -p | \\");
        println!("    yubico-piv-tool -a verify -a sign-data -A ECCP256 -s 9c \\");
        println!("    --hash SHA256 -i - -o - | xxd -p | tr -d '\\n'");
        println!(
            "Then submit (operator_signature_hex, operator_pubkey) with `audit_repair_chain`."
        );
    }
    Ok(())
}

/// PR #5684 companion — offline-verify a `RepairIntent` JSON against one
/// or more enrolled presence-Device pubkeys (`p256:<sec1-hex>`). Mirrors
/// the daemon-side `verify_repair_intent_signature` so the operator can
/// confirm a co-signature is structurally valid against the same
/// canonical bytes BEFORE submission, and an independent verifier can
/// re-check a stored RepairIntent without daemon access.
///
/// The daemon-side gate is still the trust source (it verifies against the
/// daemon-MATERIALIZED presence set, not the caller-supplied pubkeys); this
/// helper is the operator-held cross-check. Pass primary AND backup AC-2
/// pubkeys to mirror the 1-of-N presence set.
fn run_audit_verify_repair_intent(
    intent_path: &Path,
    presence_pubkeys: &[String],
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    if presence_pubkeys.is_empty() {
        return Err(core_types::ValidationError::new(
            "audit verify-repair-intent: at least one --presence-pubkey is required",
        ));
    }
    for pk in presence_pubkeys {
        if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(pk.clone())) {
            return Err(core_types::ValidationError::new(format!(
                "audit verify-repair-intent: --presence-pubkey {pk} is not a valid p256:<sec1-hex> public key"
            )));
        }
    }

    let bytes = fs::read(intent_path).map_err(|e| {
        core_types::ValidationError::new(format!(
            "audit verify-repair-intent: read {} failed: {e}",
            intent_path.display()
        ))
    })?;
    let intent: RepairIntent = serde_json::from_slice(&bytes).map_err(|e| {
        core_types::ValidationError::new(format!(
            "audit verify-repair-intent: parse {} as RepairIntent failed: {e}",
            intent_path.display()
        ))
    })?;

    // The daemon-side trust path takes &[(device_id, pubkey)] — synthesize
    // the same shape using the same device_id derivation the AC-2 cards use.
    // The daemon NEVER trusts this caller-supplied tuple; this is the
    // OPERATOR's cross-check that a sig will match the expected device_id
    // before submission.
    let mut candidates: Vec<(String, String)> = Vec::with_capacity(presence_pubkeys.len());
    for pk in presence_pubkeys {
        let (_, device_id) = operator_oob_ids_from_device_key(pk)?;
        candidates.push((device_id, pk.clone()));
    }

    match verify_repair_intent_signature(&intent, &candidates) {
        Ok(cosigner) => {
            if json_output {
                let report = serde_json::json!({
                    "schema": "emberlink.audit_repair_intent_verify.v1",
                    "intent_path": intent_path.display().to_string(),
                    "verified": true,
                    "signing_device_id": cosigner.signing_device_id,
                    "signing_device_pubkey": cosigner.signing_device_pubkey,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| {
                        core_types::ValidationError::new(format!(
                            "audit verify-repair-intent: encode JSON: {e}"
                        ))
                    })?
                );
            } else {
                println!();
                println!(
                    "OK {} sig verifies under presence device_id={} pubkey={}",
                    intent_path.display(),
                    cosigner.signing_device_id,
                    cosigner.signing_device_pubkey
                );
            }
            Ok(())
        }
        Err(_) => Err(core_types::ValidationError::new(format!(
            "audit verify-repair-intent: signature did not verify against any of the {} supplied presence pubkey(s)",
            presence_pubkeys.len()
        ))),
    }
}

/// Secure-Enclave one-shot enrollment (the dev0 presence floor). Finds-or-creates
/// a Touch-ID-gated SE P-256 key, derives the device pubkey from it, then drives
/// the daemon `identity.device.enroll` RPC prepare → SE-sign-each-blob → commit.
/// The daemon never sees the private key; each genesis/enroll event is signed by a
/// Touch ID tap on the Secure Enclave.
#[cfg(target_os = "macos")]
fn run_device_enroll_secure_enclave(
    label: &str,
    se_label: &str,
    no_provision: bool,
    ac2_card_path: Option<&Path>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    // SAFETY GATE: never bind a SOFTWARE key as a presence device. Without the
    // real SE backend the keygen returns an exportable stub key — enrolling it
    // would defeat ADR 200's hardware-presence property. Fail closed.
    if !se::se_backend_is_real() {
        return Err(core_types::ValidationError::new(
            "ember device enroll --secure-enclave: this binary lacks real Secure Enclave support \
             (built without the `se-real` feature / not a signed binary with the SE entitlement). \
             Refusing to enroll a software key as a presence device. Use a signed release build, \
             or enroll an off-host device via manual --operator-signature-hex.",
        ));
    }

    // Find-or-create the operator presence key (persistent DPK key, presence-gated).
    let key = match se::find_secure_enclave_key(se_label) {
        Ok(k) => k,
        // dev0 presence floor = `.userPresence` (Apple-native user presence):
        // biometric WHEN available, else device passcode / Apple Watch. This works
        // on EVERY Mac form factor — Mac mini / Studio / Pro have no biometric
        // sensor, and a clamshelled laptop has Touch ID unavailable; a
        // `.biometryCurrentSet` (biometric-only) key would be unusable there. It
        // also matches the enrollment event's recorded `presence_factor: UserPresence`.
        // (Stricter per-tier biometric requirements are a team0+/policy override,
        // not the dev0 floor.)
        Err(_) => se::generate_secure_enclave_key_with_policy(
            se_label,
            se::SeKeychainTarget::SystemKeychain,
            se::SeAccessPolicy::UserPresence,
        )
        .map_err(|e| {
            core_types::ValidationError::new(format!(
                "ember device enroll --secure-enclave: SE keygen failed: {e}"
            ))
        })?,
    };
    // This is the enrolled §1 presence SIGNING key (ADR 206 AC-3): carry the
    // sign role in the type so it can never be passed to a §4 ECIES operation.
    let key = se::SignKeyHandle::from_provisioned(key);

    let pub_bytes = key.public_key_bytes().map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --secure-enclave: SE pubkey export failed: {e}"
        ))
    })?;
    let device_key = format!("p256:{}", hex::encode(&pub_bytes));

    // ADR 206 §4: provision a SECOND, DISTINCT SE key as the §4 ECIES recipient
    // so presence-as-decryption can seal scope KEKs to this device. macOS SE
    // cannot enforce sign-vs-decrypt usage on one key (AC-3), so we keep two
    // physical keys: the signing key above and this ECIES recipient. It MUST be
    // `UserPresence`-gated, NOT Headless — `se_unwrap` only prompts for a tap if
    // the key's access control requires presence; a Headless ECIES key would
    // decrypt silently and void §4. This key is enrolled (its pubkey recorded as
    // the device's encryption_key) but NOT signed-over for §1 — it is purely the
    // recipient. Slice 4 wires the actual seal/open through it.
    let ecies_label = format!("{se_label}-ecies");
    let ecies_se_key = match se::find_secure_enclave_key(&ecies_label) {
        Ok(k) => k,
        Err(_) => se::generate_secure_enclave_key_with_policy(
            &ecies_label,
            se::SeKeychainTarget::SystemKeychain,
            se::SeAccessPolicy::UserPresence,
        )
        .map_err(|e| {
            core_types::ValidationError::new(format!(
                "ember device enroll --secure-enclave: §4 ECIES SE keygen failed: {e}"
            ))
        })?,
    };
    // Tag the role at the type boundary (slice 1): this label is an ECIES
    // recipient, never a signing key.
    let _ecies_role = se::EciesKeyLabel::from_provisioned(ecies_label);
    let ecies_pub_bytes = se::se_pubkey_bytes(&ecies_se_key).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --secure-enclave: §4 ECIES pubkey export failed: {e}"
        ))
    })?;
    let encryption_key = format!("p256:{}", hex::encode(&ecies_pub_bytes));

    // Defensive: the daemon also refuses this, but fail fast client-side before a
    // wasted Touch ID ceremony if the two SE keys somehow collide. Case-insensitive
    // so a hex-case difference can't mask a physically identical key.
    if encryption_key.eq_ignore_ascii_case(&device_key) {
        return Err(core_types::ValidationError::new(
            "ember device enroll --secure-enclave: signing and ECIES keys must be distinct \
             (ADR 206 §4) — the SE returned the same public key for both labels",
        ));
    }

    let socket_path = emberlink_cli::daemon_socket_path();

    // PREPARE: ask the daemon for the exact bytes to sign (authoritative; no
    // client/daemon divergence). Uses the read-only `identity.device.enroll_plan`
    // method (ConnectOnly) — it mutates nothing and holds no key, so it must NOT
    // trigger a daemon native-unlock Touch ID tap. Only the COMMIT call below
    // (`identity.device.enroll`, OperatorPresence) is a mutation.
    let prepared = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.device.enroll_plan",
        &serde_json::json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
        }),
    )?;
    let to_sign = prepared
        .get("to_sign")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if to_sign.is_empty() {
        return Err(core_types::ValidationError::new(
            "ember device enroll --secure-enclave: daemon returned an empty signing plan",
        ));
    }

    // SIGN every ceremony blob under ONE Touch ID tap. Device enrollment is a
    // single operator intent (root + persona + device), so its N events ride one
    // presence evaluation via `se_sign_batch` (one LAContext, per-intent reuse
    // window) — not N separate taps. The daemon verifies each signature over the
    // DOMAIN-SEPARATED message (`sign_with_context(DOMAIN_EVENT, …)`), not the raw
    // pre-image, so we reproduce those exact bytes via `context_message` before
    // signing; diverging would fail closed at the daemon's append-time check.
    println!(
        "Touch ID required: signing {} ceremony step(s) on the Secure Enclave (one tap)…",
        to_sign.len()
    );
    let mut messages: Vec<Vec<u8>> = Vec::with_capacity(to_sign.len());
    for step in &to_sign {
        let bytes_hex = step
            .get("bytes_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "ember device enroll: malformed signing step (no bytes_hex)",
                )
            })?;
        let bytes = hex::decode(bytes_hex).map_err(|e| {
            core_types::ValidationError::new(format!(
                "ember device enroll: bad bytes_hex from daemon: {e}"
            ))
        })?;
        messages.push(core_crypto::context_message(
            core_crypto::DOMAIN_EVENT,
            &bytes,
        ));
    }
    let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let signatures: Vec<String> = se::se_sign_batch(
        &key,
        se::SingleIntent::new(&message_refs),
        "Authenticate to enroll this device as your Emberlink operator presence device",
    )
    .map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --secure-enclave: SE signing failed (Touch ID declined or key unavailable): {e}"
        ))
    })?
    .iter()
    .map(hex::encode)
    .collect();

    // COMMIT: the daemon appends + verifies the genesis/enroll events.
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.device.enroll",
        &serde_json::json!({
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
            "signatures": signatures,
        }),
    )?;
    let ac2_card = build_ac2_oob_confirmation_card(
        &result,
        "presence",
        label,
        &device_key,
        &device_key,
        &encryption_key,
    )?;
    if let Some(path) = ac2_card_path {
        write_ac2_oob_confirmation_card(path, &ac2_card)?;
    }

    if json_output {
        let mut output = result.clone();
        output["ac2_oob_confirmation"] =
            serde_json::to_value(&ac2_card).unwrap_or(serde_json::Value::Null);
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        // ADR 206 §4: a presence-device enroll is a single command that leaves
        // §4 custody active. Auto-provision via the SAME shared seam the
        // standalone `vault se-provision` command uses, reusing the SE keys we
        // just created (no re-derivation drift). The §4 provision is a clean-
        // break re-point of any prior custody — intended for the dev0 sole
        // operator. `--no-provision` opts out for the rare manual-cutover case.
        if !no_provision {
            provision_vault_se_scope_kek(se_label, json_output)?;
        }
        return Ok(());
    }
    let device_id = result
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    let root_id = result
        .get("operator_root_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    println!("Enrolled operator presence device (Secure Enclave, Touch ID).");
    println!("  device_id:        {device_id}");
    println!("  operator_root_id: {root_id}");
    println!("  device_key:       {device_key}");
    println!("  encryption_key:   {encryption_key}");
    print_ac2_oob_confirmation_card(&ac2_card, ac2_card_path);

    // ADR 206 §4: chain the presence-as-decryption custody provision so a
    // single `device enroll --secure-enclave` leaves §4 custody active. Reuses
    // the same shared seam (and the SE keys created above), so the enroll and
    // standalone `vault se-provision` paths can never drift. The §4 provision
    // cleanly re-points any pre-§4 vault custody — intended dev0 cutover.
    if !no_provision {
        provision_vault_se_scope_kek(se_label, json_output)?;
        println!();
        println!("ADR 206 §4 presence custody is now active.");
        println!("  Any pre-§4 vault custody was re-pointed to this presence device.");
        println!("  `ember vault se-unlock` is the per-window Touch ID tap going forward.");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_device_enroll_secure_enclave(
    _label: &str,
    _se_label: &str,
    _no_provision: bool,
    _ac2_card_path: Option<&Path>,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember device enroll --secure-enclave is only available on macOS; \
         use --external-signer with an off-host signer on this platform",
    ))
}

/// SE-authorized backup-device enrollment. The backup Device's public signing
/// and ECIES keys are supplied by the operator; the already-enrolled local
/// Secure Enclave presence key signs the daemon's backup-enroll plan in one
/// Touch ID gesture. The daemon still verifies the signature at COMMIT and
/// never receives either private key.
#[cfg(target_os = "macos")]
fn run_device_enroll_backup_secure_enclave(
    authority_device_key: Option<&str>,
    device_key: &str,
    encryption_key: &str,
    label: &str,
    se_label: &str,
    ac2_card_path: Option<&Path>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    use ember_broker::secure_enclave as se;

    if !se::se_backend_is_real() {
        return Err(core_types::ValidationError::new(
            "ember device enroll --backup: this binary lacks real Secure Enclave support \
             (built without the `se-real` feature / unsigned). Use --external-signer \
             with --operator-signature-hex from the existing presence device.",
        ));
    }

    let raw_sign = se::find_secure_enclave_key(se_label).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --backup: SE signing key '{se_label}' not found — \
             enroll the primary presence device first via `ember device enroll --secure-enclave`: {e}"
        ))
    })?;
    let se_sign_pub = se::se_pubkey_bytes(&raw_sign).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --backup: read SE signing pubkey: {e}"
        ))
    })?;
    let se_authority_key = format!("p256:{}", hex::encode(&se_sign_pub));
    let resolved_authority = match authority_device_key {
        Some(explicit) => {
            if !explicit.eq_ignore_ascii_case(&se_authority_key) {
                return Err(core_types::ValidationError::new(format!(
                    "ember device enroll --backup: --authority-device-key {explicit} does not \
                     match this host's SE signing key {se_authority_key}. Use the host that holds \
                     the matching authority key, omit --authority-device-key, or use \
                     --external-signer."
                )));
            }
            explicit.to_string()
        }
        None => se_authority_key,
    };
    let sign_key = se::SignKeyHandle::from_provisioned(raw_sign);
    let socket_path = emberlink_cli::daemon_socket_path();

    let prepared = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.device.enroll_backup_plan",
        &serde_json::json!({
            "authority_device_key": resolved_authority,
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
        }),
    )?;
    let to_sign = prepared
        .get("to_sign")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if to_sign.len() != 1 {
        return Err(core_types::ValidationError::new(format!(
            "ember device enroll --backup: daemon returned {} signing step(s), expected 1",
            to_sign.len()
        )));
    }
    let bytes_hex = to_sign[0]
        .get("bytes_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "ember device enroll --backup: malformed signing step (no bytes_hex)",
            )
        })?;
    let bytes = hex::decode(bytes_hex).map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --backup: bad bytes_hex from daemon: {e}"
        ))
    })?;

    println!("Touch ID required: signing the backup-device enrollment on the Secure Enclave…");
    let message = core_crypto::context_message(core_crypto::DOMAIN_EVENT, &bytes);
    let message_refs: Vec<&[u8]> = vec![message.as_slice()];
    let signatures = se::se_sign_batch(
        &sign_key,
        se::SingleIntent::new(&message_refs),
        "Authenticate to enroll a backup Emberlink operator presence device",
    )
    .map_err(|e| {
        core_types::ValidationError::new(format!(
            "ember device enroll --backup: SE signing failed (Touch ID declined or key unavailable): {e}"
        ))
    })?;
    let der_hex = hex::encode(&signatures[0]);

    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "identity.device.enroll_backup",
        &serde_json::json!({
            "authority_device_key": resolved_authority,
            "device_key": device_key,
            "encryption_key": encryption_key,
            "device_label": label,
            "signatures": [der_hex],
        }),
    )?;
    if result.get("mode").and_then(|m| m.as_str()) != Some("committed") {
        return Err(core_types::ValidationError::new(
            "ember device enroll --backup: daemon COMMIT did not return mode=\"committed\"",
        ));
    }

    let ac2_card = build_ac2_oob_confirmation_card(
        &result,
        "presence",
        label,
        &resolved_authority,
        device_key,
        encryption_key,
    )?;
    if let Some(path) = ac2_card_path {
        write_ac2_oob_confirmation_card(path, &ac2_card)?;
    }

    if json_output {
        let mut output = result.clone();
        output["ac2_oob_confirmation"] =
            serde_json::to_value(&ac2_card).unwrap_or(serde_json::Value::Null);
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return Ok(());
    }

    let device_id = result
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    let root_id = result
        .get("operator_root_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    println!("Enrolled backup operator presence device.");
    println!("  device_id:        {device_id}");
    println!("  operator_root_id: {root_id}");
    println!("  authority_key:    {resolved_authority}");
    print_ac2_oob_confirmation_card(&ac2_card, ac2_card_path);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn run_device_enroll_backup_secure_enclave(
    _authority_device_key: Option<&str>,
    _device_key: &str,
    _encryption_key: &str,
    _label: &str,
    _se_label: &str,
    _ac2_card_path: Option<&Path>,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember device enroll --backup: the SE authority-signing lane is only available on macOS; \
         use --external-signer with --operator-signature-hex on this platform",
    ))
}

/// `ember device enroll --recovery-code` — enroll a printed recovery code as
/// a `recovery`-class device (ADR 206 §6). Shares one implementation with
/// `ember vault enroll-recovery` (the consumer-side surface that already
/// shipped): the device surface is the same daemon flow plus an AC-2 card.
/// Capability: KEK_s recipient ONLY. Never signs. The age x25519 secret is
/// shown ONCE in this session and never written to disk; the daemon never
/// holds it (ADR 206 §6 finding C3).
///
/// macOS-only at v0.3.0: the authorizer reads the operator's SE signing key
/// to sign the recovery-recipient enrollment (the daemon never holds the
/// authorizer either).
#[cfg(target_os = "macos")]
fn run_device_enroll_recovery_code(
    se_label: &str,
    label: &str,
    ac2_card_path: Option<&Path>,
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    run_device_recovery_code_enroll(se_label, label, ac2_card_path, json_output)
}

#[cfg(not(target_os = "macos"))]
fn run_device_enroll_recovery_code(
    _se_label: &str,
    _label: &str,
    _ac2_card_path: Option<&Path>,
    _json_output: bool,
) -> Result<(), core_types::ValidationError> {
    Err(core_types::ValidationError::new(
        "ember device enroll --recovery-code (ADR 206 §6) is only available on macOS \
         (the authorizing presence device is a Secure Enclave key)",
    ))
}

/// Manual two-call OOB flow against the `identity.device.enroll` daemon RPC
/// (off-host signer, e.g. YubiKey/PKCS#11), because the daemon must never hold
/// the operator's presence-device key:
///
/// * No signatures → PREPARE: the daemon returns the exact bytes to sign off-host
///   (one blob per genesis/enroll step). We print each blob's hex + purpose.
/// * Signatures supplied → COMMIT: the daemon appends + verifies the genesis and
///   device-enroll events and returns the enrolled `device_id`.
fn run_device_enroll_manual(
    device_key: &str,
    encryption_key: &str,
    label: &str,
    ac2_card_path: Option<&Path>,
    operator_signature_hex: &[String],
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    let socket_path = emberlink_cli::daemon_socket_path();

    let mut params = serde_json::json!({
        "device_key": device_key,
        "encryption_key": encryption_key,
        "device_label": label,
    });
    if !operator_signature_hex.is_empty() {
        params["signatures"] = serde_json::json!(operator_signature_hex);
    }

    let result =
        emberlink_cli::call_daemon_method(&socket_path, "identity.device.enroll", &params)?;

    let committed = result.get("mode").and_then(|m| m.as_str()) == Some("committed");
    let ac2_card = if committed {
        Some(build_ac2_oob_confirmation_card(
            &result,
            "presence",
            label,
            device_key,
            device_key,
            encryption_key,
        )?)
    } else {
        None
    };
    if let (Some(path), Some(card)) = (ac2_card_path, ac2_card.as_ref()) {
        write_ac2_oob_confirmation_card(path, card)?;
    }

    if json_output {
        let mut output = result.clone();
        if let Some(card) = ac2_card.as_ref() {
            output["ac2_oob_confirmation"] =
                serde_json::to_value(card).unwrap_or(serde_json::Value::Null);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return Ok(());
    }

    // COMMIT response: the device enrolled.
    if committed {
        let device_id = result
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let root_id = result
            .get("operator_root_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        println!("Enrolled operator presence device.");
        println!("  device_id:        {device_id}");
        println!("  operator_root_id: {root_id}");
        if let Some(card) = ac2_card.as_ref() {
            print_ac2_oob_confirmation_card(card, ac2_card_path);
        }
        return Ok(());
    }

    // PREPARE response: print the bytes to sign off-host and how to commit.
    let to_sign = result
        .get("to_sign")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let root_id = result
        .get("operator_root_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    let device_id = result
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    println!("Operator-bootstrap ceremony — PREPARE (ADR 200 §5)");
    println!("  operator_root_id: {root_id}");
    println!("  device_id:        {device_id}");
    println!();
    println!(
        "Sign each blob below with the presence device ({} steps), then re-run with one",
        to_sign.len()
    );
    println!("`--operator-signature-hex <DER-hex>` per blob, in this order:");
    println!();
    for (i, step) in to_sign.iter().enumerate() {
        let purpose = step.get("purpose").and_then(|v| v.as_str()).unwrap_or("?");
        let bytes_hex = step.get("bytes_hex").and_then(|v| v.as_str()).unwrap_or("");
        println!("  [{}] {purpose}", i + 1);
        println!("      bytes_to_sign: {bytes_hex}");
    }
    Ok(())
}

/// Manual two-call OOB flow for the bootstrap backup presence Device. The
/// backup public keys are supplied by the operator, but the existing primary
/// presence Device signs the enrollment event. This keeps the anti-substitution
/// anchor outside daemon control: the primary card's operator root pubkey is the
/// expected root, and the backup card records the backup pubkeys.
fn run_device_enroll_backup_manual(
    authority_device_key: &str,
    device_key: &str,
    encryption_key: &str,
    label: &str,
    ac2_card_path: Option<&Path>,
    operator_signature_hex: &[String],
    json_output: bool,
) -> Result<(), core_types::ValidationError> {
    let socket_path = emberlink_cli::daemon_socket_path();

    let mut params = serde_json::json!({
        "authority_device_key": authority_device_key,
        "device_key": device_key,
        "encryption_key": encryption_key,
        "device_label": label,
    });
    if !operator_signature_hex.is_empty() {
        params["signatures"] = serde_json::json!(operator_signature_hex);
    }

    let result =
        emberlink_cli::call_daemon_method(&socket_path, "identity.device.enroll_backup", &params)?;

    let committed = result.get("mode").and_then(|m| m.as_str()) == Some("committed");
    let ac2_card = if committed {
        // Capability flows from class (ADR 200 amendment 2026-06-12): the
        // second/backup presence device IS a presence device, the same class
        // as the first. v1's "backup" device_role is retired.
        Some(build_ac2_oob_confirmation_card(
            &result,
            "presence",
            label,
            authority_device_key,
            device_key,
            encryption_key,
        )?)
    } else {
        None
    };
    if let (Some(path), Some(card)) = (ac2_card_path, ac2_card.as_ref()) {
        write_ac2_oob_confirmation_card(path, card)?;
    }

    if json_output {
        let mut output = result.clone();
        if let Some(card) = ac2_card.as_ref() {
            output["ac2_oob_confirmation"] =
                serde_json::to_value(card).unwrap_or(serde_json::Value::Null);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
        return Ok(());
    }

    if committed {
        let device_id = result
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let root_id = result
            .get("operator_root_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        println!("Enrolled backup operator presence device.");
        println!("  device_id:        {device_id}");
        println!("  operator_root_id: {root_id}");
        println!("  authority_key:    {authority_device_key}");
        if let Some(card) = ac2_card.as_ref() {
            print_ac2_oob_confirmation_card(card, ac2_card_path);
        }
        return Ok(());
    }

    let to_sign = result
        .get("to_sign")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let root_id = result
        .get("operator_root_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    let device_id = result
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("(unknown)");
    println!("Backup presence-device enrollment — PREPARE (ADR 200 AC-2)");
    println!("  operator_root_id: {root_id}");
    println!("  backup_device_id: {device_id}");
    println!("  authority_key:    {authority_device_key}");
    println!();
    println!("Sign the blob below with the existing primary presence device, then re-run with");
    println!("`--operator-signature-hex <DER-hex>`:");
    println!();
    for (i, step) in to_sign.iter().enumerate() {
        let purpose = step.get("purpose").and_then(|v| v.as_str()).unwrap_or("?");
        let bytes_hex = step.get("bytes_hex").and_then(|v| v.as_str()).unwrap_or("");
        println!("  [{}] {purpose}", i + 1);
        println!("      bytes_to_sign: {bytes_hex}");
    }
    Ok(())
}

fn list_personas_via_daemon(
    config: &DaemonConfig,
) -> Result<Vec<serde_json::Value>, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let personas_value =
        emberlink_cli::call_daemon_method(&socket_path, "list_personas", &serde_json::Value::Null)?;
    personas_value
        .as_array()
        .cloned()
        .ok_or_else(|| core_types::ValidationError::new("daemon list_personas: expected array"))
}

fn resolve_operator_persona_id_from_list(
    personas: &[serde_json::Value],
    excluded_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    fn active_persona_id<'a>(
        persona: &'a serde_json::Value,
        excluded_persona_id: &str,
    ) -> Option<&'a str> {
        let id = persona.get("id").and_then(|v| v.as_str())?;
        if id == excluded_persona_id {
            return None;
        }
        let status = persona
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        (status == "active").then_some(id)
    }

    fn active_durable_persona_id<'a>(
        persona: &'a serde_json::Value,
        excluded_persona_id: &str,
    ) -> Option<&'a str> {
        let id = active_persona_id(persona, excluded_persona_id)?;
        let name = persona
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        (!name.starts_with("runtime-")
            && !name.starts_with("orchestrator-")
            && !name.starts_with('_'))
        .then_some(id)
    }

    if let Some(id) = personas.iter().find_map(|persona| {
        (persona.get("name").and_then(|v| v.as_str()) == Some("root"))
            .then(|| active_persona_id(persona, excluded_persona_id))
            .flatten()
    }) {
        return Ok(id.to_string());
    }

    if let Some(id) = personas
        .iter()
        .find_map(|persona| active_durable_persona_id(persona, excluded_persona_id))
    {
        return Ok(id.to_string());
    }

    Err(core_types::ValidationError::new(
        "could not resolve an operator persona for this daemon-backed operator action",
    ))
}

fn resolve_operator_persona_id(
    config: &DaemonConfig,
    excluded_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    let personas = list_personas_via_daemon(config)?;
    resolve_operator_persona_id_from_list(&personas, excluded_persona_id)
}

fn resolve_claude_code_grant_approver_persona_id(
    config: &DaemonConfig,
    target_persona_id: &str,
) -> Result<String, core_types::ValidationError> {
    resolve_operator_persona_id(config, target_persona_id)
}

fn run_persona_revoke(config: &DaemonConfig, id: &str) -> Result<(), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let personas = list_personas_via_daemon(config)?;
    let mut request = serde_json::json!({
        "id": id,
        "caller_persona_id": id,
    });
    if let Some(name) = personas.iter().find_map(|persona| {
        (persona.get("id").and_then(|v| v.as_str()) == Some(id))
            .then(|| persona.get("name").and_then(|v| v.as_str()))
            .flatten()
    }) {
        request["name"] = serde_json::json!(name);
    }
    let _ = emberlink_cli::call_daemon_method(&socket_path, "revoke_persona", &request)?;
    Ok(())
}

fn persona_json_id(persona: &serde_json::Value) -> Option<String> {
    persona
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn persona_json_name_is(persona: &serde_json::Value, expected_name: &str) -> bool {
    persona
        .get("name")
        .and_then(|v| v.as_str())
        .map(|name| name == expected_name)
        .unwrap_or(false)
}

fn persona_json_is_active(persona: &serde_json::Value) -> bool {
    persona
        .get("status")
        .and_then(|v| v.as_str())
        .map(|status| status == "active")
        .unwrap_or(true)
}

fn find_active_persona_id_by_name(
    personas: &[serde_json::Value],
    persona_name: &str,
) -> Option<String> {
    personas
        .iter()
        .find(|persona| {
            persona_json_name_is(persona, persona_name) && persona_json_is_active(persona)
        })
        .and_then(persona_json_id)
}

fn find_any_persona_id_by_name(
    personas: &[serde_json::Value],
    persona_name: &str,
) -> Option<String> {
    personas
        .iter()
        .find(|persona| persona_json_name_is(persona, persona_name))
        .and_then(persona_json_id)
}

fn create_runtime_persona_via_daemon(
    config: &DaemonConfig,
    persona_name: &str,
) -> Result<String, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let created = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({
            "name": persona_name,
            "enroll_peer_pid": false,
        }),
    )?;
    created
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            core_types::ValidationError::new(format!(
                "create persona {persona_name} (rpc): response missing id"
            ))
        })
}

fn retire_persona_for_reenroll_via_daemon(
    config: &DaemonConfig,
    persona_id: &str,
    persona_name: &str,
) -> Result<String, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "retire_persona_for_reenroll",
        &serde_json::json!({
            "id": persona_id,
            "expected_name": persona_name,
            "caller_persona_id": persona_id,
            "name": persona_name,
        }),
    )?;
    result
        .get("retired_name")
        .and_then(|v| v.as_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "retire_persona_for_reenroll (rpc): response missing retired_name",
            )
        })
}

fn prepare_runtime_persona_for_reenroll(
    config: &DaemonConfig,
    persona_name: &str,
) -> Result<(bool, String), core_types::ValidationError> {
    let personas = list_personas_via_daemon(config)?;
    if let Some(id) = find_active_persona_id_by_name(&personas, persona_name) {
        return Ok((false, id));
    }

    if let Some(id) = find_any_persona_id_by_name(&personas, persona_name) {
        let retired_name = retire_persona_for_reenroll_via_daemon(config, &id, persona_name)?;
        eprintln!(
            "Recovered default persona slot: retired inactive persona {id} as {retired_name}."
        );
    }

    let id = create_runtime_persona_via_daemon(config, persona_name)?;
    Ok((true, id))
}

fn is_recoverable_persona_secret_error(message: &str, persona_id: &str) -> bool {
    message.contains(&format!("decrypt persona '{persona_id}' secret"))
        && (message.contains("dek unwrap failed")
            || message.contains("aead::Error")
            || message.contains("crypto error"))
}

fn recover_runtime_persona_after_secret_error(
    config: &DaemonConfig,
    runtime_label: &str,
    persona_name: &str,
    persona_id: &str,
    error: &core_types::ValidationError,
) -> Result<Option<String>, core_types::ValidationError> {
    let message = error.to_string();
    if !is_recoverable_persona_secret_error(&message, persona_id) {
        return Ok(None);
    }

    let retired_name = retire_persona_for_reenroll_via_daemon(config, persona_id, persona_name)?;
    eprintln!(
        "Recovered stale {runtime_label} persona {persona_id}: retired as {retired_name}; minting a fresh {persona_name}."
    );
    create_runtime_persona_via_daemon(config, persona_name).map(Some)
}

/// List receipts via the daemon's `list_receipts` RPC.
///
/// receipt_actions_migrated_to_rpc: under ADR 131's separate-uid posture the
/// daemon owns the SQLite read path; the prior `open_store(config)` local
/// fallback was silently-broken-by-design under the new posture. The
/// fallback branch was removed; missing-socket errors surface clearly
/// through `call_daemon_method`.
fn run_receipt_list(
    config: &DaemonConfig,
    persona: Option<&str>,
) -> Result<
    (
        ReceiptActionDispatch,
        Vec<core_grant_types::grant_receipt::GrantReceipt>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_receipts",
        &serde_json::json!({ "persona_id": persona }),
    )?;
    let receipts = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon list_receipts: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipts))
}

/// Fetch a receipt via the daemon's `get_receipt` RPC.
///
/// The daemon preserves the existing CLI contract: callers may supply either
/// a receipt id or a grant id, and the daemon resolves terminal grants to
/// their receipt rows. Local fallback removed — see the
/// `receipt_actions_migrated_to_rpc` note on [`run_receipt_list`].
fn run_receipt_get(
    config: &DaemonConfig,
    id: &str,
) -> Result<
    (
        ReceiptActionDispatch,
        core_grant_types::grant_receipt::GrantReceipt,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "get_receipt",
        &serde_json::json!({ "id": id }),
    )?;
    let receipt = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon get_receipt: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipt))
}

/// Fetch a receipt artifact through the dotted receipt RPC.
///
/// Unlike the legacy `get_receipt` RPC, `receipt.get` returns the persisted
/// JSON body as stored: v1 rows stay `GrantReceipt`, and v2 rows stay ADR 118
/// `ReceiptEnvelope`. That is the shape consumed by `trust explain --kind receipt`.
fn run_receipt_get_artifact(
    config: &DaemonConfig,
    id: &str,
) -> Result<(ReceiptActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let receipt = emberlink_cli::call_daemon_method(
        &socket_path,
        "receipt.get",
        &serde_json::json!({ "id": id }),
    )
    .map_err(|e| core_types::ValidationError::new(format!("daemon receipt.get: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipt))
}

fn run_receipt_list_artifacts(
    config: &DaemonConfig,
    persona: Option<&str>,
) -> Result<(ReceiptActionDispatch, Vec<serde_json::Value>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "receipt.list",
        &serde_json::json!({ "persona": persona }),
    )
    .map_err(|e| core_types::ValidationError::new(format!("daemon receipt.list: {e}")))?;
    let receipts = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon receipt.list: {e}")))?;
    Ok((ReceiptActionDispatch::DaemonRpc, receipts))
}

fn receipt_artifact_id(receipt: &serde_json::Value) -> Option<&str> {
    receipt
        .get("receipt_id")
        .or_else(|| receipt.get("id"))
        .and_then(|v| v.as_str())
}

fn receipt_artifact_version_number(receipt: &serde_json::Value) -> Option<u32> {
    let version = receipt.get("version")?;
    if let Some(value) = version.as_u64() {
        return u32::try_from(value).ok();
    }
    version.as_str()?.parse::<u32>().ok()
}

fn read_receipt_verify_file_value(path: &str) -> Result<serde_json::Value, String> {
    const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
    let bytes = if path == "-" {
        let mut buf = Vec::with_capacity(8192);
        let mut handle = std::io::stdin().lock().take((MAX_RECEIPT_BYTES + 1) as u64);
        handle
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        if buf.len() > MAX_RECEIPT_BYTES {
            return Err(format!("receipt input exceeds {MAX_RECEIPT_BYTES} bytes"));
        }
        buf
    } else {
        let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        if meta.len() > MAX_RECEIPT_BYTES as u64 {
            return Err(format!(
                "{path} is {} bytes; limit is {MAX_RECEIPT_BYTES}",
                meta.len()
            ));
        }
        std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|e| format!("not a valid receipt JSON: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptVerifyArtifactSource {
    DaemonId,
    File,
}

fn load_receipt_verify_artifact(
    config: &DaemonConfig,
    id: Option<String>,
    file: Option<String>,
) -> Result<(ReceiptVerifyArtifactSource, serde_json::Value), String> {
    match (id, file) {
        (Some(_), Some(_)) => Err("pass either <id> or --file <PATH>, not both".to_string()),
        (None, None) => {
            Err("pass either a receipt <id>, --file <PATH>, or --materialization <ID>".to_string())
        }
        (Some(id), None) => run_receipt_get_artifact(config, &id)
            .map(|(_, artifact)| (ReceiptVerifyArtifactSource::DaemonId, artifact))
            .map_err(|e| e.to_string()),
        (None, Some(path)) => read_receipt_verify_file_value(&path)
            .map(|value| (ReceiptVerifyArtifactSource::File, value)),
    }
}

fn run_receipt_verify_v2_trust_explain(
    config: &DaemonConfig,
    envelope: &core_events::receipt::envelope::ReceiptEnvelope,
) -> Result<emberlink_cli::trust::explain::TrustExplainResponse, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let artifact_bytes = serde_json::to_vec(envelope)
        .map_err(|e| core_types::ValidationError::new(format!("encode receipt envelope: {e}")))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let response = emberlink_cli::call_daemon_method(
        &socket_path,
        "trust.explain",
        &serde_json::json!({
            "artifact_kind": "receipt",
            "artifact_bytes_b64": b64.encode(&artifact_bytes),
            "sidecar_bytes_b64": "",
        }),
    )
    .map_err(|e| core_types::ValidationError::new(format!("daemon trust.explain: {e}")))?;
    emberlink_cli::trust::explain::parse_trust_explain_response(&response)
        .map_err(|e| core_types::ValidationError::new(format!("daemon trust.explain: {e}")))
}

fn resolve_receipt_export_target(
    config: &DaemonConfig,
    id: Option<&str>,
    latest: bool,
) -> Result<String, core_types::ValidationError> {
    if let Some(id) = id {
        return Ok(id.to_string());
    }
    if !latest {
        return Err(core_types::ValidationError::new(
            "pass a receipt <id> or `--latest`".to_string(),
        ));
    }

    let (_, receipts) = run_receipt_list(config, None)?;
    let latest_receipt = receipts.first().ok_or_else(|| {
        core_types::ValidationError::new(
            "no receipts found; run a session first or pass an explicit receipt id".to_string(),
        )
    })?;
    Ok(latest_receipt.id.clone())
}

fn resolve_receipt_artifact_export_target(
    config: &DaemonConfig,
    id: Option<&str>,
    latest: bool,
) -> Result<String, core_types::ValidationError> {
    if let Some(id) = id {
        return Ok(id.to_string());
    }
    if !latest {
        return Err(core_types::ValidationError::new(
            "pass a receipt <id> or `--latest`".to_string(),
        ));
    }

    let (_, receipts) = run_receipt_list_artifacts(config, None)?;
    let latest_receipt = receipts.first().ok_or_else(|| {
        core_types::ValidationError::new(
            "no receipts found; run a session first or pass an explicit receipt id".to_string(),
        )
    })?;
    receipt_artifact_id(latest_receipt)
        .map(str::to_string)
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "latest receipt has no receipt_id/id field; pass an explicit receipt id"
                    .to_string(),
            )
        })
}

/// Build the receipt tree export on the current authority surface.
///
/// Installed-path tree assembly now belongs to the daemon; the CLI keeps
/// only the ASCII rendering and optional export-file write.
fn run_receipt_tree(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<(ReceiptActionDispatch, emberlink_cli::receipt::TreeExport), core_types::ValidationError>
{
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "receipt_tree",
            &serde_json::json!({ "grant_id": grant_id }),
        )?;
        let tree = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon receipt_tree: {e}")))?;
        Ok((ReceiptActionDispatch::DaemonRpc, tree))
    } else {
        let store = open_store(config);
        let tree = emberlink_cli::receipt::build_tree(&store, &config.data_dir, grant_id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ReceiptActionDispatch::LocalFallback, tree))
    }
}

/// Query receipt-backed audit rows via the daemon's `receipt_query` RPC.
///
/// Local fallback removed;
/// see the `receipt_actions_migrated_to_rpc` note on [`run_receipt_list`].
fn run_audit_receipt_query(
    config: &DaemonConfig,
    filter: &ember_daemon::infra::receipt::ReceiptFilter,
) -> Result<
    (
        AuditActionDispatch,
        Vec<ember_daemon::infra::receipt::ReceiptRow>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "receipt_query",
        &serde_json::json!({
            "actor": filter.persona_id,
            "kind": filter.kind,
            "grant_id": filter.grant_id,
            "resource": filter.resource,
            "since": filter.since_iso,
            "limit": filter.limit,
        }),
    )?;
    let rows = serde_json::from_value(result)
        .map_err(|e| core_types::ValidationError::new(format!("daemon receipt_query: {e}")))?;
    Ok((AuditActionDispatch::DaemonRpc, rows))
}

/// Query raw audit-log rows on the current authority surface.
///
/// The installed daemon path uses the operator-only `audit_log_query`
/// seam so raw `details` stay off the broader ConnectOnly summary surface
/// exposed by `audit_query`.
fn run_audit_log_query(
    config: &DaemonConfig,
    filter: &ember_daemon::infra::audit::AuditFilter,
) -> Result<
    (
        AuditActionDispatch,
        Vec<ember_daemon::infra::audit::AuditEntry>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "audit_log_query",
            &serde_json::json!({
                "id": filter.id,
                "agent_id": filter.agent_id,
                "action": filter.action,
                "limit": filter.limit,
                "action_prefix": filter.action_prefix,
                "persona_id": filter.persona_id,
                "scope": filter.scope,
                "since_ms": filter.since_ms,
                "before_ms": filter.before_ms,
            }),
        )?;
        let rows = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon audit_log_query: {e}"))
        })?;
        Ok((AuditActionDispatch::DaemonRpc, rows))
    } else {
        let store = open_store(config);
        let rows = store
            .query_audit(filter)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((AuditActionDispatch::LocalFallback, rows))
    }
}

/// Load the daemon-owned current-state explanation for one audit event.
///
/// The installed daemon path owns both the raw event lookup and the current
/// grant/policy projections. The no-daemon fallback reuses the same shared
/// builder so the CLI keeps one explanation shape.
fn run_audit_explain(
    config: &DaemonConfig,
    id: i64,
) -> Result<
    (
        AuditActionDispatch,
        ember_daemon::infra::audit_explain::AuditExplainView,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "audit_explain",
            &serde_json::json!({ "id": id }),
        )?;
        let explain = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon audit_explain: {e}")))?;
        Ok((AuditActionDispatch::DaemonRpc, explain))
    } else {
        let store = open_store(config);
        let policy = if config.policy_file.exists() {
            ember_daemon::trust::policy::PolicyEngine::from_file(&config.policy_file)
                .unwrap_or_default()
        } else {
            ember_daemon::trust::policy::PolicyEngine::default()
        };
        let explain = ember_daemon::infra::audit_explain::build_audit_explain(&store, &policy, id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((AuditActionDispatch::LocalFallback, explain))
    }
}

/// List pending approvals on the current authority surface.
fn run_approval_list(
    config: &DaemonConfig,
) -> Result<
    (
        ApprovalActionDispatch,
        Vec<ember_daemon::trust::approval::ApprovalRequestInfo>,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "list_pending_approvals",
            &serde_json::Value::Null,
        )?;
        let requests = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon list_pending_approvals: {e}"))
        })?;
        Ok((ApprovalActionDispatch::DaemonRpc, requests))
    } else {
        let store = open_store(config);
        let requests = store
            .list_pending_approvals()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ApprovalActionDispatch::LocalFallback, requests))
    }
}

/// Resolve an approval on the current authority surface.
fn run_approval_resolve(
    config: &DaemonConfig,
    id: &str,
    outcome: &ApprovalOutcome,
) -> Result<
    (
        ApprovalActionDispatch,
        ember_daemon::trust::approval::ApprovalRequestInfo,
    ),
    core_types::ValidationError,
> {
    let caller_persona_id = resolve_approval_operator_caller_persona_id(config, id)?;
    run_approval_resolve_with_caller(config, id, outcome, caller_persona_id.as_deref())
}

fn resolve_approval_operator_caller_persona_id(
    config: &DaemonConfig,
    id: &str,
) -> Result<Option<String>, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if !socket_path.exists() {
        return Ok(None);
    }

    let (_, requests) = run_approval_list(config)?;
    let Some(request) = requests.iter().find(|request| request.id == id) else {
        return Ok(None);
    };
    resolve_operator_persona_id(config, &request.persona_id).map(Some)
}

fn run_approval_resolve_with_caller(
    config: &DaemonConfig,
    id: &str,
    outcome: &ApprovalOutcome,
    caller_persona_id: Option<&str>,
) -> Result<
    (
        ApprovalActionDispatch,
        ember_daemon::trust::approval::ApprovalRequestInfo,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let mut params = match outcome {
            ApprovalOutcome::Approved => {
                serde_json::json!({ "id": id, "decision": "approve" })
            }
            ApprovalOutcome::Denied { reason } => {
                serde_json::json!({ "id": id, "decision": "deny", "reason": reason })
            }
            ApprovalOutcome::Narrowed { new_scope } => serde_json::json!({
                "id": id,
                "decision": "narrow",
                "scope": new_scope,
            }),
            ApprovalOutcome::Always { scope, expires_at } => serde_json::json!({
                "id": id,
                "decision": "always",
                "scope": scope,
                "expires_at": expires_at,
            }),
        };
        if let Some(caller_persona_id) = caller_persona_id {
            params["caller_persona_id"] = serde_json::json!(caller_persona_id);
        }
        let result = emberlink_cli::call_daemon_method(&socket_path, "resolve_approval", &params)?;
        let resolved = serde_json::from_value(result).map_err(|e| {
            core_types::ValidationError::new(format!("daemon resolve_approval: {e}"))
        })?;
        Ok((ApprovalActionDispatch::DaemonRpc, resolved))
    } else {
        let store = open_store(config);
        store
            .resolve_approval(id, outcome)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let resolved = store
            .get_approval(id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((ApprovalActionDispatch::LocalFallback, resolved))
    }
}

/// Load the daemon-owned status aggregate on the current authority surface.
///
/// When the daemon is running, prefer its read surface so installed-path
/// operators do not need direct SQLite access. When the daemon is absent, keep
/// the historical local fallback for dev/no-daemon paths.
fn run_status_summary(
    config: &DaemonConfig,
    daemon_running: bool,
) -> Result<
    (
        StatusActionDispatch,
        Option<emberlink_cli::LiveDaemonStatus>,
        ember_daemon::infra::status::StatusSummary,
    ),
    core_types::ValidationError,
> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if let Some(live) = emberlink_cli::probe_live_daemon_status(&socket_path, &config.pid_file)? {
        return Ok((
            StatusActionDispatch::DaemonRpc,
            Some(live.clone()),
            live.summary,
        ));
    }

    if daemon_running {
        return Err(core_types::ValidationError::new(
            "daemon runtime probe reported running, but the live status RPC was unavailable; rerun `sudo ember daemon install` if this persists",
        ));
    }

    let store = open_store(config);
    let summary = ember_daemon::infra::status::StatusSummary {
        personas: store
            .list_personas()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        grants: store
            .list_active_grants()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        sandboxes: store
            .list_sandboxes()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        approvals: store
            .list_pending_approvals()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        recent_activity: store
            .query_audit(&AuditFilter {
                limit: Some(5),
                ..Default::default()
            })
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        standing_grants: store
            .list_standing_grants()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?
            .len(),
        audit_events_total: store
            .audit_count()
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?,
        quarantined: false,
        quarantine_authority: None,
        grant_live_leases: Vec::new(),
    };
    Ok((StatusActionDispatch::LocalFallback, None, summary))
}

fn live_daemon_identity(
    runtime_status: Option<&ember_daemon::infra::runtime::DaemonStatus>,
    live_status: Option<&emberlink_cli::LiveDaemonStatus>,
) -> (bool, Option<u32>, Option<String>) {
    if let Some(status) = live_status {
        return (
            true,
            status.pid.or_else(|| runtime_status.map(|s| s.pid)),
            Some(status.socket.display().to_string()),
        );
    }

    match runtime_status {
        Some(status) if status.running => (
            true,
            Some(status.pid),
            Some(status.socket.display().to_string()),
        ),
        Some(status) => (
            false,
            Some(status.pid),
            Some(status.socket.display().to_string()),
        ),
        None => (false, None, None),
    }
}

fn build_status_banner(
    config: &DaemonConfig,
    runtime_status: Option<&ember_daemon::infra::runtime::DaemonStatus>,
    live_status: Option<&emberlink_cli::LiveDaemonStatus>,
    vault_backend: String,
    vault_addr: String,
    vault_session: Option<VaultStatusView>,
) -> DaemonStatusBanner {
    let dashboard = match config.dashboard_addr {
        Some(addr) => match probe_dashboard_addr_bound(addr) {
            Some(bound) => {
                let pretty = bound
                    .parse::<std::net::SocketAddr>()
                    .ok()
                    .filter(|a| a.ip().is_loopback())
                    .map(|a| format!("localhost:{}", a.port()))
                    .unwrap_or(bound);
                format!("http://{pretty}/")
            }
            None => "not running (bind failed or not configured)".to_string(),
        },
        None => "not running (bind failed or not configured)".to_string(),
    };

    let (running, pid, socket) = live_daemon_identity(runtime_status, live_status);
    match (running, pid, socket) {
        (true, Some(pid), Some(socket)) => DaemonStatusBanner::Running {
            pid,
            socket,
            dashboard,
            vault_backend,
            vault_addr,
            vault_session,
        },
        (false, Some(pid), _) => DaemonStatusBanner::StalePid { pid },
        _ => DaemonStatusBanner::NotRunning,
    }
}

fn parse_default_yes_response(input: &str) -> Option<bool> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

fn prompt_yes_no_default_yes(prompt: &str) -> Result<bool, String> {
    loop {
        eprint!("{}: ", format_default_yes_prompt(prompt));
        let _ = io::stderr().flush();
        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .map_err(|e| format!("read {prompt}: {e}"))?;
        if let Some(choice) = parse_default_yes_response(&buf) {
            return Ok(choice);
        }
        eprintln!("  enter Y or n");
    }
}

fn prompt_decision_card_default_yes(
    title: &str,
    consequence: &str,
    primary_choice: &str,
    secondary_choice: &str,
) -> Result<bool, String> {
    eprintln!("{title}");
    eprintln!("  {consequence}");
    eprintln!();
    eprintln!("  1. {primary_choice}");
    eprintln!("  2. {secondary_choice}");
    prompt_yes_no_default_yes("  Continue with option 1")
}

fn should_offer_primary_action(
    action: Option<&PrimaryAction>,
    allow_next: bool,
    no_input: bool,
) -> bool {
    if no_input || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return false;
    }
    match action.map(|action| action.kind) {
        Some(PrimaryActionKind::Start | PrimaryActionKind::FixNow) => true,
        Some(PrimaryActionKind::Next) => allow_next,
        None => false,
    }
}

fn should_auto_run_primary_action(
    action: Option<&PrimaryAction>,
    allow_next: bool,
    yes: bool,
) -> bool {
    if !yes {
        return false;
    }
    match action.map(|action| action.kind) {
        Some(PrimaryActionKind::Start | PrimaryActionKind::FixNow) => true,
        Some(PrimaryActionKind::Next) => allow_next,
        None => false,
    }
}

fn run_prompted_command(command: &str) -> Result<i32, String> {
    let argv = command
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(program) = argv.first() else {
        return Err("command was empty".to_string());
    };
    let status = process::Command::new(program)
        .args(&argv[1..])
        .stdin(process::Stdio::inherit())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .status()
        .map_err(|e| format!("spawn `{command}`: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn maybe_prompt_run_primary_action(
    action: Option<&PrimaryAction>,
    allow_next: bool,
    no_input: bool,
    yes: bool,
) -> Result<Option<i32>, String> {
    if should_auto_run_primary_action(action, allow_next, yes) {
        let action = action.expect("checked above");
        eprintln!();
        eprintln!("{}", style_section_heading("Run now"));
        eprintln!("  {}", display_command_text(&action.command));
        eprintln!();
        return run_prompted_command(&action.command).map(Some);
    }
    if !should_offer_primary_action(action, allow_next, no_input) {
        return Ok(None);
    }
    let action = action.expect("checked above");
    eprintln!();
    eprintln!("{}", style_section_heading("Run now"));
    eprintln!("  {}", display_command_text(&action.command));
    if !prompt_yes_no_default_yes("  Do you want to run this now")? {
        return Ok(None);
    }
    eprintln!();
    run_prompted_command(&action.command).map(Some)
}

fn exit_on_prompted_action(result: Result<Option<i32>, String>) {
    match result {
        Ok(Some(code)) => process::exit(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("error: {error}");
            process::exit(1);
        }
    }
}

#[derive(Debug, Clone)]
enum DaemonStatusBanner {
    Running {
        pid: u32,
        socket: String,
        dashboard: String,
        vault_backend: String,
        vault_addr: String,
        vault_session: Option<VaultStatusView>,
    },
    StalePid {
        pid: u32,
    },
    NotRunning,
}

#[derive(Debug, Clone)]
struct UiSection {
    heading: &'static str,
    lines: Vec<String>,
}

#[derive(Debug, Clone)]
struct StatusOverview {
    dispatch: StatusActionDispatch,
    banner: DaemonStatusBanner,
    summary: ember_daemon::infra::status::StatusSummary,
    github_status: Option<GithubProviderStatusView>,
    ember_initialized: bool,
    launcher_issue: Option<InstalledLauncherIssue>,
    current_launcher_lane: Option<CurrentLauncherLane>,
    managed_daemon_issue: Option<ManagedDaemonIssue>,
    delegation_template_issue: Option<DelegationTemplateInstallIssue>,
    daemon_running: bool,
    daemon_pid: Option<u32>,
    daemon_socket: Option<String>,
    vault_backend: String,
    vault_addr: String,
    vault_session: Option<VaultStatusView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaudeRuntimeAuthTruth {
    GovernedOauth {
        grant_id: String,
        credential_name: String,
    },
    GovernedApiKeyFallback {
        grant_id: String,
        credential_name: String,
    },
    GovernedOther {
        grant_id: String,
        credential_name: String,
    },
    NoActiveBrokeredGrant,
}

impl ClaudeRuntimeAuthTruth {
    fn status_line(&self) -> String {
        match self {
            Self::GovernedOauth {
                credential_name, ..
            } => format!("Claude auth: governed plan lane active ({credential_name})."),
            Self::GovernedApiKeyFallback {
                credential_name, ..
            } => format!("Claude auth: governed API-key fallback active ({credential_name})."),
            Self::GovernedOther {
                credential_name, ..
            } => format!("Claude auth: governed runtime grant active ({credential_name})."),
            Self::NoActiveBrokeredGrant => {
                "Claude auth: no active brokered runtime grant.".to_string()
            }
        }
    }

    fn json_value(&self) -> serde_json::Value {
        match self {
            Self::GovernedOauth {
                grant_id,
                credential_name,
            } => serde_json::json!({
                "kind": "governed_oauth",
                "grant_id": grant_id,
                "credential_name": credential_name,
            }),
            Self::GovernedApiKeyFallback {
                grant_id,
                credential_name,
            } => serde_json::json!({
                "kind": "governed_api_key_fallback",
                "grant_id": grant_id,
                "credential_name": credential_name,
            }),
            Self::GovernedOther {
                grant_id,
                credential_name,
            } => serde_json::json!({
                "kind": "governed_other",
                "grant_id": grant_id,
                "credential_name": credential_name,
            }),
            Self::NoActiveBrokeredGrant => serde_json::json!({
                "kind": "no_active_brokered_grant",
                "grant_id": serde_json::Value::Null,
                "credential_name": serde_json::Value::Null,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CodexRuntimeAuthTruth {
    /// Codex HOST runs through the daemon's per-session responses proxy
    /// (ADR 197 §9): the model credential is brokered server-side (the
    /// refresh_token never leaves the daemon) and the request path is mediated,
    /// upstream-pinned, and revocable on session close. Governed at the
    /// model-auth layer — but spend is NOT bypass-proof: the loopback-TCP
    /// transport carries no peer attestation, so a same-uid sibling that finds
    /// the ephemeral port can spend the session budget (it cannot exfil the
    /// credential, redirect upstream, or reach other endpoints). That residual
    /// — not credential governance — is the gap vs the Claude UDS lane.
    BrokeredResponsesProxyActive {
        grant_id: String,
        credential_name: String,
    },
    NoActiveBrokeredSession,
}

impl CodexRuntimeAuthTruth {
    fn status_line(&self) -> String {
        match self {
            Self::BrokeredResponsesProxyActive { .. } => {
                "Codex auth: model credential brokered + request-path mediated via the responses proxy (governed, ADR 197 §9); session-budget spend is not bypass-proof on the loopback transport (active session grant).".to_string()
            }
            Self::NoActiveBrokeredSession => {
                "Codex auth: responses-proxy brokered lane (governed when launched, ADR 197 §9); no active session grant.".to_string()
            }
        }
    }

    fn json_value(&self) -> serde_json::Value {
        match self {
            Self::BrokeredResponsesProxyActive {
                grant_id,
                credential_name,
            } => serde_json::json!({
                "kind": "brokered_responses_proxy",
                "model_auth_governed": true,
                "spend_non_bypassable": false,
                "session_grant_active": true,
                "grant_id": grant_id,
                "credential_name": credential_name,
            }),
            Self::NoActiveBrokeredSession => serde_json::json!({
                "kind": "brokered_responses_proxy",
                "model_auth_governed": true,
                "spend_non_bypassable": false,
                "session_grant_active": false,
                "grant_id": serde_json::Value::Null,
                "credential_name": serde_json::Value::Null,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CursorRuntimeAuthTruth {
    LaunchReadyGrant {
        grant_id: String,
        credential_name: String,
    },
    NoLaunchReadyGrant,
}

impl CursorRuntimeAuthTruth {
    fn status_line(&self) -> String {
        match self {
            Self::LaunchReadyGrant {
                credential_name, ..
            } => format!(
                "Cursor auth: Cursor account/model auth remains Cursor-owned; Ember launch grant ready ({credential_name}); model spend is not brokered."
            ),
            Self::NoLaunchReadyGrant => {
                "Cursor auth: Cursor account/model auth remains Cursor-owned; no launch-ready Ember grant; model spend is not brokered.".to_string()
            }
        }
    }

    fn json_value(&self) -> serde_json::Value {
        match self {
            Self::LaunchReadyGrant {
                grant_id,
                credential_name,
            } => serde_json::json!({
                "kind": "cursor_owned_model_auth",
                "model_auth_governed": false,
                "launcher_grant_active": true,
                "grant_id": grant_id,
                "credential_name": credential_name,
            }),
            Self::NoLaunchReadyGrant => serde_json::json!({
                "kind": "cursor_owned_model_auth",
                "model_auth_governed": false,
                "launcher_grant_active": false,
                "grant_id": serde_json::Value::Null,
                "credential_name": serde_json::Value::Null,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimaryActionKind {
    Start,
    FixNow,
    Next,
}

#[derive(Debug, Clone)]
struct PrimaryAction {
    kind: PrimaryActionKind,
    command: String,
}

fn push_row_section(out: &mut String, heading: &str, rows: &[(&str, &str)]) {
    if rows.is_empty() {
        return;
    }
    const COMMAND_COLUMN_WIDTH: usize = 28;

    let theme = current_cli_render_theme();
    let _ = writeln!(out, "{}", style_section_heading(heading));
    for (left, right) in rows {
        if left.len() > COMMAND_COLUMN_WIDTH {
            let _ = writeln!(out, "  {}", theme.command(left));
            let _ = writeln!(out, "    {right}");
        } else {
            let command = format!("{left:<width$}", width = COMMAND_COLUMN_WIDTH);
            let _ = writeln!(out, "  {} {right}", theme.command(&command));
        }
    }
    let _ = writeln!(out);
}

fn render_help_card(
    title: &str,
    summary: &str,
    common: &[(&str, &str)],
    options: &[(&str, &str)],
    see_also: &[(&str, &str)],
) -> String {
    let theme = current_cli_render_theme();
    let mut out = String::new();
    let _ = writeln!(out, "{}", theme.title(title, tone_for_card_title(title)));
    let _ = writeln!(out);
    let _ = writeln!(out, "{summary}");
    let _ = writeln!(out);
    push_row_section(&mut out, "Common", common);
    push_row_section(&mut out, "Options", options);
    push_row_section(&mut out, "See also", see_also);
    out.trim_end().to_string()
}

fn is_help_flag(arg: &str) -> bool {
    arg == "--help" || arg == "-h"
}

fn strip_global_help_noise(raw_args: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut skip_next = false;
    for arg in raw_args {
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "--" => break,
            "--config" | "--color" => {
                skip_next = true;
            }
            "--json" | "--quiet" | "--verbose" | "--no-input" | "--yes" | "-y" => {}
            _ if arg.starts_with("--config=") || arg.starts_with("--color=") => {}
            _ => normalized.push(arg.clone()),
        }
    }
    normalized
}

fn raw_args_target_home_screen(raw_args: &[String]) -> bool {
    if raw_args.is_empty() {
        return true;
    }

    let mut raw_iter = raw_args.iter();
    while let Some(arg) = raw_iter.next() {
        match arg.as_str() {
            "--config" | "--color" => {
                if raw_iter.next().is_none() {
                    return false;
                }
            }
            "--verbose" | "--no-input" | "--yes" | "-y" => {}
            _ if arg.starts_with("--config=") || arg.starts_with("--color=") => {}
            _ => return false,
        }
    }

    true
}

fn raw_config_override(raw_args: &[String]) -> Option<PathBuf> {
    let mut config = None;
    let mut raw_iter = raw_args.iter();
    while let Some(arg) = raw_iter.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            config = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--config"
            && let Some(value) = raw_iter.next()
        {
            config = Some(PathBuf::from(value));
        }
    }
    config
}

fn find_visible_subcommand<'a>(command: &'a ClapCommand, token: &str) -> Option<&'a ClapCommand> {
    command.get_subcommands().find(|subcommand| {
        !subcommand.is_hide_set()
            && (subcommand.get_name() == token
                || subcommand.get_visible_aliases().any(|alias| alias == token))
    })
}

fn resolve_help_path(raw_args: &[String]) -> Option<Vec<String>> {
    let normalized = strip_global_help_noise(raw_args);
    if !normalized.iter().any(|arg| is_help_flag(arg)) {
        return None;
    }

    let mut command = Cli::command();
    let mut path = Vec::new();
    for token in normalized {
        if is_help_flag(&token) {
            break;
        }
        if token.starts_with('-') {
            continue;
        }
        let token = token.as_str();
        let Some(subcommand) = find_visible_subcommand(&command, token) else {
            if command.get_subcommands().next().is_some() {
                return None;
            }
            break;
        };
        path.push(subcommand.get_name().to_string());
        command = subcommand.clone();
    }
    Some(path)
}

fn resolve_entry_help_path(raw_args: &[String]) -> Option<Vec<String>> {
    let normalized = strip_global_help_noise(raw_args);
    if normalized.is_empty() || normalized.iter().any(|arg| is_help_flag(arg)) {
        return None;
    }

    let mut command = Cli::command();
    let mut path = Vec::new();
    for token in normalized {
        if token.starts_with('-') {
            return None;
        }
        let token = token.as_str();
        let subcommand = find_visible_subcommand(&command, token)?;
        path.push(subcommand.get_name().to_string());
        command = subcommand.clone();
    }

    command.get_subcommands().next().map(|_| path)
}

fn format_arg_label(arg: &Arg) -> String {
    if arg.is_positional() {
        return arg
            .get_value_names()
            .and_then(|names| names.first())
            .map(|name| format!("<{}>", name))
            .unwrap_or_else(|| format!("<{}>", arg.get_id().as_str()));
    }

    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        let mut long_part = format!("--{long}");
        if matches!(arg.get_action(), ArgAction::Set | ArgAction::Append) {
            if let Some(value_name) = arg.get_value_names().and_then(|names| names.first()) {
                long_part.push(' ');
                long_part.push('<');
                long_part.push_str(value_name);
                long_part.push('>');
            }
        }
        parts.push(long_part);
    }
    if parts.is_empty() {
        format!("--{}", arg.get_id().as_str())
    } else {
        parts.join(", ")
    }
}

fn explain_topic_for_path(path: &[String]) -> Option<&'static str> {
    match path.first().map(String::as_str) {
        Some("init") => Some("init"),
        Some("uninstall") => Some("uninstall"),
        Some("delegation") => Some("delegation"),
        Some("recover") => Some("recover"),
        Some("daemon") => Some("daemon"),
        Some("persona") => Some("persona"),
        Some("vault") => Some("vault"),
        Some("grant") => Some("grant"),
        Some("sandbox") => Some("sandbox"),
        Some("approval") => Some("approval"),
        Some("audit") => Some("audit"),
        Some("receipt") => Some("receipt"),
        Some("config") => Some("config"),
        Some("github") => Some("github"),
        Some("trust") => Some("trust"),
        Some("status") => Some("status"),
        Some("doctor") => Some("doctor"),
        Some("claude") => Some("claude"),
        Some("codex") => Some("codex"),
        Some("headless") => Some("headless"),
        _ => None,
    }
}

fn generated_help_should_surface_json(path: &[String]) -> bool {
    match path {
        [leaf] => matches!(leaf.as_str(), "status" | "doctor"),
        [_, leaf] => matches!(
            leaf.as_str(),
            "list" | "show" | "status" | "verify" | "query" | "usage" | "preflight" | "path"
        ),
        _ => false,
    }
}

fn render_generated_help_card(path: &[String]) -> Option<String> {
    let mut command = Cli::command();
    for segment in path {
        let subcommand = find_visible_subcommand(&command, segment)?;
        command = subcommand.clone();
    }

    if command.is_hide_set() {
        return None;
    }

    let title = if path.is_empty() {
        "ember".to_string()
    } else {
        format!("ember {}", path.join(" "))
    };
    let summary = command
        .get_about()
        .map(|about| about.to_string())
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| "Inspect or run this Ember command.".to_string());

    let visible_subcommands = command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| {
            let command_text = if path.is_empty() {
                format!("ember {}", subcommand.get_name())
            } else {
                format!("ember {} {}", path.join(" "), subcommand.get_name())
            };
            (
                command_text,
                subcommand
                    .get_about()
                    .map(|about| about.to_string())
                    .filter(|text| !text.trim().is_empty())
                    .unwrap_or_else(|| "Run this subcommand".to_string()),
            )
        })
        .collect::<Vec<_>>();

    let mut visible_args = command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .filter(|arg| {
            !matches!(
                arg.get_long(),
                Some("config" | "quiet" | "verbose" | "color" | "no-input")
            )
        })
        .map(|arg| {
            let detail = arg
                .get_help()
                .map(|help| help.to_string())
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| {
                    if arg.is_required_set() {
                        "Required input".to_string()
                    } else {
                        "Optional control".to_string()
                    }
                });
            (format_arg_label(arg), detail)
        })
        .collect::<Vec<_>>();

    if generated_help_should_surface_json(path)
        && !visible_args.iter().any(|(label, _)| label == "--json")
    {
        visible_args.push((
            "--json".to_string(),
            "Emit machine-readable output where supported".to_string(),
        ));
    }
    if matches!(path, [command, subcommand] if command == "audit" && subcommand == "export") {
        if !visible_args.iter().any(|(label, _)| label == "--sign") {
            visible_args.push((
                "--sign".to_string(),
                "Produce an ADR 160 signed CBOR compliance bundle".to_string(),
            ));
        }
        visible_args.sort_by_key(|(label, _)| match label.as_str() {
            "--sign" => 0,
            "--output <OUTPUT>" => 1,
            "--since <SINCE>" => 2,
            "--workflow <WORKFLOW>" => 3,
            "--redact <RULE,...>" => 4,
            "--format <FORMAT>" => 5,
            "--limit <LIMIT>" => 6,
            "--agent <AGENT>" => 7,
            _ => 8,
        });
    }

    let mut common_rows = Vec::new();
    if visible_subcommands.is_empty() {
        common_rows.push((title.clone(), "Run this command".to_string()));
    } else {
        common_rows.extend(visible_subcommands.into_iter().take(4));
    }

    let mut see_also_rows = Vec::new();
    if path.len() > 1 {
        see_also_rows.push((
            format!("ember {}", path[..path.len() - 1].join(" ")),
            "Return to the parent command".to_string(),
        ));
    } else {
        see_also_rows.push((
            "ember --help".to_string(),
            "Return to the compact command map".to_string(),
        ));
    }
    if let Some(topic) = explain_topic_for_path(path) {
        see_also_rows.push((
            format!("ember explain {topic}"),
            "Read the deeper manual".to_string(),
        ));
    }

    let common_refs = common_rows
        .iter()
        .map(|(left, right)| (left.as_str(), right.as_str()))
        .collect::<Vec<_>>();
    let option_refs = visible_args
        .iter()
        .take(6)
        .map(|(left, right)| (left.as_str(), right.as_str()))
        .collect::<Vec<_>>();
    let see_also_refs = see_also_rows
        .iter()
        .map(|(left, right)| (left.as_str(), right.as_str()))
        .collect::<Vec<_>>();

    Some(render_help_card(
        &title,
        &summary,
        &common_refs,
        &option_refs,
        &see_also_refs,
    ))
}

/// Parse a `--since` argument.
///
/// Accepts either an ISO-8601 timestamp (e.g. `2026-04-01T00:00:00Z`) or
/// a relative duration like `24h` / `7d` / `30m` / `45s`. Relative values
/// are resolved against `now` and converted to ISO-8601 so the daemon
/// receives a single canonical shape.
///
/// Returns `None` for malformed input — callers surface a clean usage
/// error to the operator instead of guessing.
pub(crate) fn parse_since(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Try ISO-8601 first — RFC3339 covers the canonical wire shape.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    // Fall back to relative duration. Reuse the existing `parse_duration`
    // helper so unit semantics stay consistent across the binary.
    let secs = parse_duration(trimmed).ok()?;
    let secs_i64 = i64::try_from(secs).ok()?;
    chrono::Utc::now().checked_sub_signed(chrono::Duration::seconds(secs_i64))
}

/// Print the initial banner lines (version, socket, database, PID) immediately on startup.
/// Call `print_banner_startup` once the dashboard + git-proxy bind results are known.
/// Check whether the ember-init shadow PATH
/// has been installed on this host. Returns `Err(msg)` with a precise
/// remediation hint if `$HOME/.ember/shadow/bin/` is missing or doesn't
/// contain the expected shim binaries (`gh`, `git`).
///
/// Shim binaries live under `~/.ember/shadow/bin/` (the PATH-prepended
/// subdirectory); credential and config files live at `~/.ember/shadow/`.
///
/// Without the shadow PATH, raw `gh` / `git` invocations from sequential
/// agents (autopilot SKILL, ralph loops, `ship-pr.sh`'s `EMBER_GH_BIN`
/// fallback) bypass the broker entirely — every PR ships as the operator's
/// identity and the audit trail collapses. This is the host-side invariant
/// that closes the gap.
fn ensure_shadow_path_installed() -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "$HOME not set".to_string())?;
    let shadow_bin_dir = std::path::Path::new(&home)
        .join(".ember")
        .join("shadow")
        .join("bin");
    if !shadow_bin_dir.is_dir() {
        return Err(format!(
            "shadow path not installed at {}; run `ember init --for claude`",
            shadow_bin_dir.display()
        ));
    }
    let critical = ["gh", "git"];
    let missing: Vec<&str> = critical
        .iter()
        .filter(|name| !shadow_bin_dir.join(name).exists())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "shadow path at {} is missing shims: {} — run `ember init --for claude`",
            shadow_bin_dir.display(),
            missing.join(", ")
        ));
    }
    Ok(())
}

fn print_banner_preamble(config: &DaemonConfig) {
    let version = env!("CARGO_PKG_VERSION");
    let socket = config.socket_dir.join("daemon.sock");
    let db = config.data_dir.join("daemon.db");
    let log = config.data_dir.join("daemon.log");
    let pid = std::process::id();

    eprintln!();
    eprintln!("  ember daemon v{version}");
    eprintln!("  The trust layer for AI agents");
    eprintln!();
    eprintln!("  Socket:    {}", socket.display());
    eprintln!("  Database:  {}", db.display());
    eprintln!("  Log:       {}", log.display());
    eprintln!("  PID:       {pid}");
}

/// Print the dashboard + git-proxy banner lines, followed by the "Ctrl+C to stop"
/// footer. Called after both bind results are known (from the StartupBinds callback).
/// This was extended from a single dashboard line to the full
/// startup-binds aggregate.
fn print_banner_startup(binds: &StartupBinds) {
    // Identity line first — for the camera-clean demo flow, the daemon's
    // signing fingerprint is the load-bearing visual the viewer needs to
    // match across the dashboard header, the receipt detail card, and the
    // post-take `ember receipt verify --pubkey` arg. Surface it before the
    // listener URLs so the eye registers it as the daemon's "name."
    if !binds.identity_pubkey.is_empty() {
        let fp = ember_daemon::infra::runtime::daemon_identity_fingerprint(&binds.identity_pubkey);
        eprintln!("  Identity:  {fp} (Ed25519)");
    }
    match &binds.dashboard {
        DashboardBind::Bound(addr) => {
            // Display loopback addresses as "localhost" for readability.
            if addr.ip().is_loopback() {
                eprintln!("  Dashboard: http://localhost:{}", addr.port());
            } else {
                eprintln!("  Dashboard: http://{addr}");
            }
        }
        DashboardBind::Failed { addr, error: _ } => {
            eprintln!("  Dashboard: unavailable (port {} in use)", addr.port());
        }
        DashboardBind::Disabled => {
            eprintln!("  Dashboard: disabled");
        }
        DashboardBind::Timeout => {
            eprintln!("  Dashboard: status unknown (startup timeout)");
        }
    }
    match &binds.llm_proxy {
        LlmProxyBind::Bound(addr) => {
            // The LLM proxy is what the
            // Anthropic SDK demo posts to via `base_url=$EMBER_PROXY_URL`,
            // so the canonical `EMBER_PROXY_URL=…` line carries this URL.
            // qember.sh + the smoke-runner wrapper read this line.
            eprintln!("  EMBER_PROXY_URL=http://{addr}");
        }
        LlmProxyBind::Failed { addr, error: _ } => {
            eprintln!("  LLM proxy: unavailable (port {} in use)", addr.port());
        }
        LlmProxyBind::Disabled => {
            eprintln!("  LLM proxy: disabled");
        }
        LlmProxyBind::Timeout => {
            eprintln!("  LLM proxy: status unknown (startup timeout)");
        }
    }
    match &binds.git_proxy {
        GitProxyBind::Bound(addr) => {
            // The git-echo proxy URL now lives
            // at `EMBER_GIT_PROXY_URL` (was previously `EMBER_PROXY_URL`).
            // ember-git.sh's allowlisted shape still reads `EMBER_PROXY_URL`,
            // so this line is informational; ember-git.sh callers should
            // export `EMBER_GIT_PROXY_URL` directly when both are needed.
            eprintln!("  EMBER_GIT_PROXY_URL=http://{addr}");
        }
        GitProxyBind::Failed { addr, error: _ } => {
            eprintln!("  Git proxy: unavailable (port {} in use)", addr.port());
        }
        GitProxyBind::Disabled => {
            eprintln!("  Git proxy: disabled");
        }
        GitProxyBind::Timeout => {
            eprintln!("  Git proxy: status unknown (startup timeout)");
        }
    }
    eprintln!();
    eprintln!("  Ctrl+C to stop");
    eprintln!();
}

/// Resolve the user-pinned config path from
/// the precedence chain (flag → `EMBER_CONFIG` → `EMBER_DEMO_DIR/config.toml`),
/// returning `None` if none of the inputs point at a config so the caller
/// falls through to the default (`~/.ember/config.toml`).
///
/// Pure function so tests cover priority order without mutating
/// process-global env vars (mirrors `resolve_init_keyring_value`).
///
/// Precedence:
/// 1. `--config <path>` flag (always wins, even if file doesn't exist —
///    the caller surfaces the error).
/// 2. `EMBER_CONFIG=<path>` env var.
/// 3. `EMBER_DEMO_DIR=<dir>` env var, when `<dir>/config.toml` exists.
/// 4. `None` — caller falls back to `DaemonConfig::default_config_path()`.
///
/// The `EMBER_DEMO_DIR` fallback only fires when the candidate file
/// actually exists, so a stale env var pointing at a removed demo dir
/// doesn't make every CLI invocation fail.
fn resolve_config_path(
    cli_config: Option<&PathBuf>,
    env_config: Option<String>,
    env_demo_dir: Option<String>,
) -> Option<PathBuf> {
    if let Some(p) = cli_config {
        return Some(p.clone());
    }
    if let Some(env) = env_config.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(env));
    }
    if let Some(dir) = env_demo_dir.filter(|s| !s.is_empty()) {
        let candidate = PathBuf::from(dir).join("config.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Read `EMBER_CONFIG` / `EMBER_DEMO_DIR` from the live process env and
/// resolve a user-pinned config path (or `None` to fall through to default).
///
/// Thin runtime wrapper around `resolve_config_path` so call sites that
/// previously read `cli.config.as_ref()` can adopt env-var auto-discovery
/// in one substitution.
fn resolved_user_config_path(cli_config: Option<&PathBuf>) -> Option<PathBuf> {
    resolve_config_path(
        cli_config,
        std::env::var("EMBER_CONFIG").ok(),
        std::env::var("EMBER_DEMO_DIR").ok(),
    )
}

fn effective_config_path(cli_config: Option<&PathBuf>) -> PathBuf {
    resolved_user_config_path(cli_config).unwrap_or_else(DaemonConfig::default_config_path)
}

fn managed_separate_uid_topology_paths(home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let ember_root = home.join(".ember");
    (
        ember_root.join("run"),
        ember_root.join("data"),
        ember_root.join("run").join("emberd.pid"),
    )
}

fn matches_managed_separate_uid_topology_paths(config: &DaemonConfig, home: &Path) -> bool {
    let (socket_dir, data_dir, pid_file) = managed_separate_uid_topology_paths(home);
    config.socket_dir == socket_dir && config.data_dir == data_dir && config.pid_file == pid_file
}

fn uses_managed_separate_uid_topology(config: &DaemonConfig) -> bool {
    if !ember_daemon::install::is_separate_uid_posture() {
        return false;
    }
    let Some(home) = dirs_next::home_dir() else {
        return false;
    };
    matches_managed_separate_uid_topology_paths(config, &home)
}

fn managed_local_vault_fallback_refused() -> core_types::ValidationError {
    core_types::ValidationError::new(
        "daemon is not running on the managed separate-uid path; local vault fallback is refused. \
         Run `ember status` to inspect daemon posture and `sudo ember daemon install` to repair it."
            .to_string(),
    )
}

fn vault_control_daemon_required(action: &str) -> core_types::ValidationError {
    core_types::ValidationError::new(format!(
        "vault {action} requires the daemon-owned vault control plane; no daemon socket is available. \
         Run `ember status` to inspect daemon posture and `sudo ember daemon install` to install or repair the managed daemon."
    ))
}

/// Probe `/api/status` on the configured
/// dashboard address and return the daemon's reported `dashboard_addr_bound`.
///
/// `None` means: connect failed, response was malformed, or the daemon
/// reported `dashboard_addr_bound: null` (bind failed / not configured).
/// `Some(addr_string)` means: the daemon is serving traffic on that address
/// — the CLI can render it without lying to the operator.
///
/// Implemented as a blocking raw-TCP HTTP/1.1 GET so the CLI can stay free
/// of an HTTP-client dependency. Local-only request, short timeout, no body
/// content negotiation. Mirrors the integration-test pattern in
/// `crates/ember-daemon/tests/integration.rs`.
fn probe_dashboard_addr_bound(addr: std::net::SocketAddr) -> Option<String> {
    use std::io::{Read as _, Write as _};

    let mut stream =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;

    let req = b"GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(req).ok()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let resp = std::str::from_utf8(&buf).ok()?;
    if !resp.starts_with("HTTP/1.1 200") {
        return None;
    }
    // Body starts after the first blank line (CRLF CRLF).
    let body = resp.split("\r\n\r\n").nth(1)?;
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get("dashboard_addr_bound")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Guard that keeps the non-blocking file-appender thread alive.
/// Drop it only when the process is about to exit.
pub struct LogGuard {
    _worker: tracing_appender::non_blocking::WorkerGuard,
}

/// Initialize daemon tracing: rolling JSON file appender always; console fmt layer when
/// `console` is true (foreground). Returns a `LogGuard` the caller must hold for the
/// lifetime of the process.
fn configure_tracing(
    data_dir: &std::path::Path,
    log_level: &ember_daemon::infra::config::LogLevel,
    console: bool,
) -> LogGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level.as_filter_str()));

    let log_dir = data_dir;
    let file_appender = tracing_appender::rolling::daily(log_dir, "daemon.log");
    let (non_blocking, worker_guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking);

    let registry = tracing_subscriber::registry().with(filter).with(file_layer);

    if console {
        let console_layer = tracing_subscriber::fmt::layer();
        registry.with(console_layer).try_init().ok();
    } else {
        registry.try_init().ok();
    }

    tracing::info!(log_dir = %log_dir.display(), log_prefix = "daemon.log", "daemon logging initialized");

    LogGuard {
        _worker: worker_guard,
    }
}

fn load_config(path: Option<&PathBuf>) -> DaemonConfig {
    // When `--config` is absent, fall back
    // through `EMBER_CONFIG` and `EMBER_DEMO_DIR/config.toml` before the
    // default path. Lets `bash scripts/recording-day.sh prep` export
    // `EMBER_DEMO_DIR=/tmp/ember-demo-<id>` and have every subsequent
    // `ember <verb>` talk to the demo daemon without `--config` plumbing.
    if let Some(resolved) = resolved_user_config_path(path) {
        return match DaemonConfig::load(&resolved) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "error: failed to load config from {}: {e}",
                    resolved.display()
                );
                process::exit(1);
            }
        };
    }

    let default_path = DaemonConfig::default_config_path();
    if default_path.exists() {
        match DaemonConfig::load(&default_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "error: failed to load config from {}: {e}",
                    default_path.display()
                );
                process::exit(1);
            }
        }
    } else {
        // Loud-fail instead of silent
        // DaemonConfig::default() fallback. The May-12 25-hour leaked-daemon
        // incident was rooted in this fallback silently inheriting user-home
        // paths in test contexts where --config / EMBER_CONFIG / EMBER_DEMO_DIR
        // were absent. Subtask A's type-system change removes Default outright;
        // this loud-fail closes the same gap from the CLI entry-point.
        let init_cmd =
            init_command_with_ember_command(&ember_command_prefix_for_current_launcher(), None);
        eprintln!(
            "no ember config found at {}. Run `{init_cmd}` to create one, or pass --config <path>.",
            default_path.display(),
        );
        process::exit(1);
    }
}

fn load_bootstrap_config(path: Option<&PathBuf>) -> DaemonConfig {
    if let Some(resolved) = resolved_user_config_path(path) {
        if resolved.exists() {
            return match DaemonConfig::load(&resolved) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!(
                        "error: failed to load config from {}: {e}",
                        resolved.display()
                    );
                    process::exit(1);
                }
            };
        }
    } else {
        let default_path = DaemonConfig::default_config_path();
        if default_path.exists() {
            return match DaemonConfig::load(&default_path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!(
                        "error: failed to load config from {}: {e}",
                        default_path.display()
                    );
                    process::exit(1);
                }
            };
        }
    }

    let base = dirs_next::home_dir()
        .map(|home| home.join(".ember"))
        .unwrap_or_else(|| PathBuf::from("/tmp/.ember"));
    DaemonConfig {
        socket_dir: base.join("run"),
        data_dir: base.join("data"),
        pid_file: base.join("run").join("emberd.pid"),
        policy_file: base.join("policy.toml"),
        log_level: ember_daemon::infra::config::LogLevel::Info,
        dashboard_addr: Some(
            ember_daemon::infra::config::DEFAULT_DASHBOARD_ADDR
                .parse()
                .expect("valid default addr"),
        ),
        git_proxy_addr: Some(
            ember_daemon::infra::config::DEFAULT_GIT_PROXY_ADDR
                .parse()
                .expect("valid default addr"),
        ),
        llm_proxy_addr: Some(
            ember_daemon::infra::config::DEFAULT_LLM_PROXY_ADDR
                .parse()
                .expect("valid default addr"),
        ),
        keyring: ember_daemon::infra::config::KeyringConfig::default(),
        stale_approval_threshold_secs: 3600,
        snapshot_interval_secs: 3600,
        snapshot_pull_interval_secs: 600,
        snapshot_pull_endpoint: None,
        snapshot_pull_cluster_id: None,
        presence: ember_daemon::infra::config::PresenceConfigSection::default(),
        credential_store: None,
        runtime_backend: ember_daemon::spawn::runtime::RuntimeBackend::DockerEngine,
        scion_binary_path: PathBuf::new(),
        scion_binary_sha256: String::new(),
        bridge_bind: None,
        trust_roots: String::new(),
        spawn_pool: None,
        tier: ember_daemon::infra::config::DeploymentTier::Dev0,
        // V030-AUTH-LEASE-3: single-knob per-window lease TTL (1h default).
        // Operators override via `[daemon].lease_ttl_secs` or
        // `EMBER_LEASE_TTL_SECS`; range-checked in `DaemonConfig::validate`.
        lease_ttl_secs: ember_daemon::infra::config::DEFAULT_LEASE_TTL_SECS,
    }
}

fn load_config_if_present_or_default(path: Option<&PathBuf>) -> DaemonConfig {
    if let Some(resolved) = resolved_user_config_path(path)
        && resolved.exists()
    {
        return match DaemonConfig::load(&resolved) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "error: failed to load config from {}: {e}",
                    resolved.display()
                );
                process::exit(1);
            }
        };
    }

    let default_path = DaemonConfig::default_config_path();
    if default_path.exists() {
        match DaemonConfig::load(&default_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "error: failed to load config from {}: {e}",
                    default_path.display()
                );
                process::exit(1);
            }
        }
    } else {
        load_bootstrap_config(path)
    }
}

fn command_allows_bootstrap_config(command: &Commands) -> bool {
    match command {
        Commands::Init { .. } => true,
        Commands::Daemon { action } => matches!(
            action,
            DaemonAction::Install { .. }
                | DaemonAction::InstallAgent { .. }
                | DaemonAction::UninstallAgent
                | DaemonAction::Migrate { .. }
        ),
        _ => false,
    }
}

fn command_allows_missing_config(command: &Commands) -> bool {
    match command {
        // receipt_verify_file_config_independent: file/tree/materialization
        // verify modes are daemon-free and should reach their own content/path
        // errors even when no ~/.ember/config.toml exists.
        Commands::Receipt {
            action:
                ReceiptAction::Verify {
                    id: None,
                    file,
                    materialization,
                    tree,
                    ..
                },
        } => file.is_some() || materialization.is_some() || tree.is_some(),
        _ => false,
    }
}

#[cfg(test)]
fn init_rerun_command(for_target: Option<OnboardingTarget>) -> &'static str {
    match for_target {
        Some(OnboardingTarget::Claude) => "`ember init --for claude`",
        Some(OnboardingTarget::Codex) => "`ember init --for codex`",
        Some(OnboardingTarget::Cursor) => "`ember init --for cursor`",
        Some(OnboardingTarget::Gemini) => "`ember init --for gemini`",
        None => "`ember init`",
    }
}

fn init_rerun_command_with_ember_command(
    ember_cmd: &str,
    for_target: Option<OnboardingTarget>,
) -> String {
    format!(
        "`{}`",
        init_command_with_ember_command(ember_cmd, for_target)
    )
}

fn init_managed_daemon_install_starting_line(ember_cmd: &str) -> String {
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(ember_cmd);
    format!("  Daemon:   not running — running `{daemon_install_cmd}`")
}

fn init_managed_daemon_install_started_line() -> &'static str {
    "  Daemon:   managed separate-uid daemon is up"
}

fn init_autostart_repair_line(ember_cmd: &str, rerun_cmd: &str) -> String {
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(ember_cmd);
    format!(
        "Run `{daemon_install_cmd}` to install or repair the managed daemon service, \
         then re-run {rerun_cmd}."
    )
}

fn init_noncanonical_daemon_topology_line(ember_cmd: &str, rerun_cmd: &str) -> String {
    let daemon_install_cmd = sudo_daemon_install_command_with_ember_command(ember_cmd);
    format!(
        "Friendly init only auto-installs the managed daemon from the default operator HOME \
         and default config path. This invocation is using an isolated HOME or custom config, \
         so the same-uid fallback is refused. Run `{daemon_install_cmd}` from your normal \
         shell and then re-run {rerun_cmd}."
    )
}

fn wait_for_init_daemon_socket(socket_path: &Path) -> Result<(), String> {
    let timeout_secs = emberlink_cli::onboarding::claude_code::autostart_liveness_timeout_secs();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let pid_path = socket_path
        .parent()
        .map(|dir| dir.join("emberd.pid"))
        .unwrap_or_else(|| std::path::PathBuf::from("emberd.pid"));
    loop {
        match emberlink_cli::probe_live_daemon_status(socket_path, &pid_path) {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "daemon install completed but the live status probe failed: {e}"
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "daemon install completed but the daemon never became live within {timeout_secs}s \
                 (expected socket at {}); check daemon logs at $HOME/.ember/logs/daemon.out and retry. \
                 Override the timeout with EMBER_DAEMON_AUTOSTART_TIMEOUT_SECS=<seconds>.",
                socket_path.display()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn ensure_managed_daemon_for_init(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    ember_cmd: &str,
    rerun_cmd: &str,
    non_interactive: bool,
) -> Result<(), String> {
    let socket_path = config.socket_dir.join("daemon.sock");
    match emberlink_cli::probe_live_daemon_status(&socket_path, &config.pid_file) {
        Ok(Some(live)) => {
            println!(
                "  Daemon:   already running (socket {})",
                live.socket.display()
            );
            return Ok(());
        }
        Ok(None) => {}
        Err(e) => return Err(format!("could not inspect managed daemon posture: {e}")),
    }

    let config_path = resolved_user_config_path(cli_config_path);
    let home = dirs_next::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
    if !emberlink_cli::onboarding::claude_code::supports_managed_daemon_install(
        &home,
        config_path.as_deref(),
    ) {
        return Err(init_noncanonical_daemon_topology_line(ember_cmd, rerun_cmd));
    }

    if non_interactive || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err(init_autostart_repair_line(ember_cmd, rerun_cmd));
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("could not resolve ember binary for managed install: {e}"))?;
    println!("{}", init_managed_daemon_install_starting_line(ember_cmd));
    let status = std::process::Command::new("sudo")
        .arg(&exe)
        .arg("daemon")
        .arg("install")
        .status()
        .map_err(|e| format!("failed to launch `sudo ember daemon install`: {e}"))?;
    if !status.success() {
        let suffix = status
            .code()
            .map(|code| format!("exit code {code}"))
            .unwrap_or_else(|| "terminated by signal".to_string());
        return Err(format!(
            "managed daemon install failed ({suffix}). {}",
            init_autostart_repair_line(ember_cmd, rerun_cmd)
        ));
    }

    wait_for_init_daemon_socket(&socket_path)?;
    println!("{}", init_managed_daemon_install_started_line());
    Ok(())
}

fn open_store(config: &DaemonConfig) -> DaemonStore {
    if let Err(e) = config.ensure_dirs() {
        eprintln!("error: failed to create directories: {e}");
        process::exit(1);
    }
    let db_path = config.data_dir.join("daemon.db");
    let store = match DaemonStore::open(&db_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: failed to open database: {e}");
            process::exit(1);
        }
    };

    // In-process CLI subcommands (grant/sandbox/persona) talk to
    // the same SQLite DB the daemon uses, but without going through the
    // socket — so they need their own attached vault to encrypt/decrypt
    // persona secrets. Best-effort auto-unseal from keyring is still useful
    // for dev/test and same-uid local paths.
    //
    // Under ADR 131's managed separate-uid topology, though, the keyring lane
    // has been superseded by the daemon's native unlock RPC. Offline local
    // summaries (for example `ember status` when the daemon is down) must not
    // drag the operator back through the legacy login-keychain prompt.
    // ADR 216 S4: direct SE unseal retired. Vault opens exclusively via the
    // daemon's double-envelope unlock RPC. CLI commands that need the vault
    // access it through the daemon socket, not via local Vault::open_from_config.

    // Initialise the daemon's Ed25519 process identity so that
    // `DaemonStore::revoke_grant` (and other terminal-transition paths)
    // can emit signed Grant Receipts via `trigger_receipt_if_terminal_current`.
    // Without this, the identity `OnceCell` stays empty and receipt emission
    // silently no-ops, leaving `ember receipt show <id>` returning "grant
    // exists but has not reached terminal state".
    if let Err(e) = ember_daemon::infra::receipt::init_identity(&config.data_dir) {
        tracing::warn!("could not initialise daemon identity for receipt emission: {e}");
    }

    store
}

/// Detect whether a basic `ember init` has
/// already been run. Returns true if `daemon.db` exists in `config.data_dir`.
/// On live daemon-backed runs the daemon owns creating that file; the old
/// local-store fallback still creates it in-process. Used by the
/// `--for claude` handler to skip re-running basic init (and creating a
/// duplicate "root" persona) when the daemon DB is already present.
fn is_ember_initialized(config: &DaemonConfig) -> bool {
    config.data_dir.join("daemon.db").exists()
}

fn should_skip_basic_init(for_target: Option<OnboardingTarget>, config: &DaemonConfig) -> bool {
    for_target.is_some() && is_ember_initialized(config)
}

/// Resolve an image digest via `docker inspect`. Returns None if docker is unavailable or fails.
fn resolve_image_digest(image: &str) -> Option<String> {
    let output = std::process::Command::new("docker")
        .args(["inspect", "--format={{.Id}}", image])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let digest = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if digest.is_empty() {
        None
    } else {
        Some(digest)
    }
}

/// Record an image digest into the registry at `registry_path`.
/// Prints a warning to stderr if the digest changed (tag mutation detected).
pub fn record_image_digest(registry_path: &Path, image: &str, digest: &str) {
    let mut registry = match ImageRegistry::load(registry_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: could not load image registry: {e}");
            return;
        }
    };
    let already_known = registry.images.contains_key(image);
    let digest_changed = already_known && !registry.verify(image, digest);
    registry.record(image, digest, "docker");
    if let Err(e) = registry.save(registry_path) {
        eprintln!("warning: could not save image registry: {e}");
        return;
    }
    if digest_changed {
        eprintln!("warning: image {image} digest changed — possible tag mutation");
    }
}

/// Default policy seed written by `ember init` when no `policy.toml` exists.
/// Schema must round-trip through `core_approval::policy::PolicyConfig` —
/// regression-tested in `tests::default_policy_seed_parses`.
const DEFAULT_POLICY_TOML: &str = "\
# Ember daemon policy
# Rules evaluated in order — first match wins.

default_requirement = \"required\"
default_risk = \"medium\"

[[rules]]
action = \"git.push.main\"
risk = \"critical\"
requirement = \"denied\"

[[rules]]
action = \"git.push.*\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"deploy.production\"
risk = \"critical\"
requirement = \"required\"

[[rules]]
action = \"deploy.staging\"
risk = \"medium\"
requirement = \"auto\"

[[rules]]
action = \"credential.access\"
risk = \"high\"
requirement = \"required\"
";

/// Resolve a keyring service/account value for `ember init`. Pure function so
/// tests can verify the priority order (flag → env → default) without mutating
/// process-global environment — env races caused `ember init` to leak to the
/// production keyring on 2026-04-23.
fn resolve_init_keyring_value(
    flag: Option<String>,
    env_value: Option<String>,
    default_value: &str,
) -> String {
    flag.or(env_value)
        .unwrap_or_else(|| default_value.to_string())
}

fn take_init_vault_passphrase_override() -> Option<String> {
    let passphrase = std::env::var("EMBER_VAULT_PASSPHRASE").ok();
    if passphrase.is_some() {
        unsafe { std::env::remove_var("EMBER_VAULT_PASSPHRASE") };
    }
    passphrase
}

fn load_first_grant_receipt_summary(
    receipt_path: &Path,
    reused_existing: bool,
) -> Result<FirstGrantReceiptSummaryView, String> {
    let raw = std::fs::read_to_string(receipt_path)
        .map_err(|e| format!("read init first-grant receipt: {e}"))?;
    let file: emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile =
        serde_json::from_str(&raw).map_err(|e| format!("parse init first-grant receipt: {e}"))?;
    Ok(summarize_first_grant_receipt(
        receipt_path.to_path_buf(),
        &file,
        reused_existing,
    ))
}

fn emit_first_grant_receipt_after_init(
    config: &DaemonConfig,
    socket_path: &Path,
    persona_id: &str,
    persona_public_key: &str,
) -> Result<FirstGrantReceiptSummaryView, String> {
    if let Some(receipt_path) =
        emberlink_cli::onboarding::first_grant::short_circuit_first_grant_receipt_emit(
            &config.data_dir,
        )
    {
        return load_first_grant_receipt_summary(&receipt_path, true);
    }

    let built = emberlink_cli::call_daemon_method(
        socket_path,
        "build_init_first_grant_receipt",
        &serde_json::json!({"persona_id": persona_id}),
    )
    .map_err(|e| format!("build init first-grant receipt (rpc): {e}"))?;
    let file: emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile =
        serde_json::from_value(built)
            .map_err(|e| format!("parse init first-grant receipt (rpc): {e}"))?;
    let _ = persona_public_key;
    let receipt_path = emberlink_cli::onboarding::first_grant::write_first_grant_receipt_file(
        &config.data_dir,
        &file,
    )
    .map_err(|e| e.to_string())?;
    Ok(summarize_first_grant_receipt(receipt_path, &file, false))
}

// CLI command handler — flags map 1:1 to init params, structurally many params.
#[allow(clippy::too_many_arguments)]
fn cmd_init(
    config: &DaemonConfig,
    name: Option<String>,
    for_target: Option<OnboardingTarget>,
    cli_config_path: Option<&PathBuf>,
    keyring_service_override: Option<String>,
    keyring_account_override: Option<String>,
    touch_id: bool,
    non_interactive: bool,
) {
    // P63.A: `--touch-id` selects the SE-backed VaultKeyStore lane on macOS.
    // The SE wiring itself is deferred to P63.A-SE-WIRE; today the flag is
    // accepted so the init flow + config schema can land first. Print a
    // notice and fall back to the passphrase lane until the wiring ships.
    //
    // On non-macOS, the flag is a hard error — Touch ID has no meaning.
    if touch_id {
        #[cfg(target_os = "macos")]
        {
            eprintln!(
                "note: --touch-id is accepted but not yet wired (P63.A-SE-WIRE).\n      \
                 Falling back to the passphrase lane for this init."
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("error: --touch-id is only supported on macOS.");
            process::exit(1);
        }
    }
    // Respect --config: if the user passed one, use it as the init target;
    // otherwise consult `EMBER_CONFIG` / `EMBER_DEMO_DIR` (config
    // auto-discovery) before falling back to the default
    // (`~/.ember/config.toml`).
    let config_path = resolved_user_config_path(cli_config_path)
        .unwrap_or_else(DaemonConfig::default_config_path);

    if let Err(e) = config.ensure_dirs() {
        eprintln!("error: failed to create directories: {e}");
        process::exit(1);
    }

    // Determine the keyring service/account to embed in the config.
    // Matches daemon-runtime `resolve_keyring_service` at vault.rs:249 so
    // CLI and daemon paths agree. Missing env-var fallback was the
    // 2026-04-23 leak: qember.sh set the env but `ember init` wrote the
    // passphrase to the production service anyway.
    let init_keyring_service = resolve_init_keyring_value(
        keyring_service_override.clone(),
        std::env::var("EMBER_KEYRING_SERVICE").ok(),
        DEFAULT_KEYRING_SERVICE,
    );
    let init_keyring_account = resolve_init_keyring_value(
        keyring_account_override.clone(),
        std::env::var("EMBER_KEYRING_ACCOUNT").ok(),
        DEFAULT_KEYRING_ACCOUNT,
    );

    // If the config file doesn't exist yet, write the default template.
    // If it already exists, respect the user's config and skip overwriting —
    // but refuse if a persona has already been created (truly already initialized).
    if !config_path.exists() {
        // Shared template with the install lane's `write_default_config_if_absent`
        // (ADR 202): config.toml is system configuration, written identically by
        // whichever first-run path reaches it first.
        let default_config = ember_daemon::install::default_config_toml(
            &init_keyring_service,
            &init_keyring_account,
        );
        if let Err(e) = fs::write(&config_path, &default_config) {
            eprintln!("error: failed to write config: {e}");
            process::exit(1);
        }
    }

    // Use the loaded config's policy_file path (respects --config + explicit overrides).
    let policy_path = config.policy_file.clone();
    if !policy_path.exists()
        && let Err(e) = fs::write(&policy_path, DEFAULT_POLICY_TOML)
    {
        eprintln!("warning: failed to write policy: {e}");
    }

    let root_name = name.as_deref().unwrap_or("root");
    // init_migrated_to_rpc: cmd_init no longer opens the daemon SQLite store.
    // The daemon owns root persona creation and first-grant signing over RPC
    // under ADR 131 separate-uid posture. Keep consuming the legacy env knob so
    // scripted callers do not leak the bootstrap passphrase to child processes.
    let _ = take_init_vault_passphrase_override();

    // init_persona_rpc_after_autostart_reorder
    // Autostart fires BEFORE the RPC so the socket is live when create_persona dispatches.
    //
    // Under ADR 131 separate-uid posture (daemon=ember uid, operator=operator uid)
    // the operator cannot write the daemon's SQLite DB, so the prior direct
    // `store.create_persona(root_name)` call failed. Route through the daemon
    // JSON-RPC instead. Mirrors the pattern in `cmd_init_for_claude_code`.
    let socket_path = config.socket_dir.join("daemon.sock");
    // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass — same env var as the
    // daemon-install precheck gate above. When set, skip the managed-daemon
    // check so binary tests running against isolated tmp dirs do not try to
    // invoke sudo or wait for a production socket.
    let skip_daemon_install_check = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
    let ember_cmd = ember_command_prefix_for_current_launcher();
    if !skip_daemon_install_check
        && let Err(e) = ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            &ember_cmd,
            &init_rerun_command_with_ember_command(&ember_cmd, for_target),
            non_interactive,
        )
    {
        eprintln!("error: {e}");
        process::exit(1);
    }

    let daemon_socket_live = socket_path.exists();
    let created = match emberlink_cli::call_daemon_method(
        &socket_path,
        "create_persona",
        &serde_json::json!({"name": root_name}),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: failed to create root persona (rpc): {e}");
            process::exit(1);
        }
    };
    let (persona_id, persona_name, persona_public_key, vault_status) = (
        created
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        created
            .get("public_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "managed by daemon (no CLI keychain bootstrap)".to_string(),
    );

    // Emit a real signed Grant
    // Receipt v2 envelope to <data_dir>/receipts/first.json. The CLI asks the
    // daemon to build/sign it; there is no local-store signing fallback in
    // cmd_init under ADR 131 separate-uid posture.
    // init_first_grant_receipt_emit
    let receipt_summary = match emit_first_grant_receipt_after_init(
        config,
        &socket_path,
        &persona_id,
        &persona_public_key,
    ) {
        Ok(summary) => Some(summary),
        Err(e) => {
            eprintln!("warning: first-grant receipt emission failed: {e}");
            if for_target.is_none() {
                // Plain `ember init` still keeps the legacy tips fallback until
                // receipt emission is made fully diagnostic.
                emberlink_cli::onboarding::first_grant::run(&config.data_dir);
            }
            None
        }
    };

    if for_target.is_none() {
        println!(
            "{}",
            render_basic_init_summary(
                &config_path,
                &policy_path,
                &config.data_dir.join("daemon.db"),
                &persona_id,
                &persona_name,
                &vault_status,
                daemon_socket_live,
                &socket_path,
                receipt_summary.as_ref(),
                &ember_cmd,
            )
        );
    }
}

/// Cohort A onboarding orchestrator.
///
/// Runs after `cmd_init` has set up the keyring/vault/salt/root persona.
/// Creates the agent persona, writes the scope template, mints a 24h
/// Relocate any old-layout
/// PATH-shadow shims at `~/.ember/shadow/<tool>` to the canonical
/// `~/.ember/shadow/bin/<tool>` layout and plant back-compat
/// symlinks at the old paths. Idempotent across all four layout
/// states (none / new / old / both). shadow_path_migrate_flag_landed.
fn cmd_migrate_path_shadow_layout() -> Result<(), Box<dyn std::error::Error>> {
    let home = emberlink_cli::onboarding::claude_code::home_dir_for_migrate()?;
    let shadow_root = home.join(".ember").join("shadow");
    let specs = emberlink_cli::launcher::claude_code::managed_prod_construct_specs();
    let outcome =
        emberlink_cli::launcher::path_shadow::migrate_path_shadow_layout(&shadow_root, &specs)?;
    use emberlink_cli::launcher::path_shadow::MigrationOutcome::*;
    match outcome {
        NoShimsAtAll => {
            println!(
                "ember init --migrate: no shims found at {} or {}/bin/; \
                 nothing to migrate. Run `ember init --for claude` (without \
                 --migrate) to install the shadow PATH first.",
                shadow_root.display(),
                shadow_root.display(),
            );
        }
        AlreadyMigrated => {
            println!(
                "ember init --migrate: shadow PATH already on the new \
                 layout at {}/bin/; nothing to migrate (no-op).",
                shadow_root.display(),
            );
        }
        AlreadyMigratedSymlinksInPlace => {
            println!(
                "ember init --migrate: shadow PATH already migrated — old \
                 paths at {} are symlinks pointing into bin/; nothing to do \
                 (no-op).",
                shadow_root.display(),
            );
        }
        MigratedFromOldLayout { count } => {
            println!(
                "ember init --migrate: relocated {count} old-layout \
                 shim(s) under {} to {}/bin/; back-compat symlinks planted \
                 at the old paths.",
                shadow_root.display(),
                shadow_root.display(),
            );
        }
    }
    Ok(())
}

/// What the front-loading `ember init` presence-custody bootstrap actually did
/// on this host. Drives the one-line summary in the init output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresenceCustodyOutcome {
    SkippedNoSecureEnclave,
    SkippedNonInteractive,
    AlreadyOpen,
    Unlocked,
    ProvisionedUnlocked,
    EnrolledProvisionedUnlocked,
}

impl PresenceCustodyOutcome {
    fn summary_line(self) -> String {
        match self {
            Self::SkippedNoSecureEnclave => {
                "Presence custody: unavailable on this build (no Secure Enclave; unsigned/dev). \
                 §4 authority custody is skipped."
                    .to_string()
            }
            Self::SkippedNonInteractive => {
                "Presence custody: NOT provisioned (--non-interactive cannot tap). Re-run \
                 `ember init --for claude` interactively to set up authority custody (one Touch \
                 ID), or run `ember device enroll --secure-enclave`."
                    .to_string()
            }
            Self::AlreadyOpen => {
                "Presence custody: ready (authority window already open).".to_string()
            }
            Self::Unlocked => "Presence custody: authority window opened (Touch ID).".to_string(),
            Self::ProvisionedUnlocked => {
                "Presence custody: provisioned and opened (Touch ID).".to_string()
            }
            Self::EnrolledProvisionedUnlocked => {
                "Presence custody: presence device enrolled, provisioned, and opened.".to_string()
            }
        }
    }
}

/// Front-load ADR 206 §4 presence custody into
/// `ember init` so the reactive launch gauntlet (`ember claude` → `se-unlock`
/// → "run `se-provision` first" → …) never surfaces. Detects this host's
/// custody state WITHOUT a presence tap, then drives the single needed step
/// through the EXISTING custody primitives (`device enroll --secure-enclave`,
/// which auto-chains the §4 provision; `vault.se_provision`; `vault
/// se-unlock`). Idempotent: re-running on a ready host is a no-op — it never
/// re-enrolls an enrolled device nor rotates an already-provisioned scope KEK.
///
/// Lane: CLI-surface orchestration. This only CALLS daemon RPCs / existing
/// commands; the custody internals it sits over remain TROIKA's HOLD set.
fn ensure_claude_code_presence_custody(
    config: &DaemonConfig,
    non_interactive: bool,
) -> Result<PresenceCustodyOutcome, core_types::ValidationError> {
    let se_label = DEFAULT_OPERATOR_PRESENCE_SE_LABEL;
    let state = detect_se_custody_state(config, se_label);
    let plan = plan_presence_custody_bootstrap(
        state.se_backend_real,
        non_interactive,
        state.presence_device_enrolled,
        state.kek_wrap_present,
        state.authority_window_open,
    );
    match plan {
        PresenceCustodyPlan::SkipNoSecureEnclave => {
            Ok(PresenceCustodyOutcome::SkippedNoSecureEnclave)
        }
        PresenceCustodyPlan::SkipNonInteractive => {
            Ok(PresenceCustodyOutcome::SkippedNonInteractive)
        }
        PresenceCustodyPlan::AlreadyOpen => Ok(PresenceCustodyOutcome::AlreadyOpen),
        PresenceCustodyPlan::EnrollProvisionThenUnlock => {
            println!(
                "Setting up operator presence custody (one-time). This is the Touch ID that \
                 authorizes Ember to act on this device."
            );
            run_device_enroll_secure_enclave(
                "Operator Presence Device",
                se_label,
                false,
                None,
                false,
            )?;
            run_vault_se_unlock(se_label, None, false)?;
            Ok(PresenceCustodyOutcome::EnrolledProvisionedUnlocked)
        }
        PresenceCustodyPlan::ProvisionThenUnlock => {
            println!("Provisioning authority custody for the enrolled presence device…");
            provision_vault_se_scope_kek(se_label, false)?;
            run_vault_se_unlock(se_label, None, false)?;
            Ok(PresenceCustodyOutcome::ProvisionedUnlocked)
        }
        PresenceCustodyPlan::UnlockOnly => {
            run_vault_se_unlock(se_label, None, false)?;
            Ok(PresenceCustodyOutcome::Unlocked)
        }
    }
}

/// Model-auth capture (Claude) — drive the Claude
/// plan sign-in and capture the token into the vault so the operator never runs
/// a manual `ember vault add` (operator §0a, 2026-06-07). Plan-auth is the
/// interactive default (proposal decision 5). Preserves the existing
/// detect-or-ambient behavior when a credential already exists, under
/// `--non-interactive`, on a non-TTY, or if the operator declines — capture is
/// strictly additive on the `Absent` path.
fn ensure_claude_code_anthropic_runtime_credential_with_capture(
    config: &DaemonConfig,
    non_interactive: bool,
) -> Result<AnthropicRuntimeCredentialAvailability, core_types::ValidationError> {
    // Existing vault entry / env capture first (cheapest, no prompt).
    let availability = ensure_claude_code_anthropic_runtime_credential(config)?;
    if !matches!(availability, AnthropicRuntimeCredentialAvailability::Absent) {
        return Ok(availability);
    }
    // Absent → offer to drive the plan sign-in. Interactive terminals only;
    // CI / piped / `--non-interactive` falls back to the ambient lane.
    if non_interactive || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(AnthropicRuntimeCredentialAvailability::Absent);
    }
    eprintln!(
        "Ember can capture your Claude plan credential into the presence-gated vault \
         (the agent never sees the raw token)."
    );
    let proceed =
        prompt_yes_no_default_yes("Sign in to your Claude plan now? (runs `claude setup-token`)")
            .map_err(core_types::ValidationError::new)?;
    if !proceed {
        return Ok(AnthropicRuntimeCredentialAvailability::Absent);
    }
    let token = drive_claude_setup_token_capture()?;
    let credential =
        anthropic_runtime_credential_from_value(AnthropicRuntimeCredentialKind::OAuthToken, &token);
    run_vault_store(
        config,
        "vault_add",
        credential.credential_name(),
        token.as_bytes(),
        Some("claude subscription oauth token (claude code runtime)"),
        false,
    )?;
    Ok(AnthropicRuntimeCredentialAvailability::CapturedFromLogin(
        credential,
    ))
}

/// Run `claude setup-token` (the provider's own browser-OAuth flow — we
/// ORCHESTRATE it, we do NOT reimplement OAuth) and capture the printed token.
/// stdin/stderr are inherited so the operator sees the browser instructions and
/// can interact; stdout is captured for the `sk-ant-oat01-…` token.
fn drive_claude_setup_token_capture() -> Result<String, core_types::ValidationError> {
    println!(
        "Launching `claude setup-token` — complete the sign-in in your browser, then return here."
    );
    let output = process::Command::new("claude")
        .arg("setup-token")
        .stdin(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .output()
        .map_err(|e| {
            core_types::ValidationError::new(format!(
                "could not run `claude setup-token` (is the Claude CLI installed and on PATH?): {e}. \
                 Run it manually, then rerun `ember init --for claude` to import it under {CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN}."
            ))
        })?;
    if !output.status.success() {
        return Err(core_types::ValidationError::new(
            "`claude setup-token` did not complete. Re-run `ember init --for claude` to retry the capture.",
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_anthropic_oauth_token(&stdout).ok_or_else(|| {
        core_types::ValidationError::new(format!(
            "`claude setup-token` finished but no token was found in its output. \
             Run it manually, then rerun `ember init --for claude` to import it under {CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN}."
        ))
    })
}

/// What the Codex model-auth capture did, for the init summary line. The
/// present/captured variants carry the resolved keyed vault credential name
/// (`openai/plan/chatgpt-oauth/<account>/<subject>`) so the grant step can bind
/// the exact credential.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CodexRuntimeCredentialOutcome {
    AlreadyPresent { credential_name: String },
    Captured { credential_name: String },
    Absent,
}

impl CodexRuntimeCredentialOutcome {
    fn credential_name(&self) -> Option<&str> {
        match self {
            Self::AlreadyPresent { credential_name } | Self::Captured { credential_name } => {
                Some(credential_name)
            }
            Self::Absent => None,
        }
    }

    fn summary_line(&self) -> String {
        match self {
            Self::AlreadyPresent { credential_name } => {
                format!("Codex auth: reusing {credential_name} from vault.")
            }
            Self::Captured { credential_name } => {
                format!("Codex auth: captured {credential_name} via `codex login`.")
            }
            Self::Absent => format!(
                "Codex auth: no {CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PATTERN} credential yet — run \
                 `codex login`, then rerun `ember init --for codex` to import it."
            ),
        }
    }
}

/// Model-auth capture (Codex) — symmetric with the
/// Claude lane (proposal decision 5: "Claude and Codex are user-facing
/// identical"). Capture the ChatGPT plan credential into the vault so
/// `ember init --for codex` no longer dead-ends on the grant step's missing
/// OpenAI runtime credential error. The credential is keyed by the captured
/// token's account/subject (`openai/plan/chatgpt-oauth/<account>/<subject>`).
/// The daemon already owns the token lifecycle (refresh) + governed-use proxy
/// (ADR 197 §9); this only automates the one-time capture.
fn ensure_codex_openai_runtime_credential_with_capture(
    config: &DaemonConfig,
    non_interactive: bool,
) -> Result<CodexRuntimeCredentialOutcome, core_types::ValidationError> {
    if let Some(credential_name) = preferred_existing_codex_openai_runtime_credential_name(config) {
        return Ok(CodexRuntimeCredentialOutcome::AlreadyPresent { credential_name });
    }
    if non_interactive || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(CodexRuntimeCredentialOutcome::Absent);
    }
    eprintln!(
        "Ember can capture your ChatGPT plan credential into the presence-gated vault \
         (the agent never sees the raw token)."
    );
    let proceed = prompt_yes_no_default_yes(
        "Sign in to your ChatGPT plan now? (runs `codex login` if needed)",
    )
    .map_err(core_types::ValidationError::new)?;
    if !proceed {
        return Ok(CodexRuntimeCredentialOutcome::Absent);
    }
    let tokens_blob = drive_codex_login_and_capture()?;
    // Derive the keyed credential name from the captured token blob (account +
    // id_token subject), mirroring the daemon's account/subject helpers.
    let blob = ember_daemon::infra::codex_oauth::parse_token_blob(tokens_blob.as_bytes()).map_err(
        |e| {
            core_types::ValidationError::new(format!(
                "parse captured Codex token blob: {e}; run `codex login` and retry `ember init --for codex`"
            ))
        },
    )?;
    let credential_name = codex_openai_chatgpt_runtime_credential_name(&blob);
    run_vault_store(
        config,
        "vault_add",
        &credential_name,
        tokens_blob.as_bytes(),
        Some("chatgpt plan oauth token (codex runtime)"),
        false,
    )?;
    Ok(CodexRuntimeCredentialOutcome::Captured { credential_name })
}

fn codex_auth_json_path() -> Option<PathBuf> {
    dirs_next::home_dir().map(|home| home.join(".codex").join("auth.json"))
}

/// Run `codex login` (the provider's own browser-OAuth flow) when
/// `~/.codex/auth.json` is absent, then read + extract the bare `tokens` blob
/// for vault capture. If the file already exists we skip the login and just
/// capture it (codex login is idempotent but a browser round-trip is wasteful).
fn drive_codex_login_and_capture() -> Result<String, core_types::ValidationError> {
    let auth_path = codex_auth_json_path().ok_or_else(|| {
        core_types::ValidationError::new(
            "could not resolve the home directory for ~/.codex/auth.json",
        )
    })?;
    if !auth_path.exists() {
        println!(
            "Launching `codex login` — complete the sign-in in your browser, then return here."
        );
        let status = process::Command::new("codex")
            .arg("login")
            .stdin(process::Stdio::inherit())
            .stderr(process::Stdio::inherit())
            .stdout(process::Stdio::inherit())
            .status()
            .map_err(|e| {
                core_types::ValidationError::new(format!(
                    "could not run `codex login` (is the Codex CLI installed and on PATH?): {e}. \
                     Run it manually, then `ember init --for codex` again."
                ))
            })?;
        if !status.success() {
            return Err(core_types::ValidationError::new(
                "`codex login` did not complete. Re-run `ember init --for codex` to retry.",
            ));
        }
    }
    let raw = std::fs::read_to_string(&auth_path).map_err(|e| {
        core_types::ValidationError::new(format!("could not read {}: {e}", auth_path.display()))
    })?;
    extract_codex_tokens_blob(&raw).ok_or_else(|| {
        core_types::ValidationError::new(format!(
            "{} has no usable `access_token`. Run `codex login`, then rerun \
             `ember init --for codex` to import it under {CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PATTERN}.",
            auth_path.display()
        ))
    })
}

fn cmd_init_for_claude_code(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::claude_code as cc;

    let persona_name = cc::claude_code_persona_name();
    let template_path = cc::default_grant_template_path()?;
    let settings_path = cc::default_settings_json_path()?;
    let ember_cmd = ember_command_prefix_for_current_launcher();

    // Managed-posture: init must only use the managed
    // separate-uid daemon path. If the daemon is missing, offer the canonical
    // `sudo ember daemon install` path in the default operator topology and
    // refuse same-uid fallbacks everywhere else.
    if std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_err() {
        let ember_cmd = ember_command_prefix_for_current_launcher();
        ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            &ember_cmd,
            &init_rerun_command_with_ember_command(&ember_cmd, Some(OnboardingTarget::Claude)),
            non_interactive,
        )?;
    }

    // Route every persona /
    // grant / vault operation through the daemon's JSON-RPC instead of
    // opening SQLite + vault directly. Under ADR 131 separate-uid posture
    // (daemon=ember uid, operator=operator uid) the operator cannot read
    // `~/.ember/data/vault.salt` (mode 0600, daemon-owned), so direct
    // `Vault::open_from_config` returns "salt read: Permission denied".
    // The daemon already has DB + vault authority; the CLI proxies.
    //
    // Daemon-autostart fires earlier in this function (lines ~2596-2664),
    // so the socket is guaranteed live by the time we reach this block. Plain
    // `cmd_init` now follows the same live-socket ordering for root persona
    // creation and first-grant receipt signing, but still keeps bootstrap-local
    // config/keyring/salt work.
    //
    // Anchor: ember_init_for_claude_code_rpc_migration_landed.
    // 1. Find or create the persona via daemon RPC. Calling create_persona
    //    twice with the same name returns an error (UNIQUE constraint), so
    //    we list first and reuse.
    let (mut persona_created, mut persona_id) =
        prepare_runtime_persona_for_reenroll(config, &persona_name)
            .map_err(|e| format!("prepare claude-code persona (rpc): {e}"))?;

    // 2. Write the grant scope template (idempotent — pure file op).
    let template_written = cc::write_grant_template_if_missing(&template_path)?;

    // 3. Repair the managed shadow toolchain up front so the first friendly
    //    launcher run uses installed product constructs rather than stale
    //    repo-local target artifacts.
    let shadow_root = cc::install_managed_prod_shadow_path()
        .map_err(|e| format!("install managed shadow toolchain: {e}"))?;

    // 3b. Front-load ADR 206 §4 presence custody.
    //     A clean store reaches here with NO presence device and NO wrapped
    //     scope KEK; the credential capture (step 4) and grant (step 5) both
    //     need authority custody open. Provisioning it reactively at launch is
    //     the gauntlet (`ember claude` → se-unlock → "run se-provision first").
    //     Detect-and-invoke here instead, idempotently, so the first
    //     `ember claude` just works. On hosts without a real Secure Enclave
    //     (dev/CI) or under `--non-interactive` this is a no-op.
    let custody_outcome = ensure_claude_code_presence_custody(config, non_interactive)
        .map_err(|e| format!("set up presence custody: {e}"))?;
    println!("{}", custody_outcome.summary_line());

    // 4. Seed, detect, or CAPTURE Anthropic runtime auth for Claude Code.
    //    Reuse a stored Claude subscription OAuth token / API key when present;
    //    else (interactive) drive `claude setup-token` and capture the plan
    //    token into the presence-gated vault — no manual `ember vault add`
    //    (model-auth capture). Falls back to ambient Claude auth under
    //    `--non-interactive` / non-TTY / decline.
    let anthropic_runtime =
        ensure_claude_code_anthropic_runtime_credential_with_capture(config, non_interactive)
            .map_err(|e| format!("prepare anthropic runtime credential: {e}"))?;

    // 5. Ensure the persona has an active 24h grant. Prefer a composite
    //    Anthropic runtime grant when the vault has the credential; otherwise
    //    fall back to the plain launcher grant.
    let grant = match ensure_claude_code_runtime_grant(
        config,
        &persona_id,
        anthropic_runtime.credential_name(),
    ) {
        Ok(grant) => grant,
        Err(err) => match recover_runtime_persona_after_secret_error(
            config,
            "Claude Code",
            &persona_name,
            &persona_id,
            &err,
        )
        .map_err(|e| format!("recover claude-code persona (rpc): {e}"))?
        {
            Some(recovered_persona_id) => {
                persona_created = true;
                persona_id = recovered_persona_id;
                ensure_claude_code_runtime_grant(
                    config,
                    &persona_id,
                    anthropic_runtime.credential_name(),
                )
                .map_err(|e| format!("ensure claude-code grant after recovery (rpc): {e}"))?
            }
            None => {
                return Err(format!("ensure claude-code grant (rpc): {err}").into());
            }
        },
    };

    // 6. (retired) Per V030-CLAUDE-OVERLAY the bare `~/.claude/settings.json`
    //    is no longer mutated by `ember init`. The brokered Claude session
    //    receives the `permissions.deny` overlay through a launcher-generated
    //    settings.json in a relocated `CLAUDE_CONFIG_DIR` (see
    //    `crate::launcher::settings_overlay`). Operators upgrading from a
    //    pre-V030 install may carry residual deny entries in bare; they are
    //    harmless duplicates against the launcher overlay.

    // 7. GitHub posture guidance. The friendly v0.3.0 story is:
    //    App over HTTPS/API first, SSH substrate exists but is not
    //    auto-wired by `ember claude` yet, PAT only as an explicit
    //    degraded fallback through `ember vault add --name github-pat`.
    let mut github_posture = github_onboarding_posture(config);
    let github_status_cmd = format!("{ember_cmd} github status");
    let daemon_reload_cmd = format!("{ember_cmd} daemon reload");
    let mut github_note: Option<String> = None;
    let should_offer_github_setup = should_offer_inline_github_setup(
        github_posture.clone(),
        non_interactive,
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
    );
    if should_offer_github_setup
        && prompt_decision_card_default_yes(
            "GitHub setup available",
            "Without this, GitHub-brokered actions will fail or stay degraded.",
            "Set up the GitHub App lane now",
            "Skip for now",
        )
        .map_err(|e| format!("prompt GitHub App setup: {e}"))?
    {
        register_github_from_setup_args(
            config,
            &GithubSetupArgs::default(),
            true,
            false,
            &ember_cmd,
        )
        .map_err(|e| format!("GitHub App setup failed: {e}"))?;
        match try_reload_daemon_after_github_setup(config) {
            Ok(GithubSetupDaemonFollowup::Reloaded { .. }) => {
                github_posture = github_onboarding_posture(config);
                github_note =
                    Some("GitHub App setup completed and the daemon reloaded.".to_string());
            }
            Ok(GithubSetupDaemonFollowup::NeedsManualReload) => {
                github_note = Some(format!(
                    "GitHub App credentials were stored, but the lane will stay offline until you run `{daemon_reload_cmd}` and then `{github_status_cmd}`."
                ));
            }
            Err(e) => {
                github_note = Some(format!(
                    "GitHub App credentials were stored, but daemon reload failed: {e}. Run `{daemon_reload_cmd}` and then `{github_status_cmd}`."
                ));
            }
        }
    }

    let launcher_boundary =
        detect_default_installed_launcher_issue().map(|issue| cc::LauncherBoundaryNote {
            detail: issue.detail(),
            repair_guidance: issue.repair_guidance(),
        });
    println!(
        "{}",
        render_claude_init_summary(
            &persona_name,
            persona_created,
            &template_path,
            template_written,
            &shadow_root,
            anthropic_runtime,
            &grant,
            &settings_path,
            &github_posture,
            github_note.as_deref(),
            launcher_boundary.as_ref(),
            &ember_cmd,
        )
    );

    Ok(())
}

fn cmd_init_for_codex(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::codex as co;

    let persona_name = co::codex_persona_name();
    let template_path = co::default_grant_template_path()?;

    if std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_err() {
        let ember_cmd = ember_command_prefix_for_current_launcher();
        ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            &ember_cmd,
            &init_rerun_command_with_ember_command(&ember_cmd, Some(OnboardingTarget::Codex)),
            non_interactive,
        )?;
    }

    let (mut persona_created, mut persona_id) =
        prepare_runtime_persona_for_reenroll(config, &persona_name)
            .map_err(|e| format!("prepare codex persona (rpc): {e}"))?;

    let template_written = co::write_grant_template_if_missing(&template_path)?;

    // Front-load ADR 206 §4 presence custody.
    // Custody is provider-agnostic — Codex onboarding front-loads it through
    // the SAME idempotent bootstrap as Claude so neither launch path discovers
    // the gauntlet reactively. No-op on dev/CI hosts and under --non-interactive.
    let custody_outcome = ensure_claude_code_presence_custody(config, non_interactive)
        .map_err(|e| format!("set up presence custody: {e}"))?;
    println!("{}", custody_outcome.summary_line());

    // Capture the ChatGPT plan credential into the vault (symmetric with the
    // Claude lane) so the grant step below does not dead-end on a missing keyed
    // `openai/plan/chatgpt-oauth/<account>/<subject>` credential. The daemon
    // already owns refresh + governed-use (ADR 197 §9); this only front-loads
    // the one-time capture.
    let codex_cred_outcome =
        ensure_codex_openai_runtime_credential_with_capture(config, non_interactive)
            .map_err(|e| format!("prepare codex runtime credential: {e}"))?;
    println!("{}", codex_cred_outcome.summary_line());

    let grant =
        match ensure_codex_runtime_grant(config, &persona_id, codex_cred_outcome.credential_name())
        {
            Ok(grant) => grant,
            Err(err) => match recover_runtime_persona_after_secret_error(
                config,
                "Codex",
                &persona_name,
                &persona_id,
                &err,
            )
            .map_err(|e| format!("recover codex persona (rpc): {e}"))?
            {
                Some(recovered_persona_id) => {
                    persona_created = true;
                    persona_id = recovered_persona_id;
                    ensure_codex_runtime_grant(
                        config,
                        &persona_id,
                        codex_cred_outcome.credential_name(),
                    )
                    .map_err(|e| format!("ensure codex grant after recovery (rpc): {e}"))?
                }
                None => return Err(format!("ensure codex grant (rpc): {err}").into()),
            },
        };

    let ember_cmd = ember_command_prefix_for_current_launcher();
    println!(
        "{}",
        render_codex_init_summary(
            &persona_name,
            persona_created,
            &template_path,
            template_written,
            &grant,
            &ember_cmd,
        )
    );
    Ok(())
}

fn cmd_init_for_cursor(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::cursor as cu;

    let persona_name = cu::cursor_persona_name();
    let template_path = cu::default_grant_template_path()?;

    if std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_err() {
        let ember_cmd = ember_command_prefix_for_current_launcher();
        ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            &ember_cmd,
            &init_rerun_command_with_ember_command(&ember_cmd, Some(OnboardingTarget::Cursor)),
            non_interactive,
        )?;
    }

    let (mut persona_created, mut persona_id) =
        prepare_runtime_persona_for_reenroll(config, &persona_name)
            .map_err(|e| format!("prepare cursor persona (rpc): {e}"))?;

    let template_written = cu::write_grant_template_if_missing(&template_path)?;

    // Cursor baseline needs Ember custody for the local runtime grant, but it
    // does not capture or broker Cursor account/model credentials.
    let custody_outcome = ensure_claude_code_presence_custody(config, non_interactive)
        .map_err(|e| format!("set up presence custody: {e}"))?;
    println!("{}", custody_outcome.summary_line());

    let grant = match ensure_cursor_runtime_grant(config, &persona_id) {
        Ok(grant) => grant,
        Err(err) => match recover_runtime_persona_after_secret_error(
            config,
            "Cursor",
            &persona_name,
            &persona_id,
            &err,
        )
        .map_err(|e| format!("recover cursor persona (rpc): {e}"))?
        {
            Some(recovered_persona_id) => {
                persona_created = true;
                persona_id = recovered_persona_id;
                ensure_cursor_runtime_grant(config, &persona_id)
                    .map_err(|e| format!("ensure cursor grant after recovery (rpc): {e}"))?
            }
            None => return Err(format!("ensure cursor grant (rpc): {err}").into()),
        },
    };

    let ember_cmd = ember_command_prefix_for_current_launcher();
    println!(
        "{}",
        render_cursor_init_summary(
            &persona_name,
            persona_created,
            &template_path,
            template_written,
            &grant,
            &ember_cmd,
        )
    );
    Ok(())
}

fn cmd_uninstall_for_codex() -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::codex as co;

    println!("Uninstalling Codex integration:");
    println!(
        "  Nothing to remove from Codex config: the persona, grant, and template \
         are left in place because they may be in use."
    );
    println!("{}", co::codex_auth_status_line());
    Ok(())
}

fn cmd_uninstall_for_cursor() -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::cursor as cu;

    println!("Uninstalling Cursor integration:");
    println!(
        "  Nothing to remove from Cursor config: the persona, grant, and template \
         are left in place because they may be in use."
    );
    println!("{}", cu::cursor_auth_status_line());
    Ok(())
}

/// Outcome of the gemini Code Assist credential import step (ADR 215 §2).
enum GeminiRuntimeCredentialOutcome {
    AlreadyPresent,
    Captured,
    Absent,
}

impl GeminiRuntimeCredentialOutcome {
    fn summary_line(&self) -> String {
        use emberlink_cli::onboarding::gemini::GEMINI_CODE_ASSIST_CREDENTIAL as CRED;
        match self {
            Self::AlreadyPresent => format!("Gemini auth: reusing {CRED} from vault."),
            Self::Captured => {
                format!("Gemini auth: imported ~/.gemini/oauth_creds.json into {CRED}.")
            }
            Self::Absent => format!(
                "Gemini auth: no {CRED} credential yet — sign in with Google in the Gemini CLI \
                 (run `gemini`, choose \"Login with Google\"), then rerun `ember init --for gemini` to import it."
            ),
        }
    }
}

/// Import the host Gemini CLI's Code Assist OAuth blob
/// (`~/.gemini/oauth_creds.json`) into the presence-gated vault under the fixed
/// `google/code-assist-oauth` name (ADR 215 §2). Unlike codex there is no
/// capture subprocess — the operator signs in via the native Gemini CLI first;
/// this only automates the one-time import (with consent). The daemon owns the
/// token lifecycle (refresh) + governed-use proxy; the durable refresh token
/// never leaves the vault.
fn ensure_gemini_code_assist_runtime_credential_with_capture(
    config: &DaemonConfig,
    non_interactive: bool,
) -> Result<GeminiRuntimeCredentialOutcome, core_types::ValidationError> {
    if gemini_code_assist_runtime_credential_present(config) {
        return Ok(GeminiRuntimeCredentialOutcome::AlreadyPresent);
    }
    // Never silently import the durable credential without an interactive consent
    // gate (adversarial M2; mirrors the codex lane). In non-interactive / no-TTY
    // mode return Absent — the grant step then errors with actionable guidance to
    // re-run interactively, rather than importing a durable refresh token unasked.
    if non_interactive || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(GeminiRuntimeCredentialOutcome::Absent);
    }
    let Some(host_path) = emberlink_cli::onboarding::gemini::host_oauth_creds_path() else {
        return Ok(GeminiRuntimeCredentialOutcome::Absent);
    };
    let bytes = match std::fs::read(&host_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(GeminiRuntimeCredentialOutcome::Absent);
        }
        Err(e) => {
            return Err(core_types::ValidationError::new(format!(
                "read host Gemini oauth_creds at {}: {e}",
                host_path.display()
            )));
        }
    };
    // Validate the blob parses as JSON before storing (a corrupt file should not
    // silently land in the vault).
    serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| {
        core_types::ValidationError::new(format!(
            "parse host Gemini oauth_creds at {}: {e}; re-run the Gemini \"Login with Google\" flow",
            host_path.display()
        ))
    })?;

    // Interactive by construction here (the non-interactive / no-TTY case
    // returned Absent above). Require explicit consent before importing.
    eprintln!(
        "Ember can import your Gemini Code Assist sign-in ({}) into the presence-gated vault \
         (the agent never sees the durable refresh token).",
        host_path.display()
    );
    let proceed = prompt_yes_no_default_yes("Import your Gemini Code Assist sign-in now?")
        .map_err(core_types::ValidationError::new)?;
    if !proceed {
        return Ok(GeminiRuntimeCredentialOutcome::Absent);
    }

    run_vault_store(
        config,
        "vault_add",
        emberlink_cli::onboarding::gemini::GEMINI_CODE_ASSIST_CREDENTIAL,
        &bytes,
        Some("google code assist oauth (gemini runtime)"),
        false,
    )?;
    Ok(GeminiRuntimeCredentialOutcome::Captured)
}

fn cmd_init_for_gemini(
    config: &DaemonConfig,
    cli_config_path: Option<&PathBuf>,
    non_interactive: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::gemini as ge;

    let persona_name = ge::gemini_persona_name();

    if std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_err() {
        let ember_cmd = ember_command_prefix_for_current_launcher();
        ensure_managed_daemon_for_init(
            config,
            cli_config_path,
            &ember_cmd,
            &init_rerun_command_with_ember_command(&ember_cmd, Some(OnboardingTarget::Gemini)),
            non_interactive,
        )?;
    }

    let (mut persona_created, mut persona_id) =
        prepare_runtime_persona_for_reenroll(config, &persona_name)
            .map_err(|e| format!("prepare gemini persona (rpc): {e}"))?;

    // Provider-agnostic ADR 206 §4 presence custody — front-loaded through the
    // same idempotent bootstrap as Claude/Codex.
    let custody_outcome = ensure_claude_code_presence_custody(config, non_interactive)
        .map_err(|e| format!("set up presence custody: {e}"))?;
    println!("{}", custody_outcome.summary_line());

    // Import the Code Assist OAuth blob into the vault so the grant step does not
    // dead-end on a missing `google/code-assist-oauth` credential.
    let cred_outcome = ensure_gemini_code_assist_runtime_credential_with_capture(
        config,
        non_interactive,
    )
    .map_err(|e| format!("prepare gemini runtime credential: {e}"))?;
    println!("{}", cred_outcome.summary_line());

    let grant = match ensure_gemini_runtime_grant(config, &persona_id) {
        Ok(grant) => grant,
        Err(err) => match recover_runtime_persona_after_secret_error(
            config,
            "Gemini",
            &persona_name,
            &persona_id,
            &err,
        )
        .map_err(|e| format!("recover gemini persona (rpc): {e}"))?
        {
            Some(recovered_persona_id) => {
                persona_created = true;
                persona_id = recovered_persona_id;
                ensure_gemini_runtime_grant(config, &persona_id)
                    .map_err(|e| format!("ensure gemini grant after recovery (rpc): {e}"))?
            }
            None => return Err(format!("ensure gemini grant (rpc): {err}").into()),
        },
    };

    let ember_cmd = ember_command_prefix_for_current_launcher();
    println!(
        "{}",
        render_gemini_init_summary(
            &persona_name,
            persona_created,
            &cred_outcome.summary_line(),
            &grant,
            &ember_cmd,
        )
    );
    Ok(())
}

fn cmd_uninstall_for_gemini() -> Result<(), Box<dyn std::error::Error>> {
    use emberlink_cli::onboarding::gemini as ge;

    println!("Uninstalling Gemini integration:");
    println!(
        "  Nothing to remove from Gemini config: the persona, grant, and imported \
         credential are left in place because they may be in use."
    );
    println!("{}", ge::gemini_auth_status_line());
    Ok(())
}

/// `uninstall --for claude` orchestration.
///
/// Per V030-CLAUDE-OVERLAY (2026-06-12), `ember init --for claude` no
/// longer mutates the operator's bare `~/.claude/settings.json`, so
/// there is no deny-rule patch to reverse. Operators upgrading from a
/// pre-V030 install may carry residual deny entries in bare; they are
/// harmless and can be removed by hand.
fn cmd_uninstall_for_claude_code() -> Result<(), Box<dyn std::error::Error>> {
    println!("Uninstalling Claude Code integration:");
    println!(
        "  Nothing to remove from ~/.claude/settings.json — `ember init --for claude` no longer\n  \
         mutates it (V030-CLAUDE-OVERLAY). The brokered Claude session's structural credential\n  \
         lever is the proxy stripping inbound auth, not the harness deny rules; for an isolated\n  \
         lane use `ember claude --isolated` (container, ADR 213)."
    );
    println!();
    println!(
        "Note: persona, grant, and any github-pat vault entry are kept. \
         Remove them manually with `ember persona revoke`, `ember grant revoke`, \
         and `ember vault remove github-pat` if you want a full clean-up."
    );
    Ok(())
}

/// Install the ember daemon as a managed user service (LaunchAgent on macOS,
/// systemd user unit on Linux). See `daemon_agent` for the platform-specific
/// details. Prints a status summary on success; exits non-zero on failure.
fn cmd_daemon_install_agent(cli_config: Option<&PathBuf>, no_autostart: bool) {
    // Config path lookup: --config wins, then `EMBER_CONFIG` /
    // `EMBER_DEMO_DIR/config.toml` (config auto-discovery), then the
    // default (`~/.ember/config.toml`). We only pass a path through to the
    // plist/unit if the file actually exists — otherwise the service would
    // crash-loop on startup waiting for a config that isn't there.
    let config_path = resolved_user_config_path(cli_config).or_else(|| {
        let default = DaemonConfig::default_config_path();
        if default.exists() {
            Some(default)
        } else {
            None
        }
    });

    match daemon_agent::install_agent(config_path.as_deref(), no_autostart) {
        Ok(outcome) => {
            if outcome.wrote_file {
                println!("Installed ember daemon as a user service");
            } else {
                println!("Service file already up to date (no changes)");
            }
            println!("  File:      {}", outcome.file_path.display());
            if let Ok(logs) = daemon_agent::logs_dir() {
                println!("  Logs:      {}/daemon.{{out,err}}", logs.display());
            }
            if outcome.bootstrapped {
                println!("  Status:    running (auto-start on login)");
            } else if no_autostart {
                println!("  Status:    installed, not started (--no-autostart)");
            } else {
                println!("  Status:    installed");
            }
            println!();
            println!("  Stop:      ember daemon stop            (graceful; service auto-restarts)");
            println!("  Reload:    ember daemon reload          (after rebuild)");
            println!("  Uninstall: ember daemon uninstall-agent");
        }
        Err(daemon_agent::AgentError::UnsupportedPlatform) => {
            eprintln!(
                "error: ember daemon install-agent is a dev-only same-uid path and is only supported on macOS and Linux."
            );
            eprintln!(
                "       For the canonical managed daemon posture, use `sudo ember daemon install`."
            );
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to install agent: {e}");
            process::exit(1);
        }
    }
}

/// Uninstall the managed user service. Idempotent — silently succeeds even if
/// nothing is currently installed.
fn cmd_daemon_uninstall_agent() {
    match daemon_agent::uninstall_agent() {
        Ok(outcome) => {
            if outcome.removed_file {
                println!("Uninstalled ember daemon user service");
                println!("  Removed: {}", outcome.file_path.display());
            } else {
                println!("ember daemon user service was not installed (nothing to remove)");
            }
            if outcome.unbootstrapped {
                println!("  Stopped: running service");
            }
        }
        Err(daemon_agent::AgentError::UnsupportedPlatform) => {
            eprintln!("error: not a managed-service platform — nothing to uninstall");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: failed to uninstall agent: {e}");
            process::exit(1);
        }
    }
}

/// Refuse privileged daemon install/migrate flows unless the current process
/// is already running as root.
///
/// The canonical operator surface is `sudo ember daemon install` /
/// `sudo ember daemon migrate ...`. A plain `ember daemon install` is not a
/// wrapper that self-elevates — it shells directly into `dseditgroup`,
/// `dscl`, `useradd`, and launch-service mutation. If we only check that
/// `sudo` exists on `PATH`, the command falls through into low-level
/// provisioning errors like `Username and password must be provided` instead
/// of surfacing the real operator action. Keep the gate here so the failure
/// is loud, early, and points at the exact supported command.
fn require_root_install_invocation(command_hint: &str) -> Result<(), String> {
    let current_launcher_lane = detect_current_launcher_lane();
    require_root_install_invocation_inner(
        || {
            // SAFETY: `geteuid` is a pure libc query with no preconditions.
            unsafe { libc::geteuid() == 0 }
        },
        || {
            std::process::Command::new("which")
                .arg("sudo")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        },
        command_hint,
        current_launcher_lane.as_ref(),
    )
}

fn require_root_install_invocation_inner<IsRoot, HasSudo>(
    is_root: IsRoot,
    has_sudo: HasSudo,
    command_hint: &str,
    current_launcher_lane: Option<&CurrentLauncherLane>,
) -> Result<(), String>
where
    IsRoot: FnOnce() -> bool,
    HasSudo: FnOnce() -> bool,
{
    if is_root() {
        return Ok(());
    }

    if has_sudo() {
        let rerun_cmd = sudo_command_for_launcher(command_hint, current_launcher_lane);
        return Err(format!(
            "error: `ember {command_hint}` must be run via sudo from your normal user shell.\n       \
             Re-run exactly as:\n         \
             {rerun_cmd}"
        ));
    }

    Err(
        "error: `sudo` not found on PATH — privileged daemon install steps require sudo.\n       \
         Install sudo or run the install steps manually as root:\n         \
         - macOS: `dseditgroup -o create ember`, `sysadminctl -addUser ember ...`, \
         `dseditgroup -o create ember-clients`\n         \
         - Linux: `groupadd --system ember`, `useradd --system ... ember`, \
         `groupadd --system ember-clients`\n       \
         See ADR 131 §macOS install / §Linux install for the full sequence."
            .to_string(),
    )
}

fn sudo_command_for_launcher(
    command_hint: &str,
    current_launcher_lane: Option<&CurrentLauncherLane>,
) -> String {
    match current_launcher_lane {
        Some(CurrentLauncherLane::RepoBuild { path } | CurrentLauncherLane::Other { path }) => {
            format!("sudo {} {command_hint}", shell_quote(path))
        }
        Some(CurrentLauncherLane::InstalledHost { .. }) | None => {
            format!("sudo ember {command_hint}")
        }
    }
}

fn ember_command_prefix_for_current_launcher() -> String {
    let current_launcher_lane = detect_current_launcher_lane();
    ember_command_prefix_for_launcher_lane(current_launcher_lane.as_ref())
}

fn ember_command_prefix_for_launcher_lane(
    current_launcher_lane: Option<&CurrentLauncherLane>,
) -> String {
    match current_launcher_lane {
        Some(CurrentLauncherLane::RepoBuild { path } | CurrentLauncherLane::Other { path }) => {
            shell_quote(path)
        }
        Some(CurrentLauncherLane::InstalledHost { .. }) | None => "ember".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn launchd_trust_roots_for_install() -> String {
    if let Ok(raw) = std::env::var("EMBER_TRUST_ROOTS") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    match emberlink_cli::dev::identity_root::read_existing_dev_identity_root_pubkey_hex() {
        Ok(opt) => opt.unwrap_or_default(),
        Err(e) => {
            // Non-fatal — without this dev IdentityRoot, launchd gets no
            // additional dev trust root. Surface the diagnostic so operators
            // see what's missing.
            eprintln!(
                "warning: could not read dev IdentityRoot for EMBER_TRUST_ROOTS \
                 (run `ember dev install` to provision): {e}"
            );
            String::new()
        }
    }
}

/// Install the ember daemon under the separate-uid posture (ADR 131).
///
/// Default flow (`--single-uid` not set):
/// 1. Provision the `ember` system user + the `ember-clients` connect group
///    via [`ember_daemon::install::provision_ember_user`].
/// 2. chown the daemon's at-rest state to `ember:ember-clients`.
/// 3. Install the platform launcher (LaunchDaemon plist on macOS / systemd
///    unit on Linux) via [`ember_daemon::install::install_launchd_plist`] /
///    [`ember_daemon::install::install_systemd_unit`].
///
/// `--single-uid` is the dev-mode escape hatch (relaxed threat model — a
/// process running as the operator's uid can bypass the broker by reading
/// the vault directly). Reserved but not yet implemented; surfaces a clear
/// error pointing back to the canonical installed daemon posture.
///
/// Privileged steps (`provision_ember_user`, `install_launchd_plist`,
/// `install_systemd_unit`) require root — typically invoked under `sudo`.
/// We surface a clear progress print before each privileged subprocess so
/// the operator knows when sudo will prompt.
fn cmd_daemon_install(args: DaemonInstallArgs) {
    if args.single_uid {
        tracing::warn!(
            "installing single-uid daemon posture (dev mode — relaxed threat model). \
             See ADR 131 §Dev mode."
        );
        eprintln!(
            "error: --single-uid is reserved but not yet implemented.\n       \
             Use the canonical installed posture instead:\n         \
             sudo ember daemon install\n       \
             Tracking issue: ADR 131 §Dev mode."
        );
        process::exit(2);
    }

    // Non-interactive lane. Branches off
    // before any prompt-bearing logic so CI / Dockerfile callers never block
    // on a TTY. The posture string is parsed up-front so an unsupported
    // posture surfaces a clean clap-style error instead of running half the
    // install before refusing.
    if args.non_interactive {
        let posture = match args.posture.as_deref() {
            Some(raw) => match emberlink_cli::install::Posture::parse(raw) {
                Ok(p) => p,
                Err(msg) => {
                    eprintln!("error: {msg}");
                    process::exit(2);
                }
            },
            None => emberlink_cli::install::Posture::SeparateUid,
        };
        let opts = emberlink_cli::install::InstallNonInteractiveOptions {
            accept_defaults: args.accept_defaults,
            posture,
        };
        match emberlink_cli::install::install_non_interactive(&opts) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
    }

    if args.posture.is_some() || args.accept_defaults {
        // The interactive wizard doesn't yet branch on these, but accepting
        // them silently when `--non-interactive` is missing would be a
        // footgun — surface a clear error pointing at the missing flag.
        eprintln!(
            "error: --posture and --accept-defaults require --non-interactive in this release"
        );
        process::exit(2);
    }

    tracing::info!("installing separate-uid daemon posture (ADR 131)");

    if let Err(msg) = require_root_install_invocation("daemon install") {
        eprintln!("{msg}");
        process::exit(1);
    }

    println!(
        "about to provision ember user + ember-clients group — sudo password may be requested"
    );
    if let Err(e) = ember_daemon::install::provision_ember_user() {
        eprintln!("error: failed to provision ember user: {e}");
        process::exit(1);
    }

    // Resolve the OPERATOR's home, not root's. Under `sudo`, the calling
    // process has uid 0 and `dirs_next::home_dir()` returns `/var/root`,
    // but the daemon's at-rest state lives under the invoking human's
    // `~/.ember/...` — `resolve_operator_home` reads `$SUDO_USER` (set by
    // sudo) and looks up the home via `getpwnam_r`. The same `home` value
    // is then baked into the plist/unit's `HOME` env var so the daemon
    // (running as the `ember` system uid) resolves `~/.ember/...` back to
    // this directory at runtime.
    let home = match ember_daemon::install::resolve_operator_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to resolve operator home: {e}");
            process::exit(1);
        }
    };
    // ADR 218 (operator-locked 2026-06-14): the daemon's at-rest state +
    // config + runtime sockets all live at OS system paths under
    // `DaemonPaths::system()`, NOT under operator HOME. The banners below
    // reflect that; the legacy `~/.ember/*` references retained in this
    // function previously were stale post-PR-3d.
    let system_paths = ember_daemon::paths::DaemonPaths::system();

    println!(
        "about to seed default daemon config at {} (if absent)",
        system_paths.config_file().display()
    );
    if let Err(e) = ember_daemon::install::write_default_config_if_absent(&home) {
        eprintln!("error: failed to seed daemon config: {e}");
        process::exit(1);
    }

    println!(
        "about to chown daemon-owned state at {} to ember:ember-clients",
        system_paths.state_root.display()
    );
    if let Err(e) = ember_daemon::install::chown_ember_data_dirs(&home) {
        eprintln!("error: failed to chown daemon data dirs: {e}");
        process::exit(1);
    }

    println!(
        "about to provision vault MEK in System.keychain + prepare {}",
        system_paths.state_root.display()
    );
    if let Err(e) = ember_daemon::install::provision_se_mek(&home) {
        eprintln!("error: failed to provision vault MEK: {e}");
        process::exit(1);
    }

    #[cfg(target_os = "macos")]
    {
        println!(
            "about to install LaunchDaemon plist at /Library/LaunchDaemons/sh.emberlink.daemon.plist (system-paths per ADR 218; no HOME baked)"
        );
        let trust_roots = launchd_trust_roots_for_install();
        if let Err(e) =
            ember_daemon::install::install_launchd_plist_with_trust_roots(&home, &trust_roots)
        {
            eprintln!("error: failed to install LaunchDaemon plist: {e}");
            process::exit(1);
        }
    }

    #[cfg(target_os = "linux")]
    {
        println!(
            "about to install systemd unit at /etc/systemd/system/emberd.service (HOME={})",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_systemd_unit(&home) {
            eprintln!("error: failed to install systemd unit: {e}");
            process::exit(1);
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("error: ember daemon install is only supported on macOS and Linux.");
        process::exit(1);
    }

    tracing::info!("daemon installed; verify with `ps -o uid,pid,comm | grep emberd`");
    println!();
    println!("ember daemon installed (separate-uid posture, ADR 131)");
    println!("  Verify: ps -o uid,pid,comm | grep emberd");
    println!("  Note:   {}", daemon_install_launcher_boundary_note());
}

/// Migrate a single-uid daemon installation to the separate-uid posture
/// (ADR 131) while preserving all on-disk state.
///
/// Only `--to separate-uid` is accepted in v1.  Any other value exits
/// non-zero with a usage error.
///
/// Steps when migration is required:
/// 1. Detect current posture — exit early if already separate-uid.
/// 2. Stop the running daemon (launchctl bootout / systemctl stop).
/// 3. Provision the `ember` system user + `ember-clients` group (idempotent).
/// 4. chown existing vault/grants/sessions dirs to ember:ember-clients.
/// 5. Install the platform launcher (LaunchDaemon plist / systemd unit).
/// 6. Start the daemon under the new posture.
/// 7. Verify: report daemon uid via `ps -o uid,pid,comm`.
fn cmd_daemon_migrate(to: &str) {
    if to != "separate-uid" {
        eprintln!(
            "error: unrecognised --to value {to:?}. Only `separate-uid` is accepted in v1.\n       \
             Usage: ember daemon migrate --to separate-uid"
        );
        process::exit(2);
    }
    migrate_to_separate_uid();
}

/// Core migration logic — extracted so it can be unit-tested and so the
/// target_state_anchor `fn migrate_to_separate_uid` matches.
///
/// Posture detection: calls [`ember_daemon::install::is_separate_uid_posture`]
/// (probes `id ember`). If the host is already migrated the function prints
/// a success notice and returns without touching state.
fn migrate_to_separate_uid() {
    tracing::info!("ember daemon migrate --to separate-uid (ADR 131)");

    // Step 1 — detect current posture.
    if ember_daemon::install::is_separate_uid_posture() {
        tracing::info!("host is already on separate-uid posture — nothing to do");
        println!("Ok | already on separate-uid posture");
        return;
    }

    tracing::info!("detected single-uid posture; beginning migration to separate-uid");

    if let Err(msg) = require_root_install_invocation("daemon migrate") {
        eprintln!("{msg}");
        process::exit(1);
    }

    // Step 2 — stop the running daemon (tolerant; daemon may already be down).
    tracing::info!("step 2/7: stopping running daemon");
    println!("stopping ember daemon...");
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args([
                "bootout",
                "system",
                "/Library/LaunchDaemons/sh.emberlink.daemon.plist",
            ])
            .output()
            .map_err(|e| tracing::warn!("launchctl bootout spawn failed: {e}"));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "emberd.service"])
            .output()
            .map_err(|e| tracing::warn!("systemctl stop spawn failed: {e}"));
    }
    // Best-effort: also signal via the pid file / socket if present.
    // Errors are non-fatal — the daemon may have already exited or may not
    // be managed by a platform launcher yet (single-uid path uses
    // LaunchAgent, not LaunchDaemon).
    tracing::info!("daemon stop signal sent (errors above are non-fatal)");

    // Step 3 — provision ember user + ember-clients group.
    tracing::info!("step 3/7: provisioning ember user + ember-clients group");
    println!("provisioning ember user and ember-clients group (sudo may prompt)...");
    if let Err(e) = ember_daemon::install::provision_ember_user() {
        eprintln!("error: failed to provision ember user: {e}");
        process::exit(1);
    }
    tracing::info!("ember user provisioned");

    // Step 4 — chown existing vault/grants/sessions to ember:ember-clients.
    // Resolve the operator's home via SUDO_USER (not dirs_next::home_dir(),
    // which under sudo returns /var/root). Same home is then baked into the
    // plist/unit's HOME env var so the daemon resolves `~/.ember/...` here.
    let home = match ember_daemon::install::resolve_operator_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to resolve operator home: {e}");
            process::exit(1);
        }
    };
    tracing::info!(
        home = %home.display(),
        "step 4/7: chowning data dirs to ember:ember-clients"
    );
    let system_paths = ember_daemon::paths::DaemonPaths::system();
    println!(
        "chowning daemon-owned system state at {} to ember:ember-clients...",
        system_paths.state_root.display()
    );
    if let Err(e) = ember_daemon::install::chown_ember_data_dirs(&home) {
        eprintln!("error: failed to chown daemon data dirs: {e}");
        process::exit(1);
    }
    tracing::info!("data dirs chowned");

    // Step 5 — install platform launcher.
    tracing::info!("step 5/7: installing platform launcher");
    #[cfg(target_os = "macos")]
    {
        println!(
            "installing LaunchDaemon plist at /Library/LaunchDaemons/sh.emberlink.daemon.plist (HOME={})...",
            home.display()
        );
        let trust_roots = launchd_trust_roots_for_install();
        if let Err(e) =
            ember_daemon::install::install_launchd_plist_with_trust_roots(&home, &trust_roots)
        {
            eprintln!("error: failed to install LaunchDaemon plist: {e}");
            process::exit(1);
        }
    }
    #[cfg(target_os = "linux")]
    {
        println!(
            "installing systemd unit at /etc/systemd/system/emberd.service (HOME={})...",
            home.display()
        );
        if let Err(e) = ember_daemon::install::install_systemd_unit(&home) {
            eprintln!("error: failed to install systemd unit: {e}");
            process::exit(1);
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        eprintln!("error: ember daemon migrate is only supported on macOS and Linux.");
        process::exit(1);
    }
    tracing::info!("platform launcher installed");

    // Step 6 — start daemon under new posture.  The platform launcher
    // (LaunchDaemon / systemd) handles the actual start; on macOS
    // install_launchd_plist already runs `launchctl bootstrap`.  On
    // Linux `install_systemd_unit` runs `systemctl enable --now`.  We
    // give the daemon a moment to bind before the ps probe.
    tracing::info!("step 6/7: daemon start triggered by platform launcher (install step)");
    println!("platform launcher installed and daemon started");

    // Step 7 — verify: ps -o uid,pid,comm | grep emberd.
    tracing::info!("step 7/7: verifying daemon uid via ps");
    let ps_out = std::process::Command::new("ps")
        .args(["-eo", "uid,pid,comm"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let emberd_line = ps_out
        .lines()
        .find(|l| l.contains("emberd"))
        .map(|l| l.trim().to_string());

    println!();
    match emberd_line {
        Some(line) => {
            println!("Ok | daemon running as: {line}");
            tracing::info!(ps_line = %line, "daemon uid verified");
        }
        None => {
            println!(
                "Ok | migration complete (daemon may need a moment to start; \
                 verify with: ps -o uid,pid,comm | grep emberd)"
            );
            tracing::info!("emberd not yet visible in ps — may still be starting");
        }
    }
    println!("  Vault + grants preserved (chown is non-destructive).");
    println!("  Re-run `ember vault list` to confirm data is readable.");
}

/// Gracefully restart the running daemon. When the daemon is managed by
/// LaunchAgent/systemd, SIGTERM triggers an automatic restart with whatever
/// `ember` binary is on disk — this is the dev-rebuild-loop primitive.
///
/// When the daemon was started manually via `ember daemon start --background`,
/// `reload` falls back to re-spawning it in the same mode.
fn cmd_daemon_reload(config: &DaemonConfig, timeout_secs: u64, cli_config: Option<&PathBuf>) {
    let socket_path = config.socket_dir.join("daemon.sock");
    let pid_file = config.pid_file.clone();
    let managed_before = daemon_agent::is_managed_service();

    if !managed_before {
        // Best-effort: if the daemon was started manually (`--background`), try
        // to stop it and respawn it so the user isn't left with a dead daemon.
        match daemon_agent::reload_daemon(
            &pid_file,
            &socket_path,
            Duration::from_secs(timeout_secs),
        ) {
            Ok(_) => {
                // Shouldn't happen — if unmanaged, the daemon can't restart itself.
                // But if it did come back (e.g. user races install-agent), no harm.
                println!("Unexpected: unmanaged daemon reappeared after SIGTERM.");
            }
            Err(daemon_agent::AgentError::DaemonNotRunning) => {
                eprintln!(
                    "error: daemon is not running — run `ember status` to inspect and `sudo ember daemon install` to install or repair the managed daemon"
                );
                process::exit(1);
            }
            Err(daemon_agent::AgentError::ReloadTimeout { .. }) => {
                // Expected: unmanaged daemon won't come back on its own.
                // Respawn it the same way the user originally started it.
                eprintln!(
                    "warning: daemon is not a managed service — spawning a fresh `--background` instance"
                );
                let exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: could not resolve current exe: {e}");
                        process::exit(1);
                    }
                };
                let mut cmd = std::process::Command::new(exe);
                cmd.arg("daemon").arg("start").arg("--background");
                // The respawn child inherits
                // the resolved config path so an env-var-pinned demo daemon
                // comes back on the same config.
                if let Some(path) = resolved_user_config_path(cli_config) {
                    cmd.arg("--config").arg(path);
                }
                match cmd.spawn() {
                    Ok(_child) => {
                        println!("Respawned daemon with `ember daemon start --background`.");
                        println!(
                            "Tip: the canonical always-up posture is `sudo ember daemon install`."
                        );
                    }
                    Err(e) => {
                        eprintln!("error: failed to respawn daemon: {e}");
                        process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: reload failed: {e}");
                process::exit(1);
            }
        }
        return;
    }

    match daemon_agent::reload_daemon(&pid_file, &socket_path, Duration::from_secs(timeout_secs)) {
        Ok(outcome) => {
            let new_pid = outcome
                .new_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "✓ ember daemon reloaded — old pid {}, new pid {}",
                outcome.old_pid, new_pid
            );
        }
        Err(daemon_agent::AgentError::DaemonNotRunning) => {
            eprintln!(
                "error: daemon is not running — run `ember status` to inspect and `sudo ember daemon install` to install or repair the managed daemon"
            );
            process::exit(1);
        }
        Err(daemon_agent::AgentError::ReloadTimeout { secs }) => {
            eprintln!("error: daemon did not come back up within {secs}s");
            if let Ok(logs) = daemon_agent::logs_dir() {
                let err_log = logs.join("daemon.err");
                let tail = daemon_agent::tail_file(&err_log, 20);
                if !tail.is_empty() {
                    eprintln!();
                    eprintln!("--- last 20 lines of {} ---", err_log.display());
                    eprintln!("{tail}");
                    eprintln!("--- end ---");
                }
            }
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: reload failed: {e}");
            process::exit(1);
        }
    }
}

/// Idempotent + auditable wipe sequence for the MEK-missing-with-state
/// recovery path. Replaces the hand-typed paste-block that operators ran
/// during the 2026-05-14 SCION-demo-prep incident recovery.
///
/// Order of operations:
/// 1. Best-effort daemon stop (launchctl unload / systemctl stop)
/// 2. Archive `config.data_dir` to `<archive_to>` (refuses if dir exists —
///    idempotent guard against overwriting a prior recovery archive)
/// 3. Print canonical keychain-clear command for the operator's OS
///    (slice D-bis will own the actual System.keychain delete via the
///    daemon's privileged process; today the CLI emits the command for
///    operator copy-paste under the existing manual-process pattern)
/// 4. Print re-seed checklist
///
/// `--archive-to` REQUIRED — no destructive default. Per the brief's
/// "Archive path required (no destructive default behavior)" acceptance.
fn cmd_daemon_recover_fresh(config: &DaemonConfig, archive_to: &std::path::Path) {
    println!("ember daemon recover-fresh");
    println!();

    // Step 1: refuse if archive_to exists (idempotent guard).
    if archive_to.exists() {
        eprintln!(
            "error: archive path {} already exists; pick a unique path per recovery attempt",
            archive_to.display()
        );
        process::exit(1);
    }

    // Step 2: stop daemon (best-effort; OS-specific paths).
    println!("[1/4] stopping daemon (best-effort)");
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "/Library/LaunchDaemons/sh.emberlink.daemon.plist"])
            .output();
        println!("    launchctl unload /Library/LaunchDaemons/sh.emberlink.daemon.plist");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "emberd.service"])
            .output();
        println!("    systemctl stop emberd.service");
    }

    // Step 3: archive data dir.
    println!(
        "[2/4] archiving {} → {}",
        config.data_dir.display(),
        archive_to.display()
    );
    if !config.data_dir.exists() {
        println!(
            "    note: data dir does not exist — nothing to archive (already wiped or never initialized)"
        );
    } else if let Err(e) = std::fs::rename(&config.data_dir, archive_to) {
        eprintln!(
            "error: failed to archive {}: {e}",
            config.data_dir.display()
        );
        eprintln!(
            "    suggested workaround: manually `mv {} {}`",
            config.data_dir.display(),
            archive_to.display()
        );
        process::exit(1);
    } else {
        println!("    archived");
    }

    // Step 4: keychain-clear instructions.
    println!("[3/4] keychain clear (operator command, requires privileged uid)");
    #[cfg(target_os = "macos")]
    println!("    security delete-generic-password -s sh.emberlink.daemon -a vault-mek");
    #[cfg(target_os = "linux")]
    println!(
        "    secret-tool clear service sh.emberlink.daemon  # (or equivalent for your secret-service backend)"
    );

    // Step 5: re-seed checklist.
    println!("[4/4] re-seed checklist (operator next steps)");
    println!("    1. Restart the daemon:");
    #[cfg(target_os = "macos")]
    println!("       launchctl load /Library/LaunchDaemons/sh.emberlink.daemon.plist");
    #[cfg(target_os = "linux")]
    println!("       systemctl start emberd.service");
    println!("    2. Re-register the operator passkey:");
    println!("       ember init");
    println!("    3. Re-seed each vault credential (consult archive for known names):");
    println!("       ls {}/vault* 2>/dev/null", archive_to.display());
    println!("    4. Re-establish persona signing keys:");
    println!("       ember persona create <name>");
    println!("    5. Verify daemon is healthy:");
    println!("       ember daemon status");
    println!();
    println!(
        "recover-fresh complete. Archive at {}",
        archive_to.display()
    );
}

/// daemon_diagnose_mek_pattern_landed.
///
/// `git fsck`-style detector for the MEK-persistence-failed pattern that
/// hit the SCION demo prep on 2026-05-14: daemon silently re-provisioning
/// a fresh MEK on top of pre-existing encrypted state, destroying all
/// prior vault data + persona keys without diagnostic.
///
/// Pattern recognition (4 outcomes):
///   HEALTHY                    — keychain MEK + daemon.db state + fingerprint align
///   MEK-MISSING-WITH-STATE     — keychain empty but daemon.db has rows
///   FINGERPRINT-MISMATCH       — keychain MEK loaded but fingerprint disagrees (slice B)
///   STATE-EMPTY                — fresh install
///
/// Fingerprint-check shape depends on the MEK-fingerprint-column slice
/// landing. Pre-slice,
/// the FINGERPRINT row reports "unavailable (slice B pending)". Once B
/// lands, the row reports `present|absent|mismatch` per the brief.
fn cmd_daemon_diagnose(config: &DaemonConfig) {
    // Path existence is the proxy for the four-pattern detector. The fully
    // structural shape (keychain probe, fingerprint compare) requires
    // daemon-internal vault primitives that live in ember-daemon's
    // privileged uid; the CLI can only inspect what its uid is permitted
    // to read. Slice E (startup-probe in runtime.rs) is the
    // privileged-side complement.
    let data_dir = &config.data_dir;
    let db_path = data_dir.join("daemon.db");
    let launcher_issue = detect_default_installed_launcher_issue();

    println!("ember daemon diagnose");
    if let Some(issue) = launcher_issue.as_ref() {
        println!();
        println!("INSTALL PATH: {}", issue.detail());
    }

    // KEYCHAIN row — the daemon-side keychain entry is opaque to the
    // operator uid under ADR 131. Report what we CAN observe.
    println!();
    println!("KEYCHAIN: opaque to operator uid (daemon-side probe pending — slice E)");

    // DAEMON.DB row — file existence + rough size hint. Detailed table
    // row counts require a privileged store-open call (daemon RPC) and
    // are reported via `ember daemon status` already.
    let db_state = if db_path.exists() {
        match std::fs::metadata(&db_path) {
            Ok(m) if m.len() > 0 => format!("present ({} bytes)", m.len()),
            Ok(_) => "present (empty)".to_string(),
            Err(_) => "present (unreadable)".to_string(),
        }
    } else {
        "absent".to_string()
    };
    println!("DAEMON.DB: {db_state} ({})", db_path.display());

    // FINGERPRINT row — slice B prerequisite. Pre-B: unavailable.
    // Post-B: this row reports present(<hex prefix>) | absent | mismatch.
    println!(
        "FINGERPRINT: unavailable (slice B pending — META-AP-DAEMON-MEK-PERSISTENCE-B-MEK-FINGERPRINT-COLUMN)"
    );

    // PATTERN row — best-effort pattern recognition from what the
    // operator-uid CLI can see today.
    let pattern = if !db_path.exists() {
        "STATE-EMPTY"
    } else {
        match std::fs::metadata(&db_path) {
            Ok(m) if m.len() == 0 => "STATE-EMPTY",
            Ok(_) => "INDETERMINATE (full pattern detection requires slice B + E)",
            Err(_) => "UNREADABLE",
        }
    };
    println!();
    println!("PATTERN: {pattern}");

    // RUNBOOK row — deterministic recovery commands per pattern.
    println!();
    println!("RUNBOOK:");
    if let Some(issue) = launcher_issue.as_ref() {
        println!("  # First repair the installed `ember` launcher path:");
        println!("  # {}", issue.detail());
        println!("  # {}", issue.repair_guidance());
    }
    match pattern {
        "STATE-EMPTY" => {
            println!("  ember init                  # fresh provision");
            println!("  sudo ember daemon install   # install / repair the managed daemon");
            println!("  ember status                # confirm the daemon is up");
        }
        "UNREADABLE" => {
            println!(
                "  ls -la {}                   # check filesystem perms",
                db_path.display()
            );
            println!("  # under ADR 131 separate-uid posture, the daemon's data");
            println!("  # is chowned to ember:ember-clients; the operator uid");
            println!("  # may not be able to read it. This is by design.");
        }
        _ => {
            println!("  # Pattern is indeterminate without slice B (fingerprint column)");
            println!("  # and slice E (startup probe).");
            println!("  ember daemon status         # daemon-side state summary");
            println!("  # If status reports MEK-missing-with-state, run:");
            println!("  ember daemon recover-fresh --archive-to <path>");
            println!("  # If status reports fingerprint-mismatch, run:");
            println!("  ember vault import --sealed --recovery-passphrase");
        }
    }
}

/// Truncate a string to `max` chars, adding an ellipsis if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

// `resolve_receipt` removed;
// the daemon's `get_receipt` RPC handles the grant-id → receipt-id walk
// (see [`run_receipt_get`]).

fn up_redirect_command(profile: Option<&str>) -> String {
    match profile {
        Some(profile) => format!("ember claude --isolated --preset {profile}"),
        None => "ember claude --isolated".to_string(),
    }
}

/// Hidden legacy `ember up` redirect.
///
/// The real isolated/container launcher truth moved to
/// `ember claude --isolated` / `ember session open claude --isolated`.
/// Keep this hidden verb fail-loud so older scripts see the canonical
/// replacement instead of silently booting the stale compose scaffold.
fn cmd_up(profile: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!(
        "`ember up` is a hidden legacy scaffold and no longer tracks the isolated Claude launcher. Use `{}` instead.",
        up_redirect_command(profile.as_deref())
    )
    .into())
}

/// `ember down` body.
fn cmd_down(revoke_grants: bool, yes: bool, purge: bool) -> Result<(), Box<dyn std::error::Error>> {
    let engine = emberlink_cli::up::detect_runtime_engine()?.ok_or_else(
        || -> Box<dyn std::error::Error> {
            emberlink_cli::up::missing_runtime_remediation().into()
        },
    )?;

    let run_root = dirs_next::home_dir()
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            "could not resolve $HOME for ~/.ember/run".into()
        })?
        .join(".ember/run");
    let compose_path =
        latest_compose_yml(&run_root)?.ok_or_else(|| -> Box<dyn std::error::Error> {
            format!(
                "no compose stack found under {} — run `ember up` first",
                run_root.display()
            )
            .into()
        })?;
    println!("Compose: {}", compose_path.display());

    let (stdout, _stderr) = emberlink_cli::up::compose_down(engine, &compose_path, purge)?;
    if !stdout.trim().is_empty() {
        println!("{}", stdout.trim_end());
    }
    if purge {
        println!("Removed named compose volumes (-v).");
    }

    if revoke_grants {
        cmd_down_revoke_active_grants(yes)?;
    }

    println!("ember down: session torn down.");
    Ok(())
}

/// `ember down --revoke-grants`. BKR-4c (ADR 205 §6): runtime standing
/// grants — the per-session authority that replaced the legacy delegation
/// sidecar — are revoked automatically when their session closes
/// (`close_session` terminates the runtime persona) and when the launcher exits
/// (`launcher_watch` revokes the grant), and are TTL-bounded regardless. There
/// is no longer a caller-scoped delegation enumeration to eager-revoke here;
/// revoke a specific grant with `ember grant revoke <id>` (list with
/// `ember grant list`).
fn cmd_down_revoke_active_grants(_yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "ember down --revoke-grants: runtime standing grants are revoked on session close / \
         launcher exit and expire at TTL. To revoke a specific grant now, run \
         `ember grant revoke <id>` (list with `ember grant list`)."
    );
    Ok(())
}

fn latest_compose_yml(run_root: &std::path::Path) -> std::io::Result<Option<std::path::PathBuf>> {
    if !run_root.exists() {
        return Ok(None);
    }
    let mut newest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(run_root)? {
        let entry = entry?;
        let compose = entry.path().join("compose.yml");
        if !compose.is_file() {
            continue;
        }
        let mtime = entry.metadata()?.modified()?;
        if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
            newest = Some((mtime, compose));
        }
    }
    Ok(newest.map(|(_, p)| p))
}

/// Validate the `--emit-file <path>` arg against a strict allowlist
/// before writing:
///
/// 1. The path (after lexical `..` resolution) MUST reside under
///    `$HOME` or `$XDG_RUNTIME_DIR`.
/// 2. The path MUST NOT start with `/etc`, `/var`, `/usr`, `/sys`,
///    `/proc`, `/root`, or `/dev` — defense in depth on top of the
///    containment check, in case a symlinked HOME would otherwise
///    route through a sensitive system directory.
/// 3. `..` traversal that escapes the lexical root is refused.
///
/// Relative paths are resolved against CWD before validation.
/// Returns the lexically-cleaned absolute path on success.
///
/// Anchor: emit_file_path_validated
fn validate_emit_file_path(path: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use std::path::{Component, PathBuf};

    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("--emit-file: cannot resolve relative path (CWD: {e})"))?
            .join(path)
    };

    let mut clean = PathBuf::new();
    for component in abs.components() {
        match component {
            Component::ParentDir => {
                if !clean.pop() {
                    return Err(format!(
                        "--emit-file: `..` escapes root in {}",
                        abs.display()
                    ));
                }
            }
            Component::CurDir => {}
            Component::RootDir => clean.push("/"),
            Component::Normal(c) => clean.push(c),
            Component::Prefix(_) => {
                return Err(format!(
                    "--emit-file: unexpected path prefix in {}",
                    abs.display()
                ));
            }
        }
    }

    let s = clean.to_string_lossy();
    for forbidden in ["/etc", "/var", "/usr", "/sys", "/proc", "/root", "/dev"] {
        if s == forbidden || s.starts_with(&format!("{forbidden}/")) {
            return Err(format!(
                "--emit-file: refused — path resolves to forbidden system prefix `{forbidden}`: {}",
                clean.display()
            ));
        }
    }

    let mut allowed_roots: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var_os("HOME") {
        allowed_roots.push(PathBuf::from(h));
    }
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        allowed_roots.push(PathBuf::from(x));
    }
    if allowed_roots.is_empty() {
        return Err(
            "--emit-file: cannot validate path — neither HOME nor XDG_RUNTIME_DIR is set"
                .to_string(),
        );
    }
    if !allowed_roots.iter().any(|root| clean.starts_with(root)) {
        return Err(format!(
            "--emit-file: path must resolve under $HOME or $XDG_RUNTIME_DIR, got: {}",
            clean.display()
        ));
    }

    Ok(clean)
}

fn main() {
    // CLI-VERSION-FLAG: handle `--version` / `-V` before clap parses so the
    // output format (`ember <semver> (<sha>) built <iso8601>`) is enforced
    // here rather than fighting clap's built-in renderer. Both forms exit 0
    // without touching the daemon, vault, or config — `ember --version` must
    // never block on the keychain unlock prompt.
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    set_cli_render_theme(resolve_cli_render_theme_from_raw_args(&raw_args));
    if is_top_level_version_request(&raw_args) {
        println!("{}", print_version());
        return;
    }

    if let Some(help) = render_custom_help(&raw_args) {
        println!("{help}");
        return;
    }
    if let Some(help) = render_entry_help(&raw_args) {
        println!("{help}");
        return;
    }

    // keyring-core 1.0 split — see runtime.rs head-of-run() comment. The CLI
    // shares the same Keychain backend as the daemon; register the default
    // store before any subcommand dispatches. Subcommands that touch the
    // keyring (init, vault, dev) rely on this; subcommands that don't
    // (--version, --help, render-only commands) tolerate registration
    // failure as a warning. Always-off in EMBER_VAULT_MOCK / cargo-test
    // contexts via the three-axis gate inside resolve_passphrase.
    #[cfg(target_os = "macos")]
    {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => keyring_core::set_default_store(store),
            Err(e) => eprintln!(
                "ember: warning — failed to register macOS Keychain store: {e:?}; \
                 keyring-using subcommands will fail with NoDefaultStore"
            ),
        }
    }

    if raw_args_target_home_screen(&raw_args) {
        let config_override = raw_config_override(&raw_args);
        let no_input = raw_args.iter().any(|arg| arg == "--no-input");
        let yes = raw_args.iter().any(|arg| arg == "--yes" || arg == "-y");
        let resolved_path = resolved_user_config_path(config_override.as_ref());
        let has_config = resolved_path.as_ref().is_some_and(|path| path.exists())
            || DaemonConfig::default_config_path().exists();
        if has_config {
            let config = load_config(config_override.as_ref());
            println!("{}", render_home_screen(&config));
            if let Ok(overview) = collect_status_overview(&config) {
                let action = primary_status_action(&overview);
                exit_on_prompted_action(maybe_prompt_run_primary_action(
                    Some(&action),
                    true,
                    no_input,
                    yes,
                ));
            }
        } else {
            println!("{}", render_uninitialized_home_screen());
            let action = PrimaryAction {
                kind: PrimaryActionKind::Start,
                command: format!(
                    "{} init --for claude",
                    ember_command_prefix_for_current_launcher()
                ),
            };
            exit_on_prompted_action(maybe_prompt_run_primary_action(
                Some(&action),
                true,
                no_input,
                yes,
            ));
        }
        return;
    }

    let cli = Cli::parse();
    set_cli_render_theme(CliRenderTheme::from_choice(cli.color));
    let config = if command_allows_bootstrap_config(&cli.command) {
        load_bootstrap_config(cli.config.as_ref())
    } else if command_allows_missing_config(&cli.command) {
        load_config_if_present_or_default(cli.config.as_ref())
    } else {
        load_config(cli.config.as_ref())
    };

    match cli.command {
        Commands::Init {
            name,
            keyring_service,
            keyring_account,
            touch_id,
            for_target,
            non_interactive,
            migrate,
        } => {
            let non_interactive = non_interactive || cli.no_input;
            // On a new machine the daemon
            // service will not be installed. Detect this early — before any
            // vault or DB work — and offer to run `sudo ember daemon install`.
            // Skip the check when the daemon is already running or the operator
            // used `--for claude` (that path autostarts the daemon itself).
            {
                let socket_path = config.socket_dir.join("daemon.sock");
                // EMBER_SKIP_DAEMON_INSTALL_CHECK: test-only bypass for the
                // daemon-install precheck. Production code never sets this; the
                // env var lets binary tests construct an isolated config + tmpdir
                // without tripping the non-interactive `Declined` branch that
                // process::exit(0)s before downstream init work completes.
                let skip_check = std::env::var("EMBER_SKIP_DAEMON_INSTALL_CHECK").is_ok();
                if !skip_check {
                    let install_status = match emberlink_cli::probe_live_daemon_status(
                        &socket_path,
                        &config.pid_file,
                    ) {
                        Ok(Some(_)) => emberlink_cli::install::DaemonInstallStatus::Running,
                        Ok(None) => emberlink_cli::install::detect_daemon_installed(&socket_path),
                        Err(e) => {
                            eprintln!("error: could not inspect daemon posture: {e}");
                            process::exit(1);
                        }
                    };
                    if install_status == emberlink_cli::install::DaemonInstallStatus::NotInstalled {
                        let ember_cmd = ember_command_prefix_for_current_launcher();
                        let rerun_cmd =
                            init_rerun_command_with_ember_command(&ember_cmd, for_target);
                        let daemon_install_cmd =
                            sudo_daemon_install_command_with_ember_command(&ember_cmd);
                        match emberlink_cli::install::prompt_install_daemon(non_interactive) {
                            Ok(()) => {
                                println!("  Daemon:   installed successfully");
                            }
                            Err(emberlink_cli::install::DaemonInstallPromptError::Declined) => {
                                eprintln!(
                                    "note: setup paused before daemon install.\n\
                                     Run `{daemon_install_cmd}`, then re-run {rerun_cmd}."
                                );
                                process::exit(0);
                            }
                            Err(
                                emberlink_cli::install::DaemonInstallPromptError::NonInteractive,
                            ) => {
                                eprintln!(
                                    "error: daemon is not installed and --non-interactive is set.\n\
                                     Run `{daemon_install_cmd}` first, then re-run {rerun_cmd}."
                                );
                                process::exit(1);
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    }
                }
            }

            // Target-specific friendly onboarding (`--for claude` /
            // `--for codex`) must not re-run the legacy base-init path once
            // the managed daemon DB already exists. Otherwise a second
            // onboarding pass re-enters root-persona bootstrap and the old
            // keyring/bootstrap prompts.
            let skip_basic_init = should_skip_basic_init(for_target, &config);

            if skip_basic_init {
                // Already initialized — count existing personas for the log line.
                // We open the store read-only here (no vault needed for list).
                let db_path = config.data_dir.join("daemon.db");
                let persona_count = DaemonStore::open(&db_path)
                    .ok()
                    .and_then(|s| s.list_personas().ok())
                    .map(|ps| ps.len())
                    .unwrap_or(0);
                println!("Daemon DB: already initialized (existing personas: {persona_count})");
            } else {
                cmd_init(
                    &config,
                    name,
                    for_target,
                    cli.config.as_ref(),
                    keyring_service,
                    keyring_account,
                    touch_id,
                    non_interactive,
                );
            }
            // Layer the claude-code onboarding on top of the
            // base daemon init when `--for claude` is set. The base
            // init has already set up the keyring, vault, salt, and root
            // persona — the cohort A flow now creates the agent persona,
            // template, grant, settings.json patch, and optional PAT.
            //
            // When `--migrate` is
            // passed alongside `--for claude`, run the path-shadow
            // layout migration after the standard claude-code init.
            // Idempotent — re-running on layout=new / layout=both /
            // layout=none is a no-op with a clear status line.
            // shadow_path_migrate_flag_landed.
            if let Some(OnboardingTarget::Claude) = for_target {
                if let Err(e) =
                    cmd_init_for_claude_code(&config, cli.config.as_ref(), non_interactive)
                {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
                if migrate && let Err(e) = cmd_migrate_path_shadow_layout() {
                    eprintln!("error: shadow-path migrate failed: {e}");
                    process::exit(1);
                }
            }
            if let Some(OnboardingTarget::Codex) = for_target
                && let Err(e) = cmd_init_for_codex(&config, cli.config.as_ref(), non_interactive)
            {
                eprintln!("error: {e}");
                process::exit(1);
            }
            if let Some(OnboardingTarget::Cursor) = for_target
                && let Err(e) = cmd_init_for_cursor(&config, cli.config.as_ref(), non_interactive)
            {
                eprintln!("error: {e}");
                process::exit(1);
            }
            if let Some(OnboardingTarget::Gemini) = for_target
                && let Err(e) = cmd_init_for_gemini(&config, cli.config.as_ref(), non_interactive)
            {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Uninstall {
            for_target: OnboardingTarget::Claude,
        } => {
            if let Err(e) = cmd_uninstall_for_claude_code() {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Uninstall {
            for_target: OnboardingTarget::Codex,
        } => {
            if let Err(e) = cmd_uninstall_for_codex() {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Uninstall {
            for_target: OnboardingTarget::Cursor,
        } => {
            if let Err(e) = cmd_uninstall_for_cursor() {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Uninstall {
            for_target: OnboardingTarget::Gemini,
        } => {
            if let Err(e) = cmd_uninstall_for_gemini() {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Up { profile } => {
            if let Err(e) = cmd_up(profile) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Down {
            revoke_grants,
            purge,
        } => {
            if let Err(e) = cmd_down(revoke_grants, cli.yes, purge) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }

        Commands::Recover { action } => {
            let recover_context = emberlink_cli::recover::RecoverContext::with_socket_path(
                config.socket_dir.join("daemon.sock"),
            );
            match emberlink_cli::recover::dispatch(action, None, recover_context) {
                Ok(outcome) if outcome.exit_code() != 0 => {
                    process::exit(outcome.exit_code());
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(e.exit_code());
                }
            }
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start {
                background,
                foreground: _,
            } => {
                if background {
                    if let Err(e) = config.ensure_dirs() {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                    let log_path = config.data_dir.join("daemon.log");

                    let exe = std::env::current_exe().expect("current exe");
                    let mut cmd = std::process::Command::new(exe);
                    cmd.arg("daemon").arg("start");
                    // Propagate the resolved
                    // config path (flag → EMBER_CONFIG → EMBER_DEMO_DIR) to
                    // the background child so it pins the same demo dir.
                    if let Some(config_path) = resolved_user_config_path(cli.config.as_ref()) {
                        cmd.arg("--config").arg(config_path);
                    }
                    // Background child writes logs via tracing-appender; no console output.
                    cmd.env("EMBER_DAEMON_NO_CONSOLE", "1")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .stdin(std::process::Stdio::null());

                    let child = cmd.spawn().expect("spawn daemon");
                    println!("Daemon started in background (PID {})", child.id());
                    println!("  Log: {}", log_path.display());
                    #[allow(clippy::zombie_processes)]
                    std::mem::forget(child);
                }

                if let Err(e) = config.ensure_dirs() {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
                let console = std::env::var("EMBER_DAEMON_NO_CONSOLE").is_err();
                let _log_guard = configure_tracing(&config.data_dir, &config.log_level, console);

                // Print everything except the dashboard line up-front.
                if console {
                    print_banner_preamble(&config);
                }

                // Warn loudly when the
                // shadow PATH isn't installed — the agent-routing invariant
                // fails silently otherwise. Best-effort: a missing shadow
                // dir doesn't block daemon start, but the WARN must surface
                // so the operator notices and runs `ember init --for
                // claude`.
                if let Err(msg) = ensure_shadow_path_installed() {
                    if console {
                        eprintln!("WARN  {msg}");
                    }
                    tracing::warn!("{msg}");
                }

                // Env-var fallback — if the
                // operator pinned a config via EMBER_CONFIG / EMBER_DEMO_DIR
                // (e.g. demo/dev tooling), the runtime should track that
                // same path so reload + dashboard config-show stay coherent.
                let runtime = match resolved_user_config_path(cli.config.as_ref()) {
                    Some(p) => DaemonRuntime::new_with_config_path(config, p),
                    None => {
                        let default_path = DaemonConfig::default_config_path();
                        if default_path.exists() {
                            DaemonRuntime::new_with_config_path(config, default_path)
                        } else {
                            DaemonRuntime::new(config)
                        }
                    }
                };
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

                // The start_notify callback fires from inside the async runtime once
                // the dashboard bind result is known (within 2 seconds of startup).
                // It prints the dashboard banner line + footer from the tokio thread,
                // which is fine because eprintln! is synchronous and we're not in
                // an async context that cares about thread identity.
                let notify: Box<dyn FnOnce(StartupBinds)> = if console {
                    Box::new(|binds| print_banner_startup(&binds))
                } else {
                    Box::new(|_binds| {})
                };

                if let Err(e) = rt.block_on(runtime.run(Some(notify))) {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
            DaemonAction::Stop => {
                // Capture the daemon's identity from disk BEFORE stopping.
                // The keyfile (<data_dir>/daemon_persona.key) survives a
                // stop, but the on-camera demo close needs the pubkey
                // surfaced here so the operator can paste it into the
                // subsequent `ember receipt verify --file ... --pubkey ...`
                // command without leaving the terminal. Mirrors the
                // identity relay at end-of-life that qember.sh demo down
                // already prints.
                let identity_pubkey =
                    ember_daemon::infra::receipt::init_identity(&config.data_dir).ok();

                let runtime = DaemonRuntime::new(config);
                match runtime.stop() {
                    Ok(pid) => {
                        println!("Stopped ember daemon (PID {pid})");
                        if let Some(pubkey) = identity_pubkey {
                            let fp =
                                ember_daemon::infra::runtime::daemon_identity_fingerprint(&pubkey);
                            println!();
                            println!("  Identity preserved (data dir is intact):");
                            println!("    fingerprint:  {fp}");
                            println!("    pubkey:       {pubkey}");
                            println!();
                            println!("  Verify any receipt this daemon signed:");
                            println!("    ember receipt verify --file <path> --pubkey {pubkey}");
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
            }
            DaemonAction::Status => {
                let runtime = DaemonRuntime::new(config.clone());
                let runtime_status = runtime.status().ok();
                match emberlink_cli::probe_live_daemon_status(
                    &config.socket_dir.join("daemon.sock"),
                    &config.pid_file,
                ) {
                    Ok(Some(live)) => {
                        println!("ember daemon is running");
                        if let Some(pid) =
                            live.pid.or_else(|| runtime_status.as_ref().map(|s| s.pid))
                        {
                            println!("  PID:    {pid}");
                        }
                        println!("  Socket: {}", live.socket.display());
                        // Warn loudly if
                        // the shadow PATH isn't installed. Without it,
                        // raw `gh`/`git`/`kubectl` calls from sequential
                        // agents bypass the broker, operator-author the
                        // commits, and break audit-trail clarity.
                        if let Err(msg) = ensure_shadow_path_installed() {
                            eprintln!("WARN  {msg}");
                        }
                    }
                    Ok(None) => {
                        if let Some(status) = runtime_status
                            && !status.running
                        {
                            println!("ember daemon is not running (stale PID {})", status.pid);
                            process::exit(1);
                        }
                        println!("ember daemon is not running");
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
            }
            DaemonAction::Reload { timeout } => {
                cmd_daemon_reload(&config, timeout, cli.config.as_ref());
            }
            DaemonAction::InstallAgent { no_autostart } => {
                cmd_daemon_install_agent(cli.config.as_ref(), no_autostart);
            }
            DaemonAction::UninstallAgent => {
                cmd_daemon_uninstall_agent();
            }
            DaemonAction::Install { args } => {
                cmd_daemon_install(args);
            }
            DaemonAction::Migrate { to } => {
                cmd_daemon_migrate(&to);
            }
            DaemonAction::Diagnose => {
                cmd_daemon_diagnose(&config);
            }
            DaemonAction::RecoverFresh { archive_to } => {
                cmd_daemon_recover_fresh(&config, &archive_to);
            }
        },

        Commands::Persona { action } => {
            // All persona
            // mutations (create, revoke) and reads (list) route through the
            // daemon RPC socket so the operator uid never touches the DB file
            // directly. Under ADR 131 separate-uid posture (daemon=ember uid,
            // operator=operator uid) the DB is owned by the ember uid and the
            // operator uid cannot open it for writing — and may not be able
            // to open it for reading depending on filesystem permissions.
            // Routing every verb through JSON-RPC lets the daemon own all
            // store access under its uid while the CLI only needs socket
            // connect permission.
            let socket_path = config.socket_dir.join("daemon.sock");
            match action {
                PersonaAction::Create { name } => {
                    let request = serde_json::json!({"name": name});
                    match emberlink_cli::call_daemon_method(
                        &socket_path,
                        "create_persona",
                        &request,
                    ) {
                        Ok(result) => {
                            let id = result.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let display_name =
                                result.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let public_key = result
                                .get("public_key")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            println!("Created persona");
                            println!("  ID:         {id}");
                            println!("  Name:       {display_name}");
                            println!("  Public key: {public_key}");
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                PersonaAction::List => {
                    match emberlink_cli::call_daemon_method(
                        &socket_path,
                        "list_personas",
                        &serde_json::Value::Null,
                    ) {
                        Ok(result) => {
                            let empty = Vec::new();
                            let personas = result.as_array().unwrap_or(&empty);
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap());
                            } else {
                                println!("{}", render_persona_list_text(personas));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                PersonaAction::Revoke { id } => match run_persona_revoke(&config, &id) {
                    Ok(_) => println!("Revoked persona {id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Device { action } => match action {
            // V030-EMBER-DEVICE-LIST — read-only inventory of enrolled
            // presence devices. ConnectOnly: no vault tap, no presence gate.
            // Anchor: ember_device_list_surface_landed.
            DeviceAction::List => {
                let socket_path = emberlink_cli::daemon_socket_path();
                let code = emberlink_cli::device::list::run(&socket_path, cli.json);
                if code != 0 {
                    process::exit(code);
                }
            }
            // ADR 200 §5 operator-bootstrap ceremony. Drives the
            // `identity.device.enroll` daemon RPC (prepare→commit). The daemon
            // never holds the operator's presence-device key.
            DeviceAction::Enroll {
                device_key,
                encryption_key,
                label,
                backup,
                authority_device_key,
                secure_enclave,
                se_label,
                no_provision,
                ac2_card,
                operator_signature_hex,
                external_signer,
                recovery_code,
            } => {
                // Legacy compat: bare `--device-key …` (without `--external-signer`)
                // continues to imply the external-signer flow for first-device
                // enrollment so existing scripts do not break (ADR 200 amendment
                // 2026-06-12). Backup enrollment is different: the backup
                // Device's pubkeys are caller-supplied, while the authority
                // signer defaults to the local SE lane unless explicitly
                // marked external-signer or given a prepared signature.
                let external_signer = infer_device_enroll_external_signer(
                    backup,
                    device_key.is_some(),
                    !operator_signature_hex.is_empty(),
                    external_signer,
                );
                if let Err(e) = run_device_enroll(
                    device_key.as_deref(),
                    encryption_key.as_deref(),
                    &label,
                    backup,
                    authority_device_key.as_deref(),
                    secure_enclave,
                    &se_label,
                    no_provision,
                    ac2_card.as_deref(),
                    &operator_signature_hex,
                    external_signer,
                    recovery_code,
                    cli.json,
                ) {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
            // `pair` (the paired-device WebAuthn ceremony) is still a stub.
            DeviceAction::Pair => {
                let stub_err = ember_daemon::device::DeviceEnrollError::WebAuthnNotImplemented;
                eprintln!("error: {stub_err}");
                process::exit(1);
            }
            // Pure operator-side AC-2 confirmation card verifier — no daemon
            // contact. Closes V030-PRESENCE-AC2 follow-up item 2 (P23-S3
            // checkpoint 2026-06-05).
            DeviceAction::VerifyAc2Cards { cards } => {
                if let Err(e) = run_device_verify_ac2_cards(&cards, cli.json) {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
            // V030-EMBER-DEVICE-REVOKE — drop an enrolled presence Device out
            // of the operator's authority set. Two lanes:
            //  - Default SE-driven (one Touch ID tap, single command). The
            //    CLI fetches PREPARE, signs the bytes with the operator's
            //    `ember-operator-presence` SE key, and submits COMMIT. No
            //    second invocation. `--authority-device-key` inferred from
            //    the SE pubkey when omitted.
            //  - `--external-signer` two-call PREPARE/COMMIT off-host flow
            //    (YubiKey/PIV/PKCS#11/gpg/ssh-keygen). `--authority-device-key`
            //    required.
            // Supplying `--operator-signature-hex` implies `--external-signer`
            // for backward compat with scripts that drove the old flow.
            // Daemon refuses to revoke the LAST active presence Device.
            // Anchor: ember_device_revoke_surface_landed.
            DeviceAction::Revoke {
                device_id,
                authority_device_key,
                reason,
                operator_signature_hex,
                external_signer,
                se_label,
                compromised,
            } => {
                let socket_path = emberlink_cli::daemon_socket_path();
                let external_signer = external_signer || operator_signature_hex.is_some();
                let code = emberlink_cli::device::revoke::run(
                    &socket_path,
                    &device_id,
                    authority_device_key.as_deref(),
                    &reason,
                    operator_signature_hex.as_deref(),
                    external_signer,
                    &se_label,
                    compromised,
                    cli.json,
                );
                if code != 0 {
                    process::exit(code);
                }
            }
        },

        Commands::BinaryPin { action } => match action {
            BinaryPinAction::Generate { paths, force } => {
                let socket_path = emberlink_cli::daemon_socket_path();
                let self_exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("error: could not resolve current_exe for cli pin: {e}");
                        process::exit(1);
                    }
                };

                let mut pins: Vec<serde_json::Value> = vec![serde_json::json!({
                    "caller": "cli",
                    "path": self_exe.display().to_string(),
                })];
                for spec in &paths {
                    match spec.split_once('=') {
                        Some((caller, path)) => pins.push(serde_json::json!({
                            "caller": caller,
                            "path": path,
                        })),
                        None => {
                            eprintln!(
                                "error: --path expects caller=path form (e.g. gui=/Applications/...), got {spec:?}"
                            );
                            process::exit(1);
                        }
                    }
                }

                let request = serde_json::json!({
                    "pins": pins,
                    "force": force,
                });
                let result = match emberlink_cli::call_daemon_method(
                    &socket_path,
                    "binary_pin_generate",
                    &request,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("error: binary_pin_generate failed: {e}");
                        process::exit(1);
                    }
                };

                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    let signed = result
                        .get("pins_signed")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    let missing = result
                        .get("missing")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    println!("ember binary-pin: signed manifest with {signed} pin(s)");
                    if missing > 0 {
                        println!("  (warning: {missing} requested binary paths were not found)");
                    }
                    if let Some(pubkey) = result.get("signer_pubkey").and_then(|v| v.as_str()) {
                        println!("  signer: {pubkey}");
                    }
                    if let Some(when) = result.get("signed_at").and_then(|v| v.as_str()) {
                        println!("  signed_at: {when}");
                    }
                }
            }
        },
        Commands::Vault { action } => {
            // Handle migrate-acl before opening the vault — it operates on the
            // keyring directly and must not require the vault to already be
            // accessible under the new ACL.
            if matches!(action, VaultAction::MigrateAcl) {
                match run_vault_migrate_acl(&config) {
                    Ok(result) => {
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&result)
                                    .unwrap_or_else(|_| "{}".to_string())
                            );
                        } else {
                            let before = result
                                .get("before_acl_kind")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let after = result
                                .get("after_acl_kind")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let service =
                                result.get("service").and_then(|v| v.as_str()).unwrap_or("");
                            let account =
                                result.get("account").and_then(|v| v.as_str()).unwrap_or("");
                            if before == after {
                                println!("MEK already uses {before} ACL — no migration needed.");
                            } else {
                                println!("MEK ACL migrated: {before} → {after}");
                                println!("  service: {service}");
                                println!("  account: {account}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                return;
            }

            // These verbs can route through the daemon without changing the
            // operator-visible data contract, so prefer the daemon surface and
            // avoid opening the vault in-process when the socket exists.
            match &action {
                VaultAction::List(VaultListArgs { prefix }) => {
                    match run_vault_list(&config, prefix.as_deref()) {
                        Ok((_, entries)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&entries).unwrap());
                            } else {
                                println!("{}", render_vault_list_text(&entries, prefix.as_deref()));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                VaultAction::Add {
                    name,
                    value,
                    stdin,
                    file,
                    delete_source,
                    from_downloads,
                    metadata,
                    require_biometric,
                } => {
                    if let Err(e) = validate_credential_name(name) {
                        eprintln!("error: invalid credential name: {e}");
                        eprintln!(
                            "       see ADR 099 §5.1 for the path grammar (lowercase \
                                 + digits + hyphen, 1..=4 path segments separated by '/')"
                        );
                        process::exit(2);
                    }
                    if value.is_some() {
                        refuse_value_in_argv("value");
                    }
                    let resolved = match resolve_credential_input(
                        *stdin,
                        file.as_deref(),
                        *delete_source,
                        *from_downloads,
                    ) {
                        Ok(bytes) => bytes,
                        Err(code) => process::exit(code),
                    };
                    match run_vault_store(
                        &config,
                        "vault_add",
                        name,
                        &resolved,
                        metadata.as_deref(),
                        *require_biometric,
                    ) {
                        Ok(info) => {
                            let _ = info.dispatch;
                            println!("Stored credential");
                            println!("  ID:   {}", info.id);
                            println!("  Name: {}", info.name);
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                VaultAction::Get(VaultGetArgs {
                    name,
                    unmask,
                    i_know_what_im_doing,
                }) => match run_vault_get(&config, name) {
                    Ok((_, value)) => {
                        if *unmask {
                            if std::io::stdout().is_terminal() && !i_know_what_im_doing {
                                eprintln!("error: --unmask refused on a TTY. Re-run with one of:");
                                eprintln!(
                                    "         ember vault get {name} --unmask | tee /dev/null   # pipe to non-TTY"
                                );
                                eprintln!(
                                    "         ember vault get {name} --unmask --i-know-what-im-doing"
                                );
                                process::exit(2);
                            }
                            let text = String::from_utf8_lossy(&value);
                            println!("{text}");
                        } else {
                            println!(
                                "{}",
                                emberlink_cli::vault_io::mask_credential_for_display(&value)
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::Put(args) => {
                    if let Err(e) = validate_credential_name(&args.name) {
                        eprintln!("error: invalid credential name: {e}");
                        eprintln!(
                            "       see ADR 099 §5.1 for the path grammar (lowercase \
                                 + digits + hyphen, 1..=4 path segments separated by '/')"
                        );
                        process::exit(2);
                    }
                    if args.value.is_some() {
                        refuse_value_in_argv("value");
                    }
                    let resolved = match resolve_credential_input(
                        args.stdin,
                        args.file.as_deref(),
                        args.delete_source,
                        args.from_downloads,
                    ) {
                        Ok(bytes) => bytes,
                        Err(code) => process::exit(code),
                    };
                    match run_vault_store(
                        &config,
                        "vault_put",
                        &args.name,
                        &resolved,
                        args.metadata.as_deref(),
                        args.require_biometric,
                    ) {
                        Ok(info) => {
                            let _ = info.dispatch;
                            println!("Stored credential");
                            println!("  ID:   {}", info.id);
                            println!("  Name: {}", info.name);
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                VaultAction::Remove { name } => match run_vault_remove(&config, name) {
                    Ok(_) => println!("Removed credential {name}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                VaultAction::Export(args) if args.sealed => {
                    // vault_export_sealed_cli_landed: keep raw Interactive MEK
                    // material in daemon space; the CLI only handles the sealed EMVS blob.
                    if let Err(code) = run_vault_export(&config, cli.json, args) {
                        process::exit(code);
                    }
                }
                VaultAction::Import(args) if args.sealed => {
                    // vault_import_sealed_cli_landed: sealed restore can run before
                    // any live vault exists, so it must bypass the normal vault-open path.
                    if let Err(code) = run_vault_import(&config, args) {
                        process::exit(code);
                    }
                }
                _ => {}
            }

            if matches!(
                &action,
                VaultAction::List(_)
                    | VaultAction::Add { .. }
                    | VaultAction::Get(_)
                    | VaultAction::Put(_)
                    | VaultAction::Remove { .. }
                    | VaultAction::Export(VaultExportArgs { sealed: true, .. })
                    | VaultAction::Import(VaultImportArgs { sealed: true, .. })
            ) {
                return;
            }

            // Lock/unlock are authority-sensitive but do not need the normal
            // open_store + Vault::open_from_config data path.
            if matches!(&action, VaultAction::Lock | VaultAction::Unlock) {
                let result = match &action {
                    VaultAction::Lock => run_vault_lock(&config).map(|_| "locked"),
                    VaultAction::Unlock => run_vault_unlock(&config).map(|_| "unlocked"),
                    _ => unreachable!("lock/unlock branch must only handle lock-style actions"),
                };
                match result {
                    Ok(state) => {
                        if cli.json {
                            println!("{{\"{state}\": true}}");
                        } else if state == "locked" {
                            println!(
                                "Vault session re-locked. Next high-risk op will prompt for user presence."
                            );
                        } else {
                            println!(
                                "Vault session unlocked. Non-session operator flows may use the daemon vault again."
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                return;
            }

            // ADR 206 §4 presence-as-decryption: provision / unlock. Like
            // lock/unlock, these drive the daemon directly (the SE crypto runs
            // here in the operator session) and skip the open_store data path.
            if matches!(
                &action,
                VaultAction::SeProvision { .. }
                    | VaultAction::SeUnlock { .. }
                    | VaultAction::EnrollRecovery { .. }
            ) {
                let result = match &action {
                    VaultAction::SeProvision { se_label } => {
                        run_vault_se_provision(se_label, cli.json)
                    }
                    VaultAction::SeUnlock {
                        se_label,
                        recovery_code,
                    } => run_vault_se_unlock(se_label, recovery_code.as_deref(), cli.json),
                    VaultAction::EnrollRecovery { se_label, label } => {
                        run_vault_enroll_recovery(se_label, label, cli.json)
                    }
                    _ => unreachable!(
                        "§4 branch must only handle se-provision/se-unlock/enroll-recovery"
                    ),
                };
                if let Err(e) = result {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
                return;
            }

            // Client-side pre-validation: fail fast on a malformed name before
            // we open the store / unlock the vault (which on macOS would fire
            // a Touch ID prompt). The daemon-side check in `Vault::add` is
            // authoritative; this mirror is purely UX. If the regex constants
            // need to be tweaked, change `validate_credential_name` in
            // `ember-daemon::vault` — the CLI imports the same fn so they
            // cannot drift.
            // Mirror the daemon-side `validate_credential_name` UX gate
            // for both `add` and `put` so we fail before unlocking the
            // vault on macOS (which would fire a Touch ID prompt).
            let pre_validate_name: Option<&str> = match &action {
                VaultAction::Add { name, .. } => Some(name.as_str()),
                VaultAction::Put(args) => Some(args.name.as_str()),
                _ => None,
            };
            if let Some(name) = pre_validate_name
                && let Err(e) = validate_credential_name(name)
            {
                eprintln!("error: invalid credential name: {e}");
                eprintln!(
                    "       see ADR 099 §5.1 for the path grammar (lowercase \
                         + digits + hyphen, 1..=4 path segments separated by '/')"
                );
                process::exit(2);
            }

            // [open-store-audit] MUTATOR-MIXED: Commands::Vault.
            //   Add/Put     → MUTATOR (`vault_add`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Remove      → MUTATOR (`vault_remove`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Import      → MUTATOR. No dedicated batch RPC, but the CLI
            //                 now commits via per-entry `vault_add` on the
            //                 current authority surface.
            //   List        → READ-ONLY (`vault_list`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Get         → READ-ONLY (`vault_get`) when a daemon socket is
            //                 present; local fallback when no daemon exists.
            //   Export      → READ-ONLY. No dedicated batch RPC, but the CLI
            //                 now reads via `vault_list` + `vault_get` on the
            //                 current authority surface.
            //   Lock/Unlock → MUTATOR (`vault_lock` / `vault_unlock`) on the
            //                 daemon-owned control plane only. Handled before
            //                 `open_store`.
            // Migration is per-arm and high-traffic; deferred to follow-up.
            match action {
                VaultAction::Add { .. } => unreachable!("add is handled before vault open"),
                VaultAction::List(_) => unreachable!("list is handled before vault open"),
                VaultAction::Get(_) => unreachable!("get is handled before vault open"),
                VaultAction::Put(_) => unreachable!("put is handled before vault open"),
                VaultAction::Export(args) => {
                    if let Err(code) = run_vault_export(&config, cli.json, &args) {
                        process::exit(code);
                    }
                }
                VaultAction::Import(args) => {
                    if let Err(code) = run_vault_import(&config, &args) {
                        process::exit(code);
                    }
                }
                VaultAction::Remove { .. } => unreachable!("remove is handled before vault open"),
                VaultAction::Lock => {
                    unreachable!("lock is handled before vault open");
                }
                VaultAction::Unlock => {
                    unreachable!("unlock is handled before vault open");
                }
                VaultAction::MigrateAcl => {
                    // Handled above (before vault open) via the early-return path.
                    unreachable!("migrate-acl is handled before vault open");
                }
                VaultAction::SeProvision { .. } => {
                    unreachable!("se-provision is handled before vault open");
                }
                VaultAction::SeUnlock { .. } => {
                    unreachable!("se-unlock is handled before vault open");
                }
                VaultAction::EnrollRecovery { .. } => {
                    unreachable!("enroll-recovery is handled before vault open");
                }
            }
        }

        Commands::Grant { action } => {
            // [open-store-audit] MUTATOR-MIXED: Commands::Grant.
            //   Create   → MUTATOR (`create_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Delegate → MUTATOR (`delegate_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   List     → READ-ONLY (`list_operator_grants`) when a daemon
            //              socket is present; local fallback when no daemon exists.
            //   Revoke   → MUTATOR (`revoke_grant`) on the daemon socket.
            //   Expire   → MUTATOR (`expire_grants`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Budget   → READ-ONLY (`grant_status`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            //   Extend   → MUTATOR (`extend_grant`) when a daemon socket is
            //              present; local fallback when no daemon exists.
            match &action {
                GrantAction::Create {
                    persona,
                    kind,
                    credential,
                    scope,
                    ttl,
                    vendor,
                    max_cents,
                    window,
                    hard_cap,
                    rate_limit,
                    hours_start,
                    hours_end,
                    allowed_targets,
                    delegation_depth,
                    budget_tokens,
                    budget_usd,
                    budget_requests,
                    budget_seconds,
                    attestation_runtime: _,
                    standing,
                    max_children_per_day,
                    auto_delegate_scope_template,
                } => {
                    if matches!(kind, Some(GrantSurfaceKind::Spend)) {
                        let vendor = match vendor.as_deref() {
                            Some(value) if !value.trim().is_empty() => value.to_string(),
                            _ => {
                                eprintln!("error: --kind spend requires --vendor <name>");
                                process::exit(1);
                            }
                        };
                        if credential.is_some() || scope.is_some() {
                            eprintln!(
                                "error: --kind spend does not accept --credential or --scope"
                            );
                            process::exit(1);
                        }
                        if rate_limit.is_some()
                            || hours_start.is_some()
                            || hours_end.is_some()
                            || allowed_targets.is_some()
                            || delegation_depth.is_some()
                            || budget_tokens.is_some()
                            || budget_requests.is_some()
                            || budget_seconds.is_some()
                            || *standing
                            || max_children_per_day.is_some()
                            || auto_delegate_scope_template.is_some()
                        {
                            eprintln!(
                                "error: --kind spend only supports --persona, --vendor, --max-cents, --window/--ttl, --budget-usd, and --hard-cap"
                            );
                            process::exit(1);
                        }
                        let threshold_cents = *max_cents;
                        if budget_usd.is_some() && hard_cap.is_some() {
                            eprintln!("error: pass either --budget-usd or --hard-cap, not both");
                            process::exit(1);
                        }
                        let hard_cap_cents = match (budget_usd.as_deref(), hard_cap) {
                            (Some(s), None) => match parse_usd_to_cents(s) {
                                Ok(c) => Some(c),
                                Err(e) => {
                                    eprintln!("error: --budget-usd: {e}");
                                    process::exit(1);
                                }
                            },
                            (None, Some(value)) => Some(*value),
                            (None, None) => None,
                            (Some(_), Some(_)) => unreachable!(),
                        };
                        let ttl_secs = match (ttl.as_deref(), window.as_deref()) {
                            (Some(_), Some(_)) => {
                                eprintln!(
                                    "error: choose either --ttl or --window for spend grants"
                                );
                                process::exit(1);
                            }
                            (Some(s), None) | (None, Some(s)) => match parse_duration(s) {
                                Ok(v) => Some(v),
                                Err(e) => {
                                    eprintln!("error: invalid spend window: {e}");
                                    process::exit(1);
                                }
                            },
                            (None, None) => None,
                        };
                        let spec = build_spend_grant_create_spec(
                            persona,
                            &vendor,
                            threshold_cents,
                            hard_cap_cents,
                            ttl_secs,
                        );
                        match run_grant_create_composite(&config, &spec) {
                            Ok((_, response)) => {
                                if cli.json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&response).unwrap()
                                    );
                                } else {
                                    let id = response["id"].as_str().unwrap_or("");
                                    let expires_at = response["expires_at"].as_str();
                                    print_created_spend_grant(
                                        persona,
                                        &vendor,
                                        threshold_cents,
                                        hard_cap_cents,
                                        id,
                                        expires_at,
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                        return;
                    }

                    let credential = match credential {
                        Some(value) => value.clone(),
                        None => {
                            eprintln!(
                                "error: grant create requires --credential unless --kind spend is set"
                            );
                            process::exit(1);
                        }
                    };
                    let scope = match scope {
                        Some(value) => value.clone(),
                        None => {
                            eprintln!(
                                "error: grant create requires --scope unless --kind spend is set"
                            );
                            process::exit(1);
                        }
                    };
                    if vendor.is_some()
                        || max_cents.is_some()
                        || window.is_some()
                        || hard_cap.is_some()
                    {
                        eprintln!(
                            "error: spend-only flags (--vendor, --max-cents, --window, --hard-cap) require --kind spend"
                        );
                        process::exit(1);
                    }
                    if *standing && max_children_per_day.is_none() {
                        eprintln!("error: --standing requires --max-children-per-day");
                        process::exit(1);
                    }
                    if *standing && delegation_depth.is_none() {
                        eprintln!(
                            "error: --standing requires --delegation-depth (the parent must allow delegation)"
                        );
                        process::exit(1);
                    }
                    let parsed_cents = match budget_usd.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let spec = GrantCreateSpec {
                        persona: persona.clone(),
                        credential,
                        scope,
                        ttl_secs,
                        max_uses_per_hour: *rate_limit,
                        allowed_hours_start: *hours_start,
                        allowed_hours_end: *hours_end,
                        allowed_targets: allowed_targets.as_ref().map(|targets| {
                            targets
                                .split(',')
                                .map(str::to_owned)
                                .collect::<Vec<String>>()
                        }),
                        max_delegation_depth: *delegation_depth,
                        budget: build_budget(
                            *budget_tokens,
                            parsed_cents,
                            *budget_requests,
                            *budget_seconds,
                        ),
                        max_children_per_day: if *standing {
                            *max_children_per_day
                        } else {
                            None
                        },
                        auto_delegate_scope_template: if *standing {
                            auto_delegate_scope_template.clone()
                        } else {
                            None
                        },
                    };
                    match run_grant_create(&config, &spec) {
                        Ok((_, response)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&response).unwrap());
                            } else if response["status"] == serde_json::json!("pending_approval") {
                                let approval_id =
                                    response["approval_id"].as_str().unwrap_or("<unknown>");
                                println!("Grant creation pending approval");
                                println!("  Approval:   {approval_id}");
                            } else {
                                let id = response["id"].as_str().unwrap_or("");
                                let expires_at = response["expires_at"].as_str();
                                print_created_grant(&spec, id, expires_at);
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Delegate {
                    parent,
                    persona,
                    scope,
                    ttl,
                    budget_tokens,
                    budget_usd,
                    budget_requests,
                    budget_seconds,
                } => {
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(n) => Some(n),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let parsed_cents = match budget_usd.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let child_budget = build_budget(
                        *budget_tokens,
                        parsed_cents,
                        *budget_requests,
                        *budget_seconds,
                    );
                    match run_grant_delegate(
                        &config,
                        parent,
                        persona,
                        scope,
                        ttl_secs,
                        child_budget,
                    ) {
                        Ok((_, info)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&info).unwrap());
                            } else {
                                let id = info.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                println!("{id}");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::List { active, kind } => {
                    if matches!(kind, Some(GrantSurfaceKind::Spend)) {
                        match run_spend_grant_list(&config, *active) {
                            Ok((_, rows)) => {
                                if cli.json {
                                    println!("{}", serde_json::to_string_pretty(&rows).unwrap());
                                } else {
                                    println!("{}", render_spend_grant_list_text(&rows, *active));
                                }
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    } else {
                        match run_grant_list(&config, *active) {
                            Ok((_, list)) => {
                                if cli.json {
                                    println!("{}", serde_json::to_string_pretty(&list).unwrap());
                                } else {
                                    println!("{}", render_grant_list_text(&list, *active));
                                }
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    }
                }
                GrantAction::Show { id } => match run_grant_status(&config, id) {
                    Ok((_, status)) => {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&status).unwrap());
                        } else if payment_statement_from_status(&status).is_some() {
                            println!("{}", render_spend_grant_show_text(&status));
                        } else {
                            let budget_view = GrantBudgetStatusView {
                                id: status.id,
                                persona_id: status.persona_id,
                                status: status.status,
                                expires_at: status.expires_at,
                                statements: status
                                    .statements
                                    .into_iter()
                                    .map(|stmt| GrantBudgetStatusStatementView {
                                        sid: stmt.sid,
                                        resource_type: stmt.resource_type,
                                        resource: stmt.resource,
                                        budget: stmt.budget,
                                        usage: stmt.usage,
                                    })
                                    .collect(),
                            };
                            print!("{}", render_grant_budget_from_status(&budget_view));
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Evaluate { grant, attempt } => {
                    match run_grant_evaluate(&config, grant, attempt) {
                        Ok((_, decision)) => {
                            if cli.json {
                                println!("{}", serde_json::to_string_pretty(&decision).unwrap());
                            } else {
                                println!("{}", render_grant_evaluate_text(&decision));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Revoke { id } => {
                    let socket_path = config.socket_dir.join("daemon.sock");
                    let request = serde_json::json!({ "id": id });
                    match emberlink_cli::call_daemon_method(&socket_path, "revoke_grant", &request)
                    {
                        Ok(_) => println!("Revoked grant {id}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Expire => match run_grant_expire(&config) {
                    Ok((_, count)) => println!("Expired {} stale grant(s)", count),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                GrantAction::Extend {
                    grant_id,
                    tokens,
                    cents,
                    ttl,
                } => {
                    let parsed_cents = match cents.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --cents: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(secs) => Some(secs),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };
                    match run_grant_extend(&config, grant_id, *tokens, parsed_cents, ttl_secs) {
                        Ok(_) => {
                            let mut parts = Vec::new();
                            if let Some(t) = tokens {
                                parts.push(format!("+{} tokens", t));
                            }
                            if let Some(c) = parsed_cents {
                                parts.push(format!("+${:.2}", c as f64 / 100.0));
                            }
                            if let Some(s) = ttl_secs {
                                parts.push(format!("+{}", format_duration(s)));
                            }
                            if parts.is_empty() {
                                println!("Extended: (no changes)");
                            } else {
                                println!("Extended: {}", parts.join(", "));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                GrantAction::Budget { grant_id } => match run_grant_budget(&config, grant_id) {
                    Ok((_, rendered)) => print!("{rendered}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Sandbox { action } => {
            // [open-store-audit] MUTATOR-MIXED: Commands::Sandbox.
            //   Create/List/Stop/Delete/Exec → daemon-backed when a live
            //                socket exists; local fallback only on
            //                no-daemon/dev paths.
            //   Run        → daemon-backed for sandbox create/start plus
            //                composite grant policy/approval orchestration;
            //                local fallback only on no-daemon/dev paths.
            //                The final interactive `docker exec` handoff is
            //                still a local operator terminal step.
            //   RunScion   → escapes to async helper; does not hold store.
            match action {
                SandboxAction::Create {
                    name,
                    image,
                    privileged,
                    volume,
                    user,
                    network,
                    unsafe_root,
                    workspace_from,
                    env,
                    persona,
                } => {
                    let extra_env: Vec<(String, String)> = env
                        .iter()
                        .filter_map(|kv| {
                            kv.split_once('=')
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                        })
                        .collect();
                    let owner_persona_id =
                        persona.or_else(|| std::env::var("EMBER_PERSONA_ID").ok());
                    let opts = SandboxCreateOpts {
                        name: name.clone(),
                        image: image.clone(),
                        privileged,
                        volumes: volume.clone(),
                        user: user.clone(),
                        network: network.clone(),
                        unsafe_root,
                        workspace_from: workspace_from.clone(),
                        extra_env: extra_env.clone(),
                        owner_persona_id,
                    };
                    let created = match run_sandbox_create(&config, &opts) {
                        Ok((_, created)) => created,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if let Some(ref e) = created.start_error {
                        eprintln!("warning: sandbox created but container failed: {e}");
                    }
                    // Record image digest to ~/.ember/images.toml
                    let registry_path = config.data_dir.join("images.toml");
                    match resolve_image_digest(&image) {
                        Some(digest) => {
                            record_image_digest(&registry_path, &image, &digest);
                        }
                        None => {
                            eprintln!(
                                "warning: could not resolve image digest for {image} — docker may not be available"
                            );
                        }
                    }
                    let container_id = created.container_id.as_deref().unwrap_or("none");
                    let sandbox = &created.sandbox;
                    println!("Created sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }
                }
                SandboxAction::List => match run_sandbox_list(&config) {
                    Ok((_, sandboxes)) => {
                        println!("{}", render_sandbox_list_text(&sandboxes));
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Stop { id } => match run_sandbox_stop(&config, &id) {
                    Ok((_, resolved_id)) => println!("Stopped sandbox {resolved_id}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Delete { id } => match run_sandbox_delete(&config, &id) {
                    Ok((_, deleted)) if deleted.already_absent => {
                        println!("sandbox '{id}' not found (already deleted — ok)");
                    }
                    Ok((_, deleted)) => {
                        let resolved_id = deleted.resolved_id.as_deref().unwrap_or("(unknown)");
                        println!("Deleted sandbox {resolved_id}");
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                SandboxAction::Exec {
                    id,
                    persona,
                    command,
                } => {
                    let caller_persona = persona
                        .or_else(|| std::env::var("EMBER_PERSONA_ID").ok())
                        .filter(|s| !s.is_empty());
                    match run_sandbox_exec(&config, &id, caller_persona, &command) {
                        Ok((_, output)) => print!("{output}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                SandboxAction::Run {
                    name,
                    image,
                    workspace_from,
                    env,
                    credential_resource,
                    budget_tokens,
                    budget_usd: budget_usd_str,
                    budget_seconds,
                    ttl,
                    prompt,
                } => {
                    // Parse --budget-usd (dollars) into integer cents for storage.
                    let parsed_cents = match budget_usd_str.as_deref() {
                        Some(s) => match parse_usd_to_cents(s) {
                            Ok(c) => Some(c),
                            Err(e) => {
                                eprintln!("error: --budget-usd: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };

                    // Build the 3-statement composite envelope.
                    let statements = build_composite_grant_statements(
                        credential_resource.as_deref(),
                        budget_tokens,
                        parsed_cents,
                        budget_seconds,
                    );
                    let statement_count = statements.len();

                    // Parse TTL.
                    let ttl_secs = match ttl.as_deref() {
                        Some(s) => match parse_duration(s) {
                            Ok(v) => Some(v),
                            Err(e) => {
                                eprintln!("error: --ttl: {e}");
                                process::exit(1);
                            }
                        },
                        None => None,
                    };

                    // Build sandbox opts.
                    let extra_env: Vec<(String, String)> = env
                        .iter()
                        .filter_map(|kv| {
                            if let Some((k, v)) = kv.split_once('=') {
                                Some((k.to_string(), v.to_string()))
                            } else {
                                // Bare key — pass-through from host environment.
                                std::env::var(kv).ok().map(|v| (kv.clone(), v))
                            }
                        })
                        .collect();

                    let run_owner_persona_id = std::env::var("EMBER_PERSONA_ID").ok();
                    let opts = SandboxCreateOpts {
                        name: name.clone(),
                        image: image.clone(),
                        privileged: false,
                        volumes: vec![],
                        user: None,
                        network: None,
                        unsafe_root: false,
                        workspace_from: workspace_from.clone(),
                        extra_env: extra_env.clone(),
                        owner_persona_id: run_owner_persona_id,
                    };
                    let prepared = match run_sandbox_run(
                        &config,
                        &opts,
                        &statements,
                        ttl_secs,
                        credential_resource.as_deref(),
                    ) {
                        Ok((_, prepared)) => prepared,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if let Some(ref e) = prepared.start_error {
                        eprintln!("warning: sandbox created but container failed: {e}");
                    }
                    let container_id = prepared.container_id.as_deref().unwrap_or("none");
                    let sandbox = &prepared.sandbox;

                    println!("Started sandbox");
                    println!("  ID:        {}", sandbox.id);
                    println!("  Persona:   {}", sandbox.persona_id);
                    println!("  Container: {container_id}");
                    if let Some(ws) = &sandbox.workspace_path {
                        println!("  Workspace: {ws}");
                    }

                    // Mint the composite grant if a credential resource was supplied.
                    //
                    // Route the composite mint through the policy
                    // engine so `default_decision = "require_approval"` fires
                    // here.
                    //
                    // COMPOSITE-PR4 — collapsed both Auto and Required onto a
                    // single mint code path. Every outcome dispatches via
                    // `propose_grant`; the daemon-side `auto_resolve` handles
                    // the auto lane (immediate Approved + `auto_resolved`
                    // audit event), the human approval flow handles Required.
                    // No more inline `create_grant` + `overwrite_grant_blocks`
                    // bypass on the AutoApprove path.
                    //
                    // Three outcomes:
                    //   - Auto: propose_grant + auto_resolve (mint immediate)
                    //   - Required: propose_grant; do NOT exec prompt; exit
                    //     so the operator can `ember approval approve <id>`
                    //   - Denied: error and exit non-zero
                    //
                    // The policy action name is `credential.access` to match
                    // the daemon's existing credential-access rule shape.
                    let mut sandbox_grant_pending = false;
                    let credential_res = credential_resource.as_deref().unwrap_or("");
                    match &prepared.grant {
                        SandboxRunGrantDisposition::NotRequested => {
                            println!("  (no --credential-resource supplied — grant not minted)");
                        }
                        SandboxRunGrantDisposition::PendingApproval { approval_id } => {
                            sandbox_grant_pending = true;
                            println!("Approval required for composite grant");
                            println!("  Approval ID: {}", approval_id);
                            println!("  Statements:  {statement_count}");
                            println!("    [0] credential:read  on {credential_res}");
                            if let Some(t) = budget_tokens {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  budget={t} tokens"
                                );
                            } else {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  (no token budget)"
                                );
                            }
                            if let Some(s) = budget_seconds {
                                println!("    [2] time:wall_clock  on *             budget={s}s");
                            } else {
                                println!(
                                    "    [2] time:wall_clock  on *             (no time budget)"
                                );
                            }
                            println!();
                            println!("  Approve from CLI: ember approval approve {}", approval_id);
                            println!(
                                "  Or open dashboard: http://localhost:3141/approvals/{}",
                                approval_id
                            );
                        }
                        SandboxRunGrantDisposition::Minted { grant_id } => {
                            let grant_id = grant_id.as_deref().unwrap_or("(unknown)");
                            println!("Minted 3-statement composite grant");
                            println!("  Grant ID:   {grant_id}");
                            println!("  Statements: {statement_count}");
                            println!("    [0] credential:read  on {credential_res}");
                            if let Some(t) = budget_tokens {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  budget={t} tokens"
                                );
                            } else {
                                println!(
                                    "    [1] llm:generate     on anthropic/*  (no token budget)"
                                );
                            }
                            if let Some(s) = budget_seconds {
                                println!("    [2] time:wall_clock  on *             budget={s}s");
                            } else {
                                println!(
                                    "    [2] time:wall_clock  on *             (no time budget)"
                                );
                            }
                            println!("  One approval. Three meters. One receipt at the end.");
                            if let Some(ref p) = prompt {
                                println!("  Prompt: {p}");
                            }
                        }
                        SandboxRunGrantDisposition::Failed { message } => {
                            eprintln!("warning: sandbox started but {message}");
                        }
                    }

                    // If a prompt was given and the container started, hand off to
                    // `docker exec -it <container_id> claude -p "<prompt>"`.  The
                    // child process inherits stdin/stdout so Claude Code's output
                    // streams directly to the operator's terminal.
                    //
                    // When the composite grant is pending approval,
                    // skip the agent exec; the operator must approve first
                    // (then re-run / `ember sandbox exec`) to give the agent
                    // its credentials.
                    if sandbox_grant_pending {
                        if prompt.is_some() {
                            eprintln!(
                                "  (skipping agent exec — approve the composite grant first)"
                            );
                        }
                    } else if let Some(ref p) = prompt {
                        if container_id != "none" {
                            use std::io::IsTerminal as _;
                            let tty_flags = docker_exec_flags(std::io::stdin().is_terminal());
                            let mut exec_args = vec!["exec"];
                            exec_args.extend_from_slice(&tty_flags);
                            exec_args.push(container_id);
                            exec_args.extend_from_slice(&["claude", "-p", p]);
                            let exit_status = std::process::Command::new("docker")
                                .args(&exec_args)
                                .status();
                            match exit_status {
                                Ok(s) if s.success() => {}
                                Ok(s) => {
                                    eprintln!(
                                        "warning: claude exited with status {}",
                                        s.code().unwrap_or(-1)
                                    );
                                }
                                Err(e) => {
                                    eprintln!("error: docker exec failed: {e}");
                                    process::exit(1);
                                }
                            }
                        } else {
                            eprintln!("warning: container did not start — skipping claude exec");
                        }
                    }
                }
                SandboxAction::RunScion {
                    task,
                    ttl,
                    dry_run,
                    stream_checkpoints,
                    no_receipt_tree,
                } => {
                    let rt =
                        tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                    match rt.block_on(emberlink_cli::sandbox::cmd_sandbox_run_scion(
                        &config,
                        &task,
                        ttl.as_deref(),
                        dry_run,
                        stream_checkpoints,
                        no_receipt_tree,
                    )) {
                        Ok(()) => {}
                        Err(code) => process::exit(code),
                    }
                }
            }
        }

        Commands::Approval { action } => {
            // [open-store-audit] MUTATOR-MIXED: Commands::Approval.
            //   List              → `list_pending_approvals` when a daemon
            //                       socket is live.
            //   Approve/Deny/Narrow → `resolve_approval` when a daemon
            //                       socket is live.
            // Direct store fallback remains only for no-daemon/dev paths.
            match action {
                ApprovalAction::List => match run_approval_list(&config) {
                    Ok((_, requests)) => {
                        println!("{}", render_approval_list_text(&requests));
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
                ApprovalAction::Approve { id, always, ttl } => {
                    let outcome = if always {
                        let expires_at = match ttl.as_deref() {
                            Some("never") => {
                                eprintln!("warning: standing grant has no expiry (--ttl never)");
                                None
                            }
                            Some(s) => {
                                let days: i64 = if let Some(d) = s.strip_suffix('d') {
                                    d.parse().unwrap_or_else(|_| {
                                        eprintln!("error: invalid --ttl value '{s}'; expected e.g. 7d, 30d, never");
                                        process::exit(1);
                                    })
                                } else {
                                    eprintln!(
                                        "error: invalid --ttl value '{s}'; expected e.g. 7d, 30d, never"
                                    );
                                    process::exit(1);
                                };
                                let exp = chrono::Utc::now() + chrono::Duration::days(days);
                                Some(exp.format("%Y-%m-%dT%H:%M:%S").to_string())
                            }
                            None => {
                                // Default: 30 days
                                let exp = chrono::Utc::now() + chrono::Duration::days(30);
                                Some(exp.format("%Y-%m-%dT%H:%M:%S").to_string())
                            }
                        };
                        ApprovalOutcome::Always {
                            scope: None,
                            expires_at,
                        }
                    } else {
                        ApprovalOutcome::Approved
                    };
                    match run_approval_resolve(&config, &id, &outcome) {
                        Ok((_, resolved)) => {
                            if always {
                                println!("Approved {id}");
                                println!(
                                    "  Standing grant created: future requests for this action will auto-approve."
                                );
                                println!("  Review: ember grant standing list");
                            } else {
                                println!("Approved {id}");
                            }
                            // Surface the grant ID minted by a
                            // composite-approval resolution so the operator
                            // (or test harness) can use it directly.
                            if let Some(grant_id) = resolved.result_grant_id.as_deref() {
                                println!("  Grant ID: {grant_id}");
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ApprovalAction::Deny { id, reason } => {
                    match run_approval_resolve(
                        &config,
                        &id,
                        &ApprovalOutcome::Denied {
                            reason: reason.clone(),
                        },
                    ) {
                        Ok(_) => println!("Denied {id}: {reason}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ApprovalAction::Narrow { id, scope } => {
                    match run_approval_resolve(
                        &config,
                        &id,
                        &ApprovalOutcome::Narrowed {
                            new_scope: scope.clone(),
                        },
                    ) {
                        Ok(_) => println!("Narrowed {id} to scope: {scope}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Audit { action } => {
            // [open-store-audit] DAEMON-BACKED READ-ONLY on the installed path.
            //   Query   → `receipt_query` when a daemon socket is live.
            //   Show    → operator-only `audit_log_query` when a daemon
            //             socket is live.
            //   Export  → operator-only `audit_log_query` when a daemon
            //             socket is live.
            //   Explain → current-state `audit_explain` when a daemon
            //             socket is live.
            //   Verify  → daemon-backed via `audit_verify`.
            // Local direct fallback remains only for no-daemon/dev paths.
            match action {
                AuditAction::Show { agent, limit } => {
                    let filter = AuditFilter {
                        agent_id: agent,
                        limit: Some(limit),
                        ..Default::default()
                    };
                    match run_audit_log_query(&config, &filter) {
                        Ok((_, entries)) => {
                            if cli.json {
                                let arr: Vec<_> = entries
                                    .iter()
                                    .map(|e| {
                                        serde_json::json!({
                                            "timestamp": e.timestamp,
                                            "agent_id": e.agent_id,
                                            "action": e.action,
                                            "credential": e.credential,
                                            "outcome": e.outcome,
                                        })
                                    })
                                    .collect();
                                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
                            } else {
                                println!("{}", render_audit_show_text(&entries));
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                AuditAction::Export {
                    format,
                    limit,
                    agent,
                    output,
                    since,
                    workflow,
                    redact,
                    sign,
                } => {
                    if sign {
                        let output = match output {
                            Some(path) => path,
                            None => {
                                eprintln!("error: signed audit export requires --output <file>");
                                process::exit(1);
                            }
                        };
                        let since_iso = match since.as_deref() {
                            None => None,
                            Some(s) => match parse_since(s) {
                                Some(dt) => Some(dt.to_rfc3339()),
                                None => {
                                    eprintln!(
                                        "error: invalid --since '{s}' \
                                         (expected ISO-8601 like 2026-04-01T00:00:00Z \
                                         or relative duration like 24h / 7d)"
                                    );
                                    process::exit(1);
                                }
                            },
                        };
                        let redaction_rules =
                            match emberlink_cli::audit::redact::parse_redaction_rules(
                                redact.as_deref(),
                            ) {
                                Ok(rules) => rules,
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    process::exit(1);
                                }
                            };
                        let request = emberlink_cli::audit::export::ExportRequest {
                            db_path: config.data_dir.join("daemon.db"),
                            since_iso,
                            workflow,
                            redaction_rules,
                            output,
                        };
                        match emberlink_cli::audit::export::run_signed_export(request) {
                            Ok(outcome) => {
                                if cli.json {
                                    let value = serde_json::json!({
                                        "output": outcome.output,
                                        "count": outcome.count,
                                        "redacted_receipts": outcome.redacted_receipts,
                                        "operator_pubkey": outcome.operator_pubkey,
                                        "primitive_gaps": outcome.primitive_gaps,
                                    });
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&value).unwrap_or_default()
                                    );
                                } else {
                                    eprintln!(
                                        "Exported {} receipts to {}",
                                        outcome.count,
                                        outcome.output.display()
                                    );
                                    if outcome.redacted_receipts > 0 {
                                        eprintln!(
                                            "Redacted receipts: {}",
                                            outcome.redacted_receipts
                                        );
                                    }
                                    if !outcome.primitive_gaps.is_empty() {
                                        eprintln!("Primitive gaps:");
                                        for gap in outcome.primitive_gaps {
                                            eprintln!("  - {gap}");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                        return;
                    }

                    if since.is_some() || workflow.is_some() || redact.is_some() {
                        eprintln!(
                            "error: --since, --workflow, and --redact on `ember audit export` require --sign"
                        );
                        process::exit(1);
                    }

                    let filter = AuditFilter {
                        agent_id: agent,
                        limit,
                        ..Default::default()
                    };
                    let entries = match run_audit_log_query(&config, &filter) {
                        Ok(entries) => {
                            let (_, entries) = entries;
                            entries
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };

                    let content = match format.as_str() {
                        "csv" => {
                            let mut lines = vec![
                                "timestamp,agent_id,action,credential,outcome,details".to_string(),
                            ];
                            for e in &entries {
                                lines.push(format!(
                                    "{},{},{},{},{},{}",
                                    e.timestamp,
                                    e.agent_id.as_deref().unwrap_or(""),
                                    e.action,
                                    e.credential.as_deref().unwrap_or(""),
                                    e.outcome,
                                    e.details.as_deref().unwrap_or(""),
                                ));
                            }
                            lines.join("\n")
                        }
                        _ => serde_json::to_string_pretty(
                            &entries
                                .iter()
                                .map(|e| {
                                    serde_json::json!({
                                        "timestamp": e.timestamp,
                                        "agent_id": e.agent_id,
                                        "action": e.action,
                                        "credential": e.credential,
                                        "outcome": e.outcome,
                                        "details": e.details,
                                    })
                                })
                                .collect::<Vec<_>>(),
                        )
                        .unwrap_or_default(),
                    };

                    match output {
                        Some(path) => {
                            fs::write(&path, &content).expect("write output file");
                            eprintln!("Exported {} entries to {}", entries.len(), path.display());
                        }
                        None => println!("{content}"),
                    }
                }
                AuditAction::Explain { id } => {
                    let entry_id = match id.parse::<i64>() {
                        Ok(id) => id,
                        Err(_) => {
                            eprintln!("Event {} not found", id);
                            process::exit(1);
                        }
                    };

                    match run_audit_explain(&config, entry_id) {
                        Ok((_, explain)) => {
                            let e = &explain.event;
                            println!("EVENT {}", e.id);
                            println!("  Timestamp:  {}", e.timestamp);
                            println!("  Agent:      {}", e.agent_id.as_deref().unwrap_or("-"));
                            println!("  Action:     {}", e.action);
                            println!("  Credential: {}", e.credential.as_deref().unwrap_or("-"));
                            println!("  Outcome:    {}", e.outcome);
                            if let Some(ref details) = e.details {
                                println!("  Details:    {}", details);
                            }
                            println!();

                            match explain.current_grant {
                                Some(grant) => {
                                    println!("GRANT {}", grant.id);
                                    println!("  Scope:      {}", grant.scope);
                                    println!("  Created:    {}", grant.created_at);
                                    println!(
                                        "  Expires:    {}",
                                        grant.expires_at.as_deref().unwrap_or("never")
                                    );
                                    println!("  Status:     {}", grant.status);
                                }
                                None => println!("GRANT: no active grant found"),
                            }
                            println!();

                            println!("POLICY");
                            println!("  Decision:   {:?}", explain.current_policy.requirement);
                            println!("  Risk:       {:?}", explain.current_policy.risk);
                            println!("  Tier:       {:?}", explain.current_policy.tier);
                            println!(
                                "  Rule:       {}",
                                explain
                                    .current_policy
                                    .matched_rule
                                    .as_deref()
                                    .unwrap_or("(default)")
                            );
                            println!();
                            println!("NOTE");
                            println!("  {}", explain.note);
                        }
                        Err(e) => {
                            if e.to_string().contains("not found") {
                                eprintln!("Event {} not found", id);
                            } else {
                                eprintln!("error: {e}");
                            }
                            process::exit(1);
                        }
                    }
                }
                AuditAction::Query {
                    since,
                    actor,
                    kind,
                    grant_id,
                    resource,
                    json,
                    limit,
                } => {
                    // audit_actions_migrated_to_rpc: routes through the
                    // daemon's `receipt_query` JSON-RPC rather than opening
                    // the store directly. The daemon side parses ReceiptFilter
                    // fields from the params object and returns a JSON array
                    // of ReceiptRow-shaped objects.

                    // Validate `--since` up front — surface a clean usage
                    // error rather than handing a malformed string to the
                    // RPC params.
                    let since_iso = match since.as_deref() {
                        None => None,
                        Some(s) => match parse_since(s) {
                            Some(dt) => Some(dt.to_rfc3339()),
                            None => {
                                eprintln!(
                                    "error: invalid --since '{s}' \
                                     (expected ISO-8601 like 2026-04-01T00:00:00Z \
                                     or relative duration like 24h / 7d)"
                                );
                                process::exit(1);
                            }
                        },
                    };
                    let filter = ember_daemon::infra::receipt::ReceiptFilter {
                        persona_id: actor,
                        kind,
                        grant_id,
                        resource,
                        since_iso,
                        limit,
                        ..Default::default()
                    };
                    let (_, rows) = match run_audit_receipt_query(&config, &filter) {
                        Ok(rows) => rows,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };

                    // `--json` (subcommand-local) and the global `--json`
                    // flag both opt into raw machine output; either is OK.
                    if json || cli.json {
                        match serde_json::to_string_pretty(&rows) {
                            Ok(s) => println!("{s}"),
                            Err(e) => {
                                eprintln!("error: serialize rows: {e}");
                                process::exit(1);
                            }
                        }
                    } else {
                        println!("{}", render_receipt_query_text(&rows));
                    }
                }
                AuditAction::Summary {
                    since,
                    workflow,
                    persona,
                    format,
                    json,
                } => {
                    let since_iso = match since.as_deref() {
                        None => None,
                        Some(s) => match parse_since(s) {
                            Some(dt) => Some(dt.to_rfc3339()),
                            None => {
                                eprintln!(
                                    "error: invalid --since '{s}' \
                                     (expected ISO-8601 like 2026-04-01T00:00:00Z \
                                     or relative duration like 24h / 7d)"
                                );
                                process::exit(1);
                            }
                        },
                    };
                    let filter = emberlink_cli::audit::summary::SummaryFilter {
                        since_iso,
                        delegation: workflow,
                        persona,
                    };
                    let db_path = config.data_dir.join("daemon.db");
                    let summary =
                        match emberlink_cli::audit::summary::run_audit_summary(&db_path, &filter) {
                            Ok(summary) => summary,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                    if json || cli.json || format == "json" {
                        match emberlink_cli::audit::summary::format_summary_json(&summary, true) {
                            Ok(s) => println!("{s}"),
                            Err(e) => {
                                eprintln!("error: serialize summary: {e}");
                                process::exit(1);
                            }
                        }
                    } else {
                        print!(
                            "{}",
                            emberlink_cli::audit::summary::format_summary_pretty(&summary)
                        );
                    }
                }
                // Chain verify via
                // daemon socket. Routes through `audit_verify` so the
                // verdict is the daemon's authoritative answer (same
                // path startup verify uses). Exit code: 0 on Ok, 2 on
                // Break (a tampered chain is a distinct signal from
                // operational error), 1 on transport / RPC failure.
                //
                // audit_actions_migrated_to_rpc: routes through the
                // daemon's `audit_verify` JSON-RPC (via
                // `emberlink_cli::audit::verify`); no open_store needed.
                AuditAction::Verify {
                    tail,
                    since,
                    import,
                    trust_roots,
                    operator_pubkey,
                } => {
                    if let Some(path) = import {
                        match emberlink_cli::audit::import_verify::verify_import_file(
                            &path,
                            &trust_roots,
                            operator_pubkey.as_deref(),
                        ) {
                            Ok(report) => {
                                if cli.json {
                                    println!(
                                        "{}",
                                        emberlink_cli::audit::import_verify::format_report_json(
                                            &report
                                        )
                                    );
                                } else {
                                    print!(
                                        "{}",
                                        emberlink_cli::audit::import_verify::format_report_human(
                                            &report
                                        )
                                    );
                                }
                                if !report.ok {
                                    process::exit(2);
                                }
                            }
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                        return;
                    }

                    if let Some(window) = since.as_deref() {
                        if emberlink_cli::audit::query::parse_since(window).is_none() {
                            eprintln!(
                                "error: invalid --since value {window:?}; expected an ISO-8601 timestamp or relative duration such as 1d, 7d, 24h"
                            );
                            process::exit(2);
                        }
                        // The daemon verifier currently supports full-chain
                        // and tail walks. Full-chain verification is stricter
                        // than any documented v0.3 --since window.
                    }

                    let socket_path = config.socket_dir.join("daemon.sock");
                    match emberlink_cli::audit::verify::run_audit_verify_cli(&socket_path, tail) {
                        Ok(verdict) => {
                            if cli.json {
                                let v = emberlink_cli::audit::verify::format_verdict_json(&verdict);
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                );
                            } else {
                                print!(
                                    "{}",
                                    emberlink_cli::audit::verify::format_verdict_human(&verdict)
                                );
                            }
                            if matches!(
                                verdict,
                                emberlink_cli::audit::verify::VerifyVerdict::Break { .. }
                            ) {
                                process::exit(2);
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                AuditAction::Usage => {
                    // Read prod (~/.ember/audit/) and
                    // dev (~/.ember-dev/audit/) audit roots; print the
                    // per-daemon + grand-total footprint with 80% / 100%
                    // ceiling flags. Exits 1 in warn range, 2 at/above
                    // 100% so operators can gate scripts on the verdict.
                    let home = match std::env::var("HOME") {
                        Ok(h) => PathBuf::from(h),
                        Err(_) => {
                            eprintln!("error: $HOME not set; cannot locate audit roots");
                            process::exit(1);
                        }
                    };
                    let code = emberlink_cli::audit::usage::run(&home);
                    if code != 0 {
                        process::exit(code);
                    }
                }
                // PR #5684 companion — offline helpers around the
                // `audit_repair_chain` operator co-sign. Pure CLI-side: no
                // daemon roundtrip. Gives the operator the canonical bytes
                // to sign and an independent verifier for the resulting
                // RepairIntent.
                AuditAction::CanonicalRepairIntent {
                    from_row,
                    tip_hash,
                    daemon_fingerprint,
                } => {
                    if let Err(e) = run_audit_canonical_repair_intent(
                        from_row,
                        &tip_hash,
                        &daemon_fingerprint,
                        cli.json,
                    ) {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                AuditAction::VerifyRepairIntent {
                    intent,
                    presence_pubkeys,
                } => {
                    if let Err(e) =
                        run_audit_verify_repair_intent(&intent, &presence_pubkeys, cli.json)
                    {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                }
                // PR #5684 + #5694 + #5700 capstone — the operator-CLI
                // driver for the `audit_repair_chain` daemon RPC.
                // Retires the runbook's "submit by hand" step. Routes
                // through `emberlink_cli::audit::repair_chain`; the
                // daemon-side `verify_repair_intent_signature` remains
                // the trust source.
                AuditAction::RepairChain {
                    from_row,
                    tip_hash,
                    daemon_fingerprint,
                    operator_pubkey,
                    operator_signature_hex,
                    repair_kind,
                } => {
                    let socket_path = config.socket_dir.join("daemon.sock");
                    let request = emberlink_cli::audit::repair_chain::RepairChainRequest {
                        from_row_id: from_row,
                        repair_kind,
                        operator_signature_hex,
                        operator_pubkey,
                        current_chain_tip_hash: tip_hash,
                        daemon_identity_root_fingerprint: daemon_fingerprint,
                    };
                    match emberlink_cli::audit::repair_chain::run_audit_repair_chain_cli(
                        &socket_path,
                        &request,
                    ) {
                        Ok(outcome) => {
                            if cli.json {
                                let v = emberlink_cli::audit::repair_chain::format_outcome_json(
                                    &outcome,
                                );
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                );
                            } else {
                                print!(
                                    "{}",
                                    emberlink_cli::audit::repair_chain::format_outcome_human(
                                        &outcome
                                    )
                                );
                            }
                            // Distinct exit codes per outcome variant so
                            // scripts can branch — Ok is 0, the two
                            // incomplete-repair states are 3 (daemon
                            // crashed mid-repair; needs operator
                            // re-resolution per ADR 174 v2 §6).
                            match outcome {
                                emberlink_cli::audit::repair_chain::RepairChainOutcome::Ok {
                                    ..
                                } => {}
                                _ => process::exit(3),
                            }
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Receipt { action } => {
            // [open-store-audit] READ-ONLY: Commands::Receipt.
            //   List   → `receipt.list` when a daemon socket is live.
            //   Show   → `receipt.get` when a daemon socket is live.
            //   Export → markdown uses `get_receipt`; JSON uses `receipt.get`
            //            so v2 ReceiptEnvelope rows round-trip as artifacts.
            //   Tree   → `receipt_tree` when a daemon socket is live.
            //   Verify → `receipt.get` only for the id-mode path; file/tree/
            //            materialization modes stay daemon-free.
            // Local direct fallback remains only for no-daemon/dev paths.
            match action {
                ReceiptAction::List {
                    persona,
                    json: list_json,
                } => {
                    let (_, receipts) =
                        match run_receipt_list_artifacts(&config, persona.as_deref()) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                    if cli.json || list_json {
                        // ember receipt list --json emits raw persisted artifacts.
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&receipts).unwrap_or_default()
                        );
                    } else {
                        println!("{}", render_receipt_artifact_list_text(&receipts));
                    }
                }
                ReceiptAction::Show { id, format, raw } => {
                    let (_, artifact) = match run_receipt_get_artifact(&config, &id) {
                        Ok(artifact) => artifact,
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    };
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&artifact).unwrap_or_default()
                        );
                    } else if let Ok(r) = serde_json::from_value::<
                        core_grant_types::grant_receipt::GrantReceipt,
                    >(artifact.clone())
                    {
                        if format == "md" {
                            println!(
                                "{}",
                                emberlink_cli::receipt::render_receipt_markdown(&r, raw)
                            );
                        } else {
                            print_receipt_summary(&r);
                        }
                    } else {
                        println!("{}", render_receipt_artifact_summary_text(&artifact));
                    }
                }
                ReceiptAction::Export {
                    id,
                    latest,
                    format,
                    raw,
                } => {
                    if format == "md" {
                        let target_id =
                            match resolve_receipt_export_target(&config, id.as_deref(), latest) {
                                Ok(id) => id,
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    process::exit(1);
                                }
                            };
                        let (_, r) = match run_receipt_get(&config, &target_id) {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                        println!(
                            "{}",
                            emberlink_cli::receipt::render_receipt_markdown(&r, raw)
                        );
                    } else {
                        let target_id = match resolve_receipt_artifact_export_target(
                            &config,
                            id.as_deref(),
                            latest,
                        ) {
                            Ok(id) => id,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                        let (_, artifact) = match run_receipt_get_artifact(&config, &target_id) {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                        match serde_json::to_string_pretty(&artifact) {
                            Ok(s) => println!("{s}"),
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        }
                    }
                }
                ReceiptAction::Verify {
                    id,
                    file,
                    pubkey,
                    materialization,
                    events,
                    tree,
                    offline,
                } => {
                    // --tree mode: load a tree-export JSON and run all
                    // signature checks offline. Beat 8 demo close. The
                    // verify path does not touch the daemon socket — the
                    // trust anchor is embedded in the export file.
                    if let Some(tree_path) = tree {
                        let tree_export = match emberlink_cli::receipt::read_tree_export(&tree_path)
                        {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                        match emberlink_cli::receipt::verify_tree_offline(&tree_export) {
                            Ok(outcome) => {
                                print!(
                                    "{}",
                                    emberlink_cli::receipt::format_verify_outcome(&outcome)
                                );
                                return;
                            }
                            Err(e) => {
                                eprintln!("Tree verification FAILED: {e}");
                                process::exit(2);
                            }
                        }
                    }
                    // --materialization mode: chain-integrity walk over
                    // sub-Receipts in events.jsonl. Distinct from the
                    // signature-verification path below — rollup chains are
                    // not signed end-to-end (each sub-Receipt is signed
                    // individually); the integrity check is structural.
                    if let Some(mid) = materialization {
                        let events_path =
                            events.unwrap_or_else(|| config.data_dir.join("events.jsonl"));
                        let receipts =
                            match emberlink_cli::receipt::rollup::read_receipts_from_jsonl(
                                &events_path,
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    process::exit(1);
                                }
                            };
                        match emberlink_cli::receipt::verify_chain(&receipts, &mid) {
                            Ok(rollup) => {
                                println!(
                                    "Verified: chain {} ({} sub-receipts, outcome={:?})",
                                    rollup.materialization_id, rollup.receipt_count, rollup.outcome
                                );
                                return;
                            }
                            Err(e) => {
                                eprintln!("Chain verification FAILED: {e}");
                                process::exit(2);
                            }
                        }
                    }
                    if id.is_some() && file.is_some() {
                        // clap conflicts_with should prevent reaching here.
                        eprintln!("error: pass either <id> or --file <PATH>, not both");
                        process::exit(2);
                    }
                    if id.is_none() && file.is_none() {
                        eprintln!(
                            "error: pass either a receipt <id>, --file <PATH>, or --materialization <ID>"
                        );
                        process::exit(2);
                    }
                    let (artifact_source, raw_value) =
                        match load_receipt_verify_artifact(&config, id, file) {
                            Ok(value) => value,
                            Err(e) => {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                        };
                    if receipt_artifact_version_number(&raw_value) == Some(2) {
                        // v2 receipt (ADR 118 ReceiptEnvelope).
                        let envelope = match serde_json::from_value::<
                            core_events::receipt::envelope::ReceiptEnvelope,
                        >(raw_value)
                        {
                            Ok(e) => e,
                            Err(e) => {
                                eprintln!("error: not a valid v2 Receipt envelope: {e}");
                                process::exit(1);
                            }
                        };
                        if pubkey.is_none()
                            && artifact_source == ReceiptVerifyArtifactSource::DaemonId
                        {
                            match run_receipt_verify_v2_trust_explain(&config, &envelope) {
                                Ok(resp) if resp.verdict == "verified" => {
                                    println!("Verified: receipt {}", envelope.receipt_id);
                                    println!("  Daemon root: {}", envelope.daemon_root_id);
                                    if let Some(root) = resp.trust_root {
                                        println!(
                                            "  Trust root: {} ({})",
                                            root.fingerprint_hex, root.source
                                        );
                                    }
                                    println!("  Kind: {}", envelope.kind);
                                    println!("  Version: v{}", envelope.version.0);
                                    println!("  Chain: {}", resp.chain);
                                    return;
                                }
                                Ok(resp) => {
                                    eprintln!("Verification FAILED: {}", resp.verdict);
                                    eprintln!("  Chain: {}", resp.chain);
                                    process::exit(2);
                                }
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    process::exit(1);
                                }
                            }
                        }
                        // Explicit --pubkey and file-mode verification stay
                        // local/offline-compatible.
                        // Resolve trust anchor: --pubkey <hex> or daemon identity.
                        // v2 PublicKey has "ed25519:" prefix; pubkey arg is bare hex.
                        let pubkey_hex = match pubkey.as_deref() {
                            Some(p) => p.to_string(),
                            None => {
                                let key_path = ember_daemon::infra::receipt::identity_key_path(
                                    &config.data_dir,
                                );
                                match ember_daemon::infra::receipt::DaemonPersona::load_or_create(
                                    &config.data_dir,
                                ) {
                                    Ok(id) => id.pubkey_hex(),
                                    Err(e) => {
                                        eprintln!(
                                            "error: could not load trust anchor from {}: {e}",
                                            key_path.display()
                                        );
                                        process::exit(1);
                                    }
                                }
                            }
                        };
                        let pk = core_crypto::PublicKey(format!("ed25519:{pubkey_hex}"));
                        match core_events::receipt::sign::verify_receipt_v2(
                            &envelope,
                            &pk,
                            &core_crypto::Ed25519Verifier,
                        ) {
                            Ok(()) => {
                                println!("Verified: receipt {}", envelope.receipt_id);
                                println!("  Signer pubkey: {pubkey_hex}");
                                println!("  Kind: {}", envelope.kind);
                                println!("  Version: v{}", envelope.version.0);
                                return;
                            }
                            Err(e) if offline => {
                                // ember_receipt_verify_walks_rotation_chain —
                                // in `--offline` mode, the trust anchor may
                                // be a previous-epoch daemon identity. Load
                                // identity.rotation_witness Receipts from
                                // the local store and delegate to Slice E3's
                                // chain-walker (verify_receipt_v2_with_rotation_chain).
                                // The first verify_receipt_v2 attempt above
                                // already confirmed the anchor doesn't sign
                                // the receipt directly — only fall through
                                // to the chain walker on that legitimate
                                // signature-mismatch path.
                                let direct_signature_mismatch = matches!(
                                    e,
                                    core_events::receipt::sign::SignError::InvalidSignature
                                );
                                if !direct_signature_mismatch {
                                    eprintln!("Verification FAILED: {e}");
                                    process::exit(2);
                                }
                                let events_path = events
                                    .clone()
                                    .unwrap_or_else(|| config.data_dir.join("events.jsonl"));
                                let chain = match emberlink_cli::receipt::list_witnesses_ascending(
                                    &events_path,
                                ) {
                                    Ok(c) => c,
                                    Err(load_err) => {
                                        eprintln!("Verification FAILED: {load_err}");
                                        process::exit(1);
                                    }
                                };
                                match core_events::receipt::sign::verify_receipt_v2_with_rotation_chain(
                                    &envelope,
                                    &[pk],
                                    &chain,
                                    &core_crypto::Ed25519Verifier,
                                ) {
                                    Ok(()) => {
                                        println!(
                                            "{}",
                                            emberlink_cli::receipt::format_chain_success(&envelope, &chain)
                                        );
                                        return;
                                    }
                                    Err(chain_err) => {
                                        eprintln!(
                                            "{}",
                                            emberlink_cli::receipt::format_chain_failure(&chain_err, &chain)
                                        );
                                        process::exit(2);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Verification FAILED: {e}");
                                process::exit(2);
                            }
                        }
                    }
                    // v1 receipt (or no version field): existing GrantReceipt path.
                    let r = match serde_json::from_value::<
                        core_grant_types::grant_receipt::GrantReceipt,
                    >(raw_value)
                    {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("error: not a valid Grant Receipt JSON: {e}");
                            process::exit(1);
                        }
                    };
                    let expected_pubkey = match pubkey {
                        Some(p) => p,
                        None => {
                            // Read pubkey from the identity file.
                            let path =
                                ember_daemon::infra::receipt::identity_key_path(&config.data_dir);
                            match ember_daemon::infra::receipt::DaemonPersona::load_or_create(
                                &config.data_dir,
                            ) {
                                Ok(id) => id.pubkey_hex(),
                                Err(e) => {
                                    eprintln!(
                                        "error: could not load trust anchor from {}: {e}",
                                        path.display()
                                    );
                                    process::exit(1);
                                }
                            }
                        }
                    };
                    match ember_daemon::infra::receipt::verify_receipt(&r, &expected_pubkey) {
                        Ok(()) => {
                            println!("Verified: receipt {}", r.id);
                            println!("  Signer pubkey: {}", expected_pubkey);
                            println!("  Hash: {}", r.evidence.hash);
                            println!("  Canonical version: v{}", r.evidence.canonical_version);
                        }
                        Err(e) => {
                            eprintln!("Verification FAILED: {e}");
                            process::exit(2);
                        }
                    }
                }
                ReceiptAction::Rollup {
                    since,
                    materialization,
                    incomplete_only,
                    events,
                } => {
                    let events_path =
                        events.unwrap_or_else(|| config.data_dir.join("events.jsonl"));
                    let filters = emberlink_cli::receipt::RollupFilters {
                        since: Some(since),
                        materialization,
                        incomplete_only,
                    };
                    match emberlink_cli::receipt::rollup_command(&events_path, &filters, cli.json) {
                        Ok(out) => print!("{out}"),
                        Err(e) => {
                            eprintln!("error: {e}");
                            process::exit(1);
                        }
                    }
                }
                ReceiptAction::Tree { grant, export } => match run_receipt_tree(&config, &grant) {
                    Ok((_, tree)) => {
                        print!("{}", emberlink_cli::receipt::render_tree_ascii(&tree));
                        if let Some(path) = export.as_deref() {
                            if let Err(e) =
                                emberlink_cli::receipt::tree::write_tree_export(&tree, path)
                            {
                                eprintln!("error: {e}");
                                process::exit(1);
                            }
                            println!("Exported tree to {}", path.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(1);
                    }
                },
            }
        }

        Commands::Broker { action } => {
            // Resolve the daemon socket path from the same config that
            // every other socket-talking subcommand uses.
            let socket_path = config.socket_dir.join("daemon.sock");
            let opts = emberlink_cli::broker::GlobalOpts { socket_path };
            if let Err(e) = emberlink_cli::broker::broker_command(action, opts) {
                eprintln!("error: {e}");
                process::exit(e.exit_code());
            }
        }

        Commands::Bind { action } => {
            // Admin path for
            // daemon-controlled credential bindings. Same socket
            // resolution as `Broker` so the two surfaces share the
            // operator-facing daemon-socket invariant.
            let socket_path = config.socket_dir.join("daemon.sock");
            let opts = emberlink_cli::bind::GlobalOpts { socket_path };
            if let Err(e) = emberlink_cli::bind::cmd_bind(action, opts) {
                eprintln!("error: {e}");
                process::exit(e.exit_code());
            }
        }

        Commands::Policy { action } => {
            let policy = ember_daemon::trust::policy::PolicyEngine::default();
            match action {
                PolicyAction::Show => {
                    println!("Policy rules (first match wins):");
                    println!();
                    let (h1, h2, h3) = ("ACTION", "RISK", "DECISION");
                    println!("  {h1:25} {h2:10} {h3}");
                    println!("  {}", "-".repeat(55));
                    for (action, risk, decision) in [
                        ("git.push.main", "critical", "deny"),
                        ("git.push.*", "medium", "auto_approve"),
                        ("deploy.production", "critical", "require_approval"),
                        ("deploy.staging", "medium", "auto_approve"),
                        ("credential.access", "high", "require_approval"),
                        ("*", "medium", "require_approval"),
                    ] {
                        println!("  {action:25} {risk:10} {decision}");
                    }
                }
                PolicyAction::Eval { action: act } => {
                    let eval = policy.evaluate(&act);
                    let risk = format!("{:?}", eval.risk).to_lowercase();
                    let decision = format!("{:?}", eval.requirement);
                    let rule = eval.matched_rule.as_deref().unwrap_or("(default)");
                    println!("Action:   {act}");
                    println!("Decision: {decision}");
                    println!("Risk:     {risk}");
                    println!("Rule:     {rule}");
                }
            }
        }

        Commands::Status {
            troubleshoot,
            session,
            session_id,
            all,
        } => {
            // `ember status --session`
            // routes through the dedicated attestation surface so an operator can
            // confirm the calling shell IS brokered without log-tailing. Anchor:
            // `dev_prod_parity_attestation_surface_landed`.
            if session {
                let target = emberlink_cli::status_session::resolve_target(session_id, all);
                let env_snapshot = emberlink_cli::status_session::read_calling_shell_env();
                let socket_path = config.socket_dir.join("daemon.sock");
                let trust = emberlink_cli::trust::list::fetch_trust_list(&socket_path).ok();
                let summary = run_status_summary(&config, true).ok().map(|(_, _, s)| s);
                let attestation = emberlink_cli::status_session::build_attestation(
                    &target,
                    env_snapshot.daemon_socket.clone(),
                    env_snapshot.persona.clone(),
                    env_snapshot.flavor_value.as_deref(),
                    env_snapshot.daemon_socket.as_deref(),
                    trust.as_ref(),
                    summary.as_ref(),
                );
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&emberlink_cli::status_session::render_json(
                            &attestation
                        ))
                        .unwrap()
                    );
                } else {
                    println!(
                        "{}",
                        emberlink_cli::status_session::render_human(&attestation)
                    );
                }
                return;
            }
            let overview = match collect_status_overview(&config) {
                Ok(overview) => overview,
                Err(e) => {
                    let ember_cmd = ember_command_prefix_for_current_launcher();
                    let rewritten = rewrite_status_and_daemon_install_mentions(&e, &ember_cmd);
                    if cli.json {
                        eprintln!(
                            "{}",
                            render_actionable_error(
                                "E-STATUS-COLLECT",
                                "Status could not inspect the current machine posture",
                                &rewritten,
                                &[format!(
                                    "Run `{ember_cmd} doctor` to open the deeper diagnosis lane."
                                )],
                                &[format!("{ember_cmd} explain status")],
                            )
                        );
                    } else {
                        eprintln!(
                            "{}",
                            render_status_collection_failure_text(&rewritten, &ember_cmd)
                        );
                    }
                    process::exit(1);
                }
            };

            if cli.json {
                if troubleshoot {
                    eprintln!(
                        "{}",
                        render_actionable_error(
                            "E-STATUS-JSON-TROUBLESHOOT-CONFLICT",
                            "`ember status --json --troubleshoot` is not supported",
                            "The machine-readable contract and the human troubleshoot appendix are separate surfaces.",
                            &[format!(
                                "Run `{}`",
                                ember_command_prefix_for_current_launcher() + " status --json"
                            )],
                            &[
                                "ember doctor".to_string(),
                                "ember explain error E-STATUS-JSON-TROUBLESHOOT-CONFLICT"
                                    .to_string(),
                            ],
                        )
                    );
                    process::exit(2);
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status_json_value(&overview)).unwrap()
                );
            } else {
                println!("{}", render_status_overview_text(&overview));
                // F8: the read-only per-lane onboarding checklist beneath the
                // focused card — every lane's ✓/⚠/✗ at a glance plus the one
                // next action (proposal: "`ember status` is the read-only
                // per-lane checklist").
                println!();
                println!("{}", render_status_lane_checklist(&overview));
                if troubleshoot {
                    println!();
                    println!(
                        "{}",
                        render_status_troubleshoot_text(
                            &overview.banner,
                            &overview.summary,
                            overview.dispatch,
                            overview.github_status.as_ref(),
                            overview.ember_initialized,
                            overview.launcher_issue.as_ref(),
                            overview.current_launcher_lane.as_ref(),
                            overview.managed_daemon_issue.as_ref(),
                            overview.delegation_template_issue.as_ref(),
                        )
                    );
                }
                let action = primary_status_action(&overview);
                exit_on_prompted_action(maybe_prompt_run_primary_action(
                    Some(&action),
                    false,
                    cli.no_input,
                    cli.yes,
                ));
            }
        }

        Commands::Doctor => {
            let overview = match collect_status_overview(&config) {
                Ok(overview) => overview,
                Err(e) => {
                    let ember_cmd = ember_command_prefix_for_current_launcher();
                    let rewritten = rewrite_status_and_daemon_install_mentions(&e, &ember_cmd);
                    eprintln!(
                        "{}",
                        render_actionable_error(
                            "E-DOCTOR-STATUS-COLLECT",
                            "Doctor could not inspect the current machine posture",
                            &rewritten,
                            &[format!(
                                "Run `{ember_cmd} status` after repairing the current machine posture."
                            )],
                            &[format!("{ember_cmd} explain status")],
                        )
                    );
                    eprintln!();
                    eprintln!("{}", diagnose_daemon_socket(&config));
                    process::exit(1);
                }
            };
            if cli.json {
                let mut payload = status_json_value(&overview);
                payload["mode"] = serde_json::json!("doctor");
                println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            } else {
                println!("{}", render_doctor_text(&overview));
                let action = primary_status_action(&overview);
                exit_on_prompted_action(maybe_prompt_run_primary_action(
                    Some(&action),
                    false,
                    cli.no_input,
                    cli.yes,
                ));
            }
        }

        Commands::Explain { topic } => match render_explain_topic(&topic) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("{err}");
                process::exit(2);
            }
        },

        Commands::Config { action } => match action {
            ConfigAction::Show => {
                println!("Socket dir:  {}", config.socket_dir.display());
                println!("Data dir:    {}", config.data_dir.display());
                println!("PID file:    {}", config.pid_file.display());
                println!("Log level:   {}", config.log_level.as_filter_str());
                println!(
                    "Config file: {}",
                    effective_config_path(cli.config.as_ref()).display()
                );
            }
            ConfigAction::Path => {
                println!("{}", effective_config_path(cli.config.as_ref()).display());
            }
        },

        Commands::Github { action } => match action {
            GithubAction::Status => match run_github_provider_status(&config) {
                Ok(status) => {
                    let launcher_issue = detect_default_installed_launcher_issue();
                    if cli.json {
                        let payload = github_status_json_payload(&status, launcher_issue.as_ref());
                        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
                    } else {
                        let ember_cmd = ember_command_prefix_for_current_launcher();
                        print!(
                            "{}",
                            render_github_status_text_with_ember_command(
                                &status,
                                launcher_issue.as_ref(),
                                &ember_cmd,
                            )
                        );
                    }
                }
                Err(e) => {
                    let launcher_issue = detect_default_installed_launcher_issue();
                    let ember_cmd = ember_command_prefix_for_current_launcher();
                    eprintln!(
                        "{}",
                        render_github_status_error_guidance(
                            &core_types::ValidationError::new(
                                rewrite_status_and_daemon_install_mentions(
                                    &e.to_string(),
                                    &ember_cmd,
                                ),
                            ),
                            launcher_issue.as_ref(),
                            &ember_cmd,
                        )
                    );
                    process::exit(1);
                }
            },
            GithubAction::Setup(args) => {
                if let Err(exit_code) = run_github_registration_flow(
                    &config,
                    &args,
                    io::stdin().is_terminal() && !cli.no_input,
                    cli.json,
                ) {
                    process::exit(exit_code);
                }
            }
            GithubAction::App { action } => match action {
                GithubAppAction::InstallUrl => {
                    let url = emberlink_cli::onboarding::github_app::print_install_url();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "install_url": url,
                            }))
                            .unwrap()
                        );
                    } else {
                        println!("{url}");
                    }
                }
                GithubAppAction::Show => {
                    if let Some(note) = render_github_app_manifest_launcher_note(
                        &ember_command_prefix_for_current_launcher(),
                    ) {
                        print!("{note}");
                    }
                    emberlink_cli::onboarding::github_app::show_manifest();
                }
                GithubAppAction::Register(args) => {
                    if let Err(exit_code) = run_github_registration_flow(
                        &config,
                        &github_setup_args_from_app_register(&args),
                        io::stdin().is_terminal() && !cli.no_input,
                        cli.json,
                    ) {
                        process::exit(exit_code);
                    }
                }
            },
        },

        Commands::Trust { action } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            let exit_code = match action {
                TrustAction::List => emberlink_cli::trust::list::run(&socket_path, cli.json),
                TrustAction::Show { root_id } => {
                    emberlink_cli::trust::show::run(&socket_path, &root_id, cli.json)
                }
                TrustAction::Explain {
                    artifact_path,
                    sidecar,
                    kind,
                } => emberlink_cli::trust::explain::run(
                    &socket_path,
                    &kind,
                    &artifact_path,
                    sidecar.as_deref(),
                    cli.json,
                ),
                TrustAction::Backup {
                    to,
                    force,
                    no_biometric,
                } => {
                    // Resolve hostname from `$HOSTNAME` / `$HOST` with
                    // an "unknown" fallback (mirrors internal-automation's
                    // event-emit helper — daemons under systemd/launchd
                    // commonly don't export `HOSTNAME`, and the audit
                    // surface tolerates the fallback).
                    let hostname = std::env::var("HOSTNAME")
                        .or_else(|_| std::env::var("HOST"))
                        .unwrap_or_else(|_| "unknown".to_string());
                    // Daemon-mode label is best-effort: the local CLI
                    // doesn't query the daemon for posture before
                    // sealing the backup. The metadata is rendered to
                    // the operator at restore-time for *context*, not
                    // enforcement, so an "unknown" or label mismatch
                    // never blocks the flow. Follow-up slice can wire
                    // the live `trust.list` `dev_mode_active` field.
                    let daemon_mode = std::env::var("EMBER_DAEMON_MODE")
                        .unwrap_or_else(|_| "unknown".to_string());
                    emberlink_cli::trust::backup::run(
                        &to,
                        force,
                        no_biometric,
                        &daemon_mode,
                        &hostname,
                    )
                }
                TrustAction::Restore { from, no_biometric } => {
                    emberlink_cli::trust::restore::run(&from, no_biometric)
                }
                TrustAction::Rotate {
                    target,
                    reason,
                    grace_window_secs,
                    no_biometric,
                    manifest_path,
                } => {
                    // identity_root_persona_cli_unified_rotate_landed
                    // (ADR 200 2026-06-15 amendment + ADR 162
                    // §Component 3 amended). The CLI accepts a
                    // Principal id or label; resolution happens inside
                    // trust::rotate so the dispatch arm stays a
                    // single delta. PR #6019's `dev-identity-root` is
                    // accepted as a transitional alias with a
                    // migration hint, not as target vocabulary.
                    emberlink_cli::trust::rotate::run(
                        &socket_path,
                        &target,
                        manifest_path.as_deref(),
                        reason,
                        grace_window_secs,
                        no_biometric,
                    )
                }
            };
            if exit_code != 0 {
                process::exit(exit_code);
            }
        }

        Commands::Version => {
            if cli.json {
                let v = serde_json::json!({
                    "name": "ember",
                    "version": env!("CARGO_PKG_VERSION"),
                    "git_sha": env!("EMBERLINK_GIT_SHA"),
                    "build_timestamp": env!("EMBERLINK_BUILD_TIMESTAMP"),
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!("{}", print_version());
            }
        }

        Commands::Cluster { action } => {
            cmd_cluster(action, &config, cli.json);
        }

        Commands::ClaudeCode {
            dev,
            prod: _,
            host,
            isolated,
            sandbox,
            strict,
            delegated,
            attach_runtime_persona_id,
            fork_runtime,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::claude_code_alias_request_with_sandvault(
                dev,
                host,
                isolated,
                matches!(sandbox, Some(SandboxRuntime::Sandvault)),
                strict,
                delegated,
                attach_runtime_persona_id,
                fork_runtime,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    let (rendered, exit_code) =
                        render_launcher_actionable_error("claude", &e.to_string());
                    eprintln!("{rendered}");
                    process::exit(exit_code);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                let (rendered, exit_code) =
                    render_launcher_actionable_error("claude", &e.to_string());
                eprintln!("{rendered}");
                process::exit(exit_code);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Codex {
            dev,
            prod: _,
            host,
            isolated,
            sandbox,
            strict,
            delegated,
            attach_runtime_persona_id,
            fork_runtime,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::codex_alias_request_with_sandvault(
                dev,
                host,
                isolated,
                matches!(sandbox, Some(SandboxRuntime::Sandvault)),
                strict,
                delegated,
                attach_runtime_persona_id,
                fork_runtime,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    let (rendered, exit_code) =
                        render_launcher_actionable_error("codex", &e.to_string());
                    eprintln!("{rendered}");
                    process::exit(exit_code);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                let (rendered, exit_code) =
                    render_launcher_actionable_error("codex", &e.to_string());
                eprintln!("{rendered}");
                process::exit(exit_code);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Cursor {
            dev,
            prod: _,
            host,
            isolated,
            sandbox,
            strict,
            delegated,
            attach_runtime_persona_id,
            fork_runtime,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::cursor_alias_request_with_sandvault(
                dev,
                host,
                isolated,
                matches!(sandbox, Some(SandboxRuntime::Sandvault)),
                strict,
                delegated,
                attach_runtime_persona_id,
                fork_runtime,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    let (rendered, exit_code) =
                        render_launcher_actionable_error("cursor", &e.to_string());
                    eprintln!("{rendered}");
                    process::exit(exit_code);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                let (rendered, exit_code) =
                    render_launcher_actionable_error("cursor", &e.to_string());
                eprintln!("{rendered}");
                process::exit(exit_code);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Gemini {
            dev,
            prod: _,
            host,
            isolated,
            sandbox,
            strict,
            delegated,
            attach_runtime_persona_id,
            fork_runtime,
            backend,
            preset,
            worktree,
            branch,
            purpose,
            args,
        } => {
            let request = match emberlink_cli::session::gemini_alias_request(
                dev,
                host,
                isolated,
                matches!(sandbox, Some(SandboxRuntime::Sandvault)),
                strict,
                delegated,
                attach_runtime_persona_id,
                fork_runtime,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                &args,
            ) {
                Ok(request) => request,
                Err(e) => {
                    let (rendered, exit_code) =
                        render_launcher_actionable_error("gemini", &e.to_string());
                    eprintln!("{rendered}");
                    process::exit(exit_code);
                }
            };
            if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                let (rendered, exit_code) =
                    render_launcher_actionable_error("gemini", &e.to_string());
                eprintln!("{rendered}");
                process::exit(exit_code);
            }
            unreachable!("session open either exec-replaces or returns Err");
        }

        Commands::Demo { action } => match action {
            DemoAction::Wedge { teardown } => {
                if let Err(e) = emberlink_cli::demo::wedge::cmd_demo_wedge(teardown) {
                    eprintln!("ember demo wedge: {e}");
                    process::exit(1);
                }
            }
            DemoAction::Bundle => {
                if let Err(e) = emberlink_cli::demo::bundle::cmd_demo_bundle(&config) {
                    eprintln!("ember demo bundle: {e}");
                    process::exit(1);
                }
            }
            DemoAction::Seed { grant, count } => {
                match emberlink_cli::demo::seed::cmd_demo_seed(&config, &grant, count) {
                    Ok(ids) => {
                        println!("Seeded {} synthetic receipts on grant {grant}:", ids.len());
                        for id in &ids {
                            println!("  {id}");
                        }
                    }
                    Err(e) => {
                        eprintln!("ember demo seed: {e}");
                        process::exit(1);
                    }
                }
            }
        },

        Commands::Grants { rest } => {
            let exit = emberlink_cli::grants::dispatch(&rest);
            process::exit(match exit {
                std::process::ExitCode::SUCCESS => 0,
                _ => 1,
            });
        }

        Commands::Session { action } => match action {
            SessionAction::Open {
                target,
                dev,
                prod: _,
                host,
                isolated,
                sandbox,
                strict,
                delegated,
                attach_runtime_persona_id,
                fork_runtime,
                backend,
                preset,
                worktree,
                branch,
                purpose,
                args,
            } => {
                let request = match emberlink_cli::session::build_open_request_with_sandvault(
                    target,
                    dev,
                    host,
                    isolated,
                    matches!(sandbox, Some(SandboxRuntime::Sandvault)),
                    strict,
                    delegated,
                    attach_runtime_persona_id,
                    fork_runtime,
                    backend,
                    preset,
                    worktree,
                    branch,
                    purpose,
                    args,
                ) {
                    Ok(request) => request,
                    Err(e) => {
                        eprintln!("ember session open: {e}");
                        process::exit(2);
                    }
                };
                if let Err(e) = emberlink_cli::session::cmd_session_open(&request) {
                    eprintln!("ember session open: {e}");
                    process::exit(2);
                }
                unreachable!("session open either exec-replaces or returns Err");
            }
            SessionAction::Tail { id, pretty } => {
                if let Err(e) = emberlink_cli::session::cmd_session_tail(id.as_deref(), pretty) {
                    eprintln!("ember session tail: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Construct { action } => match action {
            ConstructAction::Sign {
                binary,
                construct_toml,
                version,
                identity_root_keypath,
            } => {
                let args = emberlink_cli::construct::sign::SignConstructArgs {
                    binary,
                    construct_toml,
                    version,
                    identity_root_keypath,
                };
                if let Err(e) = emberlink_cli::construct::sign::sign_construct(&args) {
                    eprintln!("ember construct sign: {e}");
                    process::exit(1);
                }
            }
            ConstructAction::Dev {
                path,
                list,
                unregister,
            } => {
                let args = emberlink_cli::construct::dev::DevConstructArgs {
                    path,
                    list,
                    unregister,
                };
                if let Err(e) = emberlink_cli::construct::dev::dev_construct(&args) {
                    eprintln!("ember construct dev: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Binary { action } => match action {
            BinaryAction::Install {
                tool_at_version,
                from_path,
                publisher,
                manifest_path,
            } => {
                let args = emberlink_cli::binary::install::BinaryInstallArgs {
                    tool_at_version,
                    from_path,
                    publisher,
                    manifest_path,
                };
                if let Err(e) = emberlink_cli::binary::install::binary_install(&args) {
                    eprintln!("ember binary install: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::InstallBundle {
                from_dir,
                manifest_path,
                publisher,
                version,
                staged_root,
                identity_root_keypath,
            } => {
                let home = match dirs_next::home_dir() {
                    Some(h) => h,
                    None => {
                        eprintln!(
                            "ember binary install-bundle: could not determine home directory"
                        );
                        process::exit(1);
                    }
                };
                let from_dir =
                    from_dir.unwrap_or_else(ember_daemon::binary_manifest::bundled_install_dir);
                let args = emberlink_cli::binary::install_bundle::BinaryInstallBundleArgs {
                    from_dir,
                    manifest_path,
                    publisher,
                    version,
                    staged_root,
                    identity_root_keypath,
                };
                if let Err(e) =
                    emberlink_cli::binary::install_bundle::binary_install_bundle(&args, &home)
                {
                    eprintln!("ember binary install-bundle: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::List { manifest_path } => {
                if let Err(e) = emberlink_cli::binary::list::binary_list(manifest_path) {
                    eprintln!("ember binary list: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::Update { tool_name } => {
                let args = emberlink_cli::binary::update::BinaryUpdateArgs { tool_name };
                if let Err(e) = emberlink_cli::binary::update::binary_update(&args) {
                    eprintln!("ember binary update: {e}");
                    process::exit(1);
                }
            }
            BinaryAction::Remove {
                tool_at_version,
                manifest_path,
            } => {
                let args = emberlink_cli::binary::remove::BinaryRemoveArgs {
                    tool_at_version,
                    manifest_path,
                };
                if let Err(e) = emberlink_cli::binary::remove::binary_remove(&args) {
                    eprintln!("ember binary remove: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Headless { action } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            match action {
                HeadlessAction::Enroll {
                    input,
                    duration,
                    persona,
                } => {
                    let args = emberlink_cli::headless::EnrollArgs {
                        input_json_path: input,
                        duration,
                        persona,
                        yes: cli.yes,
                    };
                    if let Err(e) = emberlink_cli::headless::cmd_enroll(&socket_path, args) {
                        eprintln!("ember headless enroll: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Revoke { enrollment_id } => {
                    let args = emberlink_cli::headless::RevokeArgs { enrollment_id };
                    if let Err(e) = emberlink_cli::headless::cmd_revoke(&socket_path, args) {
                        eprintln!("ember headless revoke: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Status => {
                    if let Err(e) = emberlink_cli::headless::cmd_status(&socket_path) {
                        eprintln!("ember headless status: {e}");
                        process::exit(1);
                    }
                }
                HeadlessAction::Preflight { input, json } => {
                    let args = emberlink_cli::headless::PreflightArgs {
                        input_json_path: input,
                        json,
                    };
                    if let Err(e) = emberlink_cli::headless::cmd_preflight(&socket_path, args) {
                        eprintln!("ember headless preflight: {e}");
                        process::exit(1);
                    }
                }
            }
        }

        Commands::Preflight {
            service,
            persona,
            strict,
            headless,
            json,
        } => {
            let socket_path = config.socket_dir.join("daemon.sock");
            let args = emberlink_cli::preflight::PreflightArgs {
                service,
                persona,
                strict,
                headless,
                json,
            };
            if let Err(e) = emberlink_cli::preflight::cmd_preflight(&socket_path, args) {
                eprintln!("ember preflight: {e}");
                process::exit(1);
            }
        }

        Commands::Catalog { action } => match action {
            CatalogAction::Plan {
                service,
                action,
                posture,
                persona,
                save,
                ttl,
                json,
            } => {
                let socket_path = config.socket_dir.join("daemon.sock");
                let args = emberlink_cli::preflight::PlanArgs {
                    services: service,
                    actions: action,
                    posture,
                    persona,
                    save,
                    ttl,
                    json,
                };
                if let Err(e) = emberlink_cli::preflight::cmd_catalog_plan(&socket_path, args) {
                    eprintln!("ember catalog plan: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Kms { action } => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            match action {
                KmsAction::InitEdge => {
                    if let Err(e) =
                        rt.block_on(emberlink_cli::kms::cmd_kms_init_edge(&config.data_dir))
                    {
                        eprintln!("ember kms init-edge: {e}");
                        process::exit(1);
                    }
                }
                KmsAction::Peer {
                    action: peer_action,
                } => match peer_action {
                    KmsPeerAction::Prepare { target } => {
                        if let Err(e) =
                            rt.block_on(emberlink_cli::kms::cmd_kms_peer_prepare(&target))
                        {
                            eprintln!("ember kms peer prepare: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Enroll { csr_file } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_enroll(
                            &csr_file,
                            &config.data_dir,
                        )) {
                            eprintln!("ember kms peer enroll: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Install {
                        bundle_file,
                        ca_fingerprint,
                        global,
                    } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_install(
                            &bundle_file,
                            &ca_fingerprint,
                            global,
                        )) {
                            eprintln!("ember kms peer install: {e}");
                            process::exit(1);
                        }
                    }
                    KmsPeerAction::Revoke { name } => {
                        if let Err(e) = rt.block_on(emberlink_cli::kms::cmd_kms_peer_revoke(
                            &name,
                            &config.data_dir,
                        )) {
                            eprintln!("ember kms peer revoke: {e}");
                            process::exit(1);
                        }
                    }
                },
            }
        }

        Commands::Orchestrator { action } => {
            use emberlink_cli::orchestrator::OrchestratorAction;
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            match action {
                OrchestratorAction::Spawn {
                    max_depth,
                    template,
                    brief,
                    budget_usd,
                    extra_hosts,
                } => {
                    match rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_spawn(
                        &config,
                        max_depth,
                        template,
                        brief,
                        budget_usd,
                        extra_hosts,
                    )) {
                        Ok(_) => {}
                        Err(code) => process::exit(code),
                    }
                }
                OrchestratorAction::Status {
                    verbose,
                    follow,
                    follow_timeout_secs,
                } => {
                    if let Err(code) =
                        rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_status(
                            &config,
                            verbose,
                            follow,
                            follow_timeout_secs,
                        ))
                    {
                        process::exit(code);
                    }
                }
                OrchestratorAction::Stop => {
                    if let Err(code) =
                        rt.block_on(emberlink_cli::orchestrator::cmd_orchestrator_stop(&config))
                    {
                        process::exit(code);
                    }
                }
            }
        }

        Commands::Dev { action } => match action {
            DevAction::Install { resume, redo } => {
                // ADR 163 §Component 1+2 — drive the 5-stage pipeline via
                // the install_pipeline state machine. Until the real stage
                // bodies land, production install fails closed instead of
                // stamping fake first-run completion into install-state.
                use emberlink_cli::install_pipeline::stages::Stage;
                use emberlink_cli::install_pipeline::{InstallFlags, run_install};

                let redo_stage = match redo {
                    Some(slug) => match Stage::from_slug(&slug) {
                        Some(s) => Some(s),
                        None => {
                            eprintln!(
                                "ember dev install: --redo: unknown stage '{slug}' (accepted: preflight, primitives, github_provisioning, daemon_install, smoke_test)"
                            );
                            process::exit(2);
                        }
                    },
                    None => None,
                };

                let flags = InstallFlags {
                    resume,
                    redo: redo_stage,
                };
                if let Err(e) = run_install(flags) {
                    eprintln!("ember dev install: {e}");
                    process::exit(1);
                }
            }
            DevAction::Info => {
                if let Err(e) = emberlink_cli::dev::info::run() {
                    eprintln!("ember dev info: {e}");
                    process::exit(1);
                }
            }
            DevAction::Sync { no_launchctl } => {
                let args = emberlink_cli::dev::sync::SyncArgs {
                    no_launchctl,
                    workspace_root: None,
                };
                if let Err(e) = emberlink_cli::dev::sync::run(&args) {
                    eprintln!("ember dev sync: {e}");
                    process::exit(1);
                }
            }
        },

        Commands::Bridge { action } => match action {
            // ember_bridge_endpoint_emit_file
            BridgeAction::Endpoint { emit_file, json } => {
                use core_crypto::ca::generate_edge_ca;

                // Refuse if daemon not running.
                let runtime = DaemonRuntime::new(config.clone());
                let runtime_status = runtime.status().ok();
                match emberlink_cli::probe_live_daemon_status(
                    &config.socket_dir.join("daemon.sock"),
                    &config.pid_file,
                ) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        if runtime_status.as_ref().is_some_and(|s| !s.running) {
                            eprintln!(
                                "ember bridge endpoint: daemon not running (stale runtime state)"
                            );
                        } else {
                            eprintln!("ember bridge endpoint: daemon not running");
                        }
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("ember bridge endpoint: {e}");
                        process::exit(1);
                    }
                }

                // Resolve the port from bridge_bind config; refuse if not configured.
                let port = match config.bridge_bind {
                    Some(addr) => {
                        let p = addr.port();
                        if p == 0 {
                            // Port 0 means kernel-assigned — not yet bound/advertised.
                            eprintln!(
                                "ember bridge endpoint: bridge not bound (port is 0 — daemon not yet listening)"
                            );
                            process::exit(1);
                        }
                        p
                    }
                    None => {
                        eprintln!(
                            "ember bridge endpoint: bridge not bound (bridge_bind not configured)"
                        );
                        process::exit(1);
                    }
                };

                // Build bridge addr using the host.docker.internal name that
                // in-container callers use to reach the host.
                let addr = format!("host.docker.internal:{port}");

                // Derive the CA fingerprint from the KMS edge CA seed on disk.
                // TODO(bridge-state-rpc): replace with a daemon RPC once
                // `bridge.endpoint` exists in the JSON-RPC surface. For now we
                // read the seed file directly — same path the daemon loads at
                // startup (data_dir/kms/edge-ca/ca.seed).
                let seed_path = config.data_dir.join("kms").join("edge-ca").join("ca.seed");
                let ca_fingerprint_sha256: String = if seed_path.exists() {
                    match fs::read(&seed_path) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut seed = [0u8; 32];
                            seed.copy_from_slice(&bytes);
                            match generate_edge_ca(Some(seed)) {
                                Ok(edge_ca) => hex::encode(edge_ca.fingerprint),
                                Err(e) => {
                                    eprintln!(
                                        "ember bridge endpoint: failed to derive CA fingerprint: {e}"
                                    );
                                    process::exit(1);
                                }
                            }
                        }
                        Ok(_) => {
                            eprintln!("ember bridge endpoint: edge CA seed has unexpected size");
                            process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("ember bridge endpoint: failed to read edge CA seed: {e}");
                            process::exit(1);
                        }
                    }
                } else {
                    // Edge CA not initialized yet — emit a placeholder.
                    // Run `ember kms init-edge` first.
                    "TODO-bridge-state-rpc-missing".to_string()
                };

                let endpoint_json = serde_json::json!({
                    "addr": addr,
                    "ca_fingerprint_sha256": ca_fingerprint_sha256,
                });
                let json_text = serde_json::to_string_pretty(&endpoint_json)
                    .expect("bridge endpoint JSON serialization is infallible");

                // Resolve output path: --emit-file or default ~/.ember/bridge-endpoint.json.
                let output_path = emit_file.unwrap_or_else(|| {
                    dirs_next::home_dir()
                        .expect("HOME directory must be resolvable")
                        .join(".ember")
                        .join("bridge-endpoint.json")
                });

                // Refuse paths that escape $HOME / $XDG_RUNTIME_DIR or
                // resolve into system dirs (`/etc`, `/var`, …).
                // Anchor: emit_file_path_validated
                let output_path = match validate_emit_file_path(&output_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("ember bridge endpoint: {e}");
                        process::exit(2);
                    }
                };

                // Create parent directory if needed.
                if let Some(parent) = output_path.parent()
                    && let Err(e) = fs::create_dir_all(parent)
                {
                    eprintln!(
                        "ember bridge endpoint: failed to create parent dir {}: {e}",
                        parent.display()
                    );
                    process::exit(1);
                }

                // Write JSON to the output path (mode 0644).
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut opts = fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true).mode(0o644);
                    match opts.open(&output_path) {
                        Ok(mut f) => {
                            use std::io::Write;
                            if let Err(e) = f.write_all(json_text.as_bytes()) {
                                eprintln!(
                                    "ember bridge endpoint: failed to write {}: {e}",
                                    output_path.display()
                                );
                                process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "ember bridge endpoint: failed to open {} for writing: {e}",
                                output_path.display()
                            );
                            process::exit(1);
                        }
                    }
                }

                // Print to stdout when --json is given or when no --emit-file was supplied
                // (emit-file absent means stdout is the primary output).
                if json {
                    println!("{json_text}");
                } else {
                    println!("bridge endpoint written to {}", output_path.display());
                }
            }
        },
        Commands::Admin { action } => match action {
            AdminAction::V030Survey { action } => match action {
                V030SurveyAction::Complete { out_dir } => {
                    if cli.no_input {
                        eprintln!(
                            "ember admin v030-survey complete: {}",
                            emberlink_cli::v030_survey::RETIRED_MESSAGE
                        );
                        process::exit(2);
                    }
                    match emberlink_cli::v030_survey::run_complete_cli(out_dir) {
                        Ok(_) => {}
                        Err(emberlink_cli::v030_survey::SurveyError::Retired(msg)) => {
                            eprintln!("ember admin v030-survey complete: {msg}");
                            process::exit(2);
                        }
                        Err(e) => {
                            eprintln!("ember admin v030-survey complete: {e}");
                            process::exit(1);
                        }
                    }
                }
            },
        },
    }
}

/// `ember cluster <action>` — cluster management subcommands.
///
/// `snapshots` lists locally-pulled cluster snapshots.
/// `bootstrap` generates the Daemon
/// Persona keypair for single-phase EmberSeal bootstrap (ADR 117).
fn cmd_cluster(action: ClusterAction, config: &DaemonConfig, json_output: bool) {
    match action {
        ClusterAction::Snapshots { cluster_id } => {
            cmd_cluster_snapshots(config, cluster_id.as_deref(), json_output);
        }
        ClusterAction::Bootstrap {
            cluster_id,
            two_phase,
        } => {
            emberlink_cli::cluster::cmd_cluster_bootstrap(
                &cluster_id,
                two_phase,
                config,
                json_output,
            );
        }
        ClusterAction::Restore {
            cluster_id,
            verify,
            seed_out,
        } => {
            emberlink_cli::cluster::cmd_cluster_restore(
                &cluster_id,
                verify,
                seed_out.as_deref(),
                config,
                json_output,
            );
        }
    }
}

/// `ember cluster snapshots [--cluster-id <id>]`
///
/// Reads locally-stored cluster snapshots from the vault and prints them.
/// Each row: { snapshot_id, cluster_id, taken_at, prev_snapshot_id, size_bytes }.
fn cmd_cluster_snapshots(
    config: &DaemonConfig,
    cluster_id_filter: Option<&str>,
    json_output: bool,
) {
    if uses_managed_separate_uid_topology(config) {
        eprintln!("error: {}", managed_local_vault_fallback_refused());
        process::exit(1);
    }

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

    let entries = ember_daemon::snapshot::list_local_snapshots(&vault, &store, cluster_id_filter);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
        );
    } else if entries.is_empty() {
        if let Some(cid) = cluster_id_filter {
            println!("No local snapshots for cluster {cid}.");
        } else {
            println!("No local cluster snapshots found.");
        }
        println!(
            "Configure snapshot_pull_endpoint + snapshot_pull_cluster_id in config.toml to enable pulling."
        );
    } else {
        println!(
            "{:<18} {:<16} {:<12} {:<10}",
            "SNAPSHOT_ID", "CLUSTER", "TAKEN_AT", "SIZE"
        );
        println!("{}", "-".repeat(60));
        for e in &entries {
            let id_short: String = e.snapshot_id.chars().take(16).collect();
            let cluster_short: String = e.cluster_id.chars().take(14).collect();
            println!(
                "{:<18} {:<16} {:<12} {:>8}B",
                id_short, cluster_short, e.taken_at, e.size_bytes,
            );
        }
    }
}

#[cfg(test)]
#[path = "ember/tests.rs"]
mod tests;
