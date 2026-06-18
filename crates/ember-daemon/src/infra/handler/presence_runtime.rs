use super::*;

/// Parse a 32-byte scope KEK from a `<field>` hex param (64 hex chars). Used by
/// the ADR 206 §4 unlock/provision endpoints, where the operator-session CLI
/// submits the KEK it just `se_unwrap`ped. The KEK is secret-in-transit (the §4
/// interactive-honesty clause accepts this at dev0; eviction is load-bearing).
pub(crate) fn parse_scope_kek_hex(
    params: &Value,
    field: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, (i32, String)> {
    use zeroize::{Zeroize as _, Zeroizing};
    let hex_str = params.get(field).and_then(|v| v.as_str()).ok_or((
        -32602,
        format!("'{field}' (64-hex 32-byte scope KEK) is required"),
    ))?;
    let mut bytes =
        hex::decode(hex_str).map_err(|e| (-32602, format!("'{field}': invalid hex: {e}")))?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err((
            -32602,
            format!(
                "'{field}': scope KEK must be 32 bytes (64 hex chars), got {}",
                bytes.len()
            ),
        ));
    }
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&bytes);
    // Scrub the decoded heap copy; the KEK now lives only in the Zeroizing array.
    bytes.zeroize();
    Ok(kek)
}

pub(super) fn parse_enroll_device_material(
    params: &Value,
) -> Result<
    (
        core_principals::PublicKeyMaterial,
        core_principals::PublicKeyMaterial,
        String,
    ),
    (i32, String),
> {
    let device_key = params
        .get("device_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                -32602,
                "identity.device.enroll: 'device_key' (p256:<sec1-hex>) is required".to_string(),
            )
        })?;
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(device_key.to_string())) {
        return Err((
            -32602,
            "identity.device.enroll: 'device_key' is not a valid p256:<sec1-hex> P-256 public key"
                .to_string(),
        ));
    }

    // ADR 206 §4: the founding device must also supply a DISTINCT ECIES recipient
    // key (a second `UserPresence` SE key) so presence-as-decryption can seal
    // scope KEKs to it. Required (clean break, pre-users) and validated on-curve
    // before it is bound as the Device's encryption key. It MUST differ from the
    // signing key — reusing one key is the exact sign==decrypt collapse the cut
    // kills (macOS SE can't enforce usage separation, so we enforce distinctness
    // here, AC-4).
    let encryption_key = params
        .get("encryption_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                -32602,
                "identity.device.enroll: 'encryption_key' (p256:<sec1-hex>, the ECIES recipient \
                 key, distinct from 'device_key') is required"
                    .to_string(),
            )
        })?;
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(encryption_key.to_string())) {
        return Err((
            -32602,
            "identity.device.enroll: 'encryption_key' is not a valid p256:<sec1-hex> P-256 public \
             key"
            .to_string(),
        ));
    }
    // Compare case-insensitively: `p256:<hex>` decodes the same regardless of hex
    // case, so a re-cased signing key (`…AB…` vs `…ab…`) would slip a raw `==`
    // string check and re-introduce the sign==decrypt reuse this guard exists to
    // refuse. Hex is the only representation variance for a fixed-length SEC1 key,
    // so `eq_ignore_ascii_case` has no false positives.
    if encryption_key.eq_ignore_ascii_case(device_key) {
        return Err((
            -32602,
            "identity.device.enroll: 'encryption_key' must be DISTINCT from 'device_key' \
             (ADR 206 §4: the §4 ECIES recipient cannot be the signing key)"
                .to_string(),
        ));
    }

    let device_label = params
        .get("device_label")
        .and_then(|v| v.as_str())
        .unwrap_or("Operator Presence Device")
        .to_string();

    // `key_id` is rebound to the derived operator key_id inside the ceremony, so
    // the value supplied here is not load-bearing; the pubkey is the trust anchor.
    let device_material = core_principals::PublicKeyMaterial {
        key_id: "operator-presence-device".to_string(),
        algorithm: core_principals::KeyAlgorithm::EcdsaP256,
        public_key: device_key.to_string(),
    };
    let encryption_material = core_principals::PublicKeyMaterial {
        key_id: "operator-presence-device-ecies".to_string(),
        algorithm: core_principals::KeyAlgorithm::EcdsaP256,
        public_key: encryption_key.to_string(),
    };
    Ok((device_material, encryption_material, device_label))
}

fn parse_authority_device_key(
    params: &Value,
    method: &str,
) -> Result<core_crypto::PublicKey, (i32, String)> {
    let authority_device_key = params
        .get("authority_device_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                -32602,
                format!("{method}: 'authority_device_key' (primary p256:<sec1-hex>) is required"),
            )
        })?;
    if !core_crypto::p256_public_key_is_valid(&core_crypto::PublicKey(
        authority_device_key.to_string(),
    )) {
        return Err((
            -32602,
            format!(
                "{method}: 'authority_device_key' is not a valid p256:<sec1-hex> P-256 public key"
            ),
        ));
    }
    Ok(core_crypto::PublicKey(authority_device_key.to_string()))
}

fn operator_root_id_for_authority_key(authority_device_key: &core_crypto::PublicKey) -> String {
    let pubkey_hex = authority_device_key
        .0
        .strip_prefix("p256:")
        .unwrap_or(&authority_device_key.0);
    format!(
        "{}{}",
        crate::infra::operator_identity::OPERATOR_ROOT_ID_PREFIX,
        pubkey_hex
    )
}

fn open_operator_identity_store(
    daemon_store: &DaemonStore,
    method: &str,
) -> Result<core_state::EventStore, (i32, String)> {
    let data_dir = daemon_store.data_dir().ok_or_else(|| {
        (
            -32000,
            format!("{method}: daemon has no data_dir; operator identity cannot be persisted on an in-memory store"),
        )
    })?;
    crate::infra::identity_substrate::open_identity_store(data_dir)
        .map_err(|e| (-32000, format!("{method}: open identity store: {e}")))
}

/// Compute the ordered ceremony bytes the founding presence device must sign.
/// **Pure**: no key, no vault, no state mutation — just the authoritative
/// signing plan. Shared by the ConnectOnly plan RPC and the COMMIT RPC's
/// no-signatures branch.
fn build_enroll_plan(
    device_material: &core_principals::PublicKeyMaterial,
    encryption_material: &core_principals::PublicKeyMaterial,
    device_label: &str,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::genesis_enroll_plan;

    let (ids, device_id, steps) =
        genesis_enroll_plan(device_material, encryption_material, device_label)
            .map_err(|e| (-32000, format!("identity.device.enroll prepare: {e}")))?;
    let to_sign: Vec<Value> = steps
        .iter()
        .map(|s| {
            json!({
                "purpose": s.purpose,
                "event_id": s.event_id,
                "bytes_hex": hex::encode(&s.signing_bytes),
            })
        })
        .collect();
    Ok(json!({
        "mode": "prepare",
        "operator_root_id": ids.root_id,
        "operator_persona_id": ids.persona_id,
        "device_id": device_id,
        "to_sign": to_sign,
    }))
}

fn build_backup_enroll_plan(
    identity_store: &core_state::EventStore,
    authority_device_key: &core_crypto::PublicKey,
    device_material: &core_principals::PublicKeyMaterial,
    encryption_material: &core_principals::PublicKeyMaterial,
    device_label: &str,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::backup_presence_device_enroll_plan;

    let root_id = operator_root_id_for_authority_key(authority_device_key);
    let plan = backup_presence_device_enroll_plan(
        identity_store,
        &root_id,
        authority_device_key,
        device_material,
        encryption_material,
        device_label,
    )
    .map_err(|e| {
        (
            -32000,
            format!("identity.device.enroll_backup prepare: {e}"),
        )
    })?;
    Ok(json!({
        "mode": "prepare",
        "operator_root_id": plan.root_id,
        "device_id": plan.device_id,
        "authority_device_key": authority_device_key.0,
        "to_sign": [{
            "purpose": plan.step.purpose,
            "event_id": plan.step.event_id,
            "bytes_hex": hex::encode(&plan.step.signing_bytes),
        }],
    }))
}

/// ADR 200 §5 — `identity.device.enroll_plan`: the **read-only PREPARE** half of
/// the operator-bootstrap ceremony, split out of `identity.device.enroll` so it
/// can be classified `ConnectOnly`.
///
/// It validates the device key and computes the exact ordered bytes to sign; it
/// mutates nothing, holds no key, and touches no vault. Classifying it
/// ConnectOnly (peer-cred gated to the operator uid, like the other `presence/*`
/// proof-acquisition reads) removes a redundant daemon native-unlock Touch ID
/// tap from the enrollment flow — the operator's Secure Enclave tap over the
/// returned ceremony bytes is the real presence proof, verified at COMMIT append
/// time. The plan reveals no secret material: the `to_sign` bytes are
/// deterministic from the caller-supplied `device_key` plus the public genesis
/// scheme.
pub(super) fn handle_identity_device_enroll_plan(
    _daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let (device_material, encryption_material, device_label) =
        parse_enroll_device_material(params)?;
    build_enroll_plan(&device_material, &encryption_material, &device_label)
}

/// ADR 200 §5 / AC-2 — read-only PREPARE half for enrolling the bootstrap backup
/// `presence` Device under the existing operator root. It returns the exact
/// single `DeviceEnrolled` event bytes the already-enrolled primary authority
/// device must sign.
pub(super) fn handle_identity_device_enroll_backup_plan(
    daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let (device_material, encryption_material, device_label) =
        parse_enroll_device_material(params)?;
    let authority_device_key =
        parse_authority_device_key(params, "identity.device.enroll_backup_plan")?;
    let identity_store =
        open_operator_identity_store(daemon_store, "identity.device.enroll_backup_plan")?;
    build_backup_enroll_plan(
        &identity_store,
        &authority_device_key,
        &device_material,
        &encryption_material,
        &device_label,
    )
}

/// `identity.device.list` — ConnectOnly read of the full enrolled-device
/// inventory from the operator identity event store (ADR 200).
///
/// Returns every `DeviceRecord` in `devices_current`, regardless of custody
/// class or status, so the operator can inspect the complete set (presence,
/// recovery, daemon, container, co-authority). No vault tap; no presence
/// gate required.
///
/// **`device_role`** is the wire-compatible field name shipped in #5897;
/// from the ADR 200 amendment 2026-06-12 forward, its value mirrors
/// `custody_class` (the founding "primary"/"backup" distinction is retired —
/// capability flows from custody class, not an orthogonal role label). The
/// genesis device is still surfaced via the stable-order sort so the
/// `device list` UI keeps a predictable shape, but its `device_role` is now
/// `"presence"` like any other presence device.
///
/// Anchor: `ember_device_list_surface_landed`.
pub(super) fn handle_identity_device_list(
    daemon_store: &DaemonStore,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::{
        OPERATOR_ROOT_ID_PREFIX, active_presence_device_keys_under_operator_root, operator_root_id,
    };
    use core_event_types::{AttestationTier, CustodyClass, PresenceFactor};
    use core_state::DeviceStatus;

    let data_dir = daemon_store.data_dir().ok_or_else(|| {
        (
            -32000,
            "identity.device.list: daemon has no data_dir; identity store unavailable".to_string(),
        )
    })?;
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(data_dir).map_err(|e| {
            (
                -32000,
                format!("identity.device.list: open identity store: {e}"),
            )
        })?;

    let state = identity_store.materialized();

    // Use the operator root signing pubkey to identify the genesis presence
    // device for stable sort order. (We no longer expose it as a separate
    // role on the wire — see device_role/device_class.)
    let genesis_pubkey_suffix: Option<String> = operator_root_id(state)
        .and_then(|root_id| root_id.strip_prefix(OPERATOR_ROOT_ID_PREFIX))
        .map(|s| s.to_string());

    // (F9.3 LOW): compute
    // whether the operator-authority set is currently down to exactly ONE
    // Active `presence`-class Device. If so, surface `is_last_authority:
    // true` on that single device so the CLI/dashboard can render a
    // "WARNING: revoking would brick" affordance. We reuse the same filter
    // the structural last-presence-device guard in `device_revoke_plan` uses
    // — `active_presence_device_keys_under_operator_root` — so the surface
    // can never drift away from the guard's truth. Anchor:
    // device_list_is_last_authority_flag_landed.
    let active_presence_pubkeys = active_presence_device_keys_under_operator_root(state);
    let last_authority_pubkey: Option<String> = if active_presence_pubkeys.len() == 1 {
        Some(active_presence_pubkeys.into_iter().next().unwrap())
    } else {
        None
    };

    let mut devices: Vec<Value> = state
        .devices_current
        .values()
        .map(|d| {
            let status = match d.status {
                DeviceStatus::Active => "active",
                DeviceStatus::Revoked => "revoked",
                DeviceStatus::Frozen => "frozen",
                DeviceStatus::Replaced => "replaced",
            };
            let custody = d.custody_class.as_str();

            // `device_class` is the v2 wire field (post ADR 200 amendment
            // 2026-06-12) — mirrors custody_class directly. `device_role`
            // continues to ship for backward compat with #5897 callers; its
            // value now matches `device_class` (the primary/backup
            // distinction is retired).
            let device_class = match d.custody_class {
                CustodyClass::Recovery => "recovery",
                CustodyClass::Daemon => "daemon",
                CustodyClass::Container => "container",
                CustodyClass::CoAuthority => "co-authority",
                CustodyClass::Presence => "presence",
            };

            // Map AttestationTier to attestation_kind string.
            let attestation_kind = match d.attestation_tier {
                AttestationTier::None => {
                    // Distinguish SE (user_presence) from generic none.
                    match d.presence_factor {
                        PresenceFactor::UserPresence | PresenceFactor::Biometric => {
                            "secure_enclave"
                        }
                        PresenceFactor::HardwareTouch => "yubikey_piv",
                        PresenceFactor::Unattended => "none",
                    }
                }
                AttestationTier::GenuineApp => "genuine_app",
                AttestationTier::VendorHw => "yubikey_piv",
            };

            // Stable-sort helper: prefer the genesis presence device first.
            let is_genesis = match d.custody_class {
                CustodyClass::Presence => {
                    let signing_pubkey_hex = d
                        .active_key
                        .public_key
                        .strip_prefix("p256:")
                        .unwrap_or(&d.active_key.public_key);
                    genesis_pubkey_suffix
                        .as_deref()
                        .map(|suffix| suffix == signing_pubkey_hex)
                        .unwrap_or(false)
                }
                _ => false,
            };

            // A device is
            // the "only authority" iff it matches the lone Active
            // presence-class pubkey computed above. Non-presence devices
            // and revoked/frozen/replaced presence devices are never the
            // last-authority device because the guard's filter excludes
            // them. Anchor: device_list_is_last_authority_flag_landed.
            let is_last_authority = last_authority_pubkey
                .as_deref()
                .map(|pk| pk == d.active_key.public_key)
                .unwrap_or(false);

            json!({
                "device_id": d.device_id,
                "device_label": d.label,
                "device_role": device_class,
                "device_class": device_class,
                "device_pubkey": d.active_key.public_key,
                "device_encryption_pubkey": d.active_encryption_key.public_key,
                // enrolled_at: not stored in DeviceRecord; omit (None)
                "status": status,
                "custody_class": custody,
                "attestation_kind": attestation_kind,
                "is_last_authority": is_last_authority,
                "__is_genesis": is_genesis,
            })
        })
        .collect();

    // Stable order: genesis presence first, then other presence devices, then
    // recovery, then daemon/container/co-authority. Within a band, by device_id.
    devices.sort_by(|a, b| {
        let ord = |v: &Value| -> u8 {
            let is_genesis = v
                .get("__is_genesis")
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let class = v.get("device_class").and_then(|v| v.as_str()).unwrap_or("");
            match (is_genesis, class) {
                (true, "presence") => 0,
                (_, "presence") => 1,
                (_, "recovery") => 2,
                (_, "co-authority") => 3,
                (_, "container") => 4,
                (_, "daemon") => 5,
                _ => 6,
            }
        };
        let ord_a = ord(a);
        let ord_b = ord(b);
        ord_a.cmp(&ord_b).then_with(|| {
            let id_a = a.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
            let id_b = b.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
            id_a.cmp(id_b)
        })
    });

    // Strip the internal sort key before returning to the wire.
    for d in devices.iter_mut() {
        if let Some(obj) = d.as_object_mut() {
            obj.remove("__is_genesis");
        }
    }

    Ok(json!({ "devices": devices }))
}

/// Map an `OperatorIdentityError`
/// from the device-revoke plan/commit path into the daemon's wire `(code,
/// message)` pair. The structural last-presence-device guard gets its own
/// subspace code (-32032 via `RpcError::LastPresenceDeviceGuard`) so the CLI
/// can shape an "enroll a replacement first" affordance; every other revoke
/// refusal (unknown device id, already-revoked, signer-not-an-active-
/// presence) stays on the generic presence-locked bucket (-32030).
///
/// Anchor: `device_revoke_last_device_distinct_error_code_landed`.
fn map_revoke_error(
    stage: &str,
    err: crate::infra::operator_identity::OperatorIdentityError,
) -> (i32, String) {
    use crate::infra::operator_identity::OperatorIdentityError;
    use crate::infra::rpc_error::RpcError;
    match err {
        OperatorIdentityError::LastPresenceDeviceGuard(_) => {
            RpcError::LastPresenceDeviceGuard(format!("{stage}: {err}")).into()
        }
        other => (-32030, format!("{stage}: {other}")),
    }
}

/// `identity.device.revoke` — operator-driven revocation of an enrolled
/// presence Device (ADR 200 §5/§6, V030-EMBER-DEVICE-REVOKE).
///
/// Two-call ceremony mirroring `identity.device.enroll_backup`: PREPARE
/// (no `signatures`) returns the exact `DeviceRevoked` event bytes the
/// authority presence Device must sign; COMMIT (with `signatures: [DER_hex]`)
/// verifies the signature against the recorded P-256 key and appends.
/// The daemon never holds either presence Device's private key.
///
/// Structural last-presence-device guard: the operator_identity helper
/// refuses to revoke the last Active `presence`-class Device under the
/// root — bricking the authority set is structurally refused, surfaced as
/// `-32030` so the CLI prints the daemon's refusal message verbatim.
///
/// V030-EMBER-DEVICE-REVOKE F4.1 race fix: the COMMIT branch acquires the
/// daemon's identity-mutation lock BEFORE opening the per-call
/// `EventStore`. Without this, two concurrent COMMITs targeting the two
/// remaining devices in a 2-device authority set could each independently
/// open a fresh `EventStore` snapshot, each see two active presence
/// Devices in their per-instance in-memory `MaterializedState`, each
/// independently pass the last-presence-device guard, and both append —
/// bricking the authority set despite the structural guard
/// ([`commit_device_revoke`] re-runs the guard but against the same stale
/// per-handler snapshot, so the SQLite write serialization alone is not
/// enough). The lock serializes the whole open → guard → commit window so
/// the second handler call opens AFTER the first commit has materialized
/// to disk and observes the now-1-device state.
///
/// PREPARE does not acquire the lock — it never mutates state, so a stale
/// "prepare succeeds, COMMIT might race" is captured by the lock-protected
/// re-check inside `commit_device_revoke`.
///
/// After the `DeviceRevoked`
/// event commits, the COMMIT branch ALWAYS cascade-deletes the revoked
/// Device's `presence_scope_kek` row (the encryption-side wrap an attacker
/// holding only the daemon DB + the revoked Device's ECIES private key
/// could otherwise still unwrap). The cascade-delete is structural and
/// not gated by `--compromised`: a routine retire is also a wrap a Device
/// that no longer holds authority should not be able to consume.
///
/// When the COMMIT carries `"compromised": true`, the daemon also rotates
/// `KEK_s` per operator-authority scope: a fresh `KEK_s` is generated,
/// new wraps for every surviving recipient (presence + recovery) are
/// written, and the prior wraps the leaked Device could have unwrapped
/// are replaced wholesale (ADR 211 inverted-envelope shape: DEKs wrap
/// bulk material under `KEK_s`, so rewrap cost is bounded to the small
/// fan-out of per-recipient wraps — there is no production DEK in the
/// daemon today, so the structural rotation is the full mitigation).
/// An audit-log row with action `kek.rotation` is emitted alongside the
/// `DeviceRevoked` event so an external auditor sees the encryption-side
/// mitigation landed.
///
/// Anchor: `ember_device_revoke_surface_landed`.
pub(super) async fn handle_identity_device_revoke(
    daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::{commit_device_revoke, device_revoke_plan};

    let target_device_id = params
        .get("device_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "identity.device.revoke: 'device_id' is required".to_string(),
        ))?
        .to_string();
    let authority_device_key = parse_authority_device_key(params, "identity.device.revoke")?;
    let reason = params
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("operator-initiated revoke")
        .to_string();
    // The opt-in flag that
    // triggers `KEK_s` rotation on COMMIT. Missing field defaults to
    // `false` so a client that hasn't been recompiled against the new
    // schema gets the routine cascade-delete-only path, never an
    // unintended rotation. Any non-bool value fails closed with -32602.
    let compromised = match params.get("compromised") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err((
                -32602,
                "identity.device.revoke: 'compromised' must be a boolean".to_string(),
            ));
        }
    };

    match params.get("signatures") {
        // PREPARE — return the canonical bytes to sign. Pure: no key, no
        // mutation. The plan also runs the last-presence-device guard so
        // the operator is not asked to tap for an op COMMIT will refuse.
        None => {
            let identity_store =
                open_operator_identity_store(daemon_store, "identity.device.revoke")?;
            let plan = device_revoke_plan(
                &identity_store,
                &authority_device_key,
                &target_device_id,
                &reason,
            )
            // The last-presence
            // -device guard surfaces as -32032 so the CLI can render a typed
            // "enroll a replacement first" affordance; other revoke refusals
            // stay on -32030.
            // Anchor: device_revoke_last_device_distinct_error_code_landed.
            .map_err(|e| map_revoke_error("identity.device.revoke prepare", e))?;
            Ok(json!({
                "mode": "prepare",
                "operator_root_id": plan.root_id,
                "device_id": plan.device_id,
                "authority_device_key": authority_device_key.0,
                "to_sign": [{
                    "purpose": plan.step.purpose,
                    "event_id": plan.step.event_id,
                    "bytes_hex": hex::encode(&plan.step.signing_bytes),
                }],
            }))
        }
        // COMMIT — verify the signature and append the DeviceRevoked event.
        Some(sigs_value) => {
            let sig_entries = sigs_value.as_array().ok_or_else(|| {
                (
                    -32602,
                    "identity.device.revoke: 'signatures' must be an array with one hex string"
                        .to_string(),
                )
            })?;
            if sig_entries.len() != 1 {
                return Err((
                    -32602,
                    format!(
                        "identity.device.revoke: expected exactly one signature, got {}",
                        sig_entries.len()
                    ),
                ));
            }
            let raw_sig = sig_entries[0].as_str().ok_or_else(|| {
                (
                    -32602,
                    "identity.device.revoke: signature must be a hex string".to_string(),
                )
            })?;
            let der_hex = raw_sig.strip_prefix("p256sig:").unwrap_or(raw_sig);
            let signature = core_crypto::Signature(format!("p256sig:{der_hex}"));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // V030-EMBER-DEVICE-REVOKE F4.1 — acquire the identity-mutation
            // lock BEFORE opening the per-call `EventStore`. The lock makes
            // the open → guard → SQLite-append window atomic across
            // concurrent handler calls: the second caller blocks until the
            // first's append has committed, then opens an `EventStore` that
            // already reflects the first revoke. Cloning the `Rc` decouples
            // the guard's lifetime from the `&daemon_store` borrow so the
            // store is still available for `open_operator_identity_store`
            // below.
            let lock = std::rc::Rc::clone(daemon_store.identity_mutation_lock());
            let _guard = lock.lock().await;

            let mut identity_store =
                open_operator_identity_store(daemon_store, "identity.device.revoke")?;
            let (root_id, device_id) = commit_device_revoke(
                &mut identity_store,
                &authority_device_key,
                &target_device_id,
                &reason,
                signature,
                now,
            )
            // Same typed-error
            // mapping the PREPARE path uses, so a COMMIT racing in after a
            // sibling-revoke draining the authority set down to the target
            // also surfaces -32032 (not -32030).
            // Anchor: device_revoke_last_device_distinct_error_code_landed.
            .map_err(|e| map_revoke_error("identity.device.revoke commit", e))?;

            // The cascade-
            // delete + optional rotation MUST run UNDER the same
            // identity-mutation lock that gated the `DeviceRevoked`
            // append above (held by `_guard`), so a concurrent revoke
            // cannot interleave with the wrap-side mitigation. The
            // identity event log and the `presence_scope_kek` table live
            // in DIFFERENT SQLite databases (operator events vs daemon
            // DB), so a literal cross-DB transaction is not available;
            // ordering matters instead: append the event first (so a
            // partial failure leaves the durable record of the revoke
            // intact), then drop the wrap row(s), then optionally
            // rotate. The lock + DeviceRevoked-event durability give
            // the same "no-mutation-without-the-event" guarantee a
            // cross-DB tx would.
            let (rotation_emitted, wraps_dropped) = apply_revoke_wrap_mitigation(
                daemon_store,
                &identity_store,
                &root_id,
                &device_id,
                compromised,
                &reason,
            )?;

            let mut response = json!({
                "mode": "committed",
                "device_id": device_id,
                "reason": reason,
                "operator_root_id": root_id,
                "cascade_deleted_wraps": wraps_dropped,
                "kek_rotation_emitted": rotation_emitted,
            });
            // Echo the compromised flag back so the operator-facing CLI
            // can render a distinct "rotation ran" affordance without
            // re-reading its own input.
            response["compromised"] = Value::Bool(compromised);
            Ok(response)
        }
    }
}

// device_revoke_cascade_kek_wrap_rotation_landed
/// The load-bearing post-`DeviceRevoked` mitigation: ALWAYS cascade-delete the revoked
/// Device's `presence_scope_kek` wraps under the operator-authority
/// scope, and OPTIONALLY rotate `KEK_s` per scope when the COMMIT
/// carries `"compromised": true`. Returns `(rotation_emitted,
/// wraps_dropped)` so the RPC response can echo the structural facts to
/// the caller without leaking key material.
///
/// **Why the cascade is structural (always-on):** the revoked Device's
/// wrap row would otherwise let an attacker holding (a) the daemon DB
/// and (b) the revoked Device's ECIES private key still unwrap `KEK_s`
/// — exactly the encryption-side hole F8.1 surfaced. A routine retire
/// shares the same shape: a Device that no longer holds authority
/// should not be able to unwrap the scope either.
///
/// **Why rotation is opt-in:** rotation generates a fresh `KEK_s` and
/// drops EVERY recipient's wrap (including the surviving ones), so on
/// dev0 single-host the operator pays a rewrap fan-out per surviving
/// recipient. That fan-out is cheap (ADR 211 inverted-envelope: DEKs
/// wrap bulk, `KEK_s` only wraps DEKs), but the rotation also requires
/// the surviving recipients' SE keys to be locally accessible for
/// `se_wrap`. On a multi-host fleet that constraint can't be satisfied
/// from the daemon's process — so we only rotate when the operator
/// EXPLICITLY signals compromise (the lost Device's ECIES key may be
/// in adversary hands and the residual surviving-device wraps reveal
/// the SAME `KEK_s` material).
fn apply_revoke_wrap_mitigation(
    daemon_store: &DaemonStore,
    identity_store: &core_state::EventStore,
    root_id: &str,
    device_id: &str,
    compromised: bool,
    reason: &str,
) -> Result<(bool, usize), (i32, String)> {
    // The operator-authority scope is the dev0 default §4 sealing scope
    // (see `operator_authority_scope` in `operator_identity.rs`). At
    // dev0 single-owner the operator's authority is the one default
    // scope; future per-resource scopes earn their own rows under the
    // same `(scope_kind, scope_id, device_id)` key.
    const SCOPE_KIND: &str = "operator";

    // 1) Cascade-delete the revoked Device's wrap. Idempotent: a Device
    //    with no wrap row (never §4-provisioned) yields a DELETE of 0
    //    rows, which is the correct no-op. We deliberately do NOT
    //    cascade across non-operator scopes today — dev0 has exactly
    //    one scope, and adding cross-scope reach without a
    //    materialized-state read would be a footgun on the future
    //    per-resource scope shape.
    let before = daemon_store
        .list_presence_scope_kek_wraps(SCOPE_KIND, root_id)
        .map_err(|e| {
            (
                -32000,
                format!(
                    "identity.device.revoke: list presence_scope_kek wraps under {SCOPE_KIND}/{root_id}: {e}"
                ),
            )
        })?;
    let device_had_wrap = before.iter().any(|(dev, _, _)| dev == device_id);
    daemon_store
        .delete_presence_scope_kek_wrap(SCOPE_KIND, root_id, device_id)
        .map_err(|e| {
            (
                -32000,
                format!(
                    "identity.device.revoke: cascade-delete presence_scope_kek for {device_id} under {SCOPE_KIND}/{root_id}: {e}"
                ),
            )
        })?;
    let wraps_dropped = if device_had_wrap { 1 } else { 0 };

    if !compromised {
        // Routine revoke: cascade-delete only. No `kek.rotation`
        // receipt — the audit-log surface is reserved for the
        // structural mitigation (rotation), not for "we did the
        // always-on cleanup."
        return Ok((false, wraps_dropped));
    }

    // 2) Rotation path — surviving recipients only. The revoked
    //    Device's wrap is already gone above; any other wraps under
    //    this scope belong to surviving recipients (presence Devices
    //    still active OR off-host Recovery recipients) and MUST be
    //    replaced because they all wrap the SAME compromised `KEK_s`
    //    bytes. ADR 211 amplification: DEKs are the bulk-data layer
    //    above `KEK_s`, so re-wrapping `KEK_s` does not require
    //    touching any persona-secret bytes; the rotation cost is
    //    bounded to the per-recipient wrap fan-out.
    let recipients = crate::infra::presence_seal::resolve_authorized_kek_recipients(
        identity_store.materialized(),
    );
    if recipients.is_empty() {
        // Rotation requested but there is no surviving recipient to
        // wrap to. Fail closed (do not silently emit a `kek.rotation`
        // receipt against zero recipients): the operator should see
        // this as a structural refusal so they enroll a recovery
        // recipient before retrying. Note: the cascade-delete of
        // the revoked Device's wrap above DID run (cascade is
        // always-on, per the brief's AC-1) — the error message
        // names that partial-success so the operator does not
        // mistake "rotation refused" for "nothing happened."
        return Err((
            -32030,
            format!(
                "identity.device.revoke: --compromised requires at least one surviving \
                 recipient (presence Device OR recovery) to rotate KEK_s to; no recipient \
                 remains under the operator root after the revoke. The revoked Device's \
                 own wrap row was dropped ({} wrap(s)) by the always-on cascade-delete \
                 BEFORE the rotation refusal — KEK_s itself is unchanged. Enroll a \
                 recovery recipient (`ember device enroll --recovery-code`) and re-run \
                 `ember device revoke --compromised` to complete the rotation.",
                wraps_dropped
            ),
        ));
    }

    // Adversarial-review fix (PR #5998 review): cross-check the
    // surviving wrap rows against the resolved recipient set BEFORE
    // any mutation. A row in `before` for a `device_id` that the
    // resolver no longer recognizes (e.g., an age-X25519 recovery
    // recipient row that survives in DB but the `age` feature is now
    // off so `resolve_authorized_kek_recipients` filters it out)
    // would otherwise be silently DELETED with no replacement wrap
    // written — the operator loses the recovery wrap without a
    // log row. Fail closed: refuse to rotate until the orphan rows
    // are resolved (operator-initiated cleanup) so the rotation
    // semantics ("every surviving recipient is re-wrapped") hold.
    let surviving = before
        .iter()
        .filter(|(dev, _, _)| dev != device_id)
        .cloned()
        .collect::<Vec<_>>();
    let recipient_devices: std::collections::HashSet<&str> =
        recipients.iter().map(|r| r.device_id()).collect();
    let orphans: Vec<&str> = surviving
        .iter()
        .map(|(dev, _, _)| dev.as_str())
        .filter(|dev| !recipient_devices.contains(dev))
        .collect();
    if !orphans.is_empty() {
        return Err((
            -32030,
            format!(
                "identity.device.revoke: --compromised refuses to rotate while \
                 {} surviving wrap row(s) reference recipient(s) the daemon can no \
                 longer resolve: [{}]. Drop the orphan rows (e.g. via \
                 `vault se-provision --reset`) or rebuild the recipient set \
                 before re-running with --compromised.",
                orphans.len(),
                orphans.join(", ")
            ),
        ));
    }

    let new_kek = crate::infra::presence_seal::generate_scope_kek();
    let mut new_wraps: Vec<(String, String, Vec<u8>)> = Vec::with_capacity(recipients.len());
    for recipient in &recipients {
        let wrapped = recipient.wrap(&new_kek).map_err(|e| {
            (
                -32000,
                format!(
                    "identity.device.revoke: rewrap KEK_s for surviving recipient {} ({}): {e}",
                    recipient.device_id(),
                    recipient.key_id()
                ),
            )
        })?;
        new_wraps.push((
            recipient.device_id().to_string(),
            recipient.key_id().to_string(),
            wrapped,
        ));
    }

    // Drop EVERY surviving wrap, write the freshly-rotated ones,
    // and emit the `kek.rotation` audit row — all inside ONE
    // `BEGIN IMMEDIATE` transaction so the daemon DB observes
    // exactly two outcomes: the rotation fully committed (every
    // surviving recipient on the new `KEK_s` + audit-log row
    // landed) OR nothing changed (the tx rolled back, the
    // pre-rotation wraps are still there). A daemon crash mid-loop
    // is then materially indistinguishable from a never-started
    // rotation, which closes the audit-suppression hole flagged in
    // the adversarial review of PR #5998 (rotation succeeds
    // structurally but `log_event` fails, leaving the operator
    // with rotated wraps and no receipt).
    //
    // The order inside the tx still matters: delete, then write —
    // writing first and deleting after would risk admitting a wrap
    // for the OLD `KEK_s` alongside the new ones if a recipient is
    // both in `surviving` and in `recipients`. UPSERT replaces the
    // row regardless, but routing through delete-then-write keeps
    // the post-rotation state unambiguous.
    let conn = daemon_store.conn();
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| {
        (
            -32000,
            format!("identity.device.revoke: BEGIN IMMEDIATE for rotation: {e}"),
        )
    })?;
    let rotation_tx_result: Result<(), (i32, String)> = (|| {
        for (dev, _, _) in &surviving {
            daemon_store
                .delete_presence_scope_kek_wrap(SCOPE_KIND, root_id, dev)
                .map_err(|e| {
                    (
                        -32000,
                        format!(
                            "identity.device.revoke: drop pre-rotation wrap for {dev} under {SCOPE_KIND}/{root_id}: {e}"
                        ),
                    )
                })?;
        }
        for (dev_id, ecies_key_id, wrapped) in &new_wraps {
            daemon_store
                .write_presence_scope_kek_wrap(SCOPE_KIND, root_id, dev_id, ecies_key_id, wrapped)
                .map_err(|e| {
                    (
                        -32000,
                        format!(
                            "identity.device.revoke: write rotated wrap for {dev_id} under {SCOPE_KIND}/{root_id}: {e}"
                        ),
                    )
                })?;
        }

        // 3) Emit the `kek.rotation` audit-log row alongside the
        //    revoke. The action string is the receipt-kind catalog
        //    name; the `details` payload carries the structural
        //    metadata an auditor needs (scope + recipient count +
        //    the originating reason) but no key material.
        //    `log_event` probes `is_autocommit()` and dispatches to
        //    the in-tx variant because the outer transaction is
        //    open, so the audit-chain extension joins this tx and
        //    commits atomically with the wrap writes.
        let details = serde_json::json!({
            "scope_kind": SCOPE_KIND,
            "scope_id": root_id,
            "revoked_device_id": device_id,
            "surviving_recipient_count": recipients.len(),
            "reason": reason,
        })
        .to_string();
        daemon_store
            .log_event(
                Some(root_id),
                "kek.rotation",
                None,
                "success",
                Some(&details),
            )
            .map_err(|e| {
                (
                    -32000,
                    format!("identity.device.revoke: emit kek.rotation audit row: {e}"),
                )
            })?;
        Ok(())
    })();
    match rotation_tx_result {
        Ok(()) => {
            conn.execute("COMMIT", []).map_err(|e| {
                (
                    -32000,
                    format!("identity.device.revoke: COMMIT rotation tx: {e}"),
                )
            })?;
            Ok((true, wraps_dropped))
        }
        Err(err) => {
            // Roll back to discard the partial wraps + the (not-yet-
            // committed) audit-chain row. Ignore ROLLBACK errors —
            // the connection is single-threaded and a failed
            // ROLLBACK still leaves SQLite in a consistent state
            // (no half-committed write would land).
            let _ = conn.execute("ROLLBACK", []);
            Err(err)
        }
    }
}

/// ADR 200 §5 — `identity.device.enroll`: the two-call operator-bootstrap
/// ceremony. PREPARE computes the ordered bytes the founding presence Device
/// must sign; COMMIT appends and verifies the genesis/enroll events. The daemon
/// never holds the operator's presence-device key.
pub(super) fn handle_identity_device_enroll(
    daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::commit_first_run_enrollment;

    let (device_material, encryption_material, device_label) =
        parse_enroll_device_material(params)?;

    // PREPARE vs COMMIT is selected by the presence of `signatures`. An empty
    // array is treated as COMMIT (and fails closed on the count mismatch) rather
    // than silently degrading to PREPARE — explicit intent. PREPARE is retained
    // here for back-compat / manual operators; the CLI drives it through the
    // ConnectOnly `identity.device.enroll_plan` method (no native-unlock tap).
    match params.get("signatures") {
        None => build_enroll_plan(&device_material, &encryption_material, &device_label),
        Some(sigs_value) => {
            let sig_entries = sigs_value.as_array().ok_or_else(|| {
                (
                    -32602,
                    "identity.device.enroll: 'signatures' must be an array of hex strings \
                     (one per prepare step, in order)"
                        .to_string(),
                )
            })?;
            // Each entry is the device's ECDSA-P256 DER signature as hex over the
            // matching prepare step's `bytes_hex`. Accept it with or without the
            // `p256sig:` tag the verifier strips — normalize to the tagged form.
            let signatures: Vec<core_crypto::Signature> = sig_entries
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| {
                            let der_hex = s.strip_prefix("p256sig:").unwrap_or(s);
                            core_crypto::Signature(format!("p256sig:{der_hex}"))
                        })
                        .ok_or_else(|| {
                            (
                                -32602,
                                "identity.device.enroll: each signature must be a hex string"
                                    .to_string(),
                            )
                        })
                })
                .collect::<Result<_, _>>()?;

            // The operator identity lives in the daemon's event-sourced
            // `identity-events.db` (same store as `ensure_daemon_identity`). Reopen
            // it on demand — the daemon idiom for `!Send` rusqlite handles (see
            // runtime.rs genesis). An in-memory store has no data_dir and cannot
            // durably hold the operator identity, so we fail closed.
            let data_dir = daemon_store.data_dir().ok_or_else(|| {
                (
                    -32000,
                    "identity.device.enroll: daemon has no data_dir; operator identity \
                     cannot be persisted on an in-memory store"
                        .to_string(),
                )
            })?;
            let mut identity_store =
                crate::infra::identity_substrate::open_identity_store(data_dir).map_err(|e| {
                    (
                        -32000,
                        format!("identity.device.enroll: open identity store: {e}"),
                    )
                })?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (ids, device_id) = commit_first_run_enrollment(
                &mut identity_store,
                &device_material,
                &encryption_material,
                &device_label,
                &signatures,
                now,
            )
            .map_err(|e| (-32000, format!("identity.device.enroll commit: {e}")))?;
            Ok(json!({
                "mode": "committed",
                "operator_root_id": ids.root_id,
                "device_id": device_id,
            }))
        }
    }
}

/// ADR 200 §5 / AC-2 — two-call backup-device ceremony. The existing primary
/// presence Device signs one `DeviceEnrolled` event for the backup key; the daemon
/// appends only after verifying that signature against the active operator device
/// set. The daemon never holds either private key.
pub(super) fn handle_identity_device_enroll_backup(
    daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::commit_backup_presence_device_enrollment;

    let (device_material, encryption_material, device_label) =
        parse_enroll_device_material(params)?;
    let authority_device_key = parse_authority_device_key(params, "identity.device.enroll_backup")?;
    let mut identity_store =
        open_operator_identity_store(daemon_store, "identity.device.enroll_backup")?;

    match params.get("signatures") {
        None => build_backup_enroll_plan(
            &identity_store,
            &authority_device_key,
            &device_material,
            &encryption_material,
            &device_label,
        ),
        Some(sigs_value) => {
            let sig_entries = sigs_value.as_array().ok_or_else(|| {
                (
                    -32602,
                    "identity.device.enroll_backup: 'signatures' must be an array with one hex string"
                        .to_string(),
                )
            })?;
            if sig_entries.len() != 1 {
                return Err((
                    -32602,
                    format!(
                        "identity.device.enroll_backup: expected exactly one signature, got {}",
                        sig_entries.len()
                    ),
                ));
            }
            let der_hex = sig_entries[0]
                .as_str()
                .ok_or_else(|| {
                    (
                        -32602,
                        "identity.device.enroll_backup: signature must be a hex string".to_string(),
                    )
                })?
                .strip_prefix("p256sig:")
                .unwrap_or(sig_entries[0].as_str().unwrap());
            let signature = core_crypto::Signature(format!("p256sig:{der_hex}"));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let root_id = operator_root_id_for_authority_key(&authority_device_key);
            let device_id = commit_backup_presence_device_enrollment(
                &mut identity_store,
                &root_id,
                &authority_device_key,
                &device_material,
                &encryption_material,
                &device_label,
                signature,
                now,
            )
            .map_err(|e| (-32000, format!("identity.device.enroll_backup commit: {e}")))?;
            Ok(json!({
                "mode": "committed",
                "operator_root_id": root_id,
                "device_id": device_id,
                "authority_device_key": authority_device_key.0,
            }))
        }
    }
}

/// Parse + lightly validate the `age1…` recovery recipient public half. The
/// cryptographic parse happens operator-side at wrap time (the daemon never holds
/// the recovery secret and never wraps to it — finding C3); here we only check the
/// shape so a malformed recipient is rejected before enrollment.
fn parse_recovery_age_pubkey(params: &Value) -> Result<String, (i32, String)> {
    let pk = params
        .get("recovery_pubkey")
        .and_then(|v| v.as_str())
        .ok_or((
            -32602,
            "identity.recovery.enroll: 'recovery_pubkey' (age1…) is required".to_string(),
        ))?;
    // age x25519 recipients are bech32 `age1…`. Keep this a shape check, not a
    // full bech32 decode, to avoid pulling the `age` feature into the handler.
    if !pk.starts_with("age1") || pk.len() < 20 || pk.len() > 200 {
        return Err((
            -32602,
            "identity.recovery.enroll: 'recovery_pubkey' must be an age1… X25519 recipient"
                .to_string(),
        ));
    }
    if !pk
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err((
            -32602,
            "identity.recovery.enroll: 'recovery_pubkey' has non-bech32 characters".to_string(),
        ));
    }
    Ok(pk.to_string())
}

/// ADR 206 §6 — two-call off-host recovery-recipient enrollment. An existing
/// operator presence Device signs ONE `DeviceEnrolled(Recovery)` event binding the
/// printed `age` recovery code's public half; the daemon appends only after
/// verifying that signature against the active operator device set (non-forgeable
/// AC-7). The daemon holds neither the authority key nor the recovery secret
/// (finding C3). After COMMIT, the operator session wraps the live `KEK_s` to the
/// recovery recipient and stores it via `vault.se_add_recipient_wrap` (the
/// returned `recovery_ecies_key_id` is that wrap's AC-7 allowlist token).
pub(super) fn handle_identity_recovery_enroll(
    daemon_store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use crate::infra::operator_identity::{
        commit_recovery_recipient_enrollment, operator_recovery_ecies_key_id,
        recovery_recipient_enroll_plan,
    };

    let recovery_pubkey = parse_recovery_age_pubkey(params)?;
    let label = params
        .get("label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Printed recovery code")
        .to_string();
    let authority_device_key = parse_authority_device_key(params, "identity.recovery.enroll")?;
    let mut identity_store =
        open_operator_identity_store(daemon_store, "identity.recovery.enroll")?;
    let root_id = operator_root_id_for_authority_key(&authority_device_key);
    let recovery_ecies_key_id = operator_recovery_ecies_key_id(&recovery_pubkey);

    match params.get("signatures") {
        None => {
            let plan = recovery_recipient_enroll_plan(
                &identity_store,
                &root_id,
                &authority_device_key,
                &recovery_pubkey,
                &label,
            )
            .map_err(|e| (-32000, format!("identity.recovery.enroll prepare: {e}")))?;
            Ok(json!({
                "mode": "prepare",
                "operator_root_id": plan.root_id,
                "operator_root_pubkey": authority_device_key.0,
                "device_id": plan.device_id,
                "authority_device_key": authority_device_key.0,
                "recovery_ecies_key_id": recovery_ecies_key_id,
                "to_sign": [{
                    "purpose": plan.step.purpose,
                    "event_id": plan.step.event_id,
                    "bytes_hex": hex::encode(&plan.step.signing_bytes),
                }],
            }))
        }
        Some(sigs_value) => {
            let sig_entries = sigs_value.as_array().ok_or((
                -32602,
                "identity.recovery.enroll: 'signatures' must be an array with one hex string"
                    .to_string(),
            ))?;
            if sig_entries.len() != 1 {
                return Err((
                    -32602,
                    format!(
                        "identity.recovery.enroll: expected exactly one signature, got {}",
                        sig_entries.len()
                    ),
                ));
            }
            let raw = sig_entries[0].as_str().ok_or((
                -32602,
                "identity.recovery.enroll: signature must be a hex string".to_string(),
            ))?;
            let der_hex = raw.strip_prefix("p256sig:").unwrap_or(raw);
            let signature = core_crypto::Signature(format!("p256sig:{der_hex}"));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let device_id = commit_recovery_recipient_enrollment(
                &mut identity_store,
                &root_id,
                &authority_device_key,
                &recovery_pubkey,
                &label,
                signature,
                now,
            )
            .map_err(|e| (-32000, format!("identity.recovery.enroll commit: {e}")))?;
            Ok(json!({
                "mode": "committed",
                "operator_root_id": root_id,
                "operator_root_pubkey": authority_device_key.0,
                "device_id": device_id,
                "authority_device_key": authority_device_key.0,
                "recovery_ecies_key_id": recovery_ecies_key_id,
            }))
        }
    }
}

/// TTL for a presence-intent nonce — the operator must perform the off-host
/// hardware tap (YubiKey PIV / SE) and submit the signed widening op within this
/// window. Mirrors the WebAuthn `CHALLENGE_TTL_SECS` (5 min).
const PRESENCE_NONCE_TTL_SECONDS: i64 = 300;

fn method_accepts_fresh_presence_proof(method: &str) -> bool {
    crate::auth::presence_gate::is_presence_widening(method)
        || matches!(
            method,
            "vault_get" | "use_credential" | "sops_unwrap_dek" | "sops.unwrap"
        )
}

/// ADR 200 §3 — `presence/request_nonce`: the operator-facing proof-acquisition
/// RPC that mints the single-use, daemon-bound nonce a widening op's presence
/// signature must cover (the G3 signing-driver's first call).
///
/// Flow: the operator (CLI) asks for a nonce for a specific widening `(op_id,
/// method)`; the daemon mints it bound to `(op_id, daemon_fingerprint, method)`
/// via [`DaemonStore::mint_presence_nonce`] and returns the nonce, the daemon
/// fingerprint, and — authoritatively computed daemon-side, so there is no
/// client/daemon reconstruction divergence — the exact
/// `canonical_presence_intent_bytes` the presence Device must sign. The operator
/// signs those bytes off-host (the daemon holds no presence key, G1) and submits
/// the widening op with the resulting [`PresenceProof`]; the verifier consumes
/// the nonce (`consume_presence_nonce`) and checks the signature.
///
/// Classified `ConnectOnly` (proof-acquisition, like the other `presence/*`
/// proof endpoints): it produces proof material, mints no credential, and
/// mutates no authority state. The nonce alone grants nothing — it is inert
/// until signed by the enrolled presence Device. Widening methods and protected
/// vault-entry reads get a nonce; unrelated routine methods ride the existing
/// session proof and are refused here (fail-closed, avoids minting meaningless
/// nonces).
pub(super) fn handle_presence_request_nonce(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let op_id = params
        .get("op_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "presence/request_nonce: 'op_id' is required".to_string(),
        ))?;
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "presence/request_nonce: 'method' is required".to_string(),
        ))?;

    if !method_accepts_fresh_presence_proof(method) {
        return Err((
            -32602,
            format!(
                "presence/request_nonce: '{method}' is not a presence-proof method; \
                 no presence nonce is required for it"
            ),
        ));
    }

    // ADR 206 §1.3 / approval-laundering Finding 1 — the operator-session signing
    // driver supplies `params_digest`, the canonical digest of the op's
    // authority-relevant params (computed by the SAME `presence_params_digest`
    // the chokepoint recomputes at consume). We bind it into the nonce row and
    // into the signed intent bytes so the proof covers the OBJECT, not just the
    // VERB. Required + non-empty (fail-closed): the daemon must NOT compute the
    // digest itself here — it has only `{op_id, method}` at this point and the
    // whole point is that the OPERATOR's signer commits to the body it is about
    // to invoke. A widening request with no digest cannot be authorized.
    let params_digest = params
        .get("params_digest")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((
            -32602,
            "presence/request_nonce: 'params_digest' is required (the canonical \
             digest of the op's params the operator is signing over)"
                .to_string(),
        ))?;

    let identity = crate::infra::receipt::current_identity().ok_or((
        -32000,
        "presence/request_nonce: daemon identity not initialized".to_string(),
    ))?;
    let daemon_fingerprint = identity.identity_root_fingerprint();
    let peer_uid = ctx.peer.as_ref().map(|p| p.uid);

    let (nonce, expires_at) = store
        .mint_presence_nonce(
            op_id,
            &daemon_fingerprint,
            method,
            params_digest,
            peer_uid,
            PRESENCE_NONCE_TTL_SECONDS,
        )
        .map_err(|e| {
            (
                -32000,
                format!("presence/request_nonce: mint nonce failed: {e}"),
            )
        })?;

    // The exact bytes the operator's presence Device must sign — computed by the
    // daemon (the authoritative byte-computer) so an off-host signer never
    // diverges from what the verifier reconstructs (AC-1). The signer RE-DERIVES
    // these independently from the primitive fields it holds (method, op_id,
    // nonce, daemon_fingerprint, params_digest) and refuses on divergence
    // (Finding 2) — the daemon's copy is checked for agreement, never blindly
    // trusted.
    let intent_bytes = crate::auth::presence_gate::canonical_presence_intent_bytes(
        method,
        op_id,
        &nonce,
        &daemon_fingerprint,
        params_digest,
    );

    Ok(json!({
        "op_id": op_id,
        "method": method,
        "nonce": nonce,
        "daemon_fingerprint": daemon_fingerprint,
        "params_digest": params_digest,
        "expires_at": expires_at,
        "intent_bytes_hex": hex::encode(&intent_bytes),
    }))
}

/// Whether the ADR 206 presence chokepoint enforces a per-op proof for `method`.
///
/// This is the authority-MINTING subset of `is_presence_widening`: the ops that
/// create/expand standing authority (grants, vault writes, persona/grant
/// mutations, key rotations, device enroll, daemon-held-key unseal). Four classes
/// of widening method are deliberately **carved out** of the per-op chokepoint,
/// each for a concrete correctness reason (not laziness). Each carve-out is still
/// gated fail-closed by the §4 unlock window (the OperatorPresence gate below) —
/// the carve-out only exempts them from the *additional* per-op signature here:
///
/// - **`register_session`** — session-open is the ADR 206 §Sequencing step-3
///   "per-op proof whose output is a bounded session lease" item. Its dispatch
///   path is entangled with vault-set verification and the launcher's separate
///   RPC client; enforcing it additively here would break agent launches before
///   the launcher acquires proofs. It is gated by the §4 unlock window instead
///   (proven by `dispatch_vault_unlock_and_register_session_fail_closed_when_window_locked`).
/// - **`presence/request_proof` / `presence_request_proof`** — these *produce*
///   presence proofs; requiring a proof to acquire one would deadlock. They
///   validate their own request-scoped proof material in-handler. (The freshness
///   the chokepoint itself consumes comes from `presence/request_nonce`,
///   ConnectOnly — a distinct bootstrap endpoint.)
/// - **`audit_repair_chain`** — carries its own authority anchor (an enrolled
///   operator persona's Ed25519 `RepairIntent` co-signature) and runs ONLY while
///   the daemon is quarantined, where `presence/request_nonce` is itself refused
///   as non-read-class — so layering a nonce-bound proof requirement on top would
///   deadlock the operator's unbrick path. Its co-signature is the gate.
/// - **`headless_enroll`** — the headless runtime persona enrollment belongs to
///   the ADR 206 §5 headless lane (standing-grant + one-gesture-at-issuance),
///   which has its own presence model and a separate, independent CLI client
///   (`headless.rs`). Forcing the interactive per-op proof onto the headless
///   enroll path is wrong (you enroll headless precisely to act without an
///   interactive operator). It still fails closed on the §4 unlock window; the
///   §5 lane governs its standing-grant issuance model.
///
/// Everything else in `is_presence_widening` is enforced. Keeping this list in
/// the chokepoint (rather than mutating the operator-approved `is_presence_
/// widening` lane map) preserves that map's meaning while scoping which arms this
/// enforcement slice covers.
pub(super) fn presence_chokepoint_applies(method: &str) -> bool {
    crate::auth::presence_gate::is_presence_widening(method)
        && !matches!(
            method,
            "register_session"
                | "presence/request_proof"
                | "presence_request_proof"
                | "audit_repair_chain"
                | "headless_enroll"
        )
}

/// ADR 206 §1 / §Sequencing — the **fail-closed presence-authority chokepoint**
/// for authority-widening operations. This is the structural enforcement point
/// that makes the nonce-bound presence-signature lane (`presence_gate.rs`) the
/// *only* presence mechanism for widening ops. The forgeable "tap-once-opens-a-
/// session" native-unlock window it originally closed the hole on top of was
/// **retired** in ADR 206 slice 4 C (#5199); the gate below is now the §4
/// presence-as-decryption unlock window, not native-unlock.
///
/// Returns `Ok(())` when the method may proceed (it is Routine, or it is a
/// widening op carrying a verified proof) and `Err(..)` when it is a widening op
/// with no valid proof. A widening op must pass **both** gates: the unforgeable
/// per-op signature here AND the OperatorPresence §4-window gate below (which
/// performs the vault-MEK-release / vault attachment a widening handler needs).
/// The chokepoint is the unforgeable per-op layer; the §4 window below is the
/// presence-as-decryption unlock that a real cross-uid SE tap establishes. The
/// daemon holds no presence private key (G1), so neither layer is daemon-forgeable.
///
/// Enforcement steps (all fail-closed): parse the `_presence_proof` the operator-
/// session signing driver attached → atomically consume the daemon-issued nonce
/// (`consume_presence_nonce` binds `op_id`/`method`/`daemon_fingerprint` +
/// freshness + single-use; a failed attempt still tombstones the nonce so it
/// cannot be replayed) → materialize the enrolled `presence`-Device key set from
/// the operator root → verify the signature against it (1-of-N). The daemon holds
/// no presence private key (G1), so it cannot synthesize this proof.
///
/// **Covered arms.** Only the authority-minting widening subset — see
/// [`presence_chokepoint_applies`] for the carve-outs (`register_session`,
/// `presence/request_proof`, `audit_repair_chain`, `headless_enroll`) and the
/// concrete reason each is excluded from the per-op chokepoint (each still fails
/// closed on the §4 unlock window).
///
/// **Source scope (this slice).** Enforced for `Socket` (wire) callers — the
/// G1-relevant attack surface (a compromised daemon's agents/clients minting
/// authority). Internal in-process callers (admin CLI / recovery / test harness)
/// retain the established `!source.is_internal()` carve-out the OperatorPresence
/// block below also uses. FORWARD NOTE (ADR 206 finding A2): the *target* end
/// state is internal-not-exempted; flipping that requires first auditing the
/// internal widening-dispatch callers (admin/recovery wrappers) so they supply a
/// proof or are explicitly justified. Tracked as a follow-up, surfaced in the PR.
#[cfg(test)]
pub(super) fn enforce_presence_chokepoint(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<(), (i32, String)> {
    enforce_presence_chokepoint_with_audit(store, method, params).map(|_| ())
}

pub(super) fn enforce_presence_chokepoint_with_audit(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<Option<VerifiedPresenceProof>, (i32, String)> {
    // Only the authority-MINTING widening ops are enforced here (see
    // `presence_chokepoint_applies` for the carve-outs and why).
    if !presence_chokepoint_applies(method) {
        return Ok(None);
    }

    // Test-only: the broad socket-dispatch suite predates this gate (see
    // PRESENCE_CHOKEPOINT_TEST_ENFORCE). Default off; the dedicated enforcement
    // tests opt in. Compiled out of production — production always enforces.
    #[cfg(test)]
    if !PRESENCE_CHOKEPOINT_TEST_ENFORCE.with(|c| c.get()) {
        return Ok(None);
    }

    enforce_presence_proof_with_audit(store, method, params).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPresenceProof {
    pub presence_authenticator_id: String,
    pub presence_public_key: String,
    pub op_id: String,
    pub nonce: String,
    pub signature: String,
    pub daemon_fingerprint: String,
    pub params_digest: String,
}

impl VerifiedPresenceProof {
    pub(crate) fn public_key_hash(&self) -> String {
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(self.presence_public_key.as_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

pub(super) fn enforce_presence_proof(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<(), (i32, String)> {
    enforce_presence_proof_with_audit(store, method, params).map(|_| ())
}

pub(super) fn enforce_presence_proof_with_audit(
    store: &DaemonStore,
    method: &str,
    params: &Value,
) -> Result<VerifiedPresenceProof, (i32, String)> {
    use crate::auth::presence_gate::{WirePresenceProof, wire_proof_matching_device};

    // Presence-gated op — a presence proof is mandatory. `-32030` mirrors the
    // presence/unlock authority error family the CLI already recognizes (so its
    // retry harness can acquire a proof and retry, like the native-unlock lane).
    let proof_value = params.get("_presence_proof").ok_or_else(|| {
        (
            -32030,
            format!(
                "operation '{method}' requires a presence-Device signature \
                 (acquire one via presence/request_nonce and resubmit with _presence_proof)"
            ),
        )
    })?;
    let proof: WirePresenceProof = serde_json::from_value(proof_value.clone()).map_err(|e| {
        (
            -32602,
            format!("malformed _presence_proof for '{method}': {e}"),
        )
    })?;

    let identity = crate::infra::receipt::current_identity().ok_or((
        -32000,
        "presence chokepoint: daemon identity not initialized".to_string(),
    ))?;
    let daemon_fingerprint = identity.identity_root_fingerprint();

    // ADR 206 §1.3 / approval-laundering Finding 1 — RE-derive the params digest
    // over the params AS RECEIVED (envelope fields stripped by the helper). This
    // is the daemon-side half of the binding: if a compromised daemon substituted
    // the op body after the operator's tap, this recomputed digest will not match
    // the digest the operator committed at mint (and signed into the intent
    // bytes), so BOTH the nonce consume below AND the signature verify will
    // reject. `params` here is the exact value that flows to the op handler, so
    // the digest covers the params the op actually uses.
    let params_digest =
        crate::auth::presence_gate::presence_params_digest(params).map_err(|e| {
            (
                -32030,
                format!("presence chokepoint: cannot canonicalize params for '{method}': {e}"),
            )
        })?;

    // Atomic single-use + freshness + (op_id, method, daemon_fingerprint,
    // params_digest) binding. DELETE-then-validate: a failed verify below cannot
    // leave a replayable nonce.
    store
        .consume_presence_nonce(
            &proof.nonce,
            &proof.op_id,
            &daemon_fingerprint,
            method,
            &params_digest,
        )
        .map_err(|_| {
            (
                -32030,
                format!(
                    "presence proof for '{method}' rejected: nonce unknown, expired, \
                     already used, or not bound to this op (method/params)"
                ),
            )
        })?;

    // The enrolled presence-Device key set lives in the operator identity
    // substrate (`identity-events.db`), not the main grant store — reopen it on
    // demand (the daemon idiom for `!Send` rusqlite handles). An in-memory store
    // has no durable operator identity, so we fail closed.
    let data_dir = store.data_dir().ok_or((
        -32030,
        "presence chokepoint: no data_dir; cannot load enrolled presence-Device keys".to_string(),
    ))?;
    let identity_store =
        crate::infra::identity_substrate::open_identity_store(data_dir).map_err(|e| {
            (
                -32000,
                format!("presence chokepoint: open identity store: {e}"),
            )
        })?;
    let enrolled_devices =
        crate::infra::operator_identity::active_presence_devices_under_operator_root(
            identity_store.materialized(),
        );
    if enrolled_devices.is_empty() {
        return Err((
            -32030,
            format!(
                "presence chokepoint: no enrolled presence Device under the operator root; \
                 cannot authorize widening op '{method}'"
            ),
        ));
    }

    let Some((device_id, device_public_key)) = wire_proof_matching_device(
        method,
        &daemon_fingerprint,
        &params_digest,
        &enrolled_devices,
        &proof,
    ) else {
        return Err((
            -32030,
            format!("presence signature for '{method}' did not verify against any enrolled Device"),
        ));
    };

    Ok(VerifiedPresenceProof {
        presence_authenticator_id: device_id,
        presence_public_key: device_public_key,
        op_id: proof.op_id,
        nonce: proof.nonce,
        signature: proof.signature,
        daemon_fingerprint,
        params_digest,
    })
}

/// ADR 206 §1 (AC-2/AC-3) — the **transient-KEK widening subset**: the
/// authority-MINTING widening ops that *seal under `KEK_s`* (so they genuinely
/// need the §4 scope key available to run) AND are safe to authorize off a
/// single batched widening gesture with **no standing time-window**.
///
/// When a method in this set arrives carrying a verified §1 proof (enforced by
/// [`enforce_presence_chokepoint`]) *and* an operator-supplied `scope_kek` (the
/// operator-session CLI's own `se_unwrap` output, submitted in the SAME widening
/// request), the dispatcher installs `KEK_s` TRANSIENTLY for the duration of the
/// op and EVICTS it immediately afterward — it does NOT arm the grace window or
/// leave a standing `mark_unlocked`. The op is authorized on `(verified proof +
/// op-supplied KEK_s)`, not on a standing window (AC-2: widening holds no
/// time-window state).
///
/// **Scope (deliberately narrow).** Only the minting ops that seal under
/// `KEK_s` and are safe for the transient path. Vault MEK / local-state-key
/// rotation, `sops_unwrap_dek`, and `register_session` are EXCLUDED — they have
/// their own lifecycle (rotation re-sources the interactive key; session-open
/// mints a standing lease) and must NOT ride this transient one-shot install.
///
/// **Backward compatibility.** This applies ONLY when `scope_kek` is present. A
/// widening request WITHOUT `scope_kek` takes the unchanged §4 standing-window
/// path below (`vault.se_unlock_complete` → `mark_unlocked` + grace window),
/// so the routine / session-open lane and every existing caller/test is
/// byte-for-byte unaffected.
pub(super) fn widening_transient_kek_applies(method: &str) -> bool {
    matches!(
        method,
        "create_persona"
            | "create_grant"
            | "create_composite_grant"
            | "create_standing_grant"
            | "propose_grant"
            | "save_delegation_template"
            | "resolve_approval"
            | "approval.resolve"
            | "approval_resolve"
            | "approval.narrow"
            | "approval_narrow"
            | "build_init_first_grant_receipt"
    )
}

/// Mirrors [`enforce_presence_chokepoint`]'s test-enforcement gate so the
/// transient authorize-as-operator path can NEVER engage in a build where the
/// chokepoint did not actually verify a proof. In production this is always
/// `true` (the chokepoint always enforces). Under `cfg(test)` the chokepoint
/// short-circuits to `Ok` when `PRESENCE_CHOKEPOINT_TEST_ENFORCE` is off (the
/// default) — so without this coupling a test that supplied `scope_kek` without
/// enabling enforcement would self-authorize with no verified proof. (Defense
/// against the exact test-soundness sharp edge; covered widening methods are all
/// chokepoint-enforced, never carved out.)
#[cfg(test)]
pub(super) fn presence_chokepoint_will_enforce() -> bool {
    PRESENCE_CHOKEPOINT_TEST_ENFORCE.with(|c| c.get())
}
#[cfg(not(test))]
pub(super) fn presence_chokepoint_will_enforce() -> bool {
    true
}

/// RAII guard that EVICTS a transiently-installed §4 `KEK_s` when it drops —
/// success OR failure of the op, and on any early-return path. Eviction is
/// [`crate::infra::interactive_unlock::evict_live_vault_slot`], which drops the
/// live-vault slot (the `Rc<Vault>` whose `ZeroizeOnDrop` wipes the in-memory
/// `KEK_s`). This is the AC-2 "no window" guarantee for the transient widening
/// path: the `KEK_s` the operator supplied exists ONLY for the lifetime of this
/// guard, never re-cached, never logged. (The transient install left the session
/// `Locked` and armed no window, so there is no SE session cache or presence
/// state to tear down — see the slot-only note below.)
///
/// The guard is created ONLY when this dispatch actually installed a transient
/// `KEK_s` (i.e. the §4 window was NOT already open from a prior
/// `vault.se_unlock_complete`). If a standing window was already open, the
/// transient path does not engage and this guard never exists — so the
/// transient eviction can never tear down a legitimately-open standing window.
///
/// Eviction drops the live-vault slot ONLY (the `Rc<Vault>` whose
/// `ZeroizeOnDrop` wipes the in-memory `KEK_s`). It does NOT touch session pins
/// or presence state — the transient install left the session Locked and armed
/// no window, so there is nothing else to tear down, and clobbering a
/// concurrently-open session's pin would be wrong.
pub(super) struct TransientKekEvictionGuard<'a> {
    active: bool,
    store: &'a DaemonStore,
}

impl<'a> TransientKekEvictionGuard<'a> {
    pub(super) fn active(store: &'a DaemonStore) -> Self {
        Self {
            active: true,
            store,
        }
    }

    pub(super) fn inactive(store: &'a DaemonStore) -> Self {
        Self {
            active: false,
            store,
        }
    }
}

impl Drop for TransientKekEvictionGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            crate::infra::interactive_unlock::evict_live_vault_slot(self.store);
            tracing::info!(
                "ADR 206 §1 (AC-2): evicted transient widening KEK_s after op (no standing window)"
            );
        }
    }
}

// ── KEK wrap-rotation T2 integration tests ─────────────
#[cfg(test)]
mod kek_wrap_rotation_tests {
    //! T2: in-memory `DaemonStore::open_in_memory()` paired with a
    //! temp-dir-backed identity `EventStore`. Drives
    //! `apply_revoke_wrap_mitigation` directly so the structural
    //! cascade-delete + opt-in rotation invariants land without a socket
    //! roundtrip (the on-wire `compromised` plumb-through is covered by
    //! T1 in `crates/emberlink-cli/src/device/revoke.rs`).
    use super::*;
    use core_crypto::{P256Signer, Signer};
    use core_event_types::{AttestationTier, CustodyClass, DeviceEnrolledEvent, PresenceFactor};
    use core_principals::{KeyAlgorithm, PublicKeyMaterial};
    use core_state::EventStore;
    use ember_broker::secure_enclave::{new_stub_key, se_register_stub_key};
    use tempfile::TempDir;

    use crate::infra::operator_identity::{
        OPERATOR_ROOT_ID_PREFIX, ensure_operator_identity, operator_root_id,
    };
    use crate::infra::store::DaemonStore;

    const SCOPE_KIND: &str = "operator";

    /// Synthetic P-256 device signer seeded by a deterministic scalar — same
    /// shape `operator_identity::tests::device_signer` uses, but we can't
    /// reach into another module's `#[cfg(test)]` items. Reproducing the
    /// minimal version locally is cheaper than promoting that helper.
    fn device_signer(scalar: u8) -> (P256Signer, PublicKeyMaterial) {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        let signer = P256Signer::from_scalar_bytes(&bytes).expect("scalar in range");
        let pubkey = signer.public_key().0;
        let key_id = format!("key-operator-{:02x}", scalar);
        let material = PublicKeyMaterial {
            key_id,
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: pubkey,
        };
        (signer, material)
    }

    /// SE-ECIES material for the §4 recipient slot. Each recipient gets a
    /// distinct stub label so `wrap` resolves it locally.
    fn enc_material(scalar: u8) -> (PublicKeyMaterial, String) {
        let label = format!("test-revoke-ecies-{:02x}", scalar);
        let handle = new_stub_key(&label);
        se_register_stub_key(&label, &handle);
        // Stub registry keys aren't real SEC1 points; the wrap path consults
        // the stub registry first by label, so the public_key field is
        // opaque-to-wrap. Synthesize a deterministic 65-byte stand-in.
        let mut pk = [0u8; 65];
        pk[0] = 0x04;
        pk[1] = scalar;
        let public_key = format!("p256:{}", hex::encode(pk));
        let material = PublicKeyMaterial {
            key_id: label.clone(),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key,
        };
        (material, label)
    }

    /// Bootstrap an operator identity store with a founding presence Device
    /// plus a backup presence Device. Returns the temp dir (kept alive),
    /// the open identity `EventStore`, the operator root_id, the founding
    /// signer (so tests can drive `commit_device_revoke`), and the
    /// `(founding_device_id, backup_device_id)` pair.
    fn bootstrap_two_device_identity() -> (TempDir, EventStore, String, P256Signer, String, String)
    {
        let dir = TempDir::new().expect("tempdir");
        let mut store =
            EventStore::open(dir.path().join("identity-events.db")).expect("open identity store");

        let (founding, f_material) = device_signer(0xA1);
        let ids = ensure_operator_identity(&mut store, &f_material, &founding)
            .expect("ensure operator identity");
        let root_id = ids.root_id.clone();

        // Founding presence Device row.
        let (founding_enc, _founding_enc_label) = enc_material(0xA1);
        let founding_device_id = format!(
            "device-operator-{}",
            f_material.public_key.strip_prefix("p256:").unwrap()
        );
        crate::infra::operator_identity::enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: founding_device_id.clone(),
                label: "Founding".to_string(),
                device_key: PublicKeyMaterial {
                    key_id: ids.key_id.clone(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                    public_key: f_material.public_key.clone(),
                },
                encryption_key: founding_enc,
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs_test(),
        )
        .expect("enroll founding device");

        // Backup presence Device row.
        let (backup_signer, _b_material) = device_signer(0xB2);
        let backup_device_id = "device-backup-b2".to_string();
        let (backup_enc, _backup_enc_label) = enc_material(0xB2);
        crate::infra::operator_identity::enroll_presence_device(
            &mut store,
            &ids.root_id,
            DeviceEnrolledEvent {
                root_id: ids.root_id.clone(),
                device_id: backup_device_id.clone(),
                label: "Backup".to_string(),
                device_key: PublicKeyMaterial {
                    key_id: "key-backup-b2".to_string(),
                    algorithm: KeyAlgorithm::EcdsaP256,
                    public_key: backup_signer.public_key().0,
                },
                encryption_key: backup_enc,
                custody_class: CustodyClass::Presence,
                attestation_statement: None,
                attestation_tier: AttestationTier::None,
                presence_factor: PresenceFactor::UserPresence,
            },
            &founding,
            &ids.key_id,
            now_epoch_secs_test(),
        )
        .expect("enroll backup device");

        // Sanity: the operator root resolves out of the materialized state.
        let resolved = operator_root_id(store.materialized()).expect("resolves");
        assert!(resolved.starts_with(OPERATOR_ROOT_ID_PREFIX));

        (
            dir,
            store,
            root_id,
            founding,
            founding_device_id,
            backup_device_id,
        )
    }

    fn now_epoch_secs_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Seed the daemon DB with a wrap row per active recipient under the
    /// operator-authority scope (the dev0 default §4 sealing scope), so
    /// the cascade-delete + rotation paths have something to act on.
    /// The wrap blob is the SAME bytes for every recipient — that
    /// represents "every device's wrap of the SAME KEK_s," the exact
    /// shape that makes the compromise scenario reachable.
    fn seed_wraps(
        daemon_store: &DaemonStore,
        identity_store: &EventStore,
        root_id: &str,
        wrap_blob: &[u8],
    ) {
        let recipients = crate::infra::presence_seal::resolve_authorized_kek_recipients(
            identity_store.materialized(),
        );
        for r in &recipients {
            daemon_store
                .write_presence_scope_kek_wrap(
                    SCOPE_KIND,
                    root_id,
                    r.device_id(),
                    r.key_id(),
                    wrap_blob,
                )
                .expect("seed wrap");
        }
        // Must seed at least the 2-device pair.
        assert!(
            recipients.len() >= 2,
            "fixture must seed at least the 2-device authority set"
        );
    }

    /// Append a `DeviceRevoked` event for `device_id` under the operator
    /// root via the production `commit_device_revoke` helper so the
    /// materialized state correctly excludes the revoked Device from
    /// `resolve_authorized_kek_recipients` — exactly mirroring the
    /// production sequencing inside `handle_identity_device_revoke`
    /// where the event commits BEFORE the wrap-side mitigation runs.
    fn run_commit_device_revoke(
        identity_store: &mut EventStore,
        founding: &P256Signer,
        device_id: &str,
        reason: &str,
    ) {
        use core_crypto::{DOMAIN_EVENT, PublicKey, sign_with_context};
        let founding_pub = PublicKey(founding.public_key().0);
        let plan = crate::infra::operator_identity::device_revoke_plan(
            identity_store,
            &founding_pub,
            device_id,
            reason,
        )
        .expect("revoke plan");
        let sig = sign_with_context(DOMAIN_EVENT, founding, &plan.step.signing_bytes);
        crate::infra::operator_identity::commit_device_revoke(
            identity_store,
            &founding_pub,
            device_id,
            reason,
            sig,
            now_epoch_secs_test(),
        )
        .expect("commit revoke");
    }

    /// AC-1 / AC-4 (routine path): a non-compromised revoke runs the
    /// always-on cascade-delete of the revoked Device's wrap and does NOT
    /// rotate `KEK_s`. The surviving devices' wraps are unchanged — they
    /// still decrypt to the SAME `KEK_s` they did before.
    #[test]
    fn routine_revoke_drops_only_the_revoked_devices_wrap() {
        let (_dir, mut identity_store, root_id, founding, _founding_id, backup_id) =
            bootstrap_two_device_identity();
        let daemon_store = DaemonStore::open_in_memory().unwrap();
        let original_blob = b"original-kek-wrap-bytes".to_vec();
        seed_wraps(&daemon_store, &identity_store, &root_id, &original_blob);

        // Drive the production `commit_device_revoke` so the materialized
        // state reflects the revoke before the wrap-side mitigation runs
        // (production sequencing in `handle_identity_device_revoke`).
        run_commit_device_revoke(&mut identity_store, &founding, &backup_id, "routine retire");

        let (rotation_emitted, wraps_dropped) = apply_revoke_wrap_mitigation(
            &daemon_store,
            &identity_store,
            &root_id,
            &backup_id,
            false, // routine — NOT compromised
            "routine retire",
        )
        .expect("mitigation runs");

        assert!(
            !rotation_emitted,
            "routine revoke MUST NOT emit a kek.rotation receipt"
        );
        assert_eq!(
            wraps_dropped, 1,
            "exactly one wrap (the revoked Device's) was dropped"
        );

        // The revoked Device's wrap is gone; the surviving Device's wrap
        // still carries the ORIGINAL bytes (same KEK_s).
        let remaining = daemon_store
            .list_presence_scope_kek_wraps(SCOPE_KIND, &root_id)
            .unwrap();
        assert!(
            remaining.iter().all(|(dev, _, _)| dev != &backup_id),
            "revoked Device's wrap must be gone"
        );
        assert!(
            !remaining.is_empty(),
            "the surviving founding Device's wrap must remain"
        );
        for (dev, _, blob) in &remaining {
            assert_eq!(
                blob, &original_blob,
                "routine revoke does NOT rewrap surviving Device {dev}'s blob"
            );
        }
    }

    /// AC-3 (compromise path): a `--compromised` revoke runs the
    /// cascade-delete AND rotates `KEK_s`. Every surviving recipient gets
    /// a NEW wrap whose bytes differ from the original (new KEK_s wraps
    /// to fresh ciphertext under the stub ECIES path). A `kek.rotation`
    /// audit-log row is emitted alongside.
    #[test]
    fn compromised_revoke_rotates_kek_and_rewraps_survivors() {
        let (_dir, mut identity_store, root_id, founding, _founding_id, backup_id) =
            bootstrap_two_device_identity();
        let daemon_store = DaemonStore::open_in_memory().unwrap();
        let original_blob = b"compromised-kek-wrap-bytes".to_vec();
        seed_wraps(&daemon_store, &identity_store, &root_id, &original_blob);

        // Drive `commit_device_revoke` first so the materialized state
        // excludes the revoked Device from `resolve_authorized_kek_recipients`.
        run_commit_device_revoke(
            &mut identity_store,
            &founding,
            &backup_id,
            "device key leaked",
        );

        let (rotation_emitted, wraps_dropped) = apply_revoke_wrap_mitigation(
            &daemon_store,
            &identity_store,
            &root_id,
            &backup_id,
            true, // COMPROMISED — rotation runs
            "device key leaked",
        )
        .expect("mitigation runs");

        assert!(
            rotation_emitted,
            "compromised revoke MUST emit a kek.rotation receipt"
        );
        assert_eq!(
            wraps_dropped, 1,
            "the revoked Device's pre-rotation wrap was also counted in the drop"
        );

        // Revoked Device's wrap is gone.
        let after = daemon_store
            .list_presence_scope_kek_wraps(SCOPE_KIND, &root_id)
            .unwrap();
        assert!(
            after.iter().all(|(dev, _, _)| dev != &backup_id),
            "revoked Device's wrap must be gone after compromise rotation"
        );

        // Survivors' blobs MUST differ from the original (fresh KEK_s).
        // Under stub ECIES the wrap is deterministic per (label, plaintext),
        // and `generate_scope_kek` draws fresh OS entropy, so the
        // probability of a collision is cryptographically negligible.
        assert!(
            !after.is_empty(),
            "the surviving Device's wrap must persist after rotation"
        );
        for (dev, _, blob) in &after {
            assert_ne!(
                blob, &original_blob,
                "compromised revoke MUST rewrap surviving Device {dev} under a fresh KEK_s"
            );
        }

        // The `kek.rotation` audit-log row landed alongside the revoke.
        let entries = daemon_store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("kek.rotation".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert_eq!(
            entries.len(),
            1,
            "exactly one kek.rotation audit row must be emitted by the rotation path"
        );
        let row = &entries[0];
        assert_eq!(row.outcome, "success");
        let details = row.details.as_ref().expect("details");
        assert!(
            details.contains(&root_id),
            "details must carry the operator scope id; got: {details}"
        );
        assert!(
            details.contains(&backup_id),
            "details must name the revoked device; got: {details}"
        );
        assert!(
            details.contains("kek_s")
                || details.contains("KEK")
                || details.contains("surviving_recipient_count"),
            "details must carry structural rotation metadata; got: {details}"
        );
    }

    /// Rotation requested with NO surviving recipient fails closed —
    /// silently emitting a `kek.rotation` against zero recipients would
    /// be a structural lie (no Device's wrap of the new `KEK_s` exists,
    /// so no one could ever recover the rotated scope). The operator
    /// must enroll a recovery first. Construction: the operator root
    /// exists but no presence/recovery Device is enrolled yet (the
    /// 'caught mid-bootstrap' shape — a real production COMMIT would
    /// fail the last-presence-device guard up top, but the wrap-side
    /// helper's own fail-closed needs its own test).
    #[test]
    fn compromised_revoke_without_survivors_fails_closed() {
        let dir = TempDir::new().expect("tempdir");
        let mut identity_store =
            EventStore::open(dir.path().join("identity-events.db")).expect("open identity store");
        let (founding, f_material) = device_signer(0xC3);
        let ids = ensure_operator_identity(&mut identity_store, &f_material, &founding).unwrap();
        // Deliberately do NOT enroll any presence Device row — the operator
        // root + persona exist (so `operator_root_id` resolves), but
        // `devices_current` is empty so `resolve_authorized_kek_recipients`
        // returns an empty vector. This is the structural "no survivor"
        // condition the helper must fail closed on.
        assert!(
            crate::infra::presence_seal::resolve_authorized_kek_recipients(
                identity_store.materialized()
            )
            .is_empty(),
            "fixture sanity — no Device must mean no recipient"
        );

        let daemon_store = DaemonStore::open_in_memory().unwrap();
        let err = apply_revoke_wrap_mitigation(
            &daemon_store,
            &identity_store,
            &ids.root_id,
            "device-that-does-not-exist",
            true, // compromised — exercise the rotation refusal
            "compromise + no survivors",
        )
        .unwrap_err();
        assert_eq!(err.0, -32030, "no-survivor rotation must fail closed");
        assert!(
            err.1.contains("surviving recipient"),
            "error must name the structural reason; got: {}",
            err.1
        );

        // No audit row was emitted on the failure path.
        let entries = daemon_store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("kek.rotation".to_string()),
                ..Default::default()
            })
            .expect("query audit");
        assert!(
            entries.is_empty(),
            "failure path MUST NOT emit a kek.rotation receipt"
        );
    }

    /// Adversarial-review fix coverage: rotation refuses to mutate
    /// when the wrap table holds an orphan row whose Device the
    /// resolver no longer recognizes (e.g., an `AgeRecovery` recipient
    /// is in the wrap table but `resolve_authorized_kek_recipients`
    /// dropped it). Without the cross-check, the rotation would
    /// silently DELETE that orphan with no replacement wrap written.
    #[test]
    fn compromised_revoke_refuses_to_rotate_with_orphan_wrap() {
        let (_dir, mut identity_store, root_id, founding, _founding_id, backup_id) =
            bootstrap_two_device_identity();
        let daemon_store = DaemonStore::open_in_memory().unwrap();
        let original_blob = b"original-bytes".to_vec();
        seed_wraps(&daemon_store, &identity_store, &root_id, &original_blob);

        // Seed an EXTRA wrap row whose device_id the resolver doesn't
        // know about — mirrors the bug-class where a recipient row
        // outlived its event-sourced custody (e.g., a future schema
        // migration cleaned `devices_current` but missed the wrap
        // table).
        daemon_store
            .write_presence_scope_kek_wrap(
                SCOPE_KIND,
                &root_id,
                "device-orphan-x",
                "ecies-orphan-x",
                b"orphan-bytes",
            )
            .unwrap();

        run_commit_device_revoke(
            &mut identity_store,
            &founding,
            &backup_id,
            "device key leaked",
        );

        let err = apply_revoke_wrap_mitigation(
            &daemon_store,
            &identity_store,
            &root_id,
            &backup_id,
            true,
            "device key leaked",
        )
        .unwrap_err();
        assert_eq!(err.0, -32030, "orphan-row rotation must fail closed");
        assert!(
            err.1.contains("device-orphan-x"),
            "error must name the orphan device id; got: {}",
            err.1
        );

        // The pre-existing wraps (including the orphan) must be
        // UNCHANGED — the helper bails BEFORE deleting anything in
        // the rotation phase. (The cascade-delete of the revoked
        // device's wrap happened first; that is structurally
        // separate from rotation per the brief.)
        let remaining = daemon_store
            .list_presence_scope_kek_wraps(SCOPE_KIND, &root_id)
            .unwrap();
        assert!(
            remaining
                .iter()
                .any(|(dev, _, blob)| dev == "device-orphan-x" && blob == &b"orphan-bytes".to_vec()),
            "orphan wrap must still be intact after the refusal"
        );
    }

    /// Cascade-delete is idempotent: revoking a Device that never had a
    /// `presence_scope_kek` row (e.g. provisioning never ran) does not
    /// fail and reports `wraps_dropped == 0`.
    #[test]
    fn cascade_delete_is_idempotent_when_no_wrap_exists() {
        let (_dir, mut identity_store, root_id, founding, _founding_id, backup_id) =
            bootstrap_two_device_identity();
        let daemon_store = DaemonStore::open_in_memory().unwrap();
        // NOTE: no `seed_wraps` call — the wrap table is empty.

        // Run the revoke commit so the materialized state matches what
        // production would see when the helper runs.
        run_commit_device_revoke(
            &mut identity_store,
            &founding,
            &backup_id,
            "never-provisioned device retire",
        );

        let (rotation_emitted, wraps_dropped) = apply_revoke_wrap_mitigation(
            &daemon_store,
            &identity_store,
            &root_id,
            &backup_id,
            false,
            "never-provisioned device retire",
        )
        .expect("mitigation must be idempotent on empty wrap state");

        assert!(!rotation_emitted);
        assert_eq!(
            wraps_dropped, 0,
            "idempotent cascade-delete reports zero rows dropped"
        );
    }
}
