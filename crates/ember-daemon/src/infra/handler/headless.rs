use super::*;

fn data_dir_from_sessions_dir(sessions_dir: &std::path::Path) -> std::path::PathBuf {
    sessions_dir.parent().unwrap_or(sessions_dir).join("data")
}

pub(super) fn data_dir_from_context(
    ctx: &RequestContext,
) -> Result<std::path::PathBuf, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    Ok(data_dir_from_sessions_dir(sessions_dir))
}

// HEADLESS-ENROLL-CLI-ATTESTED-B — first real local enrollment cut.
//
// Per ADR 139 §"Headless: attested device, variable enrollment".
// This slice makes `headless_enroll` truthful for the local broker
// authority seam only:
// - require a live interactive vault
// - mint a fresh random headless MEK
// - when the queued task set is fully declared against bundled
//   manifest `authority_refs`, copy only those local provider
//   families; otherwise fall back to the currently configured local
//   broker-authority subset
// - surface manifest-declared extra runtime requirements (for example
//   runtime KMS-backed Pulumi) as advisories instead of silently
//   pretending those lanes were narrowed by this local broker subset
// - persist the attested enrollment so runtime broker reloads can use
//   that subset when the interactive lane is locked
//
// Template-bound subset shaping, receipt emission, and snapshot-hash
// wiring are still follow-up work; this is intentionally narrower than
// the full ADR target but no longer a fake user surface.
pub(super) fn handle_enroll(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    use zeroize::Zeroize as _;

    presence::record_activity();
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
    let duration_seconds = match params["duration_seconds"].as_u64() {
        Some(0) => 14400, // 4h default for dev0 per ADR 139
        Some(d) => d,
        None => 14400,
    };

    // Tier ceiling — dev0 cohort: 7 days. ADR 139.
    const MAX_DURATION_DEV0_SECONDS: u64 = 7 * 24 * 3600;
    if duration_seconds > MAX_DURATION_DEV0_SECONDS {
        return Err((
            -32602,
            format!(
                "headless_enrollment_duration_exceeds_tier_ceiling: \
                 {duration_seconds} > {MAX_DURATION_DEV0_SECONDS} (dev0 ceiling)"
            ),
        ));
    }

    let data_dir = data_dir_from_context(ctx)?;
    let interactive_vault = current_vault(store, "headless_enroll")?;
    let queued_tasks = params
        .get("tasks")
        .map(preflight::parse_headless_task_input)
        .transpose()?;
    let tasks = queued_tasks.ok_or((
        -32602,
        "headless_enroll: bounded headless enrollment requires a non-empty 'tasks' declaration"
            .to_string(),
    ))?;
    if tasks.is_empty() {
        return Err((
            -32602,
            "headless_enroll: bounded headless enrollment requires a non-empty 'tasks' declaration"
                .to_string(),
        ));
    }
    let registry = preflight::bundled_construct_registry().map_err(|e| {
        (
            -32000,
            format!("load bundled construct manifest registry: {e}"),
        )
    })?;
    let authority_resolution =
        core_construct_runtime::preflight::resolve_queued_task_authority_refs(&tasks, &registry);
    let material_resolution =
        core_construct_runtime::preflight::resolve_queued_task_material_declarations(
            &tasks, &registry,
        );
    let requirement_resolution =
        core_construct_runtime::preflight::resolve_queued_task_headless_requirements(
            &tasks, &registry,
        );
    let action_identity_resolution =
        core_construct_runtime::preflight::resolve_queued_task_action_identities(&tasks, &registry);
    if !authority_resolution.fully_declared
        || !material_resolution.fully_declared
        || !requirement_resolution.fully_declared
        || !action_identity_resolution.fully_declared
    {
        return Err((
            -32000,
            "headless_enroll: queued task set is not fully declared; broad fallback is retired for headless bounded enrollment"
                .to_string(),
        ));
    }

    let authority_refs: Vec<String> = authority_resolution
        .refs_by_task
        .values()
        .flat_map(|refs| refs.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let headless_requirements: Vec<String> = requirement_resolution
        .requirements_by_task
        .values()
        .flat_map(|requirements| requirements.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !headless_requirements.is_empty() {
        return Err((
            -32000,
            format!(
                "headless_enroll: unmet headless requirements {:?}; unattended bounded enrollment refuses advisory fallback",
                headless_requirements
            ),
        ));
    }
    let delegated_material = {
        let mut material = core_events::receipt::HeadlessDelegatedMaterial::default();
        for task_material in material_resolution.materials_by_task.values() {
            material
                .vault_paths
                .extend(task_material.vault_paths.iter().cloned());
            material
                .env_passthrough
                .extend(task_material.env_passthrough.iter().cloned());
            material
                .file_env
                .extend(task_material.file_env.iter().cloned());
        }
        material.vault_paths.sort();
        material.vault_paths.dedup();
        material.env_passthrough.sort();
        material.env_passthrough.dedup();
        material.file_env.sort();
        material.file_env.dedup();
        material
    };
    let interactive_keys = crate::infra::headless_scope::list_scope_keys(
        store,
        crate::infra::vault::VaultScope::Interactive,
    )
    .map_err(|err| {
        (
            -32000,
            format!("headless_enroll: enumerate interactive authority keys: {err}"),
        )
    })?;
    let authority_keys = if authority_refs.is_empty() {
        Vec::new()
    } else {
        crate::broker::authority::local_store_authority_keys_for_refs(
            &interactive_keys,
            &authority_refs,
        )
        .map_err(|err| (-32000, format!("headless_enroll: {err}")))?
    };
    if authority_keys.is_empty()
        && delegated_material.vault_paths.is_empty()
        && delegated_material.env_passthrough.is_empty()
        && delegated_material.file_env.is_empty()
    {
        return Err((
            -32000,
            "headless_enroll: queued task set resolved to an empty delegated subset".to_string(),
        ));
    }

    let mut actions: Vec<crate::infra::template_snapshot::SnapshotActionIdentity> =
        action_identity_resolution
            .identities_by_task
            .values()
            .flat_map(|identities| identities.iter())
            .map(
                |identity| crate::infra::template_snapshot::SnapshotActionIdentity {
                    plugin_address: identity.plugin_address.clone(),
                    plugin_version: identity.plugin_version.clone(),
                    action_key: identity.action_key.clone(),
                    action_version: identity.action_version.clone(),
                },
            )
            .collect();
    actions.sort_by(|left, right| {
        (
            &left.plugin_address,
            &left.plugin_version,
            &left.action_key,
            &left.action_version,
        )
            .cmp(&(
                &right.plugin_address,
                &right.plugin_version,
                &right.action_key,
                &right.action_version,
            ))
    });
    actions.dedup_by(|left, right| {
        left.plugin_address == right.plugin_address
            && left.plugin_version == right.plugin_version
            && left.action_key == right.action_key
            && left.action_version == right.action_version
    });
    let expiry_unix = (std::time::SystemTime::now()
        + std::time::Duration::from_secs(duration_seconds))
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or(0);
    let snapshot = crate::infra::template_snapshot::EffectiveDelegatedPolicySnapshot {
        schema_version: 1,
        persona_id: persona_id.to_string(),
        posture: crate::infra::template_snapshot::SnapshotPosture::default(),
        duration_seconds,
        expiry_unix,
        actions,
        authority_refs: authority_refs.clone(),
        delegated_material: delegated_material.clone(),
        widenings: Vec::new(),
    };
    let template_snapshot_hash =
        crate::infra::template_snapshot::store_snapshot(&data_dir, &snapshot).map_err(|err| {
            (
                -32000,
                format!("headless_enroll: persist template snapshot: {err}"),
            )
        })?;

    crate::infra::attested_device::AttestedDevice::revoke_active(&data_dir, None).map_err(
        |err| {
            (
                -32000,
                format!("headless_enroll: revoke prior enrollment: {err}"),
            )
        },
    )?;
    crate::infra::headless_scope::clear_headless_scope(store).map_err(|err| {
        (
            -32000,
            format!("headless_enroll: clear prior headless scope: {err}"),
        )
    })?;

    let mut mek = [0u8; 32];
    getrandom::fill(&mut mek).map_err(|err| {
        (
            -32000,
            format!("headless_enroll: generate headless MEK: {err}"),
        )
    })?;
    // VAULT-SCOPE-MEK-SPLIT-CRYPTOGRAPHIC (B1) + adversarial CRIT-1
    // fix (2026-05-22): use `Vault::new_headless_only`. The
    // headless-runtime Vault MUST refuse Interactive-lane ops on
    // an in-memory single-key shape; `new_headless_only` sets
    // `interactive_key` to the all-zero checkpoint, and the
    // refusal gate in `seal`/`open`/`add(Interactive)` etc.
    // closes the API boundary.
    let headless_vault = crate::infra::vault::Vault::new_headless_only(mek);
    crate::infra::headless_scope::replace_headless_subset(
        &interactive_vault,
        &headless_vault,
        store,
        &authority_keys,
        &delegated_material.vault_paths,
        &delegated_material.env_passthrough,
        &delegated_material.file_env,
    )
    .map_err(|err| {
        (
            -32000,
            format!("headless_enroll: install headless authority subset: {err}"),
        )
    })?;
    let device = crate::infra::attested_device::AttestedDevice::enroll_active_with_metadata(
        &data_dir,
        persona_id,
        std::time::Duration::from_secs(duration_seconds),
        &mek,
        crate::infra::attested_device::EnrollmentMetadata {
            template_snapshot_hash: template_snapshot_hash.clone(),
            delegated_authority_refs: authority_refs.clone(),
            delegated_material: delegated_material.clone(),
            attested_device_ref: format!(
                "keychain:{}:{}",
                crate::infra::attested_device::KEYCHAIN_SERVICE,
                persona_id
            ),
        },
    )
    .map_err(|err| {
        (
            -32000,
            format!("headless_enroll: persist enrollment: {err}"),
        )
    })?;
    mek.zeroize();
    let receipt_body = core_events::receipt::HeadlessEnrollmentBody {
        enrollment_id: device.enrollment_id.clone(),
        peer_uid: ctx.peer.as_ref().map(|peer| peer.uid).unwrap_or(0),
        persona: device.persona.clone(),
        duration_seconds,
        expiry_unix: device.expiry_unix(),
        unlock_method: "touch-id".to_string(),
        template_snapshot_hash: template_snapshot_hash.clone(),
        delegated_authority_refs: authority_refs.clone(),
        delegated_material: delegated_material.clone(),
        attested_device_ref: device.attested_device_ref.clone(),
    };
    if crate::infra::receipt::emit_headless_enrollment_receipt_current(store, &receipt_body)
        .is_none()
    {
        let _ = crate::infra::attested_device::AttestedDevice::revoke_active(
            &data_dir,
            Some(&device.enrollment_id),
        );
        let _ = crate::infra::headless_scope::clear_headless_scope(store);
        return Err((
            -32000,
            "headless_enroll: failed to emit headless_enrollment receipt".to_string(),
        ));
    }

    Ok(json!({
        "enrolled": true,
        "enrollment_id": device.enrollment_id,
        "persona": device.persona,
        "expiry_unix": device.expiry_unix(),
        "authority_keys": authority_keys,
        "authority_refs": authority_refs,
        "delegated_material": delegated_material,
        "template_snapshot_hash": template_snapshot_hash,
        "attested_device_ref": device.attested_device_ref,
    }))
}

pub(super) fn handle_revoke(
    store: &DaemonStore,
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    presence::record_activity();
    let enrollment_id = params["enrollment_id"].as_str();
    let data_dir = data_dir_from_context(ctx)?;
    match crate::infra::attested_device::AttestedDevice::revoke_active(&data_dir, enrollment_id) {
        Ok(Some(device)) => {
            if let Err(err) = crate::infra::headless_scope::clear_headless_scope(store) {
                tracing::warn!(
                    error = %err,
                    "headless revoke deleted the active enrollment but failed to prune stale headless ciphertext"
                );
            }
            let receipt_body = core_events::receipt::HeadlessRevocationBody {
                peer_uid: ctx.peer.as_ref().map(|peer| peer.uid).unwrap_or(0),
                persona: device.persona.clone(),
                enrollment_id: device.enrollment_id.clone(),
                template_snapshot_hash: device.template_snapshot_hash.clone(),
                reason: "explicit".to_string(),
            };
            if crate::infra::receipt::emit_headless_revocation_receipt_current(store, &receipt_body)
                .is_none()
            {
                tracing::warn!(
                    enrollment_id = %device.enrollment_id,
                    "headless revoke completed but failed to emit headless_revocation receipt"
                );
            }
            Ok(json!({
                "revoked": true,
                "enrollment_id": device.enrollment_id,
                "persona": device.persona,
                "expiry_unix": device.expiry_unix(),
                "template_snapshot_hash": device.template_snapshot_hash,
            }))
        }
        Ok(None) => Ok(json!({
            "revoked": false,
            "active_enrollment": null,
        })),
        Err(crate::infra::attested_device::Error::EnrollmentIdMismatch { requested, active }) => {
            Err((
                -32602,
                format!(
                    "headless_revoke: requested enrollment_id '{requested}' does not match \
                     active enrollment '{active}'"
                ),
            ))
        }
        Err(e) => Err((-32000, format!("headless_revoke: {e}"))),
    }
}

pub(super) fn handle_status(ctx: &RequestContext) -> Result<Value, (i32, String)> {
    presence::record_activity();
    let data_dir = data_dir_from_context(ctx)?;
    match crate::infra::attested_device::AttestedDevice::active_status(&data_dir) {
        Ok(Some(status)) => Ok(json!({
            "active_enrollment": status,
        })),
        Ok(None) => Ok(json!({
            "active_enrollment": null,
        })),
        Err(e) => Err((-32000, format!("headless_status: {e}"))),
    }
}

// HEADLESS-PREFLIGHT-LAYER2-GAPS — Phase 1 substrate.
//
// PREFLIGHT-LAYER2-HISTORICAL
//
// Per ADR 139 §"Pre-flight scope check at enrollment" Layer 2
// (Historical): the daemon exposes the recent-gaps reader so
// the CLI's `ember headless enroll` flow can render the
// pre-flight CTA without poking the JSONL file directly. The
// gap log lives under the primary worktree's
// `.ember/engine/permission-gaps.jsonl`; the orchestrator
// (internal-automation) writes it, and the shared path + record shape
// live below both in `core_construct_runtime::permission_gaps`
// (ADR 183/184). Routing through the daemon keeps file
// discipline on one side of the socket.
//
// Authorization: read-only, then ConnectOnly principal-scoped on
// declared multi-uid tiers so one enrolled principal cannot inspect
// another principal's gap log.
pub(super) fn handle_preflight_gaps(
    ctx: &RequestContext,
    params: &Value,
) -> Result<Value, (i32, String)> {
    presence::record_activity();
    let persona = crate::infra::handlers::principal::persona_scoped_param_for_connect_only(
        ctx,
        params,
        "headless_preflight_gaps",
        "persona",
        true,
    )?
    .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
    let since_seconds = params["since_seconds"].as_u64().ok_or((
        -32602,
        "missing 'since_seconds' parameter (u64)".to_string(),
    ))?;

    let gaps = core_construct_runtime::permission_gaps::recent_gaps_for_persona(
        &persona,
        std::time::Duration::from_secs(since_seconds),
    );
    serde_json::to_value(&gaps).map_err(|e| (-32000, format!("serialize PermissionGap list: {e}")))
}
