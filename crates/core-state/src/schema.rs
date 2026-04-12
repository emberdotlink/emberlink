use core_types::ValidationError;
use rusqlite::Connection;

pub(crate) const SQLITE_MIGRATION_V1: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    signer_kind TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    signer_role TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signer_public_key TEXT NOT NULL,
    payload BLOB NOT NULL,
    retention_class TEXT NOT NULL DEFAULT 'ephemeral'
);

CREATE TABLE IF NOT EXISTS event_refs (
    event_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    target_event_id TEXT NOT NULL,
    PRIMARY KEY (event_id, relation, target_event_id)
);

CREATE TABLE IF NOT EXISTS event_signatures (
    event_id TEXT NOT NULL PRIMARY KEY,
    signer TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_batches (
    batch_id TEXT NOT NULL PRIMARY KEY,
    cursor_peer_id TEXT NOT NULL,
    last_event_id TEXT
);

CREATE TABLE IF NOT EXISTS roots_current (
    root_id TEXT NOT NULL PRIMARY KEY,
    display_name TEXT NOT NULL,
    active_key_id TEXT NOT NULL,
    active_public_key TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices_current (
    device_id TEXT NOT NULL PRIMARY KEY,
    root_id TEXT NOT NULL,
    label TEXT NOT NULL,
    active_key_id TEXT NOT NULL,
    active_public_key TEXT NOT NULL,
    active_encryption_key_id TEXT NOT NULL,
    active_encryption_public_key TEXT NOT NULL,
    status TEXT NOT NULL,
    replacement_device_id TEXT
);

CREATE TABLE IF NOT EXISTS personas_current (
    persona_id TEXT NOT NULL PRIMARY KEY,
    root_id TEXT NOT NULL,
    label TEXT NOT NULL,
    disclosure_profile TEXT,
    survival_mode TEXT NOT NULL,
    active_key_id TEXT NOT NULL,
    active_public_key TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trust_edges_current (
    attestation_id TEXT NOT NULL PRIMARY KEY,
    attester TEXT NOT NULL,
    subject TEXT NOT NULL,
    domain TEXT NOT NULL,
    score REAL NOT NULL,
    recipient_bound TEXT
);

CREATE TABLE IF NOT EXISTS derived_trust_current (
    statement_id TEXT NOT NULL PRIMARY KEY,
    subject TEXT NOT NULL,
    domain TEXT NOT NULL,
    normalized_score REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_policies_current (
    root_id TEXT NOT NULL PRIMARY KEY,
    guardian_threshold INTEGER NOT NULL,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS recovery_requests_current (
    request_id TEXT NOT NULL PRIMARY KEY,
    root_id TEXT NOT NULL,
    target_device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    approval_count INTEGER NOT NULL,
    executed_scope TEXT,
    cooldown_until INTEGER,
    contest_reason TEXT,
    rejection_reason TEXT
);

CREATE TABLE IF NOT EXISTS storage_relationships_current (
    relationship_id TEXT NOT NULL PRIMARY KEY,
    local_peer_id TEXT NOT NULL,
    remote_peer_id TEXT NOT NULL,
    approved INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS storage_balances_current (
    relationship_id TEXT NOT NULL PRIMARY KEY,
    stored_bytes_delta INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS storage_manifests_current (
    manifest_id TEXT NOT NULL PRIMARY KEY,
    encrypted_root_chunk_id TEXT NOT NULL,
    chunk_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS storage_manifest_chunks_current (
    manifest_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    chunk_id TEXT NOT NULL,
    ciphertext_bytes INTEGER NOT NULL,
    PRIMARY KEY (manifest_id, ordinal),
    UNIQUE (manifest_id, chunk_id)
);

CREATE TABLE IF NOT EXISTS storage_manifest_device_access_current (
    manifest_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    wrapped_manifest_key_hex TEXT NOT NULL,
    PRIMARY KEY (manifest_id, device_id)
);

CREATE TABLE IF NOT EXISTS endpoints_current (
    peer_id TEXT NOT NULL PRIMARY KEY,
    device_id TEXT NOT NULL,
    transport_hint TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_root_associations (
    source_root_id TEXT NOT NULL,
    target_root_id TEXT NOT NULL,
    PRIMARY KEY (source_root_id, target_root_id)
);

CREATE TABLE IF NOT EXISTS private_graph_annotations (
    annotation_id TEXT NOT NULL PRIMARY KEY,
    subject TEXT NOT NULL,
    note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disclosure_overrides (
    override_id TEXT NOT NULL PRIMARY KEY,
    subject TEXT NOT NULL,
    rule TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_notes (
    peer_id TEXT NOT NULL PRIMARY KEY,
    note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watch_state (
    watcher_id TEXT NOT NULL PRIMARY KEY,
    cursor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS persona_device_access (
    persona_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    PRIMARY KEY (persona_id, device_id)
);

CREATE TABLE IF NOT EXISTS local_blocks (
    chunk_id TEXT NOT NULL PRIMARY KEY,
    ciphertext_bytes INTEGER NOT NULL,
    nonce_hex TEXT,
    ciphertext BLOB
);

CREATE TABLE IF NOT EXISTS local_vault_catalogs (
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    manifest_payload BLOB NOT NULL,
    content_key TEXT NOT NULL,
    PRIMARY KEY (owner_kind, owner_id)
);

CREATE TABLE IF NOT EXISTS local_vault_catalog_manifest_history (
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    PRIMARY KEY (owner_kind, owner_id, manifest_id)
);

CREATE TABLE IF NOT EXISTS local_manifests (
    manifest_id TEXT NOT NULL PRIMARY KEY,
    encrypted_root_chunk_id TEXT NOT NULL,
    chunk_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_manifest_chunks (
    manifest_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    chunk_id TEXT NOT NULL,
    ciphertext_bytes INTEGER NOT NULL,
    PRIMARY KEY (manifest_id, ordinal),
    UNIQUE (manifest_id, chunk_id)
);

CREATE TABLE IF NOT EXISTS local_manifest_device_access (
    manifest_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    wrapped_manifest_key_hex TEXT NOT NULL,
    PRIMARY KEY (manifest_id, device_id)
);

CREATE TABLE IF NOT EXISTS local_manifest_keys (
    manifest_id TEXT NOT NULL PRIMARY KEY,
    content_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_device_encryption_keys (
    device_id TEXT NOT NULL PRIMARY KEY,
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_presentation_templates (
    template_id TEXT NOT NULL PRIMARY KEY,
    template_payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS local_presentation_artifacts (
    artifact_id TEXT NOT NULL PRIMARY KEY,
    artifact_payload BLOB NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    grant_id TEXT
);

CREATE TABLE IF NOT EXISTS local_received_presentation_artifacts (
    artifact_id TEXT NOT NULL PRIMARY KEY,
    artifact_payload BLOB NOT NULL,
    payload_bytes BLOB NOT NULL,
    first_received_at INTEGER NOT NULL,
    last_received_at INTEGER NOT NULL,
    first_source_kind TEXT NOT NULL,
    first_source_ref TEXT NOT NULL,
    last_source_kind TEXT NOT NULL,
    last_source_ref TEXT NOT NULL,
    receipt_count INTEGER NOT NULL,
    issuer_persona_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    issuer_public_key TEXT NOT NULL,
    issuer_signature_hex TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_bindings (
    binding_id TEXT NOT NULL PRIMARY KEY,
    persona_id TEXT NOT NULL,
    adapter_kind TEXT NOT NULL,
    service_label TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    external_account_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_service_bindings_persona_id ON service_bindings(persona_id);

-- Performance indexes for FK lookups and common query patterns
CREATE INDEX IF NOT EXISTS idx_event_refs_event_id ON event_refs(event_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_subject_id ON events(subject_id);
CREATE INDEX IF NOT EXISTS idx_devices_current_root_id ON devices_current(root_id);
CREATE INDEX IF NOT EXISTS idx_personas_current_root_id ON personas_current(root_id);
CREATE INDEX IF NOT EXISTS idx_persona_device_access_device_id ON persona_device_access(device_id);
CREATE INDEX IF NOT EXISTS idx_local_artifacts_owner ON local_presentation_artifacts(owner_kind, owner_id);
CREATE INDEX IF NOT EXISTS idx_received_artifacts_issuer ON local_received_presentation_artifacts(issuer_persona_id);

CREATE TABLE IF NOT EXISTS access_grants (
    grant_id TEXT NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    issuing_persona_id TEXT NOT NULL,
    recipient_kind TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    recipient_profile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    mode TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    not_before INTEGER,
    expires_at INTEGER,
    renewable_until INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT,
    last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_grants_persona ON access_grants(issuing_persona_id);
CREATE INDEX IF NOT EXISTS idx_grants_recipient ON access_grants(recipient_kind, recipient_id);
CREATE INDEX IF NOT EXISTS idx_grants_status ON access_grants(status);

CREATE TABLE IF NOT EXISTS access_grant_history (
    history_id TEXT NOT NULL PRIMARY KEY,
    grant_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    action TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    capabilities_snapshot TEXT,
    note TEXT
);

CREATE INDEX IF NOT EXISTS idx_grant_history_grant_id ON access_grant_history(grant_id);

CREATE TABLE IF NOT EXISTS grant_offers (
    offer_id TEXT NOT NULL PRIMARY KEY,
    issuer_persona_id TEXT NOT NULL,
    ephemeral_public_key_hex TEXT NOT NULL,
    sealed_payload_hex TEXT NOT NULL,
    relay_hint TEXT,
    expires_at INTEGER NOT NULL,
    conditions_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending',
    recipient_persona_id TEXT,
    claim_response_hex TEXT,
    claimed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_grant_offers_issuer ON grant_offers(issuer_persona_id);
CREATE INDEX IF NOT EXISTS idx_grant_offers_status ON grant_offers(status);

CREATE TABLE IF NOT EXISTS badges (
    badge_id TEXT NOT NULL PRIMARY KEY,
    issuer_persona_id TEXT NOT NULL,
    recipient_persona_id TEXT NOT NULL,
    badge_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    evidence_type TEXT,
    evidence_payload_hex TEXT,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER,
    status TEXT NOT NULL DEFAULT 'active',
    revoked_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_badges_issuer ON badges(issuer_persona_id);
CREATE INDEX IF NOT EXISTS idx_badges_recipient ON badges(recipient_persona_id);
CREATE INDEX IF NOT EXISTS idx_badges_badge_type ON badges(badge_type);
CREATE INDEX IF NOT EXISTS idx_badges_status ON badges(status);

CREATE TABLE IF NOT EXISTS badge_disputes (
    dispute_id TEXT NOT NULL PRIMARY KEY,
    target_badge_id TEXT NOT NULL,
    disputer_persona_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT
);

CREATE INDEX IF NOT EXISTS idx_badge_disputes_target ON badge_disputes(target_badge_id);
CREATE INDEX IF NOT EXISTS idx_badge_disputes_disputer ON badge_disputes(disputer_persona_id);

-- Local-only badge visibility preferences (never crosses disclosure boundary, design).
-- Default visibility is hidden (0); the owner explicitly shows badges in their gallery.
CREATE TABLE IF NOT EXISTS badge_visibility (
    badge_id TEXT NOT NULL,
    persona_id TEXT NOT NULL,
    visible INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (badge_id, persona_id)
);

CREATE INDEX IF NOT EXISTS idx_badge_visibility_persona ON badge_visibility(persona_id);

CREATE TABLE IF NOT EXISTS credential_deposits (
    deposit_id TEXT NOT NULL PRIMARY KEY,
    grant_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    encrypted_blocks_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_credential_deposits_grant ON credential_deposits(grant_id);

CREATE TABLE IF NOT EXISTS approval_requests (
    request_id TEXT NOT NULL PRIMARY KEY,
    requester_id TEXT NOT NULL,
    requester_label TEXT,
    requested_scope_json TEXT NOT NULL,
    requested_duration_secs INTEGER,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL,
    resolved_at INTEGER,
    resolver_id TEXT,
    narrowed_scope_json TEXT,
    denial_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_requester ON approval_requests(requester_id);
"#;

pub(crate) fn ensure_runtime_columns(conn: &Connection) -> Result<(), ValidationError> {
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE trust_edges_current ADD COLUMN recipient_bound TEXT",
            [],
        ),
        "ensure trust_edges_current recipient_bound column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE endpoints_current ADD COLUMN device_id TEXT",
            [],
        ),
        "ensure endpoints_current device_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE devices_current ADD COLUMN active_encryption_key_id TEXT",
            [],
        ),
        "ensure devices_current active_encryption_key_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE devices_current ADD COLUMN active_encryption_public_key TEXT",
            [],
        ),
        "ensure devices_current active_encryption_public_key column",
    )?;
    allow_duplicate_column(
        conn.execute("ALTER TABLE local_blocks ADD COLUMN nonce_hex TEXT", []),
        "ensure local_blocks nonce_hex column",
    )?;
    allow_duplicate_column(
        conn.execute("ALTER TABLE local_blocks ADD COLUMN ciphertext BLOB", []),
        "ensure local_blocks ciphertext column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_presentation_artifacts ADD COLUMN owner_kind TEXT NOT NULL DEFAULT ''",
            [],
        ),
        "ensure local_presentation_artifacts owner_kind column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_presentation_artifacts ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''",
            [],
        ),
        "ensure local_presentation_artifacts owner_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_presentation_artifacts ADD COLUMN template_id TEXT NOT NULL DEFAULT ''",
            [],
        ),
        "ensure local_presentation_artifacts template_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_presentation_artifacts ADD COLUMN grant_id TEXT",
            [],
        ),
        "ensure local_presentation_artifacts grant_id column",
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_local_artifacts_grant ON local_presentation_artifacts(grant_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure grant_id index: {err}")))?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_received_presentation_artifacts ADD COLUMN issuer_persona_id TEXT",
            [],
        ),
        "ensure local_received_presentation_artifacts issuer_persona_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_received_presentation_artifacts ADD COLUMN issuer_key_id TEXT",
            [],
        ),
        "ensure local_received_presentation_artifacts issuer_key_id column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_received_presentation_artifacts ADD COLUMN issuer_public_key TEXT",
            [],
        ),
        "ensure local_received_presentation_artifacts issuer_public_key column",
    )?;
    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE local_received_presentation_artifacts ADD COLUMN issuer_signature_hex TEXT",
            [],
        ),
        "ensure local_received_presentation_artifacts issuer_signature_hex column",
    )?;

    allow_duplicate_column(
        conn.execute(
            "ALTER TABLE grant_offers ADD COLUMN conditions_json TEXT NOT NULL DEFAULT '[]'",
            [],
        ),
        "ensure grant_offers conditions_json column",
    )?;

    // Ensure access_grants tables exist for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS access_grants (
            grant_id TEXT NOT NULL PRIMARY KEY,
            version INTEGER NOT NULL DEFAULT 1,
            issuing_persona_id TEXT NOT NULL,
            recipient_kind TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_profile TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            mode TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            label TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            not_before INTEGER,
            expires_at INTEGER,
            renewable_until INTEGER,
            revoked_at INTEGER,
            revoked_reason TEXT,
            last_used_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_grants_persona ON access_grants(issuing_persona_id);
        CREATE INDEX IF NOT EXISTS idx_grants_recipient ON access_grants(recipient_kind, recipient_id);
        CREATE INDEX IF NOT EXISTS idx_grants_status ON access_grants(status);
        CREATE TABLE IF NOT EXISTS access_grant_history (
            history_id TEXT NOT NULL PRIMARY KEY,
            grant_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            action TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            capabilities_snapshot TEXT,
            note TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_grant_history_grant_id ON access_grant_history(grant_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure access_grants tables: {err}")))?;

    // Ensure service_bindings table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS service_bindings (
            binding_id TEXT NOT NULL PRIMARY KEY,
            persona_id TEXT NOT NULL,
            adapter_kind TEXT NOT NULL,
            service_label TEXT NOT NULL,
            endpoint TEXT NOT NULL DEFAULT '',
            external_account_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_service_bindings_persona_id ON service_bindings(persona_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure service_bindings table: {err}")))?;

    // Ensure badges table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS badges (
            badge_id TEXT NOT NULL PRIMARY KEY,
            issuer_persona_id TEXT NOT NULL,
            recipient_persona_id TEXT NOT NULL,
            badge_type TEXT NOT NULL,
            display_name TEXT NOT NULL,
            evidence_type TEXT,
            evidence_payload_hex TEXT,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER,
            status TEXT NOT NULL DEFAULT 'active',
            revoked_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_badges_issuer ON badges(issuer_persona_id);
        CREATE INDEX IF NOT EXISTS idx_badges_recipient ON badges(recipient_persona_id);
        CREATE INDEX IF NOT EXISTS idx_badges_badge_type ON badges(badge_type);
        CREATE INDEX IF NOT EXISTS idx_badges_status ON badges(status);",
    )
    .map_err(|err| ValidationError::new(format!("ensure badges table: {err}")))?;

    // Ensure badge_visibility table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS badge_visibility (
            badge_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            visible INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (badge_id, persona_id)
        );
        CREATE INDEX IF NOT EXISTS idx_badge_visibility_persona ON badge_visibility(persona_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure badge_visibility table: {err}")))?;

    // Ensure badge_disputes table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS badge_disputes (
            dispute_id TEXT NOT NULL PRIMARY KEY,
            target_badge_id TEXT NOT NULL,
            disputer_persona_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_badge_disputes_target ON badge_disputes(target_badge_id);
        CREATE INDEX IF NOT EXISTS idx_badge_disputes_disputer ON badge_disputes(disputer_persona_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure badge_disputes table: {err}")))?;

    // Ensure grant_offers table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS grant_offers (
            offer_id TEXT NOT NULL PRIMARY KEY,
            issuer_persona_id TEXT NOT NULL,
            ephemeral_public_key_hex TEXT NOT NULL,
            sealed_payload_hex TEXT NOT NULL,
            relay_hint TEXT,
            expires_at INTEGER NOT NULL,
            conditions_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            recipient_persona_id TEXT,
            claim_response_hex TEXT,
            claimed_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_grant_offers_issuer ON grant_offers(issuer_persona_id);
        CREATE INDEX IF NOT EXISTS idx_grant_offers_status ON grant_offers(status);",
    )
    .map_err(|err| ValidationError::new(format!("ensure grant_offers table: {err}")))?;

    // Ensure credential_deposits table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS credential_deposits (
            deposit_id TEXT NOT NULL PRIMARY KEY,
            grant_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            encrypted_blocks_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_at INTEGER NOT NULL,
            expires_at INTEGER,
            revoked_at INTEGER,
            revoked_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_credential_deposits_grant ON credential_deposits(grant_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure credential_deposits table: {err}")))?;

    // Ensure approval_requests table exists for existing databases.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS approval_requests (
            request_id TEXT NOT NULL PRIMARY KEY,
            requester_id TEXT NOT NULL,
            requester_label TEXT,
            requested_scope_json TEXT NOT NULL,
            requested_duration_secs INTEGER,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            resolved_at INTEGER,
            resolver_id TEXT,
            narrowed_scope_json TEXT,
            denial_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
        CREATE INDEX IF NOT EXISTS idx_approval_requests_requester ON approval_requests(requester_id);",
    )
    .map_err(|err| ValidationError::new(format!("ensure approval_requests table: {err}")))?;

    Ok(())
}

pub(crate) fn allow_duplicate_column(
    result: rusqlite::Result<usize>,
    context: &str,
) -> Result<(), ValidationError> {
    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            let message = err.to_string();
            if message.contains("duplicate column name") {
                Ok(())
            } else {
                Err(ValidationError::new(format!("{context}: {message}")))
            }
        }
    }
}
