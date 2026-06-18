pub(crate) const SQLITE_INIT_DDL: &str = r#"
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
    -- Per-root monotonic sequence number of the referenced edge. This is part of
    -- the canonical signing pre-image (`EventRef` → `.seq=` in core-events), so it
    -- MUST round-trip through persistence or a reloaded chain fails external
    -- `verify_chain` (ADR 200 AC-1). Defaulted for rows written before the column
    -- existed; the idempotent ADD COLUMN migration in `from_connection` backfills
    -- the column on pre-existing databases.
    seq INTEGER NOT NULL DEFAULT 0,
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
    replacement_device_id TEXT,
    -- ADR 200: key-custody class (daemon|presence|co-authority|container) and
    -- the raw vendor attestation statement proving it (NULL for daemon-class).
    custody_class TEXT NOT NULL DEFAULT 'daemon',
    attestation_statement TEXT,
    -- ADR 200 §3 two-axis model: attestation_tier (none|genuine_app|vendor_hw) is
    -- the CLAIMED attestation strength (authority reads the tier verify_chain
    -- proves, never this column blind); presence_factor (unattended|user_presence|
    -- biometric|hardware_touch) is the use-time human-presence gate.
    attestation_tier TEXT NOT NULL DEFAULT 'none',
    presence_factor TEXT NOT NULL DEFAULT 'unattended'
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

-- ADR 187 §10b / ADR 186: structured claim-event action identity for
-- Authority Catalog service rollups. `legacy_flat=1` marks rows whose old
-- flat `tool` string could not be deterministically decomposed.
CREATE TABLE IF NOT EXISTS claim_events (
    event_id TEXT NOT NULL PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    claim_kind TEXT NOT NULL,
    tool TEXT NOT NULL,
    action_plugin_address TEXT,
    action_key TEXT,
    action_version TEXT,
    runner_class TEXT,
    execution_domain TEXT,
    materialization_class TEXT,
    legacy_flat INTEGER NOT NULL DEFAULT 0,
    persona_id TEXT,
    grant_id TEXT,
    input_hash TEXT NOT NULL,
    input_redacted_json TEXT NOT NULL,
    resolved_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claim_events_plugin_time
    ON claim_events(action_plugin_address, occurred_at);
CREATE INDEX IF NOT EXISTS idx_claim_events_action_full
    ON claim_events(action_plugin_address, action_key, action_version);

-- Performance indexes for FK lookups and common query patterns
CREATE INDEX IF NOT EXISTS idx_event_refs_event_id ON event_refs(event_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_subject_id ON events(subject_id);
CREATE INDEX IF NOT EXISTS idx_devices_current_root_id ON devices_current(root_id);
CREATE INDEX IF NOT EXISTS idx_personas_current_root_id ON personas_current(root_id);
CREATE INDEX IF NOT EXISTS idx_persona_device_access_device_id ON persona_device_access(device_id);
CREATE INDEX IF NOT EXISTS idx_local_artifacts_owner ON local_presentation_artifacts(owner_kind, owner_id);
CREATE INDEX IF NOT EXISTS idx_local_artifacts_grant ON local_presentation_artifacts(grant_id);
CREATE INDEX IF NOT EXISTS idx_received_artifacts_issuer ON local_received_presentation_artifacts(issuer_persona_id);

-- ADR 073 — composite grant statements shape.
-- blocks_json holds the full signed block chain; per-statement budget +
-- conditions live inside. Envelope columns (status, mode, expires_at) are
-- derived projections stored for indexing/listing convenience.
CREATE TABLE IF NOT EXISTS access_grants (
    grant_id TEXT NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    issuing_persona_id TEXT NOT NULL,
    recipient_kind TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    recipient_profile TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    mode TEXT NOT NULL,
    blocks_json TEXT NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT,
    last_used_at INTEGER,
    resource_types_csv TEXT NOT NULL DEFAULT '',
    attestation_json TEXT NOT NULL DEFAULT '{"status":"unattested_local_dev"}',
    skill_ref_json TEXT
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
    blocks_snapshot TEXT,
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

-- Local-only badge visibility preferences (never crosses disclosure boundary, ADR 008).
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
    denial_reason TEXT,
    skill_ref_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approval_requests_requester ON approval_requests(requester_id);

CREATE TABLE IF NOT EXISTS credential_access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id    TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    accessed_at INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    outcome     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_access_log_grant ON credential_access_log(grant_id);
CREATE INDEX IF NOT EXISTS idx_credential_access_log_agent ON credential_access_log(agent_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::{HashMap, HashSet};

    /// Snapshot of column names required on each table by the pre-collapse
    /// `ensure_runtime_columns` pass. If the init DDL is truly complete, every
    /// one of these must be present after running the DDL against a fresh DB.
    fn required_runtime_columns() -> HashMap<&'static str, Vec<&'static str>> {
        let mut map = HashMap::new();
        map.insert("trust_edges_current", vec!["recipient_bound"]);
        map.insert("endpoints_current", vec!["device_id"]);
        map.insert(
            "devices_current",
            vec!["active_encryption_key_id", "active_encryption_public_key"],
        );
        map.insert("local_blocks", vec!["nonce_hex", "ciphertext"]);
        map.insert(
            "local_presentation_artifacts",
            vec!["owner_kind", "owner_id", "template_id", "grant_id"],
        );
        map.insert(
            "local_received_presentation_artifacts",
            vec![
                "issuer_persona_id",
                "issuer_key_id",
                "issuer_public_key",
                "issuer_signature_hex",
            ],
        );
        map.insert("grant_offers", vec!["conditions_json"]);
        map.insert(
            "claim_events",
            vec![
                "action_plugin_address",
                "action_key",
                "action_version",
                "runner_class",
                "execution_domain",
                "materialization_class",
                "legacy_flat",
            ],
        );
        map
    }

    fn table_columns(conn: &Connection, table: &str) -> HashSet<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("prepare table_info");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query table_info");
        rows.collect::<Result<HashSet<_>, _>>()
            .expect("collect table_info")
    }

    #[test]
    fn fresh_init_ddl_includes_all_runtime_columns() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(SQLITE_INIT_DDL).expect("run init ddl");

        for (table, expected) in required_runtime_columns() {
            let columns = table_columns(&conn, table);
            for col in expected {
                assert!(
                    columns.contains(col),
                    "table {table} missing column {col} after init DDL (present: {columns:?})",
                );
            }
        }

        // Sanity: init DDL should also create the two indexes the old ensure
        // pass added out-of-band.
        let index_names: HashSet<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index'")
            .expect("prepare index list")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query indexes")
            .collect::<Result<_, _>>()
            .expect("collect indexes");
        assert!(
            index_names.contains("idx_local_artifacts_grant"),
            "expected idx_local_artifacts_grant in {index_names:?}",
        );
        assert!(
            index_names.contains("idx_credential_access_log_agent"),
            "expected idx_credential_access_log_agent in {index_names:?}",
        );
        assert!(
            index_names.contains("idx_claim_events_plugin_time"),
            "expected idx_claim_events_plugin_time in {index_names:?}",
        );
        assert!(
            index_names.contains("idx_claim_events_action_full"),
            "expected idx_claim_events_action_full in {index_names:?}",
        );
    }

    #[test]
    fn fresh_init_ddl_accepts_basic_inserts() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(SQLITE_INIT_DDL).expect("run init ddl");
        conn.execute(
            "INSERT INTO credential_access_log (grant_id, agent_id, accessed_at, scope, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["g1", "a1", 0_i64, "read", "ok"],
        )
        .expect("insert credential_access_log row");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM credential_access_log", [], |r| {
                r.get(0)
            })
            .expect("count credential_access_log rows");
        assert_eq!(count, 1);
    }

    #[test]
    fn claim_events_schema_supports_service_rollup_index_plan() {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(SQLITE_INIT_DDL).expect("run init ddl");

        let legacy_default: String = conn
            .query_row(
                "SELECT dflt_value
                   FROM pragma_table_info('claim_events')
                  WHERE name = 'legacy_flat'",
                [],
                |row| row.get(0),
            )
            .expect("legacy_flat default");
        assert_eq!(legacy_default, "0");

        conn.execute(
            "INSERT INTO claim_events
                (event_id, occurred_at, claim_kind, tool, action_plugin_address, action_key, action_version, runner_class, execution_domain, materialization_class, input_hash, input_redacted_json, resolved_json)
             VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                "evt-1",
                "2026-05-22T12:00:00Z",
                "credential_vended",
                "registry.ember.systems/ember-systems/ember-gh/pr_create@v1",
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
                "local_trusted",
                "host",
                "brokered_credential",
                "h1",
                "{}",
                "{}"
            ],
        )
        .expect("insert claim_event");

        let mut stmt = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT COUNT(*)
                   FROM claim_events
                  WHERE action_plugin_address = ?1
                    AND occurred_at >= ?2
                    AND occurred_at <= ?3
                    AND legacy_flat = 0",
            )
            .expect("prepare query plan");
        let plan = stmt
            .query_map(
                rusqlite::params![
                    "registry.ember.systems/ember-systems/ember-gh",
                    "2026-05-22T00:00:00Z",
                    "2026-05-23T00:00:00Z"
                ],
                |row| row.get::<_, String>(3),
            )
            .expect("query plan")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect query plan")
            .join("\n");
        assert!(
            plan.contains("idx_claim_events_plugin_time"),
            "expected claim_events service rollup to use plugin_time index, got:\n{plan}"
        );
    }
}
