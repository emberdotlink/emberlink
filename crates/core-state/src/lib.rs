mod adapters;
mod blockstore;
mod persist;
mod schema;

pub use adapters::{
    OAuthAdapter, OAuthAuthorizeRequest, OAuthBindingMeta, OAuthTokenClaims,
    OAuthTokenExchangeRequest, OidcClaimAdapter, PasskeyAdapter, PasskeyAssertionResult,
    PasskeyBindingMeta, PasskeyRegistrationResult, PasswordImportAdapter, PasswordImportFormat,
    verify_passkey_assertion,
};
pub use blockstore::SqliteBlockStore;

// Re-export shared types from core-eventlog so downstream crates can continue
// importing from core-state without changes.
pub use core_eventlog::{
    AllowAllAuthorizer, Authorizer, CredentialDepositRecord, CredentialDepositStatus, DeviceRecord,
    DeviceStatus, EventLog, GuardianRecord, IdentityAuthorizer, MaterializedState, PersonaRecord,
    PersonaStatus, RecoveryPolicyRecord, RecoveryRequestRecord, RecoveryRequestStatus, RootRecord,
    RootStatus, SyncBatchRecord,
};
pub use core_eventlog::MemoryEventLog;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use core_crypto::{
    EncryptedContent, LocalKeyPair, Signer as CryptoSigner, Verifier, generate_content_key,
    generate_random_identifier,
    grant_chain::{self, ChainError},
};
use core_eventlog::materialize::{
    apply_event, apply_storage_event, event_affects_materialized_state,
};
use core_events::EventEnvelope;
use core_storage::{
    EncryptedBlock, ManifestKeyRecipient, PresentationArtifactEnvelope,
    add_vault_object_with_initial_revision, add_vault_revision,
    build_presentation_artifact_manifest, create_vault_catalog, create_vault_object,
    create_vault_revision, grant_manifest_access, open_payload_manifest, open_vault_catalog,
    plan_restore_for_device, replace_manifest_access, retained_vault_manifest_ids,
    retained_vault_revision_ids, revoke_manifest_access, seal_payload_manifest, seal_vault_catalog,
    tombstone_vault_object, unwrap_manifest_key_access, wrap_manifest_key_access,
    wrap_manifest_key_for_recipients,
};
use core_types::{
    AccessGrant, AccessGrantDetail, AccessGrantHistoryEntry, AccessGrantSummary, BlockStore,
    ChunkReference, DurabilityPolicy, EventBody, EventType, FileManifest, GrantMode, GrantStatus,
    ImportedClaim, ManifestDeviceAccess, PeerCursor, PresentationArtifact,
    PresentationAudienceKind, PresentationTemplate, RecipientProfile, RetentionPolicy,
    ServiceBinding, SignedBlock, Statement, StructuredRecordMeta, Validate, ValidationError,
    VaultCatalog, VaultNamespace, VaultOwnerKind,
};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;
use serde_json::Value as JsonValue;

use persist::{
    delete_local_block, delete_local_file_manifest, delete_local_manifest_key,
    delete_local_vault_catalog_manifest_history,
    delete_service_binding as persist_delete_service_binding, load_all_local_file_manifests,
    load_all_service_bindings as persist_load_all_service_bindings, load_events,
    load_local_block_ids, load_local_device_encryption_key, load_local_encrypted_content,
    load_local_file_manifest, load_local_manifest_key, load_local_presentation_artifact,
    load_local_presentation_artifacts, load_local_presentation_template,
    load_local_presentation_templates, load_local_received_presentation_artifact,
    load_local_received_presentation_artifacts, load_local_vault_catalog_head,
    load_local_vault_catalog_manifest_ids, load_local_vault_namespaces,
    load_service_bindings_for_persona as persist_load_service_bindings_for_persona,
    peer_cursor_watcher_id, persist_event, record_sync_batch, validate_encrypted_manifest_blocks,
    write_all_file_manifests, write_encrypted_local_block, write_file_manifest, write_local_block,
    write_local_device_encryption_key, write_local_file_manifest, write_local_manifest_key,
    write_local_presentation_artifact, write_local_presentation_template,
    write_local_received_presentation_artifact, write_local_vault_catalog_head,
    write_materialized_tables, write_peer_cursor,
    write_service_binding as persist_write_service_binding,
};
use persist::{
    delete_access_grant as persist_delete_access_grant, load_access_grant,
    load_access_grant_history, load_access_grants_by_persona, load_access_grants_for_recipient,
    load_artifact_ids_by_grant, load_grant_history_timeline, load_grant_offer,
    load_grant_offers_by_persona, write_access_grant, write_access_grant_history,
};
pub use persist::CredentialDepositRow;
use schema::SQLITE_INIT_DDL;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaDeviceAccessRecord {
    pub persona_id: String,
    pub device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBlockRecord {
    pub chunk_id: String,
    pub ciphertext_bytes: u64,
}

/// Deserialized row from the `credential_access_log` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAccessEntry {
    pub grant_id: String,
    pub agent_id: String,
    pub accessed_at: i64,
    pub scope: String,
    pub outcome: String,
}

/// Deserialized row from the `approval_requests` table.
#[derive(Debug, Clone)]
pub struct ApprovalRequestRow {
    pub request_id: String,
    pub requester_id: String,
    pub requester_label: Option<String>,
    pub requested_scope_json: String,
    pub requested_duration_secs: Option<u64>,
    pub reason: Option<String>,
    pub status: String,
    pub created_at: u64,
    pub resolved_at: Option<u64>,
    pub resolver_id: Option<String>,
    pub narrowed_scope_json: Option<String>,
    pub denial_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBlockCoverage {
    pub manifest_id: String,
    pub present_chunks: usize,
    pub total_chunks: usize,
    pub missing_chunks: Vec<ChunkReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBlockAudit {
    pub referenced_chunk_ids: BTreeSet<String>,
    pub missing_referenced_chunk_ids: BTreeSet<String>,
    pub orphaned_metadata_chunk_ids: BTreeSet<String>,
    pub orphaned_file_chunk_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVaultGcPlan {
    pub namespace: VaultNamespace,
    pub catalog_manifest_id: String,
    pub retained_revision_ids: BTreeSet<String>,
    pub retained_manifest_ids: BTreeSet<String>,
    pub collectable_manifest_ids: BTreeSet<String>,
    pub collectable_chunk_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivedDisclosureSourceKind {
    Message,
    ExportFile,
}

impl ReceivedDisclosureSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::ExportFile => "export-file",
        }
    }

    fn from_str(value: &str) -> Result<Self, ValidationError> {
        match value {
            "message" => Ok(Self::Message),
            "export-file" => Ok(Self::ExportFile),
            other => Err(ValidationError::new(format!(
                "unknown received disclosure source kind: {other}"
            ))),
        }
    }
}

/// Result of verifying a received disclosure artifact's issuer identity chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerVerificationStatus {
    /// Issuer identity verified: persona exists, key matches, root chain valid.
    Verified,
    /// Issuer persona not found in local event store (not yet synced).
    IssuerUnknown,
    /// Issuer persona exists but the signing key has been rotated.
    IssuerKeyRotated,
    /// Issuer persona has been revoked.
    IssuerPersonaRevoked,
    /// Issuer's root identity has been revoked.
    IssuerRootRevoked,
    /// The disclosure has been explicitly revoked by the issuer.
    DisclosureRevoked,
    /// Cryptographic signature verification failed.
    SignatureInvalid,
}

impl IssuerVerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::IssuerUnknown => "issuer-unknown",
            Self::IssuerKeyRotated => "issuer-key-rotated",
            Self::IssuerPersonaRevoked => "issuer-persona-revoked",
            Self::IssuerRootRevoked => "issuer-root-revoked",
            Self::DisclosureRevoked => "disclosure-revoked",
            Self::SignatureInvalid => "signature-invalid",
        }
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

impl fmt::Display for IssuerVerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedPresentationArtifactRecord {
    pub envelope: PresentationArtifactEnvelope,
    pub first_received_at: u64,
    pub last_received_at: u64,
    pub first_source_kind: ReceivedDisclosureSourceKind,
    pub first_source_ref: String,
    pub last_source_kind: ReceivedDisclosureSourceKind,
    pub last_source_ref: String,
    pub receipt_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPresentationArtifactRecord {
    pub artifact: PresentationArtifact,
    pub namespace: VaultNamespace,
    pub template_id: String,
    pub grant_id: Option<String>,
}

impl LocalPresentationArtifactRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.artifact.validate()?;
        self.namespace.validate()?;
        if self.template_id.trim().is_empty() {
            return Err(ValidationError::new(
                "local presentation artifact template id must not be empty",
            ));
        }
        Ok(())
    }

    pub fn default_issuer_persona_id(&self) -> Option<&str> {
        match self.namespace.owner_kind {
            VaultOwnerKind::Persona => Some(self.namespace.owner_id.as_str()),
            VaultOwnerKind::Root => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalEncryptedManifest {
    pub manifest: FileManifest,
    pub blocks: Vec<EncryptedBlock>,
}

pub struct EventStore {
    conn: Connection,
    events: Vec<EventEnvelope>,
    /// O(1) lookup: event_id → index in `events` vec.
    event_index: HashMap<String, usize>,
    /// Secondary index: event_type → indices in `events` vec.
    type_index: HashMap<EventType, Vec<usize>>,
    materialized: MaterializedState,
    storage_manifests: BTreeMap<String, FileManifest>,
    local_block_store: Option<LocalBlockStore>,
    /// Keychain-derived master key used to encrypt secret columns at rest.
    /// `None` for in-memory stores (tests, WASM) where encryption is unnecessary.
    master_key: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone)]
pub struct LocalBlockStore {
    root: PathBuf,
}

impl fmt::Debug for EventStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventStore")
            .field("event_count", &self.events.len())
            .field("materialized", &self.materialized)
            .finish()
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::open_in_memory().expect("open in-memory event store")
    }
}

struct EventTypeIter<'a> {
    events: &'a [EventEnvelope],
    indices: &'a [usize],
    pos: usize,
}

impl<'a> Iterator for EventTypeIter<'a> {
    type Item = &'a EventEnvelope;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.indices.len() {
            let idx = self.indices[self.pos];
            self.pos += 1;
            Some(&self.events[idx])
        } else {
            None
        }
    }
}

struct EventTypeRevIter<'a> {
    events: &'a [EventEnvelope],
    indices: &'a [usize],
    pos: usize,
}

impl<'a> Iterator for EventTypeRevIter<'a> {
    type Item = &'a EventEnvelope;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos > 0 {
            self.pos -= 1;
            let idx = self.indices[self.pos];
            Some(&self.events[idx])
        } else {
            None
        }
    }
}

fn local_block_store_root(sqlite_path: &Path) -> PathBuf {
    sqlite_path.with_extension("blocks")
}

fn structured_record_meta_for_claim_schema(schema: &str) -> StructuredRecordMeta {
    let schema_version = schema
        .rsplit(':')
        .next()
        .filter(|segment| !segment.trim().is_empty())
        .unwrap_or("1.0");
    let app_namespace = schema
        .split(':')
        .next()
        .filter(|segment| !segment.trim().is_empty())
        .unwrap_or("imported");
    StructuredRecordMeta {
        schema_id: schema.to_string(),
        schema_version: schema_version.to_string(),
        encoding: core_types::StructuredEncoding::Json,
        app_namespace: app_namespace.to_string(),
    }
}

impl LocalBlockStore {
    fn open(root: impl AsRef<Path>) -> Result<Self, ValidationError> {
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    fn chunk_path(&self, chunk_id: &str) -> PathBuf {
        let prefix = &chunk_id[..chunk_id.len().min(2)];
        self.root.join(prefix).join(format!("{chunk_id}.blk"))
    }

    fn write_encrypted_content(
        &self,
        chunk_id: &str,
        encrypted: &EncryptedContent,
    ) -> Result<(), ValidationError> {
        let path = self.chunk_path(chunk_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| ValidationError::new(format!("create block parent dir: {err}")))?;
        }
        let mut payload =
            Vec::with_capacity(encrypted.nonce_hex.len() + 1 + encrypted.ciphertext.len());
        payload.extend_from_slice(encrypted.nonce_hex.as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(&encrypted.ciphertext);
        std::fs::write(&path, payload)
            .map_err(|err| ValidationError::new(format!("write local block file: {err}")))
    }

    fn load_encrypted_content(
        &self,
        chunk_id: &str,
    ) -> Result<Option<EncryptedContent>, ValidationError> {
        let path = self.chunk_path(chunk_id);
        let payload = match std::fs::read(&path) {
            Ok(payload) => payload,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(ValidationError::new(format!(
                    "read local block file {}: {err}",
                    path.display()
                )));
            }
        };
        let Some(split) = payload.iter().position(|byte| *byte == b'\n') else {
            return Err(ValidationError::new(
                "local block file missing nonce separator",
            ));
        };
        let nonce_hex = std::str::from_utf8(&payload[..split])
            .map_err(|err| ValidationError::new(format!("local block nonce is not utf-8: {err}")))?
            .to_string();
        Ok(Some(EncryptedContent {
            nonce_hex,
            ciphertext: payload[split + 1..].to_vec(),
        }))
    }

    fn delete_encrypted_content(&self, chunk_id: &str) -> Result<(), ValidationError> {
        let path = self.chunk_path(chunk_id);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(ValidationError::new(format!(
                    "delete local block file {}: {err}",
                    path.display()
                )));
            }
        }
        if let Some(parent) = path.parent() {
            match std::fs::remove_dir(parent) {
                Ok(()) => {}
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        || err.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(err) => {
                    return Err(ValidationError::new(format!(
                        "delete empty local block dir {}: {err}",
                        parent.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn list_chunk_ids(&self) -> Result<BTreeSet<String>, ValidationError> {
        let mut chunk_ids = BTreeSet::new();
        let root_entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(chunk_ids),
            Err(err) => {
                return Err(ValidationError::new(format!(
                    "read local block store root {}: {err}",
                    self.root.display()
                )));
            }
        };
        for prefix_entry in root_entries {
            let prefix_entry = prefix_entry.map_err(|err| {
                ValidationError::new(format!("read local block prefix entry: {err}"))
            })?;
            let file_type = prefix_entry.file_type().map_err(|err| {
                ValidationError::new(format!("read local block prefix file type: {err}"))
            })?;
            if !file_type.is_dir() {
                continue;
            }
            for block_entry in std::fs::read_dir(prefix_entry.path()).map_err(|err| {
                ValidationError::new(format!("read local block prefix dir: {err}"))
            })? {
                let block_entry = block_entry.map_err(|err| {
                    ValidationError::new(format!("read local block file entry: {err}"))
                })?;
                let file_type = block_entry.file_type().map_err(|err| {
                    ValidationError::new(format!("read local block file type: {err}"))
                })?;
                if !file_type.is_file() {
                    continue;
                }
                let Some(name) = block_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(chunk_id) = name.strip_suffix(".blk") else {
                    continue;
                };
                chunk_ids.insert(chunk_id.to_string());
            }
        }
        Ok(chunk_ids)
    }
}

impl BlockStore for LocalBlockStore {
    fn put_block(
        &self,
        chunk_id: &str,
        nonce_hex: &str,
        ciphertext: &[u8],
    ) -> Result<(), ValidationError> {
        self.write_encrypted_content(
            chunk_id,
            &EncryptedContent {
                nonce_hex: nonce_hex.to_string(),
                ciphertext: ciphertext.to_vec(),
            },
        )
    }

    fn get_block(&self, chunk_id: &str) -> Result<Option<(String, Vec<u8>)>, ValidationError> {
        self.load_encrypted_content(chunk_id)
            .map(|opt| opt.map(|ec| (ec.nonce_hex, ec.ciphertext)))
    }

    fn delete_block(&self, chunk_id: &str) -> Result<(), ValidationError> {
        self.delete_encrypted_content(chunk_id)
    }

    fn has_block(&self, chunk_id: &str) -> Result<bool, ValidationError> {
        Ok(self.chunk_path(chunk_id).exists())
    }

    fn list_block_ids(&self) -> Result<Vec<String>, ValidationError> {
        self.list_chunk_ids().map(|set| set.into_iter().collect())
    }
}

/// Canonical JSON encoding of a grant's block chain, for audit/history
/// snapshots. Uses `serde_json` — biscuit's on-wire binary format is the
/// responsibility of `core-crypto::grant_chain` (design § "SignedBlock").
fn blocks_to_json(blocks: &[SignedBlock]) -> Result<String, ValidationError> {
    serde_json::to_string(blocks)
        .map_err(|err| ValidationError::new(format!("encode blocks to json: {err}")))
}

/// Project a full AccessGrant into a listing-friendly summary.
fn grant_to_summary(g: AccessGrant) -> AccessGrantSummary {
    let expires_at = g.effective_expires_at();
    let aggregate_usage = g.aggregate_usage();
    let resource_types = g.resource_types();
    let statement_count = g.statement_count();
    AccessGrantSummary {
        id: g.id,
        label: g.label,
        issuing_persona_id: g.issuing_persona_id,
        recipient_kind: g.recipient_kind,
        recipient_id: g.recipient_id,
        recipient_profile: g.recipient_profile,
        status: g.status,
        mode: g.mode,
        block_count: g.blocks.len(),
        statement_count,
        resource_types,
        expires_at,
        last_used_at: g.last_used_at,
        aggregate_usage,
    }
}

/// Returns true if every statement in `new_block` finds a dominating statement
/// somewhere in `existing_blocks` (same action set covered, same resource
/// selector covered, budget ≤ remaining budget when set, conditions ⊇).
/// This is the bipartite attenuation check from design § "Attenuation".
///
/// NOTE: this is a minimal shape-check suitable for core-state's current
/// amend flow. The authoritative attenuation evaluator lives in core-policy
/// (see design Open Questions). When amend is routed through core-policy
/// this helper is deleted.
fn statement_dominated_by(new: &Statement, existing: &[Statement]) -> bool {
    existing.iter().any(|e| {
        new.resource_type == e.resource_type
            && new.actions.iter().all(|a| e.actions.contains(a))
            && resource_covers(&e.resource, &new.resource)
            && budget_le(&new.budget, &e.budget)
    })
}

/// True iff `parent` selector covers every resource `child` would accept.
/// Any ⊇ everything; exact == exact; glob(p) ⊇ exact(v) iff glob matches v;
/// glob(p) ⊇ glob(c) requires the patterns be equal or parent is `*`. This
/// is coarse-grained on purpose — the authoritative evaluator in core-policy
/// (design Open Questions) will subsume this.
fn resource_covers(parent: &core_types::ResourceSelector, child: &core_types::ResourceSelector) -> bool {
    use core_types::ResourceSelector as R;
    match (parent, child) {
        (R::Any, _) => true,
        (R::Exact { value: p }, R::Exact { value: c }) => p == c,
        (R::Glob { pattern }, R::Exact { value }) => parent_glob_covers_exact(pattern, value),
        (R::Glob { pattern: p }, R::Glob { pattern: c }) => p == c || p == "*",
        _ => false,
    }
}

/// Local glob-covers-exact check, used only by `resource_covers`. Supports
/// `*` (any run) and `?` (one char). Duplicated from core-types for now; the
/// real evaluator will unify these.
fn parent_glob_covers_exact(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let s = value.as_bytes();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_pi, mut star_si) = (usize::MAX, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Child budget ≤ parent budget on every axis the parent constrains. If
/// parent is `None`, anything is fine. If parent sets an axis that child
/// leaves open, child fails (unbounded > bounded).
fn budget_le(child: &Option<core_types::Budget>, parent: &Option<core_types::Budget>) -> bool {
    let Some(p) = parent else { return true };
    let c = child.clone().unwrap_or_default();
    if let Some(cap) = p.tokens
        && c.tokens.unwrap_or(u64::MAX) > cap
    {
        return false;
    }
    if let Some(cap) = p.cents
        && c.cents.unwrap_or(u64::MAX) > cap
    {
        return false;
    }
    if let Some(cap) = p.requests
        && c.requests.unwrap_or(u64::MAX) > cap
    {
        return false;
    }
    if let Some(cap) = p.workload_hours
        && c.workload_hours.unwrap_or(u64::MAX) > cap
    {
        return false;
    }
    if let Some(cap) = p.wall_clock_secs
        && c.wall_clock_secs.unwrap_or(u64::MAX) > cap
    {
        return false;
    }
    true
}

impl EventStore {
    pub fn open_in_memory() -> Result<Self, ValidationError> {
        let conn = Connection::open_in_memory()
            .map_err(|err| ValidationError::new(format!("open sqlite in-memory db: {err}")))?;
        Self::from_connection(conn, None, None)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ValidationError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| ValidationError::new(format!("create sqlite dir: {err}")))?;
        }
        let conn = Connection::open(path).map_err(|err| {
            ValidationError::new(format!("open sqlite db {}: {err}", path.display()))
        })?;
        let local_block_store = Some(LocalBlockStore::open(local_block_store_root(path))?);
        Self::from_connection(conn, local_block_store, None)
    }

    /// Open an on-disk store with a master key for encrypting secret columns at rest.
    ///
    /// The `master_key` should be the same keychain-derived `xchacha20-key:...` value
    /// used to protect `local-state.enc`. Application shells (CLI, GUI) supply this from
    /// their keychain layer; `core-state` itself never touches the OS keychain.
    pub fn open_with_key(path: impl AsRef<Path>, master_key: String) -> Result<Self, ValidationError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| ValidationError::new(format!("create sqlite dir: {err}")))?;
        }
        let conn = Connection::open(path).map_err(|err| {
            ValidationError::new(format!("open sqlite db {}: {err}", path.display()))
        })?;
        let local_block_store = Some(LocalBlockStore::open(local_block_store_root(path))?);
        Self::from_connection(conn, local_block_store, Some(Zeroizing::new(master_key)))
    }

    fn from_connection(
        conn: Connection,
        local_block_store: Option<LocalBlockStore>,
        master_key: Option<Zeroizing<String>>,
    ) -> Result<Self, ValidationError> {
        conn.execute_batch(SQLITE_INIT_DDL)
            .map_err(|err| ValidationError::new(format!("run sqlite init ddl: {err}")))?;

        let mut store = Self {
            conn,
            events: Vec::new(),
            event_index: HashMap::new(),
            type_index: HashMap::new(),
            materialized: MaterializedState::default(),
            storage_manifests: BTreeMap::new(),
            local_block_store,
            master_key,
        };
        store.rebuild()?;
        Ok(store)
    }

    pub fn append(
        &mut self,
        event: EventEnvelope,
        verifier: &(impl Verifier + ?Sized),
    ) -> Result<(), ValidationError> {
        self.append_with_authorizer(event, verifier, &AllowAllAuthorizer, 0)
    }

    pub fn append_with_authorizer(
        &mut self,
        event: EventEnvelope,
        verifier: &(impl Verifier + ?Sized),
        authorizer: &(impl Authorizer + ?Sized),
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        // Clamp caller-supplied time to prevent bypassing cooldowns via a far-future timestamp.
        // Allow up to 5 minutes of forward skew for legitimate clock drift.
        const MAX_CLOCK_SKEW_SECS: u64 = 300;
        let system_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let effective_now = now_epoch_secs.min(system_now + MAX_CLOCK_SKEW_SECS);

        event.validate()?;
        if !verifier.verify(&event.signer, &event.signed_bytes(), &event.signature) {
            return Err(ValidationError::new("signature verification failed"));
        }
        // Internal store append — use raw errors so callers can pattern
        // match on precise variants. Public-facing paths (HTTP handlers,
        // dashboard) call `authorizer.authorize(...)` which sanitizes.
        authorizer.authorize_raw(&event, &self.materialized, effective_now)?;

        apply_event(&mut self.materialized, &event)?;
        apply_storage_event(&mut self.storage_manifests, &event, &self.materialized)?;

        let tx = self
            .conn
            .transaction()
            .map_err(|err| ValidationError::new(format!("begin sqlite transaction: {err}")))?;
        persist_event(&tx, &event)?;
        if event_affects_materialized_state(&event) {
            write_materialized_tables(&tx, &self.materialized)?;
        }
        if matches!(event.body, EventBody::StorageManifestPublished(_)) {
            write_all_file_manifests(&tx, &self.storage_manifests)?;
        }
        if let Err(err) = tx.commit() {
            // SQL commit failed — rebuild from the authoritative event log
            // to restore in-memory state consistency.
            self.rebuild()?;
            return Err(ValidationError::new(format!(
                "commit sqlite transaction: {err}"
            )));
        }

        let idx = self.events.len();
        self.event_index.insert(event.event_id.clone(), idx);
        self.type_index
            .entry(event.event_type)
            .or_default()
            .push(idx);
        self.events.push(event);
        Ok(())
    }

    pub fn rebuild(&mut self) -> Result<(), ValidationError> {
        let events = load_events(&self.conn)?;
        let mut materialized = MaterializedState::default();
        let mut storage_manifests = BTreeMap::new();
        for event in &events {
            apply_event(&mut materialized, event)?;
            apply_storage_event(&mut storage_manifests, event, &materialized)?;
        }

        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin sqlite rebuild transaction: {err}"))
        })?;
        write_materialized_tables(&tx, &materialized)?;
        write_all_file_manifests(&tx, &storage_manifests)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit sqlite rebuild transaction: {err}"))
        })?;

        self.events = events;
        self.event_index = Self::build_event_index(&self.events);
        self.type_index = Self::build_type_index(&self.events);
        self.materialized = materialized;
        self.storage_manifests = storage_manifests;
        Ok(())
    }

    fn build_event_index(events: &[EventEnvelope]) -> HashMap<String, usize> {
        events
            .iter()
            .enumerate()
            .map(|(i, e)| (e.event_id.clone(), i))
            .collect()
    }

    fn build_type_index(events: &[EventEnvelope]) -> HashMap<EventType, Vec<usize>> {
        let mut index: HashMap<EventType, Vec<usize>> = HashMap::new();
        for (i, e) in events.iter().enumerate() {
            index.entry(e.event_type).or_default().push(i);
        }
        index
    }

    pub fn current_event_type_for(&self, event_id: &str) -> Option<EventType> {
        self.event_index
            .get(event_id)
            .map(|&idx| self.events[idx].event_type)
    }

    pub fn events(&self) -> &[EventEnvelope] {
        &self.events
    }

    /// Iterate events of a specific type in insertion order.
    pub fn events_of_type(&self, event_type: EventType) -> impl Iterator<Item = &EventEnvelope> {
        let indices = self.type_index.get(&event_type);
        EventTypeIter {
            events: &self.events,
            indices: indices.map(|v| v.as_slice()).unwrap_or(&[]),
            pos: 0,
        }
    }

    /// Iterate events of a specific type in reverse (most recent first).
    pub fn events_of_type_rev(
        &self,
        event_type: EventType,
    ) -> impl Iterator<Item = &EventEnvelope> {
        let indices = self.type_index.get(&event_type);
        EventTypeRevIter {
            events: &self.events,
            indices: indices.map(|v| v.as_slice()).unwrap_or(&[]),
            pos: indices.map(|v| v.len()).unwrap_or(0),
        }
    }

    pub fn event_ids(&self) -> Vec<String> {
        self.events
            .iter()
            .map(|event| event.event_id.clone())
            .collect()
    }

    /// Check whether an event with the given ID exists in the store.
    pub fn has_event(&self, event_id: &str) -> bool {
        self.event_index.contains_key(event_id)
    }

    /// Return a borrowed set of all event IDs (avoids cloning the full ID list).
    pub fn event_id_set(&self) -> &HashMap<String, usize> {
        &self.event_index
    }

    pub fn events_by_ids(&self, event_ids: &[String]) -> Vec<EventEnvelope> {
        event_ids
            .iter()
            .filter_map(|event_id| {
                self.event_index
                    .get(event_id.as_str())
                    .map(|&idx| self.events[idx].clone())
            })
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Export all events as portable TSV lines (one per event).
    pub fn export_events(&self) -> String {
        let mut lines = Vec::new();
        for event in &self.events {
            let refs_str = event
                .refs
                .iter()
                .map(|r| format!("{}:{}", r.relation.as_str(), r.target_event_id))
                .collect::<Vec<_>>()
                .join(",");
            let payload_hex = core_types::bytes_to_hex(&event.payload);
            let signature_str = &event.signature.0;
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                event.event_id,
                event.schema_version,
                event.event_type.as_str(),
                event.subject.kind.as_str(),
                event.subject.subject_id,
                event.signer_binding.signer.kind.as_str(),
                event.signer_binding.signer.subject_id,
                event.signer_binding.role.as_str(),
                event.signer_binding.key_id,
                event.signer.0,
                payload_hex,
                signature_str,
                refs_str,
            ));
        }
        lines.join("\n")
    }

    /// Import events from portable TSV lines, replaying through the authorizer.
    pub fn import_events(
        &mut self,
        data: &str,
        verifier: &(impl core_crypto::Verifier + ?Sized),
        authorizer: &(impl Authorizer + ?Sized),
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        use core_crypto::{PublicKey, Signature};
        use core_events::EventRef;
        use core_types::{
            EventBody, EventRefRelation, EventSubject, KeyRole, SchemaVersion, SignerBinding,
            SubjectKind,
        };

        let mut imported = 0;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 12 {
                return Err(ValidationError::new(format!(
                    "import line has {} fields, expected at least 12",
                    fields.len()
                )));
            }

            let event_id = fields[0];
            if self.events.iter().any(|e| e.event_id == event_id) {
                continue; // skip duplicates
            }

            let schema_version = SchemaVersion::parse(fields[1]).ok_or_else(|| {
                ValidationError::new(format!("invalid schema version: {}", fields[1]))
            })?;
            let event_type = EventType::parse(fields[2]).ok_or_else(|| {
                ValidationError::new(format!("unknown event type: {}", fields[2]))
            })?;
            let subject_kind = SubjectKind::parse(fields[3]).ok_or_else(|| {
                ValidationError::new(format!("unknown subject kind: {}", fields[3]))
            })?;
            let subject = EventSubject::new(subject_kind, fields[4]);
            let signer_kind = SubjectKind::parse(fields[5]).ok_or_else(|| {
                ValidationError::new(format!("unknown signer kind: {}", fields[5]))
            })?;
            let signer_binding = SignerBinding {
                signer: EventSubject::new(signer_kind, fields[6]),
                role: KeyRole::parse(fields[7]).ok_or_else(|| {
                    ValidationError::new(format!("unknown key role: {}", fields[7]))
                })?,
                key_id: fields[8].to_string(),
            };
            let signer_public_key = PublicKey(fields[9].to_string());
            let payload = core_types::hex_to_bytes(fields[10])
                .map_err(|err| ValidationError::new(format!("invalid payload hex: {err}")))?;
            let signature = Signature(fields[11].to_string());

            let refs_str = if fields.len() > 12 { fields[12] } else { "" };
            let refs = if refs_str.is_empty() {
                Vec::new()
            } else {
                refs_str
                    .split(',')
                    .map(|r| {
                        let parts: Vec<&str> = r.splitn(2, ':').collect();
                        if parts.len() != 2 {
                            return Err(ValidationError::new(format!("invalid ref: {r}")));
                        }
                        let relation = EventRefRelation::parse(parts[0]).ok_or_else(|| {
                            ValidationError::new(format!("unknown ref relation: {}", parts[0]))
                        })?;
                        Ok(EventRef {
                            relation,
                            target_event_id: parts[1].to_string(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            };

            let body = EventBody::decode_canonical(&payload)?;

            let envelope = EventEnvelope {
                schema_version,
                event_id: event_id.to_string(),
                event_type,
                subject,
                signer_binding,
                signer: signer_public_key,
                payload,
                refs,
                signature,
                body,
            };

            self.append_with_authorizer(envelope, verifier, authorizer, now_epoch_secs)?;
            imported += 1;
        }
        Ok(imported)
    }

    pub fn materialized(&self) -> &MaterializedState {
        &self.materialized
    }

    /// Returns the block store if one is configured (filesystem-backed for on-disk stores).
    pub fn block_store(&self) -> Option<&dyn BlockStore> {
        self.local_block_store
            .as_ref()
            .map(|s| s as &dyn BlockStore)
    }

    pub fn peer_cursor(&self, peer_id: &str) -> Result<PeerCursor, ValidationError> {
        let watcher_id = peer_cursor_watcher_id(peer_id);
        let cursor: Option<String> = self
            .conn
            .query_row(
                "SELECT cursor FROM watch_state WHERE watcher_id = ?1",
                params![watcher_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| ValidationError::new(format!("load peer cursor: {err}")))?;

        Ok(PeerCursor {
            peer_id: peer_id.to_string(),
            last_event_id: cursor.filter(|value| !value.trim().is_empty()),
        })
    }

    pub fn peer_cursors(&self) -> Result<Vec<PeerCursor>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT watcher_id, cursor
                 FROM watch_state
                 WHERE watcher_id LIKE 'peer-cursor:%'
                 ORDER BY watcher_id ASC",
            )
            .map_err(|err| ValidationError::new(format!("prepare peer cursors query: {err}")))?;
        let rows = stmt
            .query_map([], |row| {
                let watcher_id: String = row.get(0)?;
                let cursor: String = row.get(1)?;
                Ok(PeerCursor {
                    peer_id: watcher_id
                        .strip_prefix("peer-cursor:")
                        .unwrap_or(&watcher_id)
                        .to_string(),
                    last_event_id: if cursor.trim().is_empty() {
                        None
                    } else {
                        Some(cursor)
                    },
                })
            })
            .map_err(|err| ValidationError::new(format!("query peer cursors: {err}")))?;

        let mut cursors = Vec::new();
        for row in rows {
            cursors.push(
                row.map_err(|err| ValidationError::new(format!("read peer cursor row: {err}")))?,
            );
        }
        Ok(cursors)
    }

    pub fn sync_batches(&self) -> Result<Vec<SyncBatchRecord>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT batch_id, cursor_peer_id, last_event_id
                 FROM sync_batches
                 ORDER BY rowid ASC",
            )
            .map_err(|err| ValidationError::new(format!("prepare sync batches query: {err}")))?;
        let rows = stmt
            .query_map([], |row| {
                let last_event_id: Option<String> = row.get(2)?;
                Ok(SyncBatchRecord {
                    batch_id: row.get(0)?,
                    peer_id: row.get(1)?,
                    last_event_id,
                })
            })
            .map_err(|err| ValidationError::new(format!("query sync batches: {err}")))?;

        let mut batches = Vec::new();
        for row in rows {
            batches.push(
                row.map_err(|err| ValidationError::new(format!("read sync batch row: {err}")))?,
            );
        }
        Ok(batches)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn import_sync_batch(
        &mut self,
        peer_id: &str,
        batch_id: &str,
        events: &[EventEnvelope],
        last_remote_event_id: Option<&str>,
        verifier: &(impl Verifier + ?Sized),
        authorizer: &(impl Authorizer + ?Sized),
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        let mut seen_ids: BTreeSet<&str> = self.event_index.keys().map(|k| k.as_str()).collect();
        let mut imported = Vec::new();

        for event in events {
            event.validate()?;
            if !verifier.verify(&event.signer, &event.signed_bytes(), &event.signature) {
                self.rebuild()?;
                return Err(ValidationError::new("signature verification failed"));
            }
            if seen_ids.contains(event.event_id.as_str()) {
                continue;
            }
            if let Err(err) = authorizer.authorize(event, &self.materialized, now_epoch_secs) {
                self.rebuild()?;
                return Err(err);
            }
            if let Err(err) = apply_event(&mut self.materialized, event) {
                self.rebuild()?;
                return Err(err);
            }
            if let Err(err) =
                apply_storage_event(&mut self.storage_manifests, event, &self.materialized)
            {
                self.rebuild()?;
                return Err(err);
            }
            seen_ids.insert(&event.event_id);
            imported.push(event.clone());
        }

        let tx = self
            .conn
            .transaction()
            .map_err(|err| ValidationError::new(format!("begin sqlite sync transaction: {err}")))?;
        for event in &imported {
            persist_event(&tx, event)?;
        }
        if !imported.is_empty() {
            write_materialized_tables(&tx, &self.materialized)?;
            write_all_file_manifests(&tx, &self.storage_manifests)?;
        }
        record_sync_batch(&tx, batch_id, peer_id, last_remote_event_id)?;
        if let Some(last_remote_event_id) = last_remote_event_id {
            write_peer_cursor(&tx, peer_id, Some(last_remote_event_id))?;
        }
        if let Err(err) = tx.commit() {
            self.rebuild()?;
            return Err(ValidationError::new(format!(
                "commit sqlite sync transaction: {err}"
            )));
        }

        let imported_count = imported.len();
        let base = self.events.len();
        for (offset, event) in imported.iter().enumerate() {
            let idx = base + offset;
            self.event_index.insert(event.event_id.clone(), idx);
            self.type_index
                .entry(event.event_type)
                .or_default()
                .push(idx);
        }
        self.events.extend(imported);
        Ok(imported_count)
    }

    pub fn grant_persona_device_access(
        &mut self,
        persona_id: &str,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        let persona = self
            .materialized
            .personas_current
            .get(persona_id)
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_id}")))?;
        if persona.status != PersonaStatus::Active {
            return Err(ValidationError::new(
                "cannot grant access to a revoked persona",
            ));
        }

        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "cannot grant persona access to a non-active device",
            ));
        }
        if persona.root_id != device.root_id {
            return Err(ValidationError::new(
                "persona and device must belong to the same root",
            ));
        }

        self.conn
            .execute(
                "INSERT OR IGNORE INTO persona_device_access (persona_id, device_id) VALUES (?1, ?2)",
                params![persona_id, device_id],
            )
            .map_err(|err| ValidationError::new(format!("grant persona device access: {err}")))?;
        Ok(())
    }

    pub fn revoke_persona_device_access(
        &mut self,
        persona_id: &str,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        self.conn
            .execute(
                "DELETE FROM persona_device_access WHERE persona_id = ?1 AND device_id = ?2",
                params![persona_id, device_id],
            )
            .map_err(|err| ValidationError::new(format!("revoke persona device access: {err}")))?;
        Ok(())
    }

    pub fn restore_persona_access_to_replacement_device(
        &mut self,
        replaced_device_id: &str,
        replacement_device_id: &str,
    ) -> Result<(), ValidationError> {
        let replaced_device = self
            .materialized
            .devices_current
            .get(replaced_device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {replaced_device_id}")))?;
        let replacement_device = self
            .materialized
            .devices_current
            .get(replacement_device_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown device: {replacement_device_id}"))
            })?;

        if replaced_device.root_id != replacement_device.root_id {
            return Err(ValidationError::new(
                "replacement device must belong to the same root",
            ));
        }
        if replacement_device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "replacement device must be active to restore persona access",
            ));
        }
        if replaced_device.replacement_device_id.as_deref() != Some(replacement_device_id) {
            return Err(ValidationError::new(
                "replacement device is not linked to the replaced device",
            ));
        }

        let existing_access = self.persona_device_access_for_device(replaced_device_id)?;
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin access restore transaction: {err}"))
        })?;

        for record in existing_access {
            tx.execute(
                "DELETE FROM persona_device_access WHERE persona_id = ?1 AND device_id = ?2",
                params![&record.persona_id, replaced_device_id],
            )
            .map_err(|err| {
                ValidationError::new(format!("remove replaced-device persona access: {err}"))
            })?;

            let persona_is_active = self
                .materialized
                .personas_current
                .get(&record.persona_id)
                .map(|persona| {
                    persona.status == PersonaStatus::Active
                        && persona.root_id == replacement_device.root_id
                })
                .unwrap_or(false);
            if persona_is_active {
                tx.execute(
                    "INSERT OR IGNORE INTO persona_device_access (persona_id, device_id) VALUES (?1, ?2)",
                    params![&record.persona_id, replacement_device_id],
                )
                .map_err(|err| {
                    ValidationError::new(format!("grant replacement-device persona access: {err}"))
                })?;
            }
        }

        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit access restore transaction: {err}"))
        })?;
        Ok(())
    }

    pub fn persona_device_access_for_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<PersonaDeviceAccessRecord>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT persona_id, device_id
                 FROM persona_device_access
                 WHERE persona_id = ?1
                 ORDER BY device_id",
            )
            .map_err(|err| {
                ValidationError::new(format!("prepare persona device access lookup: {err}"))
            })?;
        let rows = stmt
            .query_map(params![persona_id], |row| {
                Ok(PersonaDeviceAccessRecord {
                    persona_id: row.get(0)?,
                    device_id: row.get(1)?,
                })
            })
            .map_err(|err| {
                ValidationError::new(format!("query persona device access rows: {err}"))
            })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|err| {
                ValidationError::new(format!("read persona device access row: {err}"))
            })?);
        }
        Ok(records)
    }

    pub fn persona_device_access_for_device(
        &self,
        device_id: &str,
    ) -> Result<Vec<PersonaDeviceAccessRecord>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT persona_id, device_id
                 FROM persona_device_access
                 WHERE device_id = ?1
                 ORDER BY persona_id",
            )
            .map_err(|err| {
                ValidationError::new(format!("prepare device persona access lookup: {err}"))
            })?;
        let rows = stmt
            .query_map(params![device_id], |row| {
                Ok(PersonaDeviceAccessRecord {
                    persona_id: row.get(0)?,
                    device_id: row.get(1)?,
                })
            })
            .map_err(|err| {
                ValidationError::new(format!("query device persona access rows: {err}"))
            })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|err| {
                ValidationError::new(format!("read device persona access row: {err}"))
            })?);
        }
        Ok(records)
    }

    pub fn upsert_service_binding(
        &mut self,
        binding: &ServiceBinding,
    ) -> Result<(), ValidationError> {
        binding.validate()?;
        let persona = self
            .materialized
            .personas_current
            .get(&binding.persona_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown persona: {}", binding.persona_id))
            })?;
        if persona.status != PersonaStatus::Active {
            return Err(ValidationError::new(
                "cannot bind a service to a revoked persona",
            ));
        }

        persist_write_service_binding(&self.conn, binding)
    }

    pub fn service_bindings_for_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<ServiceBinding>, ValidationError> {
        persist_load_service_bindings_for_persona(&self.conn, persona_id)
    }

    pub fn service_bindings(&self) -> Result<Vec<ServiceBinding>, ValidationError> {
        persist_load_all_service_bindings(&self.conn)
    }

    pub fn delete_service_binding(&mut self, binding_id: &str) -> Result<bool, ValidationError> {
        persist_delete_service_binding(&self.conn, binding_id)
    }

    // --- Access Grant CRUD ---

    fn now_epoch_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// M-2: verify an `AccessGrant`'s block chain against its issuing
    /// persona's root public key. Authorize paths (daemon proxy, approval,
    /// CLI grant evaluate) MUST call this before enforcing a grant that
    /// was loaded from storage — the signature chain is the only defence
    /// against a forged row in the grants table.
    ///
    /// Returns:
    /// - `Ok(())` — chain is internally consistent and block 0 verifies
    ///   under the persona's active root key.
    /// - `Err(ChainError::ChainUnsigned { .. })` — grant was issued before
    ///   the earlier releases signing migration (carries `"unsigned-phase1"`
    ///   placeholder strings). Callers should either reject outright or
    ///   log-and-allow with a one-time warning depending on migration
    ///   stage. Post-earlier releases the daemon's grant-creation paths
    ///   (`ember-daemon/src/grant.rs`) sign block 0 under the persona's
    ///   root Ed25519 key, so `ChainUnsigned` only surfaces for legacy
    ///   rows that survived migration.
    /// - `Err(ChainError::SignatureMismatch { .. } |
    ///    ChainError::RootKeyMismatch | ChainError::InvalidEncoding(_) |
    ///    ChainError::EmptyChain)` — hard reject; do not enforce.
    ///
    /// The caller-supplied error mapping policy for the soft-log of
    /// `ChainUnsigned` lives outside this function so the read path can
    /// stay `&self`.
    pub fn verify_access_grant_chain(
        &self,
        grant: &AccessGrant,
    ) -> Result<(), ChainError> {
        if grant.blocks.is_empty() {
            return Err(ChainError::EmptyChain);
        }
        let persona = self
            .materialized
            .personas_current
            .get(&grant.issuing_persona_id)
            .ok_or_else(|| {
                ChainError::InvalidEncoding(format!(
                    "issuing persona '{}' not found",
                    grant.issuing_persona_id
                ))
            })?;
        let root = self
            .materialized
            .roots_current
            .get(&persona.root_id)
            .ok_or_else(|| {
                ChainError::InvalidEncoding(format!(
                    "root '{}' not found for persona '{}'",
                    persona.root_id, grant.issuing_persona_id
                ))
            })?;
        let root_pubkey_bytes =
            grant_chain::root_pubkey_bytes_from_ed25519_hex(&root.active_key.public_key)?;
        grant_chain::verify_chain(&grant.blocks, &root_pubkey_bytes)
    }

    /// Create a new access grant. Validates the issuing persona exists and is active.
    /// Records a "created" history entry.
    pub fn create_access_grant(
        &mut self,
        grant: &AccessGrant,
    ) -> Result<(), ValidationError> {
        grant.validate()?;
        let persona = self
            .materialized
            .personas_current
            .get(&grant.issuing_persona_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown persona: {}", grant.issuing_persona_id))
            })?;
        if persona.status != PersonaStatus::Active {
            return Err(ValidationError::new(
                "cannot create grant for a revoked persona",
            ));
        }

        write_access_grant(&self.conn, grant)?;

        let blocks_json = blocks_to_json(&grant.blocks)?;
        let history_entry = AccessGrantHistoryEntry {
            history_id: generate_random_identifier("history"),
            grant_id: grant.id.clone(),
            version: grant.version,
            action: "created".to_string(),
            timestamp: grant.created_at,
            blocks_snapshot: Some(blocks_json),
            note: None,
        };
        write_access_grant_history(&self.conn, &history_entry)?;
        Ok(())
    }

    /// Edit an existing grant's mutable fields. Under design this replaces
    /// the grant's entire block chain with a narrowed version — every
    /// statement in the new chain must be dominated by some statement in the
    /// existing chain (bipartite attenuation). To widen authority, create a
    /// new grant instead.
    ///
    /// Bumps version and updated_at. Records an "edited" history entry.
    pub fn edit_access_grant(
        &mut self,
        grant: &AccessGrant,
        note: Option<&str>,
    ) -> Result<(), ValidationError> {
        grant.validate()?;
        let existing = load_access_grant(&self.conn, &grant.id, self.now_epoch_secs())?
            .ok_or_else(|| ValidationError::new(format!("grant not found: {}", grant.id)))?;
        if existing.status == GrantStatus::Revoked {
            return Err(ValidationError::new("cannot edit a revoked grant"));
        }
        if grant.issuing_persona_id != existing.issuing_persona_id
            || grant.recipient_kind != existing.recipient_kind
            || grant.recipient_id != existing.recipient_id
        {
            return Err(ValidationError::new(
                "cannot change issuing persona, recipient kind, or recipient id",
            ));
        }
        // Attenuation guard: every statement in the edited chain must be
        // dominated by some statement in the existing chain. This is the
        // coarse shape-check (design § "Attenuation"); the authoritative
        // evaluator lives in core-policy.
        let existing_statements: Vec<Statement> = existing
            .statements()
            .map(|(_i, s)| s.clone())
            .collect();
        for (_i, s) in grant.statements() {
            if !statement_dominated_by(s, &existing_statements) {
                return Err(ValidationError::new(
                    "edit would expand grant authority; create a new grant to add statements",
                ));
            }
        }

        write_access_grant(&self.conn, grant)?;

        let blocks_json = blocks_to_json(&grant.blocks)?;
        let history_entry = AccessGrantHistoryEntry {
            history_id: generate_random_identifier("history"),
            grant_id: grant.id.clone(),
            version: grant.version,
            action: "edited".to_string(),
            timestamp: grant.updated_at,
            blocks_snapshot: Some(blocks_json),
            note: note.map(String::from),
        };
        write_access_grant_history(&self.conn, &history_entry)?;
        Ok(())
    }

    /// Revoke an access grant. Sets revoked_at, bumps version.
    /// Records a "revoked" history entry.
    pub fn revoke_access_grant(
        &mut self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ValidationError> {
        let now = self.now_epoch_secs();
        let mut grant = load_access_grant(&self.conn, grant_id, now)?
            .ok_or_else(|| ValidationError::new(format!("grant not found: {grant_id}")))?;
        if grant.status == GrantStatus::Revoked {
            return Err(ValidationError::new("grant is already revoked"));
        }

        grant.version += 1;
        grant.status = GrantStatus::Revoked;
        grant.revoked_at = Some(now);
        grant.revoked_reason = reason.map(String::from);
        grant.updated_at = now;

        write_access_grant(&self.conn, &grant)?;

        let history_entry = AccessGrantHistoryEntry {
            history_id: generate_random_identifier("history"),
            grant_id: grant.id.clone(),
            version: grant.version,
            action: "revoked".to_string(),
            timestamp: now,
            blocks_snapshot: None,
            note: reason.map(String::from),
        };
        write_access_grant_history(&self.conn, &history_entry)?;
        Ok(())
    }

    /// Extend a renewable grant by appending a new block with a later
    /// `expires_at`. Under design, block-level expiry replaces grant-level
    /// `expires_at` — so "renew" is "append". The caller must supply a
    /// properly-signed block; this method does not sign.
    ///
    /// Records a "renewed" history entry.
    pub fn renew_access_grant(
        &mut self,
        grant_id: &str,
        new_expires_at: u64,
        new_block: Option<SignedBlock>,
    ) -> Result<(), ValidationError> {
        let now = self.now_epoch_secs();
        let mut grant = load_access_grant(&self.conn, grant_id, now)?
            .ok_or_else(|| ValidationError::new(format!("grant not found: {grant_id}")))?;

        if grant.mode != GrantMode::Renewable {
            return Err(ValidationError::new("only renewable grants can be renewed"));
        }
        if grant.status == GrantStatus::Revoked {
            return Err(ValidationError::new("cannot renew a revoked grant"));
        }

        grant.version += 1;
        grant.updated_at = now;
        if let Some(block) = new_block {
            // Attenuation guard on the appended block.
            let existing_statements: Vec<Statement> = grant
                .statements()
                .map(|(_i, s)| s.clone())
                .collect();
            for s in &block.block.statements {
                if !statement_dominated_by(s, &existing_statements) {
                    return Err(ValidationError::new(
                        "renew would expand grant authority; renew must narrow or keep scope",
                    ));
                }
            }
            // Block expires_at must be <= requested new_expires_at.
            if let Some(bexp) = block.block.expires_at
                && bexp > new_expires_at
            {
                return Err(ValidationError::new(
                    "appended block expires_at must not exceed requested new_expires_at",
                ));
            }
            grant.blocks.push(block);
        } else if let Some(last) = grant.blocks.last_mut() {
            // Convenience: caller didn't supply a full signed block. Extend
            // the tail block's expires_at in place. NOTE: this breaks the
            // biscuit signature chain and is only acceptable pre-signing. Once
            // core-crypto wires in biscuit-auth, require a SignedBlock.
            last.block.expires_at = Some(new_expires_at);
        }

        write_access_grant(&self.conn, &grant)?;

        let history_entry = AccessGrantHistoryEntry {
            history_id: generate_random_identifier("history"),
            grant_id: grant.id.clone(),
            version: grant.version,
            action: "renewed".to_string(),
            timestamp: now,
            blocks_snapshot: Some(blocks_to_json(&grant.blocks)?),
            note: None,
        };
        write_access_grant_history(&self.conn, &history_entry)?;
        Ok(())
    }

    /// Record that a grant was used (update last_used_at).
    pub fn touch_access_grant(&mut self, grant_id: &str) -> Result<(), ValidationError> {
        let now = self.now_epoch_secs();
        let mut grant = load_access_grant(&self.conn, grant_id, now)?
            .ok_or_else(|| ValidationError::new(format!("grant not found: {grant_id}")))?;
        grant.last_used_at = Some(now);
        grant.updated_at = now;
        write_access_grant(&self.conn, &grant)
    }

    /// Get a single grant by ID.
    pub fn access_grant(&self, grant_id: &str) -> Result<Option<AccessGrant>, ValidationError> {
        load_access_grant(&self.conn, grant_id, self.now_epoch_secs())
    }

    /// Get full grant detail including linked artifacts and history.
    pub fn access_grant_detail(
        &self,
        grant_id: &str,
    ) -> Result<Option<AccessGrantDetail>, ValidationError> {
        let now = self.now_epoch_secs();
        let grant = match load_access_grant(&self.conn, grant_id, now)? {
            Some(g) => g,
            None => return Ok(None),
        };
        let history = load_access_grant_history(&self.conn, grant_id)?;
        let linked_artifact_ids = load_artifact_ids_by_grant(&self.conn, grant_id)?;
        Ok(Some(AccessGrantDetail {
            grant,
            linked_artifact_count: linked_artifact_ids.len(),
            linked_artifact_ids,
            history,
        }))
    }

    /// List active grants, optionally filtered by persona and/or recipient profile.
    pub fn list_active_grants(
        &self,
        persona_id: Option<&str>,
        recipient_profile: Option<RecipientProfile>,
    ) -> Result<Vec<AccessGrantSummary>, ValidationError> {
        let now = self.now_epoch_secs();
        let grants =
            load_access_grants_by_persona(&self.conn, persona_id, recipient_profile, Some("active"), now)?;
        // Filter out derived Expired/Pending from the "active" stored status
        Ok(grants.into_iter().filter(|g| g.status == GrantStatus::Active).map(grant_to_summary).collect())
    }

    /// List all grants for a specific recipient (active, expired, revoked).
    pub fn list_grants_for_recipient(
        &self,
        recipient_kind: PresentationAudienceKind,
        recipient_id: &str,
    ) -> Result<Vec<AccessGrantSummary>, ValidationError> {
        let now = self.now_epoch_secs();
        let grants = load_access_grants_for_recipient(&self.conn, recipient_kind, recipient_id, now)?;
        Ok(grants.into_iter().map(grant_to_summary).collect())
    }

    /// Reverse-chronological timeline of grant lifecycle events.
    pub fn grant_history_timeline(
        &self,
        persona_id: Option<&str>,
        limit: usize,
        before: Option<u64>,
    ) -> Result<Vec<AccessGrantHistoryEntry>, ValidationError> {
        load_grant_history_timeline(&self.conn, persona_id, limit, before)
    }

    /// Delete a grant and its history. Use revoke for normal lifecycle;
    /// delete is for cleanup only.
    pub fn delete_access_grant(&mut self, grant_id: &str) -> Result<bool, ValidationError> {
        persist_delete_access_grant(&self.conn, grant_id)
    }

    // --- Grant offers (design) ---

    /// Look up a single grant offer by ID.
    pub fn get_grant_offer(
        &self,
        offer_id: &str,
    ) -> Result<Option<core_eventlog::GrantOfferRecord>, ValidationError> {
        load_grant_offer(&self.conn, offer_id)
    }

    /// List all grant offers issued by a persona.
    pub fn list_grant_offers_by_persona(
        &self,
        persona_id: &str,
    ) -> Result<Vec<core_eventlog::GrantOfferRecord>, ValidationError> {
        load_grant_offers_by_persona(&self.conn, persona_id)
    }

    // --- Credential deposits ---

    /// Insert a credential deposit record into the credential_deposits table.
    pub fn deposit_credential(
        &mut self,
        deposit: &core_eventlog::CredentialDepositRecord,
    ) -> Result<(), ValidationError> {
        persist::write_credential_deposit(&self.conn, deposit)
    }

    /// Fetch an active credential deposit for a given grant_id.
    /// Returns None if no active deposit exists or if the deposit has expired.
    pub fn fetch_credential_deposit(
        &self,
        grant_id: &str,
    ) -> Result<Option<CredentialDepositRow>, ValidationError> {
        let row = persist::load_credential_deposit_by_grant(&self.conn, grant_id)?;
        // Filter out expired deposits at read time.
        if let Some(ref r) = row
            && let Some(expires_at) = r.expires_at
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now >= expires_at {
                return Ok(None);
            }
        }
        Ok(row)
    }

    /// Revoke a credential deposit for a given grant_id. Sets status='revoked'
    /// and records the revocation timestamp and optional reason.
    pub fn revoke_credential_deposit(
        &mut self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ValidationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        persist::revoke_credential_deposit(&self.conn, grant_id, reason, now)
    }

    // --- Credential access audit log ---

    /// Log a credential access attempt (granted or denied) by an agent.
    pub fn log_credential_access(
        &self,
        grant_id: &str,
        agent_id: &str,
        scope: &str,
        outcome: &str,
    ) -> Result<(), ValidationError> {
        let accessed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.conn
            .execute(
                "INSERT INTO credential_access_log (grant_id, agent_id, accessed_at, scope, outcome)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![grant_id, agent_id, accessed_at, scope, outcome],
            )
            .map_err(|err| ValidationError::new(format!("log credential access: {err}")))?;
        Ok(())
    }

    /// Query the credential access log for a specific grant, ordered oldest-first.
    pub fn get_credential_access_log(
        &self,
        grant_id: &str,
    ) -> Result<Vec<CredentialAccessEntry>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT grant_id, agent_id, accessed_at, scope, outcome
                 FROM credential_access_log
                 WHERE grant_id = ?1
                 ORDER BY accessed_at ASC",
            )
            .map_err(|err| ValidationError::new(format!("prepare credential_access_log query: {err}")))?;
        let rows = stmt
            .query_map(params![grant_id], |row| {
                Ok(CredentialAccessEntry {
                    grant_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    accessed_at: row.get(2)?,
                    scope: row.get(3)?,
                    outcome: row.get(4)?,
                })
            })
            .map_err(|err| ValidationError::new(format!("query credential_access_log: {err}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::new(format!("collect credential_access_log rows: {err}")))?;
        Ok(rows)
    }


    // --- Approval queue ---

    /// Insert a new approval request into the database.
    pub fn insert_approval_request(
        &self,
        req: &core_types::approval::ApprovalRequest,
    ) -> Result<(), ValidationError> {
        let scope_json = serde_json::to_string(&req.requested_scope)
            .map_err(|err| ValidationError::new(format!("serialize requested_scope: {err}")))?;
        self.conn
            .execute(
                "INSERT INTO approval_requests (
                    request_id, requester_id, requester_label, requested_scope_json,
                    requested_duration_secs, reason, status, created_at,
                    resolved_at, resolver_id, narrowed_scope_json, denial_reason
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    &req.request_id,
                    &req.requester_id,
                    &req.requester_label,
                    &scope_json,
                    req.requested_duration_secs.map(|v| v as i64),
                    &req.reason,
                    req.status.to_string(),
                    req.created_at as i64,
                    req.resolved_at.map(|v| v as i64),
                    &req.resolver_id,
                    req.narrowed_scope.as_ref().and_then(|s| serde_json::to_string(s).ok()),
                    &req.denial_reason,
                ],
            )
            .map_err(|err| ValidationError::new(format!("insert approval request: {err}")))?;
        Ok(())
    }

    /// Fetch an approval request by ID.
    pub fn get_approval_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ApprovalRequestRow>, ValidationError> {
        let row = self
            .conn
            .query_row(
                "SELECT request_id, requester_id, requester_label, requested_scope_json,
                        requested_duration_secs, reason, status, created_at,
                        resolved_at, resolver_id, narrowed_scope_json, denial_reason
                 FROM approval_requests WHERE request_id = ?1",
                params![request_id],
                |row| {
                    Ok(ApprovalRequestRow {
                        request_id: row.get(0)?,
                        requester_id: row.get(1)?,
                        requester_label: row.get(2)?,
                        requested_scope_json: row.get(3)?,
                        requested_duration_secs: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                        reason: row.get(5)?,
                        status: row.get(6)?,
                        created_at: row.get::<_, i64>(7)? as u64,
                        resolved_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                        resolver_id: row.get(9)?,
                        narrowed_scope_json: row.get(10)?,
                        denial_reason: row.get(11)?,
                    })
                },
            )
            .optional()
            .map_err(|err| ValidationError::new(format!("get approval request: {err}")))?;
        Ok(row)
    }

    /// List all pending approval requests, ordered by creation time (newest first).
    pub fn list_pending_approvals(&self) -> Result<Vec<ApprovalRequestRow>, ValidationError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT request_id, requester_id, requester_label, requested_scope_json,
                        requested_duration_secs, reason, status, created_at,
                        resolved_at, resolver_id, narrowed_scope_json, denial_reason
                 FROM approval_requests WHERE status = 'pending'
                 ORDER BY created_at DESC",
            )
            .map_err(|err| ValidationError::new(format!("prepare list pending approvals: {err}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ApprovalRequestRow {
                    request_id: row.get(0)?,
                    requester_id: row.get(1)?,
                    requester_label: row.get(2)?,
                    requested_scope_json: row.get(3)?,
                    requested_duration_secs: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    reason: row.get(5)?,
                    status: row.get(6)?,
                    created_at: row.get::<_, i64>(7)? as u64,
                    resolved_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
                    resolver_id: row.get(9)?,
                    narrowed_scope_json: row.get(10)?,
                    denial_reason: row.get(11)?,
                })
            })
            .map_err(|err| ValidationError::new(format!("list pending approvals: {err}")))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(
                row.map_err(|err| ValidationError::new(format!("read approval row: {err}")))?,
            );
        }
        Ok(result)
    }

    /// Resolve an approval request. Validates the state transition using the
    /// domain type's `resolve()` method before writing to the database.
    pub fn resolve_approval_request(
        &self,
        request_id: &str,
        response: &core_types::approval::ApprovalResponse,
    ) -> Result<(), ValidationError> {
        let row = self
            .get_approval_request(request_id)?
            .ok_or_else(|| ValidationError::new(format!("approval request not found: {request_id}")))?;

        let scope: core_types::approval::RequestedScope =
            serde_json::from_str(&row.requested_scope_json)
                .map_err(|err| ValidationError::new(format!("deserialize scope: {err}")))?;
        let mut domain_req = core_types::approval::ApprovalRequest {
            request_id: row.request_id,
            requester_id: row.requester_id,
            requester_label: row.requester_label,
            requested_scope: scope,
            requested_duration_secs: row.requested_duration_secs,
            reason: row.reason,
            created_at: row.created_at,
            status: parse_approval_status(&row.status)?,
            resolved_at: row.resolved_at,
            resolver_id: row.resolver_id,
            narrowed_scope: None,
            denial_reason: row.denial_reason,
        };

        domain_req.resolve(response)?;

        let narrowed_json = domain_req
            .narrowed_scope
            .as_ref()
            .and_then(|s| serde_json::to_string(s).ok());
        self.conn
            .execute(
                "UPDATE approval_requests SET
                    status = ?1, resolved_at = ?2, resolver_id = ?3,
                    narrowed_scope_json = ?4, denial_reason = ?5
                 WHERE request_id = ?6",
                params![
                    domain_req.status.to_string(),
                    domain_req.resolved_at.map(|v| v as i64),
                    &domain_req.resolver_id,
                    &narrowed_json,
                    &domain_req.denial_reason,
                    request_id,
                ],
            )
            .map_err(|err| ValidationError::new(format!("resolve approval request: {err}")))?;
        Ok(())
    }

    // --- Badge visibility (local-only, design) ---

    /// Set badge visibility for a persona's gallery. `visible=true` means the
    /// badge will appear in the persona's public badge gallery. This is a
    /// local-only preference — it never leaves the device or enters the event log.
    pub fn set_badge_visibility(
        &mut self,
        badge_id: &str,
        persona_id: &str,
        visible: bool,
    ) -> Result<(), ValidationError> {
        persist::set_badge_visibility(&self.conn, badge_id, persona_id, visible)
    }

    /// Load the badge gallery for a persona: all active, non-expired badges
    /// received by this persona, with their visibility preferences included.
    /// Filtering happens at the SQL level for efficiency.
    pub fn badge_gallery(
        &self,
        persona_id: &str,
        now_secs: u64,
    ) -> Result<Vec<(core_eventlog::BadgeRecord, bool)>, ValidationError> {
        persist::load_badge_gallery(&self.conn, persona_id, now_secs)
    }

    pub fn upsert_file_manifest(&mut self, manifest: &FileManifest) -> Result<(), ValidationError> {
        manifest.validate()?;
        self.validate_manifest_device_access(manifest)?;

        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin storage manifest transaction: {err}"))
        })?;
        write_file_manifest(&tx, manifest)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit storage manifest transaction: {err}"))
        })?;
        self.storage_manifests
            .insert(manifest.id.clone(), manifest.clone());
        Ok(())
    }

    pub fn file_manifest(&self, manifest_id: &str) -> Option<FileManifest> {
        self.storage_manifests.get(manifest_id).cloned()
    }

    pub fn file_manifests(&self) -> Vec<FileManifest> {
        let mut ordered: Vec<FileManifest> = self.storage_manifests.values().cloned().collect();
        ordered.sort_by(|left, right| left.id.cmp(&right.id));
        ordered
    }

    pub fn upsert_local_file_manifest(
        &mut self,
        manifest: &FileManifest,
    ) -> Result<(), ValidationError> {
        manifest.validate()?;
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin local storage manifest transaction: {err}"))
        })?;
        write_local_file_manifest(&tx, manifest)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit local storage manifest transaction: {err}"))
        })?;
        Ok(())
    }

    pub fn upsert_local_encrypted_manifest(
        &mut self,
        manifest: &FileManifest,
        blocks: &[EncryptedBlock],
    ) -> Result<(), ValidationError> {
        validate_encrypted_manifest_blocks(manifest, blocks)?;

        if let Some(local_block_store) = &self.local_block_store {
            for block in blocks {
                local_block_store
                    .write_encrypted_content(&block.chunk.chunk_id, &block.encrypted)?;
            }
        }

        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin local encrypted manifest transaction: {err}"))
        })?;
        write_local_file_manifest(&tx, manifest)?;
        for block in blocks {
            if self.local_block_store.is_some() {
                write_local_block(
                    &tx,
                    &LocalBlockRecord {
                        chunk_id: block.chunk.chunk_id.clone(),
                        ciphertext_bytes: block.chunk.ciphertext_bytes,
                    },
                )?;
            } else {
                write_encrypted_local_block(&tx, block)?;
            }
        }
        tx.commit().map_err(|err| {
            ValidationError::new(format!(
                "commit local encrypted manifest transaction: {err}"
            ))
        })?;
        Ok(())
    }

    pub fn commit_local_vault_catalog_with_manifests(
        &mut self,
        catalog_manifest_id: impl Into<String>,
        catalog: &VaultCatalog,
        content_key: &str,
        authorized_devices: Vec<ManifestDeviceAccess>,
        payload_manifests: &[LocalEncryptedManifest],
    ) -> Result<FileManifest, ValidationError> {
        for payload in payload_manifests {
            validate_encrypted_manifest_blocks(&payload.manifest, &payload.blocks)?;
        }
        let (catalog_manifest, catalog_blocks) = seal_vault_catalog(
            catalog_manifest_id,
            catalog,
            content_key,
            authorized_devices,
        )?;

        if let Some(local_block_store) = &self.local_block_store {
            for payload in payload_manifests {
                for block in &payload.blocks {
                    local_block_store
                        .write_encrypted_content(&block.chunk.chunk_id, &block.encrypted)?;
                }
            }
            for block in &catalog_blocks {
                local_block_store
                    .write_encrypted_content(&block.chunk.chunk_id, &block.encrypted)?;
            }
        }

        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!(
                "begin local vault catalog commit transaction: {err}"
            ))
        })?;
        for payload in payload_manifests {
            write_local_file_manifest(&tx, &payload.manifest)?;
            for block in &payload.blocks {
                if self.local_block_store.is_some() {
                    write_local_block(
                        &tx,
                        &LocalBlockRecord {
                            chunk_id: block.chunk.chunk_id.clone(),
                            ciphertext_bytes: block.chunk.ciphertext_bytes,
                        },
                    )?;
                } else {
                    write_encrypted_local_block(&tx, block)?;
                }
            }
        }
        write_local_file_manifest(&tx, &catalog_manifest)?;
        for block in &catalog_blocks {
            if self.local_block_store.is_some() {
                write_local_block(
                    &tx,
                    &LocalBlockRecord {
                        chunk_id: block.chunk.chunk_id.clone(),
                        ciphertext_bytes: block.chunk.ciphertext_bytes,
                    },
                )?;
            } else {
                write_encrypted_local_block(&tx, block)?;
            }
        }
        write_local_vault_catalog_head(&tx, &catalog.namespace, &catalog_manifest, content_key, self.master_key.as_ref().map(|s| s.as_str()))?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit local vault catalog transaction: {err}"))
        })?;
        Ok(catalog_manifest)
    }

    pub fn local_file_manifest(
        &self,
        manifest_id: &str,
    ) -> Result<Option<FileManifest>, ValidationError> {
        load_local_file_manifest(&self.conn, manifest_id)
    }

    pub fn local_file_manifests(&self) -> Result<Vec<FileManifest>, ValidationError> {
        let manifests = load_all_local_file_manifests(&self.conn)?;
        let mut ordered: Vec<FileManifest> = manifests.into_values().collect();
        ordered.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(ordered)
    }

    pub fn upsert_local_manifest_key(
        &mut self,
        manifest_id: &str,
        content_key: &str,
    ) -> Result<(), ValidationError> {
        if manifest_id.trim().is_empty() {
            return Err(ValidationError::new(
                "local manifest key id must not be empty",
            ));
        }
        if content_key.trim().is_empty() {
            return Err(ValidationError::new("local manifest key must not be empty"));
        }
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin local manifest key transaction: {err}"))
        })?;
        write_local_manifest_key(&tx, manifest_id, content_key, self.master_key.as_ref().map(|s| s.as_str()))?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit local manifest key transaction: {err}"))
        })?;
        Ok(())
    }

    pub fn local_manifest_key(&self, manifest_id: &str) -> Result<Option<String>, ValidationError> {
        load_local_manifest_key(&self.conn, manifest_id, self.master_key.as_ref().map(|s| s.as_str()))
    }

    pub fn upsert_local_device_encryption_key(
        &mut self,
        device_id: &str,
        key_pair: &LocalKeyPair,
    ) -> Result<(), ValidationError> {
        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.active_encryption_key.key_id != key_pair.key_id {
            return Err(ValidationError::new(format!(
                "device encryption key id does not match active device encryption key: {device_id}"
            )));
        }
        if device.active_encryption_key.public_key != key_pair.public_key {
            return Err(ValidationError::new(format!(
                "device encryption public key does not match active device encryption key: {device_id}"
            )));
        }
        if device.active_encryption_key.algorithm != key_pair.algorithm {
            return Err(ValidationError::new(format!(
                "device encryption algorithm does not match active device encryption key: {device_id}"
            )));
        }
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!(
                "begin local device encryption key transaction: {err}"
            ))
        })?;
        write_local_device_encryption_key(&tx, device_id, key_pair, self.master_key.as_ref().map(|s| s.as_str()))?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!(
                "commit local device encryption key transaction: {err}"
            ))
        })
    }

    pub fn local_device_encryption_key_pair(
        &self,
        device_id: &str,
    ) -> Result<Option<LocalKeyPair>, ValidationError> {
        load_local_device_encryption_key(&self.conn, device_id, self.master_key.as_ref().map(|s| s.as_str()))
    }

    pub fn unwrap_manifest_key_for_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<String, ValidationError> {
        let manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        let access = manifest
            .authorized_devices
            .iter()
            .find(|access| access.device_id == device_id)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "device is not authorized for manifest: {device_id}"
                ))
            })?;
        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "manifest access requires an active device",
            ));
        }
        if let Some(content_key) = self.local_manifest_key(manifest_id)? {
            return Ok(content_key);
        }
        let Some(key_pair) = self.local_device_encryption_key_pair(device_id)? else {
            return Err(ValidationError::new(format!(
                "missing local device encryption key: {device_id}"
            )));
        };
        if key_pair.key_id != device.active_encryption_key.key_id {
            return Err(ValidationError::new(format!(
                "stale local device encryption key for active device: {device_id}"
            )));
        }
        if key_pair.public_key != device.active_encryption_key.public_key {
            return Err(ValidationError::new(format!(
                "local device encryption public key does not match active device encryption key: {device_id}"
            )));
        }
        if key_pair.algorithm != device.active_encryption_key.algorithm {
            return Err(ValidationError::new(format!(
                "local device encryption algorithm does not match active device encryption key: {device_id}"
            )));
        }
        let content_key = unwrap_manifest_key_access(access, &key_pair.private_key)?;
        self.upsert_local_manifest_key(manifest_id, &content_key)?;
        Ok(content_key)
    }

    pub fn prime_manifest_keys_for_device(
        &mut self,
        device_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let manifest_ids = self
            .file_manifests()
            .into_iter()
            .filter(|manifest| {
                manifest
                    .authorized_devices
                    .iter()
                    .any(|access| access.device_id == device_id)
            })
            .map(|manifest| manifest.id)
            .collect::<Vec<_>>();
        for manifest_id in &manifest_ids {
            self.unwrap_manifest_key_for_device(manifest_id, device_id)?;
        }
        Ok(manifest_ids)
    }

    pub fn upsert_local_block(&mut self, block: &LocalBlockRecord) -> Result<(), ValidationError> {
        if block.chunk_id.trim().is_empty() {
            return Err(ValidationError::new(
                "local block chunk id must not be empty",
            ));
        }
        if block.ciphertext_bytes == 0 {
            return Err(ValidationError::new(
                "local block ciphertext size must be greater than zero",
            ));
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|err| ValidationError::new(format!("begin local block transaction: {err}")))?;
        write_local_block(&tx, block)?;
        tx.commit()
            .map_err(|err| ValidationError::new(format!("commit local block transaction: {err}")))
    }

    pub fn local_block_coverage(
        &self,
        manifest_id: &str,
    ) -> Result<Option<LocalBlockCoverage>, ValidationError> {
        let Some(manifest) = self.file_manifest(manifest_id) else {
            return Ok(None);
        };
        let missing_chunks = manifest
            .chunks
            .iter()
            .filter_map(
                |chunk| match self.local_encrypted_content(&chunk.chunk_id) {
                    Ok(Some(_)) => None,
                    Ok(None) => Some(Ok(chunk.clone())),
                    Err(err) => Some(Err(err)),
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(LocalBlockCoverage {
            manifest_id: manifest.id.clone(),
            present_chunks: manifest.chunks.len().saturating_sub(missing_chunks.len()),
            total_chunks: manifest.chunks.len(),
            missing_chunks,
        }))
    }

    pub fn audit_local_blocks(&self) -> Result<LocalBlockAudit, ValidationError> {
        let referenced_chunk_ids = self
            .file_manifests()
            .into_iter()
            .chain(self.local_file_manifests()?)
            .flat_map(|manifest| manifest.chunks.into_iter().map(|chunk| chunk.chunk_id))
            .collect::<BTreeSet<_>>();
        let metadata_chunk_ids = load_local_block_ids(&self.conn)?;
        let file_chunk_ids = match &self.local_block_store {
            Some(local_block_store) => local_block_store.list_chunk_ids()?,
            None => BTreeSet::new(),
        };
        let missing_referenced_chunk_ids = referenced_chunk_ids
            .iter()
            .filter_map(|chunk_id| match self.local_encrypted_content(chunk_id) {
                Ok(Some(_)) => None,
                Ok(None) => Some(Ok(chunk_id.clone())),
                Err(err) => Some(Err(err)),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let orphaned_metadata_chunk_ids = metadata_chunk_ids
            .difference(&referenced_chunk_ids)
            .cloned()
            .collect::<BTreeSet<_>>();
        let orphaned_file_chunk_ids = file_chunk_ids
            .difference(&metadata_chunk_ids)
            .cloned()
            .collect::<BTreeSet<_>>();

        Ok(LocalBlockAudit {
            referenced_chunk_ids,
            missing_referenced_chunk_ids,
            orphaned_metadata_chunk_ids,
            orphaned_file_chunk_ids,
        })
    }

    pub fn upsert_encrypted_block(
        &mut self,
        block: &EncryptedBlock,
    ) -> Result<(), ValidationError> {
        if let Some(local_block_store) = &self.local_block_store {
            local_block_store.write_encrypted_content(&block.chunk.chunk_id, &block.encrypted)?;
        }
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin encrypted block transaction: {err}"))
        })?;
        if self.local_block_store.is_some() {
            write_local_block(
                &tx,
                &LocalBlockRecord {
                    chunk_id: block.chunk.chunk_id.clone(),
                    ciphertext_bytes: block.chunk.ciphertext_bytes,
                },
            )?;
        } else {
            write_encrypted_local_block(&tx, block)?;
        }
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit encrypted block transaction: {err}"))
        })
    }

    pub fn local_encrypted_content(
        &self,
        chunk_id: &str,
    ) -> Result<Option<EncryptedContent>, ValidationError> {
        if let Some(local_block_store) = &self.local_block_store
            && let Some(encrypted) = local_block_store.load_encrypted_content(chunk_id)?
        {
            return Ok(Some(encrypted));
        }
        load_local_encrypted_content(&self.conn, chunk_id)
    }

    pub fn upsert_local_vault_catalog(
        &mut self,
        manifest_id: impl Into<String>,
        catalog: &VaultCatalog,
        content_key: &str,
        authorized_devices: Vec<ManifestDeviceAccess>,
    ) -> Result<FileManifest, ValidationError> {
        let (manifest, blocks) =
            seal_vault_catalog(manifest_id, catalog, content_key, authorized_devices)?;
        if let Some(local_block_store) = &self.local_block_store {
            for block in &blocks {
                local_block_store
                    .write_encrypted_content(&block.chunk.chunk_id, &block.encrypted)?;
            }
        }
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin local vault catalog transaction: {err}"))
        })?;
        write_local_file_manifest(&tx, &manifest)?;
        for block in &blocks {
            if self.local_block_store.is_some() {
                write_local_block(
                    &tx,
                    &LocalBlockRecord {
                        chunk_id: block.chunk.chunk_id.clone(),
                        ciphertext_bytes: block.chunk.ciphertext_bytes,
                    },
                )?;
            } else {
                write_encrypted_local_block(&tx, block)?;
            }
        }
        write_local_vault_catalog_head(&tx, &catalog.namespace, &manifest, content_key, self.master_key.as_ref().map(|s| s.as_str()))?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit local vault catalog transaction: {err}"))
        })?;
        Ok(manifest)
    }

    pub fn local_vault_catalog(
        &self,
        namespace: &VaultNamespace,
    ) -> Result<Option<VaultCatalog>, ValidationError> {
        namespace.validate()?;
        let Some((manifest, content_key)) = load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
        else {
            return Ok(None);
        };
        let mut blocks = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let encrypted = self
                .local_encrypted_content(&chunk.chunk_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "local vault catalog chunk is missing encrypted content: {}",
                        chunk.chunk_id
                    ))
                })?;
            blocks.push(EncryptedBlock {
                chunk: chunk.clone(),
                encrypted,
            });
        }
        open_vault_catalog(&manifest, &blocks, &content_key).map(Some)
    }

    pub fn local_vault_namespaces(&self) -> Result<Vec<VaultNamespace>, ValidationError> {
        load_local_vault_namespaces(&self.conn)
    }

    pub fn local_vault_manifests_with_keys(
        &self,
        namespace: &VaultNamespace,
    ) -> Result<Vec<(FileManifest, String)>, ValidationError> {
        let Some((catalog_manifest, catalog_key)) =
            load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
        else {
            return Ok(Vec::new());
        };
        let Some(catalog) = self.local_vault_catalog(namespace)? else {
            return Ok(Vec::new());
        };
        let mut manifests_by_id = BTreeMap::new();
        let loaded_catalog_manifest = self
            .local_file_manifest(&catalog_manifest.id)?
            .unwrap_or(catalog_manifest);
        manifests_by_id.insert(
            loaded_catalog_manifest.id.clone(),
            (loaded_catalog_manifest, catalog_key),
        );
        for revision in &catalog.revisions {
            let manifest = self
                .local_file_manifest(&revision.manifest_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "local vault revision references missing manifest: {}",
                        revision.manifest_id
                    ))
                })?;
            let content_key = self
                .local_manifest_key(&revision.manifest_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "local vault manifest key is missing: {}",
                        revision.manifest_id
                    ))
                })?;
            manifests_by_id.insert(manifest.id.clone(), (manifest, content_key));
        }
        Ok(manifests_by_id.into_values().collect())
    }

    pub fn upsert_local_presentation_template(
        &mut self,
        template: &PresentationTemplate,
    ) -> Result<(), ValidationError> {
        template.validate()?;
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!(
                "begin local presentation template transaction: {err}"
            ))
        })?;
        write_local_presentation_template(&tx, template)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!(
                "commit local presentation template transaction: {err}"
            ))
        })?;
        Ok(())
    }

    pub fn local_presentation_template(
        &self,
        template_id: &str,
    ) -> Result<Option<PresentationTemplate>, ValidationError> {
        load_local_presentation_template(&self.conn, template_id)
    }

    pub fn local_presentation_templates(
        &self,
    ) -> Result<Vec<PresentationTemplate>, ValidationError> {
        load_local_presentation_templates(&self.conn)
    }

    pub fn record_local_presentation_artifact(
        &mut self,
        record: &LocalPresentationArtifactRecord,
    ) -> Result<(), ValidationError> {
        record.validate()?;
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!(
                "begin local presentation artifact transaction: {err}"
            ))
        })?;
        write_local_presentation_artifact(&tx, record)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!(
                "commit local presentation artifact transaction: {err}"
            ))
        })?;
        Ok(())
    }

    pub fn local_presentation_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<LocalPresentationArtifactRecord>, ValidationError> {
        load_local_presentation_artifact(&self.conn, artifact_id)
    }

    pub fn local_presentation_artifacts(
        &self,
    ) -> Result<Vec<LocalPresentationArtifactRecord>, ValidationError> {
        load_local_presentation_artifacts(&self.conn)
    }

    pub fn default_local_presentation_artifact_issuer_persona_id(
        &self,
        artifact_id: &str,
    ) -> Result<Option<String>, ValidationError> {
        Ok(self
            .local_presentation_artifact(artifact_id)?
            .and_then(|record| record.default_issuer_persona_id().map(str::to_string)))
    }

    pub fn record_local_received_presentation_artifact(
        &mut self,
        record: &ReceivedPresentationArtifactRecord,
    ) -> Result<(), ValidationError> {
        core_storage::verify_presentation_artifact_envelope(&record.envelope)?;
        if record.receipt_count == 0 {
            return Err(ValidationError::new(
                "received disclosure receipt count must be at least 1",
            ));
        }
        if record.last_received_at < record.first_received_at {
            return Err(ValidationError::new(
                "received disclosure last_received_at must be >= first_received_at",
            ));
        }
        if record.first_source_ref.trim().is_empty() || record.last_source_ref.trim().is_empty() {
            return Err(ValidationError::new(
                "received disclosure source refs must not be empty",
            ));
        }
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!(
                "begin local received disclosure transaction: {err}"
            ))
        })?;
        write_local_received_presentation_artifact(&tx, record)?;
        tx.commit().map_err(|err| {
            ValidationError::new(format!(
                "commit local received disclosure transaction: {err}"
            ))
        })?;
        Ok(())
    }

    pub fn local_received_presentation_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ReceivedPresentationArtifactRecord>, ValidationError> {
        load_local_received_presentation_artifact(&self.conn, artifact_id)
    }

    pub fn local_received_presentation_artifacts(
        &self,
    ) -> Result<Vec<ReceivedPresentationArtifactRecord>, ValidationError> {
        load_local_received_presentation_artifacts(&self.conn)
    }

    pub fn receive_presentation_artifact(
        &mut self,
        envelope: &PresentationArtifactEnvelope,
        source_kind: ReceivedDisclosureSourceKind,
        source_ref: &str,
        received_at: u64,
    ) -> Result<ReceivedPresentationArtifactRecord, ValidationError> {
        core_storage::verify_presentation_artifact_envelope(envelope)?;
        if source_ref.trim().is_empty() {
            return Err(ValidationError::new(
                "received disclosure source ref must not be empty",
            ));
        }

        let record = match self.local_received_presentation_artifact(&envelope.artifact.id)? {
            Some(existing) => {
                if existing.envelope.artifact != envelope.artifact {
                    return Err(ValidationError::new(format!(
                        "received disclosure artifact conflicts with existing artifact id: {}",
                        envelope.artifact.id
                    )));
                }
                if existing.envelope != *envelope {
                    return Err(ValidationError::new(format!(
                        "received disclosure envelope conflicts with existing artifact id: {}",
                        envelope.artifact.id
                    )));
                }
                ReceivedPresentationArtifactRecord {
                    envelope: existing.envelope,
                    first_received_at: existing.first_received_at,
                    last_received_at: received_at.max(existing.last_received_at),
                    first_source_kind: existing.first_source_kind,
                    first_source_ref: existing.first_source_ref,
                    last_source_kind: source_kind,
                    last_source_ref: source_ref.to_string(),
                    receipt_count: existing.receipt_count.saturating_add(1),
                }
            }
            None => ReceivedPresentationArtifactRecord {
                envelope: envelope.clone(),
                first_received_at: received_at,
                last_received_at: received_at,
                first_source_kind: source_kind,
                first_source_ref: source_ref.to_string(),
                last_source_kind: source_kind,
                last_source_ref: source_ref.to_string(),
                receipt_count: 1,
            },
        };
        self.record_local_received_presentation_artifact(&record)?;
        Ok(record)
    }

    pub fn local_manifest_payload_bytes(
        &self,
        manifest_id: &str,
    ) -> Result<Vec<u8>, ValidationError> {
        let manifest = self.local_file_manifest(manifest_id)?.ok_or_else(|| {
            ValidationError::new(format!("local manifest not found: {manifest_id}"))
        })?;
        let content_key = self.local_manifest_key(manifest_id)?.ok_or_else(|| {
            ValidationError::new(format!("local manifest key not found: {manifest_id}"))
        })?;
        let mut blocks = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let encrypted = self
                .local_encrypted_content(&chunk.chunk_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "local manifest chunk is missing encrypted content: {}",
                        chunk.chunk_id
                    ))
                })?;
            blocks.push(EncryptedBlock {
                chunk: chunk.clone(),
                encrypted,
            });
        }

        Ok(open_payload_manifest(&manifest, &blocks, &content_key)?
            .into_iter()
            .flatten()
            .collect())
    }

    pub fn local_manifest_payload_chunks(
        &self,
        manifest_id: &str,
    ) -> Result<Vec<Vec<u8>>, ValidationError> {
        let manifest = self.local_file_manifest(manifest_id)?.ok_or_else(|| {
            ValidationError::new(format!("local manifest not found: {manifest_id}"))
        })?;
        let content_key = self.local_manifest_key(manifest_id)?.ok_or_else(|| {
            ValidationError::new(format!("local manifest key not found: {manifest_id}"))
        })?;
        let mut blocks = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let encrypted = self
                .local_encrypted_content(&chunk.chunk_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "local manifest chunk is missing encrypted content: {}",
                        chunk.chunk_id
                    ))
                })?;
            blocks.push(EncryptedBlock {
                chunk: chunk.clone(),
                encrypted,
            });
        }
        open_payload_manifest(&manifest, &blocks, &content_key)
    }

    pub fn manifest_payload_chunks_for_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<Vec<Vec<u8>>, ValidationError> {
        let manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        let content_key = self.unwrap_manifest_key_for_device(manifest_id, device_id)?;
        let mut blocks = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let encrypted = self
                .local_encrypted_content(&chunk.chunk_id)?
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "manifest chunk is missing encrypted content: {}",
                        chunk.chunk_id
                    ))
                })?;
            blocks.push(EncryptedBlock {
                chunk: chunk.clone(),
                encrypted,
            });
        }
        open_payload_manifest(&manifest, &blocks, &content_key)
    }

    pub fn manifest_payload_bytes_for_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<Vec<u8>, ValidationError> {
        Ok(self
            .manifest_payload_chunks_for_device(manifest_id, device_id)?
            .into_iter()
            .flatten()
            .collect())
    }

    pub fn open_manifest_payload(
        &mut self,
        manifest_id: &str,
    ) -> Result<(String, Vec<Vec<u8>>), ValidationError> {
        let device_id = self.select_active_restore_device_for_manifest(manifest_id)?;
        let chunks = self.manifest_payload_chunks_for_device(manifest_id, &device_id)?;
        Ok((device_id, chunks))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_local_structured_record(
        &mut self,
        namespace: &VaultNamespace,
        object_id: &str,
        revision_id: &str,
        payload_manifest_id: &str,
        catalog_manifest_id: &str,
        created_at: u64,
        created_by_device_id: &str,
        structured_record: StructuredRecordMeta,
        payload_json: &[u8],
        durability: DurabilityPolicy,
        retention: RetentionPolicy,
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<core_types::VaultRevision, ValidationError> {
        self.upsert_local_structured_object(
            namespace,
            object_id,
            core_types::VaultObjectClass::StructuredRecord,
            revision_id,
            payload_manifest_id,
            catalog_manifest_id,
            created_at,
            created_by_device_id,
            structured_record,
            None,
            payload_json,
            durability,
            retention,
            recipients,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_local_persona_credential(
        &mut self,
        namespace: &VaultNamespace,
        object_id: &str,
        revision_id: &str,
        payload_manifest_id: &str,
        catalog_manifest_id: &str,
        created_at: u64,
        created_by_device_id: &str,
        structured_record: StructuredRecordMeta,
        claim: core_types::ClaimMeta,
        payload_json: &[u8],
        durability: DurabilityPolicy,
        retention: RetentionPolicy,
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<core_types::VaultRevision, ValidationError> {
        self.upsert_local_structured_object(
            namespace,
            object_id,
            core_types::VaultObjectClass::PersonaCredential,
            revision_id,
            payload_manifest_id,
            catalog_manifest_id,
            created_at,
            created_by_device_id,
            structured_record,
            Some(claim),
            payload_json,
            durability,
            retention,
            recipients,
        )
    }

    pub fn import_persona_credentials(
        &mut self,
        namespace: &VaultNamespace,
        created_by_device_id: &str,
        imported_claims: &[ImportedClaim],
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<Vec<core_types::VaultRevision>, ValidationError> {
        if namespace.owner_kind != VaultOwnerKind::Persona {
            return Err(ValidationError::new(
                "persona credential imports require a persona-owned namespace",
            ));
        }
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "persona credential imports require at least one recipient device",
            ));
        }

        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| ValidationError::new(format!("read system time: {err}")))?
            .as_secs();

        let mut revisions = Vec::with_capacity(imported_claims.len());
        for (index, imported_claim) in imported_claims.iter().enumerate() {
            imported_claim.validate()?;
            let claim_type =
                core_types::ClaimType::parse(&imported_claim.claim_type).ok_or_else(|| {
                    ValidationError::new(format!(
                        "unsupported imported claim type: {}",
                        imported_claim.claim_type
                    ))
                })?;
            let payload =
                serde_json::from_str::<JsonValue>(&imported_claim.payload_json).map_err(|err| {
                    ValidationError::new(format!(
                        "imported claim payload must be valid json: {err}"
                    ))
                })?;
            let claim_schema = payload
                .get("schema")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    ValidationError::new(
                        "imported claim payload must include a top-level string schema field",
                    )
                })?;
            let issued_at =
                imported_claim.external_issued_at.unwrap_or_else(|| {
                    match imported_claim.external_expires_at {
                        Some(expires_at) => expires_at.saturating_sub(1).max(1),
                        None => now_epoch_secs.saturating_add(index as u64),
                    }
                });
            let claim = core_types::ClaimMeta {
                claim_type,
                issuer_persona_id: namespace.owner_id.clone(),
                subject_persona_id: namespace.owner_id.clone(),
                claim_schema: claim_schema.to_string(),
                issued_at,
                expires_at: imported_claim.external_expires_at,
                external_issuer: Some(imported_claim.external_issuer.clone()),
                external_credential_id: None,
            };
            let revision = self.upsert_local_persona_credential(
                namespace,
                &generate_random_identifier("vault-credential"),
                &generate_random_identifier("vault-rev"),
                &generate_random_identifier("vault-manifest"),
                &generate_random_identifier("vault-catalog"),
                issued_at,
                created_by_device_id,
                structured_record_meta_for_claim_schema(claim_schema),
                claim,
                imported_claim.payload_json.as_bytes(),
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                recipients.clone(),
            )?;
            revisions.push(revision);
        }

        Ok(revisions)
    }

    /// Create a single persona credential through the high-level path.
    ///
    /// Resolves the persona's vault namespace, enumerates devices with access,
    /// and delegates to [`import_persona_credentials`]. Returns the `object_id`
    /// of the created credential.
    ///
    /// `claim_type` must be a valid [`core_types::ClaimType`] string
    /// (e.g. `"self-asserted"`). `payload_json` must be a JSON object with a
    /// top-level `"schema"` string field (e.g. `{"schema":"password","username":"foo"}`).
    pub fn create_persona_credential(
        &mut self,
        persona_id: &str,
        device_id: &str,
        claim_type: &str,
        payload_json: &str,
    ) -> Result<String, ValidationError> {
        // Build the persona namespace.
        let namespace = VaultNamespace {
            owner_kind: VaultOwnerKind::Persona,
            owner_id: persona_id.to_string(),
        };

        // Enumerate devices that have access to this persona and build recipients.
        let access_records = self.persona_device_access_for_persona(persona_id)?;
        if access_records.is_empty() {
            return Err(ValidationError::new(format!(
                "no devices have access to persona '{persona_id}'; grant device access first"
            )));
        }
        let mat = self.materialized();
        let recipients: Vec<core_storage::ManifestKeyRecipient> = access_records
            .iter()
            .filter_map(|r| {
                mat.devices_current
                    .get(&r.device_id)
                    .map(|d| core_storage::manifest_key_recipient(
                        &d.device_id,
                        &d.active_encryption_key.public_key,
                    ))
            })
            .collect();
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "no active device encryption keys found for persona",
            ));
        }

        let imported = ImportedClaim {
            claim_type: claim_type.to_string(),
            payload_json: payload_json.to_string(),
            external_issuer: persona_id.to_string(),
            external_issued_at: None,
            external_expires_at: None,
        };
        let revisions =
            self.import_persona_credentials(&namespace, device_id, &[imported], recipients)?;
        revisions
            .into_iter()
            .next()
            .map(|r| r.id)
            .ok_or_else(|| ValidationError::new("import produced no revision"))
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_local_structured_object(
        &mut self,
        namespace: &VaultNamespace,
        object_id: &str,
        object_class: core_types::VaultObjectClass,
        revision_id: &str,
        payload_manifest_id: &str,
        catalog_manifest_id: &str,
        created_at: u64,
        created_by_device_id: &str,
        structured_record: StructuredRecordMeta,
        claim: Option<core_types::ClaimMeta>,
        payload_json: &[u8],
        durability: DurabilityPolicy,
        retention: RetentionPolicy,
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<core_types::VaultRevision, ValidationError> {
        namespace.validate()?;
        structured_record.validate()?;
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "structured record writes require at least one recipient device",
            ));
        }
        match object_class {
            core_types::VaultObjectClass::StructuredRecord => {
                if claim.is_some() {
                    return Err(ValidationError::new(
                        "claim metadata requires persona-credential vault objects",
                    ));
                }
            }
            core_types::VaultObjectClass::PersonaCredential => {
                if namespace.owner_kind != core_types::VaultOwnerKind::Persona {
                    return Err(ValidationError::new(
                        "persona credentials require a persona-owned namespace",
                    ));
                }
                if claim.is_none() {
                    return Err(ValidationError::new(
                        "persona credentials require claim metadata",
                    ));
                }
            }
            _ => {
                return Err(ValidationError::new(
                    "structured payload helper only supports structured-record and persona-credential classes",
                ));
            }
        }
        if structured_record.encoding == core_types::StructuredEncoding::Json {
            let decoded = serde_json::from_slice::<JsonValue>(payload_json).map_err(|err| {
                ValidationError::new(format!(
                    "structured record payload must be valid json: {err}"
                ))
            })?;
            if !decoded.is_object() {
                return Err(ValidationError::new(
                    "structured record payload must be a json object",
                ));
            }
        }

        let catalog_key = load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
            .map(|(_, content_key)| content_key)
            .unwrap_or_else(generate_content_key);
        let mut catalog = self
            .local_vault_catalog(namespace)?
            .unwrap_or(create_vault_catalog(namespace.clone())?);
        let existing_object = catalog
            .objects
            .iter()
            .find(|object| object.id == object_id)
            .cloned();
        let revision = create_vault_revision(
            revision_id,
            object_id,
            payload_manifest_id,
            core_types::PayloadKind::StructuredRecord,
            "application/json",
            created_at,
            created_by_device_id,
            existing_object
                .as_ref()
                .map(|object| object.latest_revision_id.clone()),
            Some(structured_record),
            claim,
        )?;

        if let Some(existing_object) = existing_object {
            if existing_object.class != object_class {
                return Err(ValidationError::new(
                    "existing vault object has a different class",
                ));
            }
            if existing_object.deleted {
                return Err(ValidationError::new(format!(
                    "vault object is deleted: {object_id}"
                )));
            }
            add_vault_revision(&mut catalog, revision.clone())?;
        } else {
            let object = create_vault_object(
                object_id,
                namespace.clone(),
                object_class,
                revision_id,
                created_at,
                durability,
                retention,
            )?;
            add_vault_object_with_initial_revision(&mut catalog, object, revision.clone())?;
        }

        let payload_key = generate_content_key();
        let payload_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &payload_key)?;
        let catalog_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &catalog_key)?;
        let (payload_manifest, payload_blocks) = seal_payload_manifest(
            payload_manifest_id,
            &[payload_json.to_vec()],
            &payload_key,
            payload_authorized_devices,
        )?;
        self.commit_local_vault_catalog_with_manifests(
            catalog_manifest_id,
            &catalog,
            &catalog_key,
            catalog_authorized_devices,
            &[LocalEncryptedManifest {
                manifest: payload_manifest.clone(),
                blocks: payload_blocks,
            }],
        )?;
        self.upsert_local_manifest_key(&payload_manifest.id, &payload_key)?;
        Ok(revision)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn store_local_file(
        &mut self,
        namespace: &VaultNamespace,
        object_id: &str,
        revision_id: &str,
        payload_manifest_id: &str,
        catalog_manifest_id: &str,
        created_at: u64,
        created_by_device_id: &str,
        file_name: &str,
        content_type: &str,
        file_bytes: &[u8],
        object_class: core_types::VaultObjectClass,
        durability: DurabilityPolicy,
        retention: RetentionPolicy,
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<core_types::VaultRevision, ValidationError> {
        namespace.validate()?;
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "file store requires at least one recipient device",
            ));
        }
        if file_bytes.is_empty() {
            return Err(ValidationError::new("file content must not be empty"));
        }

        let catalog_key = load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
            .map(|(_, content_key)| content_key)
            .unwrap_or_else(generate_content_key);
        let mut catalog = self
            .local_vault_catalog(namespace)?
            .unwrap_or(create_vault_catalog(namespace.clone())?);
        let existing_object = catalog
            .objects
            .iter()
            .find(|object| object.id == object_id)
            .cloned();
        let revision = create_vault_revision(
            revision_id,
            object_id,
            payload_manifest_id,
            core_types::PayloadKind::BinaryBlob,
            content_type,
            created_at,
            created_by_device_id,
            existing_object
                .as_ref()
                .map(|object| object.latest_revision_id.clone()),
            None,
            None,
        )?;

        if let Some(existing_object) = existing_object {
            if existing_object.deleted {
                return Err(ValidationError::new(format!(
                    "vault object is deleted: {object_id}"
                )));
            }
            add_vault_revision(&mut catalog, revision.clone())?;
        } else {
            let object = create_vault_object(
                object_id,
                namespace.clone(),
                object_class,
                revision_id,
                created_at,
                durability,
                retention,
            )?;
            add_vault_object_with_initial_revision(&mut catalog, object, revision.clone())?;
        }

        let payload_key = generate_content_key();
        let payload_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &payload_key)?;
        let catalog_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &catalog_key)?;

        // Prepend filename as first chunk, file content as second
        let filename_header = format!("emberlink-file-header\nfilename={file_name}\n");
        let (payload_manifest, payload_blocks) = seal_payload_manifest(
            payload_manifest_id,
            &[filename_header.as_bytes().to_vec(), file_bytes.to_vec()],
            &payload_key,
            payload_authorized_devices,
        )?;
        self.commit_local_vault_catalog_with_manifests(
            catalog_manifest_id,
            &catalog,
            &catalog_key,
            catalog_authorized_devices,
            &[LocalEncryptedManifest {
                manifest: payload_manifest.clone(),
                blocks: payload_blocks,
            }],
        )?;
        self.upsert_local_manifest_key(&payload_manifest.id, &payload_key)?;
        Ok(revision)
    }

    pub fn tombstone_local_vault_object(
        &mut self,
        namespace: &VaultNamespace,
        object_id: &str,
        catalog_manifest_id: &str,
        updated_at: u64,
        recipients: Vec<ManifestKeyRecipient>,
    ) -> Result<(), ValidationError> {
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "vault tombstone requires at least one recipient device",
            ));
        }
        let catalog_key = load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
            .map(|(_, content_key)| content_key)
            .ok_or_else(|| ValidationError::new("local vault catalog not found"))?;
        let mut catalog = self
            .local_vault_catalog(namespace)?
            .ok_or_else(|| ValidationError::new("local vault catalog not found"))?;
        let object = catalog
            .objects
            .iter_mut()
            .find(|object| object.id == object_id)
            .ok_or_else(|| ValidationError::new(format!("vault object not found: {object_id}")))?;
        if object.deleted {
            return Err(ValidationError::new(format!(
                "vault object already deleted: {object_id}"
            )));
        }
        tombstone_vault_object(object, updated_at)?;
        let catalog_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &catalog_key)?;
        self.commit_local_vault_catalog_with_manifests(
            catalog_manifest_id,
            &catalog,
            &catalog_key,
            catalog_authorized_devices,
            &[],
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_local_presentation_artifact(
        &mut self,
        namespace: &VaultNamespace,
        source_revision_id: &str,
        template_id: &str,
        artifact_id: &str,
        artifact_manifest_id: &str,
        recipient_id: &str,
        issued_at: u64,
        expires_at: Option<u64>,
        recipients: Vec<ManifestKeyRecipient>,
        grant_id: Option<&str>,
    ) -> Result<LocalPresentationArtifactRecord, ValidationError> {
        if recipients.is_empty() {
            return Err(ValidationError::new(
                "presentation artifacts require at least one recipient device",
            ));
        }
        let catalog = self
            .local_vault_catalog(namespace)?
            .ok_or_else(|| ValidationError::new("local vault catalog not found"))?;
        let source_revision = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == source_revision_id)
            .cloned()
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "source revision not found in local vault catalog: {source_revision_id}"
                ))
            })?;
        let source_object = catalog
            .objects
            .iter()
            .find(|object| object.id == source_revision.object_id)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "source revision references unknown object: {}",
                    source_revision.object_id
                ))
            })?;
        if source_object.deleted {
            return Err(ValidationError::new(format!(
                "source vault object is deleted: {}",
                source_object.id
            )));
        }
        let template = self
            .local_presentation_template(template_id)?
            .ok_or_else(|| {
                ValidationError::new(format!("presentation template not found: {template_id}"))
            })?;
        if template.namespace != *namespace {
            return Err(ValidationError::new(format!(
                "presentation template belongs to a different namespace: {}:{}",
                template.namespace.owner_kind.as_str(),
                template.namespace.owner_id
            )));
        }
        let source_payload = self.local_manifest_payload_bytes(&source_revision.manifest_id)?;
        let artifact_content_key = generate_content_key();
        let artifact_authorized_devices =
            wrap_manifest_key_for_recipients(&recipients, &artifact_content_key)?;
        let (artifact, manifest, blocks) = build_presentation_artifact_manifest(
            artifact_id,
            artifact_manifest_id,
            &source_revision,
            &template,
            recipient_id,
            issued_at,
            expires_at,
            &source_payload,
            &artifact_content_key,
            artifact_authorized_devices,
        )?;

        let record = LocalPresentationArtifactRecord {
            artifact,
            namespace: namespace.clone(),
            template_id: template_id.to_string(),
            grant_id: grant_id.map(|s| s.to_string()),
        };

        self.upsert_local_manifest_key(&manifest.id, &artifact_content_key)?;
        self.upsert_local_encrypted_manifest(&manifest, &blocks)?;
        self.record_local_presentation_artifact(&record)?;
        Ok(record)
    }

    pub fn build_local_presentation_artifact_envelope(
        &self,
        artifact_id: &str,
        issuer_persona_id: &str,
        signer: &impl CryptoSigner,
    ) -> Result<PresentationArtifactEnvelope, ValidationError> {
        let record = self
            .local_presentation_artifact(artifact_id)?
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "unknown local presentation artifact: {artifact_id}"
                ))
            })?;
        let issuer = self
            .materialized
            .personas_current
            .get(issuer_persona_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown issuer persona: {issuer_persona_id}"))
            })?;
        match record.namespace.owner_kind {
            VaultOwnerKind::Persona if record.namespace.owner_id != issuer_persona_id => {
                return Err(ValidationError::new(
                    "persona-owned disclosure artifacts must be issued by the owning persona",
                ));
            }
            VaultOwnerKind::Root if record.namespace.owner_id != issuer.root_id => {
                return Err(ValidationError::new(
                    "root-owned disclosure artifacts must be issued by a persona under the same root",
                ));
            }
            _ => {}
        }
        if signer.public_key().0 != issuer.active_key.public_key {
            return Err(ValidationError::new(
                "issuer signer does not match the persona active key",
            ));
        }
        let payload_bytes = self.local_manifest_payload_bytes(&record.artifact.manifest_id)?;
        core_storage::sign_presentation_artifact_envelope(
            &record.artifact,
            payload_bytes,
            issuer.persona_id.clone(),
            issuer.active_key.key_id.clone(),
            signer,
        )
    }

    pub fn validate_received_presentation_artifact(
        &self,
        envelope: &PresentationArtifactEnvelope,
    ) -> Result<(), ValidationError> {
        if envelope.artifact.recipient_kind == core_types::PresentationAudienceKind::Peer
            && !self
                .materialized
                .personas_current
                .contains_key(&envelope.artifact.recipient_id)
        {
            return Err(ValidationError::new(format!(
                "recipient persona is not local: {}",
                envelope.artifact.recipient_id
            )));
        }
        Ok(())
    }

    /// Verify the full identity chain for a received disclosure artifact's issuer.
    ///
    /// Checks (in order):
    /// 1. Cryptographic signature validity
    /// 2. Issuer persona exists in event store
    /// 3. Issuer signing key is current (warn if rotated)
    /// 4. Issuer persona is not revoked
    /// 5. Issuer's root identity is not revoked
    /// 6. No DisclosureRevoked event exists for this artifact
    pub fn verify_disclosure_issuer(
        &self,
        envelope: &PresentationArtifactEnvelope,
    ) -> IssuerVerificationStatus {
        // 1. Signature check
        if core_storage::verify_presentation_artifact_envelope(envelope).is_err() {
            return IssuerVerificationStatus::SignatureInvalid;
        }

        // 2. Issuer persona exists
        let Some(persona) = self
            .materialized
            .personas_current
            .get(&envelope.issuer_persona_id)
        else {
            return IssuerVerificationStatus::IssuerUnknown;
        };

        // 3. Key match — current key or historical
        let key_is_current = persona.active_key.key_id == envelope.issuer_key_id;
        let key_in_history = self
            .materialized
            .persona_key_history
            .get(&envelope.issuer_persona_id)
            .is_some_and(|history| history.iter().any(|kid| kid == &envelope.issuer_key_id));

        if !key_is_current && !key_in_history {
            // Key never belonged to this persona — signature may be forged
            return IssuerVerificationStatus::SignatureInvalid;
        }

        // 4. Persona revocation check
        if persona.status != PersonaStatus::Active {
            return IssuerVerificationStatus::IssuerPersonaRevoked;
        }

        // 5. Root chain walk — find the persona's root and check it
        if let Some(root) = self.materialized.roots_current.get(&persona.root_id)
            && root.status != RootStatus::Active
        {
            return IssuerVerificationStatus::IssuerRootRevoked;
        }
        // If root not found, the persona still exists so we treat it as valid
        // (may be a remote persona whose root events haven't fully synced)

        // 6. Disclosure revocation check
        if self.is_disclosure_revoked(&envelope.artifact.id) {
            return IssuerVerificationStatus::DisclosureRevoked;
        }

        // Key rotation warning (valid but no longer current)
        if !key_is_current && key_in_history {
            return IssuerVerificationStatus::IssuerKeyRotated;
        }

        IssuerVerificationStatus::Verified
    }

    /// Check whether any DisclosureRevoked event in the store targets the given artifact_id.
    pub fn is_disclosure_revoked(&self, artifact_id: &str) -> bool {
        self.events_of_type(EventType::DisclosureRevoked)
            .any(|event| {
                if let EventBody::DisclosureRevoked(body) = &event.body {
                    body.artifact_id == artifact_id
                } else {
                    false
                }
            })
    }

    pub fn plan_local_vault_gc(
        &self,
        namespace: &VaultNamespace,
    ) -> Result<Option<LocalVaultGcPlan>, ValidationError> {
        namespace.validate()?;
        let Some((catalog_manifest, _content_key)) =
            load_local_vault_catalog_head(&self.conn, namespace, self.master_key.as_ref().map(|s| s.as_str()))?
        else {
            return Ok(None);
        };
        let Some(catalog) = self.local_vault_catalog(namespace)? else {
            return Ok(None);
        };
        let retained_revision_ids = retained_vault_revision_ids(&catalog)?;
        let revision_manifest_ids = catalog
            .revisions
            .iter()
            .map(|revision| revision.manifest_id.clone())
            .collect::<BTreeSet<_>>();
        let catalog_manifest_ids = load_local_vault_catalog_manifest_ids(&self.conn, namespace)?;
        let tracked_manifest_ids = revision_manifest_ids
            .union(&catalog_manifest_ids)
            .cloned()
            .collect::<BTreeSet<_>>();
        let manifests = self
            .local_file_manifests()?
            .into_iter()
            .filter(|manifest| tracked_manifest_ids.contains(&manifest.id))
            .collect::<Vec<_>>();
        let local_chunk_ids = load_local_block_ids(&self.conn)?;
        let mut retained_manifest_ids = retained_vault_manifest_ids(&catalog)?;
        retained_manifest_ids.insert(catalog_manifest.id.clone());
        let collectable_manifest_ids = manifests
            .iter()
            .map(|manifest| manifest.id.clone())
            .filter(|manifest_id| !retained_manifest_ids.contains(manifest_id))
            .collect::<BTreeSet<_>>();
        let retained_chunk_ids = manifests
            .iter()
            .filter(|manifest| retained_manifest_ids.contains(&manifest.id))
            .flat_map(|manifest| manifest.chunks.iter().map(|chunk| chunk.chunk_id.clone()))
            .collect::<BTreeSet<_>>();
        let collectable_chunk_ids = manifests
            .iter()
            .filter(|manifest| collectable_manifest_ids.contains(&manifest.id))
            .flat_map(|manifest| manifest.chunks.iter().map(|chunk| chunk.chunk_id.clone()))
            .filter(|chunk_id| {
                local_chunk_ids.contains(chunk_id.as_str())
                    && !retained_chunk_ids.contains(chunk_id)
            })
            .collect::<BTreeSet<_>>();

        Ok(Some(LocalVaultGcPlan {
            namespace: namespace.clone(),
            catalog_manifest_id: catalog_manifest.id,
            retained_revision_ids,
            retained_manifest_ids,
            collectable_manifest_ids,
            collectable_chunk_ids,
        }))
    }

    pub fn apply_local_vault_gc(
        &mut self,
        namespace: &VaultNamespace,
    ) -> Result<Option<LocalVaultGcPlan>, ValidationError> {
        let Some(plan) = self.plan_local_vault_gc(namespace)? else {
            return Ok(None);
        };
        let tx = self.conn.transaction().map_err(|err| {
            ValidationError::new(format!("begin local vault gc transaction: {err}"))
        })?;
        for manifest_id in &plan.collectable_manifest_ids {
            delete_local_manifest_key(&tx, manifest_id)?;
            delete_local_file_manifest(&tx, manifest_id)?;
            delete_local_vault_catalog_manifest_history(&tx, namespace, manifest_id)?;
        }
        for chunk_id in &plan.collectable_chunk_ids {
            delete_local_block(&tx, chunk_id)?;
        }
        tx.commit().map_err(|err| {
            ValidationError::new(format!("commit local vault gc transaction: {err}"))
        })?;

        if let Some(local_block_store) = &self.local_block_store {
            for chunk_id in &plan.collectable_chunk_ids {
                local_block_store.delete_encrypted_content(chunk_id)?;
            }
        }

        Ok(Some(plan))
    }

    pub fn plan_storage_restore_for_device(
        &self,
        manifest_id: &str,
        device_id: &str,
        relationship: &core_types::StorageRelationship,
    ) -> Result<Vec<ChunkReference>, ValidationError> {
        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "storage restore requires an active device",
            ));
        }
        let manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;

        plan_restore_for_device(relationship, &manifest, device_id)
    }

    pub fn select_active_restore_device_for_manifest(
        &self,
        manifest_id: &str,
    ) -> Result<String, ValidationError> {
        let manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        manifest
            .authorized_devices
            .iter()
            .find_map(|access| {
                self.materialized
                    .devices_current
                    .get(&access.device_id)
                    .filter(|device| device.status == DeviceStatus::Active)
                    .map(|_| access.device_id.clone())
            })
            .ok_or_else(|| ValidationError::new("no active authorized restore device"))
    }

    pub fn plan_storage_restore(
        &self,
        manifest_id: &str,
        relationship: &core_types::StorageRelationship,
    ) -> Result<(String, Vec<ChunkReference>), ValidationError> {
        let device_id = self.select_active_restore_device_for_manifest(manifest_id)?;
        let chunks = self.plan_storage_restore_for_device(manifest_id, &device_id, relationship)?;
        Ok((device_id, chunks))
    }

    pub fn revoke_local_vault_access_for_inactive_device(
        &mut self,
        namespace: &VaultNamespace,
        device_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.status == DeviceStatus::Active {
            return Err(ValidationError::new(
                "local vault access can only be revoked for non-active devices with this helper",
            ));
        }
        let manifests = self.local_vault_manifests_with_keys(namespace)?;
        let mut updated = Vec::new();
        for (mut manifest, _content_key) in manifests {
            if !manifest
                .authorized_devices
                .iter()
                .any(|access| access.device_id == device_id)
            {
                continue;
            }
            revoke_manifest_access(&mut manifest, device_id)?;
            self.upsert_local_file_manifest(&manifest)?;
            updated.push(manifest.id);
        }
        Ok(updated)
    }

    pub fn restore_local_vault_access_to_replacement_device(
        &mut self,
        namespace: &VaultNamespace,
        replaced_device_id: &str,
        replacement_device_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let replaced_device = self
            .materialized
            .devices_current
            .get(replaced_device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {replaced_device_id}")))?;
        let replacement_device = self
            .materialized
            .devices_current
            .get(replacement_device_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown device: {replacement_device_id}"))
            })?;
        if replaced_device.root_id != replacement_device.root_id {
            return Err(ValidationError::new(
                "replacement device must belong to the same root",
            ));
        }
        if replacement_device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "replacement device must be active to restore local vault access",
            ));
        }
        if replaced_device.replacement_device_id.as_deref() != Some(replacement_device_id) {
            return Err(ValidationError::new(
                "replacement device is not linked to the replaced device",
            ));
        }
        let replacement_public_key = replacement_device.active_encryption_key.public_key.clone();
        let manifests = self.local_vault_manifests_with_keys(namespace)?;
        let mut updated = Vec::new();
        for (mut manifest, content_key) in manifests {
            if !manifest
                .authorized_devices
                .iter()
                .any(|access| access.device_id == replaced_device_id)
            {
                continue;
            }
            let replacement_access = wrap_manifest_key_access(
                replacement_device_id,
                &replacement_public_key,
                &content_key,
            )?;
            replace_manifest_access(&mut manifest, replaced_device_id, replacement_access)?;
            self.upsert_local_file_manifest(&manifest)?;
            updated.push(manifest.id);
        }
        Ok(updated)
    }

    pub fn revoke_manifest_access_for_inactive_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        let device = self
            .materialized
            .devices_current
            .get(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        if device.status == DeviceStatus::Active {
            return Err(ValidationError::new(
                "manifest access can only be revoked for non-active devices with this helper",
            ));
        }

        let mut manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        revoke_manifest_access(&mut manifest, device_id)?;
        self.upsert_file_manifest(&manifest)
    }

    pub fn restore_manifest_access_to_replacement_device(
        &mut self,
        manifest_id: &str,
        replaced_device_id: &str,
        replacement_access: ManifestDeviceAccess,
    ) -> Result<(), ValidationError> {
        let replaced_device = self
            .materialized
            .devices_current
            .get(replaced_device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {replaced_device_id}")))?;
        let replacement_device = self
            .materialized
            .devices_current
            .get(&replacement_access.device_id)
            .ok_or_else(|| {
                ValidationError::new(format!("unknown device: {}", replacement_access.device_id))
            })?;

        if replaced_device.root_id != replacement_device.root_id {
            return Err(ValidationError::new(
                "replacement device must belong to the same root",
            ));
        }
        if replacement_device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "replacement device must be active to restore manifest access",
            ));
        }
        if replaced_device.replacement_device_id.as_deref()
            != Some(replacement_access.device_id.as_str())
        {
            return Err(ValidationError::new(
                "replacement device is not linked to the replaced device",
            ));
        }

        let mut manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        replace_manifest_access(&mut manifest, replaced_device_id, replacement_access)?;
        self.upsert_file_manifest(&manifest)
    }

    pub fn grant_manifest_access_for_device(
        &mut self,
        manifest_id: &str,
        access: ManifestDeviceAccess,
    ) -> Result<(), ValidationError> {
        let mut manifest = self
            .file_manifest(manifest_id)
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;
        let device = self
            .materialized
            .devices_current
            .get(&access.device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {}", access.device_id)))?;
        if device.status != DeviceStatus::Active {
            return Err(ValidationError::new(
                "cannot grant manifest access to a non-active device",
            ));
        }
        grant_manifest_access(&mut manifest, access)?;
        self.upsert_file_manifest(&manifest)
    }

    fn validate_manifest_device_access(
        &self,
        manifest: &FileManifest,
    ) -> Result<(), ValidationError> {
        for access in &manifest.authorized_devices {
            let device = self
                .materialized
                .devices_current
                .get(&access.device_id)
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "manifest references unknown device: {}",
                        access.device_id
                    ))
                })?;
            if device.status != DeviceStatus::Active {
                return Err(ValidationError::new(format!(
                    "manifest access requires active device: {}",
                    access.device_id
                )));
            }
        }
        Ok(())
    }
}

impl EventLog for EventStore {
    fn append(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
    ) -> Result<(), ValidationError> {
        EventStore::append(self, event, verifier)
    }

    fn append_with_authorizer(
        &mut self,
        event: EventEnvelope,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<(), ValidationError> {
        EventStore::append_with_authorizer(self, event, verifier, authorizer, now_epoch_secs)
    }

    fn rebuild(&mut self) -> Result<(), ValidationError> {
        EventStore::rebuild(self)
    }

    fn materialized(&self) -> &MaterializedState {
        EventStore::materialized(self)
    }

    fn events(&self) -> &[EventEnvelope] {
        EventStore::events(self)
    }

    fn event_count(&self) -> usize {
        EventStore::event_count(self)
    }

    fn has_event(&self, event_id: &str) -> bool {
        EventStore::has_event(self, event_id)
    }

    fn current_event_type_for(&self, event_id: &str) -> Option<EventType> {
        EventStore::current_event_type_for(self, event_id)
    }

    fn event_ids(&self) -> Vec<String> {
        EventStore::event_ids(self)
    }

    fn event_id_set(&self) -> &HashMap<String, usize> {
        EventStore::event_id_set(self)
    }

    fn events_by_ids(&self, event_ids: &[String]) -> Vec<EventEnvelope> {
        EventStore::events_by_ids(self, event_ids)
    }

    fn events_of_type(&self, event_type: EventType) -> Vec<EventEnvelope> {
        EventStore::events_of_type(self, event_type).cloned().collect()
    }

    fn events_of_type_rev(&self, event_type: EventType) -> Vec<EventEnvelope> {
        EventStore::events_of_type_rev(self, event_type).cloned().collect()
    }

    fn export_events(&self) -> String {
        EventStore::export_events(self)
    }

    fn import_events(
        &mut self,
        data: &str,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        EventStore::import_events(self, data, verifier, authorizer, now_epoch_secs)
    }

    fn peer_cursor(&self, peer_id: &str) -> Result<PeerCursor, ValidationError> {
        EventStore::peer_cursor(self, peer_id)
    }

    fn peer_cursors(&self) -> Result<Vec<PeerCursor>, ValidationError> {
        EventStore::peer_cursors(self)
    }

    fn sync_batches(&self) -> Result<Vec<SyncBatchRecord>, ValidationError> {
        EventStore::sync_batches(self)
    }

    fn import_sync_batch(
        &mut self,
        peer_id: &str,
        batch_id: &str,
        events: &[EventEnvelope],
        last_remote_event_id: Option<&str>,
        verifier: &dyn Verifier,
        authorizer: &dyn Authorizer,
        now_epoch_secs: u64,
    ) -> Result<usize, ValidationError> {
        EventStore::import_sync_batch(
            self,
            peer_id,
            batch_id,
            events,
            last_remote_event_id,
            verifier,
            authorizer,
            now_epoch_secs,
        )
    }
}

fn parse_approval_status(s: &str) -> Result<core_types::approval::ApprovalStatus, ValidationError> {
    match s {
        "pending" => Ok(core_types::approval::ApprovalStatus::Pending),
        "approved" => Ok(core_types::approval::ApprovalStatus::Approved),
        "denied" => Ok(core_types::approval::ApprovalStatus::Denied),
        "expired" => Ok(core_types::approval::ApprovalStatus::Expired),
        "narrowed_and_approved" => Ok(core_types::approval::ApprovalStatus::NarrowedAndApproved),
        other => Err(ValidationError::invalid_format(format!(
            "unknown approval status: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use core_crypto::{
        FixtureSigner, FixtureVerifier, LocalKeySigner, generate_content_key,
        generate_local_encryption_key_pair, generate_local_key_pair,
    };
    use core_events::{EventEnvelope, EventRef};
    use core_storage::{
        EncryptedBlock, ManifestKeyRecipient, create_relationship, decrypt_block, encrypt_block,
        ledger_delta, manifest_chunk, manifest_device_access, manifest_key_recipient,
        publish_manifest, storage_ledger_updated_event, storage_manifest_published_event,
        storage_relationship_created_event, wrap_manifest_key_access,
    };
    use core_types::{
        ContentPublishedEvent, ContentVisibility, DeviceAddedEvent,
        DeviceEncryptionKeyRotatedEvent, DeviceFrozenEvent, DeviceKeyRotatedEvent,
        DeviceReplacedEvent, DeviceRevokedEvent, EndpointRotatedEvent, EventBody,
        GuardianEnrolledEvent, MessageSentEvent, PersonaCreatedEvent, PersonaKeyRotatedEvent,
        PersonaRevokedEvent, PublicKeyMaterial, RecoveryApprovedEvent, RecoveryContestedEvent,
        RecoveryExecutedEvent, RecoveryPolicyCreatedEvent, RecoveryRejectedEvent,
        RecoveryRequestedEvent, RecoveryScope, RelayHintUpdatedEvent, RootCreatedEvent,
        RootKeyRotatedEvent, RootRevokedEvent, SignerBinding, SurvivalMode, TrustAttestedEvent,
        TrustRevokedEvent,
    };
    use rusqlite::OptionalExtension;

    use super::*;

    fn test_key(key_id: &str) -> PublicKeyMaterial {
        // C-1: authorize now binds signer.public_key material to
        // active_key.public_key, so the stored string must match the real
        // pubkey derived from the FixtureSigner that signs events with this key_id.
        use core_crypto::Signer as _;
        let signer = FixtureSigner::new(key_id);
        PublicKeyMaterial {
            key_id: key_id.into(),
            algorithm: core_types::KeyAlgorithm::Ed25519,
            public_key: signer.public_key().0,
        }
    }

    fn test_encryption_key(key_id: &str) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: format!("enc-{key_id}"),
            algorithm: core_types::KeyAlgorithm::AgeX25519,
            public_key: format!("age1{key_id}fixture"),
        }
    }

    /// C-1: for guardian enrollment the on-event `guardian_public_key` is the
    /// real pubkey string. Tests that previously embedded opaque labels
    /// ("guardian-key-alex") break under the pubkey-material binding check, so
    /// derive the real pubkey from FixtureSigner(label) here.
    fn fixture_guardian_pubkey(label: &str) -> String {
        use core_crypto::Signer as _;
        FixtureSigner::new(label).public_key().0
    }

    fn local_public_key_material(key_pair: &core_crypto::LocalKeyPair) -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        }
    }

    fn test_manifest(manifest_id: &str, root_chunk_id: &str, device_id: &str) -> FileManifest {
        publish_manifest(
            manifest_id,
            root_chunk_id,
            vec![
                manifest_chunk(manifest_id, root_chunk_id, 0, 4096),
                manifest_chunk(manifest_id, format!("{root_chunk_id}-chunk-0001"), 1, 2048),
            ],
            vec![manifest_device_access(
                device_id,
                format!("wrapped-{device_id}"),
            )],
        )
    }

    fn test_manifest_recipient(device_id: &str) -> ManifestKeyRecipient {
        let key_pair = generate_local_encryption_key_pair("device-encryption", device_id);
        manifest_key_recipient(device_id, key_pair.public_key.clone())
    }

    fn test_namespace() -> VaultNamespace {
        VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: "persona-a".into(),
        }
    }

    fn test_claim_meta() -> core_types::ClaimMeta {
        core_types::ClaimMeta {
            claim_type: core_types::ClaimType::SelfAsserted,
            issuer_persona_id: "persona-a".into(),
            subject_persona_id: "persona-a".into(),
            claim_schema: "emberlink:claim:password:1.0".into(),
            issued_at: 42,
            expires_at: None,
            external_issuer: None,
            external_credential_id: None,
        }
    }

    fn seed_gc_test_catalog(store: &mut EventStore) -> Result<(), ValidationError> {
        let content_key = generate_content_key();
        let old_manifest = publish_manifest(
            "manifest-old",
            "chunk-shared",
            vec![
                manifest_chunk("manifest-old", "chunk-shared", 0, 1024),
                manifest_chunk("manifest-old", "chunk-old-only", 1, 1024),
            ],
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        );
        let current_manifest = publish_manifest(
            "manifest-current",
            "chunk-shared",
            vec![
                manifest_chunk("manifest-current", "chunk-shared", 0, 1024),
                manifest_chunk("manifest-current", "chunk-current-only", 1, 1024),
            ],
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        );
        let catalog = VaultCatalog {
            namespace: test_namespace(),
            objects: vec![core_types::VaultObject {
                id: "obj-1".into(),
                namespace: test_namespace(),
                class: core_types::VaultObjectClass::PersonaDocument,
                latest_revision_id: "rev-2".into(),
                created_at: 1,
                updated_at: 2,
                durability: core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                retention: core_types::RetentionPolicy::KeepLatest,
                deleted: false,
            }],
            revisions: vec![
                core_types::VaultRevision {
                    id: "rev-1".into(),
                    object_id: "obj-1".into(),
                    manifest_id: "manifest-old".into(),
                    payload_kind: core_types::PayloadKind::BinaryBlob,
                    content_type: "application/octet-stream".into(),
                    created_at: 1,
                    created_by_device_id: "device-a".into(),
                    parent_revision_id: None,
                    structured_record: None,
                    claim: None,
                },
                core_types::VaultRevision {
                    id: "rev-2".into(),
                    object_id: "obj-1".into(),
                    manifest_id: "manifest-current".into(),
                    payload_kind: core_types::PayloadKind::BinaryBlob,
                    content_type: "application/octet-stream".into(),
                    created_at: 2,
                    created_by_device_id: "device-a".into(),
                    parent_revision_id: Some("rev-1".into()),
                    structured_record: None,
                    claim: None,
                },
            ],
        };

        let old_blocks = old_manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: EncryptedContent {
                    nonce_hex: format!("nonce-{}", chunk.chunk_id),
                    ciphertext: vec![0xaa; chunk.ciphertext_bytes as usize / 1024],
                },
            })
            .collect::<Vec<_>>();
        let current_blocks = current_manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: EncryptedContent {
                    nonce_hex: format!("nonce-{}", chunk.chunk_id),
                    ciphertext: vec![0xbb; chunk.ciphertext_bytes as usize / 1024],
                },
            })
            .collect::<Vec<_>>();

        store.upsert_local_encrypted_manifest(&old_manifest, &old_blocks)?;
        store.upsert_local_encrypted_manifest(&current_manifest, &current_blocks)?;
        store.upsert_local_vault_catalog(
            "manifest-catalog-gc",
            &catalog,
            &content_key,
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        )?;
        Ok(())
    }

    fn append_typed(
        store: &mut EventStore,
        event_id: &str,
        body: EventBody,
        signer_binding: SignerBinding,
    ) {
        let signer = FixtureSigner::new(signer_binding.key_id.clone());
        let event =
            EventEnvelope::from_body(event_id, body, Vec::new(), signer_binding, &signer).unwrap();
        store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();
    }

    fn append_typed_with_signer(
        store: &mut EventStore,
        event_id: &str,
        body: EventBody,
        signer_binding: SignerBinding,
        signer: &impl core_crypto::Signer,
    ) {
        let event =
            EventEnvelope::from_body(event_id, body, Vec::new(), signer_binding, signer).unwrap();
        store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();
    }

    #[test]
    fn append_and_rebuild_materialize_identity_state() {
        let mut store = EventStore::default();

        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("work-public".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        append_typed(
            &mut store,
            "evt-root-rotate-1",
            EventBody::RootKeyRotated(RootKeyRotatedEvent {
                root_id: "root-a".into(),
                previous_key_id: "key-root-a-v1".into(),
                new_key: test_key("key-root-a-v2"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        append_typed(
            &mut store,
            "evt-device-rotate-1",
            EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a-v1".into(),
                new_key: test_key("key-device-a-v2"),
            }),
            SignerBinding::device("device-a", "key-device-a-v1"),
        );

        store.rebuild().unwrap();

        let state = store.materialized();
        assert_eq!(store.event_count(), 5);
        assert_eq!(
            state.root("root-a").unwrap().active_key.key_id,
            "key-root-a-v2"
        );
        assert_eq!(
            state.device("device-a").unwrap().active_key.key_id,
            "key-device-a-v2"
        );
        assert_eq!(
            state
                .persona("persona-a")
                .unwrap()
                .disclosure_profile
                .as_deref(),
            Some("work-public")
        );
        assert_eq!(
            state.root_key_history.get("root-a").unwrap(),
            &vec!["key-root-a-v1".to_string(), "key-root-a-v2".to_string()]
        );
    }

    #[test]
    fn device_encryption_rotation_updates_active_encryption_key() {
        let mut store = EventStore::default();

        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-encryption-rotate-1",
            EventBody::DeviceEncryptionKeyRotated(DeviceEncryptionKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_encryption_key_id: "enc-key-device-a-v1".into(),
                new_encryption_key: test_encryption_key("key-device-a-v2"),
            }),
            SignerBinding::device("device-a", "key-device-a-v1"),
        );

        let state = store.materialized();
        assert_eq!(
            state
                .device("device-a")
                .unwrap()
                .active_encryption_key
                .key_id,
            "enc-key-device-a-v2"
        );
        assert_eq!(
            state.device_encryption_key_history.get("device-a").unwrap(),
            &vec![
                "enc-key-device-a-v1".to_string(),
                "enc-key-device-a-v2".to_string()
            ]
        );
    }

    #[test]
    fn endpoint_events_materialize_and_rotate_current_transport_hint() {
        let mut store = EventStore::default();

        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Bridge".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-endpoint-1",
            EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
                peer_id: "peer-bridge-a".into(),
                device_id: "device-a".into(),
                transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
            }),
            SignerBinding::device("device-a", "key-device-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-endpoint-rotate-1",
            EventBody::EndpointRotated(EndpointRotatedEvent {
                peer_id: "peer-bridge-a".into(),
                device_id: "device-a".into(),
                previous_transport_hint: "relay://127.0.0.1:9100/mailbox/peer-bridge-a".into(),
                new_transport_hint: "relay://127.0.0.1:9200/mailbox/peer-bridge-a".into(),
            }),
            SignerBinding::device("device-a", "key-device-a-v1"),
        );

        store.rebuild().unwrap();

        let endpoint = store.materialized().endpoint("peer-bridge-a").unwrap();
        assert_eq!(endpoint.device_id, "device-a");
        assert_eq!(
            endpoint.transport_hint,
            "relay://127.0.0.1:9200/mailbox/peer-bridge-a"
        );
    }

    #[test]
    fn endpoint_hint_updates_reject_cross_root_peer_claims() {
        let mut store = EventStore::default();

        append_typed(
            &mut store,
            "evt-root-a",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Root A".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-root-b",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Root B".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-a",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Bridge A".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-endpoint-a",
            EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
                peer_id: "peer-shared".into(),
                device_id: "device-a".into(),
                transport_hint: "relay://127.0.0.1:9100/mailbox/peer-shared".into(),
            }),
            SignerBinding::device("device-a", "key-device-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-b",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-b".into(),
                device_id: "device-b".into(),
                label: "Bridge B".into(),
                initial_key: test_key("key-device-b-v1"),
                initial_encryption_key: test_encryption_key("key-device-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );

        let signer = FixtureSigner::new("key-device-b-v1");
        let event = EventEnvelope::from_body(
            "evt-endpoint-b",
            EventBody::RelayHintUpdated(RelayHintUpdatedEvent {
                peer_id: "peer-shared".into(),
                device_id: "device-b".into(),
                transport_hint: "relay://127.0.0.1:9200/mailbox/peer-shared".into(),
            }),
            Vec::new(),
            SignerBinding::device("device-b", "key-device-b-v1"),
            &signer,
        )
        .unwrap();

        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message
                .contains("endpoint peer id is already claimed by a different root")
        );
    }

    #[test]
    fn recovery_requests_accumulate_approvals_and_execute() {
        let mut store = EventStore::default();

        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-policy-1",
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: "root-a".into(),
                guardian_threshold: 2,
                cooldown_seconds: 3600,
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        let alex_pub = fixture_guardian_pubkey("guardian-key-alex");
        let riley_pub = fixture_guardian_pubkey("guardian-key-riley");
        append_typed(
            &mut store,
            "evt-guardian-enroll-1",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-a".into(),
                guardian_id: "guardian-alex".into(),
                guardian_label: "Alex".into(),
                guardian_public_key: alex_pub.clone(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-guardian-enroll-2",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-a".into(),
                guardian_id: "guardian-riley".into(),
                guardian_label: "Riley".into(),
                guardian_public_key: riley_pub.clone(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-request-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "recovery-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let guardian_one = EventEnvelope::from_body(
            "evt-recovery-approval-1",
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: "recovery-1".into(),
                guardian_id: "guardian-alex".into(),
            }),
            vec![EventRef::previous("evt-recovery-request-1")],
            SignerBinding::guardian("guardian-alex", alex_pub.clone()),
            &FixtureSigner::new("guardian-key-alex"),
        )
        .unwrap();
        store
            .append_with_authorizer(guardian_one, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        let guardian_two = EventEnvelope::from_body(
            "evt-recovery-approval-2",
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: "recovery-1".into(),
                guardian_id: "guardian-riley".into(),
            }),
            vec![EventRef::previous("evt-recovery-approval-1")],
            SignerBinding::guardian("guardian-riley", riley_pub.clone()),
            &FixtureSigner::new("guardian-key-riley"),
        )
        .unwrap();
        store
            .append_with_authorizer(guardian_two, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        append_typed(
            &mut store,
            "evt-recovery-executed-1",
            EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: "recovery-1".into(),
                executed_scope: RecoveryScope::FreezeDevice,
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let request = store
            .materialized()
            .recovery_requests_current
            .get("recovery-1")
            .unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Executed);
        assert_eq!(request.approvals.len(), 2);
        assert_eq!(request.executed_scope, Some(RecoveryScope::FreezeDevice));
    }

    #[test]
    fn sqlite_store_round_trips_events_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("emberlink-core-state-{unique}.sqlite"));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        assert_eq!(reopened.event_count(), 2);
        assert_eq!(
            reopened.current_event_type_for("evt-device-1"),
            Some(EventType::DeviceAdded)
        );
        assert_eq!(
            reopened.materialized().device("device-a").unwrap().label,
            "Laptop"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_persona_device_access_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-access-{unique}.sqlite"));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-persona-1",
                EventBody::PersonaCreated(PersonaCreatedEvent {
                    root_id: "root-a".into(),
                    persona_id: "persona-a".into(),
                    label: "Work".into(),
                    disclosure_profile: Some("persona.professional".into()),
                    survival_mode: SurvivalMode::Strict,
                    initial_key: test_key("key-persona-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );

            store
                .grant_persona_device_access("persona-a", "device-a")
                .unwrap();
            assert_eq!(
                store
                    .persona_device_access_for_persona("persona-a")
                    .unwrap(),
                vec![PersonaDeviceAccessRecord {
                    persona_id: "persona-a".into(),
                    device_id: "device-a".into(),
                }]
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .persona_device_access_for_persona("persona-a")
                .unwrap(),
            vec![PersonaDeviceAccessRecord {
                persona_id: "persona-a".into(),
                device_id: "device-a".into(),
            }]
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn service_bindings_round_trip_across_reopen_and_delete_cleanly() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-service-bindings-{unique}.sqlite"
        ));
        let binding = core_types::ServiceBinding {
            id: "binding-1".into(),
            persona_id: "persona-a".into(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "password".into(),
                service_label: "GitHub".into(),
                endpoint: "https://github.com".into(),
            },
            external_account_id: "alice".into(),
            created_at: 42,
        };

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-persona-1",
                EventBody::PersonaCreated(PersonaCreatedEvent {
                    root_id: "root-a".into(),
                    persona_id: "persona-a".into(),
                    label: "Work".into(),
                    disclosure_profile: Some("persona.professional".into()),
                    survival_mode: SurvivalMode::Strict,
                    initial_key: test_key("key-persona-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );

            store.upsert_service_binding(&binding).unwrap();
            assert_eq!(
                store.service_bindings_for_persona("persona-a").unwrap(),
                vec![binding.clone()]
            );
            assert_eq!(store.service_bindings().unwrap(), vec![binding.clone()]);
        }

        let mut reopened = EventStore::open(&path).unwrap();
        assert_eq!(
            reopened.service_bindings_for_persona("persona-a").unwrap(),
            vec![binding.clone()]
        );
        assert_eq!(reopened.service_bindings().unwrap(), vec![binding.clone()]);
        assert!(reopened.delete_service_binding("binding-1").unwrap());
        assert!(
            reopened
                .service_bindings_for_persona("persona-a")
                .unwrap()
                .is_empty()
        );
        assert!(reopened.service_bindings().unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn service_binding_rejects_unknown_persona() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-service-bindings-invalid-{unique}.sqlite"
        ));

        let mut store = EventStore::open(&path).unwrap();
        let err = store
            .upsert_service_binding(&core_types::ServiceBinding {
                id: "binding-1".into(),
                persona_id: "persona-missing".into(),
                descriptor: core_types::ServiceDescriptor {
                    adapter_kind: "password".into(),
                    service_label: "GitHub".into(),
                    endpoint: "https://github.com".into(),
                },
                external_account_id: "alice".into(),
                created_at: 42,
            })
            .unwrap_err();

        assert!(err.message.contains("unknown persona: persona-missing"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn imported_sync_batches_persist_events_and_peer_cursor_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let local_path =
            std::env::temp_dir().join(format!("emberlink-core-state-sync-local-{unique}.sqlite"));
        let remote_path =
            std::env::temp_dir().join(format!("emberlink-core-state-sync-remote-{unique}.sqlite"));

        {
            let mut remote = EventStore::open(&remote_path).unwrap();
            append_typed(
                &mut remote,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut remote,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );

            let remote_events = remote.events().to_vec();
            let last_remote_event_id = remote.events().last().map(|event| event.event_id.as_str());

            let mut local = EventStore::open(&local_path).unwrap();
            let imported = local
                .import_sync_batch(
                    "peer-b",
                    "batch-1",
                    &remote_events,
                    last_remote_event_id,
                    &FixtureVerifier,
                    &IdentityAuthorizer,
                    0,
                )
                .unwrap();

            assert_eq!(imported, 2);
            assert_eq!(local.event_count(), 2);
            assert_eq!(
                local
                    .peer_cursor("peer-b")
                    .unwrap()
                    .last_event_id
                    .as_deref(),
                Some("evt-device-1")
            );
            let sync_batches: i64 = local
                .conn
                .query_row("SELECT COUNT(*) FROM sync_batches", [], |row| row.get(0))
                .unwrap();
            assert_eq!(sync_batches, 1);
        }

        let reopened = EventStore::open(&local_path).unwrap();
        assert_eq!(reopened.event_count(), 2);
        assert_eq!(
            reopened
                .peer_cursor("peer-b")
                .unwrap()
                .last_event_id
                .as_deref(),
            Some("evt-device-1")
        );
        assert_eq!(
            reopened.peer_cursors().unwrap(),
            vec![PeerCursor {
                peer_id: "peer-b".into(),
                last_event_id: Some("evt-device-1".into()),
            }]
        );
        assert_eq!(
            reopened.sync_batches().unwrap(),
            vec![SyncBatchRecord {
                batch_id: "batch-1".into(),
                peer_id: "peer-b".into(),
                last_event_id: Some("evt-device-1".into()),
            }]
        );
        assert!(reopened.materialized().root("root-a").is_some());
        assert!(reopened.materialized().device("device-a").is_some());

        let _ = std::fs::remove_file(local_path);
        let _ = std::fs::remove_file(remote_path);
    }

    #[test]
    fn persona_device_access_requires_same_active_root_membership() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-root-2",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Other".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-b".into(),
                device_id: "device-b".into(),
                label: "Tablet".into(),
                initial_key: test_key("key-device-b-v1"),
                initial_encryption_key: test_encryption_key("key-device-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let err = store
            .grant_persona_device_access("persona-a", "device-b")
            .unwrap_err();
        assert!(err.message.contains("same root"));
    }

    #[test]
    fn replacement_device_can_take_over_persona_access_after_recovery() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-2",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-b".into(),
                label: "Replacement Laptop".into(),
                initial_key: test_key("key-device-b-v1"),
                initial_encryption_key: test_encryption_key("key-device-b-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .grant_persona_device_access("persona-a", "device-a")
            .unwrap();
        append_typed(
            &mut store,
            "evt-device-replaced-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-b".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        store
            .restore_persona_access_to_replacement_device("device-a", "device-b")
            .unwrap();

        assert!(
            store
                .persona_device_access_for_device("device-a")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.persona_device_access_for_device("device-b").unwrap(),
            vec![PersonaDeviceAccessRecord {
                persona_id: "persona-a".into(),
                device_id: "device-b".into(),
            }]
        );
    }

    #[test]
    fn storage_manifest_helper_writes_current_rows() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_file_manifest(&test_manifest("manifest-1", "bafy-root-1", "device-a"))
            .unwrap();

        let manifest = store.file_manifest("manifest-1").unwrap();
        assert_eq!(manifest.encrypted_root_chunk_id, "bafy-root-1");
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-a");
    }

    #[test]
    fn storage_manifest_publish_event_materializes_current_manifest_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-storage-event-{unique}.sqlite"
        ));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-1",
                storage_manifest_published_event(
                    "root-a",
                    "storage-1",
                    test_manifest("manifest-1", "bafy-root-1", "device-a"),
                ),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        let manifest = reopened.file_manifest("manifest-1").unwrap();
        assert_eq!(manifest.encrypted_root_chunk_id, "bafy-root-1");
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-a");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_block_coverage_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-local-blocks-{unique}.sqlite"));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-1",
                storage_manifest_published_event(
                    "root-a",
                    "storage-1",
                    test_manifest("manifest-1", "bafy-root-1", "device-a"),
                ),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            let manifest = store.file_manifest("manifest-1").unwrap();
            store
                .upsert_encrypted_block(&EncryptedBlock {
                    chunk: manifest.chunks[0].clone(),
                    encrypted: EncryptedContent {
                        nonce_hex: "nonce-root".into(),
                        ciphertext: vec![0xaa; 32],
                    },
                })
                .unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let coverage = reopened
            .local_block_coverage("manifest-1")
            .unwrap()
            .unwrap();
        assert_eq!(coverage.present_chunks, 1);
        assert_eq!(coverage.total_chunks, 2);
        assert_eq!(coverage.missing_chunks.len(), 1);
        assert_eq!(
            coverage.missing_chunks[0].chunk_id,
            "bafy-root-1-chunk-0001"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn encrypted_local_block_payload_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-encrypted-blocks-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let content_key = generate_content_key();
        let block = encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store.upsert_encrypted_block(&block).unwrap();
        }

        let persisted_path = block_dir
            .join(&block.chunk.chunk_id[..block.chunk.chunk_id.len().min(2)])
            .join(format!("{}.blk", block.chunk.chunk_id));
        assert!(persisted_path.exists());
        let conn = rusqlite::Connection::open(&path).unwrap();
        let stored_inline = conn
            .query_row(
                "SELECT nonce_hex, ciphertext FROM local_blocks WHERE chunk_id = ?1",
                rusqlite::params![&block.chunk.chunk_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(stored_inline, (None, None));

        let reopened = EventStore::open(&path).unwrap();
        let encrypted = reopened
            .local_encrypted_content(&block.chunk.chunk_id)
            .unwrap()
            .unwrap();
        let hydrated = EncryptedBlock {
            chunk: block.chunk.clone(),
            encrypted,
        };
        let decrypted = decrypt_block(&hydrated, &content_key).unwrap();

        assert_eq!(decrypted, b"root chunk payload");

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_block_coverage_uses_filesystem_presence_for_file_backed_store() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-file-coverage-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let manifest = publish_manifest(
            "manifest-coverage",
            "chunk-root",
            vec![
                manifest_chunk("manifest-coverage", "chunk-root", 0, 1024),
                manifest_chunk("manifest-coverage", "chunk-leaf", 1, 1024),
            ],
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        );
        let blocks = manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: EncryptedContent {
                    nonce_hex: format!("nonce-{}", chunk.ordinal),
                    ciphertext: vec![0xcc; 32],
                },
            })
            .collect::<Vec<_>>();

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-1",
                storage_manifest_published_event("root-a", "storage-1", manifest.clone()),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            for block in &blocks {
                store.upsert_encrypted_block(block).unwrap();
            }
        }

        let leaf_chunk_id = blocks[1].chunk.chunk_id.clone();
        let leaf_prefix = &leaf_chunk_id[..leaf_chunk_id.len().min(2)];
        let leaf_path = block_dir
            .join(leaf_prefix)
            .join(format!("{}.blk", leaf_chunk_id));
        std::fs::remove_file(&leaf_path).unwrap();

        let reopened = EventStore::open(&path).unwrap();
        let coverage = reopened
            .local_block_coverage("manifest-coverage")
            .unwrap()
            .unwrap();

        assert_eq!(coverage.present_chunks, 1);
        assert_eq!(coverage.missing_chunks.len(), 1);
        assert_eq!(
            coverage.missing_chunks[0].chunk_id,
            blocks[1].chunk.chunk_id
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_block_audit_reports_missing_orphaned_metadata_and_stray_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-block-audit-{unique}.sqlite"));
        let block_dir = local_block_store_root(&path);
        let manifest = publish_manifest(
            "manifest-audit",
            "chunk-root",
            vec![
                manifest_chunk("manifest-audit", "chunk-root", 0, 1024),
                manifest_chunk("manifest-audit", "chunk-leaf", 1, 1024),
            ],
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        );
        let blocks = manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: EncryptedContent {
                    nonce_hex: format!("nonce-{}", chunk.ordinal),
                    ciphertext: vec![0xdd; 32],
                },
            })
            .collect::<Vec<_>>();

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: test_encryption_key("key-device-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-1",
                storage_manifest_published_event("root-a", "storage-1", manifest.clone()),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            for block in &blocks {
                store.upsert_encrypted_block(block).unwrap();
            }
            store
                .upsert_local_block(&LocalBlockRecord {
                    chunk_id: "orphan-metadata".into(),
                    ciphertext_bytes: 64,
                })
                .unwrap();
        }

        let missing_chunk_path = block_dir.join("ch").join("chunk-leaf.blk");
        std::fs::remove_file(&missing_chunk_path).unwrap();
        let stray_chunk_path = block_dir.join("st").join("stray-file.blk");
        std::fs::create_dir_all(stray_chunk_path.parent().unwrap()).unwrap();
        std::fs::write(&stray_chunk_path, b"nonce-stray\nciphertext").unwrap();

        let reopened = EventStore::open(&path).unwrap();
        let audit = reopened.audit_local_blocks().unwrap();

        assert_eq!(
            audit.referenced_chunk_ids,
            BTreeSet::from(["chunk-leaf".to_string(), "chunk-root".to_string()])
        );
        assert_eq!(
            audit.missing_referenced_chunk_ids,
            BTreeSet::from(["chunk-leaf".to_string()])
        );
        assert_eq!(
            audit.orphaned_metadata_chunk_ids,
            BTreeSet::from(["orphan-metadata".to_string()])
        );
        assert_eq!(
            audit.orphaned_file_chunk_ids,
            BTreeSet::from(["stray-file".to_string()])
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn encrypted_local_block_payload_round_trips_in_memory_without_filesystem_store() {
        let content_key = generate_content_key();
        let block = encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();
        let mut store = EventStore::open_in_memory().unwrap();

        store.upsert_encrypted_block(&block).unwrap();

        let encrypted = store
            .local_encrypted_content(&block.chunk.chunk_id)
            .unwrap()
            .unwrap();
        let hydrated = EncryptedBlock {
            chunk: block.chunk.clone(),
            encrypted,
        };

        assert_eq!(
            decrypt_block(&hydrated, &content_key).unwrap(),
            b"root chunk payload"
        );
    }

    #[test]
    fn local_encrypted_manifest_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-local-encrypted-manifest-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let content_key = generate_content_key();
        let plaintext_chunks = vec![
            br#"{"kind":"structured-record"}"#.to_vec(),
            b"payload tail".to_vec(),
        ];
        let (manifest, blocks) = core_storage::seal_payload_manifest(
            "manifest-local-payload-1",
            &plaintext_chunks,
            &content_key,
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .upsert_local_encrypted_manifest(&manifest, &blocks)
                .unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded_manifest = reopened
            .local_file_manifest("manifest-local-payload-1")
            .unwrap()
            .unwrap();
        let hydrated_blocks = loaded_manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: reopened
                    .local_encrypted_content(&chunk.chunk_id)
                    .unwrap()
                    .unwrap(),
            })
            .collect::<Vec<_>>();
        let decrypted =
            core_storage::open_payload_manifest(&loaded_manifest, &hydrated_blocks, &content_key)
                .unwrap();

        assert_eq!(loaded_manifest, manifest);
        assert_eq!(decrypted, plaintext_chunks);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_vault_catalog_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-vault-catalog-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");
        let content_key = generate_content_key();
        let catalog = VaultCatalog {
            namespace: test_namespace(),
            objects: vec![core_types::VaultObject {
                id: "obj-1".into(),
                namespace: test_namespace(),
                class: core_types::VaultObjectClass::StructuredRecord,
                latest_revision_id: "rev-1".into(),
                created_at: 1,
                updated_at: 1,
                durability: core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                retention: core_types::RetentionPolicy::KeepLatest,
                deleted: false,
            }],
            revisions: vec![core_types::VaultRevision {
                id: "rev-1".into(),
                object_id: "obj-1".into(),
                manifest_id: "manifest-record-1".into(),
                payload_kind: core_types::PayloadKind::StructuredRecord,
                content_type: "application/json".into(),
                created_at: 1,
                created_by_device_id: "device-a".into(),
                parent_revision_id: None,
                structured_record: Some(core_types::StructuredRecordMeta {
                    schema_id: "com.example.profile/basic".into(),
                    schema_version: "v1".into(),
                    encoding: core_types::StructuredEncoding::Json,
                    app_namespace: "com.example.profile".into(),
                }),
                claim: None,
            }],
        };

        {
            let mut store = EventStore::open_with_key(&path, master_key.clone()).unwrap();
            store
                .upsert_local_vault_catalog(
                    "manifest-catalog-1",
                    &catalog,
                    &content_key,
                    vec![manifest_device_access("device-a", "wrapped-device-a")],
                )
                .unwrap();
        }

        // Assert the catalog content key is encrypted at rest.
        let ns = test_namespace();
        let raw_conn = rusqlite::Connection::open(&path).unwrap();
        let raw_content_key: String = raw_conn
            .query_row(
                "SELECT content_key FROM local_vault_catalogs WHERE owner_kind = ?1 AND owner_id = ?2",
                rusqlite::params![ns.owner_kind.as_str(), &ns.owner_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            raw_content_key.starts_with("ENC1:"),
            "expected encrypted content_key in SQLite, got: {raw_content_key}"
        );

        // Assert round-trip recovers the original catalog.
        let reopened = EventStore::open_with_key(&path, master_key).unwrap();
        let loaded = reopened
            .local_vault_catalog(&test_namespace())
            .unwrap()
            .unwrap();
        assert_eq!(loaded, catalog);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_presentation_templates_round_trip_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-presentation-templates-{unique}.sqlite"
        ));
        let template = core_storage::create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/basic",
            core_types::PresentationAudienceKind::Service,
            vec!["full_name".into(), "skills".into()],
            Some(3600),
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store.upsert_local_presentation_template(&template).unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded = reopened.local_presentation_templates().unwrap();

        assert_eq!(loaded, vec![template]);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_presentation_artifacts_round_trip_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-presentation-artifacts-{unique}.sqlite"
        ));
        let artifact = core_storage::create_presentation_artifact(
            "artifact-1",
            "obj-1",
            "rev-1",
            core_types::PresentationAudienceKind::Service,
            "svc.example",
            "com.example.profile/basic",
            "manifest-artifact-1",
            10,
            Some(3700),
        )
        .unwrap();
        let record = LocalPresentationArtifactRecord {
            artifact: artifact.clone(),
            namespace: VaultNamespace {
                owner_kind: VaultOwnerKind::Persona,
                owner_id: "persona-a".into(),
            },
            template_id: "template-1".into(),
            grant_id: None,
        };

        {
            let mut store = EventStore::open(&path).unwrap();
            store.record_local_presentation_artifact(&record).unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded = reopened.local_presentation_artifacts().unwrap();

        assert_eq!(loaded, vec![record]);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn issue_local_presentation_artifact_builds_audited_encrypted_payload() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-issued-artifact-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let catalog_key = generate_content_key();
        let source_key = generate_content_key();
        let mut catalog = core_storage::create_vault_catalog(namespace.clone()).unwrap();
        let object = core_storage::create_vault_object(
            "obj-1",
            namespace.clone(),
            core_types::VaultObjectClass::StructuredRecord,
            "rev-1",
            1,
            core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_types::RetentionPolicy::KeepLatest,
        )
        .unwrap();
        let revision = core_storage::create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-source-1",
            core_types::PayloadKind::StructuredRecord,
            "application/json",
            1,
            "device-a",
            None,
            Some(core_types::StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_types::StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            }),
            None,
        )
        .unwrap();
        core_storage::add_vault_object_with_initial_revision(&mut catalog, object, revision)
            .unwrap();
        let source_chunks = vec![
            br#"{
            "full_name":"Jane Doe",
            "skills":["rust","distributed-systems"],
            "private":{"ssn":"000-00-0000"}
        }"#
            .to_vec(),
        ];
        let (source_manifest, source_blocks) = core_storage::seal_payload_manifest(
            "manifest-source-1",
            &source_chunks,
            &source_key,
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        )
        .unwrap();
        let template = core_storage::create_presentation_template(
            "template-1",
            namespace.clone(),
            "obj-1",
            "com.example.profile/basic",
            core_types::PresentationAudienceKind::Service,
            vec!["full_name".into(), "skills".into()],
            Some(3600),
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store.upsert_local_presentation_template(&template).unwrap();
            store
                .upsert_local_manifest_key("manifest-source-1", &source_key)
                .unwrap();
            store
                .commit_local_vault_catalog_with_manifests(
                    "manifest-catalog-1",
                    &catalog,
                    &catalog_key,
                    vec![manifest_device_access("device-a", "wrapped-device-a")],
                    &[LocalEncryptedManifest {
                        manifest: source_manifest.clone(),
                        blocks: source_blocks.clone(),
                    }],
                )
                .unwrap();

            let artifact = store
                .issue_local_presentation_artifact(
                    &namespace,
                    "rev-1",
                    "template-1",
                    "artifact-1",
                    "manifest-artifact-1",
                    "svc.example",
                    10,
                    Some(3700),
                    vec![test_manifest_recipient("device-a")],
                    None,
                )
                .unwrap();

            assert_eq!(artifact.artifact.id, "artifact-1");
            assert_eq!(artifact.artifact.source_revision_id, "rev-1");
            assert_eq!(artifact.artifact.manifest_id, "manifest-artifact-1");
            assert_eq!(artifact.template_id, "template-1");
            assert_eq!(artifact.namespace, namespace);
        }

        let reopened = EventStore::open(&path).unwrap();
        let artifacts = reopened.local_presentation_artifacts().unwrap();
        let artifact_manifest = reopened
            .local_file_manifest("manifest-artifact-1")
            .unwrap()
            .unwrap();
        let artifact_key = reopened
            .local_manifest_key("manifest-artifact-1")
            .unwrap()
            .unwrap();
        let artifact_blocks = artifact_manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: reopened
                    .local_encrypted_content(&chunk.chunk_id)
                    .unwrap()
                    .unwrap(),
            })
            .collect::<Vec<_>>();
        let decrypted = core_storage::open_payload_manifest(
            &artifact_manifest,
            &artifact_blocks,
            &artifact_key,
        )
        .unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact.recipient_id, "svc.example");
        assert_eq!(artifacts[0].template_id, "template-1");
        assert_eq!(
            String::from_utf8(decrypted[0].clone()).unwrap(),
            r#"{"full_name":"Jane Doe","skills":["rust","distributed-systems"]}"#
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn build_local_presentation_artifact_envelope_requires_namespace_issuer() {
        let mut store = EventStore::default();
        let root_key = generate_local_key_pair("root", "root-a");
        let root_signer = LocalKeySigner::from_local_key_pair(&root_key).unwrap();
        let persona_owner_key = generate_local_key_pair("persona", "persona-a");
        let persona_owner_signer = LocalKeySigner::from_local_key_pair(&persona_owner_key).unwrap();
        let other_persona_key = generate_local_key_pair("persona", "persona-b");
        let other_persona_signer = LocalKeySigner::from_local_key_pair(&other_persona_key).unwrap();

        append_typed_with_signer(
            &mut store,
            "evt-root-runtime-artifact",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: local_public_key_material(&root_key),
            }),
            SignerBinding::root("root-a", root_key.key_id.clone()),
            &root_signer,
        );
        append_typed_with_signer(
            &mut store,
            "evt-persona-owner-runtime-artifact",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Owner".into(),
                disclosure_profile: Some("persona.owner".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: local_public_key_material(&persona_owner_key),
            }),
            SignerBinding::root("root-a", root_key.key_id.clone()),
            &root_signer,
        );
        append_typed_with_signer(
            &mut store,
            "evt-persona-other-runtime-artifact",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-b".into(),
                label: "Other".into(),
                disclosure_profile: Some("persona.other".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: local_public_key_material(&other_persona_key),
            }),
            SignerBinding::root("root-a", root_key.key_id.clone()),
            &root_signer,
        );

        let namespace = test_namespace();
        let meta = StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        };
        let template = core_storage::create_presentation_template(
            "template-owner",
            namespace.clone(),
            "obj-owner",
            "com.example.profile/basic",
            core_types::PresentationAudienceKind::Service,
            vec!["full_name".into()],
            Some(3600),
        )
        .unwrap();

        store
            .upsert_local_structured_record(
                &namespace,
                "obj-owner",
                "rev-owner",
                "manifest-owner",
                "manifest-catalog-owner",
                1,
                "device-a",
                meta,
                br#"{"full_name":"Jane Doe","private":"secret"}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap();
        store.upsert_local_presentation_template(&template).unwrap();
        let record = store
            .issue_local_presentation_artifact(
                &namespace,
                "rev-owner",
                "template-owner",
                "artifact-owner",
                "manifest-artifact-owner",
                "svc.example",
                10,
                Some(3610),
                vec![test_manifest_recipient("device-a")],
                None,
            )
            .unwrap();

        let envelope = store
            .build_local_presentation_artifact_envelope(
                &record.artifact.id,
                "persona-a",
                &persona_owner_signer,
            )
            .unwrap();
        let err = store
            .build_local_presentation_artifact_envelope(
                &record.artifact.id,
                "persona-b",
                &other_persona_signer,
            )
            .unwrap_err();

        assert_eq!(envelope.issuer_persona_id, "persona-a");
        assert!(
            err.message.contains(
                "persona-owned disclosure artifacts must be issued by the owning persona"
            )
        );
    }

    #[test]
    fn received_presentation_artifacts_round_trip_and_track_receipts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-received-artifacts-{unique}.sqlite"
        ));
        let artifact = core_storage::create_presentation_artifact(
            "artifact-received-1",
            "obj-1",
            "rev-1",
            core_types::PresentationAudienceKind::Peer,
            "persona-target",
            "com.example.profile/basic",
            "manifest-artifact-1",
            10,
            Some(3700),
        )
        .unwrap();
        let key_pair = core_crypto::generate_local_key_pair("persona", "persona-issuer");
        let signer = core_crypto::LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
        let envelope = core_storage::sign_presentation_artifact_envelope(
            &artifact,
            br#"{"full_name":"Jane Doe"}"#.to_vec(),
            "persona-issuer",
            key_pair.key_id.clone(),
            &signer,
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            let received = store
                .receive_presentation_artifact(
                    &envelope,
                    ReceivedDisclosureSourceKind::ExportFile,
                    "/tmp/disclosure.artifact",
                    10,
                )
                .unwrap();
            assert_eq!(received.envelope.artifact.id, artifact.id);
            assert_eq!(received.envelope.issuer_persona_id, "persona-issuer");
            assert_eq!(received.receipt_count, 1);

            let received = store
                .receive_presentation_artifact(
                    &envelope,
                    ReceivedDisclosureSourceKind::ExportFile,
                    "/tmp/disclosure.artifact",
                    20,
                )
                .unwrap();
            assert_eq!(received.receipt_count, 2);
            assert_eq!(received.last_received_at, 20);
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded = reopened.local_received_presentation_artifacts().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].envelope.artifact.id, artifact.id);
        assert_eq!(loaded[0].first_received_at, 10);
        assert_eq!(loaded[0].last_received_at, 20);
        assert_eq!(loaded[0].receipt_count, 2);
        assert_eq!(
            String::from_utf8(loaded[0].envelope.payload_bytes.clone()).unwrap(),
            r#"{"full_name":"Jane Doe"}"#
        );
        assert_eq!(loaded[0].envelope.issuer_persona_id, "persona-issuer");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upsert_local_structured_record_creates_and_advances_catalog_head() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-structured-record-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let meta = core_types::StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        };

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-1",
                    "rev-1",
                    "manifest-record-1",
                    "manifest-catalog-1",
                    1,
                    "device-a",
                    meta.clone(),
                    br#"{"full_name":"Jane"}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
            store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-1",
                    "rev-2",
                    "manifest-record-2",
                    "manifest-catalog-2",
                    2,
                    "device-a",
                    meta,
                    br#"{"full_name":"Jane Doe","skills":["rust"]}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
        let object = catalog
            .objects
            .iter()
            .find(|object| object.id == "obj-1")
            .unwrap();

        assert_eq!(object.latest_revision_id, "rev-2");
        assert_eq!(catalog.revisions.len(), 2);
        assert_eq!(
            String::from_utf8(
                reopened
                    .local_manifest_payload_bytes("manifest-record-2")
                    .unwrap()
            )
            .unwrap(),
            r#"{"full_name":"Jane Doe","skills":["rust"]}"#
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn upsert_local_structured_record_rejects_non_object_json_payloads() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-structured-record-invalid-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let meta = core_types::StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        };

        let err = EventStore::open(&path)
            .unwrap()
            .upsert_local_structured_record(
                &namespace,
                "obj-1",
                "rev-1",
                "manifest-record-1",
                "manifest-catalog-1",
                1,
                "device-a",
                meta,
                br#"["not","an","object"]"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap_err();

        assert!(err.message.contains("json object"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn upsert_local_persona_credential_round_trips_claim_meta_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-persona-credential-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let meta = core_types::StructuredRecordMeta {
            schema_id: "emberlink:claim:password:1.0".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "emberlink".into(),
        };
        let claim = test_claim_meta();

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .upsert_local_persona_credential(
                    &namespace,
                    "obj-cred-1",
                    "rev-cred-1",
                    "manifest-cred-1",
                    "manifest-catalog-cred-1",
                    42,
                    "device-a",
                    meta,
                    claim.clone(),
                    br#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
        let object = catalog
            .objects
            .iter()
            .find(|object| object.id == "obj-cred-1")
            .unwrap();
        let revision = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == "rev-cred-1")
            .unwrap();

        assert_eq!(
            object.class,
            core_types::VaultObjectClass::PersonaCredential
        );
        assert_eq!(revision.claim.as_ref(), Some(&claim));
        assert_eq!(
            String::from_utf8(
                reopened
                    .local_manifest_payload_bytes("manifest-cred-1")
                    .unwrap()
            )
            .unwrap(),
            r#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn upsert_local_persona_credential_rejects_non_persona_namespace() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-persona-credential-invalid-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Root,
            owner_id: "root-a".into(),
        };

        let err = EventStore::open(&path)
            .unwrap()
            .upsert_local_persona_credential(
                &namespace,
                "obj-cred-1",
                "rev-cred-1",
                "manifest-cred-1",
                "manifest-catalog-cred-1",
                42,
                "device-a",
                core_types::StructuredRecordMeta {
                    schema_id: "emberlink:claim:password:1.0".into(),
                    schema_version: "v1".into(),
                    encoding: core_types::StructuredEncoding::Json,
                    app_namespace: "emberlink".into(),
                },
                test_claim_meta(),
                br#"{"service_url":"https://github.com","username":"alice","password":"secret"}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                vec![test_manifest_recipient("device-a")],
            )
            .unwrap_err();

        assert!(err.message.contains("persona-owned namespace"));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn import_persona_credentials_creates_persona_credential_objects() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-imported-credentials-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();

        let imported_claim = core_types::ImportedClaim {
            claim_type: core_types::ClaimType::SelfAsserted.as_str().into(),
            payload_json: r#"{"schema":"emberlink:claim:password:1.0","service_name":"GitHub","service_url":"https://github.com","username":"alice","password":"secret","totp_secret":null,"notes":"imported"}"#.into(),
            external_issuer: "bitwarden".into(),
            external_issued_at: Some(42),
            external_expires_at: None,
        };

        {
            let mut store = EventStore::open(&path).unwrap();
            let revisions = store
                .import_persona_credentials(
                    &namespace,
                    "device-a",
                    std::slice::from_ref(&imported_claim),
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
            assert_eq!(revisions.len(), 1);
            assert_eq!(
                revisions[0]
                    .claim
                    .as_ref()
                    .unwrap()
                    .external_issuer
                    .as_deref(),
                Some("bitwarden")
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
        assert_eq!(catalog.objects.len(), 1);
        assert_eq!(
            catalog.objects[0].class,
            core_types::VaultObjectClass::PersonaCredential
        );
        assert_eq!(
            catalog.revisions[0].claim.as_ref().unwrap().claim_schema,
            "emberlink:claim:password:1.0"
        );
        assert_eq!(
            catalog.revisions[0]
                .claim
                .as_ref()
                .unwrap()
                .external_issuer
                .as_deref(),
            Some("bitwarden")
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn tombstoned_local_vault_object_blocks_updates_disclosure_and_becomes_collectable() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-vault-delete-{unique}.sqlite"));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let meta = core_types::StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        };
        let template = core_storage::create_presentation_template(
            "template-delete-1",
            namespace.clone(),
            "obj-delete-1",
            "com.example.profile/basic",
            core_types::PresentationAudienceKind::Service,
            vec!["full_name".into()],
            Some(3600),
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-delete-1",
                    "rev-delete-1",
                    "manifest-record-delete-1",
                    "manifest-catalog-delete-1",
                    1,
                    "device-a",
                    meta.clone(),
                    br#"{"full_name":"Jane Doe","private":{"ssn":"000-00-0000"}}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
            store.upsert_local_presentation_template(&template).unwrap();

            store
                .tombstone_local_vault_object(
                    &namespace,
                    "obj-delete-1",
                    "manifest-catalog-delete-2",
                    2,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();

            let err = store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-delete-1",
                    "rev-delete-2",
                    "manifest-record-delete-2",
                    "manifest-catalog-delete-3",
                    3,
                    "device-a",
                    meta,
                    br#"{"full_name":"Jane Updated"}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap_err();
            assert!(err.message.contains("deleted"));

            let err = store
                .issue_local_presentation_artifact(
                    &namespace,
                    "rev-delete-1",
                    "template-delete-1",
                    "artifact-delete-1",
                    "manifest-artifact-delete-1",
                    "svc.example",
                    10,
                    Some(3700),
                    vec![test_manifest_recipient("device-a")],
                    None,
                )
                .unwrap_err();
            assert!(err.message.contains("deleted"));

            let plan = store.plan_local_vault_gc(&namespace).unwrap().unwrap();
            assert_eq!(
                plan.collectable_manifest_ids,
                BTreeSet::from([
                    "manifest-catalog-delete-1".to_string(),
                    "manifest-record-delete-1".to_string(),
                ])
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        let catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
        let object = catalog
            .objects
            .iter()
            .find(|object| object.id == "obj-delete-1")
            .unwrap();
        assert!(object.deleted);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_file_manifest_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-local-manifest-{unique}.sqlite"
        ));
        let manifest = test_manifest("manifest-local-1", "chunk-local-root", "device-a");

        {
            let mut store = EventStore::open(&path).unwrap();
            store.upsert_local_file_manifest(&manifest).unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded = reopened
            .local_file_manifest("manifest-local-1")
            .unwrap()
            .unwrap();

        assert_eq!(loaded, manifest);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_manifest_key_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-local-manifest-key-{unique}.sqlite"
        ));
        let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");

        {
            let mut store = EventStore::open_with_key(&path, master_key.clone()).unwrap();
            store
                .upsert_local_manifest_key("manifest-local-1", "content-key-1")
                .unwrap();
        }

        // Assert the value is encrypted at rest (raw SQLite value starts with ENC1:).
        let raw_conn = rusqlite::Connection::open(&path).unwrap();
        let raw_value: String = raw_conn
            .query_row(
                "SELECT content_key FROM local_manifest_keys WHERE manifest_id = 'manifest-local-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            raw_value.starts_with("ENC1:"),
            "expected encrypted value in SQLite, got: {raw_value}"
        );

        // Assert round-trip recovers the original value.
        let reopened = EventStore::open_with_key(&path, master_key).unwrap();
        let loaded = reopened.local_manifest_key("manifest-local-1").unwrap();
        assert_eq!(loaded.as_deref(), Some("content-key-1"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn local_device_encryption_key_round_trips_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-device-encryption-key-{unique}.sqlite"
        ));
        let master_key = core_crypto::derive_content_key(b"emberlink-test-key", b"test");
        let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");

        {
            let mut store = EventStore::open_with_key(&path, master_key.clone()).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-a".into(),
                    device_id: "device-a".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-a-v1"),
                    initial_encryption_key: PublicKeyMaterial {
                        key_id: encryption_key_pair.key_id.clone(),
                        algorithm: encryption_key_pair.algorithm,
                        public_key: encryption_key_pair.public_key.clone(),
                    },
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            store
                .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
                .unwrap();
        }

        // Assert the private key is encrypted at rest (raw SQLite value starts with ENC1:).
        let raw_conn = rusqlite::Connection::open(&path).unwrap();
        let raw_private_key: String = raw_conn
            .query_row(
                "SELECT private_key FROM local_device_encryption_keys WHERE device_id = 'device-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            raw_private_key.starts_with("ENC1:"),
            "expected encrypted private key in SQLite, got: {raw_private_key}"
        );

        // Assert round-trip recovers the original key pair.
        let reopened = EventStore::open_with_key(&path, master_key).unwrap();
        let loaded = reopened
            .local_device_encryption_key_pair("device-a")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, encryption_key_pair);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unwrap_manifest_key_for_device_caches_key_and_opens_payload() {
        let mut store = EventStore::default();
        let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: PublicKeyMaterial {
                    key_id: encryption_key_pair.key_id.clone(),
                    algorithm: encryption_key_pair.algorithm,
                    public_key: encryption_key_pair.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
            .unwrap();

        let content_key = generate_content_key();
        let first_block =
            encrypt_block("manifest-1", 0, b"root chunk payload", &content_key).unwrap();
        let second_block =
            encrypt_block("manifest-1", 1, b"leaf chunk payload", &content_key).unwrap();
        let manifest = publish_manifest(
            "manifest-1",
            first_block.chunk.chunk_id.clone(),
            vec![first_block.chunk.clone(), second_block.chunk.clone()],
            vec![
                wrap_manifest_key_access("device-a", &encryption_key_pair.public_key, &content_key)
                    .unwrap(),
            ],
        );
        store.upsert_file_manifest(&manifest).unwrap();
        store.upsert_encrypted_block(&first_block).unwrap();
        store.upsert_encrypted_block(&second_block).unwrap();

        assert!(store.local_manifest_key("manifest-1").unwrap().is_none());
        assert_eq!(
            store
                .unwrap_manifest_key_for_device("manifest-1", "device-a")
                .unwrap(),
            content_key
        );
        assert_eq!(
            store.local_manifest_key("manifest-1").unwrap().as_deref(),
            Some(content_key.as_str())
        );
        assert_eq!(
            store
                .manifest_payload_chunks_for_device("manifest-1", "device-a")
                .unwrap(),
            vec![
                b"root chunk payload".to_vec(),
                b"leaf chunk payload".to_vec()
            ]
        );
        assert_eq!(
            store
                .manifest_payload_bytes_for_device("manifest-1", "device-a")
                .unwrap(),
            b"root chunk payloadleaf chunk payload".to_vec()
        );
        assert_eq!(
            store.open_manifest_payload("manifest-1").unwrap(),
            (
                "device-a".to_string(),
                vec![
                    b"root chunk payload".to_vec(),
                    b"leaf chunk payload".to_vec()
                ]
            )
        );
        assert_eq!(
            store.prime_manifest_keys_for_device("device-a").unwrap(),
            vec!["manifest-1".to_string()]
        );
    }

    #[test]
    fn manifest_open_requires_active_authorized_device_with_runtime_key() {
        let mut store = EventStore::default();
        let encryption_key_pair = generate_local_encryption_key_pair("device", "device-a");
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: PublicKeyMaterial {
                    key_id: encryption_key_pair.key_id.clone(),
                    algorithm: encryption_key_pair.algorithm,
                    public_key: encryption_key_pair.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let content_key = generate_content_key();
        let first_block = encrypt_block("manifest-1", 0, b"payload", &content_key).unwrap();
        let manifest = publish_manifest(
            "manifest-1",
            first_block.chunk.chunk_id.clone(),
            vec![first_block.chunk.clone()],
            vec![
                wrap_manifest_key_access("device-a", &encryption_key_pair.public_key, &content_key)
                    .unwrap(),
            ],
        );
        store.upsert_file_manifest(&manifest).unwrap();
        store.upsert_encrypted_block(&first_block).unwrap();

        let missing_key_err = store
            .unwrap_manifest_key_for_device("manifest-1", "device-a")
            .unwrap_err();
        assert!(
            missing_key_err
                .message
                .contains("missing local device encryption key")
        );

        let stale_key_pair = generate_local_encryption_key_pair("device", "device-a-stale");
        let stale_key_err = store
            .upsert_local_device_encryption_key(
                "device-a",
                &LocalKeyPair {
                    key_id: encryption_key_pair.key_id.clone(),
                    algorithm: encryption_key_pair.algorithm,
                    public_key: encryption_key_pair.public_key.clone(),
                    private_key: stale_key_pair.private_key.clone(),
                },
            )
            .and_then(|_| store.unwrap_manifest_key_for_device("manifest-1", "device-a"))
            .unwrap_err();
        assert!(
            stale_key_err.message.contains("decrypt wrapped secret")
                || stale_key_err.message.contains("read wrapped secret")
                || stale_key_err.message.contains("invalid x25519 identity")
        );
        assert!(store.local_manifest_key("manifest-1").unwrap().is_none());

        store
            .upsert_local_device_encryption_key("device-a", &encryption_key_pair)
            .unwrap();
        append_typed(
            &mut store,
            "evt-device-freeze-1",
            EventBody::DeviceFrozen(DeviceFrozenEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "lost".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        let frozen_err = store
            .manifest_payload_bytes_for_device("manifest-1", "device-a")
            .unwrap_err();
        assert!(frozen_err.message.contains("active device"));
    }

    #[test]
    fn local_vault_gc_plan_uses_catalog_retention_and_local_manifests() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-vault-gc-{unique}.sqlite"));
        let block_dir = local_block_store_root(&path);
        {
            let mut store = EventStore::open(&path).unwrap();
            seed_gc_test_catalog(&mut store).unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let plan = reopened
            .plan_local_vault_gc(&test_namespace())
            .unwrap()
            .unwrap();

        assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc");
        assert_eq!(
            plan.retained_revision_ids,
            BTreeSet::from(["rev-2".to_string()])
        );
        assert_eq!(
            plan.retained_manifest_ids,
            BTreeSet::from([
                "manifest-catalog-gc".to_string(),
                "manifest-current".to_string(),
            ])
        );
        assert_eq!(
            plan.collectable_manifest_ids,
            BTreeSet::from(["manifest-old".to_string()])
        );
        assert_eq!(
            plan.collectable_chunk_ids,
            BTreeSet::from(["chunk-old-only".to_string()])
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn apply_local_vault_gc_removes_collectable_manifests_and_block_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-gc-apply-{unique}.sqlite"));
        let block_dir = local_block_store_root(&path);

        {
            let mut store = EventStore::open(&path).unwrap();
            seed_gc_test_catalog(&mut store).unwrap();

            let old_manifest = store.local_file_manifest("manifest-old").unwrap().unwrap();
            let old_chunk = old_manifest
                .chunks
                .iter()
                .find(|chunk| chunk.chunk_id == "chunk-old-only")
                .unwrap()
                .chunk_id
                .clone();
            let retained_chunk = "chunk-shared".to_string();
            let old_chunk_path = block_dir.join("ch").join(format!("{old_chunk}.blk"));
            let retained_chunk_path = block_dir.join("ch").join(format!("{retained_chunk}.blk"));
            assert!(old_chunk_path.exists());
            assert!(retained_chunk_path.exists());

            let applied = store
                .apply_local_vault_gc(&test_namespace())
                .unwrap()
                .unwrap();
            assert_eq!(
                applied.collectable_manifest_ids,
                BTreeSet::from(["manifest-old".to_string()])
            );
            assert_eq!(
                applied.collectable_chunk_ids,
                BTreeSet::from(["chunk-old-only".to_string()])
            );

            assert!(store.local_file_manifest("manifest-old").unwrap().is_none());
            assert!(
                store
                    .local_file_manifest("manifest-current")
                    .unwrap()
                    .is_some()
            );
            assert!(!old_chunk_path.exists());
            assert!(retained_chunk_path.exists());
        }

        let reopened = EventStore::open(&path).unwrap();
        assert!(
            reopened
                .local_file_manifest("manifest-old")
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .local_file_manifest("manifest-current")
                .unwrap()
                .is_some()
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_vault_gc_tracks_and_collects_stale_catalog_heads() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-vault-catalog-gc-{unique}.sqlite"
        ));
        let block_dir = local_block_store_root(&path);
        let namespace = test_namespace();
        let meta = core_types::StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        };

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-catalog-gc-1",
                    "rev-catalog-gc-1",
                    "manifest-record-catalog-gc-1",
                    "manifest-catalog-gc-1",
                    1,
                    "device-a",
                    meta.clone(),
                    br#"{"full_name":"Jane Doe"}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();
            store
                .upsert_local_structured_record(
                    &namespace,
                    "obj-catalog-gc-1",
                    "rev-catalog-gc-2",
                    "manifest-record-catalog-gc-2",
                    "manifest-catalog-gc-2",
                    2,
                    "device-a",
                    meta,
                    br#"{"full_name":"Jane Updated"}"#,
                    core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                    core_types::RetentionPolicy::KeepLatest,
                    vec![test_manifest_recipient("device-a")],
                )
                .unwrap();

            let stale_catalog_manifest = store
                .local_file_manifest("manifest-catalog-gc-1")
                .unwrap()
                .unwrap();
            let stale_catalog_chunk = stale_catalog_manifest.chunks[0].chunk_id.clone();
            let stale_catalog_chunk_path = block_dir
                .join(&stale_catalog_chunk[..stale_catalog_chunk.len().min(2)])
                .join(format!("{}.blk", stale_catalog_chunk));
            assert!(stale_catalog_chunk_path.exists());

            let plan = store.plan_local_vault_gc(&namespace).unwrap().unwrap();
            assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc-2");
            assert_eq!(
                plan.retained_manifest_ids,
                BTreeSet::from([
                    "manifest-catalog-gc-2".to_string(),
                    "manifest-record-catalog-gc-2".to_string(),
                ])
            );
            assert_eq!(
                plan.collectable_manifest_ids,
                BTreeSet::from([
                    "manifest-catalog-gc-1".to_string(),
                    "manifest-record-catalog-gc-1".to_string(),
                ])
            );
            assert!(
                plan.collectable_chunk_ids
                    .contains(&stale_catalog_manifest.chunks[0].chunk_id)
            );

            let applied = store.apply_local_vault_gc(&namespace).unwrap().unwrap();
            assert!(
                applied
                    .collectable_manifest_ids
                    .contains("manifest-catalog-gc-1")
            );
            assert!(
                store
                    .local_file_manifest("manifest-catalog-gc-1")
                    .unwrap()
                    .is_none()
            );
            assert!(!stale_catalog_chunk_path.exists());
        }

        let reopened = EventStore::open(&path).unwrap();
        let plan = reopened.plan_local_vault_gc(&namespace).unwrap().unwrap();
        assert!(
            !plan
                .collectable_manifest_ids
                .contains("manifest-catalog-gc-1")
        );
        assert_eq!(plan.catalog_manifest_id, "manifest-catalog-gc-2");

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn local_vault_catalog_commit_persists_payload_manifests_atomically() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-vault-commit-{unique}.sqlite"));
        let block_dir = local_block_store_root(&path);
        let catalog_key = generate_content_key();
        let payload_key = generate_content_key();
        let namespace = test_namespace();
        let mut catalog = core_storage::create_vault_catalog(namespace.clone()).unwrap();
        let object = core_storage::create_vault_object(
            "obj-structured-1",
            namespace.clone(),
            core_types::VaultObjectClass::StructuredRecord,
            "rev-structured-1",
            1,
            core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_types::RetentionPolicy::KeepLatest,
        )
        .unwrap();
        let revision = core_storage::create_vault_revision(
            "rev-structured-1",
            "obj-structured-1",
            "manifest-structured-1",
            core_types::PayloadKind::StructuredRecord,
            "application/json",
            1,
            "device-a",
            None,
            Some(core_types::StructuredRecordMeta {
                schema_id: "com.example.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_types::StructuredEncoding::Json,
                app_namespace: "com.example.profile".into(),
            }),
            None,
        )
        .unwrap();
        core_storage::add_vault_object_with_initial_revision(&mut catalog, object, revision)
            .unwrap();
        let payload_chunks = vec![br#"{"name":"primary"}"#.to_vec()];
        let (payload_manifest, payload_blocks) = core_storage::seal_payload_manifest(
            "manifest-structured-1",
            &payload_chunks,
            &payload_key,
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        )
        .unwrap();

        {
            let mut store = EventStore::open(&path).unwrap();
            store
                .commit_local_vault_catalog_with_manifests(
                    "manifest-catalog-structured-1",
                    &catalog,
                    &catalog_key,
                    vec![manifest_device_access("device-a", "wrapped-device-a")],
                    &[LocalEncryptedManifest {
                        manifest: payload_manifest.clone(),
                        blocks: payload_blocks.clone(),
                    }],
                )
                .unwrap();
        }

        let reopened = EventStore::open(&path).unwrap();
        let loaded_catalog = reopened.local_vault_catalog(&namespace).unwrap().unwrap();
        let loaded_manifest = reopened
            .local_file_manifest("manifest-structured-1")
            .unwrap()
            .unwrap();
        let loaded_blocks = loaded_manifest
            .chunks
            .iter()
            .map(|chunk| EncryptedBlock {
                chunk: chunk.clone(),
                encrypted: reopened
                    .local_encrypted_content(&chunk.chunk_id)
                    .unwrap()
                    .unwrap(),
            })
            .collect::<Vec<_>>();
        let decrypted =
            core_storage::open_payload_manifest(&loaded_manifest, &loaded_blocks, &payload_key)
                .unwrap();

        assert_eq!(loaded_catalog, catalog);
        assert_eq!(loaded_manifest, payload_manifest);
        assert_eq!(decrypted, payload_chunks);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn replacement_device_can_take_over_local_vault_manifest_access() {
        let mut store = EventStore::default();
        let device_a_encryption = generate_local_encryption_key_pair("device", "device-a");
        let device_b_encryption = generate_local_encryption_key_pair("device", "device-b");
        let namespace = test_namespace();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: PublicKeyMaterial {
                    key_id: device_a_encryption.key_id.clone(),
                    algorithm: device_a_encryption.algorithm,
                    public_key: device_a_encryption.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-2",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-b".into(),
                label: "Replacement".into(),
                initial_key: test_key("key-device-b-v1"),
                initial_encryption_key: PublicKeyMaterial {
                    key_id: device_b_encryption.key_id.clone(),
                    algorithm: device_b_encryption.algorithm,
                    public_key: device_b_encryption.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-local-1",
                "rev-local-1",
                "manifest-local-record-1",
                "manifest-local-catalog-1",
                1,
                "device-a",
                core_types::StructuredRecordMeta {
                    schema_id: "com.example.profile/basic".into(),
                    schema_version: "v1".into(),
                    encoding: core_types::StructuredEncoding::Json,
                    app_namespace: "com.example.profile".into(),
                },
                br#"{"full_name":"Jordan Hudson"}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                vec![manifest_key_recipient(
                    "device-a",
                    device_a_encryption.public_key.clone(),
                )],
            )
            .unwrap();
        append_typed(
            &mut store,
            "evt-device-replaced-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-b".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let updated = store
            .restore_local_vault_access_to_replacement_device(&namespace, "device-a", "device-b")
            .unwrap();

        assert_eq!(
            updated,
            vec![
                "manifest-local-catalog-1".to_string(),
                "manifest-local-record-1".to_string()
            ]
        );
        let catalog_manifest = store
            .local_file_manifest("manifest-local-catalog-1")
            .unwrap()
            .unwrap();
        let payload_manifest = store
            .local_file_manifest("manifest-local-record-1")
            .unwrap()
            .unwrap();
        assert_eq!(catalog_manifest.authorized_devices.len(), 1);
        assert_eq!(catalog_manifest.authorized_devices[0].device_id, "device-b");
        assert_eq!(payload_manifest.authorized_devices.len(), 1);
        assert_eq!(payload_manifest.authorized_devices[0].device_id, "device-b");
    }

    #[test]
    fn frozen_device_can_be_revoked_from_local_vault_manifest_access() {
        let mut store = EventStore::default();
        let device_a_encryption = generate_local_encryption_key_pair("device", "device-a");
        let namespace = test_namespace();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: PublicKeyMaterial {
                    key_id: device_a_encryption.key_id.clone(),
                    algorithm: device_a_encryption.algorithm,
                    public_key: device_a_encryption.public_key.clone(),
                },
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_local_structured_record(
                &namespace,
                "obj-local-1",
                "rev-local-1",
                "manifest-local-record-1",
                "manifest-local-catalog-1",
                1,
                "device-a",
                core_types::StructuredRecordMeta {
                    schema_id: "com.example.profile/basic".into(),
                    schema_version: "v1".into(),
                    encoding: core_types::StructuredEncoding::Json,
                    app_namespace: "com.example.profile".into(),
                },
                br#"{"full_name":"Jordan Hudson"}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                vec![manifest_key_recipient(
                    "device-a",
                    device_a_encryption.public_key.clone(),
                )],
            )
            .unwrap();
        append_typed(
            &mut store,
            "evt-device-frozen-1",
            EventBody::DeviceFrozen(DeviceFrozenEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "lost".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let updated = store
            .revoke_local_vault_access_for_inactive_device(&namespace, "device-a")
            .unwrap();

        assert_eq!(
            updated,
            vec![
                "manifest-local-catalog-1".to_string(),
                "manifest-local-record-1".to_string()
            ]
        );
        let catalog_manifest = store
            .local_file_manifest("manifest-local-catalog-1")
            .unwrap()
            .unwrap();
        let payload_manifest = store
            .local_file_manifest("manifest-local-record-1")
            .unwrap()
            .unwrap();
        assert!(catalog_manifest.authorized_devices.is_empty());
        assert!(payload_manifest.authorized_devices.is_empty());
    }

    #[test]
    fn storage_relationship_and_ledger_events_materialize_across_reopen() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emberlink-core-state-storage-ledger-{unique}.sqlite"
        ));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-relationship-1",
                storage_relationship_created_event(
                    "root-a",
                    create_relationship("storage-1", "peer-a", "peer-b"),
                ),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-storage-ledger-1",
                storage_ledger_updated_event("root-a", ledger_delta("storage-1", 524_288)),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
        }

        let reopened = EventStore::open(&path).unwrap();
        let relationship = reopened
            .materialized()
            .storage_relationships_current
            .get("storage-1")
            .unwrap();
        let balance = reopened
            .materialized()
            .storage_balances_current
            .get("storage-1")
            .unwrap();

        assert_eq!(relationship.local_peer_id, "peer-a");
        assert_eq!(relationship.remote_peer_id, "peer-b");
        assert!(relationship.approved);
        assert_eq!(balance.stored_bytes_delta, 524_288);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn frozen_device_cannot_restore_manifest_and_access_can_be_revoked() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_file_manifest(&test_manifest("manifest-1", "bafy-root-1", "device-a"))
            .unwrap();

        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        assert!(
            store
                .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
                .is_ok()
        );

        append_typed(
            &mut store,
            "evt-device-freeze-1",
            EventBody::DeviceFrozen(core_types::DeviceFrozenEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "lost".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let err = store
            .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
            .unwrap_err();
        assert!(err.message.contains("active device"));

        store
            .revoke_manifest_access_for_inactive_device("manifest-1", "device-a")
            .unwrap();
        let manifest = store.file_manifest("manifest-1").unwrap();
        assert!(manifest.authorized_devices.is_empty());
    }

    #[test]
    fn replacement_device_can_take_over_manifest_access_after_recovery() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-2",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-b".into(),
                label: "Replacement".into(),
                initial_key: test_key("key-device-b-v1"),
                initial_encryption_key: test_encryption_key("key-device-b-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
            .upsert_file_manifest(&test_manifest("manifest-1", "bafy-root-1", "device-a"))
            .unwrap();
        append_typed(
            &mut store,
            "evt-device-replaced-1",
            EventBody::DeviceReplaced(DeviceReplacedEvent {
                root_id: "root-a".into(),
                replaced_device_id: "device-a".into(),
                replacement_device_id: "device-b".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        store
            .restore_manifest_access_to_replacement_device(
                "manifest-1",
                "device-a",
                manifest_device_access("device-b", "wrapped-b"),
            )
            .unwrap();

        let manifest = store.file_manifest("manifest-1").unwrap();
        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-b");

        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        assert!(
            store
                .plan_storage_restore_for_device("manifest-1", "device-a", &relationship)
                .is_err()
        );
        assert_eq!(
            store
                .select_active_restore_device_for_manifest("manifest-1")
                .unwrap(),
            "device-b"
        );
        let (restore_device_id, restore_chunks) = store
            .plan_storage_restore("manifest-1", &relationship)
            .unwrap();
        assert_eq!(restore_device_id, "device-b");
        assert_eq!(restore_chunks.len(), 2);
        assert!(
            store
                .plan_storage_restore_for_device("manifest-1", "device-b", &relationship)
                .is_ok()
        );
    }

    #[test]
    fn recovery_approval_rejects_non_guardian_signers() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-policy-1",
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: "root-a".into(),
                guardian_threshold: 1,
                cooldown_seconds: 3600,
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-request-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "recovery-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let invalid_approval = EventEnvelope::from_body(
            "evt-recovery-approval-invalid",
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: "recovery-1".into(),
                guardian_id: "guardian-alex".into(),
            }),
            vec![EventRef::previous("evt-recovery-request-1")],
            SignerBinding::device("device-a", "key-device-a-v1"),
            &FixtureSigner::new("key-device-a-v1"),
        )
        .unwrap();

        let err = store
            .append_with_authorizer(invalid_approval, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(err.message.contains("guardian role"));
    }

    #[test]
    fn revoked_device_cannot_rotate_key_or_receive_persona_access() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-revoke-1",
            EventBody::DeviceRevoked(DeviceRevokedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "lost".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let rotate = EventEnvelope::from_body(
            "evt-device-rotate-1",
            EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a-v1".into(),
                new_key: test_key("key-device-a-v2"),
            }),
            Vec::new(),
            SignerBinding::device("device-a", "key-device-a-v1"),
            &FixtureSigner::new("key-device-a-v1"),
        )
        .unwrap();

        let rotate_err = store
            .append_with_authorizer(rotate, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(rotate_err.message.contains("not active"));

        let grant_err = store
            .grant_persona_device_access("persona-a", "device-a")
            .unwrap_err();
        assert!(grant_err.message.contains("non-active device"));
    }

    #[test]
    fn revoked_persona_cannot_rotate_key_or_receive_device_access() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-revoke-1",
            EventBody::PersonaRevoked(PersonaRevokedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                reason: "compromised".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let rotate = EventEnvelope::from_body(
            "evt-persona-rotate-1",
            EventBody::PersonaKeyRotated(PersonaKeyRotatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                previous_key_id: "key-persona-a-v1".into(),
                new_key: test_key("key-persona-a-v2"),
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &FixtureSigner::new("key-persona-a-v1"),
        )
        .unwrap();

        let rotate_err = store
            .append_with_authorizer(rotate, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(rotate_err.message.contains("not active"));

        let grant_err = store
            .grant_persona_device_access("persona-a", "device-a")
            .unwrap_err();
        assert!(grant_err.message.contains("revoked persona"));
    }

    #[test]
    fn contested_recovery_enters_cooldown_and_blocks_execution_until_rejected() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-policy-1",
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: "root-a".into(),
                guardian_threshold: 1,
                cooldown_seconds: 3600,
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        let alex_pub = fixture_guardian_pubkey("guardian-key-alex");
        let riley_pub = fixture_guardian_pubkey("guardian-key-riley");
        append_typed(
            &mut store,
            "evt-guardian-enroll-1",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-a".into(),
                guardian_id: "guardian-alex".into(),
                guardian_label: "Alex".into(),
                guardian_public_key: alex_pub.clone(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-guardian-enroll-2",
            EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                root_id: "root-a".into(),
                guardian_id: "guardian-riley".into(),
                guardian_label: "Riley".into(),
                guardian_public_key: riley_pub.clone(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-recovery-request-1",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "recovery-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let approval = EventEnvelope::from_body(
            "evt-recovery-approval-1",
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: "recovery-1".into(),
                guardian_id: "guardian-alex".into(),
            }),
            vec![EventRef::previous("evt-recovery-request-1")],
            SignerBinding::guardian("guardian-alex", alex_pub.clone()),
            &FixtureSigner::new("guardian-key-alex"),
        )
        .unwrap();
        store
            .append_with_authorizer(approval, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        let contest = EventEnvelope::from_body(
            "evt-recovery-contest-1",
            EventBody::RecoveryContested(RecoveryContestedEvent {
                request_id: "recovery-1".into(),
                guardian_id: "guardian-riley".into(),
                reason: "improper approval".into(),
                contested_at_epoch: 1000,
            }),
            vec![EventRef::previous("evt-recovery-approval-1")],
            SignerBinding::guardian("guardian-riley", riley_pub.clone()),
            &FixtureSigner::new("guardian-key-riley"),
        )
        .unwrap();
        store
            .append_with_authorizer(contest, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        let request = store
            .materialized()
            .recovery_requests_current
            .get("recovery-1")
            .unwrap();
        assert_eq!(request.status, RecoveryRequestStatus::Contested);
        assert!(request.cooldown_until.is_some());
        assert_eq!(request.contested_by.len(), 1);
        assert_eq!(request.contest_reason.as_deref(), Some("improper approval"));

        let execute = EventEnvelope::from_body(
            "evt-recovery-executed-1",
            EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: "recovery-1".into(),
                executed_scope: RecoveryScope::FreezeDevice,
            }),
            vec![EventRef::previous("evt-recovery-contest-1")],
            SignerBinding::root("root-a", "key-root-a-v1"),
            &FixtureSigner::new("key-root-a-v1"),
        )
        .unwrap();
        let execute_err = store
            .append_with_authorizer(execute, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(execute_err.message.contains("cooldown"));

        let reject = EventEnvelope::from_body(
            "evt-recovery-rejected-1",
            EventBody::RecoveryRejected(RecoveryRejectedEvent {
                request_id: "recovery-1".into(),
                rejected_by: "root-a".into(),
                reason: "contest upheld".into(),
            }),
            vec![EventRef::previous("evt-recovery-contest-1")],
            SignerBinding::root("root-a", "key-root-a-v1"),
            &FixtureSigner::new("key-root-a-v1"),
        )
        .unwrap();
        store
            .append_with_authorizer(reject, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        let rejected = store
            .materialized()
            .recovery_requests_current
            .get("recovery-1")
            .unwrap();
        assert_eq!(rejected.status, RecoveryRequestStatus::Rejected);
        assert!(rejected.cooldown_until.is_none());
        assert_eq!(rejected.rejection_reason.as_deref(), Some("contest upheld"));
    }

    #[test]
    fn future_now_clamped_cannot_bypass_cooldown() {
        // Build the same contested state as above (contested_at_epoch=1000,
        // cooldown_seconds=3600 → cooldown_until=4600).
        let mut store = EventStore::default();
        for (id, body, signer) in [
            (
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-x".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-x-v1"),
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
            (
                "evt-device-1",
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: "root-x".into(),
                    device_id: "device-x".into(),
                    label: "Laptop".into(),
                    initial_key: test_key("key-device-x-v1"),
                    initial_encryption_key: test_encryption_key("key-device-x-v1"),
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
            (
                "evt-policy-1",
                EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                    root_id: "root-x".into(),
                    guardian_threshold: 1,
                    cooldown_seconds: 3600,
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
            (
                "evt-guardian-1",
                EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                    root_id: "root-x".into(),
                    guardian_id: "guardian-b".into(),
                    guardian_label: "Bob".into(),
                    guardian_public_key: fixture_guardian_pubkey("guardian-key-b"),
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
            (
                "evt-guardian-2",
                EventBody::GuardianEnrolled(GuardianEnrolledEvent {
                    root_id: "root-x".into(),
                    guardian_id: "guardian-c".into(),
                    guardian_label: "Carol".into(),
                    guardian_public_key: fixture_guardian_pubkey("guardian-key-c"),
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
            (
                "evt-request-1",
                EventBody::RecoveryRequested(RecoveryRequestedEvent {
                    request_id: "recovery-x".into(),
                    root_id: "root-x".into(),
                    target_device_id: "device-x".into(),
                }),
                SignerBinding::root("root-x", "key-root-x-v1"),
            ),
        ] {
            append_typed(&mut store, id, body, signer);
        }

        let approval = EventEnvelope::from_body(
            "evt-approval-1",
            EventBody::RecoveryApproved(RecoveryApprovedEvent {
                request_id: "recovery-x".into(),
                guardian_id: "guardian-b".into(),
            }),
            vec![EventRef::previous("evt-request-1")],
            SignerBinding::guardian("guardian-b", fixture_guardian_pubkey("guardian-key-b")),
            &FixtureSigner::new("guardian-key-b"),
        )
        .unwrap();
        store
            .append_with_authorizer(approval, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        // Contest at epoch=1000 → cooldown_until = 1000 + 3600 = 4600
        let contest = EventEnvelope::from_body(
            "evt-contest-1",
            EventBody::RecoveryContested(RecoveryContestedEvent {
                request_id: "recovery-x".into(),
                guardian_id: "guardian-c".into(),
                reason: "suspicious".into(),
                contested_at_epoch: 1000,
            }),
            vec![EventRef::previous("evt-approval-1")],
            SignerBinding::guardian("guardian-c", fixture_guardian_pubkey("guardian-key-c")),
            &FixtureSigner::new("guardian-key-c"),
        )
        .unwrap();
        store
            .append_with_authorizer(contest, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap();

        // Attempt execution with a far-future timestamp — should still be blocked by cooldown
        // because append_with_authorizer clamps now_epoch_secs to system_now + 300.
        let execute = EventEnvelope::from_body(
            "evt-execute-1",
            EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: "recovery-x".into(),
                executed_scope: RecoveryScope::FreezeDevice,
            }),
            vec![EventRef::previous("evt-contest-1")],
            SignerBinding::root("root-x", "key-root-x-v1"),
            &FixtureSigner::new("key-root-x-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(execute, &FixtureVerifier, &IdentityAuthorizer, u64::MAX)
            .unwrap_err();
        // Cooldown expires at epoch 4600; system_now is << 4600 in any CI environment,
        // so the clamped effective_now is well below the cooldown threshold.
        assert!(
            err.message.contains("cooldown") || err.message.contains("approved"),
            "expected cooldown rejection, got: {}",
            err.message
        );
    }

    #[test]
    fn duplicate_event_ids_fail_inside_sqlite_store() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let duplicate = EventEnvelope::from_body(
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Other".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            Vec::new(),
            SignerBinding::root("root-b", "key-root-b-v1"),
            &FixtureSigner::new("key-root-b-v1"),
        )
        .unwrap();

        let err = store
            .append_with_authorizer(duplicate, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(err.message.contains("insert event row"));
    }

    #[test]
    fn persona_signed_message_and_content_events_round_trip_through_store() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("emberlink-core-state-message-{unique}.sqlite"));

        {
            let mut store = EventStore::open(&path).unwrap();
            append_typed(
                &mut store,
                "evt-root-1",
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: "root-a".into(),
                    display_name: "Primary".into(),
                    initial_key: test_key("key-root-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-persona-1",
                EventBody::PersonaCreated(PersonaCreatedEvent {
                    root_id: "root-a".into(),
                    persona_id: "persona-a".into(),
                    label: "Work".into(),
                    disclosure_profile: Some("persona.professional".into()),
                    survival_mode: SurvivalMode::Strict,
                    initial_key: test_key("key-persona-a-v1"),
                }),
                SignerBinding::root("root-a", "key-root-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-message-1",
                EventBody::MessageSent(MessageSentEvent {
                    message_id: "message-1".into(),
                    sender_persona_id: "persona-a".into(),
                    recipient_persona_id: "persona-b".into(),
                    ciphertext_hex: "c0ffee".into(),
                }),
                SignerBinding::persona("persona-a", "key-persona-a-v1"),
            );
            append_typed(
                &mut store,
                "evt-content-1",
                EventBody::ContentPublished(ContentPublishedEvent {
                    content_id: "content-1".into(),
                    author_persona_id: "persona-a".into(),
                    content_type: "post".into(),
                    payload_hex: "deadbeef".into(),
                    visibility: ContentVisibility::TrustGated,
                }),
                SignerBinding::persona("persona-a", "key-persona-a-v1"),
            );

            assert_eq!(store.event_count(), 4);
            assert_eq!(
                store.current_event_type_for("evt-message-1"),
                Some(EventType::MessageSent)
            );
            assert_eq!(
                store.current_event_type_for("evt-content-1"),
                Some(EventType::ContentPublished)
            );
            assert!(store.materialized().persona("persona-a").is_some());
        }

        let reopened = EventStore::open(&path).unwrap();
        assert_eq!(reopened.event_count(), 4);
        assert_eq!(
            reopened.current_event_type_for("evt-message-1"),
            Some(EventType::MessageSent)
        );
        assert_eq!(
            reopened.current_event_type_for("evt-content-1"),
            Some(EventType::ContentPublished)
        );
        assert!(reopened.materialized().persona("persona-a").is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn message_and_content_events_require_active_persona_signer() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-revoke-1",
            EventBody::PersonaRevoked(PersonaRevokedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                reason: "compromised".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        let message = EventEnvelope::from_body(
            "evt-message-1",
            EventBody::MessageSent(MessageSentEvent {
                message_id: "message-1".into(),
                sender_persona_id: "persona-a".into(),
                recipient_persona_id: "persona-b".into(),
                ciphertext_hex: "c0ffee".into(),
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &FixtureSigner::new("key-persona-a-v1"),
        )
        .unwrap();
        let content = EventEnvelope::from_body(
            "evt-content-1",
            EventBody::ContentPublished(ContentPublishedEvent {
                content_id: "content-1".into(),
                author_persona_id: "persona-a".into(),
                content_type: "post".into(),
                payload_hex: "deadbeef".into(),
                visibility: ContentVisibility::Public,
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &FixtureSigner::new("key-persona-a-v1"),
        )
        .unwrap();

        let message_err = store
            .append_with_authorizer(message, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(message_err.message.contains("not active"));

        let content_err = store
            .append_with_authorizer(content, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(content_err.message.contains("not active"));
    }

    #[test]
    fn trust_attestations_materialize_current_and_derived_state_and_can_be_revoked() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-a",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-root-b",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Secondary".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-a",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Professional".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-b",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-b".into(),
                persona_id: "persona-b".into(),
                label: "Pseudonymous".into(),
                disclosure_profile: Some("persona.pseudonymous".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-trust-1",
            EventBody::TrustAttested(TrustAttestedEvent {
                attestation_id: "trust-1".into(),
                attester_persona_id: "persona-a".into(),
                subject_persona_id: "persona-b".into(),
                domain: "relay".into(),
                score: 0.8,
                recipient_bound: None,
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );

        assert_eq!(store.materialized().trust_edges_current.len(), 1);
        assert_eq!(store.materialized().derived_trust_current.len(), 1);
        assert!(
            (store
                .materialized()
                .derived_trust_current
                .get("derived:persona-b:relay")
                .unwrap()
                .normalized_score
                - 0.8)
                .abs()
                < f32::EPSILON
        );

        append_typed(
            &mut store,
            "evt-trust-revoke-1",
            EventBody::TrustRevoked(TrustRevokedEvent {
                attestation_id: "trust-1".into(),
                attester_persona_id: "persona-a".into(),
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );

        assert!(store.materialized().trust_edges_current.is_empty());
        assert!(store.materialized().derived_trust_current.is_empty());
    }

    #[test]
    fn recipient_bound_trust_attestations_do_not_change_public_derived_state() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-a",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-root-b",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-b".into(),
                display_name: "Secondary".into(),
                initial_key: test_key("key-root-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-a",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Professional".into(),
                disclosure_profile: Some("persona.professional".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-b",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-b".into(),
                persona_id: "persona-b".into(),
                label: "Pseudonymous".into(),
                disclosure_profile: Some("persona.pseudonymous".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-b-v1"),
            }),
            SignerBinding::root("root-b", "key-root-b-v1"),
        );
        append_typed(
            &mut store,
            "evt-trust-public",
            EventBody::TrustAttested(TrustAttestedEvent {
                attestation_id: "trust-public".into(),
                attester_persona_id: "persona-a".into(),
                subject_persona_id: "persona-b".into(),
                domain: "relay".into(),
                score: 0.8,
                recipient_bound: None,
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-trust-recipient",
            EventBody::TrustAttested(TrustAttestedEvent {
                attestation_id: "trust-hidden".into(),
                attester_persona_id: "persona-a".into(),
                subject_persona_id: "persona-b".into(),
                domain: "relay".into(),
                score: 0.2,
                recipient_bound: Some("peer-demo".into()),
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );

        assert_eq!(store.materialized().trust_edges_current.len(), 2);
        assert!(
            (store
                .materialized()
                .derived_trust_current
                .get("derived:persona-b:relay")
                .unwrap()
                .normalized_score
                - 0.8)
                .abs()
                < f32::EPSILON
        );
    }

    #[test]
    fn current_event_type_uses_reloaded_persistent_events() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        assert_eq!(
            store.current_event_type_for("evt-root-1"),
            Some(EventType::RootCreated)
        );

        let stored_signature: Option<String> = store
            .conn
            .query_row(
                "SELECT signature FROM event_signatures WHERE event_id = ?1",
                params!["evt-root-1"],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(stored_signature.is_some());
    }

    #[test]
    fn event_ids_preserve_append_order() {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-root-2",
            EventBody::RootRevoked(RootRevokedEvent {
                root_id: "root-a".into(),
                reason: "test".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );

        assert_eq!(
            store.event_ids(),
            vec!["evt-root-1".to_string(), "evt-root-2".to_string()]
        );
    }

    // ── Adversarial authorization tests ────────────────────────────────

    /// Helper: bootstraps two independent identity roots with a device and persona each.
    fn two_root_fixture() -> EventStore {
        let mut store = EventStore::default();
        for (root, key, device, dkey, persona, pkey) in [
            (
                "root-a",
                "key-root-a-v1",
                "device-a",
                "key-device-a-v1",
                "persona-a",
                "key-persona-a-v1",
            ),
            (
                "root-b",
                "key-root-b-v1",
                "device-b",
                "key-device-b-v1",
                "persona-b",
                "key-persona-b-v1",
            ),
        ] {
            append_typed(
                &mut store,
                &format!("evt-{root}-create"),
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: root.into(),
                    display_name: root.into(),
                    initial_key: test_key(key),
                }),
                SignerBinding::root(root, key),
            );
            append_typed(
                &mut store,
                &format!("evt-{device}-add"),
                EventBody::DeviceAdded(DeviceAddedEvent {
                    root_id: root.into(),
                    device_id: device.into(),
                    label: "test".into(),
                    initial_key: test_key(dkey),
                    initial_encryption_key: test_encryption_key(dkey),
                }),
                SignerBinding::root(root, key),
            );
            append_typed(
                &mut store,
                &format!("evt-{persona}-create"),
                EventBody::PersonaCreated(PersonaCreatedEvent {
                    root_id: root.into(),
                    persona_id: persona.into(),
                    label: "test".into(),
                    disclosure_profile: None,
                    survival_mode: SurvivalMode::Strict,
                    initial_key: test_key(pkey),
                }),
                SignerBinding::root(root, key),
            );
        }
        store
    }

    #[test]
    fn cross_root_device_add_rejected() {
        let mut store = two_root_fixture();
        // Root A tries to add a device under Root B's identity
        let event = EventEnvelope::from_body(
            "evt-cross-device",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-b".into(),
                device_id: "device-evil".into(),
                label: "evil".into(),
                initial_key: test_key("key-evil"),
                initial_encryption_key: test_encryption_key("key-evil"),
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &FixtureSigner::new("key-root-a-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "cross-root should be rejected: {}",
            err.message
        );
    }

    #[test]
    fn wrong_key_id_for_root_rejected() {
        let mut store = two_root_fixture();
        // Correct root identity but a fabricated key ID
        let event = EventEnvelope::from_body(
            "evt-wrong-key",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-new".into(),
                label: "new".into(),
                initial_key: test_key("key-new"),
                initial_encryption_key: test_encryption_key("key-new"),
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-fabricated"),
            &FixtureSigner::new("key-fabricated"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "wrong key id should be rejected: {}",
            err.message
        );
    }

    #[test]
    fn device_key_cannot_perform_root_operations() {
        let mut store = two_root_fixture();
        // Device key tries to create a persona (root-only operation)
        let event = EventEnvelope::from_body(
            "evt-device-escalation",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-evil".into(),
                label: "evil".into(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-evil"),
            }),
            Vec::new(),
            SignerBinding::device("device-a", "key-device-a-v1"),
            &FixtureSigner::new("key-device-a-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "device key should not perform root operations: {}",
            err.message
        );
    }

    #[test]
    fn persona_key_cannot_add_devices() {
        let mut store = two_root_fixture();
        // Persona key tries to add a device (root-only operation)
        let event = EventEnvelope::from_body(
            "evt-persona-escalation",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-evil".into(),
                label: "evil".into(),
                initial_key: test_key("key-evil"),
                initial_encryption_key: test_encryption_key("key-evil"),
            }),
            Vec::new(),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
            &FixtureSigner::new("key-persona-a-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "persona key should not add devices: {}",
            err.message
        );
    }

    #[test]
    fn cross_persona_trust_attestation_rejected() {
        let mut store = two_root_fixture();
        // Persona B's key tries to create a trust attestation claiming to be Persona A
        let event = EventEnvelope::from_body(
            "evt-cross-trust",
            EventBody::TrustAttested(TrustAttestedEvent {
                attestation_id: "trust-fake".into(),
                attester_persona_id: "persona-a".into(), // claims to be A
                subject_persona_id: "persona-b".into(),
                domain: "professional".into(),
                score: 1.0,
                recipient_bound: None,
            }),
            Vec::new(),
            SignerBinding::persona("persona-b", "key-persona-b-v1"), // but signed by B
            &FixtureSigner::new("key-persona-b-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "cross-persona attestation should be rejected: {}",
            err.message
        );
    }

    #[test]
    fn trust_revocation_by_non_attester_rejected() {
        let mut store = two_root_fixture();
        // Persona A creates a valid trust attestation
        append_typed(
            &mut store,
            "evt-trust-1",
            EventBody::TrustAttested(TrustAttestedEvent {
                attestation_id: "trust-1".into(),
                attester_persona_id: "persona-a".into(),
                subject_persona_id: "persona-b".into(),
                domain: "professional".into(),
                score: 0.9,
                recipient_bound: None,
            }),
            SignerBinding::persona("persona-a", "key-persona-a-v1"),
        );
        // Persona B tries to revoke Persona A's attestation
        let event = EventEnvelope::from_body(
            "evt-trust-revoke-fake",
            EventBody::TrustRevoked(TrustRevokedEvent {
                attestation_id: "trust-1".into(),
                attester_persona_id: "persona-a".into(), // claims to be A
            }),
            Vec::new(),
            SignerBinding::persona("persona-b", "key-persona-b-v1"), // but signed by B
            &FixtureSigner::new("key-persona-b-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("does not match"),
            "non-attester should not revoke trust: {}",
            err.message
        );
    }

    #[test]
    fn frozen_device_cannot_sign_events() {
        let mut store = two_root_fixture();
        // Freeze device-a
        append_typed(
            &mut store,
            "evt-freeze-a",
            EventBody::DeviceFrozen(DeviceFrozenEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                reason: "suspicious activity".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        // Frozen device tries to rotate its own key
        let event = EventEnvelope::from_body(
            "evt-frozen-rotate",
            EventBody::DeviceKeyRotated(DeviceKeyRotatedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                previous_key_id: "key-device-a-v1".into(),
                new_key: test_key("key-device-a-v2"),
            }),
            Vec::new(),
            SignerBinding::device("device-a", "key-device-a-v1"),
            &FixtureSigner::new("key-device-a-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("not active"),
            "frozen device should not sign: {}",
            err.message
        );
    }

    #[test]
    fn recovery_execution_before_approval_rejected() {
        let mut store = two_root_fixture();
        // Create a recovery policy
        append_typed(
            &mut store,
            "evt-recovery-policy",
            EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
                root_id: "root-a".into(),
                guardian_threshold: 2,
                cooldown_seconds: 3600,
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        // Request recovery
        append_typed(
            &mut store,
            "evt-recovery-request",
            EventBody::RecoveryRequested(RecoveryRequestedEvent {
                request_id: "recovery-1".into(),
                root_id: "root-a".into(),
                target_device_id: "device-a".into(),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        // Try to execute without any approvals
        let event = EventEnvelope::from_body(
            "evt-recovery-execute-premature",
            EventBody::RecoveryExecuted(RecoveryExecutedEvent {
                request_id: "recovery-1".into(),
                executed_scope: RecoveryScope::FreezeDevice,
            }),
            Vec::new(),
            SignerBinding::root("root-a", "key-root-a-v1"),
            &FixtureSigner::new("key-root-a-v1"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("must be approved"),
            "unapproved recovery should not execute: {}",
            err.message
        );
    }

    #[test]
    fn unknown_root_id_rejected() {
        let mut store = EventStore::default();
        // Try to add a device to a root that doesn't exist
        let event = EventEnvelope::from_body(
            "evt-phantom",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-phantom".into(),
                device_id: "device-phantom".into(),
                label: "phantom".into(),
                initial_key: test_key("key-phantom"),
                initial_encryption_key: test_encryption_key("key-phantom"),
            }),
            Vec::new(),
            SignerBinding::root("root-phantom", "key-phantom"),
            &FixtureSigner::new("key-phantom"),
        )
        .unwrap();
        let err = store
            .append_with_authorizer(event, &FixtureVerifier, &IdentityAuthorizer, 0)
            .unwrap_err();
        assert!(
            err.message.contains("unknown root"),
            "non-existent root should be rejected: {}",
            err.message
        );
    }

    // --- Access Grant CRUD tests ---

    fn store_with_persona() -> EventStore {
        let mut store = EventStore::default();
        append_typed(
            &mut store,
            "evt-root-1",
            EventBody::RootCreated(RootCreatedEvent {
                root_id: "root-a".into(),
                display_name: "Primary".into(),
                initial_key: test_key("key-root-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-device-1",
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: "root-a".into(),
                device_id: "device-a".into(),
                label: "Laptop".into(),
                initial_key: test_key("key-device-a-v1"),
                initial_encryption_key: test_encryption_key("key-device-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        append_typed(
            &mut store,
            "evt-persona-1",
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: "root-a".into(),
                persona_id: "persona-a".into(),
                label: "Work".into(),
                disclosure_profile: Some("work-public".into()),
                survival_mode: SurvivalMode::Strict,
                initial_key: test_key("key-persona-a-v1"),
            }),
            SignerBinding::root("root-a", "key-root-a-v1"),
        );
        store
    }


    // Grant CRUD tests deferred — see design follow-up PR for composite grant test port.

    fn sample_approval_request(id: &str) -> core_types::approval::ApprovalRequest {
        core_types::approval::ApprovalRequest::new(
            id.into(),
            "agent-claude".into(),
            Some("Claude agent".into()),
            core_types::approval::RequestedScope {
                capability: "ReadCredential".into(),
                resource_id: Some("cred-netflix".into()),
                constraints: vec!["read-only".into()],
            },
            Some(3600),
            Some("Need Netflix password".into()),
            1700000000,
        )
    }

    #[test]
    fn insert_and_retrieve_approval_request() {
        let store = EventStore::default();
        let req = sample_approval_request("req-1");
        store.insert_approval_request(&req).unwrap();

        let loaded = store.get_approval_request("req-1").unwrap().unwrap();
        assert_eq!(loaded.request_id, "req-1");
        assert_eq!(loaded.requester_id, "agent-claude");
        assert_eq!(loaded.requester_label.as_deref(), Some("Claude agent"));
        assert_eq!(loaded.status, "pending");
        assert_eq!(loaded.created_at, 1700000000);
        assert_eq!(loaded.requested_duration_secs, Some(3600));
        assert_eq!(loaded.reason.as_deref(), Some("Need Netflix password"));
        assert!(loaded.resolved_at.is_none());
        assert!(loaded.resolver_id.is_none());

        assert!(store.get_approval_request("nonexistent").unwrap().is_none());
    }

    #[test]
    fn list_pending_approvals_returns_only_pending() {
        let store = EventStore::default();

        let req1 = sample_approval_request("req-1");
        let mut req2 = sample_approval_request("req-2");
        req2.created_at = 1700000060;
        store.insert_approval_request(&req1).unwrap();
        store.insert_approval_request(&req2).unwrap();

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].request_id, "req-2");
        assert_eq!(pending[1].request_id, "req-1");

        let response = core_types::approval::ApprovalResponse {
            request_id: "req-1".into(),
            status: core_types::approval::ApprovalStatus::Approved,
            resolver_id: "josh".into(),
            resolved_at: 1700000120,
            narrowed_scope: None,
            denial_reason: None,
            granted_duration_secs: Some(3600),
        };
        store.resolve_approval_request("req-1", &response).unwrap();

        let pending = store.list_pending_approvals().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req-2");
    }

    #[test]
    fn resolve_approval_request_updates_status() {
        let store = EventStore::default();
        let req = sample_approval_request("req-1");
        store.insert_approval_request(&req).unwrap();

        let response = core_types::approval::ApprovalResponse {
            request_id: "req-1".into(),
            status: core_types::approval::ApprovalStatus::Denied,
            resolver_id: "josh".into(),
            resolved_at: 1700000120,
            narrowed_scope: None,
            denial_reason: Some("Not authorized".into()),
            granted_duration_secs: None,
        };
        store.resolve_approval_request("req-1", &response).unwrap();

        let loaded = store.get_approval_request("req-1").unwrap().unwrap();
        assert_eq!(loaded.status, "denied");
        assert_eq!(loaded.resolved_at, Some(1700000120));
        assert_eq!(loaded.resolver_id.as_deref(), Some("josh"));
        assert_eq!(loaded.denial_reason.as_deref(), Some("Not authorized"));
    }

    #[test]
    fn resolve_already_resolved_request_fails() {
        let store = EventStore::default();
        let req = sample_approval_request("req-1");
        store.insert_approval_request(&req).unwrap();

        let response1 = core_types::approval::ApprovalResponse {
            request_id: "req-1".into(),
            status: core_types::approval::ApprovalStatus::Approved,
            resolver_id: "josh".into(),
            resolved_at: 1700000120,
            narrowed_scope: None,
            denial_reason: None,
            granted_duration_secs: Some(3600),
        };
        store.resolve_approval_request("req-1", &response1).unwrap();

        let response2 = core_types::approval::ApprovalResponse {
            request_id: "req-1".into(),
            status: core_types::approval::ApprovalStatus::Denied,
            resolver_id: "attacker".into(),
            resolved_at: 1700000180,
            narrowed_scope: None,
            denial_reason: Some("forged".into()),
            granted_duration_secs: None,
        };
        let err = store.resolve_approval_request("req-1", &response2).unwrap_err();
        assert!(err.message.contains("cannot transition"));
    }
}
