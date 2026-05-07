mod activity_support;
mod biometric;
pub mod binary;
pub mod broker;
pub mod cli;
pub mod cluster;
pub mod construct;
pub mod grants;
mod commands;
pub mod demo;
pub mod launcher;
pub mod onboarding;
pub mod output;
pub mod receipt;
pub mod session;
mod recovery;
mod screens;
mod sync_support;
mod vault_support;

pub use cli::{Args, Cmd};

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use self::sync_support::{SyncAdmissionOutcome, SyncExportOptions};

use core_crypto::{
    FixtureSigner, FixtureVerifier, LocalKeyPair, LocalKeySigner, Signer as CryptoSigner,
    generate_content_key, generate_local_encryption_key_pair,
    generate_local_encryption_key_pair_version, generate_local_key_pair,
    generate_local_key_pair_version, generate_random_identifier,
};
use core_events::EventEnvelope;
use core_identity::{create_root, device_revoked_event, local_linkage, root_created_event};
use core_personas::{create_persona, persona_created_event, persona_revoked_event, revoke_persona};
use core_types::policy::{
    PersonaTemplate, disclosure_profile_for_template, parse_persona_template,
    persona_template_for_disclosure_profile, persona_template_label,
};
use core_recovery::create_policy;
use core_state::{
    DeviceStatus, EventStore, IdentityAuthorizer, PersonaStatus, RecoveryRequestStatus,
};
use emberlink_app::{AppRuntime, LocalState};
use emberlink_app::local_state::GrantChainSecret;
use core_storage::{
    create_relationship, encrypt_block, ledger_delta, manifest_chunk, manifest_device_access,
    manifest_key_recipient, plan_restore, publish_manifest, storage_relationship_created_event,
    wrap_manifest_key_access,
};
use core_sync::LightSyncContext;
use core_types::{
    ChunkReference, ContentVisibility, DeviceMembership, DisclosureRevokedEvent, EventBody,
    IdentityRoot, KeyAlgorithm, LinkageAssertion, Persona, PublicKeyMaterial, RelayAdmission,
    SignerBinding, SurvivalMode, TrustAttestation, ValidationError, VaultNamespace,
};

#[derive(Debug, Clone)]
struct LocalKeyRecord {
    owner_kind: String,
    owner_id: String,
    key_pair: LocalKeyPair,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoverySession {
    request_id: String,
    root_id: String,
    target_device_id: String,
    replacement_device_id: Option<String>,
    state: String,
    approvals: Vec<String>,
    notified_devices: Vec<String>,
}

#[derive(Debug, Clone)]
enum AppSigner {
    Local(LocalKeySigner),
    Fixture(FixtureSigner),
}

impl AppSigner {
    fn from_key_pair(key_pair: &LocalKeyPair) -> Result<Self, String> {
        match LocalKeySigner::from_local_key_pair(key_pair) {
            Ok(signer) => Ok(Self::Local(signer)),
            Err(e) => Err(format!(
                "failed to load signing key '{}': {e} — refusing to fall back to deterministic signer",
                key_pair.key_id
            )),
        }
    }
}

impl CryptoSigner for AppSigner {
    fn sign(&self, payload: &[u8]) -> core_crypto::Signature {
        match self {
            Self::Local(signer) => signer.sign(payload),
            Self::Fixture(signer) => signer.sign(payload),
        }
    }

    fn public_key(&self) -> core_crypto::PublicKey {
        match self {
            Self::Local(signer) => signer.public_key(),
            Self::Fixture(signer) => signer.public_key(),
        }
    }
}

#[derive(Debug)]
pub struct DemoApp {
    data_file: Option<PathBuf>,
    seed_demo: bool,
    peer_id: String,
    verifier: FixtureVerifier,
    app_runtime: AppRuntime<EventStore>,
    next_root_id: usize,
    next_persona_id: usize,
    next_device_id: usize,
    roots: Vec<IdentityRoot>,
    devices: Vec<DeviceMembership>,
    revoked_devices: Vec<DeviceMembership>,
    personas: Vec<Persona>,
    revoked_personas: Vec<Persona>,
    local_keys: Vec<LocalKeyRecord>,
    /// M-3: grant-chain `pubkey_next` secrets keyed by grant_id. Stored
    /// here so the secret persists across daemon / CLI invocations and
    /// later delegation / attenuation blocks can be signed against the
    /// block-0 chain tail. See `core_crypto::grant_chain::PubkeyNextKeyPair`.
    chain_secrets: std::collections::HashMap<String, GrantChainSecret>,
    linkages: Vec<LinkageAssertion>,
    trust_attestations: Vec<TrustAttestation>,
    recovery_policy: core_types::RecoveryPolicy,
    recovery_session: Option<RecoverySession>,
    storage_relationship: core_types::StorageRelationship,
    storage_manifest: core_types::FileManifest,
    storage_ledger: core_types::StorageLedgerEntry,
    /// Whether to attempt TLS when connecting to relays (falls back to plain TCP).
    relay_try_tls: bool,
    /// Cached TLS client configuration (avoids rebuilding the verifier on every connection).
    tls_config: Arc<rustls::ClientConfig>,
    /// Number of MessageSent events already scanned by auto_import_disclosure_messages.
    disclosure_import_cursor: usize,
    /// DRY-10: active output renderer mode. Default = `Human { color: false }`
    /// to keep the ~380 in-tree string-substring tests green; binary entry
    /// points overwrite this from `Args::output_mode()` before dispatching
    /// any command. Migrated handlers (currently just `render_grant_list`)
    /// route through this; un-migrated handlers ignore it and emit the
    /// legacy human shape.
    pub(crate) output_mode: crate::output::Mode,
}

impl DemoApp {
    pub fn seeded() -> Self {
        let mut app = Self::bootstrap(Some(default_data_file()), true);
        app.relay_try_tls = true;
        app
    }

    pub fn with_state_file(path: impl Into<PathBuf>) -> Self {
        Self::bootstrap(Some(path.into()), false)
    }

    pub fn ephemeral() -> Self {
        Self::bootstrap(None, true)
    }

    /// DRY-10: set the active output renderer mode. Migrated handlers
    /// (currently just `render_grant_list`) honor this; un-migrated
    /// handlers continue to emit the legacy human shape.
    pub fn set_output_mode(&mut self, mode: crate::output::Mode) {
        self.output_mode = mode;
    }

    /// Read the active output renderer mode. Surface for binaries that
    /// want to inspect the resolved mode (e.g. for testing).
    pub fn output_mode(&self) -> crate::output::Mode {
        self.output_mode
    }

    fn bootstrap(data_file: Option<PathBuf>, seed_demo: bool) -> Self {
        match Self::try_bootstrap(data_file, seed_demo) {
            Ok(app) => app,
            Err(err) => {
                eprintln!("Error: {err}");
                eprintln!(
                    "Hint: existing state files were preserved when possible; check permissions, keychain access, disk space, or use an explicit repair/reset path"
                );
                std::process::exit(1);
            }
        }
    }

    fn try_bootstrap(data_file: Option<PathBuf>, seed_demo: bool) -> Result<Self, ValidationError> {
        let verifier = FixtureVerifier;
        let event_store = match data_file.as_deref() {
            Some(path) => {
                let master_key = resolve_encryption_key()?;
                EventStore::open_with_key(sqlite_path_for_local_state(path), master_key)
                    .map_err(|err| {
                        ValidationError::new(format!(
                            "could not open event store at {}: {err}",
                            path.display()
                        ))
                    })?
            }
            None => EventStore::default(),
        };
        let mut app = Self::new_unhydrated(data_file, seed_demo, verifier, event_store);

        if let Some(path) = app.data_file.clone() {
            let local_state_exists = path.exists();
            let mut seeded_identities = false;
            if local_state_exists {
                app.hydrate_identity_state();
                app.load_from_disk().map_err(|err| {
                    ValidationError::new(format!(
                        "failed to load local state from {}: {err}",
                        path.display()
                    ))
                })?;
            }
            if app.app_runtime.store.event_count() == 0 && app.seed_demo && app.roots.is_empty() {
                app.seed_initial_identities().map_err(|err| {
                    ValidationError::new(format!("failed to seed initial identities: {err}"))
                })?;
                seeded_identities = true;
            }
            if (!local_state_exists || seeded_identities)
                && let Err(err) = app.persist_to_disk()
            {
                return Err(ValidationError::new(format!(
                    "failed to persist state to {}: {err}",
                    path.display()
                )));
            }
            app.hydrate_identity_state();
            app.reconcile_recovery_session_from_state();
            app.initialize_runtime_storage_state().map_err(|err| {
                ValidationError::new(format!("failed to initialize storage state: {err}"))
            })?;
            app.refresh_identity_counters();
        } else {
            app.seed_initial_identities().map_err(|err| {
                ValidationError::new(format!("failed to seed initial identities: {err}"))
            })?;
            app.initialize_runtime_storage_state().map_err(|err| {
                ValidationError::new(format!("failed to initialize storage state: {err}"))
            })?;
        }
        Ok(app)
    }

    fn open_existing(data_file: PathBuf) -> Result<Self, ValidationError> {
        let sqlite_file = sqlite_path_for_local_state(&data_file);
        if !data_file.exists() && !sqlite_file.exists() {
            return Err(ValidationError::new(format!(
                "state file does not exist: {}",
                data_file.display()
            )));
        }

        let verifier = FixtureVerifier;
        let master_key = resolve_encryption_key()?;
        let event_store = EventStore::open_with_key(&sqlite_file, master_key)?;
        let mut app = Self::new_unhydrated(Some(data_file.clone()), false, verifier, event_store);
        if data_file.exists() {
            app.load_from_disk()?;
        }
        app.hydrate_identity_state();
        app.reconcile_recovery_session_from_state();
        app.initialize_runtime_storage_state()?;
        app.refresh_identity_counters();
        Ok(app)
    }

    fn new_unhydrated(
        data_file: Option<PathBuf>,
        seed_demo: bool,
        verifier: FixtureVerifier,
        event_store: EventStore,
    ) -> Self {
        Self {
            data_file,
            seed_demo,
            peer_id: generate_random_identifier("peer"),
            verifier,
            app_runtime: AppRuntime::new(event_store, LocalState::default()),
            next_root_id: 3,
            next_persona_id: 4,
            next_device_id: 3,
            roots: Vec::new(),
            devices: Vec::new(),
            revoked_devices: Vec::new(),
            personas: Vec::new(),
            revoked_personas: Vec::new(),
            local_keys: Vec::new(),
            chain_secrets: std::collections::HashMap::new(),
            linkages: Vec::new(),
            trust_attestations: Vec::new(),
            recovery_policy: create_policy("root-a", 2, 3600),
            recovery_session: None,
            relay_try_tls: false,
            tls_config: Arc::new(build_tls_client_config()),
            disclosure_import_cursor: 0,
            output_mode: crate::output::Mode::Human { color: false },
            storage_relationship: create_relationship("storage-1", "peer-a", "peer-b"),
            storage_manifest: publish_manifest(
                "manifest-1",
                "bafy-manifest-root-1",
                (0..12)
                    .map(|ordinal| {
                        let chunk_id = if ordinal == 0 {
                            "bafy-manifest-root-1".to_string()
                        } else {
                            format!("bafy-manifest-root-1-chunk-{ordinal:04}")
                        };
                        manifest_chunk(
                            "manifest-1",
                            chunk_id,
                            ordinal,
                            if ordinal == 0 { 4096 } else { 2048 },
                        )
                    })
                    .collect(),
                vec![manifest_device_access(
                    "device-root-a-01",
                    "wrapped-root-a-01",
                )],
            ),
            storage_ledger: ledger_delta("storage-1", 524_288),
        }
    }

    fn seed_initial_identities(&mut self) -> Result<(), ValidationError> {
        self.add_root_with_id("root-a", "Primary Root")?;
        self.add_root_with_id("root-b", "Independent Root")?;
        self.add_device_with_id("device-root-a-01", "root-a", "Primary Laptop", true)?;
        self.add_device_with_id("device-root-b-01", "root-b", "Offline Vault", true)?;
        self.add_persona_with_id(
            "persona-professional",
            "root-a",
            "Professional",
            Some(disclosure_profile_for_template(PersonaTemplate::Professional).to_string()),
            SurvivalMode::Strict,
        )?;
        self.add_persona_with_id(
            "persona-friends",
            "root-a",
            "Friends",
            Some(disclosure_profile_for_template(PersonaTemplate::Friends).to_string()),
            SurvivalMode::Strict,
        )?;
        self.add_persona_with_id(
            "persona-pseudonymous",
            "root-b",
            "Pseudonymous",
            Some(disclosure_profile_for_template(PersonaTemplate::Pseudonymous).to_string()),
            SurvivalMode::LimitedPersonaContinuity,
        )?;
        self.append_trust_attestation(
            "trust-1",
            "persona-professional",
            "persona-pseudonymous",
            "professional",
            0.80,
            None,
        )?;
        self.append_trust_attestation(
            "trust-2",
            "persona-friends",
            "persona-pseudonymous",
            "professional",
            0.74,
            Some("peer-demo".to_string()),
        )?;
        self.linkages.push(local_linkage("root-a", "root-b"));
        self.enroll_guardian_command("root-a", "guardian-alex", "Alex")?;
        self.enroll_guardian_command("root-a", "guardian-riley", "Riley")?;
        self.enroll_guardian_command("root-a", "guardian-jordan", "Jordan")?;
        Ok(())
    }

    fn persist_to_disk(&self) -> Result<(), ValidationError> {
        let Some(data_file) = &self.data_file else {
            return Ok(());
        };

        if let Some(parent) = data_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| ValidationError::new(format!("create data dir: {err}")))?;
        }

        let mut lines = Vec::new();
        lines.push(format!("peer_identity\t{}", self.peer_id));
        for linkage in &self.linkages {
            lines.push(format!(
                "linkage_asserted\t{}\t{}\t{}",
                linkage.source_root_id, linkage.target_root_id, linkage.disclosed
            ));
        }
        if let Some(session) = &self.recovery_session {
            lines.push(format!(
                "recovery_session\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                session.request_id,
                session.root_id,
                session.target_device_id,
                session.replacement_device_id.as_deref().unwrap_or(""),
                session.state,
                session.approvals.join(","),
                session.notified_devices.join(",")
            ));
        }
        for record in self
            .local_keys
            .iter()
            .filter(|record| record.owner_kind != "device-encryption")
        {
            lines.push(format!(
                "local_key\t{}\t{}\t{}\t{}\t{}",
                record.owner_kind,
                record.owner_id,
                record.key_pair.key_id,
                record.key_pair.public_key,
                record.key_pair.private_key
            ));
        }
        for (grant_id, entry) in &self.chain_secrets {
            lines.push(format!(
                "chain_secret\t{}\t{}\t{}",
                grant_id, entry.public_hex, entry.secret_hex,
            ));
        }
        let plaintext = lines.join("\n");
        let key = resolve_encryption_key()?;
        let encrypted = encrypt_state(plaintext.as_bytes(), &key)?;
        atomic_write_bytes(data_file, &encrypted)
            .map_err(|err| ValidationError::new(format!("write data file: {err}")))?;
        Ok(())
    }

    fn load_from_disk(&mut self) -> Result<(), ValidationError> {
        let Some(data_file) = &self.data_file else {
            return Err(ValidationError::new("no data file configured"));
        };

        let raw = fs::read(data_file)
            .map_err(|err| ValidationError::new(format!("read data file: {err}")))?;
        let key = resolve_encryption_key()?;
        let plaintext_bytes = decrypt_state(&raw, &key)?;
        let contents = String::from_utf8(plaintext_bytes).map_err(|err| {
            ValidationError::new(format!("decrypted state is not valid utf-8: {err}"))
        })?;

        self.linkages.clear();
        self.recovery_session = None;
        self.local_keys.clear();
        self.chain_secrets.clear();

        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split('\t').collect();
            match parts.as_slice() {
                ["peer_identity", peer_id] => {
                    self.peer_id = (*peer_id).to_string();
                }
                [
                    "linkage_asserted",
                    source_root_id,
                    target_root_id,
                    disclosed,
                ] => {
                    self.linkages.push(LinkageAssertion {
                        source_root_id: (*source_root_id).to_string(),
                        target_root_id: (*target_root_id).to_string(),
                        disclosed: *disclosed == "true",
                    });
                }
                [
                    "local_key",
                    owner_kind,
                    owner_id,
                    key_id,
                    public_key,
                    private_key,
                ] => {
                    self.register_local_key(LocalKeyRecord {
                        owner_kind: (*owner_kind).to_string(),
                        owner_id: (*owner_id).to_string(),
                        key_pair: LocalKeyPair {
                            key_id: (*key_id).to_string(),
                            algorithm: key_algorithm_from_public_key(public_key)?,
                            public_key: (*public_key).to_string(),
                            private_key: (*private_key).to_string(),
                        },
                    });
                }
                ["manifest_key", manifest_id, content_key] => {
                    self.app_runtime.store
                        .upsert_local_manifest_key(manifest_id, content_key)?;
                }
                ["chain_secret", grant_id, public_hex, secret_hex] => {
                    self.chain_secrets.insert(
                        (*grant_id).to_string(),
                        GrantChainSecret {
                            grant_id: (*grant_id).to_string(),
                            public_hex: (*public_hex).to_string(),
                            secret_hex: (*secret_hex).to_string(),
                        },
                    );
                }
                [
                    "recovery_session",
                    request_id,
                    root_id,
                    target_device_id,
                    replacement_device_id,
                    state,
                    approvals,
                    notified,
                ] => {
                    self.recovery_session = Some(RecoverySession {
                        request_id: (*request_id).to_string(),
                        root_id: (*root_id).to_string(),
                        target_device_id: (*target_device_id).to_string(),
                        replacement_device_id: if replacement_device_id.is_empty() {
                            None
                        } else {
                            Some((*replacement_device_id).to_string())
                        },
                        state: (*state).to_string(),
                        approvals: if approvals.is_empty() {
                            Vec::new()
                        } else {
                            approvals
                                .split(',')
                                .map(|value| value.to_string())
                                .collect()
                        },
                        notified_devices: if notified.is_empty() {
                            Vec::new()
                        } else {
                            notified.split(',').map(|value| value.to_string()).collect()
                        },
                    });
                }
                _ => {
                    return Err(ValidationError::new(format!(
                        "unrecognized persisted line: {line}"
                    )));
                }
            }
        }

        Ok(())
    }

    fn append_device_revoked_event(
        &mut self,
        device: &DeviceMembership,
    ) -> Result<(), ValidationError> {
        let root_signer = self.root_signer(&device.root_id)?;
        self.append_live_event(
            self.allocate_event_id("device-revoked"),
            device_revoked_event(&device.root_id, &device.device_id, "manual-revoke"),
            SignerBinding::root(&device.root_id, self.root_active_key_id(&device.root_id)?),
            &root_signer,
        )?;
        Ok(())
    }

    fn append_persona_revoked_event(&mut self, persona: &Persona) -> Result<(), ValidationError> {
        let root_signer = self.root_signer(&persona.root_id)?;
        self.append_live_event(
            self.allocate_event_id("persona-revoked"),
            persona_revoked_event(&persona.root_id, &persona.id, "manual-revoke"),
            SignerBinding::root(&persona.root_id, self.root_active_key_id(&persona.root_id)?),
            &root_signer,
        )?;
        Ok(())
    }

    fn append_live_event(
        &mut self,
        event_id: String,
        body: EventBody,
        signer_binding: SignerBinding,
        signer: &impl CryptoSigner,
    ) -> Result<(), ValidationError> {
        let event = EventEnvelope::from_body(event_id, body, Vec::new(), signer_binding, signer)?;
        self.app_runtime.store.append_with_authorizer(
            event,
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        )
    }

    fn clear_local_runtime(&mut self) {
        self.next_root_id = 3;
        self.next_persona_id = 4;
        self.next_device_id = 3;
        self.roots.clear();
        self.devices.clear();
        self.revoked_devices.clear();
        self.personas.clear();
        self.revoked_personas.clear();
        self.local_keys.clear();
        self.chain_secrets.clear();
        self.linkages.clear();
        self.recovery_session = None;
    }

    fn hydrate_identity_state(&mut self) {
        self.roots.clear();
        self.devices.clear();
        self.revoked_devices.clear();
        self.personas.clear();
        self.revoked_personas.clear();
        self.trust_attestations.clear();

        for root in self.app_runtime.store.materialized().roots_current.values() {
            self.roots.push(create_root(
                &root.root_id,
                &root.display_name,
                root.active_key.clone(),
            ));
        }

        for device in self.app_runtime.store.materialized().devices_current.values() {
            let membership = DeviceMembership {
                root_id: device.root_id.clone(),
                device_id: device.device_id.clone(),
                label: device.label.clone(),
                active: matches!(device.status, DeviceStatus::Active),
                active_key: device.active_key.clone(),
                active_encryption_key: device.active_encryption_key.clone(),
            };

            if matches!(device.status, DeviceStatus::Active) {
                self.devices.push(membership);
            } else {
                self.revoked_devices.push(membership);
            }
        }

        for persona in self.app_runtime.store.materialized().personas_current.values() {
            let identity = create_persona(
                &persona.persona_id,
                &persona.root_id,
                &persona.label,
                persona.disclosure_profile.clone(),
                persona.survival_mode,
                persona.active_key.clone(),
            );

            if matches!(persona.status, PersonaStatus::Active) {
                self.personas.push(identity);
            } else {
                self.revoked_personas.push(identity);
            }
        }

        self.trust_attestations.extend(
            self.app_runtime.store
                .materialized()
                .trust_edges_current
                .values()
                .cloned(),
        );
        self.trust_attestations
            .sort_by(|left, right| left.id.cmp(&right.id));
    }

    fn refresh_identity_counters(&mut self) {
        self.next_root_id = self
            .roots
            .iter()
            .map(|root| parse_numeric_suffix(&root.id))
            .max()
            .unwrap_or(0)
            .max(2)
            + 1;
        self.next_persona_id = self
            .personas
            .iter()
            .chain(self.revoked_personas.iter())
            .map(|persona| parse_numeric_suffix(&persona.id))
            .max()
            .unwrap_or(0)
            .max(3)
            + 1;
        self.next_device_id = self
            .devices
            .iter()
            .chain(self.revoked_devices.iter())
            .map(|device| parse_numeric_suffix(&device.device_id))
            .max()
            .unwrap_or(0)
            .max(2)
            + 1;
    }

    fn register_local_key(&mut self, record: LocalKeyRecord) {
        if self.local_keys.iter().any(|existing| {
            existing.owner_kind == record.owner_kind
                && existing.owner_id == record.owner_id
                && existing.key_pair.key_id == record.key_pair.key_id
        }) {
            return;
        }
        self.local_keys.push(record);
    }

    /// M-3: persist the `pubkey_next` secret for a grant chain's tail so
    /// later delegation / attenuation blocks can be signed. Caller passes
    /// the secret by value — `PubkeyNextKeyPair` is `Zeroize`, so the
    /// in-memory copy held by `commands.rs` is wiped once the hex
    /// strings are copied into the record.
    pub(crate) fn store_chain_secret(
        &mut self,
        grant_id: &str,
        secret: core_crypto::grant_chain::PubkeyNextKeyPair,
    ) {
        self.chain_secrets.insert(
            grant_id.to_string(),
            GrantChainSecret {
                grant_id: grant_id.to_string(),
                public_hex: secret.public_hex.clone(),
                secret_hex: secret.secret_hex.clone(),
            },
        );
    }

    /// M-3: load the persisted `pubkey_next` secret for a grant chain's
    /// tail, for appending a new block.
    #[allow(dead_code)]
    pub(crate) fn load_chain_secret(
        &self,
        grant_id: &str,
    ) -> Option<core_crypto::grant_chain::PubkeyNextKeyPair> {
        self.chain_secrets
            .get(grant_id)
            .and_then(|entry| {
                core_crypto::grant_chain::PubkeyNextKeyPair::from_hex(
                    entry.public_hex.clone(),
                    entry.secret_hex.clone(),
                )
                .ok()
            })
    }

    fn local_manifest_key(&self, manifest_id: &str) -> Result<Option<String>, ValidationError> {
        self.app_runtime.store.local_manifest_key(manifest_id)
    }

    fn ensure_local_manifest_key(&mut self, manifest_id: &str) -> Result<String, ValidationError> {
        if let Some(content_key) = self.local_manifest_key(manifest_id)? {
            return Ok(content_key);
        }
        let content_key = generate_content_key("manifest");
        self.app_runtime.store
            .upsert_local_manifest_key(manifest_id, &content_key)?;
        Ok(content_key)
    }

    fn ensure_manifest_key_loaded(&mut self, manifest_id: &str) -> Result<String, ValidationError> {
        if let Some(content_key) = self.local_manifest_key(manifest_id)? {
            return Ok(content_key);
        }

        let manifest = self
            .app_runtime.store
            .file_manifest(manifest_id)
            .or_else(|| {
                (self.storage_manifest.id == manifest_id).then(|| self.storage_manifest.clone())
            })
            .ok_or_else(|| ValidationError::new(format!("unknown file manifest: {manifest_id}")))?;

        for access in &manifest.authorized_devices {
            if let Ok(content_key) = self
                .app_runtime.store
                .unwrap_manifest_key_for_device(manifest_id, &access.device_id)
            {
                return Ok(content_key);
            }
        }

        Err(ValidationError::new(format!(
            "unable to load manifest key locally: {manifest_id}"
        )))
    }

    fn next_key_version(&self, owner_kind: &str, owner_id: &str) -> u32 {
        self.local_keys
            .iter()
            .filter(|record| record.owner_kind == owner_kind && record.owner_id == owner_id)
            .count() as u32
            + 1
    }

    fn find_local_key(
        &self,
        owner_kind: &str,
        owner_id: &str,
        key_id: &str,
    ) -> Option<&LocalKeyRecord> {
        self.local_keys.iter().find(|record| {
            record.owner_kind == owner_kind
                && record.owner_id == owner_id
                && record.key_pair.key_id == key_id
        })
    }

    fn wrap_manifest_access_for_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<core_types::ManifestDeviceAccess, ValidationError> {
        let manifest_key = self.ensure_manifest_key_loaded(manifest_id)?;
        let device = self
            .resolve_device_any(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        wrap_manifest_key_access(
            &device.device_id,
            &device.active_encryption_key.public_key,
            &manifest_key,
        )
    }

    fn manifest_key_recipient_for_device(
        &self,
        device_id: &str,
    ) -> Result<core_storage::ManifestKeyRecipient, ValidationError> {
        let device = self
            .resolve_device_any(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        Ok(manifest_key_recipient(
            &device.device_id,
            &device.active_encryption_key.public_key,
        ))
    }

    fn manifest_key_recipients_for_namespace(
        &self,
        namespace: &VaultNamespace,
    ) -> Result<Vec<core_storage::ManifestKeyRecipient>, ValidationError> {
        let device_ids = match namespace.owner_kind {
            core_types::VaultOwnerKind::Persona => {
                self.active_persona_access_device_ids(&namespace.owner_id)?
            }
            core_types::VaultOwnerKind::Root => self
                .devices
                .iter()
                .filter(|device| device.root_id == namespace.owner_id && device.active)
                .map(|device| device.device_id.clone())
                .collect(),
        };
        let mut recipients = Vec::with_capacity(device_ids.len());
        for device_id in device_ids {
            recipients.push(self.manifest_key_recipient_for_device(&device_id)?);
        }
        Ok(recipients)
    }

    #[cfg(test)]
    fn unwrap_manifest_key_for_device(
        &mut self,
        manifest_id: &str,
        device_id: &str,
    ) -> Result<String, ValidationError> {
        self.app_runtime.store
            .unwrap_manifest_key_for_device(manifest_id, device_id)
    }

    fn root_active_key_id(&self, root_id: &str) -> Result<String, ValidationError> {
        self.resolve_root(root_id)
            .map(|root| root.active_key.key_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_id}")))
    }

    fn root_signer(&self, root_id: &str) -> Result<AppSigner, ValidationError> {
        let root = self
            .resolve_root(root_id)
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_id}")))?;
        let record = self
            .find_local_key("root", &root.id, &root.active_key.key_id)
            .ok_or_else(|| ValidationError::new(format!("missing local root key: {}", root.id)))?;
        AppSigner::from_key_pair(&record.key_pair).map_err(ValidationError::new)
    }

    /// Look up the root keypair in the shape expected by
    /// `core_crypto::grant_chain::sign_block_zero`. Used when minting a
    /// new grant: block 0 is signed under the issuing persona's root key
    /// per design §SignedBlock.
    pub(crate) fn grant_chain_root_key(
        &self,
        root_id: &str,
    ) -> Result<core_crypto::grant_chain::RootKeyPair, ValidationError> {
        let root = self
            .resolve_root(root_id)
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_id}")))?;
        let record = self
            .find_local_key("root", &root.id, &root.active_key.key_id)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "missing local root key for grant chain signing: {}",
                    root.id
                ))
            })?;
        core_crypto::grant_chain::root_key_from_local_key_pair(&record.key_pair)
            .map_err(|e| ValidationError::new(format!("invalid root key for grant chain: {e}")))
    }

    fn allocate_subject_id(&self, prefix: &str) -> String {
        loop {
            let candidate = generate_random_identifier(prefix);
            if !self.subject_id_exists(&candidate) {
                return candidate;
            }
        }
    }

    fn allocate_event_id(&self, label: &str) -> String {
        loop {
            let candidate = format!("evt-{label}-{}", generate_random_identifier("id"));
            if self
                .app_runtime.store
                .current_event_type_for(&candidate)
                .is_none()
            {
                return candidate;
            }
        }
    }

    fn subject_id_exists(&self, candidate: &str) -> bool {
        self.roots.iter().any(|root| root.id == candidate)
            || self
                .devices
                .iter()
                .any(|device| device.device_id == candidate)
            || self
                .revoked_devices
                .iter()
                .any(|device| device.device_id == candidate)
            || self.personas.iter().any(|persona| persona.id == candidate)
            || self
                .revoked_personas
                .iter()
                .any(|persona| persona.id == candidate)
            || self
                .recovery_session
                .as_ref()
                .map(|session| session.request_id == candidate)
                .unwrap_or(false)
    }

    fn light_sync_context(&self) -> LightSyncContext {
        LightSyncContext {
            root_ids: self.roots.iter().map(|root| root.id.clone()).collect(),
            persona_ids: self
                .personas
                .iter()
                .map(|persona| persona.id.clone())
                .collect(),
            device_ids: self
                .devices
                .iter()
                .map(|device| device.device_id.clone())
                .collect(),
            recovery_request_ids: self
                .recovery_session
                .iter()
                .map(|session| session.request_id.clone())
                .collect(),
        }
    }

    fn next_sync_cursor_event_id(
        &self,
        current_cursor: Option<&str>,
        remote_event_ids: &[String],
        local_has_event: impl Fn(&str) -> bool,
        imported_event_ids: &[String],
    ) -> Option<String> {
        let imported: HashSet<&str> = imported_event_ids
            .iter()
            .map(|value| value.as_str())
            .collect();
        let start_index = current_cursor
            .and_then(|cursor| {
                remote_event_ids
                    .iter()
                    .position(|event_id| event_id == cursor)
            })
            .map(|index| index + 1)
            .unwrap_or(0);

        let mut next_cursor = current_cursor.map(|value| value.to_string());
        for event_id in &remote_event_ids[start_index..] {
            if local_has_event(event_id) || imported.contains(event_id.as_str()) {
                next_cursor = Some(event_id.clone());
            } else {
                break;
            }
        }
        next_cursor
    }

    fn write_compare_section<I, J>(&self, out: &mut String, label: &str, local: I, other: J)
    where
        I: IntoIterator<Item = (String, String)>,
        J: IntoIterator<Item = (String, String)>,
    {
        let local_entries: Vec<(String, String)> = local.into_iter().collect();
        let other_entries: Vec<(String, String)> = other.into_iter().collect();
        let other_ids: BTreeSet<&str> = other_entries.iter().map(|(id, _)| id.as_str()).collect();
        let local_ids: BTreeSet<&str> = local_entries.iter().map(|(id, _)| id.as_str()).collect();

        let only_local: Vec<&(String, String)> = local_entries
            .iter()
            .filter(|(id, _)| !other_ids.contains(id.as_str()))
            .collect();
        let only_other: Vec<&(String, String)> = other_entries
            .iter()
            .filter(|(id, _)| !local_ids.contains(id.as_str()))
            .collect();

        writeln!(out, "Only in local {label}: {}", only_local.len()).unwrap();
        for (id, display) in only_local {
            writeln!(out, "  - {}\t{}", id, display).unwrap();
        }
        writeln!(out, "Only in other {label}: {}", only_other.len()).unwrap();
        for (id, display) in only_other {
            writeln!(out, "  - {}\t{}", id, display).unwrap();
        }
    }

    fn state_location_label(&self) -> String {
        self.data_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "(ephemeral)".to_string())
    }

    fn current_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    fn relay_round_trip(
        &self,
        bind_address: &str,
        request_payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, ValidationError> {
        let mut stream: Box<dyn ReadWrite> = if self.relay_try_tls {
            let tcp_stream = TcpStream::connect(bind_address).map_err(|err| {
                ValidationError::new(format!("connect relay {bind_address}: {err}"))
            })?;
            // Try TLS first; fall back to plain TCP if handshake fails
            match connect_tls(tcp_stream, bind_address, &self.tls_config) {
                Ok(tls_stream) => Box::new(tls_stream),
                Err(tls_err) => {
                    eprintln!(
                        "TLS handshake failed for {bind_address}: {tls_err} — falling back to plain TCP"
                    );
                    let plain = TcpStream::connect(bind_address).map_err(|err| {
                        ValidationError::new(format!(
                            "reconnect relay {bind_address} (plain): {err}"
                        ))
                    })?;
                    Box::new(plain)
                }
            }
        } else {
            let plain = TcpStream::connect(bind_address).map_err(|err| {
                ValidationError::new(format!("connect relay {bind_address}: {err}"))
            })?;
            if let Err(e) = plain.set_read_timeout(Some(std::time::Duration::from_secs(5))) {
                eprintln!("warning: could not set read timeout on relay connection: {e}");
            }
            Box::new(plain)
        };

        write_length_prefixed_frame(&mut stream, request_payload)?;

        let first_frame = read_length_prefixed_frame(&mut stream)?;
        let mut frames = vec![first_frame];
        loop {
            match read_length_prefixed_frame(&mut stream) {
                Ok(frame) => frames.push(frame),
                Err(err) if is_connection_terminated(&err) => break,
                Err(err) => {
                    return Err(ValidationError::new(format!(
                        "read relay response from {bind_address}: {err}"
                    )));
                }
            }
        }
        Ok(frames)
    }

    fn reconcile_recovery_session_from_state(&mut self) {
        let requests = &self.app_runtime.store.materialized().recovery_requests_current;
        if requests.is_empty() {
            self.recovery_session = None;
            return;
        }

        let request_id = self
            .recovery_session
            .as_ref()
            .map(|session| session.request_id.clone())
            .or_else(|| requests.keys().last().cloned());
        let Some(request_id) = request_id else {
            self.recovery_session = None;
            return;
        };
        let Some(request) = requests.get(&request_id) else {
            self.recovery_session = None;
            return;
        };

        let replacement_device_id = self
            .app_runtime.store
            .materialized()
            .devices_current
            .get(&request.target_device_id)
            .and_then(|device| device.replacement_device_id.clone());
        let notified_devices = self
            .recovery_session
            .as_ref()
            .map(|session| session.notified_devices.clone())
            .unwrap_or_else(|| {
                self.app_runtime.store
                    .materialized()
                    .devices_current
                    .values()
                    .filter(|device| {
                        matches!(device.status, DeviceStatus::Active)
                            && device.root_id == request.root_id
                            && device.device_id != request.target_device_id
                    })
                    .map(|device| device.device_id.clone())
                    .collect()
            });

        self.recovery_session = Some(RecoverySession {
            request_id: request.request_id.clone(),
            root_id: request.root_id.clone(),
            target_device_id: request.target_device_id.clone(),
            replacement_device_id,
            state: recovery_request_status_label(&request.status).to_string(),
            approvals: request.approvals.iter().cloned().collect(),
            notified_devices,
        });
    }

    fn persona_signer(&self, persona_id: &str) -> Result<AppSigner, ValidationError> {
        let persona = self
            .resolve_persona(persona_id)
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_id}")))?;
        let active_access = self.active_persona_access_device_ids(&persona.id)?;
        if active_access.is_empty() {
            return Err(ValidationError::new(format!(
                "no active device has local signing access to persona {}",
                persona.id
            )));
        }
        let record = self
            .find_local_key("persona", &persona.id, &persona.active_key.key_id)
            .ok_or_else(|| {
                ValidationError::new(format!("missing local persona key: {}", persona.id))
            })?;
        AppSigner::from_key_pair(&record.key_pair).map_err(ValidationError::new)
    }

    fn device_signer(&self, device_id: &str) -> Result<AppSigner, ValidationError> {
        let device = self
            .resolve_device(device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
        let record = self
            .find_local_key("device", &device.device_id, &device.active_key.key_id)
            .ok_or_else(|| {
                ValidationError::new(format!("missing local device key: {}", device.device_id))
            })?;
        AppSigner::from_key_pair(&record.key_pair).map_err(ValidationError::new)
    }

    fn is_active_key_record(&self, record: &LocalKeyRecord) -> bool {
        match record.owner_kind.as_str() {
            "root" => self
                .roots
                .iter()
                .find(|root| root.id == record.owner_id)
                .map(|root| root.active_key.key_id == record.key_pair.key_id)
                .unwrap_or(false),
            "persona" => self
                .personas
                .iter()
                .find(|persona| persona.id == record.owner_id)
                .map(|persona| persona.active_key.key_id == record.key_pair.key_id)
                .unwrap_or(false),
            "device" => self
                .devices
                .iter()
                .find(|device| device.device_id == record.owner_id)
                .map(|device| device.active_key.key_id == record.key_pair.key_id)
                .unwrap_or(false),
            "device-encryption" => self
                .devices
                .iter()
                .find(|device| device.device_id == record.owner_id)
                .map(|device| device.active_encryption_key.key_id == record.key_pair.key_id)
                .unwrap_or(false),
            _ => false,
        }
    }

    fn root_security_summary(&self, root_id: &str) -> &'static str {
        let active = self
            .devices
            .iter()
            .filter(|device| device.root_id == root_id && device.active)
            .count();
        let revoked = self
            .revoked_devices
            .iter()
            .filter(|device| device.root_id == root_id)
            .count();

        if active == 0 {
            "at-risk:no-active-devices"
        } else if revoked > 0 {
            "degraded:revoked-device-history"
        } else {
            "healthy"
        }
    }

    fn reset_state(&mut self) -> Result<String, ValidationError> {
        if let Some(data_file) = &self.data_file {
            if data_file.exists() {
                fs::remove_file(data_file)
                    .map_err(|err| ValidationError::new(format!("remove data file: {err}")))?;
            }
            let sqlite_file = sqlite_path_for_local_state(data_file);
            if sqlite_file.exists() {
                fs::remove_file(&sqlite_file).map_err(|err| {
                    ValidationError::new(format!("remove sqlite state file: {err}"))
                })?;
            }
            self.app_runtime = AppRuntime::new(EventStore::open(&sqlite_file)?, LocalState::default());
        } else {
            self.app_runtime = AppRuntime::new(EventStore::default(), LocalState::default());
        }

        self.clear_local_runtime();
        if self.seed_demo {
            self.seed_initial_identities()?;
        }
        self.initialize_runtime_storage_state()?;
        self.persist_to_disk()?;
        Ok("reset state\tok\n".to_string())
    }
}

fn persona_profile_label(profile: Option<&str>) -> String {
    profile.unwrap_or("(none)").to_string()
}

fn comma_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn recovery_request_status_label(status: &RecoveryRequestStatus) -> &'static str {
    match status {
        RecoveryRequestStatus::Requested => "requested",
        RecoveryRequestStatus::Approved => "approved",
        RecoveryRequestStatus::Contested => "contested",
        RecoveryRequestStatus::Rejected => "rejected",
        RecoveryRequestStatus::Executed => "executed",
    }
}

fn relay_admission_label(admission: &RelayAdmission) -> &'static str {
    match admission {
        RelayAdmission::Accept => "accept",
        RelayAdmission::Reject { .. } => "reject",
    }
}

/// Combined Read + Write trait for relay streams (plain TCP or TLS).
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Certificate verifier that accepts any server certificate.
/// Used because Emberlink relays default to self-signed certs.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Install the rustls ring crypto provider as the process default. rustls 0.23
/// no longer auto-selects a provider from enabled features; callers must
/// install one before the first `ClientConfig::builder()` / `ServerConfig::builder()`.
/// Idempotent across parallel tests and repeat calls via `Once`.
fn ensure_rustls_provider_installed() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // Ignore `Err` — means a provider was installed by another path earlier.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build the TLS client configuration once (expensive due to verifier setup).
fn build_tls_client_config() -> rustls::ClientConfig {
    ensure_rustls_provider_installed();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth()
}

/// Attempt a TLS client connection using a pre-built config.
fn connect_tls(
    tcp_stream: TcpStream,
    bind_address: &str,
    config: &Arc<rustls::ClientConfig>,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, ValidationError> {
    let server_name = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|err| ValidationError::new(format!("invalid server name: {err}")))?;

    let conn = rustls::ClientConnection::new(Arc::clone(config), server_name)
        .map_err(|err| ValidationError::new(format!("TLS connect {bind_address}: {err}")))?;

    Ok(rustls::StreamOwned::new(conn, tcp_stream))
}

fn parse_relay_drain_header(header: &str) -> Option<(String, usize)> {
    let body = header.strip_prefix("DRAIN ")?;
    let (peer_id, count_str) = body.rsplit_once(' ')?;
    let count = count_str.parse::<usize>().ok()?;
    Some((peer_id.to_string(), count))
}

fn read_length_prefixed_frame(stream: &mut impl Read) -> Result<Vec<u8>, ValidationError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| ValidationError::new(format!("read frame length: {err}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(ValidationError::new(format!(
            "frame too large (max 16MB): {len}"
        )));
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| ValidationError::new(format!("read frame payload: {err}")))?;
    Ok(payload)
}

fn write_length_prefixed_frame(
    stream: &mut (impl Write + ?Sized),
    payload: &[u8],
) -> Result<(), ValidationError> {
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|err| ValidationError::new(format!("write frame length: {err}")))?;
    stream
        .write_all(payload)
        .map_err(|err| ValidationError::new(format!("write frame payload: {err}")))?;
    stream
        .flush()
        .map_err(|err| ValidationError::new(format!("flush frame: {err}")))
}

fn is_connection_terminated(err: &ValidationError) -> bool {
    err.message.contains("UnexpectedEof")
        || err.message.contains("failed to fill whole buffer")
        || err.message.contains("Connection reset by peer")
        || err.message.contains("Broken pipe")
        || err.message.contains("timed out")
        || err.message.contains("WouldBlock")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn inferred_template_label(profile: Option<&str>) -> &'static str {
    profile
        .and_then(persona_template_for_disclosure_profile)
        .map(persona_template_label)
        .unwrap_or("(custom)")
}

fn parse_content_visibility_arg(value: &str) -> Option<ContentVisibility> {
    match value {
        "public" => Some(ContentVisibility::Public),
        "trust-gated" | "trust_gated" => Some(ContentVisibility::TrustGated),
        "direct" => Some(ContentVisibility::Direct),
        _ => None,
    }
}

fn parse_numeric_suffix(id: &str) -> usize {
    id.rsplit('-')
        .next()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

fn key_algorithm_from_public_key(public_key: &str) -> Result<KeyAlgorithm, ValidationError> {
    if public_key.starts_with("ed25519:") {
        Ok(KeyAlgorithm::Ed25519)
    } else if public_key.starts_with("age1") {
        Ok(KeyAlgorithm::AgeX25519)
    } else {
        Err(ValidationError::new(format!(
            "unsupported public key encoding: {public_key}"
        )))
    }
}

pub fn default_data_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("emberlink")
}

fn default_data_file() -> PathBuf {
    default_data_dir().join("local-state.enc")
}

#[cfg(not(test))]
const KEYRING_SERVICE: &str = "com.emberlink";
#[cfg(not(test))]
const KEYRING_USER: &str = "local-state-key";
const ENCRYPTED_MAGIC: &[u8] = b"EMBER_ENC\x01";

fn resolve_encryption_key() -> Result<String, ValidationError> {
    if let Ok(key) = std::env::var("EMBERLINK_KEY") {
        if key.starts_with("ek1:") && key.len() == 68 {
            return Ok(key);
        }
        return Err(ValidationError::new(
            "EMBERLINK_KEY must be a valid content key (ek1: prefix, 68 chars)",
        ));
    }
    #[cfg(test)]
    {
        // In tests, use a deterministic key to avoid keychain prompts in CI
        Ok(core_crypto::derive_content_key(
            b"emberlink-test-key",
            b"test",
        ))
    }
    #[cfg(not(test))]
    match keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER) {
        Ok(entry) => match entry.get_password() {
            Ok(key) => Ok(key),
            Err(keyring::Error::NoEntry) => {
                let key = core_crypto::generate_content_key("local-state");
                entry.set_password(&key).map_err(|err| {
                    ValidationError::new(format!(
                        "failed to store encryption key in keychain: {err}"
                    ))
                })?;
                Ok(key)
            }
            Err(err) => Err(ValidationError::new(format!(
                "failed to retrieve encryption key from keychain: {err}"
            ))),
        },
        Err(err) => Err(ValidationError::new(format!(
            "failed to access keychain: {err}"
        ))),
    }
}

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

fn sqlite_path_for_local_state(local_state_file: &Path) -> PathBuf {
    let stem = local_state_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("local-state");
    local_state_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.sqlite"))
}

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

fn join_or_none(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn short_key(key: &str) -> String {
    if key.len() <= 20 {
        return key.to_string();
    }
    format!("{}...{}", &key[..12], &key[key.len() - 6..])
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use core_sync::{PortableRelaySubmission, PortableSyncBatch, relay_hint_updated_event};

    use super::*;

    static TEMP_STATE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_state_file(tag: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_STATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("emberlink-app-{tag}-{timestamp}-{counter}.tsv"))
    }

    fn temp_batch_file(tag: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_STATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("emberlink-batch-{tag}-{timestamp}-{counter}.sync"))
    }

    fn temp_relay_file(tag: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_STATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("emberlink-relay-{tag}-{timestamp}-{counter}.relay"))
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

    #[test]
    fn try_bootstrap_preserves_existing_files_on_load_error() {
        let data_file = temp_state_file("bootstrap-preserve");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        {
            let app = DemoApp::bootstrap(Some(data_file.clone()), true);
            assert!(app.app_runtime.store.event_count() > 0);
        }

        let corrupted = b"not-an-encrypted-state-file".to_vec();
        fs::write(&data_file, &corrupted).unwrap();
        let sqlite_len_before = fs::metadata(&sqlite_file).unwrap().len();

        let err = DemoApp::try_bootstrap(Some(data_file.clone()), true).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("failed to load local state"),
            "unexpected error: {err_text}"
        );
        assert_eq!(fs::read(&data_file).unwrap(), corrupted);
        assert_eq!(fs::metadata(&sqlite_file).unwrap().len(), sqlite_len_before);
        assert!(EventStore::open(&sqlite_file).unwrap().event_count() > 0);

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    fn spawn_test_relay(expected_connections: usize) -> Option<(String, thread::JoinHandle<()>)> {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("bind local test relay: {err}"),
        };
        let bind_address = listener.local_addr().expect("relay addr").to_string();
        let mailboxes: Arc<Mutex<std::collections::HashMap<String, Vec<Vec<u8>>>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let relay_mailboxes = Arc::clone(&mailboxes);

        let handle = thread::spawn(move || {
            for _ in 0..expected_connections {
                let (mut stream, _) = listener.accept().expect("accept relay client");
                let payload = read_length_prefixed_frame(&mut stream).expect("read relay frame");
                if let Ok(request) = String::from_utf8(payload.clone())
                    && let Some(peer_id) = request.strip_prefix("DRAIN ")
                {
                    let mut guard = relay_mailboxes.lock().expect("lock mailboxes");
                    let queued = guard.remove(peer_id).unwrap_or_default();
                    write_length_prefixed_frame(
                        &mut stream,
                        format!("DRAIN {peer_id} {}", queued.len()).as_bytes(),
                    )
                    .expect("write drain header");
                    for frame in queued {
                        write_length_prefixed_frame(&mut stream, &frame)
                            .expect("write queued relay frame");
                    }
                    continue;
                }

                let submission =
                    PortableRelaySubmission::decode(&payload).expect("decode relay submission");
                let target = submission
                    .target_peer_id
                    .clone()
                    .expect("target peer id in relay submission");
                relay_mailboxes
                    .lock()
                    .expect("lock mailboxes")
                    .entry(target)
                    .or_default()
                    .push(payload);
                write_length_prefixed_frame(&mut stream, b"SUBMIT ok").expect("write submit ack");
            }
        });

        Some((bind_address, handle))
    }

    fn created_id(output: &str) -> String {
        output
            .trim()
            .split('\t')
            .nth(1)
            .expect("created command id field")
            .to_string()
    }

    #[test]
    fn broker_view_hides_local_link_by_default() {
        let app = DemoApp::ephemeral();
        let output = app.render_broker(false);

        assert!(output.contains("Visible cross-root links: none"));
        assert!(output.contains("LOCAL ONLY"));
    }

    #[test]
    fn trust_screen_contains_scorecard() {
        let app = DemoApp::ephemeral();
        let output = app.render_trust();

        assert!(output.contains("Audience: public"));
        assert!(output.contains("Normalized score"));
        assert!(output.contains("Redacted summary"));
    }

    #[test]
    fn trust_command_supports_recipient_bound_view() {
        let mut app = DemoApp::ephemeral();

        let public = app.handle_command("trust");
        let recipient = app.handle_command("trust --recipient peer-demo");

        assert!(public.contains("Audience: public"));
        assert!(public.contains("Normalized score: 0.80"));
        assert!(recipient.contains("Audience: peer-demo"));
        assert!(recipient.contains("Normalized score: 0.77"));
    }

    #[test]
    fn trust_attest_command_updates_event_sourced_scorecard() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "trust attest --from persona-professional --to persona-pseudonymous --domain professional --score 0.90",
        );
        let scorecard = app.handle_command("trust");

        assert!(output.contains("attested trust\ttrust-"));
        // design: only public attestations are shown; trust-2 is recipient-bound.
        assert!(scorecard.contains("Attestations loaded: 2"));
        assert!(scorecard.contains("Normalized score: 0.85"));
    }

    #[test]
    fn trust_revoke_command_updates_public_and_recipient_views() {
        let mut app = DemoApp::ephemeral();

        let output =
            app.handle_command("trust revoke --attestation trust-1 --by persona-professional");
        let public = app.handle_command("trust");
        let recipient = app.handle_command("trust --recipient peer-demo");

        assert!(output.contains("revoked trust\ttrust-1\tpersona-professional"));
        assert!(public.contains("No derived trust score available yet"));
        assert!(recipient.contains("Normalized score: 0.74"));
    }

    #[test]
    fn storage_screen_reports_deterministic_restore_status() {
        let app = DemoApp::ephemeral();
        let output = app.render_storage();

        assert!(output.contains("Local block coverage: 12 / 12 present"));
        assert!(output.contains("Missing local blocks: none"));
        assert!(output.contains("Restore determinism: yes"));
        assert!(output.contains("Restore plan chunks: 12"));
        assert!(output.contains("Ledger delta: 524288 bytes"));
    }

    #[test]
    fn storage_restore_plan_lists_deterministic_chunks() {
        let mut app = DemoApp::ephemeral();
        let manifest = app.current_storage_manifest().unwrap();
        let output = app.handle_command("storage restore-plan");

        assert!(output.contains("Storage Restore Plan"));
        assert!(output.contains("Chunks: 12"));
        assert!(output.contains(&manifest.encrypted_root_chunk_id));
        assert!(output.contains(&manifest.chunks[11].chunk_id));
    }

    #[test]
    fn storage_restore_plan_blocks_unapproved_relationships() {
        let mut app = DemoApp::ephemeral();
        app.storage_relationship.approved = false;

        let output = app.handle_command("storage restore-plan");

        assert!(output.contains("Restore blocked"));
        assert!(output.contains("approved relationship"));
    }

    #[test]
    fn storage_gc_plan_reports_retained_and_collectable_vault_state() {
        let mut app = DemoApp::ephemeral();
        let gc_plan = app
            .app_runtime.store
            .plan_local_vault_gc(&app.seed_vault_namespace())
            .unwrap()
            .unwrap();

        let output = app.handle_command("storage gc-plan");

        assert!(output.contains("Storage GC Plan"));
        assert!(output.contains("Namespace: persona:persona-professional"));
        assert!(output.contains("Catalog manifest: vault-catalog-persona-professional"));
        assert!(output.contains("Retained revisions: vault-rev-professional-v2"));
        assert!(output.contains(
            "Retained manifests: vault-catalog-persona-professional, vault-manifest-professional-v2"
        ));
        assert!(output.contains("Collectable manifests: vault-manifest-professional-v1"));
        for chunk_id in &gc_plan.collectable_chunk_ids {
            assert!(output.contains(chunk_id));
        }
    }

    #[test]
    fn storage_gc_apply_removes_collectable_vault_state() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("storage gc-apply");
        let plan = app.handle_command("storage gc-plan");

        assert!(output.contains("Applied Storage GC"));
        assert!(output.contains("Removed manifests: vault-manifest-professional-v1"));
        assert!(output.contains("Removed chunks:"));
        assert!(plan.contains("Collectable manifests: none"));
        assert!(plan.contains("Collectable chunks: none"));
    }

    #[test]
    fn storage_audit_reports_missing_and_orphaned_local_blocks() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_file =
            std::env::temp_dir().join(format!("emberlink-app-storage-audit-{unique}.tsv"));
        let sqlite_file = sqlite_path_for_local_state(&data_file);
        let block_dir = sqlite_file.with_extension("blocks");
        let manifest = publish_manifest(
            "manifest-audit",
            "chunk-root",
            vec![
                manifest_chunk("manifest-audit", "chunk-root", 0, 1024),
                manifest_chunk("manifest-audit", "chunk-leaf", 1, 1024),
            ],
            vec![manifest_device_access("device-a", "wrapped-device-a")],
        );

        let mut app = DemoApp::with_state_file(data_file.clone());
        app.add_root_with_id("root-a", "Primary").unwrap();
        app.add_device_with_id("device-a", "root-a", "Laptop", true)
            .unwrap();
        app.app_runtime.store.upsert_file_manifest(&manifest).unwrap();
        for chunk in &manifest.chunks {
            app.app_runtime.store
                .upsert_encrypted_block(&core_storage::EncryptedBlock {
                    chunk: chunk.clone(),
                    encrypted: core_crypto::EncryptedContent {
                        nonce_hex: format!("nonce-{}", chunk.ordinal),
                        ciphertext: vec![0xee; 32],
                    },
                })
                .unwrap();
        }
        app.app_runtime.store
            .upsert_local_block(&core_state::LocalBlockRecord {
                chunk_id: "orphan-metadata".into(),
                ciphertext_bytes: 64,
            })
            .unwrap();
        let missing_chunk_path = block_dir.join("ch").join("chunk-leaf.blk");
        std::fs::remove_file(&missing_chunk_path).unwrap();
        let stray_chunk_path = block_dir.join("st").join("stray-file.blk");
        std::fs::create_dir_all(stray_chunk_path.parent().unwrap()).unwrap();
        std::fs::write(&stray_chunk_path, b"nonce-stray\nciphertext").unwrap();

        let output = app.handle_command("storage audit");

        assert!(output.contains("Storage Audit"));
        assert!(output.contains("Referenced chunks: chunk-leaf, chunk-root"));
        assert!(output.contains("Missing referenced chunks: chunk-leaf"));
        assert!(output.contains("Orphaned metadata rows: orphan-metadata"));
        assert!(output.contains("Orphaned sidecar files: stray-file"));

        let _ = std::fs::remove_file(data_file);
        let _ = std::fs::remove_file(sqlite_file);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn vault_screen_reports_seeded_record_and_template() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("vault");

        assert!(output.contains("Vault"));
        assert!(output.contains("Namespace: persona:persona-professional"));
        assert!(output.contains("Objects: 1"));
        assert!(output.contains("vault-object-professional-profile"));
        assert!(output.contains("vault-rev-professional-v2"));
        assert!(output.contains("template-professional-card"));
        assert!(output.contains("Artifacts: none"));
    }

    #[test]
    fn vault_issue_command_records_local_disclosure_artifact() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let vault = app.handle_command("vault");
        let artifacts = app.app_runtime.store.local_presentation_artifacts().unwrap();

        assert!(output.contains("issued artifact\tartifact-"));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact.recipient_id, "svc.example");
        assert!(vault.contains("Artifacts:"));
        assert!(vault.contains("svc.example"));
        assert!(vault.contains(&artifacts[0].artifact.id));
    }

    #[test]
    fn vault_issue_rejects_template_namespace_mismatch() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "vault issue --template template-professional-card --namespace root:root-a --recipient svc.example",
        );

        assert!(output.contains(
            "template template-professional-card belongs to persona:persona-professional"
        ));
    }

    #[test]
    fn vault_write_record_command_adds_custom_structured_record() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "vault write-record --namespace persona:persona-professional --object vault-object-custom-profile --schema com.example.profile/custom --app com.example.profile --json {\"display_name\":\"alice\",\"skills\":[\"rust\"]}",
        );
        let vault = app.handle_command("vault");

        assert!(output.contains("wrote record\tvault-object-custom-profile"));
        assert!(vault.contains("vault-object-custom-profile"));
        assert!(vault.contains("com.example.profile/custom@v1"));
    }

    #[test]
    fn claim_store_show_and_list_round_trip() {
        let mut app = DemoApp::ephemeral();

        let store = app.handle_command(
            "claim store --persona persona-professional --object claim-employment-1 --schema emberlink:claim:employment:1.0 --json {\"schema\":\"emberlink:claim:employment:1.0\",\"title\":\"Engineer\",\"org\":\"Acme\"}",
        );
        let list = app.handle_command("claim list --persona persona-professional");
        let show = app.handle_command(
            "claim show --persona persona-professional --object claim-employment-1",
        );

        assert!(store.contains("stored claim\tclaim-employment-1"));
        assert!(list.contains("claim-employment-1"));
        assert!(list.contains("type=self-asserted"));
        assert!(show.contains("Claim"));
        assert!(show.contains("Schema: emberlink:claim:employment:1.0"));
        assert!(show.contains("\"org\":\"Acme\""));
    }

    #[test]
    fn claim_disclose_requires_explicit_fields_and_issues_peer_artifact() {
        let mut app = DemoApp::ephemeral();
        let create = app.handle_command(
            "claim store --persona persona-professional --object claim-membership-1 --schema emberlink:claim:membership:1.0 --json {\"schema\":\"emberlink:claim:membership:1.0\",\"member_id\":\"abc123\",\"tier\":\"gold\"}",
        );
        assert!(create.contains("stored claim\tclaim-membership-1"));

        let missing_fields = app.handle_command(
            "claim disclose --persona persona-professional --object claim-membership-1 --to persona-friends",
        );
        let disclose = app.handle_command(
            "claim disclose --persona persona-professional --object claim-membership-1 --to persona-friends --field tier",
        );

        assert!(missing_fields.contains("Usage: claim disclose"));
        assert!(disclose.contains("issued artifact\tartifact-"));
        assert!(disclose.contains("sent disclosure\tmessage-"));
    }

    #[test]
    fn vault_template_add_then_issue_uses_custom_structured_record() {
        let mut app = DemoApp::ephemeral();

        let write = app.handle_command(
            "vault write-record --namespace persona:persona-professional --object vault-object-custom-card --schema com.example.profile/custom-card --app com.example.profile --json {\"display_name\":\"alice\",\"skills\":[\"rust\",\"p2p\"],\"private\":{\"note\":\"hidden\"}}",
        );
        let add_template = app.handle_command(
            "vault template add --id template-custom-card --object vault-object-custom-card --schema com.example.profile/custom-card --audience service --namespace persona:persona-professional --field display_name --field skills",
        );
        let issue = app.handle_command(
            "vault issue --namespace persona:persona-professional --template template-custom-card --recipient svc.example",
        );
        let vault = app.handle_command("vault");

        assert!(write.contains("wrote record\tvault-object-custom-card"));
        assert!(add_template.contains("added template\ttemplate-custom-card"));
        assert!(issue.contains("issued artifact\tartifact-"));
        assert!(vault.contains("template-custom-card"));
        assert!(vault.contains("svc.example"));
    }

    #[test]
    fn vault_show_record_reveals_private_source_payload() {
        let mut app = DemoApp::ephemeral();

        let output =
            app.handle_command("vault show-record --object vault-object-professional-profile");

        assert!(output.contains("Vault Record"));
        assert!(output.contains("\"private\":{\"signal\":\"local-only:v2\"}"));
        assert!(
            output.contains("\"skills\":[\"rust\",\"distributed-systems\",\"identity-brokering\"]")
        );
    }

    #[test]
    fn vault_delete_tombstones_record_and_blocks_follow_on_access() {
        let mut app = DemoApp::ephemeral();

        let delete = app.handle_command("vault delete --object vault-object-professional-profile");
        let vault = app.handle_command("vault");
        let show =
            app.handle_command("vault show-record --object vault-object-professional-profile");
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );

        assert!(delete.contains("deleted record\tvault-object-professional-profile"));
        assert!(vault.contains("Deleted objects: 1"));
        assert!(vault.contains("vault-object-professional-profile"));
        assert!(vault.contains("status=deleted"));
        assert!(show.contains("object deleted"));
        assert!(issue.contains("template source object not present"));
    }

    #[test]
    fn vault_show_artifact_reveals_projected_payload_without_private_fields() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();

        let output = app.handle_command(&format!("vault show-artifact --artifact {}", artifact_id));

        assert!(output.contains("Vault Artifact"));
        assert!(output.contains("Namespace: persona\tpersona-professional"));
        assert!(output.contains("Template: template-professional-card"));
        assert!(output.contains("\"full_name\": \"Jordan Hudson\""));
        assert!(output.contains("\"skills\""));
        assert!(output.contains("rust"));
        assert!(!output.contains("local-only:v2"));
        assert!(!output.contains("\"private\""));
    }

    #[test]
    fn vault_send_artifact_emits_peer_disclosure_message() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();

        let output = app.handle_command(&format!(
            "vault send-artifact --artifact {} --from persona-professional --to persona-pseudonymous",
            artifact_id
        ));
        let messages = app.render_messages();

        assert!(output.contains(&format!("sent disclosure artifact\t{}", artifact_id)));
        assert!(messages.contains("disclosure artifact"));
        assert!(messages.contains(&artifact_id));
        assert!(messages.contains("schema com.emberlink.profile/basic"));
        assert!(messages.contains("\"full_name\":\"Jordan Hudson\""));
        assert!(!messages.contains("local-only:v2"));
    }

    #[test]
    fn vault_send_artifact_rejects_sender_outside_artifact_namespace() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();

        let output = app.handle_command(&format!(
            "vault send-artifact --artifact {} --from persona-pseudonymous --to persona-pseudonymous",
            artifact_id
        ));

        assert!(
            output.contains(
                "persona-owned disclosure artifacts must be issued by the owning persona"
            )
        );
    }

    #[test]
    fn vault_export_artifact_writes_reusable_envelope_file() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let export_path = std::env::temp_dir().join(format!(
            "emberlink-exported-artifact-{}.txt",
            now_epoch_secs()
        ));

        let output = app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {}",
            artifact_id,
            export_path.display()
        ));
        let encoded = fs::read(&export_path).expect("read exported artifact");
        let envelope =
            core_storage::decode_presentation_artifact_envelope(&encoded).expect("decode export");

        assert!(output.contains(&format!(
            "exported disclosure artifact\t{}\t{}",
            artifact_id,
            export_path.display()
        )));
        assert_eq!(envelope.artifact.id, artifact_id);
        assert_eq!(envelope.artifact.recipient_id, "svc.example");
        assert_eq!(envelope.issuer_persona_id, "persona-professional");
        assert!(
            String::from_utf8_lossy(&envelope.payload_bytes)
                .contains("\"full_name\":\"Jordan Hudson\"")
        );
        assert!(!String::from_utf8_lossy(&envelope.payload_bytes).contains("local-only:v2"));

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn root_owned_artifact_export_requires_explicit_issuer() {
        let mut app = DemoApp::ephemeral();
        assert!(app
            .handle_command("vault write-record --namespace root:root-a --object vault-object-root-note --schema com.emberlink.root/note --app com.emberlink.root --json {\"summary\":\"root-note\"}")
            .contains("wrote record"));
        assert!(app
            .handle_command("vault template add --id template-root-note --object vault-object-root-note --schema com.emberlink.root/note --audience service --namespace root:root-a --field summary")
            .contains("added template"));
        let issue = app.handle_command(
            "vault issue --namespace root:root-a --template template-root-note --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let export_path =
            std::env::temp_dir().join(format!("emberlink-root-export-{}.txt", now_epoch_secs()));

        let blocked = app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {}",
            artifact_id,
            export_path.display()
        ));
        let explicit = app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {} --by persona-professional",
            artifact_id,
            export_path.display()
        ));
        let envelope = core_storage::decode_presentation_artifact_envelope(
            &fs::read(&export_path).expect("read exported root artifact"),
        )
        .expect("decode root export");

        assert!(blocked.contains("no default issuer for artifact"));
        assert!(explicit.contains(&format!(
            "exported disclosure artifact\t{}\t{}",
            artifact_id,
            export_path.display()
        )));
        assert_eq!(envelope.issuer_persona_id, "persona-professional");

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_inspect_export_reads_exported_artifact_file() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let export_path =
            std::env::temp_dir().join(format!("emberlink-inspect-export-{}.txt", now_epoch_secs()));
        app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {}",
            artifact_id,
            export_path.display()
        ));

        let output = app.handle_command(&format!(
            "vault inspect-export --file {}",
            export_path.display()
        ));

        assert!(output.contains("Disclosure Export"));
        assert!(output.contains(&artifact_id));
        assert!(output.contains("Issuer: persona-professional"));
        assert!(output.contains("Signature: valid"));
        assert!(output.contains("service\tsvc.example"));
        assert!(output.contains("\"full_name\":\"Jordan Hudson\""));
        assert!(!output.contains("local-only:v2"));

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_import_artifact_rejects_tampered_signature() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let export_path = std::env::temp_dir().join(format!(
            "emberlink-tampered-artifact-{}.txt",
            now_epoch_secs()
        ));
        app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {}",
            artifact_id,
            export_path.display()
        ));
        let original = fs::read_to_string(&export_path).expect("read exported artifact as text");
        let tampered = original.replace("issuer_signature_hex=", "issuer_signature_hex=0");
        fs::write(&export_path, tampered).expect("write tampered artifact");

        let output = app.handle_command(&format!(
            "vault import-artifact --file {}",
            export_path.display()
        ));

        assert!(output.contains("Failed to import disclosure artifact export"));
        assert!(output.contains("signature"));

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_import_artifact_records_received_disclosure() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-card --recipient svc.example",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let export_path = std::env::temp_dir().join(format!(
            "emberlink-imported-artifact-{}.txt",
            now_epoch_secs()
        ));
        app.handle_command(&format!(
            "vault export-artifact --artifact {} --out {}",
            artifact_id,
            export_path.display()
        ));

        let import = app.handle_command(&format!(
            "vault import-artifact --file {}",
            export_path.display()
        ));
        let received = app.handle_command("vault received");
        let detail = app.handle_command(&format!("vault show-received --artifact {}", artifact_id));

        assert!(import.contains(&format!("imported disclosure artifact\t{}", artifact_id)));
        assert!(received.contains("Received Artifacts"));
        assert!(received.contains(&artifact_id));
        assert!(received.contains("svc.example"));
        assert!(detail.contains("Received Disclosure"));
        assert!(detail.contains("Issuer: persona-professional"));
        assert!(detail.contains("\"full_name\": \"Jordan Hudson\""));
        assert!(!detail.contains("local-only:v2"));

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_import_message_records_received_disclosure() {
        let sender_file = temp_state_file("import-disclosure-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let receiver_file = temp_state_file("import-disclosure-receiver");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);

        let artifact_id = {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            let issue = sender.handle_command(
                "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
            );
            let artifact_id = issue
                .trim()
                .split('\t')
                .nth(1)
                .expect("artifact id present")
                .to_string();
            let sent = sender.handle_command(&format!(
                "vault send-artifact --artifact {} --from persona-professional --to persona-pseudonymous",
                artifact_id
            ));
            assert!(sent.contains("sent disclosure artifact"));
            artifact_id
        };

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        receiver.handle_command(&format!("sync apply --state {}", sender_file.display()));
        let disclosures = receiver.handle_command("show disclosures");
        let message_id = disclosures
            .lines()
            .find(|line| line.contains(&artifact_id))
            .and_then(|line| line.split('\t').next())
            .map(|line| line.trim_start_matches("  - ").to_string())
            .expect("message id present");

        let import =
            receiver.handle_command(&format!("vault import-message --message {}", message_id));
        let received = receiver.handle_command("vault received");

        assert!(import.contains(&format!("imported disclosure artifact\t{}", artifact_id)));
        assert!(received.contains(&artifact_id));
        assert!(received.contains("persona-professional"));
        assert!(received.contains("peer\tpersona-pseudonymous"));

        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn end_to_end_disclosure_from_record_to_received_payload() {
        // Full flow: Alice writes a structured record, creates a custom template,
        // issues an artifact, sends it to Bob, and Bob imports it and reads the payload.
        let alice_file = temp_state_file("e2e-disclosure-alice");
        let alice_sqlite = sqlite_path_for_local_state(&alice_file);
        let bob_file = temp_state_file("e2e-disclosure-bob");
        let bob_sqlite = sqlite_path_for_local_state(&bob_file);

        // Alice: create identity + write structured record + issue artifact
        let (artifact_id, alice_persona_id) = {
            let mut alice = DemoApp::bootstrap(Some(alice_file.clone()), false);

            // Create Alice's identity from scratch
            let init = alice.handle_command("init --name Alice --template professional");
            assert!(init.contains("Identity initialized"), "alice init: {init}");

            let alice_persona = alice
                .personas
                .first()
                .expect("alice has persona")
                .id
                .clone();

            // Write a custom structured record with JSON data (no spaces in values — whitespace-split CLI)
            let json = r#"{"name":"Alice_Smith","email":"alice@example.com","role":"Engineer"}"#;
            let write = alice.handle_command(&format!(
                "vault write-record --namespace persona:{} --object vault-object-alice-card --schema com.example.contact/card --app com.example.contact --json {}",
                alice_persona, json
            ));
            assert!(write.contains("wrote record"), "write: {write}");

            // Create a custom template exposing only name + role (not email)
            let add_tmpl = alice.handle_command(&format!(
                "vault template add --id template-alice-public --object vault-object-alice-card --schema com.example.contact/card --audience service --namespace persona:{} --field name --field role",
                alice_persona
            ));
            assert!(add_tmpl.contains("added template"), "add_tmpl: {add_tmpl}");

            // Issue artifact for Bob
            let issue = alice.handle_command(&format!(
                "vault issue --namespace persona:{} --template template-alice-public --recipient bob-svc",
                alice_persona
            ));
            assert!(issue.contains("issued artifact"), "issue: {issue}");
            let art_id = issue
                .trim()
                .split('\t')
                .nth(1)
                .expect("artifact id")
                .to_string();

            // Verify projected payload excludes private fields
            let show = alice.handle_command(&format!("vault show-artifact --artifact {}", art_id));
            assert!(show.contains("\"name\": \"Alice_Smith\""), "show: {show}");
            assert!(show.contains("\"role\": \"Engineer\""), "show: {show}");
            assert!(
                !show.contains("alice@example.com"),
                "email should be excluded: {show}"
            );

            (art_id, alice_persona)
        };

        // Export Alice's artifact to a file
        let export_path = std::env::temp_dir().join(format!(
            "e2e-disclosure-{}.artifact",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        {
            let mut alice = DemoApp::with_state_file(alice_file.clone());
            let export = alice.handle_command(&format!(
                "vault export-artifact --artifact {} --out {}",
                artifact_id,
                export_path.display()
            ));
            assert!(export.contains("exported"), "export: {export}");
        }

        // Bob: create identity, sync Alice's events, import the artifact
        {
            let mut bob = DemoApp::bootstrap(Some(bob_file.clone()), false);
            bob.handle_command("init --name Bob");

            // Bob imports Alice's events (so he knows Alice's personas)
            let sync = bob.handle_command(&format!("sync apply --state {}", alice_file.display()));
            assert!(!sync.contains("Failed"), "sync: {sync}");

            // Bob imports the artifact file
            let import = bob.handle_command(&format!(
                "vault import-artifact --file {}",
                export_path.display()
            ));
            assert!(import.contains("imported"), "import: {import}");

            // Bob can see the received artifact
            let received = bob.handle_command("vault received");
            assert!(received.contains(&artifact_id), "received: {received}");
            assert!(
                received.contains(&alice_persona_id),
                "received should reference alice: {received}"
            );

            // Bob can inspect the received artifact and see the projected payload
            let show =
                bob.handle_command(&format!("vault show-received --artifact {}", artifact_id));
            assert!(
                show.contains("Alice_Smith"),
                "bob should see projected name: {show}"
            );
            assert!(
                show.contains("Engineer"),
                "bob should see projected role: {show}"
            );
        }

        let _ = fs::remove_file(&alice_file);
        let _ = fs::remove_file(&alice_sqlite);
        let _ = fs::remove_file(&bob_file);
        let _ = fs::remove_file(&bob_sqlite);
        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_import_artifact_rejects_peer_disclosure_for_nonlocal_persona() {
        let sender_file = temp_state_file("peer-import-mismatch-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let receiver_file = temp_state_file("peer-import-mismatch-receiver");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);
        let export_path = std::env::temp_dir().join(format!(
            "emberlink-peer-import-mismatch-{}.artifact",
            now_epoch_secs()
        ));

        {
            let mut sender = DemoApp::ephemeral();
            let issue = sender.handle_command(
                "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
            );
            let artifact_id = issue
                .trim()
                .split('\t')
                .nth(1)
                .expect("artifact id present")
                .to_string();
            sender.handle_command(&format!(
                "vault export-artifact --artifact {} --out {}",
                artifact_id,
                export_path.display()
            ));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let output = receiver.handle_command(&format!(
            "vault import-artifact --file {}",
            export_path.display()
        ));

        assert!(output.contains("recipient persona is not local"));

        let _ = fs::remove_file(&export_path);
        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn received_disclosure_views_mark_expired_artifacts() {
        let mut app = DemoApp::ephemeral();
        let artifact = core_storage::create_presentation_artifact(
            "artifact-expired-1",
            "vault-object-professional-profile",
            "vault-rev-professional-v2",
            core_types::PresentationAudienceKind::Service,
            "svc.example",
            "com.emberlink.profile/basic",
            "manifest-expired-1",
            10,
            Some(11),
        )
        .unwrap();
        let signer = app.persona_signer("persona-professional").unwrap();
        let envelope = core_storage::sign_presentation_artifact_envelope(
            &artifact,
            br#"{"full_name":"Jordan Hudson"}"#.to_vec(),
            "persona-professional",
            "key-persona-professional-v1",
            &signer,
        )
        .unwrap();
        let export_path = std::env::temp_dir().join(format!(
            "emberlink-expired-artifact-{}.artifact",
            now_epoch_secs()
        ));
        fs::write(
            &export_path,
            core_storage::encode_presentation_artifact_envelope(&envelope),
        )
        .unwrap();

        let import = app.handle_command(&format!(
            "vault import-artifact --file {}",
            export_path.display()
        ));
        let received = app.handle_command("vault received");
        let detail = app.handle_command("vault show-received --artifact artifact-expired-1");

        assert!(import.contains("imported disclosure artifact\tartifact-expired-1"));
        assert!(received.contains("status expired"));
        assert!(detail.contains("Status: expired"));

        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn sync_apply_imports_disclosure_artifact_messages_for_viewing() {
        let sender_file = temp_state_file("sync-disclosure-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let receiver_file = temp_state_file("sync-disclosure-receiver");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            let issue = sender.handle_command(
                "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
            );
            let artifact_id = issue
                .trim()
                .split('\t')
                .nth(1)
                .expect("artifact id present")
                .to_string();
            assert!(sender
                .handle_command(&format!(
                    "vault send-artifact --artifact {} --from persona-professional --to persona-pseudonymous",
                    artifact_id
                ))
                .contains("sent disclosure artifact"));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let output =
            receiver.handle_command(&format!("sync apply --state {}", sender_file.display()));
        let messages = receiver.render_messages();

        assert!(output.contains("applied sync"));
        assert!(messages.contains("disclosure artifact"));
        assert!(messages.contains("\"full_name\":\"Jordan Hudson\""));
        assert!(!messages.contains("local-only:v2"));

        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn disclosures_view_lists_disclosure_messages_separately() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        app.handle_command(&format!(
            "vault send-artifact --artifact {} --from persona-professional --to persona-pseudonymous",
            artifact_id
        ));

        let output = app.handle_command("show disclosures");

        assert!(output.contains("Disclosures"));
        assert!(output.contains(&artifact_id));
        assert!(output.contains("schema com.emberlink.profile/basic"));
        assert!(output.contains("\"full_name\":\"Jordan Hudson\""));
    }

    #[test]
    fn disclosure_detail_view_shows_full_projected_payload() {
        let mut app = DemoApp::ephemeral();
        let issue = app.handle_command(
            "vault issue --template template-professional-peer-card --recipient persona-pseudonymous",
        );
        let artifact_id = issue
            .trim()
            .split('\t')
            .nth(1)
            .expect("artifact id present")
            .to_string();
        let sent = app.handle_command(&format!(
            "vault send-artifact --artifact {} --from persona-professional --to persona-pseudonymous",
            artifact_id
        ));
        let message_id = sent
            .trim()
            .split('\t')
            .nth(3)
            .expect("message id present")
            .to_string();

        let output = app.handle_command(&format!("show disclosure {}", message_id));

        assert!(output.contains("Disclosure"));
        assert!(output.contains(&artifact_id));
        assert!(output.contains("Issuer: persona-professional"));
        assert!(output.contains("\"full_name\": \"Jordan Hudson\""));
        assert!(output.contains("\"headline\": \"Local-first identity broker\""));
        assert!(!output.contains("local-only:v2"));
    }

    #[test]
    fn seeded_storage_manifest_key_is_wrapped_to_authorized_device() {
        let mut app = DemoApp::ephemeral();
        let manifest = app.current_storage_manifest().unwrap();
        let manifest_key = app.local_manifest_key(&manifest.id).unwrap().unwrap();
        let access = manifest
            .authorized_devices
            .iter()
            .find(|access| access.device_id == "device-root-a-01")
            .unwrap();

        assert_ne!(access.wrapped_manifest_key_hex, manifest_key);
        assert_eq!(
            app.unwrap_manifest_key_for_device(&manifest.id, "device-root-a-01")
                .unwrap(),
            manifest_key
        );
    }

    #[test]
    fn storage_open_reads_seeded_payload_via_runtime_restore_device() {
        let mut app = DemoApp::ephemeral();
        let manifest = app.current_storage_manifest().unwrap();

        let output = app.handle_command("storage open");

        assert!(output.contains("Storage Open"));
        assert!(output.contains(&format!("Manifest: {}", manifest.id)));
        assert!(output.contains("Device: device-root-a-01"));
        assert!(output.contains("Chunks: 12"));
        assert!(output.contains(&format!("emberlink:manifest:{}:root", manifest.id)));
    }

    #[test]
    fn recovery_execution_without_replacement_revokes_storage_restore_access() {
        let mut app = DemoApp::ephemeral();

        app.handle_command("recovery request --root root-a --device device-root-a-01");
        app.handle_command("recovery approve --guardian guardian-alex");
        app.handle_command("recovery approve --guardian guardian-riley");

        let execute = app.handle_command("recovery execute");
        let storage = app.render_storage();
        let restore_plan = app.handle_command("storage restore-plan");

        assert!(execute.contains("executed recovery"));
        assert!(storage.contains("Authorized restore devices: none"));
        assert!(storage.contains("Restore determinism: blocked"));
        assert!(restore_plan.contains("Restore blocked"));
        assert!(restore_plan.contains("no active authorized restore device"));
    }

    #[test]
    fn sync_screen_reports_opaque_relay_and_local_policy() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command("sync");

        assert!(output.contains("Sync And Relay"));
        assert!(output.contains("Opaque bytes: 5"));
        assert!(output.contains("Payload semantics: hidden from relay"));
        assert!(output.contains("Admission: accept"));
    }

    #[test]
    fn sync_relay_check_respects_thresholds() {
        let mut app = DemoApp::ephemeral();

        let accepted = app.handle_command(
            "sync relay-check --mode trust-gated --persona persona-pseudonymous --threshold 0.75",
        );
        let rejected = app.handle_command(
            "sync relay-check --mode trust-gated --persona persona-pseudonymous --threshold 0.81",
        );

        assert!(accepted.contains("Admission: accept"));
        assert!(rejected.contains("Admission: reject"));
        assert!(rejected.contains("does not meet threshold"));
    }

    #[test]
    fn sync_endpoint_set_and_rotate_materialize_local_descriptor() {
        let mut app = DemoApp::ephemeral();
        let peer_id = app.current_peer_id();

        let updated = app.handle_command(
            "sync endpoint set --device device-root-a-01 --hint relay://127.0.0.1:9100/mailbox/local",
        );
        let rotated = app.handle_command(
            "sync endpoint rotate --device device-root-a-01 --hint relay://127.0.0.1:9200/mailbox/local",
        );
        let sync_output = app.render_sync();

        assert!(updated.contains(&format!("updated endpoint\t{}", peer_id)));
        assert!(updated.contains("relay://127.0.0.1:9100/mailbox/local"));
        assert!(rotated.contains(&format!("rotated endpoint\t{}", peer_id)));
        assert!(rotated.contains("relay://127.0.0.1:9200/mailbox/local"));
        assert!(sync_output.contains("Local endpoint: relay://127.0.0.1:9200/mailbox/local"));
        assert!(sync_output.contains(&format!(
            "  - {}\trelay://127.0.0.1:9200/mailbox/local\tvia device-root-a-01",
            peer_id
        )));
    }

    #[test]
    fn sync_endpoint_set_accepts_bind_shorthand_for_local_peer() {
        let mut app = DemoApp::ephemeral();
        let peer_id = app.current_peer_id();

        let output =
            app.handle_command("sync endpoint set --device device-root-a-01 --bind 127.0.0.1:9100");

        assert!(output.contains(&format!("updated endpoint\t{}", peer_id)));
        assert!(output.contains(&format!("relay://127.0.0.1:9100/mailbox/{}", peer_id)));
    }

    #[test]
    fn state_screen_shows_live_replay_output() {
        let app = DemoApp::ephemeral();
        let output = app.render_state();

        assert!(output.contains("State location: (ephemeral)"));
        assert!(output.contains("Peer id: peer-"));
        assert!(output.contains("Appended events: 15"));
        assert!(output.contains("Devices in memory: 2"));
        assert!(output.contains("RootCreated"));
        assert!(output.contains("PersonaCreated"));
        assert!(output.contains("StorageManifestPublished"));
    }

    #[test]
    fn state_screen_reports_named_client_state_paths() {
        let data_file = temp_state_file("client-a");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        let app = DemoApp::with_state_file(data_file.clone());
        let output = app.render_state();

        assert!(output.contains(&format!("State location: {}", data_file.display())));
        assert!(output.contains(&format!("Peer id: {}", app.current_peer_id())));
        assert!(output.contains(&format!("Local state file: {}", data_file.display())));
        assert!(output.contains(&format!("Event store file: {}", sqlite_file.display())));

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn named_client_peer_id_persists_across_reopen_without_events() {
        let data_file = temp_state_file("client-peer-id");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        let first_peer_id = DemoApp::with_state_file(data_file.clone()).current_peer_id();
        let second_peer_id = DemoApp::with_state_file(data_file.clone()).current_peer_id();

        assert_eq!(first_peer_id, second_peer_id);

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn inspect_command_reads_other_client_state_without_seeding() {
        let data_file = temp_state_file("client-b");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        {
            let mut app = DemoApp::with_state_file(data_file.clone());
            let create = app.handle_command("root create --name Research Root");
            assert!(create.contains("created root\troot-"));
        }

        let mut inspector = DemoApp::ephemeral();
        let output = inspector.handle_command(&format!(
            "inspect --state {} --screen broker",
            data_file.display()
        ));

        assert!(output.contains("Research Root"));
        assert!(output.contains("Root: Research Root (root-"));

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn create_root_command_updates_broker_and_state() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("root create --name Research Root");

        assert!(output.contains("created root\troot-"));
        assert!(app.render_broker(false).contains("Research Root"));
        assert!(app.render_state().contains("Appended events: 16"));
    }

    #[test]
    fn create_persona_command_requires_existing_root_and_updates_state() {
        let mut app = DemoApp::ephemeral();

        let output =
            app.handle_command("persona create --root root-a --label Ops --template professional");

        assert!(output.contains("created persona\tpersona-"));
        assert!(output.contains("\troot-a\tOps"));
        assert!(app.render_broker(false).contains("Ops"));
        assert!(app.render_state().contains("Appended events: 16"));
    }

    #[test]
    fn create_persona_command_resolves_root_by_display_name() {
        let mut app = DemoApp::ephemeral();
        app.handle_command("root create --name alice");

        let output = app
            .handle_command("persona create --root alice --label alice@work --template professional");

        assert!(output.contains("created persona"));
        assert!(app.render_personas().contains("alice@work"));
    }

    #[test]
    fn create_persona_command_accepts_explicit_disclosure_profile() {
        let mut app = DemoApp::ephemeral();

        let output = app
            .handle_command("persona create --root root-a --label Alias --profile persona.custom");

        assert!(output.contains("persona.custom"));
        assert!(
            app.render_persona("Alias")
                .contains("disclosure profile:\tpersona.custom")
        );
        assert!(
            app.render_persona("Alias")
                .contains("client template:\t(custom)")
        );
    }

    #[test]
    fn message_send_command_appends_message_event() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef",
        );

        assert!(output.contains("sent message\tmessage-"));
        assert!(output.contains("\tpersona-professional\tpersona-pseudonymous"));
        assert!(app.render_state().contains("Appended events: 16"));
        assert!(app.render_state().contains("Message events: 1"));
        assert!(
            app.render_state()
                .contains("Latest event:\tevt-message-sent-")
        );
        assert!(app.render_state().contains("MessageSent"));
    }

    #[test]
    fn content_publish_command_appends_content_event() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated",
        );

        assert!(output.contains("published content\tcontent-"));
        assert!(output.contains("\tpersona-professional\tpost\ttrust_gated"));
        assert!(app.render_state().contains("Appended events: 16"));
        assert!(app.render_state().contains("Content events: 1"));
        assert!(
            app.render_state()
                .contains("Latest event:\tevt-content-published-")
        );
        assert!(app.render_state().contains("ContentPublished"));
    }

    #[test]
    fn message_and_content_views_list_recent_payload_events() {
        let mut app = DemoApp::ephemeral();

        app.handle_command(
            "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef",
        );
        app.handle_command(
            "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated",
        );

        let messages = app.handle_command("show messages");
        let content = app.handle_command("show content");

        assert!(messages.contains("Messages"));
        assert!(messages.contains("from persona-professional (Professional)"));
        assert!(messages.contains("to persona-pseudonymous (Pseudonymous)"));
        assert!(messages.contains("ciphertext 4 bytes"));
        assert!(content.contains("Content"));
        assert!(content.contains("author persona-professional (Professional)"));
        assert!(content.contains("type post"));
        assert!(content.contains("visibility trust_gated"));
        assert!(content.contains("payload 4 bytes"));
    }

    #[test]
    fn inspect_command_supports_message_and_content_screens() {
        let data_file = temp_state_file("inspect-payload");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        {
            let mut app = DemoApp::bootstrap(Some(data_file.clone()), true);
            app.handle_command(
                "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef",
            );
            app.handle_command(
                "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated",
            );
        }

        let mut inspector = DemoApp::ephemeral();
        let messages = inspector.handle_command(&format!(
            "inspect --state {} --screen messages",
            data_file.display()
        ));
        let content = inspector.handle_command(&format!(
            "inspect --state {} --screen content",
            data_file.display()
        ));

        assert!(messages.contains("Messages"));
        assert!(messages.contains("persona-professional (Professional)"));
        assert!(content.contains("Content"));
        assert!(content.contains("type post"));

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn sync_apply_imports_remote_message_and_content_for_viewing() {
        let sender_file = temp_state_file("payload-sync-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let receiver_file = temp_state_file("payload-sync-receiver");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            assert!(sender
                .handle_command(
                    "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated"
                )
                .contains("published content"));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let applied =
            receiver.handle_command(&format!("sync apply --state {}", sender_file.display()));
        let messages = receiver.handle_command("show messages");
        let content = receiver.handle_command("show content");

        assert!(applied.contains("applied sync\tsync-batch-"));
        assert!(messages.contains("persona-professional (Professional)"));
        assert!(messages.contains("to persona-pseudonymous (Pseudonymous)"));
        assert!(content.contains("author persona-professional (Professional)"));
        assert!(content.contains("visibility trust_gated"));

        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
    }

    #[test]
    fn revoke_persona_command_removes_persona_and_tracks_revocation() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("persona revoke --persona persona-friends");

        assert!(output.contains("revoked persona\tpersona-friends\tFriends"));
        assert!(app.render_persona("persona-friends").contains("revoked"));
        assert!(app.render_personas().contains("Revoked"));
        assert!(app.render_state().contains("Revoked personas: 1"));
    }

    #[test]
    fn show_root_and_persona_are_high_signal() {
        let app = DemoApp::ephemeral();

        assert!(app.render_root("root-a").contains("Primary Root"));
        assert!(
            app.render_persona("persona-professional")
                .contains("Professional")
        );
        assert!(
            app.render_persona("persona-professional")
                .contains("client template:\tprofessional")
        );
        assert!(
            app.render_persona("persona-professional")
                .contains("device-root-a-01\tPrimary Laptop\tactive")
        );
    }

    #[test]
    fn create_device_command_updates_root_and_key_views() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("device add --root root-a --label tablet");
        let device_id = created_id(&output);

        assert!(output.contains("created device\tdevice-"));
        assert!(output.contains("\troot-a\ttablet"));
        assert!(
            app.render_devices()
                .contains(&format!("{device_id}\troot-a\ttablet\ttrue"))
        );
        assert!(app.render_root("root-a").contains("devices:\t2"));
        assert!(app.render_keys().contains(&format!("device\t{device_id}")));
    }

    #[test]
    fn device_encryption_keys_persist_in_runtime_not_shell_snapshot() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_file =
            std::env::temp_dir().join(format!("emberlink-app-device-encryption-key-{unique}.tsv"));
        let sqlite_file = sqlite_path_for_local_state(&data_file);
        let block_dir = sqlite_file.with_extension("blocks");

        {
            let mut app = DemoApp::with_state_file(data_file.clone());
            app.add_root_with_id("root-a", "Primary").unwrap();
            app.add_device_with_id("device-a", "root-a", "Laptop", true)
                .unwrap();

            // State file is encrypted — verify raw bytes don't contain plaintext keys
            let raw = std::fs::read(&data_file).unwrap();
            assert!(
                raw.starts_with(b"EMBER_ENC\x01"),
                "file should be encrypted"
            );
            let raw_str = String::from_utf8_lossy(&raw);
            assert!(!raw_str.contains("device-encryption"));
            assert!(
                app.app_runtime.store
                    .local_device_encryption_key_pair("device-a")
                    .unwrap()
                    .is_some()
            );
        }

        let reopened = DemoApp::open_existing(data_file.clone()).unwrap();
        let key_pair = reopened
            .app_runtime.store
            .local_device_encryption_key_pair("device-a")
            .unwrap()
            .unwrap();
        let device = reopened.resolve_device("device-a").unwrap();

        assert_eq!(key_pair.key_id, device.active_encryption_key.key_id);
        assert_eq!(key_pair.public_key, device.active_encryption_key.public_key);

        let _ = std::fs::remove_file(data_file);
        let _ = std::fs::remove_file(sqlite_file);
        let _ = std::fs::remove_dir_all(block_dir);
    }

    #[test]
    fn revoke_device_degrades_root_security_summary() {
        let mut app = DemoApp::ephemeral();

        app.handle_command("device revoke --device device-root-a-01");

        assert!(
            app.render_root("root-a")
                .contains("security:\tat-risk:no-active-devices")
        );
        assert!(app.render_state().contains("Revoked devices: 1"));
    }

    #[test]
    fn rotate_device_key_updates_active_key_material() {
        let mut app = DemoApp::ephemeral();
        let before = app.render_device("device-root-a-01");

        let output = app.handle_command("device rotate-key --device device-root-a-01");
        let after = app.render_device("device-root-a-01");

        assert!(output.contains("rotated device key\tdevice-root-a-01"));
        assert_ne!(before, after);
        assert!(after.contains("-v2"));
    }

    #[test]
    fn rotate_device_encryption_key_rewraps_storage_access() {
        let mut app = DemoApp::ephemeral();
        let manifest = app.current_storage_manifest().unwrap();
        let manifest_key = app.local_manifest_key(&manifest.id).unwrap().unwrap();
        let before_access = manifest
            .authorized_devices
            .iter()
            .find(|access| access.device_id == "device-root-a-01")
            .unwrap()
            .wrapped_manifest_key_hex
            .clone();

        let output = app.handle_command("device rotate-encryption-key --device device-root-a-01");
        let after_manifest = app.current_storage_manifest().unwrap();
        let after_access = after_manifest
            .authorized_devices
            .iter()
            .find(|access| access.device_id == "device-root-a-01")
            .unwrap()
            .wrapped_manifest_key_hex
            .clone();

        assert!(output.contains("rotated device encryption key\tdevice-root-a-01"));
        assert_ne!(before_access, after_access);
        assert!(app.render_device("device-root-a-01").contains("-enc-v2"));
        assert_eq!(
            app.unwrap_manifest_key_for_device(&after_manifest.id, "device-root-a-01")
                .unwrap(),
            manifest_key
        );
    }

    #[test]
    fn rotate_root_and_persona_keys_update_identity_views() {
        let mut app = DemoApp::ephemeral();

        let root_output = app.handle_command("root rotate-key --root root-a");
        let persona_output =
            app.handle_command("persona rotate-key --persona persona-professional");

        assert!(root_output.contains("rotated root key\troot-a"));
        assert!(persona_output.contains("rotated persona key\tpersona-professional"));
        assert!(app.render_root("root-a").contains("-v2"));
        assert!(app.render_persona("persona-professional").contains("-v2"));
    }

    #[test]
    fn persona_device_access_is_explicit_and_gates_persona_signing() {
        let mut app = DemoApp::ephemeral();

        let revoke = app.handle_command(
            "persona revoke-device --persona persona-professional --device device-root-a-01",
        );
        assert!(revoke.contains("revoked persona device access"));
        assert!(
            app.render_persona("persona-professional")
                .contains("  - none")
        );

        let blocked = app.handle_command("persona rotate-key --persona persona-professional");
        assert!(blocked.contains("no active device has local signing access"));

        let create_device = app.handle_command("device add --root root-a --label tablet");
        let device_id = created_id(&create_device);
        assert!(create_device.contains("created device\tdevice-"));

        let grant = app
            .handle_command("persona grant-device --persona persona-professional --device tablet");
        assert!(grant.contains(&format!(
            "granted persona device access\tpersona-professional\t{device_id}"
        )));
        assert!(
            app.render_device("tablet")
                .contains("persona-professional\tProfessional\tactive")
        );

        let rotated = app.handle_command("persona rotate-key --persona persona-professional");
        assert!(rotated.contains("rotated persona key\tpersona-professional"));
    }

    #[test]
    fn grant_device_rewraps_existing_vault_manifests() {
        let mut app = DemoApp::ephemeral();

        // Write a vault record under persona-professional (creates a manifest)
        let write = app.handle_command(
            "vault write-record --namespace persona:persona-professional --object vault-obj-test --schema com.test/cred --app com.test --json {\"name\":\"Alice\"}",
        );
        assert!(write.contains("wrote record"), "write failed: {write}");

        // Add a new device under root-a
        let create_device = app.handle_command("device add --root root-a --label tablet");
        assert!(create_device.contains("created device\tdevice-"));
        let device_id = created_id(&create_device);

        // Grant persona-professional access to the new device — should rewrap vault keys
        let grant = app
            .handle_command("persona grant-device --persona persona-professional --device tablet");
        assert!(grant.contains("granted persona device access"));
        assert!(
            grant.contains("re-wrapped"),
            "expected re-wrap message: {grant}"
        );
        assert!(
            grant.contains("vault manifest key(s)"),
            "expected manifest key message: {grant}"
        );

        // Verify the new device can unwrap the manifest key
        // Get the manifest id from the vault
        let namespaces = app.app_runtime.store.local_vault_namespaces().unwrap();
        let persona_ns = namespaces
            .iter()
            .find(|ns| ns.owner_id == "persona-professional")
            .expect("expected persona namespace");
        let manifests = app
            .app_runtime.store
            .local_vault_manifests_with_keys(persona_ns)
            .unwrap();
        assert!(!manifests.is_empty(), "expected at least one manifest");

        for (manifest, _content_key) in &manifests {
            let has_new_device = manifest
                .authorized_devices
                .iter()
                .any(|a| a.device_id == device_id);
            assert!(
                has_new_device,
                "manifest {} missing device {}",
                manifest.id, device_id
            );
        }

        // Verify the new device can actually unwrap the key via the wrapped access entry
        let enc_key_pair = app
            .app_runtime.store
            .local_device_encryption_key_pair(&device_id)
            .unwrap()
            .expect("missing local encryption key pair");
        for (manifest, expected_key) in &manifests {
            let access = manifest
                .authorized_devices
                .iter()
                .find(|a| a.device_id == device_id)
                .expect("missing device access entry");
            let unwrapped =
                core_storage::unwrap_manifest_key_access(access, &enc_key_pair.private_key)
                    .unwrap_or_else(|err| {
                        panic!(
                            "failed to unwrap key for {} on {}: {}",
                            manifest.id, device_id, err
                        )
                    });
            assert_eq!(
                &unwrapped, expected_key,
                "unwrapped key doesn't match for manifest {}",
                manifest.id
            );
        }
    }

    #[test]
    fn key_listing_marks_active_and_history_records() {
        let mut app = DemoApp::ephemeral();

        app.handle_command("device rotate-key --device device-root-a-01");
        let keys = app.render_keys();

        assert!(keys.contains("device\tdevice-root-a-01\tkey-device-device-root-a-01-v1-"));
        assert!(keys.contains("\thistory"));
        assert!(keys.contains("key-device-device-root-a-01-v2-"));
        assert!(keys.contains("\tactive"));
    }

    #[test]
    fn recovery_request_notifies_active_devices_and_executes_freeze() {
        let mut app = DemoApp::ephemeral();

        let create = app.handle_command("recovery request --root root-a --device device-root-a-01");
        let approve1 = app.handle_command("recovery approve --guardian guardian-alex");
        let approve2 = app.handle_command("recovery approve --guardian guardian-riley");
        let execute = app.handle_command("recovery execute");

        assert!(create.contains("created recovery request"));
        assert!(approve1.contains("approved recovery"));
        assert!(approve2.contains("2/2"));
        assert!(execute.contains("executed recovery"));
        assert!(app.render_recovery().contains("State: executed"));
        assert!(app.render_state().contains("Revoked devices: 1"));
        assert!(app.render_device("device-root-a-01").contains("revoked"));
    }

    #[test]
    fn recovery_execution_with_replacement_restores_persona_access() {
        let mut app = DemoApp::ephemeral();

        let create_device = app.handle_command("device add --root root-a --label replacement");
        let replacement_device_id = created_id(&create_device);
        assert!(create_device.contains("created device\tdevice-"));
        assert!(app.render_device("replacement").contains("  - none"));

        let create = app.handle_command("recovery request --root root-a --device device-root-a-01");
        let approve1 = app.handle_command("recovery approve --guardian guardian-alex");
        let approve2 = app.handle_command("recovery approve --guardian guardian-riley");
        let execute = app.handle_command("recovery execute --replacement-device replacement");

        assert!(create.contains("created recovery request"));
        assert!(approve1.contains("approved recovery"));
        assert!(approve2.contains("2/2"));
        assert!(execute.contains("executed recovery"));
        assert!(execute.contains(&format!("restored-to {replacement_device_id}")));
        assert!(
            app.render_recovery()
                .contains(&format!("Replacement device: {replacement_device_id}"))
        );
        assert!(
            app.render_persona("persona-professional")
                .contains(&format!("{replacement_device_id}\treplacement\tactive"))
        );
        assert!(
            !app.render_persona("persona-professional")
                .contains("device-root-a-01")
        );
        assert!(
            app.render_device("replacement")
                .contains("persona-professional\tProfessional\tactive")
        );
        assert!(app.render_device("device-root-a-01").contains("revoked"));
    }

    #[test]
    fn recovery_execution_with_replacement_restores_storage_access() {
        let mut app = DemoApp::ephemeral();

        let create_device = app.handle_command("device add --root root-a --label replacement");
        let replacement_device_id = created_id(&create_device);

        app.handle_command("recovery request --root root-a --device device-root-a-01");
        app.handle_command("recovery approve --guardian guardian-alex");
        app.handle_command("recovery approve --guardian guardian-riley");
        let execute = app.handle_command("recovery execute --replacement-device replacement");
        let storage = app.render_storage();
        let restore_plan = app.handle_command("storage restore-plan");
        let manifest = app.current_storage_manifest().unwrap();
        let manifest_key = app.local_manifest_key(&manifest.id).unwrap().unwrap();

        assert!(execute.contains("executed recovery"));
        assert!(execute.contains(&format!("restored-to {replacement_device_id}")));
        assert!(storage.contains(&format!("  - {}\tactive", replacement_device_id)));
        assert!(!storage.contains("  - device-root-a-01\t"));
        assert!(storage.contains(&format!("Restore device: {}", replacement_device_id)));
        assert!(restore_plan.contains(&format!("Restore device: {}", replacement_device_id)));
        assert!(restore_plan.contains("Chunks: 12"));
        assert_eq!(
            app.unwrap_manifest_key_for_device(&manifest.id, &replacement_device_id)
                .unwrap(),
            manifest_key
        );
        assert!(
            app.unwrap_manifest_key_for_device(&manifest.id, "device-root-a-01")
                .is_err()
        );
    }

    #[test]
    fn recovery_execution_with_replacement_restores_local_vault_manifest_access() {
        let mut app = DemoApp::ephemeral();

        let create_device = app.handle_command("device add --root root-a --label replacement");
        let replacement_device_id = created_id(&create_device);

        app.handle_command("recovery request --root root-a --device device-root-a-01");
        app.handle_command("recovery approve --guardian guardian-alex");
        app.handle_command("recovery approve --guardian guardian-riley");
        app.handle_command("recovery execute --replacement-device replacement");

        for manifest_id in [
            "vault-catalog-persona-professional",
            "vault-manifest-professional-v1",
            "vault-manifest-professional-v2",
        ] {
            let manifest = app
                .app_runtime.store
                .local_file_manifest(manifest_id)
                .unwrap()
                .unwrap();
            assert_eq!(manifest.authorized_devices.len(), 1);
            assert_eq!(
                manifest.authorized_devices[0].device_id,
                replacement_device_id
            );
        }
    }

    #[test]
    fn storage_open_after_recovery_uses_replacement_device_and_blocks_old_device() {
        let mut app = DemoApp::ephemeral();
        let manifest = app.current_storage_manifest().unwrap();

        let create_device = app.handle_command("device add --root root-a --label replacement");
        let replacement_device_id = created_id(&create_device);
        app.handle_command("recovery request --root root-a --device device-root-a-01");
        app.handle_command("recovery approve --guardian guardian-alex");
        app.handle_command("recovery approve --guardian guardian-riley");
        app.handle_command("recovery execute --replacement-device replacement");

        let opened = app.handle_command("storage open");
        let blocked = app.handle_command("storage open --device device-root-a-01");

        assert!(opened.contains(&format!("Device: {}", replacement_device_id)));
        assert!(opened.contains(&format!("emberlink:manifest:{}:root", manifest.id)));
        assert!(blocked.contains("Storage open blocked"));
        assert!(blocked.contains("unknown active device: device-root-a-01"));
    }

    #[test]
    fn recovery_contest_blocks_execution_until_rejected() {
        let mut app = DemoApp::ephemeral();

        let create = app.handle_command("recovery request --root root-a --device device-root-a-01");
        let approve1 = app.handle_command("recovery approve --guardian guardian-alex");
        let approve2 = app.handle_command("recovery approve --guardian guardian-riley");
        let contest = app.handle_command(
            "recovery contest --guardian guardian-jordan --reason improper-approval",
        );
        let blocked = app.handle_command("recovery execute");
        let contested_view = app.render_recovery();
        let reject = app.handle_command("recovery reject --reason contest-upheld");
        let rejected_execute = app.handle_command("recovery execute");
        let rejected_view = app.render_recovery();

        assert!(create.contains("created recovery request"));
        assert!(approve1.contains("approved recovery"));
        assert!(approve2.contains("2/2"));
        assert!(contest.contains("contested recovery"));
        assert!(contest.contains("guardian-jordan"));
        assert!(
            blocked.contains("cooldown") || blocked.contains("must be approved"),
            "expected contest to block execution, got: {blocked}"
        );
        assert!(contested_view.contains("State: contested"));
        assert!(
            contested_view.contains("Cooldown until:"),
            "expected cooldown timestamp: {contested_view}"
        );
        assert!(contested_view.contains("Contest reason: improper-approval"));
        assert!(reject.contains("rejected recovery"));
        assert!(rejected_view.contains("State: rejected"));
        assert!(rejected_view.contains("Cooldown until: none"));
        assert!(rejected_view.contains("Rejection reason: contest-upheld"));
        assert!(rejected_execute.contains("must be approved"));
    }

    #[test]
    fn contested_recovery_persists_across_restart() {
        let data_file = temp_state_file("recovery-contest");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        {
            let mut app = DemoApp::bootstrap(Some(data_file.clone()), true);
            app.handle_command("recovery request --root root-a --device device-root-a-01");
            app.handle_command("recovery approve --guardian guardian-alex");
            app.handle_command("recovery approve --guardian guardian-riley");
            app.handle_command(
                "recovery contest --guardian guardian-jordan --reason improper-approval",
            );
        }

        let reopened = DemoApp::bootstrap(Some(data_file.clone()), true);
        let recovery = reopened.render_recovery();

        assert!(recovery.contains("State: contested"));
        assert!(
            recovery.contains("Cooldown until:"),
            "expected cooldown timestamp: {recovery}"
        );
        assert!(recovery.contains("Contest reason: improper-approval"));

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn separately_created_clients_do_not_reuse_new_root_ids() {
        let data_file_a = temp_state_file("client-ids-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("client-ids-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        let create_a = {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            app.handle_command("root create --name Research Root")
        };
        let create_b = {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            app.handle_command("root create --name Research Root")
        };

        let root_a = created_id(&create_a);
        let root_b = created_id(&create_b);

        assert!(root_a.starts_with("root-"));
        assert!(root_b.starts_with("root-"));
        assert_ne!(root_a, root_b);

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn compare_command_reports_divergence_between_named_clients() {
        let data_file_a = temp_state_file("compare-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("compare-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            let output = app.handle_command("root create --name Alpha Root");
            assert!(output.contains("created root\troot-"));
        }
        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let output = app.handle_command("root create --name Beta Root");
            assert!(output.contains("created root\troot-"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let output = app.handle_command(&format!("compare --state {}", data_file_b.display()));

        assert!(output.contains("Client Compare"));
        assert!(output.contains("Local events: 1"));
        assert!(output.contains("Other events: 1"));
        assert!(output.contains("Shared events: 0"));
        assert!(output.contains("Missing locally: 1"));
        assert!(output.contains("Missing in other: 1"));
        assert!(output.contains("Only in local roots: 1"));
        assert!(output.contains("Alpha Root"));
        assert!(output.contains("Only in other roots: 1"));
        assert!(output.contains("Beta Root"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn compare_command_reports_message_and_content_divergence() {
        let receiver_file = temp_state_file("compare-activity-a");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);
        let sender_file = temp_state_file("compare-activity-b");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            assert!(sender
                .handle_command(
                    "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated"
                )
                .contains("published content"));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let output = receiver.handle_command(&format!("compare --state {}", sender_file.display()));

        assert!(output.contains("Only in other messages: 1"));
        assert!(output.contains("message-"));
        assert!(output.contains("Only in other content: 1"));
        assert!(output.contains("content-"));

        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_preview_lists_missing_event_ids_between_named_clients() {
        let data_file_a = temp_state_file("sync-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            app.handle_command("root create --name Alpha Root");
        }
        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            app.handle_command("root create --name Beta Root");
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let output = app.handle_command(&format!("sync preview --state {}", data_file_b.display()));

        assert!(output.contains("Sync Preview"));
        assert!(output.contains("Local cursor for peer: (none)"));
        assert!(output.contains("Local -> other missing events: 1"));
        assert!(output.contains("Other -> local missing events: 1"));
        assert!(output.contains("evt-root-created-root-"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_preview_reports_message_and_content_counts_by_direction() {
        let receiver_file = temp_state_file("sync-preview-activity-state-a");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);
        let sender_file = temp_state_file("sync-preview-activity-state-b");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            assert!(sender
                .handle_command(
                    "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated"
                )
                .contains("published content"));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let preview =
            receiver.handle_command(&format!("sync preview --state {}", sender_file.display()));

        assert!(preview.contains("Other -> local message events: 1"));
        assert!(preview.contains("Other -> local content events: 1"));

        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_apply_imports_remote_events_and_converges_preview() {
        let data_file_a = temp_state_file("sync-apply-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-apply-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let peer_id_b = DemoApp::with_state_file(data_file_b.clone()).current_peer_id();

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let created_root = app.handle_command("root create --name Shared Root");
            let root_id = created_id(&created_root);
            let created_persona = app.handle_command(&format!(
                "persona create --root {} --label shared@work --template professional",
                root_id
            ));
            assert!(created_persona.contains("created persona\tpersona-"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let preview_before =
            app.handle_command(&format!("sync preview --state {}", data_file_b.display()));
        let applied = app.handle_command(&format!("sync apply --state {}", data_file_b.display()));
        let preview_after =
            app.handle_command(&format!("sync preview --state {}", data_file_b.display()));
        let compare_after =
            app.handle_command(&format!("compare --state {}", data_file_b.display()));

        assert!(preview_before.contains("Other -> local missing events: 2"));
        assert!(applied.contains("applied sync\tsync-batch-"));
        assert!(applied.contains("\timported 2\t"));
        assert!(app.render_roots().contains("Shared Root"));
        assert!(app.render_personas().contains("shared@work"));
        assert!(app.render_sync().contains("Tracked peers:"));
        assert!(app.render_sync().contains(&peer_id_b));
        assert!(preview_after.contains("Local cursor for peer: evt-persona-created-"));
        assert!(preview_after.contains("Other -> local missing events: 0"));
        assert!(compare_after.contains("Shared events: 2"));
        assert!(compare_after.contains("Missing locally: 0"));
        assert!(compare_after.contains("Missing in other: 0"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_history_reports_batches_and_cursors_after_apply() {
        let data_file_a = temp_state_file("sync-history-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-history-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let peer_id_b = DemoApp::with_state_file(data_file_b.clone()).current_peer_id();

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let applied = app.handle_command(&format!("sync apply --state {}", data_file_b.display()));
        let history = app.handle_command("sync history");

        assert!(applied.contains("applied sync\tsync-batch-"));
        assert!(history.contains("Sync History"));
        assert!(history.contains(&peer_id_b));
        assert!(history.contains("evt-root-created-root-"));
        assert!(history.contains("sync-batch-"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn light_sync_applies_known_root_updates_without_consuming_unrelated_remote_events() {
        let data_file_a = temp_state_file("sync-light-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-light-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        let shared_root_id = {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let created = app.handle_command("root create --name Shared Root");
            created_id(&created)
        };

        {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            let full = app.handle_command(&format!("sync apply --state {}", data_file_b.display()));
            assert!(full.contains("\tprofile full\timported 1\t"));
        }

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let device = app.handle_command(&format!(
                "device add --root {} --label shared-laptop",
                shared_root_id
            ));
            assert!(device.contains("created device\tdevice-"));
            let other_root = app.handle_command("root create --name Isolated Root");
            assert!(other_root.contains("created root\troot-"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let preview_light = app.handle_command(&format!(
            "sync preview --state {} --profile light",
            data_file_b.display()
        ));
        let apply_light = app.handle_command(&format!(
            "sync apply --state {} --profile light",
            data_file_b.display()
        ));
        let compare_after_light =
            app.handle_command(&format!("compare --state {}", data_file_b.display()));
        let preview_full = app.handle_command(&format!(
            "sync preview --state {} --profile full",
            data_file_b.display()
        ));

        assert!(preview_light.contains("Profile: light"));
        assert!(preview_light.contains("Other -> local missing events: 1"));
        assert!(preview_light.contains("evt-device-added-device-"));
        assert!(apply_light.contains("\tprofile light\timported 1\t"));
        assert!(app.render_devices().contains("shared-laptop"));
        assert!(compare_after_light.contains("Missing locally: 1"));
        assert!(preview_full.contains("Profile: full"));
        assert!(preview_full.contains("Other -> local missing events: 1"));
        assert!(preview_full.contains("evt-root-created-root-"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_preview_trust_gated_rejects_when_score_is_below_threshold() {
        let data_file_a = temp_state_file("sync-gated-preview-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-gated-preview-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
        }

        let mut app = DemoApp::bootstrap(Some(data_file_a.clone()), true);
        let output = app.handle_command(&format!(
            "sync preview --state {} --mode trust-gated --source-persona persona-pseudonymous --threshold 0.81",
            data_file_b.display()
        ));

        assert!(output.contains("Sync Preview"));
        assert!(output.contains("Mode: trust-gated"));
        assert!(output.contains("Source persona: persona-pseudonymous"));
        assert!(output.contains("Trust score: 0.80"));
        assert!(output.contains("Admission: reject"));
        assert!(output.contains("does not meet threshold"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_apply_trust_gated_blocks_then_accepts_after_lower_threshold() {
        let data_file_a = temp_state_file("sync-gated-apply-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-gated-apply-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
        }

        let mut app = DemoApp::bootstrap(Some(data_file_a.clone()), true);
        let rejected = app.handle_command(&format!(
            "sync apply --state {} --mode trust-gated --source-persona persona-pseudonymous --threshold 0.81",
            data_file_b.display()
        ));
        let roots_after_reject = app.render_roots();
        let accepted = app.handle_command(&format!(
            "sync apply --state {} --mode trust-gated --source-persona persona-pseudonymous --threshold 0.75",
            data_file_b.display()
        ));

        assert!(rejected.contains("Sync Apply"));
        assert!(rejected.contains("Admission: reject"));
        assert!(!roots_after_reject.contains("Shared Root"));
        assert!(accepted.contains("applied sync\tsync-batch-"));
        assert!(accepted.contains("\timported 1\t"));
        assert!(app.render_roots().contains("Shared Root"));

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_mutual_converges_both_named_clients() {
        let data_file_a = temp_state_file("sync-mutual-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-mutual-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);

        {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            assert!(
                app.handle_command("root create --name Alpha Root")
                    .contains("created root\troot-")
            );
        }
        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Beta Root")
                    .contains("created root\troot-")
            );
        }

        let mut app_a = DemoApp::with_state_file(data_file_a.clone());
        let mutual =
            app_a.handle_command(&format!("sync mutual --state {}", data_file_b.display()));
        let reopened_b = DemoApp::with_state_file(data_file_b.clone());

        assert!(mutual.contains("mutual sync"));
        assert!(mutual.contains("applied sync\tsync-batch-"));
        assert!(app_a.render_broker(false).contains("Alpha Root"));
        assert!(app_a.render_broker(false).contains("Beta Root"));
        assert!(reopened_b.render_broker(false).contains("Alpha Root"));
        assert!(reopened_b.render_broker(false).contains("Beta Root"));
        assert!(
            app_a
                .handle_command(&format!("compare --state {}", data_file_b.display()))
                .contains("Shared events: 2")
        );

        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_export_and_import_transfer_batch_without_remote_state_access() {
        let data_file_a = temp_state_file("sync-export-import-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-export-import-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-export-import");
        let peer_id_b = DemoApp::with_state_file(data_file_b.clone()).current_peer_id();

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let created_root = app.handle_command("root create --name Shared Root");
            let root_id = created_id(&created_root);
            let created_persona = app.handle_command(&format!(
                "persona create --root {} --label shared@work --template professional",
                root_id
            ));
            assert!(created_persona.contains("created persona\tpersona-"));
        }

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let exported =
                app.handle_command(&format!("sync export --out {}", batch_file.display()));
            assert!(exported.contains("exported sync\tsync-batch-"));
            assert!(exported.contains("\tprofile full\tevents 2\t"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let imported = app.handle_command(&format!("sync import --file {}", batch_file.display()));

        assert!(imported.contains("imported sync\tsync-batch-"));
        assert!(imported.contains("\tprofile full\timported 2\t"));
        assert!(app.render_roots().contains("Shared Root"));
        assert!(app.render_personas().contains("shared@work"));
        assert!(app.render_sync().contains(&peer_id_b));

        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_export_for_state_only_includes_events_after_known_peer_cursor() {
        let data_file_a = temp_state_file("sync-export-targeted-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-export-targeted-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-export-targeted");

        let root_id = {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            let created_root = app.handle_command("root create --name Shared Root");
            created_id(&created_root)
        };

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let applied =
                app.handle_command(&format!("sync apply --state {}", data_file_a.display()));
            assert!(applied.contains("\timported 1\t"));
        }

        {
            let mut app = DemoApp::with_state_file(data_file_a.clone());
            let created_persona = app.handle_command(&format!(
                "persona create --root {} --label shared@work --template professional",
                root_id
            ));
            assert!(created_persona.contains("created persona\tpersona-"));
            let exported = app.handle_command(&format!(
                "sync export --out {} --for-state {}",
                batch_file.display(),
                data_file_b.display()
            ));
            assert!(exported.contains("exported sync\tsync-batch-"));
            assert!(exported.contains("\tevents 1\t"));
            assert!(exported.contains(&format!("\tfor {}", data_file_b.display())));
        }

        let exported_batch = PortableSyncBatch::decode(&fs::read(&batch_file).unwrap()).unwrap();
        assert_eq!(exported_batch.events.len(), 1);
        assert_eq!(exported_batch.batch.event_ids.len(), 1);
        assert!(exported_batch.batch.event_ids[0].starts_with("evt-persona-created-"));
        assert!(
            exported_batch
                .cursor_event_id
                .as_deref()
                .unwrap_or("")
                .starts_with("evt-persona-created-")
        );

        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_relay_pack_and_unpack_preserve_opaque_batch_for_import() {
        let data_file_a = temp_state_file("sync-relay-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-relay-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-relay");
        let unpacked_batch_file = temp_batch_file("sync-relay-unpacked");
        let relay_file = temp_relay_file("sync-relay");
        let target_peer_id = DemoApp::with_state_file(data_file_a.clone()).current_peer_id();

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
            assert!(
                app.handle_command(&format!("sync export --out {}", batch_file.display()))
                    .contains("exported sync\tsync-batch-")
            );
            assert!(app
                .handle_command(&format!(
                    "sync relay-pack --file {} --out {} --target-state {} --source-persona persona-professional",
                    batch_file.display(),
                    relay_file.display(),
                    data_file_a.display()
                ))
                .contains("packed relay\trelay-envelope-"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let relay_inspect = app.handle_command(&format!(
            "sync relay-inspect --file {}",
            relay_file.display()
        ));
        let relay_unpack = app.handle_command(&format!(
            "sync relay-unpack --file {} --out {}",
            relay_file.display(),
            unpacked_batch_file.display()
        ));
        let imported = app.handle_command(&format!(
            "sync import --file {}",
            unpacked_batch_file.display()
        ));

        assert!(relay_inspect.contains("Relay Submission"));
        assert!(relay_inspect.contains("Source persona: persona-professional"));
        assert!(relay_inspect.contains(&format!("Target peer: {}", target_peer_id)));
        assert!(relay_inspect.contains("Opaque bytes:"));
        assert!(!relay_inspect.contains("Shared Root"));
        assert!(relay_unpack.contains("unpacked relay\trelay-envelope-"));
        assert!(imported.contains("imported sync\tsync-batch-"));
        assert!(app.render_roots().contains("Shared Root"));

        let _ = fs::remove_file(&relay_file);
        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&unpacked_batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_relay_pack_can_include_signed_admission_token() {
        let batch_file = temp_batch_file("sync-relay-token");
        let relay_file = temp_relay_file("sync-relay-token");

        let mut app = DemoApp::ephemeral();
        assert!(
            app.handle_command(&format!("sync export --out {}", batch_file.display()))
                .contains("exported sync\tsync-batch-")
        );

        let packed = app.handle_command(&format!(
            "sync relay-pack --file {} --out {} --target-peer peer-demo-target --source-persona persona-pseudonymous --token-issuer persona-professional --threshold 0.75 --expires-in 600",
            batch_file.display(),
            relay_file.display()
        ));
        let inspect = app.handle_command(&format!(
            "sync relay-inspect --file {}",
            relay_file.display()
        ));

        assert!(packed.contains("token present"));
        assert!(packed.contains("target peer-demo-target"));
        assert!(inspect.contains("Admission token: present"));
        assert!(inspect.contains("Token issuer: persona-professional"));
        assert!(inspect.contains("Token subject: persona-pseudonymous"));
        assert!(inspect.contains("Token threshold: 0.75"));
        assert!(inspect.contains("Target peer: peer-demo-target"));

        let _ = fs::remove_file(&relay_file);
        let _ = fs::remove_file(&batch_file);
    }

    #[test]
    fn sync_relay_pack_requires_target_peer_metadata() {
        let batch_file = temp_batch_file("sync-relay-missing-target");
        let relay_file = temp_relay_file("sync-relay-missing-target");

        let mut app = DemoApp::ephemeral();
        assert!(
            app.handle_command(&format!("sync export --out {}", batch_file.display()))
                .contains("exported sync\tsync-batch-")
        );

        let output = app.handle_command(&format!(
            "sync relay-pack --file {} --out {} --source-persona persona-professional",
            batch_file.display(),
            relay_file.display()
        ));

        assert!(output.contains("Usage: sync relay-pack"));

        let _ = fs::remove_file(&relay_file);
        let _ = fs::remove_file(&batch_file);
    }

    #[test]
    fn sync_relay_send_peer_requires_known_endpoint() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command(
            "sync relay-send-peer --peer peer-missing --source-persona persona-professional",
        );

        assert!(output.contains(
            "Failed to resolve relay route: no published endpoint for peer: peer-missing"
        ));
    }

    #[test]
    fn sync_relay_send_peer_uses_published_endpoint_bind_before_network() {
        let mut app = DemoApp::ephemeral();
        let device = app
            .resolve_device("device-root-a-01")
            .cloned()
            .expect("device");
        let signer = app.device_signer(&device.device_id).expect("device signer");
        app.append_live_event(
            app.allocate_event_id("relay-hint-updated"),
            relay_hint_updated_event(
                "peer-remote",
                &device.device_id,
                "relay://127.0.0.1:0/mailbox/peer-remote",
            ),
            SignerBinding::device(&device.device_id, device.active_key.key_id.clone()),
            &signer,
        )
        .expect("append remote endpoint");

        let output = app.handle_command(&format!(
            "sync relay-send-peer --peer {} --source-persona persona-professional",
            "peer-remote"
        ));

        assert!(output.contains("Failed to send relay submission: connect relay 127.0.0.1:0"));
    }

    #[test]
    fn sync_relay_send_state_resolves_target_endpoint_before_network() {
        let target_file = temp_state_file("sync-relay-send-state-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);

        {
            let mut target = DemoApp::bootstrap(Some(target_file.clone()), true);
            let published = target
                .handle_command("sync endpoint set --device device-root-a-01 --bind 127.0.0.1:0");
            assert!(published.contains("updated endpoint"));
        }

        let mut sender = DemoApp::ephemeral();
        let output = sender.handle_command(&format!(
            "sync relay-send-state --state {} --source-persona persona-professional",
            target_file.display()
        ));

        assert!(output.contains("Failed to send relay submission: connect relay 127.0.0.1:0"));

        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
    }

    #[test]
    fn sync_relay_send_state_and_drain_state_round_trip_over_local_relay() {
        let target_file = temp_state_file("sync-relay-state-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);
        let sender_file = temp_state_file("sync-relay-state-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let Some((bind_address, relay_handle)) = spawn_test_relay(2) else {
            return;
        };

        let target_peer_id = {
            let mut target = DemoApp::with_state_file(target_file.clone());
            let root_created = target.handle_command("root create --name Relay Target");
            let root_id = created_id(&root_created);
            let device_added = target.handle_command(&format!(
                "device add --root {} --label Relay Target Device",
                root_id
            ));
            let device_id = created_id(&device_added);
            let published = target.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            assert!(published.contains("updated endpoint"));
            target.current_peer_id()
        };

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            let sent = sender.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona persona-professional",
                target_file.display()
            ));
            assert!(sent.contains("SUBMIT ok"));
            assert!(sent.contains(&format!("target {}", target_peer_id)));
        }

        let mut orchestrator = DemoApp::ephemeral();
        let drained = orchestrator.handle_command(&format!(
            "sync relay-drain-state --state {}",
            target_file.display()
        ));

        assert!(drained.contains("relay drain state"));
        assert!(drained.contains(&format!("peer {}", target_peer_id)));
        assert!(drained.contains("queued 1"));

        let target = DemoApp::with_state_file(target_file.clone());
        assert!(target.render_messages().contains("ciphertext 4 bytes"));

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_relay_cycle_requires_published_target_endpoint() {
        let target_file = temp_state_file("sync-relay-cycle-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);
        let _target = DemoApp::with_state_file(target_file.clone());

        let mut sender = DemoApp::ephemeral();
        let output = sender.handle_command(&format!(
            "sync relay-cycle --state {} --source-persona persona-professional",
            target_file.display()
        ));

        assert!(output.contains("Failed to resolve relay route: no published endpoint for peer:"));

        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
    }

    #[test]
    fn sync_relay_cycle_round_trips_over_local_relay() {
        let target_file = temp_state_file("sync-relay-cycle-live-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);
        let sender_file = temp_state_file("sync-relay-cycle-live-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let Some((bind_address, relay_handle)) = spawn_test_relay(2) else {
            return;
        };

        let target_peer_id = {
            let mut target = DemoApp::with_state_file(target_file.clone());
            let root_created = target.handle_command("root create --name Relay Target");
            let root_id = created_id(&root_created);
            let device_added = target.handle_command(&format!(
                "device add --root {} --label Relay Target Device",
                root_id
            ));
            let device_id = created_id(&device_added);
            let published = target.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            assert!(published.contains("updated endpoint"));
            target.current_peer_id()
        };

        let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
        assert!(sender
            .handle_command(
                "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
            )
            .contains("sent message"));
        let cycle = sender.handle_command(&format!(
            "sync relay-cycle --state {} --source-persona persona-professional",
            target_file.display()
        ));

        assert!(cycle.contains("relay cycle"));
        assert!(cycle.contains("SUBMIT ok"));
        assert!(cycle.contains(&format!("peer {}", target_peer_id)));
        assert!(cycle.contains("queued 1"));

        let target = DemoApp::with_state_file(target_file.clone());
        assert!(target.render_messages().contains("ciphertext 4 bytes"));

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_send_and_receive_simplified_commands() {
        let target_file = temp_state_file("sync-send-receive-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);
        let sender_file = temp_state_file("sync-send-receive-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let Some((bind_address, relay_handle)) = spawn_test_relay(2) else {
            return;
        };

        // Set up target with endpoint
        {
            let mut target = DemoApp::with_state_file(target_file.clone());
            let init = target.handle_command("init --name Bob --template professional");
            assert!(init.contains("created root"), "init failed: {init}");
            let device_id = extract_line_id(&init, "created device");
            let published = target.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            assert!(published.contains("updated endpoint"));
        }

        // Sender creates identity and sends via simplified command
        let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
        sender.handle_command(
            "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef",
        );
        let send = sender.handle_command(&format!("sync send --to {}", target_file.display()));
        assert!(send.contains("SUBMIT ok"), "send failed: {send}");

        // Target receives via simplified command
        {
            let mut target = DemoApp::with_state_file(target_file.clone());
            let receive = target.handle_command("sync receive");
            assert!(receive.contains("queued"), "receive failed: {receive}");
        }

        // Verify target got the message
        {
            let target = DemoApp::with_state_file(target_file.clone());
            let messages = target.render_messages();
            assert!(
                messages.contains("ciphertext 4 bytes"),
                "messages missing: {messages}"
            );
        }

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn relay_mailbox_frames_import_targeted_sync_batch_into_named_client() {
        let data_file_a = temp_state_file("sync-relay-live-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-relay-live-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-relay-live");
        let relay_file = temp_relay_file("sync-relay-live");
        let receiver_peer_id = DemoApp::with_state_file(data_file_b.clone()).current_peer_id();

        {
            let mut sender = DemoApp::with_state_file(data_file_a.clone());
            assert!(
                sender
                    .handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
            assert!(
                sender
                    .handle_command(&format!("sync export --out {}", batch_file.display()))
                    .contains("exported sync\tsync-batch-")
            );
            assert!(sender
                .handle_command(&format!(
                    "sync relay-pack --file {} --out {} --target-state {} --source-persona persona-professional",
                    batch_file.display(),
                    relay_file.display(),
                    data_file_b.display()
                ))
                .contains("packed relay\trelay-envelope-"));
        }

        let mut receiver = DemoApp::with_state_file(data_file_b.clone());
        let payload = fs::read(&relay_file).expect("read relay file");
        let drained = receiver
            .import_relay_mailbox_frames(
                &receiver_peer_id,
                vec![
                    format!("DRAIN {} 1", receiver_peer_id).into_bytes(),
                    payload,
                ],
            )
            .expect("import relay mailbox frames");

        assert_eq!(drained, (1, 1, 1));
        assert!(receiver.render_roots().contains("Shared Root"));

        let _ = fs::remove_file(&relay_file);
        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn relay_mailbox_frames_import_message_and_content_for_viewing() {
        let receiver_file = temp_state_file("sync-relay-activity-a");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);
        let sender_file = temp_state_file("sync-relay-activity-b");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let batch_file = temp_batch_file("sync-relay-activity");
        let relay_file = temp_relay_file("sync-relay-activity");
        let receiver_peer_id = DemoApp::with_state_file(receiver_file.clone()).current_peer_id();

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            assert!(sender
                .handle_command(
                    "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated"
                )
                .contains("published content"));
            assert!(
                sender
                    .handle_command(&format!("sync export --out {}", batch_file.display()))
                    .contains("exported sync\tsync-batch-")
            );
            assert!(sender
                .handle_command(&format!(
                    "sync relay-pack --file {} --out {} --target-state {} --source-persona persona-professional",
                    batch_file.display(),
                    relay_file.display(),
                    receiver_file.display()
                ))
                .contains("packed relay\trelay-envelope-"));
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let payload = fs::read(&relay_file).expect("read relay file");
        let drained = receiver
            .import_relay_mailbox_frames(
                &receiver_peer_id,
                vec![
                    format!("DRAIN {} 1", receiver_peer_id).into_bytes(),
                    payload,
                ],
            )
            .expect("import relay mailbox frames");

        assert_eq!(drained.0, 1);
        assert_eq!(drained.1, 1);
        assert!(drained.2 >= 2);
        assert!(receiver.render_messages().contains("ciphertext 4 bytes"));
        assert!(receiver.render_content().contains("visibility trust_gated"));

        let _ = fs::remove_file(&relay_file);
        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_relay_drain_self_requires_published_local_endpoint() {
        let mut app = DemoApp::ephemeral();

        let output = app.handle_command("sync relay-drain-self");

        assert!(output.contains("Failed to resolve relay route: no published endpoint for peer:"));
    }

    #[test]
    fn sync_relay_drain_state_requires_published_target_endpoint() {
        let target_file = temp_state_file("sync-relay-drain-state-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);
        let _target = DemoApp::with_state_file(target_file.clone());

        let mut app = DemoApp::ephemeral();
        let output = app.handle_command(&format!(
            "sync relay-drain-state --state {}",
            target_file.display()
        ));

        assert!(output.contains("Failed to resolve relay route: no published endpoint for peer:"));

        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
    }

    #[test]
    fn sync_relay_drain_self_uses_local_endpoint_bind_before_network() {
        let mut app = DemoApp::ephemeral();
        let published =
            app.handle_command("sync endpoint set --device device-root-a-01 --bind 127.0.0.1:0");
        assert!(published.contains("updated endpoint"));

        let output = app.handle_command("sync relay-drain-self");

        assert!(output.contains("Failed to drain relay mailbox: connect relay 127.0.0.1:0"));
    }

    #[test]
    fn sync_relay_drain_state_uses_target_endpoint_before_network() {
        let target_file = temp_state_file("sync-relay-drain-state-live-target");
        let target_sqlite = sqlite_path_for_local_state(&target_file);

        {
            let mut target = DemoApp::bootstrap(Some(target_file.clone()), true);
            let published = target
                .handle_command("sync endpoint set --device device-root-a-01 --bind 127.0.0.1:0");
            assert!(published.contains("updated endpoint"));
        }

        let mut app = DemoApp::ephemeral();
        let output = app.handle_command(&format!(
            "sync relay-drain-state --state {}",
            target_file.display()
        ));

        assert!(output.contains("Failed to drain relay mailbox: connect relay 127.0.0.1:0"));

        let _ = fs::remove_file(&target_file);
        let _ = fs::remove_file(&target_sqlite);
    }

    #[test]
    fn sync_preview_file_reports_missing_events_before_import() {
        let data_file_a = temp_state_file("sync-preview-file-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-preview-file-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-preview-file");
        let source_peer_id = DemoApp::with_state_file(data_file_b.clone()).current_peer_id();

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            let created_root = app.handle_command("root create --name Shared Root");
            let root_id = created_id(&created_root);
            let created_persona = app.handle_command(&format!(
                "persona create --root {} --label shared@work --template professional",
                root_id
            ));
            assert!(created_persona.contains("created persona\tpersona-"));
            let exported =
                app.handle_command(&format!("sync export --out {}", batch_file.display()));
            assert!(exported.contains("exported sync\tsync-batch-"));
        }

        let mut app = DemoApp::with_state_file(data_file_a.clone());
        let preview = app.handle_command(&format!(
            "sync preview-file --file {}",
            batch_file.display()
        ));

        assert!(preview.contains("Sync File Preview"));
        assert!(preview.contains(&format!("Source peer: {}", source_peer_id)));
        assert!(preview.contains("Profile: full"));
        assert!(preview.contains("Events in batch: 2"));
        assert!(preview.contains("Admission: accept"));
        assert!(preview.contains("Missing locally: 2"));
        assert!(preview.contains("evt-root-created-root-"));

        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn sync_preview_file_reports_message_and_content_counts() {
        let receiver_file = temp_state_file("sync-preview-activity-a");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);
        let sender_file = temp_state_file("sync-preview-activity-b");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let batch_file = temp_batch_file("sync-preview-activity");

        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            assert!(sender
                .handle_command(
                    "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
                )
                .contains("sent message"));
            assert!(sender
                .handle_command(
                    "content publish --from persona-professional --type post --payload cafefood --visibility trust-gated"
                )
                .contains("published content"));
            assert!(
                sender
                    .handle_command(&format!("sync export --out {}", batch_file.display()))
                    .contains("exported sync\tsync-batch-")
            );
        }

        let mut receiver = DemoApp::with_state_file(receiver_file.clone());
        let preview = receiver.handle_command(&format!(
            "sync preview-file --file {}",
            batch_file.display()
        ));

        assert!(preview.contains("Message events in batch: 1"));
        assert!(preview.contains("Content events in batch: 1"));

        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
    }

    #[test]
    fn sync_import_trust_gated_blocks_then_accepts_exported_batch() {
        let data_file_a = temp_state_file("sync-import-gated-a");
        let sqlite_file_a = sqlite_path_for_local_state(&data_file_a);
        let data_file_b = temp_state_file("sync-import-gated-b");
        let sqlite_file_b = sqlite_path_for_local_state(&data_file_b);
        let batch_file = temp_batch_file("sync-import-gated");

        {
            let mut app = DemoApp::with_state_file(data_file_b.clone());
            assert!(
                app.handle_command("root create --name Shared Root")
                    .contains("created root\troot-")
            );
            let exported =
                app.handle_command(&format!("sync export --out {}", batch_file.display()));
            assert!(exported.contains("exported sync\tsync-batch-"));
        }

        let mut app = DemoApp::bootstrap(Some(data_file_a.clone()), true);
        let rejected = app.handle_command(&format!(
            "sync import --file {} --mode trust-gated --source-persona persona-pseudonymous --threshold 0.81",
            batch_file.display()
        ));
        let roots_after_reject = app.render_roots();
        let accepted = app.handle_command(&format!(
            "sync import --file {} --mode trust-gated --source-persona persona-pseudonymous --threshold 0.75",
            batch_file.display()
        ));

        assert!(rejected.contains("Sync Import"));
        assert!(rejected.contains("Admission: reject"));
        assert!(!roots_after_reject.contains("Shared Root"));
        assert!(accepted.contains("imported sync\tsync-batch-"));
        assert!(accepted.contains("\timported 1\t"));
        assert!(app.render_roots().contains("Shared Root"));

        let _ = fs::remove_file(&batch_file);
        let _ = fs::remove_file(&data_file_a);
        let _ = fs::remove_file(&sqlite_file_a);
        let _ = fs::remove_file(&data_file_b);
        let _ = fs::remove_file(&sqlite_file_b);
    }

    #[test]
    fn export_events_and_import_into_empty_store() {
        let export_file = temp_state_file("event-export");
        let mut source = DemoApp::ephemeral();
        source.handle_command("root create --name Export Test Root");

        let exported =
            source.handle_command(&format!("export-events --out {}", export_file.display()));
        assert!(exported.contains("exported"));
        assert!(exported.contains("events to"));

        let import_file = temp_state_file("event-import-target");
        let import_sqlite = sqlite_path_for_local_state(&import_file);
        let mut target = DemoApp::with_state_file(import_file.clone());
        let imported =
            target.handle_command(&format!("import-events --file {}", export_file.display()));
        assert!(imported.contains("imported"));

        assert!(target.render_roots().contains("Export Test Root"));
        assert_eq!(
            source.app_runtime.store.event_count(),
            target.app_runtime.store.event_count()
        );

        let _ = fs::remove_file(&export_file);
        let _ = fs::remove_file(&import_file);
        let _ = fs::remove_file(&import_sqlite);
    }

    #[test]
    fn import_events_skips_duplicates() {
        let export_file = temp_state_file("event-export-dedup");
        let mut app = DemoApp::ephemeral();
        let count_before = app.app_runtime.store.event_count();

        let exported =
            app.handle_command(&format!("export-events --out {}", export_file.display()));
        assert!(exported.contains("exported"));

        let imported =
            app.handle_command(&format!("import-events --file {}", export_file.display()));
        assert!(imported.contains("imported 0 events"));
        assert_eq!(app.app_runtime.store.event_count(), count_before);

        let _ = fs::remove_file(&export_file);
    }

    #[test]
    fn desktop_to_relay_end_to_end_round_trip() {
        // Build and spawn the actual relay binary
        let relay_binary = std::env::current_dir()
            .unwrap()
            .join("../../target/debug/emberlink-relay");
        if !relay_binary.exists() {
            // Skip if relay binary not built
            eprintln!(
                "skipping e2e test: relay binary not built (run cargo build -p emberlink-relay)"
            );
            return;
        }

        // Find a free port
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bind_address = listener.local_addr().unwrap().to_string();
        drop(listener);

        // Spawn the relay with --no-tls and open mode
        let mut relay_process = std::process::Command::new(&relay_binary)
            .args(["--bind", &bind_address, "--mode", "open", "--no-tls"])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn relay");

        // Wait for relay to start accepting connections
        let mut ready = false;
        for _ in 0..50 {
            if std::net::TcpStream::connect(&bind_address).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !ready {
            let _ = relay_process.kill();
            panic!("relay did not become ready on {bind_address}");
        }

        let sender_file = temp_state_file("e2e-sender");
        let sender_sqlite = sqlite_path_for_local_state(&sender_file);
        let receiver_file = temp_state_file("e2e-receiver");
        let receiver_sqlite = sqlite_path_for_local_state(&receiver_file);

        // Set up receiver with an endpoint pointing at the relay
        let receiver_peer_id = {
            let mut receiver = DemoApp::with_state_file(receiver_file.clone());
            let root_created = receiver.handle_command("root create --name E2E Receiver");
            let root_id = created_id(&root_created);
            let device_added = receiver
                .handle_command(&format!("device add --root {} --label E2E Device", root_id));
            let device_id = created_id(&device_added);
            receiver.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            receiver.current_peer_id()
        };

        // Sender creates identity, sends a message, then pushes to relay
        {
            let mut sender = DemoApp::bootstrap(Some(sender_file.clone()), true);
            sender.handle_command(
                "message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeefcafe"
            );
            let sent = sender.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona persona-professional",
                receiver_file.display()
            ));
            assert!(
                sent.contains("OK accepted") || sent.contains("SUBMIT ok"),
                "relay submit failed: {sent}"
            );
            assert!(sent.contains(&format!("target {}", receiver_peer_id)));
        }

        // Receiver drains from the relay
        let mut orchestrator = DemoApp::ephemeral();
        let drained = orchestrator.handle_command(&format!(
            "sync relay-drain-state --state {}",
            receiver_file.display()
        ));

        assert!(drained.contains("relay drain"), "drain failed: {drained}");

        // Verify the receiver got the message
        let receiver = DemoApp::with_state_file(receiver_file.clone());
        let messages = receiver.render_messages();
        assert!(
            messages.contains("ciphertext 6 bytes"),
            "receiver messages missing expected content: {messages}\ndrain output: {drained}"
        );

        // Clean up
        let _ = relay_process.kill();
        let _ = relay_process.wait();
        let _ = fs::remove_file(&sender_file);
        let _ = fs::remove_file(&sender_sqlite);
        let _ = fs::remove_file(&receiver_file);
        let _ = fs::remove_file(&receiver_sqlite);
    }

    #[test]
    fn sync_convergence_through_relay_produces_identical_state() {
        let file_a = temp_state_file("converge-relay-a");
        let sqlite_a = sqlite_path_for_local_state(&file_a);
        let file_b = temp_state_file("converge-relay-b");
        let sqlite_b = sqlite_path_for_local_state(&file_b);

        // Need 4 connections: A→relay (send), B←relay (drain), B→relay (send), A←relay (drain)
        let Some((bind_address, relay_handle)) = spawn_test_relay(4) else {
            return;
        };

        // Client A: create identity + set endpoint
        {
            let mut app_a = DemoApp::with_state_file(file_a.clone());
            let root_created = app_a.handle_command("root create --name Alpha");
            let root_id = created_id(&root_created);
            let device_added = app_a.handle_command(&format!(
                "device add --root {} --label Alpha Device",
                root_id
            ));
            let device_id = created_id(&device_added);
            app_a.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            app_a.current_peer_id();
        }

        // Client B: create identity + set endpoint
        {
            let mut app_b = DemoApp::with_state_file(file_b.clone());
            let root_created = app_b.handle_command("root create --name Beta");
            let root_id = created_id(&root_created);
            let device_added = app_b.handle_command(&format!(
                "device add --root {} --label Beta Device",
                root_id
            ));
            let device_id = created_id(&device_added);
            app_b.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));
            app_b.current_peer_id();
        }

        // A sends to B's relay mailbox
        {
            let mut app_a = DemoApp::with_state_file(file_a.clone());
            let sent = app_a.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona root-",
                file_b.display()
            ));
            assert!(sent.contains("SUBMIT ok"), "A→B send failed: {sent}");
        }

        // B drains from relay
        {
            let mut orchestrator = DemoApp::ephemeral();
            let drained = orchestrator.handle_command(&format!(
                "sync relay-drain-state --state {}",
                file_b.display()
            ));
            assert!(drained.contains("relay drain"), "B drain failed: {drained}");
        }

        // B sends to A's relay mailbox
        {
            let mut app_b = DemoApp::with_state_file(file_b.clone());
            let sent = app_b.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona root-",
                file_a.display()
            ));
            assert!(sent.contains("SUBMIT ok"), "B→A send failed: {sent}");
        }

        // A drains from relay
        {
            let mut orchestrator = DemoApp::ephemeral();
            let drained = orchestrator.handle_command(&format!(
                "sync relay-drain-state --state {}",
                file_a.display()
            ));
            assert!(drained.contains("relay drain"), "A drain failed: {drained}");
        }

        // Both clients should now see both roots
        let mut app_a = DemoApp::with_state_file(file_a.clone());
        let app_b = DemoApp::with_state_file(file_b.clone());

        let broker_a = app_a.render_broker(false);
        let broker_b = app_b.render_broker(false);

        assert!(broker_a.contains("Alpha"), "A missing own root: {broker_a}");
        assert!(broker_a.contains("Beta"), "A missing B's root: {broker_a}");
        assert!(broker_b.contains("Alpha"), "B missing A's root: {broker_b}");
        assert!(broker_b.contains("Beta"), "B missing own root: {broker_b}");

        // Event stores should have the same events
        assert_eq!(
            app_a.app_runtime.store.event_count(),
            app_b.app_runtime.store.event_count(),
            "event counts diverged: A={} B={}",
            app_a.app_runtime.store.event_count(),
            app_b.app_runtime.store.event_count(),
        );

        // Compare should show full convergence
        let compare = app_a.handle_command(&format!("compare --state {}", file_b.display()));
        assert!(
            compare.contains("Missing locally: 0"),
            "A has missing events: {compare}"
        );
        assert!(
            compare.contains("Missing in other: 0"),
            "B has missing events: {compare}"
        );

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&file_a);
        let _ = fs::remove_file(&sqlite_a);
        let _ = fs::remove_file(&file_b);
        let _ = fs::remove_file(&sqlite_b);
    }

    #[test]
    fn two_user_disclosure_through_relay() {
        // Viral loop: Two users exchange identities through relay, then Alice discloses
        // a credential to Bob's persona, syncs again, and Bob receives it.
        //
        // Round 1: identity exchange (A→B, B→A)
        // Round 2: Alice discloses to Bob's persona, syncs (A→B), Bob imports
        let alice_file = temp_state_file("viral-alice");
        let alice_sqlite = sqlite_path_for_local_state(&alice_file);
        let bob_file = temp_state_file("viral-bob");
        let bob_sqlite = sqlite_path_for_local_state(&bob_file);

        // 4 connections: A→B send, B drain, A→B send again, B drain again
        let Some((bind_address, relay_handle)) = spawn_test_relay(4) else {
            return;
        };

        // Alice: create identity + set endpoint + write credential
        let alice_persona_id;
        {
            let mut alice = DemoApp::bootstrap(Some(alice_file.clone()), false);
            let init = alice.handle_command("init --name Alice --template professional");
            assert!(init.contains("Identity initialized"), "alice init: {init}");

            alice_persona_id = alice.personas.first().expect("alice persona").id.clone();
            let alice_device = alice
                .devices
                .first()
                .expect("alice device")
                .device_id
                .clone();

            alice.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                alice_device, bind_address
            ));

            // Write a credential that Alice will later disclose
            let write = alice.handle_command(&format!(
                "vault write-record --namespace persona:{} --object alice-cred --schema com.example/cred --app com.example --json {{\"title\":\"Engineer\",\"org\":\"Acme\"}}",
                alice_persona_id
            ));
            assert!(write.contains("wrote record"), "write: {write}");

            // Create a template that projects only the title field
            let tmpl = alice.handle_command(&format!(
                "vault template add --id tmpl-public-cred --object alice-cred --schema com.example/cred --audience peer --namespace persona:{} --field title",
                alice_persona_id
            ));
            assert!(tmpl.contains("added template"), "template: {tmpl}");
        }

        // Bob: create identity + set endpoint
        let bob_persona_id;
        {
            let mut bob = DemoApp::bootstrap(Some(bob_file.clone()), false);
            let init = bob.handle_command("init --name Bob --template professional");
            assert!(init.contains("Identity initialized"), "bob init: {init}");

            bob_persona_id = bob.personas.first().expect("bob persona").id.clone();
            let bob_device = bob.devices.first().expect("bob device").device_id.clone();

            bob.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                bob_device, bind_address
            ));
        }

        // Round 1: Alice sends identity to Bob
        {
            let mut alice = DemoApp::with_state_file(alice_file.clone());
            let sent = alice.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona {}",
                bob_file.display(),
                alice_persona_id
            ));
            assert!(sent.contains("SUBMIT ok"), "A→B send failed: {sent}");
        }

        // Bob drains: now Bob knows Alice's persona
        {
            let mut orchestrator = DemoApp::ephemeral();
            let drained = orchestrator.handle_command(&format!(
                "sync relay-drain-state --state {}",
                bob_file.display()
            ));
            assert!(
                drained.contains("relay drain"),
                "B drain 1 failed: {drained}"
            );
        }

        // Verify Bob sees Alice
        {
            let bob = DemoApp::with_state_file(bob_file.clone());
            let broker = bob.render_broker(false);
            assert!(broker.contains("Alice"), "bob should see Alice: {broker}");
        }

        // Round 2: Alice discloses credential to Bob's persona
        {
            let mut alice = DemoApp::with_state_file(alice_file.clone());

            // Alice needs to know Bob's persona — sync Bob's state first
            let sync = alice.handle_command(&format!("sync apply --state {}", bob_file.display()));
            assert!(!sync.contains("Failed"), "alice sync bob: {sync}");

            // Now Alice can disclose to Bob's actual persona
            let disclose = alice.handle_command(&format!(
                "disclose --from {} --to {} --template tmpl-public-cred",
                alice_persona_id, bob_persona_id
            ));
            assert!(
                disclose.contains("issued artifact"),
                "disclose issue: {disclose}"
            );
            assert!(
                disclose.contains("sent disclosure artifact"),
                "disclose send: {disclose}"
            );

            // Send updated state (with disclosure message) to Bob's relay
            let sent = alice.handle_command(&format!(
                "sync relay-send-state --state {} --source-persona {}",
                bob_file.display(),
                alice_persona_id
            ));
            assert!(sent.contains("SUBMIT ok"), "A→B send 2 failed: {sent}");
        }

        // Bob drains round 2: gets the disclosure message
        {
            let mut orchestrator = DemoApp::ephemeral();
            let drained = orchestrator.handle_command(&format!(
                "sync relay-drain-state --state {}",
                bob_file.display()
            ));
            assert!(
                drained.contains("relay drain"),
                "B drain 2 failed: {drained}"
            );
        }

        // Bob opens state: should see disclosure
        {
            let mut bob = DemoApp::with_state_file(bob_file.clone());

            // Bob sees the disclosure message
            let disclosures = bob.render_disclosures();
            assert!(
                disclosures.contains("com.example/cred"),
                "bob should see disclosure schema: {disclosures}"
            );
            assert!(
                disclosures.contains(&alice_persona_id),
                "bob should see alice as sender: {disclosures}"
            );

            // Bob imports the disclosure from the message
            let message_id = disclosures
                .lines()
                .find(|line| line.contains("com.example/cred"))
                .and_then(|line| line.split('\t').next())
                .map(|s| s.trim().trim_start_matches("- "))
                .expect("find disclosure message id");

            let import =
                bob.handle_command(&format!("vault import-message --message {}", message_id));
            assert!(import.contains("imported"), "import: {import}");

            // Bob can see the received disclosure with projected payload
            let received = bob.handle_command("vault received");
            assert!(
                received.contains(&alice_persona_id),
                "received lists alice: {received}"
            );
        }

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&alice_file);
        let _ = fs::remove_file(&alice_sqlite);
        let _ = fs::remove_file(&bob_file);
        let _ = fs::remove_file(&bob_sqlite);
    }

    #[test]
    fn recovery_session_persists_across_restart_and_executes() {
        let data_file = temp_state_file("recovery-persist-execute");
        let sqlite_file = sqlite_path_for_local_state(&data_file);

        // Phase 1: request + approve, then drop (simulates restart)
        {
            let mut app = DemoApp::bootstrap(Some(data_file.clone()), true);
            let request =
                app.handle_command("recovery request --root root-a --device device-root-a-01");
            assert!(request.contains("created recovery request"));

            let approve1 = app.handle_command("recovery approve --guardian guardian-alex");
            assert!(approve1.contains("approved recovery"));

            let approve2 = app.handle_command("recovery approve --guardian guardian-riley");
            assert!(approve2.contains("2/2"));

            // Verify state before restart
            let recovery = app.render_recovery();
            assert!(recovery.contains("State: approved"));
        }

        // Phase 2: reload from disk, verify session survived, then execute
        {
            let mut reopened = DemoApp::bootstrap(Some(data_file.clone()), true);
            let recovery = reopened.render_recovery();
            assert!(
                recovery.contains("State: approved"),
                "recovery state lost across restart: {recovery}"
            );
            assert!(
                recovery.contains("Approvals: 2"),
                "approval count lost across restart: {recovery}"
            );

            let execute = reopened.handle_command("recovery execute");
            assert!(
                execute.contains("executed recovery"),
                "execute after restart failed: {execute}"
            );

            let final_recovery = reopened.render_recovery();
            assert!(
                final_recovery.contains("State: executed"),
                "final state not executed: {final_recovery}"
            );
            assert!(
                reopened
                    .render_device("device-root-a-01")
                    .contains("revoked"),
                "target device should be revoked after execution"
            );
        }

        let _ = fs::remove_file(&data_file);
        let _ = fs::remove_file(&sqlite_file);
    }

    #[test]
    fn status_shows_identity_overview() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command("status");
        assert!(output.contains("Emberlink identity status"));
        assert!(output.contains("Roots (2):"));
        assert!(output.contains("Primary Root"));
        assert!(output.contains("Personas (3):"));
        assert!(output.contains("Professional"));
    }

    #[test]
    fn help_shows_organized_categories() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command("help");
        assert!(output.contains("Getting started"));
        assert!(output.contains("Identity — Roots"));
        assert!(output.contains("Identity — Devices"));
        assert!(output.contains("Identity — Personas"));
        assert!(output.contains("Trust"));
        assert!(output.contains("Vault & Disclosure"));
        assert!(output.contains("Recovery"));
        assert!(output.contains("Sync — Quick"));
        assert!(output.contains("Sync — Relay operations"));
        assert!(output.contains("Storage"));
        assert!(output.contains("Inspect & Debug"));
    }

    #[test]
    fn init_creates_root_device_persona() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command("init --name TestUser --template professional");
        assert!(output.contains("created root"));
        assert!(output.contains("created device"));
        assert!(output.contains("created persona"));
        assert!(output.contains("Identity initialized"));

        let status = app.handle_command("status");
        assert!(status.contains("TestUser"));
    }

    #[test]
    fn init_without_name_shows_usage() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command("init");
        assert!(output.contains("Usage:"));
        assert!(output.contains("--name"));
    }

    #[test]
    fn disclose_issues_and_sends_in_one_step() {
        let mut app = DemoApp::ephemeral();
        let output = app.handle_command(
            "disclose --from persona-professional --to persona-pseudonymous --template template-professional-peer-card",
        );
        assert!(output.contains("issued artifact"), "issue step: {output}");
        assert!(
            output.contains("sent disclosure artifact"),
            "send step: {output}"
        );

        let disclosures = app.handle_command("show disclosures");
        assert!(disclosures.contains("com.emberlink.profile/basic"));
    }

    #[test]
    fn unknown_root_shows_available() {
        let app = DemoApp::ephemeral();
        let err = app.require_root("nonexistent").unwrap_err();
        assert!(err.message.contains("Available roots:"));
        assert!(err.message.contains("Primary Root"));
    }

    #[test]
    fn unknown_persona_shows_available() {
        let app = DemoApp::ephemeral();
        let err = app.require_persona("nonexistent").unwrap_err();
        assert!(err.message.contains("Available personas:"));
        assert!(err.message.contains("Professional"));
    }

    fn extract_line_id(output: &str, prefix: &str) -> String {
        output
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("no line starting with '{prefix}' in:\n{output}"))
            .split('\t')
            .nth(1)
            .unwrap_or_else(|| panic!("no tab-separated id in line with prefix '{prefix}'"))
            .to_string()
    }

    #[test]
    fn multi_device_vault_access_after_grant() {
        // Alice creates identity from scratch, writes vault data on device A,
        // adds device B, grants access, verifies device B can decrypt vault data
        let state_file =
            std::env::temp_dir().join(format!("multi-device-{}.tsv", std::process::id()));
        let mut app = DemoApp::with_state_file(state_file);

        // Create identity: root + device A + persona
        let init = app.handle_command("init --name Alice --template professional");
        assert!(init.contains("created root"), "init failed: {init}");

        // Extract IDs
        let root_id = extract_line_id(&init, "created root");
        let device_a_id = extract_line_id(&init, "created device");
        let persona_id = extract_line_id(&init, "created persona");

        // Write a vault record under Alice's persona
        let write = app.handle_command(&format!(
            "vault write-record --namespace persona:{} --object alice-cred --schema com.test/cred --app com.test --json {{\"title\":\"Engineer\",\"org\":\"Acme\"}}",
            persona_id
        ));
        assert!(write.contains("wrote record"), "write failed: {write}");

        // Add device B under the same root
        let add_device =
            app.handle_command(&format!("device add --root {} --label tablet", root_id));
        assert!(
            add_device.contains("created device"),
            "add device failed: {add_device}"
        );
        let device_b_id = created_id(&add_device);

        // Grant persona access to device B — should trigger re-wrap
        let grant = app.handle_command(&format!(
            "persona grant-device --persona {} --device tablet",
            persona_id
        ));
        assert!(
            grant.contains("granted persona device access"),
            "grant failed: {grant}"
        );
        assert!(grant.contains("re-wrapped"), "no re-wrap: {grant}");

        // Verify device B has access to the vault manifests
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona_id.clone(),
        };
        let manifests = app
            .app_runtime.store
            .local_vault_manifests_with_keys(&namespace)
            .unwrap();
        assert!(!manifests.is_empty(), "expected vault manifests");

        // Verify device A and device B both have access entries
        for (manifest, expected_key) in &manifests {
            let has_a = manifest
                .authorized_devices
                .iter()
                .any(|a| a.device_id == device_a_id);
            let has_b = manifest
                .authorized_devices
                .iter()
                .any(|a| a.device_id == device_b_id);
            assert!(
                has_a,
                "manifest {} missing device A {}",
                manifest.id, device_a_id
            );
            assert!(
                has_b,
                "manifest {} missing device B {}",
                manifest.id, device_b_id
            );

            // Verify device B can actually unwrap the content key
            let enc_key_pair = app
                .app_runtime.store
                .local_device_encryption_key_pair(&device_b_id)
                .unwrap()
                .expect("missing device B encryption key");
            let access_b = manifest
                .authorized_devices
                .iter()
                .find(|a| a.device_id == device_b_id)
                .unwrap();
            let unwrapped =
                core_storage::unwrap_manifest_key_access(access_b, &enc_key_pair.private_key)
                    .expect("device B failed to unwrap manifest key");
            assert_eq!(&unwrapped, expected_key, "device B unwrapped wrong key");
        }
    }

    #[test]
    fn viral_adoption_alice_bob_carol_through_relay() {
        // Viral loop: Alice discloses to Bob → Bob receives → Bob discloses to Carol → Carol receives
        // Each user starts from scratch with `init`, simulating real viral adoption.

        let file_a = temp_state_file("viral-alice");
        let sqlite_a = sqlite_path_for_local_state(&file_a);
        let file_b = temp_state_file("viral-bob");
        let sqlite_b = sqlite_path_for_local_state(&file_b);
        let file_c = temp_state_file("viral-carol");
        let sqlite_c = sqlite_path_for_local_state(&file_c);

        // 6 connections: A→B send, B drain, A→B send2, B drain2, B→C send, C drain
        let Some((bind_address, relay_handle)) = spawn_test_relay(6) else {
            return;
        };

        // Helper: create identity, set endpoint, write credential + template
        fn setup_user(file: &std::path::Path, name: &str, bind_address: &str) -> (String, String) {
            let mut app = DemoApp::with_state_file(file.to_path_buf());
            let init = app.handle_command(&format!("init --name {name} --template professional"));
            assert!(init.contains("created root"), "{name} init: {init}");
            let persona_id = extract_line_id(&init, "created persona");
            let device_id = extract_line_id(&init, "created device");

            app.handle_command(&format!(
                "sync endpoint set --device {} --bind {}",
                device_id, bind_address
            ));

            let write = app.handle_command(&format!(
                "vault write-record --namespace persona:{} --object {}-cred --schema com.example/cred --app com.example --json {{\"title\":\"{name}\",\"org\":\"Corp\"}}",
                persona_id, name.to_lowercase()
            ));
            assert!(write.contains("wrote record"), "{name} write: {write}");

            let tmpl = app.handle_command(&format!(
                "vault template add --id tmpl-{}-card --object {}-cred --schema com.example/cred --audience peer --namespace persona:{} --field title",
                name.to_lowercase(), name.to_lowercase(), persona_id
            ));
            assert!(tmpl.contains("added template"), "{name} template: {tmpl}");

            (persona_id, device_id)
        }

        // === Step 1: Alice creates identity ===
        let (alice_persona_id, _alice_device_id) = setup_user(&file_a, "Alice", &bind_address);

        // === Step 2: Bob creates identity ===
        let (bob_persona_id, _bob_device_id) = setup_user(&file_b, "Bob", &bind_address);

        // === Step 3: Round 1 — Exchange identities (Alice → Bob) ===
        {
            let mut alice = DemoApp::with_state_file(file_a.clone());
            let send = alice.handle_command(&format!("sync send --to {}", file_b.display()));
            assert!(send.contains("SUBMIT ok"), "A→B identity send: {send}");
        }
        {
            let mut bob = DemoApp::with_state_file(file_b.clone());
            let receive = bob.handle_command("sync receive");
            assert!(receive.contains("queued"), "B drain round 1: {receive}");
        }

        // === Step 4: Round 2 — Alice discloses to Bob ===
        {
            let mut alice = DemoApp::with_state_file(file_a.clone());
            // Alice learns Bob's persona
            alice.handle_command(&format!("sync apply --state {}", file_b.display()));

            let disclose = alice.handle_command(&format!(
                "disclose --from {} --to {} --template tmpl-alice-card",
                alice_persona_id, bob_persona_id
            ));
            assert!(
                disclose.contains("issued artifact"),
                "Alice disclose: {disclose}"
            );

            let send = alice.handle_command(&format!("sync send --to {}", file_b.display()));
            assert!(send.contains("SUBMIT ok"), "A→B disclose send: {send}");
        }

        // Bob receives Alice's disclosure — should auto-import
        {
            let mut bob = DemoApp::with_state_file(file_b.clone());
            let receive = bob.handle_command("sync receive");
            assert!(receive.contains("queued"), "B drain round 2: {receive}");
            assert!(
                receive.contains("auto-imported"),
                "expected auto-import: {receive}"
            );

            // Verify disclosure appears in vault received (auto-imported)
            let received = bob.render_received_artifacts();
            assert!(
                received.contains("com.example/cred"),
                "Bob's vault received missing disclosure: {received}"
            );
        }

        // === Step 5: Carol creates identity (the viral step!) ===
        let (carol_persona_id, _carol_device_id) = setup_user(&file_c, "Carol", &bind_address);

        // === Step 6: Bob discloses to Carol (completing the viral chain) ===
        {
            let mut bob = DemoApp::with_state_file(file_b.clone());
            // Bob learns Carol's persona
            bob.handle_command(&format!("sync apply --state {}", file_c.display()));

            let disclose = bob.handle_command(&format!(
                "disclose --from {} --to {} --template tmpl-bob-card",
                bob_persona_id, carol_persona_id
            ));
            assert!(
                disclose.contains("issued artifact"),
                "Bob disclose to Carol: {disclose}"
            );

            let send = bob.handle_command(&format!("sync send --to {}", file_c.display()));
            assert!(send.contains("SUBMIT ok"), "B→C send: {send}");
        }

        // Carol receives Bob's disclosure
        {
            let mut carol = DemoApp::with_state_file(file_c.clone());
            let receive = carol.handle_command("sync receive");
            assert!(receive.contains("queued"), "C drain: {receive}");

            let disclosures = carol.render_disclosures();
            assert!(
                disclosures.contains("com.example/cred") || disclosures.contains(&bob_persona_id),
                "Carol doesn't see Bob's disclosure: {disclosures}"
            );
        }

        relay_handle.join().expect("join relay thread");
        let _ = fs::remove_file(&file_a);
        let _ = fs::remove_file(&sqlite_a);
        let _ = fs::remove_file(&file_b);
        let _ = fs::remove_file(&sqlite_b);
        let _ = fs::remove_file(&file_c);
        let _ = fs::remove_file(&sqlite_c);
    }

    #[test]
    fn invite_create_and_accept_bootstraps_new_user() {
        let file_a = temp_state_file("invite-alice");
        let sqlite_a = super::sqlite_path_for_local_state(&file_a);
        let mut alice = DemoApp::bootstrap(Some(file_a.clone()), true);

        let alice_persona = alice
            .app_runtime.store
            .materialized()
            .personas_current
            .keys()
            .next()
            .unwrap()
            .clone();

        // Alice creates an invite
        let invite_file = temp_batch_file("invite");
        let result = alice.handle_command(&format!(
            "invite create --persona {} --relay 127.0.0.1:9100 --out {}",
            alice_persona,
            invite_file.display()
        ));
        assert!(
            result.contains("invite created"),
            "invite create failed: {result}"
        );
        assert!(invite_file.exists(), "invite file not created");

        // Bob starts with no identity and accepts the invite
        let file_b = temp_state_file("invite-bob");
        let sqlite_b = super::sqlite_path_for_local_state(&file_b);
        let mut bob = DemoApp::bootstrap(Some(file_b.clone()), false);

        let result = bob.handle_command(&format!(
            "invite accept --file {} --name Bob --template professional",
            invite_file.display()
        ));
        assert!(
            result.contains("Imported") && result.contains("events from"),
            "invite accept failed: {result}"
        );

        // Bob should now have his own identity
        assert!(
            !bob.app_runtime.store.materialized().roots_current.is_empty(),
            "Bob should have a root after invite accept"
        );
        assert!(
            !bob.app_runtime.store.materialized().personas_current.is_empty(),
            "Bob should have a persona after invite accept"
        );

        // Bob should also have Alice's persona in his store
        assert!(
            bob.app_runtime.store
                .materialized()
                .persona(&alice_persona)
                .is_some(),
            "Bob should see Alice's persona after invite accept"
        );

        let _ = fs::remove_file(&file_a);
        let _ = fs::remove_file(&sqlite_a);
        let _ = fs::remove_file(&file_b);
        let _ = fs::remove_file(&sqlite_b);
        let _ = fs::remove_file(&invite_file);
    }

    #[test]
    fn disclosure_revocation_and_issuer_verification() {
        // Alice issues a disclosure to Bob, Bob verifies it (verified), Alice revokes it,
        // Bob syncs the revocation and sees disclosure-revoked status.
        let alice_file = temp_state_file("revoke-verify-alice");
        let alice_sqlite = sqlite_path_for_local_state(&alice_file);
        let bob_file = temp_state_file("revoke-verify-bob");
        let bob_sqlite = sqlite_path_for_local_state(&bob_file);

        // Alice: create identity, write record, issue artifact
        let (artifact_id, _alice_persona_id, export_path) = {
            let mut alice = DemoApp::bootstrap(Some(alice_file.clone()), false);
            let init = alice.handle_command("init --name Alice --template professional");
            assert!(init.contains("Identity initialized"), "alice init: {init}");

            let alice_persona = alice.personas.first().expect("alice persona").id.clone();

            let json = r#"{"name":"Alice","email":"alice@example.com"}"#;
            let write = alice.handle_command(&format!(
                "vault write-record --namespace persona:{} --object obj-alice --schema com.example/card --app com.example --json {}",
                alice_persona, json
            ));
            assert!(write.contains("wrote record"), "write: {write}");

            let add_tmpl = alice.handle_command(&format!(
                "vault template add --id tmpl-pub --object obj-alice --schema com.example/card --audience service --namespace persona:{} --field name",
                alice_persona
            ));
            assert!(add_tmpl.contains("added template"), "add_tmpl: {add_tmpl}");

            let issue = alice.handle_command(&format!(
                "vault issue --namespace persona:{} --template tmpl-pub --recipient bob-svc",
                alice_persona
            ));
            assert!(issue.contains("issued artifact"), "issue: {issue}");
            let art_id = issue
                .trim()
                .split('\t')
                .nth(1)
                .expect("artifact id")
                .to_string();

            let export_file = std::env::temp_dir().join(format!(
                "revoke-verify-{}.artifact",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let export = alice.handle_command(&format!(
                "vault export-artifact --artifact {} --out {}",
                art_id,
                export_file.display()
            ));
            assert!(export.contains("exported"), "export: {export}");

            (art_id, alice_persona, export_file)
        };

        // Bob: import Alice's events + artifact, verify shows "verified"
        {
            let mut bob = DemoApp::bootstrap(Some(bob_file.clone()), false);
            bob.handle_command("init --name Bob");

            let sync = bob.handle_command(&format!("sync apply --state {}", alice_file.display()));
            assert!(!sync.contains("Failed"), "sync: {sync}");

            let import = bob.handle_command(&format!(
                "vault import-artifact --file {}",
                export_path.display()
            ));
            assert!(import.contains("imported"), "import: {import}");

            // Verification should show "verified" since Alice's identity is synced
            let received = bob.handle_command("vault received");
            assert!(received.contains(&artifact_id), "received: {received}");
            assert!(
                received.contains("verification verified"),
                "should be verified: {received}"
            );

            let show =
                bob.handle_command(&format!("vault show-received --artifact {}", artifact_id));
            assert!(
                show.contains("Verification: verified"),
                "detail should show verified: {show}"
            );
        }

        // Alice: revoke the disclosure
        {
            let mut alice = DemoApp::with_state_file(alice_file.clone());
            let revoke = alice.handle_command(&format!(
                "vault revoke --artifact {} --reason credential-expired",
                artifact_id
            ));
            assert!(revoke.contains("revoked disclosure"), "revoke: {revoke}");
            assert!(
                revoke.contains(&artifact_id),
                "revoke contains artifact: {revoke}"
            );

            // Double revoke should warn
            let double = alice.handle_command(&format!(
                "vault revoke --artifact {} --reason duplicate",
                artifact_id
            ));
            assert!(
                double.contains("already revoked"),
                "double revoke: {double}"
            );
        }

        // Bob: sync Alice's revocation event, verify shows "disclosure-revoked"
        {
            let mut bob = DemoApp::with_state_file(bob_file.clone());
            let sync = bob.handle_command(&format!("sync apply --state {}", alice_file.display()));
            assert!(!sync.contains("Failed"), "sync revocation: {sync}");

            let received = bob.handle_command("vault received");
            assert!(
                received.contains("verification disclosure-revoked"),
                "should be revoked: {received}"
            );

            let show =
                bob.handle_command(&format!("vault show-received --artifact {}", artifact_id));
            assert!(
                show.contains("Verification: disclosure-revoked"),
                "detail should show revoked: {show}"
            );
        }

        let _ = fs::remove_file(&alice_file);
        let _ = fs::remove_file(&alice_sqlite);
        let _ = fs::remove_file(&bob_file);
        let _ = fs::remove_file(&bob_sqlite);
        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn issuer_verification_unknown_when_identity_not_synced() {
        // Bob receives an artifact but hasn't synced Alice's identity events.
        // Verification should show "issuer-unknown".
        let alice_file = temp_state_file("verify-unknown-alice");
        let alice_sqlite = sqlite_path_for_local_state(&alice_file);
        let bob_file = temp_state_file("verify-unknown-bob");
        let bob_sqlite = sqlite_path_for_local_state(&bob_file);

        let (_artifact_id, export_path) = {
            let mut alice = DemoApp::bootstrap(Some(alice_file.clone()), false);
            alice.handle_command("init --name Alice --template professional");
            let alice_persona = alice.personas.first().expect("alice persona").id.clone();

            let json = r#"{"name":"Alice"}"#;
            alice.handle_command(&format!(
                "vault write-record --namespace persona:{} --object obj --schema com.example/card --app com.example --json {}",
                alice_persona, json
            ));
            alice.handle_command(&format!(
                "vault template add --id tmpl --object obj --schema com.example/card --audience service --namespace persona:{} --field name",
                alice_persona
            ));
            let issue = alice.handle_command(&format!(
                "vault issue --namespace persona:{} --template tmpl --recipient bob-svc",
                alice_persona
            ));
            let art_id = issue.trim().split('\t').nth(1).expect("art id").to_string();

            let export_file = std::env::temp_dir().join(format!(
                "verify-unknown-{}.artifact",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            alice.handle_command(&format!(
                "vault export-artifact --artifact {} --out {}",
                art_id,
                export_file.display()
            ));
            (art_id, export_file)
        };

        // Bob: import artifact WITHOUT syncing Alice's events
        {
            let mut bob = DemoApp::bootstrap(Some(bob_file.clone()), false);
            bob.handle_command("init --name Bob");

            let import = bob.handle_command(&format!(
                "vault import-artifact --file {}",
                export_path.display()
            ));
            assert!(import.contains("imported"), "import: {import}");

            let received = bob.handle_command("vault received");
            assert!(
                received.contains("verification issuer-unknown"),
                "should be issuer-unknown: {received}"
            );
        }

        let _ = fs::remove_file(&alice_file);
        let _ = fs::remove_file(&alice_sqlite);
        let _ = fs::remove_file(&bob_file);
        let _ = fs::remove_file(&bob_sqlite);
        let _ = fs::remove_file(&export_path);
    }

    #[test]
    fn vault_store_and_export_file_roundtrip() {
        let dir = std::env::temp_dir();
        let input_file = dir.join("test-vault-input.pdf");
        let output_file = dir.join("test-vault-output.pdf");
        let _ = fs::remove_file(&input_file);
        let _ = fs::remove_file(&output_file);

        let mut app = DemoApp::ephemeral();

        // Create a test file with binary content
        let test_content = b"fake PDF content for roundtrip test -- binary \x00\x01\x02 bytes";
        fs::write(&input_file, test_content).unwrap();

        // Store the file under persona namespace (seeded DemoApp has persona-professional with device access)
        let result = app.handle_command(&format!(
            "vault store --file {} --object test-doc --namespace persona:persona-professional",
            input_file.display()
        ));
        assert!(result.contains("stored file"), "store: {result}");
        assert!(result.contains("test-doc"), "store object id: {result}");

        // Export the file
        let result = app.handle_command(&format!(
            "vault export-file --object test-doc --out {} --namespace persona:persona-professional",
            output_file.display()
        ));
        assert!(result.contains("exported file"), "export: {result}");

        // Verify roundtrip
        let exported = fs::read(&output_file).unwrap();
        assert_eq!(exported, test_content, "roundtrip content should match");

        let _ = fs::remove_file(&input_file);
        let _ = fs::remove_file(&output_file);
    }

    #[test]
    fn service_bind_list_and_unbind_round_trip() {
        let mut app = DemoApp::ephemeral();

        let bind = app.handle_command(
            "service bind --persona persona-professional --kind oauth2 --label GitHub --account alice --endpoint https://github.com",
        );
        assert!(bind.contains("bound service\t"), "bind: {bind}");
        assert!(bind.contains("oauth2"));
        assert!(bind.contains("alice"));

        let list = app.handle_command("service list");
        assert!(list.contains("oauth2"));
        assert!(list.contains("GitHub"));
        assert!(list.contains("alice"));

        let list_persona = app.handle_command("service list --persona persona-professional");
        assert!(list_persona.contains("oauth2"));

        let binding_id = bind
            .split('\t')
            .nth(1)
            .expect("binding id in output")
            .trim();
        let unbind = app.handle_command(&format!("service unbind --id {binding_id}"));
        assert!(unbind.contains("unbound service\t"), "unbind: {unbind}");

        let list_after = app.handle_command("service list");
        assert!(list_after.contains("No service bindings"));
    }

    #[test]
    fn import_passwords_stores_credentials_as_claims() {
        let mut app = DemoApp::ephemeral();

        let csv_file = std::env::temp_dir().join("emberlink-test-bitwarden.csv");
        fs::write(
            &csv_file,
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPersonal,0,login,GitHub,work account,,,https://github.com,alice,secret123,\nPersonal,0,login,GitLab,,,,https://gitlab.com,alice,pass456,\n",
        )
        .unwrap();

        let result = app.handle_command(&format!(
            "import passwords --persona persona-professional --format bitwarden --file {}",
            csv_file.display()
        ));
        assert!(
            result.contains("imported 2 of 2 credentials"),
            "import: {result}"
        );

        let list = app.handle_command("claim list --persona persona-professional");
        assert!(list.contains("pw-github"), "list: {list}");
        assert!(list.contains("pw-gitlab"), "list: {list}");

        let _ = fs::remove_file(&csv_file);
    }
}
