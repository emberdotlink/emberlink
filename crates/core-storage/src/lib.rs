use std::collections::{BTreeMap, BTreeSet};

use core_crypto::{
    Ed25519Verifier, EncryptedContent, PublicKey, Signature, Signer as CryptoSigner, Verifier,
    decrypt_content, encrypt_content, sha256_digest_hex, unwrap_secret_with_identity,
    wrap_secret_to_recipient,
};
use core_event_types::{
    ChunkReference, ClaimMeta, DurabilityPolicy, EventBody, FileManifest, ManifestDeviceAccess,
    PayloadKind, PresentationArtifact, PresentationAudienceKind, PresentationTemplate,
    RetentionPolicy, StorageLedgerEntry, StorageLedgerUpdatedEvent, StorageManifestPublishedEvent,
    StorageRelationship, StorageRelationshipCreatedEvent, StructuredEncoding, StructuredRecordMeta,
    VaultCatalog, VaultNamespace, VaultObject, VaultObjectClass, VaultRevision,
};
use core_types::{CanonicalEncode, Validate, ValidationError, bytes_to_hex, hex_to_bytes};
use serde_json::{Map as JsonMap, Value as JsonValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlock {
    pub chunk: ChunkReference,
    pub encrypted: EncryptedContent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationArtifactEnvelope {
    pub artifact: PresentationArtifact,
    pub payload_bytes: Vec<u8>,
    pub issuer_persona_id: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub issuer_signature_hex: String,
}

impl PresentationArtifactEnvelope {
    /// Canonical signing payload using length-prefixed binary encoding.
    ///
    /// Each field is encoded as:
    ///   [4-byte big-endian key length][key bytes][4-byte big-endian value length][value bytes]
    ///
    /// This prevents injection attacks where a field value containing the field
    /// separator could shift the parsing boundary and forge a different payload.
    pub fn signing_payload(&self) -> Vec<u8> {
        let artifact_hex = bytes_to_hex(&self.artifact.canonical_encode());
        let payload_hex = bytes_to_hex(&self.payload_bytes);
        let fields: &[(&[u8], &[u8])] = &[
            (b"type", b"presentation-artifact-envelope"),
            (b"artifact_payload_hex", artifact_hex.as_bytes()),
            (b"payload_hex", payload_hex.as_bytes()),
            (b"issuer_persona_id", self.issuer_persona_id.as_bytes()),
            (b"issuer_key_id", self.issuer_key_id.as_bytes()),
            (b"issuer_public_key", self.issuer_public_key.as_bytes()),
        ];
        let mut buf = Vec::with_capacity(256);
        for (key, val) in fields {
            buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(val.len() as u32).to_be_bytes());
            buf.extend_from_slice(val);
        }
        buf
    }
}

pub fn sign_presentation_artifact_envelope(
    artifact: &PresentationArtifact,
    payload_bytes: Vec<u8>,
    issuer_persona_id: impl Into<String>,
    issuer_key_id: impl Into<String>,
    signer: &impl CryptoSigner,
) -> Result<PresentationArtifactEnvelope, ValidationError> {
    let mut envelope = PresentationArtifactEnvelope {
        artifact: artifact.clone(),
        payload_bytes,
        issuer_persona_id: issuer_persona_id.into(),
        issuer_key_id: issuer_key_id.into(),
        issuer_public_key: signer.public_key().0,
        issuer_signature_hex: String::new(),
    };
    validate_presentation_artifact_envelope(&envelope, false)?;
    envelope.issuer_signature_hex = signer.sign(&envelope.signing_payload()).0;
    verify_presentation_artifact_envelope(&envelope)?;
    Ok(envelope)
}

pub fn verify_presentation_artifact_envelope(
    envelope: &PresentationArtifactEnvelope,
) -> Result<(), ValidationError> {
    validate_presentation_artifact_envelope(envelope, true)?;
    let verifier = Ed25519Verifier;
    let signature = Signature(envelope.issuer_signature_hex.clone());
    let public_key = PublicKey(envelope.issuer_public_key.clone());
    if !verifier.verify(&public_key, &envelope.signing_payload(), &signature) {
        return Err(ValidationError::new(
            "presentation artifact envelope signature verification failed",
        ));
    }
    Ok(())
}

fn validate_presentation_artifact_envelope(
    envelope: &PresentationArtifactEnvelope,
    require_signature: bool,
) -> Result<(), ValidationError> {
    envelope.artifact.validate()?;
    if envelope.payload_bytes.is_empty() {
        return Err(ValidationError::new(
            "presentation artifact envelope payload must not be empty",
        ));
    }
    if envelope.issuer_persona_id.trim().is_empty() {
        return Err(ValidationError::new(
            "presentation artifact envelope issuer persona id must not be empty",
        ));
    }
    if envelope.issuer_key_id.trim().is_empty() {
        return Err(ValidationError::new(
            "presentation artifact envelope issuer key id must not be empty",
        ));
    }
    if envelope.issuer_public_key.trim().is_empty() {
        return Err(ValidationError::new(
            "presentation artifact envelope issuer public key must not be empty",
        ));
    }
    if require_signature && envelope.issuer_signature_hex.trim().is_empty() {
        return Err(ValidationError::new(
            "presentation artifact envelope issuer signature must not be empty",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestKeyRecipient {
    pub device_id: String,
    pub recipient_public_key: String,
}

pub fn manifest_key_recipient(
    device_id: impl Into<String>,
    recipient_public_key: impl Into<String>,
) -> ManifestKeyRecipient {
    ManifestKeyRecipient {
        device_id: device_id.into(),
        recipient_public_key: recipient_public_key.into(),
    }
}

pub fn wrap_manifest_key_for_recipients(
    recipients: &[ManifestKeyRecipient],
    manifest_key: &str,
) -> Result<Vec<ManifestDeviceAccess>, ValidationError> {
    if recipients.is_empty() {
        return Err(ValidationError::new(
            "manifest recipients must not be empty",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut access = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        if recipient.device_id.trim().is_empty() {
            return Err(ValidationError::new(
                "manifest recipient device id must not be empty",
            ));
        }
        if recipient.recipient_public_key.trim().is_empty() {
            return Err(ValidationError::new(
                "manifest recipient public key must not be empty",
            ));
        }
        if !seen.insert(recipient.device_id.as_str()) {
            return Err(ValidationError::new(format!(
                "duplicate manifest recipient device id: {}",
                recipient.device_id
            )));
        }
        access.push(wrap_manifest_key_access(
            &recipient.device_id,
            &recipient.recipient_public_key,
            manifest_key,
        )?);
    }
    Ok(access)
}

pub fn create_vault_object(
    id: impl Into<String>,
    namespace: VaultNamespace,
    class: VaultObjectClass,
    initial_revision_id: impl Into<String>,
    created_at: u64,
    durability: DurabilityPolicy,
    retention: RetentionPolicy,
) -> Result<VaultObject, ValidationError> {
    let object = VaultObject {
        id: id.into(),
        namespace,
        class,
        latest_revision_id: initial_revision_id.into(),
        created_at,
        updated_at: created_at,
        durability,
        retention,
        deleted: false,
    };
    object.validate()?;
    Ok(object)
}

#[allow(clippy::too_many_arguments)]
pub fn create_vault_revision(
    id: impl Into<String>,
    object_id: impl Into<String>,
    manifest_id: impl Into<String>,
    payload_kind: PayloadKind,
    content_type: impl Into<String>,
    created_at: u64,
    created_by_device_id: impl Into<String>,
    parent_revision_id: Option<String>,
    structured_record: Option<StructuredRecordMeta>,
    claim: Option<ClaimMeta>,
) -> Result<VaultRevision, ValidationError> {
    let revision = VaultRevision {
        id: id.into(),
        object_id: object_id.into(),
        manifest_id: manifest_id.into(),
        payload_kind,
        content_type: content_type.into(),
        created_at,
        created_by_device_id: created_by_device_id.into(),
        parent_revision_id,
        structured_record,
        claim,
    };
    revision.validate()?;
    Ok(revision)
}

pub fn advance_vault_object(
    object: &mut VaultObject,
    revision_id: impl Into<String>,
    updated_at: u64,
) -> Result<(), ValidationError> {
    object.latest_revision_id = revision_id.into();
    object.updated_at = updated_at;
    object.validate()
}

pub fn tombstone_vault_object(
    object: &mut VaultObject,
    updated_at: u64,
) -> Result<(), ValidationError> {
    object.deleted = true;
    object.updated_at = updated_at;
    object.validate()
}

pub fn create_presentation_template(
    id: impl Into<String>,
    namespace: VaultNamespace,
    source_object_id: impl Into<String>,
    schema_id: impl Into<String>,
    audience_kind: PresentationAudienceKind,
    field_paths: Vec<String>,
    expires_after_secs: Option<u64>,
) -> Result<PresentationTemplate, ValidationError> {
    let template = PresentationTemplate {
        id: id.into(),
        namespace,
        source_object_id: source_object_id.into(),
        schema_id: schema_id.into(),
        audience_kind,
        field_paths,
        expires_after_secs,
    };
    template.validate()?;
    Ok(template)
}

#[allow(clippy::too_many_arguments)]
pub fn create_presentation_artifact(
    id: impl Into<String>,
    source_object_id: impl Into<String>,
    source_revision_id: impl Into<String>,
    recipient_kind: PresentationAudienceKind,
    recipient_id: impl Into<String>,
    schema_id: impl Into<String>,
    manifest_id: impl Into<String>,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Result<PresentationArtifact, ValidationError> {
    let artifact = PresentationArtifact {
        id: id.into(),
        source_object_id: source_object_id.into(),
        source_revision_id: source_revision_id.into(),
        recipient_kind,
        recipient_id: recipient_id.into(),
        schema_id: schema_id.into(),
        manifest_id: manifest_id.into(),
        issued_at,
        expires_at,
    };
    artifact.validate()?;
    Ok(artifact)
}

pub fn encode_presentation_artifact_envelope(envelope: &PresentationArtifactEnvelope) -> Vec<u8> {
    verify_presentation_artifact_envelope(envelope)
        .expect("presentation artifact envelope must verify before encoding");
    format!(
        "type=presentation-artifact-envelope\nartifact_payload_hex={}\npayload_hex={}\nissuer_persona_id={}\nissuer_key_id={}\nissuer_public_key={}\nissuer_signature_hex={}\n",
        bytes_to_hex(&envelope.artifact.canonical_encode()),
        bytes_to_hex(&envelope.payload_bytes),
        envelope.issuer_persona_id,
        envelope.issuer_key_id,
        envelope.issuer_public_key,
        envelope.issuer_signature_hex,
    )
    .into_bytes()
}

pub fn decode_presentation_artifact_envelope(
    payload: &[u8],
) -> Result<PresentationArtifactEnvelope, ValidationError> {
    let text = std::str::from_utf8(payload)
        .map_err(|err| ValidationError::new(format!("decode artifact envelope utf8: {err}")))?;
    let mut saw_type = false;
    let mut artifact_payload_hex = None;
    let mut payload_hex = None;
    let mut issuer_persona_id = None;
    let mut issuer_key_id = None;
    let mut issuer_public_key = None;
    let mut issuer_signature_hex = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(ValidationError::new(
                "artifact envelope lines must use key=value form",
            ));
        };
        match key {
            "type" if value == "presentation-artifact-envelope" => saw_type = true,
            "artifact_payload_hex" => artifact_payload_hex = Some(value.to_string()),
            "payload_hex" => payload_hex = Some(value.to_string()),
            "issuer_persona_id" => issuer_persona_id = Some(value.to_string()),
            "issuer_key_id" => issuer_key_id = Some(value.to_string()),
            "issuer_public_key" => issuer_public_key = Some(value.to_string()),
            "issuer_signature_hex" => issuer_signature_hex = Some(value.to_string()),
            _ => {}
        }
    }
    if !saw_type {
        return Err(ValidationError::new(
            "artifact envelope missing presentation-artifact-envelope type marker",
        ));
    }
    let artifact_payload_hex = artifact_payload_hex
        .ok_or_else(|| ValidationError::new("artifact envelope missing artifact_payload_hex"))?;
    let payload_hex =
        payload_hex.ok_or_else(|| ValidationError::new("artifact envelope missing payload_hex"))?;
    let envelope = PresentationArtifactEnvelope {
        artifact: PresentationArtifact::decode_canonical(&hex_to_bytes(&artifact_payload_hex)?)?,
        payload_bytes: hex_to_bytes(&payload_hex)?,
        issuer_persona_id: issuer_persona_id
            .ok_or_else(|| ValidationError::new("artifact envelope missing issuer_persona_id"))?,
        issuer_key_id: issuer_key_id
            .ok_or_else(|| ValidationError::new("artifact envelope missing issuer_key_id"))?,
        issuer_public_key: issuer_public_key
            .ok_or_else(|| ValidationError::new("artifact envelope missing issuer_public_key"))?,
        issuer_signature_hex: issuer_signature_hex.ok_or_else(|| {
            ValidationError::new("artifact envelope missing issuer_signature_hex")
        })?,
    };
    verify_presentation_artifact_envelope(&envelope)?;
    Ok(envelope)
}

pub fn materialize_presentation_payload_json(
    source_json: &[u8],
    template: &PresentationTemplate,
) -> Result<Vec<u8>, ValidationError> {
    template.validate()?;
    let source = serde_json::from_slice::<JsonValue>(source_json)
        .map_err(|err| ValidationError::new(format!("decode presentation source json: {err}")))?;
    if !source.is_object() {
        return Err(ValidationError::new(
            "presentation source payload must be a json object",
        ));
    }

    let mut output = JsonValue::Object(JsonMap::new());
    let mut field_paths = template.field_paths.clone();
    field_paths.sort();
    for field_path in field_paths {
        let selected = select_json_field_path(&source, &field_path)?;
        insert_json_field_path(&mut output, &field_path, selected)?;
    }

    serde_json::to_vec(&output)
        .map_err(|err| ValidationError::new(format!("encode presentation payload json: {err}")))
}

#[allow(clippy::too_many_arguments)]
pub fn build_presentation_artifact_manifest(
    artifact_id: impl Into<String>,
    manifest_id: impl Into<String>,
    source_revision: &VaultRevision,
    template: &PresentationTemplate,
    recipient_id: impl Into<String>,
    issued_at: u64,
    expires_at: Option<u64>,
    source_json: &[u8],
    content_key: &str,
    authorized_devices: Vec<ManifestDeviceAccess>,
) -> Result<(PresentationArtifact, FileManifest, Vec<EncryptedBlock>), ValidationError> {
    if source_revision.payload_kind != PayloadKind::StructuredRecord {
        return Err(ValidationError::new(
            "presentation artifacts require a structured-record source revision",
        ));
    }
    if source_revision.object_id != template.source_object_id {
        return Err(ValidationError::new(
            "presentation template source object must match source revision object",
        ));
    }
    let Some(structured_record) = source_revision.structured_record.as_ref() else {
        return Err(ValidationError::new(
            "presentation artifacts require structured-record metadata on the source revision",
        ));
    };
    if structured_record.schema_id != template.schema_id {
        return Err(ValidationError::new(format!(
            "presentation template schema does not match source revision schema: {} != {}",
            template.schema_id, structured_record.schema_id
        )));
    }
    if structured_record.encoding != StructuredEncoding::Json {
        return Err(ValidationError::new(
            "presentation artifacts currently require json structured-record payloads",
        ));
    }

    let payload = materialize_presentation_payload_json(source_json, template)?;
    let (manifest, blocks) =
        seal_payload_manifest(manifest_id, &[payload], content_key, authorized_devices)?;
    let artifact = create_presentation_artifact(
        artifact_id,
        template.source_object_id.clone(),
        source_revision.id.clone(),
        template.audience_kind,
        recipient_id,
        template.schema_id.clone(),
        manifest.id.clone(),
        issued_at,
        expires_at,
    )?;

    Ok((artifact, manifest, blocks))
}

pub fn create_vault_catalog(namespace: VaultNamespace) -> Result<VaultCatalog, ValidationError> {
    let catalog = VaultCatalog {
        namespace,
        objects: Vec::new(),
        revisions: Vec::new(),
    };
    catalog.validate()?;
    Ok(catalog)
}

pub fn add_vault_object(
    catalog: &mut VaultCatalog,
    object: VaultObject,
) -> Result<(), ValidationError> {
    object.validate()?;
    if object.namespace != catalog.namespace {
        return Err(ValidationError::new(
            "vault object namespace must match catalog namespace",
        ));
    }
    if catalog
        .objects
        .iter()
        .any(|existing| existing.id == object.id)
    {
        return Err(ValidationError::new(format!(
            "vault object already exists: {}",
            object.id
        )));
    }
    catalog.objects.push(object);
    Ok(())
}

pub fn add_vault_object_with_initial_revision(
    catalog: &mut VaultCatalog,
    object: VaultObject,
    revision: VaultRevision,
) -> Result<(), ValidationError> {
    object.validate()?;
    revision.validate()?;
    if object.namespace != catalog.namespace {
        return Err(ValidationError::new(
            "vault object namespace must match catalog namespace",
        ));
    }
    if object.id != revision.object_id {
        return Err(ValidationError::new(
            "initial vault revision must belong to the inserted object",
        ));
    }
    if object.latest_revision_id != revision.id {
        return Err(ValidationError::new(
            "vault object latest revision must match inserted initial revision",
        ));
    }
    if revision.parent_revision_id.is_some() {
        return Err(ValidationError::new(
            "initial vault revision must not declare a parent revision",
        ));
    }
    if catalog
        .objects
        .iter()
        .any(|existing| existing.id == object.id)
    {
        return Err(ValidationError::new(format!(
            "vault object already exists: {}",
            object.id
        )));
    }
    if catalog
        .revisions
        .iter()
        .any(|existing| existing.id == revision.id)
    {
        return Err(ValidationError::new(format!(
            "vault revision already exists: {}",
            revision.id
        )));
    }

    let mut candidate = catalog.clone();
    candidate.objects.push(object);
    candidate.revisions.push(revision);
    candidate.validate()?;
    *catalog = candidate;
    Ok(())
}

pub fn add_vault_revision(
    catalog: &mut VaultCatalog,
    revision: VaultRevision,
) -> Result<(), ValidationError> {
    revision.validate()?;
    if catalog
        .revisions
        .iter()
        .any(|existing| existing.id == revision.id)
    {
        return Err(ValidationError::new(format!(
            "vault revision already exists: {}",
            revision.id
        )));
    }
    let object = catalog
        .objects
        .iter_mut()
        .find(|object| object.id == revision.object_id)
        .ok_or_else(|| {
            ValidationError::new(format!(
                "vault revision references unknown object: {}",
                revision.object_id
            ))
        })?;
    if object.deleted {
        return Err(ValidationError::new(format!(
            "vault object is deleted: {}",
            object.id
        )));
    }
    let has_existing_revisions = catalog
        .revisions
        .iter()
        .any(|existing| existing.object_id == revision.object_id);
    if !has_existing_revisions && object.latest_revision_id != revision.id {
        return Err(ValidationError::new(
            "initial vault revision must match the object's latest revision",
        ));
    }
    object.latest_revision_id = revision.id.clone();
    object.updated_at = revision.created_at;
    catalog.revisions.push(revision);
    catalog.validate()
}

pub fn create_relationship(
    id: impl Into<String>,
    local_peer_id: impl Into<String>,
    remote_peer_id: impl Into<String>,
) -> StorageRelationship {
    StorageRelationship {
        id: id.into(),
        local_peer_id: local_peer_id.into(),
        remote_peer_id: remote_peer_id.into(),
        approved: true,
    }
}

pub fn manifest_device_access(
    device_id: impl Into<String>,
    wrapped_manifest_key_hex: impl Into<String>,
) -> ManifestDeviceAccess {
    ManifestDeviceAccess {
        device_id: device_id.into(),
        wrapped_manifest_key_hex: wrapped_manifest_key_hex.into(),
    }
}

pub fn wrap_manifest_key_access(
    device_id: impl Into<String>,
    recipient_public_key: &str,
    manifest_key: &str,
) -> Result<ManifestDeviceAccess, ValidationError> {
    Ok(manifest_device_access(
        device_id,
        wrap_secret_to_recipient(recipient_public_key, manifest_key.as_bytes())?,
    ))
}

pub fn unwrap_manifest_key_access(
    access: &ManifestDeviceAccess,
    identity_private_key: &str,
) -> Result<String, ValidationError> {
    let unwrapped =
        unwrap_secret_with_identity(identity_private_key, &access.wrapped_manifest_key_hex)?;
    String::from_utf8(unwrapped.to_vec())
        .map_err(|err| ValidationError::new(format!("manifest key is not valid utf-8: {err}")))
}

pub fn manifest_chunk(
    manifest_id: impl Into<String>,
    chunk_id: impl Into<String>,
    ordinal: u32,
    ciphertext_bytes: u64,
) -> ChunkReference {
    ChunkReference {
        manifest_id: manifest_id.into(),
        chunk_id: chunk_id.into(),
        ordinal,
        ciphertext_bytes,
    }
}

pub fn publish_manifest(
    id: impl Into<String>,
    encrypted_root_chunk_id: impl Into<String>,
    chunks: Vec<ChunkReference>,
    authorized_devices: Vec<ManifestDeviceAccess>,
) -> FileManifest {
    let manifest = FileManifest {
        id: id.into(),
        encrypted_root_chunk_id: encrypted_root_chunk_id.into(),
        chunks,
        authorized_devices,
    };
    manifest
        .validate()
        .expect("storage manifest builder should produce valid manifest");
    manifest
}

pub fn storage_manifest_published_event(
    root_id: impl Into<String>,
    relationship_id: impl Into<String>,
    manifest: FileManifest,
) -> EventBody {
    EventBody::StorageManifestPublished(StorageManifestPublishedEvent {
        root_id: root_id.into(),
        relationship_id: relationship_id.into(),
        manifest,
    })
}

pub fn ledger_delta(
    relationship_id: impl Into<String>,
    stored_bytes_delta: i64,
) -> StorageLedgerEntry {
    StorageLedgerEntry {
        relationship_id: relationship_id.into(),
        stored_bytes_delta,
    }
}

pub fn storage_relationship_created_event(
    root_id: impl Into<String>,
    relationship: StorageRelationship,
) -> EventBody {
    EventBody::StorageRelationshipCreated(StorageRelationshipCreatedEvent {
        root_id: root_id.into(),
        relationship,
    })
}

pub fn storage_ledger_updated_event(
    root_id: impl Into<String>,
    entry: StorageLedgerEntry,
) -> EventBody {
    EventBody::StorageLedgerUpdated(StorageLedgerUpdatedEvent {
        root_id: root_id.into(),
        entry,
    })
}

pub fn encrypt_block(
    manifest_id: impl Into<String>,
    ordinal: u32,
    plaintext: &[u8],
    content_key: &str,
) -> Result<EncryptedBlock, ValidationError> {
    let manifest_id = manifest_id.into();
    let aad = block_aad(&manifest_id, ordinal);
    let encrypted = encrypt_content(content_key, plaintext, aad.as_bytes())?;
    let chunk_id = format!("blk-{}", sha256_digest_hex(&block_id_material(&encrypted)));
    let chunk = manifest_chunk(
        manifest_id,
        chunk_id,
        ordinal,
        encrypted.ciphertext.len() as u64,
    );
    chunk.validate()?;
    Ok(EncryptedBlock { chunk, encrypted })
}

pub fn decrypt_block(
    block: &EncryptedBlock,
    content_key: &str,
) -> Result<Vec<u8>, ValidationError> {
    let aad = block_aad(&block.chunk.manifest_id, block.chunk.ordinal);
    decrypt_content(content_key, &block.encrypted, aad.as_bytes())
}

pub fn seal_vault_catalog(
    manifest_id: impl Into<String>,
    catalog: &VaultCatalog,
    content_key: &str,
    authorized_devices: Vec<ManifestDeviceAccess>,
) -> Result<(FileManifest, Vec<EncryptedBlock>), ValidationError> {
    catalog.validate()?;
    let manifest_id = manifest_id.into();
    let block = encrypt_block(&manifest_id, 0, &catalog.canonical_encode(), content_key)?;
    let manifest = publish_manifest(
        manifest_id,
        block.chunk.chunk_id.clone(),
        vec![block.chunk.clone()],
        authorized_devices,
    );
    Ok((manifest, vec![block]))
}

pub fn seal_payload_manifest(
    manifest_id: impl Into<String>,
    plaintext_chunks: &[Vec<u8>],
    content_key: &str,
    authorized_devices: Vec<ManifestDeviceAccess>,
) -> Result<(FileManifest, Vec<EncryptedBlock>), ValidationError> {
    if plaintext_chunks.is_empty() {
        return Err(ValidationError::new(
            "payload manifests require at least one plaintext chunk",
        ));
    }

    let manifest_id = manifest_id.into();
    let mut blocks = Vec::with_capacity(plaintext_chunks.len());
    for (ordinal, plaintext) in plaintext_chunks.iter().enumerate() {
        blocks.push(encrypt_block(
            &manifest_id,
            ordinal as u32,
            plaintext,
            content_key,
        )?);
    }

    let manifest = publish_manifest(
        manifest_id,
        blocks[0].chunk.chunk_id.clone(),
        blocks.iter().map(|block| block.chunk.clone()).collect(),
        authorized_devices,
    );
    Ok((manifest, blocks))
}

pub fn open_payload_manifest(
    manifest: &FileManifest,
    blocks: &[EncryptedBlock],
    content_key: &str,
) -> Result<Vec<Vec<u8>>, ValidationError> {
    manifest.validate()?;
    let blocks_by_chunk = blocks
        .iter()
        .map(|block| (block.chunk.chunk_id.as_str(), block))
        .collect::<BTreeMap<_, _>>();
    let mut plaintext_chunks = Vec::with_capacity(manifest.chunks.len());

    for chunk in &manifest.chunks {
        let block = blocks_by_chunk
            .get(chunk.chunk_id.as_str())
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "payload manifest chunk is missing encrypted content: {}",
                    chunk.chunk_id
                ))
            })?;
        if block.chunk != *chunk {
            return Err(ValidationError::new(format!(
                "payload block metadata does not match manifest chunk: {}",
                chunk.chunk_id
            )));
        }
        plaintext_chunks.push(decrypt_block(block, content_key)?);
    }

    Ok(plaintext_chunks)
}

pub fn open_vault_catalog(
    manifest: &FileManifest,
    blocks: &[EncryptedBlock],
    content_key: &str,
) -> Result<VaultCatalog, ValidationError> {
    manifest.validate()?;
    if manifest.chunks.len() != 1 {
        return Err(ValidationError::new(
            "vault catalog manifests currently require exactly one chunk",
        ));
    }
    let root_chunk = manifest
        .chunks
        .iter()
        .find(|chunk| chunk.chunk_id == manifest.encrypted_root_chunk_id && chunk.ordinal == 0)
        .ok_or_else(|| {
            ValidationError::new("vault catalog manifest root chunk must exist at ordinal zero")
        })?;
    let block = blocks
        .iter()
        .find(|block| block.chunk == *root_chunk)
        .ok_or_else(|| ValidationError::new("vault catalog root block is missing"))?;
    let plaintext = decrypt_block(block, content_key)?;
    VaultCatalog::decode_canonical(&plaintext)
}

pub fn retained_vault_revision_ids(
    catalog: &VaultCatalog,
) -> Result<BTreeSet<String>, ValidationError> {
    catalog.validate()?;
    let revisions_by_id = catalog
        .revisions
        .iter()
        .map(|revision| (revision.id.clone(), revision))
        .collect::<BTreeMap<_, _>>();
    let mut retained = BTreeSet::new();

    for object in &catalog.objects {
        if object.deleted {
            continue;
        }
        let retain_limit = match object.retention {
            RetentionPolicy::KeepLatest => Some(1usize),
            RetentionPolicy::KeepLastN(count) => Some(count as usize),
            RetentionPolicy::KeepAll => None,
        };
        let mut retained_count = 0usize;
        let mut next_revision_id = Some(object.latest_revision_id.clone());
        while let Some(revision_id) = next_revision_id {
            let revision = revisions_by_id.get(&revision_id).ok_or_else(|| {
                ValidationError::new(format!(
                    "vault retention references unknown revision: {revision_id}"
                ))
            })?;
            retained.insert(revision_id.clone());
            retained_count += 1;
            if retain_limit.is_some_and(|limit| retained_count >= limit) {
                break;
            }
            next_revision_id = revision.parent_revision_id.clone();
        }
    }

    Ok(retained)
}

pub fn retained_vault_manifest_ids(
    catalog: &VaultCatalog,
) -> Result<BTreeSet<String>, ValidationError> {
    let retained_revision_ids = retained_vault_revision_ids(catalog)?;
    Ok(catalog
        .revisions
        .iter()
        .filter(|revision| retained_revision_ids.contains(&revision.id))
        .map(|revision| revision.manifest_id.clone())
        .collect())
}

pub fn collectable_manifest_ids(
    catalog: &VaultCatalog,
    manifests: &[FileManifest],
) -> Result<BTreeSet<String>, ValidationError> {
    let retained_manifest_ids = retained_vault_manifest_ids(catalog)?;
    let available_manifest_ids = manifests
        .iter()
        .map(|manifest| manifest.id.clone())
        .collect::<BTreeSet<_>>();
    for manifest_id in &retained_manifest_ids {
        if !available_manifest_ids.contains(manifest_id) {
            return Err(ValidationError::new(format!(
                "retained manifest is missing from manifest set: {manifest_id}"
            )));
        }
    }

    Ok(available_manifest_ids
        .difference(&retained_manifest_ids)
        .cloned()
        .collect())
}

pub fn collectable_chunk_ids(
    catalog: &VaultCatalog,
    manifests: &[FileManifest],
    local_chunk_ids: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ValidationError> {
    let retained_manifest_ids = retained_vault_manifest_ids(catalog)?;
    let collectable_manifest_ids = collectable_manifest_ids(catalog, manifests)?;
    let manifests_by_id = manifests
        .iter()
        .map(|manifest| (manifest.id.clone(), manifest))
        .collect::<BTreeMap<_, _>>();

    let retained_chunk_ids = retained_manifest_ids
        .iter()
        .filter_map(|manifest_id| manifests_by_id.get(manifest_id))
        .flat_map(|manifest| manifest.chunks.iter().map(|chunk| chunk.chunk_id.clone()))
        .collect::<BTreeSet<_>>();

    Ok(collectable_manifest_ids
        .iter()
        .filter_map(|manifest_id| manifests_by_id.get(manifest_id))
        .flat_map(|manifest| manifest.chunks.iter().map(|chunk| chunk.chunk_id.clone()))
        .filter(|chunk_id| {
            local_chunk_ids.contains(chunk_id) && !retained_chunk_ids.contains(chunk_id)
        })
        .collect())
}

pub fn grant_manifest_access(
    manifest: &mut FileManifest,
    access: ManifestDeviceAccess,
) -> Result<(), ValidationError> {
    access.validate()?;
    if manifest
        .authorized_devices
        .iter()
        .any(|existing| existing.device_id == access.device_id)
    {
        return Err(ValidationError::new(
            "manifest access for device already exists",
        ));
    }
    manifest.authorized_devices.push(access);
    manifest
        .authorized_devices
        .sort_by(|left, right| left.device_id.cmp(&right.device_id));
    manifest.validate()
}

pub fn revoke_manifest_access(
    manifest: &mut FileManifest,
    device_id: &str,
) -> Result<(), ValidationError> {
    let original_len = manifest.authorized_devices.len();
    manifest
        .authorized_devices
        .retain(|access| access.device_id != device_id);
    if manifest.authorized_devices.len() == original_len {
        return Err(ValidationError::new(format!(
            "manifest access not found for device: {device_id}"
        )));
    }
    manifest.validate()
}

pub fn replace_manifest_access(
    manifest: &mut FileManifest,
    replaced_device_id: &str,
    replacement_access: ManifestDeviceAccess,
) -> Result<(), ValidationError> {
    if !manifest
        .authorized_devices
        .iter()
        .any(|access| access.device_id == replaced_device_id)
    {
        return Err(ValidationError::new(format!(
            "manifest access not found for device: {replaced_device_id}"
        )));
    }
    revoke_manifest_access(manifest, replaced_device_id)?;
    grant_manifest_access(manifest, replacement_access)
}

pub fn rewrap_manifest_access(
    manifest: &mut FileManifest,
    access: ManifestDeviceAccess,
) -> Result<(), ValidationError> {
    access.validate()?;
    let existing = manifest
        .authorized_devices
        .iter_mut()
        .find(|existing| existing.device_id == access.device_id)
        .ok_or_else(|| {
            ValidationError::new(format!(
                "manifest access not found for device: {}",
                access.device_id
            ))
        })?;
    *existing = access;
    manifest
        .authorized_devices
        .sort_by(|left, right| left.device_id.cmp(&right.device_id));
    manifest.validate()
}

fn select_json_field_path(
    source: &JsonValue,
    field_path: &str,
) -> Result<JsonValue, ValidationError> {
    let mut current = source;
    for segment in field_path.split('.') {
        current = current
            .as_object()
            .and_then(|object| object.get(segment))
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "presentation field path not found in source json: {field_path}"
                ))
            })?;
    }
    Ok(current.clone())
}

fn insert_json_field_path(
    target: &mut JsonValue,
    field_path: &str,
    value: JsonValue,
) -> Result<(), ValidationError> {
    let segments = field_path.split('.').collect::<Vec<_>>();
    let mut current = target
        .as_object_mut()
        .ok_or_else(|| ValidationError::new("presentation output root must be a json object"))?;

    for segment in &segments[..segments.len().saturating_sub(1)] {
        let entry = current
            .entry((*segment).to_string())
            .or_insert_with(|| JsonValue::Object(JsonMap::new()));
        current = entry.as_object_mut().ok_or_else(|| {
            ValidationError::new(format!(
                "presentation field path collides with non-object output node: {field_path}"
            ))
        })?;
    }

    let leaf = segments
        .last()
        .ok_or_else(|| ValidationError::new("presentation field path must not be empty"))?;
    if current.contains_key(*leaf) {
        return Err(ValidationError::new(format!(
            "presentation field path duplicates output leaf: {field_path}"
        )));
    }
    current.insert((*leaf).to_string(), value);
    Ok(())
}

pub fn plan_restore(
    relationship: &StorageRelationship,
    manifest: &FileManifest,
) -> Result<Vec<ChunkReference>, ValidationError> {
    if !relationship.approved {
        return Err(ValidationError::new(
            "storage restore requires an explicitly approved relationship",
        ));
    }

    Ok(build_restore_plan(manifest))
}

pub fn plan_restore_for_device(
    relationship: &StorageRelationship,
    manifest: &FileManifest,
    device_id: &str,
) -> Result<Vec<ChunkReference>, ValidationError> {
    if !relationship.approved {
        return Err(ValidationError::new(
            "storage restore requires an explicitly approved relationship",
        ));
    }
    if !manifest
        .authorized_devices
        .iter()
        .any(|access| access.device_id == device_id)
    {
        return Err(ValidationError::new(format!(
            "device is not authorized to restore manifest: {device_id}"
        )));
    }

    Ok(build_restore_plan(manifest))
}

fn build_restore_plan(manifest: &FileManifest) -> Vec<ChunkReference> {
    let mut chunks = manifest.chunks.clone();
    chunks.sort_by(|left, right| {
        left.ordinal
            .cmp(&right.ordinal)
            .then_with(|| left.chunk_id.cmp(&right.chunk_id))
    });
    chunks
}

fn block_aad(manifest_id: &str, ordinal: u32) -> String {
    format!("emberlink:block:{manifest_id}:{ordinal}")
}

fn block_id_material(encrypted: &EncryptedContent) -> Vec<u8> {
    let mut material = Vec::with_capacity(encrypted.nonce_hex.len() + encrypted.ciphertext.len());
    material.extend_from_slice(encrypted.nonce_hex.as_bytes());
    material.extend_from_slice(&encrypted.ciphertext);
    material
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::{generate_content_key, generate_local_encryption_key_pair};
    use core_event_types::{EventType, VaultOwnerKind};

    fn test_namespace() -> VaultNamespace {
        VaultNamespace {
            owner_kind: VaultOwnerKind::Persona,
            owner_id: "persona-a".into(),
        }
    }

    fn test_structured_meta() -> StructuredRecordMeta {
        StructuredRecordMeta {
            schema_id: "com.example.profile/basic".into(),
            schema_version: "v1".into(),
            encoding: core_event_types::StructuredEncoding::Json,
            app_namespace: "com.example.profile".into(),
        }
    }

    fn test_chunks(manifest_id: &str, root_chunk_id: &str) -> Vec<ChunkReference> {
        vec![
            manifest_chunk(manifest_id, root_chunk_id, 0, 4096),
            manifest_chunk(manifest_id, format!("{root_chunk_id}-chunk-0002"), 2, 512),
            manifest_chunk(manifest_id, format!("{root_chunk_id}-chunk-0001"), 1, 1024),
        ]
    }

    fn test_manifest(manifest_id: &str, chunk_ids: &[&str]) -> FileManifest {
        let chunks = chunk_ids
            .iter()
            .enumerate()
            .map(|(ordinal, chunk_id)| {
                manifest_chunk(manifest_id, (*chunk_id).to_string(), ordinal as u32, 1024)
            })
            .collect::<Vec<_>>();
        publish_manifest(
            manifest_id,
            chunk_ids[0].to_string(),
            chunks,
            vec![manifest_device_access("device-a", "deadbeef")],
        )
    }

    #[test]
    fn relationship_and_manifest_keep_explicit_operator_input() {
        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        let manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        assert_eq!(relationship.id, "storage-1");
        assert_eq!(relationship.local_peer_id, "peer-a");
        assert_eq!(relationship.remote_peer_id, "peer-b");
        assert!(relationship.approved);
        assert_eq!(manifest.id, "manifest-1");
        assert_eq!(manifest.encrypted_root_chunk_id, "bafy-root-1");
        assert_eq!(manifest.chunks.len(), 3);
        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-a");
    }

    #[test]
    fn vault_object_lifecycle_advances_revision_head() {
        let mut object = create_vault_object(
            "obj-1",
            test_namespace(),
            VaultObjectClass::StructuredRecord,
            "rev-1",
            100,
            DurabilityPolicy::ReplicatedToApprovedPeers,
            RetentionPolicy::KeepLatest,
        )
        .unwrap();

        advance_vault_object(&mut object, "rev-2", 120).unwrap();

        assert_eq!(object.latest_revision_id, "rev-2");
        assert_eq!(object.updated_at, 120);
        assert!(!object.deleted);
    }

    #[test]
    fn vault_catalog_tracks_objects_and_revisions() {
        let mut catalog = create_vault_catalog(test_namespace()).unwrap();
        let object = create_vault_object(
            "obj-1",
            test_namespace(),
            VaultObjectClass::StructuredRecord,
            "rev-1",
            100,
            DurabilityPolicy::ReplicatedToApprovedPeers,
            RetentionPolicy::KeepLatest,
        )
        .unwrap();
        let revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-1",
            PayloadKind::StructuredRecord,
            "application/json",
            100,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();

        add_vault_object_with_initial_revision(&mut catalog, object, revision).unwrap();

        assert_eq!(catalog.objects.len(), 1);
        assert_eq!(catalog.revisions.len(), 1);
        assert_eq!(catalog.objects[0].latest_revision_id, "rev-1");
    }

    #[test]
    fn staged_vault_object_can_be_completed_by_initial_revision() {
        let mut catalog = create_vault_catalog(test_namespace()).unwrap();
        let object = create_vault_object(
            "obj-1",
            test_namespace(),
            VaultObjectClass::StructuredRecord,
            "rev-1",
            100,
            DurabilityPolicy::ReplicatedToApprovedPeers,
            RetentionPolicy::KeepLatest,
        )
        .unwrap();
        let revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-1",
            PayloadKind::StructuredRecord,
            "application/json",
            100,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();

        add_vault_object(&mut catalog, object).unwrap();
        add_vault_revision(&mut catalog, revision).unwrap();

        assert_eq!(catalog.objects.len(), 1);
        assert_eq!(catalog.revisions.len(), 1);
        assert_eq!(catalog.objects[0].latest_revision_id, "rev-1");
    }

    #[test]
    fn structured_vault_revision_requires_schema_metadata() {
        let revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-1",
            PayloadKind::StructuredRecord,
            "application/json",
            100,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();

        assert_eq!(revision.payload_kind, PayloadKind::StructuredRecord);
        assert_eq!(
            revision.structured_record.as_ref().unwrap().schema_id,
            "com.example.profile/basic"
        );
    }

    #[test]
    fn presentation_templates_and_artifacts_capture_controlled_disclosure() {
        let template = create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/basic",
            PresentationAudienceKind::Service,
            vec!["full_name".into(), "skills".into()],
            Some(3600),
        )
        .unwrap();
        let artifact = create_presentation_artifact(
            "artifact-1",
            "obj-1",
            "rev-3",
            PresentationAudienceKind::Service,
            "svc.example",
            "com.example.profile/basic",
            "manifest-9",
            1_000,
            Some(4_600),
        )
        .unwrap();

        assert_eq!(template.field_paths.len(), 2);
        assert_eq!(artifact.source_revision_id, "rev-3");
        assert_eq!(artifact.recipient_id, "svc.example");
    }

    #[test]
    fn presentation_payload_json_projects_selected_fields() {
        let template = create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/basic",
            PresentationAudienceKind::Service,
            vec![
                "employment.status".into(),
                "full_name".into(),
                "skills".into(),
            ],
            Some(3600),
        )
        .unwrap();
        let source = br#"{
            "full_name":"Jane Doe",
            "employment":{"status":"contractor","team":"infra"},
            "skills":["rust","distributed-systems"],
            "private":{"ssn":"000-00-0000"}
        }"#;

        let payload = materialize_presentation_payload_json(source, &template).unwrap();
        let projected = serde_json::from_slice::<JsonValue>(&payload).unwrap();

        assert_eq!(
            projected,
            serde_json::json!({
                "employment": { "status": "contractor" },
                "full_name": "Jane Doe",
                "skills": ["rust", "distributed-systems"]
            })
        );
    }

    #[test]
    fn presentation_payload_json_rejects_missing_field_paths() {
        let template = create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/basic",
            PresentationAudienceKind::Service,
            vec!["employment.status.level".into()],
            Some(3600),
        )
        .unwrap();
        let source = br#"{
            "employment":{"status":"contractor"}
        }"#;

        let err = materialize_presentation_payload_json(source, &template).unwrap_err();

        assert!(err.message.contains("presentation field path not found"));
    }

    #[test]
    fn presentation_artifact_manifest_encrypts_projected_payload() {
        let template = create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/basic",
            PresentationAudienceKind::Service,
            vec!["full_name".into(), "skills".into()],
            Some(3600),
        )
        .unwrap();
        let source_revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-source-1",
            PayloadKind::StructuredRecord,
            "application/json",
            1,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();
        let source = br#"{
            "full_name":"Jane Doe",
            "skills":["rust","distributed-systems"],
            "private":{"ssn":"000-00-0000"}
        }"#;
        let content_key = generate_content_key("presentation-artifact");

        let (artifact, manifest, blocks) = build_presentation_artifact_manifest(
            "artifact-1",
            "manifest-artifact-1",
            &source_revision,
            &template,
            "svc.example",
            10,
            Some(3700),
            source,
            &content_key,
            vec![manifest_device_access("device-a", "wrapped-manifest-key")],
        )
        .unwrap();
        let decrypted = open_payload_manifest(&manifest, &blocks, &content_key).unwrap();

        assert_eq!(artifact.source_revision_id, "rev-1");
        assert_eq!(artifact.manifest_id, "manifest-artifact-1");
        assert_eq!(artifact.recipient_id, "svc.example");
        assert_eq!(decrypted.len(), 1);
        assert_eq!(
            serde_json::from_slice::<JsonValue>(&decrypted[0]).unwrap(),
            serde_json::json!({
                "full_name": "Jane Doe",
                "skills": ["rust", "distributed-systems"]
            })
        );
    }

    #[test]
    fn presentation_artifact_manifest_rejects_mismatched_schema() {
        let template = create_presentation_template(
            "template-1",
            test_namespace(),
            "obj-1",
            "com.example.profile/public-card",
            PresentationAudienceKind::Service,
            vec!["full_name".into()],
            Some(3600),
        )
        .unwrap();
        let source_revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-source-1",
            PayloadKind::StructuredRecord,
            "application/json",
            1,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();
        let content_key = generate_content_key("presentation-artifact");

        let err = build_presentation_artifact_manifest(
            "artifact-1",
            "manifest-artifact-1",
            &source_revision,
            &template,
            "svc.example",
            10,
            Some(3700),
            br#"{"full_name":"Jane Doe"}"#,
            &content_key,
            vec![manifest_device_access("device-a", "wrapped-manifest-key")],
        )
        .unwrap_err();

        assert!(err.message.contains("schema does not match"));
    }

    #[test]
    fn presentation_artifact_envelope_round_trips() {
        let artifact = create_presentation_artifact(
            "artifact-1",
            "obj-1",
            "rev-1",
            PresentationAudienceKind::Peer,
            "persona-target",
            "com.example.profile/basic",
            "manifest-1",
            10,
            Some(20),
        )
        .unwrap();
        let key_pair = core_crypto::generate_local_key_pair("persona", "persona-issuer");
        let signer = core_crypto::LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
        let envelope = sign_presentation_artifact_envelope(
            &artifact,
            br#"{"full_name":"Jane Doe"}"#.to_vec(),
            "persona-issuer",
            key_pair.key_id.clone(),
            &signer,
        )
        .unwrap();

        let encoded = encode_presentation_artifact_envelope(&envelope);
        let decoded = decode_presentation_artifact_envelope(&encoded).unwrap();

        assert_eq!(decoded.artifact, artifact);
        assert_eq!(
            decoded.payload_bytes,
            br#"{"full_name":"Jane Doe"}"#.to_vec()
        );
        assert_eq!(decoded.issuer_persona_id, "persona-issuer");
        assert_eq!(decoded.issuer_key_id, key_pair.key_id);
    }

    #[test]
    fn presentation_artifact_envelope_rejects_tampered_payload() {
        let artifact = create_presentation_artifact(
            "artifact-1",
            "obj-1",
            "rev-1",
            PresentationAudienceKind::Peer,
            "persona-target",
            "com.example.profile/basic",
            "manifest-1",
            10,
            Some(20),
        )
        .unwrap();
        let key_pair = core_crypto::generate_local_key_pair("persona", "persona-issuer");
        let signer = core_crypto::LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
        let mut envelope = sign_presentation_artifact_envelope(
            &artifact,
            br#"{"full_name":"Jane Doe"}"#.to_vec(),
            "persona-issuer",
            key_pair.key_id.clone(),
            &signer,
        )
        .unwrap();
        envelope.payload_bytes = br#"{"full_name":"Mallory"}"#.to_vec();

        let encoded = format!(
            "type=presentation-artifact-envelope\nartifact_payload_hex={}\npayload_hex={}\nissuer_persona_id={}\nissuer_key_id={}\nissuer_public_key={}\nissuer_signature_hex={}\n",
            bytes_to_hex(&envelope.artifact.canonical_encode()),
            bytes_to_hex(&envelope.payload_bytes),
            envelope.issuer_persona_id,
            envelope.issuer_key_id,
            envelope.issuer_public_key,
            envelope.issuer_signature_hex,
        )
        .into_bytes();

        let err = decode_presentation_artifact_envelope(&encoded).unwrap_err();
        assert!(err.message.contains("signature verification failed"));
    }

    #[test]
    fn vault_catalog_round_trips_through_encrypted_manifest() {
        let mut catalog = create_vault_catalog(test_namespace()).unwrap();
        let object = create_vault_object(
            "obj-1",
            test_namespace(),
            VaultObjectClass::StructuredRecord,
            "rev-1",
            100,
            DurabilityPolicy::ReplicatedToApprovedPeers,
            RetentionPolicy::KeepLatest,
        )
        .unwrap();
        let revision = create_vault_revision(
            "rev-1",
            "obj-1",
            "manifest-record-1",
            PayloadKind::StructuredRecord,
            "application/json",
            100,
            "device-a",
            None,
            Some(test_structured_meta()),
            None,
        )
        .unwrap();
        add_vault_object_with_initial_revision(&mut catalog, object, revision).unwrap();

        let content_key = generate_content_key("vault-catalog");
        let access = manifest_device_access("device-a", "wrapped-manifest-key");
        let (manifest, blocks) =
            seal_vault_catalog("manifest-catalog-1", &catalog, &content_key, vec![access]).unwrap();

        let decoded = open_vault_catalog(&manifest, &blocks, &content_key).unwrap();

        assert_eq!(manifest.encrypted_root_chunk_id, blocks[0].chunk.chunk_id);
        assert_eq!(decoded, catalog);
    }

    #[test]
    fn payload_manifest_round_trips_through_encrypted_blocks() {
        let content_key = generate_content_key("test");
        let plaintext_chunks = vec![
            br#"{"profile":"primary"}"#.to_vec(),
            b"attachment chunk".to_vec(),
        ];
        let access = manifest_device_access("device-a", "wrapped-manifest-key");
        let (manifest, blocks) = seal_payload_manifest(
            "manifest-payload-1",
            &plaintext_chunks,
            &content_key,
            vec![access],
        )
        .unwrap();

        let decrypted = open_payload_manifest(&manifest, &blocks, &content_key).unwrap();

        assert_eq!(decrypted, plaintext_chunks);
        assert_eq!(manifest.encrypted_root_chunk_id, blocks[0].chunk.chunk_id);
        assert_eq!(manifest.chunks.len(), 2);
    }

    #[test]
    fn vault_retention_policies_select_expected_revision_sets() {
        let catalog = VaultCatalog {
            namespace: test_namespace(),
            objects: vec![
                create_vault_object(
                    "obj-latest",
                    test_namespace(),
                    VaultObjectClass::PersonaNote,
                    "rev-latest-2",
                    100,
                    DurabilityPolicy::LocalOnly,
                    RetentionPolicy::KeepLatest,
                )
                .unwrap(),
                create_vault_object(
                    "obj-last-two",
                    test_namespace(),
                    VaultObjectClass::PersonaDocument,
                    "rev-last-two-3",
                    100,
                    DurabilityPolicy::ReplicatedToApprovedPeers,
                    RetentionPolicy::KeepLastN(2),
                )
                .unwrap(),
                create_vault_object(
                    "obj-all",
                    test_namespace(),
                    VaultObjectClass::PersonaAttachment,
                    "rev-all-2",
                    100,
                    DurabilityPolicy::ReplicatedToApprovedPeers,
                    RetentionPolicy::KeepAll,
                )
                .unwrap(),
            ],
            revisions: vec![
                create_vault_revision(
                    "rev-latest-1",
                    "obj-latest",
                    "manifest-latest-1",
                    PayloadKind::StructuredRecord,
                    "application/json",
                    100,
                    "device-a",
                    None,
                    Some(test_structured_meta()),
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-latest-2",
                    "obj-latest",
                    "manifest-latest-2",
                    PayloadKind::StructuredRecord,
                    "application/json",
                    110,
                    "device-a",
                    Some("rev-latest-1".into()),
                    Some(test_structured_meta()),
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-last-two-1",
                    "obj-last-two",
                    "manifest-last-two-1",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    100,
                    "device-a",
                    None,
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-last-two-2",
                    "obj-last-two",
                    "manifest-last-two-2",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    110,
                    "device-a",
                    Some("rev-last-two-1".into()),
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-last-two-3",
                    "obj-last-two",
                    "manifest-last-two-3",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    120,
                    "device-a",
                    Some("rev-last-two-2".into()),
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-all-1",
                    "obj-all",
                    "manifest-all-1",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    100,
                    "device-a",
                    None,
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-all-2",
                    "obj-all",
                    "manifest-all-2",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    110,
                    "device-a",
                    Some("rev-all-1".into()),
                    None,
                    None,
                )
                .unwrap(),
            ],
        };

        let retained = retained_vault_revision_ids(&catalog).unwrap();

        assert_eq!(
            retained,
            BTreeSet::from([
                "rev-latest-2".to_string(),
                "rev-last-two-2".to_string(),
                "rev-last-two-3".to_string(),
                "rev-all-1".to_string(),
                "rev-all-2".to_string(),
            ])
        );
    }

    #[test]
    fn vault_gc_collects_only_unretained_unshared_chunks() {
        let catalog = VaultCatalog {
            namespace: test_namespace(),
            objects: vec![
                create_vault_object(
                    "obj-1",
                    test_namespace(),
                    VaultObjectClass::PersonaDocument,
                    "rev-2",
                    100,
                    DurabilityPolicy::ReplicatedToApprovedPeers,
                    RetentionPolicy::KeepLatest,
                )
                .unwrap(),
            ],
            revisions: vec![
                create_vault_revision(
                    "rev-1",
                    "obj-1",
                    "manifest-1",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    100,
                    "device-a",
                    None,
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-2",
                    "obj-1",
                    "manifest-2",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    110,
                    "device-a",
                    Some("rev-1".into()),
                    None,
                    None,
                )
                .unwrap(),
            ],
        };
        let manifests = vec![
            test_manifest("manifest-1", &["chunk-shared", "chunk-old-only"]),
            test_manifest("manifest-2", &["chunk-shared", "chunk-current-only"]),
        ];
        let local_chunk_ids = BTreeSet::from([
            "chunk-shared".to_string(),
            "chunk-old-only".to_string(),
            "chunk-current-only".to_string(),
        ]);

        let collectable_manifests = collectable_manifest_ids(&catalog, &manifests).unwrap();
        let collectable_chunks =
            collectable_chunk_ids(&catalog, &manifests, &local_chunk_ids).unwrap();

        assert_eq!(
            collectable_manifests,
            BTreeSet::from(["manifest-1".to_string()])
        );
        assert_eq!(
            collectable_chunks,
            BTreeSet::from(["chunk-old-only".to_string()])
        );
    }

    #[test]
    fn deleted_vault_objects_do_not_retain_revisions_or_manifests() {
        let namespace = test_namespace();
        let mut deleted_object = create_vault_object(
            "obj-deleted",
            namespace.clone(),
            VaultObjectClass::PersonaDocument,
            "rev-deleted-1",
            100,
            DurabilityPolicy::ReplicatedToApprovedPeers,
            RetentionPolicy::KeepAll,
        )
        .unwrap();
        tombstone_vault_object(&mut deleted_object, 120).unwrap();
        let catalog = VaultCatalog {
            namespace,
            objects: vec![
                create_vault_object(
                    "obj-live",
                    test_namespace(),
                    VaultObjectClass::PersonaDocument,
                    "rev-live-1",
                    100,
                    DurabilityPolicy::ReplicatedToApprovedPeers,
                    RetentionPolicy::KeepLatest,
                )
                .unwrap(),
                deleted_object,
            ],
            revisions: vec![
                create_vault_revision(
                    "rev-live-1",
                    "obj-live",
                    "manifest-live-1",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    100,
                    "device-a",
                    None,
                    None,
                    None,
                )
                .unwrap(),
                create_vault_revision(
                    "rev-deleted-1",
                    "obj-deleted",
                    "manifest-deleted-1",
                    PayloadKind::BinaryBlob,
                    "application/octet-stream",
                    100,
                    "device-a",
                    None,
                    None,
                    None,
                )
                .unwrap(),
            ],
        };

        let retained = retained_vault_revision_ids(&catalog).unwrap();
        let retained_manifests = retained_vault_manifest_ids(&catalog).unwrap();

        assert_eq!(retained, BTreeSet::from(["rev-live-1".to_string()]));
        assert_eq!(
            retained_manifests,
            BTreeSet::from(["manifest-live-1".to_string()])
        );
    }

    #[test]
    fn ledger_delta_preserves_imbalance_direction() {
        let positive = ledger_delta("storage-1", 524_288);
        let negative = ledger_delta("storage-1", -262_144);

        assert!(positive.stored_bytes_delta > 0);
        assert!(negative.stored_bytes_delta < 0);
    }

    #[test]
    fn restore_plan_is_deterministic_for_approved_relationships() {
        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        let manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        let first = plan_restore(&relationship, &manifest).unwrap();
        let second = plan_restore(&relationship, &manifest).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 3);
        assert_eq!(first[0].chunk_id, "bafy-root-1");
        assert_eq!(first[1].chunk_id, "bafy-root-1-chunk-0001");
        assert_eq!(first[2].chunk_id, "bafy-root-1-chunk-0002");
        assert_eq!(first[0].ciphertext_bytes, 4096);
        assert_eq!(first[1].ciphertext_bytes, 1024);
        assert_eq!(first[2].ciphertext_bytes, 512);
    }

    #[test]
    fn restore_plan_requires_explicitly_approved_relationship() {
        let mut relationship = create_relationship("storage-1", "peer-a", "peer-b");
        relationship.approved = false;
        let manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        let err = plan_restore(&relationship, &manifest).unwrap_err();

        assert!(err.message.contains("approved"));
    }

    #[test]
    fn restore_plan_for_device_requires_explicit_manifest_access() {
        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        let manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        let err = plan_restore_for_device(&relationship, &manifest, "device-b").unwrap_err();

        assert!(err.message.contains("not authorized"));
    }

    #[test]
    fn manifest_key_access_wraps_to_device_encryption_key() {
        let key_pair = generate_local_encryption_key_pair("device", "device-a");
        let access =
            wrap_manifest_key_access("device-a", &key_pair.public_key, "xchacha20-key:test")
                .unwrap();

        assert_eq!(access.device_id, "device-a");
        assert_ne!(access.wrapped_manifest_key_hex, "xchacha20-key:test");
        assert_eq!(
            unwrap_manifest_key_access(&access, &key_pair.private_key).unwrap(),
            "xchacha20-key:test"
        );
    }

    #[test]
    fn replace_manifest_access_moves_restore_authority() {
        let mut manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        replace_manifest_access(
            &mut manifest,
            "device-a",
            manifest_device_access("device-b", "cafebabe"),
        )
        .unwrap();

        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-b");
        assert_eq!(
            manifest.authorized_devices[0].wrapped_manifest_key_hex,
            "cafebabe"
        );
    }

    #[test]
    fn rewrap_manifest_access_updates_existing_device_entry() {
        let mut manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );

        rewrap_manifest_access(
            &mut manifest,
            manifest_device_access("device-a", "cafebabe"),
        )
        .unwrap();

        assert_eq!(manifest.authorized_devices.len(), 1);
        assert_eq!(manifest.authorized_devices[0].device_id, "device-a");
        assert_eq!(
            manifest.authorized_devices[0].wrapped_manifest_key_hex,
            "cafebabe"
        );
    }

    #[test]
    fn revoke_manifest_access_removes_restore_authority() {
        let relationship = create_relationship("storage-1", "peer-a", "peer-b");
        let mut manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![
                manifest_device_access("device-a", "deadbeef"),
                manifest_device_access("device-b", "cafebabe"),
            ],
        );

        revoke_manifest_access(&mut manifest, "device-a").unwrap();

        assert!(plan_restore_for_device(&relationship, &manifest, "device-a").is_err());
        assert!(plan_restore_for_device(&relationship, &manifest, "device-b").is_ok());
    }

    #[test]
    fn storage_manifest_event_builder_emits_typed_event() {
        let manifest = publish_manifest(
            "manifest-1",
            "bafy-root-1",
            test_chunks("manifest-1", "bafy-root-1"),
            vec![manifest_device_access("device-a", "deadbeef")],
        );
        let body = storage_manifest_published_event("root-a", "storage-1", manifest);

        assert_eq!(body.event_type(), EventType::StorageManifestPublished);
    }

    #[test]
    fn storage_relationship_and_ledger_event_builders_emit_typed_events() {
        let relationship = storage_relationship_created_event(
            "root-a",
            create_relationship("storage-1", "peer-a", "peer-b"),
        );
        let ledger = storage_ledger_updated_event("root-a", ledger_delta("storage-1", 524_288));

        assert_eq!(
            relationship.event_type(),
            EventType::StorageRelationshipCreated
        );
        assert_eq!(ledger.event_type(), EventType::StorageLedgerUpdated);
    }

    #[test]
    fn encrypted_block_round_trips_and_binds_chunk_metadata() {
        let key = generate_content_key("test");
        let block = encrypt_block("manifest-1", 0, b"root chunk", &key).unwrap();
        let decrypted = decrypt_block(&block, &key).unwrap();

        assert_eq!(decrypted, b"root chunk");
        assert_eq!(block.chunk.manifest_id, "manifest-1");
        assert_eq!(block.chunk.ordinal, 0);
        assert!(block.chunk.chunk_id.starts_with("blk-"));
    }

    #[test]
    fn encrypted_blocks_use_nonce_bound_content_addresses() {
        let key = generate_content_key("test");
        let first = encrypt_block("manifest-1", 1, b"same payload", &key).unwrap();
        let second = encrypt_block("manifest-1", 1, b"same payload", &key).unwrap();

        assert_ne!(first.encrypted.nonce_hex, second.encrypted.nonce_hex);
        assert_ne!(first.chunk.chunk_id, second.chunk.chunk_id);
    }
}
