//! CLASSIFICATION: PUBLIC
//!
//! Signed CBOR compliance bundle for `ember audit export --sign`.
//!
//! Anchor: audit_export_cli_landed.

use std::fs::File;
use std::path::{Path, PathBuf};

use core_crypto::{CanonicalizeError, canonicalize_jcs};
use ed25519_dalek::{Signer as _, SigningKey};
use rusqlite::{Connection, OpenFlags, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::trust::principal_keychain;

use super::redact::{RedactionRule, RedactionStats, apply_redactions};

pub const AUDIT_EXPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct ExportRequest {
    pub db_path: PathBuf,
    pub since_iso: Option<String>,
    pub workflow: Option<String>,
    pub redaction_rules: Vec<RedactionRule>,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditExportManifest {
    pub schema_version: u32,
    pub exported_at: String,
    pub time_window: ExportTimeWindow,
    pub count: usize,
    pub daemon_ir_fingerprint: String,
    pub operator_ir_fingerprint: String,
    pub redaction_rules: Vec<RedactionRule>,
    pub redaction_salt_hex: String,
    pub primitive_gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportTimeWindow {
    pub since: Option<String>,
    pub until: String,
    pub first_receipt_at: Option<String>,
    pub last_receipt_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportedReceipt {
    pub id: String,
    pub kind: String,
    pub grant_id: String,
    pub persona_id: String,
    pub created_at: String,
    pub signer_pubkey: Option<String>,
    pub receipt_id: Option<String>,
    pub original_signature: Option<String>,
    pub redacted: bool,
    pub redaction_stats: RedactionStats,
    pub envelope: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditExportBundle {
    pub schema_version: u32,
    pub manifest: AuditExportManifest,
    pub receipts: Vec<ExportedReceipt>,
    pub signatures: AuditExportSignatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditExportSignatures {
    pub operator: OperatorSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorSignature {
    pub alg: String,
    pub pubkey: String,
    pub signature: String,
    pub signed_payload_blake3: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UnsignedAuditExportBundle<'a> {
    pub schema_version: u32,
    pub manifest: &'a AuditExportManifest,
    pub receipts: &'a [ExportedReceipt],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub output: PathBuf,
    pub count: usize,
    pub redacted_receipts: usize,
    pub operator_pubkey: String,
    pub primitive_gaps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReceiptSourceRow {
    pub id: String,
    pub kind: String,
    pub grant_id: String,
    pub persona_id: String,
    pub created_at: String,
    pub receipt_json: String,
    pub signer_pubkey: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("open receipts store at {path}: {source}")]
    OpenStore {
        path: PathBuf,
        source: rusqlite::Error,
    },
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("receipt row {id} has invalid receipt_json: {source}")]
    InvalidReceiptJson {
        id: String,
        source: serde_json::Error,
    },
    #[error("random salt generation failed: {0}")]
    Random(String),
    #[error("operator signing Principal not found in Keychain: {0}")]
    MissingOperatorPrincipal(String),
    #[error("Keychain error: {0}")]
    Keychain(String),
    #[error("operator signing Principal seed has wrong length: {0} bytes (expected 32)")]
    OperatorSeedLength(usize),
    #[error("canonicalization failed: {0}")]
    Canonicalize(#[from] CanonicalizeError),
    #[error("serialize unsigned export payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("write CBOR bundle to {path}: {source}")]
    WriteCbor {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("encode CBOR bundle to {path}: {source}")]
    EncodeCbor {
        path: PathBuf,
        source: ciborium::ser::Error<std::io::Error>,
    },
}

pub fn run_signed_export(request: ExportRequest) -> Result<ExportOutcome, ExportError> {
    let rows = query_receipt_rows(
        &request.db_path,
        request.since_iso.as_deref(),
        request.workflow.as_deref(),
    )?;
    let salt = random_salt()?;
    let operator_seed = read_operator_signing_principal_seed()?;
    let operator_signing_key = SigningKey::from_bytes(&operator_seed);
    let exported_at = chrono::Utc::now().to_rfc3339();
    let bundle = build_signed_bundle(
        rows,
        request.since_iso,
        request.redaction_rules,
        salt,
        exported_at,
        &operator_signing_key,
    )?;
    let mut file = File::create(&request.output).map_err(|source| ExportError::WriteCbor {
        path: request.output.clone(),
        source,
    })?;
    ciborium::ser::into_writer(&bundle, &mut file).map_err(|source| ExportError::EncodeCbor {
        path: request.output.clone(),
        source,
    })?;

    Ok(ExportOutcome {
        output: request.output,
        count: bundle.manifest.count,
        redacted_receipts: bundle.receipts.iter().filter(|r| r.redacted).count(),
        operator_pubkey: bundle.signatures.operator.pubkey,
        primitive_gaps: bundle.manifest.primitive_gaps,
    })
}

pub fn build_signed_bundle(
    rows: Vec<ReceiptSourceRow>,
    since_iso: Option<String>,
    redaction_rules: Vec<RedactionRule>,
    salt: [u8; 32],
    exported_at: String,
    operator_signing_key: &SigningKey,
) -> Result<AuditExportBundle, ExportError> {
    let home = std::env::var("HOME").ok();
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        let mut envelope: Value = serde_json::from_str(&row.receipt_json).map_err(|source| {
            ExportError::InvalidReceiptJson {
                id: row.id.clone(),
                source,
            }
        })?;
        let original_signature = envelope
            .get("signature")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let receipt_id = envelope
            .get("receipt_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| Some(row.id.clone()));
        let redaction_stats =
            apply_redactions(&mut envelope, &redaction_rules, &salt, home.as_deref());
        receipts.push(ExportedReceipt {
            id: row.id,
            kind: row.kind,
            grant_id: row.grant_id,
            persona_id: row.persona_id,
            created_at: row.created_at,
            signer_pubkey: non_empty(row.signer_pubkey),
            receipt_id,
            original_signature,
            redacted: redaction_stats.values_changed > 0,
            redaction_stats,
            envelope,
        });
    }

    let first_receipt_at = receipts.first().map(|r| r.created_at.clone());
    let last_receipt_at = receipts.last().map(|r| r.created_at.clone());
    let daemon_ir_fingerprint = daemon_ir_fingerprint(&receipts);
    let operator_pubkey = hex::encode(operator_signing_key.verifying_key().to_bytes());
    let operator_ir_fingerprint = fingerprint_hex(operator_pubkey.as_bytes());
    let primitive_gaps = manifest_primitive_gaps(&receipts);

    let manifest = AuditExportManifest {
        schema_version: AUDIT_EXPORT_SCHEMA_VERSION,
        exported_at,
        time_window: ExportTimeWindow {
            since: since_iso,
            until: chrono::Utc::now().to_rfc3339(),
            first_receipt_at,
            last_receipt_at,
        },
        count: receipts.len(),
        daemon_ir_fingerprint,
        operator_ir_fingerprint,
        redaction_rules,
        redaction_salt_hex: hex::encode(salt),
        primitive_gaps,
    };

    let unsigned = canonical_unsigned_bytes(&manifest, &receipts)?;
    let signed_payload_blake3 = blake3::hash(&unsigned).to_hex().to_string();
    let signature = operator_signing_key.sign(&unsigned);
    Ok(AuditExportBundle {
        schema_version: AUDIT_EXPORT_SCHEMA_VERSION,
        manifest,
        receipts,
        signatures: AuditExportSignatures {
            operator: OperatorSignature {
                alg: "ed25519".to_string(),
                pubkey: operator_pubkey,
                signature: format!("ed25519sig:{}", hex::encode(signature.to_bytes())),
                signed_payload_blake3,
            },
        },
    })
}

pub(crate) fn canonical_unsigned_bytes(
    manifest: &AuditExportManifest,
    receipts: &[ExportedReceipt],
) -> Result<Vec<u8>, ExportError> {
    let unsigned = UnsignedAuditExportBundle {
        schema_version: AUDIT_EXPORT_SCHEMA_VERSION,
        manifest,
        receipts,
    };
    let value = serde_json::to_value(unsigned)?;
    Ok(canonicalize_jcs(&value)?)
}

fn query_receipt_rows(
    db_path: &Path,
    since_iso: Option<&str>,
    workflow: Option<&str>,
) -> Result<Vec<ReceiptSourceRow>, ExportError> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|source| ExportError::OpenStore {
        path: db_path.to_path_buf(),
        source,
    })?;

    let mut sql = String::from(
        "SELECT id, kind, grant_id, persona_id, created_at, receipt_json, signer_pubkey \
         FROM receipts WHERE 1=1",
    );
    let mut params = Vec::new();
    if let Some(since) = since_iso {
        sql.push_str(&format!(" AND created_at >= ?{}", params.len() + 1));
        params.push(since.to_string());
    }
    sql.push_str(" ORDER BY created_at ASC");

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params.iter()), |row| {
        Ok(ReceiptSourceRow {
            id: row.get(0)?,
            kind: row.get(1)?,
            grant_id: row.get(2)?,
            persona_id: row.get(3)?,
            created_at: row.get(4)?,
            receipt_json: row.get(5)?,
            signer_pubkey: row.get(6)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        let row = row?;
        if let Some(workflow) = workflow
            && !receipt_matches_workflow(&row, workflow)?
        {
            continue;
        }
        out.push(row);
    }
    Ok(out)
}

fn receipt_matches_workflow(row: &ReceiptSourceRow, workflow: &str) -> Result<bool, ExportError> {
    let value: Value = serde_json::from_str(&row.receipt_json).map_err(|source| {
        ExportError::InvalidReceiptJson {
            id: row.id.clone(),
            source,
        }
    })?;
    let candidates = [
        "/body/delegation_template",
        "/body/workflow",
        "/body/workflow_name",
        "/delegation_template",
        "/workflow",
        "/workflow_name",
    ];
    Ok(candidates
        .iter()
        .any(|path| value.pointer(path).and_then(|v| v.as_str()) == Some(workflow)))
}

fn read_operator_signing_principal_seed() -> Result<[u8; 32], ExportError> {
    match principal_keychain::read_operator_role_persona_seed().map_err(|e| {
        ExportError::Keychain(format!("read operator-role Durable Persona seed: {e}"))
    })? {
        Some(seed) => Ok(seed),
        None => Err(ExportError::MissingOperatorPrincipal(format!(
            "no exportable Keychain entry at {} or legacy {}. Current ADR 200 \
             operator authority is device-rooted; signed audit export needs the \
             device-rooted signing path before it can sign on this host.",
            principal_keychain::OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
            principal_keychain::LEGACY_OPERATOR_IR_KEYCHAIN_LABEL
        ))),
    }
}

fn random_salt() -> Result<[u8; 32], ExportError> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| ExportError::Random(e.to_string()))?;
    Ok(salt)
}

fn daemon_ir_fingerprint(receipts: &[ExportedReceipt]) -> String {
    let mut ids: Vec<String> = receipts
        .iter()
        .filter_map(|r| {
            r.envelope
                .get("daemon_root_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| r.signer_pubkey.clone())
        })
        .collect();
    ids.sort();
    ids.dedup();
    if ids.len() == 1 {
        return fingerprint_hex(ids[0].as_bytes());
    }
    fingerprint_hex(ids.join("\n").as_bytes())
}

fn manifest_primitive_gaps(receipts: &[ExportedReceipt]) -> Vec<String> {
    let mut gaps = Vec::new();
    if receipts.iter().any(|r| r.redacted) {
        gaps.push(
            "Redacted ReceiptEnvelope bodies retain original receipt_id/signature fields, but current ADR 118 v2 signatures cover the inline body; daemon signature verification is skipped per redacted receipt during import verification."
                .to_string(),
        );
    }
    if receipts.iter().any(|r| {
        r.envelope
            .get("signature")
            .and_then(|v| v.as_str())
            .is_none()
    }) {
        gaps.push(
            "Some exported receipts do not carry an ADR 118 v2 envelope signature; verifier reports them as legacy/unsigned primitive gaps."
                .to_string(),
        );
    }
    gaps.push(
        "General audit-export receipt chains do not yet carry a prev_receipt_hash field; import verification checks bundle ordering and unique receipt ids, not a cryptographic parent chain."
            .to_string(),
    );
    gaps
}

fn fingerprint_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
pub(crate) mod test_support {
    use core_crypto::{FixtureSigner, Signer};
    use core_events::receipt::{
        ReceiptEnvelope, ReceiptVersion, TerminationAuthority, sign_receipt_v2,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::Value;

    use super::ReceiptSourceRow;

    pub(crate) fn fixture_operator_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    pub(crate) fn fixture_daemon_receipt(body: Value) -> (ReceiptSourceRow, String) {
        let daemon = FixtureSigner::new("audit-export-daemon");
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "session.claude_code".to_string(),
            receipt_id: String::new(),
            daemon_root_id: "daemon-root-fixture".to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body,
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, &daemon).unwrap();
        let pubkey = daemon
            .public_key()
            .0
            .strip_prefix("ed25519:")
            .unwrap()
            .to_string();
        let row = ReceiptSourceRow {
            id: env.receipt_id.clone(),
            kind: env.kind.clone(),
            grant_id: "grant-1".to_string(),
            persona_id: "persona-1".to_string(),
            created_at: "2026-05-15T00:00:00Z".to_string(),
            receipt_json: serde_json::to_string(&env).unwrap(),
            signer_pubkey: String::new(),
        };
        (row, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::export::test_support::{fixture_daemon_receipt, fixture_operator_key};
    use crate::trust::principal_keychain::{
        KEYCHAIN_SERVICE, KEYCHAIN_TEST_LOCK, LEGACY_OPERATOR_IR_KEYCHAIN_LABEL,
        OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL, write_seed,
    };
    use keyring_core::mock;
    use serde_json::json;

    fn install_mock_store() {
        keyring_core::set_default_store(mock::Store::new().expect("mock store"));
    }

    fn clear_operator_seed_labels() {
        for label in [
            OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
            LEGACY_OPERATOR_IR_KEYCHAIN_LABEL,
        ] {
            if let Ok(entry) = keyring_core::Entry::new(KEYCHAIN_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
    }

    #[test]
    fn export_seed_reader_accepts_target_operator_role_label() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_operator_seed_labels();

        write_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL, &[0x66; 32]).expect("operator-role seed");

        assert_eq!(read_operator_signing_principal_seed().unwrap(), [0x66; 32]);
    }

    #[test]
    fn builds_signed_bundle_with_manifest_fields() {
        let (row, _) = fixture_daemon_receipt(json!({
            "delegation_template": "emberd-development"
        }));
        let bundle = build_signed_bundle(
            vec![row],
            Some("2026-05-01T00:00:00Z".to_string()),
            Vec::new(),
            [9u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &fixture_operator_key(),
        )
        .unwrap();
        assert_eq!(bundle.manifest.count, 1);
        assert_eq!(bundle.manifest.schema_version, AUDIT_EXPORT_SCHEMA_VERSION);
        assert_eq!(bundle.manifest.redaction_salt_hex, hex::encode([9u8; 32]));
        assert_eq!(bundle.receipts[0].redacted, false);
        assert!(
            bundle
                .signatures
                .operator
                .signature
                .starts_with("ed25519sig:")
        );
    }

    #[test]
    fn redaction_marks_receipt_and_changes_body() {
        let token = ["ghp", "_secret123"].join("");
        let (row, _) = fixture_daemon_receipt(json!({
            "claim_events": [{"input_redacted": format!("GH_TOKEN={token} gh pr view")}]
        }));
        let bundle = build_signed_bundle(
            vec![row],
            None,
            vec![RedactionRule::GhTokenValues],
            [5u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &fixture_operator_key(),
        )
        .unwrap();
        assert!(bundle.receipts[0].redacted);
        let rendered = serde_json::to_string(&bundle.receipts[0].envelope).unwrap();
        assert!(rendered.contains("<redacted-blake3:"));
        assert!(!rendered.contains("ghp_secret123"));
        assert!(
            bundle
                .manifest
                .primitive_gaps
                .iter()
                .any(|gap| gap.contains("Redacted ReceiptEnvelope bodies"))
        );
    }
}
