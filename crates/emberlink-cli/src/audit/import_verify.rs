//! CLASSIFICATION: PUBLIC
//!
//! Offline verifier for `ember audit verify --import <export.cbor>`.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

use core_crypto::{Ed25519Verifier, PublicKey};
use core_events::receipt::{ReceiptEnvelope, verify_receipt_v2};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::export::{AUDIT_EXPORT_SCHEMA_VERSION, AuditExportBundle, canonical_unsigned_bytes};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportVerifyReport {
    pub ok: bool,
    pub receipt_count: usize,
    pub operator_signature_verified: bool,
    pub daemon_envelope_signatures_verified: usize,
    pub daemon_envelope_signatures_failed: usize,
    pub redacted_receipts: usize,
    pub redaction_rules: Vec<String>,
    pub primitive_gaps: Vec<String>,
    pub failures: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportVerifyError {
    #[error("open import bundle {path}: {source}")]
    Open {
        path: String,
        source: std::io::Error,
    },
    #[error("decode CBOR import bundle {path}: {source}")]
    Decode {
        path: String,
        source: ciborium::de::Error<std::io::Error>,
    },
    #[error("canonicalize unsigned export payload: {0}")]
    Canonicalize(String),
    #[error("operator pubkey is malformed: {0}")]
    OperatorPubkey(String),
    #[error("trust root is malformed: {0}")]
    TrustRoot(String),
}

pub fn verify_import_file(
    path: &Path,
    trust_roots: &[String],
    operator_pubkey: Option<&str>,
) -> Result<ImportVerifyReport, ImportVerifyError> {
    let file = File::open(path).map_err(|source| ImportVerifyError::Open {
        path: path.display().to_string(),
        source,
    })?;
    let bundle: AuditExportBundle =
        ciborium::de::from_reader(file).map_err(|source| ImportVerifyError::Decode {
            path: path.display().to_string(),
            source,
        })?;
    verify_bundle(&bundle, trust_roots, operator_pubkey)
}

pub fn verify_bundle(
    bundle: &AuditExportBundle,
    trust_roots: &[String],
    operator_pubkey: Option<&str>,
) -> Result<ImportVerifyReport, ImportVerifyError> {
    let mut failures = Vec::new();
    let mut primitive_gaps = bundle.manifest.primitive_gaps.clone();

    if bundle.schema_version != AUDIT_EXPORT_SCHEMA_VERSION {
        failures.push(format!(
            "unsupported export schema_version {} (expected {})",
            bundle.schema_version, AUDIT_EXPORT_SCHEMA_VERSION
        ));
    }
    if bundle.manifest.schema_version != AUDIT_EXPORT_SCHEMA_VERSION {
        failures.push(format!(
            "unsupported manifest schema_version {} (expected {})",
            bundle.manifest.schema_version, AUDIT_EXPORT_SCHEMA_VERSION
        ));
    }

    if bundle.manifest.count != bundle.receipts.len() {
        failures.push(format!(
            "manifest count {} does not match contained receipt count {}",
            bundle.manifest.count,
            bundle.receipts.len()
        ));
    }

    verify_unique_and_ordered(bundle, &mut failures);

    let operator_signature_verified =
        verify_operator_signature(bundle, operator_pubkey, &mut failures)?;

    let roots = normalize_pubkeys(trust_roots).map_err(ImportVerifyError::TrustRoot)?;
    let mut daemon_verified = 0usize;
    let mut daemon_failed = 0usize;
    let verifier = Ed25519Verifier;

    for receipt in &bundle.receipts {
        let env = match serde_json::from_value::<ReceiptEnvelope>(receipt.envelope.clone()) {
            Ok(env) => env,
            Err(e) => {
                primitive_gaps.push(format!(
                    "receipt {} is not an ADR 118 v2 ReceiptEnvelope: {e}",
                    receipt.id
                ));
                continue;
            }
        };
        if receipt.redacted {
            primitive_gaps.push(format!(
                "receipt {} is redacted; current ADR 118 v2 signatures cover inline body bytes, so daemon envelope signature cannot be recomputed over the redacted body",
                receipt.id
            ));
            continue;
        }
        if roots.is_empty() {
            let msg = format!(
                "receipt {} daemon envelope signature not checked: no --trust-roots supplied",
                receipt.id
            );
            primitive_gaps.push(msg.clone());
            failures.push(msg);
            continue;
        }
        let mut verified = false;
        let mut last_error = None;
        for root in &roots {
            match verify_receipt_v2(&env, &PublicKey(format!("ed25519:{root}")), &verifier) {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(e) => last_error = Some(e.to_string()),
            }
        }
        if verified {
            daemon_verified += 1;
        } else {
            daemon_failed += 1;
            failures.push(format!(
                "receipt {} daemon envelope signature did not verify against supplied trust roots: {}",
                receipt.id,
                last_error.unwrap_or_else(|| "no roots tried".to_string())
            ));
        }
    }

    let redacted_receipts = bundle.receipts.iter().filter(|r| r.redacted).count();
    let ok = failures.is_empty() && operator_signature_verified;
    Ok(ImportVerifyReport {
        ok,
        receipt_count: bundle.receipts.len(),
        operator_signature_verified,
        daemon_envelope_signatures_verified: daemon_verified,
        daemon_envelope_signatures_failed: daemon_failed,
        redacted_receipts,
        redaction_rules: bundle
            .manifest
            .redaction_rules
            .iter()
            .map(ToString::to_string)
            .collect(),
        primitive_gaps,
        failures,
    })
}

pub fn format_report_human(report: &ImportVerifyReport) -> String {
    let mut out = String::new();
    out.push_str(if report.ok {
        "audit export import verify: OK\n"
    } else {
        "audit export import verify: FAILED\n"
    });
    out.push_str(&format!("  receipts: {}\n", report.receipt_count));
    out.push_str(&format!(
        "  operator signature: {}\n",
        if report.operator_signature_verified {
            "verified"
        } else {
            "not verified"
        }
    ));
    out.push_str(&format!(
        "  daemon envelope signatures: {} verified, {} failed\n",
        report.daemon_envelope_signatures_verified, report.daemon_envelope_signatures_failed
    ));
    out.push_str(&format!(
        "  redacted receipts: {}\n",
        report.redacted_receipts
    ));
    out.push_str(&format!(
        "  redaction rules: {}\n",
        if report.redaction_rules.is_empty() {
            "-".to_string()
        } else {
            report.redaction_rules.join(",")
        }
    ));
    if !report.failures.is_empty() {
        out.push_str("Failures:\n");
        for failure in &report.failures {
            out.push_str(&format!("  - {failure}\n"));
        }
    }
    if !report.primitive_gaps.is_empty() {
        out.push_str("Primitive gaps:\n");
        for gap in &report.primitive_gaps {
            out.push_str(&format!("  - {gap}\n"));
        }
    }
    out
}

pub fn format_report_json(report: &ImportVerifyReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

fn verify_operator_signature(
    bundle: &AuditExportBundle,
    operator_pubkey: Option<&str>,
    failures: &mut Vec<String>,
) -> Result<bool, ImportVerifyError> {
    if bundle.signatures.operator.alg != "ed25519" {
        failures.push(format!(
            "unsupported operator signature algorithm {}",
            bundle.signatures.operator.alg
        ));
        return Ok(false);
    }

    let expected_pubkey = match operator_pubkey {
        Some(pk) => normalize_pubkey(pk).map_err(ImportVerifyError::OperatorPubkey)?,
        None => normalize_pubkey(&bundle.signatures.operator.pubkey)
            .map_err(ImportVerifyError::OperatorPubkey)?,
    };
    let bundle_pubkey = normalize_pubkey(&bundle.signatures.operator.pubkey)
        .map_err(ImportVerifyError::OperatorPubkey)?;
    if expected_pubkey != bundle_pubkey {
        failures.push(format!(
            "operator pubkey mismatch: supplied {expected_pubkey}, bundle signed by {bundle_pubkey}"
        ));
        return Ok(false);
    }

    let bytes = canonical_unsigned_bytes(&bundle.manifest, &bundle.receipts)
        .map_err(|e| ImportVerifyError::Canonicalize(e.to_string()))?;
    let computed_hash = blake3::hash(&bytes).to_hex().to_string();
    if computed_hash != bundle.signatures.operator.signed_payload_blake3 {
        failures.push(format!(
            "operator signed payload hash mismatch: stored {}, computed {}",
            bundle.signatures.operator.signed_payload_blake3, computed_hash
        ));
        return Ok(false);
    }

    let vk = verifying_key_from_hex(&expected_pubkey).map_err(ImportVerifyError::OperatorPubkey)?;
    let sig_hex = bundle
        .signatures
        .operator
        .signature
        .strip_prefix("ed25519sig:")
        .ok_or_else(|| {
            ImportVerifyError::OperatorPubkey(
                "operator signature missing ed25519sig: prefix".to_string(),
            )
        })?;
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| ImportVerifyError::OperatorPubkey(format!("signature hex: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| ImportVerifyError::OperatorPubkey(format!("signature length: {e}")))?;
    if vk.verify(&bytes, &sig).is_ok() {
        Ok(true)
    } else {
        failures.push("operator signature verification failed".to_string());
        Ok(false)
    }
}

fn verify_unique_and_ordered(bundle: &AuditExportBundle, failures: &mut Vec<String>) {
    let mut seen = HashSet::new();
    let mut previous: Option<&str> = None;
    for receipt in &bundle.receipts {
        if !seen.insert(receipt.id.clone()) {
            failures.push(format!("duplicate receipt id {}", receipt.id));
        }
        if let Some(prev) = previous
            && receipt.created_at.as_str() < prev
        {
            failures.push(format!(
                "receipt {} is out of order: {} appears after {}",
                receipt.id, receipt.created_at, prev
            ));
        }
        previous = Some(receipt.created_at.as_str());
    }
}

fn normalize_pubkeys(values: &[String]) -> Result<Vec<String>, String> {
    values
        .iter()
        .map(|v| {
            normalize_pubkey(v).map_err(|e| {
                format!(
                    "{} ({e})",
                    if v.trim().is_empty() {
                        "<empty>"
                    } else {
                        v.trim()
                    }
                )
            })
        })
        .collect()
}

fn normalize_pubkey(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    let raw = trimmed.strip_prefix("ed25519:").unwrap_or(trimmed);
    if raw.len() != 64 {
        return Err(format!(
            "expected 32-byte hex pubkey, got {} chars",
            raw.len()
        ));
    }
    let bytes = hex::decode(raw).map_err(|e| format!("pubkey hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(raw.to_ascii_lowercase())
}

fn verifying_key_from_hex(hex_pubkey: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(hex_pubkey).map_err(|e| format!("pubkey hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| format!("expected 32 pubkey bytes, got {}", b.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("ed25519 verifying key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::export::build_signed_bundle;
    use crate::audit::export::test_support::{fixture_daemon_receipt, fixture_operator_key};
    use crate::audit::redact::RedactionRule;
    use serde_json::json;

    #[test]
    fn verifies_operator_and_daemon_signature_for_unredacted_bundle() {
        let (row, daemon_pubkey) = fixture_daemon_receipt(json!({
            "delegation_template": "emberd-development"
        }));
        let operator = fixture_operator_key();
        let operator_pubkey = hex::encode(operator.verifying_key().to_bytes());
        let bundle = build_signed_bundle(
            vec![row],
            None,
            Vec::new(),
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &operator,
        )
        .unwrap();
        let report = verify_bundle(&bundle, &[daemon_pubkey], Some(&operator_pubkey)).unwrap();
        assert!(report.ok, "{report:?}");
        assert!(report.operator_signature_verified);
        assert_eq!(report.daemon_envelope_signatures_verified, 1);
        assert_eq!(report.daemon_envelope_signatures_failed, 0);
    }

    #[test]
    fn redacted_bundle_verifies_operator_signature_and_reports_daemon_gap() {
        let token = ["ghp", "_secret123"].join("");
        let (row, daemon_pubkey) = fixture_daemon_receipt(json!({
            "claim_events": [{"input_redacted": format!("GH_TOKEN={token} gh pr view")}]
        }));
        let operator = fixture_operator_key();
        let bundle = build_signed_bundle(
            vec![row],
            None,
            vec![RedactionRule::GhTokenValues],
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &operator,
        )
        .unwrap();
        let report = verify_bundle(&bundle, &[daemon_pubkey], None).unwrap();
        assert!(report.ok, "{report:?}");
        assert!(report.operator_signature_verified);
        assert_eq!(report.daemon_envelope_signatures_verified, 0);
        assert!(
            report
                .primitive_gaps
                .iter()
                .any(|gap| gap.contains("current ADR 118 v2 signatures cover inline body"))
        );
    }

    #[test]
    fn unredacted_bundle_without_trust_roots_is_not_fully_verified() {
        let (row, _) = fixture_daemon_receipt(json!({
            "delegation_template": "emberd-development"
        }));
        let operator = fixture_operator_key();
        let bundle = build_signed_bundle(
            vec![row],
            None,
            Vec::new(),
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &operator,
        )
        .unwrap();
        let report = verify_bundle(&bundle, &[], None).unwrap();
        assert!(!report.ok, "{report:?}");
        assert!(report.operator_signature_verified);
        assert_eq!(report.daemon_envelope_signatures_verified, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("no --trust-roots supplied"))
        );
    }

    #[test]
    fn rejects_unsupported_operator_signature_algorithm() {
        let (row, daemon_pubkey) = fixture_daemon_receipt(json!({}));
        let mut bundle = build_signed_bundle(
            vec![row],
            None,
            Vec::new(),
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &fixture_operator_key(),
        )
        .unwrap();
        bundle.signatures.operator.alg = "ed448".to_string();
        let report = verify_bundle(&bundle, &[daemon_pubkey], None).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("unsupported operator signature algorithm"))
        );
    }

    #[test]
    fn rejects_wrong_operator_pubkey() {
        let (row, daemon_pubkey) = fixture_daemon_receipt(json!({}));
        let bundle = build_signed_bundle(
            vec![row],
            None,
            Vec::new(),
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &fixture_operator_key(),
        )
        .unwrap();
        let wrong = hex::encode([9u8; 32]);
        let report = verify_bundle(&bundle, &[daemon_pubkey], Some(&wrong)).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("operator pubkey mismatch"))
        );
    }

    #[test]
    fn rejects_malformed_trust_root() {
        let (row, _) = fixture_daemon_receipt(json!({}));
        let bundle = build_signed_bundle(
            vec![row],
            None,
            Vec::new(),
            [1u8; 32],
            "2026-05-15T01:00:00Z".to_string(),
            &fixture_operator_key(),
        )
        .unwrap();
        let err = verify_bundle(&bundle, &["not-hex".to_string()], None).unwrap_err();
        assert!(matches!(err, ImportVerifyError::TrustRoot(_)));
    }
}
