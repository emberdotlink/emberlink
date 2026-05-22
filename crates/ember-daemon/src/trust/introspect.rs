//! Trust-set introspection — answers "what is this daemon prepared to
//! verify against?" for operator-visible CLI surfaces.
//!
//! Per design §Component 2. Phase 1 exposes the daemon's startup
//! trust-root snapshot via `trust.list`. Phase 2 adds `trust.show
//! <root-id>` — drill-down lookup by full fingerprint or unique hex
//! prefix. Phase 3 adds `trust.explain` — chain-walk a signed artifact
//! back to the trust root that verifies it. The receipt-envelope
//! artifact-kind branch landed in implementation-note-409; workflow
//! grant lands in implementation-note-410.
//!
//! Anchor: `trust_introspect_module_landed` (Phase 1) /
//! `trust_show_landed` (Phase 2) / `trust_explain_landed` (Phase 3
//! binary-manifest) / `trust_explain_receipt_chain_walked` (Receipt
//! envelope branch).

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};

use crate::binary_manifest::{
    ManifestSidecar, TrustRootRecord, TrustRootSource, trust_roots_snapshot,
};

/// Handle `trust.list` JSON-RPC. Returns the daemon's startup trust-root
/// snapshot as a JSON object:
///
/// ```json
/// {
///   "roots": [
///     {"fingerprint_hex": "<64-hex>", "source": "release"},
///     {"fingerprint_hex": "<64-hex>", "source": "operator"},
///     ...
///   ],
///   "dev_mode_active": <bool>
/// }
/// ```
///
/// `dev_mode_active` mirrors [`crate::binary_manifest::dev_mode_active`]
/// so a single RPC tells the operator both the trust set composition
/// and the posture flag derived from it (any `Operator` entry ⇒
/// `dev_mode_active = true`).
///
/// Read-only operation — no authority modification, no signing, no
/// peer-cred gating. Safe to expose to any caller that can reach the
/// daemon socket.
pub fn handle_trust_list(_params: &Value) -> Result<Value, (i32, String)> {
    let records = trust_roots_snapshot();
    let roots_json: Vec<Value> = records
        .iter()
        .map(|r| {
            json!({
                "fingerprint_hex": r.fingerprint_hex,
                "source": match r.source {
                    crate::binary_manifest::TrustRootSource::Release => "release",
                    crate::binary_manifest::TrustRootSource::Operator => "operator",
                },
            })
        })
        .collect();
    Ok(json!({
        "roots": roots_json,
        "dev_mode_active": crate::binary_manifest::dev_mode_active(),
    }))
}

/// Render a trust-root record set into a tabular line-per-root string
/// for `ember trust list` to print. Lives daemon-side so the CLI is a
/// thin client; the daemon owns the canonical render shape and any
/// future fields (audit count, signing purpose) accrete here without
/// touching every CLI consumer.
pub fn render_trust_list_human(records: &[TrustRootRecord], dev_mode_active: bool) -> String {
    let mut out = String::new();
    if records.is_empty() {
        out.push_str(
            "no trust roots loaded — daemon was opened without startup verification \
             (in-memory test path or single-shot utility)\n",
        );
        return out;
    }
    let posture = if dev_mode_active { "dev" } else { "prod" };
    out.push_str(&format!(
        "Trust posture: {} ({} root{}, dev_mode_active = {})\n",
        posture,
        records.len(),
        if records.len() == 1 { "" } else { "s" },
        dev_mode_active,
    ));
    for (i, r) in records.iter().enumerate() {
        let source_label = match r.source {
            crate::binary_manifest::TrustRootSource::Release => "release ",
            crate::binary_manifest::TrustRootSource::Operator => "operator",
        };
        out.push_str(&format!("  [{i}] {source_label}  {}\n", r.fingerprint_hex));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_manifest::TrustRootSource;

    fn rec(fp: &str, src: TrustRootSource) -> TrustRootRecord {
        TrustRootRecord {
            fingerprint_hex: fp.to_string(),
            source: src,
        }
    }

    #[test]
    fn render_empty_set_explains_why() {
        let out = render_trust_list_human(&[], false);
        assert!(out.contains("no trust roots loaded"));
    }

    #[test]
    fn render_prod_posture_one_release_root() {
        let recs = vec![rec("aa".repeat(32).as_str(), TrustRootSource::Release)];
        let out = render_trust_list_human(&recs, false);
        assert!(out.contains("Trust posture: prod (1 root"));
        assert!(out.contains("dev_mode_active = false"));
        assert!(out.contains("release "));
        assert!(out.contains(&"aa".repeat(32)));
    }

    #[test]
    fn render_dev_posture_release_plus_operator() {
        let recs = vec![
            rec(&"aa".repeat(32), TrustRootSource::Release),
            rec(&"bb".repeat(32), TrustRootSource::Operator),
        ];
        let out = render_trust_list_human(&recs, true);
        assert!(out.contains("Trust posture: dev (2 roots"));
        assert!(out.contains("dev_mode_active = true"));
        assert!(out.contains("release "));
        assert!(out.contains("operator"));
    }

    #[test]
    fn handle_trust_show_rejects_missing_root_id() {
        let err = handle_trust_show(&Value::Null).unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("missing root_id"));
    }

    #[test]
    fn handle_trust_show_rejects_empty_root_id() {
        let err = handle_trust_show(&json!({"root_id": "   "})).unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[test]
    fn handle_trust_show_returns_not_found_for_unknown_root() {
        // The snapshot may or may not be initialised in this test; either
        // way, a fingerprint that cannot exist (literal 'zz' is non-hex)
        // cannot match anything.
        let err = handle_trust_show(&json!({"root_id": "zz".repeat(32)})).unwrap_err();
        assert_eq!(err.0, -32004);
        assert!(err.1.contains("trust_root_not_found"));
    }

    #[test]
    fn render_trust_show_emits_three_lines() {
        let out = render_trust_show_human(&"aa".repeat(32), "release", "prod");
        assert!(out.contains("Trust root:"));
        assert!(out.contains("Fingerprint:"));
        assert!(out.contains("Source:"));
        assert!(out.contains("Posture:"));
        assert!(out.contains(&"aa".repeat(32)));
        assert!(out.contains("release"));
        assert!(out.contains("prod"));
    }

    #[test]
    fn handle_trust_explain_rejects_missing_params() {
        let err = handle_trust_explain(&Value::Null).unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[test]
    fn handle_trust_explain_rejects_unknown_artifact_kind() {
        let req = json!({
            "artifact_kind": "receipt_envelope",
            "artifact_bytes_b64": "",
            "sidecar_bytes_b64": "",
        });
        let err = handle_trust_explain(&req).unwrap_err();
        assert_eq!(err.0, -32004);
        assert!(err.1.contains("unsupported_artifact_kind"));
    }

    #[test]
    fn handle_trust_explain_rejects_malformed_base64() {
        let req = json!({
            "artifact_kind": "binary_manifest",
            "artifact_bytes_b64": "!!!not-base64!!!",
            "sidecar_bytes_b64": "",
        });
        let err = handle_trust_explain(&req).unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("artifact_bytes_b64 decode"));
    }

    #[test]
    fn explain_binary_manifest_reports_sidecar_parse_error() {
        let out = explain_binary_manifest(b"manifest-bytes", b"not-json").unwrap();
        assert_eq!(out["verdict"], "sidecar_parse_error");
        assert!(out["trust_root"].is_null());
    }

    #[test]
    fn explain_binary_manifest_reports_unsupported_schema_version() {
        let sidecar = json!({
            "schema_version": 99,
            "signature": "ed25519:AAAA",
            "signature_alg": "ed25519",
        });
        let out =
            explain_binary_manifest(b"manifest-bytes", sidecar.to_string().as_bytes()).unwrap();
        assert_eq!(out["verdict"], "unsupported_schema_version");
    }

    #[test]
    fn explain_binary_manifest_reports_unsupported_signature_alg() {
        let sidecar = json!({
            "schema_version": 1,
            "signature": "rsa:AAAA",
            "signature_alg": "rsa",
        });
        let out =
            explain_binary_manifest(b"manifest-bytes", sidecar.to_string().as_bytes()).unwrap();
        assert_eq!(out["verdict"], "unsupported_signature_alg");
    }

    #[test]
    fn explain_binary_manifest_verified_path_round_trips_real_signature() {
        use ed25519_dalek::{Signer, SigningKey};

        // Serialize against the receipt-path tests that also mutate
        // the process-global trust-root snapshot.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Mint a fresh signing key, set it as the trust-root snapshot,
        // sign manifest bytes, build a sidecar, verify the chain walk.
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let fp_hex = hex::encode(vk.to_bytes());
        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: fp_hex.clone(),
            source: TrustRootSource::Release,
        }]);

        let manifest_bytes = b"manifest = \"v1.0.0\"\n";
        let sig = sk.sign(manifest_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let sidecar = json!({
            "schema_version": 1,
            "signature": format!("ed25519:{}", sig_b64),
            "signature_alg": "ed25519",
        });

        let out = explain_binary_manifest(manifest_bytes, sidecar.to_string().as_bytes()).unwrap();
        assert_eq!(out["verdict"], "verified");
        assert_eq!(out["trust_root"]["fingerprint_hex"], fp_hex);
        assert_eq!(out["trust_root"]["source"], "release");
        assert!(out["chain"].as_str().unwrap().contains("VERIFIED"));
    }

    #[test]
    fn explain_binary_manifest_no_matching_root_when_tampered() {
        use ed25519_dalek::{Signer, SigningKey};

        // Serialize against the receipt-path tests that also mutate
        // the process-global trust-root snapshot.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let vk = sk.verifying_key();
        let fp_hex = hex::encode(vk.to_bytes());
        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: fp_hex,
            source: TrustRootSource::Release,
        }]);

        let manifest_bytes = b"manifest = \"v1.0.0\"\n";
        let sig = sk.sign(manifest_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let sidecar = json!({
            "schema_version": 1,
            "signature": format!("ed25519:{}", sig_b64),
            "signature_alg": "ed25519",
        });

        // Verify against TAMPERED manifest bytes — signature must NOT match.
        let out = explain_binary_manifest(
            b"manifest = \"v9.9.9-tampered\"\n",
            sidecar.to_string().as_bytes(),
        )
        .unwrap();
        assert_eq!(out["verdict"], "no_matching_root");
        assert!(out["trust_root"].is_null());
    }

    // ── implementation-note-409 T1 tests ───────────────────────────────

    #[test]
    fn handle_trust_explain_receipt_rejects_non_empty_sidecar() {
        // Receipts carry their signature inline; sidecar must be empty.
        let req = json!({
            "artifact_kind": "receipt",
            "artifact_bytes_b64": base64::engine::general_purpose::STANDARD
                .encode(b"{\"version\":\"2\",\"kind\":\"atomic.tool_call\"}"),
            "sidecar_bytes_b64": base64::engine::general_purpose::STANDARD.encode(b"not-empty"),
        });
        let out = handle_trust_explain(&req).unwrap();
        assert_eq!(out["verdict"], "sidecar_not_supported_for_kind");
        assert!(out["trust_root"].is_null());
        assert!(out["chain"].as_str().unwrap().contains("inline"));
    }

    #[test]
    fn explain_receipt_reports_envelope_parse_error() {
        let out = explain_receipt(b"not-json-not-envelope").unwrap();
        assert_eq!(out["verdict"], "receipt_envelope_parse_error");
        assert!(out["trust_root"].is_null());
        assert!(out["chain"].as_str().unwrap().contains("parse FAILED"));
    }

    #[test]
    fn explain_receipt_reports_signature_missing_when_envelope_unsigned() {
        // Build a structurally-valid envelope with no signature.
        let envelope = json!({
            "version": "2",
            "kind": "atomic.tool_call",
            "receipt_id": "deadbeef",
            "daemon_root_id": "did:ember:daemon:test",
            "termination_authority": "user_session",
            "body": {},
        });
        let out = explain_receipt(envelope.to_string().as_bytes()).unwrap();
        assert_eq!(out["verdict"], "receipt_signature_missing");
        assert!(out["trust_root"].is_null());
    }

    /// Build a fingerprint_hex from a `FixtureSigner`'s public key. The
    /// signer's wire form is `PublicKey("ed25519:<hex>")`; stripping the
    /// prefix yields the canonical 64-hex fingerprint stored in
    /// `TrustRootRecord::fingerprint_hex`.
    fn fingerprint_hex_of(signer: &core_crypto::FixtureSigner) -> String {
        use core_crypto::Signer as _;
        let pk = signer.public_key();
        pk.0.strip_prefix("ed25519:")
            .expect("FixtureSigner pubkey carries ed25519: prefix")
            .to_string()
    }

    #[test]
    fn explain_receipt_verified_path_round_trips_real_signature() {
        use core_events::receipt::envelope::ReceiptVersion;
        use core_events::receipt::envelope::{ReceiptEnvelope, TerminationAuthority};
        use core_events::receipt::sign::sign_receipt_v2;

        // Serialize against parallel tests that also mutate the
        // process-global trust-root snapshot (binary-manifest verified
        // path, receipt no-matching-root, etc.).
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let signer = core_crypto::FixtureSigner::new("trust-explain-receipt-verified");
        let fp_hex = fingerprint_hex_of(&signer);

        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: fp_hex.clone(),
            source: TrustRootSource::Release,
        }]);

        let mut envelope = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "atomic.tool_call".to_string(),
            receipt_id: String::new(),
            daemon_root_id: "did:ember:daemon:test".to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: json!({"tool": "test", "arg": "v"}),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut envelope, &signer).expect("sign envelope");

        let envelope_bytes = serde_json::to_vec(&envelope).expect("serialize envelope");
        let out = explain_receipt(&envelope_bytes).unwrap();
        assert_eq!(
            out["verdict"], "verified",
            "expected verified, got verdict={} chain={}",
            out["verdict"], out["chain"]
        );
        assert_eq!(out["trust_root"]["fingerprint_hex"], fp_hex);
        assert_eq!(out["trust_root"]["source"], "release");
        assert!(out["chain"].as_str().unwrap().contains("VERIFIED"));
    }

    #[test]
    fn explain_receipt_no_matching_root_when_signer_absent_from_trust_set() {
        use core_events::receipt::envelope::ReceiptVersion;
        use core_events::receipt::envelope::{ReceiptEnvelope, TerminationAuthority};
        use core_events::receipt::sign::sign_receipt_v2;

        // Serialize against parallel tests that also mutate the
        // process-global trust-root snapshot.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Mint a signer NOT in the trust set.
        let signer = core_crypto::FixtureSigner::new("trust-explain-receipt-unknown");

        // Trust snapshot carries a DIFFERENT signer's fingerprint.
        let other = core_crypto::FixtureSigner::new("trust-explain-receipt-other");
        let other_fp = fingerprint_hex_of(&other);
        crate::binary_manifest::set_trust_roots_snapshot(vec![TrustRootRecord {
            fingerprint_hex: other_fp,
            source: TrustRootSource::Release,
        }]);

        let mut envelope = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: "atomic.tool_call".to_string(),
            receipt_id: String::new(),
            daemon_root_id: "did:ember:daemon:test".to_string(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: json!({"tool": "test"}),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut envelope, &signer).expect("sign envelope");

        let envelope_bytes = serde_json::to_vec(&envelope).expect("serialize");
        let out = explain_receipt(&envelope_bytes).unwrap();
        assert_eq!(out["verdict"], "no_matching_root");
        assert!(out["trust_root"].is_null());
        assert!(out["chain"].as_str().unwrap().contains("NO VERIFICATION"));
    }

    #[test]
    fn handle_trust_list_returns_empty_when_snapshot_uninit() {
        // The OnceLock is per-process; in this isolated test the snapshot
        // may or may not be initialised depending on test ordering. Both
        // are valid: assert the response is well-shaped either way.
        let out = handle_trust_list(&Value::Null).unwrap();
        let roots = out.get("roots").and_then(|v| v.as_array()).unwrap();
        // `roots` is a possibly-empty array of objects; every entry has
        // the two known keys.
        for r in roots {
            assert!(r.get("fingerprint_hex").is_some());
            assert!(r.get("source").is_some());
        }
        assert!(out.get("dev_mode_active").is_some());
    }
}

/// Handle `trust.show` JSON-RPC. Looks up one trust root by full
/// fingerprint or unique hex prefix. Returns:
///
/// ```json
/// {
///   "fingerprint_hex": "<64-hex>",
///   "source": "release" | "operator",
///   "posture": "prod" | "dev"
/// }
/// ```
///
/// Errors (JSON-RPC `code` / message):
///
/// - `-32602 missing root-id` — the `root_id` param is absent or empty.
/// - `-32004 trust_root_not_found` — no matching root in the snapshot.
/// - `-32004 trust_root_prefix_ambiguous` — prefix matches > 1 root;
///   caller must lengthen the prefix or use the full fingerprint.
///
/// Read-only operation — no peer-cred gating, same posture as
/// `trust.list`. Anchor: `trust_show_landed`.
pub fn handle_trust_show(params: &Value) -> Result<Value, (i32, String)> {
    let root_id = params
        .get("root_id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| (-32602, "missing root_id parameter".to_string()))?
        .to_ascii_lowercase();

    let records = trust_roots_snapshot();
    let matches: Vec<&TrustRootRecord> = records
        .iter()
        .filter(|r| r.fingerprint_hex.starts_with(&root_id))
        .collect();

    match matches.len() {
        0 => Err((
            -32004,
            format!("trust_root_not_found: no root matches {root_id}"),
        )),
        1 => {
            let r = matches[0];
            let source_str = match r.source {
                crate::binary_manifest::TrustRootSource::Release => "release",
                crate::binary_manifest::TrustRootSource::Operator => "operator",
            };
            let posture = if crate::binary_manifest::dev_mode_active() {
                "dev"
            } else {
                "prod"
            };
            Ok(json!({
                "fingerprint_hex": r.fingerprint_hex,
                "source": source_str,
                "posture": posture,
            }))
        }
        n => Err((
            -32004,
            format!(
                "trust_root_prefix_ambiguous: prefix {root_id:?} matches {n} roots; \
                 lengthen the prefix or use the full 64-hex fingerprint"
            ),
        )),
    }
}

/// Render the `trust.show` response as a human-readable detail block.
/// CLI-side render in `crates/emberlink-cli/src/trust/show.rs` mirrors
/// this; kept daemon-side too so future structured callers (dashboard,
/// dump-on-error paths) can reuse it.
pub fn render_trust_show_human(fingerprint_hex: &str, source: &str, posture: &str) -> String {
    format!(
        "Trust root:\n  Fingerprint: {fingerprint_hex}\n  Source:      {source}\n  Posture:     {posture}\n"
    )
}

/// Handle `trust.explain` JSON-RPC. Chain-walks a signed artifact back
/// to the trust root that verifies it.
///
/// Wire shape — request:
/// ```json
/// {
///   "artifact_kind": "binary_manifest",
///   "artifact_bytes_b64": "<base64 of canonical artifact bytes>",
///   "sidecar_bytes_b64": "<base64 of sidecar JSON bytes>"
/// }
/// ```
///
/// Wire shape — response:
/// ```json
/// {
///   "verdict": "verified" | "no_matching_root" | "sidecar_parse_error" | ...,
///   "trust_root": {"fingerprint_hex": "<64-hex>", "source": "release"|"operator"} | null,
///   "chain": "<human-readable chain walk>"
/// }
/// ```
///
/// The daemon takes raw bytes (not a path) so it never opens an
/// operator-supplied file path; the CLI handles file I/O and base64-
/// encodes the bytes for the wire.
///
/// Supported `artifact_kind` values:
///
/// - `"binary_manifest"` — sidecar bytes are the canonical JSON;
///   artifact bytes are the manifest body.
/// - `"receipt"` — artifact bytes are the canonical JSON-encoded
///   `ReceiptEnvelope`; sidecar bytes MUST be empty (receipts carry
///   their signature inline). See implementation-note-409.
///
/// Workflow grant chain walk lands in implementation-note-410.
///
/// Read-only operation; same posture as `trust.list` / `trust.show`
/// (`AuthorityClass::ConnectOnly`). Sentinels: `trust_explain_landed`
/// (binary-manifest) / `trust_explain_receipt_chain_walked` (receipt).
pub fn handle_trust_explain(params: &Value) -> Result<Value, (i32, String)> {
    let artifact_kind = params
        .get("artifact_kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "missing artifact_kind parameter".to_string()))?;
    let artifact_bytes_b64 = params
        .get("artifact_bytes_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "missing artifact_bytes_b64 parameter".to_string()))?;
    let sidecar_bytes_b64 = params
        .get("sidecar_bytes_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (-32602, "missing sidecar_bytes_b64 parameter".to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let artifact_bytes = b64
        .decode(artifact_bytes_b64)
        .map_err(|e| (-32602, format!("artifact_bytes_b64 decode: {e}")))?;
    let sidecar_bytes = b64
        .decode(sidecar_bytes_b64)
        .map_err(|e| (-32602, format!("sidecar_bytes_b64 decode: {e}")))?;

    match artifact_kind {
        "binary_manifest" => explain_binary_manifest(&artifact_bytes, &sidecar_bytes),
        "receipt" => {
            if !sidecar_bytes.is_empty() {
                return Ok(json!({
                    "verdict": "sidecar_not_supported_for_kind",
                    "trust_root": Value::Null,
                    "chain": "artifact (receipt) → caller supplied sidecar bytes; Receipt envelopes carry their signature inline — pass empty sidecar bytes".to_string(),
                }));
            }
            explain_receipt(&artifact_bytes)
        }
        other => Err((
            -32004,
            format!(
                "unsupported_artifact_kind: {other:?}; supported: binary_manifest, receipt (workflow_grant lands in implementation-note-410)"
            ),
        )),
    }
}

/// Chain-walk a Receipt envelope (canonical JSON bytes) against the
/// daemon's startup trust-root snapshot. Tries each root in order;
/// returns the first whose Ed25519 public key (reconstructed from the
/// fingerprint hex) successfully verifies the envelope via
/// `core_events::receipt::sign::verify_receipt_v2`.
///
/// Anchor: `trust_explain_receipt_chain_walked`.
///
/// Pure function — no I/O, no socket calls. Test-friendly.
fn explain_receipt(envelope_bytes: &[u8]) -> Result<Value, (i32, String)> {
    use core_crypto::{Ed25519Verifier, PublicKey};
    use core_events::receipt::envelope::ReceiptEnvelope;
    use core_events::receipt::sign::verify_receipt_v2;

    let envelope: ReceiptEnvelope = match serde_json::from_slice(envelope_bytes) {
        Ok(e) => e,
        Err(e) => {
            return Ok(json!({
                "verdict": "receipt_envelope_parse_error",
                "trust_root": Value::Null,
                "chain": format!("artifact (receipt) → envelope parse FAILED ({e})"),
            }));
        }
    };

    if envelope.signature.is_none() {
        return Ok(json!({
            "verdict": "receipt_signature_missing",
            "trust_root": Value::Null,
            "chain": format!(
                "artifact (receipt kind={}) → envelope has no signature field; cannot chain-walk",
                envelope.kind
            ),
        }));
    }

    let records = trust_roots_snapshot();
    if records.is_empty() {
        return Ok(json!({
            "verdict": "trust_roots_empty",
            "trust_root": Value::Null,
            "chain": format!(
                "artifact (receipt kind={}) → daemon's trust-root snapshot is empty (uninitialised); no root to verify against",
                envelope.kind
            ),
        }));
    }

    let verifier = Ed25519Verifier;
    for record in &records {
        let pubkey = PublicKey(format!("ed25519:{}", record.fingerprint_hex));
        if verify_receipt_v2(&envelope, &pubkey, &verifier).is_ok() {
            let source_str = match record.source {
                TrustRootSource::Release => "release",
                TrustRootSource::Operator => "operator",
            };
            let fp_short = &record.fingerprint_hex[..16.min(record.fingerprint_hex.len())];
            return Ok(json!({
                "verdict": "verified",
                "trust_root": {
                    "fingerprint_hex": record.fingerprint_hex,
                    "source": source_str,
                },
                "chain": format!(
                    "artifact (receipt kind={}) → envelope ed25519 signature → trust root {} ({}) — VERIFIED",
                    envelope.kind, fp_short, source_str,
                ),
            }));
        }
    }

    Ok(json!({
        "verdict": "no_matching_root",
        "trust_root": Value::Null,
        "chain": format!(
            "artifact (receipt kind={}) → envelope ed25519 signature → tried {} trust root(s) — NO VERIFICATION",
            envelope.kind, records.len()
        ),
    }))
}

/// Chain-walk a binary manifest + its sidecar against the daemon's
/// startup trust-root snapshot. Tries each root in order; returns the
/// first that verifies, or `no_matching_root` if none does.
///
/// Pure function — no I/O, no socket calls. Test-friendly.
fn explain_binary_manifest(
    manifest_bytes: &[u8],
    sidecar_bytes: &[u8],
) -> Result<Value, (i32, String)> {
    let sidecar: ManifestSidecar = match serde_json::from_slice(sidecar_bytes) {
        Ok(s) => s,
        Err(e) => {
            return Ok(json!({
                "verdict": "sidecar_parse_error",
                "trust_root": Value::Null,
                "chain": format!("artifact (binary_manifest) → sidecar parse FAILED ({e})"),
            }));
        }
    };

    if sidecar.schema_version != 1 {
        return Ok(json!({
            "verdict": "unsupported_schema_version",
            "trust_root": Value::Null,
            "chain": format!(
                "artifact (binary_manifest) → sidecar schema_version = {}; only v1 supported",
                sidecar.schema_version
            ),
        }));
    }
    if sidecar.signature_alg != "ed25519" {
        return Ok(json!({
            "verdict": "unsupported_signature_alg",
            "trust_root": Value::Null,
            "chain": format!(
                "artifact (binary_manifest) → sidecar signature_alg = {:?}; only ed25519 supported",
                sidecar.signature_alg
            ),
        }));
    }

    let sig_b64 = sidecar
        .signature
        .strip_prefix("ed25519:")
        .unwrap_or(&sidecar.signature);
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(e) => {
            return Ok(json!({
                "verdict": "signature_decode_error",
                "trust_root": Value::Null,
                "chain": format!("artifact (binary_manifest) → sidecar signature base64 decode FAILED ({e})"),
            }));
        }
    };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return Ok(json!({
                "verdict": "signature_format_error",
                "trust_root": Value::Null,
                "chain": format!("artifact (binary_manifest) → sidecar signature wrong shape ({e})"),
            }));
        }
    };

    let records = trust_roots_snapshot();
    if records.is_empty() {
        return Ok(json!({
            "verdict": "trust_roots_empty",
            "trust_root": Value::Null,
            "chain": "artifact (binary_manifest) → daemon's trust-root snapshot is empty (uninitialised); no root to verify against".to_string(),
        }));
    }

    for record in &records {
        let key = match verifying_key_from_fingerprint(&record.fingerprint_hex) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if key.verify(manifest_bytes, &signature).is_ok() {
            let source_str = match record.source {
                TrustRootSource::Release => "release",
                TrustRootSource::Operator => "operator",
            };
            let fp_short = &record.fingerprint_hex[..16.min(record.fingerprint_hex.len())];
            return Ok(json!({
                "verdict": "verified",
                "trust_root": {
                    "fingerprint_hex": record.fingerprint_hex,
                    "source": source_str,
                },
                "chain": format!(
                    "artifact (binary_manifest) → sidecar ed25519 signature → trust root {} ({}) — VERIFIED",
                    fp_short, source_str,
                ),
            }));
        }
    }

    Ok(json!({
        "verdict": "no_matching_root",
        "trust_root": Value::Null,
        "chain": format!(
            "artifact (binary_manifest) → sidecar ed25519 signature → tried {} trust root(s) — NO VERIFICATION",
            records.len()
        ),
    }))
}

/// Reconstruct an Ed25519 `VerifyingKey` from a `TrustRootRecord`'s
/// `fingerprint_hex`. The fingerprint IS the hex of the 32 public-key
/// bytes (per `TrustRootRecord` docstring), so this is a pure decode.
fn verifying_key_from_fingerprint(fingerprint_hex: &str) -> Result<VerifyingKey, ()> {
    let bytes = hex::decode(fingerprint_hex).map_err(|_| ())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ())
}

// trust_introspect_module_landed
// trust_show_landed
// trust_explain_landed
// trust_explain_receipt_chain_walked
