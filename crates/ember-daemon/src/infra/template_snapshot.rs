//! Headless-enrollment delegated-policy snapshot substrate.
//!
//! Per the headless-enrollment receipt design, the daemon must record an
//! immutable, content-addressed snapshot of any policy template referenced
//! during enrollment. The snapshot is canonicalized (whitespace-stripped,
//! keys sorted) so byte-equal templates produce byte-equal hashes regardless
//! of how the operator authored the input, and then hashed with blake3 to
//! produce the stable identifier carried in the Receipt body.
//!
//! The snapshot hashes the canonicalized *effective delegated policy document*
//! emitted at enrollment time. The content-addressed namespace remains
//! `templates/<blake3-hex>`, but the backing store for this slice is the
//! daemon data dir rather than a separate vault namespace.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use core_events::receipt::HeadlessDelegatedMaterial;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPosture {
    pub operating_context: String,
    pub fallback: String,
    pub delegation: String,
}

impl Default for SnapshotPosture {
    fn default() -> Self {
        Self {
            operating_context: "headless".to_string(),
            fallback: "strict".to_string(),
            delegation: "delegated".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotActionIdentity {
    pub plugin_address: String,
    pub plugin_version: String,
    pub action_key: String,
    pub action_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveDelegatedPolicySnapshot {
    pub schema_version: u8,
    pub persona_id: String,
    pub posture: SnapshotPosture,
    pub duration_seconds: u64,
    pub expiry_unix: i64,
    pub actions: Vec<SnapshotActionIdentity>,
    pub authority_refs: Vec<String>,
    pub delegated_material: HeadlessDelegatedMaterial,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub widenings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotStoreError {
    #[error("serialize snapshot: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(String),
}

/// Canonicalize arbitrary template JSON bytes into a deterministic byte
/// representation suitable for content addressing.
///
/// Semantics:
/// - Empty input -> empty `Vec` (no JSON parse attempted).
/// - Object keys are sorted lexicographically at every nesting depth via
///   `BTreeMap` round-trip, so authoring-order drift cannot affect the hash.
/// - Whitespace is stripped because the output goes through
///   `serde_json::to_vec` (compact, no pretty-printing).
/// - Non-object JSON values (arrays, strings, numbers, bools, null) are
///   preserved verbatim except for compact re-serialization.
///
/// Invalid input that does not parse as JSON returns an empty `Vec`. This
/// keeps the function infallible at the type level - Phase 2 callers wrap
/// it in a higher-level check that refuses to mint a snapshot when the
/// input was unparseable.
pub fn canonicalize(template_bytes: &[u8]) -> Vec<u8> {
    if template_bytes.is_empty() {
        return Vec::new();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(template_bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let sorted = sort_value(parsed);
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// Hash canonical bytes with blake3.
///
/// Pure wrapper around `blake3::hash` - exists so callers reference the
/// canonical hash function rather than re-deriving blake3 invocations
/// inline (one builder, no drift; cf. canonical-receipt-builder rule).
pub fn hash(canonical_bytes: &[u8]) -> blake3::Hash {
    blake3::hash(canonical_bytes)
}

/// Format the vault namespace key used to store a template snapshot.
///
/// Convention: `templates/<blake3-hex>`. The namespace is content-addressed,
/// so multiple enrollments referencing the same canonical template share a
/// single vault entry.
pub fn vault_namespace(h: &blake3::Hash) -> String {
    format!("templates/{}", h.to_hex())
}

pub fn canonical_snapshot_bytes(
    snapshot: &EffectiveDelegatedPolicySnapshot,
) -> Result<Vec<u8>, serde_json::Error> {
    let raw = serde_json::to_vec(snapshot)?;
    Ok(canonicalize(&raw))
}

pub fn snapshot_hash(
    snapshot: &EffectiveDelegatedPolicySnapshot,
) -> Result<blake3::Hash, serde_json::Error> {
    Ok(hash(&canonical_snapshot_bytes(snapshot)?))
}

pub fn store_snapshot(
    data_dir: &Path,
    snapshot: &EffectiveDelegatedPolicySnapshot,
) -> Result<String, SnapshotStoreError> {
    let canonical = canonical_snapshot_bytes(snapshot)?;
    let digest = hash(&canonical);
    let path = snapshot_path(data_dir, &digest);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| SnapshotStoreError::Io(format!("create {}: {err}", parent.display())))?;
    }
    fs::write(&path, canonical)
        .map_err(|err| SnapshotStoreError::Io(format!("write {}: {err}", path.display())))?;
    Ok(digest.to_hex().to_string())
}

pub fn load_snapshot(
    data_dir: &Path,
    snapshot_hash_hex: &str,
) -> Result<Option<EffectiveDelegatedPolicySnapshot>, SnapshotStoreError> {
    let path = data_dir
        .join("templates")
        .join(format!("{snapshot_hash_hex}.json"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SnapshotStoreError::Io(format!(
                "read {}: {err}",
                path.display()
            )));
        }
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn snapshot_path(data_dir: &Path, digest: &blake3::Hash) -> PathBuf {
    data_dir
        .join("templates")
        .join(format!("{}.json", digest.to_hex()))
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sort_value).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_is_deterministic() {
        let input = br#"{"a":1,"b":[2,3],"c":{"d":4}}"#;
        let first = canonicalize(input);
        let second = canonicalize(input);
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn canonicalize_handles_whitespace_drift() {
        let compact = br#"{"a":1,"b":2}"#;
        let spaced = br#"{ "a" : 1, "b" : 2 }"#;
        assert_eq!(canonicalize(compact), canonicalize(spaced));
    }

    #[test]
    fn canonicalize_sorts_keys() {
        let reversed = br#"{"b":2,"a":1}"#;
        let ordered = br#"{"a":1,"b":2}"#;
        assert_eq!(canonicalize(reversed), canonicalize(ordered));
    }

    #[test]
    fn canonicalize_sorts_keys_recursively() {
        let outer_reversed = br#"{"z":{"y":2,"x":1},"a":1}"#;
        let outer_ordered = br#"{"a":1,"z":{"x":1,"y":2}}"#;
        assert_eq!(canonicalize(outer_reversed), canonicalize(outer_ordered));
    }

    #[test]
    fn canonicalize_empty_input_returns_empty() {
        assert!(canonicalize(b"").is_empty());
    }

    #[test]
    fn canonicalize_invalid_json_returns_empty() {
        assert!(canonicalize(b"not json {{{").is_empty());
    }

    #[test]
    fn hash_returns_blake3() {
        let canonical = canonicalize(br#"{"a":1}"#);
        let h = hash(&canonical);
        let expected = blake3::hash(&canonical).to_hex().to_string();
        assert_eq!(h.to_hex().to_string(), expected);
        assert_eq!(h, hash(&canonical));
    }

    #[test]
    fn hash_differs_for_different_inputs() {
        let a = canonicalize(br#"{"a":1}"#);
        let b = canonicalize(br#"{"a":2}"#);
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn vault_namespace_includes_hex_hash() {
        let canonical = canonicalize(br#"{"a":1}"#);
        let h = hash(&canonical);
        let ns = vault_namespace(&h);
        assert_eq!(ns, format!("templates/{}", h.to_hex()));
        assert!(ns.starts_with("templates/"));
        assert_eq!(ns.len(), "templates/".len() + 64);
    }

    #[test]
    fn store_snapshot_round_trips_effective_policy_document() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshot = EffectiveDelegatedPolicySnapshot {
            schema_version: 1,
            persona_id: "main".to_string(),
            posture: SnapshotPosture::default(),
            duration_seconds: 3600,
            expiry_unix: 1_717_000_000,
            actions: vec![SnapshotActionIdentity {
                plugin_address: "registry.ember.systems/ember-systems/ember-gh".to_string(),
                plugin_version: "0.1.0".to_string(),
                action_key: "pr_merge".to_string(),
                action_version: "v1".to_string(),
            }],
            authority_refs: vec!["github".to_string()],
            delegated_material: HeadlessDelegatedMaterial {
                vault_paths: vec!["pulumi/org/project/stack".to_string()],
                env_passthrough: vec!["PULUMI_CONFIG_PASSPHRASE".to_string()],
                file_env: vec!["KUBECONFIG".to_string()],
            },
            widenings: Vec::new(),
        };
        let digest = store_snapshot(tmp.path(), &snapshot).unwrap();
        let loaded = load_snapshot(tmp.path(), &digest).unwrap().unwrap();
        assert_eq!(loaded, snapshot);
    }
}
