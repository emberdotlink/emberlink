//! T2 integration tests for snapshot emission and pull-side snapshot storage
//! in `crates/ember-daemon/src/snapshot.rs`.
//!
//! These tests were previously in-tree `#[cfg(test)] mod tests { ... }` cases
//! that imported `tempfile::TempDir` and `tokio::net::TcpListener`. They need
//! real filesystem paths for daemon identity/snapshot files and a loopback HTTP
//! listener for pull-side verification, so their right home is a T2 integration
//! file rather than the source module's T1 unit tests.
//!
//! Refiled per `AUDIT-V030-T1-BASELINE-DRAIN-PART-3`. Tests cover:
//! - `SnapshotEmitter::emit_snapshot` snapshot-id emission and chain linkage
//! - `SnapshotEmitter::maybe_emit` first-call and cadence-gated paths
//! - persisted encrypted snapshot blobs carrying `vault.salt` state
//! - `pull_cluster_snapshot` signature-failure no-write behavior
//! - `pull_cluster_snapshot` happy path, including `list_local_snapshots`
//!
//! Internal-only T1 tests (manifest signing/verification, blob encryption
//! round-trip, wrong-identity decryption failure, and private cadence state)
//! remain in-tree under `src/snapshot.rs`.
//!
//! Anchor: t1_tier_baseline_drained_part3
//!
//! CLASSIFICATION: PUBLIC

use std::path::Path;

use bytes::Bytes;
use core_grant_types::grant_receipt::{Evidence, SnapshotManifest};
use ember_daemon::infra::receipt::DaemonPersona;
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::{Vault, VaultScope};
use ember_daemon::snapshot::{
    PullError, SnapshotEmitter, decrypt_vault_blob, list_local_snapshots, pull_cluster_snapshot,
    sign_snapshot_manifest,
};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::LocalSet;

fn test_identity(dir: &Path) -> DaemonPersona {
    DaemonPersona::load_or_create(dir).expect("identity")
}

fn read_snapshot_manifest(data_dir: &Path, snapshot_id: &str) -> SnapshotManifest {
    let manifest_path = data_dir
        .join("snapshots")
        .join(format!("{}.manifest.json", &snapshot_id[..16]));
    let contents = std::fs::read(&manifest_path).expect("manifest file exists");
    serde_json::from_slice(&contents).expect("parse manifest")
}

fn read_snapshot_blob(data_dir: &Path, snapshot_id: &str) -> Vec<u8> {
    let blob_path = data_dir
        .join("snapshots")
        .join(format!("{}.blob.bin", &snapshot_id[..16]));
    std::fs::read(&blob_path).expect("snapshot blob exists")
}

#[test]
fn emit_snapshot_returns_snapshot_id() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let emitter = SnapshotEmitter::new(3600);

    let id = emitter
        .emit_snapshot(&store, &identity, tmp.path(), 0)
        .expect("emit_snapshot");
    assert!(!id.is_empty(), "snapshot_id should be non-empty");
}

#[test]
fn maybe_emit_returns_some_on_first_call() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let emitter = SnapshotEmitter::new(0);

    let result = emitter
        .maybe_emit(&store, &identity, tmp.path(), 0)
        .expect("maybe_emit");
    assert!(result.is_some());
}

#[test]
fn maybe_emit_returns_none_before_interval_expires() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let emitter = SnapshotEmitter::new(86400);

    let first = emitter
        .maybe_emit(&store, &identity, tmp.path(), 0)
        .expect("first");
    assert!(first.is_some());

    let second = emitter
        .maybe_emit(&store, &identity, tmp.path(), 0)
        .expect("second");
    assert!(second.is_none());
}

#[test]
fn emit_snapshot_chains_prev_snapshot_id() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let emitter = SnapshotEmitter::new(0);

    let id1 = emitter
        .emit_snapshot(&store, &identity, tmp.path(), 0)
        .expect("first snapshot");
    let id2 = emitter
        .emit_snapshot(&store, &identity, tmp.path(), 0)
        .expect("second snapshot");

    assert_ne!(id1, id2);

    let manifest = read_snapshot_manifest(tmp.path(), &id2);
    assert_eq!(manifest.prev_snapshot_id, Some(id1));
}

#[test]
fn emit_snapshot_blob_includes_vault_salt() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();
    let salt_bytes = [0xABu8; 16];
    std::fs::write(tmp.path().join("vault.salt"), salt_bytes).unwrap();

    let id = SnapshotEmitter::new(0)
        .emit_snapshot(&store, &identity, tmp.path(), 0)
        .expect("emit_snapshot");
    let blob = read_snapshot_blob(tmp.path(), &id);
    let state = decrypt_vault_blob(&blob, &identity).expect("decrypt snapshot blob");

    assert_eq!(state.vault_salt_hex, hex::encode(salt_bytes));
}

#[test]
fn emit_snapshot_blob_without_salt_file_uses_empty_hex() {
    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());
    let store = DaemonStore::open_in_memory().unwrap();

    let id = SnapshotEmitter::new(0)
        .emit_snapshot(&store, &identity, tmp.path(), 0)
        .expect("emit_snapshot");
    let blob = read_snapshot_blob(tmp.path(), &id);
    let state = decrypt_vault_blob(&blob, &identity).expect("decrypt snapshot blob");

    assert_eq!(state.vault_salt_hex, "");
}

#[tokio::test]
async fn pull_cluster_snapshot_rejects_tampered_manifest() {
    let _process_test_guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());

    let mut manifest = SnapshotManifest {
        snapshot_id: "tamper-test-id-0000".to_string(),
        prev_snapshot_id: None,
        taken_at_epoch_secs: 1_700_000_000,
        vault_state_hash: "aabbccdd".to_string(),
        event_log_high_watermark: 5,
        daemon_persona_pubkey: identity.pubkey_hex(),
        evidence: Evidence::default(),
    };
    sign_snapshot_manifest(&mut manifest, &identity);
    manifest.event_log_high_watermark = 9999;

    let encrypted_blob_hex = hex::encode(b"fake-blob-bytes");
    let snapshot_id = manifest.snapshot_id.clone();
    let pubkey_hex = identity.pubkey_hex();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{addr}");

    let snapshot_id_clone = snapshot_id.clone();
    let manifest_clone = manifest.clone();
    let blob_hex_clone = encrypted_blob_hex.clone();

    let local = LocalSet::new();
    local.spawn_local(async move {
        for _ in 0..2 {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let snap_id = snapshot_id_clone.clone();
            let manifest_c = manifest_clone.clone();
            let blob_hex_c = blob_hex_clone.clone();
            tokio::task::spawn_local(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let path = req.uri().path().to_string();
                    let snap_id = snap_id.clone();
                    let manifest_c = manifest_c.clone();
                    let blob_hex_c = blob_hex_c.clone();
                    async move {
                        let body = if path == "/api/cluster-snapshot/latest" {
                            serde_json::json!({ "snapshot_id": snap_id }).to_string()
                        } else {
                            serde_json::json!({
                                "manifest": manifest_c,
                                "encrypted_blob_hex": blob_hex_c,
                            })
                            .to_string()
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new([0xAB; 32]);

    let result = local
        .run_until(pull_cluster_snapshot(
            &endpoint,
            "test-cluster",
            &pubkey_hex,
            &vault,
            &store,
        ))
        .await;

    assert!(
        matches!(result, Err(PullError::SignatureInvalid)),
        "expected SignatureInvalid for tampered manifest, got: {result:?}"
    );

    let creds = vault
        .list(VaultScope::Interactive, &store)
        .unwrap_or_default();
    assert!(
        creds
            .iter()
            .all(|c| !c.name.starts_with("cluster-snapshot")),
        "vault must not contain cluster-snapshot entries after signature failure"
    );
}

#[tokio::test]
async fn pull_cluster_snapshot_stores_valid_snapshot() {
    let _process_test_guard = ember_daemon::PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let tmp = TempDir::new().unwrap();
    let identity = test_identity(tmp.path());

    let mut manifest = SnapshotManifest {
        snapshot_id: "valid-pull-test-id-0000".to_string(),
        prev_snapshot_id: None,
        taken_at_epoch_secs: 1_700_000_001,
        vault_state_hash: "cafebabe".to_string(),
        event_log_high_watermark: 42,
        daemon_persona_pubkey: identity.pubkey_hex(),
        evidence: Evidence::default(),
    };
    sign_snapshot_manifest(&mut manifest, &identity);
    let pubkey_hex = identity.pubkey_hex();

    let encrypted_blob_hex = hex::encode(b"valid-snapshot-blob-bytes");
    let snapshot_id = manifest.snapshot_id.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{addr}");

    let snapshot_id_clone = snapshot_id.clone();
    let manifest_clone = manifest.clone();
    let blob_hex_clone = encrypted_blob_hex.clone();

    let local = LocalSet::new();
    local.spawn_local(async move {
        for _ in 0..2 {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let snap_id = snapshot_id_clone.clone();
            let manifest_c = manifest_clone.clone();
            let blob_hex_c = blob_hex_clone.clone();
            tokio::task::spawn_local(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let path = req.uri().path().to_string();
                    let snap_id = snap_id.clone();
                    let manifest_c = manifest_c.clone();
                    let blob_hex_c = blob_hex_c.clone();
                    async move {
                        let body = if path == "/api/cluster-snapshot/latest" {
                            serde_json::json!({ "snapshot_id": snap_id }).to_string()
                        } else {
                            serde_json::json!({
                                "manifest": manifest_c,
                                "encrypted_blob_hex": blob_hex_c,
                            })
                            .to_string()
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = Vault::new([0xAB; 32]);

    let result = local
        .run_until(pull_cluster_snapshot(
            &endpoint,
            "my-cluster",
            &pubkey_hex,
            &vault,
            &store,
        ))
        .await;

    assert!(result.is_ok(), "expected Ok, got: {result:?}");
    let returned_id = result.unwrap();
    assert_eq!(
        returned_id,
        Some(snapshot_id.clone()),
        "should return the pulled snapshot_id"
    );

    let creds = vault
        .list(VaultScope::Interactive, &store)
        .unwrap_or_default();
    let has_blob = creds.iter().any(|c| c.name.contains("snap-"));
    let has_meta = creds.iter().any(|c| c.name.contains("meta-"));
    assert!(has_blob, "vault must contain blob entry");
    assert!(has_meta, "vault must contain manifest (meta) entry");

    let entries = list_local_snapshots(&vault, &store, Some("my-cluster"));
    assert_eq!(entries.len(), 1, "expected 1 local snapshot entry");
    assert_eq!(entries[0].snapshot_id, snapshot_id);
    assert_eq!(entries[0].cluster_id, "my-cluster");
}
