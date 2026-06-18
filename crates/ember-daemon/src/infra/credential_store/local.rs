//! Local-encrypted credential store backend.
//!
//! `LocalEncryptedStore` adapts the existing `crate::infra::vault::Vault`
//! (XChaCha20-Poly1305 sealed credentials persisted in SQLite via
//! `DaemonStore`) to the `CredentialStore` trait. It is the default
//! backend for single-host daemons that don't have an external KMS.
//!
//! # Threading
//!
//! `DaemonStore` wraps a `rusqlite::Connection` which is `!Send + !Sync`.
//! The daemon runs on a single-threaded `tokio::task::LocalSet`, so the
//! struct is never moved across threads in practice. The `unsafe impl
//! Send + Sync` mirrors `crate::trust::approval::DaemonApprovalStore`'s
//! handling of the same constraint.
//!
//! Vault credential operations are CPU-bound (a single AEAD seal/open)
//! and complete synchronously in microseconds, so the async trait
//! methods just call through to the underlying sync `Vault` API
//! directly rather than dispatching through `spawn_blocking`.
//!
//! # Receipt emission
//!
//! Per security-review Findings 5 and 17 (audit-completeness
//! gap for vault reads), every successful `get` emits a v2
//! [`ReceiptEnvelope`] with `kind = "vault.read"`. Emission is
//! best-effort — failures to sign or persist log a warning but do not
//! fail the read itself. Tests and pre-startup paths that have not
//! initialised the process identity (`current_identity()` returns
//! `None`) silently skip emission.

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::sign_receipt_v2;
use zeroize::Zeroize;

use crate::infra::store::DaemonStore;
use crate::infra::vault::{VaultError, VaultScope, logical_name_from_storage};

use super::{CredentialStore, StoreError};

/// v2 kind discriminator for `LocalEncryptedStore::get` success-path
/// audit. Per security-review Findings 5, 17 — daemon
/// vault reads must leave a signed receipt so post-hoc audit can
/// reconstruct which credentials were read by whom and when.
pub(crate) const RECEIPT_KIND_VAULT_READ: &str = "vault.read";

enum VaultSource {
    SharedInteractive,
    BootstrapInteractive(Rc<crate::infra::vault::Vault>),
    HeadlessAttestedEnrollment { data_dir: PathBuf },
    InteractiveOrHeadless { data_dir: PathBuf },
}

/// `CredentialStore` impl backed by the local sealed-credential vault.
///
/// The live vault is resolved from the shared
/// store slot at point of use instead of being owned directly here. That lets
/// explicit lock cut off credential-store reads without needing to tear down
/// the helper itself.
///
/// `Rc<DaemonStore>` (the SQLite connection — `!Send + !Sync`) is confined
/// to the daemon's `LocalSet` thread.
pub struct LocalEncryptedStore {
    store: Rc<DaemonStore>,
    vault_source: VaultSource,
}

// SAFETY: `DaemonStore` (rusqlite) is `!Send + !Sync` by marker, but the
// daemon runs on a single-threaded tokio `LocalSet` and never moves
// instances of this type across threads. The `unsafe impl` mirrors
// `DaemonApprovalStore` (see `src/trust/approval.rs`) which carries the
// same invariant for the same reason — the `CredentialStore` trait
// requires `Send + Sync` so the trait object can be shared via
// `Arc<dyn CredentialStore>`.
unsafe impl Send for LocalEncryptedStore {}
unsafe impl Sync for LocalEncryptedStore {}

impl LocalEncryptedStore {
    /// Construct a new `LocalEncryptedStore` from an open store. The live
    /// vault is read from the store's shared slot on each operation.
    pub fn new(store: Rc<DaemonStore>) -> Self {
        Self {
            store,
            vault_source: VaultSource::SharedInteractive,
        }
    }

    /// Construct a bootstrap-scoped `LocalEncryptedStore` that reads through a
    /// temporary vault handle without requiring the daemon's shared live-vault
    /// slot to be populated.
    ///
    /// Runtime startup uses this narrower seam for broker credential hydration
    /// so the daemon can keep the shared interactive slot empty until an
    /// operator-triggered `register_session` / `vault_unlock` repopulates it.
    pub fn with_bootstrap_vault(
        store: Rc<DaemonStore>,
        vault: Rc<crate::infra::vault::Vault>,
    ) -> Self {
        Self {
            store,
            vault_source: VaultSource::BootstrapInteractive(vault),
        }
    }

    /// Construct a headless-scoped `LocalEncryptedStore` that rehydrates a
    /// temporary vault from the active attested enrollment on each operation.
    ///
    /// This keeps the headless MEK out of long-lived daemon memory and gives
    /// ADR 139 a real second adapter to build unattended broker authority on
    /// without publishing anything into the shared interactive live-vault
    /// slot.
    pub fn with_headless_attested_enrollment(
        store: Rc<DaemonStore>,
        data_dir: impl AsRef<Path>,
    ) -> Self {
        Self {
            store,
            vault_source: VaultSource::HeadlessAttestedEnrollment {
                data_dir: data_dir.as_ref().to_path_buf(),
            },
        }
    }

    /// Construct the local runtime authority seam for broker reloads.
    ///
    /// Read paths prefer the shared interactive live-vault slot and fall back
    /// to the active headless enrollment only when the interactive lane is
    /// unavailable. Mutation paths stay interactive-only so headless
    /// enrollment cannot silently widen into a general local-vault write lane.
    pub fn with_runtime_authority(store: Rc<DaemonStore>, data_dir: impl AsRef<Path>) -> Self {
        Self {
            store,
            vault_source: VaultSource::InteractiveOrHeadless {
                data_dir: data_dir.as_ref().to_path_buf(),
            },
        }
    }

    fn current_interactive_vault(
        &self,
        key: &str,
    ) -> Result<Rc<crate::infra::vault::Vault>, StoreError> {
        match &self.vault_source {
            VaultSource::BootstrapInteractive(vault) => Ok(Rc::clone(vault)),
            _ => crate::infra::interactive_unlock::current_live_vault(&self.store).map_err(|err| {
                StoreError::Unavailable(err.with_context(&format!("vault key {key}")))
            }),
        }
    }

    fn read_access(
        &self,
        key: &str,
    ) -> Result<(Rc<crate::infra::vault::Vault>, VaultScope), StoreError> {
        match &self.vault_source {
            VaultSource::SharedInteractive => Ok((
                self.current_interactive_vault(key)?,
                VaultScope::Interactive,
            )),
            VaultSource::BootstrapInteractive(vault) => {
                Ok((Rc::clone(vault), VaultScope::Interactive))
            }
            VaultSource::HeadlessAttestedEnrollment { data_dir } => Ok((
                current_headless_vault(&self.store, data_dir, key)?,
                VaultScope::Headless,
            )),
            VaultSource::InteractiveOrHeadless { data_dir } => {
                match self.current_interactive_vault(key) {
                    Ok(vault) => Ok((vault, VaultScope::Interactive)),
                    Err(interactive_err) => {
                        match current_headless_vault(&self.store, data_dir, key) {
                            Ok(vault) => Ok((vault, VaultScope::Headless)),
                            Err(headless_err) => Err(StoreError::Unavailable(format!(
                                "runtime authority unavailable for key {key}: interactive lane unavailable ({interactive_err}); headless lane unavailable ({headless_err})"
                            ))),
                        }
                    }
                }
            }
        }
    }

    fn write_access(
        &self,
        key: &str,
    ) -> Result<(Rc<crate::infra::vault::Vault>, VaultScope), StoreError> {
        match &self.vault_source {
            VaultSource::SharedInteractive => Ok((
                self.current_interactive_vault(key)?,
                VaultScope::Interactive,
            )),
            VaultSource::BootstrapInteractive(vault) => {
                Ok((Rc::clone(vault), VaultScope::Interactive))
            }
            VaultSource::HeadlessAttestedEnrollment { data_dir } => Ok((
                current_headless_vault(&self.store, data_dir, key)?,
                VaultScope::Headless,
            )),
            VaultSource::InteractiveOrHeadless { .. } => self
                .current_interactive_vault(key)
                .map(|vault| (vault, VaultScope::Interactive))
                .map_err(|err| {
                    StoreError::Unavailable(format!(
                        "interactive runtime authority required for key {key}: {err}"
                    ))
                }),
        }
    }

    fn list_metadata_names(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        let metadata_scope = match &self.vault_source {
            VaultSource::HeadlessAttestedEnrollment { .. } => VaultScope::Headless,
            VaultSource::SharedInteractive
            | VaultSource::BootstrapInteractive(_)
            | VaultSource::InteractiveOrHeadless { .. } => VaultScope::Interactive,
        };
        let prefix = prefix.unwrap_or("");
        let mut stmt = self
            .store
            .conn()
            .prepare("SELECT name FROM credentials ORDER BY created_at")
            .map_err(|e| StoreError::Other(format!("sqlite: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StoreError::Other(format!("sqlite: {e}")))?;

        let mut names = Vec::new();
        for row in rows {
            let stored_name = row.map_err(|e| StoreError::Other(format!("sqlite: {e}")))?;
            let Some(logical_name) = logical_name_from_storage(metadata_scope, &stored_name) else {
                continue;
            };
            if prefix.is_empty() || logical_name.starts_with(prefix) {
                names.push(logical_name);
            }
        }
        Ok(names)
    }
}

fn current_headless_vault(
    store: &DaemonStore,
    data_dir: &Path,
    key: &str,
) -> Result<Rc<crate::infra::vault::Vault>, StoreError> {
    match crate::infra::attested_device::AttestedDevice::active_status(data_dir) {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(err) = crate::infra::headless_scope::clear_headless_scope(store) {
                tracing::warn!(
                    error = %err,
                    "headless scope cleanup failed while clearing stale ciphertext after enrollment disappearance"
                );
            }
            return Err(StoreError::Unavailable(format!(
                "headless enrollment unavailable for vault key {key}: no active enrollment"
            )));
        }
        Err(err) => {
            return Err(StoreError::Unavailable(format!(
                "headless enrollment metadata unavailable for vault key {key}: {err}"
            )));
        }
    }

    let Some(device) = crate::infra::attested_device::AttestedDevice::load_active(data_dir)
        .map_err(|err| {
            StoreError::Unavailable(format!(
                "headless enrollment metadata unavailable for vault key {key}: {err}"
            ))
        })?
    else {
        return Err(StoreError::Unavailable(format!(
            "headless enrollment unavailable for vault key {key}: no active enrollment"
        )));
    };

    let mut mek = device.unwrap_mek().map_err(|err| {
        StoreError::Unavailable(format!(
            "headless enrollment key unavailable for vault key {key}: {err}"
        ))
    })?;
    // Vault-scope MEK split (B1) + adversarial CRIT-1 fix
    // (2026-05-22): construct a headless-only Vault. Pre-fix this used
    // `Vault::new(mek)` which set BOTH lanes to the headless MEK; any
    // accidental `seal()` / `Vault::add(Interactive, ...)` call on the
    // returned Rc would silently route headless-MEK through the
    // Interactive lane. The new constructor sets `interactive_key`
    // to the all-zero checkpoint and the refusal logic on Interactive
    // operations makes the lane structurally unreachable.
    let vault = Rc::new(crate::infra::vault::Vault::new_headless_only(mek));
    mek.zeroize();
    Ok(vault)
}

/// Translate `VaultError` into the abstract `StoreError`.
///
/// The mapping is intentionally narrow: only `NotFound` carries
/// directly; everything else lands in `Other` with the original message
/// preserved. `InvalidName` (ADR 097/099 path-grammar gate) is also
/// `Other` because the credential-store contract doesn't yet have a
/// dedicated "invalid key" variant — adding one is a follow-up if other
/// backends grow similar gates.
fn map_vault_error(e: VaultError, key: &str) -> StoreError {
    match e {
        VaultError::NotFound => StoreError::NotFound(key.to_string()),
        VaultError::Store(inner) => StoreError::Other(format!("sqlite: {inner}")),
        VaultError::Crypto(msg) => StoreError::Other(format!("crypto: {msg}")),
        VaultError::PresenceRequired => {
            StoreError::Unavailable("credential requires fresh biometric presence".to_string())
        }
        VaultError::Keyring(msg) => StoreError::Unavailable(format!("keyring: {msg}")),
        VaultError::Io(msg) => StoreError::Unavailable(format!("io: {msg}")),
        VaultError::ProductionSentinelMissing(msg) => {
            StoreError::Unavailable(format!("production checkpoint missing: {msg}"))
        }
        VaultError::InvalidName(name_err) => {
            // `VaultNameError` carries its own `Display` impl with a
            // human-readable rendering of the path-grammar violation.
            StoreError::Other(format!("invalid credential name: {}", name_err))
        }
        // Sealed-blob variants. These
        // errors only surface from `export_mek_sealed`/`import_mek_sealed`
        // (the vault-level sealed-export substrate), not from the
        // get/list/add/remove credential paths this mapper serves. Map
        // through `Other` with the variant's Display so an unexpected
        // surface still produces a useful operator-facing message.
        sealed @ (VaultError::SealedBlobInvalid(_)
        | VaultError::SealedBlobTruncated { .. }
        | VaultError::SealedBlobBadMagic { .. }
        | VaultError::SealedBlobUnknownVersion { .. }
        | VaultError::SealedBlobUnknownKdf { .. }
        | VaultError::SealedBlobUnknownAead { .. }
        | VaultError::SealedBlobFingerprintMismatch { .. }
        | VaultError::SealedBlobAeadFailure) => StoreError::Other(format!("sealed-blob: {sealed}")),
        // Same shape: surfaces
        // from the rotation-witness emit path
        // (`emit_identity_rotation_witness`) which the credential
        // store does not call today, but the variant must still be
        // covered so the match stays exhaustive.
        emit @ VaultError::WitnessEmit(_) => {
            StoreError::Other(format!("identity-rotation-witness: {emit}"))
        }
        // Vault-scope MEK split (B1) + adversarial CRIT-1
        // fix: a headless-only Vault refusing an Interactive-lane op
        // surfaces as `HeadlessOnly`. The local credential store only
        // routes Headless-scope operations through `current_headless_vault`
        // (which uses `Vault::new_headless_only`), so this branch fires
        // only if a caller mis-uses a headless-only Vault for an
        // Interactive op — a programmer error, not a runtime condition.
        // Map to `Other` so the operator-facing error names the
        // structural cause.
        VaultError::HeadlessOnly => {
            StoreError::Other("headless-only vault refused interactive-lane operation".to_string())
        }
        VaultError::AuthorityBearingRequiresPresence => StoreError::Other(
            "authority-bearing vault value requires presence-unwrapped scope KEK".to_string(),
        ),
        VaultError::AuthorityCustodyRotationUnsupported => StoreError::Other(
            "MEK rotation is unsupported on a presence-backed (KEK_s) vault".to_string(),
        ),
    }
}

#[async_trait::async_trait]
impl CredentialStore for LocalEncryptedStore {
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let (vault, scope) = self.read_access(key)?;
        let plaintext = vault
            .get(scope, &self.store, key)
            .map_err(|e| map_vault_error(e, key))?;

        // Emit a v2 `vault.read` Receipt
        // on the success path so the audit trail includes every
        // daemon-side credential read. Best-effort — emission failures
        // log a warning but do NOT fail the read.
        emit_vault_read_receipt(&self.store, key, scope);

        Ok(plaintext.to_vec())
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        // `put` is the overwrite-capable path. Route through
        // `Vault::replace` so the local encrypted store matches the
        // daemon RPC's `vault_put` semantics and avoids a delete/add
        // race window.
        let (vault, scope) = self.write_access(key)?;
        vault
            .replace(scope, &self.store, key, value, None)
            .map(|_info| ())
            .map_err(|e| map_vault_error(e, key))
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        let (vault, scope) = self.read_access(prefix.unwrap_or(""))?;
        let infos = vault
            .list(scope, &self.store)
            .map_err(|e| map_vault_error(e, ""))?;
        let prefix = prefix.unwrap_or("");
        let names = infos
            .into_iter()
            .map(|info| info.name)
            .filter(|name| prefix.is_empty() || name.starts_with(prefix))
            .collect();
        Ok(names)
    }

    async fn list_metadata(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        self.list_metadata_names(prefix)
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let (vault, scope) = self.write_access(key)?;
        vault
            .remove(scope, &self.store, key)
            .map_err(|e| map_vault_error(e, key))
    }
}

// ---------------------------------------------------------------------------
// Receipt emission
// ---------------------------------------------------------------------------

/// Best-effort: build, sign, and persist a v2 `vault.read` Receipt for
/// a successful `LocalEncryptedStore::get`.
///
/// Persistence path: an `audit_log` row (action = `vault.read`,
/// credential = key, outcome = `allowed`, details = the signed
/// envelope JSON). The unified `receipts` table is reserved for
/// `broker.*` kinds (per `store_broker_receipt_v2`); a future cycle
/// can either widen that path or add a sibling `store_atomic_receipt_v2`
/// — for Phase 1 the audit log row carries the full signed envelope so
/// no signed evidence is lost.
///
/// Skips silently when the process identity is not initialised
/// (test harness, pre-startup paths). Logs a warning and returns on
/// sign/persist failure rather than propagating — the caller already
/// has the plaintext; failing the read to make a side-effect green
/// would be a regression, not a fix.
fn vault_scope_label(scope: VaultScope) -> &'static str {
    match scope {
        VaultScope::Interactive => "interactive",
        VaultScope::Headless => "headless",
    }
}

fn emit_vault_read_receipt(store: &DaemonStore, key: &str, scope: VaultScope) {
    let Some(identity) = crate::infra::receipt::current_identity() else {
        // Tests and pre-startup paths — silently skip. The receipt is a
        // best-effort audit artifact; the read itself is the contract.
        return;
    };

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = serde_json::json!({
        "key": key,
        "scope": vault_scope_label(scope),
        "read_at_epoch_secs": now_epoch,
    });
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: RECEIPT_KIND_VAULT_READ.to_string(),
        receipt_id: String::new(),
        daemon_root_id: identity.pubkey_hex(),
        traceparent: None,
        // Daemon-emitted audit receipt — the daemon persona is the
        // termination authority (same posture as broker.materialization).
        termination_authority: TerminationAuthority::DaemonPersona,
        presence_kind: None,
        body,
        signature: None,
        calling_principal: None,
        presence_reason: None,
        handle_id: None,
        challenge_hash: None,
        verifier_aaguid: None,
    };

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    if let Err(e) = sign_receipt_v2(&mut envelope, &signer) {
        tracing::warn!(
            error = %e,
            key = key,
            "vault.read: failed to sign v2 receipt — read succeeded, audit row omitted"
        );
        return;
    }

    let envelope_json = match serde_json::to_string(&envelope) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                error = %e,
                key = key,
                "vault.read: failed to serialize signed envelope — audit row omitted"
            );
            return;
        }
    };

    if let Err(e) = store.log_event(
        None,
        RECEIPT_KIND_VAULT_READ,
        Some(key),
        "allowed",
        Some(&envelope_json),
    ) {
        tracing::warn!(
            error = %e,
            key = key,
            receipt_id = %envelope.receipt_id,
            "vault.read: failed to persist audit row — read succeeded"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests (T1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::store::DaemonStore;
    use crate::infra::vault::Vault;

    /// Build a `LocalEncryptedStore` over an in-memory daemon store +
    /// deterministic test vault. Mirrors the pattern used elsewhere in
    /// `infra::store::tests` (open_in_memory ships a vault-attached
    /// store under `cfg(test)`).
    fn fresh_store() -> LocalEncryptedStore {
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        store.set_vault(Rc::new(Vault::new([0xABu8; 32])));
        LocalEncryptedStore::new(store)
    }

    // The async trait surface is exercised on a current_thread runtime
    // because LocalEncryptedStore intentionally pins to the daemon's
    // single-threaded LocalSet model.
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn get_put_round_trip() {
        let cs = fresh_store();
        rt().block_on(async {
            cs.put("svc/api-token", b"hunter2").await.unwrap();
            let got = cs.get("svc/api-token").await.unwrap();
            assert_eq!(got, b"hunter2");
        });
    }

    #[test]
    fn get_missing_key_returns_not_found() {
        let cs = fresh_store();
        rt().block_on(async {
            let err = cs.get("does-not-exist").await.unwrap_err();
            match err {
                StoreError::NotFound(key) => assert_eq!(key, "does-not-exist"),
                other => panic!("expected NotFound, got {other:?}"),
            }
        });
    }

    #[test]
    fn get_without_live_vault_surfaces_shared_unavailable_contract() {
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let cs = LocalEncryptedStore::new(store);

        rt().block_on(async {
            let err = cs.get("svc/no-vault").await.unwrap_err();
            match err {
                StoreError::Unavailable(message) => {
                    assert!(
                        message.contains("live vault is locked"),
                        "shared live-vault seam must keep the unavailable reason: {message}"
                    );
                    assert!(
                        message.contains("ember vault unlock"),
                        "shared live-vault seam must keep operator guidance: {message}"
                    );
                }
                other => panic!("expected Unavailable, got {other:?}"),
            }
        });
    }

    #[test]
    fn bootstrap_vault_override_reads_without_live_slot() {
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let cs = LocalEncryptedStore::with_bootstrap_vault(
            Rc::clone(&store),
            Rc::new(Vault::new([0xBCu8; 32])),
        );

        rt().block_on(async {
            cs.put("svc/bootstrap-token", b"bootstrap").await.unwrap();
            let got = cs.get("svc/bootstrap-token").await.unwrap();
            assert_eq!(got, b"bootstrap");
            assert!(
                store.vault().is_none(),
                "bootstrap credential hydration must not populate the shared live-vault slot"
            );
        });
    }

    #[test]
    fn headless_attested_enrollment_requires_active_enrollment() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let cs =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());

        rt().block_on(async {
            let err = cs.get("svc/headless-token").await.unwrap_err();
            match err {
                StoreError::Unavailable(message) => {
                    assert!(
                        message.contains("headless enrollment unavailable"),
                        "missing headless enrollment must surface the authority seam: {message}"
                    );
                    assert!(
                        message.contains("no active enrollment"),
                        "missing headless enrollment must explain the operator action: {message}"
                    );
                }
                other => panic!("expected Unavailable, got {other:?}"),
            }
            assert!(
                store.vault().is_none(),
                "headless credential reads must not rely on the shared interactive live-vault slot"
            );
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_headless_enrollment_clears_stale_headless_scope() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let stray = Vault::new([0xD3u8; 32]);
        stray
            .add(
                VaultScope::Headless,
                &store,
                "svc/stale-headless",
                b"stale",
                None,
            )
            .unwrap();
        assert_eq!(
            crate::infra::headless_scope::list_headless_keys(&store).unwrap(),
            vec!["svc/stale-headless".to_string()]
        );

        let cs =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());

        rt().block_on(async {
            let err = cs.get("svc/stale-headless").await.unwrap_err();
            assert!(
                matches!(err, StoreError::Unavailable(_)),
                "missing enrollment must still fail closed"
            );
        });

        assert!(
            crate::infra::headless_scope::list_headless_keys(&store)
                .unwrap()
                .is_empty(),
            "stale headless ciphertext must be pruned once the daemon observes no active enrollment"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn headless_attested_enrollment_round_trips_without_live_slot() {
        use std::time::Duration;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let persona = "test-local-encrypted-store-headless";
        let mek = [0xD4u8; 32];
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let device = crate::infra::attested_device::AttestedDevice::enroll_active(
            tmp.path(),
            persona,
            Duration::from_secs(3600),
            &mek,
        )
        .expect("enroll active succeeds");
        let cs =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());

        rt().block_on(async {
            cs.put("svc/headless-token", b"headless").await.unwrap();
            let got = cs.get("svc/headless-token").await.unwrap();
            assert_eq!(got, b"headless");
            assert!(
                store.vault().is_none(),
                "headless credential hydration must not populate the shared interactive live-vault slot"
            );
        });

        crate::infra::attested_device::AttestedDevice::revoke_active(
            tmp.path(),
            Some(&device.enrollment_id),
        )
        .expect("revoke active succeeds");
    }

    #[test]
    fn runtime_authority_falls_back_to_headless_when_interactive_unavailable() {
        use std::time::Duration;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let persona = "test-runtime-headless-read-fallback";
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let device = crate::infra::attested_device::AttestedDevice::enroll_active(
            tmp.path(),
            persona,
            Duration::from_secs(3600),
            &[0xD5u8; 32],
        )
        .expect("enroll active succeeds");
        let headless =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());
        let runtime = LocalEncryptedStore::with_runtime_authority(Rc::clone(&store), tmp.path());

        rt().block_on(async {
            headless.put("svc/runtime-token", b"headless").await.unwrap();
            let got = runtime.get("svc/runtime-token").await.unwrap();
            assert_eq!(got, b"headless");
            assert!(
                store.vault().is_none(),
                "runtime authority fallback must not repopulate the shared interactive live-vault slot"
            );
        });

        crate::infra::attested_device::AttestedDevice::revoke_active(
            tmp.path(),
            Some(&device.enrollment_id),
        )
        .expect("revoke active succeeds");
    }

    #[test]
    fn runtime_authority_writes_still_require_interactive_unlock() {
        use std::time::Duration;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let persona = "test-runtime-headless-write-locked";
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let device = crate::infra::attested_device::AttestedDevice::enroll_active(
            tmp.path(),
            persona,
            Duration::from_secs(3600),
            &[0xE1u8; 32],
        )
        .expect("enroll active succeeds");
        let runtime = LocalEncryptedStore::with_runtime_authority(Rc::clone(&store), tmp.path());

        rt().block_on(async {
            let err = runtime
                .put("svc/runtime-write", b"blocked")
                .await
                .unwrap_err();
            match err {
                StoreError::Unavailable(message) => {
                    assert!(
                        message.contains("interactive runtime authority required"),
                        "runtime writes must stay interactive-only: {message}"
                    );
                }
                other => panic!("expected Unavailable, got {other:?}"),
            }
            assert!(
                store.vault().is_none(),
                "interactive-only write failure must not repopulate the shared live-vault slot"
            );
        });

        crate::infra::attested_device::AttestedDevice::revoke_active(
            tmp.path(),
            Some(&device.enrollment_id),
        )
        .expect("revoke active succeeds");
    }

    #[test]
    fn list_empty_prefix_returns_all() {
        let cs = fresh_store();
        rt().block_on(async {
            cs.put("alpha", b"a").await.unwrap();
            cs.put("beta", b"b").await.unwrap();
            cs.put("gamma", b"g").await.unwrap();

            let mut all = cs.list(None).await.unwrap();
            all.sort();
            assert_eq!(
                all,
                vec!["alpha".to_string(), "beta".into(), "gamma".into()]
            );

            let mut all2 = cs.list(Some("")).await.unwrap();
            all2.sort();
            assert_eq!(all2, all);
        });
    }

    #[test]
    fn list_prefix_filters_correctly() {
        let cs = fresh_store();
        rt().block_on(async {
            cs.put("svc/a", b"1").await.unwrap();
            cs.put("svc/b", b"2").await.unwrap();
            cs.put("other/c", b"3").await.unwrap();

            let mut svc = cs.list(Some("svc/")).await.unwrap();
            svc.sort();
            assert_eq!(svc, vec!["svc/a".to_string(), "svc/b".into()]);

            let other = cs.list(Some("other/")).await.unwrap();
            assert_eq!(other, vec!["other/c".to_string()]);

            let none = cs.list(Some("nope/")).await.unwrap();
            assert!(none.is_empty(), "expected empty list, got {none:?}");
        });
    }

    #[test]
    fn list_metadata_without_live_vault_uses_store_names_only() {
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let bootstrap = LocalEncryptedStore::with_bootstrap_vault(
            Rc::clone(&store),
            Rc::new(Vault::new([0xA7u8; 32])),
        );
        let shared = LocalEncryptedStore::new(Rc::clone(&store));

        rt().block_on(async {
            bootstrap.put("svc/a", b"1").await.unwrap();
            bootstrap.put("svc/b", b"2").await.unwrap();
            bootstrap.put("other/c", b"3").await.unwrap();

            let mut svc = shared.list_metadata(Some("svc/")).await.unwrap();
            svc.sort();
            assert_eq!(svc, vec!["svc/a".to_string(), "svc/b".to_string()]);
            assert!(
                store.vault().is_none(),
                "metadata-only listing must not populate the shared live-vault slot"
            );

            let err = shared.get("svc/a").await.unwrap_err();
            assert!(
                matches!(err, StoreError::Unavailable(_)),
                "metadata-only enumeration must not imply plaintext access"
            );
        });
    }

    #[test]
    fn list_metadata_respects_headless_namespace_boundaries() {
        use std::time::Duration;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let persona = "test-headless-metadata-scope";
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let bootstrap = LocalEncryptedStore::with_bootstrap_vault(
            Rc::clone(&store),
            Rc::new(Vault::new([0xA7u8; 32])),
        );
        let device = crate::infra::attested_device::AttestedDevice::enroll_active(
            tmp.path(),
            persona,
            Duration::from_secs(3600),
            &[0xC4u8; 32],
        )
        .expect("enroll active succeeds");
        let headless =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());
        let shared = LocalEncryptedStore::new(Rc::clone(&store));

        rt().block_on(async {
            bootstrap.put("svc/interactive", b"i").await.unwrap();
            headless.put("svc/headless", b"h").await.unwrap();

            let mut interactive = shared.list_metadata(Some("svc/")).await.unwrap();
            interactive.sort();
            assert_eq!(interactive, vec!["svc/interactive".to_string()]);

            let mut headless_keys = headless.list_metadata(Some("svc/")).await.unwrap();
            headless_keys.sort();
            assert_eq!(headless_keys, vec!["svc/headless".to_string()]);
        });

        crate::infra::attested_device::AttestedDevice::revoke_active(
            tmp.path(),
            Some(&device.enrollment_id),
        )
        .expect("revoke active succeeds");
    }

    #[test]
    fn delete_removes_key() {
        let cs = fresh_store();
        rt().block_on(async {
            cs.put("ephemeral", b"v").await.unwrap();
            cs.delete("ephemeral").await.unwrap();
            let err = cs.get("ephemeral").await.unwrap_err();
            assert!(matches!(err, StoreError::NotFound(_)));
        });
    }

    #[test]
    fn delete_missing_key_returns_not_found() {
        let cs = fresh_store();
        rt().block_on(async {
            let err = cs.delete("never-existed").await.unwrap_err();
            assert!(matches!(err, StoreError::NotFound(_)));
        });
    }

    /// With the daemon identity
    /// initialised, a successful `get` must leave a signed
    /// `vault.read` row in the audit log carrying the credential
    /// name + the signed envelope JSON.
    ///
    /// Identity initialisation is process-wide (`OnceCell`), so the
    /// test tolerates the cell already being set by a sibling test —
    /// it only requires that `current_identity()` returns `Some` at
    /// the moment of emission.
    #[test]
    fn get_emits_vault_read_audit_row_when_identity_present() {
        use crate::infra::audit::AuditFilter;

        let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
        store.set_vault(Rc::new(Vault::new([0xCDu8; 32])));
        let cs = LocalEncryptedStore::new(Rc::clone(&store));

        // Ensure the process-singleton daemon identity is initialised
        // for this test run. `OnceCell` guarantees idempotency across
        // parallel tests; we just need *some* identity present.
        let tmp = tempfile::TempDir::new().expect("tempdir for identity");
        let _ = crate::infra::receipt::init_identity(tmp.path());
        assert!(
            crate::infra::receipt::current_identity().is_some(),
            "identity must initialise for this test"
        );

        rt().block_on(async {
            cs.put("svc/api-token", b"hunter2").await.unwrap();
            // Drain any audit rows the `put` may have emitted by
            // recording the count before the `get` under test.
            let before = store
                .query_audit(&AuditFilter {
                    action: Some(RECEIPT_KIND_VAULT_READ.to_string()),
                    ..AuditFilter::default()
                })
                .unwrap();
            let _ = cs.get("svc/api-token").await.unwrap();
            let after = store
                .query_audit(&AuditFilter {
                    action: Some(RECEIPT_KIND_VAULT_READ.to_string()),
                    ..AuditFilter::default()
                })
                .unwrap();
            assert_eq!(
                after.len(),
                before.len() + 1,
                "exactly one vault.read audit row must be added per successful get"
            );
            let row = after.first().expect("at least one row");
            assert_eq!(row.action, RECEIPT_KIND_VAULT_READ);
            assert_eq!(row.credential.as_deref(), Some("svc/api-token"));
            assert_eq!(row.outcome, "allowed");
            // Details should be a JSON-serialized signed envelope with a
            // non-empty receipt_id and signature.
            let details = row
                .details
                .as_deref()
                .expect("vault.read row must carry the signed envelope JSON");
            let envelope: ReceiptEnvelope =
                serde_json::from_str(details).expect("details must be a ReceiptEnvelope");
            assert_eq!(envelope.kind, RECEIPT_KIND_VAULT_READ);
            assert!(
                !envelope.receipt_id.is_empty(),
                "signed envelope must have a non-empty receipt_id"
            );
            assert!(
                envelope.signature.is_some(),
                "signed envelope must carry a signature"
            );
            // Body must include the key + scope discriminator.
            assert_eq!(
                envelope.body.get("key").and_then(|v| v.as_str()),
                Some("svc/api-token")
            );
            assert_eq!(
                envelope.body.get("scope").and_then(|v| v.as_str()),
                Some("interactive")
            );
        });
    }

    /// A cache-miss `get` (NotFound)
    /// must NOT emit a vault.read audit row — emission is success-path
    /// only so the audit log reflects credentials actually exposed.
    #[test]
    fn get_does_not_emit_audit_row_on_not_found() {
        use crate::infra::audit::AuditFilter;

        let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
        store.set_vault(Rc::new(Vault::new([0xEFu8; 32])));
        let cs = LocalEncryptedStore::new(Rc::clone(&store));

        // Same identity-init posture as the success-path test.
        let tmp = tempfile::TempDir::new().expect("tempdir for identity");
        let _ = crate::infra::receipt::init_identity(tmp.path());

        rt().block_on(async {
            let err = cs.get("absent-key").await.unwrap_err();
            assert!(matches!(err, StoreError::NotFound(_)));
            let rows = store
                .query_audit(&AuditFilter {
                    action: Some(RECEIPT_KIND_VAULT_READ.to_string()),
                    ..AuditFilter::default()
                })
                .unwrap();
            // The store is fresh — no successful get has happened — so
            // there must be zero vault.read rows.
            assert!(
                rows.is_empty(),
                "cache-miss must NOT emit vault.read audit row; got {} rows",
                rows.len()
            );
        });
    }
}
