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
//! # Receipt emission (implementation-note-93)
//!
//! Per implementation-note-136 security-review Findings 5 and 17 (audit-completeness
//! gap for vault reads), every successful `get` emits a v2
//! [`ReceiptEnvelope`] with `kind = "vault.read"`. Emission is
//! best-effort — failures to sign or persist log a warning but do not
//! fail the read itself. Tests and pre-startup paths that have not
//! initialised the process identity (`current_identity()` returns
//! `None`) silently skip emission.

use std::rc::Rc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::sign_receipt_v2;

use crate::infra::store::DaemonStore;
use crate::infra::vault::{Vault, VaultError, VaultScope};

use super::{CredentialStore, StoreError};

/// v2 kind discriminator for `LocalEncryptedStore::get` success-path
/// audit. Per implementation-note-93 (Findings 5, 17 — daemon
/// vault reads must leave a signed receipt so post-hoc audit can
/// reconstruct which credentials were read by whom and when).
pub(crate) const RECEIPT_KIND_VAULT_READ: &str = "vault.read";

/// `CredentialStore` impl backed by the local sealed-credential vault.
///
/// implementation-note-137: holds an `Rc<Vault>` (was `Arc<Vault>`
/// — switched to `Rc` so the daemon's LocalSet has a single
/// reference-count substrate, the MEK byte-array is shared with the
/// proxy / dashboard / store Rc<Vault>s, and the Send/Sync invariant is
/// carried by the unsafe impl below rather than by the inner Arc).
/// `Rc<DaemonStore>` (the SQLite connection — `!Send + !Sync`) is
/// confined to the daemon's `LocalSet` thread.
pub struct LocalEncryptedStore {
    vault: Rc<Vault>,
    store: Rc<DaemonStore>,
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
    /// Construct a new `LocalEncryptedStore` from an open vault and an
    /// open store. Both arguments are typically minted at daemon startup
    /// (`runtime.rs` — wired in sub-piece D) and reused for the rest of
    /// the process lifetime.
    pub fn new(vault: Rc<Vault>, store: Rc<DaemonStore>) -> Self {
        Self { vault, store }
    }
}

/// Translate `VaultError` into the abstract `StoreError`.
///
/// The mapping is intentionally narrow: only `NotFound` carries
/// directly; everything else lands in `Other` with the original message
/// preserved. `InvalidName` (design path-grammar gate) is also
/// `Other` because the credential-store contract doesn't yet have a
/// dedicated "invalid key" variant — adding one is a follow-up if other
/// backends grow similar gates.
fn map_vault_error(e: VaultError, key: &str) -> StoreError {
    match e {
        VaultError::NotFound => StoreError::NotFound(key.to_string()),
        VaultError::Store(inner) => StoreError::Other(format!("sqlite: {inner}")),
        VaultError::Crypto(msg) => StoreError::Other(format!("crypto: {msg}")),
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
    }
}

#[async_trait::async_trait]
impl CredentialStore for LocalEncryptedStore {
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let plaintext = self
            .vault
            .get(VaultScope::Interactive, &self.store, key)
            .map_err(|e| map_vault_error(e, key))?;

        // implementation-note-93: emit a v2 `vault.read` Receipt
        // on the success path so the audit trail includes every
        // daemon-side credential read. Best-effort — emission failures
        // log a warning but do NOT fail the read.
        emit_vault_read_receipt(&self.store, key);

        Ok(plaintext)
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        // `Vault::add` enforces the design path-grammar gate on new
        // keys and inserts a freshly-encrypted row. SQLite enforces
        // `name` uniqueness via index, so a "put" over an existing key
        // currently fails — this matches the existing `vault_add`
        // semantics. Overwrite-in-place is a follow-up; for now callers
        // must `delete` first if they really mean overwrite.
        self.vault
            .add(VaultScope::Interactive, &self.store, key, value, None)
            .map(|_info| ())
            .map_err(|e| map_vault_error(e, key))
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        let infos = self
            .vault
            .list(VaultScope::Interactive, &self.store)
            .map_err(|e| map_vault_error(e, ""))?;
        let prefix = prefix.unwrap_or("");
        let names = infos
            .into_iter()
            .map(|info| info.name)
            .filter(|name| prefix.is_empty() || name.starts_with(prefix))
            .collect();
        Ok(names)
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.vault
            .remove(VaultScope::Interactive, &self.store, key)
            .map_err(|e| map_vault_error(e, key))
    }
}

// ---------------------------------------------------------------------------
// Receipt emission (implementation-note-93)
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
fn emit_vault_read_receipt(store: &DaemonStore, key: &str) {
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
        "scope": "interactive",
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
        let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
        let vault = Rc::new(Vault::new([0xABu8; 32]));
        LocalEncryptedStore::new(vault, store)
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
    fn list_empty_prefix_returns_all() {
        let cs = fresh_store();
        rt().block_on(async {
            cs.put("alpha", b"a").await.unwrap();
            cs.put("beta", b"b").await.unwrap();
            cs.put("gamma", b"g").await.unwrap();

            let mut all = cs.list(None).await.unwrap();
            all.sort();
            assert_eq!(all, vec!["alpha".to_string(), "beta".into(), "gamma".into()]);

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

    /// implementation-note-93: with the daemon identity
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
        let vault = Rc::new(Vault::new([0xCDu8; 32]));
        let cs = LocalEncryptedStore::new(vault, Rc::clone(&store));

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

    /// implementation-note-93: a cache-miss `get` (NotFound)
    /// must NOT emit a vault.read audit row — emission is success-path
    /// only so the audit log reflects credentials actually exposed.
    #[test]
    fn get_does_not_emit_audit_row_on_not_found() {
        use crate::infra::audit::AuditFilter;

        let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
        let vault = Rc::new(Vault::new([0xEFu8; 32]));
        let cs = LocalEncryptedStore::new(vault, Rc::clone(&store));

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
