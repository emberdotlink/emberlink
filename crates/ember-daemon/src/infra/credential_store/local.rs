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

use std::rc::Rc;
use std::sync::Arc;

use crate::infra::store::DaemonStore;
use crate::infra::vault::{Vault, VaultError};

use super::{CredentialStore, StoreError};

/// `CredentialStore` impl backed by the local sealed-credential vault.
///
/// Holds an `Arc<Vault>` (the encryption key — `Send + Sync`) and an
/// `Rc<DaemonStore>` (the SQLite connection — `!Send + !Sync`, but
/// confined to the daemon's `LocalSet` thread).
pub struct LocalEncryptedStore {
    vault: Arc<Vault>,
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
    pub fn new(vault: Arc<Vault>, store: Rc<DaemonStore>) -> Self {
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
        self.vault
            .get(&self.store, key)
            .map_err(|e| map_vault_error(e, key))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        // `Vault::add` enforces the design path-grammar gate on new
        // keys and inserts a freshly-encrypted row. SQLite enforces
        // `name` uniqueness via index, so a "put" over an existing key
        // currently fails — this matches the existing `vault_add`
        // semantics. Overwrite-in-place is a follow-up; for now callers
        // must `delete` first if they really mean overwrite.
        self.vault
            .add(&self.store, key, value, None)
            .map(|_info| ())
            .map_err(|e| map_vault_error(e, key))
    }

    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        let infos = self
            .vault
            .list(&self.store)
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
            .remove(&self.store, key)
            .map_err(|e| map_vault_error(e, key))
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
        let vault = Arc::new(Vault::new([0xABu8; 32]));
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
}
