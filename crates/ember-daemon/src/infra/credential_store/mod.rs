//! Pluggable credential-store backend (ADR 137 — sub-piece A).
//!
//! Defines the `CredentialStore` trait that abstracts the byte-level
//! credential operations every backend (local-encrypted, HashiCorp Vault,
//! cloud KMS, …) must implement. Provider-config code (and any new
//! credential-aware path) takes `&dyn CredentialStore` instead of the
//! concrete `Vault`, so swapping backends is a startup-wiring concern
//! rather than a per-call-site rewrite.
//!
//! # Sub-piece A scope
//!
//! This commit ships:
//! - the `CredentialStore` trait + `StoreError` enum (this file)
//! - the `LocalEncryptedStore` impl that wraps the existing
//!   `crate::infra::vault::Vault` (in `local.rs`)
//!
//! Subsequent autopilot cycles ship the `HashiVaultStore` impl, the
//! retrofit of provider-config modules, daemon-startup wiring, CLI
//! extensions, and the cross-backend integration test harness.

pub mod hashicorp_vault;
pub mod local;

pub use hashicorp_vault::HashiVaultStore;
pub use local::LocalEncryptedStore;

/// Errors returned by `CredentialStore` impls.
///
/// Backend-specific errors flatten into one of these four variants so
/// callers can branch on the abstract failure mode (missing key, backend
/// unavailable, auth failed, generic) without depending on a particular
/// backend's error type.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The requested key does not exist in this backend.
    #[error("not found: {0}")]
    NotFound(String),
    /// The backend itself is unreachable or in a bad state (network down,
    /// vault sealed, SQLite locked, …). Callers may retry.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// The credentials/token used to talk to the backend were rejected.
    /// Distinct from `Unavailable` because the operator action is
    /// different (rotate creds vs wait/retry).
    #[error("auth failed: {0}")]
    AuthFailed(String),
    /// Catch-all for backend-specific errors that don't map cleanly onto
    /// the variants above. Carry the backend's message verbatim.
    #[error("backend error: {0}")]
    Other(String),
}

/// Backend-agnostic credential store.
///
/// Implementations MUST be `Send + Sync` so the trait object can be held
/// behind an `Arc<dyn CredentialStore>` shared across the daemon's async
/// surface. Daemon-internal impls that wrap `!Send` types (e.g. the
/// rusqlite-backed `DaemonStore`) rely on the daemon's single-threaded
/// `tokio::task::LocalSet` invariant and use `unsafe impl Send + Sync`
/// the same way `DaemonApprovalStore` does — see
/// `crate::trust::approval::DaemonApprovalStore` for the pattern.
#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    /// Fetch the raw credential value at `key`.
    ///
    /// Returns `StoreError::NotFound` if the key is absent. Callers MUST
    /// NOT distinguish "absent" from "auth failed" — the backend-level
    /// error variants exist precisely so callers can react correctly.
    async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError>;

    /// Store `value` at `key`. Overwrites if the key already exists.
    ///
    /// Backends that don't support overwrite-in-place (e.g. immutable
    /// cloud KMS material) MAY return `StoreError::Other` describing the
    /// constraint.
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError>;

    /// List keys, optionally filtered to those starting with `prefix`.
    ///
    /// `None` and `Some("")` are equivalent — both list every key in the
    /// backend. Sort order is backend-defined; callers that need a
    /// stable order MUST sort the returned vec themselves.
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError>;

    /// Enumerate key names without reading the underlying plaintext values.
    ///
    /// Backends that can answer from metadata alone should override this so
    /// callers can distinguish "is this provider configured?" from "can I
    /// decrypt/use the secret right now?". The default falls back to
    /// [`Self::list`] for backends where plain enumeration and normal listing
    /// are the same operation.
    async fn list_metadata(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
        self.list(prefix).await
    }

    /// Delete the key at `key`.
    ///
    /// Backends that don't support deletion fall back to the default
    /// impl, which returns `StoreError::Other("delete unsupported …")`.
    /// Sub-piece A's `LocalEncryptedStore` implements real deletion;
    /// future immutable-backend impls may keep the default.
    async fn delete(&self, _key: &str) -> Result<(), StoreError> {
        Err(StoreError::Other(
            "delete unsupported by this backend".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// In-memory `CredentialStore` impl used by provider-config unit tests
/// that exercise the `<provider>_config_from_store` sibling functions.
///
/// Backed by a `Mutex<HashMap<String, Vec<u8>>>` so the trait's async
/// methods can be called from a `#[tokio::test]` without spinning up a
/// real `LocalEncryptedStore`. Behaviour is intentionally minimal:
/// `get`/`put`/`list`/`delete` are byte-faithful, and absent keys
/// surface as `StoreError::NotFound`.
#[cfg(test)]
pub mod test_helpers {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::{CredentialStore, StoreError};

    pub struct MockCredentialStore {
        inner: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl Default for MockCredentialStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockCredentialStore {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl CredentialStore for MockCredentialStore {
        async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
            let guard = self.inner.lock().expect("mock store mutex poisoned");
            match guard.get(key) {
                Some(v) => Ok(v.clone()),
                None => Err(StoreError::NotFound(key.to_string())),
            }
        }

        async fn put(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
            let mut guard = self.inner.lock().expect("mock store mutex poisoned");
            guard.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
            let guard = self.inner.lock().expect("mock store mutex poisoned");
            let prefix = prefix.unwrap_or("");
            Ok(guard
                .keys()
                .filter(|k| prefix.is_empty() || k.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn list_metadata(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
            self.list(prefix).await
        }

        async fn delete(&self, key: &str) -> Result<(), StoreError> {
            let mut guard = self.inner.lock().expect("mock store mutex poisoned");
            match guard.remove(key) {
                Some(_) => Ok(()),
                None => Err(StoreError::NotFound(key.to_string())),
            }
        }
    }
}
