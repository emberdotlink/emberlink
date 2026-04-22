//! Credential cache with zeroize-on-revocation semantics.
//!
//! The agent SDK holds cached credential material in [`SecretHandle`] from
//! `core-crypto`. When the daemon pushes a `grant_revoked` notification, the
//! cache invalidates the matching entry, zeroizing the underlying bytes.
//! Subsequent calls to [`CredentialCache::use_credential`] for that grant
//! return [`UseError::Revoked`] without hitting the network.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use core_crypto::secret_handle::{SecretError, SecretHandle};

/// Cache of secret handles keyed by grant ID.
///
/// Shared across tasks via [`Arc`]. Interior mutability allows the reader
/// task to invalidate entries while other tasks read them.
#[derive(Clone, Default)]
pub struct CredentialCache {
    inner: Arc<Mutex<HashMap<String, SecretHandle>>>,
}

/// Error returned when a cached credential cannot be used.
#[derive(Debug)]
pub enum UseError {
    /// No handle cached for the given grant ID.
    NotCached,
    /// The grant has been revoked by the owner. The cached buffer has been
    /// zeroized. The minimal message deliberately omits the grant ID, scope,
    /// credential name, or persona — those would leak authority context.
    Revoked,
}

impl std::fmt::Display for UseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UseError::NotCached => write!(f, "credential not cached"),
            UseError::Revoked => write!(f, "grant revoked by owner"),
        }
    }
}

impl std::error::Error for UseError {}

impl CredentialCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a cached secret for a grant. Replaces any prior entry; the
    /// replaced [`SecretHandle`]'s [`Drop`] zeroizes its bytes.
    pub fn insert(&self, grant_id: impl Into<String>, secret: Vec<u8>) {
        let handle = SecretHandle::new(secret);
        let mut guard = self.inner.lock().expect("credential cache lock poisoned");
        guard.insert(grant_id.into(), handle);
    }

    /// Run a closure with access to the cached credential bytes. The bytes
    /// never leave the cache — the closure receives a short-lived reference.
    ///
    /// Returns [`UseError::NotCached`] if no entry exists, or
    /// [`UseError::Revoked`] if the entry has been revoked.
    pub fn use_credential<T>(
        &self,
        grant_id: &str,
        f: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, UseError> {
        let guard = self.inner.lock().expect("credential cache lock poisoned");
        let handle = guard.get(grant_id).ok_or(UseError::NotCached)?;
        match handle.expose() {
            Ok(bytes) => Ok(f(bytes)),
            Err(SecretError::Revoked) => Err(UseError::Revoked),
        }
    }

    /// Mark a grant's cached credential as revoked and zeroize its bytes.
    ///
    /// Idempotent: revoking an unknown or already-revoked grant is a no-op.
    /// After revocation, `use_credential` returns [`UseError::Revoked`] for
    /// this grant ID until a new value is inserted.
    pub fn revoke(&self, grant_id: &str) {
        let mut guard = self.inner.lock().expect("credential cache lock poisoned");
        if let Some(handle) = guard.get_mut(grant_id) {
            handle.revoke();
        }
    }

    /// Whether a cached entry exists for this grant and is still active.
    pub fn is_active(&self, grant_id: &str) -> bool {
        let guard = self.inner.lock().expect("credential cache lock poisoned");
        guard
            .get(grant_id)
            .map(|h| !h.is_revoked())
            .unwrap_or(false)
    }

    /// Number of cache entries (including revoked tombstones).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_use_returns_bytes() {
        let cache = CredentialCache::new();
        cache.insert("grant-1", b"secret-token".to_vec());
        let got = cache
            .use_credential("grant-1", |b| b.to_vec())
            .expect("should succeed");
        assert_eq!(got, b"secret-token");
    }

    #[test]
    fn use_without_insert_returns_not_cached() {
        let cache = CredentialCache::new();
        let err = cache
            .use_credential("grant-missing", |_| ())
            .expect_err("should fail");
        assert!(matches!(err, UseError::NotCached));
    }

    #[test]
    fn revoke_zeroizes_and_blocks_use() {
        let cache = CredentialCache::new();
        cache.insert("grant-1", b"super-secret".to_vec());
        assert!(cache.is_active("grant-1"));

        cache.revoke("grant-1");
        assert!(!cache.is_active("grant-1"));

        let err = cache
            .use_credential("grant-1", |_| ())
            .expect_err("should fail");
        assert!(matches!(err, UseError::Revoked));
    }

    #[test]
    fn revoke_unknown_grant_is_noop() {
        let cache = CredentialCache::new();
        cache.revoke("grant-nonexistent");
        // Nothing panics.
        assert!(cache.is_empty());
    }

    #[test]
    fn revoke_then_insert_replaces_handle() {
        let cache = CredentialCache::new();
        cache.insert("grant-1", b"v1".to_vec());
        cache.revoke("grant-1");
        cache.insert("grant-1", b"v2".to_vec());
        // Reinsertion supersedes the revoked tombstone.
        let got = cache
            .use_credential("grant-1", |b| b.to_vec())
            .expect("fresh insert is usable");
        assert_eq!(got, b"v2");
    }

    #[test]
    fn revoke_error_message_leaks_nothing() {
        let err = UseError::Revoked;
        let msg = err.to_string();
        // The error message must not include grant IDs, credential names,
        // scopes, or personas — that would leak authority context to the
        // agent.
        assert_eq!(msg, "grant revoked by owner");
    }

    #[test]
    fn multiple_grants_revoke_independently() {
        let cache = CredentialCache::new();
        cache.insert("a", b"v-a".to_vec());
        cache.insert("b", b"v-b".to_vec());
        cache.insert("c", b"v-c".to_vec());

        cache.revoke("b");
        assert!(cache.is_active("a"));
        assert!(!cache.is_active("b"));
        assert!(cache.is_active("c"));
    }

    #[test]
    fn concurrent_revoke_and_use_is_safe() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(CredentialCache::new());
        cache.insert("grant-1", b"secret".to_vec());

        let c1 = Arc::clone(&cache);
        let r = thread::spawn(move || {
            c1.revoke("grant-1");
        });
        let c2 = Arc::clone(&cache);
        let u = thread::spawn(move || {
            // May succeed or fail depending on race — both are valid.
            let _ = c2.use_credential("grant-1", |b| b.to_vec());
        });
        r.join().unwrap();
        u.join().unwrap();

        // Post-race, the cache must reflect revoked state.
        assert!(!cache.is_active("grant-1"));
    }
}
