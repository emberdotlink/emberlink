//! presence_token_module_skeleton_landed
//! CLASSIFICATION: PUBLIC
//!
//! Phase D presence-token cache + cohort A authority semantics.
//!
//! A `PresenceToken` is a short-lived, daemon-signed capability that asserts
//! a specific uid is authorised to exercise a given `ScopeKey` (a JSON-RPC
//! method or parameter-derived identifier).  Tokens are cached in a
//! single-threaded `PresenceTokenCache` (tokio `LocalSet` pattern) and pruned
//! lazily on access.
//!
//! ## Lifecycle
//!
//! 1. The daemon calls `mint` with the uid, scope, TTL, and the daemon's
//!    identity signer.  `mint` produces a deterministic byte payload via
//!    `mint_message` and signs it with the `DaemonSigner`.
//! 2. The caller inserts the token into a `PresenceTokenCache`.
//! 3. On every incoming RPC the daemon calls `validate`, which checks expiry,
//!    uid equality, and re-verifies the signature.
//!
//! Slices D-2 / D-3 / D-4 wire `PresenceTokenCache` into the RPC handler and
//! daemon startup; this module is intentionally free of runtime dependencies.
//!
//! ## `DaemonSigner` trait
//!
//! A minimal local abstraction that supports both sign and verify in a single
//! trait object.  `core_crypto::Signer` only exposes `sign` + `public_key`; a
//! full consolidation (re-exporting from `core-crypto`) is tracked in
//! `META-AP-DAEMON-SIGNER-CONSOLIDATION`.

use std::collections::HashMap;
use std::time::SystemTime;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Custom serde for `bytes::Bytes`: serializes/deserializes as a `Vec<u8>`.
mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        b.as_ref().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        Ok(Bytes::from(v))
    }
}

// ---------------------------------------------------------------------------
// ScopeKey
// ---------------------------------------------------------------------------

/// Newtype wrapping a JSON-RPC method name or parameter-derived identifier
/// that scopes a `PresenceToken` to a specific authority surface.
///
/// Use `ScopeKey::all()` for tokens that span every method, or
/// `ScopeKey::new(method)` to pin to a single method.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopeKey(String);

impl ScopeKey {
    /// A wildcard scope that matches every JSON-RPC method.
    pub fn all() -> ScopeKey {
        ScopeKey("*".to_string())
    }

    /// Pin the scope to a single JSON-RPC method name.
    pub fn new(method: &str) -> Self {
        ScopeKey(method.to_string())
    }

    /// Return the raw scope string stored in the token.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// PresenceToken
// ---------------------------------------------------------------------------

/// A short-lived, daemon-signed capability token.
///
/// The signature field covers the deterministic byte representation produced
/// by `mint_message`; re-verification is done in `validate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceToken {
    pub uid: u32,
    pub scope: ScopeKey,
    pub expiry: SystemTime,
    #[serde(with = "bytes_serde")]
    pub signature: Bytes,
}

// ---------------------------------------------------------------------------
// PresenceTokenCache
// ---------------------------------------------------------------------------

/// Single-threaded presence-token cache (tokio `LocalSet` / `!Send` pattern).
///
/// `RefCell` provides interior mutability without requiring `Mutex` — the cache
/// lives on a single LocalSet thread.  Expired tokens are pruned lazily on
/// every `get` call via `prune_expired`.
pub struct PresenceTokenCache {
    entries: std::cell::RefCell<HashMap<(u32, ScopeKey), PresenceToken>>,
}

impl Default for PresenceTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceTokenCache {
    pub fn new() -> Self {
        Self {
            entries: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// Insert (or overwrite) a token keyed by `(uid, scope)`.
    pub fn insert(&self, token: PresenceToken) {
        let key = (token.uid, token.scope.clone());
        self.entries.borrow_mut().insert(key, token);
    }

    /// Return a clone of the token for `(uid, scope)` if it exists and has
    /// not yet expired.  Expired tokens are removed from the cache as a
    /// side-effect.
    pub fn get(&self, uid: u32, scope: &ScopeKey) -> Option<PresenceToken> {
        self.prune_expired();
        self.entries.borrow().get(&(uid, scope.clone())).cloned()
    }

    /// Remove all tokens whose `expiry` is in the past.
    pub fn prune_expired(&self) {
        let now = SystemTime::now();
        self.entries
            .borrow_mut()
            .retain(|_, token| token.expiry > now);
    }
}

// ---------------------------------------------------------------------------
// AuthError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("presence token has expired")]
    Expired,
    #[error("uid mismatch: token uid does not match request uid")]
    UidMismatch,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("scope mismatch: token scope does not cover the requested method")]
    ScopeMismatch,
}

// ---------------------------------------------------------------------------
// DaemonSigner trait
// ---------------------------------------------------------------------------

/// Minimal signing + verification abstraction for daemon identity keys.
///
/// `core_crypto::Signer` only exposes `sign` and `public_key`; a full
/// consolidation that makes this trait redundant is tracked in
/// `META-AP-DAEMON-SIGNER-CONSOLIDATION`.
pub trait DaemonSigner {
    fn sign(&self, msg: &[u8]) -> Bytes;
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// mint_message
// ---------------------------------------------------------------------------

/// Produce the deterministic byte payload that is signed/verified for a
/// `PresenceToken`.  Layout: `uid(4 LE) || scope_len(4 LE) || scope_bytes ||
/// expiry_secs(8 LE) || expiry_nanos(4 LE)`.
fn mint_message(uid: u32, scope: &ScopeKey, expiry: &SystemTime) -> Vec<u8> {
    let scope_bytes = scope.0.as_bytes();
    let duration = expiry
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs: u64 = duration.as_secs();
    let nanos: u32 = duration.subsec_nanos();

    let mut msg = Vec::with_capacity(4 + 4 + scope_bytes.len() + 8 + 4);
    msg.extend_from_slice(&uid.to_le_bytes());
    msg.extend_from_slice(&(scope_bytes.len() as u32).to_le_bytes());
    msg.extend_from_slice(scope_bytes);
    msg.extend_from_slice(&secs.to_le_bytes());
    msg.extend_from_slice(&nanos.to_le_bytes());
    msg
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

/// Mint a fresh `PresenceToken` signed by `signer`.
pub fn mint(
    uid: u32,
    scope: ScopeKey,
    ttl: std::time::Duration,
    signer: &dyn DaemonSigner,
) -> PresenceToken {
    let expiry = SystemTime::now() + ttl;
    let msg = mint_message(uid, &scope, &expiry);
    let signature = signer.sign(&msg);
    PresenceToken {
        uid,
        scope,
        expiry,
        signature,
    }
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

/// Validate a `PresenceToken` against the cache and the daemon signer.
///
/// Checks, in order:
/// 1. Expiry vs `SystemTime::now()`.
/// 2. `uid` equality with `request_uid`.
/// 3. Signature re-verification against the message derived from the token's
///    own fields.
pub fn validate(
    _cache: &PresenceTokenCache,
    token: &PresenceToken,
    request_uid: u32,
    signer: &dyn DaemonSigner,
) -> Result<(), AuthError> {
    if token.expiry <= SystemTime::now() {
        return Err(AuthError::Expired);
    }
    if token.uid != request_uid {
        return Err(AuthError::UidMismatch);
    }
    let msg = mint_message(token.uid, &token.scope, &token.expiry);
    if !signer.verify(&msg, &token.signature) {
        return Err(AuthError::SignatureInvalid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    /// Test-only signer: signs by SHA-256 hashing the message (not real crypto).
    struct StubSigner;

    impl DaemonSigner for StubSigner {
        fn sign(&self, msg: &[u8]) -> Bytes {
            let hash = Sha256::digest(msg);
            Bytes::copy_from_slice(&hash)
        }

        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            let expected = Sha256::digest(msg);
            sig == expected.as_slice()
        }
    }

    #[test]
    fn mint_then_validate_round_trip() {
        let signer = StubSigner;
        let cache = PresenceTokenCache::new();
        let token = mint(
            1,
            ScopeKey::new("session.open"),
            Duration::from_secs(60),
            &signer,
        );
        cache.insert(token.clone());
        assert!(validate(&cache, &token, 1, &signer).is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let signer = StubSigner;
        let cache = PresenceTokenCache::new();
        let token = mint(
            1,
            ScopeKey::new("session.open"),
            Duration::from_millis(1),
            &signer,
        );
        cache.insert(token.clone());
        std::thread::sleep(Duration::from_millis(50));
        let result = validate(&cache, &token, 1, &signer);
        assert!(matches!(result, Err(AuthError::Expired)));
    }

    #[test]
    fn wrong_uid_rejected() {
        let signer = StubSigner;
        let cache = PresenceTokenCache::new();
        let token = mint(
            42,
            ScopeKey::new("session.open"),
            Duration::from_secs(60),
            &signer,
        );
        cache.insert(token.clone());
        let result = validate(&cache, &token, 43, &signer);
        assert!(matches!(result, Err(AuthError::UidMismatch)));
    }

    #[test]
    fn tampered_signature_rejected() {
        let signer = StubSigner;
        let cache = PresenceTokenCache::new();
        let token = mint(
            1,
            ScopeKey::new("session.open"),
            Duration::from_secs(60),
            &signer,
        );
        let mut sig_vec = token.signature.to_vec();
        let last = sig_vec.last_mut().unwrap();
        *last ^= 0xff;
        let tampered = PresenceToken {
            signature: Bytes::from(sig_vec),
            ..token.clone()
        };
        cache.insert(tampered.clone());
        let result = validate(&cache, &tampered, 1, &signer);
        assert!(matches!(result, Err(AuthError::SignatureInvalid)));
    }
}
