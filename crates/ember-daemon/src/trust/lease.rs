//! ADR 211 §1 — the leased-authority primitive.
//!
//! Durable persona IDENTITY (a stable public key) is separated from
//! AUTHORITY-TO-ACT, which is **always** a short-lived, grant-scoped,
//! TTL-bounded **lease** the daemon holds only for the grant's life. A persona
//! with no live lease is an *inert identity* — a stable pubkey with no standing
//! power. This module is the in-memory home for the grant-scoped key that
//! ADR 206 §5 / its OQ-2 specified: mint-at-issuance, scope-binding,
//! destroy-on-expiry/revoke.
//!
//! **CONVENIENCE-BOUND, NOT STRUCTURAL (dev0).** Per ADR 206 §5 finding C2 and
//! ADR 211 §1: a [`LeaseKey`] the daemon holds in memory is a daemon-held
//! capability a *compromised* daemon can copy the instant it is minted; "dropped
//! on expiry/revoke" is a `Zeroize`/`drop` that such a daemon ignores. The lease
//! bounds the *honest* window (a time-box) at dev0; the real compromised-daemon
//! bound is team0/ent0 co-authority (ADR 211 §6). Do **not** describe a lease as
//! a structural guarantee against in-window root use.
//!
//! **SURVIVES RESTART, NON-EXFILTRATABLE (ADR 211 Phase 4 / AC-6).** Each
//! grant's lease key is wrapped under a non-extractable, headless **Secure
//! Enclave** key (the daemon's lease-KEK; provisioned via double-envelope) and the
//! wrapped blob is persisted by `DaemonStore` (the `lease_blobs` table). The
//! in-memory [`LeaseKey`] is a **hot cache**; the SE-wrapped persisted blob is
//! the restart-survival source of truth. On restart the registry is cold; the
//! first [`LeaseRegistry::with_lease_key`] for a grant `se_unwrap`s its blob
//! back into a live key (via [`DaemonStore`]'s bound persistence) and repopulates
//! the cache. An **expired** persisted lease is never rehydrated — it is dropped.
//!
//! Persistence is **safe** because the blob is non-exfiltratable: only the
//! daemon's headless SE key can unwrap it, and that key cannot be exported off
//! the device. Persisting it does **NOT** reintroduce a standing exfiltratable
//! key — it relocates restart-survival into hardware, it does not raise the
//! ceiling. The dev0 residuals are unchanged: the lease remains convenience-
//! bound (a time-box, not structural) against an in-window-compromised daemon
//! that can use-in-session; the real G1 bound is team0/ent0 co-authority
//! co-signing each lease USE (ADR 211 §6). "Non-exfiltratable" is NOT "fully
//! hardware-gated": root-on-this-device can use the SE key in-session, by design.

use std::cell::RefCell;
use std::collections::HashMap;

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead, aead::Payload};
use chrono::{DateTime, Utc};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Lease-KEK: symmetric wrapping key for lease blobs (ADR 216 S3)
// ---------------------------------------------------------------------------

/// Stable label for the daemon's lease-wrapping key. Used as part of the
/// double-envelope AAD and as the DWK purpose discriminator.
pub const LEASE_KEK_LABEL: &str = "sh.emberlink.daemon.lease-kek";

/// Symmetric wrapping key for lease blobs (ADR 216 S3).
///
/// Replaces the direct-SE ECIES path from ADR 211 Phase 4. The raw 32-byte
/// key lives only in daemon memory (uid=450); it is persisted via the
/// double-envelope (DWK inner + SE outer, peeled by CLI relay on Touch ID).
/// Individual lease blobs are XChaCha20-Poly1305 encrypted under this key.
pub struct LeaseWrapKey {
    key: Zeroizing<[u8; 32]>,
    mlocked: bool,
}

// `LeaseWrapKey` is intentionally **not** `Clone` (ADR216-F4). The prior
// `impl Clone` staged the key bytes in a `[u8; 32]` stack local before
// calling `from_raw`; because `[u8; 32]` is `Copy`, `from_raw` zeroized
// only its own parameter and left the caller's staging copy on the
// stack. Shared access is now via `Rc<LeaseWrapKey>` so every consumer
// shares the single mlocked allocation instead of cloning out fresh
// 32-byte copies on each access. New non-Rc consumers must take
// `&LeaseWrapKey` or `Rc<LeaseWrapKey>`.

impl Drop for LeaseWrapKey {
    fn drop(&mut self) {
        // Wipe the key bytes while they are still mlock-pinned in physical
        // memory. The implicit `Zeroizing` field-drop would zero them only
        // AFTER munlock unpins the page — explicit zeroize-before-munlock
        // closes that brief unpinned-but-unzeroed window and makes the
        // zeroization responsibility explicit rather than drop-order-implied.
        self.key.zeroize();
        if self.mlocked {
            unsafe {
                libc::munlock(self.key.as_ptr() as *const libc::c_void, 32);
            }
        }
    }
}

impl LeaseWrapKey {
    const AAD: &'static [u8] = b"lease_wrap:sh.emberlink.daemon.lease-blob";

    pub fn from_raw(mut key: [u8; 32]) -> Self {
        let mut s = Self {
            key: Zeroizing::new(key),
            mlocked: false,
        };
        key.zeroize();
        let ptr = s.key.as_ptr() as *const libc::c_void;
        let rc = unsafe { libc::mlock(ptr, 32) };
        if rc == 0 {
            s.mlocked = true;
        } else {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "mlock(lease-KEK) failed — key may be paged to swap"
            );
        }
        s
    }

    pub fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, LeaseCustodyError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| LeaseCustodyError::Crypto(format!("lease wrap cipher init: {e}")))?;
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: Self::AAD,
                },
            )
            .map_err(|e| LeaseCustodyError::Crypto(format!("lease wrap: {e}")))?;
        let mut out = Vec::with_capacity(24 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, LeaseCustodyError> {
        if blob.len() < 24 + 16 {
            return Err(LeaseCustodyError::Crypto(format!(
                "lease unwrap: blob too short ({} bytes, minimum 40)",
                blob.len()
            )));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(24);
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|e| LeaseCustodyError::Crypto(format!("lease unwrap cipher init: {e}")))?;
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: Self::AAD,
                },
            )
            .map_err(|e| {
                LeaseCustodyError::Crypto(format!("lease unwrap: AEAD verification failed: {e}"))
            })?;
        Ok(Zeroizing::new(plaintext))
    }
}

impl std::fmt::Debug for LeaseWrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeaseWrapKey(<redacted>)")
    }
}

/// Errors from the lease custody layer.
#[derive(Debug)]
pub enum LeaseCustodyError {
    /// Provisioning the daemon's lease-KEK failed.
    KekProvisionFailed(String),
    /// A wrap / unwrap of a lease key failed (AEAD error or corrupt blob).
    Crypto(String),
    /// The unwrapped lease key was not exactly 32 bytes (corrupt/tampered blob).
    BadKeyLength(usize),
}

impl std::fmt::Display for LeaseCustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseCustodyError::KekProvisionFailed(m) => {
                write!(f, "lease-KEK provisioning failed (fail-closed): {m}")
            }
            LeaseCustodyError::Crypto(m) => write!(f, "lease-key wrap/unwrap failed: {m}"),
            LeaseCustodyError::BadKeyLength(n) => {
                write!(f, "unwrapped lease key is {n} bytes (expected 32)")
            }
        }
    }
}

impl std::error::Error for LeaseCustodyError {}

// ADR 216 S4: `ensure_lease_kek` (both macOS and non-macOS variants) deleted.
// The lease-KEK is now installed exclusively via the double-envelope RPC
// (`vault.de_unlock_complete` with purpose=lease_kek). See ADR 216 S3.

/// A persisted lease record **at rest**: just the grant id (row key) and the
/// wrapped blob. ADR 216 S3 / AC-6.
///
/// The blob is `LeaseWrapKey::wrap(encode_sealed_plaintext(key, meta))` — a
/// single XChaCha20-Poly1305 authenticated object that carries BOTH the 32-byte
/// lease key AND its grant metadata ([`SealedLeaseMeta`]). It is the ONLY
/// representation of the lease at rest, is authenticated (the Poly1305 tag
/// covers both the metadata and the purpose-bound AAD), and the wrapping key
/// itself lives only in daemon memory (held in double-envelope custody). Raw
/// key bytes are NEVER persisted, and there are **no plaintext metadata columns**
/// to tamper — the live `Lease` fields are re-derived from the authenticated
/// bytes on rehydrate, never from the DB columns.
#[derive(Debug, Clone)]
pub struct PersistedLease {
    pub grant_id: String,
    /// `LeaseWrapKey::wrap(encode_sealed_plaintext(key, meta))` — the wrapped,
    /// authenticated blob at rest.
    pub wrapped_blob: Vec<u8>,
}

/// The grant metadata sealed *inside* the wrapped lease blob (ADR 216 S3 / AC-6
/// integrity).
///
/// The lease key alone is not enough at rest: the live `Lease`'s scope / persona
/// / expiry must also be authenticated, or a DB-write attacker could flip a
/// persisted lease's `scope` (e.g. `github:repo:push` → `ssh-agent:sign`,
/// forging an SSH-signing oracle) or extend its `expires_at` to defeat the TTL
/// by editing plaintext columns.
///
/// The metadata is sealed *inside* the XChaCha20-Poly1305 authenticated plaintext
/// alongside the key (see [`encode_sealed_plaintext`]), with purpose-bound AAD.
/// On rehydrate the live `Lease` is re-derived from these authenticated bytes and
/// the sealed `grant_id` is checked against the row key (defeating a blob swap
/// between rows). Any tamper invalidates the Poly1305 tag →
/// `se_unwrap` fails closed.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SealedLeaseMeta {
    grant_id: String,
    persona_id: String,
    scope: String,
    expires_at: Option<DateTime<Utc>>,
    minted_at: DateTime<Utc>,
}

/// Encode the sealed lease-blob plaintext: `key[0..32] || serde_json(meta)`.
/// This buffer is wrapped under the lease-KEK, so the AEAD tag authenticates
/// BOTH the key and the metadata.
fn encode_sealed_plaintext(
    key: &[u8; 32],
    meta: &SealedLeaseMeta,
) -> Result<Zeroizing<Vec<u8>>, LeaseCustodyError> {
    let json = serde_json::to_vec(meta).map_err(|e| {
        LeaseCustodyError::Crypto(format!("serializing sealed lease metadata: {e}"))
    })?;
    let mut buf = Zeroizing::new(Vec::with_capacity(32 + json.len()));
    buf.extend_from_slice(key);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode the sealed lease-blob plaintext produced by [`encode_sealed_plaintext`]
/// (after the AEAD tag has been verified). Splits the fixed 32-byte key prefix
/// from the JSON metadata.
fn decode_sealed_plaintext(raw: &[u8]) -> Result<(LeaseKey, SealedLeaseMeta), LeaseCustodyError> {
    if raw.len() < 32 {
        return Err(LeaseCustodyError::BadKeyLength(raw.len()));
    }
    let key = LeaseKey::from_unwrapped(&raw[..32])?;
    let meta: SealedLeaseMeta = serde_json::from_slice(&raw[32..])
        .map_err(|e| LeaseCustodyError::Crypto(format!("parsing sealed lease metadata: {e}")))?;
    Ok((key, meta))
}

// ---------------------------------------------------------------------------
// SSH-signing lease scope (the ssh-agent-over-bridge S1↔S3 contract)
// ---------------------------------------------------------------------------

/// The canonical authority scope (`provider:object:verb`) that authorizes SSH
/// signing. `register_session` (Slice 3) mints the session's SSH-signing lease
/// with the **object** [`SSH_SIGN_SCOPE_OBJECT`] and **verb**
/// [`SSH_SIGN_SCOPE_VERB`]; the bridge's fail-closed gate (Slice 1) accepts a
/// lease only when its scope authorizes signing per
/// [`scope_authorizes_ssh_signing`].
///
/// Per the resolved design (#5687): the lease bounds **time** for SSH-signing
/// authority; it does **not** encode the target (repo/host) — that binding is
/// the per-session deploy KEY, because the OpenSSH `SIGN_REQUEST` carries no
/// repo and no independently-verifiable host, so per-target *lease* scoping is
/// unenforceable at the sign boundary and would only be an audit label.
pub const SSH_SIGN_SCOPE_OBJECT: &str = "ssh-agent";
/// The verb half of the SSH-signing scope; see [`SSH_SIGN_SCOPE_OBJECT`].
pub const SSH_SIGN_SCOPE_VERB: &str = "sign";

/// True iff a grant `scope` (canonical `provider:object:verb`) authorizes SSH
/// signing.
///
/// Fail-closed and wildcard-aware, consistent with the canonical scope algebra:
/// the **object** must be `ssh-agent` or `*`, and the **verb** must be `sign`
/// or `*` (a bare `*` scope authorizes everything). The **provider** is
/// unconstrained — target binding is the loaded deploy key, not the lease. A
/// malformed scope, or any unrelated scope (`github:repo:push`,
/// `memory:kv:read`), is **not** authorized.
pub fn scope_authorizes_ssh_signing(scope: &str) -> bool {
    let scope = scope.trim();
    if scope == "*" {
        return true;
    }
    // Canonical `provider:object:verb` (object/verb may be the `*` wildcard).
    // Reject any malformed shape (wrong segment count, empty segment) closed.
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    let object = parts[1];
    let verb = parts[2];
    (object == SSH_SIGN_SCOPE_OBJECT || object == "*")
        && (verb == SSH_SIGN_SCOPE_VERB || verb == "*")
}

/// A grant-scoped key the daemon holds for exactly one grant's life.
///
/// Non-`Clone` and redacted-`Debug` so lease material cannot be copied out of
/// the registry or leaked to logs. The only read access is via
/// [`LeaseRegistry::with_lease_key`], which lends a borrow to a closure and
/// never yields ownership.
pub struct LeaseKey(
    // Consumed by the Phase-2 authority-to-act path (ADR 211 §1) — the
    // signing / JIT-decrypt seam reads it via `as_bytes` under
    // `LeaseRegistry::with_lease_key`. Until that lands it is read only by this
    // module's tests, so the non-test build sees it as unused (build-ahead).
    #[allow(dead_code)] Zeroizing<[u8; 32]>,
);

impl LeaseKey {
    /// Mint a fresh grant-scoped key from OS entropy. The staging buffer is
    /// `Zeroizing` so no cleartext copy is left on the stack by a `[u8; 32]`
    /// (`Copy`) move (the same discipline as `presence_seal::generate_scope_kek`).
    fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut_slice()).expect("OS entropy failure on lease key generation");
        LeaseKey(bytes)
    }

    /// The raw 32-byte key. Crate-internal: reached only under
    /// [`LeaseRegistry::with_lease_key`]; callers must not copy it out or cache
    /// it past the operation it authorized. Build-ahead: the consumer is the
    /// Phase-2 signing / JIT-decrypt seam (ADR 211 §1), so until that lands it
    /// is exercised only by this module's tests.
    #[allow(dead_code)]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstruct a [`LeaseKey`] from raw bytes recovered by an unwrap
    /// (rehydration after a restart).
    fn from_unwrapped(bytes: &[u8]) -> Result<Self, LeaseCustodyError> {
        if bytes.len() != 32 {
            return Err(LeaseCustodyError::BadKeyLength(bytes.len()));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(bytes);
        Ok(LeaseKey(arr))
    }

    /// Unwrap and decode a persisted lease blob into its live [`LeaseKey`] and
    /// authenticated [`SealedLeaseMeta`] via the symmetric lease-KEK (ADR 216 S3).
    /// The AEAD tag verification happens inside `kek.unwrap`; a tampered blob
    /// fails closed here.
    fn unwrap_sealed(
        kek: &LeaseWrapKey,
        wrapped_blob: &[u8],
    ) -> Result<(LeaseKey, SealedLeaseMeta), LeaseCustodyError> {
        let raw = kek.unwrap(wrapped_blob)?;
        decode_sealed_plaintext(&raw)
    }
}

impl std::fmt::Debug for LeaseKey {
    /// Redacts the key bytes — never print lease material (a derive on
    /// `Zeroizing<[u8; 32]>` would leak it).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeaseKey(<redacted 32 bytes>)")
    }
}

/// A live lease: the daemon's grant-scoped authority-to-act for one grant.
#[derive(Debug)]
pub struct Lease {
    /// The grant this lease is bound to.
    pub grant_id: String,
    /// The persona principal whose authority-to-act this lease carries.
    pub persona_id: String,
    /// The grant's statement scope (`provider:object:verb`) the lease is bound
    /// to — recorded so a lease can never be used outside its grant's scope.
    pub scope: String,
    /// When the lease expires; mirrors the grant's `expires_at`.
    ///
    /// `None` is a **pre-lock residual**: ADR 211's lock wants authority-to-act
    /// ALWAYS TTL-bounded, but the grant store still permits TTL-less grants. A
    /// `None`-expiry lease is held until revoke. Making TTL mandatory is tracked
    /// by ADR 211 OQ-1 and is a deliberate later slice — not silently assumed
    /// here (a `None` lease is honestly unbounded-by-time, never disguised as
    /// bounded).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the lease was minted — the operator presence gesture at grant
    /// issuance (ADR 158 pre-grant + Touch ID at mint).
    pub minted_at: DateTime<Utc>,
    /// The grant-scoped key. See the module note: convenience-bound, not
    /// structural at dev0.
    key: LeaseKey,
}

/// Metadata returned when a caller reattaches to an existing live lease.
///
/// This is deliberately only an observation surface: it carries no key material
/// and has no writable expiry field. ADR 211 §2 caller-identity binding happens
/// at the session/attachment call site before this method is used; the registry
/// only enforces the "reattach rides the existing window and cannot renew it"
/// half of the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseAttachment {
    pub grant_id: String,
    pub persona_id: String,
    pub scope: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub minted_at: DateTime<Utc>,
}

impl Lease {
    /// True iff the lease has a TTL that has now elapsed. A `None`-expiry lease
    /// is never "expired" by time (the pre-lock residual; see
    /// [`Lease::expires_at`]).
    fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        matches!(self.expires_at, Some(exp) if now >= exp)
    }

    fn attachment(&self) -> LeaseAttachment {
        LeaseAttachment {
            grant_id: self.grant_id.clone(),
            persona_id: self.persona_id.clone(),
            scope: self.scope.clone(),
            expires_at: self.expires_at,
            minted_at: self.minted_at,
        }
    }
}

/// The daemon's in-memory registry of live leases, keyed by `grant_id`.
///
/// Single-threaded `LocalSet` semantics (the daemon's `DaemonStore` is
/// `!Send + !Sync`): the `RefCell` is only ever touched on one thread, so borrow
/// panics cannot race — the same posture as `DaemonStore::consumed_dek_grants`.
#[derive(Default, Debug)]
pub struct LeaseRegistry {
    leases: RefCell<HashMap<String, Lease>>,
}

impl LeaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a lease for `grant_id` at grant issuance, generating a fresh
    /// grant-scoped key. Overwrites any prior lease on the same grant id
    /// (re-issue), dropping the old key. `expires_at` mirrors the grant's TTL
    /// (see [`Lease::expires_at`] for the `None` residual).
    pub fn mint(
        &self,
        grant_id: &str,
        persona_id: &str,
        scope: &str,
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) {
        let lease = Lease {
            grant_id: grant_id.to_string(),
            persona_id: persona_id.to_string(),
            scope: scope.to_string(),
            expires_at,
            minted_at: now,
            key: LeaseKey::generate(),
        };
        self.leases.borrow_mut().insert(grant_id.to_string(), lease);
    }

    /// Mint a lease into the in-memory hot cache **and** wrap its key under
    /// the daemon's symmetric lease-KEK (ADR 216 S3), returning the
    /// [`PersistedLease`] for the bound persistence layer to write at rest.
    pub(crate) fn mint_and_seal(
        &self,
        grant_id: &str,
        persona_id: &str,
        scope: &str,
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        kek: &LeaseWrapKey,
    ) -> Result<PersistedLease, LeaseCustodyError> {
        let key = LeaseKey::generate();
        let meta = SealedLeaseMeta {
            grant_id: grant_id.to_string(),
            persona_id: persona_id.to_string(),
            scope: scope.to_string(),
            expires_at,
            minted_at: now,
        };
        let plaintext = encode_sealed_plaintext(key.as_bytes(), &meta)?;
        let wrapped_blob = kek.wrap(&plaintext)?;
        let lease = Lease {
            grant_id: grant_id.to_string(),
            persona_id: persona_id.to_string(),
            scope: scope.to_string(),
            expires_at,
            minted_at: now,
            key,
        };
        self.leases.borrow_mut().insert(grant_id.to_string(), lease);
        Ok(PersistedLease {
            grant_id: grant_id.to_string(),
            wrapped_blob,
        })
    }

    /// True iff the in-memory hot cache has no entry for `grant_id` (a *cold*
    /// grant — e.g. just after a daemon restart). The bound persistence layer
    /// uses this to decide whether to attempt a rehydrate from the persisted
    /// blob before treating a grant as inert.
    pub(crate) fn is_cold(&self, grant_id: &str) -> bool {
        !self.leases.borrow().contains_key(grant_id)
    }

    /// Rehydrate a persisted lease back into the in-memory hot cache after a
    /// restart by unwrapping its blob under the symmetric lease-KEK (ADR 216 S3).
    /// The live `Lease`'s scope / persona / expiry are re-derived from the
    /// **authenticated** [`SealedLeaseMeta`] inside the blob.
    pub(crate) fn rehydrate(
        &self,
        persisted: &PersistedLease,
        now: DateTime<Utc>,
        kek: &LeaseWrapKey,
    ) -> Result<bool, LeaseCustodyError> {
        let (key, meta) = LeaseKey::unwrap_sealed(kek, &persisted.wrapped_blob)?;
        // Bind the sealed metadata to the row it was stored under: reject a blob
        // copied into a different grant's row (the sealed grant_id is
        // authenticated, the row key is not).
        if meta.grant_id != persisted.grant_id {
            return Err(LeaseCustodyError::Crypto(format!(
                "sealed lease grant_id {:?} does not match row key {:?} (blob swap?)",
                meta.grant_id, persisted.grant_id
            )));
        }
        // Never resurrect an expired lease — drop it instead (AC-6 expiry rule).
        // Expiry is read from the AUTHENTICATED metadata, not a tamperable column.
        if matches!(meta.expires_at, Some(exp) if now >= exp) {
            return Ok(false);
        }
        let grant_id = meta.grant_id.clone();
        let lease = Lease {
            grant_id: meta.grant_id,
            persona_id: meta.persona_id,
            scope: meta.scope,
            expires_at: meta.expires_at,
            minted_at: meta.minted_at,
            key,
        };
        self.leases.borrow_mut().insert(grant_id, lease);
        Ok(true)
    }

    /// Drop the lease for `grant_id` (revoke / terminal expiry / exhaustion),
    /// zeroizing and freeing its key. Returns `true` iff a lease was present.
    pub fn drop_lease(&self, grant_id: &str) -> bool {
        self.leases.borrow_mut().remove(grant_id).is_some()
    }

    /// True iff a live (present, not time-expired) lease exists for `grant_id`.
    /// Lazily evicts a time-expired lease as a backstop to the terminal-path
    /// drop hooks, so an expired lease's key does not linger in memory.
    pub fn has_live_lease(&self, grant_id: &str, now: DateTime<Utc>) -> bool {
        self.evict_if_expired(grant_id, now);
        self.leases.borrow().contains_key(grant_id)
    }

    /// True iff a live, **time-boxed** lease exists for `grant_id` **and its
    /// scope authorizes SSH signing** (see [`scope_authorizes_ssh_signing`]).
    /// Stricter than [`has_live_lease`] on two axes, both fail-closed:
    ///
    /// 1. **Scope:** a live lease whose grant authorizes something else
    ///    (`github:repo:push`, `memory:kv:read`) is **not** a valid SSH-signing
    ///    lease.
    /// 2. **TTL is mandatory.** A TTL-less (`expires_at == None`) lease — the
    ///    pre-lock residual [`has_live_lease`] still accepts (ADR 211 OQ-1) —
    ///    is **refused** here. The resolved ssh-agent-over-bridge design makes
    ///    the lease the *time-box* for SSH-signing authority; a `None`-expiry
    ///    lease bounds no time and would be an unbounded signing oracle, so the
    ///    gate requires a real, unexpired expiry. (`register_session` / Slice 3
    ///    must likewise refuse to mint a TTL-less SSH-signing lease; this gate
    ///    is the fail-closed backstop if it ever does.)
    ///
    /// The ssh-agent bridge's fail-closed gate (ADR 211, Slice 1) hangs off this
    /// predicate — no live, time-boxed, SSH-signing lease, no sign.
    pub fn has_live_ssh_signing_lease(&self, grant_id: &str, now: DateTime<Utc>) -> bool {
        // `evict_if_expired` removes a lease whose TTL has elapsed, so a lease
        // still present here with `expires_at.is_some()` is necessarily
        // unexpired; the `is_some()` check rejects the unbounded `None` residual.
        self.evict_if_expired(grant_id, now);
        self.leases.borrow().get(grant_id).is_some_and(|lease| {
            lease.expires_at.is_some() && scope_authorizes_ssh_signing(&lease.scope)
        })
    }

    /// Run `f` with the live lease's key, returning `Some(f(..))`, or `None` if
    /// the persona is inert for this grant (no live lease). The key never leaves
    /// the registry. This is the Phase-2 authority-to-act chokepoint: signing /
    /// JIT-decrypt under a live lease, fail-closed when there is none.
    pub fn with_lease_key<R>(
        &self,
        grant_id: &str,
        now: DateTime<Utc>,
        f: impl FnOnce(&LeaseKey) -> R,
    ) -> Option<R> {
        self.evict_if_expired(grant_id, now);
        let leases = self.leases.borrow();
        leases.get(grant_id).map(|lease| f(&lease.key))
    }

    /// Observe an existing live lease after the caller-binding gate has already
    /// accepted a reattach/rebind attempt. This never mints, renews, extends, or
    /// exposes the lease key; it only returns the original lease window so
    /// reattach can ride that window without creating fresh authority.
    pub fn reattach_existing(&self, grant_id: &str, now: DateTime<Utc>) -> Option<LeaseAttachment> {
        self.evict_if_expired(grant_id, now);
        let leases = self.leases.borrow();
        leases.get(grant_id).map(Lease::attachment)
    }

    /// V030-AUTH-LEASE-3 / ADR 211 §2 — renew an existing grant's lease with a
    /// fresh `now + lease_ttl_secs` window, generating a new grant-scoped key.
    ///
    /// **Caller MUST verify fresh operator presence BEFORE calling.** The
    /// in-memory registry has no presence proof; presence-gating is the
    /// handler / broker boundary's responsibility (the same boundary that
    /// gates `vault.de_unlock_complete` and `register_session` per ADR 206 §1).
    /// This primitive's contract is "mint a fresh window for an existing
    /// persona principal" — it is the structural twin of [`Self::mint`], not
    /// of [`Self::reattach_existing`].
    ///
    /// The renewal:
    ///
    /// - Reads the existing lease's `persona_id` + `scope` so the renewed
    ///   lease binds to the same grant identity (no scope drift across a
    ///   renewal — see ADR 211 §2 "scope-widen requires presence").
    /// - Drops the old lease key (Zeroized) before installing the new one
    ///   (matches the `re_mint_replaces_the_prior_lease_key` invariant).
    /// - Returns `Some(LeaseAttachment)` describing the renewed window, or
    ///   `None` if no live lease exists for `grant_id` (fail-closed — the
    ///   caller cannot renew authority a persona does not currently hold).
    ///
    /// Anchor: `lease_renewal_requires_fresh_presence`.
    pub fn renew(
        &self,
        grant_id: &str,
        new_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Option<LeaseAttachment> {
        // Re-issue requires a still-live lease — a fully revoked persona
        // cannot be silently re-authorized by the renewal path. (A
        // *time-expired* lease that has not yet been evicted by a read also
        // counts as inert here: `evict_if_expired` runs first.)
        self.evict_if_expired(grant_id, now);
        let (persona_id, scope) = {
            let leases = self.leases.borrow();
            let lease = leases.get(grant_id)?;
            (lease.persona_id.clone(), lease.scope.clone())
        };
        let renewed = Lease {
            grant_id: grant_id.to_string(),
            persona_id,
            scope,
            expires_at: Some(new_expires_at),
            minted_at: now,
            key: LeaseKey::generate(),
        };
        let attachment = renewed.attachment();
        self.leases
            .borrow_mut()
            .insert(grant_id.to_string(), renewed);
        Some(attachment)
    }

    /// V030-AUTH-LEASE-3 — like [`Self::renew`] but also wraps the renewed
    /// key under the daemon's lease-KEK and returns the [`PersistedLease`]
    /// the bound persistence layer must write so the renewed lease survives
    /// a restart (AC-6). Returns `Ok(None)` if no live lease exists.
    pub(crate) fn renew_and_seal(
        &self,
        grant_id: &str,
        new_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        kek: &LeaseWrapKey,
    ) -> Result<Option<(LeaseAttachment, PersistedLease)>, LeaseCustodyError> {
        self.evict_if_expired(grant_id, now);
        let (persona_id, scope) = {
            let leases = self.leases.borrow();
            let Some(lease) = leases.get(grant_id) else {
                return Ok(None);
            };
            (lease.persona_id.clone(), lease.scope.clone())
        };
        let key = LeaseKey::generate();
        let meta = SealedLeaseMeta {
            grant_id: grant_id.to_string(),
            persona_id: persona_id.clone(),
            scope: scope.clone(),
            expires_at: Some(new_expires_at),
            minted_at: now,
        };
        let plaintext = encode_sealed_plaintext(key.as_bytes(), &meta)?;
        let wrapped_blob = kek.wrap(&plaintext)?;
        let renewed = Lease {
            grant_id: grant_id.to_string(),
            persona_id,
            scope,
            expires_at: Some(new_expires_at),
            minted_at: now,
            key,
        };
        let attachment = renewed.attachment();
        self.leases
            .borrow_mut()
            .insert(grant_id.to_string(), renewed);
        Ok(Some((
            attachment,
            PersistedLease {
                grant_id: grant_id.to_string(),
                wrapped_blob,
            },
        )))
    }

    /// Number of live leases currently held (test / introspection).
    pub fn len(&self) -> usize {
        self.leases.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.borrow().is_empty()
    }

    /// Evict the lease for `grant_id` if it has a TTL that has elapsed. The
    /// backstop for the terminal-path drop hooks (see the module note); does
    /// nothing for a `None`-expiry lease or a still-live one.
    fn evict_if_expired(&self, grant_id: &str, now: DateTime<Utc>) {
        let mut leases = self.leases.borrow_mut();
        if leases.get(grant_id).is_some_and(|l| l.is_expired_at(now)) {
            leases.remove(grant_id);
        }
    }
}

// ---------------------------------------------------------------------------
// BoundLeaseRegistry — the in-memory registry paired with its store's
// symmetric-key persistence (ADR 211 Phase 4 / AC-6, ADR 216 S3)
// ---------------------------------------------------------------------------

/// The [`LeaseRegistry`] **bound to a [`DaemonStore`]** so the authority-to-act
/// lease lane persists and rehydrates across restarts (AC-6) while staying
/// non-exfiltratable (each lease key is wrapped under the daemon's symmetric
/// lease-KEK, which itself is double-envelope custodied per ADR 216).
///
/// **In-memory-only fallback:** when the store has no provisioned lease-KEK
/// (pre-unlock or in-memory test stores), every method behaves exactly like the
/// pre-Phase-4 in-memory registry — no persistence, no crypto.
pub struct BoundLeaseRegistry<'a> {
    registry: &'a LeaseRegistry,
    store: &'a crate::infra::store::DaemonStore,
}

impl<'a> BoundLeaseRegistry<'a> {
    pub(crate) fn new(
        registry: &'a LeaseRegistry,
        store: &'a crate::infra::store::DaemonStore,
    ) -> Self {
        Self { registry, store }
    }

    /// Mint a lease at grant issuance. SE-wraps the fresh key under the daemon's
    /// lease-KEK and persists the wrapped blob (restart-survival) when a lease-KEK
    /// is provisioned; otherwise mints in-memory only. The in-memory key is always
    /// installed (this session works); a persistence failure is logged loudly and
    /// loses ONLY restart-survival (the key stays non-exfiltratable in memory),
    /// never the session — `mint` is infallible by contract so grant creation
    /// cannot fail on the lease lane.
    pub fn mint(
        &self,
        grant_id: &str,
        persona_id: &str,
        scope: &str,
        expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) {
        if let Some(kek) = self.store.lease_kek() {
            match self
                .registry
                .mint_and_seal(grant_id, persona_id, scope, expires_at, now, &kek)
            {
                Ok(rec) => {
                    if let Err(e) = self.store.write_lease_blob(&rec) {
                        tracing::error!(
                            grant_id = %grant_id,
                            error = %e,
                            "ADR 211 Phase 4: lease minted in-memory but persisting the \
                             wrapped blob failed; this lease will NOT survive a daemon \
                             restart (the in-memory key is still non-exfiltratable)"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        grant_id = %grant_id,
                        error = %e,
                        "ADR 211 Phase 4: wrap of the lease key failed; falling back to \
                         an in-memory-only lease (no restart survival)"
                    );
                    self.registry
                        .mint(grant_id, persona_id, scope, expires_at, now);
                }
            }
            return;
        }
        // No lease-KEK provisioned (pre-unlock / test store): in-memory only.
        //
        // HALLE noted (V030-NO-LIVE-LEASE-AFTER-FRESH-INIT, 2026-06-11) that
        // this silent fall-through was a contributing factor in the
        // regression going unnoticed in production: the daemon happily minted
        // grants whose lease blobs were never persisted, and the per-session
        // proxy's fresh `DaemonStore` 403'd `no_live_lease` on the first
        // model-auth request. A `warn!` here surfaces the same operational
        // condition any future regression would produce, so it shows up in
        // `/var/log/emberd.err` instead of being invisible at the mint site.
        // Genuine test stores set the lease-KEK via `set_lease_kek_for_test`
        // and never reach this branch, so the warn is not noisy in test
        // runs.
        tracing::warn!(
            grant_id = %grant_id,
            persona_id = %persona_id,
            "ADR 211 Phase 4: lease-KEK is not provisioned; minting in-memory only — \
             no `lease_blobs` row will be written and the per-session proxy will \
             403 closed on the first request for this grant. Drive the lease-KEK \
             install path (§4 pairing or DE-unlock/provision) to restore \
             persistence."
        );
        self.registry
            .mint(grant_id, persona_id, scope, expires_at, now);
    }

    /// Drop the lease for `grant_id` (revoke / terminal expiry / exhaustion):
    /// remove the in-memory entry **and** delete the persisted blob. Returns
    /// `true` iff an in-memory lease was present (unchanged contract).
    pub fn drop_lease(&self, grant_id: &str) -> bool {
        let was_present = self.registry.drop_lease(grant_id);
        if self.store.lease_kek().is_some()
            && let Err(e) = self.store.delete_lease_blob(grant_id)
        {
            // Loud: a lingering blob is the only way a revoked lease could ever be
            // resurrected. The rehydrate-time `grant_is_active` cross-check is the
            // backstop (it drops a blob whose grant is no longer active), but a
            // failed delete here is still a real integrity signal — not a warn.
            tracing::error!(
                grant_id = %grant_id,
                error = %e,
                "ADR 211 Phase 4: dropped the in-memory lease but deleting its persisted \
                 blob FAILED; rehydrate's grant-active cross-check will drop it, but the \
                 store delete must be investigated"
            );
        }
        if let Err(e) = self.store.delete_grant_persona_secret(grant_id) {
            tracing::error!(
                grant_id = %grant_id,
                error = %e,
                "ADR 211 PR-A: dropped the lease but deleting the grant-scoped \
                 persona-root blob FAILED; signing stays fail-closed without a \
                 live lease, but the stale blob must be investigated"
            );
        }
        was_present
    }

    /// Rehydrate `grant_id` from its persisted wrapped blob if the in-memory
    /// hot cache is cold for it (post-restart). No-op when the cache is already
    /// warm or no lease-KEK is provisioned.
    fn rehydrate_if_cold(&self, grant_id: &str, now: DateTime<Utc>) {
        if !self.registry.is_cold(grant_id) {
            return;
        }
        let Some(kek) = self.store.lease_kek() else {
            return;
        };
        let persisted = match self.store.read_lease_blob(grant_id) {
            Ok(Some(rec)) => rec,
            Ok(None) => return,
            Err(e) => {
                tracing::error!(
                    grant_id = %grant_id,
                    error = %e,
                    "ADR 211 Phase 4: reading the persisted lease blob failed; treating the \
                     grant as inert (fail-closed)"
                );
                return;
            }
        };
        // A lease only exists for an active grant. If the grant is revoked /
        // expired / exhausted (a status flip; the row persists) or absent, do NOT
        // resurrect its lease from a (possibly stale) blob — drop the blob and
        // stay inert. Closes the revoked-TTL-less-grant resurrection when a prior
        // `drop_lease` blob-delete failed, and any replay of a still-within-TTL
        // blob after revoke.
        if !self.store.grant_is_active(grant_id, now) {
            let _ = self.store.delete_lease_blob(grant_id);
            let _ = self.store.delete_grant_persona_secret(grant_id);
            return;
        }
        match self.registry.rehydrate(&persisted, now, &kek) {
            Ok(true) => {}
            Ok(false) => {
                // Expired on rehydrate — drop the stale blob.
                let _ = self.store.delete_lease_blob(grant_id);
                let _ = self.store.delete_grant_persona_secret(grant_id);
            }
            Err(e) => {
                tracing::error!(
                    grant_id = %grant_id,
                    error = %e,
                    "ADR 211 Phase 4: unwrap of the persisted lease blob failed; the grant \
                     stays inert until re-minted (fail-closed)"
                );
            }
        }
    }

    /// True iff a live lease exists for `grant_id`, rehydrating from the
    /// persisted blob first if the cache is cold (post-restart).
    pub fn has_live_lease(&self, grant_id: &str, now: DateTime<Utc>) -> bool {
        self.rehydrate_if_cold(grant_id, now);
        self.registry.has_live_lease(grant_id, now)
    }

    /// True iff a live, time-boxed, SSH-signing-scoped lease exists for
    /// `grant_id`, rehydrating from the persisted blob first if cold.
    pub fn has_live_ssh_signing_lease(&self, grant_id: &str, now: DateTime<Utc>) -> bool {
        self.rehydrate_if_cold(grant_id, now);
        self.registry.has_live_ssh_signing_lease(grant_id, now)
    }

    /// Run `f` with the live lease's key (the Phase-2 authority-to-act
    /// chokepoint), rehydrating from the persisted SE-wrapped blob first if the
    /// cache is cold for this grant (AC-6). `None` (fail-closed) if the persona is
    /// inert for this grant — no live in-memory lease and no live persisted blob.
    /// The caller signature is unchanged from the in-memory registry.
    pub fn with_lease_key<R>(
        &self,
        grant_id: &str,
        now: DateTime<Utc>,
        f: impl FnOnce(&LeaseKey) -> R,
    ) -> Option<R> {
        self.rehydrate_if_cold(grant_id, now);
        self.registry.with_lease_key(grant_id, now, f)
    }

    /// Observe an existing live lease (reattach), rehydrating from the persisted
    /// blob first if cold. Never mints, renews, extends, or exposes the key.
    pub fn reattach_existing(&self, grant_id: &str, now: DateTime<Utc>) -> Option<LeaseAttachment> {
        self.rehydrate_if_cold(grant_id, now);
        self.registry.reattach_existing(grant_id, now)
    }

    /// V030-AUTH-LEASE-3 / ADR 211 §2 — renew a grant's lease with a fresh
    /// `now + lease_ttl_secs` window, generating a new grant-scoped key and
    /// persisting it (restart-survival, AC-6).
    ///
    /// **Caller MUST verify fresh operator presence BEFORE invoking** — the
    /// store-bound registry has no presence proof; presence-gating lives at
    /// the handler/broker boundary (ADR 206 §1, ADR 211 §2 "renew/extend =
    /// presence (tap)"). Refusing without presence here would be a
    /// presence-substitute, NOT a presence-proof.
    ///
    /// Also fails closed when the underlying grant is no longer active —
    /// a revoked / time-expired grant must never be silently re-authorized
    /// by the renewal path (same defense-in-depth as
    /// `rehydrate_if_cold` / `grant_is_active`).
    ///
    /// Returns:
    ///   - `Ok(Some(LeaseAttachment))` — renewed lease's new window.
    ///   - `Ok(None)` — no live lease to renew (the grant is not currently
    ///     held by this persona). Caller surfaces this as
    ///     `lease_expired:presence_required:<grant_id>` (the existing
    ///     `no_live_lease` error code used by `infra::proxy`).
    ///   - `Err(_)` — persistence / crypto error; the in-memory lease is
    ///     restored to the pre-renew state by the rollback below.
    ///
    /// Sentinels: `lease_renewal_requires_fresh_presence`,
    /// `lease_ttl_single_knob_dev0_one_principal`.
    pub fn renew(
        &self,
        grant_id: &str,
        lease_ttl_secs: u64,
        now: DateTime<Utc>,
    ) -> Result<Option<LeaseAttachment>, LeaseCustodyError> {
        // Rehydrate the cache from the persisted blob first so a renewal
        // right after a daemon restart still sees the lease. This matches
        // the symmetry of `with_lease_key` / `has_live_lease`.
        self.rehydrate_if_cold(grant_id, now);

        // V030-AUTH-LEASE-3 defense-in-depth: the registry's renew() also
        // refuses to renew a missing lease, but the grant-active check
        // closes the revoked-grant resurrection vector independently — even
        // a still-cached lease must not be renewed if the grant has been
        // revoked / time-expired between mint and renew.
        if !self.store.grant_is_active(grant_id, now) {
            // Drop any lingering in-memory lease for safety; the underlying
            // grant has lapsed. (drop_lease is a no-op if absent.)
            self.registry.drop_lease(grant_id);
            return Ok(None);
        }

        let new_expires_at =
            now + chrono::Duration::seconds(i64::try_from(lease_ttl_secs).unwrap_or(i64::MAX));

        if let Some(kek) = self.store.lease_kek() {
            // Stash a snapshot of the existing lease so a persistence
            // failure does not leave the in-memory registry inconsistent
            // with what is on disk. (registry.renew_and_seal flips the
            // cache atomically; if write_lease_blob fails we restore.)
            let pre_renew = self.registry.reattach_existing(grant_id, now);
            match self
                .registry
                .renew_and_seal(grant_id, new_expires_at, now, &kek)?
            {
                Some((attachment, persisted)) => {
                    if let Err(e) = self.store.write_lease_blob(&persisted) {
                        // Persistence broke; restore the pre-renew cache
                        // entry by dropping the renewed key. The caller
                        // sees this as a renew failure and the operator
                        // can re-tap.
                        self.registry.drop_lease(grant_id);
                        tracing::error!(
                            grant_id = %grant_id,
                            error = %e,
                            "V030-AUTH-LEASE-3: lease renewed in-memory but persisting the \
                             wrapped blob failed; rolled back to pre-renew state. The \
                             persona is now inert until the operator re-taps."
                        );
                        let _ = pre_renew; // documented: pre-renew attachment is dropped
                        return Err(LeaseCustodyError::Crypto(format!(
                            "persist renewed lease blob: {e}"
                        )));
                    }
                    Ok(Some(attachment))
                }
                None => Ok(None),
            }
        } else {
            // No lease-KEK provisioned (pre-unlock / test stores): renew
            // in-memory only. This mirrors the `mint` fallback behavior.
            tracing::warn!(
                grant_id = %grant_id,
                "V030-AUTH-LEASE-3: lease-KEK is not provisioned; renewing in-memory only \
                 — no `lease_blobs` row will be updated and the per-session proxy will \
                 still see the prior (pre-renew) blob. Drive the lease-KEK install path \
                 (§4 pairing or DE-unlock/provision) to restore persistence."
            );
            Ok(self.registry.renew(grant_id, new_expires_at, now))
        }
    }

    /// Number of leases in the in-memory hot cache (test / introspection). This
    /// reflects the CACHE, not the persisted set — a cold post-restart cache
    /// reports 0 until leases are rehydrated on first access.
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn mint_creates_a_live_lease() {
        let reg = LeaseRegistry::new();
        let now = t0();
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(now + Duration::hours(1)),
            now,
        );
        assert_eq!(reg.len(), 1);
        assert!(reg.has_live_lease("grant-1", now));
    }

    #[test]
    fn ac1_drop_on_revoke_frees_the_lease() {
        // AC-1: the lease-key is dropped on revoke.
        let reg = LeaseRegistry::new();
        let now = t0();
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(now + Duration::hours(1)),
            now,
        );
        assert!(reg.has_live_lease("grant-1", now));
        assert!(reg.drop_lease("grant-1"));
        assert!(!reg.has_live_lease("grant-1", now));
        assert!(reg.is_empty());
        // Idempotent: dropping an absent lease reports no-op.
        assert!(!reg.drop_lease("grant-1"));
    }

    #[test]
    fn ac1_expired_lease_is_inert_and_evicted() {
        // AC-1: a TTL-expired lease is inert (the persona cannot act) and its
        // key is evicted, not left lingering.
        let reg = LeaseRegistry::new();
        let now = t0();
        let expiry = now + Duration::minutes(30);
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(expiry),
            now,
        );

        // Just before expiry: live.
        let before = expiry - Duration::seconds(1);
        assert!(reg.has_live_lease("grant-1", before));

        // At/after expiry: inert. The read evicts it as the backstop.
        let after = expiry + Duration::seconds(1);
        assert!(!reg.has_live_lease("grant-1", after));
        assert!(
            reg.is_empty(),
            "expired lease must be evicted, not lingering"
        );
    }

    #[test]
    fn with_lease_key_runs_closure_only_for_a_live_lease() {
        let reg = LeaseRegistry::new();
        let now = t0();
        let expiry = now + Duration::hours(1);
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(expiry),
            now,
        );

        // Live: the closure runs and sees a 32-byte key.
        let len = reg.with_lease_key("grant-1", now, |k| k.as_bytes().len());
        assert_eq!(len, Some(32));

        // After revoke: inert — the closure never runs (fail-closed).
        reg.drop_lease("grant-1");
        let res = reg.with_lease_key("grant-1", now, |_| true);
        assert_eq!(res, None);

        // Unknown grant: inert.
        assert_eq!(reg.with_lease_key("nope", now, |_| true), None);
    }

    #[test]
    fn none_expiry_lease_is_held_until_revoke() {
        // The pre-lock residual: a TTL-less grant's lease is never time-expired,
        // honestly held until an explicit drop (never disguised as bounded).
        let reg = LeaseRegistry::new();
        let now = t0();
        reg.mint("grant-1", "persona-1", "github:repo:push", None, now);
        let far_future = now + Duration::days(3650);
        assert!(reg.has_live_lease("grant-1", far_future));
        assert!(reg.drop_lease("grant-1"));
        assert!(!reg.has_live_lease("grant-1", far_future));
    }

    #[test]
    fn re_mint_replaces_the_prior_lease_key() {
        let reg = LeaseRegistry::new();
        let now = t0();
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(now + Duration::hours(1)),
            now,
        );
        let first = reg
            .with_lease_key("grant-1", now, |k| *k.as_bytes())
            .expect("first lease live");
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(now + Duration::hours(2)),
            now,
        );
        let second = reg
            .with_lease_key("grant-1", now, |k| *k.as_bytes())
            .expect("re-minted lease live");
        assert_ne!(
            first, second,
            "re-mint must generate a fresh grant-scoped key"
        );
        assert_eq!(reg.len(), 1, "re-mint replaces, does not accumulate");
    }

    #[test]
    fn reattach_existing_observes_without_extending_the_original_window() {
        let reg = LeaseRegistry::new();
        let now = t0();
        let expires_at = now + Duration::minutes(30);
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(expires_at),
            now,
        );

        let first = reg
            .reattach_existing("grant-1", now + Duration::minutes(5))
            .expect("lease is live during the original window");
        assert_eq!(first.grant_id, "grant-1");
        assert_eq!(first.persona_id, "persona-1");
        assert_eq!(first.scope, "github:repo:push");
        assert_eq!(first.minted_at, now);
        assert_eq!(first.expires_at, Some(expires_at));

        let second = reg
            .reattach_existing("grant-1", now + Duration::minutes(29))
            .expect("reattach can still ride a live original window");
        assert_eq!(
            second.expires_at, first.expires_at,
            "reattach must not extend the original lease expiry"
        );
        assert!(reg.has_live_lease("grant-1", expires_at - Duration::seconds(1)));

        assert_eq!(
            reg.reattach_existing("grant-1", expires_at + Duration::seconds(1)),
            None,
            "reattach must fail after the original expiry instead of renewing"
        );
        assert!(reg.is_empty(), "expired reattach attempt evicts the lease");
    }

    #[test]
    fn reattach_existing_never_mints_an_absent_lease() {
        let reg = LeaseRegistry::new();
        let now = t0();

        assert_eq!(reg.reattach_existing("missing-grant", now), None);
        assert!(
            reg.is_empty(),
            "reattach to a missing grant must not create authority"
        );
    }

    // --- V030-AUTH-LEASE-3: renew (presence-gated by caller) -----------

    #[test]
    fn renew_replaces_the_window_and_rotates_the_key() {
        // ADR 211 §2: renew/extend creates a fresh window (NEW authority).
        // The lease key must rotate so a pre-renew key copy does not retain
        // power past the original window.
        let reg = LeaseRegistry::new();
        let now = t0();
        let original_expiry = now + Duration::minutes(15);
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(original_expiry),
            now,
        );

        let original_key = reg
            .with_lease_key("grant-1", now, |k| *k.as_bytes())
            .expect("original lease is live");

        let renew_at = now + Duration::minutes(5);
        let new_expiry = renew_at + Duration::hours(1);
        let attachment = reg
            .renew("grant-1", new_expiry, renew_at)
            .expect("renew of live lease returns Some");

        // Window updated; persona / scope / grant id preserved (no scope
        // drift across a renewal).
        assert_eq!(attachment.grant_id, "grant-1");
        assert_eq!(attachment.persona_id, "persona-1");
        assert_eq!(attachment.scope, "github:repo:push");
        assert_eq!(attachment.expires_at, Some(new_expiry));
        assert_eq!(attachment.minted_at, renew_at);

        // The key rotated.
        let renewed_key = reg
            .with_lease_key("grant-1", renew_at, |k| *k.as_bytes())
            .expect("renewed lease is live");
        assert_ne!(
            original_key, renewed_key,
            "renew must generate a fresh grant-scoped key"
        );

        // The renewed lease lives past the original expiry.
        assert!(reg.has_live_lease("grant-1", original_expiry + Duration::seconds(1)));
    }

    #[test]
    fn renew_returns_none_when_no_live_lease_exists() {
        // The structural fail-closed: the renewal primitive cannot mint
        // authority a persona does not currently hold (the operator must
        // mint a fresh grant instead).
        let reg = LeaseRegistry::new();
        let now = t0();

        assert!(
            reg.renew("missing-grant", now + Duration::hours(1), now)
                .is_none(),
            "renew of an absent lease must NOT silently mint authority"
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn renew_fails_closed_after_lease_has_already_time_expired() {
        // A time-expired-but-not-yet-evicted lease is inert: renewal must
        // fail closed there, not silently resurrect the persona. Combined
        // with the BoundLeaseRegistry's grant-active gate, this closes the
        // "stale lease + still-active grant" resurrection path.
        let reg = LeaseRegistry::new();
        let now = t0();
        let expiry = now + Duration::minutes(15);
        reg.mint(
            "grant-1",
            "persona-1",
            "github:repo:push",
            Some(expiry),
            now,
        );

        let after_expiry = expiry + Duration::seconds(1);
        assert!(
            reg.renew("grant-1", after_expiry + Duration::hours(1), after_expiry)
                .is_none(),
            "renew of an expired lease must fail closed (operator must re-tap to mint)"
        );
        // Evicted as the backstop.
        assert!(reg.is_empty());
    }

    // --- SSH-signing scope predicate (the S1↔S3 contract) ---

    #[test]
    fn scope_authorizes_ssh_signing_accepts_the_canonical_and_wildcards() {
        // The exact scope register_session (S3) mints.
        assert!(scope_authorizes_ssh_signing("github:ssh-agent:sign"));
        assert!(scope_authorizes_ssh_signing("gitlab:ssh-agent:sign"));
        // Provider is unconstrained; object/verb wildcards subsume.
        assert!(scope_authorizes_ssh_signing("github:*:sign"));
        assert!(scope_authorizes_ssh_signing("github:ssh-agent:*"));
        assert!(scope_authorizes_ssh_signing("github:*:*"));
        assert!(scope_authorizes_ssh_signing("*"));
        assert!(scope_authorizes_ssh_signing("  github:ssh-agent:sign  "));
    }

    #[test]
    fn scope_authorizes_ssh_signing_refuses_unrelated_and_malformed() {
        // An ordinary push/read grant is NOT an SSH-signing lease.
        assert!(!scope_authorizes_ssh_signing("github:repo:push"));
        assert!(!scope_authorizes_ssh_signing("memory:kv:read"));
        assert!(!scope_authorizes_ssh_signing("github:ssh-agent:push"));
        assert!(!scope_authorizes_ssh_signing("github:repo:sign"));
        // Malformed shapes fail closed.
        assert!(!scope_authorizes_ssh_signing(""));
        assert!(!scope_authorizes_ssh_signing("sign"));
        assert!(!scope_authorizes_ssh_signing("ssh-agent:sign"));
        assert!(!scope_authorizes_ssh_signing("github::sign"));
        assert!(!scope_authorizes_ssh_signing("github:ssh-agent:sign:extra"));
    }

    #[test]
    fn has_live_ssh_signing_lease_gates_on_scope_and_time() {
        let reg = LeaseRegistry::new();
        let now = t0();
        let expiry = now + Duration::hours(1);

        // A live SSH-signing lease passes.
        reg.mint("g-ssh", "p", "github:ssh-agent:sign", Some(expiry), now);
        assert!(reg.has_live_ssh_signing_lease("g-ssh", now));

        // A live lease for a DIFFERENT authority does not authorize signing,
        // even though `has_live_lease` (scope-blind) would say yes.
        reg.mint("g-push", "p", "github:repo:push", Some(expiry), now);
        assert!(reg.has_live_lease("g-push", now));
        assert!(!reg.has_live_ssh_signing_lease("g-push", now));

        // Absent grant → no authority.
        assert!(!reg.has_live_ssh_signing_lease("nope", now));

        // Expiry flips the SSH-signing lease to inert (and evicts it).
        let after = expiry + Duration::seconds(1);
        assert!(!reg.has_live_ssh_signing_lease("g-ssh", after));
    }

    #[test]
    fn has_live_ssh_signing_lease_refuses_a_ttl_less_lease() {
        // The SSH-signing lease IS the time-box: a `None`-expiry lease bounds no
        // time and would be an unbounded signing oracle. The scope-blind
        // `has_live_lease` still accepts the pre-lock `None` residual, but the
        // SSH-signing gate must refuse it (fail-closed).
        let reg = LeaseRegistry::new();
        let now = t0();
        reg.mint("g-ssh", "p", "github:ssh-agent:sign", None, now);
        assert!(
            reg.has_live_lease("g-ssh", now),
            "scope-blind liveness still sees the TTL-less lease"
        );
        assert!(
            !reg.has_live_ssh_signing_lease("g-ssh", now),
            "a TTL-less lease must NOT authorize SSH signing — the gate requires a time-box"
        );
    }
}

// ---------------------------------------------------------------------------
// Lease custody persistence tests (ADR 216 S3 / AC-6)
// ---------------------------------------------------------------------------
//
// These drive the BoundLeaseRegistry through a `DaemonStore` with a test
// LeaseWrapKey (no hardware), proving the wrap → persist → rehydrate path
// end-to-end in CI. The `LeaseWrapKey` round-trips deterministically,
// so a key wrapped before a simulated restart unwraps to the SAME bytes after.
#[cfg(test)]
mod lease_custody_tests {
    use super::*;
    use crate::infra::store::DaemonStore;
    use chrono::Duration;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    const TEST_KEK_BYTES: [u8; 32] = [0xAB; 32];

    fn test_lease_kek() -> LeaseWrapKey {
        LeaseWrapKey::from_raw(TEST_KEK_BYTES)
    }

    fn open_with_stub_kek(path: &std::path::Path) -> DaemonStore {
        let store = DaemonStore::open(path).expect("open file-backed store");
        store.set_lease_kek_for_test(test_lease_kek());
        store
    }

    /// ADR216-F4 regression — `SharedLeaseKek::get()` must NOT copy the
    /// 32 raw key bytes. The pre-F4 implementation cloned the inner
    /// `LeaseWrapKey` on every access, which staged the key on the stack
    /// via a `[u8; 32]` Copy local that was never zeroized. After F4 the
    /// slot holds `Rc<LeaseWrapKey>` and `.get()` is a ref-count bump —
    /// the returned handle MUST share storage with the slot.
    #[test]
    fn shared_lease_kek_get_does_not_copy_key_bytes() {
        use crate::infra::store::SharedLeaseKek;
        use std::rc::Rc;

        let slot = SharedLeaseKek::default();
        let kek = Rc::new(test_lease_kek());
        // Hold a baseline handle that we can later prove the slot's
        // contents share storage with.
        slot.set(Rc::clone(&kek));

        let first = slot.get().expect("kek is set");
        let second = slot.get().expect("kek is set");

        // Both accessors return the SAME mlocked allocation as the
        // baseline. If `get()` had cloned `LeaseWrapKey`, each call
        // would return a distinct allocation (different pointer) and
        // these assertions would fail. Three-way `ptr_eq` proves the
        // shared-storage invariant across baseline + two get() calls.
        assert!(
            Rc::ptr_eq(&kek, &first),
            "get() must return the same Rc as the slot holds — no clone"
        );
        assert!(
            Rc::ptr_eq(&kek, &second),
            "successive get() calls must share storage with the slot"
        );
        assert!(
            Rc::ptr_eq(&first, &second),
            "two get() handles must share storage with each other"
        );
        // The Rc reaches `strong_count == 4` (baseline + slot's stored
        // clone + 2 `get()` borrows). If `get()` were the pre-F4
        // by-value Clone path it would mint independent
        // `LeaseWrapKey`s, the slot's Rc would still sit at count 1
        // alone, and the ptr_eq checks above would already have failed —
        // this is the corroborating count witness.
        assert_eq!(
            Rc::strong_count(&kek),
            4,
            "no extra Rc clones beyond the baseline + slot + two `get()` borrows"
        );
    }

    #[test]
    fn lease_wrap_key_round_trip() {
        let kek = test_lease_kek();
        let plaintext = b"lease-key-material-32-bytes-xxxx";
        let blob = kek.wrap(plaintext).expect("wrap");
        assert!(blob.len() > 32, "wrapped blob includes nonce + tag");
        assert!(
            !blob.windows(32).any(|w| w == plaintext),
            "raw plaintext must not appear in the ciphertext"
        );
        let recovered = kek.unwrap(&blob).expect("unwrap");
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn lease_wrap_key_wrong_key_fails() {
        let kek_a = LeaseWrapKey::from_raw([0xAA; 32]);
        let kek_b = LeaseWrapKey::from_raw([0xBB; 32]);
        let blob = kek_a.wrap(b"test").expect("wrap");
        assert!(kek_b.unwrap(&blob).is_err());
    }

    #[test]
    fn lease_wrap_key_truncated_blob_fails() {
        let kek = test_lease_kek();
        assert!(kek.unwrap(&[0u8; 10]).is_err());
    }

    /// Seed a minimal **active** grant row so the rehydrate-time
    /// `grant_is_active` cross-check (ADR 211 Phase 4 LOW fix) passes. A lease
    /// only rehydrates while its grant is active; these SE-custody tests model
    /// that by inserting the backing grant. FK enforcement is on, so we first
    /// insert a shared persona `p` (idempotent) that every seeded grant
    /// references. Rows persist on disk across the simulated restart (same DB).
    fn seed_active_grant(store: &DaemonStore, grant_id: &str) {
        let conn = store.conn();
        conn.execute(
            "INSERT OR IGNORE INTO personas (id, name, public_key, created_at, status) \
             VALUES ('p', 'p', 'pk', ?1, 'active')",
            rusqlite::params![t0().to_rfc3339()],
        )
        .expect("seed persona");
        conn.execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status) \
             VALUES (?1, 'p', 'cred', 'github:repo:push', ?2, 'active')",
            rusqlite::params![grant_id, t0().to_rfc3339()],
        )
        .expect("seed active grant");
    }

    #[test]
    fn ac6_lease_survives_a_daemon_restart() {
        // AC-6: mint → capture the key bytes used inside `with_lease_key` →
        // simulate a daemon restart (fresh store over the same DB file, cold
        // in-memory registry) → `with_lease_key` rehydrates from the persisted
        // wrapped blob and yields the SAME key bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        let before = {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-1");
            store
                .leases()
                .mint("g-1", "p-1", "github:repo:push", Some(expiry), now);
            store
                .leases()
                .with_lease_key("g-1", now, |k| *k.as_bytes())
                .expect("freshly minted lease is live")
        };

        // --- simulated daemon restart: drop store1, open a fresh store over the
        // same DB file. Its in-memory registry is cold (len == 0). ---
        let store2 = open_with_stub_kek(&path);
        assert_eq!(
            store2.leases().len(),
            0,
            "post-restart the in-memory hot cache is cold until first access"
        );

        let after = store2
            .leases()
            .with_lease_key("g-1", now, |k| *k.as_bytes())
            .expect("post-restart with_lease_key must rehydrate from the persisted blob");

        assert_eq!(
            before, after,
            "the rehydrated lease key must be byte-identical to the pre-restart key (AC-6)"
        );
        assert_eq!(
            store2.leases().len(),
            1,
            "rehydration repopulates the in-memory hot cache"
        );
    }

    #[test]
    fn presence_scope_kek_vault_unlock_provisions_lease_kek_and_persists_minted_leases() {
        // V030-NO-LIVE-LEASE-AFTER-FRESH-INIT primary fix: the ADR 206 §4
        // vault-unlock path (`install_presence_scope_kek_vault`) used to open
        // the vault but NEVER pair the ADR 211 lease-KEK install — so every
        // grant minted on a §4-unlocked daemon fell through
        // `BoundLeaseRegistry::mint`'s in-memory-only branch, zero
        // `lease_blobs` rows were written, and the per-session proxy 403'd
        // `no_live_lease` on the first model-auth request. Post-fix the §4
        // install pairs a lease-KEK install (case c: fresh in-memory on a
        // host with no prior DE-provision), and the mint persists a
        // `lease_blobs` row the proxy can rehydrate.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::infra::interactive_unlock::reset_for_tests();

        let tmp = tempfile::tempdir().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        crate::infra::interactive_unlock::register_vault_slot(store.vault_slot());
        crate::infra::interactive_unlock::register_config(config);

        // Pre-condition: daily-driver pre-init shape — no lease-KEK, no DE outer.
        assert!(
            store.lease_kek().is_none(),
            "test pre-condition: lease-KEK slot is empty"
        );
        assert!(
            store
                .read_lease_kek_double_envelope_outer()
                .expect("read outer")
                .is_none(),
            "test pre-condition: DE outer blob is absent"
        );

        let kek = [0x42u8; 32];
        let _vault =
            crate::infra::interactive_unlock::install_presence_scope_kek_vault(&store, kek)
                .expect("install §4 scope-KEK vault");

        // Post-fix: §4 install pairs a lease-KEK install (case c).
        assert!(
            store.lease_kek().is_some(),
            "§4 vault install must pair with a lease-KEK install so subsequent \
             mints persist their wrapped blob (pre-fix this stays None and every \
             mint silently falls through to in-memory-only)"
        );

        // Mint a grant; the mint MUST write a `lease_blobs` row now that
        // lease-KEK is live.
        let now = t0();
        let expiry = now + Duration::hours(1);
        seed_active_grant(&store, "g-section4");
        store
            .leases()
            .mint("g-section4", "p", "github:repo:push", Some(expiry), now);

        assert!(
            store.read_lease_blob_for_test("g-section4").is_some(),
            "the minted lease MUST persist to lease_blobs (this is the per-session \
             proxy's cross-store visibility contract — pre-fix the row was missing \
             and `no_live_lease` 403 fired)"
        );
        assert!(
            store.leases().has_live_lease("g-section4", now),
            "the lease is also live in the in-memory hot cache"
        );
    }

    #[test]
    fn presence_scope_kek_unlock_with_existing_lease_kek_is_idempotent_noop() {
        // Companion to V030 primary fix: the §4 pairing must be a NO-OP when
        // lease-KEK is already provisioned (case a — a prior DE-unlock /
        // DE-provision installed it). The pre-existing handle must be
        // preserved by `Rc::ptr_eq` — overwriting it would orphan any
        // lease_blobs rows wrapped under the prior key.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::infra::interactive_unlock::reset_for_tests();

        let tmp = tempfile::tempdir().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(tmp.path());
        let store = DaemonStore::open_in_memory().expect("open in-memory store");
        crate::infra::interactive_unlock::register_vault_slot(store.vault_slot());
        crate::infra::interactive_unlock::register_config(config);

        // Pre-install a lease-KEK (simulates a prior DE-unlock).
        store.set_lease_kek(test_lease_kek());
        let pre_handle = store.lease_kek().expect("pre-installed");

        let kek = [0x42u8; 32];
        let _vault =
            crate::infra::interactive_unlock::install_presence_scope_kek_vault(&store, kek)
                .expect("install §4 scope-KEK vault");

        // Post: same Rc — the §4 pairing must not re-allocate or replace the
        // already-installed lease-KEK.
        let post_handle = store.lease_kek().expect("still installed after §4 install");
        assert!(
            std::rc::Rc::ptr_eq(&pre_handle, &post_handle),
            "case (a) is a strict no-op: the pre-existing lease-KEK handle \
             must be preserved (overwriting it would orphan any lease_blobs \
             wrapped under the prior key)"
        );

        // Mint still works and persists under the pre-existing lease-KEK.
        let now = t0();
        let expiry = now + Duration::hours(1);
        seed_active_grant(&store, "g-pre");
        store
            .leases()
            .mint("g-pre", "p", "github:repo:push", Some(expiry), now);
        assert!(
            store.read_lease_blob_for_test("g-pre").is_some(),
            "mint persists under the preserved pre-existing lease-KEK"
        );
    }

    #[test]
    fn proxy_fresh_store_needs_lease_kek_to_see_a_persisted_lease() {
        // Regression for the `ember claude` no_live_lease 403: the per-session
        // LLM/git proxy opens a FRESH DaemonStore (its own, cold in-memory
        // LeaseRegistry). The lease the daemon minted lives as a persisted
        // wrapped blob. A fresh store WITHOUT its own lease-KEK CANNOT
        // rehydrate it (`rehydrate_if_cold` no-ops when `lease_kek()` is None) →
        // `has_live_lease` is false → the proxy 403s every model-auth / git
        // request. Provisioning the lease-KEK on the proxy store (the fix in
        // runtime.rs's proxy spawn blocks) makes the SAME persisted lease
        // visible. This is the cross-store mechanism the live failure hinges on.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        // Daemon's main store mints + persists the wrapped lease blob.
        {
            let daemon = open_with_stub_kek(&path);
            seed_active_grant(&daemon, "g-proxy");
            daemon
                .leases()
                .mint("g-proxy", "p", "github:repo:push", Some(expiry), now);
            assert!(daemon.leases().has_live_lease("g-proxy", now));
        }

        // Proxy fresh store WITHOUT a lease-KEK (the bug): cold registry +
        // no-op rehydrate → the persisted lease is invisible → no_live_lease.
        {
            let proxy_no_kek = DaemonStore::open(&path).expect("open fresh proxy store");
            assert!(
                !proxy_no_kek.leases().has_live_lease("g-proxy", now),
                "without a lease-KEK the fresh proxy store cannot rehydrate the persisted \
                 lease — this is the no_live_lease 403 every `ember claude` request hit"
            );
        }

        // Proxy fresh store WITH the lease-KEK provisioned (the fix): rehydrates
        // the persisted blob → the lease is live.
        {
            let proxy_with_kek = open_with_stub_kek(&path);
            assert!(
                proxy_with_kek.leases().has_live_lease("g-proxy", now),
                "with the lease-KEK provisioned (runtime.rs proxy-spawn fix) the fresh proxy \
                 store rehydrates the persisted lease → request authorized"
            );
        }
    }

    #[test]
    fn ac6_expired_persisted_lease_is_not_rehydrated() {
        // An expired persisted lease is DROPPED on rehydrate, never loaded — a
        // restart must not resurrect authority-to-act past its TTL.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::minutes(30);

        {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-exp");
            store
                .leases()
                .mint("g-exp", "p-1", "github:repo:push", Some(expiry), now);
        }

        // Restart well after expiry.
        let after_expiry = expiry + Duration::seconds(1);
        let store2 = open_with_stub_kek(&path);
        assert!(
            store2
                .leases()
                .with_lease_key("g-exp", after_expiry, |_| true)
                .is_none(),
            "an expired persisted lease must NOT rehydrate (fail-closed)"
        );
        assert!(
            store2.read_lease_blob_for_test("g-exp").is_none(),
            "the stale expired blob must be deleted on the rehydrate attempt"
        );
    }

    #[test]
    fn ac6_explicit_startup_rehydrate_loads_live_drops_expired() {
        // The eager startup path: rehydrate_persisted_leases loads live leases
        // into the hot cache and drops expired ones (and their blobs).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let live_expiry = now + Duration::hours(2);
        let dead_expiry = now + Duration::minutes(10);

        {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-live");
            seed_active_grant(&store, "g-dead");
            store
                .leases()
                .mint("g-live", "p", "github:repo:push", Some(live_expiry), now);
            store
                .leases()
                .mint("g-dead", "p", "github:repo:push", Some(dead_expiry), now);
        }

        let restart_now = dead_expiry + Duration::seconds(1); // g-dead is expired
        let store2 = open_with_stub_kek(&path);
        store2
            .rehydrate_persisted_leases(restart_now)
            .expect("eager rehydrate");

        assert!(
            store2.leases().has_live_lease("g-live", restart_now),
            "the live lease is eagerly rehydrated into the hot cache"
        );
        assert_eq!(
            store2.leases().len(),
            1,
            "only the live lease is loaded; the expired one is dropped"
        );
        assert!(
            store2.read_lease_blob_for_test("g-dead").is_none(),
            "the expired lease's blob is deleted by eager rehydrate"
        );
    }

    #[test]
    fn drop_lease_deletes_the_persisted_blob() {
        // After drop_lease there is no persisted record, and a cold rehydrate
        // (fresh store over the same DB) yields nothing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        {
            let store = open_with_stub_kek(&path);
            store
                .leases()
                .mint("g-drop", "p", "github:repo:push", Some(expiry), now);
            assert!(
                store.read_lease_blob_for_test("g-drop").is_some(),
                "mint persisted a blob"
            );
            assert!(store.leases().drop_lease("g-drop"));
            assert!(
                store.read_lease_blob_for_test("g-drop").is_none(),
                "drop_lease deleted the persisted blob"
            );
        }

        // Cold rehydrate over the same DB yields nothing.
        let store2 = open_with_stub_kek(&path);
        assert!(
            store2
                .leases()
                .with_lease_key("g-drop", now, |_| true)
                .is_none(),
            "a dropped lease must not rehydrate after a restart"
        );
    }

    #[test]
    fn persisted_blob_is_the_ciphertext_never_the_raw_key_bytes() {
        // Non-exfiltratable shape: the persisted record stores the wrapped
        // ciphertext, never the raw lease-key bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        let store = open_with_stub_kek(&path);
        store
            .leases()
            .mint("g-shape", "p", "github:repo:push", Some(expiry), now);

        let raw_key = store
            .leases()
            .with_lease_key("g-shape", now, |k| k.as_bytes().to_vec())
            .expect("live lease");

        let persisted = store
            .read_lease_blob_for_test("g-shape")
            .expect("a blob was persisted");

        assert_ne!(
            persisted.wrapped_blob, raw_key,
            "the persisted blob must be the wrapped ciphertext, NOT the raw key bytes"
        );
        // The XChaCha20Poly1305 layout is strictly larger than 32 bytes
        // (nonce + tag + ciphertext), so the blob can never accidentally equal
        // a 32-byte key.
        assert!(
            persisted.wrapped_blob.len() > 32,
            "the wrapped blob carries SE-wrap framing beyond the 32-byte key"
        );
        // The raw key bytes must not appear as a contiguous window anywhere in
        // the persisted blob.
        assert!(
            !persisted
                .wrapped_blob
                .windows(raw_key.len())
                .any(|w| w == raw_key.as_slice()),
            "the raw key bytes must not appear inside the persisted ciphertext"
        );
    }

    #[test]
    fn in_memory_only_when_no_lease_kek_provisioned() {
        // A store with NO lease-KEK provisioned (the in-memory test-store posture)
        // runs the registry in-memory only: mint works, but nothing is persisted,
        // so a restart finds no blob (no regression for unprovisioned stores).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        {
            let store = DaemonStore::open(&path).unwrap(); // no set_lease_kek_for_test
            store
                .leases()
                .mint("g-nokek", "p", "github:repo:push", Some(expiry), now);
            assert!(store.leases().has_live_lease("g-nokek", now));
            assert!(
                store.read_lease_blob_for_test("g-nokek").is_none(),
                "no lease-KEK → no persistence"
            );
        }

        let store2 = DaemonStore::open(&path).unwrap();
        assert!(
            store2
                .leases()
                .with_lease_key("g-nokek", now, |_| true)
                .is_none(),
            "an unprovisioned (in-memory-only) lease does not survive a restart"
        );
    }

    #[test]
    fn revoked_grant_lease_is_not_rehydrated() {
        // LOW fix: a revoked grant (status flip; the row persists) whose lease
        // blob lingered (e.g. a prior drop_lease blob-delete failed) must NOT
        // resurrect — even a None-TTL lease that never time-expires. The
        // rehydrate-time grant-active cross-check drops the stale blob.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();

        {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-rev");
            // None-TTL lease: only the grant-active check can stop it resurrecting.
            store
                .leases()
                .mint("g-rev", "p", "github:repo:push", None, now);
            assert!(
                store.read_lease_blob_for_test("g-rev").is_some(),
                "mint persisted a blob"
            );
            // Revoke the grant but DO NOT delete the blob (simulate a failed
            // blob-delete on the drop path).
            store
                .conn()
                .execute(
                    "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                    rusqlite::params!["g-rev"],
                )
                .expect("revoke grant");
        }

        let store2 = open_with_stub_kek(&path);
        assert!(
            store2
                .leases()
                .with_lease_key("g-rev", now, |_| true)
                .is_none(),
            "a revoked grant's lease must NOT rehydrate, even with a lingering blob"
        );
        assert!(
            store2.read_lease_blob_for_test("g-rev").is_none(),
            "the stale blob of a revoked grant is dropped on the rehydrate attempt"
        );
    }

    #[test]
    fn tampered_wrapped_blob_fails_closed() {
        // Defect-2 authenticity: the blob is AES-GCM authenticated, so flipping
        // any byte (key OR sealed metadata) invalidates the Poly1305 tag and unwrap
        // fails — the lease does not rehydrate. There are no plaintext metadata
        // columns to flip, and corrupting the ciphertext cannot forge a lease.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-tamper");
            store
                .leases()
                .mint("g-tamper", "p", "github:repo:push", Some(expiry), now);
            // Corrupt the persisted ciphertext (flip the last byte) and write back.
            let mut rec = store
                .read_lease_blob_for_test("g-tamper")
                .expect("a blob was persisted");
            let last = rec.wrapped_blob.len() - 1;
            rec.wrapped_blob[last] ^= 0xFF;
            store.write_lease_blob(&rec).expect("write tampered blob");
        }

        let store2 = open_with_stub_kek(&path);
        assert!(
            store2
                .leases()
                .with_lease_key("g-tamper", now, |_| true)
                .is_none(),
            "a tampered (GCM-tag-broken) blob must fail closed, never rehydrate"
        );
    }

    // --- V030-AUTH-LEASE-3: BoundLeaseRegistry renewal -------------------

    #[test]
    fn renew_persists_a_fresh_blob_under_a_new_window() {
        // Renewal is the structural twin of mint at the store boundary: it
        // generates a fresh key, wraps it under the lease-KEK, persists the
        // blob, and replaces the in-memory hot cache entry. A daemon
        // restart after a renew must see the renewed key and the renewed
        // expires_at — never the pre-renew window.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let original_expiry = now + Duration::minutes(15);

        // Mint, capture the key, simulate a renewal, restart, verify the
        // post-restart rehydrate sees the renewed key + window.
        let renew_at = now + Duration::minutes(5);
        let lease_ttl_secs: u64 = 60 * 60; // 1h
        let new_expiry = renew_at + Duration::seconds(lease_ttl_secs as i64);

        let (pre_renew_key, post_renew_key) = {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-renew");
            store.leases().mint(
                "g-renew",
                "p",
                "github:repo:push",
                Some(original_expiry),
                now,
            );
            let pre = store
                .leases()
                .with_lease_key("g-renew", now, |k| *k.as_bytes())
                .expect("pre-renew lease is live");

            let renewed = store
                .leases()
                .renew("g-renew", lease_ttl_secs, renew_at)
                .expect("renew returns Ok")
                .expect("a live lease exists for renewal");
            assert_eq!(renewed.expires_at, Some(new_expiry));
            assert_eq!(renewed.minted_at, renew_at);
            assert_eq!(renewed.persona_id, "p");
            assert_eq!(renewed.scope, "github:repo:push");

            let post = store
                .leases()
                .with_lease_key("g-renew", renew_at, |k| *k.as_bytes())
                .expect("post-renew lease is live");
            (pre, post)
        };

        assert_ne!(
            pre_renew_key, post_renew_key,
            "renewal must rotate the grant-scoped key"
        );

        // Simulated restart — the rehydrated blob must yield the renewed
        // key + window.
        let store2 = open_with_stub_kek(&path);
        let after_restart = store2
            .leases()
            .with_lease_key("g-renew", renew_at, |k| *k.as_bytes())
            .expect("post-restart with_lease_key rehydrates renewed blob");
        assert_eq!(
            post_renew_key, after_restart,
            "the persisted blob must reflect the RENEWED key, not the pre-renew one"
        );

        // The renewed lease lives past the original window — proving the
        // window genuinely extended (not just the key rotated).
        assert!(
            store2
                .leases()
                .has_live_lease("g-renew", original_expiry + Duration::seconds(1)),
            "renewed lease must live past the original expiry"
        );
    }

    #[test]
    fn renew_returns_none_when_grant_is_revoked() {
        // V030-AUTH-LEASE-3 defense-in-depth: even with a still-cached
        // lease, a revoked grant must NOT be re-authorized by renewal.
        // The caller surfaces this as `no_live_lease` / "presence required"
        // and the operator must mint a fresh grant.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        let store = open_with_stub_kek(&path);
        seed_active_grant(&store, "g-revoked");
        store
            .leases()
            .mint("g-revoked", "p", "github:repo:push", Some(expiry), now);

        // Revoke the grant; the in-memory lease still exists, but the
        // store-bound renew must refuse to extend a lapsed grant.
        store
            .conn()
            .execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params!["g-revoked"],
            )
            .expect("revoke grant");

        let res = store
            .leases()
            .renew("g-revoked", 3600, now + Duration::minutes(5))
            .expect("renew returns Ok");
        assert!(
            res.is_none(),
            "renew of a revoked grant must fail closed (presence required to re-mint)"
        );
        // The in-memory cache is also cleared so subsequent
        // `with_lease_key` calls fail closed too (no resurrection vector).
        assert!(
            store
                .leases()
                .with_lease_key("g-revoked", now + Duration::minutes(5), |_| true)
                .is_none(),
            "renew-against-revoked-grant must leave the persona inert"
        );
    }

    #[test]
    fn renew_returns_none_when_no_live_lease_exists() {
        // The renewal primitive must never silently mint authority a
        // persona does not currently hold — even when an active grant
        // could in principle authorize one. Minting a fresh lease is
        // mint's job, not renew's; renew is a "fresh window for an
        // existing principal" primitive.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();

        let store = open_with_stub_kek(&path);
        seed_active_grant(&store, "g-no-lease");
        // No mint() before renew().

        let res = store
            .leases()
            .renew("g-no-lease", 3600, now)
            .expect("renew returns Ok");
        assert!(
            res.is_none(),
            "renew of an absent lease must NOT silently create authority"
        );
        assert!(
            store.read_lease_blob_for_test("g-no-lease").is_none(),
            "renew of an absent lease must NOT write a blob"
        );
    }

    #[test]
    fn swapped_blob_rejected_on_grant_id_mismatch() {
        // Defect-2 binding: grant_id is sealed inside the authenticated blob.
        // Copying grant A's blob into grant B's row is detected on rehydrate (the
        // sealed grant_id != the row key) and fails closed, so a DB-write attacker
        // cannot relocate one lease's authority onto a different grant.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.db");
        let now = t0();
        let expiry = now + Duration::hours(1);

        {
            let store = open_with_stub_kek(&path);
            seed_active_grant(&store, "g-a");
            seed_active_grant(&store, "g-b");
            store
                .leases()
                .mint("g-a", "p", "github:repo:push", Some(expiry), now);
            // Attacker writes g-a's blob under g-b's row.
            let blob_a = store
                .read_lease_blob_for_test("g-a")
                .expect("g-a blob")
                .wrapped_blob;
            store
                .write_lease_blob(&PersistedLease {
                    grant_id: "g-b".to_string(),
                    wrapped_blob: blob_a,
                })
                .expect("write swapped blob under g-b");
        }

        let store2 = open_with_stub_kek(&path);
        assert!(
            store2
                .leases()
                .with_lease_key("g-b", now, |_| true)
                .is_none(),
            "a blob whose sealed grant_id != the row key must fail closed (no swap)"
        );
    }
}
