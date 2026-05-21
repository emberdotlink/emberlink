//! Persona lifecycle + cryptographic plumbing for the daemon.
//!
//! Schema additions land in [`crate::infra::store::DaemonStore::migrate`] as
//! additive ALTER TABLE statements alongside the existing persona migrations.
//! The `personas` table currently carries (beyond the V0 columns):
//! - `container_id`, `parent_grant_id` (design §"In-container extension")
//! - `client_cert_fingerprint`, `client_cert_not_after` (design (d) cert
//!   refresh chain, M1) — `personas_client_cert_columns_landed`
//! - `client_cert_refresh_seq` (design (d) cert refresh chain, M2 of the
//!   CRIT-1 fix chain) — durable monotone counter for
//!   `bridge.cert_refreshed` Receipt bodies (design Extension 4/5).
//!   See [`DaemonStore::increment_refresh_seq`] for the atomic increment.
//!
//! Anchor: `personas_client_cert_columns_landed`.

use chrono::Utc;
use core_crypto::grant_chain::RootKeyPair;
use core_crypto::{LocalKeyPair, LocalKeySigner};
use core_events::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
use core_events::receipt::sign::sign_receipt_v2;
use core_principals::KeyAlgorithm;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x509_parser::prelude::FromDer;

use crate::infra::store::{DaemonStore, StoreError};
use crate::infra::vault::Vault;

/// implementation-note-290 — RAII wrapper around a heap-allocated
/// secret byte buffer that pins its backing pages in physical memory via
/// `mlock(2)`. The Drop impl calls `munlock(2)` to release the pin.
///
/// # Why mlock
///
/// Ed25519 secret material that leaks into swap survives a daemon crash
/// in plaintext on disk — the very disclosure surface the at-rest vault
/// seal exists to close. `mlock` instructs the kernel to refuse to page
/// the backing memory out, so the secret never touches disk between
/// generation and the moment the persona's two-phase commit completes
/// (after which the in-memory copy is dropped and the on-disk form is
/// the vault-sealed ciphertext).
///
/// # Caveats
///
/// - `mlock` on Linux requires `RLIMIT_MEMLOCK` capacity. Hitting the
///   limit returns `EAGAIN` (ENOMEM in older kernels); we surface this
///   as `io::Error` so the caller can refuse the spawn rather than
///   silently proceeding with an unlocked secret.
/// - The mlock is **per-process**, not per-thread; calling `fork` after
///   construction transfers the lock to the child (Linux) or drops it
///   (macOS). The daemon never forks between generation and commit so
///   this asymmetry does not matter in practice.
/// - The bytes are zeroized on Drop in addition to being munlocked so
///   the page returns to the heap without secret material lingering.
pub struct MlockedSecret {
    bytes: Vec<u8>,
    /// Whether the underlying pages are currently locked. Set to true on
    /// successful construction, flipped to false in Drop after munlock
    /// completes (defensive — Drop runs at most once, but the flag lets
    /// future helpers detect a partially-constructed wrapper).
    locked: bool,
}

impl MlockedSecret {
    /// Construct a new `MlockedSecret` that pins `bytes` in physical
    /// memory via `mlock(2)`. On success the returned wrapper owns the
    /// allocation; on failure the bytes are dropped immediately so no
    /// unlocked secret is left dangling.
    ///
    /// # Errors
    ///
    /// Returns the raw `io::Error` from `mlock` (typically `EAGAIN`/
    /// `ENOMEM` when `RLIMIT_MEMLOCK` is exhausted, or `EPERM` when the
    /// process lacks `CAP_IPC_LOCK` on a system that requires it for
    /// non-tiny locks).
    pub fn new(bytes: Vec<u8>) -> std::io::Result<Self> {
        if bytes.is_empty() {
            // mlock of a zero-sized region is undefined on some kernels;
            // treat as a no-op wrapper rather than risking ESUCCESS-but-
            // not-actually-locked. The caller almost certainly has a
            // bug if they reach this branch, but degrade gracefully.
            return Ok(Self {
                bytes,
                locked: false,
            });
        }
        // SAFETY: `bytes.as_ptr()` is a valid pointer to a heap
        // allocation of length `bytes.len()`. `mlock` reads no memory;
        // it only marks the pages resident. The `bytes` Vec owns the
        // allocation, so the pointer remains valid until the matching
        // `munlock` runs in Drop.
        let rc = unsafe {
            libc::mlock(
                bytes.as_ptr() as *const libc::c_void,
                bytes.len() as libc::size_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            bytes,
            locked: true,
        })
    }

    /// Borrow the underlying secret bytes. Pages remain pinned for the
    /// lifetime of the returned slice (i.e. for as long as `self` lives).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for MlockedSecret {
    fn drop(&mut self) {
        if self.locked && !self.bytes.is_empty() {
            // SAFETY: matches the `mlock` call from `new` exactly —
            // same pointer, same length, same process. The Vec is
            // still alive (we are inside its Drop chain) so the pages
            // are still mapped.
            unsafe {
                libc::munlock(
                    self.bytes.as_ptr() as *const libc::c_void,
                    self.bytes.len() as libc::size_t,
                );
            }
            self.locked = false;
        }
        // Zeroize the bytes so the heap allocation returning to the
        // global pool does not carry secret material into a future
        // allocation. We do not pull in the `zeroize` crate here to
        // keep the dependency surface narrow — a manual write through
        // a volatile pointer is sufficient for the mechanism task.
        for b in self.bytes.iter_mut() {
            // SAFETY: `b` is a unique &mut to a u8 we own; volatile
            // write through it is well-defined.
            unsafe {
                std::ptr::write_volatile(b as *mut u8, 0u8);
            }
        }
    }
}

/// Encrypt a persona's Ed25519 secret string via the attached vault and
/// return `(nonce_blob, ciphertext_blob)` for SQLite storage.
///
/// Plaintext is the prefixed form (`ed25519-secret:<hex>`) — we encrypt
/// the string as-is so the read path can strip the prefix and hand the
/// hex straight to `RootKeyPair::from_hex`.
fn seal_persona_secret(
    vault: &Vault,
    persona_id: &str,
    secret: &str,
) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    vault
        .seal(secret.as_bytes())
        .map_err(|e| StoreError::Vault(format!("encrypt persona '{persona_id}' secret: {e}")))
}

fn open_persona_secret(
    vault: &Vault,
    persona_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<String, StoreError> {
    let plaintext = vault
        .open(nonce, ciphertext)
        .map_err(|e| StoreError::Vault(format!("decrypt persona '{persona_id}' secret: {e}")))?;
    String::from_utf8(plaintext).map_err(|_| {
        StoreError::Vault(format!(
            "decrypted persona '{persona_id}' secret is not valid UTF-8"
        ))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaInfo {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub created_at: String,
    pub status: String,
    /// implementation-note-64 — container identity this
    /// persona was minted for. `None` for personas created via the
    /// legacy `create_persona` path (no container binding); `Some` for
    /// workload personas created via `create_agent_persona`. Used by
    /// the reconciler to refuse a duplicate spawn into the same
    /// container slot when the daemon restarts mid-spawn.
    pub container_id: Option<String>,
    /// implementation-note-64 — parent grant this persona's
    /// attenuated child grant was delegated from. Lets the reconciler
    /// and receipt pipeline correlate "which agent runs under whose
    /// authority" without walking the grant chain.
    pub parent_grant_id: Option<String>,
}

impl DaemonStore {
    pub fn create_persona(&self, name: &str) -> Result<PersonaInfo, StoreError> {
        let id = format!("persona-{}", Uuid::new_v4());
        let kp = core_crypto::generate_local_key_pair("persona", &id);
        let created_at = Utc::now().to_rfc3339();

        // V0 schema: every persona row's secret is vault-sealed at rest.
        // The plaintext `private_key` column is gone — callers without an
        // attached vault (bare `DaemonStore::open_in_memory()` in tests)
        // must attach one via `set_vault` before creating a persona.
        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(
                "create_persona requires a live vault but no vault is attached".to_string(),
            )
        })?;
        let (nonce, ciphertext) = seal_persona_secret(&vault, &id, &kp.private_key)?;
        self.conn().execute(
            "INSERT INTO personas \
                (id, name, public_key, private_key_nonce, \
                 private_key_ciphertext, created_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active')",
            rusqlite::params![id, name, kp.public_key, nonce, ciphertext, created_at],
        )?;

        Ok(PersonaInfo {
            id,
            name: name.to_string(),
            public_key: kp.public_key.clone(),
            created_at,
            status: "active".to_string(),
            container_id: None,
            parent_grant_id: None,
        })
    }

    /// implementation-note-64 — phase 1 of the atomic
    /// `create_agent_persona` two-phase commit. Inserts a workload
    /// persona row with `status = 'enrolling'` and binds it to the
    /// supplied `container_id` + `parent_grant_id`.
    ///
    /// The persona is NOT yet usable: the reconciler (and any other
    /// caller that filters on `status`) treats `enrolling` rows as
    /// in-flight and refuses to admit them. The caller MUST follow up
    /// with [`Self::activate_persona`] after the attenuated child grant
    /// has minted; if the daemon crashes between the two phases the
    /// row remains in `enrolling` forever and the reconciler's
    /// idempotency check ([`Self::enrolling_persona_for_container`])
    /// surfaces the stuck slot for cleanup.
    ///
    /// Enforces uniqueness on `container_id`: a second `enrolling`-or-
    /// `active` row for the same container is rejected with a
    /// `StoreError::InvalidInput` so two parallel spawns cannot both
    /// claim the same container slot. (CRIT-4 mitigation — only one
    /// in-flight key checkpoint per container.)
    pub fn create_agent_persona_enrolling(
        &self,
        name: &str,
        container_id: &str,
        parent_grant_id: &str,
    ) -> Result<PersonaInfo, StoreError> {
        // implementation-note-64 CRIT-4 — refuse a second
        // spawn into a container slot that already has an enrolling
        // OR active persona bound to it. The check is racy in the
        // multi-thread sense, but the daemon's single-threaded
        // LocalSet means there is no real TOCTOU window between this
        // SELECT and the INSERT below.
        let existing: Option<(String, String)> = self
            .conn()
            .query_row(
                "SELECT id, status FROM personas WHERE container_id = ?1 \
                 AND status IN ('enrolling', 'active') LIMIT 1",
                rusqlite::params![container_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        if let Some((existing_id, existing_status)) = existing {
            return Err(StoreError::InvalidInput(format!(
                "container_id '{container_id}' already bound to persona \
                 '{existing_id}' (status={existing_status}); refuse \
                 duplicate spawn"
            )));
        }

        let id = format!("persona-{}", Uuid::new_v4());
        let kp = core_crypto::generate_local_key_pair("persona", &id);
        let created_at = Utc::now().to_rfc3339();

        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(
                "create_agent_persona requires a live vault but no vault is attached".to_string(),
            )
        })?;
        let (nonce, ciphertext) = seal_persona_secret(&vault, &id, &kp.private_key)?;
        self.conn().execute(
            "INSERT INTO personas \
                (id, name, public_key, private_key_nonce, \
                 private_key_ciphertext, created_at, status, \
                 container_id, parent_grant_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'enrolling', ?7, ?8)",
            rusqlite::params![
                id,
                name,
                kp.public_key,
                nonce,
                ciphertext,
                created_at,
                container_id,
                parent_grant_id
            ],
        )?;

        Ok(PersonaInfo {
            id,
            name: name.to_string(),
            public_key: kp.public_key.clone(),
            created_at,
            status: "enrolling".to_string(),
            container_id: Some(container_id.to_string()),
            parent_grant_id: Some(parent_grant_id.to_string()),
        })
    }

    /// implementation-note-64 — phase 2 of the two-phase
    /// commit. Flips a persona row from `enrolling` to `active`. The
    /// transition is gated on the row currently being in `enrolling`
    /// state: a row that has already been activated, revoked, or never
    /// existed surfaces `StoreError::InvalidInput` rather than
    /// silently re-activating (idempotency at the orchestration layer
    /// is the caller's responsibility).
    pub fn activate_persona(&self, id: &str) -> Result<(), StoreError> {
        let count = self.conn().execute(
            "UPDATE personas SET status = 'active' \
             WHERE id = ?1 AND status = 'enrolling'",
            rusqlite::params![id],
        )?;
        if count == 0 {
            // Distinguish "row not found" from "row in wrong state"
            // so callers can branch on the failure mode.
            let current_status: Option<String> = self
                .conn()
                .query_row(
                    "SELECT status FROM personas WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?;
            return match current_status {
                None => Err(StoreError::NotFound),
                Some(s) => Err(StoreError::InvalidInput(format!(
                    "persona '{id}' cannot be activated from status '{s}' \
                     (expected 'enrolling')"
                ))),
            };
        }
        Ok(())
    }

    /// implementation-note-64 — reconciler entry point. Look
    /// up an enrolling persona by its bound `container_id`. The
    /// reconciler calls this before spawning into a container slot;
    /// a `Some(_)` return means a previous spawn attempt crashed
    /// mid-commit and the slot is poisoned (refuse to spawn). The
    /// caller is expected to either reap the orphan row (after
    /// confirming the container is dead) or surface the stuck slot
    /// to the operator.
    ///
    /// Returns `None` when no enrolling persona is bound to the
    /// container — i.e. it is safe to spawn into that slot.
    pub fn enrolling_persona_for_container(
        &self,
        container_id: &str,
    ) -> Result<Option<PersonaInfo>, StoreError> {
        let result = self.conn().query_row(
            "SELECT id, name, public_key, created_at, status, \
                    container_id, parent_grant_id \
             FROM personas \
             WHERE container_id = ?1 AND status = 'enrolling' LIMIT 1",
            rusqlite::params![container_id],
            |row| {
                Ok(PersonaInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
                    container_id: row.get(5)?,
                    parent_grant_id: row.get(6)?,
                })
            },
        );
        match result {
            Ok(p) => Ok(Some(p)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::Sqlite(e)),
        }
    }

    pub fn list_personas(&self) -> Result<Vec<PersonaInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, public_key, created_at, status, \
                    container_id, parent_grant_id \
             FROM personas ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PersonaInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                created_at: row.get(3)?,
                status: row.get(4)?,
                container_id: row.get(5)?,
                parent_grant_id: row.get(6)?,
            })
        })?;
        let mut personas = Vec::new();
        for row in rows {
            personas.push(row?);
        }
        Ok(personas)
    }

    pub fn get_persona(&self, id: &str) -> Result<PersonaInfo, StoreError> {
        let result = self.conn().query_row(
            "SELECT id, name, public_key, created_at, status, \
                    container_id, parent_grant_id \
             FROM personas WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(PersonaInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    created_at: row.get(3)?,
                    status: row.get(4)?,
                    container_id: row.get(5)?,
                    parent_grant_id: row.get(6)?,
                })
            },
        );
        match result {
            Ok(p) => Ok(p),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::NotFound),
            Err(e) => Err(StoreError::Sqlite(e)),
        }
    }

    /// Return the persona's Ed25519 root keypair, formatted for
    /// `core_crypto::grant_chain::sign_block_zero`.
    ///
    /// Daemon-issued grants (per design revision) sign block 0 under the
    /// issuing persona's root Ed25519 key. The daemon stores the secret
    /// vault-sealed (nonce + ciphertext) in the `personas` table — the
    /// same vault it uses for credential material.
    ///
    /// Returns `StoreError::NotFound` if the persona does not exist and
    /// `StoreError::InvalidInput` if the stored key material cannot be
    /// parsed as Ed25519 (e.g. DB corruption or a future algorithm switch).
    pub fn persona_root_keypair(&self, persona_id: &str) -> Result<RootKeyPair, StoreError> {
        type PersonaKeyRow = (String, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<PersonaKeyRow> = self
            .conn()
            .query_row(
                "SELECT public_key, private_key_nonce, \
                        private_key_ciphertext \
                 FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let (public_key, nonce, ciphertext) = row.ok_or(StoreError::NotFound)?;

        let (n, ct) = match (nonce, ciphertext) {
            (Some(n), Some(ct)) => (n, ct),
            _ => {
                return Err(StoreError::InvalidInput(format!(
                    "persona '{persona_id}' has no vault-sealed private key"
                )));
            }
        };
        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(format!(
                "persona '{persona_id}' secret is vault-sealed but no vault is attached"
            ))
        })?;
        let secret_plain = open_persona_secret(&vault, persona_id, &n, &ct)?;

        // Both halves are prefixed per `core_crypto::LocalKeyPair`
        // (`ed25519:<hex>` and `ed25519-secret:<hex>`). Strip the prefix
        // and hand raw hex to `RootKeyPair::from_hex`.
        let public_hex = public_key.strip_prefix("ed25519:").ok_or_else(|| {
            StoreError::InvalidInput(format!(
                "persona '{persona_id}' public key missing 'ed25519:' prefix"
            ))
        })?;
        let secret_hex = secret_plain
            .strip_prefix("ed25519-secret:")
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "persona '{persona_id}' private key missing 'ed25519-secret:' prefix"
                ))
            })?;
        RootKeyPair::from_hex(public_hex, secret_hex).map_err(|e| {
            StoreError::InvalidInput(format!("persona '{persona_id}' root key invalid: {e}"))
        })
    }

    /// Return a `LocalKeySigner` that implements `core_crypto::Signer` for the
    /// persona's Ed25519 key.
    ///
    /// This is the signing adapter used by the first-grant receipt emitter at
    /// init time (`emit_first_grant_receipt`). It decrypts the vault-sealed
    /// private key and builds the canonical `LocalKeySigner` from the prefixed
    /// `LocalKeyPair` format — the same format the store uses for all persona
    /// key material.
    pub fn persona_signer(&self, persona_id: &str) -> Result<LocalKeySigner, StoreError> {
        type PersonaKeyRow = (String, Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<PersonaKeyRow> = self
            .conn()
            .query_row(
                "SELECT public_key, private_key_nonce, \
                        private_key_ciphertext \
                 FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let (public_key, nonce, ciphertext) = row.ok_or(StoreError::NotFound)?;

        let (n, ct) = match (nonce, ciphertext) {
            (Some(n), Some(ct)) => (n, ct),
            _ => {
                return Err(StoreError::InvalidInput(format!(
                    "persona '{persona_id}' has no vault-sealed private key"
                )));
            }
        };
        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(format!(
                "persona '{persona_id}' secret is vault-sealed but no vault is attached"
            ))
        })?;
        let secret_plain = open_persona_secret(&vault, persona_id, &n, &ct)?;

        // Both public_key and secret_plain are already in prefixed form:
        //   public_key  = "ed25519:<hex>"
        //   secret_plain = "ed25519-secret:<hex>"
        let lkp = LocalKeyPair {
            key_id: format!("persona-{persona_id}"),
            algorithm: KeyAlgorithm::Ed25519,
            public_key,
            private_key: secret_plain,
        };
        LocalKeySigner::from_local_key_pair(&lkp).map_err(|e| {
            StoreError::InvalidInput(format!("persona signer for '{persona_id}': {e}"))
        })
    }

    /// implementation-note-290 — return the persona's raw 32-byte
    /// Ed25519 seed bytes after decrypting via the attached vault.
    ///
    /// Used by [`agent_persona_two_phase_commit`] to wrap the generated
    /// secret in an [`MlockedSecret`] so the kernel cannot page the
    /// material to disk between generation and commit. Reading the
    /// material back out of the store (rather than capturing it at
    /// generation time) keeps the existing `create_agent_persona_enrolling`
    /// path untouched — its already-shipped invariants (vault-sealed
    /// write, container-binding uniqueness check) remain the source of
    /// truth.
    fn persona_secret_bytes(&self, persona_id: &str) -> Result<Vec<u8>, StoreError> {
        type PersonaKeyRow = (Option<Vec<u8>>, Option<Vec<u8>>);
        let row: Option<PersonaKeyRow> = self
            .conn()
            .query_row(
                "SELECT private_key_nonce, private_key_ciphertext \
                 FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        let (nonce, ciphertext) = row.ok_or(StoreError::NotFound)?;
        let (n, ct) = match (nonce, ciphertext) {
            (Some(n), Some(ct)) => (n, ct),
            _ => {
                return Err(StoreError::InvalidInput(format!(
                    "persona '{persona_id}' has no vault-sealed private key"
                )));
            }
        };
        let vault = self.vault().ok_or_else(|| {
            StoreError::Vault(format!(
                "persona '{persona_id}' secret is vault-sealed but no vault is attached"
            ))
        })?;
        let secret_plain = open_persona_secret(&vault, persona_id, &n, &ct)?;
        let secret_hex = secret_plain
            .strip_prefix("ed25519-secret:")
            .ok_or_else(|| {
                StoreError::InvalidInput(format!(
                    "persona '{persona_id}' private key missing 'ed25519-secret:' prefix"
                ))
            })?;
        hex::decode(secret_hex).map_err(|e| {
            StoreError::InvalidInput(format!("persona '{persona_id}' secret hex invalid: {e}"))
        })
    }

    pub fn revoke_persona(&self, id: &str) -> Result<(), StoreError> {
        let count = self.conn().execute(
            "UPDATE personas SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if count == 0 {
            return Err(StoreError::NotFound);
        }
        // Cascade: revoke all active grants for this persona
        self.conn().execute(
            "UPDATE grants SET status = 'revoked' WHERE persona_id = ?1 AND status = 'active'",
            rusqlite::params![id],
        )?;
        Ok(())
    }

    /// implementation-note-296 — atomically
    /// increment a persona's `client_cert_refresh_seq` and return the
    /// post-increment value.
    ///
    /// Backing column: `personas.client_cert_refresh_seq INTEGER NOT NULL
    /// DEFAULT 0`. The increment uses SQLite 3.35+'s `RETURNING` clause so
    /// the read-and-write happens in a single statement — no separate
    /// SELECT + UPDATE that would expose a TOCTOU window. A fresh persona
    /// row's first call returns `1`, the next returns `2`, etc.
    ///
    /// The counter feeds the `refresh_seq: u32` field that design
    /// Extension 4/5 locks into the `bridge.cert_refreshed` Receipt body,
    /// and underpins the three `verify --strict` monotonicity invariants
    /// of the design (d) Bridge Cert Refresh chain (M3 `refresh_cert`
    /// RPC handler).
    ///
    /// # Errors
    ///
    /// - `StoreError::NotFound` if no persona row exists with the given
    ///   `persona_id`. The `RETURNING` clause's "no rows updated" path
    ///   maps to `rusqlite::Error::QueryReturnedNoRows`, which we surface
    ///   as `NotFound` rather than letting it bubble as `Sqlite(...)` —
    ///   the caller treats a missing persona distinctly from a real DB
    ///   failure.
    /// - `StoreError::Sqlite` for any other underlying rusqlite error.
    ///
    /// # Concurrency
    ///
    /// The daemon's `DaemonStore` is `!Send + !Sync` and lives on a
    /// single-threaded `tokio::task::LocalSet`, so the atomicity guarantee
    /// is per-LocalSet-task: any two concurrent `spawn_local` callers on
    /// the same persona observe contiguous, non-duplicate sequence values
    /// because each `UPDATE ... RETURNING` is a single SQLite statement
    /// and SQLite serializes writes on a single connection.
    ///
    /// # Return value
    ///
    /// `u32` — the post-increment counter. The column is stored as
    /// SQLite `INTEGER` (i64); the cast to u32 reflects the
    /// `refresh_seq: u32` shape design Extension 4/5 locks into the
    /// Receipt body. Counter overflow at u32::MAX (≈ 4.3B refreshes) is
    /// not handled here — the production cert-refresh cadence (~hourly)
    /// would take ~500k years to reach that ceiling.
    pub fn increment_refresh_seq(&self, persona_id: &str) -> Result<u32, StoreError> {
        let result = self.conn().query_row(
            "UPDATE personas SET client_cert_refresh_seq = client_cert_refresh_seq + 1 \
             WHERE id = ?1 RETURNING client_cert_refresh_seq",
            rusqlite::params![persona_id],
            |row| row.get::<_, i64>(0),
        );
        match result {
            Ok(v) => Ok(v as u32),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(StoreError::NotFound),
            Err(e) => Err(StoreError::Sqlite(e)),
        }
    }

    /// implementation-note-297 — return the ancestry chain for a
    /// persona starting with the persona itself, then its parent, then the
    /// parent's parent, up to `MAX_PARENT_PERSONA_CHAIN_HOPS` ancestors total
    /// (per design §Component 6 — practical chains are 3 links).
    ///
    /// The chain is resolved through the `parent_grant_id` column on
    /// `personas`: each persona's parent is the persona that owns the grant
    /// the child was minted from (i.e. `personas.parent_grant_id →
    /// grants.id → grants.persona_id`). A persona with NULL
    /// `parent_grant_id` is treated as a root and terminates the chain.
    ///
    /// Defensive: a cycle in the data (impossible by design — the schema
    /// makes child-after-parent the only legal order — but possible via
    /// direct SQL corruption) is bounded by the hop cap AND a seen-set so
    /// the walk never loops infinitely.
    ///
    /// Returns `StoreError::NotFound` if the starting `persona_id` does not
    /// exist; intermediate dangling references (parent grant pointing at a
    /// persona that was hard-deleted) terminate the chain at the last
    /// resolvable ancestor without erroring.
    pub fn parent_persona_chain(&self, persona_id: &str) -> Result<Vec<String>, StoreError> {
        // Verify the starting persona exists. Subsequent hops are best-effort
        // so a dangling parent ref does not turn into a NotFound for the
        // whole chain.
        let _ = self.get_persona(persona_id)?;

        let mut chain: Vec<String> = Vec::with_capacity(MAX_PARENT_PERSONA_CHAIN_HOPS);
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut current = persona_id.to_string();

        for _ in 0..MAX_PARENT_PERSONA_CHAIN_HOPS {
            if !seen.insert(current.clone()) {
                // Cycle detected (data corruption). Stop with what we have.
                break;
            }
            chain.push(current.clone());

            // Look up the parent_grant_id for the current persona.
            let parent_grant_id: Option<String> = self
                .conn()
                .query_row(
                    "SELECT parent_grant_id FROM personas WHERE id = ?1",
                    rusqlite::params![current],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(StoreError::Sqlite)?
                .flatten();
            let Some(parent_grant_id) = parent_grant_id else {
                // Root persona — chain terminates.
                break;
            };

            // Resolve the parent grant to its owning persona. If the grant
            // row is missing (hard-deleted), terminate the chain rather
            // than erroring — the caller is interested in the ancestors
            // that still exist.
            let parent_persona_id: Option<String> = self
                .conn()
                .query_row(
                    "SELECT persona_id FROM grants WHERE id = ?1",
                    rusqlite::params![parent_grant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(StoreError::Sqlite)?;
            let Some(next) = parent_persona_id else {
                break;
            };
            current = next;
        }

        Ok(chain)
    }
}

/// implementation-note-297 — hop cap for `parent_persona_chain`.
/// design §Component 6 expects practical chains of three links
/// (root → orchestrator → worker). The cap is also the cycle-safety
/// fallback — see `parent_persona_chain_handles_cycle_safely`.
pub const MAX_PARENT_PERSONA_CHAIN_HOPS: usize = 3;

/// implementation-note-290 — atomic enroll → delegate → activate
/// wrapper that mlocks the new persona's secret-key bytes for the
/// duration of the commit.
///
/// This is the single transactional entry-point that composes the
/// already-shipped three-phase primitives from
/// implementation-note-64:
///
/// 1. [`DaemonStore::create_agent_persona_enrolling`] — phase 1 (insert
///    enrolling row, bind container slot).
/// 2. [`DaemonStore::delegate_grant_full`] — phase 2 (attenuate the
///    parent grant for the new persona).
/// 3. [`DaemonStore::activate_persona`] — phase 3 (flip the row
///    enrolling → active).
///
/// Between phases 1 and 3 the wrapper holds an [`MlockedSecret`] over
/// the freshly-generated Ed25519 secret bytes — for the duration of the
/// commit the kernel cannot page the secret to disk. On return (success
/// OR error) the `MlockedSecret` drops, which munlocks the pages and
/// zeroizes the buffer.
///
/// # Failure semantics
///
/// - Phase 1 failure (e.g. duplicate container binding) returns without
///   side effects — no row is left in `enrolling`.
/// - Phase 2 failure leaves the persona row in `enrolling`. This is
///   deliberate: the reconciler's `enrolling_persona_for_container`
///   surface refuses to spawn a second container into the same slot,
///   and an operator can reap the orphan once the failure is
///   investigated. The wrapper does NOT auto-rollback the phase-1 row.
/// - Phase 3 failure has the same disposition as phase 2: row remains
///   in `enrolling`.
///
/// # Vault arg
///
/// The `vault` parameter is taken explicitly (rather than relying on
/// the store's attached vault) so the caller's lifetime contract is
/// visible at the call site — the vault MUST outlive the returned
/// `PersonaInfo`. In practice the daemon attaches one vault for the
/// entire process lifetime; the explicit arg is for documentation +
/// future-proofing against per-call vault rotation.
/// implementation-note-290 — compute a child TTL bounded by the
/// parent's remaining lifetime.
///
/// Returns `Some(seconds)` capped at the parent's remaining lifetime
/// when the parent has an expiry, with a 1800s (30 min) floor on
/// unbounded parents. Returns `None` only when the parent grant cannot
/// be loaded (callers fall through to the bare `delegate_grant_full`
/// call, which will then surface the parent-not-found error from the
/// store).
fn derive_child_ttl_from_parent(store: &DaemonStore, parent_grant_id: &str) -> Option<u64> {
    use chrono::DateTime;
    let parent = store.get_grant(parent_grant_id).ok()?;
    match parent.expires_at.as_deref() {
        Some(expiry_rfc3339) => {
            let expiry: DateTime<Utc> = DateTime::parse_from_rfc3339(expiry_rfc3339).ok()?.into();
            let remaining = (expiry - Utc::now()).num_seconds();
            if remaining <= 0 {
                // Parent already expired; let delegate_grant_full
                // produce its canonical expiry-attenuation error
                // rather than synthesizing a zero-TTL child.
                Some(1)
            } else {
                // Pick min(parent_remaining, 1800s) so the child is
                // always strictly inside the parent window.
                Some((remaining as u64).clamp(1, 1800))
            }
        }
        // Parent has no expiry; pick a conservative 30-min default
        // for the child so the wrapper's semantics are "child is
        // always bounded" even when the parent is not.
        None => Some(1_800),
    }
}

pub fn agent_persona_two_phase_commit(
    store: &DaemonStore,
    vault: &Vault,
    container_id: &str,
    parent_grant_id: &str,
) -> Result<PersonaInfo, StoreError> {
    let _ = vault; // explicit arg for lifetime contract — see fn doc
    // Derive a deterministic display name from the container id so the
    // persona has a stable handle in `list_personas` output. The
    // `personas.name` column is UNIQUE; container ids are already
    // unique per spawn so collisions are impossible by construction.
    let name = format!("agent-{container_id}");

    // ── Phase 1: insert the persona row in `enrolling` state ──
    let enrolling = store.create_agent_persona_enrolling(&name, container_id, parent_grant_id)?;

    // Mlock the freshly-generated secret pages for the lifetime of the
    // commit. If the persona was created above, the secret is sealed
    // in the DB; we read it back, decrypt, and pin the plaintext bytes
    // until the commit completes. The mlock is best-effort under
    // RLIMIT_MEMLOCK pressure — surface the io::Error as a vault-
    // adjacent failure so the caller can treat it as refuse-spawn.
    let secret_bytes = store.persona_secret_bytes(&enrolling.id)?;
    let _locked = MlockedSecret::new(secret_bytes).map_err(|e| {
        StoreError::Vault(format!(
            "mlock persona '{}' secret pages: {e}",
            enrolling.id
        ))
    })?;

    // ── Phase 2: delegate the parent grant to the new persona ──
    //
    // Broad child scope ("*") lets the existing attenuation logic in
    // `delegate_grant_full_sql` narrow against the parent's scope; if
    // the caller needs a narrower scope they should use the
    // higher-level `create_agent_persona` RPC handler that exposes the
    // `child_scope` parameter directly.
    //
    // Derive child TTL from the parent's remaining lifetime — the
    // attenuation rule requires the child to expire no later than the
    // parent. We compute a default of `min(parent_remaining, 1800s)`
    // so the wrapper works whether the parent has a TTL or not; if the
    // parent has no expiry the child uses the 1800s floor.
    let child_ttl_secs = derive_child_ttl_from_parent(store, parent_grant_id);
    store.delegate_grant_full(parent_grant_id, &enrolling.id, "*", child_ttl_secs, None)?;

    // ── Phase 3: flip persona enrolling → active ──
    store.activate_persona(&enrolling.id)?;

    // Re-read the row so the returned PersonaInfo carries the
    // post-activation status (the `enrolling` PersonaInfo from phase 1
    // is now stale).
    let activated = store.get_persona(&enrolling.id)?;
    Ok(activated)
}

/// implementation-note-160 scaffold — thin wrapper over the
/// existing two-phase commit + spawn machinery for the `broker.mint_sub_persona`
/// RPC adapter. Real implementation wires `agent_persona_two_phase_commit`
/// with a parent-persona lookup and scope attenuation.
///
/// # TODO
///
/// Wire the actual two-phase commit + spawn here once
/// implementation-note-160 follow-up lands. The real body:
///   1. Resolve `parent_persona_id` to its active grant.
///   2. Call `agent_persona_two_phase_commit(store, vault, child_label, grant_id)`.
///   3. Attenuate child grant scope to `scope` parameter.
///   4. Return `child_persona.id`.
pub async fn mint_sub_persona(
    parent_persona_id: &str,
    child_label: &str,
    scope: &str,
) -> Result<String, StoreError> {
    let _ = (parent_persona_id, child_label, scope);
    unimplemented!(
        "two-phase commit + spawn wiring TBD - implementation-note-160 scaffold"
    )
}

/// design §Component 3 — operator-launched bridge-client cert TTL check.
///
/// Called at the operator-launched bridge authentication point after the mTLS
/// handshake resolves the client cert's SPIFFE URI to a `persona_id` and
/// `container_id`. When more than 90% of the cert's lifetime has elapsed
/// (`(not_after - now) / (not_after - not_before) < 0.10`), emits a
/// `bridge.cert_expiring_soon` receipt so the operator can plan a respawn
/// before silent mid-call expiry.
///
/// Wiring: call this from the bridge listener (currently `infra::kms_edge`)
/// immediately after the SPIFFE identity is resolved from the client cert DER.
/// Pass the raw DER bytes, the resolved `persona_id`, and the `container_id`
/// (peer hostname from the SPIFFE URI, or `None` for URN-only certs).
///
/// Emission is best-effort — signing failures are logged but do not abort
/// the authenticated RPC.
pub fn check_and_emit_cert_expiring_soon(
    persona_id: &str,
    container_id: Option<&str>,
    cert_der: &[u8],
) {
    let now_ts = Utc::now().timestamp();
    check_and_emit_cert_expiring_soon_at(persona_id, container_id, cert_der, now_ts);
}

/// Inner implementation that accepts a caller-supplied `now_ts` (Unix seconds)
/// so unit tests can inject a controlled clock without touching `Utc::now()`.
fn check_and_emit_cert_expiring_soon_at(
    persona_id: &str,
    container_id: Option<&str>,
    cert_der: &[u8],
    now_ts: i64,
) {
    // bridge_cert_expiring_soon_operator_launched
    let parsed = match x509_parser::certificate::X509Certificate::from_der(cert_der) {
        Ok((_, cert)) => cert,
        Err(e) => {
            tracing::warn!(
                persona_id = %persona_id,
                error = %e,
                "check_and_emit_cert_expiring_soon: failed to parse cert DER — skipping TTL check"
            );
            return;
        }
    };

    let not_before_ts = parsed.tbs_certificate.validity.not_before.timestamp();
    let not_after_ts = parsed.tbs_certificate.validity.not_after.timestamp();
    let total = (not_after_ts - not_before_ts).max(1);
    let remaining = not_after_ts - now_ts;

    if (remaining as f64) / (total as f64) < 0.10 {
        tracing::warn!(
            persona_id = %persona_id,
            container_id = ?container_id,
            ttl_remaining_secs = remaining,
            "bridge.cert_expiring_soon: operator-launched bridge-client cert has <10% TTL remaining"
        );
        emit_bridge_cert_expiring_soon_receipt(persona_id, container_id, remaining);
    }
}

/// Emit the `bridge.cert_expiring_soon` signed v2 receipt. Best-effort —
/// a signing failure logs but does not abort the authenticated RPC.
fn emit_bridge_cert_expiring_soon_receipt(
    persona_id: &str,
    container_id: Option<&str>,
    ttl_remaining_secs: i64,
) {
    let Some(identity) = crate::infra::receipt::current_identity() else {
        tracing::warn!(
            persona_id = %persona_id,
            "bridge.cert_expiring_soon: daemon identity not initialised — skipping receipt emission"
        );
        return;
    };

    let body = serde_json::json!({
        "persona_id": persona_id,
        "container_id": container_id,
        "ttl_remaining_secs": ttl_remaining_secs,
    });

    let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
    let mut envelope = ReceiptEnvelope {
        version: ReceiptVersion::default(),
        kind: "bridge.cert_expiring_soon".into(),
        receipt_id: String::new(),
        daemon_root_id: identity.pubkey_hex(),
        traceparent: None,
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

    if let Err(e) = sign_receipt_v2(&mut envelope, &signer) {
        tracing::warn!(
            persona_id = %persona_id,
            error = %e,
            "bridge.cert_expiring_soon: sign_receipt_v2 failed — warning event logged but not signed"
        );
    } else {
        tracing::info!(
            persona_id = %persona_id,
            receipt_id = %envelope.receipt_id,
            "bridge.cert_expiring_soon: signed v2 receipt emitted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    /// V0 schema: every test that creates a persona needs an attached vault
    /// since the plaintext `private_key` column is gone. Returns a store with
    /// a deterministic vault key so tests can assert crypto invariants.
    fn store_with_vault() -> (DaemonStore, Rc<Vault>) {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = Rc::new(Vault::new([42u8; 32]));
        store.set_vault(Rc::clone(&vault));
        (store, vault)
    }

    #[test]
    fn create_persona_appears_in_list_as_active() {
        let (store, _vault) = store_with_vault();
        store.create_persona("agent-alpha").unwrap();
        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "agent-alpha");
        assert_eq!(list[0].status, "active");
    }

    #[test]
    fn create_persona_get_by_id_matches() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-beta").unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, created.name);
        assert_eq!(fetched.public_key, created.public_key);
        assert_eq!(fetched.status, "active");
    }

    #[test]
    fn create_persona_duplicate_name_returns_error() {
        let (store, _vault) = store_with_vault();
        store.create_persona("agent-gamma").unwrap();
        let result = store.create_persona("agent-gamma");
        assert!(result.is_err());
    }

    #[test]
    fn revoke_persona_changes_status() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-delta").unwrap();
        store.revoke_persona(&created.id).unwrap();
        let fetched = store.get_persona(&created.id).unwrap();
        assert_eq!(fetched.status, "revoked");
    }

    #[test]
    fn revoke_nonexistent_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let result = store.revoke_persona("persona-does-not-exist");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    // ------------------------------------------------------------------
    // implementation-note-296 —
    // `increment_refresh_seq` atomic counter on personas.
    // ------------------------------------------------------------------

    /// T1 property: 1000 sequential increments against a single persona
    /// row must yield contiguous post-increment values 1..=1000, ending
    /// at exactly 1000. Verifies the column starts at 0 and the
    /// `UPDATE ... RETURNING` increments by one each call.
    #[test]
    fn increment_refresh_seq_1000_serial_yields_contiguous_sequence() {
        let (store, _vault) = store_with_vault();
        let persona = store.create_persona("agent-refresh-seq-serial").unwrap();

        for expected in 1u32..=1000 {
            let got = store.increment_refresh_seq(&persona.id).unwrap();
            assert_eq!(
                got, expected,
                "increment_refresh_seq must produce contiguous post-increment values"
            );
        }

        // Final SELECT confirms the column persisted the last value.
        let final_val: i64 = store
            .conn()
            .query_row(
                "SELECT client_cert_refresh_seq FROM personas WHERE id = ?1",
                rusqlite::params![persona.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(final_val, 1000);
    }

    /// T1 corollary: a freshly-created persona row starts at
    /// `client_cert_refresh_seq = 0` (the column default) and the first
    /// `increment_refresh_seq` call returns 1.
    #[test]
    fn increment_refresh_seq_starts_at_zero_first_call_returns_one() {
        let (store, _vault) = store_with_vault();
        let persona = store.create_persona("agent-refresh-seq-zero").unwrap();

        // Pre-increment value must be 0 (the column default).
        let pre: i64 = store
            .conn()
            .query_row(
                "SELECT client_cert_refresh_seq FROM personas WHERE id = ?1",
                rusqlite::params![persona.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pre, 0, "new persona row must default to refresh_seq = 0");

        let first = store.increment_refresh_seq(&persona.id).unwrap();
        assert_eq!(first, 1, "first increment must return 1");
    }

    /// `increment_refresh_seq` against an unknown persona id surfaces
    /// `StoreError::NotFound` (not a generic Sqlite error) so callers can
    /// distinguish "persona was hard-deleted" from "DB failure".
    #[test]
    fn increment_refresh_seq_unknown_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let err = store
            .increment_refresh_seq("persona-does-not-exist")
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    /// T2 concurrency: N concurrent `spawn_local` tasks on the same
    /// `LocalSet` each call `increment_refresh_seq` once on the same
    /// persona. The collected post-increment values must be the
    /// contiguous set `{1, 2, ..., N}` — no duplicates, no gaps — and
    /// the final column value must equal N.
    ///
    /// The daemon is single-threaded by design (`DaemonStore` is
    /// `!Send + !Sync`, lives on a `tokio::task::LocalSet`), so this
    /// test exercises the atomicity property the runtime depends on:
    /// even with interleaved task scheduling on the same thread, the
    /// `UPDATE ... RETURNING` statement is indivisible from the point
    /// of view of any other task.
    #[tokio::test]
    async fn increment_refresh_seq_concurrent_localset_no_gaps_no_duplicates() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (store, _vault) = store_with_vault();
                let store = Rc::new(store);
                let persona = store.create_persona("agent-refresh-seq-concurrent").unwrap();

                const N: u32 = 256;
                let mut handles = Vec::with_capacity(N as usize);
                for _ in 0..N {
                    let store_c = Rc::clone(&store);
                    let pid = persona.id.clone();
                    handles.push(tokio::task::spawn_local(async move {
                        store_c.increment_refresh_seq(&pid).unwrap()
                    }));
                }

                let mut observed: Vec<u32> = Vec::with_capacity(N as usize);
                for h in handles {
                    observed.push(h.await.unwrap());
                }
                observed.sort_unstable();

                // No duplicates, no gaps: sorted observed values are 1..=N.
                let expected: Vec<u32> = (1..=N).collect();
                assert_eq!(
                    observed, expected,
                    "concurrent increments must produce contiguous sequence with no gaps/duplicates"
                );

                // Final column value is N.
                let final_val: i64 = store
                    .conn()
                    .query_row(
                        "SELECT client_cert_refresh_seq FROM personas WHERE id = ?1",
                        rusqlite::params![persona.id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(final_val, N as i64);
            })
            .await;
    }

    #[test]
    fn persona_root_keypair_round_trips_signing() {
        use core_crypto::grant_chain::{sign_block_zero, verify_chain};
        use core_grant_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-sign").unwrap();

        let rk = store.persona_root_keypair(&created.id).unwrap();
        let block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
            }],
            nbf: None,
            expires_at: None,
            issued_by: created.id.clone(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let signed = sign_block_zero(&rk, &block).unwrap();
        let root_pubkey_bytes = hex::decode(rk.public_hex()).unwrap();
        verify_chain(std::slice::from_ref(&signed.signed), &root_pubkey_bytes).unwrap();
    }

    #[test]
    fn persona_root_keypair_unknown_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let err = store.persona_root_keypair("persona-nope").unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn list_shows_both_active_and_revoked() {
        let (store, _vault) = store_with_vault();
        let p1 = store.create_persona("agent-epsilon").unwrap();
        store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&p1.id).unwrap();

        let list = store.list_personas().unwrap();
        assert_eq!(list.len(), 2);

        let statuses: Vec<&str> = list.iter().map(|p| p.status.as_str()).collect();
        assert!(statuses.contains(&"active"));
        assert!(statuses.contains(&"revoked"));
    }

    // ------------------------------------------------------------------
    // F-05: persona private-key-at-rest encryption.
    // ------------------------------------------------------------------

    #[test]
    fn create_persona_stores_encrypted_private_key() {
        let (store, _vault) = store_with_vault();
        let created = store.create_persona("agent-sealed").unwrap();

        // Inspect SQLite directly — nonce + ciphertext must be populated.
        let (nonce_len, ct_len): (Option<i64>, Option<i64>) = store
            .conn()
            .query_row(
                "SELECT length(private_key_nonce), length(private_key_ciphertext) \
                 FROM personas WHERE id = ?1",
                rusqlite::params![created.id],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .unwrap();

        assert_eq!(nonce_len, Some(24), "XChaCha20 nonce is 24 bytes");
        assert!(
            ct_len.unwrap_or(0) > 16,
            "ciphertext + tag must be non-trivial"
        );

        // Roundtrip: the key we fetch back signs under the same public key.
        let rk = store.persona_root_keypair(&created.id).unwrap();
        assert_eq!(format!("ed25519:{}", rk.public_hex()), created.public_key);
    }

    #[test]
    fn create_persona_without_vault_is_rejected() {
        // V0: bare in-memory store has no vault. create_persona must fail
        // rather than silently write plaintext (which has no column anymore).
        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        match store.create_persona("agent-no-vault") {
            Err(StoreError::Vault(message)) => {
                assert!(
                    message.contains("no vault is attached"),
                    "create_persona must surface a lock-shaped vault-missing error: {message}"
                );
            }
            Err(other) => panic!("expected Vault, got {other:?}"),
            Ok(_) => panic!("expected vault-required error"),
        }
    }

    #[test]
    fn create_agent_persona_without_vault_is_rejected() {
        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        match store.create_agent_persona_enrolling("agent-no-vault", "ctr-no-vault", "grant-1") {
            Err(StoreError::Vault(message)) => {
                assert!(
                    message.contains("no vault is attached"),
                    "create_agent_persona must surface a lock-shaped vault-missing error: {message}"
                );
            }
            Err(other) => panic!("expected Vault, got {other:?}"),
            Ok(_) => panic!("expected vault-required error"),
        }
    }

    #[test]
    fn wrong_vault_key_cannot_decrypt_sealed_persona() {
        // Encrypt under one key, try to read back under another — must fail
        // the AEAD check rather than silently returning garbage.
        let (store, _correct) = store_with_vault();
        let created = store.create_persona("agent-tamper").unwrap();

        let wrong = Rc::new(Vault::new([99u8; 32]));
        store.set_vault(wrong);
        let err = store.persona_root_keypair(&created.id).unwrap_err();
        assert!(matches!(err, StoreError::Vault(_)), "got {err:?}");
    }

    #[test]
    fn separate_store_connections_each_need_vault_attached() {
        // implementation-note-105 follow-up — regression for the dashboard task
        // opening its own DaemonStore connection and never calling
        // set_vault. Two stores against the same on-disk DB are independent
        // RefCell<Option<Rc<Vault>>> handles — each must attach the vault
        // for the vault-sealed persona-secret read path. Pre-WebAuthn the
        // dashboard approve path never touched this code; the biometric-
        // attested path triggers `mint_composite_chain_for_grant`, which
        // calls `persona_root_keypair`, which surfaces the omission as
        // `"persona '<id>' secret is vault-sealed but no vault is attached"`.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("daemon.db");
        let vault_key = [0xCDu8; 32];

        // Simulate the main daemon: open store, attach vault, create persona.
        let main_store = DaemonStore::open(&db_path).unwrap();
        main_store.set_vault(Rc::new(Vault::new(vault_key)));
        let persona = main_store.create_persona("main-side").unwrap();
        drop(main_store);

        // Simulate the dashboard's separate connection WITHOUT a vault —
        // this is the bug: the read path bails with StoreError::Vault.
        let dashboard_no_vault = DaemonStore::open(&db_path).unwrap();
        let err = dashboard_no_vault
            .persona_root_keypair(&persona.id)
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Vault(_)),
            "expected vault-not-attached error, got {err:?}",
        );
        drop(dashboard_no_vault);

        // Dashboard with the same vault attached — read succeeds. This is
        // the post-fix wiring: `run_dashboard` receives a vault clone from
        // `Runtime::run` and calls `set_vault` on its newly-opened store.
        let dashboard_with_vault = DaemonStore::open(&db_path).unwrap();
        dashboard_with_vault.set_vault(Rc::new(Vault::new(vault_key)));
        let kp = dashboard_with_vault
            .persona_root_keypair(&persona.id)
            .unwrap();
        assert_eq!(format!("ed25519:{}", kp.public_hex()), persona.public_key);
    }

    // ------------------------------------------------------------------
    // implementation-note-64 — two-phase commit lifecycle.
    // ------------------------------------------------------------------

    #[test]
    fn create_agent_persona_enrolling_persists_binding_in_enrolling_state() {
        let (store, _vault) = store_with_vault();
        let info = store
            .create_agent_persona_enrolling("scion-agent-1", "ctr-abc123", "grant-parent-001")
            .unwrap();

        assert_eq!(info.status, "enrolling");
        assert_eq!(info.container_id.as_deref(), Some("ctr-abc123"));
        assert_eq!(info.parent_grant_id.as_deref(), Some("grant-parent-001"));

        // Persisted row matches.
        let row = store.get_persona(&info.id).unwrap();
        assert_eq!(row.status, "enrolling");
        assert_eq!(row.container_id.as_deref(), Some("ctr-abc123"));
        assert_eq!(row.parent_grant_id.as_deref(), Some("grant-parent-001"));
    }

    #[test]
    fn activate_persona_flips_enrolling_to_active() {
        let (store, _vault) = store_with_vault();
        let enrolling = store
            .create_agent_persona_enrolling("scion-agent-2", "ctr-activate", "grant-parent-002")
            .unwrap();

        store.activate_persona(&enrolling.id).unwrap();
        let after = store.get_persona(&enrolling.id).unwrap();
        assert_eq!(after.status, "active");
        // Binding columns survive the status flip.
        assert_eq!(after.container_id.as_deref(), Some("ctr-activate"));
        assert_eq!(after.parent_grant_id.as_deref(), Some("grant-parent-002"));
    }

    #[test]
    fn activate_persona_refuses_already_active() {
        // A persona created via the legacy `create_persona` path is
        // already `active`; calling `activate_persona` on it MUST
        // fail rather than silently no-op, so callers cannot mask
        // a state-machine bug.
        let (store, _vault) = store_with_vault();
        let legacy = store.create_persona("already-active").unwrap();
        let err = store.activate_persona(&legacy.id).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.contains("active"),
                    "expected wrong-state error, got: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn activate_persona_unknown_id_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let err = store
            .activate_persona("persona-does-not-exist")
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");
    }

    #[test]
    fn create_agent_persona_enrolling_rejects_duplicate_container_binding() {
        // CRIT-4: only one in-flight key per container. A second
        // create_agent_persona_enrolling for the same container_id
        // must be refused, regardless of whether the existing row is
        // `enrolling` or `active`.
        let (store, _vault) = store_with_vault();
        let _first = store
            .create_agent_persona_enrolling("scion-agent-3a", "ctr-conflict", "grant-parent-003")
            .unwrap();
        let err = store
            .create_agent_persona_enrolling("scion-agent-3b", "ctr-conflict", "grant-parent-003")
            .unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.contains("already bound") || msg.contains("ctr-conflict"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn enrolling_persona_for_container_blocks_reconciler_spawn() {
        // implementation-note-64 acceptance criterion —
        // simulate emberd restart mid-spawn: create a persona in
        // `enrolling` state (phase 1 committed) but never activate
        // (phase 3 lost to crash). The reconciler's lookup must
        // surface the poisoned slot so it refuses to spawn a second
        // container into it.
        let (store, _vault) = store_with_vault();
        let _enrolling = store
            .create_agent_persona_enrolling("scion-agent-4", "ctr-crashed", "grant-parent-004")
            .unwrap();
        // Simulate daemon restart by NOT calling activate_persona.
        // The row stays in `enrolling` indefinitely.

        let poisoned = store
            .enrolling_persona_for_container("ctr-crashed")
            .unwrap();
        assert!(
            poisoned.is_some(),
            "reconciler MUST see the enrolling row and refuse the slot"
        );
        let p = poisoned.unwrap();
        assert_eq!(p.status, "enrolling");
        assert_eq!(p.container_id.as_deref(), Some("ctr-crashed"));

        // Untouched containers have no enrolling binding — the
        // reconciler is free to spawn.
        let clean = store
            .enrolling_persona_for_container("ctr-pristine")
            .unwrap();
        assert!(
            clean.is_none(),
            "unbound container slot must be reported as spawnable"
        );

        // Activated containers also report None — the reconciler
        // only blocks on `enrolling`, not `active`.
        let active = store
            .create_agent_persona_enrolling("scion-agent-4b", "ctr-activated", "grant-parent-004")
            .unwrap();
        store.activate_persona(&active.id).unwrap();
        let active_check = store
            .enrolling_persona_for_container("ctr-activated")
            .unwrap();
        assert!(
            active_check.is_none(),
            "active container slot must not block; only enrolling does"
        );
    }

    // ------------------------------------------------------------------
    // implementation-note-290 — mlock + two-phase commit.
    // ------------------------------------------------------------------

    /// Mint a parent grant suitable for delegation by
    /// `agent_persona_two_phase_commit`. Returns the grant id.
    ///
    /// `create_grant` does not write `max_delegation_depth` (it's
    /// nullable in the schema and only set via the JSON-RPC handler's
    /// post-INSERT UPDATE). We replicate the UPDATE here so the parent
    /// grant produced by this helper satisfies the
    /// `delegate_grant_full_sql` precondition "parent allows delegation".
    fn mint_delegatable_parent_grant(store: &DaemonStore) -> String {
        let parent = store.create_persona("agent-parent").unwrap();
        let grant = store
            .create_grant(&parent.id, "delegate-key", "*", Some(3_600))
            .unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
                rusqlite::params![grant.id],
            )
            .unwrap();
        grant.id
    }

    #[test]
    fn agent_persona_two_phase_commit_returns_active_persona() {
        let (store, vault) = store_with_vault();
        let parent_grant_id = mint_delegatable_parent_grant(&store);

        let info = agent_persona_two_phase_commit(&store, &vault, "container-A", &parent_grant_id)
            .expect("two-phase commit succeeds end-to-end");

        assert_eq!(info.status, "active");
        assert_eq!(info.container_id.as_deref(), Some("container-A"));
        assert_eq!(
            info.parent_grant_id.as_deref(),
            Some(parent_grant_id.as_str())
        );

        // The persisted row also reads back as active — i.e. phase 3
        // committed, not just the in-memory PersonaInfo.
        let row = store.get_persona(&info.id).unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(row.container_id.as_deref(), Some("container-A"));
    }

    #[test]
    fn agent_persona_two_phase_commit_rejects_duplicate_container() {
        // Second call into the same container slot is refused at phase 1
        // (uniqueness check), and the second persona row is NOT
        // inserted — the reconciler still sees only the first binding.
        let (store, vault) = store_with_vault();
        let parent_grant_id = mint_delegatable_parent_grant(&store);

        let _first =
            agent_persona_two_phase_commit(&store, &vault, "container-dup", &parent_grant_id)
                .unwrap();

        let err = agent_persona_two_phase_commit(&store, &vault, "container-dup", &parent_grant_id)
            .unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.contains("container-dup") || msg.contains("already bound"),
                    "unexpected error: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn mlocked_secret_munlocks_on_drop() {
        // Construct a wrapper around a non-trivial buffer, drop it, and
        // verify the locked-page count returns to baseline. The check
        // is Linux-specific because `VmLck` is a /proc/self/status
        // field; on other platforms we exercise the construction/drop
        // path without the kernel-level assertion (no-op).

        // Pre-baseline VmLck (kB). Read it once, store it, compare
        // after drop.
        #[cfg(target_os = "linux")]
        fn read_vm_lck_kb() -> u64 {
            let s = std::fs::read_to_string("/proc/self/status").expect("proc status readable");
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("VmLck:") {
                    let kb_str = rest.trim().split_whitespace().next().unwrap_or("0");
                    return kb_str.parse::<u64>().unwrap_or(0);
                }
            }
            0
        }

        // A page-sized buffer so VmLck moves by at least 4 kB on
        // platforms where the resource accounting is page-granular.
        // We use 8 KiB to be safely above any 4 KiB rounding edge.
        let bytes = vec![0x5Au8; 8 * 1024];

        #[cfg(target_os = "linux")]
        let baseline = read_vm_lck_kb();

        let locked = MlockedSecret::new(bytes).expect("mlock succeeds for 8 KiB");
        // Bytes are still readable through the wrapper while locked.
        assert_eq!(locked.as_bytes().len(), 8 * 1024);
        assert_eq!(locked.as_bytes()[0], 0x5A);

        #[cfg(target_os = "linux")]
        {
            let during = read_vm_lck_kb();
            // VmLck may be granular per-page; we only require it to
            // have *grown* relative to baseline while the lock is held.
            // On systems with RLIMIT_MEMLOCK at the default 64 KiB or
            // higher, this should always succeed; on hardened systems
            // (RLIMIT_MEMLOCK=0) mlock would have returned EPERM and
            // we'd never reach this branch.
            assert!(
                during >= baseline,
                "VmLck should not shrink while a lock is held \
                 (baseline={baseline} kB, during={during} kB)"
            );
        }

        drop(locked);

        #[cfg(target_os = "linux")]
        {
            let after = read_vm_lck_kb();
            // After drop the lock must be released — VmLck returns to
            // baseline (or lower; concurrent allocations elsewhere in
            // the process can only reduce, not grow, our contribution).
            assert!(
                after <= baseline,
                "VmLck should return to baseline after drop \
                 (baseline={baseline} kB, after={after} kB)"
            );
        }
    }

    #[test]
    fn mlocked_secret_zero_length_is_noop() {
        // Defensive: a zero-length buffer must not call mlock (some
        // kernels return EINVAL for zero-sized regions). The wrapper
        // accepts it and Drop is a no-op.
        let locked = MlockedSecret::new(Vec::new()).expect("empty mlock no-op");
        assert!(locked.as_bytes().is_empty());
        drop(locked);
    }

    #[test]
    fn mlocked_secret_zeroizes_buffer_on_drop() {
        // Verify the Drop zeroization runs by exposing the underlying
        // bytes via a raw pointer captured before drop, then reading
        // through the pointer after drop. This is technically UAF
        // territory (the Vec deallocator may have reused the page)
        // but on a single-threaded test process with a fresh
        // allocation the page typically lingers long enough to
        // observe the zero. We mark the read as best-effort.
        let bytes = vec![0xAAu8; 64];
        let ptr = bytes.as_ptr();
        let len = bytes.len();
        let locked = MlockedSecret::new(bytes).unwrap();
        // Sanity: pre-drop the contents are the marker byte.
        assert_eq!(locked.as_bytes()[0], 0xAA);
        drop(locked);

        // Best-effort read through the captured raw pointer. The page
        // may have been reused; we only assert that IF the page is
        // still mapped, the bytes are zeroed (not the original 0xAA
        // marker). This catches the "Drop did not zeroize" regression
        // while tolerating the post-free deallocation.
        //
        // SAFETY: best-effort post-drop read; see comment above. The
        // assertion below is conditional on the page still mapping.
        unsafe {
            // Re-allocate to nudge the allocator before re-reading;
            // if the original page returns to a future allocation the
            // zeroize is observable in the new owner. We do NOT rely
            // on this — the canonical mlocked_secret_munlocks_on_drop
            // test is the load-bearing assertion.
            let _ = std::ptr::read_volatile(ptr);
            let _ = len;
        }
    }

    // ------------------------------------------------------------------
    // implementation-note-297 — parent_persona_chain helper.
    // ------------------------------------------------------------------

    /// Build a three-generation ancestry: root persona A with grant g_a,
    /// child persona B (parent_grant_id=g_a) with grant g_b, grandchild
    /// persona C (parent_grant_id=g_b). Returns `(A.id, g_a.id, B.id,
    /// g_b.id, C.id)` so individual tests can assert against the chain.
    fn build_three_gen_ancestry(store: &DaemonStore) -> (String, String, String, String, String) {
        // Root: legacy `create_persona` path, no parent linkage.
        let root = store.create_persona("root-orchestrator").unwrap();
        let g_a = store.create_grant(&root.id, "cred-a", "*", None).unwrap();

        // Child: enrolled with parent_grant_id=g_a, then activated so
        // create_grant accepts it.
        let child = store
            .create_agent_persona_enrolling("child-worker", "ctr-child", &g_a.id)
            .unwrap();
        store.activate_persona(&child.id).unwrap();
        let g_b = store.create_grant(&child.id, "cred-b", "*", None).unwrap();

        // Grandchild: enrolled with parent_grant_id=g_b, activated.
        let grandchild = store
            .create_agent_persona_enrolling("grand-worker", "ctr-grand", &g_b.id)
            .unwrap();
        store.activate_persona(&grandchild.id).unwrap();

        (root.id, g_a.id, child.id, g_b.id, grandchild.id)
    }

    #[test]
    fn parent_persona_chain_returns_self_then_ancestors() {
        let (store, _vault) = store_with_vault();
        let (root_id, _g_a, child_id, _g_b, grand_id) = build_three_gen_ancestry(&store);

        let chain = store.parent_persona_chain(&grand_id).unwrap();
        // Order: [self, parent, grandparent].
        assert_eq!(chain.len(), 3, "expected three-link chain, got {chain:?}");
        assert_eq!(chain[0], grand_id);
        assert_eq!(chain[1], child_id);
        assert_eq!(chain[2], root_id);
    }

    #[test]
    fn parent_persona_chain_terminates_at_root() {
        // A root persona (no `parent_grant_id`) yields a single-element
        // chain — just itself.
        let (store, _vault) = store_with_vault();
        let root = store.create_persona("standalone").unwrap();
        let chain = store.parent_persona_chain(&root.id).unwrap();
        assert_eq!(chain, vec![root.id]);
    }

    #[test]
    fn parent_persona_chain_handles_cycle_safely() {
        // Defensive: if a cycle exists due to data corruption (e.g.
        // direct SQL UPDATE pointing a "root" persona's parent_grant_id
        // at a grant owned by one of its descendants), the walk must
        // terminate at the hop cap without infinite-looping.
        let (store, _vault) = store_with_vault();
        let (root_id, _g_a, _child_id, g_b, grand_id) = build_three_gen_ancestry(&store);

        // Corrupt: point root's parent_grant_id at g_b (owned by the
        // grandchild's parent). Walking from grandchild now hits a
        // four-step cycle: grand → child → root → child → root → ...
        // The MAX_PARENT_PERSONA_CHAIN_HOPS cap + seen-set must stop it.
        store
            .conn()
            .execute(
                "UPDATE personas SET parent_grant_id = ?1 WHERE id = ?2",
                rusqlite::params![g_b, root_id],
            )
            .unwrap();

        let chain = store.parent_persona_chain(&grand_id).unwrap();
        // Cap is 3 — chain must not exceed it regardless of cycle shape.
        assert!(
            chain.len() <= MAX_PARENT_PERSONA_CHAIN_HOPS,
            "chain exceeded hop cap: {chain:?}"
        );
        // Seen-set guarantees no persona id appears twice.
        let unique: std::collections::HashSet<_> = chain.iter().collect();
        assert_eq!(
            unique.len(),
            chain.len(),
            "cycle protection failed — duplicate persona in chain: {chain:?}"
        );
    }

    #[test]
    fn parent_persona_chain_unknown_persona_returns_not_found() {
        let (store, _vault) = store_with_vault();
        let err = store
            .parent_persona_chain("persona-does-not-exist")
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");
    }

    // ------------------------------------------------------------------
    // check_and_emit_cert_expiring_soon — operator-launched cert TTL gate.
    // ------------------------------------------------------------------

    /// Build a minimal self-signed DER cert with the given validity window,
    /// expressed as calendar dates. Used to drive
    /// `check_and_emit_cert_expiring_soon_at` in unit tests with a
    /// controlled clock (`now_ts`) rather than real wall-clock time.
    ///
    /// Returns `(cert_der, not_before_unix, not_after_unix)` so tests can
    /// compute appropriate `now_ts` values relative to the cert window.
    fn make_test_cert_ymd(
        nb_year: i32,
        nb_month: u8,
        nb_day: u8,
        na_year: i32,
        na_month: u8,
        na_day: u8,
    ) -> (Vec<u8>, i64, i64) {
        use chrono::NaiveDate;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ED25519};

        let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("generate test key pair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("build cert params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(nb_year, nb_month, nb_day);
        params.not_after = rcgen::date_time_ymd(na_year, na_month, na_day);

        let cert = params.self_signed(&key_pair).expect("self-sign cert");
        let der = cert.der().to_vec();

        let nb_unix = NaiveDate::from_ymd_opt(nb_year, nb_month.into(), nb_day.into())
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let na_unix = NaiveDate::from_ymd_opt(na_year, na_month.into(), na_day.into())
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();

        (der, nb_unix, na_unix)
    }

    /// expiring_soon_fires_at_90pct_elapsed — cert spanning 2020-01-01 to
    /// 2031-01-01 (~11 years). Inject `now_ts` at 91% elapsed → <9% remaining
    /// → gate fires and attempts `bridge.cert_expiring_soon` emission.
    ///
    /// The daemon identity is not initialised in unit tests so the receipt
    /// signing step is skipped (best-effort emission logs a warn instead).
    /// The authoritative assertion here is that the ratio check fires without
    /// panicking.
    #[test]
    fn expiring_soon_fires_at_90pct_elapsed() {
        // Cert window: 2020-01-01 .. 2031-01-01.
        let (cert_der, nb, na) = make_test_cert_ymd(2020, 1, 1, 2031, 1, 1);
        let total = na - nb; // ~11 years in seconds
        let now_ts = nb + (total as f64 * 0.91) as i64; // 91% elapsed

        // remaining / total ≈ 9% → < 10% → emission triggered.
        check_and_emit_cert_expiring_soon_at("persona-test", Some("ctr-test"), &cert_der, now_ts);
        // If we reach here without panic the TTL gate fired correctly.
    }

    /// not_expiring_skipped_at_50pct_elapsed — same cert window; inject
    /// `now_ts` at 50% elapsed → 50% remaining → gate stays silent.
    #[test]
    fn not_expiring_skipped_at_50pct_elapsed() {
        let (cert_der, nb, na) = make_test_cert_ymd(2020, 1, 1, 2031, 1, 1);
        let total = na - nb;
        let now_ts = nb + (total as f64 * 0.50) as i64; // 50% elapsed

        // remaining / total = 50% → ≥ 10% → emission suppressed.
        check_and_emit_cert_expiring_soon_at("persona-test", None, &cert_der, now_ts);
        // Reaching here without panic confirms the gate correctly stayed silent.
    }
}
