//! bridge_ca_se_sealed_persistent
//! ember_rpc_sibling_server_cert_minted_at_startup
//! bridge_ca_pem_publish_format_reconciled
//! CLASSIFICATION: PUBLIC
//!
//! SE-sealed-persistent client-auth CA per ADR 154 component 3 (reversed from
//! v1 ephemeral mlock'd). Private key material is persisted under a
//! vault-sealed module wrapping key, held in-memory only while the daemon is
//! running, and survives daemon restart without wiping outstanding per-agent
//! client certs.
//!
//! ## Why SE-sealed (not ephemeral mlock'd)
//!
//! Daemon restart (macOS update, ember upgrade, MEK rotation, crash +
//! KeepAlive) must NOT wipe outstanding per-agent client certs. The CA's
//! persistence is what makes the cert chain stable across restart.
//!
//! ## This file
//!
//! `BridgeCa::load_or_mint` owns the persisted bridge-CA substrate:
//!
//! - `bridge_ca.wrap` stores a vault-sealed 32-byte module wrapping key.
//! - `bridge_ca.sealed` stores the ed25519 Bridge CA secret sealed under that
//!   module key via `seal_with_key`.
//! - `bridge_ca.pub` and `bridge_ca.pem` are always republished so the raw-key
//!   fingerprint cache and PEM trust root stay current without opening the
//!   sealed blob elsewhere.
//!
//! ## Bridge CA publish format — dual raw+PEM (META-AP-DAEMON-BRIDGE-CA-PEM-PUBLISH-FORMAT)
//!
//! Anchor: `bridge_ca_pem_publish_format_reconciled`.
//!
//! Two on-disk consumers want different shapes of the same key material, and
//! `load_or_mint` republishes BOTH on every call (Option A from the brief —
//! least disruption to existing consumers):
//!
//! - `bridge_ca.pub` — **raw 32 bytes** of the ed25519 verifying key. Read
//!   without any TLS/X.509 machinery by [`load_cached_bridge_ca_fingerprint`]
//!   for the Spawn-Receipt fingerprint cache + the `bridge_ca_fingerprint`
//!   embedded in receipts (Slice C/D). Preserving the raw-bytes contract is
//!   what keeps Spawn-Receipt continuity stable across the PEM addition.
//! - `bridge_ca.pem` — **PEM-encoded self-signed root cert** suitable for
//!   `rustls_pemfile::certs` and rustls `RootCertStore::add`. This is what
//!   the OS-supervised `ember-rpc` sibling (ADR 155 amendment) reads at
//!   `cfg.ca_cert_path` to build the closed `WebPkiClientVerifier` trust
//!   domain — see `crates/ember-rpc/src/listener.rs::load_certs`.
//!
//! The launchd plist + systemd unit env-pin `EMBER_RPC_CA_CERT` to the `.pem`
//! file under `<data_dir>` (see [`crate::install::render_rpc_launchd_plist_body`]
//! and [`crate::install::render_rpc_systemd_unit_body`]) so the sibling never
//! falls back to the lib `Config::default()` path (`/var/lib/emberd/...`),
//! which the prod daemon never writes.
//!
//! T3 integration coverage that wires emberd's mint → ember-rpc's listener →
//! a real mTLS handshake (with a client cert signed by the same BridgeCa)
//! lives at `crates/ember-daemon/tests/bridge_ca_pem_listener_handshake.rs`.
//!
//! The lower-level crypto primitives (`mint`, `seal_with_key`,
//! `unseal_from_key`, `verifying_key`, `trust_root_cert_pem`) remain here so
//! the persistence format and the cert-minting primitives stay co-located.
//!
//! ## Sibling server-cert mint (ARCH-EMBER-RPC-PHASE-C-SIBLING-CERT-MINT)
//!
//! Anchor: `ember_rpc_sibling_server_cert_minted_at_startup`.
//!
//! The ember-rpc sibling process (ADR 155 amendment) terminates mTLS on
//! behalf of emberd core. Its TLS server identity is a leaf cert signed by
//! this `BridgeCa`. `sign_server_cert` below is the primitive; the wiring
//! that calls it at daemon startup (and writes the PEM-pair under
//! `<data_dir>/ember-rpc/`) lives in `infra::runtime`. The cert chain is:
//!
//!   BridgeCa (self-signed root, SE-sealed) → ember-rpc server leaf (30-day TTL)
//!
//! Runtime publishes the same root in two on-disk shapes:
//!
//! - `bridge_ca.pub` — raw 32-byte ed25519 verifying-key bytes for
//!   fingerprint caching / Spawn Receipt continuity.
//! - `bridge_ca.pem` — PEM-encoded self-signed root cert for rustls clients
//!   like `ember-rpc`.
//!
//! Honest scope: `sign_server_cert` only mints. It does NOT enforce the
//! chain-validation invariants the listener relies on at handshake time —
//! that's the listener's job (`crates/ember-rpc/src/listener.rs`). What this
//! function DOES guarantee structurally:
//!
//! - The leaf cert's signature is verifiable against `BridgeCa`'s
//!   verifying key (the math is rcgen's, not ours).
//! - The leaf carries `serverAuth` EKU (so a client rejecting non-server
//!   EKUs refuses it on the wrong lane).
//! - The leaf is not a CA (`IsCa::NoCa`) and cannot issue further certs.
//!
//! What this function does NOT enforce:
//!
//! - Operator-supplied SANs are NOT validated for shape. The caller in
//!   `infra::runtime` is responsible for SAN content (it derives them from
//!   `EMBER_BRIDGE_BIND`). A malformed SAN string surfaces as
//!   `BridgeCaError::CertGen` from rcgen.
//! - TTL bounds are NOT enforced here — the caller picks 30 days for the
//!   ember-rpc sibling cert; other callers picking absurd TTLs would
//!   produce certs that still validate cryptographically but trip
//!   handshake-time `not_after` checks.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519, SanType,
};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use zeroize::{Zeroize, Zeroizing};

use crate::infra::vault::{SealedEnvelope, Vault, VaultError};

/// ADR 198 Part B — purpose-bound AAD identifier for the bridge-CA module
/// wrapping key sealed under the vault MEK. There is exactly one bridge CA
/// per data dir, so the purpose label alone is a stable identifier (the
/// module key is minted before the CA exists, so no owning id is available
/// at seal time). Folded into both the DEK-wrap AAD and the payload AAD.
pub(crate) const BRIDGE_CA_MODULE_KEY_AAD_ID: &[u8] = b"bridge-ca-module-key";

/// XChaCha20-Poly1305 nonce length. NOTE: since the S6a.2 envelope, the
/// `bridge_ca.wrap` module-key blob is a serialized `SealedEnvelope`
/// (magic + payload nonce + dek nonce + length-framed wrapped-DEK +
/// ciphertext), NOT a bare `[nonce][ciphertext]`. The `bridge_ca.sealed`
/// blob (sealed under the module key, not the MEK) remains the simple shape.
const SEALED_NONCE_LEN: usize = 24;
/// Length of the bridge-CA module wrapping key.
const BRIDGE_CA_MODULE_KEY_LEN: usize = 32;

/// ADR 198 D1 — read-only probe for the relocated Bridge-CA module-key wrap
/// in `<data_dir>/daemon.db`'s `vault_meta.bridge_ca_wrapped` column.
/// Mirrors the vault module's `salt_from_vault_meta` / `headless_mek_from_vault_meta`
/// probes: opens a read-only connection so `load_or_mint` resolves the DB
/// copy without threading a live `DaemonStore` through its (widely-called)
/// signature. Returns `None` (→ `bridge_ca.wrap` file fallback) on any
/// failure or NULL column.
fn bridge_ca_wrap_from_vault_meta(data_dir: &Path) -> Option<Vec<u8>> {
    let db_path = data_dir.join("daemon.db");
    if !db_path.exists() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    use rusqlite::OptionalExtension as _;
    let row: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT bridge_ca_wrapped FROM vault_meta WHERE id = 1",
            [],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .ok()?;
    row.flatten()
}

/// SE-sealed Bridge CA.
///
/// `pubkey_path` — path to the on-disk pubkey file (`<data_dir>/bridge_ca.pub`).
/// `fingerprint` — 32-byte blake3 fingerprint for Spawn Receipt embedding.
/// `sealed`      — true when the CA private key is persisted and the public
///                 root artifacts have been published to disk.
///
/// The ed25519 private key is held in-memory and zeroized on drop.
pub struct BridgeCa {
    /// On-disk pubkey path (`<data_dir>/bridge_ca.pub`).
    pub pubkey_path: PathBuf,
    /// Cached blake3 fingerprint of the public-key bytes.
    /// Slice C reads this to embed in Spawn Receipts; Slice D compares.
    pub fingerprint: [u8; 32],
    /// True when pubkey material has been published to disk.
    pub sealed: bool,
    /// ed25519 signing key (private + public). Held in-memory only.
    key: SigningKey,
}

impl std::fmt::Debug for BridgeCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material — only the fingerprint.
        f.debug_struct("BridgeCa")
            .field("pubkey_path", &self.pubkey_path)
            .field("fingerprint_hex", &hex::encode(self.fingerprint))
            .field("sealed", &self.sealed)
            .finish()
    }
}

impl Drop for BridgeCa {
    fn drop(&mut self) {
        // ed25519-dalek's SigningKey's internal ScalarBytes is dropped and
        // zeroized automatically via its ZeroizeOnDrop impl. We scribble the
        // fingerprint (not sensitive, but signals intent).
        self.fingerprint.zeroize();
    }
}

/// Errors from BridgeCa operations.
#[derive(Debug, thiserror::Error)]
pub enum BridgeCaError {
    /// AEAD encrypt or decrypt failed (wrong key, tampered ciphertext, or
    /// wrong nonce). Used by the lower-level `seal_with_key`/`unseal_from_key`
    /// crypto primitives.
    #[error("AEAD failure: {0}")]
    Aead(String),
    /// Wrapping key is the wrong length (must be 32 bytes).
    #[error("wrapping key must be 32 bytes (got {0})")]
    InvalidWrappingKey(usize),
    /// Sealed blob is malformed (wrong nonce length, truncated).
    #[error("sealed blob malformed: {0}")]
    MalformedSealed(String),
    /// Sealed bytes don't decode to a valid ed25519 SigningKey.
    #[error("sealed blob doesn't decode to a valid ed25519 key")]
    InvalidKeyMaterial,
    /// Server cert minting failed (rcgen / key encoding / SAN encoding /
    /// signature). Surfaced as `BridgeCaError` so callers in
    /// `infra::runtime` can wrap it in `DaemonError::BridgeCaInit` and
    /// fail-closed at startup rather than booting a daemon that the
    /// ember-rpc sibling cannot bind against.
    #[error("server cert generation failed: {0}")]
    CertGen(String),
    /// Subject CN was empty. The CN is load-bearing for operator
    /// log-readability ("which cert just rotated?"); rcgen would accept
    /// an empty CN but we refuse it here so a bug in the caller cannot
    /// silently produce a CN-less cert.
    #[error("server cert subject must not be empty")]
    EmptySubject,
    /// SAN list was empty. mTLS handshake validation requires SAN entries
    /// matching the server hostname; a cert with no SANs is unusable.
    #[error("server cert SAN list must not be empty")]
    EmptySanList,
}

/// Errors from [`BridgeCa::load_or_mint`].
#[derive(Debug, thiserror::Error)]
pub enum BridgeCaLoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault: {0}")]
    Vault(#[from] VaultError),
    #[error("bridge ca: {0}")]
    Bridge(#[from] BridgeCaError),
    /// On-disk sealed blob is shorter than the 24-byte nonce prefix.
    /// Indicates either disk corruption or a truncated write from a
    /// crash mid-`std::fs::write`.
    #[error("malformed sealed blob at {path}: file too short ({len} bytes; need >= 24)")]
    MalformedBlob { path: PathBuf, len: usize },
    /// Wrapping key (decoded from `bridge_ca.wrap`) has unexpected length.
    #[error("bridge ca wrapping key has unexpected length: {0}")]
    WrappingKeyLen(usize),
}

impl BridgeCa {
    // ── Persisted Bridge CA substrate ──

    /// Load the persisted Bridge CA from `<data_dir>` if present, otherwise
    /// mint a fresh one.
    ///
    /// The Bridge CA private key is sealed under a module wrapping key; that
    /// module key is itself AEAD-enveloped under the daemon vault's
    /// Interactive MEK. The public root artifacts are always republished to
    /// `bridge_ca.pub` and `bridge_ca.pem` so external consumers can recover
    /// the fingerprint and trust root without opening the vault.
    ///
    /// **ADR 198 D1 — DB-first module-key wrap.** The authoritative store for
    /// the MEK-wrapped module key is `vault_meta.bridge_ca_wrapped` (a
    /// serialized [`SealedEnvelope`]); the `bridge_ca.wrap` file is the
    /// transitional/bootstrap location. Resolution order: DB column →
    /// `bridge_ca.wrap` file → first-mint. An Interactive-MEK rotation
    /// re-wraps the module key under the new MEK and writes the DB column
    /// inside the rotation transaction (then retires the file), so the wrap
    /// re-protection is atomic with the per-row DEK rewraps — closing the
    /// brick window a separate post-commit file rewrite would open. A
    /// rotation deletes the file, so this DB-first read is what stops the
    /// `else`-branch from minting a NEW (identity-losing) CA after a rotation.
    pub fn load_or_mint(data_dir: &Path, vault: &Vault) -> Result<Self, BridgeCaLoadError> {
        let wrap_path = data_dir.join("bridge_ca.wrap");
        let sealed_path = data_dir.join("bridge_ca.sealed");
        let pubkey_path = data_dir.join("bridge_ca.pub");
        let pem_path = data_dir.join("bridge_ca.pem");

        // ADR 198 Part B / D1 — the module wrapping key is enveloped: the
        // vault MEK no longer directly encrypts it. The wrap is a serialized
        // `SealedEnvelope` (per-blob DEK seals the key; the DEK is wrapped
        // under the Interactive MEK with the bridge-CA-bound AAD), held
        // DB-first (`vault_meta.bridge_ca_wrapped`) with the `bridge_ca.wrap`
        // file as the transitional fallback.
        let db_wrap = bridge_ca_wrap_from_vault_meta(data_dir);
        let module_key: Zeroizing<[u8; BRIDGE_CA_MODULE_KEY_LEN]> = if let Some(blob) = db_wrap {
            let env =
                SealedEnvelope::from_blob(&blob).map_err(|_| BridgeCaLoadError::MalformedBlob {
                    path: data_dir.join("daemon.db#vault_meta.bridge_ca_wrapped"),
                    len: blob.len(),
                })?;
            let plaintext = vault.open(
                crate::infra::vault::ValueClass::DaemonOperational,
                BRIDGE_CA_MODULE_KEY_AAD_ID,
                &env,
            )?;
            if plaintext.len() != BRIDGE_CA_MODULE_KEY_LEN {
                return Err(BridgeCaLoadError::WrappingKeyLen(plaintext.len()));
            }
            let mut key = [0u8; BRIDGE_CA_MODULE_KEY_LEN];
            key.copy_from_slice(&plaintext);
            Zeroizing::new(key)
        } else if wrap_path.exists() {
            let blob = std::fs::read(&wrap_path)?;
            let env =
                SealedEnvelope::from_blob(&blob).map_err(|_| BridgeCaLoadError::MalformedBlob {
                    path: wrap_path.clone(),
                    len: blob.len(),
                })?;
            let plaintext = vault.open(
                crate::infra::vault::ValueClass::DaemonOperational,
                BRIDGE_CA_MODULE_KEY_AAD_ID,
                &env,
            )?;
            if plaintext.len() != BRIDGE_CA_MODULE_KEY_LEN {
                return Err(BridgeCaLoadError::WrappingKeyLen(plaintext.len()));
            }
            let mut key = [0u8; BRIDGE_CA_MODULE_KEY_LEN];
            key.copy_from_slice(&plaintext);
            Zeroizing::new(key)
        } else {
            let mut key = [0u8; BRIDGE_CA_MODULE_KEY_LEN];
            getrandom::fill(&mut key).expect("OS entropy failure");
            let env = vault.seal(
                crate::infra::vault::ValueClass::DaemonOperational,
                BRIDGE_CA_MODULE_KEY_AAD_ID,
                &key,
            )?;
            std::fs::write(&wrap_path, env.to_blob())?;
            Zeroizing::new(key)
        };

        let mut bridge_ca = if sealed_path.exists() {
            let blob = std::fs::read(&sealed_path)?;
            if blob.len() < SEALED_NONCE_LEN {
                return Err(BridgeCaLoadError::MalformedBlob {
                    path: sealed_path,
                    len: blob.len(),
                });
            }
            let (nonce, ct) = blob.split_at(SEALED_NONCE_LEN);
            BridgeCa::unseal_from_key(nonce, ct, module_key.as_slice())?
        } else {
            let ca = BridgeCa::mint();
            let (nonce, ct) = ca.seal_with_key(module_key.as_slice())?;
            let mut blob = Vec::with_capacity(nonce.len() + ct.len());
            blob.extend_from_slice(&nonce);
            blob.extend_from_slice(&ct);
            std::fs::write(&sealed_path, &blob)?;
            ca
        };

        std::fs::write(&pubkey_path, bridge_ca.verifying_key().to_bytes())?;
        let pem = bridge_ca.trust_root_cert_pem()?;
        std::fs::write(&pem_path, pem.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pubkey_path, std::fs::Permissions::from_mode(0o644))?;
            std::fs::set_permissions(&pem_path, std::fs::Permissions::from_mode(0o644))?;
        }

        bridge_ca.pubkey_path = pubkey_path;
        bridge_ca.sealed = true;
        Ok(bridge_ca)
    }

    /// Fingerprint accessor for Spawn Receipt embedding.
    /// Per the existing `ca_fingerprint` field in `core-receipts`.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Path to the on-disk pubkey file for operator visibility
    /// (operator can `cat <data_dir>/bridge_ca.pub`).
    pub fn pubkey_path(&self) -> &Path {
        &self.pubkey_path
    }

    // ── Lower-level crypto primitives ──

    /// Mint a fresh Bridge CA keypair from OS entropy.
    pub fn mint() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OS entropy failure");
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let fingerprint = compute_fingerprint(&key.verifying_key());
        Self {
            pubkey_path: PathBuf::new(),
            fingerprint,
            sealed: false,
            key,
        }
    }

    /// Public verifying key. Published to `<data_dir>/bridge_ca.pub` by
    /// `infra::runtime::load_or_mint_bridge_ca`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Seal the private-key bytes under a 32-byte wrapping key using
    /// XChaCha20-Poly1305. Returns `(nonce, ciphertext)`.
    ///
    /// Used by `BridgeCa::load_or_mint` to persist the private key under the
    /// module wrapping key.
    pub fn seal_with_key(&self, wrapping_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), BridgeCaError> {
        if wrapping_key.len() != 32 {
            return Err(BridgeCaError::InvalidWrappingKey(wrapping_key.len()));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
            .expect("wrapping_key length validated above");
        let mut nonce_bytes = [0u8; 24];
        getrandom::fill(&mut nonce_bytes).expect("OS entropy failure");
        let nonce = XNonce::from_slice(&nonce_bytes);
        let secret_bytes = Zeroizing::new(self.key.to_bytes());
        let ciphertext = cipher
            .encrypt(nonce, secret_bytes.as_slice())
            .map_err(|e| BridgeCaError::Aead(e.to_string()))?;
        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    /// Inverse of [`Self::seal_with_key`].
    ///
    /// Used by `BridgeCa::load_or_mint` to recover the persisted private key.
    pub fn unseal_from_key(
        nonce_bytes: &[u8],
        ciphertext: &[u8],
        wrapping_key: &[u8],
    ) -> Result<Self, BridgeCaError> {
        if wrapping_key.len() != 32 {
            return Err(BridgeCaError::InvalidWrappingKey(wrapping_key.len()));
        }
        if nonce_bytes.len() != 24 {
            return Err(BridgeCaError::MalformedSealed(format!(
                "invalid nonce length: {}",
                nonce_bytes.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key)
            .expect("wrapping_key length validated above");
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| BridgeCaError::Aead(e.to_string()))?,
        );
        if plaintext.len() != 32 {
            return Err(BridgeCaError::InvalidKeyMaterial);
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&plaintext);
        let key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();
        let fingerprint = compute_fingerprint(&key.verifying_key());
        Ok(Self {
            pubkey_path: PathBuf::new(),
            fingerprint,
            sealed: false,
            key,
        })
    }
}

/// Subject Alternative Name entry for [`BridgeCa::sign_server_cert`].
///
/// Mirrors the subset of `rcgen::SanType` we actually emit for the
/// ember-rpc sibling server cert: DNS hostnames + IP literals. URI SANs
/// (used elsewhere for SPIFFE identities) are intentionally not exposed
/// here; this primitive's job is server-side identity, not persona
/// identity.
#[derive(Debug, Clone)]
pub enum ServerSan {
    /// DNS hostname, e.g. `host.docker.internal` or `localhost`.
    Dns(String),
    /// IPv4 or IPv6 address literal, e.g. `127.0.0.1` or `::1`.
    Ip(IpAddr),
}

impl BridgeCa {
    /// Mint an ed25519 client keypair, build an X.509 leaf cert with the
    /// Ember client-auth SAN shape, sign it with this `BridgeCa`, and return
    /// `(cert_pem, key_pem)`.
    ///
    /// SAN policy mirrors the existing per-agent client-cert contract:
    /// - always emit `urn:emberlink:agent:<persona_id>` for one-release compat
    /// - when `container_id` is present, also emit:
    ///   - `spiffe://emberd/persona/<persona_id>`
    ///   - `spiffe://emberd/container/<container_id>`
    ///
    /// The validity window is anchored at the current wall clock, not the Unix
    /// epoch, so rustls handshake-time validity checks succeed in live use.
    pub fn sign_client_cert(
        &self,
        persona_id: &str,
        container_id: Option<&str>,
        ttl: std::time::Duration,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), BridgeCaError> {
        if persona_id.is_empty() {
            return Err(BridgeCaError::EmptySubject);
        }

        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| BridgeCaError::CertGen(format!("leaf keygen: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| BridgeCaError::CertGen(format!("params: {e}")))?;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(DnType::CommonName, format!("ember-persona-{persona_id}"));
            dn
        };

        let mut san_entries: Vec<SanType> = Vec::with_capacity(3);
        let urn = format!("urn:emberlink:agent:{persona_id}");
        let urn_ia5: rcgen::string::Ia5String = urn
            .as_str()
            .try_into()
            .map_err(|e: rcgen::Error| BridgeCaError::CertGen(format!("URN SAN: {e}")))?;
        san_entries.push(SanType::URI(urn_ia5));

        if let Some(container_id) = container_id {
            let persona_uri = format!("spiffe://emberd/persona/{persona_id}");
            let persona_ia5: rcgen::string::Ia5String =
                persona_uri.as_str().try_into().map_err(|e: rcgen::Error| {
                    BridgeCaError::CertGen(format!("persona SPIFFE SAN: {e}"))
                })?;
            san_entries.push(SanType::URI(persona_ia5));

            let container_uri = format!("spiffe://emberd/container/{container_id}");
            let container_ia5: rcgen::string::Ia5String = container_uri
                .as_str()
                .try_into()
                .map_err(|e: rcgen::Error| {
                    BridgeCaError::CertGen(format!("container SPIFFE SAN: {e}"))
                })?;
            san_entries.push(SanType::URI(container_ia5));
        }
        params.subject_alt_names = san_entries;

        let now = std::time::SystemTime::now();
        let not_before = time::OffsetDateTime::from(now);
        let not_after = time::OffsetDateTime::from(
            now.checked_add(ttl)
                .ok_or_else(|| BridgeCaError::CertGen("ttl overflow".to_string()))?,
        );
        params.not_before = not_before;
        params.not_after = not_after;

        let ca_key_pair = signing_key_to_rcgen_keypair(&self.key)?;
        let ca_cert = build_ca_cert_for_issuer(&ca_key_pair)?;
        let ca_cert_der_typed = CertificateDer::from(ca_cert.der().to_vec());
        let issuer = Issuer::from_ca_cert_der(&ca_cert_der_typed, ca_key_pair)
            .map_err(|e| BridgeCaError::CertGen(format!("issuer: {e}")))?;

        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| BridgeCaError::CertGen(format!("sign: {e}")))?;

        Ok((
            Zeroizing::new(cert.pem()),
            Zeroizing::new(leaf_key.serialize_pem()),
        ))
    }

    /// Mint an ed25519 server keypair, build an X.509 leaf cert with the
    /// supplied subject CN + SAN entries + TTL, sign it with this
    /// `BridgeCa`'s signing key, and return `(cert_pem, key_pem)`.
    ///
    /// The returned key PEM is wrapped in `Zeroizing` so it is wiped on
    /// drop; the caller is responsible for not leaving plaintext copies
    /// of the bytes around (e.g. write to disk + `Zeroizing` drops; do
    /// not hold an unzeroed `String::from(...)`).
    ///
    /// # Parameters
    ///
    /// - `subject` — CN string embedded in the leaf's distinguished name.
    ///   Must not be empty (operator-visible identifier in logs +
    ///   `openssl x509 -in server.crt -noout -subject` output).
    /// - `sans` — Subject Alternative Names. Must not be empty. mTLS
    ///   handshake validation requires the server hostname/IP to match
    ///   one of these entries; an empty list would produce a cert that
    ///   no client could validate.
    /// - `ttl` — validity duration from now. The cert's `not_before` is
    ///   the current wall-clock time; `not_after` is `now + ttl`. The
    ///   caller picks the TTL: ember-rpc's sibling cert uses 30 days
    ///   (operator-friendly, with daemon-boot rotation when `<24h` to
    ///   expiry).
    ///
    /// # What this DOES guarantee
    ///
    /// - The returned cert's signature is verifiable against this
    ///   `BridgeCa`'s `verifying_key()` (rcgen's signing math, not ours).
    /// - The cert carries `serverAuth` EKU.
    /// - The cert is not a CA (`IsCa::NoCa`).
    ///
    /// # What this does NOT enforce
    ///
    /// - SAN content shape — operator-supplied `Dns` strings are passed
    ///   through to rcgen verbatim. A malformed DNS label surfaces as
    ///   [`BridgeCaError::CertGen`] from rcgen.
    /// - TTL bounds — passing an absurd TTL produces a cert that still
    ///   validates cryptographically but trips handshake-time `not_after`
    ///   checks.
    /// - Wall-clock monotonicity — `not_before = SystemTime::now()` is
    ///   subject to clock skew. The 30-day ember-rpc TTL has a 24h
    ///   rotation slack precisely to absorb this.
    ///
    /// # Errors
    ///
    /// - [`BridgeCaError::EmptySubject`] — `subject` is empty.
    /// - [`BridgeCaError::EmptySanList`] — `sans` is empty.
    /// - [`BridgeCaError::CertGen`] — rcgen key generation, SAN encoding,
    ///   issuer construction, or signing failed.
    pub fn sign_server_cert(
        &self,
        subject: &str,
        sans: &[ServerSan],
        ttl: std::time::Duration,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>), BridgeCaError> {
        if subject.is_empty() {
            return Err(BridgeCaError::EmptySubject);
        }
        if sans.is_empty() {
            return Err(BridgeCaError::EmptySanList);
        }

        // Generate a fresh ed25519 leaf keypair via rcgen. We use rcgen's
        // KeyPair (not ed25519-dalek) on the leaf so the signing math
        // stays inside rcgen — same pattern as `core_crypto::x509::
        // mint_per_agent_client_cert`.
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| BridgeCaError::CertGen(format!("leaf keygen: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| BridgeCaError::CertGen(format!("params: {e}")))?;

        // Server leaf cert — not a CA, serverAuth EKU only.
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(DnType::CommonName, subject.to_string());
            dn
        };

        // Translate ServerSan → rcgen::SanType. DNS strings are passed
        // verbatim; rcgen validates them as Ia5String when serializing.
        let mut san_entries: Vec<SanType> = Vec::with_capacity(sans.len());
        for san in sans {
            match san {
                ServerSan::Dns(name) => {
                    let ia5: rcgen::string::Ia5String =
                        name.as_str().try_into().map_err(|e: rcgen::Error| {
                            BridgeCaError::CertGen(format!("DNS SAN {name:?}: {e}"))
                        })?;
                    san_entries.push(SanType::DnsName(ia5));
                }
                ServerSan::Ip(addr) => {
                    san_entries.push(SanType::IpAddress(*addr));
                }
            }
        }
        params.subject_alt_names = san_entries;

        // Validity window. `not_before = now`, `not_after = now + ttl`.
        // SystemTime is wall-clock and subject to skew — the 24h rotation
        // slack at the caller absorbs typical drift.
        let now = std::time::SystemTime::now();
        let not_before_offset = time::OffsetDateTime::from(now);
        let not_after = now
            .checked_add(ttl)
            .ok_or_else(|| BridgeCaError::CertGen("ttl overflow".to_string()))?;
        let not_after_offset = time::OffsetDateTime::from(not_after);
        params.not_before = not_before_offset;
        params.not_after = not_after_offset;

        // Build the CA Issuer from the BridgeCa signing key. We hand
        // rcgen the self-signed CA-cert-DER (built on-the-fly from the
        // ed25519 verifying key) plus a `KeyPair` re-derived from the
        // BridgeCa seed. The CA cert produced for the issuer side is
        // ephemeral and not persisted — it exists only as the
        // SubjectIssuer field for the leaf.
        let ca_key_pair = signing_key_to_rcgen_keypair(&self.key)?;
        let ca_cert = build_ca_cert_for_issuer(&ca_key_pair)?;
        let ca_cert_der_typed = CertificateDer::from(ca_cert.der().to_vec());
        let issuer = Issuer::from_ca_cert_der(&ca_cert_der_typed, ca_key_pair)
            .map_err(|e| BridgeCaError::CertGen(format!("issuer: {e}")))?;

        let cert = params
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| BridgeCaError::CertGen(format!("sign: {e}")))?;

        let cert_pem = Zeroizing::new(cert.pem());
        let key_pem = Zeroizing::new(leaf_key.serialize_pem());
        Ok((cert_pem, key_pem))
    }
}

/// Re-derive an rcgen `KeyPair` from a dalek `SigningKey`'s 32-byte seed.
///
/// Same pattern as `core_crypto::ca::signing_key_to_rcgen_keypair`. We
/// duplicate it here (rather than depend on `core_crypto` for one
/// helper) because this crate already pulls in `rcgen` directly for the
/// per-agent client-cert path and `core_crypto::ca` is not in
/// `ember-daemon`'s dep tree.
fn signing_key_to_rcgen_keypair(signing_key: &SigningKey) -> Result<KeyPair, BridgeCaError> {
    let seed = Zeroizing::new(signing_key.to_bytes());
    let pkcs8 = Zeroizing::new(seed_to_pkcs8_v1_der(&seed));
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &PKCS_ED25519,
    )
    .map_err(|e| BridgeCaError::CertGen(format!("ed25519 pkcs8: {e}")))?;
    Ok(kp)
}

/// Encode a 32-byte ed25519 seed as a PKCS#8 v1 DER document.
///
/// Mirrors `core_crypto::ca::seed_to_pkcs8_v1_der`. See that file for the
/// ASN.1 structure breakdown; the bytes here are verbatim.
fn seed_to_pkcs8_v1_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(seed);
    der
}

/// Build the self-signed CA-side certificate the leaf-cert Issuer wraps.
///
/// rcgen requires an `Issuer` to be constructed from a CA-cert + signing
/// key pair. The same self-signed cert also backs the published
/// `bridge_ca.pem` trust root that rustls clients load. The raw
/// `bridge_ca.pub` file remains the fingerprint/cache artifact.
fn build_ca_cert_for_issuer(ca_key: &KeyPair) -> Result<rcgen::Certificate, BridgeCaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| BridgeCaError::CertGen(format!("ca params: {e}")))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "emberd bridge CA");
        dn
    };
    // Wide validity window — this cert is never persisted and is only
    // used as the leaf's issuer field. The leaf's own not_before /
    // not_after are what matters at handshake time.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    params
        .self_signed(ca_key)
        .map_err(|e| BridgeCaError::CertGen(format!("ca self_signed: {e}")))
}

impl BridgeCa {
    /// PEM-encoded self-signed root cert suitable for rustls trust stores.
    ///
    /// The runtime publishes this as `<data_dir>/bridge_ca.pem` alongside the
    /// raw `bridge_ca.pub` fingerprint cache so bridge consumers can use the
    /// standard PEM-loading path without losing the 32-byte raw-key contract.
    pub fn trust_root_cert_pem(&self) -> Result<Zeroizing<String>, BridgeCaError> {
        let ca_key_pair = signing_key_to_rcgen_keypair(&self.key)?;
        let ca_cert = build_ca_cert_for_issuer(&ca_key_pair)?;
        Ok(Zeroizing::new(ca_cert.pem()))
    }
}

/// blake3-256 of the verifying key bytes.
fn compute_fingerprint(vk: &VerifyingKey) -> [u8; 32] {
    *blake3::hash(vk.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    //! T2: bridge CA unit tests use temporary data directories.

    use super::*;
    use tempfile::TempDir;

    const TEST_VAULT_KEY: [u8; 32] = [0x42u8; 32];

    /// Pre: empty data_dir. Post: bridge_ca public artifacts exist and the
    /// returned BridgeCa reflects the published path/state.
    #[test]
    fn load_or_mint_publishes_pubkey_file() {
        let dir = TempDir::new().expect("tempdir");
        let vault = Vault::new(TEST_VAULT_KEY);
        let ca = BridgeCa::load_or_mint(dir.path(), &vault).expect("load_or_mint succeeds");
        assert!(
            ca.pubkey_path().exists(),
            "pubkey file must exist after load_or_mint"
        );
        assert!(
            dir.path().join("bridge_ca.pem").exists(),
            "PEM root must exist"
        );
        assert!(ca.sealed, "returned BridgeCa must reflect persisted state");
    }

    /// Pre: data_dir. Post: pubkey_path is data_dir/bridge_ca.pub.
    #[test]
    fn pubkey_path_returns_join_with_data_dir() {
        let dir = TempDir::new().expect("tempdir");
        let vault = Vault::new(TEST_VAULT_KEY);
        let ca = BridgeCa::load_or_mint(dir.path(), &vault).expect("load_or_mint succeeds");
        let expected = dir.path().join("bridge_ca.pub");
        assert_eq!(ca.pubkey_path(), expected.as_path());
    }

    /// Pre: any load_or_mint. Post: fingerprint() returns exactly 32 bytes.
    #[test]
    fn fingerprint_is_32_bytes() {
        let dir = TempDir::new().expect("tempdir");
        let vault = Vault::new(TEST_VAULT_KEY);
        let ca = BridgeCa::load_or_mint(dir.path(), &vault).expect("load_or_mint succeeds");
        let fp = ca.fingerprint();
        assert_eq!(fp.len(), 32);
    }

    /// Pre: helper called twice with the same data_dir + vault. Post: the
    /// Bridge CA fingerprint is stable across restart.
    #[test]
    fn load_or_mint_preserves_fingerprint_across_restart() {
        let dir = TempDir::new().expect("tempdir");
        let vault = Vault::new(TEST_VAULT_KEY);
        let ca1 = BridgeCa::load_or_mint(dir.path(), &vault).expect("first load_or_mint");
        let fingerprint = ca1.fingerprint();
        drop(ca1);

        let ca2 = BridgeCa::load_or_mint(dir.path(), &vault).expect("restart load_or_mint");
        assert_eq!(ca2.fingerprint(), fingerprint);
    }

    /// ADR 198 Part B — the module wrapping key is enveloped: a different
    /// MEK cannot open the persisted `bridge_ca.wrap` blob. Proves the MEK no
    /// longer directly encrypts the module key (the DEK does), and that the
    /// wrap is bound to the Interactive MEK via the AEAD tag.
    #[test]
    fn wrap_blob_undecryptable_under_wrong_mek() {
        let dir = TempDir::new().expect("tempdir");
        let vault = Vault::new(TEST_VAULT_KEY);
        let _ca = BridgeCa::load_or_mint(dir.path(), &vault).expect("mint under correct mek");

        // The on-disk wrap blob parses as a SealedEnvelope (enveloped, not a
        // bare [nonce||ct] direct-MEK blob).
        let blob = std::fs::read(dir.path().join("bridge_ca.wrap")).unwrap();
        let env = SealedEnvelope::from_blob(&blob).expect("wrap blob is a sealed envelope");

        // A different MEK cannot open it.
        let wrong = Vault::new([0x11u8; 32]);
        let err = wrong
            .open(
                crate::infra::vault::ValueClass::DaemonOperational,
                BRIDGE_CA_MODULE_KEY_AAD_ID,
                &env,
            )
            .expect_err("wrong mek must fail to open the wrap blob");
        assert!(matches!(err, VaultError::Crypto(_)));

        // The correct MEK opens it and recovers a 32-byte module key.
        let key = vault
            .open(
                crate::infra::vault::ValueClass::DaemonOperational,
                BRIDGE_CA_MODULE_KEY_AAD_ID,
                &env,
            )
            .expect("correct mek opens the wrap blob");
        assert_eq!(key.len(), BRIDGE_CA_MODULE_KEY_LEN);
    }

    // ─── sign_server_cert (ARCH-EMBER-RPC-PHASE-C-SIBLING-CERT-MINT T2) ───

    /// Pre: minted BridgeCa, valid subject + SANs + TTL.
    /// Post: returned PEMs parse; leaf cert validates against the BridgeCa's
    /// signing key; SAN matches expected entries.
    #[test]
    fn sign_server_cert_minted_validates_against_bridge_ca() {
        use std::time::Duration;
        use x509_parser::prelude::*;

        let ca = BridgeCa::mint();
        let sans = vec![
            ServerSan::Dns("host.docker.internal".to_string()),
            ServerSan::Dns("localhost".to_string()),
            ServerSan::Ip("127.0.0.1".parse().unwrap()),
        ];
        let (cert_pem, key_pem) = ca
            .sign_server_cert("ember-rpc", &sans, Duration::from_secs(30 * 24 * 3600))
            .expect("sign_server_cert succeeds");

        // PEM parses + DER decodes.
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).expect("PEM parses");
        let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("DER parses");

        // Subject CN matches.
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .expect("CN present")
            .as_str()
            .expect("CN is utf8");
        assert_eq!(cn, "ember-rpc");

        // SANs include all three entries.
        let san_ext = parsed
            .subject_alternative_name()
            .expect("SAN parses")
            .expect("SAN present");
        let names: Vec<String> = san_ext
            .value
            .general_names
            .iter()
            .map(|gn| format!("{:?}", gn))
            .collect();
        let joined = names.join(",");
        assert!(
            joined.contains("host.docker.internal"),
            "DNS SAN host.docker.internal: {joined}"
        );
        assert!(joined.contains("localhost"), "DNS SAN localhost: {joined}");
        // x509-parser renders IPv4 SANs as the raw octet array, not dotted-quad.
        assert!(
            joined.contains("[127, 0, 0, 1]"),
            "IP SAN 127.0.0.1 (rendered as [127, 0, 0, 1]): {joined}"
        );

        // Signature verifies against BridgeCa's verifying key. Use
        // ed25519-dalek (already a direct dep) rather than ring so the
        // test compiles without expanding the dep graph.
        let vk = ca.verifying_key();
        let tbs = parsed.tbs_certificate.as_ref();
        let sig_bytes = parsed.signature_value.as_ref();
        let sig = ed25519_dalek::Signature::try_from(sig_bytes)
            .expect("signature bytes decode as ed25519::Signature");
        ed25519_dalek::Verifier::verify(&vk, tbs, &sig)
            .expect("BridgeCa verifying key validates leaf sig");

        // Key PEM parses as an Ed25519 PKCS#8 document.
        let (_, key_pem_parsed) = parse_x509_pem(key_pem.as_bytes()).expect("key PEM parses");
        assert!(
            !key_pem_parsed.contents.is_empty(),
            "key PEM has DER contents"
        );

        // EKU is serverAuth (not clientAuth).
        let eku = parsed
            .extended_key_usage()
            .expect("EKU parses")
            .expect("EKU present");
        assert!(eku.value.server_auth, "serverAuth EKU set");
        assert!(!eku.value.client_auth, "clientAuth NOT set");
    }

    /// SCION-209 #2 — a client cert minted WITH a container_id carries both
    /// the persona and container SPIFFE SANs (the container's mTLS identity per
    /// ADR 209 §2). WITHOUT a container_id only the compat URN is emitted (no
    /// SPIFFE leakage). This pins the identity binding the orchestrator relies
    /// on so the daemon's `extract_agent_id_from_cert` can cross-check
    /// persona↔container.
    #[test]
    fn sign_client_cert_emits_persona_and_container_spiffe_sans() {
        use std::time::Duration;
        use x509_parser::prelude::*;

        let ca = BridgeCa::mint();
        let (cert_pem, _key) = ca
            .sign_client_cert("alice", Some("ctr-abc123"), Duration::from_secs(3600))
            .expect("sign with container_id");
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).expect("PEM parses");
        let (_, parsed) = X509Certificate::from_der(&pem.contents).expect("DER parses");
        let san = parsed
            .subject_alternative_name()
            .expect("SAN parses")
            .expect("SAN present");
        let joined = san
            .value
            .general_names
            .iter()
            .map(|gn| format!("{gn:?}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            joined.contains("spiffe://emberd/persona/alice"),
            "persona SPIFFE SAN: {joined}"
        );
        assert!(
            joined.contains("spiffe://emberd/container/ctr-abc123"),
            "container SPIFFE SAN: {joined}"
        );

        // Without a container_id: compat URN only, no SPIFFE SANs.
        let (cert_pem2, _key2) = ca
            .sign_client_cert("alice", None, Duration::from_secs(3600))
            .expect("sign without container_id");
        let (_, pem2) = parse_x509_pem(cert_pem2.as_bytes()).expect("PEM parses");
        let (_, parsed2) = X509Certificate::from_der(&pem2.contents).expect("DER parses");
        let joined2 = parsed2
            .subject_alternative_name()
            .expect("SAN parses")
            .expect("SAN present")
            .value
            .general_names
            .iter()
            .map(|gn| format!("{gn:?}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            joined2.contains("urn:emberlink:agent:alice"),
            "compat URN SAN: {joined2}"
        );
        assert!(
            !joined2.contains("spiffe://"),
            "no SPIFFE SAN without container_id: {joined2}"
        );
    }

    /// Pre: empty subject string. Post: EmptySubject error.
    #[test]
    fn sign_server_cert_rejects_empty_subject() {
        use std::time::Duration;
        let ca = BridgeCa::mint();
        let sans = vec![ServerSan::Dns("localhost".to_string())];
        let err = ca
            .sign_server_cert("", &sans, Duration::from_secs(3600))
            .expect_err("empty subject must fail");
        assert!(matches!(err, BridgeCaError::EmptySubject));
    }

    /// Pre: empty SAN list. Post: EmptySanList error.
    #[test]
    fn sign_server_cert_rejects_empty_sans() {
        use std::time::Duration;
        let ca = BridgeCa::mint();
        let err = ca
            .sign_server_cert("ember-rpc", &[], Duration::from_secs(3600))
            .expect_err("empty SAN list must fail");
        assert!(matches!(err, BridgeCaError::EmptySanList));
    }
}
