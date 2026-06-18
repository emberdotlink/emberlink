//! ADR 200 §2 / §5 — event-sourced identity substrate for the daemon.
//!
//! Until now the daemon persisted identity in a legacy `personas` SQLite table
//! with no event-sourcing (no `RootCreated`/`PersonaCreated` emission, no
//! `EventStore`). ADR 200 re-anchors identity on an event-sourced, externally
//! re-verifiable log: `core_state::EventStore` is the canonical store of
//! `roots_current` / `personas_current` / `devices_current`, materialized from a
//! signed, append-only event log. This module stands that substrate up inside
//! the daemon and event-sources the daemon's *own* identity.
//!
//! ## What PR2 establishes (this module)
//! - A persistent `core_state::EventStore` opened at `<data_dir>/identity-events.db`.
//! - The daemon's **self-root** (`RootCreated`) — `root_id` derived from the daemon
//!   pubkey so it is distinct from the operator's IdentityRoot (§2: "the daemon did
//!   X" and "the operator authorized X" must never be confusable).
//! - The **Daemon Persona** (`PersonaCreated`) — a Durable Persona under the
//!   self-root, signing on the daemon key.
//!
//! Both genesis events are **self-signed** by the daemon's Ed25519 key (the daemon
//! holds its own key because it *is* the daemon-class Device, §1). Verification of
//! a `Root`-role event checks `envelope.signer == root.initial_key`, which holds
//! by construction here.
//!
//! ## What later S3 PRs add against this same store
//! - PR3: the device-rooted **operator** IdentityRoot + operator Durable Persona
//!   (no `seal_persona_secret`), plus cutting agent/runtime persona creation onto
//!   this substrate (enrolled on the daemon-Device).
//! - PR4: presence-`Device` enrollment (`DeviceEnrolled`, attested) bound via
//!   `persona_device_access`.
//! - PR5: dispatch reads the enrolled presence-device pubkey from `devices_current`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use core_crypto::{
    DeviceSignatureVerifier, LocalKeyPair, LocalKeySigner, Signer,
    derive_emberseal_x25519_recipient,
};
use core_event_types::{
    DeviceAddedEvent, EventBody, PersonaCreatedEvent, RootCreatedEvent, SignerBinding,
};
use core_events::EventEnvelope;
use core_principals::{KeyAlgorithm, PublicKeyMaterial, SurvivalMode};
use core_state::{EventStore, IdentityAuthorizer};

use crate::infra::receipt::DaemonPersona;

/// Filename of the daemon's identity event log (separate SQLite db from the
/// legacy daemon store; the legacy `personas` table is superseded by this
/// substrate over the course of S3, per ADR 200's clean-break directive).
pub const IDENTITY_DB_FILENAME: &str = "identity-events.db";

/// Stable identifiers for the daemon's event-sourced identity, derived
/// deterministically from the daemon pubkey so genesis is **idempotent** across
/// restarts (re-running bootstrap recomputes the same ids and the materialized
/// root is detected as already-present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIdentityIds {
    pub root_id: String,
    pub persona_id: String,
    pub device_id: String,
    pub key_id: String,
}

impl DaemonIdentityIds {
    /// Derive the daemon identity ids from the **full** Ed25519 pubkey hex
    /// (256-bit). The pubkey is the real trust anchor (it is what an external
    /// verifier checks signatures against), so the id binds the full pubkey —
    /// no truncation. This makes a daemon-root id collision require a full
    /// Ed25519 pubkey collision, and keeps the daemon root structurally
    /// distinct from the operator root (ADR 200 §2), which is derived from a
    /// different key in PR3.
    fn derive(pubkey_hex: &str) -> Self {
        Self {
            root_id: format!("root-daemon-{pubkey_hex}"),
            persona_id: format!("persona-daemon-{pubkey_hex}"),
            device_id: daemon_signing_device_id(pubkey_hex),
            key_id: format!("key-daemon-{pubkey_hex}"),
        }
    }
}

/// Receipt/intent signer attribution after ADR 200's Principal unification.
/// `principal_id` identifies the signer in the recursive Principal tree;
/// `signing_device_id` identifies the concrete Device key that made the
/// signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningAttribution {
    pub principal_id: String,
    pub signing_device_id: String,
}

/// Minimal recursive Principal row used by daemon signing gates.
///
/// The event log still carries compatibility `RootCreated`/`PersonaCreated`
/// events. Signing decisions use this normalized view so the daemon can reject
/// missing, cyclic, or wrong-anchor parent chains before attributing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPrincipalRecord {
    pub principal_id: String,
    pub parent_id: String,
    pub signing_device_id: Option<String>,
}

impl SigningPrincipalRecord {
    pub fn signing_attribution(&self) -> Result<SigningAttribution, PrincipalChainError> {
        let signing_device_id = self.signing_device_id.clone().ok_or_else(|| {
            PrincipalChainError::MissingSigningDevice {
                principal_id: self.principal_id.clone(),
            }
        })?;
        Ok(SigningAttribution {
            principal_id: self.principal_id.clone(),
            signing_device_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalChainError {
    MissingPrincipal {
        principal_id: String,
    },
    MissingParent {
        principal_id: String,
        parent_id: String,
    },
    Cycle {
        principal_id: String,
    },
    WrongAnchor {
        principal_id: String,
        expected_anchor_id: String,
    },
    MissingSigningDevice {
        principal_id: String,
    },
}

impl std::fmt::Display for PrincipalChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPrincipal { principal_id } => {
                write!(f, "principal not found: {principal_id}")
            }
            Self::MissingParent {
                principal_id,
                parent_id,
            } => write!(
                f,
                "principal {principal_id} references missing parent {parent_id}"
            ),
            Self::Cycle { principal_id } => {
                write!(f, "principal parent chain cycles at {principal_id}")
            }
            Self::WrongAnchor {
                principal_id,
                expected_anchor_id,
            } => write!(
                f,
                "principal chain anchored at {principal_id}, expected {expected_anchor_id}"
            ),
            Self::MissingSigningDevice { principal_id } => {
                write!(f, "principal {principal_id} has no signing_device_id")
            }
        }
    }
}

impl std::error::Error for PrincipalChainError {}

pub fn daemon_signing_device_id(pubkey_hex: &str) -> String {
    format!("device-daemon-{pubkey_hex}")
}

pub fn daemon_principal_record(pubkey_hex: &str) -> SigningPrincipalRecord {
    SigningPrincipalRecord {
        principal_id: pubkey_hex.to_string(),
        parent_id: pubkey_hex.to_string(),
        signing_device_id: Some(daemon_signing_device_id(pubkey_hex)),
    }
}

pub fn daemon_signing_attribution(pubkey_hex: &str) -> SigningAttribution {
    SigningAttribution {
        principal_id: pubkey_hex.to_string(),
        signing_device_id: daemon_signing_device_id(pubkey_hex),
    }
}

pub fn validate_principal_parent_chain(
    records: &[SigningPrincipalRecord],
    principal_id: &str,
    trust_anchor_id: &str,
) -> Result<(), PrincipalChainError> {
    let by_id: BTreeMap<&str, &SigningPrincipalRecord> = records
        .iter()
        .map(|record| (record.principal_id.as_str(), record))
        .collect();
    let mut seen = BTreeSet::new();
    let mut current = principal_id;

    loop {
        let record = by_id
            .get(current)
            .ok_or_else(|| PrincipalChainError::MissingPrincipal {
                principal_id: current.to_string(),
            })?;
        if !seen.insert(current.to_string()) {
            return Err(PrincipalChainError::Cycle {
                principal_id: current.to_string(),
            });
        }
        if record.parent_id == record.principal_id {
            if record.principal_id == trust_anchor_id {
                return Ok(());
            }
            return Err(PrincipalChainError::WrongAnchor {
                principal_id: record.principal_id.clone(),
                expected_anchor_id: trust_anchor_id.to_string(),
            });
        }
        if !by_id.contains_key(record.parent_id.as_str()) {
            return Err(PrincipalChainError::MissingParent {
                principal_id: record.principal_id.clone(),
                parent_id: record.parent_id.clone(),
            });
        }
        current = record.parent_id.as_str();
    }
}

/// Errors standing up or bootstrapping the identity substrate. Kept distinct
/// from `StoreError` so callers can tell substrate-genesis failures apart from
/// legacy-store failures during the S3 cutover.
#[derive(Debug)]
pub enum IdentitySubstrateError {
    /// Opening / initializing the `core_state::EventStore` failed.
    Open(String),
    /// Constructing the daemon's `LocalKeySigner` from its seed failed.
    Signer(String),
    /// Building or appending a genesis event failed.
    Genesis(String),
}

impl std::fmt::Display for IdentitySubstrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(m) => write!(f, "open identity substrate: {m}"),
            Self::Signer(m) => write!(f, "build daemon signer: {m}"),
            Self::Genesis(m) => write!(f, "daemon identity genesis: {m}"),
        }
    }
}

impl std::error::Error for IdentitySubstrateError {}

/// Build a `core_crypto::LocalKeyPair` from the daemon's Ed25519 identity key.
///
/// The daemon holds this key because it *is* the daemon-class Device (ADR 200
/// §1). The resulting key pair drives a `LocalKeySigner` that self-signs the
/// daemon's genesis events. The seed never leaves this function's stack beyond
/// the returned (zeroizing) `LocalKeyPair`.
fn daemon_local_key_pair(persona: &DaemonPersona, key_id: &str) -> LocalKeyPair {
    let seed = persona.seed_bytes();
    // `hex::encode` returns a plain `String` holding the secret seed hex; wrap
    // it in `Zeroizing` so that intermediate is scrubbed on drop. The borrow
    // `&seed[..]` (not `*seed`) avoids copying the seed out of its wrapper. The
    // final `private_key` lands in `LocalKeyPair`, which is `ZeroizeOnDrop`.
    let secret_hex = zeroize::Zeroizing::new(hex::encode(&seed[..]));
    LocalKeyPair {
        key_id: key_id.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        // `ed25519:` / `ed25519-secret:` are core-crypto's wire prefixes; the
        // public half must equal what core-crypto re-derives from the secret or
        // `from_local_key_pair` rejects the pair (mismatch guard).
        public_key: format!("ed25519:{}", persona.pubkey_hex()),
        private_key: format!("ed25519-secret:{}", secret_hex.as_str()),
    }
}

/// The daemon's public key as `PublicKeyMaterial`, used as the `initial_key` of
/// both the self-root and the Daemon Persona (self-rooting: the root's key and
/// the signing key are the same daemon key).
fn daemon_public_key_material(persona: &DaemonPersona, key_id: &str) -> PublicKeyMaterial {
    PublicKeyMaterial {
        key_id: key_id.to_string(),
        algorithm: KeyAlgorithm::Ed25519,
        public_key: format!("ed25519:{}", persona.pubkey_hex()),
    }
}

fn daemon_encryption_key_material(persona: &DaemonPersona, key_id: &str) -> PublicKeyMaterial {
    let seed = persona.seed_bytes();
    PublicKeyMaterial {
        key_id: format!("{key_id}-x25519"),
        algorithm: KeyAlgorithm::AgeX25519,
        public_key: derive_emberseal_x25519_recipient(&seed[..]),
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Open the daemon's identity `EventStore` at `<data_dir>/identity-events.db`,
/// rebuilding materialized state from the persisted log.
pub fn open_identity_store(data_dir: &Path) -> Result<EventStore, IdentitySubstrateError> {
    let path = data_dir.join(IDENTITY_DB_FILENAME);
    EventStore::open(&path).map_err(|e| IdentitySubstrateError::Open(e.to_string()))
}

/// Ensure the daemon's self-root + Daemon Persona exist in the identity
/// substrate, emitting the genesis events on first run. **Idempotent**: if the
/// self-root is already materialized (restart, or a prior bootstrap), this is a
/// no-op and returns the existing ids.
///
/// Returns the daemon identity ids regardless of whether genesis ran, so callers
/// can wire the daemon principal without branching on first-run.
pub fn ensure_daemon_identity(
    store: &mut EventStore,
    persona: &DaemonPersona,
) -> Result<DaemonIdentityIds, IdentitySubstrateError> {
    let pubkey_hex = persona.pubkey_hex();
    let ids = DaemonIdentityIds::derive(&pubkey_hex);

    // Per-event idempotency: genesis emits TWO events (root, then persona) in
    // separate SQLite transactions. A crash *between* them would leave the root
    // committed but the persona missing. Guarding on the root alone would then
    // skip genesis forever, stranding the daemon without its persona. So we
    // check each independently and (re-)append only what is missing — this both
    // no-ops a fully-bootstrapped daemon and *repairs* a half-bootstrapped one.
    let root_missing = store.materialized().root(&ids.root_id).is_none();
    let persona_missing = store.materialized().persona(&ids.persona_id).is_none();
    let device_missing = store
        .materialized()
        .devices_current
        .get(&ids.device_id)
        .is_none();
    if !root_missing && !persona_missing && !device_missing {
        return Ok(ids);
    }

    let key_pair = daemon_local_key_pair(persona, &ids.key_id);
    let signer = LocalKeySigner::from_local_key_pair(&key_pair)
        .map_err(|e| IdentitySubstrateError::Signer(e.to_string()))?;
    let key_material = daemon_public_key_material(persona, &ids.key_id);
    let encryption_key_material = daemon_encryption_key_material(persona, &ids.key_id);

    // Self-root invariant (ADR 200 §2 / verify_chain): a Root-role event is
    // accepted by an external verifier only if `envelope.signer == initial_key`.
    // True by construction here (both from the same daemon seed); enforce it at
    // runtime so a future refactor that decouples them fails closed instead of
    // shipping a genesis no external verifier would accept.
    if signer.public_key().0 != key_material.public_key {
        return Err(IdentitySubstrateError::Genesis(
            "self-root signer key does not match initial_key (would fail external verify)"
                .to_string(),
        ));
    }
    let now = now_epoch_secs();

    // 1) Self-root. `root_id` binds the full daemon pubkey so it can never
    //    collide with the operator's IdentityRoot — keeping daemon-attributable
    //    and operator-authorized actions structurally distinguishable (§2).
    if root_missing {
        append_root_signed(
            store,
            &signer,
            &ids,
            EventBody::RootCreated(RootCreatedEvent {
                root_id: ids.root_id.clone(),
                display_name: "Emberlink Daemon".to_string(),
                initial_key: key_material.clone(),
            }),
            &format!("{}/genesis", ids.root_id),
            now,
        )?;
    }

    // 2) Daemon Persona — a Durable Persona under the self-root, signing on the
    //    daemon key. "Admin/operator/agent" are attributes, not types (§2); this
    //    is just the principal the daemon acts as for its own lifecycle receipts.
    if persona_missing {
        append_root_signed(
            store,
            &signer,
            &ids,
            EventBody::PersonaCreated(PersonaCreatedEvent {
                root_id: ids.root_id.clone(),
                persona_id: ids.persona_id.clone(),
                label: "Daemon Persona".to_string(),
                disclosure_profile: None,
                survival_mode: SurvivalMode::Strict,
                initial_key: key_material.clone(),
            }),
            &format!("{}/persona", ids.root_id),
            now,
        )?;
    }

    // 3) Daemon Device — the concrete unattended Device whose key makes daemon
    //    signatures. This is the persisted counterpart of `signing_device_id`.
    if device_missing {
        append_root_signed(
            store,
            &signer,
            &ids,
            EventBody::DeviceAdded(DeviceAddedEvent {
                root_id: ids.root_id.clone(),
                device_id: ids.device_id.clone(),
                label: "Daemon Device".to_string(),
                initial_key: key_material,
                initial_encryption_key: encryption_key_material,
            }),
            &format!("{}/device", ids.root_id),
            now,
        )?;
    }

    Ok(ids)
}

/// Append a root-signed identity event (empty refs, `SignerBinding::root`),
/// verified with the real Ed25519 verifier under the `IdentityAuthorizer`.
fn append_root_signed(
    store: &mut EventStore,
    signer: &LocalKeySigner,
    ids: &DaemonIdentityIds,
    body: EventBody,
    event_id: &str,
    now: u64,
) -> Result<(), IdentitySubstrateError> {
    let envelope = EventEnvelope::from_body(
        event_id,
        body,
        Vec::new(),
        SignerBinding::root(ids.root_id.clone(), ids.key_id.clone()),
        signer,
    )
    .map_err(|e| IdentitySubstrateError::Genesis(e.to_string()))?;

    store
        .append_with_authorizer(envelope, &DeviceSignatureVerifier, &IdentityAuthorizer, now)
        .map_err(|e| IdentitySubstrateError::Genesis(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_persona(dir: &Path) -> DaemonPersona {
        DaemonPersona::load_or_create(dir).expect("load_or_create daemon persona")
    }

    #[test]
    fn genesis_materializes_self_root_and_daemon_persona() {
        let dir = TempDir::new().unwrap();
        let persona = test_persona(dir.path());
        let mut store = open_identity_store(dir.path()).unwrap();

        let ids = ensure_daemon_identity(&mut store, &persona).unwrap();

        let root = store
            .materialized()
            .root(&ids.root_id)
            .expect("self-root materialized");
        let pid = store
            .materialized()
            .persona(&ids.persona_id)
            .expect("daemon persona materialized");
        let device = store
            .materialized()
            .devices_current
            .get(&ids.device_id)
            .expect("daemon device materialized");

        // Self-rooting: the persona is under the self-root, and the root's key
        // is the daemon key (so the genesis self-signature verifies).
        assert_eq!(root.root_id, ids.root_id);
        assert_eq!(pid.root_id, ids.root_id);
        // Self-rooted: the materialized root key carries the daemon pubkey.
        assert_eq!(
            root.active_key.public_key,
            format!("ed25519:{}", persona.pubkey_hex())
        );
        assert_eq!(root.active_key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(device.root_id, ids.root_id);
        assert_eq!(device.active_key.public_key, root.active_key.public_key);
        assert_eq!(device.active_key.algorithm, KeyAlgorithm::Ed25519);
    }

    #[test]
    fn daemon_persona_is_self_parented_principal() {
        let pubkey_hex = "daemon-principal-pubkey";
        let principal = daemon_principal_record(pubkey_hex);
        let checkpoint = "identity_root_persona_daemon_signing_paths_landed";

        assert_eq!(principal.principal_id, pubkey_hex);
        assert_eq!(principal.parent_id, principal.principal_id);
        assert_eq!(
            principal.signing_device_id.as_deref(),
            Some("device-daemon-daemon-principal-pubkey")
        );
        validate_principal_parent_chain(
            std::slice::from_ref(&principal),
            &principal.principal_id,
            &principal.principal_id,
        )
        .unwrap();
        assert_eq!(
            checkpoint,
            "identity_root_persona_daemon_signing_paths_landed"
        );
    }

    #[test]
    fn ensure_is_idempotent_across_calls_and_reopen() {
        let dir = TempDir::new().unwrap();
        let persona = test_persona(dir.path());

        let ids1 = {
            let mut store = open_identity_store(dir.path()).unwrap();
            let ids = ensure_daemon_identity(&mut store, &persona).unwrap();
            // Second call on the same store is a no-op.
            let again = ensure_daemon_identity(&mut store, &persona).unwrap();
            assert_eq!(ids, again);
            assert_eq!(store.materialized().personas_current.len(), 1);
            assert_eq!(store.materialized().devices_current.len(), 1);
            ids
        };

        // Reopen from disk: genesis must NOT be re-emitted (the persisted log
        // rebuilds the materialized self-root, which the guard detects).
        let mut store = open_identity_store(dir.path()).unwrap();
        let ids2 = ensure_daemon_identity(&mut store, &persona).unwrap();
        assert_eq!(ids1, ids2);
        assert_eq!(store.materialized().roots_current.len(), 1);
        assert_eq!(store.materialized().personas_current.len(), 1);
        assert_eq!(store.materialized().devices_current.len(), 1);
    }

    #[test]
    fn half_bootstrap_is_repaired_not_stranded() {
        // Simulate a crash between the root append and the persona append: a
        // store that has the self-root but NOT the Daemon Persona. A guard that
        // checked only the root would skip genesis forever; ensure_daemon_identity
        // must instead append the missing persona.
        let dir = TempDir::new().unwrap();
        let persona = test_persona(dir.path());
        let ids = DaemonIdentityIds::derive(&persona.pubkey_hex());

        // Build a store with ONLY the root event appended (root_missing=false,
        // persona_missing=true on the next call).
        {
            let mut store = open_identity_store(dir.path()).unwrap();
            let key_pair = daemon_local_key_pair(&persona, &ids.key_id);
            let signer = LocalKeySigner::from_local_key_pair(&key_pair).unwrap();
            let key_material = daemon_public_key_material(&persona, &ids.key_id);
            append_root_signed(
                &mut store,
                &signer,
                &ids,
                EventBody::RootCreated(RootCreatedEvent {
                    root_id: ids.root_id.clone(),
                    display_name: "Emberlink Daemon".to_string(),
                    initial_key: key_material,
                }),
                &format!("{}/genesis", ids.root_id),
                now_epoch_secs(),
            )
            .unwrap();
            assert!(store.materialized().root(&ids.root_id).is_some());
            assert!(store.materialized().persona(&ids.persona_id).is_none());
        }

        // Reopen and run ensure: it must repair (append the missing persona).
        let mut store = open_identity_store(dir.path()).unwrap();
        assert!(store.materialized().root(&ids.root_id).is_some());
        assert!(store.materialized().persona(&ids.persona_id).is_none());
        assert!(
            store
                .materialized()
                .devices_current
                .get(&ids.device_id)
                .is_none()
        );
        ensure_daemon_identity(&mut store, &persona).unwrap();
        assert!(
            store.materialized().persona(&ids.persona_id).is_some(),
            "half-bootstrap must be repaired: Daemon Persona created on next ensure"
        );
        assert!(
            store
                .materialized()
                .devices_current
                .get(&ids.device_id)
                .is_some(),
            "half-bootstrap must be repaired: daemon Device created on next ensure"
        );
        assert_eq!(store.materialized().roots_current.len(), 1);
        assert_eq!(store.materialized().personas_current.len(), 1);
        assert_eq!(store.materialized().devices_current.len(), 1);
    }

    #[test]
    fn daemon_root_id_is_pubkey_derived_and_distinct_from_operator() {
        // Two different daemon keys → two different self-root ids. (Sanity that
        // the operator root, derived from a *different* key in PR3, can never
        // collide with the daemon self-root.)
        let dir_a = TempDir::new().unwrap();
        let dir_b = TempDir::new().unwrap();
        let a = DaemonIdentityIds::derive(&test_persona(dir_a.path()).pubkey_hex());
        let b = DaemonIdentityIds::derive(&test_persona(dir_b.path()).pubkey_hex());
        assert_ne!(a.root_id, b.root_id);
    }

    #[test]
    fn signing_rejects_principal_parent_cycle() {
        let a = SigningPrincipalRecord {
            principal_id: "principal-a".to_string(),
            parent_id: "principal-b".to_string(),
            signing_device_id: Some("device-a".to_string()),
        };
        let b = SigningPrincipalRecord {
            principal_id: "principal-b".to_string(),
            parent_id: "principal-a".to_string(),
            signing_device_id: Some("device-b".to_string()),
        };

        let err = validate_principal_parent_chain(&[a, b], "principal-a", "principal-a")
            .expect_err("identity_root_persona_daemon_signing_paths_landed");
        assert_eq!(
            err,
            PrincipalChainError::Cycle {
                principal_id: "principal-a".to_string()
            }
        );
    }

    #[test]
    fn signing_rejects_missing_parent_and_wrong_anchor() {
        let missing_parent = SigningPrincipalRecord {
            principal_id: "principal-child".to_string(),
            parent_id: "principal-missing".to_string(),
            signing_device_id: Some("device-child".to_string()),
        };
        let err = validate_principal_parent_chain(
            std::slice::from_ref(&missing_parent),
            "principal-child",
            "principal-root",
        )
        .expect_err("missing parent must fail closed");
        assert_eq!(
            err,
            PrincipalChainError::MissingParent {
                principal_id: "principal-child".to_string(),
                parent_id: "principal-missing".to_string()
            }
        );

        let wrong_root = SigningPrincipalRecord {
            principal_id: "principal-wrong-root".to_string(),
            parent_id: "principal-wrong-root".to_string(),
            signing_device_id: Some("device-wrong-root".to_string()),
        };
        let child = SigningPrincipalRecord {
            principal_id: "principal-child".to_string(),
            parent_id: wrong_root.principal_id.clone(),
            signing_device_id: Some("device-child".to_string()),
        };
        let err = validate_principal_parent_chain(
            &[wrong_root],
            "principal-wrong-root",
            "principal-root",
        )
        .expect_err("wrong anchor must fail closed");
        assert_eq!(
            err,
            PrincipalChainError::WrongAnchor {
                principal_id: "principal-wrong-root".to_string(),
                expected_anchor_id: "principal-root".to_string()
            }
        );
        let err = validate_principal_parent_chain(
            &[child, daemon_principal_record("principal-root")],
            "principal-child",
            "principal-root",
        )
        .expect_err("missing intermediate parent must fail closed");
        assert!(matches!(err, PrincipalChainError::MissingParent { .. }));
    }
}
