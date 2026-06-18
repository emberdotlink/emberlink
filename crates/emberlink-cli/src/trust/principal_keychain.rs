//! Principal-rooted keychain layout (ADR 200 amendment 2026-06-15).
//!
//! Per the operator-locked IdentityRoot / Persona unification, the v0.3
//! dual-IR keychain (`sh.emberlink.dev-identity-root` +
//! `sh.emberlink.operator-identity-root`) collapses into one
//! self-parented root Principal seed plus two Durable Persona children:
//!
//! - `sh.emberlink.root-principal.seed` — the person's self-parented
//!   root Principal Ed25519 seed.
//! - `sh.emberlink.persona.workstation.seed` — workstation Durable
//!   Persona seed; signs dev-box construct manifests (replaces the
//!   legacy `sh.emberlink.dev-identity-root` slot).
//! - `sh.emberlink.persona.operator-role.seed` — operator-role Durable
//!   Persona seed; signs AccessGrants and audit exports (replaces the
//!   legacy `sh.emberlink.operator-identity-root` slot).
//!
//! The legacy labels remain valid as **import sources only** — a fresh
//! v0.3 install must not teach or create the dual-IR target. Existing
//! operator installs are migrated by [`migrate_dual_ir_to_root_principal`]
//! on first `ember dev install` (or any caller that runs the migration).
//! After verification, the legacy labels are left in place so an
//! operator who needs to roll back can still reach the original
//! material; a future task (Slice F follow-on) deletes them once the
//! safe rollback window passes.
//!
//! Anchor: `identity_root_persona_keychain_consolidation_landed`.
//!
//! CLASSIFICATION: PUBLIC

use ed25519_dalek::{SigningKey, VerifyingKey};

#[cfg(test)]
pub(crate) static KEYCHAIN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Keychain service namespace shared across all `sh.emberlink.*`
/// labels.
pub const KEYCHAIN_SERVICE: &str = "sh.emberlink";

// ---------------------------------------------------------------------------
// Target-state labels (ADR 200 amendment 2026-06-15).
// ---------------------------------------------------------------------------

/// Target-state macOS Keychain label for the **root Principal** seed —
/// the self-parented (`id == parent_id`) trust anchor for the person.
/// Every Durable / Runtime Persona under the operator's tree walks its
/// `parent_id` chain up to this Principal.
pub const ROOT_PRINCIPAL_KEYCHAIN_LABEL: &str = "sh.emberlink.root-principal.seed";

/// Target-state macOS Keychain label for the **workstation Durable
/// Persona** seed — the child Principal that signs dev-box construct
/// manifests. Replaces the legacy `sh.emberlink.dev-identity-root`
/// slot. Parent is the root Principal at
/// [`ROOT_PRINCIPAL_KEYCHAIN_LABEL`].
pub const WORKSTATION_PERSONA_KEYCHAIN_LABEL: &str =
    "sh.emberlink.persona.workstation.seed";

/// Target-state macOS Keychain label for the **operator-role Durable
/// Persona** seed — the child Principal that signs AccessGrants and
/// audit-export artifacts. Replaces the legacy
/// `sh.emberlink.operator-identity-root` slot. Parent is the root
/// Principal at [`ROOT_PRINCIPAL_KEYCHAIN_LABEL`].
pub const OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL: &str =
    "sh.emberlink.persona.operator-role.seed";

// ---------------------------------------------------------------------------
// Transitional / legacy labels — import sources only.
// ---------------------------------------------------------------------------

/// **Transitional / legacy** macOS Keychain label for the v0.1-v0.2
/// dev IdentityRoot. New code must not write to this label;
/// [`migrate_dual_ir_to_root_principal`] reads it as an import source
/// and copies the seed into [`WORKSTATION_PERSONA_KEYCHAIN_LABEL`].
pub const LEGACY_DEV_IR_KEYCHAIN_LABEL: &str = "sh.emberlink.dev-identity-root";

/// **Transitional / legacy** macOS Keychain label for the v0.1-v0.2
/// operator IdentityRoot. New code must not write to this label;
/// [`migrate_dual_ir_to_root_principal`] reads it as an import source
/// and copies the seed into [`OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL`].
pub const LEGACY_OPERATOR_IR_KEYCHAIN_LABEL: &str = "sh.emberlink.operator-identity-root";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors surfaced by the keychain consolidation migration / accessor
/// surface. Wrapped strings keep the surface flat — every caller (dev
/// install, trust backup, trust restore) renders these into an
/// operator-facing diagnostic.
#[derive(Debug, thiserror::Error)]
pub enum PrincipalKeychainError {
    /// Failed to open or read a keyring entry for a reason other than
    /// "no entry".
    #[error("keyring error at label {label}: {source}")]
    Keyring {
        label: String,
        #[source]
        source: keyring_core::Error,
    },
    /// A stashed seed was not 32 hex-decoded bytes.
    #[error("seed at {label} has wrong length {got} (expected 32 bytes)")]
    SeedLength { label: String, got: usize },
    /// A stashed seed was not valid hex.
    #[error("seed at {label} is not valid hex: {message}")]
    SeedHex { label: String, message: String },
    /// OS entropy failed during fresh-key generation.
    #[error("OS entropy failure generating Principal seed: {0}")]
    Entropy(String),
    /// A migration verification check failed (post-write read-back).
    #[error("migration verify failed at {label}: {detail}")]
    VerifyFailed { label: String, detail: String },
}

// ---------------------------------------------------------------------------
// Public read/write surface
// ---------------------------------------------------------------------------

/// Compute the 32-char hex fingerprint of a public key (blake3 of the
/// raw bytes, first 16 bytes as hex). Same algorithm as
/// `crate::dev::identity_root::fingerprint_of` so the operator-facing
/// fingerprints stay consistent across the old and new surfaces.
pub fn fingerprint_of(public: &VerifyingKey) -> String {
    let hash = blake3::hash(public.as_bytes());
    hex::encode(&hash.as_bytes()[..16])
}

fn keyring_entry(label: &str) -> Result<keyring_core::Entry, PrincipalKeychainError> {
    keyring_core::Entry::new(KEYCHAIN_SERVICE, label).map_err(|source| {
        PrincipalKeychainError::Keyring {
            label: label.to_string(),
            source,
        }
    })
}

fn decode_seed(label: &str, hex_seed: &str) -> Result<[u8; 32], PrincipalKeychainError> {
    let bytes =
        hex::decode(hex_seed.trim()).map_err(|e| PrincipalKeychainError::SeedHex {
            label: label.to_string(),
            message: e.to_string(),
        })?;
    if bytes.len() != 32 {
        return Err(PrincipalKeychainError::SeedLength {
            label: label.to_string(),
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read the raw 32-byte seed stashed at `label`. Returns `Ok(None)`
/// when no entry exists.
pub fn read_seed(label: &str) -> Result<Option<[u8; 32]>, PrincipalKeychainError> {
    let entry = keyring_entry(label)?;
    match entry.get_password() {
        Ok(hex_seed) => Ok(Some(decode_seed(label, &hex_seed)?)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(PrincipalKeychainError::Keyring {
            label: label.to_string(),
            source: e,
        }),
    }
}

/// Stash a 32-byte seed at `label`. Overwrites any existing entry.
pub fn write_seed(label: &str, seed: &[u8; 32]) -> Result<(), PrincipalKeychainError> {
    let entry = keyring_entry(label)?;
    let hex_seed = hex::encode(seed);
    entry
        .set_password(&hex_seed)
        .map_err(|source| PrincipalKeychainError::Keyring {
            label: label.to_string(),
            source,
        })
}

/// Read an existing Ed25519 signing key from `label`, or generate +
/// stash a fresh one if no entry exists. Idempotent: re-running loads
/// the same key.
pub fn ensure_seed_at(label: &str) -> Result<SigningKey, PrincipalKeychainError> {
    if let Some(seed) = read_seed(label)? {
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| PrincipalKeychainError::Entropy(e.to_string()))?;
    write_seed(label, &seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

// ---------------------------------------------------------------------------
// Target-state convenience accessors.
// ---------------------------------------------------------------------------

/// Read the **workstation Durable Persona** seed, honoring the
/// target-state label first and falling back to the legacy
/// `sh.emberlink.dev-identity-root` slot when the target slot is
/// empty. Returns `Ok(None)` when neither label holds an entry.
///
/// New writers (`ensure_workstation_persona`) only ever write to the
/// target slot, so post-migration reads always satisfy from the new
/// label. This fallback exists so that a code path between the
/// install start and the migration completing still sees the existing
/// workstation key.
pub fn read_workstation_persona_seed() -> Result<Option<[u8; 32]>, PrincipalKeychainError> {
    if let Some(seed) = read_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL)? {
        return Ok(Some(seed));
    }
    read_seed(LEGACY_DEV_IR_KEYCHAIN_LABEL)
}

/// Read the **operator-role Durable Persona** seed, honoring the
/// target-state label first and falling back to the legacy
/// `sh.emberlink.operator-identity-root` slot when the target slot is
/// empty. Returns `Ok(None)` when neither label holds an entry.
pub fn read_operator_role_persona_seed() -> Result<Option<[u8; 32]>, PrincipalKeychainError> {
    if let Some(seed) = read_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL)? {
        return Ok(Some(seed));
    }
    read_seed(LEGACY_OPERATOR_IR_KEYCHAIN_LABEL)
}

/// Ensure the **root Principal** seed exists at the target-state label,
/// generating a fresh Ed25519 seed on first run. Idempotent.
pub fn ensure_root_principal() -> Result<SigningKey, PrincipalKeychainError> {
    ensure_seed_at(ROOT_PRINCIPAL_KEYCHAIN_LABEL)
}

/// Ensure the **workstation Durable Persona** seed exists at the
/// target-state label, generating a fresh Ed25519 seed on first run.
/// Idempotent.
pub fn ensure_workstation_persona() -> Result<SigningKey, PrincipalKeychainError> {
    ensure_seed_at(WORKSTATION_PERSONA_KEYCHAIN_LABEL)
}

/// Ensure the **operator-role Durable Persona** seed exists at the
/// target-state label, generating a fresh Ed25519 seed on first run.
/// Idempotent.
pub fn ensure_operator_role_persona() -> Result<SigningKey, PrincipalKeychainError> {
    ensure_seed_at(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL)
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// Auditable record of what the migration did. Carries only **public**
/// fingerprints — private seed material never appears in this struct
/// so the migration is safe to emit into operator-facing logs and
/// (future) `trust.keychain.migrated` Receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Whether a root Principal seed already existed at the target
    /// label before migration ran (idempotency probe).
    pub root_principal_already_present: bool,
    /// Pre-migration fingerprint of the legacy dev IR, if present.
    pub legacy_dev_ir_fingerprint: Option<String>,
    /// Pre-migration fingerprint of the legacy operator IR, if present.
    pub legacy_operator_ir_fingerprint: Option<String>,
    /// Post-migration fingerprint of the root Principal seed at the
    /// target label.
    pub root_principal_fingerprint: String,
    /// Post-migration fingerprint of the workstation Durable Persona
    /// seed at the target label.
    pub workstation_persona_fingerprint: String,
    /// Post-migration fingerprint of the operator-role Durable
    /// Persona seed at the target label.
    pub operator_role_persona_fingerprint: String,
    /// Whether the workstation persona seed was imported from the
    /// legacy dev IR slot (rather than freshly generated).
    pub workstation_imported_from_legacy: bool,
    /// Whether the operator-role persona seed was imported from the
    /// legacy operator IR slot (rather than freshly generated).
    pub operator_role_imported_from_legacy: bool,
}

fn fingerprint_for_seed(seed: &[u8; 32]) -> String {
    let key = SigningKey::from_bytes(seed);
    fingerprint_of(&key.verifying_key())
}

/// Run the dual-IR → root-Principal keychain consolidation migration.
///
/// Per the ADR 200 amendment 2026-06-15 target shape:
///
/// 1. If the **root Principal** target slot is empty, generate a fresh
///    Ed25519 seed and stash it there.
/// 2. If the **workstation Durable Persona** target slot is empty,
///    import the legacy `sh.emberlink.dev-identity-root` seed into it
///    (when present), else generate a fresh seed.
/// 3. If the **operator-role Durable Persona** target slot is empty,
///    import the legacy `sh.emberlink.operator-identity-root` seed
///    into it (when present), else generate a fresh seed.
/// 4. Verify each target slot by read-back: a stored seed must
///    round-trip to the same public-key fingerprint we just computed
///    before declaring success. A failed verify leaves the legacy
///    slots untouched.
///
/// The migration is **idempotent**: running it a second time produces
/// the same fingerprints, does not regenerate any seed, and does not
/// duplicate any record (Keychain entries are keyed by label, so
/// re-writing the same label is a no-op when the seed already matches).
///
/// The legacy slots are **deliberately not deleted** — this preserves
/// a safe rollback window during the v0.3.0 → v0.3.1 transition. A
/// future task removes them once the cutover is proven on real installs.
pub fn migrate_dual_ir_to_root_principal()
-> Result<MigrationReport, PrincipalKeychainError> {
    // identity_root_persona_keychain_consolidation_landed — checkpoint
    // anchoring the migration entrypoint.

    // Snapshot pre-migration legacy state (public fingerprints only).
    let legacy_dev = read_seed(LEGACY_DEV_IR_KEYCHAIN_LABEL)?;
    let legacy_operator = read_seed(LEGACY_OPERATOR_IR_KEYCHAIN_LABEL)?;
    let legacy_dev_ir_fingerprint = legacy_dev.as_ref().map(fingerprint_for_seed);
    let legacy_operator_ir_fingerprint = legacy_operator.as_ref().map(fingerprint_for_seed);

    // 1) Root Principal slot — generate a fresh seed on first run.
    let pre_root = read_seed(ROOT_PRINCIPAL_KEYCHAIN_LABEL)?;
    let root_principal_already_present = pre_root.is_some();
    let root_key = ensure_root_principal()?;
    let root_principal_fingerprint = fingerprint_of(&root_key.verifying_key());

    // 2) Workstation Durable Persona slot.
    let pre_workstation = read_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL)?;
    let (workstation_key, workstation_imported_from_legacy) = match pre_workstation {
        Some(seed) => (SigningKey::from_bytes(&seed), false),
        None => match legacy_dev {
            Some(seed) => {
                write_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL, &seed)?;
                (SigningKey::from_bytes(&seed), true)
            }
            None => (ensure_workstation_persona()?, false),
        },
    };
    let workstation_persona_fingerprint =
        fingerprint_of(&workstation_key.verifying_key());

    // 3) Operator-role Durable Persona slot.
    let pre_operator = read_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL)?;
    let (operator_role_key, operator_role_imported_from_legacy) = match pre_operator {
        Some(seed) => (SigningKey::from_bytes(&seed), false),
        None => match legacy_operator {
            Some(seed) => {
                write_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL, &seed)?;
                (SigningKey::from_bytes(&seed), true)
            }
            None => (ensure_operator_role_persona()?, false),
        },
    };
    let operator_role_persona_fingerprint =
        fingerprint_of(&operator_role_key.verifying_key());

    // 4) Verify each target slot round-trips. If any verify fails, the
    //    legacy slots are untouched (rollback path is just "delete the
    //    new labels and re-run").
    verify_target_slot(
        ROOT_PRINCIPAL_KEYCHAIN_LABEL,
        &root_principal_fingerprint,
    )?;
    verify_target_slot(
        WORKSTATION_PERSONA_KEYCHAIN_LABEL,
        &workstation_persona_fingerprint,
    )?;
    verify_target_slot(
        OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
        &operator_role_persona_fingerprint,
    )?;

    Ok(MigrationReport {
        root_principal_already_present,
        legacy_dev_ir_fingerprint,
        legacy_operator_ir_fingerprint,
        root_principal_fingerprint,
        workstation_persona_fingerprint,
        operator_role_persona_fingerprint,
        workstation_imported_from_legacy,
        operator_role_imported_from_legacy,
    })
}

fn verify_target_slot(
    label: &str,
    expected_fingerprint: &str,
) -> Result<(), PrincipalKeychainError> {
    let seed = read_seed(label)?.ok_or_else(|| PrincipalKeychainError::VerifyFailed {
        label: label.to_string(),
        detail: "target slot empty after migration write".to_string(),
    })?;
    let got = fingerprint_for_seed(&seed);
    if got != expected_fingerprint {
        return Err(PrincipalKeychainError::VerifyFailed {
            label: label.to_string(),
            detail: format!(
                "fingerprint mismatch: expected {expected_fingerprint}, got {got}"
            ),
        });
    }
    Ok(())
}

/// Render the migration report as an operator-facing block. Private
/// material never appears — only public fingerprints + booleans.
pub fn render_migration_report(report: &MigrationReport) -> String {
    let mut out = String::from("Keychain consolidation (dual-IR → root Principal):\n");
    out.push_str(&format!(
        "  Root Principal:         {} (already present: {})\n",
        report.root_principal_fingerprint, report.root_principal_already_present
    ));
    out.push_str(&format!(
        "  Workstation Persona:    {} (imported from legacy dev IR: {})\n",
        report.workstation_persona_fingerprint,
        report.workstation_imported_from_legacy
    ));
    out.push_str(&format!(
        "  Operator-role Persona:  {} (imported from legacy operator IR: {})\n",
        report.operator_role_persona_fingerprint,
        report.operator_role_imported_from_legacy
    ));
    if let Some(fp) = &report.legacy_dev_ir_fingerprint {
        out.push_str(&format!("  Legacy dev IR (pre):    {fp}\n"));
    }
    if let Some(fp) = &report.legacy_operator_ir_fingerprint {
        out.push_str(&format!("  Legacy operator IR (pre): {fp}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::mock;

    // keyring-core has a single process-wide default store; serialize
    // tests that touch it. The mock-store API doesn't have a clear()
    // helper, so each test scrubs the labels it cares about up front.
    fn install_mock_store() {
        // set_default_store is idempotent-safe for our purposes: the
        // tests don't rely on each other's state, and we clear labels
        // at the start of each test.
        keyring_core::set_default_store(mock::Store::new().expect("mock store"));
    }

    fn clear_all_labels() {
        for label in [
            ROOT_PRINCIPAL_KEYCHAIN_LABEL,
            WORKSTATION_PERSONA_KEYCHAIN_LABEL,
            OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL,
            LEGACY_DEV_IR_KEYCHAIN_LABEL,
            LEGACY_OPERATOR_IR_KEYCHAIN_LABEL,
        ] {
            if let Ok(entry) = keyring_core::Entry::new(KEYCHAIN_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
    }

    fn write_legacy(label: &str, seed_byte: u8) {
        let seed = [seed_byte; 32];
        let entry = keyring_core::Entry::new(KEYCHAIN_SERVICE, label)
            .expect("legacy entry");
        entry.set_password(&hex::encode(seed)).expect("seed write");
    }

    /// META-V030-IDENTITY-ROOT-PERSONA-UNIFICATION-KEYCHAIN-CONSOLIDATION:
    /// the load-bearing migration test. Seeds the two legacy labels,
    /// runs the migration, asserts one root Principal + the two
    /// children with the imported legacy fingerprints. Then runs the
    /// migration a SECOND time and asserts the fingerprints are
    /// identical (idempotency).
    ///
    /// Checkpoint anchored: `identity_root_persona_keychain_consolidation_landed`.
    #[test]
    fn dual_ir_keychain_imports_to_root_principal_children() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        // Pre-migration: seed both legacy slots.
        write_legacy(LEGACY_DEV_IR_KEYCHAIN_LABEL, 0xAA);
        write_legacy(LEGACY_OPERATOR_IR_KEYCHAIN_LABEL, 0xBB);

        let report = migrate_dual_ir_to_root_principal().expect("first migration");

        // Imports happened — workstation seed equals legacy dev IR fingerprint;
        // operator-role seed equals legacy operator IR fingerprint.
        assert!(report.workstation_imported_from_legacy);
        assert!(report.operator_role_imported_from_legacy);
        assert!(!report.root_principal_already_present);
        let legacy_dev_fp = fingerprint_for_seed(&[0xAA; 32]);
        let legacy_op_fp = fingerprint_for_seed(&[0xBB; 32]);
        assert_eq!(report.workstation_persona_fingerprint, legacy_dev_fp);
        assert_eq!(report.operator_role_persona_fingerprint, legacy_op_fp);
        assert_eq!(report.legacy_dev_ir_fingerprint, Some(legacy_dev_fp.clone()));
        assert_eq!(
            report.legacy_operator_ir_fingerprint,
            Some(legacy_op_fp.clone())
        );

        // Target-state slots now hold the same seed bytes as the legacy slots
        // (imports preserve material; rotation is a separate operation).
        let imported_workstation =
            read_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL).expect("read").expect("present");
        assert_eq!(imported_workstation, [0xAA; 32]);
        let imported_operator =
            read_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL).expect("read").expect("present");
        assert_eq!(imported_operator, [0xBB; 32]);

        // Legacy slots are left in place (safe rollback window).
        let legacy_dev =
            read_seed(LEGACY_DEV_IR_KEYCHAIN_LABEL).expect("read").expect("present");
        assert_eq!(legacy_dev, [0xAA; 32]);
        let legacy_op =
            read_seed(LEGACY_OPERATOR_IR_KEYCHAIN_LABEL).expect("read").expect("present");
        assert_eq!(legacy_op, [0xBB; 32]);

        // Second run is idempotent — same fingerprints, no new fresh
        // generation. The root Principal seed must NOT be regenerated
        // on the second run; `root_principal_already_present` flips
        // to true.
        let report2 =
            migrate_dual_ir_to_root_principal().expect("second migration");
        assert_eq!(
            report2.root_principal_fingerprint,
            report.root_principal_fingerprint
        );
        assert_eq!(
            report2.workstation_persona_fingerprint,
            report.workstation_persona_fingerprint
        );
        assert_eq!(
            report2.operator_role_persona_fingerprint,
            report.operator_role_persona_fingerprint
        );
        assert!(report2.root_principal_already_present);
        // Imports do NOT re-fire on the second run — the target slots
        // are already populated.
        assert!(!report2.workstation_imported_from_legacy);
        assert!(!report2.operator_role_imported_from_legacy);
    }

    /// Fresh install (no legacy entries) generates three fresh seeds
    /// at the target labels. Re-running is idempotent.
    #[test]
    fn fresh_install_creates_root_principal_and_two_children() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        let report = migrate_dual_ir_to_root_principal().expect("first migration");
        assert!(!report.root_principal_already_present);
        assert!(!report.workstation_imported_from_legacy);
        assert!(!report.operator_role_imported_from_legacy);
        assert!(report.legacy_dev_ir_fingerprint.is_none());
        assert!(report.legacy_operator_ir_fingerprint.is_none());
        // Each target slot is populated with a fresh seed.
        assert!(read_seed(ROOT_PRINCIPAL_KEYCHAIN_LABEL).unwrap().is_some());
        assert!(read_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL).unwrap().is_some());
        assert!(read_seed(OPERATOR_ROLE_PERSONA_KEYCHAIN_LABEL).unwrap().is_some());
        // Distinct fingerprints — the three seeds are independent.
        assert_ne!(
            report.root_principal_fingerprint,
            report.workstation_persona_fingerprint
        );
        assert_ne!(
            report.root_principal_fingerprint,
            report.operator_role_persona_fingerprint
        );
        assert_ne!(
            report.workstation_persona_fingerprint,
            report.operator_role_persona_fingerprint
        );

        // Idempotency.
        let report2 =
            migrate_dual_ir_to_root_principal().expect("second migration");
        assert_eq!(report2, MigrationReport {
            root_principal_already_present: true,
            legacy_dev_ir_fingerprint: None,
            legacy_operator_ir_fingerprint: None,
            root_principal_fingerprint: report.root_principal_fingerprint.clone(),
            workstation_persona_fingerprint: report.workstation_persona_fingerprint.clone(),
            operator_role_persona_fingerprint: report.operator_role_persona_fingerprint.clone(),
            workstation_imported_from_legacy: false,
            operator_role_imported_from_legacy: false,
        });
    }

    /// Half-migrated state: target root + workstation slot already
    /// populated, but operator-role missing and legacy operator IR
    /// available. Migration imports just the missing child.
    #[test]
    fn half_migrated_install_imports_only_missing_child() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        // Pre-state: workstation already at target slot, operator-role
        // still on legacy slot.
        let workstation_seed = [0x11u8; 32];
        write_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL, &workstation_seed)
            .expect("seed workstation");
        write_legacy(LEGACY_OPERATOR_IR_KEYCHAIN_LABEL, 0x22);
        // Root principal slot starts empty.

        let report = migrate_dual_ir_to_root_principal().expect("migration");
        assert!(!report.root_principal_already_present);
        // Workstation NOT re-imported — already at target slot.
        assert!(!report.workstation_imported_from_legacy);
        assert_eq!(
            report.workstation_persona_fingerprint,
            fingerprint_for_seed(&workstation_seed)
        );
        // Operator-role IS imported from the legacy slot.
        assert!(report.operator_role_imported_from_legacy);
        assert_eq!(
            report.operator_role_persona_fingerprint,
            fingerprint_for_seed(&[0x22; 32])
        );
    }

    /// Round-trip read/write on a target slot produces the same seed.
    #[test]
    fn seed_round_trip_at_target_label() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        let seed = [0x77u8; 32];
        write_seed(ROOT_PRINCIPAL_KEYCHAIN_LABEL, &seed).expect("write");
        let read = read_seed(ROOT_PRINCIPAL_KEYCHAIN_LABEL)
            .expect("read")
            .expect("present");
        assert_eq!(read, seed);
    }

    /// The read-and-fallback helpers prefer the target slot when both
    /// labels are populated.
    #[test]
    fn read_workstation_prefers_target_over_legacy() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        write_seed(WORKSTATION_PERSONA_KEYCHAIN_LABEL, &[0xCC; 32])
            .expect("target");
        write_legacy(LEGACY_DEV_IR_KEYCHAIN_LABEL, 0xDD);

        let got = read_workstation_persona_seed().expect("read").expect("present");
        assert_eq!(got, [0xCC; 32]); // target wins over legacy
    }

    /// The fallback fires when the target slot is empty but the legacy
    /// slot is populated.
    #[test]
    fn read_workstation_falls_back_to_legacy_when_target_empty() {
        let _guard = KEYCHAIN_TEST_LOCK.lock().unwrap();
        install_mock_store();
        clear_all_labels();

        write_legacy(LEGACY_DEV_IR_KEYCHAIN_LABEL, 0xEE);

        let got = read_workstation_persona_seed().expect("read").expect("present");
        assert_eq!(got, [0xEE; 32]);
    }

    /// Render report contains the expected operator-facing fields and
    /// **does not** leak private material.
    #[test]
    fn render_report_shows_only_public_fingerprints() {
        let report = MigrationReport {
            root_principal_already_present: false,
            legacy_dev_ir_fingerprint: Some("aa".repeat(16)),
            legacy_operator_ir_fingerprint: Some("bb".repeat(16)),
            root_principal_fingerprint: "cc".repeat(16),
            workstation_persona_fingerprint: "dd".repeat(16),
            operator_role_persona_fingerprint: "ee".repeat(16),
            workstation_imported_from_legacy: true,
            operator_role_imported_from_legacy: true,
        };
        let s = render_migration_report(&report);
        assert!(s.contains("Root Principal:"));
        assert!(s.contains("Workstation Persona:"));
        assert!(s.contains("Operator-role Persona:"));
        assert!(s.contains(&"cc".repeat(16)));
        assert!(s.contains(&"dd".repeat(16)));
        assert!(s.contains(&"ee".repeat(16)));
        // Sanity: no obvious hex-only-32-char private blob (seed length
        // would be 64 hex chars). Public fingerprints are 32 hex chars.
        for line in s.lines() {
            for token in line.split_whitespace() {
                if token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit())
                {
                    panic!("render leaked a 32-byte hex blob: {token}");
                }
            }
        }
    }
}
