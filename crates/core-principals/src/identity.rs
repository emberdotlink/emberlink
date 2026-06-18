//! Identity / Principal type definitions.
//!
//! Per ADR 200 2026-06-15 amendment (checkpoint
//! `identity_root_persona_unification_phase1_landed`), the v0.1
//! `IdentityRoot` / `Persona` split collapses into one recursive
//! `Principal` protocol type. Root-ness is derived solely from
//! `id == parent_id`; there is no rootless verifier branch.
//!
//! `IdentityRoot` and `Persona` remain as **transitional** `pub type`
//! aliases of `Principal` while consumer crates (Slice B and later)
//! migrate to the unified vocabulary. The aliases are NOT distinct
//! structs — they exist only to keep downstream crates compiling
//! during the rolling collapse and must be retired once Slice B lands.
//!
//! Anchor: `identity_root_persona_core_principals_type_collapse_landed`.

use core_types::encoding::*;
use core_types::{CanonicalEncode, Validate, ValidationError};
use std::collections::HashMap;

/// Unified protocol type for principals (root identity, durable persona,
/// runtime persona — one type, one recursive chain).
///
/// Root-ness is derived: `id == parent_id`. There is no separate
/// `IdentityRoot` type. `parent_id` is a required `String` — a
/// self-parented Principal is the top of the tree (matches the daemon
/// self-rooting pattern; avoids a rootless verifier branch).
///
/// `active_key` is **public verification material** for the Principal;
/// private signing custody lives on Devices per ADR 200, never on the
/// Principal record.
// identity_root_persona_core_principals_type_collapse_landed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: String,
    /// Parent Principal id. `parent_id == id` denotes the self-parented
    /// trust-anchor root (no rootless branch).
    pub parent_id: String,
    pub label: String,
    pub disclosure_profile: Option<String>,
    pub survival_mode: SurvivalMode,
    pub active_key: PublicKeyMaterial,
}

impl Principal {
    /// True iff this Principal is the self-parented top of its chain.
    pub fn is_self_root(&self) -> bool {
        !self.id.is_empty() && self.id == self.parent_id
    }
}

/// **Transitional** alias for a Principal at the top of a chain
/// (`id == parent_id`). Will be removed once Slice B + downstream
/// consumers retire the legacy name. Per ADR 200 amendment 2026-06-15.
pub type IdentityRoot = Principal;

/// **Transitional** alias for a scoped Principal. Domain vocabulary
/// (product / docs) still names this concept "Persona"; protocol
/// storage treats it as the same recursive `Principal` type. Will be
/// retired once Slice B + downstream consumers complete the rolling
/// collapse. Per ADR 200 amendment 2026-06-15.
pub type Persona = Principal;

/// Error returned by [`principal_chain_terminates_at_self_root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalChainError {
    /// A Principal in the chain was not present in the lookup table.
    MissingParent { principal_id: String, parent_id: String },
    /// The chain visited a Principal twice before reaching a
    /// self-parented anchor (cycle without self-root).
    Cycle { revisited: String },
    /// The chain exceeded the safety bound without terminating.
    DepthExceeded { limit: usize },
    /// The chain tip itself is unknown to the lookup table.
    UnknownTip { id: String },
}

impl std::fmt::Display for PrincipalChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingParent { principal_id, parent_id } => write!(
                f,
                "principal {principal_id} references missing parent {parent_id}"
            ),
            Self::Cycle { revisited } => write!(
                f,
                "principal chain revisits {revisited} without reaching a self-parented root"
            ),
            Self::DepthExceeded { limit } => {
                write!(f, "principal chain exceeded depth {limit}")
            }
            Self::UnknownTip { id } => {
                write!(f, "principal chain tip {id} not present in lookup")
            }
        }
    }
}

impl std::error::Error for PrincipalChainError {}

/// Safety bound on the parent-chain walk. Real principal trees are
/// shallow; this exists only to make a malformed input terminate.
pub const PRINCIPAL_CHAIN_MAX_DEPTH: usize = 128;

/// Walk `tip_id`'s `parent_id` chain in `lookup` and verify it
/// terminates at a self-parented Principal. Per ADR 200 amendment
/// 2026-06-15: a valid chain reaches `id == parent_id`, or
/// verification fails.
pub fn principal_chain_terminates_at_self_root(
    tip_id: &str,
    lookup: &HashMap<String, Principal>,
) -> Result<(), PrincipalChainError> {
    let mut current = lookup
        .get(tip_id)
        .ok_or_else(|| PrincipalChainError::UnknownTip { id: tip_id.to_string() })?;
    let mut visited: Vec<String> = Vec::new();
    for _ in 0..PRINCIPAL_CHAIN_MAX_DEPTH {
        if current.is_self_root() {
            return Ok(());
        }
        if visited.iter().any(|v| v == &current.id) {
            return Err(PrincipalChainError::Cycle {
                revisited: current.id.clone(),
            });
        }
        visited.push(current.id.clone());
        let parent = lookup.get(&current.parent_id).ok_or_else(|| {
            PrincipalChainError::MissingParent {
                principal_id: current.id.clone(),
                parent_id: current.parent_id.clone(),
            }
        })?;
        current = parent;
    }
    Err(PrincipalChainError::DepthExceeded { limit: PRINCIPAL_CHAIN_MAX_DEPTH })
}

/// Compute the rotation-cascade target set for `rotated_principal_id`
/// given the current `(grant_id, issuer_principal_id)` table.
///
/// Per ADR 200 amendment §"Recursive cascade rule": rotating any
/// Principal targets every active grant whose issuer is that
/// Principal — and no grant whose issuer is a different Principal.
/// The recursion is in the *Principal chain*, not in the cascade set:
/// rotating a root vs a Runtime Persona is the same operation, only
/// the fan-out differs.
///
/// Grants are modeled here as `(grant_id, issuer)` tuples to keep
/// `core-principals` free of a `core-grant-types` dep cycle.
pub fn rotation_cascade_targets(
    rotated_principal_id: &str,
    grants: &[(String, String)],
) -> Vec<String> {
    grants
        .iter()
        .filter_map(|(gid, issuer)| {
            if issuer == rotated_principal_id {
                Some(gid.clone())
            } else {
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyMaterial {
    pub key_id: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    DevEd25519Like,
    Ed25519,
    AgeX25519,
    /// ECDSA over NIST P-256 (ES256). First-class per ADR 200: the dev0
    /// `presence`-class Device key is a YubiKey PIV ECDSA-P256 key, verified by
    /// core-crypto's dedicated P256 verifier (never the Ed25519 path).
    EcdsaP256,
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevEd25519Like => "dev-ed25519-like",
            Self::Ed25519 => "ed25519",
            Self::AgeX25519 => "age-x25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dev-ed25519-like" => Some(Self::DevEd25519Like),
            "ed25519" => Some(Self::Ed25519),
            "age-x25519" => Some(Self::AgeX25519),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkageAssertion {
    pub source_root_id: String,
    pub target_root_id: String,
    pub disclosed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureView {
    pub root_id: String,
    pub personas: Vec<DisclosedPersona>,
    pub disclosed_links: Vec<DisclosedLinkage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedPersona {
    pub persona_id: String,
    pub label: String,
    pub disclosure_profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedLinkage {
    pub target_root_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMembership {
    pub root_id: String,
    pub device_id: String,
    pub label: String,
    pub active: bool,
    pub active_key: PublicKeyMaterial,
    pub active_encryption_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurvivalMode {
    Strict,
    LimitedPersonaContinuity,
}

impl SurvivalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::LimitedPersonaContinuity => "limited-persona-continuity",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" => Some(Self::Strict),
            "limited-persona-continuity" => Some(Self::LimitedPersonaContinuity),
            _ => None,
        }
    }
}

// --- Validate impls ---

impl Validate for PublicKeyMaterial {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.key_id, "key id")?;
        validate_non_empty(&self.public_key, "public key")?;
        Ok(())
    }
}

impl Validate for Principal {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "principal id")?;
        // Per ADR 200 amendment 2026-06-15: parent_id is required; the
        // top of a tree is self-parented, not rootless. An empty
        // parent_id is rejected here so missing-parent and rootless
        // invariants both fail at the same gate.
        validate_non_empty(&self.parent_id, "parent id")?;
        validate_non_empty(&self.label, "principal label")?;
        self.active_key.validate()
    }
}

impl Validate for DeviceMembership {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.label, "device label")?;
        self.active_key.validate()?;
        self.active_encryption_key.validate()
    }
}

// --- CanonicalEncode impls ---

impl CanonicalEncode for PublicKeyMaterial {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "public-key",
            &[
                ("key_id", self.key_id.clone()),
                ("algorithm", self.algorithm.as_str().to_string()),
                ("public_key", self.public_key.clone()),
            ],
        )
    }
}

impl CanonicalEncode for Principal {
    fn canonical_encode(&self) -> Vec<u8> {
        // Per ADR 200 amendment 2026-06-15 §"Wire-format implications":
        // canonical tag is "principal"; legacy "identity-root" /
        // "persona" tags are retired. parent_id is the canonical
        // attribution field. active_key remains public verification
        // material; this record never implies private key custody.
        canonical_record(
            "principal",
            &[
                ("id", self.id.clone()),
                ("parent_id", self.parent_id.clone()),
                ("label", self.label.clone()),
                (
                    "disclosure_profile",
                    self.disclosure_profile.clone().unwrap_or_default(),
                ),
                ("survival_mode", self.survival_mode.as_str().to_string()),
                ("active_key_id", self.active_key.key_id.clone()),
                ("active_key", self.active_key.public_key.clone()),
            ],
        )
    }
}

impl CanonicalEncode for DeviceMembership {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "device-membership",
            &[
                ("root_id", self.root_id.clone()),
                ("device_id", self.device_id.clone()),
                ("label", self.label.clone()),
                ("active", self.active.to_string()),
                ("active_key_id", self.active_key.key_id.clone()),
                ("active_key", self.active_key.public_key.clone()),
                (
                    "active_encryption_key_id",
                    self.active_encryption_key.key_id.clone(),
                ),
                (
                    "active_encryption_key",
                    self.active_encryption_key.public_key.clone(),
                ),
            ],
        )
    }
}
