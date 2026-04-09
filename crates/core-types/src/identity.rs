use crate::encoding::*;
use crate::{CanonicalEncode, Validate, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRoot {
    pub id: String,
    pub display_name: String,
    pub active_key: PublicKeyMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Persona {
    pub id: String,
    pub root_id: String,
    pub label: String,
    pub disclosure_profile: Option<String>,
    pub survival_mode: SurvivalMode,
    pub active_key: PublicKeyMaterial,
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
}

impl KeyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevEd25519Like => "dev-ed25519-like",
            Self::Ed25519 => "ed25519",
            Self::AgeX25519 => "age-x25519",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dev-ed25519-like" => Some(Self::DevEd25519Like),
            "ed25519" => Some(Self::Ed25519),
            "age-x25519" => Some(Self::AgeX25519),
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

impl Validate for IdentityRoot {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "root id")?;
        validate_non_empty(&self.display_name, "root display name")?;
        self.active_key.validate()
    }
}

impl Validate for Persona {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "persona id")?;
        validate_non_empty(&self.root_id, "root id")?;
        validate_non_empty(&self.label, "persona label")?;
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

impl CanonicalEncode for IdentityRoot {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "identity-root",
            &[
                ("id", self.id.clone()),
                ("display_name", self.display_name.clone()),
                ("active_key_id", self.active_key.key_id.clone()),
                ("active_key", self.active_key.public_key.clone()),
            ],
        )
    }
}

impl CanonicalEncode for Persona {
    fn canonical_encode(&self) -> Vec<u8> {
        canonical_record(
            "persona",
            &[
                ("id", self.id.clone()),
                ("root_id", self.root_id.clone()),
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
