use std::error::Error;
use std::fmt;

// TODO(DRY-4 next wave, 2026-04-27): the second-slice brief asked for one of
// four protocol-type cleanups in `core-types`:
//   1. Move shared event-id helpers out of `events.rs`/`materialize.rs` into
//      one place — no duplicated helpers found between the two files.
//   2. Tighten `grant_link.rs` field types where `String` is really a UUID —
//      the only id-shaped field is `offer_id`, but its wire format is
//      `offer-{random}` (not a UUID), and `grant_link.rs` is CODEOWNERS-gated.
//   3. Remove dead variants from `grant_conditions.rs` — all three variants
//      (`BadgeGate`, `All`, `Any`) are actively used, and the file is
//      CODEOWNERS-gated.
//   4. Hoist tuple structs to named structs — brief instructed to skip unless
//      a clearly-wrong tuple was found; none was.
// Verified at HEAD `worktree-agent-a9a4e84c40a6bea5e`. Re-evaluate when the
// CODEOWNERS-gated targets gain a smaller-blast-radius angle (e.g. once
// `#[non_exhaustive]` lands on `EventBody`/`EventType`, or when an `OfferId`
// newtype lands as a strategic refactor rather than a String→Uuid swap).

pub const SCHEMA_VERSION: &str = "0.1.0";

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

pub trait CanonicalEncode {
    fn canonical_encode(&self) -> Vec<u8>;
}

/// Categorized error kind for programmatic matching on validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorKind {
    /// A required field was empty or missing.
    EmptyField,
    /// A referenced entity was not found in state.
    NotFound,
    /// The signer lacks authority for this operation.
    Unauthorized,
    /// The operation violates a state precondition (e.g., cooldown, already revoked).
    StateViolation,
    /// A value has an invalid format (bad hex, bad enum variant, parse failure).
    InvalidFormat,
    /// An I/O or database operation failed.
    IoError,
    /// Uncategorized validation error.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub kind: ValidationErrorKind,
    pub message: String,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::Other,
            message: message.into(),
        }
    }

    pub fn empty_field(field_name: &str) -> Self {
        Self {
            kind: ValidationErrorKind::EmptyField,
            message: format!("{field_name} must not be empty"),
        }
    }

    pub fn not_found(entity: &str, id: &str) -> Self {
        Self {
            kind: ValidationErrorKind::NotFound,
            message: format!("unknown {entity}: {id}"),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::Unauthorized,
            message: message.into(),
        }
    }

    pub fn state_violation(message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::StateViolation,
            message: message.into(),
        }
    }

    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::InvalidFormat,
            message: message.into(),
        }
    }

    pub fn io_error(message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::IoError,
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for ValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersion(pub u16, pub u16, pub u16);

impl SchemaVersion {
    pub const V0_1_0: Self = Self(0, 1, 0);

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "0.1.0" => Some(Self::V0_1_0),
            _ => None,
        }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

pub mod encoding;
pub mod size_limits;

pub use encoding::{bytes_to_hex, decode_hex_nibble, hex_to_bytes};
