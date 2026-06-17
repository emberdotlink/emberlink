use std::error::Error;
use std::fmt;


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
