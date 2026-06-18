use core_types::ValidationError;

#[derive(Debug, Clone, PartialEq)]
pub struct TrustAttestation {
    pub id: String,
    pub attester: String,
    pub subject: String,
    pub domain: String,
    pub score: f32,
    pub recipient_bound: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DerivedTrustStatement {
    pub id: String,
    pub subject: String,
    pub domain: String,
    pub normalized_score: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustExplanation {
    pub summary: String,
    pub redacted_summary: String,
}

/// A trust threshold is a normalized score in [0.0, 1.0] used to gate access
/// to a resource or service. Callers supply thresholds; the trust engine does
/// not embed policy decisions about what score is "enough."
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrustThreshold(f32);

impl TrustThreshold {
    pub fn new(value: f32) -> Result<Self, ValidationError> {
        if !(0.0..=1.0).contains(&value) {
            return Err(ValidationError::new(
                "trust threshold must be in [0.0, 1.0]",
            ));
        }
        Ok(Self(value))
    }

    pub fn value(self) -> f32 {
        self.0
    }

    pub fn is_met_by(self, score: f32) -> bool {
        score >= self.0
    }
}

// --- Validate impls ---
// (TrustAttestation, DerivedTrustStatement, TrustExplanation have no Validate impls in the original)

// TrustAttestedEvent and TrustRevokedEvent Validate impls are in events.rs since
// those types live there.

// No CanonicalEncode impls for these domain types in the original either.
// The event-level canonical encoding is in events.rs.
