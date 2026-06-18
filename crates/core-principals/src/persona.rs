//! Persona ID 2-slot schema (per ADR 116).
//!
//! Persona ID = `<runtime>-<context>` (open lowercase-hyphen-digit strings).
//! Slot 1 `runtime`: cohort A first-party (`claude-code`, `autopilot`).
//! Slot 2 `context`: worktree directory name when launched with `-w`; else `default`.
//!
//! This is the human-readable narrative form. The opaque `persona_id` UUID
//! on the existing `Persona` struct stays the verifiable identity primitive;
//! Receipts carry both.

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

/// 2-slot Persona ID per ADR 116.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersonaIdSlots {
    /// Runtime slot — e.g. `claude-code`, `autopilot`.
    pub runtime: String,
    /// Context slot — e.g. worktree directory name, or `default`.
    pub context: String,
}

impl PersonaIdSlots {
    /// Build from runtime + context, validating each slot.
    pub fn new(
        runtime: impl Into<String>,
        context: impl Into<String>,
    ) -> Result<Self, PersonaIdParseError> {
        let runtime = runtime.into();
        let context = context.into();
        validate_slot(&runtime).map_err(PersonaIdParseError::InvalidRuntime)?;
        validate_slot(&context).map_err(PersonaIdParseError::InvalidContext)?;
        Ok(Self { runtime, context })
    }

    /// Parse `<runtime>-<context>` form. Splits on FIRST `-`, so
    /// `autopilot-myrepo` → runtime=`autopilot`, context=`myrepo`.
    pub fn parse(s: &str) -> Result<Self, PersonaIdParseError> {
        let (runtime, context) = s
            .split_once('-')
            .ok_or(PersonaIdParseError::MissingSeparator)?;
        Self::new(runtime, context)
    }

    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    pub fn context(&self) -> &str {
        &self.context
    }
}

impl fmt::Display for PersonaIdSlots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.runtime, self.context)
    }
}

/// Validate a slot: lowercase, digits, hyphens only; non-empty; no leading/trailing hyphen.
fn validate_slot(s: &str) -> Result<(), SlotError> {
    if s.is_empty() {
        return Err(SlotError::Empty);
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(SlotError::EdgeHyphen);
    }
    for c in s.chars() {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(SlotError::InvalidChar(c));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    /// Slot is empty.
    Empty,
    /// Slot has a leading or trailing hyphen.
    EdgeHyphen,
    /// Slot contains an invalid character.
    InvalidChar(char),
}

impl fmt::Display for SlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotError::Empty => write!(f, "slot is empty"),
            SlotError::EdgeHyphen => write!(f, "slot has leading or trailing hyphen"),
            SlotError::InvalidChar(c) => write!(f, "slot contains invalid character: {c:?}"),
        }
    }
}

impl Error for SlotError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonaIdParseError {
    /// Missing `-` separator between runtime and context slots.
    MissingSeparator,
    /// Invalid runtime slot.
    InvalidRuntime(SlotError),
    /// Invalid context slot.
    InvalidContext(SlotError),
}

impl fmt::Display for PersonaIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersonaIdParseError::MissingSeparator => {
                write!(f, "missing `-` separator between runtime and context slots")
            }
            PersonaIdParseError::InvalidRuntime(e) => write!(f, "invalid runtime slot: {e}"),
            PersonaIdParseError::InvalidContext(e) => write!(f, "invalid context slot: {e}"),
        }
    }
}

impl Error for PersonaIdParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PersonaIdParseError::MissingSeparator => None,
            PersonaIdParseError::InvalidRuntime(e) | PersonaIdParseError::InvalidContext(e) => {
                Some(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_reproduces_slots() {
        let id = PersonaIdSlots::new("autopilot", "default").unwrap();
        assert_eq!(id.to_string(), "autopilot-default");
    }

    #[test]
    fn parse_splits_on_first_hyphen() {
        let parsed = PersonaIdSlots::parse("autopilot-myrepo").unwrap();
        assert_eq!(parsed.runtime(), "autopilot");
        assert_eq!(parsed.context(), "myrepo");
    }

    #[test]
    fn parse_keeps_remainder_in_context() {
        let parsed = PersonaIdSlots::parse("claude-code-emberlink").unwrap();
        assert_eq!(parsed.runtime(), "claude");
        assert_eq!(parsed.context(), "code-emberlink");
    }

    #[test]
    fn rejects_uppercase() {
        let err = PersonaIdSlots::new("Claude", "default").unwrap_err();
        assert!(matches!(
            err,
            PersonaIdParseError::InvalidRuntime(SlotError::InvalidChar('C'))
        ));
    }

    #[test]
    fn rejects_empty_slot() {
        assert!(matches!(
            PersonaIdSlots::new("", "default").unwrap_err(),
            PersonaIdParseError::InvalidRuntime(SlotError::Empty),
        ));
    }

    #[test]
    fn rejects_edge_hyphen() {
        assert!(matches!(
            PersonaIdSlots::new("-bad", "default").unwrap_err(),
            PersonaIdParseError::InvalidRuntime(SlotError::EdgeHyphen),
        ));
        assert!(matches!(
            PersonaIdSlots::new("bad-", "default").unwrap_err(),
            PersonaIdParseError::InvalidRuntime(SlotError::EdgeHyphen),
        ));
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(matches!(
            PersonaIdSlots::parse("noseparator").unwrap_err(),
            PersonaIdParseError::MissingSeparator,
        ));
    }

    #[test]
    fn round_trip_serde_json() {
        let id = PersonaIdSlots::new("autopilot", "myrepo").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: PersonaIdSlots = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
