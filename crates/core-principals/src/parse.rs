//! Parse helpers for principals-level types.
//!
//! Migrated from `core-types/src/encoding.rs::parse_public_key_material` per
//! ADR 156 step 5 — the helper constructs a `PublicKeyMaterial` from a
//! string-map and so belongs alongside the type it returns, not in the
//! foundation `core-types::encoding` module that cannot know about
//! identity-shape primitives.

use crate::identity::{KeyAlgorithm, PublicKeyMaterial};
use core_types::ValidationError;
use core_types::encoding::required_field;

pub fn parse_public_key_material(
    fields: &std::collections::BTreeMap<String, String>,
    key_id_field: &str,
    algorithm_field: &str,
    public_key_field: &str,
) -> Result<PublicKeyMaterial, ValidationError> {
    Ok(PublicKeyMaterial {
        key_id: required_field(fields, key_id_field)?,
        algorithm: KeyAlgorithm::parse(&required_field(fields, algorithm_field)?)
            .ok_or_else(|| ValidationError::invalid_format("invalid key algorithm"))?,
        public_key: required_field(fields, public_key_field)?,
    })
}
