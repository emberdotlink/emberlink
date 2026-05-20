//! grants.toml schema. ADR-locked envelope + [[credential]] + [defaults].
//!
//! v1 supports kinds: credential.ephemeral, credential.static, credential.sealed.
//! v2+ kinds parse with a warning instead of rejection (forward-compat).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Locked at "1" for v1 schema. Major-version mismatch is a hard error.
pub const GRANTS_SCHEMA_VERSION_V1: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantsManifest {
    pub grants_schema_version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default, rename = "credential")]
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
}

/// Tagged enum on `kind`. v1 = ephemeral / static / sealed.
/// v2+ kinds map to `Unknown { kind, payload }` for forward-compat (caller decides on warning).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Credential {
    #[serde(rename = "credential.ephemeral")]
    Ephemeral {
        name: String,
        #[serde(default)]
        scope: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<u64>,
    },
    #[serde(rename = "credential.static")]
    Static {
        name: String,
        #[serde(default)]
        scope: Value,
    },
    #[serde(rename = "credential.sealed")]
    Sealed {
        name: String,
        sealed_blob: String,
        #[serde(default)]
        scope: Value,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug)]
pub enum ManifestError {
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    Parse(toml::de::Error),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { found, expected } => {
                write!(
                    f,
                    "unsupported schema version {found} (expected {expected})"
                )
            }
            Self::Parse(e) => write!(f, "parse: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl GrantsManifest {
    /// Parse a manifest string. Major-version mismatch returns `UnsupportedSchemaVersion`.
    /// Unknown credential kinds map to `Credential::Unknown` (caller may warn).
    pub fn from_toml(input: &str) -> Result<Self, ManifestError> {
        let manifest: Self = toml::from_str(input).map_err(ManifestError::Parse)?;
        if manifest.grants_schema_version != GRANTS_SCHEMA_VERSION_V1 {
            return Err(ManifestError::UnsupportedSchemaVersion {
                found: manifest.grants_schema_version,
                expected: GRANTS_SCHEMA_VERSION_V1,
            });
        }
        Ok(manifest)
    }

    /// Validate a parsed manifest for semantic correctness. Returns a list
    /// of error strings if any rule is violated; empty Ok(()) if clean.
    ///
    /// Rules:
    /// - Every `Ephemeral`/`Static`/`Sealed` credential MUST have a non-empty `name`.
    /// - Credential names MUST be unique within a manifest.
    /// - `Sealed` credentials MUST have a non-empty `sealed_blob`.
    /// - `Unknown` credential kinds (forward-compat) trigger a warning-shaped
    ///   error so the caller can surface "this manifest references a kind
    ///   we don't understand."
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for (idx, cred) in self.credentials.iter().enumerate() {
            match cred {
                Credential::Ephemeral { name, .. }
                | Credential::Static { name, .. }
                | Credential::Sealed { name, .. } => {
                    if name.is_empty() {
                        errors.push(ValidationError::EmptyName { index: idx });
                    } else if !seen_names.insert(name.as_str()) {
                        errors.push(ValidationError::DuplicateName {
                            index: idx,
                            name: name.clone(),
                        });
                    }
                }
                Credential::Unknown => {
                    errors.push(ValidationError::UnknownKind { index: idx });
                }
            }

            if let Credential::Sealed {
                name, sealed_blob, ..
            } = cred
                && sealed_blob.is_empty()
            {
                errors.push(ValidationError::EmptySealedBlob {
                    index: idx,
                    name: name.clone(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Per-rule validation error for `GrantsManifest::validate()`.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Credential at the given index has an empty `name`.
    EmptyName { index: usize },
    /// Credential at the given index reuses a name already declared earlier.
    DuplicateName { index: usize, name: String },
    /// `Sealed` credential at the given index has an empty `sealed_blob`.
    EmptySealedBlob { index: usize, name: String },
    /// Credential at the given index is `Unknown` (forward-compat warning).
    UnknownKind { index: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName { index } => {
                write!(f, "credential[{index}]: name is empty")
            }
            Self::DuplicateName { index, name } => {
                write!(f, "credential[{index}]: duplicate name {name:?}")
            }
            Self::EmptySealedBlob { index, name } => {
                write!(f, "credential[{index}] ({name:?}): sealed_blob is empty")
            }
            Self::UnknownKind { index } => {
                write!(
                    f,
                    "credential[{index}]: unknown kind (forward-compat warning)"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v1_minimal() {
        let manifest = GrantsManifest::from_toml("grants_schema_version = 1").unwrap();
        assert_eq!(manifest.grants_schema_version, 1);
        assert!(manifest.credentials.is_empty());
    }

    #[test]
    fn parses_v1_all_kinds() {
        let toml = r#"
grants_schema_version = 1

[[credential]]
kind = "credential.ephemeral"
name = "openai-prod"
ttl_secs = 600

[[credential]]
kind = "credential.static"
name = "github-readonly"

[[credential]]
kind = "credential.sealed"
name = "anthropic-prod"
sealed_blob = "age1abc..."
"#;
        let manifest = GrantsManifest::from_toml(toml).unwrap();
        assert_eq!(manifest.credentials.len(), 3);
    }

    #[test]
    fn unknown_kind_parses_as_unknown_variant() {
        let toml = r#"
grants_schema_version = 1

[[credential]]
kind = "credential.future_v2_kind"
name = "x"
"#;
        let manifest = GrantsManifest::from_toml(toml).unwrap();
        assert!(matches!(manifest.credentials[0], Credential::Unknown));
    }

    #[test]
    fn major_version_mismatch_rejected() {
        let err = GrantsManifest::from_toml("grants_schema_version = 2").unwrap_err();
        assert!(matches!(
            err,
            ManifestError::UnsupportedSchemaVersion {
                found: 2,
                expected: 1
            }
        ));
    }

    fn manifest(toml_str: &str) -> GrantsManifest {
        GrantsManifest::from_toml(toml_str).expect("test manifest must parse")
    }

    #[test]
    fn validate_clean_manifest_passes() {
        let m = manifest(
            r#"
            grants_schema_version = 1
            [[credential]]
            kind = "credential.ephemeral"
            name = "vault-token"
            ttl_secs = 300
        "#,
        );
        assert_eq!(m.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_empty_name() {
        let m = manifest(
            r#"
            grants_schema_version = 1
            [[credential]]
            kind = "credential.ephemeral"
            name = ""
        "#,
        );
        assert_eq!(
            m.validate(),
            Err(vec![ValidationError::EmptyName { index: 0 }])
        );
    }

    #[test]
    fn validate_rejects_duplicate_name() {
        let m = manifest(
            r#"
            grants_schema_version = 1
            [[credential]]
            kind = "credential.ephemeral"
            name = "shared-name"
            [[credential]]
            kind = "credential.static"
            name = "shared-name"
        "#,
        );
        assert_eq!(
            m.validate(),
            Err(vec![ValidationError::DuplicateName {
                index: 1,
                name: "shared-name".to_string()
            }])
        );
    }

    #[test]
    fn validate_rejects_empty_sealed_blob() {
        let m = manifest(
            r#"
            grants_schema_version = 1
            [[credential]]
            kind = "credential.sealed"
            name = "vault-secret"
            sealed_blob = ""
        "#,
        );
        assert_eq!(
            m.validate(),
            Err(vec![ValidationError::EmptySealedBlob {
                index: 0,
                name: "vault-secret".to_string()
            }])
        );
    }

    #[test]
    fn validate_warns_on_unknown_kind() {
        let m = manifest(
            r#"
            grants_schema_version = 1
            [[credential]]
            kind = "credential.future-kind"
            some_field = "ignored"
        "#,
        );
        assert_eq!(
            m.validate(),
            Err(vec![ValidationError::UnknownKind { index: 0 }])
        );
    }
}
