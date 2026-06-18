//! Builder identity scoping for image signing — `builder_identity`.
//!
//! # builder_identity
//!
//! Encodes *who* signed a given image manifest and enforces channel-level
//! constraints on which builder identities are permitted.
//!
//! Two signing principals are recognised (ADR-DRAFT-IMG-SIGNING-AND-UPDATE-FLOW
//! D6):
//!
//! - **CI keyless** (`Ci`) — sigstore / Fulcio OIDC issuing a short-lived
//!   certificate whose SAN is scoped to `release.yml@refs/tags/v*`. Any
//!   non-tag workflow reference is refused by the gate in
//!   `.github/workflows/release.yml`.
//!
//! - **Local hardware key** (`LocalHardware`) — the operator's hardware security
//!   key (YubiKey / Secure Enclave). The only identity permitted to sign
//!   `dev`-channel images.
//!
//! Channel constraints (enforced by [`validate_for_channel`]):
//!
//! | Channel  | `Ci` | `LocalHardware` |
//! |----------|------|-----------------|
//! | `release`| OK   | OK              |
//! | `dev`    | ERR  | OK              |
//! | `ent0`   | ERR  | ERR (always)    |

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::channel::Channel;

/// Identity of the entity that signed an image manifest.
///
/// Serialized into the image manifest so the update daemon can verify the
/// signing principal matches the channel's policy at install time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BuilderIdentity {
    /// CI keyless signing via sigstore / Fulcio OIDC.
    ///
    /// `workflow_ref` MUST be `refs/tags/v*` — any other reference is refused
    /// at the workflow level (see `.github/workflows/release.yml` signing step
    /// `if: startsWith(github.ref, 'refs/tags/v')`).
    Ci {
        /// The fully-qualified workflow ref used at signing time, e.g.
        /// `refs/tags/v0.3.1`. Embedded verbatim from `GITHUB_REF` at CI
        /// build time.
        workflow_ref: String,
    },

    /// Operator local hardware key (YubiKey / Apple Secure Enclave).
    ///
    /// Used exclusively for `dev`-channel image signing (e.g. nightly builds
    /// distributed via the dev-channel opt-in flow).
    LocalHardware {
        /// Hex-encoded fingerprint of the hardware-resident public key, e.g.
        /// `sha256:abcdef...`. Recorded for audit; the verifier cross-checks
        /// this against its pinned public key store.
        key_fingerprint: String,
    },
}

/// Errors returned by [`validate_for_channel`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuilderIdentityError {
    /// The `dev` channel only accepts `LocalHardware` signing; CI keyless is
    /// refused because dev builds are never tag-triggered.
    #[error(
        "dev channel requires a LocalHardware builder identity; \
         CI keyless signing is only valid for tag-triggered release builds"
    )]
    DevRequiresLocalHardware,

    /// The `ent0` deployment tier forbids all dev-channel builds regardless of
    /// builder identity.
    #[error(
        "ent0 forbids dev channel: ent0 deployments only accept release-channel images \
         signed by the CI keyless builder identity on a tag-triggered workflow"
    )]
    Ent0ForbidsDev,
}

/// Validate that `identity` is permitted to sign images for `channel`.
///
/// # Rules
///
/// - `Channel::Release` and `Channel::Canary` — both `Ci` and `LocalHardware`
///   are accepted (no constraint at this layer; the cosign verifier enforces
///   the Fulcio OIDC SAN at install time for `Ci`).
/// - `Channel::Dev` — only `LocalHardware` is accepted. Returns
///   [`BuilderIdentityError::DevRequiresLocalHardware`] for `Ci`.
///
/// Ent0 rejection is handled separately by [`reject_if_ent0_dev`] because
/// `ent0` is a deployment tier, not a `Channel` variant. Call that function
/// when the deployment target is known to be ent0.
pub fn validate_for_channel(
    identity: &BuilderIdentity,
    channel: &Channel,
) -> Result<(), BuilderIdentityError> {
    match channel {
        Channel::Release | Channel::Canary => Ok(()),
        Channel::Dev => match identity {
            BuilderIdentity::LocalHardware { .. } => Ok(()),
            BuilderIdentity::Ci { .. } => Err(BuilderIdentityError::DevRequiresLocalHardware),
        },
    }
}

/// Reject a dev-channel image when the deployment target is `ent0`.
///
/// `ent0` is Emberlink's enterprise-zero deployment tier, which is pinned to
/// release-channel images only. Any `dev`-channel image — regardless of its
/// builder identity — is refused with a clear diagnostic message.
///
/// # Errors
///
/// Returns [`BuilderIdentityError::Ent0ForbidsDev`] when `channel` is
/// [`Channel::Dev`].
pub fn reject_if_ent0_dev(channel: &Channel) -> Result<(), BuilderIdentityError> {
    if *channel == Channel::Dev {
        Err(BuilderIdentityError::Ent0ForbidsDev)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_for_channel ---

    #[test]
    fn ci_identity_accepted_for_release() {
        let id = BuilderIdentity::Ci {
            workflow_ref: "refs/tags/v0.3.1".to_string(),
        };
        assert!(validate_for_channel(&id, &Channel::Release).is_ok());
    }

    #[test]
    fn local_hardware_accepted_for_release() {
        let id = BuilderIdentity::LocalHardware {
            key_fingerprint: "sha256:abcdef1234".to_string(),
        };
        assert!(validate_for_channel(&id, &Channel::Release).is_ok());
    }

    #[test]
    fn local_hardware_accepted_for_dev() {
        let id = BuilderIdentity::LocalHardware {
            key_fingerprint: "sha256:abcdef1234".to_string(),
        };
        assert!(validate_for_channel(&id, &Channel::Dev).is_ok());
    }

    #[test]
    fn ci_identity_refused_for_dev() {
        let id = BuilderIdentity::Ci {
            workflow_ref: "refs/heads/main".to_string(),
        };
        let err = validate_for_channel(&id, &Channel::Dev).unwrap_err();
        assert_eq!(err, BuilderIdentityError::DevRequiresLocalHardware);
    }

    #[test]
    fn ci_identity_accepted_for_canary() {
        let id = BuilderIdentity::Ci {
            workflow_ref: "refs/tags/v0.4.0-canary.1".to_string(),
        };
        assert!(validate_for_channel(&id, &Channel::Canary).is_ok());
    }

    // --- reject_if_ent0_dev ---

    #[test]
    fn ent0_rejects_dev_channel() {
        let err = reject_if_ent0_dev(&Channel::Dev).unwrap_err();
        assert_eq!(err, BuilderIdentityError::Ent0ForbidsDev);
    }

    #[test]
    fn ent0_allows_release_channel() {
        assert!(reject_if_ent0_dev(&Channel::Release).is_ok());
    }

    #[test]
    fn ent0_allows_canary_channel() {
        assert!(reject_if_ent0_dev(&Channel::Canary).is_ok());
    }

    // --- serialization round-trip ---

    #[test]
    fn ci_identity_serializes() {
        let id = BuilderIdentity::Ci {
            workflow_ref: "refs/tags/v0.3.1".to_string(),
        };
        let json = serde_json::to_string(&id).expect("serialize");
        let roundtrip: BuilderIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, roundtrip);
    }

    #[test]
    fn local_hardware_identity_serializes() {
        let id = BuilderIdentity::LocalHardware {
            key_fingerprint: "sha256:deadbeef".to_string(),
        };
        let json = serde_json::to_string(&id).expect("serialize");
        let roundtrip: BuilderIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, roundtrip);
    }
}
