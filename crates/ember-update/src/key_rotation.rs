//! image_key_rotation
//! CLASSIFICATION: PUBLIC
//!
//! Two-tier key-rotation scaffold for image signing.
//!
//! # Hierarchy
//!
//! The image-signing trust hierarchy is intentionally split into two tiers so
//! that the long-lived **root** material never directly signs an image, and
//! routine builder rotation does not require re-establishing root trust:
//!
//! 1. **Root key** — held in the `ember` CLI's local hardware key (YubiKey /
//!    Apple Secure Enclave). Never signs an image manifest. Its sole job is to
//!    issue [`RotationDelegation`] documents that authorise a particular
//!    [`BuilderIdentity`] to sign images on the root's behalf for a bounded
//!    time window. Compromise of the root requires the emergency-revoke
//!    primitive from ADR 143 (see also ADR-DRAFT-IMG-EMERGENCY-ROOT-REVOKE-QUORUM).
//!
//! 2. **Builder identity keys** — short-lived per-builder identities (CI
//!    keyless or local hardware). These are the keys that actually sign
//!    individual image manifests. Compromise of one builder identity is
//!    contained: a [`RotationDelegation`] revocation (or natural expiry plus
//!    grace) removes that identity from the trust set without touching the
//!    root.
//!
//! # Grace window
//!
//! Builder rotations overlap: when a new builder identity is delegated, the
//! outgoing identity remains valid for [`BUILDER_ROTATION_GRACE_DAYS`] past
//! its `expires_at` so that in-flight installs and air-gapped fleets can still
//! verify recently-built images while the new identity is being propagated.
//! The grace window is large (180 days) on purpose — it is sized for the
//! enterprise / air-gapped tier, not the homelab tier.
//!
//! # Channel constraints
//!
//! The matrix mirrors [`crate::builder_identity`]: `release` and `dev` accept
//! delegated builders; the `ent0` deployment tier refuses delegated builders
//! entirely and pins to direct, tag-triggered CI keyless signing. Because
//! `ent0` is a deployment tier and not a [`Channel`] variant (it is checked
//! separately at install time via [`reject_delegation_if_ent0`]), the
//! channel-scoped validator only operates on the present `Channel` variants.

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;

use crate::builder_identity::BuilderIdentity;
use crate::channel::Channel;

/// Grace-window length (in days) during which a builder delegation remains
/// acceptable past its `expires_at` so that in-flight installs and
/// air-gapped fleets can still verify recently-built images.
pub const BUILDER_ROTATION_GRACE_DAYS: i64 = 180;

/// A signed delegation document authorising a [`BuilderIdentity`] to sign
/// images on the root's behalf for a bounded time window.
///
/// The `root_signature` covers the canonical encoding of all other fields. The
/// canonical encoding is intentionally left unspecified at this scaffold layer
/// and will be defined when the delegation is wired into the image manifest
/// verifier (see ADR-DRAFT-IMG-SIGNING-AND-UPDATE-FLOW).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationDelegation {
    /// Ed25519 public key of the root that issued this delegation.
    pub root_pubkey: [u8; 32],
    /// The builder identity authorised by this delegation.
    pub builder_identity: BuilderIdentity,
    /// Issuance timestamp (UTC).
    pub issued_at: DateTime<Utc>,
    /// Expiry timestamp (UTC). After this, the delegation is no longer
    /// **active** but remains acceptable through the
    /// [`BUILDER_ROTATION_GRACE_DAYS`] grace window.
    pub expires_at: DateTime<Utc>,
    /// Ed25519 signature by `root_pubkey` over the canonical encoding of the
    /// other fields.
    pub root_signature: Vec<u8>,
}

/// Errors returned by [`validate_delegation_for_channel`] and
/// [`reject_delegation_if_ent0`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RotationError {
    /// The delegation lacked a root signature (or it was empty).
    #[error("delegation root_signature is missing or empty")]
    RootSignatureMissing,

    /// The delegation's root signature failed verification.
    #[error("delegation root_signature failed verification against the pinned root key")]
    RootSignatureInvalid,

    /// The deployment tier does not permit delegated builders (e.g. `ent0`,
    /// which is pinned to direct tag-triggered CI keyless signing).
    #[error("deployment tier forbids delegated builders; ent0 pins to direct CI keyless signing")]
    ChannelDisallowsBuilder,

    /// The delegation is outside its active window AND outside the
    /// [`BUILDER_ROTATION_GRACE_DAYS`] grace window past `expires_at`.
    #[error(
        "delegation is outside its active window and outside the {grace_days}-day grace window"
    )]
    OutsideGrace { grace_days: i64 },
}

/// Returns `true` if `now` is within the delegation's active window
/// (`issued_at <= now < expires_at`).
pub fn delegation_is_active(d: &RotationDelegation, now: DateTime<Utc>) -> bool {
    d.issued_at <= now && now < d.expires_at
}

/// Returns `true` if `now` is within the grace window: i.e. the delegation
/// either is still active, or `now <= expires_at + BUILDER_ROTATION_GRACE_DAYS`.
///
/// Note that a delegation `now < issued_at` is **not** within grace — the
/// grace window only relaxes the upper bound.
pub fn delegation_is_within_grace(d: &RotationDelegation, now: DateTime<Utc>) -> bool {
    if now < d.issued_at {
        return false;
    }
    let grace_end = d.expires_at + Duration::days(BUILDER_ROTATION_GRACE_DAYS);
    now <= grace_end
}

/// Validate that `d` is acceptable for the given channel.
///
/// At this scaffold layer the validator only enforces the channel-tier rules.
/// Signature verification, freshness, and grace-window enforcement are layered
/// on top by callers (see [`delegation_is_active`] and
/// [`delegation_is_within_grace`]).
///
/// The `ent0` deployment tier is enforced separately via
/// [`reject_delegation_if_ent0`] because `ent0` is a deployment tier rather
/// than a [`Channel`] variant — the same shape as
/// [`crate::builder_identity::reject_if_ent0_dev`].
pub fn validate_delegation_for_channel(
    d: &RotationDelegation,
    ch: Channel,
) -> Result<(), RotationError> {
    if d.root_signature.is_empty() {
        return Err(RotationError::RootSignatureMissing);
    }
    match ch {
        Channel::Release | Channel::Dev | Channel::Canary => Ok(()),
    }
}

/// Reject a delegation when the deployment target is `ent0`.
///
/// `ent0` is Emberlink's enterprise-zero deployment tier and pins to direct,
/// tag-triggered CI keyless signing (no builder delegation). Mirrors
/// [`crate::builder_identity::reject_if_ent0_dev`].
pub fn reject_delegation_if_ent0() -> Result<(), RotationError> {
    Err(RotationError::ChannelDisallowsBuilder)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_delegation(issued_at: DateTime<Utc>, expires_at: DateTime<Utc>) -> RotationDelegation {
        RotationDelegation {
            root_pubkey: [7u8; 32],
            builder_identity: BuilderIdentity::Ci {
                workflow_ref: "refs/tags/v0.3.1".to_string(),
            },
            issued_at,
            expires_at,
            root_signature: vec![0xAB; 64],
        }
    }

    #[test]
    fn delegation_active_within_window() {
        let issued = Utc::now() - Duration::days(10);
        let expires = Utc::now() + Duration::days(10);
        let d = test_delegation(issued, expires);
        assert!(delegation_is_active(&d, Utc::now()));
    }

    #[test]
    fn delegation_within_grace_after_expiry() {
        let issued = Utc::now() - Duration::days(400);
        let expires = Utc::now() - Duration::days(30);
        let d = test_delegation(issued, expires);
        // 30 days past expiry; 180-day grace window is still open.
        assert!(!delegation_is_active(&d, Utc::now()));
        assert!(delegation_is_within_grace(&d, Utc::now()));

        // 200 days past expiry; outside the 180-day grace window.
        let past_grace = expires + Duration::days(BUILDER_ROTATION_GRACE_DAYS + 1);
        assert!(!delegation_is_within_grace(&d, past_grace));
    }

    #[test]
    fn validate_delegation_for_channel_rejects_ent0() {
        // ent0 is enforced as a deployment tier (not a Channel variant), so the
        // ent0 rejection path is the dedicated helper. This mirrors the same
        // shape as `builder_identity::reject_if_ent0_dev` and the matrix
        // documented in that module: ent0 ERR ERR (always).
        let err = reject_delegation_if_ent0().unwrap_err();
        assert_eq!(err, RotationError::ChannelDisallowsBuilder);
    }

    #[test]
    fn delegation_inactive_before_issuance() {
        let issued = Utc::now() + Duration::days(5);
        let expires = Utc::now() + Duration::days(30);
        let d = test_delegation(issued, expires);
        assert!(!delegation_is_active(&d, Utc::now()));
        // Before issuance is NOT within grace — the grace window only relaxes
        // the upper bound, not the lower.
        assert!(!delegation_is_within_grace(&d, Utc::now()));
    }

    #[test]
    fn validate_rejects_missing_root_signature() {
        let issued = Utc::now() - Duration::days(1);
        let expires = Utc::now() + Duration::days(1);
        let mut d = test_delegation(issued, expires);
        d.root_signature.clear();
        let err = validate_delegation_for_channel(&d, Channel::Release).unwrap_err();
        assert_eq!(err, RotationError::RootSignatureMissing);
    }

    #[test]
    fn validate_accepts_release_and_dev() {
        let issued = Utc::now() - Duration::days(1);
        let expires = Utc::now() + Duration::days(1);
        let d = test_delegation(issued, expires);
        assert!(validate_delegation_for_channel(&d, Channel::Release).is_ok());
        assert!(validate_delegation_for_channel(&d, Channel::Dev).is_ok());
        assert!(validate_delegation_for_channel(&d, Channel::Canary).is_ok());
    }
}
