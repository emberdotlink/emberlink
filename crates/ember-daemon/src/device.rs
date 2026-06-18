//! Device enrollment scaffold (P63.C).
//!
//! Real iCloud Passkey / WebAuthn enrollment runs through Apple's
//! `AuthenticationServices` framework on macOS and is tracked separately under
//! [`P63.C-WEBAUTHN-WIRE`]. This module ships only the typed scaffold that the
//! CLI verbs (`ember device enroll --passkey`, `ember device pair`) and the
//! eventual ceremony glue will call once the platform binding lands.
//!
//! The shape locked here:
//!
//! * [`DeviceEnrolledStub`] — the carrier the wire-up will return on success.
//!   Lined up against `core_types::events::DeviceAddedEvent` so the future
//!   patch can lift the `(device_id, public_key)` tuple straight into a
//!   real event without churn.
//! * [`DeviceEnrollError::WebAuthnNotImplemented`] — the typed error every
//!   stubbed call site returns today. Keeping it as a named variant means
//!   downstream code (CLI, daemon handlers) can match on the not-yet-wired
//!   case explicitly instead of stringly-comparing error messages.
//!
//! When P63.C-WEBAUTHN-WIRE lands it should:
//!
//! 1. Replace the body of [`issue_device_enrolled_event`] with the real
//!    persistence path (currently a TODO).
//! 2. Emit a `DeviceAdded` event onto the daemon event log via the existing
//!    `core_types::events::DeviceAddedEvent` shape.
//! 3. Drop [`DeviceEnrollError::WebAuthnNotImplemented`] (or keep it for the
//!    "feature compiled out" case).

use core_principals::PublicKeyMaterial;
use thiserror::Error;

/// Error raised by the device-enrollment scaffold.
///
/// Today every variant is the not-yet-implemented stub. The variants are
/// named so callers can pattern-match on the failure mode rather than
/// scraping a string — when the WebAuthn ceremony actually wires up under
/// P63.C-WEBAUTHN-WIRE only `WebAuthnNotImplemented` should disappear and
/// real failure modes (cancelled, timed-out, attestation-rejected, …) take
/// its place.
#[derive(Debug, Error)]
pub enum DeviceEnrollError {
    /// The WebAuthn ceremony has not been wired up yet. Tracked in
    /// `P63.C-WEBAUTHN-WIRE` — this variant is the entire failure surface
    /// of the scaffold.
    #[error(
        "WebAuthn ceremony not yet implemented; \
         see P63.C-WEBAUTHN-WIRE"
    )]
    WebAuthnNotImplemented,
}

/// Successful enrollment carrier — the data the daemon will eventually
/// turn into a `DeviceAddedEvent` once the WebAuthn ceremony lands.
///
/// Field shape mirrors [`core_types::events::DeviceAddedEvent`] so the
/// wire-up patch can drop the values straight into an event without an
/// adapter layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrolledStub {
    pub device_id: String,
    pub public_key: PublicKeyMaterial,
}

/// Persist a device-enrollment record once the WebAuthn ceremony returns
/// successfully.
///
/// **Stub:** today this always returns
/// [`DeviceEnrollError::WebAuthnNotImplemented`]. The signature is locked so
/// the CLI verbs and any future ceremony glue can call it now and have the
/// wire-up patch flip the body without disturbing call sites. See
/// `P63.C-WEBAUTHN-WIRE` for the implementation task.
///
/// TODO(P63.C-WEBAUTHN-WIRE): persist the enrollment as a real
/// `DeviceAddedEvent` on the daemon event log and return the carrier.
pub fn issue_device_enrolled_event(
    device_id: impl Into<String>,
    public_key: PublicKeyMaterial,
) -> Result<DeviceEnrolledStub, DeviceEnrollError> {
    let _ = (device_id, public_key);
    Err(DeviceEnrollError::WebAuthnNotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_principals::KeyAlgorithm;

    fn fixture_pubkey() -> PublicKeyMaterial {
        PublicKeyMaterial {
            key_id: "key-fixture".to_string(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: "deadbeef".to_string(),
        }
    }

    #[test]
    fn issue_device_enrolled_event_returns_not_implemented_stub() {
        let err = issue_device_enrolled_event("device-fixture", fixture_pubkey())
            .expect_err("scaffold must error until P63.C-WEBAUTHN-WIRE wires the ceremony");

        // Pattern-match the typed variant — callers depend on this shape,
        // not on the string rendering, so a future variant rename without a
        // call-site update would fail the build instead of silently passing.
        match err {
            DeviceEnrollError::WebAuthnNotImplemented => {}
        }
    }

    #[test]
    fn webauthn_not_implemented_message_points_at_wire_task() {
        let rendered = DeviceEnrollError::WebAuthnNotImplemented.to_string();
        assert!(
            rendered.contains("P63.C-WEBAUTHN-WIRE"),
            "stub error must point at the follow-up task; got: {rendered}"
        );
        assert!(
            rendered.contains("not yet implemented"),
            "stub error must say it's not implemented; got: {rendered}"
        );
    }
}
