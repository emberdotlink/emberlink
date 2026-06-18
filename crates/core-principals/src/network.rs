use core_types::encoding::*;
use core_types::{Validate, ValidationError};

/// Operating mode for a relay node (007-sync-and-relays.md).
/// The protocol envelope is identical regardless of mode; mode affects only
/// admission policy at the relay process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Blind forwarding — no trust check, no source identity required.
    Open,
    /// Forward only for personas whose trust score meets the relay's threshold.
    TrustGated,
    /// Serve only an explicit allowlist of personas.
    NetworkScoped,
}

impl RelayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::TrustGated => "trust-gated",
            Self::NetworkScoped => "network-scoped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "trust-gated" => Some(Self::TrustGated),
            "network-scoped" => Some(Self::NetworkScoped),
            _ => None,
        }
    }
}

/// Sync profile determines which events a node replicates.
/// Light nodes sync only events in their trust context.
/// Full nodes replicate everything they are offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProfile {
    /// Full event store — replicates all offered events.
    Full,
    /// Light sync — only events relevant to own roots, personas, devices,
    /// trusted peers, and active recovery/storage relationships.
    Light,
}

impl SyncProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Light => "light",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(Self::Full),
            "light" => Some(Self::Light),
            _ => None,
        }
    }
}

/// Node tier in the network model (013-network-model.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeTier {
    /// Mobile light node — identity holder, no relay duty.
    MobileLight,
    /// Personal bridge node — always-on relay for close trust network.
    PersonalBridge,
    /// Community/institutional relay — configurable operating mode.
    CommunityRelay,
    /// Bootstrap/discovery service — peer discovery only.
    Bootstrap,
}

impl NodeTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MobileLight => "mobile-light",
            Self::PersonalBridge => "personal-bridge",
            Self::CommunityRelay => "community-relay",
            Self::Bootstrap => "bootstrap",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mobile-light" => Some(Self::MobileLight),
            "personal-bridge" => Some(Self::PersonalBridge),
            "community-relay" => Some(Self::CommunityRelay),
            "bootstrap" => Some(Self::Bootstrap),
            _ => None,
        }
    }

    pub fn default_sync_profile(self) -> SyncProfile {
        match self {
            Self::MobileLight => SyncProfile::Light,
            _ => SyncProfile::Full,
        }
    }

    pub fn default_relay_mode(self) -> Option<RelayMode> {
        match self {
            Self::MobileLight => None,
            Self::PersonalBridge => Some(RelayMode::NetworkScoped),
            Self::CommunityRelay => Some(RelayMode::TrustGated),
            Self::Bootstrap => Some(RelayMode::Open),
        }
    }

    pub fn has_relay_duty(self) -> bool {
        self.default_relay_mode().is_some()
    }
}

/// Relay admission decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAdmission {
    Accept,
    Reject { reason: String },
}

// ---------------------------------------------------------------------------
// Admission token (trust-gated relay authentication)
// ---------------------------------------------------------------------------

use crate::TrustThreshold;

/// A signed token asserting that a persona meets a trust threshold, presented
/// to a trust-gated relay as proof of admission. The relay verifies the issuer
/// signature and checks that the issuer is in its trust set.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionToken {
    pub token_id: String,
    pub persona_id: String,
    pub issuer_persona_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub threshold_met: TrustThreshold,
    /// Hex-encoded signature from the issuer over the canonical token fields.
    pub issuer_signature_hex: String,
}

impl AdmissionToken {
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str("type=admission-token\n");
        out.push_str("token_id=");
        out.push_str(&self.token_id);
        out.push('\n');
        out.push_str("persona_id=");
        out.push_str(&self.persona_id);
        out.push('\n');
        out.push_str("issuer_persona_id=");
        out.push_str(&self.issuer_persona_id);
        out.push('\n');
        out.push_str("issued_at=");
        out.push_str(&self.issued_at.to_string());
        out.push('\n');
        out.push_str("expires_at=");
        out.push_str(&self.expires_at.to_string());
        out.push('\n');
        out.push_str("threshold_met=");
        out.push_str(&format!("{:.6}", self.threshold_met.value()));
        out.push('\n');
        out.into_bytes()
    }
}

impl Validate for AdmissionToken {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.token_id, "token id")?;
        validate_non_empty(&self.persona_id, "persona id")?;
        validate_non_empty(&self.issuer_persona_id, "issuer persona id")?;
        validate_non_empty(&self.issuer_signature_hex, "issuer signature")?;
        if self.expires_at <= self.issued_at {
            return Err(ValidationError::new(
                "admission token expiry must be after issue time",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Invite payload types (013-network-model.md — viral growth mechanism)
// ---------------------------------------------------------------------------

/// An invite payload encodes the data needed to bootstrap a new user's trust
/// context. The invite link carries this payload so that a new user can create
/// a root+persona and immediately redeem the inviter's trust attestation.
///
/// See 013-network-model.md "Viral Growth Mechanism" for the full flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    /// Unique identifier for this invite.
    pub invite_id: String,
    /// The inviter's persona ID (the persona extending trust).
    pub inviter_persona_id: String,
    /// Ephemeral key commitment: a public key the invitee will use to decrypt
    /// the sealed attestation. The corresponding private key is delivered
    /// out-of-band (e.g., embedded in the invite link).
    pub ephemeral_public_key: String,
    /// Relay endpoint descriptor where the invitee's client should sync on
    /// first contact. This is a transport-layer hint, not a trust authority.
    pub relay_endpoint: EndpointDescriptor,
    /// The trust attestation payload, sealed (encrypted) to the ephemeral key.
    /// The invitee decrypts this after creating their root+persona to receive
    /// the inviter's initial TrustAttestation.
    pub sealed_attestation: Vec<u8>,
    /// Invite scope and constraints.
    pub scope: InviteScope,
}

/// Constraints on invite redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteScope {
    /// Whether this invite can only be redeemed once.
    pub single_use: bool,
    /// Optional expiry as seconds since UNIX epoch. None means no expiry.
    pub expires_at: Option<u64>,
}

impl InviteScope {
    pub fn single_use() -> Self {
        Self {
            single_use: true,
            expires_at: None,
        }
    }

    pub fn single_use_with_expiry(expires_at: u64) -> Self {
        Self {
            single_use: true,
            expires_at: Some(expires_at),
        }
    }

    pub fn is_expired(&self, now_epoch_secs: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_epoch_secs >= exp)
    }
}

// --- Sync/relay structural types ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCursor {
    pub peer_id: String,
    pub last_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEnvelope {
    pub id: String,
    pub opaque_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBatch {
    pub id: String,
    pub event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub peer_id: String,
    pub device_id: String,
    pub transport_hint: String,
}

impl Validate for EndpointDescriptor {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.peer_id, "peer id")?;
        validate_non_empty(&self.device_id, "device id")?;
        validate_non_empty(&self.transport_hint, "transport hint")
    }
}
