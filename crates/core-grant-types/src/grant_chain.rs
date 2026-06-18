//! core-grant-types::grant_chain — Biscuit-inspired grant chain protocol types.
//!
//! Per ADR 073 (composite-grant shape). Migrated from
//! `core-types/src/storage.rs` lines 464-1603, 1905-1998, 2136-2150 per
//! ADR 156 §step 3 — these types were squatting in storage.rs as a
//! consequence of historical co-location with the storage wire types,
//! not because they shared a concern.

use core_event_types::PresentationAudienceKind;
use core_types::encoding::*;
use core_types::{CanonicalEncode, Validate, ValidationError};
use serde::{Deserialize, Serialize};

// --- Access grant types ---

/// Logical identifier of an ADR 200 unified Principal when it appears in grant
/// issuer attribution.
///
/// Some compatibility field names in this crate still say `persona_id` while
/// downstream storage and UI surfaces migrate. Those fields carry this value;
/// they do not create a second IdentityRoot-vs-Persona issuer namespace.
pub type PrincipalId = String;

/// UX-layer classification of a grant recipient.
/// Not a new transport primitive — layered on top of Peer/Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientProfile {
    Human,
    Agent,
    Service,
}

impl RecipientProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "human" => Some(Self::Human),
            "agent" => Some(Self::Agent),
            "service" => Some(Self::Service),
            _ => None,
        }
    }
}

// ============================================================================
// Composite Grant — ADR 073
// ============================================================================
//
// A Grant is a signed, append-only chain of blocks (Biscuit-style), each
// carrying one or more IAM-shaped Statements. One envelope, one approval,
// one receipt, one revocation cascade. Per-statement budgets are the
// primitive's novel axis.

/// Lifecycle status of a grant. See ADR 073.
///
/// `Expired` and `Pending` are derived at query time from timestamps;
/// `Active`, `Paused`, `Revoked`, `Abandoned`, and `ExhaustedByBudget`
/// are persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    Active,
    /// Human-requested freeze. No metering accrues; not a terminal state.
    Paused,
    Revoked,
    /// Terminal recovery disposition: the grant is intentionally not rebuilt.
    Abandoned,
    Expired,
    Pending,
    /// Terminal state: at least one statement's budget has been exhausted
    /// such that no applicable-statement set has remaining capacity.
    ExhaustedByBudget,
}

impl GrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
            Self::Abandoned => "abandoned",
            Self::Expired => "expired",
            Self::Pending => "pending",
            Self::ExhaustedByBudget => "exhausted_by_budget",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            "revoked" => Some(Self::Revoked),
            "abandoned" => Some(Self::Abandoned),
            "expired" => Some(Self::Expired),
            "pending" => Some(Self::Pending),
            "exhausted_by_budget" | "expired_by_budget" => Some(Self::ExhaustedByBudget),
            _ => None,
        }
    }

    /// Derive the effective status from stored status and timestamps.
    pub fn derive(
        stored_status: &str,
        not_before: Option<u64>,
        expires_at: Option<u64>,
        now: u64,
    ) -> Self {
        if stored_status == "revoked" {
            return Self::Revoked;
        }
        if stored_status == "abandoned" {
            return Self::Abandoned;
        }
        if stored_status == "exhausted_by_budget" || stored_status == "expired_by_budget" {
            return Self::ExhaustedByBudget;
        }
        if stored_status == "paused" {
            return Self::Paused;
        }
        if let Some(nb) = not_before
            && now < nb
        {
            return Self::Pending;
        }
        if let Some(exp) = expires_at
            && now > exp
        {
            return Self::Expired;
        }
        Self::Active
    }
}

/// Access duration model for a grant envelope. Orthogonal to the statements
/// inside — a Standing grant can still carry budget-capped statements that
/// self-expire on exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrantMode {
    /// One disclosure or approval, then done.
    #[default]
    OneShot,
    /// Short-lived, refreshable within existing scope.
    Renewable,
    /// Durable ongoing relationship until explicit revocation.
    Standing,
}

impl GrantMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OneShot => "one_shot",
            Self::Renewable => "renewable",
            Self::Standing => "standing",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "one_shot" => Some(Self::OneShot),
            "renewable" => Some(Self::Renewable),
            "standing" => Some(Self::Standing),
            _ => None,
        }
    }
}

// --- Unified Grant primitive (ADR 072) ---
//
// The four additive fields below generalize `AccessGrant` into the unified
// authority object for every resource an agent might consume. A "credential
// grant" is just a Grant with `resource_type = Credential`. A "token budget
// grant" is just a Grant with `resource_type = Session` and `budget.tokens`
// set. A "spending grant" is `Payment + budget.cents`. Same primitive, same
// UX, same audit log, same revocation semantics, same downhill attenuation
// rules.

/// Kind of resource an agent consumes through a grant.
///
/// See ADR 072 §"The primitive: the unified Grant." Extensible — additional
/// variants will be added as new grant classes come online (attestation scope,
/// compute budgets, payment surfaces, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// Credential grants — the original shape of `AccessGrant`. An agent gets
    /// bounded use of a stored credential without the credential itself.
    #[default]
    Credential,
    /// Session grants — LLM/compute sessions metered by tokens, requests, or
    /// wall-clock seconds.
    Session,
    /// Payment grants — bounded spend authority (x402 and sibling surfaces).
    Payment,
    /// Compute grants — bounded workload / container / GPU time.
    Compute,
    /// Time grants — bounded human attention or calendar windows.
    Time,
    /// Recovery grants — bounded recovery-plane actions such as guardian
    /// enrollment offers.
    Recovery,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Session => "session",
            Self::Payment => "payment",
            Self::Compute => "compute",
            Self::Time => "time",
            Self::Recovery => "recovery",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "credential" => Some(Self::Credential),
            "session" => Some(Self::Session),
            "payment" => Some(Self::Payment),
            "compute" => Some(Self::Compute),
            "time" => Some(Self::Time),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }
}

impl TryFrom<&str> for ResourceType {
    type Error = ValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value).ok_or_else(|| {
            ValidationError::invalid_format(format!("unknown resource_type: {value}"))
        })
    }
}

/// Optional ceiling values attached to a grant. `None` on every field (or on
/// the whole `Option<Budget>`) means TTL-only — the existing pre-ADR-072
/// behavior. All counters are integer-valued to keep audit math exact; `cents`
/// is integer cents (no fractional currency).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    /// Integer cents. No float, no fractional currency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cents: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_hours: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_secs: Option<u64>,
}

impl Budget {
    /// True when no ceiling is set on any axis. A `Budget` with
    /// `is_none_set() == true` is functionally equivalent to `Option::None`.
    pub fn is_none_set(&self) -> bool {
        self.tokens.is_none()
            && self.cents.is_none()
            && self.requests.is_none()
            && self.workload_hours.is_none()
            && self.wall_clock_secs.is_none()
    }
}

/// Running tally of consumption against a grant's `Budget`. Always present
/// (defaults to zeros); the absence of a budget does not imply the absence of
/// usage tracking — even TTL-only grants may accumulate usage for audit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub tokens: u64,
    /// Integer-cent display value. Derived from `cents_micro` at increment
    /// time so receipt JSON / audit rows stay human-readable; do NOT use
    /// for budget enforcement (sub-cent calls truncate to 0). The
    /// authoritative budget axis is `cents_micro`.
    #[serde(default)]
    pub cents: u64,
    #[serde(default)]
    pub requests: u64,
    #[serde(default)]
    pub workload_hours: u64,
    #[serde(default)]
    pub wall_clock_secs: u64,
    /// Epoch seconds when the usage tally was last updated. Zero on a freshly
    /// created grant that has never been exercised.
    #[serde(default)]
    pub last_updated: u64,
    /// Sub-cent precision accumulator (cents × 10⁶ = micro-cents).
    /// Authoritative for budget enforcement: `has_budget_remaining` and
    /// `emit_threshold_crossings` compare this against the budget cap
    /// scaled to the same unit. Without this, a single Haiku-4.5 call
    /// (~0.1¢ per call) rounds to 0¢ via integer division and the cap
    /// can never accumulate enough to trip — DEMO-MAY3-WEDGE-METER-WIRE.
    /// Defaults to 0 on legacy grants; the next `increment_statement_usage`
    /// call re-derives the displayed `cents` from this field, so
    /// pre-existing (non-zero `cents`, zero `cents_micro`) grants flush
    /// their legacy display value on first new metering — acceptable for
    /// v0 (no rollback ceremony).
    ///
    /// `skip_serializing_if` so a zero value is omitted from canonical
    /// encoding — preserves the grant-block-v1 signature bytes for any
    /// grant that hasn't yet accumulated sub-cent usage (the field is
    /// invisible to signers/verifiers until the meter touches it).
    /// Once a grant has been metered, the field appears in the canonical
    /// bytes and re-signing flows through the same persona key path —
    /// no version bump needed because the field is additive and zero-
    /// preserving for unaffected chains.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub cents_micro: u64,
}

/// Serde helper for `Usage::cents_micro` — `skip_serializing_if`
/// predicate that returns `true` when the field is its default zero.
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Agent attestation posture for a grant. First-class field today (ADR 072 §
/// "Attestation-bound grants"); enforcement is Phase 2 + Phase 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// MVS default: the daemon trusts the human at the keyboard but has no
    /// cryptographic binding to the agent binary. Local-dev only — not
    /// acceptable for shared team policies in Phase 2.
    #[default]
    UnattestedLocalDev,
    /// The agent is running inside an Ember-managed sandbox (ADR 070). The
    /// sandbox identifier is recorded in `sandbox_id`.
    SandboxContained,
    /// The agent binary hash and signer are recorded; verification is policy-
    /// gated.
    SignedBinary,
    /// The agent presents a SPIFFE identity.
    Spiffe,
    /// The agent runs inside a TEE and presents an attestation quote.
    Tee,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnattestedLocalDev => "unattested_local_dev",
            Self::SandboxContained => "sandbox_contained",
            Self::SignedBinary => "signed_binary",
            Self::Spiffe => "spiffe",
            Self::Tee => "tee",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unattested_local_dev" => Some(Self::UnattestedLocalDev),
            "sandbox_contained" => Some(Self::SandboxContained),
            "signed_binary" => Some(Self::SignedBinary),
            "spiffe" => Some(Self::Spiffe),
            "tee" => Some(Self::Tee),
            _ => None,
        }
    }
}

/// Attestation metadata bound to a grant. Every field except `status` is
/// optional — the shape is future-proof for SPIFFE/TEE enforcement without
/// blocking the local-dev demo path today.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBinding {
    #[serde(default)]
    pub status: AttestationStatus,
    /// Runtime label — `"claude_code"`, `"openclaw"`, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// sha256 hex of the agent binary, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_hash: Option<String>,
    /// ed25519 pubkey hex or DID of the signer, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    /// Base64 TEE attestation quote. Not parsed yet — stored opaquely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_quote: Option<String>,
}

// --- Statement -------------------------------------------------------------
//
// IAM-shaped clause. One grant block carries one or more. Evaluator is
// AND-all over *applicable* statements (action matches AND resource covers).
// Allow-only — Deny lives in policy.toml, not inside the grant. See ADR 073.

/// Stable identifier for a statement within a block. Unique within its block
/// but NOT globally unique — receipts reference (grant_id, block_index, sid).
pub type StatementId = String;

/// A positive enumeration of action verbs. Colon-delimited namespaces
/// (e.g. `github:pull_request:create`, `llm:generate`, `x402:pay`). No
/// NotAction variant exists — the shape designs that footgun out.
pub type Action = String;

/// Typed resource selector. Glob and Regex are distinct variants so the
/// issuer UI can warn on unbounded wildcards at issue time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceSelector {
    Exact {
        value: String,
    },
    /// Shell-style glob, anchored on both ends. `*` matches any run of chars.
    Glob {
        pattern: String,
    },
    /// Glob with a structured branch-path subtarget. `primary_glob` matches
    /// the resource (`owner/repo`), `subtarget_glob` is a secondary check
    /// applied by the resolver against an out-of-band field (e.g. the branch
    /// extracted from the request URI). `covers()` only validates the primary
    /// glob — subtarget enforcement is the resolver's job because the
    /// concrete subtarget value (branch name) is not part of `resource`.
    /// Issued from 4-segment legacy scopes like
    /// `github:push:owner/repo:feat/*` (P69E.5c).
    GlobWithSubtarget {
        primary_glob: String,
        subtarget_glob: String,
    },
    /// Regex anchored on both ends. Evaluation stub for now — issuers may
    /// declare but evaluator in core-policy is the authoritative matcher.
    Regex {
        pattern: String,
    },
    /// Unconstrained. Issuer UI should require explicit confirmation.
    Any,
}

impl ResourceSelector {
    /// True iff this selector covers the given concrete resource string.
    ///
    /// For `GlobWithSubtarget` only the `primary_glob` is consulted —
    /// subtarget matching is the resolver's responsibility (it has access
    /// to the request URI / method that carries the branch). A primary
    /// match with a missing subtarget should produce
    /// `denied_subtarget_scope`, NOT `denied_no_applicable_statement`.
    pub fn covers(&self, resource: &str) -> bool {
        match self {
            Self::Exact { value } => value == resource,
            Self::Glob { pattern } => glob_matches(pattern, resource),
            Self::GlobWithSubtarget { primary_glob, .. } => glob_matches(primary_glob, resource),
            Self::Regex { .. } => false, // evaluator lives in core-policy
            Self::Any => true,
        }
    }

    /// Subtarget glob if this selector carries one. Used by the proxy
    /// resolver to route to `denied_subtarget_scope` instead of
    /// `denied_no_applicable_statement` on a primary-but-not-subtarget
    /// match.
    pub fn subtarget_glob(&self) -> Option<&str> {
        match self {
            Self::GlobWithSubtarget { subtarget_glob, .. } => Some(subtarget_glob.as_str()),
            _ => None,
        }
    }

    /// True iff this selector is structurally unbounded (`Any` or `*`).
    pub fn is_unbounded(&self) -> bool {
        matches!(self, Self::Any) || matches!(self, Self::Glob { pattern } if pattern == "*")
    }
}

/// Condition predicate. AND-all across a statement's Vec<Condition>. Every
/// condition names its `field` explicitly. Evaluator contract: if the named
/// field is ABSENT from the invocation context, the condition is treated as
/// "not applicable to this call" — NOT passing, NOT denying. Authors who
/// want "deny if absent" must invert via `NotOneOf` or design the field in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    Subpath {
        field: String,
        prefix: String,
    },
    OneOf {
        field: String,
        values: Vec<String>,
    },
    NotOneOf {
        field: String,
        values: Vec<String>,
    },
    Range {
        field: String,
        min: Option<i64>,
        max: Option<i64>,
    },
    Cidr {
        field: String,
        cidrs: Vec<String>,
    },
    UrlPattern {
        field: String,
        pattern: String,
    },
    Regex {
        field: String,
        pattern: String,
    },
    TimeWindow {
        start_secs_of_day: u32,
        end_secs_of_day: u32,
    },
    MerchantAllowlist {
        merchants: Vec<String>,
    },
}

/// HITL handoff shape. When a block carries an `approval` challenge it is in
/// `Pending` until the human completes the method. Shared across issuance,
/// extension, threshold crossings, and grant-downhill operations — the single
/// protocol handle for ADR 047 + ADR 036 to plug into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub method: ApprovalMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    pub expires_in_secs: u32,
    pub poll_interval_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMethod {
    Notification,
    Passkey,
    YubiKey,
    Ciba,
    DeviceFlow,
}

/// Per-Statement downhill delegate facet (ADR 205 §6; subsumes the old
/// StandingGrant spawn_max_depth). `None` on a Statement = not
/// allowed to delegate further (fail-closed default);
/// `Some { max_depth }` = may delegate downhill for `max_depth` more hops.
/// Attenuates downhill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanDelegate {
    pub max_depth: u32,
}

/// One IAM-shaped clause inside a grant block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub sid: StatementId,
    pub resource_type: ResourceType,
    pub actions: Vec<Action>,
    pub resource: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can_delegate: Option<CanDelegate>,
}

impl Statement {
    /// True iff this statement is applicable to a call with the given action
    /// verb and concrete resource string.
    pub fn applicable_to(&self, action: &str, resource: &str) -> bool {
        self.actions.iter().any(|a| a == action) && self.resource.covers(resource)
    }

    /// True iff this statement's budget still has capacity on every set axis.
    /// Returns true when `budget` is `None` (TTL-only).
    pub fn has_budget_remaining(&self) -> bool {
        let Some(b) = &self.budget else { return true };
        if let Some(cap) = b.tokens
            && self.usage.tokens >= cap
        {
            return false;
        }
        if let Some(cap) = b.cents {
            // DEMO-MAY3-WEDGE-METER-WIRE: budget enforcement runs on the
            // sub-cent `cents_micro` accumulator. Sub-cent calls (typical for
            // Haiku-4.5 pricing) round the integer `cents` field to 0 per
            // call, so a cents-only check would never trip. Compare against
            // the cap scaled to micro-cents (cap × 10⁶); fall back to the
            // legacy `cents` axis when cents_micro is unset (zero) so
            // pre-fix grants stored under the old representation still
            // exhaust correctly.
            let cap_micro = cap.saturating_mul(1_000_000);
            if self.usage.cents_micro > 0 {
                if self.usage.cents_micro >= cap_micro {
                    return false;
                }
            } else if self.usage.cents >= cap {
                return false;
            }
        }
        if let Some(cap) = b.requests
            && self.usage.requests >= cap
        {
            return false;
        }
        if let Some(cap) = b.workload_hours
            && self.usage.workload_hours >= cap
        {
            return false;
        }
        if let Some(cap) = b.wall_clock_secs
            && self.usage.wall_clock_secs >= cap
        {
            return false;
        }
        true
    }
}

/// Proposal-shape sibling of [`Statement`]. Carries the per-statement clauses
/// of a [`GrantProposal`] before it is approved into a runtime [`AccessGrant`].
/// No `sid` or `usage` — both are minted at grant-creation time, not at proposal.
///
/// Per ADR 122 (composite-grant runtime) + ADR 123 (Construct collapse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementProposal {
    pub resource_type: ResourceType,
    pub credential_name: String,
    pub actions: Vec<Action>,
    pub resource: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Proposal-shape sibling of [`AccessGrant`]. Submitted to emberd to start the
/// propose-then-approve flow; on approval, materializes into a runtime
/// [`AccessGrant`].
///
/// `skill_ref` is an advisory pointer to the originating Construct/skill
/// that asked for the grant; emberd does not enforce on it. Per ADR 123.
///
/// Per ADR 122 (composite-grant runtime) + ADR 123 (Construct collapse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantProposal {
    pub persona_id: String,
    pub statements: Vec<StatementProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// --- Block + SignedBlock --------------------------------------------------
//
// A grant is a signed, append-only chain of blocks (Biscuit-style). Block 0
// is the authority, issued under the Principal's verification key. Each subsequent
// block is an attenuation signed by the previous block's `pubkey_next`.
// Reorder or remove a block and the signature chain breaks.

/// Unsigned block content. Carries statements plus block-level metadata.
/// Canonical-encoded bytes of this struct are what the previous block's
/// `pubkey_next` signs to produce the next `SignedBlock.signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub statements: Vec<Statement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Principal that minted this block.
    ///
    /// Block 0 is the AccessGrant issuer. Later blocks are the Principals that
    /// delegate the grant downhill. The field name is intentionally generic:
    /// both a self-parented root Principal and a child Durable/Runtime Persona
    /// use the same `PrincipalId` path.
    pub issued_by: String,
    pub issued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalChallenge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Block plus its Biscuit-style signature. `pubkey_next` is the public key
/// that MUST sign the *next* appended block; the current block's bytes are
/// signed by the previous block's `pubkey_next` — or, for block 0, by the
/// issuer Principal's verification key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBlock {
    pub block: Block,
    /// Hex-encoded Ed25519 public key that will sign the NEXT appended block.
    pub pubkey_next: String,
    /// Hex-encoded Ed25519 signature over canonical-encoded `block` bytes.
    pub signature: String,
}

// --- Grant envelope -------------------------------------------------------

/// Local-only runtime object representing an AccessGrant authority envelope.
/// Never appears in the protocol event log or crosses the disclosure boundary.
///
/// Per ADR 073, a grant is a signed chain of blocks. Block 0 is the authority
/// minted under the issuing Principal; subsequent blocks are attenuations.
/// Every block carries typed `Statement`s with per-statement budgets and
/// conditions. Issuer attribution and attestation live on the envelope, not
/// inside statements — a grant is always under exactly one unified Principal.
// identity_root_persona_core_grant_types_adaptation_landed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrant {
    pub id: String,
    pub version: u32,
    /// Compatibility field name for the grant issuer.
    ///
    /// The value is a unified ADR 200 [`PrincipalId`]. It may name the
    /// self-parented root Principal, a Durable Persona Principal, or a Runtime
    /// Persona Principal. It must not be interpreted as a distinct protocol
    /// type or a Persona-only issuer universe.
    pub issuing_persona_id: String,
    pub recipient_kind: PresentationAudienceKind,
    pub recipient_id: String,
    pub recipient_profile: RecipientProfile,
    pub status: GrantStatus,
    pub mode: GrantMode,
    /// Append-only signed chain. First element is block 0 (the authority);
    /// subsequent elements are attenuations.
    pub blocks: Vec<SignedBlock>,
    /// Agent attestation posture. Envelope-level; ADR 072 §"Attestation."
    pub attestation: AttestationBinding,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
    pub revoked_reason: Option<String>,
    pub last_used_at: Option<u64>,
    pub label: Option<String>,
}

impl AccessGrant {
    /// Unified Principal issuer for this grant.
    pub fn issuer_principal_id(&self) -> &str {
        &self.issuing_persona_id
    }

    /// Build a grant with a single block containing a single statement. Useful
    /// for tests and the simplest demo path (one credential, no budget).
    pub fn single_statement(
        id: impl Into<String>,
        issuer_principal_id: impl Into<String>,
        recipient_id: impl Into<String>,
        statement: Statement,
        pubkey_next: impl Into<String>,
        signature: impl Into<String>,
        issued_at: u64,
    ) -> Self {
        let issuer_principal_id = issuer_principal_id.into();
        let block = Block {
            statements: vec![statement],
            nbf: None,
            expires_at: None,
            issued_by: issuer_principal_id.clone(),
            issued_at,
            approval: None,
            note: None,
        };
        Self {
            id: id.into(),
            version: 1,
            issuing_persona_id: issuer_principal_id,
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: recipient_id.into(),
            recipient_profile: RecipientProfile::Human,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: pubkey_next.into(),
                signature: signature.into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: issued_at,
            updated_at: issued_at,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    /// Walk every (block_index, statement) pair across the whole chain, in
    /// chain order. Useful for the authorize walker and summary projections.
    pub fn statements(&self) -> impl Iterator<Item = (usize, &Statement)> {
        self.blocks
            .iter()
            .enumerate()
            .flat_map(|(i, sb)| sb.block.statements.iter().map(move |s| (i, s)))
    }

    /// Total statement count across all blocks.
    pub fn statement_count(&self) -> usize {
        self.blocks.iter().map(|sb| sb.block.statements.len()).sum()
    }

    /// Effective grant expiry = earliest `expires_at` across all blocks.
    /// `None` means no block declared an expiry (open-ended).
    pub fn effective_expires_at(&self) -> Option<u64> {
        self.blocks
            .iter()
            .filter_map(|sb| sb.block.expires_at)
            .min()
    }

    /// Effective not-before = latest `nbf` across all blocks.
    pub fn effective_nbf(&self) -> Option<u64> {
        self.blocks.iter().filter_map(|sb| sb.block.nbf).max()
    }

    /// Derive the effective status from both the stored status field and
    /// the block-level timestamps. A grant stored as `Active` but whose
    /// `effective_expires_at` has passed is `Expired`; a grant whose
    /// `effective_nbf` is in the future is `Pending`. Terminal statuses
    /// (`Revoked`, `Abandoned`, `ExhaustedByBudget`) and `Paused` are never
    /// overridden by timestamps - only `Active` can be demoted by TTL or nbf.
    pub fn effective_status(&self, now_secs: u64) -> GrantStatus {
        GrantStatus::derive(
            self.status.as_str(),
            self.effective_nbf(),
            self.effective_expires_at(),
            now_secs,
        )
    }

    /// Distinct resource_types present across all statements, in first-seen
    /// order. Used by the dashboard to render the persona-chip badges.
    pub fn resource_types(&self) -> Vec<ResourceType> {
        let mut seen = Vec::new();
        for (_i, s) in self.statements() {
            if !seen.contains(&s.resource_type) {
                seen.push(s.resource_type);
            }
        }
        seen
    }

    /// Aggregate usage snapshot — the dimensional sum of every statement's
    /// usage. View-only; the event log is the authoritative source.
    pub fn aggregate_usage(&self) -> Usage {
        let mut u = Usage::default();
        for (_i, s) in self.statements() {
            u.tokens = u.tokens.saturating_add(s.usage.tokens);
            u.cents = u.cents.saturating_add(s.usage.cents);
            u.requests = u.requests.saturating_add(s.usage.requests);
            u.workload_hours = u.workload_hours.saturating_add(s.usage.workload_hours);
            u.wall_clock_secs = u.wall_clock_secs.saturating_add(s.usage.wall_clock_secs);
            if s.usage.last_updated > u.last_updated {
                u.last_updated = s.usage.last_updated;
            }
        }
        u
    }
}

/// Summary view for grant listings. Aggregates across statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantSummary {
    pub id: String,
    pub label: Option<String>,
    /// Compatibility field name; value is the unified Principal issuer id.
    pub issuing_persona_id: String,
    pub recipient_kind: PresentationAudienceKind,
    pub recipient_id: String,
    pub recipient_profile: RecipientProfile,
    pub status: GrantStatus,
    pub mode: GrantMode,
    pub block_count: usize,
    pub statement_count: usize,
    pub resource_types: Vec<ResourceType>,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub aggregate_usage: Usage,
}

/// A lifecycle event in the grant audit history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantHistoryEntry {
    pub history_id: String,
    pub grant_id: String,
    pub version: u32,
    pub action: String,
    pub timestamp: u64,
    /// Canonical JSON snapshot of `AccessGrant.blocks` at the time of this
    /// event, when the action mutated the chain. `None` for lifecycle events
    /// that did not alter the blocks (e.g. `paused`, `last_used`).
    pub blocks_snapshot: Option<String>,
    pub note: Option<String>,
}

/// Full detail view of a grant including linked artifacts and history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessGrantDetail {
    pub grant: AccessGrant,
    pub linked_artifact_count: usize,
    pub linked_artifact_ids: Vec<String>,
    pub history: Vec<AccessGrantHistoryEntry>,
}

// --- small helpers for ResourceSelector -----------------------------------

/// Minimal shell-style glob matcher. `*` matches any run of characters
/// (including empty); `?` matches exactly one character. Anchored on both
/// ends. Sufficient for Emberlink's MVS; richer patterns should use Regex.
fn glob_matches(pattern: &str, s: &str) -> bool {
    fn inner(p: &[u8], s: &[u8]) -> bool {
        let (mut pi, mut si) = (0usize, 0usize);
        let (mut star_pi, mut star_si) = (usize::MAX, 0usize);
        while si < s.len() {
            if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
                pi += 1;
                si += 1;
            } else if pi < p.len() && p[pi] == b'*' {
                star_pi = pi;
                star_si = si;
                pi += 1;
            } else if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_si += 1;
                si = star_si;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == b'*' {
            pi += 1;
        }
        pi == p.len()
    }
    inner(pattern.as_bytes(), s.as_bytes())
}

#[cfg(test)]
mod composite_grant_tests {
    use super::*;

    fn stmt_credential_github() -> Statement {
        Statement {
            sid: "GitHubPR".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:pull_request:create".into()],
            resource: ResourceSelector::Glob {
                pattern: "emberdotlink/*".into(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    fn stmt_session_tokens() -> Statement {
        Statement {
            sid: "ClaudeTokens".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".into(),
            },
            budget: Some(Budget {
                tokens: Some(20_000),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    fn stmt_payment() -> Statement {
        Statement {
            sid: "InfraSpend".into(),
            resource_type: ResourceType::Payment,
            actions: vec!["x402:pay".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                cents: Some(50),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![Condition::MerchantAllowlist {
                merchants: vec!["openai.com".into(), "anthropic.com".into()],
            }],
            can_delegate: None,
        }
    }

    #[test]
    fn resource_selector_glob_covers_expected() {
        let g = ResourceSelector::Glob {
            pattern: "emberdotlink/*".into(),
        };
        assert!(g.covers("emberdotlink/sandbox"));
        assert!(g.covers("emberdotlink/anything-here"));
        assert!(!g.covers("other/repo"));
        assert!(!g.covers("emberdotlink"));
    }

    #[test]
    fn resource_selector_any_covers_everything() {
        let a = ResourceSelector::Any;
        assert!(a.covers(""));
        assert!(a.covers("literally anything"));
    }

    #[test]
    fn resource_selector_exact_is_exact() {
        let e = ResourceSelector::Exact {
            value: "emberdotlink/sandbox".into(),
        };
        assert!(e.covers("emberdotlink/sandbox"));
        assert!(!e.covers("emberdotlink/sandbox-demo"));
    }

    #[test]
    fn statement_applicable_only_when_action_and_resource_match() {
        let s = stmt_credential_github();
        assert!(s.applicable_to("github:pull_request:create", "emberdotlink/sandbox"));
        assert!(!s.applicable_to("github:pull_request:merge", "emberdotlink/sandbox"));
        assert!(!s.applicable_to("github:pull_request:create", "other/repo"));
    }

    #[test]
    fn statement_has_budget_remaining_honors_every_axis() {
        let mut s = stmt_session_tokens();
        assert!(s.has_budget_remaining());
        s.usage.tokens = 19_999;
        assert!(s.has_budget_remaining());
        s.usage.tokens = 20_000;
        assert!(!s.has_budget_remaining());
    }

    #[test]
    fn composite_grant_bundles_three_resource_types_in_one_envelope() {
        let block = Block {
            statements: vec![
                stmt_credential_github(),
                stmt_session_tokens(),
                stmt_payment(),
            ],
            nbf: None,
            expires_at: Some(1_800),
            issued_by: "principal_work".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant_01".into(),
            version: 1,
            issuing_persona_id: "principal_work".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent_claude_code".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: Some("Work: coding agent".into()),
        };

        assert_eq!(grant.statement_count(), 3);
        assert_eq!(grant.resource_types().len(), 3);
        assert!(grant.resource_types().contains(&ResourceType::Credential));
        assert!(grant.resource_types().contains(&ResourceType::Session));
        assert!(grant.resource_types().contains(&ResourceType::Payment));
        assert_eq!(grant.effective_expires_at(), Some(1_800));
    }

    #[test]
    fn recovery_resource_type_round_trips() {
        assert_eq!(ResourceType::Recovery.as_str(), "recovery");
        assert_eq!(
            ResourceType::parse("recovery"),
            Some(ResourceType::Recovery)
        );
    }

    #[test]
    fn block_canonical_encode_is_deterministic_and_round_trips() {
        let block = Block {
            statements: vec![
                stmt_credential_github(),
                stmt_session_tokens(),
                stmt_payment(),
            ],
            nbf: None,
            expires_at: Some(1_800),
            issued_by: "principal_work".into(),
            issued_at: 42,
            approval: None,
            note: Some("hello".into()),
        };

        let encoded = block.canonical_encode();
        // Prefix namespaces the canonical encoding version.
        assert!(
            encoded.starts_with(b"type=grant-block-v1\n"),
            "canonical encoding must carry a version prefix"
        );

        // Stability: repeated encoding produces identical bytes.
        assert_eq!(block.canonical_encode(), encoded);

        // Round-trip: decode the JSON body back to a Block and re-encode —
        // bytes must be byte-identical. This catches any non-determinism
        // sneaking into the transitive serde graph (e.g. a future HashMap).
        let json_body = &encoded[b"type=grant-block-v1\n".len()..];
        let decoded: Block = serde_json::from_slice(json_body)
            .expect("canonical encoding round-trips through serde_json");
        assert_eq!(decoded.canonical_encode(), encoded);
        assert_eq!(decoded, block);
    }

    #[test]
    fn block_canonical_encode_differs_on_material_change() {
        let base = Block {
            statements: vec![stmt_credential_github()],
            nbf: None,
            expires_at: None,
            issued_by: "principal_a".into(),
            issued_at: 10,
            approval: None,
            note: None,
        };
        let mut tampered = base.clone();
        tampered.issued_at = 11;
        assert_ne!(base.canonical_encode(), tampered.canonical_encode());

        let mut mutated_stmt = base.clone();
        mutated_stmt.statements[0].sid = "DifferentSid".into();
        assert_ne!(base.canonical_encode(), mutated_stmt.canonical_encode());
    }

    #[test]
    fn block_canonical_encode_golden_bytes_v1() {
        // Canonical-version-1 stability baseline. A change to this hash value
        // indicates a serde_json behavior change — verify the new bytes match
        // the intended canonical format and bump `canonical_version` in the
        // prefix before updating this expected value. NEVER silently update
        // this test.
        //
        // If this hash changes:
        // 1. Determine WHY (serde_json upgrade, Block field addition, etc.)
        // 2. If the change is intentional, bump canonical_version in the
        //    `type=grant-block-v1` prefix (→ v2) and update this hash.
        // 3. If the change is unintentional, REVERT the serde_json upgrade
        //    or field change that caused it.
        let fixture_block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact {
                    value: "obj-test".into(),
                },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
                can_delegate: None,
            }],
            nbf: None,
            expires_at: Some(1700000000),
            issued_by: "principal-test".into(),
            issued_at: 1699999000,
            approval: None,
            note: None,
        };
        use sha2::Digest as _;
        let encoded = fixture_block.canonical_encode();
        let hash = sha2::Sha256::digest(&encoded);
        let hex = hex::encode(hash);

        // CANONICAL-VERSION-1 BASELINE. Updated by the ADR 200 issuer
        // vocabulary adaptation so the fixture issuer is a Principal ID.
        // If this value changes again:
        // 1. Determine WHY (serde_json upgrade, Block field addition, etc.)
        // 2. If the change is intentional, bump canonical_version and update this hash
        // 3. If the change is unintentional, REVERT the serde_json upgrade or field change
        assert_eq!(
            hex, "6c5ac43dc21dfabf327077b9779fe4bbfb0fc561009f4f42fa24d259ac009167",
            "Block::canonical_encode produced unexpected bytes — see test comment"
        );
    }

    #[test]
    fn grant_status_derive_handles_all_persisted_states() {
        assert_eq!(
            GrantStatus::derive("revoked", None, None, 100),
            GrantStatus::Revoked
        );
        assert_eq!(
            GrantStatus::derive("abandoned", None, Some(50), 100),
            GrantStatus::Abandoned
        );
        assert_eq!(
            GrantStatus::derive("exhausted_by_budget", None, None, 100),
            GrantStatus::ExhaustedByBudget
        );
        assert_eq!(
            GrantStatus::derive("expired_by_budget", None, None, 100),
            GrantStatus::ExhaustedByBudget
        );
        assert_eq!(
            GrantStatus::derive("paused", None, None, 100),
            GrantStatus::Paused
        );
        assert_eq!(
            GrantStatus::derive("active", None, Some(50), 100),
            GrantStatus::Expired
        );
        assert_eq!(
            GrantStatus::derive("active", Some(200), None, 100),
            GrantStatus::Pending
        );
        assert_eq!(
            GrantStatus::derive("active", None, None, 100),
            GrantStatus::Active
        );
    }

    #[test]
    fn grant_status_abandoned_round_trips_as_terminal() {
        assert_eq!(GrantStatus::Abandoned.as_str(), "abandoned");
        assert_eq!(
            GrantStatus::parse("abandoned"),
            Some(GrantStatus::Abandoned)
        );
    }

    #[test]
    fn effective_status_returns_expired_when_ttl_passed_despite_stored_active() {
        let block = Block {
            statements: vec![stmt_credential_github()],
            nbf: None,
            expires_at: Some(50),
            issued_by: "principal_work".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant_ttl_test".into(),
            version: 1,
            issuing_persona_id: "principal_work".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent_claude".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };

        // Stored status is Active, but the block expired at epoch 50.
        assert_eq!(grant.status, GrantStatus::Active);
        assert_eq!(grant.effective_status(100), GrantStatus::Expired);
        // Still active before expiry.
        assert_eq!(grant.effective_status(49), GrantStatus::Active);
    }

    #[test]
    fn effective_status_preserves_abandoned_despite_timestamps() {
        let block = Block {
            statements: vec![stmt_credential_github()],
            nbf: Some(200),
            expires_at: Some(50),
            issued_by: "principal_work".into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let grant = AccessGrant {
            id: "grant_abandoned_test".into(),
            version: 1,
            issuing_persona_id: "principal_work".into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "agent_claude".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Abandoned,
            mode: GrantMode::OneShot,
            blocks: vec![SignedBlock {
                block,
                pubkey_next: "deadbeef".into(),
                signature: "cafebabe".into(),
            }],
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        };

        assert_eq!(grant.effective_status(100), GrantStatus::Abandoned);
        assert_eq!(grant.effective_status(300), GrantStatus::Abandoned);
    }

    #[test]
    fn statement_can_delegate_serde_round_trips() {
        let mut s = stmt_credential_github();
        s.can_delegate = Some(CanDelegate { max_depth: 2 });
        let json = serde_json::to_string(&s).expect("serialize");
        let back: Statement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, s);
        assert_eq!(back.can_delegate, Some(CanDelegate { max_depth: 2 }));

        // A None facet must be omitted from the canonical/JSON encoding so
        // existing grants' signature bytes are unchanged.
        let none_stmt = stmt_credential_github();
        assert_eq!(none_stmt.can_delegate, None);
        let none_json = serde_json::to_string(&none_stmt).expect("serialize");
        assert!(
            !none_json.contains("can_delegate"),
            "None can_delegate must be omitted, got: {none_json}"
        );
    }
}

// --- Validate impls (migrated from storage.rs lines 1905-1998) ---

impl Validate for Statement {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.sid, "statement sid")?;
        if self.actions.is_empty() {
            return Err(ValidationError::new(
                "statement must declare at least one action",
            ));
        }
        for a in &self.actions {
            validate_non_empty(a, "statement action")?;
        }
        match &self.resource {
            ResourceSelector::Exact { value } => {
                validate_non_empty(value, "resource selector exact value")?;
            }
            ResourceSelector::Glob { pattern } => {
                validate_non_empty(pattern, "resource selector glob pattern")?;
            }
            ResourceSelector::GlobWithSubtarget {
                primary_glob,
                subtarget_glob,
            } => {
                validate_non_empty(primary_glob, "resource selector primary glob pattern")?;
                validate_non_empty(subtarget_glob, "resource selector subtarget glob pattern")?;
            }
            ResourceSelector::Regex { pattern } => {
                validate_non_empty(pattern, "resource selector regex pattern")?;
            }
            ResourceSelector::Any => {}
        }
        Ok(())
    }
}

impl Validate for Block {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.issued_by, "block issued_by principal id")?;
        if self.statements.is_empty() {
            return Err(ValidationError::new(
                "block must contain at least one statement",
            ));
        }
        for s in &self.statements {
            s.validate()?;
        }
        if let (Some(nb), Some(exp)) = (self.nbf, self.expires_at)
            && exp <= nb
        {
            return Err(ValidationError::new("block expires_at must be after nbf"));
        }
        Ok(())
    }
}

impl Validate for SignedBlock {
    fn validate(&self) -> Result<(), ValidationError> {
        self.block.validate()?;
        validate_non_empty(&self.pubkey_next, "signed block pubkey_next")?;
        validate_non_empty(&self.signature, "signed block signature")?;
        Ok(())
    }
}

impl Validate for AccessGrant {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_non_empty(&self.id, "access grant id")?;
        if self.version == 0 {
            return Err(ValidationError::new(
                "access grant version must be at least 1",
            ));
        }
        validate_non_empty(&self.issuing_persona_id, "access grant issuer principal id")?;
        validate_non_empty(&self.recipient_id, "access grant recipient id")?;
        if self.blocks.is_empty() {
            return Err(ValidationError::new(
                "access grant must have at least one signed block",
            ));
        }
        for b in &self.blocks {
            b.validate()?;
        }
        if self.created_at == 0 {
            return Err(ValidationError::new(
                "access grant created_at must be non-zero",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(ValidationError::new(
                "access grant updated_at must not precede created_at",
            ));
        }
        Ok(())
    }
}

// --- CanonicalEncode impls (migrated from storage.rs lines 2136-2150) ---

impl CanonicalEncode for Block {
    fn canonical_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"type=grant-block-v1\n");
        // serde_json emits deterministic bytes for this struct — no HashMap
        // anywhere in the transitive graph. If a future field change ever
        // introduces one, the `canonical_encode_round_trips` test (below,
        // under #[cfg(test)]) will catch the non-determinism.
        let json = serde_json::to_vec(self)
            .expect("Block serializes to JSON (no HashMap/non-UTF-8 keys in the graph)");
        out.extend_from_slice(&json);
        out
    }
}
