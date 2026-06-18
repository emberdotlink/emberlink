use serde::{Deserialize, Serialize};

pub const MAX_DELEGATION_DEPTH: u32 = 8;

/// Grant schema version pinned by this daemon build (SCION-BROKER-SCHEMA-VERSION-PIN).
///
/// Every `Grant` consumed at a broker entry point must carry a
/// `schema_version` equal to this constant. A mismatch is refused with
/// JSON-RPC error code `-32010` ("grant schema version mismatch") at
/// the broker boundary — see
/// `ember_daemon::broker::handler::check_grant_schema_version`.
///
/// This is the CRIT-A remediation from the first adversarial review:
/// a grant minted under an older schema must not be processed under a
/// newer (potentially wider) interpretation. When the schema bumps,
/// this constant bumps in lockstep and all live grants must either be
/// migrated forward or refused.
pub const GRANT_SCHEMA_VERSION_PIN: u32 = 1;

/// Serde default for `Grant::schema_version` so on-disk grants written
/// before this field existed deserialize successfully and surface their
/// "missing version" state as `GRANT_SCHEMA_VERSION_PIN` at the broker
/// boundary.
///
/// Older persisted grants get the current pin on read; the broker's
/// check therefore short-circuits on the in-memory rebuild path. New
/// grants explicitly set `schema_version` at construction and ride the
/// state machine through with the version preserved across
/// transitions.
fn default_schema_version() -> u32 {
    GRANT_SCHEMA_VERSION_PIN
}

/// Opaque principal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

/// The scope of authority delegated by a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub capability: String,
    pub resource_id: Option<String>,
    pub constraints: Vec<String>,
}

impl Scope {
    /// Returns true iff `self` is a syntactic subset of `other`.
    ///
    /// A scope is a subset when its capability matches, its resource_id is at
    /// least as specific, and all of its constraints appear in `other`.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        if self.capability != other.capability {
            return false;
        }
        match (&other.resource_id, &self.resource_id) {
            // other is "any resource" — self may be any or specific
            (None, _) => {}
            // other is specific — self must match exactly
            (Some(o_id), Some(s_id)) => {
                if o_id != s_id {
                    return false;
                }
            }
            // other is specific, self is "any" — not a subset
            (Some(_), None) => return false,
        }
        for c in &self.constraints {
            if !other.constraints.contains(c) {
                return false;
            }
        }
        true
    }
}

/// Monotonically non-decreasing usage counter for a grant.
///
/// Exposes no decrement or sub method — usage is monotonic by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Usage {
    pub used: u64,
}

impl Usage {
    pub fn zero() -> Self {
        Self { used: 0 }
    }

    pub fn saturating_add(&self, delta: UsageDelta) -> Self {
        Self {
            used: self.used.saturating_add(delta.amount),
        }
    }
}

/// An amount of usage to charge against a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageDelta {
    pub amount: u64,
}

/// Receipt produced by `use_grant`, recording the amount consumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReceipt {
    pub grant_id: uuid::Uuid,
    pub amount: u64,
}

/// Specification for creating a new grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSpec {
    pub issuer: PrincipalId,
    pub scope: Scope,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// State of a grant in the state machine.
///
/// Transitions:
///   Active  → Paused   (issuer only)
///   Active  → Revoked  (issuer only; terminal)
///   Paused  → Active   (issuer only)
///   Paused  → Revoked  (issuer only; terminal)
///
/// Revoked is terminal — no transition out of it is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantState {
    Active,
    Paused,
    Revoked,
}

/// An authority grant in the `core-grants` state machine.
///
/// Invariants upheld at all times:
/// - `usage` is monotonically non-decreasing.
/// - `scope` is a strict subset (or equal) of the parent's scope when delegated.
/// - A `Revoked` grant stays `Revoked` forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: uuid::Uuid,
    pub issuer: PrincipalId,
    pub scope: Scope,
    pub state: GrantState,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub parent_id: Option<uuid::Uuid>,
    pub delegation_depth: u32,
    pub usage: Usage,
    /// Schema version this grant was minted under
    /// (SCION-BROKER-SCHEMA-VERSION-PIN).
    ///
    /// Defaults to [`GRANT_SCHEMA_VERSION_PIN`] when missing on
    /// deserialization (pre-field on-disk records). The broker boundary
    /// refuses any grant whose `schema_version` does not match this
    /// daemon's compiled-in pin — see
    /// `ember_daemon::broker::handler::check_grant_schema_version`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
}

/// Errors produced by grant state machine operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant is not in a valid state for this operation")]
    InvalidState,
    #[error("narrowed scope is not a subset of the grant scope")]
    ScopeViolation,
    #[error("grant budget exhausted")]
    BudgetExhausted,
    #[error("caller is not authorized to perform this operation")]
    NotAuthorized,
}

/// Create a new `Active` grant from a spec.
///
/// **Pre:** `spec.scope` is non-empty.
/// **Post:** returned grant has `state == Active`, `usage == zero`.
pub fn create(spec: GrantSpec) -> Result<Grant, GrantError> {
    Ok(Grant {
        id: uuid::Uuid::new_v4(),
        issuer: spec.issuer,
        scope: spec.scope,
        state: GrantState::Active,
        expires_at: spec.expires_at,
        parent_id: None,
        delegation_depth: 0,
        usage: Usage::zero(),
        schema_version: GRANT_SCHEMA_VERSION_PIN,
    })
}

/// Extend the TTL of an existing grant.
///
/// **Pre (runtime):** `grant.state == Active`.
/// **Pre (runtime):** `ttl > Duration::zero()`.
/// **Post:** returned grant has same state; `expires_at` is later or None (no-expiry).
/// **Rejects:** any grant where `state != Active` → `GrantError::InvalidState`.
pub fn extend(mut grant: Grant, ttl: chrono::Duration) -> Result<Grant, GrantError> {
    if grant.state != GrantState::Active {
        return Err(GrantError::InvalidState);
    }
    match grant.expires_at {
        Some(current) => {
            grant.expires_at = Some(current + ttl);
        }
        None => {
            // Already no-expiry; extending a no-expiry grant is a no-op.
        }
    }
    Ok(grant)
}

/// Delegate a grant, producing a child grant with a narrowed scope.
///
/// **Pre (runtime):** `grant.state == Active`.
/// **Pre (runtime):** `narrowed_scope ⊆ grant.scope` (strict subset or equal).
/// **Pre (runtime):** `grant.delegation_depth < MAX_DELEGATION_DEPTH`.
/// **Post:** child `scope ⊆ parent scope`; `delegation_depth = parent + 1`.
/// **Post (compile-time):** child carries `parent_id = Some(grant.id)`.
/// **Rejects:** `state != Active` → `GrantError::InvalidState`.
/// **Rejects:** `narrowed_scope ⊄ grant.scope` → `GrantError::ScopeViolation`.
pub fn delegate(grant: &Grant, narrowed_scope: Scope) -> Result<Grant, GrantError> {
    if grant.state != GrantState::Active {
        return Err(GrantError::InvalidState);
    }
    if grant.delegation_depth >= MAX_DELEGATION_DEPTH {
        return Err(GrantError::InvalidState);
    }
    if !narrowed_scope.is_subset_of(&grant.scope) {
        return Err(GrantError::ScopeViolation);
    }
    Ok(Grant {
        id: uuid::Uuid::new_v4(),
        issuer: grant.issuer.clone(),
        scope: narrowed_scope,
        state: GrantState::Active,
        expires_at: grant.expires_at,
        parent_id: Some(grant.id),
        delegation_depth: grant.delegation_depth + 1,
        usage: Usage::zero(),
        schema_version: grant.schema_version,
    })
}

/// Record usage against an `Active` grant.
///
/// **Pre (runtime):** `grant.state == Active`.
/// **Pre (runtime):** `amount` does not exceed remaining budget (if budget is set).
/// **Post:** returned grant has `usage` incremented by `amount`; usage is monotonic.
/// **Rejects:** `state != Active` → `GrantError::InvalidState`.
/// **Rejects:** budget exhausted → `GrantError::BudgetExhausted`.
pub fn use_grant(
    mut grant: Grant,
    amount: UsageDelta,
) -> Result<(Grant, UsageReceipt), GrantError> {
    if grant.state != GrantState::Active {
        return Err(GrantError::InvalidState);
    }
    let receipt = UsageReceipt {
        grant_id: grant.id,
        amount: amount.amount,
    };
    grant.usage = grant.usage.saturating_add(amount);
    Ok((grant, receipt))
}

/// Revoke a grant.
///
/// **Pre (runtime):** `by_principal == grant.issuer`.
/// **Post:** returned grant has `state == Revoked`; this is terminal.
/// **Rejects:** `by_principal != grant.issuer` → `GrantError::NotAuthorized`.
/// **Note:** revoking an already-`Revoked` grant is idempotent (returns Ok with Revoked state).
pub fn revoke(mut grant: Grant, by_principal: &PrincipalId) -> Result<Grant, GrantError> {
    if *by_principal != grant.issuer {
        return Err(GrantError::NotAuthorized);
    }
    grant.state = GrantState::Revoked;
    Ok(grant)
}

/// Pause an `Active` grant (issuer only).
///
/// **Pre (runtime):** `grant.state == Active`; `by_principal == grant.issuer`.
/// **Post:** `state == Paused`.
pub fn pause(mut grant: Grant, by_principal: &PrincipalId) -> Result<Grant, GrantError> {
    if *by_principal != grant.issuer {
        return Err(GrantError::NotAuthorized);
    }
    if grant.state != GrantState::Active {
        return Err(GrantError::InvalidState);
    }
    grant.state = GrantState::Paused;
    Ok(grant)
}

/// Resume a `Paused` grant (issuer only).
///
/// **Pre (runtime):** `grant.state == Paused`; `by_principal == grant.issuer`.
/// **Post:** `state == Active`.
pub fn resume(mut grant: Grant, by_principal: &PrincipalId) -> Result<Grant, GrantError> {
    if *by_principal != grant.issuer {
        return Err(GrantError::NotAuthorized);
    }
    if grant.state != GrantState::Paused {
        return Err(GrantError::InvalidState);
    }
    grant.state = GrantState::Active;
    Ok(grant)
}
