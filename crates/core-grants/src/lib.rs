pub mod chain;
pub mod grant;
pub mod scope;
pub mod state;

pub use grant::{
    GRANT_SCHEMA_VERSION_PIN, Grant, GrantError, GrantSpec, GrantState, MAX_DELEGATION_DEPTH,
    PrincipalId, Scope, Usage, UsageDelta, UsageReceipt, create, delegate, extend, pause, resume,
    revoke, use_grant,
};
pub use scope::{
    AncestorRevocation, DelegationViolation, NeedResolution, NeedUnsatisfiable, RevokedAncestor,
    check_budget_attenuation, check_expiry_attenuation, check_statement_attenuation,
    compute_statements_union_bound, enforce_subset, first_revoked_ancestor,
    resolve_need_against_grants,
};
pub use state::{TransitionEvent, apply_event, can_transition};

pub mod store;
pub use store::{GrantStore, StoreError};

// `PregrantPath` is defined in `core-event-types` (so the Receipt body in
// `core-events` can stamp it without depending on `core-grants`). Re-exported
// here for existing `core_grants::PregrantPath` callers; the BKR-4c cut removed
// the legacy delegation sidecar type that used to live alongside it (now
// folded into the persona's `StandingGrant`).
pub use core_event_types::PregrantPath;
