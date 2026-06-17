pub mod lifecycle;
pub mod outcome;
pub mod policy;
pub mod states;

pub use lifecycle::{ApprovalLifecycle, LifecycleError, RequestId, SubmitMetadata};
pub use outcome::ApprovalOutcome;
pub use policy::{
    ActionRef, ActionSelector, ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyError,
    PolicyEvaluation, PolicyRule, RiskLevel, Tier, classify_tier, normalize_action,
};
pub use states::{TransitionError, transition, ttl_elapsed};

// Re-export approval protocol types so callers can import from a single crate
// rather than splitting between `core_approval` and `core_types::approval`.
pub use core_grant_types::approval::{ApprovalResponse, ApprovalStatus};
