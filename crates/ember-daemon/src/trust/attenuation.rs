//! Re-export shim — predicates moved to `core_grants::scope`
//! per implementation-note-53 (design §2.1).
pub use core_grants::scope::{
    DelegationViolation, check_budget_attenuation, check_expiry_attenuation,
    check_statement_attenuation, compute_statements_union_bound, enforce_subset as scope_subset,
};
