use core_grant_types::approval::RequestedScope;
use serde::{Deserialize, Serialize};

/// Outcome an approver chooses when deciding a pending request.
///
/// - `Approved` — issue the requested scope verbatim.
/// - `Denied` — refuse; emit a denial Receipt, no grant.
/// - `Narrowed(scope)` — issue a strict subset of the requested scope.
///   Pre-condition: the narrowed scope must be a syntactic subset of
///   `request.requested_scope` (checked by the implementation; rejection
///   surfaces as `LifecycleError::ScopeNotNarrowing`).
/// - `Always(ttl)` — issue the requested scope as a standing grant with
///   the specified TTL; future identical requests resolve from the cache
///   without re-prompting until the standing grant expires or is revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
    Narrowed(RequestedScope),
    Always { ttl_seconds: u64 },
}
