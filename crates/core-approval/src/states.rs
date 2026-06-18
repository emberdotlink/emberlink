use core_grant_types::approval::ApprovalStatus;

use crate::outcome::ApprovalOutcome;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("terminal state cannot transition")]
    AlreadyDecided,
    #[error("narrowed scope is not a syntactic subset of request scope")]
    ScopeNotNarrowing,
}

/// Pure-fn state transition per ADR 113 §State machine.
pub fn transition(
    state: ApprovalStatus,
    outcome: &ApprovalOutcome,
) -> Result<ApprovalStatus, TransitionError> {
    match (state, outcome) {
        (ApprovalStatus::Pending, ApprovalOutcome::Approved) => Ok(ApprovalStatus::Approved),
        (ApprovalStatus::Pending, ApprovalOutcome::Denied) => Ok(ApprovalStatus::Denied),
        (ApprovalStatus::Pending, ApprovalOutcome::Narrowed(_)) => {
            Ok(ApprovalStatus::NarrowedAndApproved)
        }
        (ApprovalStatus::Pending, ApprovalOutcome::Always { .. }) => Ok(ApprovalStatus::Approved),
        // terminal states reject all events
        _ => Err(TransitionError::AlreadyDecided),
    }
}

/// Transition triggered by TTL expiry: `Pending → Expired`. All other states
/// reject the event.
pub fn ttl_elapsed(state: ApprovalStatus) -> Result<ApprovalStatus, TransitionError> {
    match state {
        ApprovalStatus::Pending => Ok(ApprovalStatus::Expired),
        _ => Err(TransitionError::AlreadyDecided),
    }
}
