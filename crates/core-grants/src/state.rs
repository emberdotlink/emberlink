use crate::grant::{Grant, GrantError, GrantState, PrincipalId, Scope, UsageDelta};

/// All events the state machine can process.
#[derive(Debug, Clone)]
pub enum TransitionEvent {
    Extend(chrono::Duration),
    Delegate(Scope),
    Use(UsageDelta),
    Pause(PrincipalId),
    Resume(PrincipalId),
    Revoke(PrincipalId),
}

/// Apply a single transition event to a grant, returning the updated grant.
///
/// Enforces the state machine table from ADR 114 §3:
///
/// | Current state | Event         | Actor check  | Next state   |
/// |---------------|---------------|--------------|--------------|
/// | Active        | extend(ttl)   | —            | Active       |
/// | Active        | delegate(s)   | —            | Active(child)|
/// | Active        | use(amount)   | —            | Active       |
/// | Active        | pause         | issuer only  | Paused       |
/// | Active        | revoke(by)    | issuer only  | Revoked      |
/// | Paused        | resume        | issuer only  | Active       |
/// | Paused        | revoke(by)    | issuer only  | Revoked      |
/// | Paused        | extend(ttl)   | —            | error        |
/// | Paused        | delegate(s)   | —            | error        |
/// | Paused        | use(amount)   | —            | error        |
/// | Revoked       | any           | —            | error        |
pub fn apply_event(grant: Grant, event: TransitionEvent) -> Result<Grant, GrantError> {
    match (grant.state, &event) {
        // Revoked is terminal — all events rejected.
        (GrantState::Revoked, _) => Err(GrantError::InvalidState),

        // Active transitions.
        (GrantState::Active, TransitionEvent::Extend(ttl)) => crate::grant::extend(grant, *ttl),
        (GrantState::Active, TransitionEvent::Use(delta)) => {
            crate::grant::use_grant(grant, *delta).map(|(g, _)| g)
        }
        (GrantState::Active, TransitionEvent::Pause(by)) => crate::grant::pause(grant, by),
        (GrantState::Active, TransitionEvent::Revoke(by)) => crate::grant::revoke(grant, by),
        // Delegate is handled specially — produces a child grant; we return the parent unchanged.
        // Callers that need the child grant should call `crate::grant::delegate` directly.
        (GrantState::Active, TransitionEvent::Delegate(scope)) => {
            let _ = crate::grant::delegate(&grant, scope.clone())?;
            Ok(grant)
        }
        (GrantState::Active, TransitionEvent::Resume(_)) => Err(GrantError::InvalidState),

        // Paused transitions.
        (GrantState::Paused, TransitionEvent::Resume(by)) => crate::grant::resume(grant, by),
        (GrantState::Paused, TransitionEvent::Revoke(by)) => crate::grant::revoke(grant, by),
        // All other events on Paused are invalid.
        (GrantState::Paused, _) => Err(GrantError::InvalidState),
    }
}

/// Returns `true` iff a state-only transition `from → to` is permitted by the
/// state machine table in ADR 114 §3 (ignoring event-specific actor checks
/// and payloads — those are enforced by `apply_event`).
///
/// Same-state transitions on `Active` are allowed (extend/use/delegate are
/// state-preserving). `Revoked` is terminal: nothing transitions out.
pub fn can_transition(from: GrantState, to: GrantState) -> bool {
    use GrantState::*;
    matches!(
        (from, to),
        (Active, Active)
            | (Active, Paused)
            | (Active, Revoked)
            | (Paused, Active)
            | (Paused, Revoked)
    )
}
