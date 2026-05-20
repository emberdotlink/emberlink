use core_event_types::{
    EventBody, GuardianEnrolledEvent, GuardianKeyRotatedEvent, RecoveryApprovedEvent,
    RecoveryContestedEvent, RecoveryExecutedEvent, RecoveryPolicyCreatedEvent,
    RecoveryRejectedEvent, RecoveryRequestedEvent,
};
use core_principals::{
    RecoveryApproval, RecoveryExecution, RecoveryPolicy, RecoveryRequest, RecoveryScope,
};

pub fn create_policy(
    root_id: impl Into<String>,
    guardian_threshold: u8,
    cooldown_seconds: u32,
) -> RecoveryPolicy {
    RecoveryPolicy {
        root_id: root_id.into(),
        guardian_threshold,
        cooldown_seconds,
    }
}

pub fn create_request(
    id: impl Into<String>,
    root_id: impl Into<String>,
    target_device_id: impl Into<String>,
) -> RecoveryRequest {
    RecoveryRequest {
        id: id.into(),
        root_id: root_id.into(),
        target_device_id: target_device_id.into(),
    }
}

pub fn approve(request_id: impl Into<String>, guardian_id: impl Into<String>) -> RecoveryApproval {
    RecoveryApproval {
        request_id: request_id.into(),
        guardian_id: guardian_id.into(),
    }
}

pub fn recovery_policy_created_event(
    root_id: impl Into<String>,
    guardian_threshold: u8,
    cooldown_seconds: u32,
) -> EventBody {
    EventBody::RecoveryPolicyCreated(RecoveryPolicyCreatedEvent {
        root_id: root_id.into(),
        guardian_threshold,
        cooldown_seconds,
    })
}

pub fn guardian_enrolled_event(
    root_id: impl Into<String>,
    guardian_id: impl Into<String>,
    guardian_label: impl Into<String>,
    guardian_public_key: impl Into<String>,
) -> EventBody {
    EventBody::GuardianEnrolled(GuardianEnrolledEvent {
        root_id: root_id.into(),
        guardian_id: guardian_id.into(),
        guardian_label: guardian_label.into(),
        guardian_public_key: guardian_public_key.into(),
    })
}

pub fn guardian_key_rotated_event(
    root_id: impl Into<String>,
    guardian_id: impl Into<String>,
    previous_key_id: impl Into<String>,
    new_guardian_public_key: impl Into<String>,
) -> EventBody {
    EventBody::GuardianKeyRotated(GuardianKeyRotatedEvent {
        guardian_id: guardian_id.into(),
        root_id: root_id.into(),
        previous_key_id: previous_key_id.into(),
        new_guardian_public_key: new_guardian_public_key.into(),
    })
}

pub fn recovery_requested_event(
    request_id: impl Into<String>,
    root_id: impl Into<String>,
    target_device_id: impl Into<String>,
) -> EventBody {
    EventBody::RecoveryRequested(RecoveryRequestedEvent {
        request_id: request_id.into(),
        root_id: root_id.into(),
        target_device_id: target_device_id.into(),
    })
}

pub fn recovery_approved_event(
    request_id: impl Into<String>,
    guardian_id: impl Into<String>,
) -> EventBody {
    EventBody::RecoveryApproved(RecoveryApprovedEvent {
        request_id: request_id.into(),
        guardian_id: guardian_id.into(),
    })
}

pub fn recovery_executed_event(
    request_id: impl Into<String>,
    executed_scope: RecoveryScope,
) -> EventBody {
    EventBody::RecoveryExecuted(RecoveryExecutedEvent {
        request_id: request_id.into(),
        executed_scope,
    })
}

pub fn recovery_contested_event(
    request_id: impl Into<String>,
    guardian_id: impl Into<String>,
    reason: impl Into<String>,
    contested_at_epoch: u64,
) -> EventBody {
    EventBody::RecoveryContested(RecoveryContestedEvent {
        request_id: request_id.into(),
        guardian_id: guardian_id.into(),
        reason: reason.into(),
        contested_at_epoch,
    })
}

pub fn recovery_rejected_event(
    request_id: impl Into<String>,
    rejected_by: impl Into<String>,
    reason: impl Into<String>,
) -> EventBody {
    EventBody::RecoveryRejected(RecoveryRejectedEvent {
        request_id: request_id.into(),
        rejected_by: rejected_by.into(),
        reason: reason.into(),
    })
}

pub fn execute(request_id: impl Into<String>, executed_scope: RecoveryScope) -> RecoveryExecution {
    RecoveryExecution {
        request_id: request_id.into(),
        executed_scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_event_types::EventType;

    #[test]
    fn recovery_event_builders_emit_typed_events() {
        let policy = recovery_policy_created_event("root-a", 2, 3600);
        let enrolled =
            guardian_enrolled_event("root-a", "guardian-alex", "Alex", "guardian-key-alex");
        let requested = recovery_requested_event("recovery-1", "root-a", "device-a");
        let approved = recovery_approved_event("recovery-1", "guardian-alex");
        let contested =
            recovery_contested_event("recovery-1", "guardian-riley", "improper approval", 1000);
        let rejected = recovery_rejected_event("recovery-1", "root-a", "contested");
        let executed = recovery_executed_event("recovery-1", RecoveryScope::FreezeDevice);

        assert_eq!(policy.event_type(), EventType::RecoveryPolicyCreated);
        assert_eq!(enrolled.event_type(), EventType::GuardianEnrolled);
        assert_eq!(requested.event_type(), EventType::RecoveryRequested);
        assert_eq!(approved.event_type(), EventType::RecoveryApproved);
        assert_eq!(contested.event_type(), EventType::RecoveryContested);
        assert_eq!(rejected.event_type(), EventType::RecoveryRejected);
        assert_eq!(executed.event_type(), EventType::RecoveryExecuted);
    }

    #[test]
    fn recovery_full_lifecycle_request_approve_contest_reject_re_request_approve_execute() {
        // First attempt: request → approve → contest → reject
        let requested_1 = recovery_requested_event("recovery-1", "root-a", "device-a");
        let approved_1 = recovery_approved_event("recovery-1", "guardian-alex");
        let contested_1 =
            recovery_contested_event("recovery-1", "guardian-riley", "suspicious", 1000);
        let rejected_1 = recovery_rejected_event("recovery-1", "root-a", "contested");

        assert_eq!(requested_1.event_type(), EventType::RecoveryRequested);
        assert_eq!(approved_1.event_type(), EventType::RecoveryApproved);
        assert_eq!(contested_1.event_type(), EventType::RecoveryContested);
        assert_eq!(rejected_1.event_type(), EventType::RecoveryRejected);

        if let EventBody::RecoveryContested(e) = &contested_1 {
            assert_eq!(e.guardian_id, "guardian-riley");
            assert_eq!(e.reason, "suspicious");
        } else {
            panic!("expected RecoveryContested");
        }

        // Second attempt: request → approve (threshold met) → execute
        let requested_2 = recovery_requested_event("recovery-2", "root-a", "device-a");
        let approved_2a = recovery_approved_event("recovery-2", "guardian-alex");
        let approved_2b = recovery_approved_event("recovery-2", "guardian-riley");
        let executed_2 = recovery_executed_event("recovery-2", RecoveryScope::RestorePersonaAccess);

        assert_eq!(requested_2.event_type(), EventType::RecoveryRequested);
        assert_eq!(approved_2a.event_type(), EventType::RecoveryApproved);
        assert_eq!(approved_2b.event_type(), EventType::RecoveryApproved);
        assert_eq!(executed_2.event_type(), EventType::RecoveryExecuted);

        if let EventBody::RecoveryExecuted(e) = &executed_2 {
            assert_eq!(e.request_id, "recovery-2");
            assert!(matches!(
                e.executed_scope,
                RecoveryScope::RestorePersonaAccess
            ));
        } else {
            panic!("expected RecoveryExecuted");
        }
    }

    #[test]
    fn builder_structs_capture_fields_correctly() {
        let policy = create_policy("root-x", 3, 3600);
        assert_eq!(policy.root_id, "root-x");
        assert_eq!(policy.guardian_threshold, 3);

        let request = create_request("recovery-99", "root-x", "device-z");
        assert_eq!(request.id, "recovery-99");
        assert_eq!(request.root_id, "root-x");
        assert_eq!(request.target_device_id, "device-z");

        let approval = approve("recovery-99", "guardian-sam");
        assert_eq!(approval.request_id, "recovery-99");
        assert_eq!(approval.guardian_id, "guardian-sam");

        let execution = execute("recovery-99", RecoveryScope::FreezeDevice);
        assert_eq!(execution.request_id, "recovery-99");
        assert!(matches!(
            execution.executed_scope,
            RecoveryScope::FreezeDevice
        ));
    }

    #[test]
    fn guardian_key_rotated_event_emits_typed_event() {
        let rotated = guardian_key_rotated_event(
            "root-a",
            "guardian-alex",
            "guardian-key-alex",
            "guardian-key-alex-v2",
        );
        assert_eq!(rotated.event_type(), EventType::GuardianKeyRotated);
        if let EventBody::GuardianKeyRotated(e) = &rotated {
            assert_eq!(e.root_id, "root-a");
            assert_eq!(e.guardian_id, "guardian-alex");
            assert_eq!(e.previous_key_id, "guardian-key-alex");
            assert_eq!(e.new_guardian_public_key, "guardian-key-alex-v2");
        } else {
            panic!("expected GuardianKeyRotated");
        }
    }

    #[test]
    fn guardian_enrolled_event_captures_key_material() {
        let enrolled = guardian_enrolled_event(
            "root-a",
            "guardian-sam",
            "Sam",
            "ed25519:guardian-sam-pubkey",
        );
        if let EventBody::GuardianEnrolled(e) = &enrolled {
            assert_eq!(e.root_id, "root-a");
            assert_eq!(e.guardian_id, "guardian-sam");
            assert_eq!(e.guardian_label, "Sam");
            assert_eq!(e.guardian_public_key, "ed25519:guardian-sam-pubkey");
        } else {
            panic!("expected GuardianEnrolled");
        }
    }
}
