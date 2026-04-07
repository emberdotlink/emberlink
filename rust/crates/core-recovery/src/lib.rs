use core_types::{RecoveryApproval, RecoveryPolicy, RecoveryRequest};

pub fn create_policy(root_id: impl Into<String>, guardian_threshold: u8) -> RecoveryPolicy {
    RecoveryPolicy {
        root_id: root_id.into(),
        guardian_threshold,
    }
}

pub fn create_request(id: impl Into<String>, root_id: impl Into<String>, target_device_id: impl Into<String>) -> RecoveryRequest {
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

