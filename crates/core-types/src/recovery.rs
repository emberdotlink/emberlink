#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub root_id: String,
    pub guardian_threshold: u8,
    /// How many seconds a contest freezes execution. Zero means immediate re-approval is allowed.
    pub cooldown_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub id: String,
    pub root_id: String,
    pub target_device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryApproval {
    pub request_id: String,
    pub guardian_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryContest {
    pub request_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryExecution {
    pub request_id: String,
    pub executed_scope: RecoveryScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryScope {
    FreezeDevice,
    RestorePersonaAccess,
}

impl RecoveryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreezeDevice => "freeze-device",
            Self::RestorePersonaAccess => "restore-persona-access",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "freeze-device" => Some(Self::FreezeDevice),
            "restore-persona-access" => Some(Self::RestorePersonaAccess),
            _ => None,
        }
    }
}
