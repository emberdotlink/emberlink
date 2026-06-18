use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Rail trust contract declared by a payment adapter manifest.
///
/// ADR 182 Component 6 intentionally keeps this binary:
/// - `side_channel_reconciliation` for rails with an authoritative read API
/// - `ephemeral_sign` for rails that can only prove commit via a per-attempt
///   daemon-minted signing key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailTrustContract {
    SideChannelReconciliation,
    EphemeralSign,
}

impl RailTrustContract {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SideChannelReconciliation => "side_channel_reconciliation",
            Self::EphemeralSign => "ephemeral_sign",
        }
    }
}

impl fmt::Display for RailTrustContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRailTrustContractError {
    input: String,
}

impl ParseRailTrustContractError {
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for ParseRailTrustContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown rail trust contract {:?}; expected side_channel_reconciliation or ephemeral_sign",
            self.input
        )
    }
}

impl std::error::Error for ParseRailTrustContractError {}

impl FromStr for RailTrustContract {
    type Err = ParseRailTrustContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "side_channel_reconciliation" => Ok(Self::SideChannelReconciliation),
            "ephemeral_sign" => Ok(Self::EphemeralSign),
            other => Err(ParseRailTrustContractError {
                input: other.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RailTrustContract;
    use std::str::FromStr;

    #[test]
    fn rail_trust_contract_round_trips_from_strings() {
        assert_eq!(
            RailTrustContract::from_str("side_channel_reconciliation").unwrap(),
            RailTrustContract::SideChannelReconciliation
        );
        assert_eq!(
            RailTrustContract::from_str("ephemeral_sign").unwrap(),
            RailTrustContract::EphemeralSign
        );
        assert_eq!(
            RailTrustContract::EphemeralSign.to_string(),
            "ephemeral_sign"
        );
    }

    #[test]
    fn rail_trust_contract_rejects_unknown_string() {
        let err = RailTrustContract::from_str("callback_only").expect_err("must reject");
        assert!(err.input().contains("callback_only"));
    }
}
