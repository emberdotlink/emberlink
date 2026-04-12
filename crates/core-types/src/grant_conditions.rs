/// Conditions that a grant offer recipient must satisfy before claiming.
///
/// Conditions are evaluated at claim time against the claimant's badge
/// holdings and the trust graph visible to the issuer. They are stored
/// with the offer event so that any verifier can replay the check.
///
/// Serialization uses `snake_case` for JSON field names and a `"type"` tag
/// to distinguish variants.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum GrantCondition {
    /// Recipient must hold an active (non-revoked, non-expired) badge of
    /// `badge_type`, and the badge's issuer must meet optional authority
    /// thresholds as computed by `core_trust::compute_badge_weight`.
    BadgeGate {
        /// Required badge type string (e.g. `"subway-rider"`, `"verified-dev"`).
        badge_type: String,
        /// Minimum convergence score `[0.0, 1.0]` — fraction of first-degree
        /// peers who recognise the badge issuer. `None` means no threshold.
        #[serde(skip_serializing_if = "Option::is_none")]
        min_convergence: Option<f64>,
        /// Maximum allowed graph distance from the grant issuer to the badge
        /// issuer. `None` means no distance limit (up to `DEFAULT_MAX_DEPTH`).
        #[serde(skip_serializing_if = "Option::is_none")]
        max_distance: Option<u32>,
        /// Minimum total authority weight `[0.0, 1.0]`. `None` means no
        /// threshold on the combined score.
        #[serde(skip_serializing_if = "Option::is_none")]
        min_authority: Option<f64>,
    },
    /// All sub-conditions must be satisfied.
    All(Vec<GrantCondition>),
    /// At least one sub-condition must be satisfied.
    Any(Vec<GrantCondition>),
}

impl GrantCondition {
    /// Convenience constructor for a simple badge gate with no thresholds.
    pub fn badge(badge_type: impl Into<String>) -> Self {
        Self::BadgeGate {
            badge_type: badge_type.into(),
            min_convergence: None,
            max_distance: None,
            min_authority: None,
        }
    }

    /// Convenience constructor for a badge gate with all thresholds specified.
    pub fn badge_with_thresholds(
        badge_type: impl Into<String>,
        min_convergence: Option<f64>,
        max_distance: Option<u32>,
        min_authority: Option<f64>,
    ) -> Self {
        Self::BadgeGate {
            badge_type: badge_type.into(),
            min_convergence,
            max_distance,
            min_authority,
        }
    }

    /// Parse a CLI condition string into a `GrantCondition`.
    ///
    /// Supported formats:
    /// - `badge:<type>` — simple badge gate
    /// - `badge:<type>,min-convergence=<f>` — with convergence threshold
    /// - `badge:<type>,max-distance=<n>` — with distance limit
    /// - `badge:<type>,min-authority=<f>` — with authority threshold
    /// - Multiple comma-separated options: `badge:<type>,min-convergence=0.5,max-distance=2`
    pub fn parse_cli(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix("badge:") {
            let mut parts = rest.splitn(2, ',');
            let badge_type = parts.next().unwrap_or("").trim().to_string();
            if badge_type.is_empty() {
                return Err("badge type must not be empty".to_string());
            }

            let mut min_convergence: Option<f64> = None;
            let mut max_distance: Option<u32> = None;
            let mut min_authority: Option<f64> = None;

            // Remaining parts after the badge type
            if let Some(opts_str) = parts.next() {
                // Reconstruct the full option string with commas
                // (splitn(2) gave us everything after the first comma)
                let full_opts = opts_str;
                for opt in full_opts.split(',') {
                    let opt = opt.trim();
                    if opt.is_empty() {
                        continue;
                    }
                    if let Some(val) = opt.strip_prefix("min-convergence=") {
                        min_convergence = Some(val.parse::<f64>().map_err(|_| {
                            format!("invalid min-convergence value: {val}")
                        })?);
                    } else if let Some(val) = opt.strip_prefix("max-distance=") {
                        max_distance = Some(val.parse::<u32>().map_err(|_| {
                            format!("invalid max-distance value: {val}")
                        })?);
                    } else if let Some(val) = opt.strip_prefix("min-authority=") {
                        min_authority = Some(val.parse::<f64>().map_err(|_| {
                            format!("invalid min-authority value: {val}")
                        })?);
                    } else {
                        return Err(format!("unknown condition option: {opt}"));
                    }
                }
            }

            Ok(Self::BadgeGate { badge_type, min_convergence, max_distance, min_authority })
        } else {
            Err(format!(
                "unknown condition format: '{s}'. Expected 'badge:<type>[,min-convergence=<f>][,max-distance=<n>][,min-authority=<f>]'"
            ))
        }
    }

    /// Serialize this condition to a compact human-readable string (for display).
    pub fn display(&self) -> String {
        match self {
            Self::BadgeGate { badge_type, min_convergence, max_distance, min_authority } => {
                let mut s = format!("badge:{badge_type}");
                if let Some(c) = min_convergence {
                    s.push_str(&format!(",min-convergence={c:.2}"));
                }
                if let Some(d) = max_distance {
                    s.push_str(&format!(",max-distance={d}"));
                }
                if let Some(a) = min_authority {
                    s.push_str(&format!(",min-authority={a:.2}"));
                }
                s
            }
            Self::All(conds) => {
                let inner: Vec<_> = conds.iter().map(|c| c.display()).collect();
                format!("all({})", inner.join(", "))
            }
            Self::Any(conds) => {
                let inner: Vec<_> = conds.iter().map(|c| c.display()).collect();
                format!("any({})", inner.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_badge() {
        let c = GrantCondition::parse_cli("badge:verified-dev").unwrap();
        assert_eq!(
            c,
            GrantCondition::BadgeGate {
                badge_type: "verified-dev".to_string(),
                min_convergence: None,
                max_distance: None,
                min_authority: None,
            }
        );
    }

    #[test]
    fn parse_badge_with_convergence() {
        let c = GrantCondition::parse_cli("badge:subway-rider,min-convergence=0.5").unwrap();
        assert_eq!(
            c,
            GrantCondition::BadgeGate {
                badge_type: "subway-rider".to_string(),
                min_convergence: Some(0.5),
                max_distance: None,
                min_authority: None,
            }
        );
    }

    #[test]
    fn parse_badge_with_all_options() {
        let c = GrantCondition::parse_cli(
            "badge:verified-dev,min-convergence=0.5,max-distance=2,min-authority=0.7",
        )
        .unwrap();
        assert_eq!(
            c,
            GrantCondition::BadgeGate {
                badge_type: "verified-dev".to_string(),
                min_convergence: Some(0.5),
                max_distance: Some(2),
                min_authority: Some(0.7),
            }
        );
    }

    #[test]
    fn parse_unknown_format_errors() {
        assert!(GrantCondition::parse_cli("trust:high").is_err());
        assert!(GrantCondition::parse_cli("badge:").is_err());
    }

    #[test]
    fn display_round_trips() {
        let c = GrantCondition::BadgeGate {
            badge_type: "verified-dev".to_string(),
            min_convergence: Some(0.5),
            max_distance: Some(2),
            min_authority: None,
        };
        let displayed = c.display();
        assert!(displayed.contains("badge:verified-dev"));
        assert!(displayed.contains("min-convergence=0.50"));
        assert!(displayed.contains("max-distance=2"));
    }

    #[test]
    fn serde_roundtrip() {
        let c = GrantCondition::All(vec![
            GrantCondition::badge("verified-dev"),
            GrantCondition::BadgeGate {
                badge_type: "subway-rider".to_string(),
                min_convergence: Some(0.5),
                max_distance: Some(3),
                min_authority: Some(0.8),
            },
        ]);
        let json = serde_json::to_string(&c).unwrap();
        let back: GrantCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
