/// Maximum allowed nesting depth for `GrantCondition` combinators.
///
/// An attacker-supplied `conditions_json` with thousands of nested `All`
/// or `Any` layers would cause a stack overflow in any recursive evaluator.
/// Conditions are validated against this limit before evaluation.
pub const MAX_CONDITION_DEPTH: u32 = 10;

/// Errors specific to grant-condition validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantConditionError {
    /// The condition tree exceeds [`MAX_CONDITION_DEPTH`] levels of nesting.
    ConditionsTooDeep {
        /// The depth at which the limit was exceeded.
        depth: u32,
    },
}

impl std::fmt::Display for GrantConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConditionsTooDeep { depth } => write!(
                f,
                "grant condition tree exceeds maximum nesting depth of {MAX_CONDITION_DEPTH} \
                 (reached depth {depth})"
            ),
        }
    }
}

impl std::error::Error for GrantConditionError {}

/// Conditions that a grant offer recipient must satisfy before claiming.
///
/// Conditions are evaluated at claim time against the claimant's badge
/// holdings and the trust graph visible to the issuer. They are stored
/// with the offer event so that any verifier can replay the check.
///
/// Serialization uses `snake_case` for JSON field names and a `"type"` tag
/// to distinguish variants.
///
/// Empty `All` and `Any` combinators are rejected at deserialization time
/// (see `GC-H1` in `docs/security-reviews/grant-conditions-rs-2026-04-23.md`):
/// a serialized `{"type":"all","value":[]}` or `{"type":"any","value":[]}`
/// is a covert always-pass shape — any wizard or upstream tool that
/// produced "no badge required" as an empty combinator would silently
/// disable gating. We fail-closed at the parse boundary so the evaluator
/// never sees the malformed shape. The evaluator additionally returns
/// `Unmet` for empty combinators as defence in depth.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    try_from = "GrantConditionRepr"
)]
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
    /// All sub-conditions must be satisfied. Must contain at least one
    /// sub-condition; an empty `All` is rejected at deserialization.
    All(Vec<GrantCondition>),
    /// At least one sub-condition must be satisfied. Must contain at least
    /// one sub-condition; an empty `Any` is rejected at deserialization.
    Any(Vec<GrantCondition>),
}

/// Inner struct for the `BadgeGate` wire variant. Extracted so that
/// `#[serde(deny_unknown_fields)]` applies: any future protocol field
/// added to `BadgeGate` that this binary does not recognise will cause
/// a hard parse error rather than a silent drop (C43-M3 / MED defence-in-depth).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BadgeGateRepr {
    badge_type: String,
    #[serde(default)]
    min_convergence: Option<f64>,
    #[serde(default)]
    max_distance: Option<u32>,
    #[serde(default)]
    min_authority: Option<f64>,
}

/// Wire-format mirror of [`GrantCondition`] used to validate empty
/// combinators at deserialization time. Kept private so external code
/// must construct conditions through the validated entry points.
#[derive(serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum GrantConditionRepr {
    BadgeGate(BadgeGateRepr),
    All(Vec<GrantCondition>),
    Any(Vec<GrantCondition>),
}

impl TryFrom<GrantConditionRepr> for GrantCondition {
    type Error = &'static str;

    fn try_from(repr: GrantConditionRepr) -> Result<Self, Self::Error> {
        match repr {
            GrantConditionRepr::BadgeGate(BadgeGateRepr {
                badge_type,
                min_convergence,
                max_distance,
                min_authority,
            }) => Ok(Self::BadgeGate {
                badge_type,
                min_convergence,
                max_distance,
                min_authority,
            }),
            GrantConditionRepr::All(sub) => {
                if sub.is_empty() {
                    return Err(
                        "empty All combinator is not allowed: an empty All vacuously \
                         passes and would silently disable gating (GC-H1)",
                    );
                }
                Ok(Self::All(sub))
            }
            GrantConditionRepr::Any(sub) => {
                if sub.is_empty() {
                    return Err("empty Any combinator is not allowed: an empty Any has no \
                         alternatives and would silently disable gating (GC-H1)");
                }
                Ok(Self::Any(sub))
            }
        }
    }
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
                        min_convergence = Some(
                            val.parse::<f64>()
                                .map_err(|_| format!("invalid min-convergence value: {val}"))?,
                        );
                    } else if let Some(val) = opt.strip_prefix("max-distance=") {
                        max_distance = Some(
                            val.parse::<u32>()
                                .map_err(|_| format!("invalid max-distance value: {val}"))?,
                        );
                    } else if let Some(val) = opt.strip_prefix("min-authority=") {
                        min_authority = Some(
                            val.parse::<f64>()
                                .map_err(|_| format!("invalid min-authority value: {val}"))?,
                        );
                    } else {
                        return Err(format!("unknown condition option: {opt}"));
                    }
                }
            }

            Ok(Self::BadgeGate {
                badge_type,
                min_convergence,
                max_distance,
                min_authority,
            })
        } else {
            Err(format!(
                "unknown condition format: '{s}'. Expected 'badge:<type>[,min-convergence=<f>][,max-distance=<n>][,min-authority=<f>]'"
            ))
        }
    }

    /// Validate that the condition tree does not exceed [`MAX_CONDITION_DEPTH`].
    ///
    /// Call this before evaluating any condition tree received from an untrusted
    /// source. Returns `Err(GrantConditionError::ConditionsTooDeep)` if any
    /// branch exceeds the depth limit. Starts the counter at 0 (the root node).
    pub fn validate_depth(&self) -> Result<(), GrantConditionError> {
        self.check_depth_inner(0)
    }

    fn check_depth_inner(&self, depth: u32) -> Result<(), GrantConditionError> {
        if depth > MAX_CONDITION_DEPTH {
            return Err(GrantConditionError::ConditionsTooDeep { depth });
        }
        match self {
            Self::BadgeGate { .. } => Ok(()),
            Self::All(subs) | Self::Any(subs) => {
                for sub in subs {
                    sub.check_depth_inner(depth + 1)?;
                }
                Ok(())
            }
        }
    }

    /// Serialize this condition to a compact human-readable string (for display).
    pub fn display(&self) -> String {
        match self {
            Self::BadgeGate {
                badge_type,
                min_convergence,
                max_distance,
                min_authority,
            } => {
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

    /// GC-H1: an empty `All` combinator must be rejected at deserialization.
    /// A serialized `{"type":"all","value":[]}` would otherwise evaluate to
    /// `Met` (vacuous truth) and silently bypass any gating.
    #[test]
    fn deserialize_rejects_empty_all() {
        let err = serde_json::from_str::<GrantCondition>(r#"{"type":"all","value":[]}"#)
            .expect_err("empty All must be rejected at deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("empty All"),
            "expected empty-All rejection message, got: {msg}"
        );
    }

    /// GC-H1: an empty `Any` combinator must be rejected at deserialization.
    /// A serialized `{"type":"any","value":[]}` would otherwise short-circuit
    /// to `Met` and silently bypass any gating.
    #[test]
    fn deserialize_rejects_empty_any() {
        let err = serde_json::from_str::<GrantCondition>(r#"{"type":"any","value":[]}"#)
            .expect_err("empty Any must be rejected at deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("empty Any"),
            "expected empty-Any rejection message, got: {msg}"
        );
    }

    /// GC-H1: empty combinators nested inside an outer `All` must also be
    /// rejected — the validator must run recursively, not just at the top.
    #[test]
    fn deserialize_rejects_nested_empty_combinator() {
        let nested_all = r#"{"type":"all","value":[{"type":"all","value":[]}]}"#;
        let err = serde_json::from_str::<GrantCondition>(nested_all)
            .expect_err("nested empty All must be rejected");
        assert!(err.to_string().contains("empty All"));

        let nested_any = r#"{"type":"any","value":[{"type":"any","value":[]}]}"#;
        let err = serde_json::from_str::<GrantCondition>(nested_any)
            .expect_err("nested empty Any must be rejected");
        assert!(err.to_string().contains("empty Any"));
    }

    /// GC-H2: an unknown variant in a Vec<GrantCondition> must fail
    /// deserialization, not silently produce an empty Vec. Older nodes
    /// encountering a future protocol variant must fail-closed.
    #[test]
    fn deserialize_rejects_unknown_variant() {
        // Single unknown top-level condition.
        let err = serde_json::from_str::<GrantCondition>(r#"{"type":"future_variant","value":{}}"#)
            .expect_err("unknown variant must be rejected");
        assert!(
            !err.to_string().is_empty(),
            "expected a non-empty error for unknown variant"
        );

        // Unknown variant inside a Vec — must not produce an empty Vec.
        let result = serde_json::from_str::<Vec<GrantCondition>>(
            r#"[{"type":"future_variant","value":{}}]"#,
        );
        assert!(
            result.is_err(),
            "Vec containing unknown variant must error, not produce empty Vec"
        );
    }

    /// GC-H1: non-empty combinators must continue to deserialize cleanly —
    /// the rejection is scoped to the empty case only.
    #[test]
    fn deserialize_accepts_nonempty_combinators() {
        let json = r#"{"type":"all","value":[{"type":"badge_gate","value":{"badge_type":"verified-dev"}}]}"#;
        let parsed: GrantCondition =
            serde_json::from_str(json).expect("non-empty All must deserialize");
        assert_eq!(
            parsed,
            GrantCondition::All(vec![GrantCondition::badge("verified-dev")])
        );

        let json = r#"{"type":"any","value":[{"type":"badge_gate","value":{"badge_type":"verified-dev"}}]}"#;
        let parsed: GrantCondition =
            serde_json::from_str(json).expect("non-empty Any must deserialize");
        assert_eq!(
            parsed,
            GrantCondition::Any(vec![GrantCondition::badge("verified-dev")])
        );
    }

    /// C43-M3: unknown fields inside a `BadgeGate` value object must be rejected.
    /// Without `deny_unknown_fields` on `BadgeGateRepr`, a future security-
    /// critical field (e.g. `expires_after`, `revocation_check_interval`) added
    /// by a newer protocol version would be silently dropped by older binaries,
    /// weakening the gate without any signal.
    #[test]
    fn test_deserialize_rejects_unknown_badge_gate_field() {
        // Extra field alongside valid ones — must error.
        let with_extra = r#"{"type":"badge_gate","value":{"badge_type":"x","unknown_field":42}}"#;
        assert!(
            serde_json::from_str::<GrantCondition>(with_extra).is_err(),
            "unknown field in BadgeGate value must be rejected"
        );

        // Extra field only, no other fields — also must error.
        let only_extra =
            r#"{"type":"badge_gate","value":{"badge_type":"x","future_security_param":true}}"#;
        assert!(
            serde_json::from_str::<GrantCondition>(only_extra).is_err(),
            "future security field in BadgeGate value must be rejected"
        );
    }

    /// C43-M3: all currently-known optional fields must still deserialize
    /// cleanly after the `deny_unknown_fields` hardening.
    #[test]
    fn test_deserialize_accepts_known_badge_gate_fields() {
        let full = r#"{
            "type": "badge_gate",
            "value": {
                "badge_type": "verified-dev",
                "min_convergence": 0.6,
                "max_distance": 3,
                "min_authority": 0.8
            }
        }"#;
        let parsed: GrantCondition =
            serde_json::from_str(full).expect("all known BadgeGate fields must deserialize");
        assert_eq!(
            parsed,
            GrantCondition::BadgeGate {
                badge_type: "verified-dev".to_string(),
                min_convergence: Some(0.6),
                max_distance: Some(3),
                min_authority: Some(0.8),
            }
        );
    }

    /// A flat leaf condition at depth 0 must pass depth validation.
    #[test]
    fn depth_check_leaf_ok() {
        let c = GrantCondition::badge("verified-dev");
        assert!(c.validate_depth().is_ok());
    }

    /// A condition tree exactly at MAX_CONDITION_DEPTH (10) must pass.
    #[test]
    fn depth_check_at_limit_ok() {
        // Build a 10-deep nested All: All([All([...All([badge])])])
        // The outermost All is depth 0; the innermost badge is depth 10.
        let mut c = GrantCondition::badge("x");
        for _ in 0..MAX_CONDITION_DEPTH {
            c = GrantCondition::All(vec![c]);
        }
        assert!(
            c.validate_depth().is_ok(),
            "condition tree at MAX_CONDITION_DEPTH must be accepted"
        );
    }

    /// A condition tree one level past MAX_CONDITION_DEPTH (11) must
    /// be rejected with `ConditionsTooDeep`.
    #[test]
    fn depth_check_exceeds_limit_error() {
        // Build an 11-deep nested All — one level beyond the cap.
        let mut c = GrantCondition::badge("x");
        for _ in 0..=MAX_CONDITION_DEPTH {
            c = GrantCondition::All(vec![c]);
        }
        let err = c
            .validate_depth()
            .expect_err("11-deep condition tree must be rejected");
        assert!(
            matches!(err, GrantConditionError::ConditionsTooDeep { .. }),
            "expected ConditionsTooDeep, got: {err:?}"
        );
        assert!(
            err.to_string().contains("maximum nesting depth"),
            "error message must mention the depth cap, got: {err}"
        );
    }

    /// A 10-deep condition tree (the inclusive limit) evaluates without
    /// returning `ConditionsTooDeep`. Mirrors `depth_check_at_limit_ok`.
    #[test]
    fn condition_at_depth_10_evaluates() {
        // Outer All at depth 0, innermost badge at depth 10 → exactly at cap.
        let mut c = GrantCondition::badge("x");
        for _ in 0..MAX_CONDITION_DEPTH {
            c = GrantCondition::All(vec![c]);
        }
        assert!(
            c.validate_depth().is_ok(),
            "condition tree at MAX_CONDITION_DEPTH (10) must evaluate"
        );
    }

    /// An 11-deep condition tree (one past the cap) must be rejected
    /// with `ConditionsTooDeep`.
    #[test]
    fn condition_at_depth_11_returns_too_deep() {
        let mut c = GrantCondition::badge("x");
        for _ in 0..=MAX_CONDITION_DEPTH {
            c = GrantCondition::All(vec![c]);
        }
        let err = c
            .validate_depth()
            .expect_err("11-deep condition tree must return ConditionsTooDeep");
        assert!(
            matches!(err, GrantConditionError::ConditionsTooDeep { .. }),
            "expected ConditionsTooDeep, got: {err:?}"
        );
    }

    /// Wire-format stability: a fixed JSON string that predates the C43-M3
    /// `BadgeGateRepr` extraction must still deserialize identically.
    #[test]
    fn serde_wire_format_stable() {
        let fixed = r#"{"type":"badge_gate","value":{"badge_type":"verified-dev"}}"#;
        let parsed: GrantCondition =
            serde_json::from_str(fixed).expect("pre-change wire format must still deserialize");
        assert_eq!(parsed, GrantCondition::badge("verified-dev"));

        // Re-serialise and confirm the JSON matches the fixed string.
        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert_eq!(reserialized, fixed);
    }
}
