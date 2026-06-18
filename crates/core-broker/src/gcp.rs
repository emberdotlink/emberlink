//! GCP native scope shared wire type + [`GcpProjector`] (ADR 204 / I7).
//!
//! CLASSIFICATION: PUBLIC
//! when present; otherwise default-INTERNAL per the rubric.
//!
//! Replaces the dead-code stub that lived in this slot prior to
//! `AUDIT-V030-GCP-PROVIDER-PROJECTOR`. The projector matches the AWS STS
//! `provider_echo + I7 clamp = matched pair` shape (PR #5716): a typed
//! `native_upper_bound` parser that reconstructs the bound identity from the
//! daemon-computed native payload so [`crate::identity_upper_bound`] can run
//! the [`crate::MintStamp::Identity`] clamp against GCP mints.
//!
//! GCP is a G2 provider in ADR 213's grading: the broker mints a
//! short-lived OAuth access token impersonating a target service account.
//! The provider's "stamp" is the identity of that SA (`client_email` for
//! the SA-key path, or the `service_account_email` for the WIF +
//! impersonation path) — there is no granular least-privilege permission
//! axis on the wire that lower-bounds the token, so `MintStamp::Permissions`
//! is structurally unavailable. The clamp shape is therefore identity-only,
//! mirroring AWS STS.
//!
//! ## Native scope shape
//!
//! The wire shape `ember_broker::GcpBroker::issue` consumes is the JSON
//! form of [`GcpNativeScope`]:
//!
//! ```json
//! {
//!   "target_service_account": "deployer@target-proj.iam.gserviceaccount.com",
//!   "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
//!   "ttl_seconds": 3600,
//!   "delegates": []
//! }
//! ```
//!
//! Per ADR 204 the caller-facing `broker_issue` path carries no native
//! `scope`; this type is daemon-computed output only. The
//! [`GcpProjector::native_upper_bound`] inverse reads the same shape back
//! to extract the impersonation-target identity that the projector
//! embedded.
//!
//! Anchor: `GcpProjector` — pinned in the grounding header for
//! `AUDIT-V030-GCP-PROVIDER-PROJECTOR`.

use serde::{Deserialize, Serialize};

use crate::project::ProjectionError;
use crate::{BrokerProvider, BrokerScope, IdentityRef};

/// GCP native scope — the wire shape `ember_broker::GcpBroker::issue`
/// consumes. Defined here, in the lower crate, so the projector and the
/// broker share **one** typed shape and cannot drift; `ember-broker`
/// re-exports this type.
///
/// `target_service_account` is the impersonation target — the SA the
/// daemon's broker is asking the IAM Credentials API to mint an access
/// token for. The projector's `native_upper_bound` extracts this as the
/// bound identity for the I7 clamp. `scopes`, `ttl_seconds`, and
/// `delegates` are passed through unchanged on the wire but are not
/// authority-bearing on the identity axis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpNativeScope {
    pub target_service_account: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub ttl_seconds: u64,
    #[serde(default)]
    pub delegates: Vec<String>,
}

/// Parsed abstract upper bound of a projected GCP native payload.
///
/// Mirrors [`crate::project::AwsStsUpperBound`] in spirit — a typed
/// envelope holding only the identity-bearing axis (the target service
/// account email) extracted from the native scope. Permission-bearing
/// fields are deliberately absent: GCP is G2, identity-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpUpperBound {
    pub target_service_account: String,
}

/// Projects GCP impersonation mints — and re-parses native payloads back
/// into the bound identity for the I7 clamp.
///
/// Mirrors the AWS STS `provider_echo + I7 clamp = matched pair` shape
/// (PR #5716): the projector is the only code permitted to speak GCP's
/// native scope language, and its inverse [`GcpProjector::native_upper_bound`]
/// is what [`crate::identity_upper_bound`] uses to extract the bound
/// identity from a minted scope so the daemon clamp can re-verify
/// `MintStamp::Identity` against the projector's claim.
///
/// Today the projector exposes only the inverse parser — the forward
/// `project()` path is not yet wired (G2 providers do not synthesize
/// caller-driven IAM policy in the same way the AWS PermissionSpec
/// projector does, and the GCP target-SA is daemon/operator-authored).
/// The parser side is what closes the I7 clamp gap for GCP mints.
///
/// Fail-closed: any native payload that omits `target_service_account`,
/// supplies an empty / whitespace-only value, or is structurally
/// unparseable refuses with [`ProjectionError`]. The
/// [`crate::identity_upper_bound`] arm wraps these failures so the daemon
/// clamp surfaces them as
/// `BrokerError::PolicyRejected("identity_upper_bound refused …")`.
pub struct GcpProjector;

impl GcpProjector {
    pub fn provider(&self) -> BrokerProvider {
        BrokerProvider::Gcp
    }

    /// Re-parse a GCP native payload into its abstract identity upper
    /// bound. The bound identity is the impersonation target service
    /// account; the daemon clamp compares this against the
    /// `MintStamp::Identity` the broker stamped.
    ///
    /// Refuses (fail-closed) on:
    /// - native scope is not the expected `GcpNativeScope` JSON shape
    /// - `target_service_account` is empty or whitespace-only (would
    ///   widen the clamp to "any SA the broker happens to impersonate")
    pub fn native_upper_bound(
        &self,
        native: &BrokerScope,
    ) -> Result<GcpUpperBound, ProjectionError> {
        let scope: GcpNativeScope = serde_json::from_value(native.clone())
            .map_err(|e| ProjectionError::Unparseable(format!("gcp native scope: {e}")))?;
        let target = scope.target_service_account.trim();
        if target.is_empty() {
            return Err(ProjectionError::Refused(
                "gcp native scope target_service_account is empty — refusing to clamp \
                 against an unbounded impersonation target"
                    .to_string(),
            ));
        }
        Ok(GcpUpperBound {
            target_service_account: target.to_string(),
        })
    }
}

/// Convenience: build an [`IdentityRef`] tagged with [`BrokerProvider::Gcp`]
/// from a parsed [`GcpUpperBound`]. Used by [`crate::identity_upper_bound`]
/// so the I7 clamp routing stays a one-line match arm per provider.
pub fn identity_ref_from_bound(bound: GcpUpperBound) -> IdentityRef {
    IdentityRef {
        provider: BrokerProvider::Gcp,
        identity: bound.target_service_account,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectionError;
    use proptest::prelude::*;

    fn valid_native() -> BrokerScope {
        serde_json::json!({
            "target_service_account": "deployer@target-proj.iam.gserviceaccount.com",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "ttl_seconds": 3600,
            "delegates": [],
        })
    }

    #[test]
    fn projector_reports_gcp_provider() {
        assert_eq!(GcpProjector.provider(), BrokerProvider::Gcp);
    }

    #[test]
    fn native_upper_bound_extracts_target_service_account() {
        let bound = GcpProjector
            .native_upper_bound(&valid_native())
            .expect("upper bound");
        assert_eq!(
            bound.target_service_account,
            "deployer@target-proj.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn native_upper_bound_round_trips_via_identity_ref() {
        let bound = GcpProjector
            .native_upper_bound(&valid_native())
            .expect("upper bound");
        let identity = identity_ref_from_bound(bound);
        assert_eq!(identity.provider, BrokerProvider::Gcp);
        assert_eq!(
            identity.identity,
            "deployer@target-proj.iam.gserviceaccount.com"
        );
    }

    #[test]
    fn native_upper_bound_refuses_empty_target() {
        let native = serde_json::json!({
            "target_service_account": "",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "ttl_seconds": 3600,
            "delegates": [],
        });
        let err = GcpProjector.native_upper_bound(&native).unwrap_err();
        assert!(
            matches!(err, ProjectionError::Refused(_)),
            "empty target_service_account must Refuse: {err:?}"
        );
    }

    #[test]
    fn native_upper_bound_refuses_whitespace_only_target() {
        let native = serde_json::json!({
            "target_service_account": "   \t\n",
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "ttl_seconds": 3600,
            "delegates": [],
        });
        let err = GcpProjector.native_upper_bound(&native).unwrap_err();
        assert!(
            matches!(err, ProjectionError::Refused(_)),
            "whitespace-only target_service_account must Refuse: {err:?}"
        );
    }

    /// T1 — property test on the clamp arm: every native shape NOT in the
    /// projector's accepted vocabulary fails closed with
    /// [`ProjectionError`]. This is the GCP counterpart to the AWS STS
    /// "other => Err fails closed" arm; the projector's `native_upper_bound`
    /// must REFUSE every unparseable / unbounded shape we can throw at it,
    /// never silently widen to an unbounded identity.
    ///
    /// Each row is a (label, native JSON value, expected variant
    /// discriminant). We assert the discriminant matches the kind we
    /// expect — `Refused` for shapes that parse structurally but are
    /// unbounded (empty/missing identity), `Unparseable` for shapes that
    /// don't even deserialize as `GcpNativeScope`. The single property:
    /// *no input in this row table returns `Ok`*.
    #[test]
    fn t1_clamp_arm_property_fails_closed_on_every_non_native_shape() {
        // (label, native, expected variant tag)
        // expected tag: "refused" | "unparseable"
        let cases: Vec<(&str, serde_json::Value, &str)> = vec![
            (
                "missing target_service_account field",
                serde_json::json!({
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                "unparseable",
            ),
            (
                "empty target_service_account",
                serde_json::json!({
                    "target_service_account": "",
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    "ttl_seconds": 3600,
                }),
                "refused",
            ),
            (
                "whitespace target_service_account",
                serde_json::json!({
                    "target_service_account": "   ",
                    "scopes": [],
                    "ttl_seconds": 0,
                }),
                "refused",
            ),
            (
                "string instead of object",
                serde_json::json!("not-an-object"),
                "unparseable",
            ),
            (
                "array instead of object",
                serde_json::json!(["target", "sa"]),
                "unparseable",
            ),
            ("null", serde_json::Value::Null, "unparseable"),
            (
                "wrong types (ttl_seconds as string)",
                serde_json::json!({
                    "target_service_account": "x@y",
                    "scopes": [],
                    "ttl_seconds": "three thousand",
                }),
                "unparseable",
            ),
            (
                "AWS-style payload (provider confusion)",
                serde_json::json!({
                    "mode": "assume_role",
                    "role_arn": "arn:aws:iam::123456789012:role/ember-agent",
                    "session_name": "ember-session",
                    "ttl_seconds": 900,
                }),
                "unparseable",
            ),
            (
                "GitHub-style payload (provider confusion)",
                serde_json::json!({
                    "repositories": ["acme/widgets"],
                    "permissions": [["contents", "write"]],
                }),
                "unparseable",
            ),
            ("empty object", serde_json::json!({}), "unparseable"),
            ("number", serde_json::json!(42), "unparseable"),
        ];

        let mut checked = 0usize;
        for (label, native, expected) in &cases {
            let result = GcpProjector.native_upper_bound(native);
            let err = match result {
                Ok(bound) => panic!(
                    "case {label:?}: native_upper_bound MUST refuse non-native shapes — \
                     unexpected Ok({bound:?})"
                ),
                Err(e) => e,
            };
            match (expected, &err) {
                (&"refused", ProjectionError::Refused(_)) => {}
                (&"unparseable", ProjectionError::Unparseable(_)) => {}
                _ => panic!("case {label:?}: expected variant {expected:?}, got {err:?}"),
            }
            checked += 1;
        }
        assert_eq!(
            checked, 11,
            "T1 property test must cover every row in the fail-closed table"
        );
    }

    fn non_string_json_value() -> impl Strategy<Value = serde_json::Value> {
        prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
            proptest::collection::vec(any::<i64>(), 0..4).prop_map(|items| {
                serde_json::Value::Array(
                    items
                        .into_iter()
                        .map(|n| serde_json::Value::Number(n.into()))
                        .collect(),
                )
            }),
            Just(serde_json::json!({"nested": "value"})),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        // Anchor: core_broker_proptest_projector_clamps_landed
        #[test]
        fn native_upper_bound_refuses_non_object_payloads(native in prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
            "[a-zA-Z0-9 _.-]{0,32}".prop_map(serde_json::Value::String),
            proptest::collection::vec(any::<i64>(), 0..4).prop_map(|items| {
                serde_json::Value::Array(
                    items
                        .into_iter()
                        .map(|n| serde_json::Value::Number(n.into()))
                        .collect(),
                )
            }),
        ]) {
            let err = GcpProjector.native_upper_bound(&native).unwrap_err();
            prop_assert!(
                matches!(err, ProjectionError::Unparseable(_)),
                "non-object payload must be unparseable: {err:?}"
            );
        }

        #[test]
        fn native_upper_bound_refuses_non_string_or_blank_targets(
            target in prop_oneof![
                non_string_json_value(),
                "[ \t\n]{0,8}".prop_map(serde_json::Value::String),
            ],
            ttl_seconds in any::<u64>(),
        ) {
            let native = serde_json::json!({
                "target_service_account": target,
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "ttl_seconds": ttl_seconds,
                "delegates": [],
            });

            let err = GcpProjector.native_upper_bound(&native).unwrap_err();

            prop_assert!(
                matches!(
                    err,
                    ProjectionError::Refused(_) | ProjectionError::Unparseable(_)
                ),
                "invalid target must fail closed: {err:?}"
            );
        }

        #[test]
        fn native_upper_bound_extracts_any_nonblank_target(
            prefix in "[ \t]{0,4}",
            target in "[a-zA-Z0-9_.@-]{1,64}",
            suffix in "[ \t]{0,4}",
            ttl_seconds in any::<u64>(),
            scopes in proptest::collection::vec("[a-zA-Z0-9:/._-]{0,64}", 0..4),
            delegates in proptest::collection::vec("[a-zA-Z0-9@._-]{0,64}", 0..4),
        ) {
            prop_assume!(!target.trim().is_empty());
            let padded = format!("{prefix}{target}{suffix}");
            let native = serde_json::json!({
                "target_service_account": padded,
                "scopes": scopes,
                "ttl_seconds": ttl_seconds,
                "delegates": delegates,
            });

            let bound = GcpProjector
                .native_upper_bound(&native)
                .expect("nonblank target should parse");

            prop_assert_eq!(bound.target_service_account, target.trim());
        }
    }
}
