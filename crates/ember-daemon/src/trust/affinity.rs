//! ember-daemon::trust::affinity — runtime consumer for the operator-locked
//! per-capability container-isolation map (`CAPABILITY_ISOLATION_MAP`).
//!
//! CLASSIFICATION: PUBLIC
//!
//! ## Checkpoint
//!
//! `capability_isolation_map_consumed` — this module is the production read
//! site for `core_grant_types::capabilities::CAPABILITY_ISOLATION_MAP`. PR
//! `4584eeef` shipped the map declaratively (565 LOC); until this module
//! landed, the map had ZERO production read sites and therefore provided
//! ZERO runtime protection. The container-split heuristic in
//! `META-ARCH-AGENT-FLEET-TRUST-CLASS-AFFINITY` consumes this module's
//! [`decide_container_split`] to choose between `SharedTrustDomain`
//! (in-broker-process) and `ContainerIsolated` (separate container boundary)
//! at child-spawn time.
//!
//! ## Fail-closed contract
//!
//! [`decide_container_split`] takes a slice of wire-form capability names
//! (the same snake_case identifiers carried on the wire by `Statement` and
//! by `broker.mint_sub_persona`'s `capabilities` array). For each name it
//! looks up the matching [`core_grant_types::capabilities::CapabilitySpec`]:
//!
//! * `share_trust_domain == true` capabilities are eligible for
//!   `SharedTrustDomain`.
//! * `share_trust_domain == false` capabilities REQUIRE `ContainerIsolated`
//!   and immediately drive the decision (strictest-isolation-wins).
//! * Unknown capabilities — names not in the map — return a typed
//!   [`AffinityError::CapabilityNotClassified`]. The consumer surfaces this
//!   as a fail-closed RPC error rather than silently defaulting to
//!   `SharedTrustDomain`, which would let an unclassified capability share
//!   the broker's address space.
//!
//! "Strictest-isolation-wins" means: a request that includes BOTH a
//! shared-trust-domain capability AND a container-isolated one is forced to
//! `ContainerIsolated`. This is the inverse of fail-open behaviour: any
//! capability in the request that needs isolation MUST get isolation, even
//! if its siblings would otherwise have stayed in-process.
//!
//! Per ADR 166 (META-AP consumer wiring); refines META-ARCH-CAPABILITY-
//! ISOLATION-MAPPING. Trust-boundary crate — CODEOWNERS protected.

use core_grant_types::capabilities::lookup_capability_spec;

/// The isolation level the broker should apply to a child spawn that carries
/// a particular set of capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// All requested capabilities are flagged `share_trust_domain: true` in
    /// `CAPABILITY_ISOLATION_MAP`. The child may run in the broker's trust
    /// domain (in-process) because every capability is broker-mediated by
    /// construct, brokered by ember-proxy, or scope-bounded by the parent's
    /// grant.
    SharedTrustDomain,
    /// At least one requested capability is flagged `share_trust_domain:
    /// false`. The child MUST run in a separate container boundary; the
    /// driving capability's wire name and threat-model reason are carried
    /// through on [`AffinityDecision`] so callers can render an operator-
    /// facing audit row.
    ContainerIsolated,
}

/// The result of [`decide_container_split`].
///
/// `driving_capability` and `driving_reason` are populated only for
/// `ContainerIsolated`; for `SharedTrustDomain` they are empty strings. The
/// downstream consumer surfaces them on the audit row that records the
/// container-split decision so a reviewer can see WHY the broker chose
/// isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinityDecision {
    /// The isolation level the broker MUST apply.
    pub level: IsolationLevel,
    /// For `ContainerIsolated`, the wire-form name of the first capability
    /// that forced isolation. Empty for `SharedTrustDomain`.
    pub driving_capability: &'static str,
    /// For `ContainerIsolated`, the matching `CapabilitySpec.reason` (the
    /// one-line threat-model justification). Empty for `SharedTrustDomain`.
    pub driving_reason: &'static str,
}

/// Typed errors returned by [`decide_container_split`].
///
/// `CapabilityNotClassified` is the fail-closed posture for unknown
/// capability names; `MalformedSpec` is a sanity check on the static map
/// itself and should never fire in a well-formed build (the
/// `every_spec_is_well_formed` test in `core-grant-types` already enforces
/// this at build time, but we keep the runtime guard so the consumer never
/// silently accepts a malformed entry if a future map edit slips through).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffinityError {
    /// The capability name was not found in `CAPABILITY_ISOLATION_MAP`.
    /// The error message names the offending capability and the literal
    /// token "fail-closed" so reviewers (and the consumer's RPC error
    /// surface) can identify the posture from the string alone.
    CapabilityNotClassified(String),
    /// A `CapabilitySpec` looked up from the map failed its own
    /// [`core_grant_types::capabilities::CapabilitySpec::validate`] gate.
    /// Defence-in-depth — should never fire in a well-formed build.
    MalformedSpec {
        /// Wire-form capability name whose spec failed validation.
        name: String,
        /// Short human-readable cause from `CapabilitySpec::validate`.
        cause: String,
    },
}

impl std::fmt::Display for AffinityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityNotClassified(name) => write!(
                f,
                "capability {name:?} has no entry in CAPABILITY_ISOLATION_MAP — \
                 fail-closed: refusing to assume share_trust_domain for an \
                 unclassified capability"
            ),
            Self::MalformedSpec { name, cause } => write!(
                f,
                "CapabilitySpec for {name:?} failed validation: {cause} — \
                 fail-closed"
            ),
        }
    }
}

impl std::error::Error for AffinityError {}

/// Decide the container-isolation level for a child spawn that will carry
/// `capabilities`.
///
/// **Strictest-isolation-wins.** A single `share_trust_domain: false`
/// capability forces [`IsolationLevel::ContainerIsolated`] regardless of
/// what its siblings say. Order-independent: the same input set returns the
/// same `level` regardless of slice order (the `driving_capability` /
/// `driving_reason` strings reflect the first-encountered isolating entry
/// in input order, but the `level` itself is stable).
///
/// **Fail-closed on unknown.** A capability name not present in
/// `CAPABILITY_ISOLATION_MAP` returns
/// [`AffinityError::CapabilityNotClassified`]; the consumer surfaces this
/// as an RPC error and refuses the spawn. Silent defaulting to
/// `SharedTrustDomain` would defeat the entire point of the fail-closed
/// map: an attacker who can name a capability the broker doesn't recognise
/// would otherwise get to share the broker's address space.
///
/// **Empty input.** A zero-capability spawn returns
/// [`IsolationLevel::SharedTrustDomain`] with empty `driving_*` strings;
/// there is no isolation-requiring capability to drive a split, and the
/// authority surface this represents is the empty-set, which is the most
/// permissive (also lowest-risk) shape.
///
/// Anchor: `capability_isolation_map_consumed`.
pub fn decide_container_split(
    capabilities: &[&str],
) -> Result<AffinityDecision, AffinityError> {
    for name in capabilities {
        let spec = lookup_capability_spec(name).ok_or_else(|| {
            AffinityError::CapabilityNotClassified((*name).to_string())
        })?;
        // Defence-in-depth: re-validate the spec we read. Cheap; runs once
        // per capability per spawn. The core-grant-types build-time test
        // (`every_spec_is_well_formed`) is the primary gate; this is the
        // belt-and-braces runtime check that a future map edit can't slip
        // a malformed entry past the consumer.
        if let Err(cause) = spec.validate() {
            return Err(AffinityError::MalformedSpec {
                name: spec.name.to_string(),
                cause: cause.to_string(),
            });
        }
        if !spec.share_trust_domain {
            // Strictest-isolation-wins: short-circuit on the first
            // isolation-requiring capability.
            return Ok(AffinityDecision {
                level: IsolationLevel::ContainerIsolated,
                driving_capability: spec.name,
                driving_reason: spec.reason,
            });
        }
    }
    Ok(AffinityDecision {
        level: IsolationLevel::SharedTrustDomain,
        driving_capability: "",
        driving_reason: "",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_grant_types::capabilities::Capability;

    /// Empty list — the no-capability case. Returns `SharedTrustDomain`
    /// because there is no isolation-requiring capability to drive a split.
    #[test]
    fn empty_capabilities_returns_shared_trust_domain() {
        let decision = decide_container_split(&[]).expect("empty input must succeed");
        assert_eq!(decision.level, IsolationLevel::SharedTrustDomain);
        assert_eq!(decision.driving_capability, "");
        assert_eq!(decision.driving_reason, "");
    }

    /// All-shared input — every capability is `share_trust_domain: true`.
    #[test]
    fn all_shared_capabilities_returns_shared_trust_domain() {
        let caps = [
            Capability::ReadFiles.name(),
            Capability::WriteFiles.name(),
            Capability::GitOp.name(),
            Capability::GhOp.name(),
        ];
        let decision = decide_container_split(&caps).expect("all-shared must succeed");
        assert_eq!(decision.level, IsolationLevel::SharedTrustDomain);
    }

    /// Mixed-strictness — one isolation-requiring capability forces the
    /// whole spawn to `ContainerIsolated` regardless of the shared siblings.
    #[test]
    fn mixed_strictness_isolation_wins() {
        let caps = [
            Capability::ReadFiles.name(),
            Capability::ReadExternalUrl.name(),
            Capability::GitOp.name(),
        ];
        let decision = decide_container_split(&caps).expect("mixed input must succeed");
        assert_eq!(decision.level, IsolationLevel::ContainerIsolated);
        assert_eq!(
            decision.driving_capability,
            Capability::ReadExternalUrl.name()
        );
    }

    /// Order independence on the LEVEL itself — the same set returns the
    /// same `IsolationLevel` regardless of order. The driving_capability
    /// string reflects insertion order (first isolation-requiring hit), but
    /// `level` is stable.
    #[test]
    fn order_independent_on_level() {
        let a = [
            Capability::ReadFiles.name(),
            Capability::ReadExternalUrl.name(),
        ];
        let b = [
            Capability::ReadExternalUrl.name(),
            Capability::ReadFiles.name(),
        ];
        let da = decide_container_split(&a).unwrap();
        let db = decide_container_split(&b).unwrap();
        assert_eq!(da.level, db.level);
        assert_eq!(da.level, IsolationLevel::ContainerIsolated);
    }

    /// Unknown capability fails closed with the typed error variant.
    #[test]
    fn unknown_capability_fails_closed() {
        let err = decide_container_split(&["not_a_real_capability"]).unwrap_err();
        match err {
            AffinityError::CapabilityNotClassified(name) => {
                assert_eq!(name, "not_a_real_capability");
            }
            other => panic!("expected CapabilityNotClassified, got {other:?}"),
        }
    }

    /// Unknown name mixed with known names — still fails closed. We do NOT
    /// silently accept a partial classification; an unclassified capability
    /// in the slice poisons the entire decision.
    #[test]
    fn unknown_mixed_with_known_still_fails_closed() {
        let caps = [
            Capability::ReadFiles.name(),
            "not_a_real_capability",
            Capability::GitOp.name(),
        ];
        let err = decide_container_split(&caps).unwrap_err();
        assert!(matches!(err, AffinityError::CapabilityNotClassified(_)));
    }

    /// The error message contains the offending name AND the literal token
    /// "fail-closed" so reviewers (and the consumer's RPC error surface)
    /// can identify the posture from the string alone.
    #[test]
    fn error_message_contains_offending_name_and_fail_closed_token() {
        let err = decide_container_split(&["mystery_capability"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mystery_capability"),
            "error message must name the offending capability, got: {msg}"
        );
        assert!(
            msg.contains("fail-closed"),
            "error message must contain the literal token \"fail-closed\", got: {msg}"
        );
    }

    /// `AffinityDecision.driving_reason` is the static `CapabilitySpec.reason`
    /// of the first isolation-requiring capability — carried through to the
    /// consumer so an audit row can render WHY isolation was chosen.
    #[test]
    fn driving_reason_carried_through_to_consumer() {
        let caps = [Capability::ExecuteUntrustedCode.name()];
        let decision = decide_container_split(&caps).unwrap();
        assert_eq!(decision.level, IsolationLevel::ContainerIsolated);
        assert_eq!(
            decision.driving_capability,
            Capability::ExecuteUntrustedCode.name()
        );
        // Match the `CAPABILITY_ISOLATION_MAP` entry for
        // `execute_untrusted_code` — locked in `core-grant-types`.
        assert!(
            !decision.driving_reason.is_empty(),
            "driving_reason must be non-empty for ContainerIsolated"
        );
        assert!(
            decision.driving_reason.contains("untrusted-as-code"),
            "driving_reason must carry the threat-model justification verbatim, got: {}",
            decision.driving_reason
        );
    }

    /// Exhaustiveness — every `Capability::ALL` variant resolves through
    /// `decide_container_split` without erroring. This is the runtime sibling
    /// of `core-grant-types`' `every_capability_has_a_spec` test: if a
    /// variant were added without a matching spec, this test fails. (Each
    /// single-cap call also exercises whichever branch the spec dictates.)
    #[test]
    fn every_capability_variant_resolves() {
        for cap in Capability::ALL.iter().copied() {
            let decision = decide_container_split(&[cap.name()]);
            assert!(
                decision.is_ok(),
                "Capability::{cap:?} ({}) failed to resolve through \
                 decide_container_split — map drift",
                cap.name(),
            );
        }
    }
}
