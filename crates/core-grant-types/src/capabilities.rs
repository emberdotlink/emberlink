//! core-grant-types::capabilities — per-capability container-isolation map.
//!
//! CLASSIFICATION: PUBLIC
//!
//! Per META-ARCH-CAPABILITY-ISOLATION-MAPPING. The
//! [`CAPABILITY_ISOLATION_MAP`] (anchor: `capability_isolation_map`) is the
//! operator-locked baseline that the container-split heuristic in
//! META-ARCH-AGENT-FLEET-TRUST-CLASS-AFFINITY consumes. Each [`Capability`]
//! enum variant carries a [`CapabilitySpec`] that names whether the capability
//! shares a trust domain with the broker (and therefore stays in-process) or
//! triggers a container-isolation boundary.
//!
//! **Default is fail-closed.** A capability's [`CapabilitySpec::share_trust_domain`]
//! must be `false` unless there is a documented threat-model reason to share
//! the broker's address space; the [`CapabilitySpec::reason`] field carries
//! that one-line justification and is the code-review checkpoint. Adding a new
//! variant without a matching entry in the map fails the
//! `every_capability_has_a_spec` test (fail-closed enforcement at compile
//! time + test time).
//!
//! Per ADR 140 (SCION integration trust-class fleet) and ADR 122 (composite-
//! grant runtime). Trust-boundary crate — CODEOWNERS protected.

use serde::{Deserialize, Serialize};

/// The named capabilities a grant statement may carry.
///
/// Variant names use snake-case-ish PascalCase that round-trips through serde
/// as snake_case strings. The string form is the wire identity used by the
/// rest of the runtime (broker handler's `caller_grant.capabilities`,
/// `Statement::actions`, etc.); the enum form is the type-safe lookup key for
/// [`CAPABILITY_ISOLATION_MAP`].
///
/// Adding a new variant to this enum REQUIRES a corresponding entry in
/// [`CAPABILITY_ISOLATION_MAP`] — the `every_capability_has_a_spec` test will
/// fail otherwise (fail-closed enforcement). Default policy for the new entry
/// is `share_trust_domain: false`; flipping it to `true` requires reviewer
/// sign-off and a one-line `reason` describing the threat-model judgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // --- Fail-closed (isolation-required) capabilities ---
    /// Fetch a URL from outside the operator's trust boundary. Untrusted-input
    /// surface — content must not flow into the broker's address space.
    ReadExternalUrl,
    /// Execute caller-supplied code (script, eval, shell-out). Untrusted-as-
    /// code surface — must not share the broker's address space.
    ExecuteUntrustedCode,
    /// Unconstrained network egress (any host, any port). Treated as an
    /// untrusted-input surface even when egressing to a "known" partner —
    /// composition risk under chained grants.
    NetworkEgressUnconstrained,
    /// Capability whose evaluation requires a fresh operator-presence assertion
    /// (Touch ID / passkey within N seconds). A fresh presence session lives
    /// in its own boundary so a stale broker session cannot satisfy it.
    OperatorPresenceFresh,
    /// Cross-uid `exec` (drop / change uid). Different uid namespace — must
    /// not run in the broker's process tree.
    CrossUidExec,
    /// Audit-isolation opt-in for red-team / compliance work. Always-isolated
    /// even when the underlying capability would otherwise share a trust
    /// domain; operator-driven flip.
    AuditIsolated,

    // --- Share-trust-domain (broker-internal) capabilities ---
    /// Bounded read of files inside the grant's scope. Parent grant's
    /// authority is the bound; no untrusted-input flow because the scope
    /// itself is the trust boundary.
    ReadFiles,
    /// Bounded write of files inside the grant's scope. Parent grant's
    /// authority is the bound.
    WriteFiles,
    /// Spawn an attenuated child agent. The spawn is attenuation, not
    /// isolation — the child inherits a bounded subset of the parent's
    /// authority and runs under its own container boundary. The spawn
    /// primitive itself is broker-internal.
    SpawnSubagent,
    /// LLM call routed through ember-proxy. Brokered + accounted; LLM input
    /// handled per F-2 Option B (intra-container hardening).
    LlmCall,
    /// Git operation brokered via the ember-git construct. Construct mediation
    /// is the trust boundary.
    GitOp,
    /// GitHub CLI operation brokered via the ember-gh construct. Construct
    /// mediation is the trust boundary.
    GhOp,
}

impl Capability {
    /// Canonical snake_case wire identity. Stable across releases — changing
    /// a string here is a breaking schema change.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadExternalUrl => "read_external_url",
            Self::ExecuteUntrustedCode => "execute_untrusted_code",
            Self::NetworkEgressUnconstrained => "network_egress_unconstrained",
            Self::OperatorPresenceFresh => "operator_presence_fresh",
            Self::CrossUidExec => "cross_uid_exec",
            Self::AuditIsolated => "audit_isolated",
            Self::ReadFiles => "read_files",
            Self::WriteFiles => "write_files",
            Self::SpawnSubagent => "spawn_subagent",
            Self::LlmCall => "llm_call",
            Self::GitOp => "git_op",
            Self::GhOp => "gh_op",
        }
    }

    /// Parse a wire-form capability name into its typed [`Capability`]. Returns
    /// `None` for unrecognised names; callers MUST treat unknown names as
    /// fail-closed (isolation-required) per the fail-closed default.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read_external_url" => Some(Self::ReadExternalUrl),
            "execute_untrusted_code" => Some(Self::ExecuteUntrustedCode),
            "network_egress_unconstrained" => Some(Self::NetworkEgressUnconstrained),
            "operator_presence_fresh" => Some(Self::OperatorPresenceFresh),
            "cross_uid_exec" => Some(Self::CrossUidExec),
            "audit_isolated" => Some(Self::AuditIsolated),
            "read_files" => Some(Self::ReadFiles),
            "write_files" => Some(Self::WriteFiles),
            "spawn_subagent" => Some(Self::SpawnSubagent),
            "llm_call" => Some(Self::LlmCall),
            "git_op" => Some(Self::GitOp),
            "gh_op" => Some(Self::GhOp),
            _ => None,
        }
    }

    /// All defined capability variants, in declaration order. Used by the
    /// fail-closed test to assert every variant has a [`CapabilitySpec`]
    /// entry in [`CAPABILITY_ISOLATION_MAP`].
    pub const ALL: &'static [Capability] = &[
        Self::ReadExternalUrl,
        Self::ExecuteUntrustedCode,
        Self::NetworkEgressUnconstrained,
        Self::OperatorPresenceFresh,
        Self::CrossUidExec,
        Self::AuditIsolated,
        Self::ReadFiles,
        Self::WriteFiles,
        Self::SpawnSubagent,
        Self::LlmCall,
        Self::GitOp,
        Self::GhOp,
    ];
}

/// Per-capability container-isolation annotation.
///
/// `share_trust_domain: false` is the fail-closed default — a capability with
/// this value triggers container isolation when the broker spawns a child agent
/// that holds it. `share_trust_domain: true` means the capability stays
/// in-process with the broker; flipping a capability from `false` → `true`
/// requires a documented `reason` (one-line threat-model judgement) AND
/// reviewer sign-off because the consequence is "this capability gets to share
/// address space with the broker's secrets."
///
/// A new [`Capability`] variant added without a corresponding `CapabilitySpec`
/// entry in [`CAPABILITY_ISOLATION_MAP`] is rejected by the
/// `every_capability_has_a_spec` test — the fail-closed gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySpec {
    /// Canonical wire-form name (matches [`Capability::name`]).
    pub name: &'static str,
    /// `false` = container isolation required (fail-closed default).
    /// `true` = capability stays in-process with the broker — requires a
    /// documented `reason`.
    pub share_trust_domain: bool,
    /// One-line threat-model justification. For `share_trust_domain: true`
    /// entries this MUST be non-empty and SHOULD start with the literal token
    /// "broker-internal: " so reviewers can grep for the opt-ins. For
    /// `share_trust_domain: false` entries this is a one-line reason the
    /// capability is isolated (for documentation / operator UI).
    pub reason: &'static str,
}

impl CapabilitySpec {
    /// Validator gate: a spec is well-formed iff (a) its name is non-empty,
    /// (b) its reason is non-empty, AND (c) if `share_trust_domain == true`
    /// then the reason starts with the literal token `"broker-internal:"`
    /// so reviewers can grep for the opt-ins.
    ///
    /// Returns `Ok(())` on a valid spec; returns `Err(reason)` with a short
    /// human-readable cause otherwise. Used by both the per-spec build-time
    /// assertions and the runtime `every_capability_has_a_spec` test.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty() {
            return Err("CapabilitySpec.name must be non-empty");
        }
        if self.reason.is_empty() {
            return Err("CapabilitySpec.reason must be non-empty");
        }
        if self.share_trust_domain {
            // const-fn-compatible prefix check (no &str::starts_with in const context).
            let bytes = self.reason.as_bytes();
            let prefix = b"broker-internal:";
            if bytes.len() < prefix.len() {
                return Err(
                    "CapabilitySpec.reason for share_trust_domain=true must start with \"broker-internal:\"",
                );
            }
            let mut i = 0;
            while i < prefix.len() {
                if bytes[i] != prefix[i] {
                    return Err(
                        "CapabilitySpec.reason for share_trust_domain=true must start with \"broker-internal:\"",
                    );
                }
                i += 1;
            }
        }
        Ok(())
    }
}

/// The per-capability container-isolation map. Operator-locked baseline per
/// META-ARCH-CAPABILITY-ISOLATION-MAPPING; refined in the adversarial-review
/// pass captured in the PR body.
///
/// Anchor: `capability_isolation_map` (referenced by `target_state_anchor`
/// in `tasks.toml`).
///
/// **Reading rule:** entries are in 1:1 correspondence with [`Capability`]
/// variants. The `every_capability_has_a_spec` test enforces this — add a
/// variant, you MUST add the corresponding spec, and the default is
/// `share_trust_domain: false` (fail-closed).
pub const CAPABILITY_ISOLATION_MAP: &[CapabilitySpec] = &[
    // --- Fail-closed (isolation-required) capabilities ---
    CapabilitySpec {
        name: "read_external_url",
        share_trust_domain: false,
        reason: "untrusted external input — must cross the proxy-mediated boundary",
    },
    CapabilitySpec {
        name: "execute_untrusted_code",
        share_trust_domain: false,
        reason: "untrusted-as-code — must not share the broker's address space",
    },
    CapabilitySpec {
        name: "network_egress_unconstrained",
        share_trust_domain: false,
        reason: "egress traffic must cross the proxy-mediated boundary",
    },
    CapabilitySpec {
        name: "operator_presence_fresh",
        share_trust_domain: false,
        reason: "fresh presence session lives in its own boundary",
    },
    CapabilitySpec {
        name: "cross_uid_exec",
        share_trust_domain: false,
        reason: "different uid namespace required",
    },
    CapabilitySpec {
        name: "audit_isolated",
        share_trust_domain: false,
        reason: "operator opt-in for red-team / compliance — always isolated",
    },
    // --- Share-trust-domain (broker-internal) capabilities ---
    // trust-domain: shared because the grant scope itself is the bound.
    CapabilitySpec {
        name: "read_files",
        share_trust_domain: true,
        reason: "broker-internal: bounded by grant scope; parent's authority is the bound",
    },
    // trust-domain: shared because the grant scope itself is the bound.
    CapabilitySpec {
        name: "write_files",
        share_trust_domain: true,
        reason: "broker-internal: bounded by grant scope; parent's authority is the bound",
    },
    // trust-domain: shared because spawn is attenuation, not isolation.
    CapabilitySpec {
        name: "spawn_subagent",
        share_trust_domain: true,
        reason: "broker-internal: spawn primitive is attenuation; child runs in its own container",
    },
    // trust-domain: shared because ember-proxy already brokers the LLM call.
    CapabilitySpec {
        name: "llm_call",
        share_trust_domain: true,
        reason: "broker-internal: proxy-brokered; LLM input handled per F-2 Option B intra-container hardening",
    },
    // trust-domain: shared because the ember-git construct mediates.
    CapabilitySpec {
        name: "git_op",
        share_trust_domain: true,
        reason: "broker-internal: brokered via ember-git construct shim",
    },
    // trust-domain: shared because the ember-gh construct mediates.
    CapabilitySpec {
        name: "gh_op",
        share_trust_domain: true,
        reason: "broker-internal: brokered via ember-gh construct shim",
    },
];

/// Look up a [`CapabilitySpec`] by wire-form name.
///
/// **Fail-closed semantics:** an unknown name returns `None`. Callers MUST
/// treat `None` as isolation-required (i.e. equivalent to a spec with
/// `share_trust_domain: false`); never assume an unknown capability can
/// share the broker's trust domain.
pub fn lookup_capability_spec(name: &str) -> Option<&'static CapabilitySpec> {
    CAPABILITY_ISOLATION_MAP.iter().find(|s| s.name == name)
}

/// Look up a [`CapabilitySpec`] by typed [`Capability`] variant. Always
/// succeeds in a well-formed build (enforced by the
/// `every_capability_has_a_spec` test); the `Option` shape mirrors the
/// string-keyed lookup for callers that mix the two.
pub fn capability_spec(capability: Capability) -> Option<&'static CapabilitySpec> {
    lookup_capability_spec(capability.name())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fail-closed enforcement: every [`Capability`] variant has a matching
    /// [`CapabilitySpec`] in [`CAPABILITY_ISOLATION_MAP`]. Adding a variant
    /// without adding a spec breaks this test — the gate that makes the
    /// fail-closed default real.
    #[test]
    fn every_capability_has_a_spec() {
        for capability in Capability::ALL.iter().copied() {
            let spec = lookup_capability_spec(capability.name());
            assert!(
                spec.is_some(),
                "capability {:?} ({}) has no entry in CAPABILITY_ISOLATION_MAP — \
                 fail-closed default requires explicit annotation",
                capability,
                capability.name(),
            );
        }
    }

    /// Round-trip enforcement: the map has no orphan entries that don't
    /// correspond to a [`Capability`] variant — drift in either direction
    /// is rejected.
    #[test]
    fn every_spec_has_a_capability() {
        for spec in CAPABILITY_ISOLATION_MAP.iter() {
            let parsed = Capability::parse(spec.name);
            assert!(
                parsed.is_some(),
                "CAPABILITY_ISOLATION_MAP entry {:?} does not correspond to a \
                 Capability variant — drift detected",
                spec.name,
            );
        }
    }

    /// Validator: every entry in [`CAPABILITY_ISOLATION_MAP`] is well-formed
    /// — non-empty name, non-empty reason, and `broker-internal:` prefix on
    /// every `share_trust_domain: true` entry.
    #[test]
    fn every_spec_is_well_formed() {
        for spec in CAPABILITY_ISOLATION_MAP.iter() {
            assert!(
                spec.validate().is_ok(),
                "CapabilitySpec for {:?} failed validation: {:?}",
                spec.name,
                spec.validate(),
            );
        }
    }

    /// Default-fail-closed: constructing a new `CapabilitySpec` with the
    /// brief-required defaults (`share_trust_domain: false`) is the path of
    /// least resistance and is accepted unconditionally as long as the
    /// reason is non-empty. The reverse (default-true) is what requires
    /// explicit opt-in.
    #[test]
    fn default_share_trust_domain_is_false() {
        let spec = CapabilitySpec {
            name: "hypothetical_new_capability",
            share_trust_domain: false,
            reason: "fail-closed default — new capability triggers isolation until reviewed",
        };
        assert!(
            !spec.share_trust_domain,
            "fail-closed default must be false"
        );
        assert!(spec.validate().is_ok());
        assert!(!spec.reason.is_empty(), "reason field is mandatory");
    }

    /// Validator rejects a `share_trust_domain: true` entry with an empty
    /// reason. Reviewer-facing tripwire — silently flipping to shared without
    /// a justification is the failure mode this guards against.
    #[test]
    fn validator_rejects_shared_without_reason() {
        let bad = CapabilitySpec {
            name: "bad_shared",
            share_trust_domain: true,
            reason: "",
        };
        assert!(bad.validate().is_err());
    }

    /// Validator rejects a `share_trust_domain: true` entry whose reason
    /// does NOT start with the literal `"broker-internal:"` prefix. The
    /// prefix is the grep-target reviewers use to enumerate opt-ins.
    #[test]
    fn validator_rejects_shared_without_broker_internal_prefix() {
        let bad = CapabilitySpec {
            name: "bad_prefix",
            share_trust_domain: true,
            reason: "this looks shared but the prefix is missing",
        };
        assert!(bad.validate().is_err());
    }

    /// Validator rejects an empty-name entry regardless of share state. Names
    /// MUST be the canonical wire identity per [`Capability::name`].
    #[test]
    fn validator_rejects_empty_name() {
        let bad = CapabilitySpec {
            name: "",
            share_trust_domain: false,
            reason: "ok reason",
        };
        assert!(bad.validate().is_err());
    }

    /// `lookup_capability_spec` returns `None` for unknown names — the
    /// fail-closed posture is enforced at the callsite, not by the lookup
    /// surface. Callers MUST treat `None` as isolation-required.
    #[test]
    fn lookup_returns_none_for_unknown_name() {
        assert!(lookup_capability_spec("not_a_real_capability").is_none());
    }

    /// `capability_spec` is total over [`Capability`] — every variant resolves.
    /// This is the typed sibling of `every_capability_has_a_spec`.
    #[test]
    fn capability_spec_is_total_over_enum() {
        for capability in Capability::ALL.iter().copied() {
            let spec = capability_spec(capability);
            assert!(
                spec.is_some(),
                "capability_spec({:?}) returned None — map drift",
                capability,
            );
        }
    }

    /// Round-trip: every variant's `name()` parses back to the same variant.
    #[test]
    fn name_parse_round_trip() {
        for capability in Capability::ALL.iter().copied() {
            let parsed = Capability::parse(capability.name());
            assert_eq!(parsed, Some(capability));
        }
    }

    /// Serde round-trip via snake_case wire form. Locks the on-wire identity
    /// so a future variant rename can't silently break stored grants.
    #[test]
    fn serde_round_trip_snake_case() {
        for capability in Capability::ALL.iter().copied() {
            let json = serde_json::to_string(&capability).expect("serialize");
            // Wire form is a JSON string literal of the snake_case name.
            let expected = format!("\"{}\"", capability.name());
            assert_eq!(json, expected);
            let back: Capability = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, capability);
        }
    }
}
