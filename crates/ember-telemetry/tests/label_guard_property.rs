//! T1: property tests for the telemetry label-discipline trust boundary
//! (ADR 212 §5). No I/O — pure exposition rendering + the forbidden-value gate.

use ember_telemetry::{ResourceIdentity, TelemetryRegistry, guard_label_value};
use proptest::prelude::*;

proptest! {
    /// INVARIANT: the rendered exposition never contains a per-principal
    /// identifier as a label, regardless of the resource-identity values.
    /// `ResourceIdentity` only carries process/instance/version/build_sha;
    /// there is no constructor path that puts persona/grant/session into it.
    #[test]
    fn exposition_never_carries_per_principal_label(
        process in "[a-z][a-z0-9_-]{0,20}",
        instance in "[a-z0-9.:_-]{0,30}",
        version in "[0-9]\\.[0-9]\\.[0-9]",
        sha in "[0-9a-f]{7,40}",
    ) {
        let reg = TelemetryRegistry::new(ResourceIdentity::new(
            process, instance, version, sha,
        ));
        let out = reg.render().expect("render");
        prop_assert!(!out.contains("persona_id"), "leaked persona_id: {out}");
        prop_assert!(!out.contains("grant_id"), "leaked grant_id: {out}");
        prop_assert!(!out.contains("session_id"), "leaked session_id: {out}");
    }

    /// INVARIANT: the guard is total — every input either returns the same
    /// borrowed value (safe) or a non-empty reason string (forbidden). It never
    /// panics and never mutates the input.
    #[test]
    fn guard_is_total_and_value_preserving(value in ".{0,64}") {
        match guard_label_value(&value) {
            Ok(passed) => prop_assert_eq!(passed, value.as_str()),
            Err(reason) => prop_assert!(!reason.is_empty()),
        }
    }

    /// INVARIANT: a known credential prefix is ALWAYS rejected, no matter what
    /// suffix follows it. The guard is the trust boundary, so it must trip on
    /// the whole prefix family, not just the fixture strings.
    #[test]
    fn known_credential_prefixes_always_rejected(suffix in "[A-Za-z0-9_]{0,40}") {
        for prefix in ["ghp_", "github_pat_", "sk-ant-", "AKIA", "hvs."] {
            let candidate = format!("{prefix}{suffix}");
            prop_assert!(
                guard_label_value(&candidate).is_err(),
                "guard let a {prefix} value through: {candidate}"
            );
        }
    }
}
