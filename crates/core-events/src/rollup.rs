//! Construct-invocation rollup types and computation.
//!
//! Implements the read-time rollup design at
//! [`docs/construct-receipt-rollup.md`](../../../docs/construct-receipt-rollup.md):
//! a single Construct invocation currently produces 4+ Receipts as it crosses
//! ADR 183's authority-space / execution-space boundary — `broker.materialization`
//! + `broker.resolution` + `session.construct_invocation` + `broker.revocation`.
//!
//! The dashboard's default view and the `ember receipt rollup` CLI verb
//! collapse them into one row keyed by `materialization_id`, with sub-Receipt
//! detail one click / flag away.
//!
//! This module is the **type surface** (envelope shape + outcome enum + sub-Receipt
//! reference) plus the rollup computation. Sub-Receipt types themselves live in
//! [`crate::receipt`]; this module just references them by `(kind, ts, hash)`.
//!
//! Tracks **AP-CONSTRUCT-RECEIPT-ROLLUP-VIEW** (P2/M). The four-receipt shape is
//! an implementation detail; the architecture framing is ADR 183's split between
//! agent space, authority space, and execution space.

use std::collections::HashMap;

use core_event_types::ActionRef;

/// Outcome of a Construct invocation, derived from the chained sub-Receipts.
///
/// **Mapping rules** (per design doc §1):
/// - `Success` if `session.construct_invocation.exit_code == 0` AND
///   `broker.revocation` has fired for the same `materialization_id`.
/// - `Denied` if any sub-Receipt is a `*_denied` kind (e.g.
///   `broker.exec.denied_resource_limit`, `broker.exec.denied_binary_pin_mismatch`).
/// - `Errored` if `session.construct_invocation` reports non-zero exit AND
///   the chain is otherwise complete (revocation fired).
/// - `InFlight` if `broker.revocation` has not yet fired (caller still
///   running). `ended_at` is `None` for in-flight rollups.
/// - `Incomplete` if the daemon crashed mid-spawn — `broker.materialization` +
///   `broker.resolution` present but `session.construct_invocation` never
///   landed. Operator follow-up via `ember receipt rollup --incomplete-only`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RollupOutcome {
    Success,
    Denied { reason: String },
    Errored { exit_code: i32 },
    InFlight,
    Incomplete,
}

/// Reference to a sub-Receipt inside a rollup. Carries enough to render the
/// rollup row and to fetch the full Receipt by hash on click-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubReceiptRef {
    /// Receipt kind (e.g. `broker.materialization`, `session.construct_invocation`).
    pub kind: String,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// blake3 over JCS form, prefixed (`blake3:abc…`).
    pub receipt_hash: String,
}

/// Server-side rollup envelope rendered by the dashboard's `?view=rollup`
/// endpoint and the `ember receipt rollup` CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstructInvocationRollup {
    /// Join key shared across all sub-Receipts in this rollup.
    pub materialization_id: String,
    /// Canonical structured action identity when the receipt chain carries it.
    pub action_ref: Option<ActionRef>,
    /// Action identifier (e.g. `gh.pr_create`, `git.push`) — taken from
    /// `action_ref` when present, otherwise from the legacy action string.
    pub action: String,
    /// Selected runner class, when any sub-Receipt carries ADR 184 §13
    /// placement truth.
    pub runner_class: Option<String>,
    /// Selected execution domain, when any sub-Receipt carries ADR 184 §13
    /// placement truth.
    pub execution_domain: Option<String>,
    /// Materialization class actually used, when any sub-Receipt carries
    /// ADR 184 §13 placement truth.
    pub materialization_class: Option<String>,
    /// Persona that authored the dispatch.
    pub persona: String,
    /// Earliest sub-Receipt timestamp.
    pub started_at: String,
    /// Latest sub-Receipt timestamp; `None` for in-flight rollups.
    pub ended_at: Option<String>,
    /// Derived outcome (see [`RollupOutcome`]).
    pub outcome: RollupOutcome,
    /// Number of sub-Receipts in this rollup (always ≥3, typically 4).
    pub receipt_count: u32,
    /// Ordered list of sub-Receipts (oldest first) for click-through detail.
    pub sub_receipts: Vec<SubReceiptRef>,
}

/// Minimal view into a sub-Receipt that `compute_rollups` needs. Real callers
/// pass concrete `Receipt` types; this trait shape keeps the rollup algorithm
/// independent of the receipt module's exact struct.
pub trait RollupReceiptView {
    fn materialization_id(&self) -> Option<&str>;
    fn kind(&self) -> &str;
    fn ts(&self) -> &str;
    fn receipt_hash(&self) -> &str;
    fn persona(&self) -> Option<&str>;
    fn action(&self) -> Option<&str>;
    fn action_ref(&self) -> Option<&ActionRef>;
    fn runner_class(&self) -> Option<&str> {
        None
    }
    fn execution_domain(&self) -> Option<&str> {
        None
    }
    fn materialization_class(&self) -> Option<&str> {
        None
    }
    fn exit_code(&self) -> Option<i32>;
    fn denied_reason(&self) -> Option<&str>;
}

/// Compute one [`ConstructInvocationRollup`] per distinct `materialization_id`
/// across the input receipts. Receipts that lack a `materialization_id` (e.g.
/// session lifecycle events) are skipped.
///
/// **Read-time, not write-time** — the audit log is unchanged; this function
/// is called per-request to render the rollup view. Per the design doc §1,
/// changing the rollup logic does not require re-emitting the audit chain.
pub fn compute_rollups<R: RollupReceiptView>(receipts: &[R]) -> Vec<ConstructInvocationRollup> {
    let mut groups: HashMap<String, Vec<&R>> = HashMap::new();
    for r in receipts {
        if let Some(mid) = r.materialization_id() {
            groups.entry(mid.to_string()).or_default().push(r);
        }
    }

    let mut rollups: Vec<ConstructInvocationRollup> = groups
        .into_iter()
        .map(|(mid, group)| build_rollup(&mid, &group))
        .collect();
    rollups.sort_by(|a, b| a.started_at.cmp(&b.started_at));
    rollups
}

fn build_rollup<R: RollupReceiptView>(
    materialization_id: &str,
    group: &[&R],
) -> ConstructInvocationRollup {
    let mut sub_receipts: Vec<SubReceiptRef> = group
        .iter()
        .map(|r| SubReceiptRef {
            kind: r.kind().to_string(),
            ts: r.ts().to_string(),
            receipt_hash: r.receipt_hash().to_string(),
        })
        .collect();
    sub_receipts.sort_by(|a, b| a.ts.cmp(&b.ts));

    let action_ref = group.iter().find_map(|r| r.action_ref().cloned());
    let action = action_ref
        .as_ref()
        .map(ToString::to_string)
        .or_else(|| group.iter().find_map(|r| r.action().map(|s| s.to_string())))
        .unwrap_or_else(|| "<unknown>".to_string());
    let runner_class = group
        .iter()
        .find_map(|r| r.runner_class().map(str::to_string));
    let execution_domain = group
        .iter()
        .find_map(|r| r.execution_domain().map(str::to_string));
    let materialization_class = group
        .iter()
        .find_map(|r| r.materialization_class().map(str::to_string));
    let persona = group
        .iter()
        .find_map(|r| r.persona().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string());

    let started_at = sub_receipts
        .first()
        .map(|s| s.ts.clone())
        .unwrap_or_default();

    let has_revocation = group.iter().any(|r| r.kind() == "broker.revocation");
    let has_invocation = group
        .iter()
        .any(|r| r.kind() == "session.construct_invocation");
    let denial = group
        .iter()
        .find_map(|r| r.denied_reason().map(|s| s.to_string()));
    let exit_code = group
        .iter()
        .find(|r| r.kind() == "session.construct_invocation")
        .and_then(|r| r.exit_code());

    let outcome = if let Some(reason) = denial {
        RollupOutcome::Denied { reason }
    } else if !has_invocation {
        // Daemon crashed mid-spawn — materialization/resolution may be
        // present but invocation never landed.
        RollupOutcome::Incomplete
    } else if !has_revocation {
        RollupOutcome::InFlight
    } else if exit_code == Some(0) {
        RollupOutcome::Success
    } else {
        RollupOutcome::Errored {
            exit_code: exit_code.unwrap_or(-1),
        }
    };

    let ended_at = if matches!(outcome, RollupOutcome::InFlight) {
        None
    } else {
        sub_receipts.last().map(|s| s.ts.clone())
    };

    ConstructInvocationRollup {
        materialization_id: materialization_id.to_string(),
        action_ref,
        action,
        runner_class,
        execution_domain,
        materialization_class,
        persona,
        started_at,
        ended_at,
        outcome,
        receipt_count: u32::try_from(group.len()).unwrap_or(u32::MAX),
        sub_receipts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only receipt view for fixture construction.
    struct FixtureReceipt {
        mid: Option<String>,
        kind: String,
        ts: String,
        hash: String,
        persona: Option<String>,
        action: Option<String>,
        action_ref: Option<ActionRef>,
        runner_class: Option<String>,
        execution_domain: Option<String>,
        materialization_class: Option<String>,
        exit_code: Option<i32>,
        denied: Option<String>,
    }

    impl RollupReceiptView for FixtureReceipt {
        fn materialization_id(&self) -> Option<&str> {
            self.mid.as_deref()
        }
        fn kind(&self) -> &str {
            &self.kind
        }
        fn ts(&self) -> &str {
            &self.ts
        }
        fn receipt_hash(&self) -> &str {
            &self.hash
        }
        fn persona(&self) -> Option<&str> {
            self.persona.as_deref()
        }
        fn action(&self) -> Option<&str> {
            self.action.as_deref()
        }
        fn action_ref(&self) -> Option<&ActionRef> {
            self.action_ref.as_ref()
        }
        fn runner_class(&self) -> Option<&str> {
            self.runner_class.as_deref()
        }
        fn execution_domain(&self) -> Option<&str> {
            self.execution_domain.as_deref()
        }
        fn materialization_class(&self) -> Option<&str> {
            self.materialization_class.as_deref()
        }
        fn exit_code(&self) -> Option<i32> {
            self.exit_code
        }
        fn denied_reason(&self) -> Option<&str> {
            self.denied.as_deref()
        }
    }

    fn fx(
        mid: &str,
        kind: &str,
        ts: &str,
        hash: &str,
        persona: Option<&str>,
        action: Option<&str>,
        action_ref: Option<ActionRef>,
        exit_code: Option<i32>,
        denied: Option<&str>,
    ) -> FixtureReceipt {
        FixtureReceipt {
            mid: Some(mid.to_string()),
            kind: kind.to_string(),
            ts: ts.to_string(),
            hash: hash.to_string(),
            persona: persona.map(String::from),
            action: action.map(String::from),
            action_ref,
            runner_class: None,
            execution_domain: None,
            materialization_class: None,
            exit_code,
            denied: denied.map(String::from),
        }
    }

    fn fx_with_placement(
        mut receipt: FixtureReceipt,
        runner_class: Option<&str>,
        execution_domain: Option<&str>,
        materialization_class: Option<&str>,
    ) -> FixtureReceipt {
        receipt.runner_class = runner_class.map(String::from);
        receipt.execution_domain = execution_domain.map(String::from);
        receipt.materialization_class = materialization_class.map(String::from);
        receipt
    }

    #[test]
    fn success_path_produces_one_rollup_with_4_receipts() {
        let receipts = vec![
            fx(
                "m_abc",
                "broker.materialization",
                "2026-05-05T13:01:22Z",
                "blake3:7c2a",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_abc",
                "broker.resolution",
                "2026-05-05T13:01:22Z",
                "blake3:9f81",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_abc",
                "session.construct_invocation",
                "2026-05-05T13:01:24Z",
                "blake3:b3f9",
                None,
                None,
                Some(ActionRef::new(
                    "registry.ember.systems/ember-systems/ember-gh",
                    "pr_create",
                    "v1",
                )),
                Some(0),
                None,
            ),
            fx(
                "m_abc",
                "broker.revocation",
                "2026-05-05T13:01:24Z",
                "blake3:e1d8",
                None,
                None,
                None,
                None,
                None,
            ),
        ];
        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 1);
        let r = &rollups[0];
        assert_eq!(r.materialization_id, "m_abc");
        assert_eq!(
            r.action,
            "registry.ember.systems/ember-systems/ember-gh/pr_create@v1"
        );
        assert_eq!(
            r.action_ref,
            Some(ActionRef::new(
                "registry.ember.systems/ember-systems/ember-gh",
                "pr_create",
                "v1",
            ))
        );
        assert_eq!(r.persona, "dev");
        assert_eq!(r.outcome, RollupOutcome::Success);
        assert_eq!(r.receipt_count, 4);
        assert_eq!(r.runner_class, None);
        assert_eq!(r.execution_domain, None);
        assert_eq!(r.materialization_class, None);
        assert_eq!(r.started_at, "2026-05-05T13:01:22Z");
        assert_eq!(r.ended_at, Some("2026-05-05T13:01:24Z".to_string()));
        assert_eq!(r.sub_receipts.len(), 4);
    }

    #[test]
    fn rollup_carries_first_available_placement_truth() {
        let receipts = vec![
            fx(
                "m_place",
                "broker.materialization",
                "2026-05-05T13:01:22Z",
                "blake3:7c2a",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx_with_placement(
                fx(
                    "m_place",
                    "session.construct_invocation",
                    "2026-05-05T13:01:23Z",
                    "blake3:b3f9",
                    None,
                    None,
                    Some(ActionRef::new(
                        "registry.ember.systems/ember-systems/ember-gh",
                        "pr_create",
                        "v1",
                    )),
                    Some(0),
                    None,
                ),
                Some("local_trusted"),
                Some("host"),
                Some("brokered_credential"),
            ),
            fx(
                "m_place",
                "broker.revocation",
                "2026-05-05T13:01:24Z",
                "blake3:e1d8",
                None,
                None,
                None,
                None,
                None,
            ),
        ];

        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].runner_class.as_deref(), Some("local_trusted"));
        assert_eq!(rollups[0].execution_domain.as_deref(), Some("host"));
        assert_eq!(
            rollups[0].materialization_class.as_deref(),
            Some("brokered_credential")
        );
    }

    #[test]
    fn denied_path_produces_denied_outcome() {
        let receipts = vec![
            fx(
                "m_def",
                "broker.materialization",
                "2026-05-05T13:02:00Z",
                "blake3:111",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_def",
                "broker.exec.denied_resource_limit",
                "2026-05-05T13:02:00Z",
                "blake3:222",
                None,
                Some("git.push"),
                None,
                None,
                Some("rate_limited"),
            ),
        ];
        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 1);
        match &rollups[0].outcome {
            RollupOutcome::Denied { reason } => assert_eq!(reason, "rate_limited"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn in_flight_chain_omits_ended_at() {
        let receipts = vec![
            fx(
                "m_inflight",
                "broker.materialization",
                "2026-05-05T13:03:00Z",
                "blake3:a",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_inflight",
                "broker.resolution",
                "2026-05-05T13:03:00Z",
                "blake3:b",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_inflight",
                "session.construct_invocation",
                "2026-05-05T13:03:01Z",
                "blake3:c",
                None,
                Some("kubectl.apply"),
                None,
                None,
                None,
            ),
            // No broker.revocation yet.
        ];
        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].outcome, RollupOutcome::InFlight);
        assert!(rollups[0].ended_at.is_none());
    }

    #[test]
    fn incomplete_chain_no_invocation() {
        let receipts = vec![
            fx(
                "m_crash",
                "broker.materialization",
                "2026-05-05T13:04:00Z",
                "blake3:x",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_crash",
                "broker.resolution",
                "2026-05-05T13:04:00Z",
                "blake3:y",
                None,
                None,
                None,
                None,
                None,
            ),
            // Daemon crashed before invocation landed.
        ];
        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 1);
        assert_eq!(rollups[0].outcome, RollupOutcome::Incomplete);
    }

    #[test]
    fn errored_path_carries_exit_code() {
        let receipts = vec![
            fx(
                "m_err",
                "broker.materialization",
                "2026-05-05T13:05:00Z",
                "blake3:p",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_err",
                "broker.resolution",
                "2026-05-05T13:05:00Z",
                "blake3:q",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_err",
                "session.construct_invocation",
                "2026-05-05T13:05:02Z",
                "blake3:r",
                None,
                Some("git.push"),
                None,
                Some(128),
                None,
            ),
            fx(
                "m_err",
                "broker.revocation",
                "2026-05-05T13:05:02Z",
                "blake3:s",
                None,
                None,
                None,
                None,
                None,
            ),
        ];
        let rollups = compute_rollups(&receipts);
        match &rollups[0].outcome {
            RollupOutcome::Errored { exit_code } => assert_eq!(*exit_code, 128),
            other => panic!("expected Errored, got {other:?}"),
        }
    }

    #[test]
    fn receipts_without_materialization_id_skipped() {
        struct NoMid;
        impl RollupReceiptView for NoMid {
            fn materialization_id(&self) -> Option<&str> {
                None
            }
            fn kind(&self) -> &str {
                "session.opened"
            }
            fn ts(&self) -> &str {
                "2026-05-05T00:00:00Z"
            }
            fn receipt_hash(&self) -> &str {
                "blake3:nope"
            }
            fn persona(&self) -> Option<&str> {
                None
            }
            fn action(&self) -> Option<&str> {
                None
            }
            fn action_ref(&self) -> Option<&ActionRef> {
                None
            }
            fn exit_code(&self) -> Option<i32> {
                None
            }
            fn denied_reason(&self) -> Option<&str> {
                None
            }
        }
        let receipts = vec![NoMid, NoMid];
        assert!(compute_rollups(&receipts).is_empty());
    }

    #[test]
    fn multiple_materialization_ids_produce_separate_rollups() {
        let receipts = vec![
            fx(
                "m_one",
                "broker.materialization",
                "2026-05-05T13:00:00Z",
                "blake3:a",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_one",
                "broker.resolution",
                "2026-05-05T13:00:00Z",
                "blake3:b",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_one",
                "session.construct_invocation",
                "2026-05-05T13:00:01Z",
                "blake3:c",
                None,
                Some("gh.pr_create"),
                None,
                Some(0),
                None,
            ),
            fx(
                "m_one",
                "broker.revocation",
                "2026-05-05T13:00:01Z",
                "blake3:d",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_two",
                "broker.materialization",
                "2026-05-05T13:00:05Z",
                "blake3:e",
                Some("dev"),
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_two",
                "broker.resolution",
                "2026-05-05T13:00:05Z",
                "blake3:f",
                None,
                None,
                None,
                None,
                None,
            ),
            fx(
                "m_two",
                "session.construct_invocation",
                "2026-05-05T13:00:06Z",
                "blake3:g",
                None,
                Some("git.push"),
                None,
                Some(0),
                None,
            ),
            fx(
                "m_two",
                "broker.revocation",
                "2026-05-05T13:00:06Z",
                "blake3:h",
                None,
                None,
                None,
                None,
                None,
            ),
        ];
        let rollups = compute_rollups(&receipts);
        assert_eq!(rollups.len(), 2);
        // Sorted by started_at — m_one comes first.
        assert_eq!(rollups[0].materialization_id, "m_one");
        assert_eq!(rollups[1].materialization_id, "m_two");
    }
}
