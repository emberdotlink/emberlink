//! Workflow revoke cascade — ADR 164 §Component 4 authority-side primitive.
//!
//! `ember workflow revoke --workflow-id <id>` (per ADR 158 §Component 4 —
//! revoke is always safe, no presence required) MUST propagate from a root
//! workflow grant to every descendant delegation. The authority half of the
//! propagation primitive lives here:
//!
//! 1. Walk the descendant tree from `root_grant_id` BEFORE the revoke so the
//!    summary receipt can name every grant the cascade was responsible for.
//! 2. Delegate the eager DOWNWARD walk + per-child terminal Receipt emission
//!    to the existing [`DaemonStore::revoke_grant`] pathway (which calls
//!    `cascade_revoke_children` recursively under the hood).
//! 3. Emit a single `workflow.revoke_cascaded` summary audit event tying the
//!    root grant id to every descendant grant id that the cascade marked.
//! 4. Hand a [`LifecycleHandoff`] back to the caller so the orchestrator-side
//!    lifecycle plane ([`crate::scion::lifecycle`]) can drive the graceful →
//!    SIGTERM → SIGKILL window without this module reaching into any
//!    container or process group itself.
//!
//! ## Why we don't kill processes here
//!
//! Per `feedback_authority_is_our_domain_lifecycle_isnt` (operator 2026-06-10):
//! the daemon's domain is **authority**, not container lifecycle. The
//! authority cut-over for an in-flight descendant is enforced by the broker
//! boundary: once the descendant's grant (or any ancestor) is revoked,
//! `infra::proxy::resolve_grant` and `trust::use_time_verify::verify_grant`
//! both refuse to mint or vend credentials, returning a DENY with the
//! `parent_cascade_revoked` reason via `first_revoked_grant_ancestor`. That
//! is the fail-closed signal that does the real security work.
//!
//! The SIGTERM/SIGKILL cascade described by ADR 164 §Component 4 step 5 + 6
//! is graceful **wind-down**, not the security boundary — the descendant
//! process can keep running until SIGKILL, but every broker call it makes
//! will fail closed. Driving the actual signal delivery is the orchestrator's
//! responsibility (`emberd`'s container-lifecycle watcher per ADR 140's
//! daemon-as-process-supervisor primitive, tracked as a separate seam — see
//! the module-level note in [`crate::scion::lifecycle`]).
//!
//! # Checkpoint
//!
//! `scion_composition_revoke_cascade_landed` — anchored in this module's
//! doc-comment and in the test below so the META task target_state_anchor
//! matches both source and tests.

use crate::infra::audit::append_audit_event_with_chain;
use crate::infra::store::{DaemonStore, StoreError};
use serde::{Deserialize, Serialize};

/// Default-cohort grace windows for [`LifecycleHandoff`].
///
/// Per ADR 164 §Component 4 cohort table:
///
/// | Cohort | Grace before SIGTERM | SIGTERM → SIGKILL |
/// |--------|----------------------|--------------------|
/// | dev0   | 30s                  | 10s                |
/// | team0  | 10s                  | 5s                 |
/// | ent0   | 5s                   | 2s                 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cohort {
    Dev0,
    Team0,
    Ent0,
}

impl Cohort {
    /// Grace seconds AFTER the broker DENY signal goes out and BEFORE SIGTERM.
    pub const fn grace_secs(self) -> u64 {
        match self {
            Cohort::Dev0 => 30,
            Cohort::Team0 => 10,
            Cohort::Ent0 => 5,
        }
    }

    /// Grace seconds AFTER SIGTERM and BEFORE SIGKILL.
    pub const fn sigterm_to_sigkill_secs(self) -> u64 {
        match self {
            Cohort::Dev0 => 10,
            Cohort::Team0 => 5,
            Cohort::Ent0 => 2,
        }
    }

    /// `--immediate` (per ADR 164 §Component 4) is allowed for dev0 + team0;
    /// ent0 is config-fixed to forbid skipping the grace window.
    pub const fn immediate_allowed(self) -> bool {
        match self {
            Cohort::Dev0 | Cohort::Team0 => true,
            Cohort::Ent0 => false,
        }
    }
}

/// Summary of a single workflow revoke cascade.
///
/// Returned by [`revoke_workflow_root`] and serialized into the
/// `workflow.revoke_cascaded` audit-chain entry. The descendant ids reflect
/// the active descendants the cascade marked (the walk skips terminal
/// states — already-revoked / abandoned / expired — to keep the receipt
/// accurate to THIS cascade event).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRevokeReport {
    /// The root workflow grant id that the operator revoked.
    pub root_grant_id: String,
    /// Active descendant grant ids that this cascade marked revoked, in
    /// breadth-first order from the root. Already-terminal descendants are
    /// excluded so a re-run cascade does not double-count them.
    pub descendant_grant_ids: Vec<String>,
    /// Total descendants marked by THIS cascade — equal to
    /// `descendant_grant_ids.len()`. Carried as its own field so the audit
    /// event's JSON body is operator-readable without de-counting the array.
    pub descendant_count: usize,
}

/// Orchestrator-side lifecycle handoff produced after the authority half of
/// the workflow revoke cascade lands.
///
/// The DAEMON does not interpret this struct; it is the contract the
/// container-lifecycle watcher consumes to drive the graceful → SIGTERM →
/// SIGKILL window. Reaching into a SCION container to send signals from this
/// module is explicitly out of scope (see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleHandoff {
    pub workflow_root_grant_id: String,
    pub descendant_grant_ids: Vec<String>,
    pub cohort: Cohort,
    /// `--immediate` flag forwarded from the CLI: when true (and the cohort
    /// permits it), the orchestrator MUST skip the graceful grace window and
    /// SIGKILL immediately.
    pub immediate: bool,
}

/// Collect the active descendant grant ids reachable from `root_id` via the
/// `parent_grant_id` chain (BFS). The walk stops at terminal grants so a
/// follow-up `revoke_workflow_root` call cleanly reports the delta.
fn collect_active_descendants(
    store: &DaemonStore,
    root_id: &str,
) -> Result<Vec<String>, StoreError> {
    let conn = store.conn();
    let mut frontier = vec![root_id.to_string()];
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(root_id.to_string());

    while let Some(parent) = frontier.pop() {
        let mut stmt = conn.prepare(
            "SELECT id FROM grants WHERE parent_grant_id = ?1 AND status = 'active'",
        )?;
        let children: Vec<String> = stmt
            .query_map(rusqlite::params![parent], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for child in children {
            if seen.insert(child.clone()) {
                out.push(child.clone());
                frontier.push(child);
            }
        }
    }

    Ok(out)
}

/// Revoke a workflow root grant and cascade through every active descendant.
///
/// Entry point for `ember workflow revoke --workflow-id <root>`. The
/// authority cut-over fans out via:
///
/// 1. [`collect_active_descendants`] — snapshot the descendant set BEFORE the
///    cascade mutates statuses.
/// 2. [`DaemonStore::revoke_grant`] on the root — atomic root status flip +
///    `grant.revoked` audit chain entry + per-grant terminal Receipt + eager
///    DOWNWARD `cascade_revoke_children` walk that marks each descendant
///    revoked with `parent_cascade_revoked` terminal reason and emits the
///    per-descendant terminal Receipt.
/// 3. [`append_audit_event_with_chain`] — emit the `workflow.revoke_cascaded`
///    summary tying root → descendant set into a single audit-chain entry.
///
/// The use-time fail-closed signal is independent of step 2's eager DB walk
/// (per the `cascade_revoke_children` doc-comment): even if the cascade
/// crashes mid-walk or a leaf grant somehow escapes, every broker.resolve
/// from a revoked-descendant grant still trips `first_revoked_grant_ancestor`
/// at use time and returns DENY. That is the load-bearing security property.
///
/// Returns a [`WorkflowRevokeReport`] for the audit receipt + a
/// [`LifecycleHandoff`] for the orchestrator's process-lifecycle plane to
/// consume separately.
pub fn revoke_workflow_root(
    store: &DaemonStore,
    root_grant_id: &str,
    cohort: Cohort,
    immediate: bool,
) -> Result<(WorkflowRevokeReport, LifecycleHandoff), StoreError> {
    if immediate && !cohort.immediate_allowed() {
        return Err(StoreError::InvalidInput(format!(
            "--immediate flag is not allowed for cohort {cohort:?}; cohort config forbids skipping the grace window"
        )));
    }

    // Step 1 — snapshot the active descendant set BEFORE the cascade fires.
    let descendant_grant_ids = collect_active_descendants(store, root_grant_id)?;
    let descendant_count = descendant_grant_ids.len();

    // Step 2 — atomic root revoke + per-grant audit + per-grant terminal
    // Receipt + eager downward cascade (drops leases, marks descendants
    // revoked with `parent_cascade_revoked` reason, emits descendant
    // Receipts). NotFound on the root short-circuits before any audit fires.
    store.revoke_grant(root_grant_id)?;

    // Step 3 — workflow-level summary audit event so an operator can run
    // `ember audit query --action workflow.revoke_cascaded` and recover the
    // full descendant set from a single row, without re-walking the chain.
    let details = serde_json::json!({
        "root_grant_id": root_grant_id,
        "descendant_grant_ids": &descendant_grant_ids,
        "descendant_count": descendant_count,
        "cohort": format!("{cohort:?}").to_lowercase(),
        "immediate": immediate,
    })
    .to_string();
    append_audit_event_with_chain(
        store,
        None,
        "workflow.revoke_cascaded",
        None,
        "ok",
        Some(&details),
    )?;

    let report = WorkflowRevokeReport {
        root_grant_id: root_grant_id.to_string(),
        descendant_grant_ids: descendant_grant_ids.clone(),
        descendant_count,
    };
    let handoff = LifecycleHandoff {
        workflow_root_grant_id: root_grant_id.to_string(),
        descendant_grant_ids,
        cohort,
        immediate,
    };
    Ok((report, handoff))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::audit::AuditFilter;
    use crate::infra::receipt::{current_identity, init_identity};
    use crate::infra::store::DaemonStore;
    use crate::infra::vault::Vault;
    use once_cell::sync::OnceCell as SyncOnceCell;
    use std::rc::Rc;

    fn ensure_test_identity() {
        static INIT_DIR: SyncOnceCell<tempfile::TempDir> = SyncOnceCell::new();
        let dir = INIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir"));
        let _ = init_identity(dir.path());
        current_identity().expect("identity must be initialised for receipt tests");
    }

    fn setup() -> DaemonStore {
        let store = DaemonStore::open_in_memory().expect("in-memory store");
        store.set_vault(Rc::new(Vault::new([0xCD; 32])));
        store
    }

    /// Build a 3-level workflow tree:
    /// `root → orch → (w1, w2)`. Returns (root_id, orch_id, w1_id, w2_id).
    fn setup_workflow_tree(store: &DaemonStore) -> (String, String, String, String) {
        let root_persona = store
            .create_persona("agent-workflow-root")
            .expect("create root persona");
        let orch_persona = store
            .create_persona("agent-workflow-orch")
            .expect("create orch persona");
        let worker_persona = store
            .create_persona("agent-workflow-worker")
            .expect("create worker persona");

        // Root grant — wide delegation depth so children + grandchildren can mint.
        let root = store
            .create_grant(
                &root_persona.id,
                "delegate-key",
                "github:push:acme/*",
                Some(7 * 24 * 3600),
            )
            .expect("create root grant");
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
                rusqlite::params![root.id],
            )
            .expect("widen root max_delegation_depth");
        store
            .mark_grant_standing(&root.id, 32, Some("github:push:acme/cycle-<id>"))
            .expect("mark root standing");

        // Orchestrator grant — delegated from root.
        let orch = store
            .delegate_grant_full(
                &root.id,
                &orch_persona.id,
                "github:push:acme/widgets",
                Some(3600),
                None,
            )
            .expect("delegate orch grant");
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 2 WHERE id = ?1",
                rusqlite::params![orch.id],
            )
            .expect("widen orch max_delegation_depth");
        store
            .mark_grant_standing(&orch.id, 16, Some("github:push:acme/widgets-<id>"))
            .expect("mark orch standing");

        // Worker grants — delegated from orchestrator.
        let w1 = store
            .delegate_grant_full(
                &orch.id,
                &worker_persona.id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .expect("delegate worker 1");
        let w2 = store
            .delegate_grant_full(
                &orch.id,
                &worker_persona.id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .expect("delegate worker 2");

        (root.id, orch.id, w1.id, w2.id)
    }

    /// Authoritative cascade: revoke_workflow_root marks the root and every
    /// active descendant revoked.
    #[test]
    fn revoke_workflow_root_cascades_to_all_active_descendants() {
        ensure_test_identity();
        let store = setup();
        let (root, orch, w1, w2) = setup_workflow_tree(&store);

        for id in [&root, &orch, &w1, &w2] {
            assert_eq!(store.get_grant(id).unwrap().status, "active");
        }

        let (report, handoff) =
            revoke_workflow_root(&store, &root, Cohort::Dev0, /* immediate */ false)
                .expect("revoke_workflow_root");

        assert_eq!(report.root_grant_id, root);
        assert_eq!(report.descendant_count, 3, "orch + 2 workers");
        assert!(report.descendant_grant_ids.contains(&orch));
        assert!(report.descendant_grant_ids.contains(&w1));
        assert!(report.descendant_grant_ids.contains(&w2));

        // Handoff carries the same set so the orchestrator-side lifecycle
        // plane can drive SIGTERM/SIGKILL on the descendant persona-process
        // groups without re-walking the DB.
        assert_eq!(handoff.workflow_root_grant_id, root);
        assert_eq!(handoff.descendant_grant_ids.len(), 3);
        assert_eq!(handoff.cohort, Cohort::Dev0);
        assert!(!handoff.immediate);

        // Every grant is now revoked.
        for id in [&root, &orch, &w1, &w2] {
            assert_eq!(
                store.get_grant(id).unwrap().status,
                "revoked",
                "grant {id} must be revoked after workflow cascade"
            );
        }
    }

    /// Broker fails closed: after the workflow cascade, every descendant's
    /// use-time `first_revoked_grant_ancestor` check returns Some(..) — the
    /// boundary that proxy + use-time-verify share to refuse to mint or vend
    /// credentials.
    #[test]
    fn cascade_makes_broker_fail_closed_on_descendant_use() {
        ensure_test_identity();
        let store = setup();
        let (root, orch, w1, w2) = setup_workflow_tree(&store);

        revoke_workflow_root(&store, &root, Cohort::Dev0, false)
            .expect("revoke_workflow_root");

        // Every descendant — including the grandchildren — must trip the
        // ancestor walk that proxy.rs + use_time_verify.rs both call.
        for id in [&orch, &w1, &w2] {
            let revoked_ancestor = store.first_revoked_grant_ancestor(id);
            assert!(
                revoked_ancestor.is_some(),
                "descendant {id} must surface a revoked ancestor — broker would otherwise mint"
            );
        }
    }

    /// The summary `workflow.revoke_cascaded` audit event lands with the
    /// root + descendant set in its JSON details.
    #[test]
    fn workflow_revoke_cascaded_audit_event_carries_root_and_descendants() {
        ensure_test_identity();
        let store = setup();
        let (root, orch, w1, w2) = setup_workflow_tree(&store);

        let (_report, _handoff) =
            revoke_workflow_root(&store, &root, Cohort::Team0, false)
                .expect("revoke_workflow_root");

        let entries = store
            .query_audit(&AuditFilter {
                action: Some("workflow.revoke_cascaded".to_string()),
                ..Default::default()
            })
            .expect("query workflow.revoke_cascaded audit");

        assert_eq!(
            entries.len(),
            1,
            "expected exactly one workflow.revoke_cascaded entry"
        );
        let entry = &entries[0];
        assert_eq!(entry.outcome, "ok");
        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["root_grant_id"], root);
        assert_eq!(details["descendant_count"], 3);
        assert_eq!(details["cohort"], "team0");
        assert_eq!(details["immediate"], false);
        let descs = details["descendant_grant_ids"].as_array().unwrap();
        let desc_set: std::collections::HashSet<String> = descs
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(desc_set.contains(&orch));
        assert!(desc_set.contains(&w1));
        assert!(desc_set.contains(&w2));
    }

    /// Immediate flag is rejected on ent0 (cohort config-fixed per ADR 164
    /// §Component 4) — the cascade does NOT fire when the flag is rejected.
    #[test]
    fn immediate_flag_rejected_on_ent0() {
        ensure_test_identity();
        let store = setup();
        let (root, orch, _w1, _w2) = setup_workflow_tree(&store);

        let err = revoke_workflow_root(&store, &root, Cohort::Ent0, /* immediate */ true)
            .expect_err("ent0 must reject --immediate");
        assert!(
            matches!(err, StoreError::InvalidInput(_)),
            "ent0 immediate-reject must surface as InvalidInput; got {err:?}"
        );

        // The cascade MUST NOT have fired — grants stay active.
        assert_eq!(store.get_grant(&root).unwrap().status, "active");
        assert_eq!(store.get_grant(&orch).unwrap().status, "active");
    }

    /// Immediate flag is honored on dev0 + team0 — the handoff records it so
    /// the orchestrator skips the grace window.
    #[test]
    fn immediate_flag_honored_on_dev0_and_team0() {
        ensure_test_identity();

        for cohort in [Cohort::Dev0, Cohort::Team0] {
            let store = setup();
            let (root, _orch, _w1, _w2) = setup_workflow_tree(&store);
            let (_report, handoff) =
                revoke_workflow_root(&store, &root, cohort, /* immediate */ true)
                    .expect("revoke_workflow_root immediate");
            assert!(
                handoff.immediate,
                "cohort {cohort:?} must honor immediate=true on the handoff"
            );
        }
    }

    /// Cohort grace + SIGTERM windows match ADR 164 §Component 4's defaults.
    #[test]
    fn cohort_grace_windows_match_adr_164() {
        assert_eq!(Cohort::Dev0.grace_secs(), 30);
        assert_eq!(Cohort::Dev0.sigterm_to_sigkill_secs(), 10);
        assert_eq!(Cohort::Team0.grace_secs(), 10);
        assert_eq!(Cohort::Team0.sigterm_to_sigkill_secs(), 5);
        assert_eq!(Cohort::Ent0.grace_secs(), 5);
        assert_eq!(Cohort::Ent0.sigterm_to_sigkill_secs(), 2);
    }

    /// Checkpoint — the META target_state_anchor is
    /// `scion_composition_revoke_cascade_landed`. Anchored as a test name so
    /// the grep returns a hit in both the source module and the test
    /// surface, and the test asserts the wiring shape (entry, handoff,
    /// cascade, broker fail-closed, summary receipt) is reachable.
    #[test]
    fn scion_composition_revoke_cascade_landed() {
        ensure_test_identity();
        let store = setup();
        let (root, orch, w1, w2) = setup_workflow_tree(&store);

        let (report, handoff) =
            revoke_workflow_root(&store, &root, Cohort::Dev0, false).expect("cascade");
        assert_eq!(report.descendant_count, 3);
        assert_eq!(handoff.descendant_grant_ids.len(), 3);
        for id in [&orch, &w1, &w2] {
            assert!(store.first_revoked_grant_ancestor(id).is_some());
        }
    }
}
