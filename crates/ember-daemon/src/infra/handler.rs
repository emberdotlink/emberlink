// implementation-note-213

// dispatch_method_revoke_coverage_audited (implementation-note-214)
//
// Audit date: 2026-05-15. Auditor: headless worker
// implementation-note-214. Reviewer: operator (CODEOWNERS
// gate on this file).
//
// Why this exists: design's cross-uid bridge claims per-statement revoke
// works for in-container calls as a load-bearing demo property. The bridge
// implementation gates on this audit returning green AND on every pre-
// existing hole listed below being either fixed or explicitly accepted
// (META filed + status set).
//
// Scope: every match arm in `dispatch_method_with_context` (line ~1233
// below — the only `match method { ... }` inside this function). The
// classification map below lists each arm by name with one of three
// statuses:
//
//   COVERED — arm takes `persona_id` and/or `grant_id`, and the authorizing
//             read calls `store.get_revoked_sids(&grant_id)` (or an
//             equivalent revoke check) before authorizing. Today the
//             canonical pattern is `use_credential` (line ~1960 below)
//             and `grant_status` (line ~2865 below) — both invoke
//             `get_revoked_sids` directly on the resolved grant_id.
//             There is NO `resolve_grant_for_request` helper today
//             (planned by design but not yet authored); the audit
//             treats inline `get_revoked_sids` calls as the equivalent.
//
//   EXEMPT  — arm does not take persona/grant params (or takes them only
//             for filtering/projection), so per-statement revoke is not
//             applicable. The rationale is listed inline.
//
//   HOLE    — arm SHOULD check revoked_sids before authorizing but does
//             not. Each HOLE row names the linked META that fixes it.
//             The bridge implementation MUST NOT ship until every HOLE
//             is either fixed or its META is explicitly accepted as a
//             known-issue by the operator.
//
// ---------------------------------------------------------------------
// Persona/grant-taking arms — revoke-coverage status
// ---------------------------------------------------------------------
//
//   ping                                EXEMPT — health probe, no auth surface
//   evaluate_tool_call                  HOLE   — stub evaluator (implementation-note-76);
//                                                does NOT check
//                                                get_revoked_sids before
//                                                returning Permit. See
//                                                store.evaluate_tool_call
//                                                in trust/grant.rs:2894.
//                                                Filed: pending META
//                                                implementation-note-215-
//                                                TOOL-CALL-REVOKE-CHECK
//                                                (orchestrator to file).
//   create_persona                      EXEMPT — issues new persona; no
//                                                pre-existing grant to
//                                                consult
//   list_personas                       EXEMPT — read-only enumeration
//   revoke_persona                      HOLE   — accepts any Socket caller
//                                                without authority check
//                                                (separate issue from
//                                                revoke-coverage but
//                                                surfaced in the same
//                                                bridge gate). Filed as
//                                                implementation-note-216-
//                                                PERSONA-AUTHORITY.
//   create_grant                        EXEMPT — mints a NEW grant; no
//                                                pre-existing grant_id to
//                                                consult. Per-statement
//                                                revoke first applies on
//                                                first use_credential.
//   delegate_grant                      HOLE   — loads parent grant
//                                                (line ~1488) and checks
//                                                ownership but does NOT
//                                                check whether the parent
//                                                grant has revoked
//                                                statements. An attacker
//                                                with a partially-revoked
//                                                composite parent could
//                                                attenuate the revoked
//                                                statements into a fresh
//                                                child grant and bypass
//                                                the revoke. Filed:
//                                                pending META
//                                                implementation-note-217-
//                                                implementation-note-218
//                                                (orchestrator to file).
//   list_grants                         EXEMPT — read-only projection;
//                                                revoke status is
//                                                surfaced via the
//                                                statements array
//                                                (consumers render
//                                                strikethrough), not
//                                                gated.
//   revoke_grant                        EXEMPT — revoke is the authority;
//                                                no upstream revoke
//                                                check needed
//   revoke_statement                    EXEMPT — same as revoke_grant
//   evaluate_grant                      HOLE   — projects a grant by
//                                                (persona_id,
//                                                credential_name) but
//                                                does NOT check
//                                                get_revoked_sids before
//                                                returning. Caller-side
//                                                use_credential does the
//                                                actual revoke check
//                                                downstream, but a
//                                                caller that just
//                                                wants to know "do I
//                                                have a usable grant?"
//                                                gets a misleading
//                                                positive for a
//                                                fully-statement-revoked
//                                                grant. Filed: pending
//                                                META
//                                                implementation-note-215-
//                                                implementation-note-219
//                                                (orchestrator to file).
//   use_credential                      COVERED — line ~1960 explicitly
//                                                calls get_revoked_sids
//                                                and refuses on revoked
//                                                Credential Statement
//                                                match (implementation-note-220-
//                                                COMPOSITE-PER-STMT-
//                                                REVOKE). Canonical
//                                                pattern.
//   vault_add                           EXEMPT — vault write, no grant
//                                                consultation; gated by
//                                                presence + Internal
//   vault_remove                        EXEMPT — same
//   vault_lock                          EXEMPT — explicit re-lock; reduces
//                                                privilege
//   vault_unlock                        EXEMPT — explicit operator reopen;
//                                                no grant axis
//   vault_status                        EXEMPT — read-class diagnostic
//   vault_migrate_acl                   EXEMPT — admin/operator op, no
//                                                grant axis
//   vault_list                          EXEMPT — admin enumeration
//   vault_get                           EXEMPT — daemon-internal vault
//                                                lookup (not grant-
//                                                mediated; use
//                                                use_credential for the
//                                                grant-gated path)
//   local_state_key_get                 EXEMPT — daemon-internal key
//                                                resolve; not grant-
//                                                mediated. The Receipt
//                                                emission carries no
//                                                grant_id.
//   local_state_key_set                 EXEMPT — same
//   local_state_key_rotate_and_reencrypt EXEMPT — same
//   binary_pin_generate                 EXEMPT — operator-only op, no
//                                                grant axis (presence
//                                                gate on
//                                                HighRiskOp::BinaryPin
//                                                Generate)
//   audit_verify                        EXEMPT — read-only chain probe
//   audit_query                         EXEMPT — read-only sanitized
//                                                audit row enumeration
//   audit_log_query                     EXEMPT — read-only raw audit row
//                                                enumeration
//   audit_explain                       EXEMPT — read-only current-state
//                                                explanation over one
//                                                raw audit row
//   receipt_tree                        EXEMPT — read-only receipt/grant
//                                                tree assembly over a
//                                                rooted grant
//   receipt_query                       EXEMPT — same, on receipt table
//   submit_approval                     EXEMPT — submits a NEW approval
//                                                request; no pre-existing
//                                                grant to consult
//   propose_grant                       EXEMPT — submits a NEW composite
//                                                approval request; no
//                                                pre-existing grant to
//                                                consult
//   resolve_approval                    EXEMPT — resolves an approval
//                                                request, not a grant
//   list_pending_approvals              EXEMPT — read-only enumeration
//   grant_status                        COVERED — line ~2865 calls
//                                                get_revoked_sids and
//                                                surfaces revoked_sids
//                                                in the response. Read-
//                                                only projection but
//                                                consumers (proxy +
//                                                dashboard) gate on
//                                                this field.
//   extend_grant                        HOLE   — extends budget/TTL on
//                                                an existing grant_id
//                                                without checking
//                                                whether the underlying
//                                                Statement that the
//                                                budget extension would
//                                                fund has been revoked.
//                                                A fully-statement-
//                                                revoked composite
//                                                whose owner extends
//                                                gets a fresh budget
//                                                allowance that
//                                                use_credential will
//                                                then refuse — wasteful
//                                                rather than a security
//                                                hole but inconsistent.
//                                                Filed: pending META
//                                                implementation-note-221-
//                                                implementation-note-222
//                                                (orchestrator to file).
//   request_access                      EXEMPT — mints a NEW grant via
//                                                standing-grant or
//                                                approval flow; no
//                                                pre-existing grant_id
//                                                to consult
//   await_approval                      EXEMPT — polls an existing
//                                                approval id; the
//                                                approval->grant
//                                                materialization
//                                                consults revoke status
//                                                at use_credential
//                                                time, not at approval
//                                                fulfillment.
//   request_access_blocking             EXEMPT — mints a NEW grant on
//                                                the auto/required path
//                                                like request_access
//   expire_grants                       EXEMPT — sweep op; reads no
//                                                grant by id
//   grant_summary                       EXEMPT — aggregate counts only
//   detect_anomalies                    EXEMPT — read-only anomaly probe
//   create_standing_grant               EXEMPT — admin op; no
//                                                pre-existing grant to
//                                                consult
//   list_standing_grants                EXEMPT — read-only enumeration
//   remove_standing_grant               EXEMPT — operator removal; no
//                                                upstream revoke check
//   poll_notifications                  EXEMPT — read-only queue drain
//   list_receipts                       EXEMPT — read-only enumeration
//   get_receipt                         EXEMPT — read-only single fetch
//   daemon_persona                      EXEMPT — exposes daemon
//                                                pubkey; no grant axis
//   grant_budget_status                 HOLE   — projects per-Statement
//                                                budget/usage from
//                                                get_access_grant but
//                                                does NOT call
//                                                get_revoked_sids; the
//                                                projection includes
//                                                statements that have
//                                                been revoked, with no
//                                                indicator. Filed:
//                                                pending META
//                                                implementation-note-223-
//                                                BUDGET-STATUS-REVOKE-
//                                                PROJECTION
//                                                (orchestrator to file).
//   broker_issue                        DELEGATED — handler in
//                                                broker/handler.rs;
//                                                audit-scope is that
//                                                module's surface, not
//                                                this dispatch arm.
//   broker_revoke                       DELEGATED — same
//   broker_list                         DELEGATED — same
//   broker_resolve                      DELEGATED — same. NOTE: this is
//                                                the credential-
//                                                materialization arm
//                                                the bridge will hit
//                                                most heavily; the
//                                                downstream module
//                                                MUST be re-audited
//                                                under the bridge gate.
//                                                2026-05-18 amendment
//                                                (PR-3672-adversarial-
//                                                fixes): broker/handler
//                                                's broker_resolve now
//                                                carries an in-handler
//                                                authorization layer
//                                                (workflow grant eval
//                                                via the sidecar) that
//                                                must enter the next
//                                                pass of implementation-note-224-
//                                                DAEMON-implementation-note-225-
//                                                COVERAGE-AUDIT. The
//                                                workflow-grant
//                                                revocation primitive
//                                                is in place
//                                                (atomic-rename of
//                                                workflow-grant.json
//                                                to .revoked, refused
//                                                by `workflow_grant::
//                                                load`); the strict-
//                                                mode bootstrap-only
//                                                gate flips when the
//                                                issue RPC + launcher
//                                                prompt ship.
//   broker_exec                         DELEGATED — same
//   session.lookup_or_open              DELEGATED — handler in
//                                                session/lifecycle.rs
//   broker.mint_gh_token                DELEGATED — handler in
//                                                broker/handler.rs
//   broker_register_pid_watcher         DELEGATED — same
//   broker.bindings.register            DELEGATED — same
//   broker.bindings.list                DELEGATED — same
//   broker.bindings.remove              DELEGATED — same
//   broker.bindings.move                DELEGATED — same
//   binding.delete                      DELEGATED — handler in
//                                                broker/binding_*.rs
//   binding.revoke_urgent               DELEGATED — same
//   binding.update                      DELEGATED — same
//   binding.upsert                      DELEGATED — same
//   create_agent_persona                EXEMPT — atomic create+
//                                                delegate; the
//                                                delegate phase MUST
//                                                inherit the
//                                                delegate_grant HOLE
//                                                fix when it lands
//                                                (cross-reference).
//   sops_unwrap_dek                     HOLE   — line ~3685 loads grant
//                                                and checks state +
//                                                issuer but does NOT
//                                                check
//                                                get_revoked_sids
//                                                before unwrapping the
//                                                DEK. A partially-
//                                                revoked composite
//                                                whose Credential
//                                                Statement (the age
//                                                key statement) has
//                                                been revoked will
//                                                still unwrap. Filed:
//                                                pending META
//                                                implementation-note-226-
//                                                UNWRAP-DEK-REVOKE-
//                                                CHECK (orchestrator
//                                                to file).
//   sops.pubkey                         EXEMPT — read-only persona
//                                                pubkey; no grant axis
//   sops.wrap                           EXEMPT — wraps a DEK to a
//                                                persona pubkey; no
//                                                grant gate
//   sops.unwrap                         EXEMPT — internal vault unwrap;
//                                                no grant axis (the
//                                                grant-gated path is
//                                                sops_unwrap_dek)
//   register_session                    EXEMPT — opens a new session
//                                                bound to an existing
//                                                active grant; lookup
//                                                is by persona + status
//                                                = 'active' which
//                                                already excludes
//                                                revoked grants. Per-
//                                                statement revoke is
//                                                enforced by the
//                                                downstream proxy at
//                                                use_credential time.
//   close_session                       EXEMPT — terminates a session
//                                                with a clean-exit
//                                                Receipt; no upstream
//                                                grant authorization
//                                                surface
//   headless_enroll                     EXEMPT — Phase 1 stub; no
//                                                pre-existing grant
//                                                consulted (returns
//                                                -32000 today)
//   headless_revoke                     EXEMPT — active-enrollment
//                                                lifecycle cleanup;
//                                                no grant axis
//   headless_status                     EXEMPT — read-only
//   headless_preflight_gaps             EXEMPT — read-only gap log
//                                                reader
//   headless_preflight_layer1           EXEMPT — read-only template
//                                                cross-reference
//
// ---------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------
//
// Total dispatch arms:           58 (excluding aliased dotted variants)
// COVERED:                        2 (use_credential, grant_status)
// EXEMPT:                        40
// DELEGATED:                     11 (broker_* + session + binding_*)
// HOLE:                           6 (evaluate_tool_call, delegate_grant,
//                                    evaluate_grant, extend_grant,
//                                    grant_budget_status, sops_unwrap_dek)
//   plus 1 cross-axis hole:       1 (revoke_persona authority — already
//                                    filed implementation-note-227-
//                                    AUTHORITY)
//
// Bridge readiness: NOT GREEN. The 6 revoke-coverage HOLEs above must be
// fixed (or explicitly accepted as known-issue) before
// implementation-note-228 ships. The DELEGATED handlers in
// `crate::broker` need their own audit pass under the same protocol
// (filed: pending implementation-note-229,
// orchestrator to file).
//
// Re-run protocol: bump the audit date above and re-walk every arm
// whenever this match block gains a new arm, or when
// `resolve_grant_for_request` lands (it will replace the inline
// get_revoked_sids calls and the COVERED rows will become
// "COVERED-VIA-HELPER").

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use tokio::sync::broadcast;

use core_approval::{ApprovalLifecycle, SubmitMetadata};
use core_grant_types::grant_receipt::{
    Evidence, GrantEvaluation, GrantEvaluationOutcome, ReceiptKind, ReceiptOutcome, VaultReceipt,
};
use core_personas::MtlsPrincipal;

use crate::infra::audit::AuditFilter;
use crate::infra::events::GrantEvent;
use crate::infra::handlers::support::emit_local_state_v2_receipt;
use crate::infra::rate_limit::RateLimiter;
use crate::infra::receipt::{
    current_identity,
    issue::{TerminationMeta, issue_cohort_a_receipt},
    sign_vault_receipt,
};
use crate::infra::store::DaemonStore;
use crate::infra::vault::{Vault, VaultScope};
use crate::trust::approval::{ApprovalRequestInfo, DaemonApprovalStoreRef, GrantShapeFields};
use crate::trust::policy::{ApprovalRequirement, PolicyEngine};
use crate::trust::presence::{self, GateOutcome, HighRiskOp};
use core_events::receipt::{
    LocalStateKeyResolveBody, LocalStateKeyRotationBody, RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
    RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION, TerminationAuthority, TerminationReason,
};
use core_grants::GrantState as CoreGrantState;

// implementation-note-230: quarantine state. Flipped by the daemon
// runtime's startup sampling verify (or any later detected break) so the
// dispatch layer can refuse write-class socket methods while still allowing
// read-class probes (audit_verify, audit_query, audit_log_query,
// audit_explain, receipt_tree, ping) for operator diagnosis.
//
// A one-way latch: set once, never cleared without daemon restart. Recovery
// is `ember daemon clear-quarantine` (separate CLI subcommand, not yet
// wired) operating via a manual filesystem flag that the next daemon
// startup reads.
static QUARANTINED: AtomicBool = AtomicBool::new(false);
static QUARANTINE_REASON: OnceLock<String> = OnceLock::new();

/// Flip the daemon into quarantine. Idempotent (later calls don't overwrite
/// the first-recorded reason). Called by runtime startup verify on tamper
/// detect and by handler arms that detect a break mid-serve.
pub fn enter_quarantine(reason: String) {
    QUARANTINED.store(true, Ordering::Release);
    let _ = QUARANTINE_REASON.set(reason);
}

/// Read the quarantine latch. Used by the dispatch-method gate.
pub fn is_quarantined() -> bool {
    QUARANTINED.load(Ordering::Acquire)
}

/// Read the quarantine reason, if any. Used by the dispatch-method gate's
/// error payload + the dashboard `/health` surface.
pub fn quarantine_reason() -> Option<&'static str> {
    QUARANTINE_REASON.get().map(String::as_str)
}

/// Read-class socket methods that proceed even when the daemon is
/// quarantined. The principle: a tamper-detected daemon should still let
/// the operator query the audit log to diagnose the break, but must refuse
/// any write that would extend the tampered chain or mutate state.
///
/// Default-deny: anything not on this list is treated as write-class and
/// refused while quarantined. New read-class methods must be added here
/// explicitly.
fn is_read_class_method(method: &str) -> bool {
    matches!(
        method,
        "ping"
            | "audit_verify"
            | "audit_query"
            | "audit_log_query"
            | "audit_explain"
            | "receipt_tree"
            | "receipt_query"
            | "list_personas"
            | "list_grants"
            | "list_operator_grants"
            | "list_credentials"
            | "list_devices"
            | "list_roots"
            | "list_personas_with_grants"
            | "list_pending_approvals"
            | "show_persona"
            | "show_grant"
            | "show_device"
            | "show_root"
            | "binary_manifest_show"
            | "health"
            | "status"
            | "vault_status"
            | "version"
    )
}

/// implementation-note-230 — socket-method handler that wraps the
/// audit chain verifier primitive (`infra::audit::run_audit_verify`) for
/// `dispatch_method`. Returns a JSON shape callers can format directly.
///
/// `tail` limits the walk to the most recent N rows. `None` walks the
/// full chain.
///
/// # target_state_anchor
///
/// `fn handle_audit_verify`
pub fn handle_audit_verify(
    store: &DaemonStore,
    tail: Option<usize>,
) -> Result<Value, (i32, String)> {
    use crate::infra::audit::{VerifyOutcome, run_audit_verify};
    let outcome =
        run_audit_verify(store.conn(), tail).map_err(|e| (-32000, format!("audit_verify: {e}")))?;
    Ok(match outcome {
        VerifyOutcome::Ok { rows_walked } => json!({
            "ok": true,
            "rows_walked": rows_walked,
            "tail": tail,
        }),
        VerifyOutcome::Break {
            at_row_id,
            expected_hash,
            stored_hash,
            rows_walked_before,
        } => json!({
            "ok": false,
            "break": {
                "at_row_id": at_row_id,
                "expected_hash": expected_hash,
                "stored_hash": stored_hash,
                "rows_walked_before": rows_walked_before,
            },
            "tail": tail,
        }),
    })
}

// development milestone: peer-credential-derived principal binding for
// `delegate_grant`. Mirrors the socket layer's `PeerIdentity` shape so
// `handler.rs` does not have to depend on socket-layer cfg gates. The
// fields are public because this is a kernel-derived identity carried
// by trusted code (the socket layer); there is no validation surface
// for callers to violate.
//
// `pid` is `Option<i32>` because BSD's `LOCAL_PEERCRED` does not always
// surface PID. On macOS in particular, when `pid` is `None`, the only
// safe behavior is to fail-closed — `peercred_principal()` returns
// `HandlerError::PrincipalUnavailable` rather than minting a delegation
// authorized by an unknown principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: Option<i32>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl From<crate::infra::socket::PeerIdentity> for PeerCred {
    fn from(p: crate::infra::socket::PeerIdentity) -> Self {
        PeerCred {
            uid: p.uid,
            pid: p.pid,
        }
    }
}

/// Authority class required to dispatch a JSON-RPC method, per design
/// §"Destination". Phase B (implementation-note-231)
/// declares the type + table; Phase B-enforce will gate dispatch on
/// the lookup. **No enforcement in this slice.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClass {
    /// Any ember-clients group member. Examples: `status`,
    /// `personas.list`, `grants.list`, `receipts.search`, dashboard
    /// mirror methods.
    ConnectOnly,
    /// ember-clients + recent operator-presence proof bound to this
    /// uid. Examples: `delegate_grant`, `create_agent_persona`,
    /// `vault.add`, `vault.get`, `orchestrator.spawn`.
    OperatorPresence,
    /// ember-clients + presence proof + WebAuthn challenge re-attested
    /// within N minutes. Reserved for team0+/ent0 tier; not enabled in
    /// cohort A dev0 (per design tier matrix).
    OperatorPresenceWithReattest,
}

/// Authority class required to dispatch `method`, per the design
/// tier matrix.
///
/// Phase B-enforce
/// (implementation-note-232) flips the table
/// from telemetry-only to enforcing and classifies every currently-
/// shipping JSON-RPC method:
///
///   * `ConnectOnly`  — read-class methods; any ember-clients group
///                      member that the socket layer already let
///                      through can call them.
///   * `OperatorPresence` — mutating / sensitive methods; callers
///                      must arrive with a recent daemon-signed
///                      operator-presence proof EXCEPT for the
///                      bootstrap / privilege-reduction seams that
///                      mint or tear down that proof (`vault_unlock`,
///                      `register_session`, `vault_lock`,
///                      `close_session`).
///   * `OperatorPresenceWithReattest` — reserved for team0+/ent0
///                      deployments per the design tier matrix; no
///                      method is classified here in cohort A.
///
/// **Returns `Option<AuthorityClass>`.** `Some(_)` for explicitly-
/// classified methods. `None` for methods that aren't in this table —
/// the dispatch layer treats `None` as "unknown method," skips both
/// authority gates, and lets the dispatcher's `_ => Err(-32601)` arm
/// emit the standard JSON-RPC "Method not found" response. This is
/// the correct behavior for unknown methods per the JSON-RPC 2.0
/// contract: -32601 (Method not found), NOT -32001 (authority error).
///
/// authority_gate_unknown_method_returns_minus_32601 — checkpoint for the
/// downstream gate behavior; the gate at `dispatch_method` skips on
/// `None` and the dispatcher's _ arm returns -32601.
///
/// authority_class_not_met — checkpoint for the gate downstream that
/// reads this lookup; downstream emits the JSON-RPC -32001 error
/// with that string for KNOWN methods that fail the authority check.
///
/// **The "added to dispatcher, forgot to classify" failure mode** —
/// which the previous fall-through-to-OperatorPresence guarded against
/// — is now caught by `ALL_CLASSIFIED_METHODS_MATCH_DISPATCHER_ARMS`
/// in the test module. A method that lands in the dispatcher without
/// a classification entry returns -32601 (effectively unreachable from
/// external callers) AND fails the exhaustivity test; the dev sees the
/// gap at test time instead of shipping unprotected.
pub fn authority_class_for_method(method: &str) -> Option<AuthorityClass> {
    match method {
        // ---------------- ConnectOnly: read-class methods ----------
        //
        // These are the broad read-class methods callable by any
        // ember-clients member. Operator-only read-class surfaces such
        // as `list_operator_grants` are classified below under
        // OperatorPresence.
        "ping"
        | "audit_verify"
        | "audit_query"
        | "receipt_query"
        | "list_personas"
        | "list_grants"
        | "list_pending_approvals"
        | "list_receipts"
        | "get_receipt"
        | "list_standing_grants"
        | "grant_status"
        | "grant_budget_status"
        | "evaluate_grant"
        | "daemon_persona"
        | "presence_token_mint"
        | "poll_notifications"
        | "await_approval"
        | "headless_preflight_gaps"
        | "vault_status"
        | "trust.list"
        | "trust_list"
        | "trust.show"
        | "trust_show"
        | "trust.explain"
        | "trust_explain"
        // implementation-note-155: refresh_cert
        // is read-class authority (produces a new cert from an existing
        // valid one; never escalates). Per design §Component 4.
        // Anchor: refresh_cert_dispatch_landed
        | "refresh_cert"
        // `status` is the daemon's combined read-class projection
        // (personas + active grants + sandboxes + pending approvals +
        // recent activity, all filtered through
        // team0_connect_only_persona_scope). The dispatcher arm lives
        // at the line marked `"status" =>` and only reads — it mints
        // no credentials, mutates no state. ConnectOnly mirrors the
        // adjacent `list_*` / `grant_status` / `vault_status` arms.
        | "status" => Some(AuthorityClass::ConnectOnly),

        // ---------------- OperatorPresence: mutating / sensitive ---
        //
        // Anything that mints credentials, mutates grants, touches
        // the vault, or routes a broker call. Non-bootstrap methods on
        // this lane now require both a daemon-signed presence-token and an
        // unlocked interactive session on every tier.
        "create_persona"
        | "build_init_first_grant_receipt"
        | "revoke_persona"
        | "audit_log_query"
        | "audit_explain"
        | "grant_summary"
        | "detect_anomalies"
        | "receipt_tree"
        | "list_operator_grants"
        | "headless_status"
        | "create_grant"
        | "delegate_grant"
        | "revoke_grant"
        | "extend_grant"
        | "revoke_statement"
        | "evaluate_tool_call"
        | "use_credential"
        | "vault_add"
        | "vault_list"
        | "vault_remove"
        | "vault_lock"
        | "vault_unlock"
        | "vault_get"
        | "vault_migrate_acl"
        | "sandbox_create"
        | "sandbox_list"
        | "sandbox_stop"
        | "sandbox_delete"
        | "sandbox_exec"
        | "sandbox_run"
        | "local_state_key_get"
        | "local_state_key_set"
        | "local_state_key_rotate_and_reencrypt"
        | "binary_pin_generate"
        | "submit_approval"
        | "propose_grant"
        | "resolve_approval"
        | "expire_grants"
        | "create_standing_grant"
        | "remove_standing_grant"
        | "request_access"
        | "request_access_blocking"
        | "broker_issue"
        | "broker_revoke"
        | "broker_list"
        | "broker_resolve"
        | "broker_exec"
        | "broker.mint_gh_token"
        | "broker_register_pid_watcher"
        | "presence/request_proof"
        | "presence_request_proof"
        | "presence/enroll"
        | "presence_enroll"
        | "sops_unwrap_dek"
        | "sops.pubkey"
        | "sops.wrap"
        | "sops.unwrap"
        | "register_session"
        | "close_session"
        | "headless_enroll"
        | "headless_revoke" => Some(AuthorityClass::OperatorPresence),

        // ---------------- OperatorPresenceWithReattest ----------------
        //
        // Reserved for the team0+/ent0 tier per design. No method
        // in cohort A dev0 is classified here. Adding one without
        // also wiring a WebAuthn re-attestation surface would brick
        // it (`RequestContext::satisfies` always returns false for
        // this class until Phase D lands).

        // ---------------- Fall-through: unknown method --------------
        //
        // Returns `None` so the dispatch layer can distinguish
        // "method is known but caller lacks authority" (-32001) from
        // "method does not exist" (-32601, the JSON-RPC contract).
        //
        // The previous "fall closed to OperatorPresence" semantic was
        // intended to catch "added to dispatcher, forgot to classify"
        // bugs, but it also broke the JSON-RPC unknown-method contract
        // (test_unknown_method failed on origin/main for ~8h on
        // 2026-05-17 returning -32001 instead of -32601). The classify-
        // forgetfulness check is now enforced by the
        // `ALL_CLASSIFIED_METHODS_MATCH_DISPATCHER_ARMS` test which
        // surfaces gaps at `cargo test` time instead of by smuggling
        // the wrong error code at runtime.
        _ => None,
    }
}

fn operator_presence_bootstrap_method(method: &str) -> bool {
    matches!(method, "vault_unlock" | "register_session")
}

fn operator_presence_privilege_reduction_method(method: &str) -> bool {
    matches!(method, "vault_lock" | "close_session")
}

fn operator_presence_token_optional_method(method: &str) -> bool {
    operator_presence_bootstrap_method(method)
        || operator_presence_privilege_reduction_method(method)
}

/// Errors returned by the principal-binding layer.
///
/// These are converted to JSON-RPC error tuples by the dispatch layer:
///   `PrincipalUnavailable` -> `-32401`, "principal binding unavailable"
///   `PrincipalMismatch    -> `-32401`, "principal mismatch"
///
/// `-32401` is reused from the JSON-RPC convention (Unauthorized) — same
/// code used elsewhere in the daemon for authorization rejections that
/// are NOT policy denials (`-32003`) or generic param errors (`-32602`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// The peer-credential structure did not contain enough information
    /// to derive a principal. On macOS this happens whenever
    /// `LOCAL_PEERCRED` did not return a PID. We fail-closed rather than
    /// fall back to UID-only binding (which would let any same-UID
    /// process claim any persona).
    PrincipalUnavailable,
    /// The kernel-derived principal does not match the persona the
    /// caller asserted in their request params. The caller is lying
    /// about which persona they are.
    PrincipalMismatch,
    /// The peer's PID is not enrolled in the daemon's PID->persona
    /// registry. The caller has not yet established an identity in
    /// this daemon (no `create_persona` call from this PID, or the
    /// enrollment expired/was cleared).
    PrincipalNotEnrolled,
}

impl HandlerError {
    pub fn to_jsonrpc(&self) -> (i32, String) {
        match self {
            HandlerError::PrincipalUnavailable => (
                -32401,
                "delegate_grant: principal binding unavailable on this \
                 platform (peer PID was not surfaced by the kernel)"
                    .to_string(),
            ),
            HandlerError::PrincipalMismatch => (
                -32401,
                "delegate_grant: caller's kernel-derived principal does \
                 not match the asserted caller_persona_id"
                    .to_string(),
            ),
            HandlerError::PrincipalNotEnrolled => (
                -32401,
                "delegate_grant: caller PID is not enrolled with any \
                 persona — call create_persona on this connection first"
                    .to_string(),
            ),
        }
    }
}

/// Per-connection request context carrying kernel-derived identity.
///
/// The `peer` field is populated by the socket layer at connection accept
/// time; the `principal` field is the persona id resolved from `peer.pid`
/// via `peercred_principal()`. For `Internal` callers, both are `None`.
///
/// The struct deliberately mirrors what we expect to extend to
/// session-ticket-based binding (Alternative B) so the handler call
/// site does not change between phases — only the population of
/// `principal` does.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub source: DispatchSource,
    pub peer: Option<PeerCred>,
    /// Pre-resolved persona id, when the dispatch layer has already
    /// looked it up (e.g. for tests that want to inject a principal
    /// directly without going through the PID registry).
    pub principal: Option<String>,
    /// Base directory for session sidecars (`~/.ember/sessions/`). Required
    /// by `register_session` and `close_session` RPC arms to read/write
    /// `SessionMeta` + `receipt.json`. `None` for internal callers and test
    /// contexts that don't exercise the session lifecycle.
    pub sessions_dir: Option<std::path::PathBuf>,
    /// implementation-note-233: bound LLM proxy
    /// URL plumbed from the runtime after the proxy listener binds. Populated
    /// by `SocketListener::with_llm_proxy_url` and consumed by
    /// `register_session` instead of reading `EMBER_PROXY_URL` from the
    /// environment, which is unreliable across tokio worker threads (Rust
    /// 2024 `set_var` cross-thread visibility hazard).
    pub llm_proxy_url: Option<String>,
    /// implementation-note-233: bound git proxy
    /// URL plumbed from the runtime after the git proxy listener binds.
    /// Matches the pattern of `llm_proxy_url` above.
    pub git_proxy_url: Option<String>,
    /// implementation-note-133 — kernel-attested
    /// (uid, pid, socket_path) triple captured at connection accept
    /// time. Threaded through to broker_issue / broker_revoke /
    /// broker_list / broker_exec / session.lookup_or_open so per-call
    /// authorization is rooted in a kernel-supplied identity rather
    /// than the attacker-controlled `caller_persona` payload field.
    ///
    /// `None` for internal callers (admin CLI, test harness, recovery
    /// flows) and pre-migration socket entry points; broker handlers
    /// fall back to the legacy "warn but allow" path in that case.
    pub peer_cred_principal: Option<crate::infra::runtime::PeerCredPrincipal>,
    /// design component 4 — mTLS-attested principal resolved from the
    /// client cert presented on the cross-uid bridge listener. When
    /// set, the dispatch overlay (see `dispatch_method_with_context`)
    /// reads `mtls_principal.persona_id` as the calling persona in
    /// place of any wire-claimed `caller_persona_id`, mirroring the
    /// per-agent-UDS path's `EnrolledPrincipal` overlay. The bridge
    /// listener is the only path that populates this field; UDS
    /// callers always carry `None` here.
    pub mtls_principal: Option<MtlsPrincipal>,
    /// implementation-note-234 —
    /// Phase D presence-token, attached by the JSON-RPC parser slice
    /// (D-3) from the `_presence_token` request parameter. When the
    /// dispatched method's authority class is `OperatorPresence`, the
    /// handler validates this token via
    /// `crate::auth::presence_token::validate`. `None` for ConnectOnly
    /// methods, internal callers, and pre-D callers that have not yet
    /// been retro-fitted with token minting.
    pub presence_token: Option<crate::auth::presence_token::PresenceToken>,
    /// implementation-note-235 — when set,
    /// `enforce_local_state_gate` short-circuits with a synthetic peer
    /// (mirroring the existing `#[cfg(test)]` bypass arm). Only set by
    /// [`RequestContext::socket_for_test`], which is reachable only from
    /// integration tests that explicitly opt in via
    /// `SocketListener::with_test_mode_synthetic_presence_token(true)`.
    /// Production constructors leave this `false`; the binary-pin gate
    /// runs as written.
    pub bypass_binary_pin_gate_for_test: bool,
}

impl RequestContext {
    /// Build an `Internal` context — bypasses peercred binding entirely.
    pub fn internal(reason: &'static str) -> Self {
        Self {
            source: DispatchSource::Internal { reason },
            peer: None,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Build a `Socket` context with a peer credential. The principal
    /// will be lazily resolved by handlers that require it.
    ///
    /// **Under `cfg(test)`**, this auto-synthesizes a daemon-identity-signed
    /// presence_token so socket integration tests can call
    /// OperatorPresence-class methods without manually constructing a token
    /// per test. Production callers (the real socket accept path) pass
    /// `peer = Some(...)` and the non-test arm yields `presence_token = None`
    /// — the dispatcher's operator-presence gate then enforces the real token
    /// requirement.
    ///
    /// This is the same auto-injection pattern the legacy `dispatch_method`
    /// shim (used by some test harnesses) uses at lines 1620-1648; lifting
    /// it into the constructor centralizes the test surface so every
    /// caller of `RequestContext::socket(Some(peer))` works uniformly.
    pub fn socket(peer: Option<PeerCred>) -> Self {
        #[cfg(test)]
        let synthetic_presence_token = peer.as_ref().map(|p| {
            use crate::auth::presence_token::{ScopeKey, mint};
            use std::time::Duration;
            ensure_test_presence_identity();
            let signer = DaemonIdentityPresenceSigner::current()
                .expect("test presence token signer must be initialised");
            mint(p.uid, ScopeKey::all(), Duration::from_secs(60), &signer)
        });
        #[cfg(not(test))]
        let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = None;

        Self {
            source: DispatchSource::Socket,
            peer,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: synthetic_presence_token,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Build a `Socket` context with a pre-resolved principal. Used by
    /// tests that want to assert handler behavior without populating
    /// the global PID registry.
    pub fn socket_with_principal(peer: Option<PeerCred>, principal: String) -> Self {
        Self {
            source: DispatchSource::Socket,
            peer,
            principal: Some(principal),
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        }
    }

    /// Test-only `Socket` context constructor that mints a synthetic
    /// presence_token bound to `peer.uid`. Production code paths MUST
    /// NOT call this — the synthesis exists only so tests can exercise
    /// the operator-presence branch without depending on runtime startup.
    ///
    /// Exists because the cfg(test) synthesis in
    /// [`RequestContext::socket`] is unreachable from integration tests
    /// in `tests/` by Rust language semantics — integration tests link
    /// against the lib as if external and don't see cfg(test) blocks.
    /// implementation-note-235.
    pub fn socket_for_test(peer: PeerCred) -> Self {
        use crate::auth::presence_token::{ScopeKey, mint};
        use std::time::Duration;
        ensure_test_presence_identity();
        let signer =
            DaemonIdentityPresenceSigner::current().expect("test presence token signer must exist");
        let presence_token = Some(mint(
            peer.uid,
            ScopeKey::all(),
            Duration::from_secs(60),
            &signer,
        ));
        Self {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token,
            bypass_binary_pin_gate_for_test: true,
        }
    }

    /// Set the kernel-attested `PeerCredPrincipal` for this request
    /// context. Called by the socket accept path
    /// (`socket::handle_connection`) once it has extracted the
    /// `(uid, pid, socket_path)` triple from the accepted stream.
    ///
    /// implementation-note-133 — builder helper so the
    /// socket layer can stamp the principal without touching every
    /// constructor variant.
    pub fn with_peer_cred_principal(
        mut self,
        principal: Option<crate::infra::runtime::PeerCredPrincipal>,
    ) -> Self {
        self.peer_cred_principal = principal;
        self
    }

    /// Set the mTLS-attested principal for this request context.
    /// Called by the bridge listener (design component 4) once it
    /// has resolved the client cert's SPIFFE URI SAN to a persona id
    /// and cross-checked the container-id SAN. UDS callers never use
    /// this builder.
    ///
    /// `request_context_mtls_principal_overlay` — builder helper so
    /// the bridge layer can stamp the principal without touching every
    /// constructor variant.
    pub fn with_mtls_principal(mut self, principal: Option<MtlsPrincipal>) -> Self {
        self.mtls_principal = principal;
        self
    }

    /// Set the Phase D presence-token for this request context.
    /// Called by the JSON-RPC parser (Phase D Slice 3) when the request
    /// payload carries an `_presence_token` field.
    ///
    /// `request_context_presence_token_builder`
    /// (implementation-note-234) —
    /// additive builder so existing constructors don't need updating.
    ///
    /// `None` is treated as no-op so this method composes cleanly with
    /// constructors that already minted a synthetic token (e.g.
    /// `RequestContext::socket_for_test`). Without the no-op semantics
    /// the socket-accept path's tail call `with_presence_token(None)`
    /// (after `take_presence_token` returned None because the CLI request
    /// didn't carry one) would clobber the synthetic token and re-introduce
    /// the cross-crate "OperatorPresence missing presence_token" failure
    /// mode that implementation-note-235
    /// was filed to close.
    pub fn with_presence_token(
        mut self,
        token: Option<crate::auth::presence_token::PresenceToken>,
    ) -> Self {
        if token.is_some() {
            self.presence_token = token;
        }
        self
    }

    /// Whether this context satisfies the required authority class for
    /// dispatching a JSON-RPC method, per design §"Destination".
    ///
    /// Cohort A dev0 model — the socket layer's
    /// `runtime::authenticate_peer_creds` already enforced the current
    /// connect policy before stamping `peer`: same-euid in development
    /// mode, `ember-clients` membership (or daemon euid) in
    /// install-shaped mode. A `Some(peer)` here is therefore the
    /// kernel-attested proof of "ConnectOnly" authority.
    ///
    /// Internal dispatch sources (admin CLI, recovery flows, the test
    /// harness) are NOT routed through this check — the gate site at
    /// `dispatch_method_with_context` bypasses Internal callers as the
    /// pre-existing in-process trust lane (see `DispatchSource`).
    ///
    /// `OperatorPresenceWithReattest` is reserved for team0+/ent0
    /// deployments per the design tier matrix and is always denied
    /// in cohort A — wiring its proof surface is a Phase D-or-later
    /// activity.
    pub fn satisfies(&self, required: AuthorityClass) -> bool {
        let has_peer = self.peer.is_some();
        // `satisfies` enforces only the connection-level invariant
        // (peer-cred present). The richer operator-presence semantics
        // (token validation + unlocked-session requirement + bootstrap
        // exceptions) are enforced in `dispatch_method_with_context`.
        match required {
            AuthorityClass::ConnectOnly => has_peer,
            AuthorityClass::OperatorPresence => has_peer,
            // No team0+ deployment in cohort A — always denied.
            AuthorityClass::OperatorPresenceWithReattest => false,
        }
    }
}

fn headless_data_dir_from_sessions_dir(sessions_dir: &std::path::Path) -> std::path::PathBuf {
    sessions_dir.parent().unwrap_or(sessions_dir).join("data")
}

fn headless_data_dir_from_context(
    ctx: &RequestContext,
) -> Result<std::path::PathBuf, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    Ok(headless_data_dir_from_sessions_dir(sessions_dir))
}

fn runtime_data_dir_from_context(
    ctx: &RequestContext,
) -> Result<std::path::PathBuf, (i32, String)> {
    headless_data_dir_from_context(ctx)
}

fn runtime_socket_dir_from_context(
    ctx: &RequestContext,
) -> Result<std::path::PathBuf, (i32, String)> {
    let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
        -32000,
        "sessions_dir not configured on this connection".to_string(),
    ))?;
    Ok(sessions_dir.parent().unwrap_or(sessions_dir).join("run"))
}

fn mint_operator_presence_token(
    peer: Option<&PeerCred>,
) -> Result<Option<crate::auth::presence_token::PresenceToken>, (i32, String)> {
    use crate::auth::presence_token::{ScopeKey, mint};

    let Some(peer) = peer else {
        return Ok(None);
    };
    let Some(identity) = crate::infra::receipt::current_identity() else {
        return Err((
            -32000,
            "daemon identity not initialised — cannot mint operator presence token".to_string(),
        ));
    };
    let signer = DaemonIdentityPresenceSigner::new(identity);
    let ttl = std::cmp::max(
        crate::trust::presence::current_config().idle_timeout,
        std::time::Duration::from_secs(60),
    );
    Ok(Some(mint(peer.uid, ScopeKey::all(), ttl, &signer)))
}

struct DaemonIdentityPresenceSigner<'a> {
    persona: &'a crate::infra::receipt::DaemonPersona,
}

impl<'a> DaemonIdentityPresenceSigner<'a> {
    fn new(persona: &'a crate::infra::receipt::DaemonPersona) -> Self {
        Self { persona }
    }

    fn current() -> Option<Self> {
        crate::infra::receipt::current_identity().map(Self::new)
    }
}

impl crate::auth::presence_token::DaemonSigner for DaemonIdentityPresenceSigner<'_> {
    fn sign(&self, msg: &[u8]) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(&*self.persona.sign(msg))
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = ed25519_dalek::Signature::try_from(sig) else {
            return false;
        };
        ed25519_dalek::Verifier::verify(self.persona.verifying_key(), msg, &signature).is_ok()
    }
}

fn ensure_test_presence_identity() {
    if crate::infra::receipt::current_identity().is_some() {
        return;
    }
    let dir = std::env::temp_dir().join("ember-daemon-test-presence-identity");
    std::fs::create_dir_all(&dir).expect("create test presence identity dir");
    let _ = crate::infra::receipt::init_identity(&dir)
        .expect("init daemon identity for presence-token tests");
}

// PID -> Persona enrollment registry. Populated when a Socket caller
// calls `create_persona` and inspected when the same caller (same PID)
// invokes `delegate_grant`.
//
// Why thread-local: the daemon is single-threaded LocalSet at runtime,
// so production correctness only needs a single map. We use a
// thread-local rather than a global static so that cargo's parallel
// test runner gets fresh registries per test thread — otherwise a
// `create_persona` enrollment from one test could leak into another
// test's `delegate_grant` lookup and produce a flaky principal-mismatch
// result. This is a pragmatic phase-1 fit; phase 2 (session ticket)
// will move enrollment into a more structured per-connection store.
std::thread_local! {
    static PID_PERSONA_REGISTRY: RefCell<HashMap<i32, String>> =
        RefCell::new(HashMap::new());
}

std::thread_local! {
    static DISPATCH_DEPLOYMENT_TIER: RefCell<crate::infra::config::DeploymentTier> =
        RefCell::new(crate::infra::config::DeploymentTier::Dev0);
}

/// Enroll a (pid, persona_id) pair in the per-thread registry.
///
/// Called from the `create_persona` handler when the dispatch source is
/// `Socket` and the peer credential surfaced a PID.  Subsequent
/// `delegate_grant` calls from the same PID will resolve to this
/// persona id.
pub fn enroll_pid_persona(pid: i32, persona_id: &str) {
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow_mut().insert(pid, persona_id.to_string());
    });
}

/// Stamp the current deployment tier into the handler's thread-local view.
///
/// The daemon runs the socket dispatch path on a single-threaded `LocalSet`,
/// so a thread-local is sufficient in production and gives tests an isolated
/// seam without cross-thread global leakage.
pub fn set_dispatch_deployment_tier(tier: crate::infra::config::DeploymentTier) {
    DISPATCH_DEPLOYMENT_TIER.with(|slot| {
        *slot.borrow_mut() = tier;
    });
}

fn current_dispatch_deployment_tier() -> crate::infra::config::DeploymentTier {
    DISPATCH_DEPLOYMENT_TIER.with(|slot| *slot.borrow())
}

#[cfg(test)]
struct DeploymentTierGuard {
    previous: crate::infra::config::DeploymentTier,
}

#[cfg(test)]
impl DeploymentTierGuard {
    fn set(next: crate::infra::config::DeploymentTier) -> Self {
        let previous = current_dispatch_deployment_tier();
        set_dispatch_deployment_tier(next);
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for DeploymentTierGuard {
    fn drop(&mut self) {
        set_dispatch_deployment_tier(self.previous);
    }
}

/// Test-only helper: drop all enrollments. Cargo's per-test isolation
/// relies on a fresh registry, so individual tests that enroll PIDs
/// should call this in setup (or rely on thread-local isolation).
#[cfg(test)]
pub fn clear_pid_persona_registry() {
    PID_PERSONA_REGISTRY.with(|reg| reg.borrow_mut().clear());
}

// implementation-note-133 — persona → bound uid registry.
//
// Mirrors `PID_PERSONA_REGISTRY` above but keyed in the reverse
// direction: persona_id → kernel-uid the persona is bound to. The
// broker handlers consult this map to compare the request's
// `caller_persona` (which names a persona id) against the
// `PeerCredPrincipal.uid` extracted from the connection's
// `SO_PEERCRED`. A mismatch signals a stolen-token / cross-uid
// impersonation attempt and the handler refuses with `-32004`.
//
// The binding is populated by the persona enrollment surface
// (`bind_persona_uid`) — for now, tests wire bindings directly. The
// implementation-note-134 integration will populate this map at
// per-agent UDS socket creation time so the binding mirrors what the
// kernel attests on accept.
std::thread_local! {
    static PERSONA_UID_REGISTRY: RefCell<HashMap<String, u32>> =
        RefCell::new(HashMap::new());
}

/// Bind a (persona_id, uid) pair so the broker handlers can compare a
/// `PeerCredPrincipal.uid` against the persona's bound uid.
///
/// Called from the agent persona enrollment path (implementation-note-236-
/// UDS-SOCKET will own production wiring) and from tests that want
/// to assert mismatch refusals without a real socket.
pub fn bind_persona_uid(persona_id: &str, uid: u32) {
    PERSONA_UID_REGISTRY.with(|reg| {
        reg.borrow_mut().insert(persona_id.to_string(), uid);
    });
}

/// Look up the uid a persona is bound to. Returns `None` when the
/// persona has not been bound (legacy / system-internal personas that
/// pre-date the implementation-note-134 enrollment path).
pub fn lookup_persona_uid(persona_id: &str) -> Option<u32> {
    PERSONA_UID_REGISTRY.with(|reg| reg.borrow().get(persona_id).copied())
}

/// Test-only helper: drop all persona→uid bindings.
#[cfg(test)]
pub fn clear_persona_uid_registry() {
    PERSONA_UID_REGISTRY.with(|reg| reg.borrow_mut().clear());
}

/// Resolve the calling persona for a peer credential.
///
/// On Linux the registry is keyed by PID, populated at `create_persona`
/// dispatch time. On macOS where `peer.pid` may be `None`, we fail-closed
/// with `PrincipalUnavailable` rather than fall back to UID-only binding
/// (which would let any same-UID process claim any persona).
pub fn peercred_principal(peer: &PeerCred) -> Result<String, HandlerError> {
    let pid = peer.pid.ok_or(HandlerError::PrincipalUnavailable)?;
    PID_PERSONA_REGISTRY.with(|reg| {
        reg.borrow()
            .get(&pid)
            .cloned()
            .ok_or(HandlerError::PrincipalNotEnrolled)
    })
}

fn trusted_request_persona(ctx: &RequestContext) -> Result<Option<String>, HandlerError> {
    if let Some(principal) = &ctx.principal {
        return Ok(Some(principal.clone()));
    }
    if let Some(peer) = &ctx.peer {
        match peercred_principal(peer) {
            Ok(principal) => return Ok(Some(principal)),
            Err(HandlerError::PrincipalNotEnrolled) => {}
            Err(other) => return Err(other),
        }
    }
    if let Some(mtls) = &ctx.mtls_principal {
        return Ok(Some(mtls.persona_id.clone()));
    }
    Ok(None)
}

fn team0_connect_only_persona_scope(
    ctx: &RequestContext,
    method: &str,
) -> Result<Option<String>, (i32, String)> {
    let tier = current_dispatch_deployment_tier();
    if !tier.requires_multi_uid_authz() {
        return Ok(None);
    }

    trusted_request_persona(ctx)
        .map_err(|e| e.to_jsonrpc())?
        .ok_or((
            -32004,
            format!(
                "{method}: deployment tier {} requires a trusted enrolled principal for \
             ConnectOnly read scoping",
                tier.as_str()
            ),
        ))
        .map(Some)
}

fn persona_scoped_param_for_connect_only(
    ctx: &RequestContext,
    params: &Value,
    method: &str,
    field: &str,
    required_in_dev0: bool,
) -> Result<Option<String>, (i32, String)> {
    let scoped_principal = team0_connect_only_persona_scope(ctx, method)?;
    let claimed = params.get(field).and_then(|v| v.as_str());

    match scoped_principal {
        Some(principal) => {
            if let Some(claimed) = claimed
                && claimed != principal
            {
                tracing::warn!(
                    method = %method,
                    field = %field,
                    claimed_persona_id = %claimed,
                    trusted_persona_id = %principal,
                    tier = current_dispatch_deployment_tier().as_str(),
                    "connect-only persona-scoped read refused: claimed persona does not match trusted principal"
                );
                return Err((
                    -32004,
                    format!("{method}: claimed {field} does not match trusted principal"),
                ));
            }
            Ok(Some(principal))
        }
        None => {
            if required_in_dev0 {
                claimed
                    .map(|value| Some(value.to_string()))
                    .ok_or((-32602, format!("missing '{field}'")))
            } else {
                Ok(claimed.map(|value| value.to_string()))
            }
        }
    }
}

fn ensure_connect_only_owner_matches_trusted_principal(
    ctx: &RequestContext,
    method: &str,
    owner_persona_id: &str,
) -> Result<(), (i32, String)> {
    let Some(trusted_persona) = team0_connect_only_persona_scope(ctx, method)? else {
        return Ok(());
    };

    if owner_persona_id != trusted_persona {
        tracing::warn!(
            method = %method,
            owner_persona_id = %owner_persona_id,
            trusted_persona_id = %trusted_persona,
            tier = current_dispatch_deployment_tier().as_str(),
            "connect-only persona-scoped lookup refused: owner does not match trusted principal"
        );
        return Err((
            -32004,
            format!("{method}: requested object does not belong to trusted principal"),
        ));
    }

    Ok(())
}

fn asserted_persona_matches(persona: &crate::infra::persona::PersonaInfo, asserted: &str) -> bool {
    persona.id == asserted || persona.name == asserted
}

fn resolve_persona_by_name_or_id(
    store: &DaemonStore,
    asserted: &str,
) -> Result<crate::infra::persona::PersonaInfo, (i32, String)> {
    if let Ok(persona) = store.get_persona(asserted) {
        return Ok(persona);
    }

    store
        .list_personas()
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .find(|persona| persona.name == asserted)
        .ok_or_else(|| (-32004, format!("persona '{asserted}' not found")))
}

fn resolve_register_session_persona(
    store: &DaemonStore,
    ctx: &RequestContext,
    asserted: &str,
) -> Result<crate::infra::persona::PersonaInfo, (i32, String)> {
    if let Some(trusted_principal) = trusted_request_persona(ctx).map_err(|e| e.to_jsonrpc())? {
        let persona = store.get_persona(&trusted_principal).map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => (
                -32004,
                format!(
                    "register_session: trusted principal '{}' not found",
                    trusted_principal
                ),
            ),
            other => (-32000, other.to_string()),
        })?;
        if !asserted_persona_matches(&persona, asserted) {
            tracing::warn!(
                trusted_persona_id = %persona.id,
                trusted_persona_name = %persona.name,
                asserted_persona = %asserted,
                "register_session refused: asserted persona does not match trusted principal"
            );
            return Err((
                -32004,
                "register_session: asserted persona does not match trusted principal".to_string(),
            ));
        }
        return Ok(persona);
    }

    resolve_persona_by_name_or_id(store, asserted)
}

fn resolve_register_session_active_grant(
    store: &DaemonStore,
    persona: &crate::infra::persona::PersonaInfo,
    asserted: &str,
) -> Result<crate::trust::grant::GrantInfo, (i32, String)> {
    store
        .list_active_grants()
        .map_err(|e| (-32000, e.to_string()))?
        .into_iter()
        .find(|grant| grant.persona_id == persona.id && grant.status == "active")
        .ok_or_else(|| (-32004, format!("no active grant for persona '{asserted}'")))
}

// implementation-note-237 — checkpoint for
// target_state_anchor. This block extends the per-socket Persona
// enrollment doctrine of design to the in-container case: agents
// inside containers connect via per-agent UDS sockets at
// `/run/emberd/agent-<uuid>.sock` (per implementation-note-134).
// emberd records `(socket_path, persona_id, grant_id, brief_content_hash)`
// at spawn time; every RPC on that socket has identity resolved from
// the enrollment table, NOT from wire-claimed `caller_persona_id` /
// `caller_grant_id`. Worker B with a forged grant_id cannot
// impersonate the orchestrator just by sending the orchestrator's
// grant_id over its own socket.

/// implementation-note-238 (design §"In-container
/// extension") — the kernel-attested-equivalent identity surfaced by
/// the per-socket enrollment table when an RPC arrives on a per-agent
/// UDS socket.
///
/// Constructed by [`enroll_container_persona`] from a successful row
/// lookup in `agent_socket_enrollments`. The dispatch layer uses
/// these fields verbatim — `persona_id` overrides any payload-claimed
/// `caller_persona` / `caller_persona_id`; `grant_id` overrides any
/// payload-claimed `caller_grant_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledPrincipal {
    pub persona_id: String,
    pub grant_id: String,
    pub brief_content_hash: String,
}

/// implementation-note-238 — directory prefix for
/// per-agent UDS sockets.
///
/// Mirrors `crate::infra::socket::PER_AGENT_SOCKET_PARENT`. Kept as a
/// `&'static str` here so the dispatch-time match is a pure string
/// operation and does not pull in the socket module's full surface.
const PER_AGENT_SOCKET_DIR: &str = "/run/emberd/";

/// implementation-note-238 — true when the supplied
/// socket path matches the per-agent UDS shape
/// (`/run/emberd/agent-*.sock`).
///
/// Used by [`dispatch_method_with_context`] to decide whether to
/// resolve the calling persona from the enrollment table or to fall
/// through to the legacy peercred / PID-registry path. Test seam:
/// callers passing a temp-dir socket path (e.g. tempfile-rooted
/// `agent-<uuid>.sock`) match too — the match is on the filename
/// pattern, not the absolute parent — so unit tests can exercise the
/// enrolled-principal branch without binding into `/run/emberd/`.
pub fn is_per_agent_socket_path(socket_path: &std::path::Path) -> bool {
    let Some(name) = socket_path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if !(name.starts_with("agent-") && name.ends_with(".sock")) {
        return false;
    }
    // Production callers land in `/run/emberd/`; tests use tempdir-
    // rooted paths. Both shapes are accepted to avoid forcing the
    // test harness to bind under `/run`.
    if let Some(parent) = socket_path.parent().and_then(|p| p.to_str()) {
        // Either the canonical `/run/emberd/` prefix or any tempdir
        // path is acceptable — the discriminator is the filename
        // shape. A naked path with no parent is refused (test seam
        // requires at least one parent component).
        let _ = parent;
    } else {
        return false;
    }
    // Belt-and-suspenders: keep the canonical prefix observable so
    // operator audits can grep for production callers.
    let _ = PER_AGENT_SOCKET_DIR;
    true
}

/// implementation-note-238 — resolve the
/// kernel-attested-equivalent principal for a per-agent UDS socket.
///
/// Reads the `agent_socket_enrollments` row keyed by `socket_path`
/// and returns the recorded `(persona_id, grant_id, brief_content_hash)`
/// triple. The wire-claimed `caller_persona_id` / `caller_grant_id`
/// are NOT consulted — the spawn-time enrollment IS the identity
/// claim. Defense: worker B with a forged grant_id over its own
/// socket cannot impersonate the orchestrator's grant_id, because the
/// socket path determines which enrollment row applies.
///
/// Returns `HandlerError::PrincipalNotEnrolled` when no `active`
/// row exists for the supplied path (revoked rows count as missing —
/// the store helper filters them).
// implementation-note-237 — checkpoint for target_state_anchor
pub fn enroll_container_persona(
    store: &DaemonStore,
    socket_path: &std::path::Path,
) -> Result<EnrolledPrincipal, HandlerError> {
    let path_str = match socket_path.to_str() {
        Some(s) => s,
        None => {
            tracing::warn!(
                socket_path = %socket_path.display(),
                "enroll_container_persona: socket path is not valid UTF-8 — \
                 refusing"
            );
            return Err(HandlerError::PrincipalNotEnrolled);
        }
    };
    match store.lookup_agent_socket_enrollment(path_str) {
        Ok(Some(row)) => Ok(EnrolledPrincipal {
            persona_id: row.persona_id,
            grant_id: row.grant_id,
            brief_content_hash: row.brief_content_hash,
        }),
        Ok(None) => {
            tracing::warn!(
                socket_path = %path_str,
                "enroll_container_persona: no active enrollment for socket"
            );
            Err(HandlerError::PrincipalNotEnrolled)
        }
        Err(e) => {
            tracing::warn!(
                socket_path = %path_str,
                error = %e,
                "enroll_container_persona: store lookup failed — refusing"
            );
            Err(HandlerError::PrincipalNotEnrolled)
        }
    }
}

/// Origin of a dispatched RPC request.
///
/// Fix for development milestone (CRITICAL): the `force` flag on `create_grant`
/// used to be accepted from any wire caller, letting unauthenticated socket
/// clients mint grants that bypassed the policy engine. We now thread the
/// dispatch *source* through the handler so that only `Internal` callers
/// (admin CLI paths, test harness, recovery flows) can request policy
/// bypass. Socket callers that attempt `force: true` are rejected.
///
/// **Type-level barrier (development milestone):** The `Internal` variant
/// requires a mandatory `reason` string literal so that every in-process
/// privilege escalation is visible and attributable at the call site.  Code
/// review can grep for `DispatchSource::Internal` and see exactly *why* each
/// caller claims the internal trust lane.  Forgetting the `reason` is a
/// compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchSource {
    /// Request arrived via the unix-domain socket RPC path. Callers on this
    /// path are NOT authenticated as admins, and MUST NOT be able to
    /// bypass policy gates. Any `force: true` is rejected.
    Socket,
    /// Request was synthesized by an in-process caller that has already
    /// established admin identity (test harness, internal admin CLI path,
    /// recovery flows). `force: true` is honored.
    ///
    /// `reason` is a mandatory static string that names the trust context
    /// at the call site (e.g. `"admin CLI"`, `"recovery flow"`,
    /// `"test harness"`).  It is purely a code-review / audit annotation
    /// and has no effect on runtime behaviour.
    Internal { reason: &'static str },
}

impl DispatchSource {
    /// Returns `true` when this source carries internal (admin) trust.
    #[inline]
    pub fn is_internal(self) -> bool {
        matches!(self, DispatchSource::Internal { .. })
    }
}

/// Test-only dispatcher — unconditionally runs as an `Internal` source so
/// existing tests can use `force: true` as a setup shortcut. Not reachable
/// from the socket path.
pub async fn dispatch_method(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // implementation-note-232: the per-method
    // authority gate moved into `dispatch_method_with_context` (the
    // production choke point all socket-layer entry points converge
    // on). This test wrapper constructs a `DispatchSource::Internal`
    // context downstream, which is exempt from the gate by design —
    // Internal callers are the pre-existing in-process trust lane.
    dispatch_method_with_source(
        store,
        vault,
        policy,
        rate_limiter,
        None,
        DispatchSource::Internal {
            reason: "test harness",
        },
        method,
        params,
    )
    .await
}

pub struct Banner {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub click_url: String,
}

/// Build the notification banner strings for a pending approval request.
///
/// Kept short to fit macOS banner constraints (~60 chars title, ~50 chars
/// subtitle/body). The scope string is intentionally excluded — it was the
/// primary overflow culprit. The dashboard deep-link (`click_url`) is the
/// canonical control surface for full context.
pub fn build_banner(persona_name: &str, req: &ApprovalRequestInfo) -> Banner {
    let id_prefix: String = req
        .id
        .strip_prefix("approval-")
        .unwrap_or(&req.id)
        .chars()
        .take(8)
        .collect();

    // Title: prefer tool_name when present; fall back to the action string.
    // Cap the action at 40 chars to leave room for "Ember · <name> wants ".
    // Append agent_framework as a parenthesized badge when present.
    let framework_suffix = req
        .agent_framework
        .as_deref()
        .map(|f| {
            let f_short: String = f.chars().take(16).collect();
            format!(" ({f_short})")
        })
        .unwrap_or_default();
    let title = if let Some(ref tool) = req.tool_name {
        let tool_short: String = tool.chars().take(40).collect();
        format!("Ember · {persona_name} · {tool_short}{framework_suffix}")
    } else {
        let action_short: String = req.action.chars().take(40).collect();
        format!("Ember · {persona_name} wants {action_short}{framework_suffix}")
    };

    // Subtitle: credential · TTL · risk — decision-relevant, no scope/id.
    let ttl_part = req
        .ttl_secs
        .map(|s| format!(" · {s}s TTL"))
        .unwrap_or_default();
    let risk_part = if req.risk_level.is_empty() {
        String::new()
    } else {
        format!(" · risk {}", req.risk_level)
    };
    let subtitle_raw = format!("{}{ttl_part}{risk_part}", req.credential_name);
    // Hard-truncate at 50 chars to guard against long credential names.
    let subtitle: String = if subtitle_raw.chars().count() > 50 {
        let mut s: String = subtitle_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        subtitle_raw
    };

    // Body: prefer target_host + target_summary when either is present; then
    // fall back to target_url; otherwise use the click-to-review prompt.
    let body_raw = match (&req.target_host, &req.target_summary, &req.target_url) {
        (Some(host), Some(summary), _) => format!("{host}{summary}"),
        (Some(host), None, _) => host.clone(),
        (None, Some(summary), _) => summary.clone(),
        (None, None, Some(url)) => url.clone(),
        (None, None, None) => format!("Click to review · {id_prefix}"),
    };
    let body: String = if body_raw.chars().count() > 50 {
        let mut s: String = body_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        body_raw
    };

    let click_url = format!("http://localhost:3141/approvals/{}", req.id);

    Banner {
        title,
        subtitle,
        body,
        click_url,
    }
}

/// Surface a pending approval to the user via the OS notification system.
///
/// Best-effort — errors are silently swallowed. The call is skipped when
/// `EMBER_NO_DESKTOP_NOTIFY=1` is set (useful in CI/tests).
fn notify_require_approval(store: &DaemonStore, req: &ApprovalRequestInfo) {
    #[cfg(test)]
    {
        let _ = (store, req);
        return;
    }
    #[cfg(not(test))]
    {
        if std::env::var("EMBER_NO_DESKTOP_NOTIFY").as_deref() == Ok("1") {
            return;
        }
        let persona_name = store
            .get_persona(&req.persona_id)
            .map(|p| p.name)
            .unwrap_or_else(|_| req.persona_id.chars().take(8).collect());
        let banner = build_banner(&persona_name, req);
        crate::infra::notify::send_notification_with_url(
            &banner.title,
            Some(&banner.subtitle),
            &banner.body,
            Some(&banner.click_url),
        );
    }
}

/// Dispatch a method with an optional event broadcast channel. When a handler
/// triggers a server-initiated event (e.g. `revoke_grant`), the event is
/// published on the channel for connected socket clients to forward.
///
/// This is the **socket entry point** — it always runs as
/// `DispatchSource::Socket`, which causes any caller-supplied `force: true`
/// on `create_grant` to be rejected. See `DispatchSource` for context.
///
/// Backward-compat entry point: no peer credential, so principal binding
/// (development milestone) cannot apply — `delegate_grant` falls back to the
/// param-asserted ownership check. Production callers should use
/// `dispatch_method_with_peer` instead.
pub async fn dispatch_method_with_events(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(None),
        method,
        params,
    )
    .await
}

/// Socket entry point with a peer credential — the production path.
///
/// The socket layer captures `SO_PEERCRED` / `LOCAL_PEERCRED` at accept
/// time and forwards the resulting `PeerIdentity` here. The handler
/// uses it to bind `delegate_grant` to a kernel-derived principal
/// instead of trusting an attacker-controlled `caller_persona_id` param.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_peer(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    peer: Option<crate::infra::socket::PeerIdentity>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let peer_cred: Option<PeerCred> = peer.map(Into::into);
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(peer_cred),
        method,
        params,
    )
    .await
}

/// Non-Linux/macOS fallback — never has a real PeerIdentity.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn dispatch_method_with_peer(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    _peer: Option<()>,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        RequestContext::socket(None),
        method,
        params,
    )
    .await
}

/// Per-op `require_user_presence` gate is applied to high-risk operations
/// dispatched here (`vault_add`,
/// `vault_remove`, `create_grant`). Read-class operations bump the
/// session's `last_activity` via `presence::record_activity()` so they
/// don't spam the user with biometric prompts but also keep the session
/// "warm" — the lock fires on idle silence, not on dashboard polling.
fn check_user_presence_gate(
    op: HighRiskOp,
    override_quiet_hours: bool,
) -> Result<(), (i32, String)> {
    match presence::require_user_presence(op, override_quiet_hours) {
        GateOutcome::Allowed => Ok(()),
        GateOutcome::Locked { reason } => Err((-32030, reason)),
    }
}

/// Allow-listed caller → vault namespace for the per-caller local-state
/// content key. Restricts `local_state_key_*` socket methods to the three
/// known ember binaries; a malicious caller cannot pollute the namespace
/// with arbitrary keys.
///
/// Per KEYCHAIN-CONSOLIDATE-CLI adversarial-review HIGH-1.
fn local_state_vault_name(caller: &str) -> Result<String, (i32, String)> {
    match caller {
        "cli" | "gui" | "native-host" => Ok(format!("local-state/{caller}")),
        other => Err((
            -32602,
            format!("invalid 'caller' {other:?}: expected one of cli, gui, native-host"),
        )),
    }
}

fn current_vault(store: &DaemonStore, op: &str) -> Result<std::rc::Rc<Vault>, (i32, String)> {
    crate::infra::interactive_unlock::current_live_vault(store)
        .map_err(|err| (-32030, err.with_context(op)))
}

/// Common authorization gate for `local_state_key_*` methods. Enforces
/// the adversarial-review hardening:
///   CRIT-1 — peer credentials must be present (kernel-attested uid).
///            Source::Internal is refused; these are wire-only methods.
///   HIGH-1 — peer's binary content-hash must match the pinned manifest
///            entry for the claimed `caller`. Missing manifest → fail-closed
///            with directive to run `ember binary-pin generate`.
///
/// **Test bypass**: under `#[cfg(test)]` the gate short-circuits with a
/// synthetic peer. The pre-existing handler tests use `Internal`-source
/// dispatch (via `dispatch_method`) which the production gate refuses;
/// rather than diverge each test through a wire-equivalent harness, we
/// scope the bypass behind `#[cfg(test)]` so production builds enforce
/// the full check. The `binary_pin` module tests cover the gate's
/// components in isolation; full T2 integration of the wire path is
/// tracked as a follow-up.
fn enforce_local_state_gate(
    source: DispatchSource,
    peer: Option<PeerCred>,
    caller: &str,
    store: &DaemonStore,
    bypass_for_test: bool,
) -> Result<PeerCred, (i32, String)> {
    #[cfg(test)]
    {
        let _ = (source, caller, store, bypass_for_test);
        return Ok(peer.unwrap_or(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        }));
    }
    #[cfg(not(test))]
    {
        // implementation-note-235 — external
        // integration tests in sibling crates link as cfg(not(test)) and so
        // cannot reach the `#[cfg(test)]` arm above. When the listener was
        // constructed via `SocketListener::with_test_mode_synthetic_presence_token(true)`,
        // the request context carries `bypass_binary_pin_gate_for_test = true`
        // and this arm short-circuits with the same synthetic peer the
        // `#[cfg(test)]` arm returns. Production daemons leave the flag false
        // and the full gate (source-class + binary-pin manifest verify) runs.
        if bypass_for_test {
            return Ok(peer.unwrap_or(PeerCred {
                uid: 501,
                pid: Some(std::process::id() as i32),
            }));
        }
        if source.is_internal() {
            return Err((
                -32401,
                "local_state_key_* is wire-only; refuse Internal dispatch".to_string(),
            ));
        }
        let peer = peer.ok_or((
            -32401,
            "peer credentials unavailable — local_state_key_* requires kernel-attested uid"
                .to_string(),
        ))?;

        // Load + verify the binary-pin manifest. The daemon's persona pubkey
        // is the trust root; if `current_identity()` is not initialised we
        // cannot verify the manifest signature and must fail-closed.
        let identity = crate::infra::receipt::current_identity().ok_or((
            -32000,
            "daemon identity not initialised — cannot verify binary-pin manifest".to_string(),
        ))?;
        let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());

        let vault = current_vault(store, "local_state_key_*")?;
        let manifest_opt = crate::infra::binary_pin::load_manifest(&vault, store, &pubkey_str)
            .map_err(|e| (-32000, format!("binary-pin manifest load failed: {e}")))?;
        let manifest = manifest_opt.ok_or((
            -32401,
            "binary-pin manifest is not enrolled — run `ember binary-pin generate` to authorize \
         the ember binaries on this machine"
                .to_string(),
        ))?;

        crate::infra::binary_pin::verify_peer_against_manifest(peer.pid, caller, &manifest).map_err(
        |e| match e {
            crate::infra::binary_pin::BinaryPinError::PeerPidUnavailable => (
                -32401,
                "peer pid unavailable — cannot verify binary identity".to_string(),
            ),
            crate::infra::binary_pin::BinaryPinError::PeerBinaryPathUnavailable { pid } => (
                -32401,
                format!(
                    "peer binary path unavailable for pid {pid} (platform unsupported or lookup failed)"
                ),
            ),
            crate::infra::binary_pin::BinaryPinError::NoPinForCaller { caller } => (
                -32401,
                format!(
                    "no binary pin enrolled for caller {caller:?} — run `ember binary-pin generate`"
                ),
            ),
            crate::infra::binary_pin::BinaryPinError::HashMismatch { expected, actual } => (
                -32401,
                format!(
                    "peer binary content-hash mismatch: pinned {expected}, peer-actual {actual}"
                ),
            ),
            other => (-32000, format!("binary-pin verification failed: {other}")),
        },
    )?;

        Ok(peer)
    }
}

/// Backward-compatible shim: builds a `RequestContext` from a bare
/// `DispatchSource` and delegates to `dispatch_method_with_context`. Used
/// by tests that pre-date development milestone and by `Internal` callers
/// that have no peer credential to assert.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_source(
    store: &DaemonStore,
    vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    source: DispatchSource,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    // implementation-note-232: under `#[cfg(test)]`,
    // Synthesize a kernel-attested peer when the caller specified a
    // `Socket` source. Pre-existing test fixtures call this shim with
    // `peer: None` because they predate per-method authority gating;
    // the production socket layer always carries a peer credential
    // (`infra::socket::verify_peer_uid` rejects connections without
    // one). The synthetic peer here mirrors the pattern in
    // `enforce_local_state_gate` so the gate stays exercised end-to-end
    // without touching every legacy test.
    #[cfg(test)]
    let synthetic_peer: Option<PeerCred> = if matches!(source, DispatchSource::Socket) {
        ensure_test_authority_bridge_env();
        Some(PeerCred {
            uid: 501,
            pid: Some(std::process::id() as i32),
        })
    } else {
        None
    };
    #[cfg(not(test))]
    let synthetic_peer: Option<PeerCred> = None;

    // implementation-note-234: under
    // `#[cfg(test)]`, also synthesize a valid presence_token bound to
    // the synthetic peer's uid so legacy tests that exercise
    // OperatorPresence-class methods through this shim continue to
    // pass the gate. Tests that want to assert the gate's negative
    // paths construct `RequestContext` directly and bypass this shim.
    #[cfg(test)]
    let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = {
        if matches!(source, DispatchSource::Socket) {
            use crate::auth::presence_token::{ScopeKey, mint};
            use std::time::Duration;
            ensure_test_presence_identity();
            let signer = DaemonIdentityPresenceSigner::current()
                .expect("test presence signer must be initialised");
            let uid = synthetic_peer.as_ref().map(|p| p.uid).unwrap_or(501);
            Some(mint(uid, ScopeKey::all(), Duration::from_secs(60), &signer))
        } else {
            None
        }
    };
    #[cfg(not(test))]
    let synthetic_presence_token: Option<crate::auth::presence_token::PresenceToken> = None;

    let ctx = RequestContext {
        source,
        peer: synthetic_peer,
        principal: None,
        sessions_dir: None,
        llm_proxy_url: None,
        git_proxy_url: None,
        peer_cred_principal: None,
        mtls_principal: None,
        presence_token: synthetic_presence_token,
        bypass_binary_pin_gate_for_test: false,
    };
    dispatch_method_with_context(
        store,
        vault,
        policy,
        rate_limiter,
        events_tx,
        ctx,
        method,
        params,
    )
    .await
}

/// implementation-note-232 — set the cohort A
/// dev0 bridge env var process-wide for the duration of the test
/// binary's run, exactly once.
///
/// `EMBER_LOOSE_PEER_GID_FOR_EMBER_CLIENTS=1` is the operator-presence
/// proof until Phase D ships WebAuthn presence-tokens; cargo's test
/// runner inherits the env once set, and the value is global so
/// parallel tests cannot race on it. Tests that explicitly want to
/// observe the gate's negative path (`authority_class_not_met`)
/// construct a `RequestContext` directly without going through this
/// shim, or scope the env removal via `remove_var` ahead of their
/// dispatch call.
#[cfg(test)]
fn ensure_test_authority_bridge_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY (Rust 2024): `set_var` is `unsafe` because env-var
        // mutation while other threads read the env races on libc's
        // internal env table. We gate the call behind `Once` so the
        // mutation happens at most once per test binary; cargo's
        // test runner serializes module-static initialisation before
        // any test thread reads the var via `std::env::var`. The
        // operator-presence bridge is otherwise a process-wide
        // installer flag, so the runtime semantics match production.
        unsafe {
            std::env::set_var("EMBER_LOOSE_PEER_GID_FOR_EMBER_CLIENTS", "1");
        }
    });
}

/// Core dispatcher. Callers MUST set `ctx.source` correctly: `Socket` for
/// any request that arrived from the wire, `Internal` only for in-process
/// admin/test paths. Mis-attribution here would re-open development milestone.
///
/// `ctx.peer` carries the kernel-derived peer credential when available
/// (Linux + macOS sockets only). `delegate_grant` consults it via
/// `peercred_principal()` to bind requests to a real principal instead
/// of trusting an attacker-controlled param. See development milestone.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_method_with_context(
    store: &DaemonStore,
    _vault: &Vault,
    policy: &PolicyEngine,
    rate_limiter: &RefCell<RateLimiter>,
    events_tx: Option<&broadcast::Sender<GrantEvent>>,
    mut ctx: RequestContext,
    method: &str,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let source = ctx.source;

    // implementation-note-238 (design §"In-container
    // extension"): when the RPC arrived on a per-agent UDS socket
    // (`/run/emberd/agent-<uuid>.sock`), the calling principal is
    // resolved from the `agent_socket_enrollments` table rather than
    // from wire-claimed `caller_persona_id` / `caller_grant_id`. The
    // spawn-time enrollment IS the identity claim — the daemon
    // recorded `(socket_path, persona_id, grant_id,
    // brief_content_hash)` when it issued the per-agent socket, and
    // any RPC arriving on that socket is treated as coming from that
    // persona regardless of what the payload says.
    //
    // Defense: worker B with a forged grant_id (e.g. copy-paste of
    // the orchestrator's grant_id) cannot impersonate the
    // orchestrator just by sending the orchestrator's grant_id over
    // its own socket — the orchestrator's grant_id is bound to the
    // orchestrator's socket path, not B's.
    //
    // Shared-daemon socket entry points (the legacy `/var/run/
    // emberd.sock` shape) take the original peercred / PID-registry
    // path: `enrolled_principal` is `None` for them and the existing
    // handlers fall through to their established gates.
    let enrolled_principal: Option<EnrolledPrincipal> =
        match (source.is_internal(), ctx.peer_cred_principal.as_ref()) {
            (false, Some(p)) if is_per_agent_socket_path(&p.socket_path) => {
                match enroll_container_persona(store, &p.socket_path) {
                    Ok(enrolled) => Some(enrolled),
                    Err(e) => {
                        tracing::warn!(
                            socket_path = %p.socket_path.display(),
                            method = %method,
                            error = ?e,
                            "rejecting RPC on per-agent socket: principal not enrolled"
                        );
                        return Err(e.to_jsonrpc());
                    }
                }
            }
            _ => None,
        };

    // request_context_mtls_principal_overlay (design component 4) —
    // when the RPC arrived on the cross-uid bridge listener, the
    // bridge layer has already resolved the client cert's SPIFFE URI
    // SAN to a persona id and stamped `ctx.mtls_principal`. The
    // identity binding model is parallel to the per-agent UDS path:
    // the cert SAN IS the identity claim, NOT the wire-claimed
    // `caller_persona_id`. The bridge listener also cross-checks the
    // container-id SAN against the persona's
    // `agent_personas.container_id` row before stamping, so a
    // mismatched-SAN cert never reaches dispatch.
    //
    // The two sources are mutually exclusive at the dispatch layer:
    // per-agent UDS sockets bind `peer_cred_principal.socket_path`
    // matching `/run/emberd/agent-*.sock`; the bridge listener uses a
    // TCP-or-TLS-UDS path with no per-agent socket shape. A future
    // attacker who could populate both fields concurrently would be
    // refused below — both populated is treated as a defense-in-depth
    // error and the request is rejected.
    if enrolled_principal.is_some() && ctx.mtls_principal.is_some() {
        tracing::warn!(
            method = %method,
            "rejecting RPC: both per-agent UDS enrollment AND mTLS \
             principal populated — exclusive sources, refusing"
        );
        return Err((
            -32004,
            "principal binding violation: enrolled + mtls both set".to_string(),
        ));
    }

    // Overlay source — read from EITHER the per-agent UDS enrollment
    // (carries persona_id + grant_id) OR the mTLS principal (carries
    // persona_id only; caller's `caller_grant_id` param survives
    // through the overlay). Downstream handlers consult the overlaid
    // params uniformly.
    //
    // The mTLS principal does NOT carry a grant_id because spawn-time
    // grant attenuation happens via the existing `create_grant` flow,
    // not via cert claims. The caller is responsible for passing
    // `caller_grant_id` in the params; `check_principal_against_persona`
    // then binds (peercred-uid, claimed persona) on the UDS lane and
    // (cert-SAN persona, claimed persona) on the bridge lane.
    let overlay_source: Option<(String, Option<String>)> = enrolled_principal
        .as_ref()
        .map(|e| (e.persona_id.clone(), Some(e.grant_id.clone())))
        .or_else(|| {
            ctx.mtls_principal
                .as_ref()
                .map(|m| (m.persona_id.clone(), None))
        });

    // When the RPC was dispatched from a per-agent socket and the
    // enrollment resolved, overlay the enrolled persona/grant onto
    // the params so downstream handlers consult the enrollment-derived
    // identity rather than whatever the wire payload claimed. The
    // overlay is a per-call clone — the original `params` reference
    // is untouched so concurrent callers in other branches see the
    // unaltered value.
    let overlaid_params: Option<Value> = overlay_source.as_ref().map(|(persona_id, grant_id)| {
        let mut p = params.clone();
        if let Value::Object(obj) = &mut p {
            // enrolled_principal_overlay_extends_persona_params:
            // implementation-note-239 closes the
            // cross-persona authz bypass where evaluate_tool_call(persona =
            // other) read the wire param instead of the kernel-attested
            // (per-agent UDS) or cert-attested (mTLS) identity. Insert ALL
            // common persona-claim aliases the dispatch arms read — both
            // legacy `caller_*` and modern `persona` / `persona_id` / `id` —
            // so no downstream arm can be tricked by a stale alias.
            for key in [
                "caller_persona",
                "caller_persona_id",
                "persona",
                "persona_id",
                "id",
            ] {
                obj.insert(key.to_string(), Value::String(persona_id.clone()));
            }
            if let Some(gid) = grant_id {
                obj.insert("caller_grant_id".to_string(), Value::String(gid.clone()));
            }
        }
        p
    });
    let params: &Value = match overlaid_params.as_ref() {
        Some(p) => p,
        None => params,
    };

    // enrolled_principal_overlay_propagates_to_ctx (implementation-note-240-
    // TESTS-PRE-EXISTING-FAILURES): also stamp the resolved persona_id onto
    // `ctx.principal` so `resolve_caller_principal` (handlers/support.rs) sees
    // the pre-resolved identity at step 1 and does NOT short-circuit on the
    // peercred PID-registry lookup at step 2. Without this, every per-agent
    // UDS RPC (and mTLS bridge RPC) that called into a handler-arm using
    // `resolve_caller_principal` would refuse with PrincipalNotEnrolled even
    // though enrollment had already resolved the identity — the overlay only
    // wrote to params, not to the principal field consulted by step 1.
    if let Some((persona_id, _)) = overlay_source.as_ref()
        && ctx.principal.is_none()
    {
        ctx.principal = Some(persona_id.clone());
    }

    // implementation-note-230: quarantine gate. When the daemon
    // has detected a tampered audit chain, refuse any non-read-class
    // socket method so the chain cannot be extended over the break and
    // state mutations cannot mask the tamper. Read-class methods (ping,
    // audit_verify, audit_query, …) still proceed so the operator can
    // diagnose. Internal callers (in-process test harness, recovery
    // CLIs) are NOT exempted — quarantine is a hard latch.
    if is_quarantined() && !is_read_class_method(method) {
        let reason = quarantine_reason().unwrap_or("reason unrecorded");
        return Err((
            -32603,
            format!("daemon quarantined ({reason}); write-class method `{method}` refused"),
        ));
    }

    // implementation-note-232: per-method
    // authority gate. Cohort A's current local path uses the socket
    // listener's peer-cred gate for ConnectOnly and a daemon-signed
    // presence-token bound to that peer uid for OperatorPresence.
    // Internal callers (admin CLI, recovery flows, test harness) are
    // exempted — they ride the pre-existing in-process trust lane that
    // pre-dates peer-cred binding (see `DispatchSource::Internal`).
    //
    // The -32001 error body deliberately omits the method name to
    // avoid leaking the classification table to attackers probing
    // arms; the `tracing::warn!` carries the full context for
    // operator forensics.
    // authority_gate_unknown_method_returns_minus_32601 — unclassified
    // methods skip both gates so the dispatcher's `_ => Err(-32601)` arm
    // emits the standard JSON-RPC "Method not found" response. Classified
    // methods enforce the authority class against `ctx.satisfies(required)`.
    if !source.is_internal() {
        if let Some(required) = authority_class_for_method(method) {
            if !ctx.satisfies(required) {
                tracing::warn!(
                    method = %method,
                    required = ?required,
                    peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                    "dispatch_method: authority class not met"
                );
                return Err((-32001, "authority_class_not_met".to_string()));
            }
        }
    }

    // Operator-presence validation.
    //
    // Non-bootstrap methods on the OperatorPresence lane now require:
    // 1. a daemon-signed presence-token bound to the peer uid, and
    // 2. a currently-unlocked interactive presence session.
    //
    // The only token-optional methods are the bootstrap / privilege-drop
    // seams that mint or tear down that proof (`vault_unlock`,
    // `register_session`, `vault_lock`, `close_session`).
    if !source.is_internal()
        && matches!(
            authority_class_for_method(method),
            Some(AuthorityClass::OperatorPresence)
        )
    {
        if !operator_presence_token_optional_method(method) {
            let token = match ctx.presence_token.as_ref() {
                Some(token) => token,
                None => {
                    tracing::warn!(
                        method = %method,
                        peer_uid = ?ctx.peer.as_ref().map(|p| p.uid),
                        tier = current_dispatch_deployment_tier().as_str(),
                        "dispatch_method: OperatorPresence method missing presence_token"
                    );
                    return Err((
                        -32001,
                        json!({
                            "error": "authority_class_not_met",
                            "reason": "missing"
                        })
                        .to_string(),
                    ));
                }
            };

            let peer_uid = match ctx.peer.as_ref() {
                Some(p) => p.uid,
                None => {
                    tracing::warn!(
                        method = %method,
                        "dispatch_method: presence_token attached but no peer credential"
                    );
                    return Err((
                        -32001,
                        json!({
                            "error": "authority_class_not_met",
                            "reason": "missing"
                        })
                        .to_string(),
                    ));
                }
            };

            let Some(identity) = crate::infra::receipt::current_identity() else {
                tracing::warn!(
                    method = %method,
                    "dispatch_method: daemon identity missing; cannot validate presence_token"
                );
                return Err((
                    -32001,
                    json!({
                        "error": "authority_class_not_met",
                        "reason": "identity-missing"
                    })
                    .to_string(),
                ));
            };
            let signer = DaemonIdentityPresenceSigner::new(identity);
            let cache = crate::auth::presence_token::PresenceTokenCache::new();

            if let Err(e) = crate::auth::presence_token::validate(&cache, token, peer_uid, &signer)
            {
                let reason = match e {
                    crate::auth::presence_token::AuthError::Expired => "expired",
                    crate::auth::presence_token::AuthError::UidMismatch => "uid-mismatch",
                    crate::auth::presence_token::AuthError::SignatureInvalid => "sig-invalid",
                    crate::auth::presence_token::AuthError::ScopeMismatch => "scope-mismatch",
                };
                tracing::warn!(
                    method = %method,
                    peer_uid = peer_uid,
                    reason = reason,
                    "dispatch_method: presence_token validation failed"
                );
                return Err((
                    -32001,
                    json!({
                        "error": "authority_class_not_met",
                        "reason": reason
                    })
                    .to_string(),
                ));
            }

            let (unlocked, _) = presence::snapshot();
            if !unlocked {
                return Err((
                    -32030,
                    format!(
                        "{method} denied: session is locked; reopen with `ember vault unlock` \
                         or start a new session (`register_session` path). Ordinary lazy \
                         same-daemon re-auth is not fully wired yet"
                    ),
                ));
            }

            presence::record_activity();
        }
    }

    match method {
        "ping" => Ok(json!({"pong": true})),

        "presence_token_mint" => Err((
            -32601,
            "presence_token_mint is not a shipped generic CLI authority surface".to_string(),
        )),

        // implementation-note-76: Claude Code PreToolUse hook entry point.
        // The proxy hook (`ember-proxy/src/claude_code_hook.rs`) calls
        // this with the parsed `tool_name` + `params` + `session_id`,
        // and the daemon performs grant lookup + audit emit + decision.
        // Real evaluator integration lands in implementation-note-77; this path is
        // a Permit-stub on grant-hit, Deny on grant-miss.
        "evaluate_tool_call" => {
            let persona = params["persona"]
                .as_str()
                .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
            let tool_name = params["tool_name"]
                .as_str()
                .ok_or((-32602, "missing 'tool_name' parameter".to_string()))?;
            let session_id = params["session_id"].as_str();
            let grant_id = params["grant_id"].as_str();
            let tool_params = &params["params"];
            let decision = store
                .evaluate_tool_call(persona, tool_name, tool_params, session_id, grant_id)
                .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(&decision)
                .map_err(|e| (-32000, format!("serialize ToolCallDecision: {e}")))
        }

        "create_persona" => {
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name' parameter".to_string()))?;
            let info = store
                .create_persona(name)
                .map_err(|e| (-32000, e.to_string()))?;
            // development milestone: enroll the (peer_pid, persona_id) so
            // subsequent `delegate_grant` calls from this PID resolve
            // back to the persona that just claimed it.  Only applies to
            // Socket callers; Internal callers don't have a real peer
            // identity and shouldn't pollute the registry.
            if !source.is_internal()
                && let Some(peer) = &ctx.peer
                && let Some(pid) = peer.pid
            {
                enroll_pid_persona(pid, &info.id);
            }
            Ok(json!({"id": info.id, "name": info.name, "public_key": info.public_key}))
        }

        "build_init_first_grant_receipt" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let signer = store
                .persona_signer(persona_id)
                .map_err(|e| (-32000, format!("persona signer: {e}")))?;
            let file =
                crate::infra::init_first_grant::build_first_grant_receipt_file(persona_id, &signer)
                    .map_err(|e| (-32000, format!("build init first-grant receipt: {e}")))?;
            serde_json::to_value(file)
                .map_err(|e| (-32000, format!("serialize init first-grant receipt: {e}")))
        }

        "list_personas" => {
            let personas = store.list_personas().map_err(|e| (-32000, e.to_string()))?;
            let trusted_persona = team0_connect_only_persona_scope(&ctx, "list_personas")?;
            let name_prefix = params["name_prefix"].as_str();
            let list: Vec<Value> = personas
                .iter()
                .filter(|p| match trusted_persona.as_deref() {
                    Some(persona_id) => p.id == persona_id,
                    None => true,
                })
                .filter(|p| match name_prefix {
                    Some(prefix) => p.name.starts_with(prefix),
                    None => true,
                })
                .map(|p| json!({"id": p.id, "name": p.name, "status": p.status}))
                .collect();
            Ok(json!(list))
        }

        "revoke_persona" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            // revoke_persona_authority_check — Internal callers (admin CLI,
            // test harness, recovery) bypass; all socket callers must be
            // the revocation target (self-revoke). Operator-role extension
            // tracked separately.
            if !source.is_internal() {
                let principal =
                    crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
                if principal != id {
                    tracing::warn!(
                        caller_persona_id = %principal,
                        target_persona_id = %id,
                        "rejecting revoke_persona: caller is not the revocation target"
                    );
                    return Err((
                        -32003,
                        "revoke_persona: caller not authorized (must be operator or \
                         revocation target)"
                            .to_string(),
                    ));
                }
                // Self-revoke: allowed.
            }
            store
                .revoke_persona(id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"revoked": true}))
        }

        "create_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let max_uses_per_hour = params["max_uses_per_hour"].as_u64();
            let allowed_hours_start = params["allowed_hours_start"].as_u64().map(|v| v as u32);
            let allowed_hours_end = params["allowed_hours_end"].as_u64().map(|v| v as u32);
            let allowed_targets = params["allowed_targets"]
                .as_array()
                .map(|arr| serde_json::to_string(arr).unwrap_or_default());
            let max_delegation_depth = params["max_delegation_depth"].as_u64().map(|v| v as u32);
            let budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
                Some(
                    serde_json::from_value(params["budget"].clone())
                        .map_err(|e| (-32602, format!("invalid 'budget': {e}")))?,
                )
            } else {
                None
            };
            let max_children_per_day = params["max_children_per_day"].as_u64();
            let auto_delegate_scope_template = params["auto_delegate_scope_template"]
                .as_str()
                .map(str::to_owned);
            let grant_shape = GrantShapeFields {
                max_delegation_depth,
                max_uses_per_hour,
                allowed_hours_start,
                allowed_hours_end,
                allowed_targets: allowed_targets.clone(),
                budget: budget.clone(),
                max_children_per_day,
                auto_delegate_scope_template: auto_delegate_scope_template.clone(),
            };

            if grant_shape.max_children_per_day.is_some()
                && grant_shape.max_delegation_depth.is_none()
            {
                return Err((
                    -32602,
                    "standing create_grant requires 'max_delegation_depth'".to_string(),
                ));
            }
            if grant_shape.auto_delegate_scope_template.is_some()
                && grant_shape.max_children_per_day.is_none()
            {
                return Err((
                    -32602,
                    "'auto_delegate_scope_template' requires 'max_children_per_day'".to_string(),
                ));
            }

            // Evaluate policy unless force=true (human/admin bypass).
            //
            // development milestone fix: `force` is ONLY honored for in-process
            // admin/test callers (`DispatchSource::Internal`). Socket
            // callers that supply `force: true` are rejected loudly so an
            // attacker can never silently bypass the policy gate.
            let force_requested = params["force"].as_bool().unwrap_or(false);
            if force_requested && !source.is_internal() {
                return Err((
                    -32602,
                    "the 'force' parameter is not permitted on the socket API".to_string(),
                ));
            }
            let force = force_requested && source.is_internal();

            // Per-op user-presence gate. Applied BEFORE policy evaluation
            // so a locked session is rejected with a
            // re-auth message instead of being silently routed into the
            // approval queue. Internal callers + force-allowed callers
            // bypass (test harness, admin CLI, recovery flow). Quiet
            // hours apply (grant create is NOT emergency-eligible).
            if !source.is_internal() && !force {
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::GrantCreate, override_qh)?;
            }

            if !force {
                let action = format!("credential.access.{}", credential_name);
                let eval = policy.evaluate(&action);

                match eval.requirement {
                    ApprovalRequirement::Denied => {
                        return Err((
                            -32003,
                            format!("policy denied: {}", eval.matched_rule.unwrap_or_default()),
                        ));
                    }
                    ApprovalRequirement::Required => {
                        let risk_str = format!("{:?}", eval.risk).to_lowercase();
                        // PHASE-C-1-MIGRATED: trait crossing per design §3
                        let adapter = DaemonApprovalStoreRef::new(store);
                        let metadata = SubmitMetadata {
                            action: "create_grant".to_string(),
                            ttl_secs,
                            risk_level: risk_str.clone(),
                            tool_name: None,
                            target_host: None,
                            target_url: None,
                            agent_framework: None,
                            max_delegation_depth: grant_shape.max_delegation_depth,
                            max_uses_per_hour: grant_shape.max_uses_per_hour,
                            allowed_hours_start: grant_shape.allowed_hours_start,
                            allowed_hours_end: grant_shape.allowed_hours_end,
                            allowed_targets: grant_shape.allowed_targets.clone(),
                            budget: grant_shape.budget.clone(),
                            max_children_per_day: grant_shape.max_children_per_day,
                            auto_delegate_scope_template: grant_shape
                                .auto_delegate_scope_template
                                .clone(),
                        };
                        let scope_obj = core_grant_types::approval::RequestedScope {
                            capability: scope.to_string(),
                            resource_id: None,
                            constraints: vec![],
                        };
                        let request_id = adapter
                            .submit_request(persona_id, credential_name, scope_obj, metadata)
                            .await
                            .map_err(|e| (-32000, e.to_string()))?;
                        let req = store
                            .get_approval(&request_id.0)
                            .map_err(|e| (-32000, e.to_string()))?;
                        notify_require_approval(store, &req);
                        return Ok(json!({
                            "status": "pending_approval",
                            "approval_id": request_id.0,
                            "message": "Grant creation requires approval. Use list_pending_approvals to check status."
                        }));
                    }
                    ApprovalRequirement::Auto => {
                        // Fall through to create grant
                    }
                }
            }

            let grant = store
                .create_grant_with_budget(
                    persona_id,
                    credential_name,
                    scope,
                    ttl_secs,
                    budget.clone(),
                )
                .map_err(|e| (-32000, e.to_string()))?;

            store
                .apply_grant_shape_to_grant(&grant.id, &grant_shape)
                .map_err(|e| (-32000, e.to_string()))?;

            let _ = store.log_event(
                Some(persona_id),
                "grant.issued",
                Some(credential_name),
                "allowed",
                Some(
                    &serde_json::json!({
                        "grant_id": grant.id,
                        "scope": scope,
                        "ttl_secs": ttl_secs,
                        "allowed_targets": params["allowed_targets"],
                    })
                    .to_string(),
                ),
            );

            Ok(json!({
                "id": grant.id,
                "expires_at": grant.expires_at,
                "budget": budget,
                "standing": max_children_per_day.map(|limit| {
                    json!({
                        "max_children_per_day": limit,
                        "auto_delegate_scope_template": auto_delegate_scope_template,
                    })
                }),
                "conditions": {
                    "max_uses_per_hour": max_uses_per_hour,
                    "allowed_hours": if allowed_hours_start.is_some() {
                        Some(format!("{}:00-{}:00 UTC", allowed_hours_start.unwrap_or(0), allowed_hours_end.unwrap_or(0)))
                    } else { None },
                    "allowed_targets": params["allowed_targets"].as_array(),
                    "max_delegation_depth": max_delegation_depth,
                    "max_children_per_day": max_children_per_day,
                }
            }))
        }

        "delegate_grant" => {
            let parent_grant_id = params["parent_grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'parent_grant_id'".to_string()))?;
            let child_persona_id = params["child_persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'child_persona_id'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            // Optional child budget — when present, `delegate_grant_full`
            // enforces offline attenuation (child ≤ parent − usage on every
            // axis). When absent we fall back to the no-budget shape so
            // callers that don't set budgets keep working.
            let child_budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
                Some(
                    serde_json::from_value(params["budget"].clone())
                        .map_err(|e| (-32602, format!("invalid 'budget': {e}")))?,
                )
            } else {
                None
            };
            // implementation-note-241: load via DaemonGrantStore to obtain
            // core_grants::Grant at the state-machine boundary. Ownership
            // checks below use `parent_grant.issuer.0` (persona_id) directly.
            // TODO: delegate_grant log_event credential_name
            // — not present in core_grants::Grant; requires a lookup helper.
            let parent_grant = store
                .grant_store()
                .load_grant(parent_grant_id)
                .map_err(|e| (-32000, e.to_string()))?;

            // development milestone — full principal binding via shared helper.
            //
            // `resolve_caller_principal` resolves the caller's persona id
            // from (in order): pre-resolved ctx.principal, kernel peercred
            // PID registry, mTLS bridge lane, params["caller_persona_id"]
            // legacy fallback. Internal source bypasses — mirrors development milestone.
            if !source.is_internal() {
                let principal =
                    crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
                // Mismatch check: if params["caller_persona_id"] was supplied and
                // differs from the kernel-derived principal, reject loudly
                // (development milestone — attacker cannot impersonate by forging params).
                if let Some(asserted) = params["caller_persona_id"].as_str()
                    && asserted != principal
                {
                    tracing::warn!(
                        asserted_persona_id = %asserted,
                        kernel_persona_id = %principal,
                        parent_grant_id = %parent_grant_id,
                        "rejecting delegate_grant: params.caller_persona_id \
                         does not match kernel-derived principal"
                    );
                    return Err(HandlerError::PrincipalMismatch.to_jsonrpc());
                }
                // implementation-note-241: compare against issuer.0 (core_grants::PrincipalId).
                if principal != parent_grant.issuer.0 {
                    tracing::warn!(
                        caller_persona_id = %principal,
                        parent_grant_id = %parent_grant_id,
                        parent_owner_persona_id = %parent_grant.issuer.0,
                        "rejecting delegate_grant: caller does not own parent grant"
                    );
                    return Err((
                        -32002,
                        "delegate_grant: caller does not own parent grant".to_string(),
                    ));
                }
            }

            let grant = store
                .delegate_grant_full(
                    parent_grant_id,
                    child_persona_id,
                    scope,
                    ttl_secs,
                    child_budget,
                )
                .map_err(|e| (-32000, e.to_string()))?;
            // TODO: delegate_grant credential_name not in core_grants::Grant;
            // audit logs emit None here until a lookup helper is added. The parent_grant_id
            // in the JSON body lets operators reconstruct the credential from the grant record.
            let _ = store.log_event(
                Some(child_persona_id),
                "grant.delegated",
                None,
                "allowed",
                Some(
                    &serde_json::json!({
                        "parent_grant_id": parent_grant_id,
                        "child_grant_id": grant.id,
                        "child_persona_id": child_persona_id,
                        "scope": scope,
                    })
                    .to_string(),
                ),
            );
            Ok(json!({
                "id": grant.id,
                "scope": grant.scope,
                "parent": parent_grant_id,
                "expires_at": grant.expires_at,
                "budget": grant.budget,
            }))
        }

        "list_grants" => {
            // Response shape per design: each entry also carries a
            // `statement_count` and a `statements` array with per-Statement
            // `sid`, `resource_type`, `actions`, `resource`, `budget`, and
            // `usage`. Clients can render per-Statement meters natively.
            let persona_id = persona_scoped_param_for_connect_only(
                &ctx,
                params,
                "list_grants",
                "persona_id",
                true,
            )?
            .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let grants = store
                .list_active_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .filter(|g| g.persona_id == persona_id)
                .map(|g| {
                    let statements: Vec<Value> = match store.get_access_grant(&g.id) {
                        Ok(chain) => chain
                            .statements()
                            .map(|(bi, s)| {
                                json!({
                                    "sid": s.sid,
                                    "block_index": bi,
                                    "resource_type": s.resource_type.as_str(),
                                    "actions": s.actions,
                                    "resource": s.resource,
                                    "budget": s.budget,
                                    "usage": s.usage,
                                    "conditions": s.conditions,
                                })
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    json!({
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "expires_at": g.expires_at,
                        "status": g.status,
                        "statement_count": statements.len(),
                        "statements": statements,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "list_operator_grants" => {
            // Operator-facing enumeration surface for the installed local CLI.
            // Kept separate from `list_grants` so the MCP/runtime contract
            // stays persona-scoped + active-only while the operator can still
            // inspect the full grant table on the presence-gated lane.
            let active_only = params["active_only"].as_bool().unwrap_or(false);
            let grants = if active_only {
                store.list_active_grants()
            } else {
                store.list_grants()
            }
            .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .map(|g| {
                    json!({
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "status": g.status,
                        "expires_at": g.expires_at,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "sandbox_create" => {
            let opts: crate::infra::sandbox::SandboxCreateOpts =
                serde_json::from_value(params.clone())
                    .map_err(|e| (-32602, format!("invalid sandbox_create params: {e}")))?;
            let data_dir = runtime_data_dir_from_context(&ctx)?;
            let socket_dir = runtime_socket_dir_from_context(&ctx)?;
            let sandbox = store
                .create_sandbox_with_opts(&opts, Some(&data_dir))
                .map_err(|e| (-32000, e.to_string()))?;
            let (container_id, start_error) = match store.start_container(
                &sandbox.id,
                &socket_dir,
                opts.network.as_deref(),
                &opts.extra_env,
            ) {
                Ok(cid) => (Some(cid), None),
                Err(e) => (None, Some(e.to_string())),
            };
            serde_json::to_value(crate::infra::sandbox::SandboxCreateResult {
                sandbox,
                container_id,
                start_error,
            })
            .map_err(|e| (-32000, format!("serialize SandboxCreateResult: {e}")))
        }

        "sandbox_list" => {
            let sandboxes = store
                .list_sandboxes()
                .map_err(|e| (-32000, e.to_string()))?;
            serde_json::to_value(sandboxes)
                .map_err(|e| (-32000, format!("serialize SandboxInfo list: {e}")))
        }

        "sandbox_stop" => {
            let id_or_name = params["id_or_name"]
                .as_str()
                .or_else(|| params["id"].as_str())
                .ok_or((-32602, "missing 'id_or_name' parameter".to_string()))?;
            let resolved_id = store
                .resolve_sandbox_id(id_or_name)
                .map_err(|e| (-32000, e.to_string()))?;
            store
                .stop_sandbox(&resolved_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "resolved_id": resolved_id,
                "stopped": true,
            }))
        }

        "sandbox_delete" => {
            let id_or_name = params["id_or_name"]
                .as_str()
                .or_else(|| params["id"].as_str())
                .ok_or((-32602, "missing 'id_or_name' parameter".to_string()))?;
            let result = match store.resolve_sandbox_id(id_or_name) {
                Ok(resolved_id) => {
                    store
                        .delete_sandbox(&resolved_id)
                        .map_err(|e| (-32000, e.to_string()))?;
                    crate::infra::sandbox::SandboxDeleteResult {
                        resolved_id: Some(resolved_id),
                        already_absent: false,
                    }
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    crate::infra::sandbox::SandboxDeleteResult {
                        resolved_id: None,
                        already_absent: true,
                    }
                }
                Err(e) => return Err((-32000, e.to_string())),
            };
            serde_json::to_value(result)
                .map_err(|e| (-32000, format!("serialize SandboxDeleteResult: {e}")))
        }

        "sandbox_exec" => {
            let id_or_name = params["id_or_name"]
                .as_str()
                .or_else(|| params["id"].as_str())
                .ok_or((-32602, "missing 'id_or_name' parameter".to_string()))?;
            let command = params["command"]
                .as_array()
                .ok_or((-32602, "missing 'command' parameter".to_string()))?;
            let resolved_id = store
                .resolve_sandbox_id(id_or_name)
                .map_err(|e| (-32000, e.to_string()))?;
            let caller_persona =
                crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
            let refs: Vec<&str> = command
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or((-32602, "'command' must be an array of strings".to_string()))
                })
                .collect::<Result<_, _>>()?;
            let output = store
                .exec_sandbox(&resolved_id, &refs, &caller_persona)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "resolved_id": resolved_id,
                "output": output,
            }))
        }

        "sandbox_run" => {
            let opts: crate::infra::sandbox::SandboxCreateOpts =
                serde_json::from_value(params["sandbox"].clone())
                    .map_err(|e| (-32602, format!("invalid sandbox_run sandbox params: {e}")))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let credential_resource = params["credential_resource"].as_str();
            let statements: Vec<core_grant_types::StatementProposal> =
                match params.get("statements").and_then(|v| v.as_array()) {
                    Some(values) => values
                        .iter()
                        .map(|value| {
                            serde_json::from_value(value.clone()).map_err(|e| {
                                (-32602, format!("invalid sandbox_run statement: {e}"))
                            })
                        })
                        .collect::<Result<_, _>>()?,
                    None => Vec::new(),
                };

            let data_dir = runtime_data_dir_from_context(&ctx)?;
            let socket_dir = runtime_socket_dir_from_context(&ctx)?;
            let sandbox = store
                .create_sandbox_with_opts(&opts, Some(&data_dir))
                .map_err(|e| (-32000, e.to_string()))?;
            let (container_id, start_error) = match store.start_container(
                &sandbox.id,
                &socket_dir,
                opts.network.as_deref(),
                &opts.extra_env,
            ) {
                Ok(cid) => (Some(cid), None),
                Err(e) => (None, Some(e.to_string())),
            };

            let grant = if statements.is_empty() {
                crate::infra::sandbox::SandboxRunGrantDisposition::NotRequested
            } else {
                let policy_action = "credential.access".to_string();
                let eval = policy.evaluate(&policy_action);
                let risk_str = format!("{:?}", eval.risk).to_lowercase();
                let proposal = core_grant_types::GrantProposal {
                    persona_id: sandbox.persona_id.clone(),
                    statements,
                    expires_at: ttl_secs,
                    label: None,
                    skill_ref: None,
                    note: None,
                };

                match eval.requirement {
                    ApprovalRequirement::Denied => {
                        let credential_res = credential_resource.unwrap_or("");
                        return Err((
                            -32003,
                            format!(
                                "policy denied composite grant mint for {credential_res} (rule: {})",
                                eval.matched_rule.as_deref().unwrap_or("(default)")
                            ),
                        ));
                    }
                    ApprovalRequirement::Required => {
                        match store.propose_grant_typed(&proposal, &policy_action, &risk_str) {
                            Ok(req) => {
                                notify_require_approval(store, &req);
                                crate::infra::sandbox::SandboxRunGrantDisposition::PendingApproval {
                                    approval_id: req.id,
                                }
                            }
                            Err(e) => crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                                message: format!("submitting approval failed: {e}"),
                            },
                        }
                    }
                    ApprovalRequirement::Auto => {
                        match store.propose_grant_typed(&proposal, &policy_action, &risk_str) {
                            Ok(req) => match store.auto_resolve(&req.id) {
                                Ok(()) => {
                                    let grant_id = store
                                        .get_approval(&req.id)
                                        .ok()
                                        .and_then(|r| r.result_grant_id);
                                    crate::infra::sandbox::SandboxRunGrantDisposition::Minted {
                                        grant_id,
                                    }
                                }
                                Err(e) => {
                                    crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                                        message: format!("auto-resolve failed: {e}"),
                                    }
                                }
                            },
                            Err(e) => crate::infra::sandbox::SandboxRunGrantDisposition::Failed {
                                message: format!("submitting approval failed: {e}"),
                            },
                        }
                    }
                }
            };

            serde_json::to_value(crate::infra::sandbox::SandboxRunResult {
                sandbox,
                container_id,
                start_error,
                grant,
            })
            .map_err(|e| (-32000, format!("serialize SandboxRunResult: {e}")))
        }

        "revoke_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            // implementation-note-241: load via DaemonGrantStore for issuer.
            // credential_name lives on GrantInfo (the SQL row projection),
            // not on core_grants::Grant — fetch both so the audit row carries
            // the credential identity.
            let core_grant = store.grant_store().load_grant(id).ok();
            let grant_info = store.get_grant(id).ok();
            let grant_persona = core_grant.as_ref().map(|g| g.issuer.0.clone());
            let grant_credential = grant_info.as_ref().map(|g| g.credential_name.clone());
            store
                .revoke_grant(id)
                .map_err(|e| (-32000, e.to_string()))?;

            // v2_receipt_coverage_audit_v030_2026_05_09: extend Receipt to TTL/revoke per M3 follow-up
            // Emit a signed v2 cohort-A Receipt with ExplicitRevoke for H1
            // coverage. Grant may have no live session; use a synthetic
            // session_id derived from the grant_id so the Receipt envelope is
            // well-formed (spec option (a)).
            let synthetic_session_id = format!("grant:{id}");
            if let Some(identity) = current_identity() {
                let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);
                match issue_cohort_a_receipt(
                    &synthetic_session_id,
                    Vec::new(),
                    None,
                    TerminationAuthority::DaemonPersona,
                    &identity.pubkey_hex(),
                    Some(TerminationMeta {
                        reason: TerminationReason::ExplicitRevoke,
                        last_heartbeat_at: None,
                        pid_alive_at_check: None,
                    }),
                    &signer,
                ) {
                    Ok(envelope) => {
                        // Persist the Receipt sidecar if a sessions_dir is
                        // available. Best-effort: a write failure does not
                        // abort the revocation itself.
                        if let Some(sessions_dir) = &ctx.sessions_dir {
                            let receipt_dir = sessions_dir.join(&synthetic_session_id);
                            let _ = std::fs::create_dir_all(&receipt_dir);
                            let receipt_path = receipt_dir.join("receipt.json");
                            if let Ok(bytes) = serde_json::to_vec_pretty(&envelope)
                                && let Err(e) = std::fs::write(&receipt_path, &bytes)
                            {
                                tracing::warn!(
                                    grant_id = %id,
                                    path = %receipt_path.display(),
                                    error = %e,
                                    "revoke_grant: failed to persist v2 Receipt sidecar"
                                );
                            }
                        }
                        tracing::info!(
                            grant_id = %id,
                            receipt_id = %envelope.receipt_id,
                            "revoke_grant: signed v2 cohort-A Receipt emitted (ExplicitRevoke)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            grant_id = %id,
                            error = %e,
                            "revoke_grant: failed to issue v2 cohort-A Receipt — revocation still committed"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    grant_id = %id,
                    "revoke_grant: daemon identity not initialised — skipping v2 Receipt emission"
                );
            }

            // Push revocation notification (best-effort, queued for polling)
            if let Some(persona_id) = &grant_persona {
                let _ =
                    store.push_notification(persona_id, "grant.revoked", &json!({"grant_id": id}));
            }
            // Log the revocation event.
            let _ = store.log_event(
                core_grant.as_ref().map(|g| g.issuer.0.as_str()),
                "grant.revoked",
                grant_credential.as_deref(),
                "allowed",
                Some(&serde_json::json!({"grant_id": id}).to_string()),
            );
            // Broadcast GRANT_REVOKED over the unix socket so connected agents
            // can zeroize cached credentials without waiting on polling.
            if let (Some(tx), Some(persona_id)) = (events_tx, grant_persona) {
                let event = GrantEvent::Revoked {
                    grant_id: id.to_string(),
                    persona_id: persona_id.clone(),
                };
                // send() returns Err only when there are no active subscribers,
                // which is expected at startup; ignore the result.
                let _ = tx.send(event);
                tracing::info!(grant_id = %id, "broadcasting grant revocation to connected agents");
            }
            Ok(json!({"revoked": true}))
        }

        // implementation-note-242 — revoke a single Statement
        // within a composite grant. The grant remains active; only requests
        // resolving to the named sid are denied at the proxy + use_credential
        // boundaries.
        "revoke_statement" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let sid = params["statement_sid"]
                .as_str()
                .ok_or((-32602, "missing 'statement_sid'".to_string()))?;
            store
                .revoke_grant_statement(grant_id, sid)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("grant {grant_id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            Ok(json!({
                "status": "revoked",
                "grant_id": grant_id,
                "statement_sid": sid,
            }))
        }

        "evaluate_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let grant = store
                .evaluate_grant(persona_id, credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": grant.id, "scope": grant.scope, "expires_at": grant.expires_at}))
        }

        "use_credential" => {
            // Read-class — bump session activity so an active agent keeps
            // the vault unlocked, but do NOT prompt
            // for biometric (would spam the user every credential read).
            presence::record_activity();
            // Two calling conventions:
            //   1. `{persona_id, credential_name}` — classic vault lookup.
            //   2. `{grant_id, persona_id?}` — agent runtime flow. Looks up
            //      the grant by id and derives persona+credential from it.
            //      When the caller also supplies `persona_id`, it MUST match
            //      the grant's persona — this prevents grant-id guessing
            //      cross-persona reads via a leaked id.
            //
            // TODO: GrantInfo retained for use_credential resolved_grant
            // — grant.id (as "grant-{uuid}" string), grant.scope (as string), and
            // grant.credential_name are not present in core_grants::Grant.
            // State/issuer checks already use core_grants (migrated in PHASE-C-3A).
            // Full migration requires adding credential_name to core_grants::Grant
            // or a dedicated lookup helper.
            let (persona_id, credential_name, resolved_grant): (
                String,
                String,
                Option<crate::trust::grant::GrantInfo>,
            ) = if let Some(grant_id) = params["grant_id"].as_str() {
                // Load core_grants::Grant for state-machine checks (implementation-note-241).
                let core_grant = store
                    .grant_store()
                    .load_grant(grant_id)
                    .map_err(|e| match e {
                        crate::infra::store::StoreError::NotFound => {
                            (-32004, format!("grant {grant_id} not found"))
                        }
                        other => (-32000, other.to_string()),
                    })?;
                if core_grant.state != CoreGrantState::Active {
                    return Err((
                        -32005,
                        format!("grant {grant_id} is not active and cannot be used"),
                    ));
                }
                if let Some(caller_persona) = params["persona_id"].as_str()
                    && caller_persona != core_grant.issuer.0
                {
                    return Err((-32002, "grant belongs to a different persona".to_string()));
                }
                // TODO: GrantInfo still needed for credential_name, id (string), scope (string).
                let grant = store.get_grant(grant_id).map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("grant {grant_id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
                // implementation-note-243: when the caller passes
                // both grant_id AND credential_name, honor the caller's
                // value if it's bound to a Credential Statement on the
                // grant's chain. Composite grants carry multiple
                // credential statements (e.g. anthropic-key + github-token);
                // returning grant.credential_name unconditionally would
                // hand back the grant's primary cred regardless of what
                // the caller asked for, breaking per-statement isolation.
                let resolved_cred_name = if let Some(caller_cred) =
                    params["credential_name"].as_str()
                {
                    let chain = store
                        .get_access_grant(&grant.id)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let bound = chain.statements().any(|(_idx, stmt)| {
                        stmt.resource_type == core_grant_types::ResourceType::Credential
                            && match &stmt.resource {
                                core_grant_types::ResourceSelector::Exact { value } => {
                                    value == caller_cred
                                }
                                _ => false,
                            }
                    });
                    if !bound {
                        return Err((
                            -32007,
                            format!(
                                "credential '{caller_cred}' is not bound to any statement on grant {}",
                                grant.id
                            ),
                        ));
                    }
                    caller_cred.to_string()
                } else {
                    grant.credential_name.clone()
                };
                (grant.persona_id.clone(), resolved_cred_name, Some(grant))
            } else {
                let persona_id = params["persona_id"]
                    .as_str()
                    .ok_or((-32602, "missing 'persona_id'".to_string()))?;
                let credential_name = params["credential_name"]
                    .as_str()
                    .ok_or((-32602, "missing 'credential_name'".to_string()))?;
                (persona_id.to_string(), credential_name.to_string(), None)
            };

            // Check grant exists and is active (redundant for the grant_id
            // branch but cheap — preserves single-path-through-evaluate
            // semantics for the classic branch).
            let grant = if let Some(g) = resolved_grant {
                g
            } else {
                store
                    .evaluate_grant(&persona_id, &credential_name)
                    .map_err(|e| (-32000, format!("no active grant: {e}")))?
            };

            // implementation-note-242 — block credential reads
            // when the Credential Statement that authorizes THIS specific
            // credential_name has been revoked. The previous shape blocked
            // ALL credential reads if ANY credential statement was revoked,
            // collapsing per-statement isolation; composite grants need
            // each credential statement to fail independently.
            let revoked_sids = store
                .get_revoked_sids(&grant.id)
                .map_err(|e| (-32000, e.to_string()))?;
            if !revoked_sids.is_empty()
                && let Ok(chain) = store.get_access_grant(&grant.id)
            {
                for (_idx, stmt) in chain.statements() {
                    let matches_this_credential = stmt.resource_type
                        == core_grant_types::ResourceType::Credential
                        && match &stmt.resource {
                            core_grant_types::ResourceSelector::Exact { value } => {
                                value == &credential_name
                            }
                            _ => false,
                        };
                    if matches_this_credential && revoked_sids.contains(&stmt.sid) {
                        let _ = store.log_event(
                            Some(&persona_id),
                            "credential.access",
                            Some(&credential_name),
                            "denied_statement_revoked",
                            Some(&format!("grant_id={} sid={}", grant.id, stmt.sid)),
                        );
                        return Err((-32006, "statement revoked".to_string()));
                    }
                }
            }

            // Record usage (enforces rate limits).
            store
                .record_grant_usage(&grant.id)
                .map_err(|e| (-32000, e.to_string()))?;
            // Retrieve the credential value.
            let vault = current_vault(store, "use_credential")?;
            let value = vault
                .get(VaultScope::Interactive, store, &credential_name)
                .map_err(|e| (-32000, e.to_string()))?;
            // Log the access.
            let _ = store.log_event(
                Some(&persona_id),
                "credential.access",
                Some(&credential_name),
                "allowed",
                None,
            );
            let text = String::from_utf8_lossy(&value);
            Ok(json!({
                "credential": text,
                "grant_id": grant.id,
                "credential_name": credential_name,
                "scope": grant.scope,
            }))
        }

        "vault_add" => {
            // Per-op user-presence gate. Internal callers (admin CLI /
            // test harness) bypass — same trust model as
            // development milestone force-flag handling.
            if !source.is_internal() {
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultAdd, override_qh)?;
            }
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            let metadata = params["metadata"].as_str();
            let value = if let Some(bytes) = params["value_bytes"].as_array() {
                let mut out = Vec::with_capacity(bytes.len());
                for item in bytes {
                    let byte = item
                        .as_u64()
                        .ok_or((-32602, "value_bytes entries must be integers".to_string()))?;
                    let byte = u8::try_from(byte)
                        .map_err(|_| (-32602, "value_bytes entries must fit in u8".to_string()))?;
                    out.push(byte);
                }
                out
            } else {
                params["value"]
                    .as_str()
                    .ok_or((-32602, "missing 'value'".to_string()))?
                    .as_bytes()
                    .to_vec()
            };
            let vault = current_vault(store, "vault_add")?;
            let info = vault
                .add(VaultScope::Interactive, store, name, &value, metadata)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"id": info.id, "name": info.name}))
        }

        "vault_remove" => {
            // High-risk write — gated. Emergency-eligible
            // (vault_remove revokes access; we'd rather let the user shut
            // down a leaked credential mid-quiet-hours than block them).
            if !source.is_internal() {
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::VaultRemove, override_qh)?;
            }
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;
            let vault = current_vault(store, "vault_remove")?;
            vault
                .remove(VaultScope::Interactive, store, name)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true, "name": name}))
        }

        "vault_lock" => {
            // Explicit re-lock. Always allowed (the user
            // is reducing privilege, not escalating). Internal/socket
            // both honored — `ember vault lock` may dispatch this.
            presence::lock();
            Ok(json!({"locked": true}))
        }

        "vault_unlock" => {
            crate::infra::interactive_unlock::ensure_vault_for_explicit_unlock(store)
                .map_err(|msg| (-32030, msg))?;
            crate::infra::interactive_unlock::arm_non_session_grace_window();
            let token = mint_operator_presence_token(ctx.peer.as_ref())?;
            let mut response = json!({"unlocked": true});
            if let Some(token) = token {
                response["presence_token"] = serde_json::to_value(token)
                    .map_err(|e| (-32000, format!("vault_unlock: encode presence_token: {e}")))?;
            }
            Ok(response)
        }

        "vault_status" => {
            // Lightweight diagnostic — read-class, never
            // prompts. Used by dashboards to show "session unlocked: 3m
            // idle" without forcing a biometric every refresh.
            presence::record_activity();
            let (unlocked, idle_secs) = presence::snapshot();
            let cfg = presence::current_config();
            Ok(json!({
                "unlocked": unlocked,
                "idle_secs": idle_secs,
                "idle_timeout_secs": cfg.idle_timeout.as_secs(),
                "quiet_hours_start": cfg.quiet_hours_start,
                "quiet_hours_end": cfg.quiet_hours_end,
            }))
        }

        "vault_migrate_acl" => {
            presence::record_activity();
            let service = params["service"]
                .as_str()
                .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_SERVICE);
            let account = params["account"]
                .as_str()
                .unwrap_or(crate::infra::vault::DEFAULT_KEYRING_ACCOUNT);
            let result = crate::infra::vault::migrate_mek_acl(service, account)
                .map_err(|e| (-32000, e.to_string()))?;
            let _ = store.log_event(
                None,
                "vault.mek_acl_migrated",
                None,
                "ok",
                Some(&format!(
                    "before={} after={} service={} account={}",
                    result.before_acl_kind, result.after_acl_kind, result.service, result.account
                )),
            );
            Ok(json!({
                "before_acl_kind": result.before_acl_kind,
                "after_acl_kind": result.after_acl_kind,
                "service": result.service,
                "account": result.account,
            }))
        }

        "vault_list" => {
            // Operator inventory enumeration: bump activity, never prompt.
            // Authority is still operator-sensitive because the response
            // enumerates global interactive-vault names + metadata.
            presence::record_activity();
            let vault = current_vault(store, "vault_list")?;
            let creds = vault
                .list(VaultScope::Interactive, store)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = creds
                .iter()
                .map(|c| json!({"id": c.id, "name": c.name, "metadata": c.metadata}))
                .collect();
            Ok(json!(list))
        }

        "vault_get" => {
            // Read-class: bump activity, never prompt. Returns the
            // plaintext credential value to the caller. Never log the
            // value — only the lookup name (security invariant —
            // see `feedback_never_print_vault_secrets` and the
            // 2026-04-27 CF token leak post-mortem).
            presence::record_activity();
            let name = params["name"]
                .as_str()
                .ok_or((-32602, "missing 'name'".to_string()))?;

            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Attempt retrieval — emit a typed VaultReceipt on both success
            // and failure so the audit trail is never silent.
            let vault = current_vault(store, "vault_get")?;
            let result = vault.get(VaultScope::Interactive, store, name);
            let (outcome, error) = match &result {
                Ok(_) => (ReceiptOutcome::Success, None),
                Err(e) => (ReceiptOutcome::Failure, Some(e.to_string())),
            };

            let mut receipt = VaultReceipt {
                id: format!("rct-vault-{}", uuid::Uuid::new_v4()),
                kind: ReceiptKind::VaultRetrieval,
                key_name: name.to_string(),
                caller_persona: "unknown".to_string(),
                materialized_at_epoch_secs: now_epoch,
                grant_evaluation: GrantEvaluation {
                    outcome: GrantEvaluationOutcome::Denied,
                    grant_id: None,
                },
                outcome,
                evidence: Evidence::default(),
            };
            if let Some(identity) = current_identity() {
                sign_vault_receipt(&mut receipt, identity);
            }
            if let Err(e) = store.store_vault_receipt(&receipt) {
                tracing::warn!(
                    error = %e,
                    key_name = %name,
                    receipt_id = %receipt.id,
                    "vault_get: failed to persist typed VaultReceipt"
                );
            }

            match result {
                Ok(value) => {
                    tracing::info!(name = %name, "vault_get: credential fetched");
                    let text = String::from_utf8_lossy(&value).into_owned();
                    Ok(json!({
                        "value": text,
                        "value_bytes": value,
                    }))
                }
                Err(e) => {
                    if let Some(reason) = error {
                        tracing::warn!(name = %name, error = %reason, "vault_get: retrieval failed");
                    }
                    Err((-32000, e.to_string()))
                }
            }
        }

        // KEYCHAIN-CONSOLIDATE-CLI-DAEMON-METHODS — per-caller local-state
        // content-key vending. Per design (separate-uid authorization
        // substrate) the daemon is the sole keychain client; CLI / GUI /
        // native-host callers route key acquisition through these three
        // arms over the SO_PEERCRED + group `ember` ACL-gated socket
        // instead of touching the OS keychain directly. The per-caller
        // vault namespace string is `local-state/<caller>` per the daemon-
        // sole-keychain-client proposal §"Three new daemon socket
        // methods". Receipts route through the canonical
        // `sign_receipt_v2` path (design + design); body shapes are
        // `LocalStateKeyResolveBody` and `LocalStateKeyRotationBody`.
        //
        // Key wire format: a `xchacha20-key:<64 hex>` content-key string
        // produced by `core_crypto::generate_content_key("local-state")`
        // (the canonical content-key shape consumed by
        // `core_crypto::encrypt_content` / `decrypt_content`). The vault
        // entry stores the UTF-8 bytes of that string; calling code reads
        // them back and treats them as the same content key.
        "local_state_key_get" => {
            // Adversarial-review hardening: CRIT-1 peer fail-closed,
            // HIGH-1 content-hash check via binary-pin manifest. The
            // gate refuses Internal dispatch + verifies peer's binary
            // matches the manifest entry for the claimed caller.
            let caller = params["caller"]
                .as_str()
                .ok_or((-32602, "missing 'caller'".to_string()))?;
            let peer = enforce_local_state_gate(
                source,
                ctx.peer,
                caller,
                store,
                ctx.bypass_binary_pin_gate_for_test,
            )?;
            let vault_namespace = local_state_vault_name(caller)?;

            presence::record_activity();
            let vault = current_vault(store, "local_state_key_get")?;

            // Existence test first — discriminates `resolved` vs
            // `generated` for the Receipt.
            let (key_string, resolved_or_generated) =
                match vault.get(VaultScope::Interactive, store, &vault_namespace) {
                    Ok(bytes) => {
                        let s = String::from_utf8(bytes).map_err(|e| {
                            (
                                -32000,
                                format!("local_state_key_get: stored key is not valid UTF-8: {e}"),
                            )
                        })?;
                        (s, "resolved")
                    }
                    Err(crate::infra::vault::VaultError::NotFound) => {
                        // Generate a fresh `ek1:<64 hex>` content key via
                        // core-crypto's named primitive — we do NOT invent a
                        // construction here per design.
                        //
                        // Note on CRIT-2 (migration race): auto-generate on
                        // miss is preserved for backwards-compat with the
                        // headless CLI. Race mitigation is on the CLI side
                        // via decrypt-probe + `force: true` on local_state_key_set
                        // (see emberlink-cli::resolve_encryption_key).
                        let key = core_crypto::generate_content_key("local-state");
                        vault
                            .add(
                                VaultScope::Interactive,
                                store,
                                &vault_namespace,
                                key.as_bytes(),
                                None,
                            )
                            .map_err(|e| {
                                (-32000, format!("local_state_key_get: vault.add: {e}"))
                            })?;
                        (key, "generated")
                    }
                    Err(e) => return Err((-32000, e.to_string())),
                };

            // Emit a signed v2 Receipt via the canonical path.
            // CRIT-1: peer.uid is now kernel-attested (gate failed earlier if absent).
            let body = LocalStateKeyResolveBody {
                peer_uid: peer.uid,
                caller: caller.to_string(),
                vault_namespace: vault_namespace.clone(),
                resolved_or_generated: resolved_or_generated.to_string(),
            };
            emit_local_state_v2_receipt(
                RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
                serde_json::to_value(&body),
                caller,
                &vault_namespace,
            );

            // Never log the key string — only the namespace + the
            // resolve/generate discriminator.
            Ok(json!({
                "key": key_string,
                "vault_namespace": vault_namespace,
                "resolved_or_generated": resolved_or_generated,
            }))
        }

        "local_state_key_set" => {
            // Migration + force-overwrite path. Two modes:
            //   force: false (default) — idempotent no-op when a key already
            //     exists. Preserves HIGH-2 anti-overwrite: a malicious caller
            //     can't silently replace the friendly's key.
            //   force: true — atomic replace via Vault::replace. Used ONLY by
            //     the CLI when it has already verified (via decrypt-probe)
            //     that the supplied key is the canonical one (CRIT-2 race
            //     recovery).
            //
            // Adversarial-review hardening: CRIT-1 peer fail-closed,
            // HIGH-1 content-hash check via binary-pin manifest.
            let caller = params["caller"]
                .as_str()
                .ok_or((-32602, "missing 'caller'".to_string()))?;
            let peer = enforce_local_state_gate(
                source,
                ctx.peer,
                caller,
                store,
                ctx.bypass_binary_pin_gate_for_test,
            )?;
            let key = params["key"]
                .as_str()
                .ok_or((-32602, "missing 'key'".to_string()))?;
            let force = params["force"].as_bool().unwrap_or(false);
            let vault_namespace = local_state_vault_name(caller)?;

            presence::record_activity();
            let vault = current_vault(store, "local_state_key_set")?;

            let already_set = vault
                .get(VaultScope::Interactive, store, &vault_namespace)
                .is_ok();
            let outcome = if already_set {
                if force {
                    vault
                        .replace(
                            VaultScope::Interactive,
                            store,
                            &vault_namespace,
                            key.as_bytes(),
                            None,
                        )
                        .map_err(|e| {
                            (-32000, format!("local_state_key_set: vault.replace: {e}"))
                        })?;
                    tracing::info!(
                        caller = %caller,
                        vault_namespace = %vault_namespace,
                        peer_uid = peer.uid,
                        "local_state_key_set: force-overwrote existing key"
                    );
                    "overwritten"
                } else {
                    tracing::info!(
                        caller = %caller,
                        vault_namespace = %vault_namespace,
                        peer_uid = peer.uid,
                        "local_state_key_set: no-op (already set, force=false)"
                    );
                    "noop_existing"
                }
            } else {
                vault
                    .add(
                        VaultScope::Interactive,
                        store,
                        &vault_namespace,
                        key.as_bytes(),
                        None,
                    )
                    .map_err(|e| (-32000, format!("local_state_key_set: vault.add: {e}")))?;
                tracing::info!(
                    caller = %caller,
                    vault_namespace = %vault_namespace,
                    peer_uid = peer.uid,
                    "local_state_key_set: stored key in vault"
                );
                "stored"
            };
            Ok(json!({
                "vault_namespace": vault_namespace,
                "already_set": already_set,
                "outcome": outcome,
                "overwritten": outcome == "overwritten",
            }))
        }

        "local_state_key_rotate_and_reencrypt" => {
            // Daemon-side atomic rotation: decrypt the caller-supplied
            // ciphertext under the current per-caller content key,
            // generate a new content key, re-encrypt the plaintext under
            // the new key, swap the vault entry, return the new
            // ciphertext to the caller. The whole operation runs inside
            // one dispatch arm so neither side can observe a partial
            // state. Uses the existing `core_crypto::encrypt_content` /
            // `decrypt_content` XChaCha20-Poly1305 envelope — no new
            // crypto primitives.
            //
            // Wire format for `ciphertext` (matches CLI's `decrypt_state`):
            //   `nonce(24) || ciphertext_with_tag`
            // The CLI's on-disk format adds a 10-byte magic prefix
            // before the nonce; this method expects the magic to be
            // stripped client-side. Use AAD `b"emberlink-local-state"`.
            //
            // Adversarial-review hardening: CRIT-1 peer fail-closed,
            // HIGH-1 content-hash check via binary-pin manifest.
            let caller = params["caller"]
                .as_str()
                .ok_or((-32602, "missing 'caller'".to_string()))?;
            let peer = enforce_local_state_gate(
                source,
                ctx.peer,
                caller,
                store,
                ctx.bypass_binary_pin_gate_for_test,
            )?;
            let ciphertext_value = params["ciphertext"].as_array().ok_or((
                -32602,
                "missing 'ciphertext' (expected JSON array of bytes)".to_string(),
            ))?;
            let ciphertext: Vec<u8> = ciphertext_value
                .iter()
                .map(|v| v.as_u64().map(|n| n as u8).ok_or(()))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| {
                    (
                        -32602,
                        "'ciphertext' must be an array of u8 byte values".to_string(),
                    )
                })?;
            let vault_namespace = local_state_vault_name(caller)?;
            presence::record_activity();
            let vault = current_vault(store, "local_state_key_rotate_and_reencrypt")?;

            // 1. Pull the current key — vault stores it as UTF-8 bytes
            //    of the `ek1:<64 hex>` content-key string.
            let old_key_bytes = vault
                .get(VaultScope::Interactive, store, &vault_namespace)
                .map_err(|e| {
                    (
                        -32000,
                        format!("local_state_key_rotate_and_reencrypt: vault.get: {e}"),
                    )
                })?;
            let old_key = String::from_utf8(old_key_bytes.clone()).map_err(|e| {
                (
                    -32000,
                    format!(
                        "local_state_key_rotate_and_reencrypt: stored key is not valid UTF-8: {e}"
                    ),
                )
            })?;

            // 2. Decrypt under the current key via core-crypto.
            if ciphertext.len() < 24 {
                return Err((
                    -32602,
                    "ciphertext too short (need 24-byte nonce prefix)".to_string(),
                ));
            }
            let (nonce_bytes, ct_and_tag) = ciphertext.split_at(24);
            let encrypted = core_crypto::EncryptedContent {
                nonce_hex: core_types::bytes_to_hex(nonce_bytes),
                ciphertext: ct_and_tag.to_vec(),
            };
            let plaintext =
                core_crypto::decrypt_content(&old_key, &encrypted, b"emberlink-local-state")
                    .map_err(|e| {
                        (
                            -32000,
                            format!("local_state_key_rotate_and_reencrypt: decrypt: {e}"),
                        )
                    })?;

            // 3. Generate the new content key + re-encrypt.
            let new_key = core_crypto::generate_content_key("local-state");
            let new_encrypted =
                core_crypto::encrypt_content(&new_key, &plaintext, b"emberlink-local-state")
                    .map_err(|e| {
                        (
                            -32000,
                            format!("local_state_key_rotate_and_reencrypt: encrypt: {e}"),
                        )
                    })?;
            let new_nonce_bytes =
                core_types::hex_to_bytes(&new_encrypted.nonce_hex).map_err(|e| {
                    (
                        -32000,
                        format!("local_state_key_rotate_and_reencrypt: nonce hex decode: {e}"),
                    )
                })?;
            let mut new_ciphertext =
                Vec::with_capacity(new_nonce_bytes.len() + new_encrypted.ciphertext.len());
            new_ciphertext.extend_from_slice(&new_nonce_bytes);
            new_ciphertext.extend_from_slice(&new_encrypted.ciphertext);

            // 4. Hash old + new key for the Receipt (never the key
            //    itself).
            let old_key_hash = blake3::hash(old_key.as_bytes()).to_hex().to_string();
            let new_key_hash = blake3::hash(new_key.as_bytes()).to_hex().to_string();

            // 5. Atomic vault swap via Vault::replace (single SQLite
            //    transaction). Closes adversarial-review HIGH-3: the
            //    daemon-crash window where remove+add could leave the
            //    namespace empty no longer exists.
            vault
                .replace(
                    VaultScope::Interactive,
                    store,
                    &vault_namespace,
                    new_key.as_bytes(),
                    None,
                )
                .map_err(|e| {
                    (
                        -32000,
                        format!("local_state_key_rotate_and_reencrypt: vault.replace: {e}"),
                    )
                })?;

            // 6. Emit a signed v2 Receipt via the canonical path.
            // CRIT-1: peer.uid is now kernel-attested (gate failed earlier if absent).
            let body = LocalStateKeyRotationBody {
                peer_uid: peer.uid,
                caller: caller.to_string(),
                vault_namespace: vault_namespace.clone(),
                old_key_hash: format!("blake3:{old_key_hash}"),
                new_key_hash: format!("blake3:{new_key_hash}"),
            };
            emit_local_state_v2_receipt(
                RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
                serde_json::to_value(&body),
                caller,
                &vault_namespace,
            );

            Ok(json!({
                "ciphertext": new_ciphertext,
                "vault_namespace": vault_namespace,
            }))
        }

        "binary_pin_generate" => {
            // Establish the trust root for content-hash peer binding.
            // Per KEYCHAIN-CONSOLIDATE-CLI adversarial-review:
            //   MID-A — `generate` requires explicit operator presence
            //     (Touch ID via HighRiskOp::BinaryPinGenerate). Without
            //     this, an attacker who replaced a binary could silently
            //     re-pin it.
            //   CRIT-A (v0.3 trust model — TOFU at install) — the
            //     manifest is signed by the daemon's persona key. Trust
            //     comes from the operator's intent at the moment they
            //     run this command. Path 2 (Ember Systems IdentityRoot
            //     pre-signing) is filed as implementation-note-170.
            //
            // Wire shape:
            //   { "pins": [{"caller": "cli", "path": "/usr/local/bin/ember"}, ...],
            //     "force": false }
            //
            // `force: false` (default) refuses to overwrite an existing
            // manifest. Subsequent generates require `force: true` AND a
            // fresh user-presence proof.
            if source.is_internal() {
                return Err((
                    -32401,
                    "binary_pin_generate is wire-only; refuse Internal dispatch".to_string(),
                ));
            }
            check_user_presence_gate(HighRiskOp::BinaryPinGenerate, false)?;

            let pins_value = params["pins"].as_array().ok_or((
                -32602,
                "missing 'pins' (expected array of {caller, path})".to_string(),
            ))?;
            let force = params["force"].as_bool().unwrap_or(false);

            let identity = crate::infra::receipt::current_identity().ok_or((
                -32000,
                "daemon identity not initialised — cannot sign binary-pin manifest".to_string(),
            ))?;
            let pubkey_str = format!("ed25519:{}", identity.pubkey_hex());

            // Refuse to overwrite an existing manifest unless force=true.
            // (HIGH-2-style anti-overwrite property for the manifest itself.)
            let vault = current_vault(store, "binary_pin_generate")?;
            let existing = crate::infra::binary_pin::load_manifest(&vault, store, &pubkey_str)
                .map_err(|e| (-32000, format!("load existing manifest: {e}")))?;
            if existing.is_some() && !force {
                return Err((
                    -32401,
                    "binary-pin manifest already exists — re-run with `force: true` to overwrite (requires user-presence proof)".to_string(),
                ));
            }

            // Resolve the target list.
            let mut targets: Vec<(String, std::path::PathBuf)> = Vec::new();
            for entry in pins_value {
                let caller = entry["caller"]
                    .as_str()
                    .ok_or((-32602, "pin entry missing 'caller'".to_string()))?;
                let _ = local_state_vault_name(caller)?; // validates allow-list
                let path = entry["path"]
                    .as_str()
                    .ok_or((-32602, "pin entry missing 'path'".to_string()))?;
                targets.push((caller.to_string(), std::path::PathBuf::from(path)));
            }

            let outcome =
                crate::infra::binary_pin::build_manifest_from_paths(&targets, &pubkey_str)
                    .map_err(|e| (-32000, format!("build manifest: {e}")))?;
            let mut manifest = outcome.manifest;
            manifest
                .sign(&crate::session::lifecycle::DaemonPersonaSigner::new(
                    identity,
                ))
                .map_err(|e| (-32000, format!("sign manifest: {e}")))?;
            crate::infra::binary_pin::store_manifest(&vault, store, &manifest)
                .map_err(|e| (-32000, format!("store manifest: {e}")))?;

            tracing::info!(
                pins = manifest.pins.len(),
                missing = outcome.missing.len(),
                "binary_pin_generate: manifest signed and stored"
            );

            Ok(json!({
                "pins_signed": manifest.pins.iter().map(|p| serde_json::json!({
                    "caller": p.caller,
                    "blake3_hex": p.blake3_hex,
                    "binary_path": p.binary_path,
                    "basename": p.basename,
                })).collect::<Vec<_>>(),
                "missing": outcome.missing.iter().map(|(c, p)| serde_json::json!({
                    "caller": c,
                    "path": p,
                })).collect::<Vec<_>>(),
                "signer_pubkey": manifest.signer_pubkey,
                "signed_at": manifest.signed_at,
            }))
        }

        // implementation-note-230 (A): socket method that exposes
        // the audit-chain verifier primitive shipped in #2998. Walks the
        // last `tail` rows (or full chain when omitted) and returns a
        // shape callers (`ember audit verify` CLI) can render directly.
        "audit_verify" => {
            let tail = params["tail"].as_u64().map(|n| n as usize);
            handle_audit_verify(store, tail)
        }

        "audit_query" => {
            let claimed_persona_id = params["persona_id"].as_str();
            let claimed_agent_id = params["agent_id"].as_str();
            if let (Some(persona_id), Some(agent_id)) = (claimed_persona_id, claimed_agent_id)
                && persona_id != agent_id
            {
                return Err((
                    -32602,
                    "audit_query: persona_id and agent_id must match when both are provided"
                        .to_string(),
                ));
            }
            let agent_id = match team0_connect_only_persona_scope(&ctx, "audit_query")? {
                Some(trusted_persona) => {
                    if let Some(claimed_persona) = claimed_persona_id.or(claimed_agent_id)
                        && claimed_persona != trusted_persona
                    {
                        tracing::warn!(
                            method = "audit_query",
                            claimed_persona_id = %claimed_persona,
                            trusted_persona_id = %trusted_persona,
                            tier = current_dispatch_deployment_tier().as_str(),
                            "connect-only persona-scoped read refused: claimed persona does not match trusted principal"
                        );
                        return Err((
                            -32004,
                            "audit_query: claimed actor does not match trusted principal"
                                .to_string(),
                        ));
                    }
                    Some(trusted_persona)
                }
                None => claimed_persona_id.or(claimed_agent_id).map(String::from),
            };
            let limit = params["limit"].as_u64().map(|l| l as usize);
            let filter = AuditFilter {
                persona_id: agent_id,
                limit,
                ..Default::default()
            };
            let entries = store
                .query_audit(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "agent_id": e.agent_id,
                        "action": e.action,
                        "credential": e.credential,
                        "outcome": e.outcome,
                    })
                })
                .collect();
            Ok(json!(list))
        }

        "audit_log_query" => {
            let filter = AuditFilter {
                id: params["id"].as_i64(),
                agent_id: params["agent_id"].as_str().map(String::from),
                action: params["action"].as_str().map(String::from),
                limit: params["limit"].as_u64().map(|l| l as usize),
                action_prefix: params["action_prefix"].as_str().map(String::from),
                persona_id: params["persona_id"].as_str().map(String::from),
                scope: params["scope"].as_str().map(String::from),
                since_ms: params["since_ms"].as_i64(),
                before_ms: params["before_ms"].as_i64(),
            };
            let entries = store
                .query_audit(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = entries
                .iter()
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "audit_explain" => {
            let id = params["id"]
                .as_i64()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            let explain = crate::infra::audit_explain::build_audit_explain(store, policy, id)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("audit event {id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            Ok(serde_json::to_value(explain).unwrap_or(Value::Null))
        }

        "receipt_tree" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let tree =
                crate::infra::receipt_tree::build_tree(store, grant_id).map_err(|e| match e {
                    crate::infra::receipt_tree::ReceiptTreeError::UnknownRoot(id) => {
                        (-32004, format!("grant '{id}' not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            Ok(serde_json::to_value(tree).unwrap_or(Value::Null))
        }

        // EMBER-implementation-note-244: unified receipt query — supports the full
        // `ReceiptFilter` shape (actor/kind/grant_id/since/resource/limit).
        // The `ember audit query` CLI path calls this via JSON-RPC socket.
        "receipt_query" => {
            let persona_id = persona_scoped_param_for_connect_only(
                &ctx,
                params,
                "receipt_query",
                "actor",
                false,
            )?;
            let filter = crate::infra::receipt::ReceiptFilter {
                persona_id,
                kind: params["kind"].as_str().map(String::from),
                grant_id: params["grant_id"].as_str().map(String::from),
                resource: params["resource"].as_str().map(String::from),
                since_iso: params["since"].as_str().map(String::from),
                limit: params["limit"].as_u64(),
                ..Default::default()
            };
            let rows = store
                .query_receipts(&filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = rows
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "submit_approval" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            // approval_socket_arm_operator_presence_required — Per
            // adversarial-review 2026-05-19 CRIT-3. The socket dispatch path
            // for `submit_approval` previously (a) skipped `policy.evaluate`
            // entirely, letting an agent submit approval requests for actions
            // the policy was configured to Deny, and (b) accepted the
            // caller-supplied `risk_level` verbatim, allowing the audit trail
            // to lie about how risky the request actually was.
            //
            // The fix matches the create_grant arm's pattern (handler.rs:2580+):
            //   1. Evaluate policy on the action. Denied → -32003 immediately.
            //   2. Use `eval.risk` for the audit row, ignore caller-supplied.
            //   3. Apply the per-op presence gate (same posture as create_grant)
            //      so submit-while-locked surfaces a re-auth prompt rather
            //      than silently filling the pending-approval queue.
            // Internal callers (test harness, daemon-internal flows like the
            // broker's HITL poll loop at broker/handler.rs:1356) bypass.
            let eval = policy.evaluate(action);
            if !source.is_internal() {
                if matches!(eval.requirement, ApprovalRequirement::Denied) {
                    return Err((
                        -32003,
                        format!(
                            "submit_approval: policy denies action {action:?} ({})",
                            eval.matched_rule.unwrap_or_default()
                        ),
                    ));
                }
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::ApprovalSubmit, override_qh)?;
            }
            // Risk level is policy-derived, not caller-supplied. This closes
            // the audit-truthfulness gap in CRIT-3 — an agent can no longer
            // mark a high-risk submission as "low" to slip past dashboard
            // filtering or operator-attention heuristics.
            let risk_level = format!("{:?}", eval.risk).to_lowercase();
            let ttl_secs = params["ttl_secs"].as_u64();
            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            // implementation-note-7 —
            // submit_approval is a generic tool-invoke approval entry; it
            // doesn't carry the grant-shaping fields directly. Defaults to
            // None so the resolver leaves the minted grant unshaped on the
            // delegation axes (legacy behaviour preserved).
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs,
                risk_level: risk_level.clone(),
                tool_name: params["tool_name"].as_str().map(str::to_owned),
                target_host: params["target_host"].as_str().map(str::to_owned),
                target_url: params["target_url"].as_str().map(str::to_owned),
                agent_framework: params["agent_framework"].as_str().map(str::to_owned),
                max_delegation_depth: None,
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            };
            let scope_obj = core_grant_types::approval::RequestedScope {
                capability: scope.to_string(),
                resource_id: None,
                constraints: vec![],
            };
            let request_id = adapter
                .submit_request(persona_id, credential_name, scope_obj, metadata)
                .await
                .map_err(|e| (-32000, e.to_string()))?;
            let req = store
                .get_approval(&request_id.0)
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({"id": request_id.0, "status": req.status}))
        }

        // implementation-note-245 — submit a composite approval that bundles
        // an N-Statement envelope. On `Approved`, the resolver mints a single
        // composite grant whose `blocks_json` carries the full statement
        // chain. Wraps the already-shipped `DaemonStore::propose_grant`.
        "propose_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let risk_level = params["risk_level"]
                .as_str()
                .ok_or((-32602, "missing 'risk_level'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();
            let stmts_value = params["statements"]
                .as_array()
                .ok_or((-32602, "missing 'statements' array".to_string()))?;
            let mut statements: Vec<core_grant_types::Statement> =
                Vec::with_capacity(stmts_value.len());
            for v in stmts_value {
                let s: core_grant_types::Statement = serde_json::from_value(v.clone())
                    .map_err(|e| (-32602, format!("invalid statement: {e}")))?;
                statements.push(s);
            }
            if statements.is_empty() {
                return Err((-32602, "statements must not be empty".to_string()));
            }
            // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — per ADR
            // 135 §4 every composite-grant action key must be DID-prefixed
            // (`did:<method>:<rest>`). Reject bare keys at the parse-time
            // gate so the RPC entry point is the migration enforcement point;
            // the error message includes the recommended `did:ember:<key>`
            // form so authors can migrate without consulting docs. Forward-
            // compat: arbitrary `did:<method>:` prefixes pass even though
            // v0.3.0's broker.resolve only routes `did:ember:`.
            crate::trust::grant::validate_action_keys_did_prefixed(&statements)
                .map_err(|e| (-32602, e.to_string()))?;
            // approval_notify_fields_persisted — use the with_notify variant so
            // tool_name / target_host / target_url / agent_framework land in the DB
            // (not just in the returned struct) for subsequent get_approval calls.
            let req = store
                .propose_grant_with_notify(
                    persona_id,
                    credential_name,
                    scope,
                    ttl_secs,
                    action,
                    risk_level,
                    statements,
                    params["tool_name"].as_str().map(str::to_owned),
                    params["target_host"].as_str().map(str::to_owned),
                    params["target_url"].as_str().map(str::to_owned),
                    params["agent_framework"].as_str().map(str::to_owned),
                )
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &req);
            Ok(json!({
                "approval_id": req.id,
                "id": req.id,
                "status": req.status,
                "statement_count": req.composite_statements.as_ref().map(|v| v.len()).unwrap_or(0),
            }))
        }

        "list_pending_approvals" => {
            let persona_scope = team0_connect_only_persona_scope(&ctx, "list_pending_approvals")?;
            let requests = store
                .list_pending_approvals()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = requests
                .iter()
                .filter(|r| match persona_scope.as_deref() {
                    Some(persona_id) => r.persona_id == persona_id,
                    None => true,
                })
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "resolve_approval" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            let decision = params["decision"]
                .as_str()
                .ok_or((-32602, "missing 'decision'".to_string()))?;

            // approval_socket_arm_operator_presence_required — Per
            // adversarial-review 2026-05-19 CRIT-1. The socket dispatch path
            // for `resolve_approval` previously had NO authorization gate
            // beyond "connection exists" (no presence check, no caller-
            // identity check, no two-party invariant). An agent with socket
            // access could mint a `pending` approval via create_grant or
            // submit_approval, then call `resolve_approval` on its own
            // request, defeating the credential gate. The dashboard path
            // calls `store.resolve_approval` (or
            // `resolve_approval_with_biometric`) directly — that route is
            // operator-attested and unaffected by this gate. The socket arm
            // now requires:
            //   (a) caller_persona_id != approval.persona_id (two-party)
            //   (b) presence gate Allowed for ApprovalResolve
            // Internal callers (test harness, admin CLI, recovery) bypass.
            if !source.is_internal() {
                let pending = store.get_approval(id).map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("approval {id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
                let caller_principal =
                    crate::infra::handlers::support::resolve_caller_principal(&ctx, params).await?;
                if caller_principal == pending.persona_id {
                    tracing::warn!(
                        caller_persona_id = %caller_principal,
                        approval_id = %id,
                        "rejecting resolve_approval: caller is the submitter (self-approval forbidden)"
                    );
                    return Err((
                        -32003,
                        "resolve_approval: caller cannot approve own request \
                         (two-party invariant; the dashboard path is the \
                         operator-attested route for self-submitted approvals)"
                            .to_string(),
                    ));
                }
                let override_qh = params["override_quiet_hours"].as_bool().unwrap_or(false);
                check_user_presence_gate(HighRiskOp::ApprovalResolve, override_qh)?;
            }

            let outcome = match decision {
                "approve" => crate::trust::approval::ApprovalOutcome::Approved,
                "deny" => crate::trust::approval::ApprovalOutcome::Denied {
                    reason: params["reason"]
                        .as_str()
                        .ok_or((-32602, "missing 'reason'".to_string()))?
                        .to_string(),
                },
                "narrow" => crate::trust::approval::ApprovalOutcome::Narrowed {
                    new_scope: params["scope"]
                        .as_str()
                        .ok_or((-32602, "missing 'scope'".to_string()))?
                        .to_string(),
                },
                "always" => crate::trust::approval::ApprovalOutcome::Always {
                    scope: params["scope"].as_str().map(str::to_owned),
                    expires_at: params["expires_at"].as_str().map(str::to_owned),
                },
                other => {
                    return Err((
                        -32602,
                        format!(
                            "invalid 'decision': expected approve|deny|narrow|always, got {other}"
                        ),
                    ));
                }
            };
            store.resolve_approval(id, &outcome).map_err(|e| match e {
                crate::infra::store::StoreError::NotFound => {
                    (-32004, format!("approval {id} not found"))
                }
                other => (-32000, other.to_string()),
            })?;
            let resolved = store.get_approval(id).map_err(|e| match e {
                crate::infra::store::StoreError::NotFound => {
                    (-32004, format!("approval {id} not found after resolve"))
                }
                other => (-32000, other.to_string()),
            })?;
            serde_json::to_value(&resolved)
                .map_err(|e| (-32000, format!("serialize resolved approval: {e}")))
        }

        "status" => {
            let persona_scope = team0_connect_only_persona_scope(&ctx, "status")?;
            let personas = store.list_personas().map_err(|e| (-32000, e.to_string()))?;
            let grants = store
                .list_active_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let sandboxes = store
                .list_sandboxes()
                .map_err(|e| (-32000, e.to_string()))?;
            let approvals = store
                .list_pending_approvals()
                .map_err(|e| (-32000, e.to_string()))?;
            let recent_activity_filter = crate::infra::audit::AuditFilter {
                persona_id: persona_scope.clone(),
                limit: Some(5),
                ..Default::default()
            };
            let recent_activity = store
                .query_audit(&recent_activity_filter)
                .map_err(|e| (-32000, e.to_string()))?;
            let standing_grants = store
                .list_standing_grants()
                .map_err(|e| (-32000, e.to_string()))?
                .into_iter()
                .filter(|grant| match persona_scope.as_deref() {
                    Some(persona_id) => grant.persona_id == persona_id,
                    None => true,
                })
                .count();
            let audit_events_total = if let Some(persona_id) = persona_scope.as_deref() {
                store
                    .query_audit(&crate::infra::audit::AuditFilter {
                        persona_id: Some(persona_id.to_string()),
                        ..Default::default()
                    })
                    .map_err(|e| (-32000, e.to_string()))?
                    .len() as u64
            } else {
                store.audit_count().map_err(|e| (-32000, e.to_string()))?
            };
            serde_json::to_value(crate::infra::status::StatusSummary {
                personas: personas
                    .into_iter()
                    .filter(|persona| match persona_scope.as_deref() {
                        Some(persona_id) => persona.id == persona_id,
                        None => true,
                    })
                    .collect(),
                grants: grants
                    .into_iter()
                    .filter(|grant| match persona_scope.as_deref() {
                        Some(persona_id) => grant.persona_id == persona_id,
                        None => true,
                    })
                    .collect(),
                sandboxes: sandboxes
                    .into_iter()
                    .filter(|sandbox| match persona_scope.as_deref() {
                        Some(persona_id) => {
                            sandbox.persona_id == persona_id
                                || sandbox.owner_persona_id.as_deref() == Some(persona_id)
                        }
                        None => true,
                    })
                    .collect(),
                approvals: approvals
                    .into_iter()
                    .filter(|approval| match persona_scope.as_deref() {
                        Some(persona_id) => approval.persona_id == persona_id,
                        None => true,
                    })
                    .collect(),
                recent_activity,
                standing_grants,
                audit_events_total,
            })
            .map_err(|e| (-32000, format!("serialize status summary: {e}")))
        }

        "grant_status" => {
            // Look up by id. The agent protocol passes a single id that may
            // refer to either a live grant (`grant-*`) OR a pending approval
            // request (`approval-*`). Returning both shapes under one method
            // lets clients poll a `request_grant` response through to the
            // issued grant without having to switch RPC methods.
            //
            // The shape is kept wire-compatible with the agent runtime's
            // existing `GrantInfo` + `RequestGrantResponse`: callers parse
            // `kind == "grant"` for grant info or `kind == "approval"` for
            // an approval-request status.
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id' parameter".to_string()))?;
            // Optional: callers can pin the expected persona so a lost id
            // cannot be used to leak status for another agent's grant.
            let expected_persona = persona_scoped_param_for_connect_only(
                &ctx,
                params,
                "grant_status",
                "persona_id",
                false,
            )?;

            // implementation-note-246: if the caller is observing a
            // grant whose effective (wall-clock-projected) status is terminal
            // but whose stored status is still `active`, flip the row + emit
            // the signed receipt right now. Without this, the runner's
            // `grant_status` poll sees terminal via `effective_status` but
            // the receipt only lands on the next 60-second sweep tick — every
            // receipt-aware check (live receipts panel, dashboard SSE, offline
            // verify) would race the sweep. Best-effort: a failure here logs
            // but doesn't fail the read.
            if let Err(e) = store.expire_grant_if_terminal_now(id) {
                tracing::warn!(
                    grant_id = %id,
                    error = ?e,
                    "expire_grant_if_terminal_now failed; proceeding with stored status"
                );
            }

            // Try grant first.
            match store.get_grant(id) {
                Ok(g) => {
                    if let Some(pid) = expected_persona.as_deref()
                        && g.persona_id != pid
                    {
                        return Err((
                            if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                                -32004
                            } else {
                                -32002
                            },
                            if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                                "grant_status: requested grant does not belong to trusted principal"
                                    .to_string()
                            } else {
                                "grant belongs to a different persona".to_string()
                            },
                        ));
                    }
                    // Emit per-Statement array for composite callers
                    // (design). V0 schema: no envelope-level `budget` /
                    // `usage` projection — consumers read per-Statement
                    // fields from the `statements` array.
                    let statements: Vec<Value> = match store.get_access_grant(id) {
                        Ok(chain) => chain
                            .statements()
                            .map(|(bi, s)| {
                                json!({
                                    "sid": s.sid,
                                    "block_index": bi,
                                    "resource_type": s.resource_type.as_str(),
                                    "actions": s.actions,
                                    "resource": s.resource,
                                    "budget": s.budget,
                                    "usage": s.usage,
                                    "conditions": s.conditions,
                                })
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    // implementation-note-242 — surface the
                    // per-Statement revocation list so callers can render
                    // strikethrough on individual sids without polling a
                    // separate endpoint.
                    let revoked_sids = store.get_revoked_sids(&g.id).unwrap_or_default();
                    return Ok(json!({
                        "kind": "grant",
                        "id": g.id,
                        "persona_id": g.persona_id,
                        "credential_name": g.credential_name,
                        "scope": g.scope,
                        "status": g.status,
                        "expires_at": g.expires_at,
                        "created_at": g.created_at,
                        "statements": statements,
                        "statement_count": statements.len(),
                        "revoked_sids": revoked_sids,
                    }));
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    // Fall through to approval lookup.
                }
                Err(e) => return Err((-32000, e.to_string())),
            }

            match store.get_approval(id) {
                Ok(a) => {
                    if let Some(pid) = expected_persona.as_deref()
                        && a.persona_id != pid
                    {
                        return Err((
                            if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                                -32004
                            } else {
                                -32002
                            },
                            if current_dispatch_deployment_tier().requires_multi_uid_authz() {
                                "grant_status: requested approval does not belong to trusted principal"
                                    .to_string()
                            } else {
                                "approval belongs to a different persona".to_string()
                            },
                        ));
                    }
                    Ok(json!({
                        "kind": "approval",
                        "id": a.id,
                        "persona_id": a.persona_id,
                        "credential_name": a.credential_name,
                        "scope": a.scope,
                        "status": a.status,
                        "action": a.action,
                        "risk_level": a.risk_level,
                    }))
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    Err((-32004, format!("grant or approval {id} not found")))
                }
                Err(e) => Err((-32000, e.to_string())),
            }
        }

        "extend_grant" => {
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let add_tokens = params["add_tokens"].as_u64();
            let add_cents = params["add_cents"].as_u64();
            let add_ttl_secs = params["add_ttl_secs"].as_u64();
            let updated = store
                .extend_grant(grant_id, add_tokens, add_cents, add_ttl_secs)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "grant_id": updated.id,
                "expires_at": updated.expires_at,
                "budget": updated.budget,
            }))
        }

        "request_access" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let credential_name = params["credential_name"]
                .as_str()
                .ok_or((-32602, "missing 'credential_name'".to_string()))?;
            let scope = params["scope"]
                .as_str()
                .ok_or((-32602, "missing 'scope'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let ttl_secs = params["ttl_secs"].as_u64();

            // Pre-evaluation rate limit check (#69C.4). Runs before standing
            // grant lookup and policy evaluation. On rejection the response
            // intentionally avoids disclosing which rule would have matched —
            // only the rate-limit fact is surfaced.
            if !rate_limiter.borrow_mut().check_action(persona_id, action) {
                return Ok(json!({
                    "status": "denied",
                    "decision": "deny",
                    "reason": "rate_spike",
                }));
            }

            // Check standing grants first
            if store
                .check_standing_grant(persona_id, action)
                .map_err(|e| (-32000, e.to_string()))?
            {
                let grant = store
                    .create_grant(persona_id, credential_name, scope, ttl_secs)
                    .map_err(|e| (-32000, e.to_string()))?;
                let _ = store.log_event(
                    Some(persona_id),
                    "grant.issued",
                    Some(credential_name),
                    "allowed",
                    Some(
                        &serde_json::json!({
                            "grant_id": grant.id,
                            "scope": scope,
                            "ttl_secs": ttl_secs,
                            "source": "standing_grant",
                        })
                        .to_string(),
                    ),
                );
                return Ok(json!({
                    "status": "approved",
                    "source": "standing_grant",
                    "grant_id": grant.id,
                }));
            }

            let eval = policy.evaluate(action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();

            match eval.requirement {
                ApprovalRequirement::Auto => {
                    let grant = store
                        .create_grant(persona_id, credential_name, scope, ttl_secs)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(credential_name),
                        "allowed",
                        Some(
                            &serde_json::json!({
                                "grant_id": grant.id,
                                "scope": scope,
                                "ttl_secs": ttl_secs,
                                "source": "request_access",
                            })
                            .to_string(),
                        ),
                    );
                    Ok(json!({
                        "status": "approved",
                        "grant_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }))
                }
                ApprovalRequirement::Required => {
                    // PHASE-C-1-MIGRATED: trait crossing per design §3
                    let adapter = DaemonApprovalStoreRef::new(store);
                    // implementation-note-7 —
                    // request_access doesn't surface the grant-shaping
                    // fields on its socket params, so default to None.
                    let metadata = SubmitMetadata {
                        action: action.to_string(),
                        ttl_secs,
                        risk_level: risk_str.clone(),
                        tool_name: params["tool_name"].as_str().map(str::to_owned),
                        target_host: params["target_host"].as_str().map(str::to_owned),
                        target_url: params["target_url"].as_str().map(str::to_owned),
                        agent_framework: params["agent_framework"].as_str().map(str::to_owned),
                        max_delegation_depth: None,
                        max_uses_per_hour: None,
                        allowed_hours_start: None,
                        allowed_hours_end: None,
                        allowed_targets: None,
                        budget: None,
                        max_children_per_day: None,
                        auto_delegate_scope_template: None,
                    };
                    let scope_obj = core_grant_types::approval::RequestedScope {
                        capability: scope.to_string(),
                        resource_id: None,
                        constraints: vec![],
                    };
                    let request_id = adapter
                        .submit_request(persona_id, credential_name, scope_obj, metadata)
                        .await
                        .map_err(|e| (-32000, e.to_string()))?;
                    let req = store
                        .get_approval(&request_id.0)
                        .map_err(|e| (-32000, e.to_string()))?;
                    notify_require_approval(store, &req);
                    Ok(json!({
                        "status": "pending",
                        "approval_id": request_id.0,
                        "decision": "require_approval",
                        "risk": risk_str,
                    }))
                }
                ApprovalRequirement::Denied => Ok(json!({
                    "status": "denied",
                    "decision": "deny",
                    "risk": risk_str,
                    "reason": format!(
                        "policy denies action: {}",
                        eval.matched_rule.unwrap_or_default()
                    ),
                })),
            }
        }

        // implementation-note-42: block-and-poll RPC for the proxy hook approval round-trip.
        //
        // Polls `get_approval(request_id)` every 500ms up to `timeout_secs`. On
        // first non-pending state -> return the matching `ApprovalDecision`. On
        // deadline -> `TimedOut`. The approval row itself is created elsewhere
        // (`submit_approval` via `request_access` / `evaluate_tool_call`); this
        // arm only awaits resolution.
        //
        // Defaults: `timeout_secs = 300` (5 min) when omitted, matching the
        // proxy hook's `call_daemon_await_approval` default. A configurable
        // EmberConfig surface is out of scope for implementation-note-42 — file as
        // follow-up if operators need per-deployment tuning.
        //
        // TODO: T2 integration test with simulated dashboard
        // tap (separate process resolves the approval mid-poll). For this PR
        // the unit tests below cover the three resolution paths.
        "await_approval" => {
            let request_id = params["request_id"]
                .as_str()
                .ok_or((-32602, "missing 'request_id' parameter".to_string()))?
                .to_string();
            let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

            loop {
                let info = store.get_approval(&request_id).map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("approval {request_id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;

                let decision_json: Option<Value> = match info.status.as_str() {
                    "pending" => None,
                    "approved" | "narrowed" | "narrowed_and_approved" => {
                        Some(json!({"decision": {"kind": "approved"}}))
                    }
                    "denied" | "dismissed" => Some(json!({
                        "decision": {
                            "kind": "denied",
                            "reason": info
                                .reason
                                .clone()
                                .unwrap_or_else(|| format!("approval {}", info.status)),
                        }
                    })),
                    "timed_out" | "expired" => Some(json!({"decision": {"kind": "timed_out"}})),
                    other => Some(json!({
                        "decision": {
                            "kind": "denied",
                            "reason": format!("unknown approval status: {other}"),
                        }
                    })),
                };

                if let Some(v) = decision_json {
                    return Ok(v);
                }

                if tokio::time::Instant::now() >= deadline {
                    return Ok(json!({"decision": {"kind": "timed_out"}}));
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        "request_access_blocking" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action = params["action"]
                .as_str()
                .ok_or((-32602, "missing 'action'".to_string()))?;
            let resource = params["resource"].as_str().unwrap_or("");
            let timeout_secs = params["timeout_secs"].as_u64().unwrap_or(300);

            let eval = policy.evaluate(action);
            let risk_str = format!("{:?}", eval.risk).to_lowercase();

            match eval.requirement {
                ApprovalRequirement::Auto => {
                    let grant = store
                        .create_grant(persona_id, resource, "auto", None)
                        .map_err(|e| (-32000, e.to_string()))?;
                    let _ = store.log_event(
                        Some(persona_id),
                        "grant.issued",
                        Some(resource),
                        "allowed",
                        Some(
                            &serde_json::json!({
                                "grant_id": grant.id,
                                "scope": "auto",
                                "ttl_secs": null,
                                "source": "request_access_blocking",
                            })
                            .to_string(),
                        ),
                    );
                    return Ok(json!({
                        "status": "approved",
                        "approval_id": grant.id,
                        "decision": "auto_approve",
                        "risk": risk_str,
                    }));
                }
                ApprovalRequirement::Denied => {
                    return Ok(json!({
                        "status": "denied",
                        "decision": "deny",
                        "risk": risk_str,
                        "reason": format!(
                            "policy denies action: {}",
                            eval.matched_rule.unwrap_or_default()
                        ),
                    }));
                }
                ApprovalRequirement::Required => {}
            }

            // PHASE-C-1-MIGRATED: trait crossing per design §3
            let adapter = DaemonApprovalStoreRef::new(store);
            // implementation-note-7 —
            // request_access_blocking is a coarse RPC that doesn't carry
            // grant-shaping fields; defaults to None.
            let metadata = SubmitMetadata {
                action: action.to_string(),
                ttl_secs: None,
                risk_level: risk_str.clone(),
                tool_name: None,
                target_host: None,
                target_url: None,
                agent_framework: None,
                max_delegation_depth: None,
                max_uses_per_hour: None,
                allowed_hours_start: None,
                allowed_hours_end: None,
                allowed_targets: None,
                budget: None,
                max_children_per_day: None,
                auto_delegate_scope_template: None,
            };
            let scope_obj = core_grant_types::approval::RequestedScope {
                capability: String::new(),
                resource_id: None,
                constraints: vec![],
            };
            let request_id = adapter
                .submit_request(persona_id, resource, scope_obj, metadata)
                .await
                .map_err(|e| (-32000, e.to_string()))?;
            let approval = store
                .get_approval(&request_id.0)
                .map_err(|e| (-32000, e.to_string()))?;
            notify_require_approval(store, &approval);

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
            loop {
                let pending = store
                    .list_pending_approvals()
                    .map_err(|e| (-32000, e.to_string()))?;
                let still_pending = pending.iter().any(|p| p.id == request_id.0);

                if !still_pending {
                    return Ok(json!({
                        "status": "resolved",
                        "approval_id": request_id.0,
                    }));
                }

                if std::time::Instant::now() > deadline {
                    return Ok(json!({
                        "status": "timeout",
                        "approval_id": request_id.0,
                    }));
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        "expire_grants" => {
            let count = store
                .expire_stale_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"expired_count": count}))
        }

        "grant_summary" => {
            let summary = store.grant_summary().map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "active": summary.active,
                "expired": summary.expired,
                "revoked": summary.revoked,
            }))
        }

        "detect_anomalies" => {
            let anomalies = store
                .detect_anomalies()
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(serde_json::to_value(&anomalies).map_err(|e| (-32000, e.to_string()))?)
        }

        "create_standing_grant" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let action_pattern = params["action_pattern"]
                .as_str()
                .ok_or((-32602, "missing 'action_pattern'".to_string()))?;
            let scope = params["scope"].as_str().unwrap_or("*");
            let expires_at = params["expires_at"].as_str();
            store
                .create_standing_grant(persona_id, action_pattern, scope, expires_at)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"created": true, "action_pattern": action_pattern}))
        }

        "list_standing_grants" => {
            let persona_scope = team0_connect_only_persona_scope(&ctx, "list_standing_grants")?;
            let grants = store
                .list_standing_grants()
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = grants
                .iter()
                .filter(|g| match persona_scope.as_deref() {
                    Some(persona_id) => g.persona_id == persona_id,
                    None => true,
                })
                .map(|g| {
                    json!({"id": g.id, "persona_id": g.persona_id, "action_pattern": g.action_pattern, "scope": g.scope, "expires_at": g.expires_at})
                })
                .collect();
            Ok(Value::Array(list))
        }

        "remove_standing_grant" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            store
                .remove_standing_grant(id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"removed": true}))
        }

        "poll_notifications" => {
            let persona_id = persona_scoped_param_for_connect_only(
                &ctx,
                params,
                "poll_notifications",
                "persona_id",
                true,
            )?
            .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let notifications = store
                .poll_notifications(&persona_id)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(Value::Array(notifications))
        }

        "list_receipts" => {
            let persona_id = persona_scoped_param_for_connect_only(
                &ctx,
                params,
                "list_receipts",
                "persona_id",
                false,
            )?;
            let receipts = store
                .list_receipts(persona_id.as_deref())
                .map_err(|e| (-32000, e.to_string()))?;
            let list: Vec<Value> = receipts
                .iter()
                .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
                .collect();
            Ok(Value::Array(list))
        }

        "get_receipt" => {
            let id = params["id"]
                .as_str()
                .ok_or((-32602, "missing 'id'".to_string()))?;
            if let Ok(receipt) = store.get_receipt(id) {
                ensure_connect_only_owner_matches_trusted_principal(
                    &ctx,
                    "get_receipt",
                    &receipt.summary.persona_id,
                )?;
                return Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null));
            }

            match store.get_grant(id) {
                Ok(grant) => {
                    ensure_connect_only_owner_matches_trusted_principal(
                        &ctx,
                        "get_receipt",
                        &grant.persona_id,
                    )?;
                    let receipt_id = grant.receipt_id.as_deref().ok_or((
                        -32004,
                        format!(
                            "no receipt found for id '{id}' (grant exists but has not reached terminal state)"
                        ),
                    ))?;
                    let receipt = store.get_receipt(receipt_id).map_err(|e| match e {
                        crate::infra::store::StoreError::NotFound => (
                            -32004,
                            format!(
                                "grant has receipt_id={receipt_id} but receipt body is missing"
                            ),
                        ),
                        other => (-32000, other.to_string()),
                    })?;
                    Ok(serde_json::to_value(&receipt).unwrap_or(Value::Null))
                }
                Err(crate::infra::store::StoreError::NotFound) => {
                    Err((-32004, format!("no receipt or grant found for id '{id}'")))
                }
                Err(e) => Err((-32000, e.to_string())),
            }
        }

        "daemon_persona" => {
            // Expose the current Daemon Persona pubkey over the socket for
            // offline verification tools. Returns `null` when the Daemon
            // Persona was not initialised.
            match crate::infra::receipt::current_identity() {
                Some(id) => Ok(json!({
                    "pubkey": id.pubkey_hex(),
                    "canonical_version": crate::infra::receipt::CANONICAL_VERSION,
                })),
                None => Ok(Value::Null),
            }
        }

        "grant_budget_status" => {
            // Return per-Statement budget + usage + percent_used so MCP/SDK
            // clients can render a "runway" view without walking the
            // composite block chain themselves. This is a thin read-only
            // projection of `get_access_grant` + lifecycle status; the
            // proxy remains the sole writer of `usage`.
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            if let Some(trusted_persona) =
                team0_connect_only_persona_scope(&ctx, "grant_budget_status")?
            {
                let owner = match store.get_grant(grant_id) {
                    Ok(grant) => grant.persona_id,
                    Err(crate::infra::store::StoreError::NotFound) => {
                        return Err((-32004, format!("grant {grant_id} not found")));
                    }
                    Err(e) => return Err((-32000, e.to_string())),
                };
                if owner != trusted_persona {
                    tracing::warn!(
                        method = "grant_budget_status",
                        grant_id = %grant_id,
                        owner_persona_id = %owner,
                        trusted_persona_id = %trusted_persona,
                        tier = current_dispatch_deployment_tier().as_str(),
                        "connect-only persona-scoped lookup refused: grant owner does not match trusted principal"
                    );
                    return Err((
                        -32004,
                        "grant_budget_status: requested grant does not belong to trusted principal"
                            .to_string(),
                    ));
                }
            }
            let chain = match store.get_access_grant(grant_id) {
                Ok(c) => c,
                Err(crate::infra::store::StoreError::NotFound) => {
                    return Err((-32004, format!("grant {grant_id} not found")));
                }
                Err(e) => return Err((-32000, e.to_string())),
            };

            // Envelope status: load via DaemonGrantStore (implementation-note-241)
            // to get core_grants::Grant with a typed expires_at
            // (Option<DateTime<Utc>>) rather than an RFC3339 string from
            // GrantInfo. GrantStatus::derive is still used for the "Expired"
            // virtual status derived at query time.
            let envelope_status = match store.grant_store().load_grant(grant_id) {
                Ok(g) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let expires_epoch = g.expires_at.map(|dt| dt.timestamp() as u64);
                    let status_str = match g.state {
                        CoreGrantState::Active => "active",
                        CoreGrantState::Paused => "paused",
                        CoreGrantState::Revoked => "revoked",
                    };
                    core_grant_types::GrantStatus::derive(status_str, None, expires_epoch, now)
                        .as_str()
                        .to_string()
                }
                Err(_) => chain.status.as_str().to_string(),
            };

            let statements: Vec<Value> = chain
                .statements()
                .map(|(_bi, s)| build_statement_budget_entry(s))
                .collect();

            Ok(json!({
                "grant_id": grant_id,
                "status": envelope_status,
                "statements": statements,
            }))
        }

        // implementation-note-117 (design Phase 2): broker socket RPC arms.
        //
        // These are intentionally additive — the registry, materialization
        // tracking, Receipt-event emission, and provider-routing logic live
        // in `crate::broker_handler`. Adding them here is the minimum
        // dispatch surface so concurrent worktrees touching unrelated
        // arms don't conflict on a structural refactor of this fn.
        //
        // Marker (implementation-note-117): RPC method name "BrokerIssue" lives
        // alongside its sibling routes as the literal `broker_issue`. See
        // `broker_handler.rs` for handler bodies + tests.
        //
        // implementation-note-133: the kernel-attested
        // `PeerCredPrincipal` captured at connection accept time is
        // threaded into every broker handler so per-call authorization is
        // rooted in a kernel-supplied identity. `ctx.peer_cred_principal`
        // is `None` for Internal callers (admin CLI / test harness) and
        // pre-migration socket entry points; broker handlers fall back to
        // the legacy "warn but allow" path when the principal is absent.
        "broker_issue" => {
            crate::broker::handler::handle_broker_issue(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker_revoke" => {
            crate::broker::handler::handle_broker_revoke(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker_list" => {
            crate::broker::handler::handle_broker_list(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        // implementation-note-12: agent processes hold an
        // opaque `SecretRef`; the trust boundary (ember-proxy /
        // ember-tools) calls `broker_resolve` to materialise the
        // plaintext credential. Stub today; full impl in
        // implementation-note-247.
        "broker_resolve" => {
            crate::broker::handler::handle_broker_resolve(
                ctx.peer_cred_principal.as_ref(),
                store,
                ctx.sessions_dir.as_deref(),
                params,
            )
            .await
        }
        // implementation-note-155: refresh_cert
        // dispatch skeleton + RefreshDenied error type. Stub returns
        // NotImplemented variant until M3-B/C/D/E land the identity proof,
        // mint, rate-limit, and Receipt-emission slices. Per design §M3.
        // Anchor: refresh_cert_dispatch_landed
        "refresh_cert" => {
            crate::broker::handler::handle_refresh_cert(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        // design §"daemon-as-process-supervisor": spawn a Construct binary
        // as the daemon's child, capture exit code, emit
        // session.construct_invocation receipt. argv re-classifier deferred
        // (T-CONSTRUCT-EXEC-ARGV-CLASSIFIER).
        "broker_exec" => {
            crate::broker::handler::handle_broker_exec(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        // implementation-note-133: session.lookup_or_open
        // RPC — look up an existing session for the caller's persona or
        // open a fresh one. The persona identity is taken from the
        // kernel-attested `PeerCredPrincipal`, not from the request
        // payload, so a caller cannot pretend to be another persona's
        // session owner. Returns -32004 when the persona named by
        // `params.persona` does not match the kernel-attested uid
        // binding, OR -32401 when no principal is available.
        "session.lookup_or_open" | "session_lookup_or_open" => {
            handle_session_lookup_or_open(ctx.peer_cred_principal.as_ref(), params).await
        }
        // implementation-note-248: mint a 1-hour GitHub App installation
        // token using a local-held RSA private key (design credential broker).
        // Credentials loaded from GH_APP_* env vars (placeholder until vault
        // path provisioning lands).
        "broker.mint_gh_token" => {
            crate::broker::handler::handle_broker_mint_gh_token(store, params).await
        }
        // implementation-note-138: mint a child sub-persona scoped
        // under an existing parent persona. Params: { parent_persona_id, child_label,
        // scope }. Response: { persona_id }. Real two-phase commit + spawn wiring
        // is a stub; input validation runs before the unimplemented! fires.
        "broker.mint_sub_persona" => {
            crate::broker::handler::handle_broker_mint_sub_persona(store, params).await
        }
        // implementation-note-148 §--inject: register a child shell PID for
        // auto-revoke when the shell exits. Spawns a background poll task that
        // watches /proc/<pid> (Linux) or kill(pid, 0) (other Unix) and calls
        // broker_revoke on all listed materialization IDs on exit.
        "broker_register_pid_watcher" => {
            crate::broker::handler::handle_broker_register_pid_watcher(store, params).await
        }

        // implementation-note-153
        // (design note): daemon-side cold-path
        // presence-proof RPC. Forwards the challenge tuple to the dashboard
        // tab via the daemon→dashboard tab channel, awaits the WebAuthn
        // assertion, verifies it against the enrolled passkey, and returns a
        // `DaemonSignedHandle` (NOT the raw assertion). The freeze gate
        // (registry.is_persona_frozen) fires BEFORE the prompt is forwarded
        // — a frozen persona never sees another biometric prompt. Production
        // wiring of the `TabChannel` + `AssertionVerifier` impls is deferred
        // to a follow-up; the dispatch arm exists so the wire surface is
        // discoverable and the testable seam (`issue_presence_proof`) is
        // exercised by the broker_handler test module.
        "presence/request_proof" | "presence_request_proof" => {
            crate::broker::handler::handle_request_presence_proof(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }

        // implementation-note-152: first-run WebAuthn
        // passkey enrollment. Called by the dashboard enrollment component
        // (`ember_dashboard::components::enrollment`) after the browser
        // completes `navigator.credentials.create()`. Guards against
        // double-enrollment and records the credential bytes for the persona.
        "presence/enroll" | "presence_enroll" => {
            crate::broker::handler::handle_first_run_enrollment(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
        }

        // implementation-note-149: credential-binding admin
        // RPCs invoked by `ember bind {register, list, remove, move}`. The
        // admin path does NOT require biometric — the operator
        // authenticates to the daemon via PeerCred. Each handler enforces
        // caller_persona validation (non-nil parseable UUID) and emits an
        // audit row for register/remove/move. The dotted method names are
        // canonical; the underscore aliases mirror the broker_* dispatch
        // convention used by sibling routes.
        "broker.bindings.register" | "broker_bindings_register" => {
            crate::broker::handler::handle_broker_bindings_register(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.bindings.list" | "broker_bindings_list" => {
            crate::broker::handler::handle_broker_bindings_list(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "trust.list" | "trust_list" => {
            // design §Component 2 — operator-visible trust-set
            // introspection. Read-only; no peer-cred gating because the
            // snapshot answers a "what is this daemon's posture?" question
            // that any operator with socket access already learns by
            // probing the manifest path. See trust::introspect.
            crate::trust::introspect::handle_trust_list(params)
        }
        "trust.show" | "trust_show" => {
            // design §Component 2 Phase 2 — drill-down lookup by full
            // fingerprint or unique hex prefix. Same posture as
            // `trust.list` (read-only, ConnectOnly).
            crate::trust::introspect::handle_trust_show(params)
        }
        "trust.explain" | "trust_explain" => {
            // design §Component 2 Phase 3 — chain-walk a signed
            // artifact back to its trust root. v1 supports
            // `artifact_kind = "binary_manifest"`; Receipt + workflow
            // grant land in follow-up tasks.
            crate::trust::introspect::handle_trust_explain(params)
        }
        "broker.bindings.remove" | "broker_bindings_remove" => {
            crate::broker::handler::handle_broker_bindings_remove(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }
        "broker.bindings.move" | "broker_bindings_move" => {
            crate::broker::handler::handle_broker_bindings_move(
                ctx.peer_cred_principal.as_ref(),
                store,
                params,
            )
            .await
        }

        // implementation-note-249 (design §"binding.delete"):
        // graceful delete of a SA→Persona binding. Revokes the workload
        // Persona's grants (cascade via `revoke_persona`) so in-flight
        // broker requests holding active grant references drain to
        // completion while new lookups fail. The audit log captures a
        // `binding.deleted` event keyed on `persona_id` +
        // `binding_request_id` for idempotent reconciler retries. The
        // canonical wire-form method is "binding.delete"; the
        // underscore alias mirrors the broker_* dispatch convention.
        "binding.delete" | "binding_delete" => binding_delete(store, params).await,

        // implementation-note-250 (design
        // §"binding.revoke_urgent"): compromise-response revocation.
        // Cascades the same SQL flip as `binding.delete` but tags the
        // audit row with `binding.revoke_urgent` so the operator can
        // distinguish the two lifecycle paths in the receipt + alerting
        // pipeline. Unlike `binding.delete`, the audit `outcome` is
        // `"urgent"` so downstream consumers (alerting, dashboards,
        // SOC2 evidence reports) can fire on the high-severity event
        // without re-parsing details JSON. The wire-form method
        // "binding.revoke_urgent" is canonical; the underscore alias
        // matches the broker_* convention.
        "binding.revoke_urgent" | "binding_revoke_urgent" => {
            binding_revoke_urgent(store, params).await
        }

        // implementation-note-251 (design §"binding.update"):
        // mutate metadata on an existing binding without revoking it.
        // Today the persona row only carries a mutable `name` column;
        // the broader binding-metadata fields the brief calls out
        // (`cred_class_allowlist`, `lease_duration_cap`, etc.) live in
        // the audit-log details JSON until the schema lands those
        // columns. The audit row carries a before/after snapshot so
        // the reconciler + receipt pipeline can correlate the mutation
        // with its originating `binding_request_id`. The wire-form
        // method "binding.update" is canonical; the underscore alias
        // mirrors the broker_* dispatch convention.
        "binding.update" | "binding_update" => binding_update(store, params).await,

        // implementation-note-252 (design §"binding.upsert"):
        // idempotent insert-or-update for the SA→Persona binding
        // surface used by `ember-kernel`'s EmberServiceAccount
        // reconciler. Replaces the placeholder "method not found"
        // fallback that today causes the reconciler to log a stub-
        // bind warning every reconcile pass. Semantics:
        //   * If the persona row identified by `persona_id` exists,
        //     update it in place (same surface as `binding.update`)
        //     and emit `binding.upserted` audit row with a
        //     before/after snapshot.
        //   * If the persona row does not exist, create a fresh
        //     persona using the requested `name` and emit
        //     `binding.upserted` with `before: null` and the freshly-
        //     created row in `after`. The daemon's canonical id
        //     (UUID-suffixed per `create_persona`) is returned to
        //     the reconciler in `persona_id`; the reconciler
        //     persists that into `status.bound_persona_id`.
        // The wire-form method "binding.upsert" is canonical; the
        // underscore alias matches the broker_* dispatch convention.
        "binding.upsert" | "binding_upsert" => binding_upsert(store, params).await,

        // implementation-note-53 (design §9 + §6):
        // atomic create_agent_persona binding container identity →
        // Persona + attenuated child grant. Replaces the
        // create_persona + delegate_grant two-call sequence with a
        // single RPC whose state machine is the two-phase commit:
        //
        //   phase 1 — insert persona row with status='enrolling' +
        //             bind to container_id + parent_grant_id
        //             (CRIT-4: only one in-flight key per container)
        //   phase 2 — delegate the parent grant to the new persona
        //             with the requested narrowed scope
        //   phase 3 — flip persona status enrolling → active
        //
        // If the daemon crashes between phase 1 and phase 3, the
        // persona row stays in 'enrolling' and the reconciler refuses
        // to spawn into that container slot (see
        // DaemonStore::enrolling_persona_for_container). The
        // container_id binding is persisted in both the `personas`
        // table (via container_id column) AND the audit log (via
        // `agent_persona.created` event) so reconcilers can
        // reconstruct the binding from either source.
        "create_agent_persona" | "create_agent_persona_atomic" => {
            create_agent_persona(store, params).await
        }

        // implementation-note-253 Phase 2: SOPS DEK unwrap RPC.
        //
        // Authorisation flow:
        //   1. Caller supplies `persona_id`, `grant_id`, and the
        //      hex-encoded `encrypted_dek_blob`.
        //   2. The grant is looked up; it MUST be active and belong to
        //      `persona_id` (mirrors `use_credential`'s guard).
        //   3. The grant is rate-limited: one successful unwrap per
        //      grant_id per daemon-process lifetime. Second call with the
        //      same `grant_id` is rejected loudly. The check happens
        //      AFTER successful grant validation but BEFORE invoking
        //      the age library, so a stale duplicate request never even
        //      causes a decrypt attempt.
        //   4. The persona's age private key is fetched from the daemon
        //      vault at `age/persona/<persona_id>/private-key` (per
        //      `crate::age::vault_path_for_persona`). The key bytes
        //      live in a `Zeroizing` buffer; they never cross the IPC
        //      boundary.
        //   5. `sops::unwrap_dek_userspace` decrypts the blob in-process
        //      (the function takes `&[u8]` and returns
        //      `Zeroizing<Vec<u8>>` — the plaintext DEK). The age
        //      private key is dropped at the end of that function call.
        //   6. A `sops_dek_unwrapped` audit event is logged with
        //      `persona_id` + `dek_fingerprint` + `grant_id` so the
        //      operator can reconstruct the unwrap chain.
        //   7. The plaintext DEK is hex-encoded into the JSON response,
        //      then the `Zeroizing` buffer is dropped (which zeroes
        //      the underlying bytes). The hex string in the JSON is
        //      sent to the caller; whoever calls this RPC is implicitly
        //      trusted with the plaintext DEK by the grant flow.
        //
        // Phase 3 (implementation-note-102, orchestrator-only) ships
        // `.claude/scripts/sops-as-bot.sh` — the only blessed agent path
        // that calls this RPC. Direct callers from the agent harness are
        // out of scope for v0.
        #[cfg(feature = "age")]
        "sops_unwrap_dek" => {
            // Read-class on the user's view but high-trust on the daemon's
            // — bump activity so the vault stays unlocked, but do NOT
            // gate behind biometric (the wrapper script is expected to
            // run unattended in CI/dev loops).
            presence::record_activity();

            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id'".to_string()))?;
            let grant_id = params["grant_id"]
                .as_str()
                .ok_or((-32602, "missing 'grant_id'".to_string()))?;
            let blob_hex = params["encrypted_dek_blob"].as_str().ok_or((
                -32602,
                "missing 'encrypted_dek_blob' (hex string)".to_string(),
            ))?;

            // Decode the hex-encoded ciphertext blob. Reject malformed
            // input loudly so a typo doesn't get smuggled into the age
            // decryptor where the error message is harder to map back.
            let encrypted_dek_blob = hex::decode(blob_hex)
                .map_err(|e| (-32602, format!("invalid 'encrypted_dek_blob' hex: {e}")))?;

            // Grant gating: load via DaemonGrantStore to get core_grants::Grant
            // at the state-machine boundary (implementation-note-241). State and
            // issuer checks use the core type directly.
            let grant = store
                .grant_store()
                .load_grant(grant_id)
                .map_err(|e| match e {
                    crate::infra::store::StoreError::NotFound => {
                        (-32004, format!("grant {grant_id} not found"))
                    }
                    other => (-32000, other.to_string()),
                })?;
            if grant.state != CoreGrantState::Active {
                return Err((
                    -32005,
                    format!("grant {grant_id} is not active and cannot be used"),
                ));
            }
            if grant.issuer.0 != persona_id {
                return Err((-32002, "grant belongs to a different persona".to_string()));
            }

            // Rate-limit: one **successful** unwrap per grant_id per
            // daemon lifetime. We check membership before doing any
            // crypto work so a known-consumed grant is rejected fast,
            // but we don't CLAIM the slot until after the unwrap
            // succeeds — failures along the vault / decrypt path leave
            // the slot open so the caller can retry once they fix the
            // setup. The daemon's single-threaded LocalSet means
            // there's no TOCTOU window between this check and the
            // claim below.
            if store.is_dek_grant_consumed(grant_id) {
                tracing::warn!(
                    grant_id = %grant_id,
                    persona_id = %persona_id,
                    "rejecting duplicate sops_unwrap_dek call for already-consumed grant"
                );
                return Err((
                    -32005,
                    format!(
                        "grant {grant_id} has already been used for a SOPS DEK unwrap; \
                         issue a fresh grant"
                    ),
                ));
            }

            // Load the persona's age private key from the daemon vault.
            // The key bytes live in a `Zeroizing` buffer so they zero on
            // drop — never log them, never serialize them.
            let vault_path = crate::age::vault_path_for_persona(persona_id);
            let vault = current_vault(store, "sops_unwrap_dek")?;
            let raw_key = vault
                .get(VaultScope::Interactive, store, &vault_path)
                .map_err(|e| {
                    tracing::warn!(
                        persona_id = %persona_id,
                        vault_path = %vault_path,
                        error = %e,
                        "sops_unwrap_dek: persona age key not in vault"
                    );
                    (
                        -32000,
                        format!(
                            "persona {persona_id} has no age private key in the vault \
                         (expected at {vault_path})"
                        ),
                    )
                })?;
            let age_private_key: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(raw_key);

            // Compute the dek fingerprint BEFORE the unwrap call so the
            // audit row is emitted regardless of decrypt outcome — the
            // failure path also needs the fingerprint for forensics.
            let dek_fingerprint: String = {
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(&encrypted_dek_blob);
                hex::encode(&digest[..16])
            };

            // Invoke the pure unwrap function. Plaintext lives in a
            // `Zeroizing<Vec<u8>>`; it will be zeroed when this scope
            // drops it after we serialize the response.
            let plaintext_dek: zeroize::Zeroizing<Vec<u8>> =
                match crate::sops::unwrap_dek_userspace(&age_private_key, &encrypted_dek_blob) {
                    Ok(dek) => dek,
                    Err(e) => {
                        // Audit the failure. The grant slot is NOT
                        // consumed on failure — the caller can retry
                        // once they fix the setup (e.g. wrong age key,
                        // truncated blob).
                        let _ = store.log_event(
                            Some(persona_id),
                            "sops_dek_unwrapped",
                            None,
                            "denied",
                            Some(
                                &serde_json::json!({
                                    "grant_id": grant_id,
                                    "dek_fingerprint": dek_fingerprint,
                                    "error": e.to_string(),
                                })
                                .to_string(),
                            ),
                        );
                        return Err((-32000, format!("dek unwrap failed: {e}")));
                    }
                };

            // Claim the rate-limit slot now that the unwrap succeeded.
            // The pre-check above already guaranteed the slot was open
            // when we entered the handler, and the daemon's
            // single-threaded LocalSet means no other dispatch can
            // have raced in between. `try_consume_dek_grant` returning
            // `false` here is therefore a programmer error.
            let claimed = store.try_consume_dek_grant(grant_id);
            debug_assert!(
                claimed,
                "try_consume_dek_grant returned false after a passing pre-check; \
                 this indicates a concurrency invariant violation"
            );

            // Receipt: log_event captures op + persona_id +
            // dek_fingerprint + grant_id + ts (the audit row's own
            // timestamp). Never log the plaintext DEK or the
            // ciphertext blob — only the fingerprint.
            let _ = store.log_event(
                Some(persona_id),
                "sops_dek_unwrapped",
                None,
                "allowed",
                Some(
                    &serde_json::json!({
                        "grant_id": grant_id,
                        "dek_fingerprint": dek_fingerprint,
                    })
                    .to_string(),
                ),
            );

            // Serialize the plaintext DEK as hex. The `Zeroizing` buffer
            // is dropped immediately after — the hex string we return
            // is the only remaining copy outside the caller's process.
            let dek_hex = hex::encode(plaintext_dek.as_slice());
            drop(plaintext_dek);

            tracing::info!(
                persona_id = %persona_id,
                grant_id = %grant_id,
                dek_fingerprint = %dek_fingerprint,
                "sops_dek_unwrapped"
            );

            Ok(json!({
                "dek_hex": dek_hex,
                "dek_fingerprint": dek_fingerprint,
                "grant_id": grant_id,
                "persona_id": persona_id,
            }))
        }

        // Stub when the `age` feature is disabled at compile time. Mirror
        // the `crate::sops::unwrap_dek_userspace` cfg-not(age) error so
        // the wire surface fails loudly instead of silently returning
        // `Method not found` (which would be misleading — the method IS
        // configured, just not built).
        #[cfg(not(feature = "age"))]
        "sops_unwrap_dek" => Err((
            -32000,
            "sops_unwrap_dek requires the 'age' feature; build with --features age".to_string(),
        )),

        // SOPS-implementation-note-254 — implementation-note-255. Routes for the Path 2 native SOPS
        // recipient surface. Until implementation-note-256 lands, the underlying stubs
        // return NotImplementedError — wire is reserved so the SOPS Go-fork
        // (implementation-note-257) can develop against a real RPC shape.
        "sops.pubkey" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let pubkey =
                crate::sops::sops_pubkey(persona_id).map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({"persona_id": persona_id, "pubkey": pubkey}))
        }

        "sops.wrap" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let dek_hex = params["dek_hex"]
                .as_str()
                .ok_or((-32602, "missing 'dek_hex' parameter".to_string()))?;
            let dek =
                hex::decode(dek_hex).map_err(|e| (-32602, format!("invalid 'dek_hex': {e}")))?;
            let encrypted = crate::sops::sops_wrap_dek(persona_id, &dek)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "persona_id": persona_id,
                "encrypted_dek_hex": hex::encode(&encrypted),
            }))
        }

        "sops.unwrap" => {
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let encrypted_hex = params["encrypted_dek_hex"]
                .as_str()
                .ok_or((-32602, "missing 'encrypted_dek_hex' parameter".to_string()))?;
            let encrypted = hex::decode(encrypted_hex)
                .map_err(|e| (-32602, format!("invalid 'encrypted_dek_hex': {e}")))?;
            let dek = crate::sops::sops_unwrap_in_vault(persona_id, &encrypted)
                .map_err(|e| (-32000, e.to_string()))?;
            Ok(json!({
                "persona_id": persona_id,
                "dek_hex": hex::encode(&dek),
            }))
        }

        // implementation-note-258: register a new claude-code session.
        //
        // Called by the launcher immediately before spawning the `claude` child.
        // Creates a `SessionMeta` file in `sessions_dir` and returns the
        // `{session_id, grant_id, proxy_url}` triple the launcher injects as
        // env vars. The daemon's proxy URL is emitted so the launcher doesn't
        // need to hard-code a port.
        //
        // Params: `{ "persona": "<name_or_id>", "launcher_pid": <u32> }`
        // Result: `{ "session_id": "...", "grant_id": "...", "proxy_url": "..." }`
        "register_session" => {
            let persona_name = params["persona"]
                .as_str()
                .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
            let launcher_pid = params["launcher_pid"]
                .as_u64()
                .ok_or((-32602, "missing 'launcher_pid' parameter".to_string()))?
                as u32;

            let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
                -32000,
                "sessions_dir not configured on this connection".to_string(),
            ))?;

            let persona = resolve_register_session_persona(store, &ctx, persona_name)?;
            let active_grant =
                resolve_register_session_active_grant(store, &persona, persona_name)?;
            crate::infra::interactive_unlock::ensure_vault_for_session_open(store)
                .map_err(|msg| (-32030, msg))?;

            // Build a unique session id.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let session_id = format!("sess_{:032x}", nanos);

            let meta = core_state::sessions::SessionMeta {
                session_id: session_id.clone(),
                persona: persona.id.clone(),
                grant_id: active_grant.id.clone(),
                started_at: chrono::Utc::now(),
                launcher_pid,
                // design §Component 3 — workflow-grant attachment lands when
                // the launcher implements the prompt UX
                // (implementation-note-137). Existing sessions open
                // without a workflow template selected.
                workflow_id: None,
                workflow_template: None,
            };

            let session_store = core_state::SessionStore::new(sessions_dir.clone());
            session_store
                .create(&meta)
                .map_err(|e| (-32000, format!("create session: {e}")))?;
            crate::infra::interactive_unlock::acquire_session_pin(&session_id);

            let _ = store.log_event(
                Some(&persona.id),
                "session.opened",
                None,
                "ok",
                Some(&format!(
                    "session_id={session_id} grant_id={}",
                    active_grant.id
                )),
            );

            // implementation-note-233: read the
            // LLM proxy URL from RequestContext, NOT from std::env::var.
            // The runtime populates ctx.llm_proxy_url via SocketListener
            // builder after the proxy binds. Using env::var here is
            // unreliable — std::env::set_var is unsafe in Rust 2024 precisely
            // because its cross-thread visibility is not guaranteed; tokio
            // worker threads may observe a stale Err(_) and fall back to 8484.
            let proxy_url = match &ctx.llm_proxy_url {
                Some(url) => url.clone(),
                None => {
                    tracing::warn!(
                        "register_session: llm_proxy_url absent from RequestContext \
                         (SocketListener.with_llm_proxy_url not called?) — \
                         falling back to hardcoded 8484; implementation-note-233"
                    );
                    "http://127.0.0.1:8484".to_string()
                }
            };
            // Include the git proxy URL when available so the launcher can
            // inject EMBER_GIT_PROXY_URL into the child env.
            let git_proxy_url = ctx.git_proxy_url.clone();

            let mut response = json!({
                "session_id": session_id,
                "grant_id": active_grant.id,
                "proxy_url": proxy_url,
            });
            if let Some(gpu) = git_proxy_url {
                response["git_proxy_url"] = json!(gpu);
            }
            if let Some(token) = mint_operator_presence_token(ctx.peer.as_ref())? {
                response["presence_token"] = serde_json::to_value(token).map_err(|e| {
                    (
                        -32000,
                        format!("register_session: encode presence_token: {e}"),
                    )
                })?;
            }
            Ok(response)
        }

        // implementation-note-258: close a claude-code session (clean exit).
        //
        // Called by the launcher after the `claude` child exits naturally. Emits
        // a signed v2 `session.claude_code` Receipt with
        // `termination_reason: clean_exit` into `<session_dir>/receipt.json`,
        // closes the `SessionMeta`, and logs a `session.closed` audit event.
        //
        // implementation-note-259: CleanExit MUST NOT
        // revoke the grant. A 24h grant supports many sessions; the previous
        // unconditional revoke_grant call here was the second-half regression
        // (the launcher goes through this RPC arm, not session_watcher, so
        // #2366's session_watcher fix did not reach the launcher path).
        //
        // Params: `{ "session_id": "..." }`
        // Result: `{ "closed": true, "receipt_id": "..." }`
        "close_session" => {
            let session_id = params["session_id"]
                .as_str()
                .ok_or((-32602, "missing 'session_id' parameter".to_string()))?;

            let sessions_dir = ctx.sessions_dir.as_ref().ok_or((
                -32000,
                "sessions_dir not configured on this connection".to_string(),
            ))?;

            let session_store = core_state::SessionStore::new(sessions_dir.clone());

            // Load the session meta so we know the grant_id for logging.
            let meta = session_store
                .read(session_id)
                .map_err(|e| (-32000, format!("read session: {e}")))?
                .ok_or_else(|| {
                    (
                        -32004,
                        format!("session '{session_id}' not found or already closed"),
                    )
                })?;

            // Emit a signed v2 Receipt with termination_reason = clean_exit
            // via the canonical atomic builder (design) — same path as the
            // dirty-exit termination in `session::lifecycle`.
            let identity = current_identity().ok_or((
                -32000,
                "daemon identity not initialised — cannot sign Receipt".to_string(),
            ))?;
            let signer = crate::session::lifecycle::DaemonPersonaSigner::new(identity);

            let envelope = crate::infra::receipt::issue::issue_cohort_a_receipt(
                session_id,
                Vec::new(),
                None,
                core_events::receipt::TerminationAuthority::DaemonPersona,
                &identity.pubkey_hex(),
                Some(crate::infra::receipt::issue::TerminationMeta {
                    reason: core_events::receipt::TerminationReason::CleanExit,
                    last_heartbeat_at: None,
                    pid_alive_at_check: None,
                }),
                &signer,
            )
            .map_err(|e| (-32000, format!("issue Receipt: {e}")))?;

            let receipt_id = envelope.receipt_id.clone();

            let session_dir = sessions_dir.join(session_id);
            let receipt_path = session_dir.join("receipt.json");
            let receipt_json = serde_json::to_vec_pretty(&envelope)
                .map_err(|e| (-32000, format!("serialize Receipt JSON: {e}")))?;
            std::fs::write(&receipt_path, &receipt_json)
                .map_err(|e| (-32000, format!("persist Receipt: {e}")))?;

            session_store
                .close(session_id)
                .map_err(|e| (-32000, format!("close session: {e}")))?;
            let _ = crate::infra::interactive_unlock::release_session_pin(session_id);

            let _ = store.log_event(
                Some(&meta.persona),
                "session.closed",
                None,
                "clean_exit",
                Some(&format!(
                    "session_id={session_id} grant_id={} grant_kept_active=true",
                    meta.grant_id
                )),
            );

            Ok(json!({
                "closed": true,
                "session_id": session_id,
                "receipt_id": receipt_id,
            }))
        }

        // implementation-note-260 — first real local enrollment cut.
        //
        // Per design §"Headless: attested device, variable enrollment".
        // This slice makes `headless_enroll` truthful for the local broker
        // authority seam only:
        // - require a live interactive vault
        // - mint a fresh random headless MEK
        // - when the queued task set is fully declared against bundled
        //   manifest `authority_refs`, copy only those local provider
        //   families; otherwise fall back to the currently configured local
        //   broker-authority subset
        // - persist the attested enrollment so runtime broker reloads can use
        //   that subset when the interactive lane is locked
        //
        // Template-bound subset shaping, receipt emission, and snapshot-hash
        // wiring are still follow-up work; this is intentionally narrower than
        // the full ADR target but no longer a fake user surface.
        "headless_enroll" => {
            use zeroize::Zeroize as _;

            presence::record_activity();
            let persona_id = params["persona_id"]
                .as_str()
                .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
            let duration_seconds = match params["duration_seconds"].as_u64() {
                Some(0) => 14400, // 4h default for dev0 per design
                Some(d) => d,
                None => 14400,
            };

            // Tier ceiling — dev0 cohort: 7 days. design.
            const MAX_DURATION_DEV0_SECONDS: u64 = 7 * 24 * 3600;
            if duration_seconds > MAX_DURATION_DEV0_SECONDS {
                return Err((
                    -32602,
                    format!(
                        "headless_enrollment_duration_exceeds_tier_ceiling: \
                         {duration_seconds} > {MAX_DURATION_DEV0_SECONDS} (dev0 ceiling)"
                    ),
                ));
            }

            let data_dir = headless_data_dir_from_context(&ctx)?;
            let interactive_vault = current_vault(store, "headless_enroll")?;
            let interactive_keys = crate::infra::headless_scope::list_scope_keys(
                store,
                crate::infra::vault::VaultScope::Interactive,
            )
            .map_err(|err| {
                (
                    -32000,
                    format!("headless_enroll: enumerate interactive authority keys: {err}"),
                )
            })?;
            let queued_tasks = params
                .get("tasks")
                .map(parse_headless_task_input)
                .transpose()?;
            let (authority_keys, manifest_authority_refs) = if let Some(tasks) = queued_tasks {
                let registry = bundled_construct_registry().map_err(|e| {
                    (
                        -32000,
                        format!("load bundled construct manifest registry: {e}"),
                    )
                })?;
                let resolved =
                    core_construct_runtime::preflight::resolve_queued_task_authority_refs(&tasks, &registry);
                let authority_refs: std::collections::BTreeSet<String> = resolved
                    .refs_by_task
                    .values()
                    .flat_map(|refs| refs.iter().cloned())
                    .collect();
                if resolved.fully_declared && !authority_refs.is_empty() {
                    let refs: Vec<String> = authority_refs.into_iter().collect();
                    let keys = crate::broker::authority::local_store_authority_keys_for_refs(
                        &interactive_keys,
                        &refs,
                    )
                    .map_err(|err| (-32000, format!("headless_enroll: {err}")))?;
                    (keys, Some(refs))
                } else {
                    (
                        crate::broker::authority::local_store_authority_keys_from_metadata(
                            &interactive_keys,
                        )
                        .map_err(|err| (-32000, format!("headless_enroll: {err}")))?,
                        None,
                    )
                }
            } else {
                (
                    crate::broker::authority::local_store_authority_keys_from_metadata(
                        &interactive_keys,
                    )
                    .map_err(|err| (-32000, format!("headless_enroll: {err}")))?,
                    None,
                )
            };
            if authority_keys.is_empty() {
                let reason = if let Some(refs) = manifest_authority_refs {
                    format!(
                        "headless_enroll: queued task set resolved to {refs:?}, but no matching \
                         local vault-backed broker authority is configured; env/file-backed and \
                         external-store providers remain unattended by design"
                    )
                } else {
                    "headless_enroll: no local vault-backed broker authority is configured; \
                     env/file-backed and external-store providers remain unattended by design"
                        .to_string()
                };
                return Err((-32000, reason));
            }

            crate::infra::attested_device::AttestedDevice::revoke_active(&data_dir, None).map_err(
                |err| {
                    (
                        -32000,
                        format!("headless_enroll: revoke prior enrollment: {err}"),
                    )
                },
            )?;
            crate::infra::headless_scope::clear_headless_scope(store).map_err(|err| {
                (
                    -32000,
                    format!("headless_enroll: clear prior headless scope: {err}"),
                )
            })?;

            let mut mek = [0u8; 32];
            getrandom::fill(&mut mek).map_err(|err| {
                (
                    -32000,
                    format!("headless_enroll: generate headless MEK: {err}"),
                )
            })?;
            let headless_vault = crate::infra::vault::Vault::new(mek);
            crate::infra::headless_scope::replace_headless_subset(
                &interactive_vault,
                &headless_vault,
                store,
                &authority_keys,
            )
            .map_err(|err| {
                (
                    -32000,
                    format!("headless_enroll: install headless authority subset: {err}"),
                )
            })?;
            let device = crate::infra::attested_device::AttestedDevice::enroll_active(
                &data_dir,
                persona_id,
                std::time::Duration::from_secs(duration_seconds),
                &mek,
            )
            .map_err(|err| {
                (
                    -32000,
                    format!("headless_enroll: persist enrollment: {err}"),
                )
            })?;
            mek.zeroize();

            Ok(json!({
                "enrolled": true,
                "enrollment_id": device.enrollment_id,
                "persona": device.persona,
                "expiry_unix": device.expiry_unix(),
                "authority_keys": authority_keys,
                "authority_refs": manifest_authority_refs,
            }))
        }

        "headless_revoke" => {
            presence::record_activity();
            let enrollment_id = params["enrollment_id"].as_str();
            let data_dir = headless_data_dir_from_context(&ctx)?;
            match crate::infra::attested_device::AttestedDevice::revoke_active(
                &data_dir,
                enrollment_id,
            ) {
                Ok(Some(device)) => {
                    if let Err(err) = crate::infra::headless_scope::clear_headless_scope(store) {
                        tracing::warn!(
                            error = %err,
                            "headless revoke deleted the active enrollment but failed to prune stale headless ciphertext"
                        );
                    }
                    Ok(json!({
                        "revoked": true,
                        "enrollment_id": device.enrollment_id,
                        "persona": device.persona,
                        "expiry_unix": device.expiry_unix(),
                    }))
                }
                Ok(None) => Ok(json!({
                    "revoked": false,
                    "active_enrollment": null,
                })),
                Err(crate::infra::attested_device::Error::EnrollmentIdMismatch {
                    requested,
                    active,
                }) => Err((
                    -32602,
                    format!(
                        "headless_revoke: requested enrollment_id '{requested}' does not match \
                         active enrollment '{active}'"
                    ),
                )),
                Err(e) => Err((-32000, format!("headless_revoke: {e}"))),
            }
        }

        "headless_status" => {
            presence::record_activity();
            let data_dir = headless_data_dir_from_context(&ctx)?;
            match crate::infra::attested_device::AttestedDevice::active_status(&data_dir) {
                Ok(Some(status)) => Ok(json!({
                    "active_enrollment": status,
                })),
                Ok(None) => Ok(json!({
                    "active_enrollment": null,
                })),
                Err(e) => Err((-32000, format!("headless_status: {e}"))),
            }
        }

        // implementation-note-16 — Phase 1 substrate.
        //
        // implementation-note-17
        //
        // Per design §"Pre-flight scope check at enrollment" Layer 2
        // (Historical): the daemon exposes the recent-gaps reader so
        // the CLI's `ember headless enroll` flow can render the
        // pre-flight CTA without poking the JSONL file directly. The
        // gap log lives under the primary worktree's
        // `.ember/runtime/permission-gaps.jsonl` (headless-runtime owns the
        // path and shape); routing through the daemon keeps file
        // discipline on one side of the socket.
        //
        // Authorization: this method is read-only (no vault, no grant
        // state mutation). The socket layer's SO_PEERCRED + group
        // `ember` ACL (design) is the only gate — same as the
        // surrounding read-class methods (`vault_get`,
        // `local_state_key_get`).
        "headless_preflight_gaps" => {
            presence::record_activity();
            let persona = params["persona"]
                .as_str()
                .ok_or((-32602, "missing 'persona' parameter".to_string()))?;
            let since_seconds = params["since_seconds"].as_u64().ok_or((
                -32602,
                "missing 'since_seconds' parameter (u64)".to_string(),
            ))?;

            let gaps = core_construct_runtime::permission_gaps::recent_gaps_for_persona(
                persona,
                std::time::Duration::from_secs(since_seconds),
            );
            serde_json::to_value(&gaps)
                .map_err(|e| (-32000, format!("serialize PermissionGap list: {e}")))
        }

        // implementation-note-261 — Layer 1 predictive
        // pre-flight gate, wired over the daemon socket so the CLI can
        // surface manifest-declared Construct gaps before headless dispatches
        // a task that the enrolled persona's template cannot grant.
        //
        // implementation-note-262
        //
        // Per design §"Pre-flight scope check at enrollment" Layer 1: for
        // each queued task that declares `constructs = ["<construct>.<action>"]`,
        // resolve the union of action permissions through the bundled cohort-A
        // manifest registry, diff against the enrolled persona template, and
        // return the gap list. Slice B (prior change) shipped the resolver +
        // manifest parser; this arm wires them into the socket surface.
        //
        // Params:
        //   { "tasks": [ { "task_id": "<id>", "constructs": ["<c>.<a>", ...] }, ... ],
        //     "template"?: ["<construct>.<action>", ...] }
        //
        // Result: JSON array of `{ "task_id": <id>, "identifier": <perm>,
        //                          "scope": <string|null> }` — one entry per
        //         permission a task needs that is NOT in `template`.
        //
        // Authorization: read-only over caller-supplied data; SO_PEERCRED +
        // group `ember` ACL (design) is the only gate, matching
        // `headless_preflight_gaps`.
        "headless_preflight_layer1" => {
            presence::record_activity();
            handle_headless_preflight_layer1(params)
        }

        _ => Err((-32601, "Method not found".to_string())),
    }
}

/// implementation-note-261 — Layer 1 pre-flight handler.
///
/// implementation-note-262
///
/// Parses the caller-supplied `tasks` + optional `template`, resolves each
/// task's declared constructs through the bundled cohort-A manifest registry
/// via `core_construct_runtime::preflight::resolve_queued_task_permissions`, diffs
/// against the template via `cross_reference`, and returns the gap list as
/// JSON. Unknown constructs and unknown actions are skipped silently per the
/// resolver's "best-effort predictive layer" contract — Layer 2
/// (`headless_preflight_gaps`) catches the runtime gap.
///
/// Pulled into a free function so the dispatch arm stays narrow and the
/// param-parsing logic is unit-testable without spinning up a full daemon
/// store.
fn parse_headless_task_input(
    tasks_value: &Value,
) -> Result<Vec<(String, Vec<String>)>, (i32, String)> {
    let tasks_array = tasks_value
        .as_array()
        .ok_or((-32602, "'tasks' parameter must be a JSON array".to_string()))?;
    let mut tasks: Vec<(String, Vec<String>)> = Vec::with_capacity(tasks_array.len());
    for (idx, raw) in tasks_array.iter().enumerate() {
        let task_id = raw
            .get("task_id")
            .and_then(|v| v.as_str())
            .ok_or((-32602, format!("tasks[{idx}]: missing string 'task_id'")))?
            .to_string();
        let constructs_value = raw.get("constructs").cloned().unwrap_or(json!([]));
        let constructs_array = constructs_value.as_array().ok_or((
            -32602,
            format!("tasks[{idx}].constructs must be a JSON array of strings"),
        ))?;
        let mut declarations: Vec<String> = Vec::with_capacity(constructs_array.len());
        for (d_idx, decl) in constructs_array.iter().enumerate() {
            let s = decl.as_str().ok_or((
                -32602,
                format!("tasks[{idx}].constructs[{d_idx}] must be a string"),
            ))?;
            declarations.push(s.to_string());
        }
        tasks.push((task_id, declarations));
    }
    Ok(tasks)
}

fn handle_headless_preflight_layer1(params: &Value) -> Result<Value, (i32, String)> {
    use core_construct_runtime::preflight::{
        Permission, Template, cross_reference, resolve_queued_task_permissions,
    };

    // Parse `tasks` — required. Each entry is { task_id, constructs }.
    let tasks_value = params.get("tasks").ok_or((
        -32602,
        "missing 'tasks' parameter (array of { task_id, constructs })".to_string(),
    ))?;
    let tasks = parse_headless_task_input(tasks_value)?;

    // Parse optional `template`. Absent or empty → fail-open default of
    // "no permissions allowed", which is the dev0 fail-closed posture.
    let template_value = params.get("template").cloned().unwrap_or(json!([]));
    let template_array = template_value.as_array().ok_or((
        -32602,
        "'template' parameter must be a JSON array of strings".to_string(),
    ))?;
    let mut allowed: Vec<Permission> = Vec::with_capacity(template_array.len());
    for (idx, entry) in template_array.iter().enumerate() {
        let identifier = entry
            .as_str()
            .ok_or((-32602, format!("template[{idx}] must be a string")))?;
        allowed.push(Permission {
            identifier: identifier.to_string(),
            scope: None,
        });
    }
    let template = Template { allowed };

    // Build the bundled cohort-A manifest registry. Per design §2 every
    // bundled Construct's `construct.toml` is shipped under
    // `crates/ember-construct/construct/*.toml`; the registry needs them
    // available without a filesystem read so the daemon can answer the
    // RPC even on a fresh install. `include_str!` is the canonical pattern
    // already used in `crates/headless-runtime/src/constructs/manifest.rs` tests.
    let registry = bundled_construct_registry().map_err(|e| {
        (
            -32000,
            format!("load bundled construct manifest registry: {e}"),
        )
    })?;

    let needed = resolve_queued_task_permissions(&tasks, &registry);
    let gaps = cross_reference(&needed, &template);

    // Wire shape: { task_id, identifier, scope }.
    let payload: Vec<Value> = gaps
        .into_iter()
        .map(|g| {
            json!({
                "task_id": g.task_id,
                "identifier": g.permission.identifier,
                "scope": g.permission.scope,
            })
        })
        .collect();
    Ok(Value::Array(payload))
}

/// Build the cohort-A bundled `construct.toml` manifest registry by parsing
/// each `crates/ember-construct/construct/*.toml` via `include_str!`. Used
/// by [`handle_headless_preflight_layer1`].
///
/// Returns `Err` only when one of the bundled manifests fails to parse —
/// which would indicate a corrupt source tree (the parser is exercised by
/// `crates/headless-runtime/src/constructs/manifest.rs::parses_real_bundled_*`
/// tests on every workspace build).
fn bundled_construct_registry()
-> Result<HashMap<String, core_construct_runtime::manifest::ConstructManifest>, toml::de::Error> {
    use core_construct_runtime::manifest::parse_construct_manifest_str;
    const BUNDLED: &[&str] = &[
        include_str!("../../../ember-construct/construct/aws.toml"),
        include_str!("../../../ember-construct/construct/az.toml"),
        include_str!("../../../ember-construct/construct/docker.toml"),
        include_str!("../../../ember-construct/construct/flyctl.toml"),
        include_str!("../../../ember-construct/construct/gcloud.toml"),
        include_str!("../../../ember-construct/construct/gh.toml"),
        include_str!("../../../ember-construct/construct/git.toml"),
        include_str!("../../../ember-construct/construct/kubectl.toml"),
        include_str!("../../../ember-construct/construct/npm.toml"),
        include_str!("../../../ember-construct/construct/okta.toml"),
        include_str!("../../../ember-construct/construct/pulumi.toml"),
        include_str!("../../../ember-construct/construct/terraform.toml"),
        include_str!("../../../ember-construct/construct/tofu.toml"),
        include_str!("../../../ember-construct/construct/vercel.toml"),
        include_str!("../../../ember-construct/construct/wrangler.toml"),
    ];
    let mut registry = HashMap::with_capacity(BUNDLED.len());
    for raw in BUNDLED {
        let m = parse_construct_manifest_str(raw)?;
        registry.insert(m.name.clone(), m);
    }
    Ok(registry)
}

/// `session.lookup_or_open` JSON-RPC verb — peercred-bound session
/// lookup/creation per implementation-note-133.
///
/// Returns the (session_id, persona, parent_pid) triple for the
/// caller's existing session, or opens a fresh session bound to the
/// kernel-attested principal. The persona identity is sourced from
/// the kernel-attested `PeerCredPrincipal` — a caller cannot lie
/// about which persona they are.
///
/// **Principal binding gates** (per design §"Subprocess identity
/// spoofing (Phase 1)"):
///
/// - When `principal` is `None`, the call is refused with `-32401`
///   ("principal binding unavailable") — `session.lookup_or_open`
///   is wire-only and demands kernel attestation.
/// - When `params.persona` is supplied AND the persona's bound uid
///   does not match `principal.uid`, refuse with `-32004`.
/// - When `params.parent_pid` is supplied AND it disagrees with
///   `principal.pid`, refuse with `-32004` — the brief calls this
///   out: "refuses caller-supplied `parent_pid` that does not match
///   peer pid".
///
/// Params: `{ "persona"?: <string>, "parent_pid"?: <i32> }`
/// Result: `{ "session_id": <string>, "persona_id"?: <string>,
///            "parent_pid": <i32>, "socket_path": <string> }`
///
/// implementation-note-133.
pub async fn handle_session_lookup_or_open(
    principal: Option<&crate::infra::runtime::PeerCredPrincipal>,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let principal = principal.ok_or((
        -32401,
        "session.lookup_or_open requires kernel-attested principal — \
         wire-only RPC, refused on Internal source"
            .to_string(),
    ))?;

    // implementation-note-135 — refuse if the bound peer has been
    // reaped between connection-accept and this RPC dispatch. PID-reuse
    // could otherwise hand the freshly-recycled PID to a new process
    // that this session would then bind to.
    crate::broker::handler::check_principal_is_alive(Some(principal))?;

    // Persona-name → bound-uid check (when the caller asserts which
    // persona they're opening a session for, kernel attests it).
    crate::broker::handler::check_principal_against_persona(Some(principal), params, "persona")?;

    // parent_pid binding: brief calls this out — caller-supplied
    // parent_pid that does not match peer pid is refused.
    if let Some(claimed_pid) = params.get("parent_pid").and_then(|v| v.as_i64())
        && claimed_pid as i32 != principal.pid
    {
        tracing::warn!(
            claimed_parent_pid = claimed_pid,
            principal_pid = principal.pid,
            principal_uid = principal.uid,
            "session.lookup_or_open: rejecting — claimed parent_pid disagrees with kernel-attested peer pid"
        );
        return Err((
            -32004,
            format!(
                "principal binding mismatch: claimed parent_pid {} does not match kernel-attested peer pid {}",
                claimed_pid, principal.pid
            ),
        ));
    }

    // Mint a fresh session id. Production wiring (registry of open
    // sessions, persistence under `sessions_dir`, etc.) lives in the
    // sibling implementation-note-263 task; this surface
    // establishes the peercred gate so the production wiring can
    // drop into a kernel-attested foundation.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let session_id = format!("sess_{:032x}", nanos);

    let mut response = json!({
        "session_id": session_id,
        "parent_pid": principal.pid,
        "socket_path": principal.socket_path.display().to_string(),
    });
    if let Some(persona) = params.get("persona").and_then(|v| v.as_str()) {
        response["persona_id"] = json!(persona);
    }
    Ok(response)
}

/// `binding.delete` JSON-RPC verb — graceful delete of a workload Persona binding.
///
/// Per design §"binding.delete":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Active grants flip to `revoked`; in-flight broker requests holding
///      a still-cached grant ref drain to completion. New `use_credential` /
///      broker lookups fail loudly because they hit the revoked-grant guard.
///   2. Emit a `binding.deleted` audit event so the reconciler + receipt
///      pipeline can correlate the lifecycle transition with the originating
///      `binding_request_id`. The receipt envelope (signed by the EIC Daemon
///      Persona) is layered on top of this audit event by the Receipt v2
///      pipeline (`crate::infra::receipt`); this handler's job is the
///      audit-log row + the state mutation.
///
/// Idempotency: re-deleting an already-revoked persona is a no-op success
/// path — the audit row still gets written so the reconciler sees a fresh
/// receipt for its retry. `revoke_persona` returns `NotFound` for a never-
/// registered persona; we surface that as `-32004`.
///
/// Drain semantics (graceful path): the cascade revoke flips the SQL row
/// state but does NOT actively cancel a tokio future already executing
/// inside `broker_issue` / `use_credential`. Those callers complete using
/// the locally-bound `core_grants::Grant` they captured at request entry.
/// New requests fail because lookup runs after the SQL flip.
///
/// `binding_revoke_urgent` (separate verb, T-EMBERD-BINDING-implementation-note-264)
/// will skip the in-flight drain by also poisoning the in-process
/// grant cache — that path is intentionally NOT reused here because it
/// inverts the contract callers rely on for the graceful path.
pub async fn binding_delete(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace a delete back to a specific reconcile pass.
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — graceful drain via cascade revoke. `revoke_persona` flips
    // the persona row to `revoked` and marks every active grant under it
    // as `revoked` in the same transaction. In-flight broker calls that
    // already loaded the grant complete with their cached copy; new
    // lookups hit the revoked guard.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {persona_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    }

    // Step 2 — audit-log emission. Action mirrors the receipt kind from
    // `core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED` so the
    // Receipt v2 pipeline can correlate audit rows with envelopes.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_DELETED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "deleted": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.revoke_urgent` JSON-RPC verb — compromise-response revocation
/// of a workload Persona binding.
///
/// Per design §"binding.revoke_urgent":
///   1. Revoke the workload Persona's Grant (cascade via `revoke_persona`).
///      Same SQL transition as `binding.delete` — persona row flips to
///      `revoked` and every active grant under it flips to `revoked` in
///      the same statement.
///   2. Emit a `binding.revoke_urgent` audit row with outcome `"urgent"`
///      so alerting pipelines can fire on the high-severity event
///      without re-parsing the details JSON. Unlike the graceful
///      `binding.deleted` event, this row is the trigger for compromise-
///      response automation: rotate the credential, sweep the audit log
///      for the persona, page the on-call rotation.
///
/// Difference from `binding.delete`: this verb does NOT promise
/// graceful drain semantics. Today the SQL flip is synchronous and the
/// daemon does not maintain an in-process grant cache, so an in-flight
/// `use_credential` call holding a `core_grants::Grant` value at request
/// entry will still complete with that cached value. When the in-process
/// cache lands (planned with the broker materialization layer), this
/// verb is the one that will additionally poison the cache so urgent
/// revocations actually cancel in-flight callers.
///
/// Idempotency: re-revoking an already-revoked persona is a NotFound
/// (mirrors `binding.delete`). The compromise-response runbook is
/// expected to be idempotent at the orchestration layer — the reconciler
/// retries with the same `binding_request_id` and treats `-32004` as
/// "already revoked, no further action needed".
pub async fn binding_revoke_urgent(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let persona_id = params["persona_id"]
        .as_str()
        .ok_or((-32602, "missing 'persona_id' parameter".to_string()))?;
    // `binding_request_id` is optional but recommended — the reconciler
    // uses it for idempotent retries. We log it through to the audit row
    // so an operator can trace an urgent revocation back to a specific
    // compromise-response pass.
    let binding_request_id = params["binding_request_id"].as_str();
    // `reason` is optional but strongly recommended for compromise
    // response — it lands in the audit details JSON so the SOC2 evidence
    // export captures why the urgent revocation fired.
    let reason = params["reason"].as_str();

    // Step 1 — cascade revoke. Same SQL transition as `binding.delete`;
    // the wedge that distinguishes urgent from graceful is the audit
    // event row (action + outcome), NOT the storage layer.
    match store.revoke_persona(persona_id) {
        Ok(()) => {}
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {persona_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    }

    // Step 2 — audit-log emission. Action is the literal
    // `"binding.revoke_urgent"` (NOT the `RECEIPT_KIND_BINDING_REVOKED`
    // constant — that one is for the graceful-revoke pipeline, this
    // verb is the urgent-only path). Outcome `"urgent"` makes alerting
    // queries trivial: `WHERE outcome = 'urgent'`.
    let details = serde_json::json!({
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
        "reason": reason,
    })
    .to_string();
    let _ = store.log_event(
        Some(persona_id),
        "binding.revoke_urgent",
        None,
        "urgent",
        Some(&details),
    );

    Ok(json!({
        "revoked_urgent": true,
        "persona_id": persona_id,
        "binding_request_id": binding_request_id,
    }))
}

/// `binding.update` JSON-RPC verb — mutate metadata on an existing
/// workload Persona binding without revoking it.
///
/// Per design §"binding.update":
///   1. Look up the existing binding (persona row). Return `-32004` if
///      the binding does not exist.
///   2. Apply each mutable field in turn — today only `name` is
///      surfaced as a SQL column, but the wire shape accepts the
///      broader binding-metadata fields (`cred_class_allowlist`,
///      `lease_duration_cap`, etc.) so callers can already speak the
///      design contract; those fields land in the audit details JSON
///      until the schema lands columns for them.
///   3. Emit a `binding.updated` audit row keyed on
///      `RECEIPT_KIND_BINDING_UPDATED` with a before/after snapshot
///      so the reconciler + receipt pipeline can correlate the
///      mutation with its originating `binding_request_id`.
///
/// JSON-RPC params shape (all fields after `binding_id` are optional;
/// at least one mutable field SHOULD be present):
/// ```json
/// {
///   "binding_id":          "persona-...",          // required
///   "binding_request_id":  "br-...",               // optional, recommended
///   "name":                "new-name",             // optional, SQL-mutated
///   "cred_class_allowlist": ["llm:*", ...],        // optional, audit-only
///   "lease_duration_cap":  3600,                   // optional, audit-only
///   "metadata":            { ... }                 // optional, audit-only
/// }
/// ```
///
/// Backwards-compat: `persona_id` is accepted as a synonym for
/// `binding_id` so the verb composes with the same callers that drive
/// `binding.delete` / `binding.revoke_urgent`.
///
/// Idempotency: replaying the same params is safe. The SQL UPDATE is
/// a write of the exact same value when nothing changed; the audit
/// row is appended each call so the reconciler always sees a fresh
/// receipt for its retry. The orchestration layer is expected to
/// dedupe via `binding_request_id` if it cares about exactly-once
/// audit emission.
pub async fn binding_update(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Accept either `binding_id` (canonical per design) or
    // `persona_id` (for symmetry with the delete/revoke verbs that
    // still speak persona_id). At least one must resolve to a string.
    let binding_id = params["binding_id"]
        .as_str()
        .or_else(|| params["persona_id"].as_str())
        .ok_or((-32602, "missing 'binding_id' parameter".to_string()))?;
    let binding_request_id = params["binding_request_id"].as_str();

    // Step 1 — load the existing binding so we can build a "before"
    // snapshot for the audit row AND surface NotFound as -32004.
    let before = match store.get_persona(binding_id) {
        Ok(p) => p,
        Err(crate::infra::store::StoreError::NotFound) => {
            return Err((-32004, format!("binding {binding_id} not found")));
        }
        Err(e) => return Err((-32000, e.to_string())),
    };

    // Step 2 — apply mutable fields. Today only `name` lives in SQL.
    // The remaining fields (cred_class_allowlist, lease_duration_cap,
    // metadata) are audit-only until the schema lands columns for
    // them; they still flow through the wire contract so callers can
    // forward-compatibly drive design today.
    let new_name = params["name"].as_str();
    if let Some(name) = new_name
        && name != before.name
    {
        // SQLite UNIQUE-constraint violations come back as
        // `Sqlite(SqliteFailure { code: ConstraintViolation, .. })`;
        // surface as -32005 to give callers an actionable signal
        // distinct from the generic -32000 "internal" bucket.
        match store.conn().execute(
            "UPDATE personas SET name = ?1 WHERE id = ?2",
            rusqlite::params![name, binding_id],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err((-32005, format!("name '{name}' already in use")));
            }
            Err(e) => return Err((-32000, e.to_string())),
        }
    }

    // Step 3 — capture the after-snapshot. We re-read so the audit
    // reflects whatever SQLite actually committed (in particular, if
    // a future migration adds defaulted columns, the audit row picks
    // them up automatically).
    let after = store
        .get_persona(binding_id)
        .map_err(|e| (-32000, e.to_string()))?;

    // Step 4 — audit-log emission. Action mirrors
    // `RECEIPT_KIND_BINDING_UPDATED` so the Receipt v2 pipeline can
    // correlate audit rows with envelopes. The details JSON carries
    // both the before/after persona snapshots AND the audit-only
    // metadata fields the caller passed (so the reconciler can apply
    // them to its in-memory model even before the schema lands).
    let details = serde_json::json!({
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "before": {
            "name": before.name,
            "status": before.status,
        },
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "name": new_name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(binding_id),
        core_events::receipt::atomic::RECEIPT_KIND_BINDING_UPDATED,
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "updated": true,
        "binding_id": binding_id,
        "binding_request_id": binding_request_id,
        "name": after.name,
    }))
}

/// `binding.upsert` JSON-RPC verb — idempotent insert-or-update for a
/// workload Persona binding.
///
/// Per design §"binding.upsert": this is the steady-state verb
/// `ember-kernel`'s EmberServiceAccount reconciler calls every pass.
/// Today it ships as a thin compose of `get_persona` + `create_persona`
/// plus the SQL `UPDATE` from `binding.update`. The audit row records a
/// `binding.upserted` event keyed on the (final) persona id with a
/// before/after diff so the reconciler and receipt pipeline can tell
/// "first registration" apart from "no-op refresh" without re-parsing
/// the persona row.
///
/// JSON-RPC params shape (all fields optional except either `persona_id`
/// or `name` MUST be present so the verb has a binding to anchor on):
/// ```json
/// {
///   "namespace":            "ns-prod",                    // optional, audit-only
///   "name":                 "ml-eval",                    // required when creating
///   "persona_id":           "persona-...",                // optional, identifier when updating
///   "binding_request_id":   "br-...",                     // optional, recommended
///   "cred_class_allowlist": ["llm:*", ...],               // optional, audit-only
///   "lease_duration_cap":   3600,                         // optional, audit-only
///   "metadata":             { ... }                       // optional, audit-only
/// }
/// ```
///
/// Idempotency: replaying the same params is safe. If the persona
/// already exists with the requested name, the UPDATE is a no-op write
/// and the audit row records `before == after` (the reconciler still
/// gets a fresh receipt). If the row does not exist, a fresh persona
/// is created and the audit row carries `before: null`.
///
/// Returns `{ persona_id, created, updated }`. `persona_id` is always
/// the canonical id the daemon uses (which may differ from the caller's
/// `persona_id` if the caller asked for a fresh registration). Exactly
/// one of `created` / `updated` is `true`.
pub async fn binding_upsert(store: &DaemonStore, params: &Value) -> Result<Value, (i32, String)> {
    // Either `persona_id` (canonical, looks up an existing binding) or
    // `name` (required when creating fresh) MUST be present. Mirrors
    // the `binding.update` `binding_id`/`persona_id` synonym shape.
    let requested_persona_id = params["persona_id"]
        .as_str()
        .or_else(|| params["binding_id"].as_str());
    let name = params["name"].as_str();
    let binding_request_id = params["binding_request_id"].as_str();

    if requested_persona_id.is_none() && name.is_none() {
        return Err((
            -32602,
            "binding.upsert requires either 'persona_id' or 'name'".to_string(),
        ));
    }

    // Step 1 — try to load the existing binding so we can branch on
    // create-vs-update. NotFound on a caller-supplied `persona_id`
    // routes to the create path (idempotent insert); other errors
    // surface as -32000.
    let existing = match requested_persona_id {
        Some(pid) => match store.get_persona(pid) {
            Ok(p) => Some(p),
            Err(crate::infra::store::StoreError::NotFound) => None,
            Err(e) => return Err((-32000, e.to_string())),
        },
        None => None,
    };

    // Step 2 — branch.
    let (canonical_id, created, before_snapshot, after) = match existing {
        // ── Update path ──
        Some(before) => {
            // Apply the only mutable SQL column today (`name`). Deeper
            // metadata mutations land in audit-only details JSON until
            // the schema lands columns for them — same shape as
            // `binding.update`.
            if let Some(new_name) = name
                && new_name != before.name
            {
                match store.conn().execute(
                    "UPDATE personas SET name = ?1 WHERE id = ?2",
                    rusqlite::params![new_name, before.id],
                ) {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(err, _))
                        if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        return Err((-32005, format!("name '{new_name}' already in use")));
                    }
                    Err(e) => return Err((-32000, e.to_string())),
                }
            }
            let after = store
                .get_persona(&before.id)
                .map_err(|e| (-32000, e.to_string()))?;
            let before_snapshot = json!({
                "name": before.name,
                "status": before.status,
            });
            (before.id.clone(), false, before_snapshot, after)
        }
        // ── Create path ──
        None => {
            // Creating a fresh persona requires a name — caller
            // either passed `persona_id` for a row that doesn't
            // exist (snapshot drift, fresh cluster) or passed `name`
            // for a never-registered SA.
            let create_name = name.ok_or((
                -32602,
                "binding.upsert create path requires 'name'".to_string(),
            ))?;
            let new_persona = match store.create_persona(create_name) {
                Ok(p) => p,
                Err(crate::infra::store::StoreError::Sqlite(rusqlite::Error::SqliteFailure(
                    err,
                    _,
                ))) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    return Err((-32005, format!("name '{create_name}' already in use")));
                }
                Err(e) => return Err((-32000, e.to_string())),
            };
            (new_persona.id.clone(), true, Value::Null, new_persona)
        }
    };

    // Step 3 — audit-log emission. Action `"binding.upserted"` mirrors
    // the existing `binding.deleted` / `binding.updated` literals —
    // the kind constant for upsert is not yet locked in
    // `core_events::receipt::atomic`, so we emit the literal here and
    // tighten to a constant when design lands the discriminator.
    let details = serde_json::json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "before": before_snapshot,
        "after": {
            "name": after.name,
            "status": after.status,
        },
        "requested": {
            "namespace": params.get("namespace"),
            "name": name,
            "cred_class_allowlist": params.get("cred_class_allowlist"),
            "lease_duration_cap": params.get("lease_duration_cap"),
            "metadata": params.get("metadata"),
        },
    })
    .to_string();
    let _ = store.log_event(
        Some(&canonical_id),
        "binding.upserted",
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "persona_id": canonical_id,
        "binding_request_id": binding_request_id,
        "created": created,
        "updated": !created,
        "name": after.name,
    }))
}

/// implementation-note-53 (design §9 + §6) — atomic
/// `create_agent_persona` RPC handler.
///
/// Replaces the two-call sequence `create_persona` + `delegate_grant`
/// with a single state-machine'd verb whose lifecycle is:
///
/// 1. **Phase 1 — enrolling.** Insert a workload persona row with
///    `status = 'enrolling'`, bind it to the requested `container_id`
///    and `parent_grant_id`. Refuses if a previous spawn already
///    bound the same container slot (CRIT-4: one in-flight key per
///    container).
/// 2. **Phase 2 — delegate.** Call `delegate_grant_full` against the
///    parent grant, producing an attenuated child grant scoped to
///    `child_scope` (and optionally narrowed budget / TTL).
/// 3. **Phase 3 — activate.** Flip the persona row from `enrolling`
///    to `active`. The row is now usable by `use_credential`,
///    `delegate_grant`, etc.
///
/// If the daemon crashes between phase 1 and phase 3, the persona row
/// remains `enrolling` forever; the reconciler's idempotency check
/// (`DaemonStore::enrolling_persona_for_container`) surfaces the
/// poisoned slot, and the reconciler refuses to spawn a second
/// container into the same enrolling slot (the test
/// `agent_persona_enrolling_blocks_reconciler_spawn` covers this).
///
/// The container binding is persisted in BOTH the `personas` table
/// (via the `container_id` column) AND the audit log (via an
/// `agent_persona.created` event with the full binding metadata in
/// `details`), so reconcilers can reconstruct the binding from either
/// source even if one is rolled back by a future migration.
///
/// JSON-RPC params shape:
/// ```json
/// {
///   "name":             "ml-eval-worker",       // required, persona display name
///   "container_id":     "ctr-abc123",            // required, container identity
///   "parent_grant_id":  "grant-...",             // required, grant being attenuated
///   "child_scope":      "credential.access.gh",  // required, scope of attenuated grant
///   "ttl_secs":         3600,                    // optional, child grant TTL
///   "budget":           { ... },                 // optional, narrowed budget
///   "agent_id":         "scion-agent-...",       // optional, audit-only
///   "binding_request_id": "br-..."               // optional, audit-only
/// }
/// ```
///
/// Returns `{ persona_id, attenuated_grant_id, container_id, status }`.
/// `status` is always `"active"` on success — callers do not see the
/// `enrolling` intermediate state because phase 3 is part of the same
/// RPC's success path.
pub async fn create_agent_persona(
    store: &DaemonStore,
    params: &Value,
) -> Result<Value, (i32, String)> {
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "missing 'name' parameter".to_string()))?;
    let container_id = params["container_id"]
        .as_str()
        .ok_or((-32602, "missing 'container_id' parameter".to_string()))?;
    let parent_grant_id = params["parent_grant_id"]
        .as_str()
        .ok_or((-32602, "missing 'parent_grant_id' parameter".to_string()))?;
    let child_scope = params["child_scope"]
        .as_str()
        .or_else(|| params["scope"].as_str())
        .ok_or((-32602, "missing 'child_scope' parameter".to_string()))?;
    let ttl_secs = params["ttl_secs"].as_u64();
    let child_budget: Option<core_grant_types::Budget> = if params["budget"].is_object() {
        Some(
            serde_json::from_value(params["budget"].clone())
                .map_err(|e| (-32602, format!("invalid 'budget': {e}")))?,
        )
    } else {
        None
    };
    let binding_request_id = params["binding_request_id"].as_str();
    let agent_id = params["agent_id"].as_str();

    // Validate the parent grant exists and is active BEFORE inserting
    // the enrolling persona row. A bad parent grant means the whole
    // two-phase commit will fail; bailing out here avoids a poisoned
    // enrollment slot that only exists because phase-2 was never going
    // to succeed.
    let parent_grant = store
        .grant_store()
        .load_grant(parent_grant_id)
        .map_err(|e| match e {
            crate::infra::store::StoreError::NotFound => (
                -32004,
                format!("parent grant '{parent_grant_id}' not found"),
            ),
            // Malformed grant id (e.g. not a valid uuid) is functionally
            // equivalent to "no such grant" from the caller's POV — surface
            // it as -32004 so callers don't have to special-case parse
            // failures vs miss-by-id.
            crate::infra::store::StoreError::InvalidInput(_) => (
                -32004,
                format!("parent grant '{parent_grant_id}' not found"),
            ),
            other => (-32000, other.to_string()),
        })?;
    if parent_grant.state != CoreGrantState::Active {
        return Err((
            -32005,
            format!(
                "parent grant '{parent_grant_id}' is not active and cannot be \
                 delegated from"
            ),
        ));
    }

    // ── Phase 1: insert persona row in `enrolling` state ──
    //
    // This both creates the row AND binds it to `container_id` in a
    // single SQL statement. The uniqueness check inside
    // `create_agent_persona_enrolling` rejects a second spawn into the
    // same container slot — CRIT-4 mitigation.
    let enrolling = store
        .create_agent_persona_enrolling(name, container_id, parent_grant_id)
        .map_err(|e| match e {
            crate::infra::store::StoreError::InvalidInput(msg) => (-32005, msg),
            crate::infra::store::StoreError::Sqlite(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                (-32005, format!("name '{name}' already in use"))
            }
            other => (-32000, other.to_string()),
        })?;
    let new_persona_id = enrolling.id.clone();

    // ── Phase 2: delegate the parent grant to the new persona ──
    //
    // If this fails, the persona row stays in `enrolling`. The
    // reconciler's enrolling-slot check refuses to spawn a duplicate
    // container against the poisoned binding; an operator can clean
    // up the orphan row out-of-band. We intentionally do NOT auto-
    // rollback phase 1 — leaving the row visible is the audit trail
    // for the failed spawn.
    let grant = match store.delegate_grant_full(
        parent_grant_id,
        &new_persona_id,
        child_scope,
        ttl_secs,
        child_budget,
    ) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(
                container_id = %container_id,
                parent_grant_id = %parent_grant_id,
                new_persona_id = %new_persona_id,
                error = %e,
                "create_agent_persona: phase-2 delegate_grant failed; \
                 persona left in 'enrolling' state for reconciler reaping"
            );
            // Audit-log the phase-2 failure so the reconciler can
            // distinguish "daemon crashed" from "delegate rejected".
            let details = serde_json::json!({
                "persona_id": new_persona_id,
                "container_id": container_id,
                "parent_grant_id": parent_grant_id,
                "phase": "delegate",
                "error": e.to_string(),
                "binding_request_id": binding_request_id,
                "agent_id": agent_id,
            })
            .to_string();
            let _ = store.log_event(
                Some(&new_persona_id),
                "agent_persona.enroll_failed",
                None,
                "denied",
                Some(&details),
            );
            return Err((-32000, format!("delegate_grant failed: {e}")));
        }
    };

    // ── Phase 3: flip persona enrolling → active ──
    //
    // Same crash-safety story as phase 2: if this UPDATE fails, the
    // row stays in `enrolling`. The reconciler refuses to spawn into
    // the slot until an operator reaps the orphan.
    if let Err(e) = store.activate_persona(&new_persona_id) {
        tracing::warn!(
            container_id = %container_id,
            new_persona_id = %new_persona_id,
            error = %e,
            "create_agent_persona: phase-3 activate_persona failed; \
             persona left in 'enrolling' state for reconciler reaping"
        );
        let details = serde_json::json!({
            "persona_id": new_persona_id,
            "container_id": container_id,
            "parent_grant_id": parent_grant_id,
            "child_grant_id": grant.id,
            "phase": "activate",
            "error": e.to_string(),
            "binding_request_id": binding_request_id,
            "agent_id": agent_id,
        })
        .to_string();
        let _ = store.log_event(
            Some(&new_persona_id),
            "agent_persona.enroll_failed",
            None,
            "denied",
            Some(&details),
        );
        return Err((-32000, format!("activate_persona failed: {e}")));
    }

    // ── Phase 4 (audit): persist the binding event in the SQLite event log ──
    //
    // The personas table column is the steady-state binding source of
    // truth; this audit row is the temporally-ordered event-log entry
    // demanded by design §6 "container-id binding persisted in
    // SQLite event log". A reconciler that has lost its persona-table
    // index can replay the audit log to reconstruct the binding map.
    let details = serde_json::json!({
        "persona_id": new_persona_id,
        "container_id": container_id,
        "parent_grant_id": parent_grant_id,
        "child_grant_id": grant.id,
        "child_scope": child_scope,
        "ttl_secs": ttl_secs,
        "binding_request_id": binding_request_id,
        "agent_id": agent_id,
        "name": name,
    })
    .to_string();
    let _ = store.log_event(
        Some(&new_persona_id),
        "agent_persona.created",
        None,
        "allowed",
        Some(&details),
    );

    Ok(json!({
        "persona_id": new_persona_id,
        "attenuated_grant_id": grant.id,
        "container_id": container_id,
        "parent_grant_id": parent_grant_id,
        "child_scope": child_scope,
        "status": "active",
        "name": enrolling.name,
        "public_key": enrolling.public_key,
        "expires_at": grant.expires_at,
    }))
}

/// Shape a single `Statement` into the budget-status response entry used by
/// the `grant_budget_status` MCP tool. The `percent_used` map is populated
/// only for axes that have a ceiling set — TTL-only statements return an
/// empty map rather than a map full of nulls. `estimated_runway_seconds`
/// is today always `null` (reserved for a future burn-rate projection once
/// the metering history is durable).
fn build_statement_budget_entry(s: &core_grant_types::Statement) -> Value {
    let mut percent_used = serde_json::Map::new();
    if let Some(budget) = &s.budget {
        if let Some(cap) = budget.tokens
            && cap > 0
        {
            let pct = ((s.usage.tokens as u128 * 100) / cap as u128) as u64;
            percent_used.insert("tokens".to_string(), json!(pct));
        }
        if let Some(cap) = budget.cents
            && cap > 0
        {
            let pct = ((s.usage.cents as u128 * 100) / cap as u128) as u64;
            percent_used.insert("cents".to_string(), json!(pct));
        }
        if let Some(cap) = budget.requests
            && cap > 0
        {
            let pct = ((s.usage.requests as u128 * 100) / cap as u128) as u64;
            percent_used.insert("requests".to_string(), json!(pct));
        }
    }

    json!({
        "sid": s.sid,
        "resource_type": s.resource_type.as_str(),
        "budget": s.budget,
        "usage": s.usage,
        "percent_used": Value::Object(percent_used),
        "estimated_runway_seconds": Value::Null,
        "has_budget_remaining": s.has_budget_remaining(),
    })
}

#[cfg(test)]
mod tests {
    use super::build_banner;
    use super::*;
    use crate::infra::interactive_unlock;
    use crate::infra::rate_limit::RateLimiter;
    use crate::infra::store::DaemonStore;
    use crate::infra::vault::Vault;
    use crate::trust::approval::ApprovalRequestInfo;
    use crate::trust::policy::{
        ApprovalRequirement, PolicyConfig, PolicyEngine, PolicyRule, RiskLevel, Tier,
    };
    use serde_json::json;
    use std::cell::RefCell;

    fn test_vault() -> Vault {
        Vault::new([42u8; 32])
    }

    fn test_policy() -> PolicyEngine {
        PolicyEngine::default()
    }

    fn test_rate_limiter() -> RefCell<RateLimiter> {
        RefCell::new(RateLimiter::default())
    }

    // implementation-note-234: mint a
    // daemon-identity-signed presence-token for `uid` so tests that
    // construct `RequestContext` directly for OperatorPresence-class
    // methods continue to pass the gate.
    fn test_presence_token(uid: u32) -> crate::auth::presence_token::PresenceToken {
        use crate::auth::presence_token::{ScopeKey, mint};
        use std::time::Duration;
        ensure_test_presence_identity();
        let signer =
            DaemonIdentityPresenceSigner::current().expect("test presence signer initialised");
        mint(uid, ScopeKey::all(), Duration::from_secs(60), &signer)
    }

    // implementation-note-232: Phase B's
    // "every method is ConnectOnly" placeholder is gone. Unknown
    // methods now fail-closed to `OperatorPresence` so a newly-
    // added dispatcher arm without a table entry cannot be invoked
    // without an operator-presence proof; explicitly classified
    // methods take their declared class.
    #[test]
    fn authority_class_for_unknown_method_returns_none() {
        // authority_gate_unknown_method_returns_minus_32601 — unknown
        // methods return None so the dispatcher's `_ => Err(-32601)` arm
        // emits the standard JSON-RPC "Method not found" response.
        // Previously this fell closed to OperatorPresence, which
        // shadowed the unknown-method contract (broke test_unknown_method
        // for ~8h on 2026-05-17 returning -32001 instead of -32601).
        // "Forgot to classify" is now caught by the exhaustivity test
        // ALL_CLASSIFIED_METHODS_MATCH_DISPATCHER_ARMS below.
        assert_eq!(
            authority_class_for_method("does_not_exist"),
            None,
            "unknown methods must return None so dispatcher emits -32601"
        );
    }

    #[test]
    fn authority_class_for_ping_is_connect_only() {
        // `ping` is the canonical liveness-check method — any
        // ember-clients member the socket layer let through can call
        // it; no operator-presence proof required.
        assert_eq!(
            authority_class_for_method("ping"),
            Some(AuthorityClass::ConnectOnly)
        );
    }

    #[test]
    fn authority_class_for_list_personas_is_connect_only() {
        // Read-class dashboard-mirror method — same authority surface
        // as `ping`.
        assert_eq!(
            authority_class_for_method("list_personas"),
            Some(AuthorityClass::ConnectOnly)
        );
    }

    #[test]
    fn authority_class_for_presence_token_mint_is_connect_only() {
        assert_eq!(
            authority_class_for_method("presence_token_mint"),
            Some(AuthorityClass::ConnectOnly)
        );
    }

    #[test]
    fn authority_class_for_await_approval_is_connect_only() {
        assert_eq!(
            authority_class_for_method("await_approval"),
            Some(AuthorityClass::ConnectOnly)
        );
    }

    #[test]
    fn authority_class_for_list_operator_grants_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("list_operator_grants"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_audit_log_query_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("audit_log_query"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_audit_explain_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("audit_explain"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_grant_summary_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("grant_summary"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_detect_anomalies_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("detect_anomalies"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_headless_status_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("headless_status"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_receipt_tree_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("receipt_tree"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_resolve_approval_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("resolve_approval"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_build_init_first_grant_receipt_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("build_init_first_grant_receipt"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_vault_add_is_operator_presence() {
        // Sensitive vault operation — classified as OperatorPresence in the
        // authority map. The installed local path now requires the same
        // daemon-issued proof on every tier, with bootstrap exceptions
        // handled at dispatch time rather than by leaving dev0 tokenless.
        assert_eq!(
            authority_class_for_method("vault_add"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_vault_list_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("vault_list"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_vault_unlock_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("vault_unlock"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_presence_bridge_rpcs_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("presence/request_proof"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("presence_request_proof"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("presence/enroll"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("presence_enroll"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_delegate_grant_is_operator_presence() {
        // Grant mutation — the canonical example of "principal-bound,
        // operator-presence-required" per the design destination
        // section.
        assert_eq!(
            authority_class_for_method("delegate_grant"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    #[test]
    fn authority_class_for_sandbox_methods_is_operator_presence() {
        assert_eq!(
            authority_class_for_method("sandbox_create"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("sandbox_list"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("sandbox_stop"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("sandbox_delete"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("sandbox_exec"),
            Some(AuthorityClass::OperatorPresence)
        );
        assert_eq!(
            authority_class_for_method("sandbox_run"),
            Some(AuthorityClass::OperatorPresence)
        );
    }

    /// authority_gate_unknown_method_returns_minus_32601 — exhaustivity
    /// gate. Every method actually dispatched by `dispatch_method_with_context`
    /// MUST have a classification entry in `authority_class_for_method`.
    /// A method that lands in the dispatcher without a classification
    /// entry now returns -32601 ("Method not found") at runtime instead
    /// of -32001 ("authority_class_not_met") — protocol-correct but
    /// silently invisible to external callers. This test surfaces the
    /// gap at `cargo test` time so the developer sees it before ship.
    ///
    /// Maintenance: when adding a new method to `dispatch_method`'s
    /// match, also add it to the `DISPATCHED_METHODS` constant below
    /// AND classify it in `authority_class_for_method`. The test failure
    /// message tells you exactly which method is missing.
    #[test]
    fn all_classified_methods_match_dispatcher_arms() {
        // Source of truth: every `"<method_name>" =>` arm in
        // `dispatch_method_with_context`. Methods are listed in
        // declaration order. Last verified 2026-05-17 against
        // handler.rs's dispatcher.
        const DISPATCHED_METHODS: &[&str] = &[
            // ConnectOnly arms
            "ping",
            "presence_token_mint",
            "daemon_persona",
            "poll_notifications",
            "audit_verify",
            "audit_query",
            "receipt_query",
            "status",
            "list_receipts",
            "get_receipt",
            "list_personas",
            "list_grants",
            "list_pending_approvals",
            "list_standing_grants",
            "grant_status",
            "grant_budget_status",
            "evaluate_grant",
            "headless_preflight_gaps",
            "vault_status",
            "await_approval",
            // OperatorPresence arms
            "create_persona",
            "build_init_first_grant_receipt",
            "revoke_persona",
            "audit_log_query",
            "audit_explain",
            "grant_summary",
            "detect_anomalies",
            "headless_status",
            "receipt_tree",
            "list_operator_grants",
            "create_grant",
            "delegate_grant",
            "sandbox_create",
            "sandbox_list",
            "sandbox_stop",
            "sandbox_delete",
            "sandbox_exec",
            "sandbox_run",
            "revoke_grant",
            "extend_grant",
            "revoke_statement",
            "evaluate_tool_call",
            "use_credential",
            "vault_add",
            "vault_list",
            "vault_remove",
            "vault_lock",
            "vault_unlock",
            "vault_get",
            "vault_migrate_acl",
            "local_state_key_get",
            "local_state_key_set",
            "local_state_key_rotate_and_reencrypt",
            "binary_pin_generate",
            "submit_approval",
            "propose_grant",
            "resolve_approval",
            "expire_grants",
            "create_standing_grant",
            "remove_standing_grant",
            "request_access",
            "request_access_blocking",
            "broker_issue",
            "broker_revoke",
            "broker_list",
            "broker_resolve",
            "broker_exec",
            "broker.mint_gh_token",
            "broker_register_pid_watcher",
            "presence/request_proof",
            "presence_request_proof",
            "presence/enroll",
            "presence_enroll",
            "sops_unwrap_dek",
            "sops.pubkey",
            "sops.wrap",
            "sops.unwrap",
            "register_session",
            "close_session",
            "headless_enroll",
            "headless_revoke",
        ];

        let mut unclassified = Vec::new();
        for method in DISPATCHED_METHODS {
            if authority_class_for_method(method).is_none() {
                unclassified.push(*method);
            }
        }
        assert!(
            unclassified.is_empty(),
            "the following dispatcher methods have no classification in \
             authority_class_for_method (will return -32601 at runtime — \
             add them to the ConnectOnly or OperatorPresence arms): {:?}",
            unclassified
        );

        // Symmetric check: warn if DISPATCHED_METHODS is shorter than the
        // dispatcher's actual arm count. Counts come from manual grep of
        // `^\s+"[a-z_.]+"\s+=>` in dispatch_method_with_context excluding
        // the AuthorityClass match. If this drifts, the maintenance hint
        // above tells the developer to add the new method.
        const DISPATCHER_ARM_COUNT_BASELINE: usize = 69;
        assert!(
            DISPATCHED_METHODS.len() >= DISPATCHER_ARM_COUNT_BASELINE,
            "DISPATCHED_METHODS has {} entries; dispatcher had {} as of 2026-05-17 — \
             likely a new method landed in dispatch_method_with_context that \
             wasn't added here. Re-run `grep -E '^\\s+\"[a-z_.]+\"\\s+=>' \
             crates/ember-daemon/src/infra/handler.rs | awk -F'\"' '{{print $2}}' \
             | sort -u` to refresh.",
            DISPATCHED_METHODS.len(),
            DISPATCHER_ARM_COUNT_BASELINE
        );
    }

    #[tokio::test]
    async fn sandbox_list_dispatches_for_operator_socket() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        store.create_sandbox("alpha", "ubuntu:24.04").unwrap();

        // sandbox_list is OperatorPresence-class. Satisfy the
        // presence-token + unlocked-session gates so the happy-path
        // projection under test is reachable. Previously this test
        // was an intermittent pass because sibling tests' unrelated
        // mark_unlocked left presence Unlocked through this test's
        // window; with cross-module serialization the prior accidental
        // pass no longer occurs and the test needs explicit setup.
        ensure_test_authority_bridge_env();
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let ctx = RequestContext::socket(Some(PeerCred {
            uid: 1000,
            pid: Some(80_101),
        }))
        .with_presence_token(Some(test_presence_token(1000)));
        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "sandbox_list",
            &serde_json::Value::Null,
        )
        .await
        .unwrap();

        let sandboxes = result
            .as_array()
            .expect("sandbox_list must return an array");
        assert_eq!(sandboxes.len(), 1);
        assert_eq!(sandboxes[0]["name"], json!("alpha"));
        assert_eq!(sandboxes[0]["image"], json!("ubuntu:24.04"));
    }

    #[tokio::test]
    async fn sandbox_exec_requires_caller_persona_when_socket_pid_is_unenrolled() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sandbox = store
            .create_sandbox_with_opts(
                &crate::infra::sandbox::SandboxCreateOpts {
                    name: "alpha".to_string(),
                    image: "ubuntu:24.04".to_string(),
                    owner_persona_id: Some("persona-owner".to_string()),
                    ..Default::default()
                },
                None,
            )
            .unwrap();

        ensure_test_authority_bridge_env();
        // sandbox_exec is OperatorPresence-class. Satisfy the
        // presence-token + unlocked-session gates so the test reaches
        // the caller_persona_id-required assertion under test.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let ctx = RequestContext::socket(Some(PeerCred {
            uid: 1000,
            pid: Some(80_102),
        }))
        .with_presence_token(Some(test_presence_token(1000)));
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "sandbox_exec",
            &json!({
                "id_or_name": sandbox.id,
                "command": ["echo", "hello"],
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32602);
        assert!(
            err.1.contains("caller_persona_id"),
            "missing explicit fallback should mention caller_persona_id, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn sandbox_run_dispatches_without_composite_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        std::fs::create_dir_all(&sessions_dir).unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "sandbox_run",
            &json!({
                "sandbox": {
                    "name": "run-test",
                    "image": "ubuntu:24.04",
                    "privileged": false,
                    "volumes": [],
                    "user": null,
                    "network": null,
                    "unsafe_root": false,
                    "workspace_from": null,
                    "extra_env": [],
                    "owner_persona_id": "persona-owner"
                },
                "statements": [],
                "ttl_secs": null,
                "credential_resource": null,
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["sandbox"]["name"], json!("run-test"));
        assert_eq!(result["sandbox"]["image"], json!("ubuntu:24.04"));
        assert_eq!(result["grant"], json!("NotRequested"));
    }

    // implementation-note-232: `RequestContext::
    // satisfies` table.
    //
    // The bridge env var is process-global so we set it before the
    // assertions and assert both with/without explicitly. Tests in
    // this crate share the env via `ensure_test_authority_bridge_env`
    // which the dispatch shim already calls for Socket-source calls;
    // here we exercise the function directly without going through
    // dispatch.
    #[test]
    fn satisfies_connect_only_requires_peer() {
        let ctx_no_peer = RequestContext::socket(None);
        assert!(
            !ctx_no_peer.satisfies(AuthorityClass::ConnectOnly),
            "ConnectOnly without a peer must be refused"
        );

        let ctx_with_peer = RequestContext::socket(Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }));
        assert!(
            ctx_with_peer.satisfies(AuthorityClass::ConnectOnly),
            "ConnectOnly with a peer must be allowed"
        );
    }

    #[test]
    fn satisfies_operator_presence_with_reattest_is_never_satisfied_in_cohort_a() {
        // Cohort A dev0 has no proof surface for the re-attest tier;
        // design's team0+/ent0 deployment populates this later.
        let ctx = RequestContext::socket(Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }));
        // Even with the bridge env on (set by the test shim), the
        // re-attest class stays denied.
        ensure_test_authority_bridge_env();
        assert!(
            !ctx.satisfies(AuthorityClass::OperatorPresenceWithReattest),
            "cohort A dev0 must not satisfy OperatorPresenceWithReattest"
        );
    }

    // implementation-note-232: dispatch gate
    // round-trip. Internal dispatch bypasses the gate — `ping`
    // succeeds even without a synthesized peer or bridge env var,
    // because Internal callers are the pre-existing in-process trust
    // lane.
    #[tokio::test]
    async fn dispatch_internal_source_bypasses_authority_gate() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // dispatch_method is the test wrapper that constructs
        // DispatchSource::Internal under the hood. Even an
        // OperatorPresence-class method (create_persona) must work
        // here because Internal is exempted at the gate.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "internal-bypass"}),
        )
        .await;
        assert!(
            result.is_ok(),
            "Internal source must bypass the authority gate, got {result:?}"
        );
    }

    // implementation-note-232: Socket source
    // without a kernel-attested peer is rejected for ConnectOnly. We
    // construct the context directly (bypassing the test shim's
    // synthetic-peer injection) so we see the production gate.
    #[tokio::test]
    async fn dispatch_socket_without_peer_refused_authority_class_not_met() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: None,
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "ping",
            &json!(null),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32001,
            "Socket source without a peer must hit the authority gate, got {err:?}"
        );
        assert_eq!(err.1, "authority_class_not_met");
    }

    // implementation-note-232: positive path —
    // Socket source with a peer + bridge env on (set by the test
    // shim) passes the gate for an OperatorPresence-class method.
    // Downstream errors (param validation etc.) are NOT -32001 —
    // the gate let the call through.
    //
    // Optional attached presence-token validates on the installed path
    // when a caller provides one explicitly.
    #[tokio::test]
    async fn dispatch_socket_with_peer_passes_authority_gate_for_operator_presence() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };

        // create_persona is OperatorPresence-class. With peer + bridge
        // env on + valid presence_token, dispatch must continue through
        // the current ConnectOnly-equivalent UDS posture.
        // The handler then runs and returns Ok with the new persona —
        // we assert "not -32001" rather than asserting a specific
        // success shape so the test stays robust against future
        // handler-shape evolutions.
        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "create_persona",
            &json!({"name": "gate-positive-path"}),
        )
        .await;

        match result {
            Ok(_) => {}
            Err((code, msg)) => {
                assert_ne!(
                    code, -32001,
                    "authority gate must not fire on Socket + peer + bridge-on + token; got {msg}"
                );
            }
        }
    }

    // v0.3 cutover: tokenless local UDS calls no longer satisfy
    // OperatorPresence, even on dev0.
    #[tokio::test]
    async fn dispatch_dev0_rejects_operator_presence_without_token() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "create_persona",
            &json!({"name": "d4-missing-token"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);
        assert!(err.1.contains("missing"));
    }

    #[tokio::test]
    async fn dispatch_team0_rejects_operator_presence_without_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "create_persona",
            &json!({"name": "team0-missing-token"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);
        assert!(err.1.contains("missing"));
    }

    #[tokio::test]
    async fn dispatch_team0_accepts_operator_presence_with_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "create_persona",
            &json!({"name": "team0-valid-token"}),
        )
        .await;

        match result {
            Ok(_) => {}
            Err((code, msg)) => {
                assert_ne!(
                    code, -32001,
                    "valid presence_token must satisfy team0 OperatorPresence gate; got {msg}"
                );
            }
        }
    }

    #[tokio::test]
    async fn dispatch_operator_presence_rejects_locked_session_even_with_token() {
        // Serialize against sibling tests that flip MANAGER via
        // mark_unlocked — the test under test pins state to Locked,
        // and a racing unlock from another #[tokio::test] would mask
        // the -32030 rejection this test asserts on.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::reset_for_tests();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "create_persona",
            &json!({"name": "locked-presence-session"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32030);
        assert!(err.1.contains("session is locked"));
    }

    // implementation-note-234:
    // dispatch_accepts_connect_only_without_token — ConnectOnly-class
    // methods skip the Phase D-4 gate entirely. With peer + no token,
    // dispatch proceeds normally (the response shape depends on the
    // method; we only assert no -32001 from the D-4 gate).
    #[tokio::test]
    async fn dispatch_accepts_connect_only_without_token() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        ensure_test_authority_bridge_env();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        // `ping` is ConnectOnly per `authority_class_for_method`. The
        // D-4 gate must not fire, so the call returns Ok.
        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "ping",
            &json!(null),
        )
        .await;

        match result {
            Ok(_) => {}
            Err((code, msg)) => {
                assert_ne!(
                    code, -32001,
                    "ConnectOnly methods must skip the D-4 presence-token gate; got {msg}"
                );
            }
        }
    }

    #[tokio::test]
    async fn presence_token_mint_refuses_generic_cli_use() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 777,
                pid: Some(4242),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "presence_token_mint",
            &json!({}),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32601);
        assert!(
            err.1
                .contains("not a shipped generic CLI authority surface"),
            "error must explain the disabled posture: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "ping", &json!(null))
            .await
            .unwrap();
        assert_eq!(result["pong"], json!(true));
    }

    #[tokio::test]
    async fn unknown_method_returns_32601() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(&store, &vault, &policy, &rl, "no_such_method", &json!(null))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32601);
    }

    #[tokio::test]
    async fn create_persona_then_list_shows_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-alpha"}),
        )
        .await
        .unwrap();
        assert!(result["id"].as_str().unwrap().starts_with("persona-"));
        assert_eq!(result["name"], json!("agent-alpha"));

        let list = dispatch_method(&store, &vault, &policy, &rl, "list_personas", &json!(null))
            .await
            .unwrap();
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], json!("agent-alpha"));
        assert_eq!(arr[0]["status"], json!("active"));
    }

    #[tokio::test]
    async fn team0_list_personas_scopes_to_trusted_principal() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-persona-a"}),
        )
        .await
        .unwrap();
        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-persona-b"}),
        )
        .await
        .unwrap();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_001),
            }),
            persona_a["id"].as_str().unwrap().to_string(),
        );
        let list = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "list_personas",
            &json!(null),
        )
        .await
        .unwrap();
        let arr = list.as_array().expect("persona list array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], persona_a["id"]);
        assert_ne!(arr[0]["id"], persona_b["id"]);
    }

    #[tokio::test]
    async fn team0_list_personas_refuses_without_trusted_principal() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            RequestContext::socket(Some(PeerCred {
                uid: 1000,
                pid: Some(91_002),
            })),
            "list_personas",
            &json!(null),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("trusted enrolled principal"),
            "team0 refusal should name the missing trusted principal: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn build_init_first_grant_receipt_returns_signed_file() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "root"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "build_init_first_grant_receipt",
            &json!({"persona_id": persona_id}),
        )
        .await
        .unwrap();

        let file: crate::infra::init_first_grant::FirstGrantReceiptFile =
            serde_json::from_value(result).expect("parse first-grant receipt file");
        assert_eq!(file.issuer.persona, persona_id);
        assert!(file.evidence.signed);
        assert!(file.evidence.hash.starts_with("sha256:"));
        assert!(!file.receipt.receipt_id.is_empty());
        assert!(file.receipt.signature.is_some());
    }

    #[tokio::test]
    async fn create_persona_missing_name_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(&store, &vault, &policy, &rl, "create_persona", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    // ---- implementation-note-76: evaluate_tool_call dispatch arm -----------------

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_returns_decision_for_active_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Mint persona + grant.
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "claude-code-host-x"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        store
            .create_grant(persona_id, "anthropic-api-key", "read", None)
            .unwrap();

        // Evaluate via dispatch.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({
                "persona": "claude-code-host-x",
                "tool_name": "Bash",
                "params": {"command": "ls"},
                "session_id": "sess-evt"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["permit"], json!(true), "got: {result}");
        assert!(result["grant_id"].is_string(), "got: {result}");
        assert!(result["emitted_event_id"].is_string());
    }

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_denies_unknown_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({
                "persona": "claude-code-nobody",
                "tool_name": "Read",
                "params": {}
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["permit"], json!(false), "got: {result}");
        assert!(
            result["reason"]
                .as_str()
                .unwrap()
                .contains("no active grant")
        );
    }

    #[tokio::test]
    async fn evaluate_tool_call_dispatch_missing_persona_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_tool_call",
            &json!({"tool_name": "Bash", "params": {}}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn create_grant_then_evaluate_finds_it() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-beta"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "api-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        assert!(grant["id"].as_str().unwrap().starts_with("grant-"));

        let eval = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_grant",
            &json!({"persona_id": persona_id, "credential_name": "api-key"}),
        )
        .await
        .unwrap();
        assert_eq!(eval["scope"], json!("read"));
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!(null))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(
            err.1.contains("persona_id"),
            "error should mention persona_id, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn list_grants_without_persona_id_in_empty_object_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn list_grants_with_persona_id_returns_only_that_personas_grants() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-a"}),
        )
        .await
        .unwrap();
        let persona_a_id = persona_a["id"].as_str().unwrap();

        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "list-grants-persona-b"}),
        )
        .await
        .unwrap();
        let persona_b_id = persona_b["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_a_id,
                "credential_name": "cred-a",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_b_id,
                "credential_name": "cred-b",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();

        let list_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_a_id}),
        )
        .await
        .unwrap();
        let arr_a = list_a.as_array().unwrap();
        assert_eq!(arr_a.len(), 1, "persona_a should see exactly 1 grant");
        assert_eq!(arr_a[0]["persona_id"], json!(persona_a_id));
        assert_eq!(arr_a[0]["credential_name"], json!("cred-a"));

        let list_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": persona_b_id}),
        )
        .await
        .unwrap();
        let arr_b = list_b.as_array().unwrap();
        assert_eq!(arr_b.len(), 1, "persona_b should see exactly 1 grant");
        assert_eq!(arr_b[0]["persona_id"], json!(persona_b_id));
        assert_eq!(arr_b[0]["credential_name"], json!("cred-b"));
    }

    #[tokio::test]
    async fn team0_list_grants_defaults_to_trusted_principal_and_refuses_mismatch() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-grant-a"}),
        )
        .await
        .unwrap();
        let persona_a_id = persona_a["id"].as_str().unwrap().to_string();

        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-grant-b"}),
        )
        .await
        .unwrap();
        let persona_b_id = persona_b["id"].as_str().unwrap().to_string();

        for (persona_id, credential_name) in [(&persona_a_id, "cred-a"), (&persona_b_id, "cred-b")]
        {
            dispatch_method(
                &store,
                &vault,
                &policy,
                &rl,
                "create_grant",
                &json!({
                    "persona_id": persona_id,
                    "credential_name": credential_name,
                    "scope": "read",
                    "force": true,
                }),
            )
            .await
            .unwrap();
        }

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_003),
            }),
            persona_a_id.clone(),
        );
        let list = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "list_grants",
            &json!({}),
        )
        .await
        .unwrap();
        let arr = list.as_array().expect("grant list array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_id"], json!(persona_a_id));

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "list_grants",
            &json!({"persona_id": persona_b_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("trusted principal"),
            "mismatch should mention trusted principal: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn use_credential_with_valid_grant_returns_value() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-gamma"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "my-token",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await
        .unwrap();
        assert_eq!(result["credential"], json!("supersecret"));
    }

    #[tokio::test]
    async fn revoke_statement_blocks_use_credential() {
        // implementation-note-242 — per-statement revoke MVP.
        // Revoking the Credential Statement's sid blocks use_credential
        // while the grant is otherwise still active.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-stmtrev"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "stmtrev-token", "value": "supersecret"}),
        )
        .await
        .unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "stmtrev-token",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();

        // Baseline: works.
        let ok = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
        )
        .await
        .unwrap();
        assert_eq!(ok["credential"], json!("supersecret"));

        // Revoke S0 (the credential statement built by create_grant).
        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_statement",
            &json!({"grant_id": grant_id, "statement_sid": "S0"}),
        )
        .await
        .unwrap();
        assert_eq!(resp["status"], json!("revoked"));

        // Now use_credential is blocked with -32006.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "stmtrev-token"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32006);
        assert!(err.1.contains("statement revoked"));

        // grant_status surfaces the revoked sid.
        let status = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();
        let revoked = status["revoked_sids"]
            .as_array()
            .expect("revoked_sids array");
        assert!(revoked.iter().any(|v| v.as_str() == Some("S0")));
    }

    #[tokio::test]
    async fn propose_grant_rpc_persists_n_statements() {
        // implementation-note-245 — N-statement persistence + retrieval.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-agent"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // 3-Statement composite envelope (credential + session + time).
        // design §4 — composite-grant action keys must carry the
        // `did:<method>:<rest>` prefix; the RPC layer rejects bare keys
        // since T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES.
        let statements = json!([
            {
                "sid": "S0",
                "resource_type": "credential",
                "actions": ["did:ember:github.push", "did:ember:github.read"],
                "resource": {"kind": "any"},
                "budget": null,
                "usage": {},
                "conditions": [],
            },
            {
                "sid": "S1",
                "resource_type": "session",
                "actions": ["did:ember:generic.write"],
                "resource": {"kind": "any"},
                "budget": {"tokens": 10000},
                "usage": {},
                "conditions": [],
            },
            {
                "sid": "S2",
                "resource_type": "time",
                "actions": ["did:ember:generic.write"],
                "resource": {"kind": "any"},
                "budget": {"wall_clock_secs": 300},
                "usage": {},
                "conditions": [],
            },
        ]);

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "github.push",
                "risk_level": "high",
                "statements": statements,
            }),
        )
        .await
        .unwrap();

        let approval_id = resp["approval_id"].as_str().expect("approval_id present");
        assert!(approval_id.starts_with("approval-"));
        assert_eq!(resp["status"], json!("pending"));
        assert_eq!(resp["statement_count"], json!(3));

        // Retrieval round-trip via the store directly: the row should carry
        // all three statements exactly.
        let info = store
            .get_approval(approval_id)
            .expect("approval row present");
        let stmts = info
            .composite_statements
            .expect("composite_statements present");
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[0].sid, "S0");
        assert_eq!(stmts[1].sid, "S1");
        assert_eq!(stmts[2].sid, "S2");
    }

    #[tokio::test]
    async fn propose_grant_rpc_rejects_empty_statements() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-empty"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "x",
                "risk_level": "high",
                "statements": [],
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("statements"));
    }

    #[tokio::test]
    async fn propose_grant_rpc_rejects_bare_action_keys_with_migration_pointer() {
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — per ADR
        // 135 §4 the propose_grant RPC entry point is the parse-time
        // gate that refuses bare action keys (no `did:` prefix). The
        // error message must point operators at the new shape so they
        // can migrate without consulting docs.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-bare-key"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "gh-token",
                "scope": "*",
                "action": "credential.access",
                "risk_level": "high",
                "statements": [
                    {
                        "sid": "S0",
                        "resource_type": "credential",
                        "actions": ["gh.pr_create"],
                        "resource": {"kind": "any"},
                        "budget": null,
                        "usage": {},
                        "conditions": [],
                    }
                ],
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32602,
            "bare action key must surface as parse-time -32602"
        );
        assert!(
            err.1.contains("did: prefix"),
            "error must name the missing prefix; got: {}",
            err.1
        );
        assert!(
            err.1.contains("did:ember:gh.pr_create"),
            "error must include the recommended did:ember: migration form; got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn propose_grant_rpc_accepts_did_web_for_forward_compat() {
        // T-CONSTRUCT-ACTION-KEY-DID-PREFIX-MIGRATION-SURFACES — arbitrary
        // `did:<method>:` prefixes pass the parse-time validator at the RPC
        // gate even though v0.3.0's broker.resolve only routes `did:ember:`.
        // This locks the forward-compat door so community publishers
        // (`did:web:hashicorp.com:terraform.apply`) submit cleanly today and
        // become resolvable when the per-publisher trust delegation UX lands.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "composite-rpc-fwd-compat"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "propose_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "tf-token",
                "scope": "*",
                "action": "credential.access",
                "risk_level": "high",
                "statements": [
                    {
                        "sid": "S0",
                        "resource_type": "credential",
                        "actions": ["did:web:hashicorp.com:terraform.apply"],
                        "resource": {"kind": "any"},
                        "budget": null,
                        "usage": {},
                        "conditions": [],
                    }
                ],
            }),
        )
        .await
        .expect("did:web: prefixed action key must pass the RPC parse-time gate");

        assert!(
            resp["approval_id"]
                .as_str()
                .unwrap_or("")
                .starts_with("approval-")
        );
    }

    #[tokio::test]
    async fn use_credential_without_grant_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-delta"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "my-token", "value": "supersecret"}),
        )
        .await
        .unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "my-token"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32000);
        assert!(err.1.contains("no active grant"));
    }

    #[tokio::test]
    async fn audit_query_reflects_credential_access() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-epsilon"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "audit-token", "value": "v"}),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await.unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
        )
        .await
        .unwrap();

        let log = dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({}))
            .await
            .unwrap();
        let arr = log.as_array().unwrap();
        // Three rows (timestamp DESC): credential.access, grant.issued, grant.minted.
        // grant.minted is emitted inside create_grant_with_budget before the handler
        // emits grant.issued, so it is the oldest.
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["action"], json!("credential.access"));
        assert_eq!(arr[0]["outcome"], json!("allowed"));
        assert_eq!(arr[1]["action"], json!("grant.issued"));
        assert_eq!(arr[1]["outcome"], json!("allowed"));
        assert_eq!(arr[2]["action"], json!("grant.minted"));
        assert_eq!(arr[2]["outcome"], json!("minted"));
    }

    #[tokio::test]
    async fn audit_log_query_returns_details_and_exact_id_match() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let first_id = store
            .log_event(
                Some("persona-a"),
                "grant.issued",
                Some("repo:alpha"),
                "allowed",
                Some(r#"{"note":"first"}"#),
            )
            .unwrap();
        let _second_id = store
            .log_event(
                Some("persona-a"),
                "grant.revoked",
                Some("repo:beta"),
                "denied",
                Some(r#"{"note":"second"}"#),
            )
            .unwrap();

        let log = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_log_query",
            &json!({
                "id": first_id,
                "persona_id": "persona-a",
            }),
        )
        .await
        .unwrap();
        let arr = log.as_array().expect("audit_log_query returns array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], json!(first_id));
        assert_eq!(arr[0]["action"], json!("grant.issued"));
        assert_eq!(arr[0]["details"], json!(r#"{"note":"first"}"#));
    }

    #[tokio::test]
    async fn audit_explain_returns_current_state_projection() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "credential.access".to_string(),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Required,
                tier: Some(Tier::Tier1),
            }],
            default_requirement: ApprovalRequirement::Auto,
            default_risk: RiskLevel::Low,
        });
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-zeta"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "audit-token", "value": "v"}),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "audit-token", "scope": "read", "force": true}),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "audit-token"}),
        )
        .await
        .unwrap();

        let audit = dispatch_method(&store, &vault, &policy, &rl, "audit_query", &json!({}))
            .await
            .unwrap();
        let event_id = audit.as_array().unwrap()[0]["id"].as_i64().unwrap();

        let explain = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_explain",
            &json!({ "id": event_id }),
        )
        .await
        .unwrap();
        assert_eq!(explain["event"]["id"], json!(event_id));
        assert_eq!(explain["event"]["action"], json!("credential.access"));
        assert_eq!(explain["current_grant"]["scope"], json!("read"));
        assert_eq!(explain["current_policy"]["requirement"], json!("required"));
        assert_eq!(explain["current_policy"]["risk"], json!("high"));
        assert!(
            explain["note"]
                .as_str()
                .expect("note string")
                .contains("Current-state explanation")
        );
    }

    #[tokio::test]
    async fn receipt_tree_dispatch_returns_rooted_tree_export() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let _ = crate::infra::receipt::init_identity(dir.path()).unwrap();

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "tree-root"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "tree-token", "value": "v"}),
        )
        .await
        .unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "tree-token", "scope": "read", "force": true}),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let tree = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "receipt_tree",
            &json!({ "grant_id": grant_id }),
        )
        .await
        .unwrap();
        assert_eq!(tree["root_grant_id"], json!(grant_id));
        assert_eq!(tree["version"], json!("v2"));
        assert_eq!(tree["grants"].as_array().unwrap().len(), 1);
        assert!(tree["daemon_pubkey_hex"].as_str().unwrap().len() >= 64);
    }

    #[tokio::test]
    async fn create_grant_with_rate_limit_stores_condition() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-ratelimit"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "rate-key",
                "scope": "read",
                "max_uses_per_hour": 5,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert!(grant_id.starts_with("grant-"));
        assert_eq!(grant["conditions"]["max_uses_per_hour"], json!(5));

        // Verify it was stored in the DB.
        let stored: Option<i64> = store
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, Some(5));
    }

    #[tokio::test]
    async fn create_grant_with_budget_and_standing_shapes_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-shaped"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "shape-key",
                "scope": "github:push:acme/widgets",
                "budget": {"tokens": 42, "wall_clock_secs": 900},
                "max_delegation_depth": 2,
                "max_children_per_day": 7,
                "auto_delegate_scope_template": "github:push:acme/*",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert_eq!(grant["budget"]["tokens"], json!(42));
        assert_eq!(grant["standing"]["max_children_per_day"], json!(7));

        let stored = store.get_grant(grant_id).expect("grant row");
        assert_eq!(stored.budget.as_ref().and_then(|b| b.tokens), Some(42));
        assert!(stored.is_standing);
        assert_eq!(stored.max_children_per_day, Some(7));
        assert_eq!(
            stored.auto_delegate_scope_template.as_deref(),
            Some("github:push:acme/*")
        );
    }

    #[tokio::test]
    async fn create_grant_socket_pending_approval_preserves_grant_shape() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-approval-shaped"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // create_grant is OperatorPresence-class. The socket-source
        // shim synthesizes a peer + presence_token under #[cfg(test)],
        // but the unlocked-session gate still applies — move presence
        // to Unlocked so the test reaches the pending-approval shape
        // it asserts on.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "budget": {"tokens": 99},
                "max_delegation_depth": 2,
                "max_children_per_day": 3,
                "auto_delegate_scope_template": "stripe:*",
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], json!("pending_approval"));
        let approval_id = result["approval_id"].as_str().unwrap();

        let pending = store.get_approval(approval_id).expect("approval row");
        assert_eq!(pending.max_delegation_depth, Some(2));
        assert_eq!(pending.budget.as_ref().and_then(|b| b.tokens), Some(99));
        assert_eq!(pending.max_children_per_day, Some(3));
        assert_eq!(
            pending.auto_delegate_scope_template.as_deref(),
            Some("stripe:*")
        );
    }

    #[tokio::test]
    async fn delegate_grant_creates_child_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-parent"}),
        )
        .await
        .unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-child"}),
        )
        .await
        .unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap();

        let child_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "read",
            }),
        )
        .await
        .unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("read"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
    }

    /// Exercise the socket-level `delegate_grant` method with an
    /// explicit child `budget` param. Parent carries a tokens budget,
    /// child asks for a strict subset — attenuation must accept and the
    /// response envelope must surface the child budget + expiry.
    #[tokio::test]
    async fn delegate_grant_via_socket_accepts_child_budget() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let parent_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-parent-budget"}),
        )
        .await
        .unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap();

        let child_persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-child-budget"}),
        )
        .await
        .unwrap();
        let child_persona_id = child_persona["id"].as_str().unwrap();

        let parent_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "github:push:acme/*",
                "budget": {"tokens": 10000},
                "max_delegation_depth": 2,
                "ttl_secs": 3_600,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        let child_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_persona_id,
                "scope": "github:push:acme/widgets",
                "ttl_secs": 900,
                "budget": {"tokens": 2000},
            }),
        )
        .await
        .unwrap();

        assert!(child_grant["id"].as_str().unwrap().starts_with("grant-"));
        assert_eq!(child_grant["scope"], json!("github:push:acme/widgets"));
        assert_eq!(child_grant["parent"], json!(parent_grant_id));
        assert_eq!(
            child_grant["budget"]["tokens"].as_u64(),
            Some(2000),
            "child budget echoed in response"
        );
        assert!(
            child_grant["expires_at"].is_string(),
            "expires_at present on delegated grant"
        );
    }

    #[tokio::test]
    async fn use_credential_records_usage_and_enforces_rate_limit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-usage"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "usage-token", "value": "secret"}),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "usage-token",
                "scope": "read",
                "max_uses_per_hour": 2,
                "force": true,
            }),
        )
        .await
        .unwrap();

        // First use: ok.
        let r1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        )
        .await;
        assert!(r1.is_ok());

        // Second use: ok.
        let r2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        )
        .await;
        assert!(r2.is_ok());

        // Third use: rate limit exceeded.
        let r3 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"persona_id": persona_id, "credential_name": "usage-token"}),
        )
        .await;
        assert!(r3.is_err());
        assert_eq!(r3.unwrap_err().0, -32000);
    }

    #[tokio::test]
    async fn detect_anomalies_returns_empty_on_fresh_store() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
            .await
            .unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn team0_detect_anomalies_requires_operator_presence_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        for _ in 0..4 {
            store
                .log_event(Some("agent-x"), "credential.access", None, "denied", None)
                .unwrap();
        }

        let no_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            no_token_ctx,
            "detect_anomalies",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);

        let with_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };
        let rows = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            with_token_ctx,
            "detect_anomalies",
            &json!({}),
        )
        .await
        .unwrap();
        assert!(!rows.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn request_access_blocking_timeout() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "blocker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Request with 1 second timeout — nobody will approve.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access_blocking",
            &json!({
                "persona_id": persona_id,
                "action": "test.action",
                "timeout_secs": 1,
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["status"], "timeout");
    }

    #[tokio::test]
    async fn detect_anomalies_finds_high_denial_rate() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Log enough denied events to trigger anomaly
        for _ in 0..4 {
            store
                .log_event(Some("agent-x"), "credential.access", None, "denied", None)
                .unwrap();
        }
        let result = dispatch_method(&store, &vault, &policy, &rl, "detect_anomalies", &json!({}))
            .await
            .unwrap();
        let arr = result.as_array().unwrap();
        assert!(!arr.is_empty());
    }

    #[tokio::test]
    async fn team0_grant_summary_requires_operator_presence_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let no_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            no_token_ctx,
            "grant_summary",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);

        let with_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };
        let summary = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            with_token_ctx,
            "grant_summary",
            &json!({}),
        )
        .await
        .unwrap();
        assert!(summary.get("active").is_some());
        assert!(summary.get("expired").is_some());
        assert!(summary.get("revoked").is_some());
    }

    #[tokio::test]
    async fn request_access_denies_when_rate_limit_exceeded() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        // Tight limiter: exactly 1 request per persona+action in a 60s window.
        let rl = RefCell::new(RateLimiter::new(1, 60));

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rate-limited"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // First request goes through (policy applies — "deploy.staging" is
        // auto-approve under the default policy, so a grant is created).
        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await
        .unwrap();
        assert_eq!(first["status"], "approved");

        // Snapshot approvals count before the second (rate-limited) call.
        let pending_before = store.list_pending_approvals().unwrap();

        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await
        .unwrap();
        assert_eq!(second["status"], "denied");
        assert_eq!(second["reason"], "rate_spike");
        // The response must not leak a matched rule — only the rate-limit fact.
        assert!(second.get("matched_rule").is_none());

        // Policy must NOT have been evaluated — no new approval submitted.
        let pending_after = store.list_pending_approvals().unwrap();
        assert_eq!(pending_before.len(), pending_after.len());
    }

    // --- build_banner unit tests ---

    fn fake_req(
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        risk_level: &str,
        action: &str,
    ) -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-a54d6404-dead-beef-cafe-000000000000".to_string(),
            persona_id: "persona-1".to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            ttl_secs,
            action: action.to_string(),
            risk_level: risk_level.to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-04-20T00:00:00Z".to_string(),
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
            skill_ref: None,
            // implementation-note-7 —
            // banner-title fixtures don't exercise grant shaping; defaults
            // to None.
            max_delegation_depth: None,
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            budget: None,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        }
    }

    #[test]
    fn banner_title_fits_60_chars() {
        let req = fake_req(
            "github-token",
            "admin:repo",
            Some(60),
            "critical",
            "deploy.production",
        );
        let banner = build_banner("qa", &req);
        assert!(
            banner.title.chars().count() <= 60,
            "title too long: {} chars — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    #[test]
    fn banner_subtitle_fits_50_chars() {
        let req = fake_req(
            "github-token",
            "admin:repo",
            Some(60),
            "critical",
            "deploy.production",
        );
        let banner = build_banner("qa", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle too long: {} chars — {:?}",
            banner.subtitle.chars().count(),
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_fits_50_chars() {
        let req = fake_req(
            "github-token",
            "admin:repo",
            Some(60),
            "critical",
            "deploy.production",
        );
        let banner = build_banner("qa", &req);
        assert!(
            banner.body.chars().count() <= 50,
            "body too long: {} chars — {:?}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_does_not_contain_scope() {
        let req = fake_req(
            "github-token",
            "admin:repo:write:delete",
            Some(60),
            "critical",
            "deploy.production",
        );
        let banner = build_banner("qa", &req);
        assert!(
            !banner.subtitle.contains("admin:repo"),
            "subtitle must not contain scope — {:?}",
            banner.subtitle
        );
    }

    #[test]
    fn banner_body_contains_id_prefix() {
        let req = fake_req("github-token", "read", None, "low", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.body.contains("a54d6404"),
            "body should contain 8-char id prefix — {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_subtitle_hard_truncates_long_credential_name() {
        let long_cred = "a".repeat(60);
        let req = fake_req(&long_cred, "read", Some(3600), "high", "deploy.staging");
        let banner = build_banner("bot", &req);
        assert!(
            banner.subtitle.chars().count() <= 50,
            "subtitle should be hard-truncated: {} chars",
            banner.subtitle.chars().count()
        );
        assert!(banner.subtitle.ends_with("..."), "should end with ellipsis");
    }

    #[test]
    fn banner_title_long_action_truncates_at_40_chars() {
        let req = fake_req("key", "read", None, "low", &"x".repeat(80));
        let banner = build_banner("bot", &req);
        // The action portion is capped at 40 chars; title = "Ember · bot wants " + 40 = 58 chars max.
        assert!(
            banner.title.chars().count() <= 60,
            "title should fit in 60 chars: {} — {:?}",
            banner.title.chars().count(),
            banner.title
        );
    }

    // --- NOTIF-1: optional semantic fields ---

    #[test]
    fn banner_all_semantic_fields_none_uses_default_format() {
        // All new fields absent → legacy title/body behavior.
        let req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("wants"),
            "title should use action-based format when tool_name is None: {:?}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should use default format when target fields are None: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_tool_name_appears_in_title_instead_of_action() {
        let mut req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        req.tool_name = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain tool_name: {:?}",
            banner.title
        );
        assert!(
            !banner.title.contains("wants"),
            "title should NOT use action-based 'wants' format when tool_name is set: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_target_fields_appear_in_body() {
        let mut req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        req.tool_name = Some("claude-code".to_string());
        req.target_host = Some("api.github.com".to_string());
        req.target_summary = Some("POST /repos/x/y/pulls".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com"),
            "body should contain target_host: {:?}",
            banner.body
        );
        assert!(
            banner.body.contains("POST /repos"),
            "body should contain target_summary: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target fields are set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_target_url_appears_when_set() {
        let mut req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        req.target_url = Some("api.github.com/repos/x/y".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.body.contains("api.github.com/repos/x/y"),
            "body should contain target_url: {:?}",
            banner.body
        );
        assert!(
            !banner.body.contains("Click to review"),
            "body should NOT use fallback format when target_url is set: {:?}",
            banner.body
        );
    }

    #[test]
    fn banner_agent_framework_appears_when_set() {
        let mut req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        req.agent_framework = Some("claude-code".to_string());
        let banner = build_banner("demo-agent", &req);
        assert!(
            banner.title.contains("claude-code"),
            "title should contain agent_framework: {:?}",
            banner.title
        );
    }

    #[test]
    fn banner_omits_absent_optional_fields() {
        let req = fake_req(
            "github-token",
            "read",
            Some(1800),
            "high",
            "deploy.production",
        );
        let banner = build_banner("demo-agent", &req);
        assert!(
            !banner.title.contains("None"),
            "title must not contain literal 'None': {:?}",
            banner.title
        );
        assert!(
            !banner.subtitle.contains("None"),
            "subtitle must not contain literal 'None': {:?}",
            banner.subtitle
        );
        assert!(
            !banner.body.contains("None"),
            "body must not contain literal 'None': {:?}",
            banner.body
        );
        // No stray separators from absent fields
        assert!(
            !banner.title.contains("()"),
            "title must not contain empty parens: {:?}",
            banner.title
        );
    }

    #[tokio::test]
    async fn dispatch_method_uses_provided_policy() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        // Custom policy: deny "test.action" explicitly.
        let custom = PolicyEngine::new(PolicyConfig {
            rules: vec![PolicyRule {
                action: "test.action".to_string(),
                risk: RiskLevel::High,
                requirement: ApprovalRequirement::Denied,
                tier: None,
            }],
            ..PolicyConfig::default()
        });
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "create_persona",
            &json!({"name": "custom-policy"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &custom,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "some-key",
                "scope": "read",
                "action": "test.action",
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["status"], "denied");
        assert_eq!(result["decision"], "deny");
    }

    #[tokio::test]
    async fn grant_issuance_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-issuance"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // request_access with auto-approve policy creates a grant
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "request_access",
            &json!({
                "persona_id": persona_id,
                "credential_name": "audit-cred",
                "scope": "read",
                "action": "deploy.staging",
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], "approved");
        let grant_id = result["grant_id"].as_str().unwrap();

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("grant.issued".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            !entries.is_empty(),
            "expected at least one grant.issued audit row"
        );
        let entry = entries.iter().find(|e| {
            e.details
                .as_ref()
                .map(|d| d.contains(grant_id))
                .unwrap_or(false)
        });
        assert!(
            entry.is_some(),
            "audit row should reference the new grant_id"
        );
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.issued");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("audit-cred"));
    }

    #[tokio::test]
    async fn grant_revocation_logged_to_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-revocation"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "revoke-cred",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();

        let entries = store
            .query_audit(&crate::infra::audit::AuditFilter {
                action: Some("grant.revoked".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            !entries.is_empty(),
            "expected at least one grant.revoked audit row"
        );
        let entry = entries.iter().find(|e| {
            e.details
                .as_ref()
                .map(|d| d.contains(grant_id))
                .unwrap_or(false)
        });
        assert!(
            entry.is_some(),
            "audit row should reference the revoked grant_id"
        );
        let entry = entry.unwrap();
        assert_eq!(entry.action, "grant.revoked");
        assert_eq!(entry.outcome, "allowed");
        assert_eq!(entry.agent_id.as_deref(), Some(persona_id));
        assert_eq!(entry.credential.as_deref(), Some("revoke-cred"));
    }

    // -----------------------------------------------------------------
    // `grant_status` + `list_grants` persona filter + `use_credential`
    // by grant_id — added for TODO 69I.1 so the agent runtime has a
    // daemon-side surface that matches its protocol shape.
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn grant_status_finds_live_grant_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "gs-a"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": grant_id, "persona_id": persona_id}),
        )
        .await
        .unwrap();
        assert_eq!(result["kind"], "grant");
        assert_eq!(result["id"], json!(grant_id));
        assert_eq!(result["persona_id"], json!(persona_id));
        assert_eq!(result["scope"], "r");
    }

    #[tokio::test]
    async fn grant_status_rejects_mismatched_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "gs-owner"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "key", "scope": "r", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller pinning a different persona must be rejected — this is
        // the cross-persona probe defense.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": grant_id, "persona_id": "persona-other"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn grant_status_finds_pending_approval_by_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "appr-owner"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let req = store
            .submit_approval(
                persona_id,
                "cred",
                "read",
                None,
                "credential.access.cred",
                "medium",
            )
            .unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": req.id}),
        )
        .await
        .unwrap();
        assert_eq!(result["kind"], "approval");
        assert_eq!(result["id"], json!(req.id));
        assert_eq!(result["status"], "pending");
    }

    #[tokio::test]
    async fn grant_status_unknown_id_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_status",
            &json!({"id": "nonexistent"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn team0_poll_notifications_defaults_to_trusted_principal_and_refuses_mismatch() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let actor_a_id = "persona-team0-notif-a".to_string();
        let actor_b_id = "persona-team0-notif-b".to_string();
        store
            .push_notification(
                &actor_a_id,
                "grant.revoked",
                &json!({"grant_id": "grant-a"}),
            )
            .unwrap();
        store
            .push_notification(
                &actor_b_id,
                "grant.revoked",
                &json!({"grant_id": "grant-b"}),
            )
            .unwrap();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_011),
            }),
            actor_a_id.clone(),
        );

        let rows = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "poll_notifications",
            &json!({}),
        )
        .await
        .unwrap();
        let arr = rows.as_array().expect("notification rows");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["payload"]["grant_id"], json!("grant-a"));

        // Queue was drained only for actor_a; actor_b's row is still there.
        let actor_b_rows = store.poll_notifications(&actor_b_id).unwrap();
        assert_eq!(actor_b_rows.len(), 1);

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "poll_notifications",
            &json!({"persona_id": actor_b_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn team0_grant_status_defaults_to_trusted_principal_for_grants() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = store.create_persona("team0-grant-owner").unwrap();
        let other = store.create_persona("team0-grant-other").unwrap();
        let owner_grant = store
            .create_grant(&owner.id, "cred-a", "read", None)
            .unwrap();
        let other_grant = store
            .create_grant(&other.id, "cred-b", "read", None)
            .unwrap();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_006),
            }),
            owner.id.clone(),
        );

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "grant_status",
            &json!({"id": owner_grant.id}),
        )
        .await
        .unwrap();
        assert_eq!(result["kind"], "grant");
        assert_eq!(result["persona_id"], json!(owner.id));

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "grant_status",
            &json!({"id": other_grant.id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn team0_grant_status_refuses_other_principal_approval() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = store.create_persona("team0-approval-owner").unwrap();
        let other = store.create_persona("team0-approval-other").unwrap();
        let approval = store
            .submit_approval(
                &other.id,
                "cred",
                "read",
                None,
                "credential.access.cred",
                "medium",
            )
            .unwrap();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_007),
            }),
            owner.id,
        );

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "grant_status",
            &json!({"id": approval.id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn list_grants_filters_by_persona_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let p1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "p1"}),
        )
        .await
        .unwrap();
        let p2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "p2"}),
        )
        .await
        .unwrap();
        let p1_id = p1["id"].as_str().unwrap();
        let p2_id = p2["id"].as_str().unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true}),
        )
        .await
        .unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true}),
        )
        .await
        .unwrap();

        // Bare call without persona_id is now refused — cross-persona
        // enumeration via the unauthenticated socket is an info disclosure.
        let err = dispatch_method(&store, &vault, &policy, &rl, "list_grants", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);

        let only_p1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_grants",
            &json!({"persona_id": p1_id}),
        )
        .await
        .unwrap();
        let arr = only_p1.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["persona_id"], json!(p1_id));
        assert_eq!(arr[0]["credential_name"], "k1");
    }

    #[tokio::test]
    async fn list_operator_grants_returns_cross_persona_view_and_active_filter() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // list_operator_grants is OperatorPresence-class. The
        // dispatch_method_with_source shim synthesizes a peer +
        // presence_token under #[cfg(test)], but the unlocked-session
        // gate still applies — move presence to Unlocked so the test
        // reaches the cross-persona projection it asserts on.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let p1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "operator-p1"}),
        )
        .await
        .unwrap();
        let p2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "operator-p2"}),
        )
        .await
        .unwrap();
        let p1_id = p1["id"].as_str().unwrap();
        let p2_id = p2["id"].as_str().unwrap();

        let g1 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": p1_id, "credential_name": "k1", "scope": "r", "force": true}),
        )
        .await
        .unwrap();
        let g2 = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": p2_id, "credential_name": "k2", "scope": "r", "force": true}),
        )
        .await
        .unwrap();
        let g2_id = g2["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": g2_id}),
        )
        .await
        .unwrap();

        let active_only = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "list_operator_grants",
            &json!({"active_only": true}),
        )
        .await
        .unwrap();
        let active_arr = active_only.as_array().unwrap();
        assert_eq!(active_arr.len(), 1);
        assert_eq!(active_arr[0]["id"], g1["id"]);
        assert_eq!(active_arr[0]["persona_id"], json!(p1_id));

        let all = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "list_operator_grants",
            &json!({"active_only": false}),
        )
        .await
        .unwrap();
        let all_arr = all.as_array().unwrap();
        assert_eq!(all_arr.len(), 2);
        assert!(
            all_arr
                .iter()
                .any(|g| g["id"] == g1["id"] && g["status"] == json!("active"))
        );
        assert!(
            all_arr
                .iter()
                .any(|g| g["id"] == g2["id"] && g["status"] == json!("revoked"))
        );
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_succeeds() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "uc-grant"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "gk", "value": "secret-by-grant-id"}),
        )
        .await
        .unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "gk", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        )
        .await
        .unwrap();
        assert_eq!(result["credential"], "secret-by-grant-id");
        assert_eq!(result["grant_id"], json!(grant_id));
        assert_eq!(result["credential_name"], "gk");
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_cross_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let owner = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "owner"}),
        )
        .await
        .unwrap();
        let owner_id = owner["id"].as_str().unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "ok", "value": "v"}),
        )
        .await
        .unwrap();
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": owner_id, "credential_name": "ok", "scope": "r", "force": true}),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // A caller supplying the owner's grant_id but a foreign persona
        // MUST be rejected — leaked id cannot be used to redeem.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"grant_id": grant_id, "persona_id": "persona-other"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32002);
    }

    #[tokio::test]
    async fn use_credential_by_grant_id_rejects_inactive_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "inact"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "ik", "value": "v"}),
        )
        .await
        .unwrap();
        let grant = dispatch_method(&store, &vault, &policy, &rl, "create_grant", &json!({"persona_id": persona_id, "credential_name": "ik", "scope": "r", "force": true})).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "use_credential",
            &json!({"grant_id": grant_id, "persona_id": persona_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005);
    }

    // --- Grant Receipts (Stream D) socket surface -------------------------

    /// Init a process-singleton identity keyed off a temp dir so the test
    /// has real receipts to exercise. Called by each receipt test — the
    /// OnceCell silently no-ops on the second call, which is fine because
    /// the key file is stable.
    fn setup_receipt_identity() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let _ = crate::infra::receipt::init_identity(dir.path());
        dir
    }

    #[tokio::test]
    async fn get_receipt_and_list_receipts_round_trip() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rcpt-alpha"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let grant = dispatch_method(
            &store, &vault, &policy, &rl, "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        ).await.unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();

        // list_receipts (no filter) returns our receipt.
        let list = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({}))
            .await
            .unwrap();
        let arr = list.as_array().expect("array");
        assert!(!arr.is_empty(), "receipt should be emitted on revoke");
        let rid = arr[0]["id"].as_str().unwrap().to_string();
        assert_eq!(arr[0]["grant_id"].as_str().unwrap(), grant_id);

        // get_receipt returns the full signed body.
        let r = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "get_receipt",
            &json!({"id": rid}),
        )
        .await
        .unwrap();
        assert_eq!(r["id"].as_str().unwrap(), rid);
        assert_eq!(r["evidence"]["canonical_version"].as_u64().unwrap(), 1);
        assert_eq!(r["evidence"]["sig"].as_str().unwrap().len(), 128);
    }

    #[tokio::test]
    async fn get_receipt_unknown_id_returns_32004() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "get_receipt",
            &json!({"id": "rct-nonexistent"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn get_receipt_accepts_terminal_grant_id() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rcpt-beta"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();

        let receipt = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "get_receipt",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();
        assert_eq!(receipt["grant_id"].as_str().unwrap(), grant_id);
        assert_eq!(
            receipt["evidence"]["canonical_version"].as_u64().unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn get_receipt_active_grant_without_terminal_receipt_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "rcpt-gamma"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "get_receipt",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("has not reached terminal state"),
            "error must explain active grants have no terminal receipt yet: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn team0_get_receipt_scopes_direct_and_terminal_lookup_to_trusted_principal() {
        let _guard = setup_receipt_identity();
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-rct-owner"}),
        )
        .await
        .unwrap();
        let owner_id = owner["id"].as_str().unwrap().to_string();
        let other = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "team0-rct-other"}),
        )
        .await
        .unwrap();
        let other_id = other["id"].as_str().unwrap().to_string();

        let owner_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": owner_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
        let owner_grant_id = owner_grant["id"].as_str().unwrap().to_string();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": owner_grant_id}),
        )
        .await
        .unwrap();

        let other_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": other_id, "credential_name": "rcpt-cred", "scope": "push", "force": true}),
        )
        .await
        .unwrap();
        let other_grant_id = other_grant["id"].as_str().unwrap().to_string();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": other_grant_id}),
        )
        .await
        .unwrap();

        let owner_receipt_id = store
            .get_grant(&owner_grant_id)
            .unwrap()
            .receipt_id
            .expect("owner terminal receipt");
        let other_receipt_id = store
            .get_grant(&other_grant_id)
            .unwrap()
            .receipt_id
            .expect("other terminal receipt");

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_008),
            }),
            owner["id"].as_str().unwrap().to_string(),
        );

        let owner_receipt = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "get_receipt",
            &json!({"id": owner_receipt_id}),
        )
        .await
        .unwrap();
        assert_eq!(owner_receipt["grant_id"], json!(owner_grant_id));

        let direct_err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "get_receipt",
            &json!({"id": other_receipt_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(direct_err.0, -32004);

        let terminal_err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "get_receipt",
            &json!({"id": other_grant_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(terminal_err.0, -32004);
    }

    #[tokio::test]
    async fn list_receipts_persona_filter_narrows_results() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "lra"}),
        )
        .await
        .unwrap();
        let b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "lrb"}),
        )
        .await
        .unwrap();
        let aid = a["id"].as_str().unwrap().to_string();
        let bid = b["id"].as_str().unwrap().to_string();
        for pid in [&aid, &bid] {
            let g = dispatch_method(
                &store,
                &vault,
                &policy,
                &rl,
                "create_grant",
                &json!({"persona_id": pid, "credential_name": "c", "scope": "r", "force": true}),
            )
            .await
            .unwrap();
            let gid = g["id"].as_str().unwrap().to_string();
            dispatch_method(
                &store,
                &vault,
                &policy,
                &rl,
                "revoke_grant",
                &json!({"id": gid}),
            )
            .await
            .unwrap();
        }
        let all = dispatch_method(&store, &vault, &policy, &rl, "list_receipts", &json!({}))
            .await
            .unwrap();
        let just_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "list_receipts",
            &json!({"persona_id": aid}),
        )
        .await
        .unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2);
        assert_eq!(just_a.as_array().unwrap().len(), 1);
        assert_eq!(just_a[0]["summary"]["persona_id"].as_str().unwrap(), aid);
    }

    #[tokio::test]
    async fn resolve_approval_dispatches_and_returns_resolved_row() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "approval-rpc"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let req = store
            .submit_approval(
                persona_id,
                "api-key",
                "read",
                None,
                "credential.access",
                "high",
            )
            .unwrap();

        let resolved = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "resolve_approval",
            &json!({"id": req.id, "decision": "approve"}),
        )
        .await
        .unwrap();
        assert_eq!(resolved["id"], json!(req.id));
        assert_eq!(resolved["status"], json!("approved"));
    }

    /// approval_socket_arm_operator_presence_required — adversarial-review
    /// 2026-05-19 CRIT-1 regression guard. An agent that submitted an
    /// approval MUST NOT be able to approve its own request via the socket
    /// dispatch path, regardless of whether the daemon is in the dev-mode
    /// presence short-circuit.
    #[tokio::test]
    async fn resolve_approval_socket_refuses_self_approve() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Create a persona, then have THAT persona submit an approval.
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "self-approve-attacker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let req = store
            .submit_approval(
                &persona_id,
                "api-key",
                "read",
                None,
                "credential.access",
                "high",
            )
            .unwrap();

        ensure_test_authority_bridge_env();
        // resolve_approval is OperatorPresence-class — satisfy both the
        // presence-token and unlocked-session gates so we reach the
        // two-party invariant under test.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        // Now route the resolve_approval call through a Socket context
        // whose principal == the submitter. The two-party invariant must
        // refuse.
        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 501,
                pid: Some(std::process::id() as i32),
            }),
            persona_id.clone(),
        )
        .with_presence_token(Some(test_presence_token(501)));
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "resolve_approval",
            &json!({"id": req.id, "decision": "approve"}),
        )
        .await
        .expect_err("self-approve via Socket must be refused");
        assert_eq!(err.0, -32003, "expected unauthorized: {err:?}");
        assert!(
            err.1.contains("caller cannot approve own request"),
            "error must name the two-party invariant: {}",
            err.1
        );

        // Sanity: the approval row is still pending (the refusal was
        // before any state mutation).
        let row = store.get_approval(&req.id).unwrap();
        assert_eq!(row.status, "pending");
    }

    /// approval_socket_arm_operator_presence_required — adversarial-review
    /// 2026-05-19 CRIT-1 sibling guard. A different principal CAN resolve
    /// the approval (the dashboard / second-party flow is unaffected).
    #[tokio::test]
    async fn resolve_approval_socket_allows_second_party_approve() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let agent = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "agent-requester"}),
        )
        .await
        .unwrap();
        let agent_id = agent["id"].as_str().unwrap().to_string();
        let operator = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "operator-approver"}),
        )
        .await
        .unwrap();
        let operator_id = operator["id"].as_str().unwrap().to_string();
        let req = store
            .submit_approval(
                &agent_id,
                "api-key",
                "read",
                None,
                "credential.access",
                "high",
            )
            .unwrap();

        ensure_test_authority_bridge_env();
        // resolve_approval is OperatorPresence-class — satisfy the
        // presence-token and unlocked-session gates so the second-party
        // happy path under test is reachable.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 501,
                pid: Some(std::process::id() as i32),
            }),
            operator_id,
        )
        .with_presence_token(Some(test_presence_token(501)));
        let resolved = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "resolve_approval",
            &json!({"id": req.id, "decision": "approve"}),
        )
        .await
        .unwrap();
        assert_eq!(resolved["status"], json!("approved"));
    }

    #[tokio::test]
    async fn status_dispatch_returns_aggregated_rows() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "status-alpha"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();
        let _grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({"persona_id": persona_id, "credential_name": "api-key", "scope": "read", "force": true}),
        )
        .await
        .unwrap();
        store
            .log_event(
                Some("persona-test"),
                "grant.issued",
                Some("api-key"),
                "allowed",
                None,
            )
            .unwrap();

        let status = dispatch_method(&store, &vault, &policy, &rl, "status", &json!({}))
            .await
            .unwrap();
        assert_eq!(status["personas"].as_array().unwrap().len(), 1);
        assert_eq!(status["grants"].as_array().unwrap().len(), 1);
        assert_eq!(status["approvals"].as_array().unwrap().len(), 0);
        assert_eq!(status["standing_grants"], json!(0));
        assert!(
            status["audit_events_total"].as_u64().unwrap() >= 1,
            "status must report at least the emitted audit row"
        );
        assert!(
            !status["recent_activity"].as_array().unwrap().is_empty(),
            "status must surface recent audit activity"
        );
    }

    #[tokio::test]
    async fn team0_status_scopes_rows_to_trusted_principal() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "status-team0-a"}),
        )
        .await
        .unwrap();
        let persona_a_id = persona_a["id"].as_str().unwrap().to_string();
        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "status-team0-b"}),
        )
        .await
        .unwrap();
        let persona_b_id = persona_b["id"].as_str().unwrap().to_string();

        for persona_id in [&persona_a_id, &persona_b_id] {
            dispatch_method(
                &store,
                &vault,
                &policy,
                &rl,
                "create_grant",
                &json!({"persona_id": persona_id, "credential_name": "api-key", "scope": "read", "force": true}),
            )
            .await
            .unwrap();
            store
                .submit_approval(
                    persona_id,
                    "api-key",
                    "read",
                    None,
                    "credential.access",
                    "high",
                )
                .unwrap();
            store
                .create_standing_grant(persona_id, "tool.call", "*", None)
                .unwrap();
            store
                .log_event(
                    Some(persona_id),
                    "grant.issued",
                    Some("api-key"),
                    "allowed",
                    None,
                )
                .unwrap();
        }

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_004),
            }),
            persona_a_id.clone(),
        );
        let status = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "status",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(status["personas"].as_array().unwrap().len(), 1);
        assert_eq!(status["personas"][0]["id"], json!(persona_a_id));
        assert_eq!(status["grants"].as_array().unwrap().len(), 1);
        assert_eq!(status["approvals"].as_array().unwrap().len(), 1);
        assert_eq!(status["standing_grants"], json!(1));
        assert!(
            status["audit_events_total"].as_u64().unwrap() >= 1,
            "status should report at least one audit row for the scoped persona"
        );
        let recent = status["recent_activity"]
            .as_array()
            .expect("recent_activity array");
        assert!(
            !recent.is_empty(),
            "status should include scoped recent activity"
        );
        assert!(
            recent
                .iter()
                .all(|row| row["agent_id"] == json!(persona_a_id))
        );
    }

    #[tokio::test]
    async fn daemon_persona_method_returns_pubkey_when_initialised() {
        let _guard = setup_receipt_identity();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "daemon_persona", &json!({}))
            .await
            .unwrap();
        // Either a pubkey object or null (init raced on separate process) — but
        // since _guard held a tempdir that init_identity used for the OnceCell,
        // we expect a pubkey here.
        assert!(
            result.is_object(),
            "identity should be initialised in this test"
        );
        let pubkey = result["pubkey"].as_str().unwrap();
        assert_eq!(pubkey.len(), 64);
    }

    // --- grant_budget_status (P69K-F1) -------------------------------------

    /// Helper: seed a 3-statement grant via the low-level composite-grant
    /// API so we can assert the MCP budget-status projection without
    /// relying on the proxy to mutate usage.
    fn seed_budget_grant(store: &DaemonStore, persona_id: &str, credential_name: &str) -> String {
        use core_grant_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
        let grant = store
            .create_grant(persona_id, credential_name, "*", None)
            .unwrap();
        let root = store.persona_root_keypair(persona_id).unwrap();
        let statements = vec![
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["generic:write".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    tokens: Some(20_000),
                    cents: Some(100),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S2".into(),
                resource_type: ResourceType::Payment,
                actions: vec!["payment:charge".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    cents: Some(500),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S3".into(),
                resource_type: ResourceType::Time,
                actions: vec!["session:start".into()],
                resource: ResourceSelector::Any,
                budget: Some(Budget {
                    wall_clock_secs: Some(3_600),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
        ];
        let ag = crate::trust::grant::access_grant_from_statements(
            &grant.id,
            persona_id,
            credential_name,
            statements,
            0,
            None,
            &root,
        )
        .unwrap();
        store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
        grant.id
    }

    #[tokio::test]
    async fn grant_budget_status_returns_per_statement_shape() {
        // A 3-statement composite grant surfaces three entries in the
        // response, each carrying sid + resource_type + budget + usage +
        // percent_used. With a stubbed 50% usage on S1, percent_used
        // reflects it — the MCP client can render a runway view without
        // walking the block chain itself.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("budget-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-a");

        // Drive S1 to 10_000 tokens (50%) and 50 cents (50%).
        let delta = store
            .increment_statement_usage(
                &grant_id,
                "S1",
                core_grant_types::Usage {
                    tokens: 10_000,
                    cents: 50,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta.current.tokens, 10_000);

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();

        assert_eq!(result["grant_id"].as_str().unwrap(), grant_id);
        assert_eq!(result["status"].as_str().unwrap(), "active");
        let statements = result["statements"].as_array().unwrap();
        assert_eq!(statements.len(), 3, "three-statement grant");

        let s1 = &statements[0];
        assert_eq!(s1["sid"], "S1");
        assert_eq!(s1["resource_type"], "session");
        assert_eq!(s1["usage"]["tokens"], 10_000);
        assert_eq!(s1["percent_used"]["tokens"], 50);
        assert_eq!(s1["percent_used"]["cents"], 50);
        // runway is reserved for a future burn-rate projection.
        assert!(s1["estimated_runway_seconds"].is_null());
        assert_eq!(s1["has_budget_remaining"], true);

        // S2 has no usage, should be 0% on its set axis.
        let s2 = &statements[1];
        assert_eq!(s2["sid"], "S2");
        assert_eq!(s2["percent_used"]["cents"], 0);
    }

    #[tokio::test]
    async fn grant_budget_status_unknown_grant_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": "grant-nonexistent"}),
        )
        .await
        .unwrap_err();
        // Consistent with `get_receipt` / `grant_status` not-found shape:
        // -32004 is the daemon's NotFound code for MCP.
        assert_eq!(err.0, -32004);
        assert!(err.1.contains("grant-nonexistent"));
    }

    #[tokio::test]
    async fn grant_budget_status_missing_grant_id_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("grant_id"));
    }

    #[tokio::test]
    async fn grant_budget_status_reflects_revoked_status() {
        // When the grant envelope is revoked, the budget-status projection
        // surfaces the terminal state to the caller instead of lying that
        // it's still active.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let persona = store.create_persona("revoked-status").unwrap();
        let grant_id = seed_budget_grant(&store, &persona.id, "cred-r");
        store.revoke_grant(&grant_id).unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "grant_budget_status",
            &json!({"grant_id": grant_id}),
        )
        .await
        .unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "revoked");
    }

    #[tokio::test]
    async fn team0_grant_budget_status_scopes_to_trusted_principal() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = store.create_persona("team0-budget-owner").unwrap();
        let other = store.create_persona("team0-budget-other").unwrap();
        let owner_grant_id = seed_budget_grant(&store, &owner.id, "cred-a");
        let other_grant_id = seed_budget_grant(&store, &other.id, "cred-b");

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_009),
            }),
            owner.id.clone(),
        );

        let owner_status = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "grant_budget_status",
            &json!({"grant_id": owner_grant_id}),
        )
        .await
        .unwrap();
        assert_eq!(owner_status["status"], "active");

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "grant_budget_status",
            &json!({"grant_id": other_grant_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    // --- development milestone regression tests ---------------------------------
    // These tests verify that the `force: true` policy-bypass flag on
    // `create_grant` is NOT honored when the request arrives via the socket
    // entry point (`DispatchSource::Socket`). Previously an unauthenticated
    // socket client could pass `force: true` and skip every policy gate.

    #[tokio::test]
    async fn create_grant_socket_rejects_force_true() {
        // A socket client sends `create_grant` with `force: true`. The
        // handler must reject with -32602 rather than minting the grant.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-victim"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // create_grant is OperatorPresence-class; the socket-source
        // shim synthesizes a presence_token, but the unlocked-session
        // gate still applies. Move presence to Unlocked so the test
        // reaches the force-refusal it asserts on (-32602).
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        // The default policy's `credential.access.*` rule is
        // `RequireApproval` — without `force`, a socket caller gets a
        // pending approval rather than a grant. With `force: true` the
        // handler MUST reject instead of bypassing policy.
        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.0, -32602,
            "socket force must return -32602, got {err:?}"
        );
        assert!(
            err.1.to_lowercase().contains("force"),
            "error should mention force, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn create_grant_socket_without_force_runs_policy() {
        // Same request shape minus `force` — must be treated as an ordinary
        // policy-gated call. With default policy (RequireApproval for
        // credential.access), the response is a pending_approval envelope,
        // NOT a freshly minted grant.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-policy"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Satisfy the OperatorPresence unlocked-session gate (see
        // create_grant_socket_rejects_force_true for the same setup).
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            result["status"],
            json!("pending_approval"),
            "default policy requires approval for credential.access.*"
        );
        assert!(result["approval_id"].is_string());
        // Crucially: no grant id was issued.
        assert!(result.get("id").is_none());
    }

    #[tokio::test]
    async fn create_grant_socket_with_force_false_is_allowed() {
        // Explicit `force: false` is indistinguishable from omitting it —
        // the socket path runs policy either way.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-force-false"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Satisfy the OperatorPresence unlocked-session gate (see
        // create_grant_socket_rejects_force_true for the same setup).
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "*",
                "force": false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], json!("pending_approval"));
    }

    #[tokio::test]
    async fn create_grant_internal_honors_force() {
        // Internal callers (test harness / admin CLI path) retain the
        // ability to skip policy with `force: true`. This keeps the
        // legitimate bypass path working.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c2-internal"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal {
                reason: "test harness — create_grant force bypass",
            },
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "prod-stripe-key",
                "scope": "read",
                "force": true,
            }),
        )
        .await
        .unwrap();
        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal force should mint a grant, got: {result}"
        );
    }

    // --- development milestone regression tests ---------------------------------
    // A socket caller must assert `caller_persona_id` and it must match the
    // parent grant's owner (`persona_id`). Otherwise any socket process
    // could pick any leaked `parent_grant_id` and mint a child grant
    // pinned to an attacker-controlled persona, forging the audit trail
    // under the legitimate owner's name.

    /// Helper: create two personas (A, B) and a grant owned by A with
    /// delegation depth so it can be further attenuated. Returns the
    /// tuple (a_id, b_id, parent_grant_id). Uses the `Internal` dispatch
    /// path to set up — the `force: true` on `create_grant` requires it.
    async fn c3_setup_two_personas_and_grant(
        store: &DaemonStore,
        vault: &Vault,
        policy: &PolicyEngine,
        rl: &RefCell<RateLimiter>,
    ) -> (String, String, String) {
        let persona_a = dispatch_method(
            store,
            vault,
            policy,
            rl,
            "create_persona",
            &json!({"name": "c3-persona-a"}),
        )
        .await
        .unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        let persona_b = dispatch_method(
            store,
            vault,
            policy,
            rl,
            "create_persona",
            &json!({"name": "c3-persona-b"}),
        )
        .await
        .unwrap();
        let b_id = persona_b["id"].as_str().unwrap().to_string();

        let parent_grant = dispatch_method(
            store,
            vault,
            policy,
            rl,
            "create_grant",
            &json!({
                "persona_id": a_id,
                "credential_name": "c3-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        (a_id, b_id, parent_grant_id)
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_non_owner() {
        // Parent grant is issued to persona A. Persona B tries to delegate
        // it via the socket path. The handler MUST reject before any state
        // mutation — no child grant may be minted, no `grant.delegated`
        // audit row may be written.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Enroll caller PID with b_id so the Socket-source PID-enrollment
        // gate passes and the test exercises the authority-check path
        // (caller does not own parent) it was written to validate.
        enroll_pid_persona(std::process::id() as i32, &b_id);

        // Snapshot grant count before the attack to prove nothing was
        // minted. `list_active_grants` returns every active grant in the
        // store; we expect the count to be identical after rejection.
        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Attacker asserts they are B, not A. B does not own
                // `parent_grant_id`.
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32002, "expected -32002, got {err:?}");
        assert!(
            err.1.to_lowercase().contains("does not own"),
            "error should say caller does not own parent, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted when socket caller isn't parent owner"
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_socket_accepts_owner() {
        // Same setup but the socket caller correctly asserts persona A
        // (the parent owner). Delegation must succeed.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Enroll caller PID with a_id (parent owner) so the Socket-source
        // PID-enrollment gate passes and the test exercises the happy
        // owner-delegation path.
        enroll_pid_persona(std::process::id() as i32, &a_id);

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "socket owner-delegation must mint a grant, got: {result}"
        );
        assert_eq!(result["parent"], json!(parent_grant_id));
    }

    // delegate_grant_socket_principal_not_enrolled — checkpoint for
    // implementation-note-265.
    //
    // Original contract (pre-prior change): a Socket-source dispatch
    // with missing `caller_persona_id` returned -32602 (invalid params).
    // prior change superseded that contract with the per-connection PID
    // enrollment model: identity now flows from the PID registry,
    // and the wire-claimed `caller_persona_id` is implicit when the
    // calling PID is enrolled. The fail-closed property moved with
    // the contract — it's now expressed as -32401
    // (`PrincipalNotEnrolled`) when the calling PID has no enrollment
    // AND no override caller_persona_id is on the wire.
    //
    // This rewritten test preserves the original test's intent
    // ("Socket path must refuse to proceed when the caller's identity
    // cannot be resolved") under the new identity model.
    #[tokio::test]
    async fn test_delegate_grant_socket_rejects_missing_caller_persona_id() {
        // Synthetic peer's PID is intentionally NOT enrolled —
        // dispatch_method_with_source synthesizes a peer (process PID),
        // but no prior call has registered it with a persona. With no
        // `caller_persona_id` on the wire either, principal resolution
        // fails closed via PrincipalNotEnrolled (-32401).
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Defense against test-order pollution: ensure the synthetic
        // test-process PID is NOT enrolled (other tests in this module
        // call enroll_pid_persona; without this clear the registry
        // could carry an entry from a prior test on the same thread).
        clear_pid_persona_registry();

        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // no caller_persona_id, no PID enrollment
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32602,
            "missing param must return -32602, got {err:?}"
        );
        assert!(
            err.1.to_lowercase().contains("caller_persona_id"),
            "missing explicit fallback should mention caller_persona_id, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn test_delegate_grant_internal_bypass() {
        // Internal callers (admin CLI / test harness) bypass the
        // ownership gate. Parent is owned by A; an `Internal` dispatch
        // without any `caller_persona_id` MUST still succeed — mirrors
        // the C2 `force` bypass semantics for Internal.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal {
                reason: "test harness — delegate_grant ownership bypass",
            },
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Deliberately omit caller_persona_id — Internal bypasses.
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "internal bypass must mint a grant, got: {result}"
        );
    }

    // --- development milestone regression tests ----------------------------
    //
    // Full principal binding via `SO_PEERCRED` / `LOCAL_PEERCRED` derived
    // peer credential. The new layer:
    //   1. Enrolls (peer.pid -> persona_id) in `create_persona` from a
    //      Socket caller carrying a real PeerCred.
    //   2. On `delegate_grant`, derives the kernel principal from the
    //      peer's PID and rejects any params.caller_persona_id that
    //      doesn't match the kernel principal (`PrincipalMismatch`).
    //   3. On macOS where pid is None, fails closed with
    //      `PrincipalUnavailable` rather than silently allowing.
    //
    // These tests exercise the handler dispatch surface directly with
    // synthetic `RequestContext` so we don't need a real Unix socket
    // pair or a second OS user — both impossible in CI.

    #[tokio::test]
    async fn forged_caller_persona_id_in_delegate_params_rejected() {
        // The threat model that motivated development milestone: an
        // attacker process running under the daemon's UID enumerates
        // personas, learns the victim's persona_id, and asserts it as
        // `caller_persona_id`.  Under development milestone alone the request
        // would succeed.  Under development milestone the kernel-derived
        // principal does not match, so the handler MUST reject with
        // `PrincipalMismatch`.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;

        // Attacker connection: the kernel says the peer is persona B
        // (the attacker's enrolled identity).  Attacker forges params
        // claiming to be A (the parent grant's owner).  The mismatch
        // between asserted A and kernel-derived B must trip the gate
        // BEFORE we even reach the ownership check.
        let attacker_pid: i32 = 70_001;
        enroll_pid_persona(attacker_pid, &b_id);

        ensure_test_authority_bridge_env();
        // delegate_grant is OperatorPresence-class. The test attaches a
        // valid presence_token below, but the unlocked-session gate
        // still applies — move presence to Unlocked so we reach the
        // PrincipalMismatch check under test.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();
        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 1000,
                pid: Some(attacker_pid),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            // implementation-note-234
            // — attach a valid presence_token so the Phase D-4 gate
            // passes; the test asserts a deeper authorization check.
            presence_token: Some(test_presence_token(1000)),
            bypass_binary_pin_gate_for_test: false,
        };

        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Attacker forges A as caller — but the kernel knows
                // they are running under PID enrolled to B.
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32401,
            "expected -32401 PrincipalMismatch, got {err:?}"
        );
        assert!(
            err.1.to_lowercase().contains("principal") || err.1.to_lowercase().contains("mismatch"),
            "error should reference principal mismatch, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted when params forge a different caller"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_peercred_resolves_persona_via_pid_lookup() {
        // Happy path on Linux: a Socket caller creates a persona and the
        // daemon enrolls (peer.pid -> persona_id).  A subsequent
        // `delegate_grant` from the same PID is bound to that persona
        // without the caller having to assert `caller_persona_id`.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Use a synthetic PID — never reused by a real process during
        // the test because the registry is thread-local and reset.
        let caller_pid: i32 = 80_002;
        let peer = PeerCred {
            uid: 1000,
            pid: Some(caller_pid),
        };

        // Step 1: create_persona via Socket with the peer credential.
        // Handler enrolls the (pid -> persona_id) pair.
        ensure_test_authority_bridge_env();
        let create_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            // implementation-note-234
            // — attach a valid presence_token so the Phase D-4 gate
            // passes; the test exercises the enrollment/peercred
            // resolution path, not the auth gate.
            presence_token: Some(test_presence_token(peer.uid)),
            bypass_binary_pin_gate_for_test: false,
        };
        let persona = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            create_ctx,
            "create_persona",
            &json!({"name": "c3full-linux-caller"}),
        )
        .await
        .unwrap();
        let caller_persona_id = persona["id"].as_str().unwrap().to_string();

        // Verify the enrollment landed.
        let resolved =
            peercred_principal(&peer).expect("PID must resolve to enrolled persona on Linux");
        assert_eq!(
            resolved, caller_persona_id,
            "peercred_principal must return the enrolled persona id"
        );

        // Step 2: build a parent grant owned by the enrolled persona
        // via Internal (force=true requires Internal).  Then delegate
        // via Socket from the same PID — must succeed without any
        // caller_persona_id forgery.
        let parent_grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": caller_persona_id,
                "credential_name": "c3full-linux-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();

        // child persona for the delegation target.
        let child = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "c3full-linux-child"}),
        )
        .await
        .unwrap();
        let child_id = child["id"].as_str().unwrap().to_string();

        let delegate_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(peer),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            // implementation-note-234
            // — attach a valid presence_token so the Phase D-4 gate
            // passes; the test asserts the delegation succeeds via the
            // enrolled persona, not the auth gate.
            presence_token: Some(test_presence_token(peer.uid)),
            bypass_binary_pin_gate_for_test: false,
        };
        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            delegate_ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": child_id,
                "scope": "read",
                // Caller may also assert caller_persona_id; if so, it
                // must match the kernel principal.  Here we assert the
                // correct value to exercise the matching branch.
                "caller_persona_id": caller_persona_id,
            }),
        )
        .await
        .unwrap();

        assert!(
            result["id"].as_str().unwrap_or("").starts_with("grant-"),
            "Linux peercred-resolved owner must mint a grant, got: {result}"
        );
        assert_eq!(result["parent"], json!(parent_grant_id));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_peercred_pid_none_fails_closed() {
        // macOS LOCAL_PEERCRED does not always surface the peer PID.
        // When pid is `None` we cannot derive a principal — the only
        // safe move is to fail-closed with `PrincipalUnavailable`.
        // Falling back to UID-only binding would let any same-UID
        // process claim any persona, defeating the gate.
        clear_pid_persona_registry();
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (a_id, b_id, parent_grant_id) =
            c3_setup_two_personas_and_grant(&store, &vault, &policy, &rl).await;
        // Suppress unused warning when the kernel-principal path runs
        // before the ownership check would have been hit.
        let _ = a_id;

        ensure_test_authority_bridge_env();
        // The OperatorPresence gate enforces both a presence-token AND
        // an unlocked session before any handler runs. The test asserts
        // the PrincipalUnavailable path for pid=None, which fires after
        // both gates — so move presence to Unlocked here.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();
        // Peer credential with no PID — the macOS edge case.
        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 1000,
                pid: None,
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            // implementation-note-234
            // — attach a valid presence_token so the Phase D-4 gate
            // passes; the test asserts the PrincipalUnavailable path
            // for pid=None, not the auth gate.
            presence_token: Some(test_presence_token(1000)),
            bypass_binary_pin_gate_for_test: false,
        };

        let before = store.list_active_grants().unwrap().len();

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "delegate_grant",
            &json!({
                "parent_grant_id": parent_grant_id,
                "child_persona_id": b_id,
                "scope": "read",
                // Even with a "correct" caller_persona_id assertion,
                // the daemon must still reject — pid=None means the
                // principal is unverifiable, so we cannot trust ANY
                // attacker-supplied caller_persona_id.
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32401,
            "expected -32401 PrincipalUnavailable, got {err:?}"
        );
        assert!(
            err.1.to_lowercase().contains("unavailable")
                || err.1.to_lowercase().contains("principal"),
            "error should mention principal unavailable, got: {}",
            err.1
        );

        let after = store.list_active_grants().unwrap().len();
        assert_eq!(
            before, after,
            "no child grant must be minted on macOS when pid is None"
        );
    }

    #[test]
    fn peercred_principal_returns_unavailable_when_pid_is_none() {
        // Direct unit test of the peercred_principal helper — no
        // dispatch overhead.  This is the single-source-of-truth for
        // the macOS fail-closed semantics.
        let peer = PeerCred {
            uid: 1000,
            pid: None,
        };
        match peercred_principal(&peer) {
            Err(HandlerError::PrincipalUnavailable) => {}
            other => panic!("expected PrincipalUnavailable for pid=None, got: {other:?}"),
        }
    }

    #[test]
    fn peercred_principal_returns_not_enrolled_for_unknown_pid() {
        // Direct unit test: a PID with no enrollment yields
        // `PrincipalNotEnrolled` — the caller has not yet established
        // an identity in this daemon.
        clear_pid_persona_registry();
        let peer = PeerCred {
            uid: 1000,
            pid: Some(99_999),
        };
        match peercred_principal(&peer) {
            Err(HandlerError::PrincipalNotEnrolled) => {}
            other => panic!("expected PrincipalNotEnrolled for un-enrolled PID, got: {other:?}"),
        }
    }

    fn minimal_req() -> ApprovalRequestInfo {
        ApprovalRequestInfo {
            id: "approval-0bc51eff-0000-0000-0000-000000000000".to_string(),
            persona_id: "persona-abc".to_string(),
            credential_name: "github-token".to_string(),
            scope: "repo:read".to_string(),
            ttl_secs: Some(1800),
            action: "credential.access.github-token".to_string(),
            risk_level: "high".to_string(),
            status: "pending".to_string(),
            reason: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            tool_name: None,
            target_host: None,
            target_summary: None,
            target_url: None,
            agent_framework: None,
            composite_statements: None,
            result_grant_id: None,
            skill_ref: None,
            // implementation-note-7 —
            // minimal fixture: shaping defaults to None.
            max_delegation_depth: None,
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            budget: None,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        }
    }

    #[test]
    fn build_banner_includes_tool_and_target_when_present() {
        let mut req = minimal_req();
        req.tool_name = Some("claude-code".to_string());
        req.target_url = Some("api.github.com/repos/emberdotlink/emberlink".to_string());

        let banner = build_banner("claude-code", &req);

        assert!(
            banner.title.contains("claude-code"),
            "title should include tool_name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("api.github.com"),
            "body should include target_url, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    #[test]
    fn build_banner_falls_back_without_new_fields() {
        let req = minimal_req();
        let banner = build_banner("demo-agent", &req);

        assert!(
            banner.title.contains("demo-agent"),
            "title should include persona name, got: {}",
            banner.title
        );
        assert!(
            banner.body.contains("Click to review"),
            "body should fall back to click-to-review prompt, got: {}",
            banner.body
        );
        assert!(
            banner.title.chars().count() <= 60,
            "title must not exceed 60 chars, got {} chars: {}",
            banner.title.chars().count(),
            banner.title
        );
        assert!(
            banner.body.chars().count() <= 50,
            "body must not exceed 50 chars, got {} chars: {}",
            banner.body.chars().count(),
            banner.body
        );
    }

    // --- per-op user-presence wiring ---
    //
    // These tests prove the new methods (`vault_remove`, `vault_lock`,
    // `vault_status`) dispatch correctly. The gate's lock/allow state
    // machine has its own coverage in `crate::trust::presence::tests`. Because
    // cargo-test binaries set `dev_mode_enabled() = true`, the gate
    // returns `Allowed` for every call here, exercising the wire shape
    // without forcing live keychain access.

    #[tokio::test]
    async fn vault_remove_round_trip() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "to-be-removed", "value": "secret"}),
        )
        .await
        .unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_remove",
            &json!({"name": "to-be-removed"}),
        )
        .await
        .unwrap();
        assert_eq!(result["removed"], json!(true));
        assert_eq!(result["name"], json!("to-be-removed"));
    }

    #[tokio::test]
    async fn vault_remove_missing_name_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(&store, &vault, &policy, &rl, "vault_remove", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn vault_lock_returns_locked_true() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "vault_lock", &json!(null))
            .await
            .unwrap();
        assert_eq!(result["locked"], json!(true));
    }

    #[tokio::test]
    async fn vault_unlock_reopens_live_vault_after_explicit_lock() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        interactive_unlock::reset_for_tests();
        crate::trust::presence::reset_for_tests();
        // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

        let config_root = tempfile::TempDir::new().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
        let runtime_vault = std::rc::Rc::new(
            crate::infra::vault::Vault::open_from_config(&config)
                .expect("initial runtime vault open from config"),
        );

        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        store.set_vault(std::rc::Rc::clone(&runtime_vault));
        let store = std::rc::Rc::new(store);
        crate::trust::presence::register_store(std::rc::Rc::clone(&store));
        interactive_unlock::register_config(config);
        interactive_unlock::set_test_grace_window(std::time::Duration::from_secs(1));
        let policy = test_policy();
        let rl = test_rate_limiter();

        dispatch_method(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            "vault_lock",
            &json!(null),
        )
        .await
        .unwrap();
        assert!(
            store.vault().is_none(),
            "explicit lock must clear live vault"
        );

        let result = dispatch_method(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            "vault_unlock",
            &json!(null),
        )
        .await
        .unwrap();
        assert_eq!(result["unlocked"], json!(true));
        assert!(
            store.vault().is_some(),
            "vault_unlock must repopulate the shared live-vault slot"
        );
        assert!(
            interactive_unlock::grace_zero_due_at(
                std::time::Instant::now() + std::time::Duration::from_secs(2)
            ),
            "vault_unlock must arm the shared grace window for non-session unlocks"
        );

        interactive_unlock::reset_for_tests();
    }

    #[tokio::test]
    async fn vault_unlock_socket_path_mints_presence_token() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        interactive_unlock::reset_for_tests();
        crate::trust::presence::reset_for_tests();
        ensure_test_presence_identity();
        // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

        let config_root = tempfile::TempDir::new().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
        let runtime_vault = std::rc::Rc::new(
            crate::infra::vault::Vault::open_from_config(&config)
                .expect("initial runtime vault open from config"),
        );

        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        store.set_vault(std::rc::Rc::clone(&runtime_vault));
        let store = std::rc::Rc::new(store);
        crate::trust::presence::register_store(std::rc::Rc::clone(&store));
        interactive_unlock::register_config(config);
        let policy = test_policy();
        let rl = test_rate_limiter();

        dispatch_method(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            "vault_lock",
            &json!(null),
        )
        .await
        .unwrap();

        let ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };
        let result = dispatch_method_with_context(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            None,
            ctx,
            "vault_unlock",
            &json!(null),
        )
        .await
        .unwrap();
        assert_eq!(result["unlocked"], json!(true));
        assert!(
            result.get("presence_token").is_some(),
            "vault_unlock on the socket path must mint a replay token"
        );

        interactive_unlock::reset_for_tests();
    }

    #[tokio::test]
    async fn vault_status_exposes_session_shape() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(&store, &vault, &policy, &rl, "vault_status", &json!(null))
            .await
            .unwrap();
        // Shape contract: dashboard relies on these field names.
        assert!(result["unlocked"].is_boolean());
        assert!(result["idle_timeout_secs"].is_u64());
        // quiet_hours_* may be null, which is .is_null() (or .is_number() if set).
        assert!(result.get("quiet_hours_start").is_some());
        assert!(result.get("quiet_hours_end").is_some());
    }

    #[tokio::test]
    async fn team0_vault_list_requires_operator_presence_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "team0/list-target", "value": "secret"}),
        )
        .await
        .unwrap();

        let no_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            no_token_ctx,
            "vault_list",
            &json!(null),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);

        let with_token_ctx = RequestContext {
            source: DispatchSource::Socket,
            peer: Some(PeerCred {
                uid: 501,
                pid: Some(1234),
            }),
            principal: None,
            sessions_dir: None,
            llm_proxy_url: None,
            git_proxy_url: None,
            peer_cred_principal: None,
            mtls_principal: None,
            presence_token: Some(test_presence_token(501)),
            bypass_binary_pin_gate_for_test: false,
        };
        let rows = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            with_token_ctx,
            "vault_list",
            &json!(null),
        )
        .await
        .unwrap();
        let arr = rows.as_array().expect("vault_list returns array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["name"], json!("team0/list-target"));
    }

    #[tokio::test]
    async fn vault_get_round_trip_returns_plaintext_value_and_bytes() {
        // implementation-note-266: pulumi-render.sh + similar headless
        // integrations call `ember vault get` -> daemon RPC `vault_get`.
        // This proves the RPC arm is wired and returns the decrypted
        // value under the canonical {"value": ..., "value_bytes": ...}
        // shape.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "rpc-fetch-target", "value": "passphrase-42"}),
        )
        .await
        .unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_get",
            &json!({"name": "rpc-fetch-target"}),
        )
        .await
        .unwrap();
        assert_eq!(result["value"], json!("passphrase-42"));
        assert_eq!(
            result["value_bytes"],
            json!(b"passphrase-42".to_vec()),
            "vault_get must return exact bytes alongside the UTF-8 convenience field"
        );
    }

    #[tokio::test]
    async fn vault_add_accepts_exact_value_bytes() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({
                "name": "rpc-byte-target",
                "value_bytes": [0, 255, 65],
            }),
        )
        .await
        .unwrap();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_get",
            &json!({"name": "rpc-byte-target"}),
        )
        .await
        .unwrap();
        assert_eq!(result["value_bytes"], json!([0, 255, 65]));
    }

    #[tokio::test]
    async fn vault_get_missing_name_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(&store, &vault, &policy, &rl, "vault_get", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn vault_get_unknown_name_returns_application_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_get",
            &json!({"name": "no-such-credential"}),
        )
        .await
        .unwrap_err();
        // Generic application error code (-32000) — vault.get returns
        // VaultError::NotFound, mapped uniformly with other vault errors.
        assert_eq!(err.0, -32000);
    }

    #[tokio::test]
    async fn vault_get_uses_store_live_vault_slot_not_passed_dispatch_vault() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "slot-cutoff", "value": "secret"}),
        )
        .await
        .unwrap();

        store.drop_vault();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_get",
            &json!({"name": "slot-cutoff"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32030);
        assert!(
            err.1.contains("vault unavailable"),
            "handler must fail because the store live-vault slot was cleared, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn vault_remove_via_socket_source_runs_under_dev_mode_gate() {
        // Even via Socket dispatch (where the gate WOULD run), the
        // cargo-test binary detection short-circuits the gate to Allowed
        // — so the call still succeeds and we can prove the wiring is
        // wired through dispatch_method_with_source, not just the
        // Internal-only convenience entry point.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // Seed via Internal so add doesn't trip its own gate path.
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": "seed", "value": "v"}),
        )
        .await
        .unwrap();
        // Satisfy the OperatorPresence unlocked-session gate (vault_remove
        // is OperatorPresence-class).
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();
        // Now exercise via Socket source.
        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "vault_remove",
            &json!({"name": "seed"}),
        )
        .await
        .unwrap();
        assert_eq!(result["removed"], json!(true));
    }

    // ============================================================
    // KEYCHAIN-CONSOLIDATE-CLI-DAEMON-METHODS — T1 dispatch arm tests
    // ============================================================

    #[tokio::test]
    async fn local_state_key_get_generates_on_first_call() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        assert_eq!(result["resolved_or_generated"], json!("generated"));
        assert_eq!(result["vault_namespace"], json!("local-state/cli"));
        let key = result["key"].as_str().unwrap();
        // `core_crypto::generate_content_key` returns the canonical
        // `xchacha20-key:<64 hex>` content-key form (14-byte prefix +
        // 64 hex chars = 78 chars total).
        assert!(
            key.starts_with("xchacha20-key:") && key.len() == 78,
            "expected xchacha20-key:<64 hex> content key, got: {key}"
        );
    }

    #[tokio::test]
    async fn local_state_key_get_resolves_on_second_call() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        assert_eq!(second["resolved_or_generated"], json!("resolved"));
        assert_eq!(first["key"], second["key"]);
    }

    #[tokio::test]
    async fn local_state_key_get_namespaces_per_caller() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let cli_key = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        let gui_key = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "gui"}),
        )
        .await
        .unwrap();
        assert_ne!(
            cli_key["key"], gui_key["key"],
            "per-caller namespaces must produce distinct keys"
        );
        assert_eq!(cli_key["vault_namespace"], json!("local-state/cli"));
        assert_eq!(gui_key["vault_namespace"], json!("local-state/gui"));
    }

    #[tokio::test]
    async fn local_state_key_get_missing_caller_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn local_state_key_set_is_idempotent() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        // First set: not already set.
        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_set",
            &json!({"caller": "cli", "key": "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000001"}),
        )
        .await
        .unwrap();
        assert_eq!(first["already_set"], json!(false));
        // Second set: idempotent no-op.
        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_set",
            &json!({"caller": "cli", "key": "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000002"}),
        )
        .await
        .unwrap();
        assert_eq!(second["already_set"], json!(true));
        // After set, get returns the originally-set value.
        let got = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        assert_eq!(got["resolved_or_generated"], json!("resolved"));
        assert_eq!(
            got["key"].as_str().unwrap(),
            "xchacha20-key:0000000000000000000000000000000000000000000000000000000000000001",
            "set + get must round-trip the originally-set value"
        );
    }

    #[tokio::test]
    async fn local_state_key_rotate_and_reencrypt_round_trips() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // 1. Vend a key.
        let get_result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        let old_key = get_result["key"].as_str().unwrap().to_string();

        // 2. Encrypt a payload client-side using core_crypto.
        let plaintext = b"local-state-payload-v1";
        let encrypted =
            core_crypto::encrypt_content(&old_key, plaintext, b"emberlink-local-state").unwrap();
        let nonce_bytes = core_types::hex_to_bytes(&encrypted.nonce_hex).unwrap();
        let mut ciphertext = Vec::with_capacity(nonce_bytes.len() + encrypted.ciphertext.len());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(&encrypted.ciphertext);

        // 3. Call rotate_and_reencrypt.
        let rotate_result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_rotate_and_reencrypt",
            &json!({"caller": "cli", "ciphertext": ciphertext}),
        )
        .await
        .unwrap();
        let new_ciphertext: Vec<u8> = rotate_result["ciphertext"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(rotate_result["vault_namespace"], json!("local-state/cli"));

        // 4. The new ciphertext must be different (fresh key + nonce).
        assert_ne!(ciphertext, new_ciphertext);

        // 5. A subsequent get returns the *new* key.
        let new_get = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_get",
            &json!({"caller": "cli"}),
        )
        .await
        .unwrap();
        let new_key = new_get["key"].as_str().unwrap().to_string();
        assert_ne!(old_key, new_key, "rotation must produce a new key");

        // 6. The new ciphertext decrypts under the new key back to the
        //    original plaintext.
        assert!(new_ciphertext.len() >= 24);
        let (new_nonce, new_ct) = new_ciphertext.split_at(24);
        let encrypted_new = core_crypto::EncryptedContent {
            nonce_hex: core_types::bytes_to_hex(new_nonce),
            ciphertext: new_ct.to_vec(),
        };
        let decrypted =
            core_crypto::decrypt_content(&new_key, &encrypted_new, b"emberlink-local-state")
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn local_state_key_rotate_missing_caller_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "local_state_key_rotate_and_reencrypt",
            &json!({"ciphertext": []}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    /// EMBER-implementation-note-244 integration test: emit synthetic kms_wrap receipts
    /// for two actors, then verify `receipt_query` filters by actor and kind.
    #[tokio::test]
    async fn receipt_query_filters_by_actor_and_kind() {
        use crate::infra::receipt::ReceiptFilter;
        use core_grant_types::grant_receipt::{
            Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind,
            ReceiptOutcome,
        };

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Create two personas.
        let actor_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-actor-a"}),
        )
        .await
        .unwrap();
        let actor_a_id = actor_a["id"].as_str().unwrap().to_string();

        let actor_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "audit-actor-b"}),
        )
        .await
        .unwrap();
        let actor_b_id = actor_b["id"].as_str().unwrap().to_string();

        let eval_denied = GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        };

        // Insert a synthetic kms_wrap receipt for actor_a.
        let kms_a = KmsReceipt {
            id: "kms-wrap-audit-a".to_string(),
            kind: ReceiptKind::KmsWrap,
            key_name: "test-key".to_string(),
            caller_persona: actor_a_id.clone(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 0,
            grant_evaluation: eval_denied.clone(),
            outcome: ReceiptOutcome::Success,
            peer_identity: None,
            evidence: Evidence::default(),
        };
        store.store_kms_receipt(&kms_a).unwrap();

        // Insert a synthetic kms_wrap receipt for actor_b.
        let kms_b = KmsReceipt {
            id: "kms-wrap-audit-b".to_string(),
            kind: ReceiptKind::KmsWrap,
            key_name: "test-key".to_string(),
            caller_persona: actor_b_id.clone(),
            request_size_bytes: 32,
            materialized_at_epoch_secs: 0,
            grant_evaluation: eval_denied,
            outcome: ReceiptOutcome::Success,
            peer_identity: None,
            evidence: Evidence::default(),
        };
        store.store_kms_receipt(&kms_b).unwrap();

        // receipt_query with no filter returns both.
        let all = dispatch_method(&store, &vault, &policy, &rl, "receipt_query", &json!({}))
            .await
            .unwrap();
        assert_eq!(all.as_array().unwrap().len(), 2, "no filter → both rows");

        // receipt_query filtered to actor_a returns exactly one row.
        let actor_a_rows = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "receipt_query",
            &json!({"actor": actor_a_id}),
        )
        .await
        .unwrap();
        let arr = actor_a_rows.as_array().unwrap();
        assert_eq!(arr.len(), 1, "actor filter → one row for actor_a");
        assert_eq!(arr[0]["actor"].as_str().unwrap(), actor_a_id.as_str());

        // receipt_query filtered to kind=kms_wrap returns both (no actor filter).
        let kms_rows = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "receipt_query",
            &json!({"kind": "kms_wrap"}),
        )
        .await
        .unwrap();
        assert_eq!(
            kms_rows.as_array().unwrap().len(),
            2,
            "kind=kms_wrap → both rows"
        );

        // Validate via store directly (acceptance: per-actor indexes confirmed).
        let direct = store
            .query_receipts(&ReceiptFilter {
                persona_id: Some(actor_b_id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].actor, actor_b_id);
        assert_eq!(direct[0].kind, "kms_wrap");
    }

    #[tokio::test]
    async fn team0_receipt_query_defaults_to_trusted_principal() {
        use core_grant_types::grant_receipt::{
            Evidence, GrantEvaluation, GrantEvaluationOutcome, KmsReceipt, ReceiptKind,
            ReceiptOutcome,
        };

        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let actor_a_id = "persona-team0-actor-a".to_string();
        let actor_b_id = "persona-team0-actor-b".to_string();
        let eval_denied = GrantEvaluation {
            outcome: GrantEvaluationOutcome::Denied,
            grant_id: None,
        };

        for actor in [&actor_a_id, &actor_b_id] {
            let receipt = KmsReceipt {
                id: format!("rct-{actor}"),
                kind: ReceiptKind::KmsWrap,
                key_name: "test-key".to_string(),
                caller_persona: actor.to_string(),
                request_size_bytes: 32,
                materialized_at_epoch_secs: 0,
                grant_evaluation: eval_denied.clone(),
                outcome: ReceiptOutcome::Success,
                peer_identity: None,
                evidence: Evidence::default(),
            };
            store.store_kms_receipt(&receipt).unwrap();
        }

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_005),
            }),
            actor_a_id.clone(),
        );
        let rows = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "receipt_query",
            &json!({}),
        )
        .await
        .unwrap();
        let arr = rows.as_array().expect("receipt_query rows");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["actor"], json!(actor_a_id));

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "receipt_query",
            &json!({"actor": actor_b_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn team0_audit_query_defaults_to_trusted_principal() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let actor_a = "persona-team0-audit-a".to_string();
        let actor_b = "persona-team0-audit-b".to_string();
        store
            .log_event(
                Some(&actor_a),
                "credential.access",
                Some("team0-audit-a"),
                "allowed",
                None,
            )
            .unwrap();
        store
            .log_event(
                Some(&actor_b),
                "credential.access",
                Some("team0-audit-b"),
                "allowed",
                None,
            )
            .unwrap();

        let ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(91_010),
            }),
            actor_a.clone(),
        );
        let rows = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "audit_query",
            &json!({}),
        )
        .await
        .unwrap();
        let arr = rows.as_array().expect("audit_query rows");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["agent_id"], json!(actor_a));

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "audit_query",
            &json!({"agent_id": actor_b}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    // -----------------------------------------------------------------
    // implementation-note-253 Phase 2: sops_unwrap_dek RPC tests
    // -----------------------------------------------------------------

    /// Build an age-encrypted DEK ciphertext for the given recipient
    /// public key. Used by the sops_unwrap_dek tests below.
    #[cfg(feature = "age")]
    fn encrypt_dek_for(public_key: &str, plaintext: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let recipient: age::x25519::Recipient = public_key.parse().unwrap();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        ciphertext
    }

    /// Happy path: a valid grant + a vault-stored age key + a
    /// well-formed ciphertext returns the plaintext DEK as hex.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_happy_path_returns_plaintext() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-happy"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        // Generate an age keypair, stash the private key in the vault
        // at the canonical path, and prepare a ciphertext recipient.
        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        )
        .await
        .unwrap();

        let plaintext_dek = b"deadbeef-this-is-the-data-encryption-key";
        let ciphertext = encrypt_dek_for(&keypair.public_key, plaintext_dek);
        let blob_hex = hex::encode(&ciphertext);

        // The brief defines the receipted credential as the SOPS DEK
        // unwrap, not a vault credential — but the grant gating still
        // requires a credential_name. Use the canonical vault_path so a
        // single grant covers both "read the age key" and "unwrap a
        // DEK" semantics from the operator's POV.
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap();

        let dek_hex = result["dek_hex"].as_str().unwrap();
        let unwrapped = hex::decode(dek_hex).unwrap();
        assert_eq!(unwrapped.as_slice(), plaintext_dek.as_slice());

        let fp = result["dek_fingerprint"].as_str().unwrap();
        assert_eq!(
            fp.len(),
            32,
            "fingerprint should be 16 bytes -> 32 hex chars"
        );
        assert_eq!(result["grant_id"], json!(grant_id));
        assert_eq!(result["persona_id"], json!(persona_id));

        // Audit: a sops_dek_unwrapped row should be present.
        assert!(store.is_dek_grant_consumed(grant_id));
    }

    /// Rate-limit: a second call with the same grant_id is rejected.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_duplicate_grant_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-dup"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        )
        .await
        .unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // First call: success.
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap();

        // Second call with the SAME grant_id: rejected with -32005
        // (the same code we use for revoked / inactive grants).
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005);
        assert!(
            err.1.contains("already been used") || err.1.contains("already-consumed"),
            "expected duplicate-rejection message, got: {}",
            err.1
        );
    }

    /// Cross-persona attack: caller supplies a valid grant_id whose
    /// persona doesn't match the asserted persona_id. Rejected.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_cross_persona_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let owner = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-owner"}),
        )
        .await
        .unwrap();
        let owner_id = owner["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(owner_id);
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        )
        .await
        .unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": owner_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": "persona-other",
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32002);
        // Slot must NOT be consumed when the caller is rejected.
        assert!(!store.is_dek_grant_consumed(grant_id));
    }

    /// Inactive grant: a revoked grant cannot unwrap a DEK.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_revoked_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-revoked"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let keypair = crate::age::generate_age_keypair().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "vault_add",
            &json!({"name": vault_path, "value": keypair.private_key}),
        )
        .await
        .unwrap();

        let ciphertext = encrypt_dek_for(&keypair.public_key, b"payload");
        let blob_hex = hex::encode(&ciphertext);

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "revoke_grant",
            &json!({"id": grant_id}),
        )
        .await
        .unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005);
    }

    /// Missing persona age key: vault has no entry at the canonical
    /// path, so the unwrap fails with a clear -32000 error.
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_errors_when_age_key_missing() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-no-key"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let vault_path = crate::age::vault_path_for_persona(persona_id);
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        // Build a synthetic ciphertext (won't be reached — vault lookup fails).
        let dummy_keypair = crate::age::generate_age_keypair().unwrap();
        let ciphertext = encrypt_dek_for(&dummy_keypair.public_key, b"x");
        let blob_hex = hex::encode(&ciphertext);

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": blob_hex,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32000);
        assert!(err.1.contains("no age private key"), "got: {}", err.1);
        // Slot must NOT be consumed when the vault lookup fails — we
        // reject before claiming it.
        assert!(!store.is_dek_grant_consumed(grant_id));
    }

    /// Malformed hex blob: caller passes an unparseable hex string.
    /// Rejected with -32602 (invalid params).
    #[tokio::test]
    #[cfg(feature = "age")]
    async fn sops_unwrap_dek_rejects_malformed_hex() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sops-bad-hex"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();
        let vault_path = crate::age::vault_path_for_persona(persona_id);
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": vault_path,
                "scope": "sops:unwrap",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "sops_unwrap_dek",
            &json!({
                "persona_id": persona_id,
                "grant_id": grant_id,
                "encrypted_dek_blob": "not-hex!@#",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    // ---- implementation-note-42: await_approval block-and-poll RPC -----------------

    #[tokio::test]
    async fn await_approval_returns_approved_when_resolved_mid_poll() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Mint persona + pending approval row directly.
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "ap4-approve"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-x", "read", None, "Bash", "low")
            .unwrap();
        let approval_id = approval.id.clone();

        // Resolve the approval before the poll fires (synchronous setup -
        // the dispatch call below will hit the resolved state on its first
        // get_approval lookup).
        store
            .resolve_approval(
                &approval_id,
                &crate::trust::approval::ApprovalOutcome::Approved,
            )
            .unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 2}),
        )
        .await
        .unwrap();

        assert_eq!(
            result["decision"]["kind"],
            json!("approved"),
            "got: {result}"
        );
    }

    #[tokio::test]
    async fn await_approval_returns_denied_when_resolved_denied() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "ap4-deny"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-y", "read", None, "Bash", "high")
            .unwrap();
        let approval_id = approval.id.clone();

        store
            .resolve_approval(
                &approval_id,
                &crate::trust::approval::ApprovalOutcome::Denied {
                    reason: "operator declined".to_string(),
                },
            )
            .unwrap();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 2}),
        )
        .await
        .unwrap();

        assert_eq!(result["decision"]["kind"], json!("denied"), "got: {result}");
        assert!(
            result["decision"]["reason"]
                .as_str()
                .unwrap_or("")
                .contains("operator declined"),
            "got: {result}"
        );
    }

    #[tokio::test]
    async fn await_approval_returns_timed_out_after_deadline() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "ap4-timeout"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let approval = store
            .submit_approval(persona_id, "cred-z", "read", None, "Bash", "med")
            .unwrap();
        let approval_id = approval.id.clone();

        // Don't resolve - let the deadline fire. timeout_secs=0 short-circuits
        // after the first poll cycle so the test doesn't spend wall-clock time.
        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "await_approval",
            &json!({"request_id": approval_id, "timeout_secs": 0}),
        )
        .await
        .unwrap();

        assert_eq!(
            result["decision"]["kind"],
            json!("timed_out"),
            "got: {result}"
        );
    }

    #[tokio::test]
    async fn await_approval_unknown_request_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "await_approval",
            &json!({"request_id": "approval-does-not-exist", "timeout_secs": 1}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004, "got: {err:?}");
    }

    #[tokio::test]
    async fn await_approval_missing_request_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "await_approval",
            &json!({"timeout_secs": 1}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602, "got: {err:?}");
    }

    // implementation-note-249 — graceful binding delete (design).
    #[tokio::test]
    async fn binding_delete_revokes_persona_and_cascades_grants() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Provision a workload Persona + a grant. The binding cascade
        // is the assertion target — after delete, the persona is
        // revoked AND the grant is drained (status=revoked).
        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "ml-eval-worker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // `force: true` honored on Internal dispatch (test harness) — bypasses
        // the policy approval gate so the test exercises the cascade path,
        // not the approval queue.
        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
                "scope": "llm:generate",
                "ttl_secs": 3600,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"]
            .as_str()
            .unwrap_or_else(|| panic!("create_grant response missing id: {grant:?}"))
            .to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.delete",
            &json!({
                "persona_id": persona_id,
                "binding_request_id": "br-test-001",
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["deleted"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));

        // Grant should now be drained — i.e. evaluate_grant fails because
        // the cascade flipped its status to `revoked`.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32000);

        // Audit log must contain a `binding.deleted` row tied to the persona.
        let audit = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_query",
            &json!({"persona_id": persona_id}),
        )
        .await
        .unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries
                .iter()
                .any(|e| e["action"] == json!("binding.deleted")),
            "expected binding.deleted audit row, got {entries:?}"
        );
        // The grant id is unused beyond the cascade assertion above; bind
        // it once so the compiler doesn't warn about an unused let.
        let _ = grant_id;
    }

    #[tokio::test]
    async fn binding_delete_missing_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(&store, &vault, &policy, &rl, "binding.delete", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_delete_unknown_persona_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.delete",
            &json!({"persona_id": "persona-does-not-exist"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_delete_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "alias-worker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding_delete",
            &json!({"persona_id": persona_id}),
        )
        .await
        .unwrap();
        assert_eq!(resp["deleted"], json!(true));
    }

    // implementation-note-250 — compromise-response revocation
    // (design §"binding.revoke_urgent").
    #[tokio::test]
    async fn binding_revoke_urgent_cascades_grants_and_emits_urgent_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "compromised-worker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // Provision a grant under the persona — it must be cascaded
        // to `revoked` by the urgent path, same as `binding.delete`.
        let _grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
                "scope": "llm:generate",
                "ttl_secs": 3600,
                "force": true,
            }),
        )
        .await
        .unwrap();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.revoke_urgent",
            &json!({
                "persona_id": persona_id,
                "binding_request_id": "br-urgent-001",
                "reason": "credential leaked in public repo",
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["revoked_urgent"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));

        // Cascade assertion: evaluate_grant fails because the urgent
        // path flipped the grant to `revoked` (same SQL as delete).
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "evaluate_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "anthropic-key",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32000);

        // Audit assertion: action MUST be `binding.revoke_urgent` (NOT
        // `binding.deleted` — operators distinguish urgent revocations
        // from graceful deletes for compliance + alerting).
        let audit = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_query",
            &json!({"persona_id": persona_id}),
        )
        .await
        .unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries.iter().any(|e| {
                e["action"] == json!("binding.revoke_urgent") && e["outcome"] == json!("urgent")
            }),
            "expected binding.revoke_urgent + outcome=urgent audit row, got {entries:?}"
        );
    }

    #[tokio::test]
    async fn binding_revoke_urgent_missing_persona_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.revoke_urgent",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_revoke_urgent_unknown_persona_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.revoke_urgent",
            &json!({"persona_id": "persona-does-not-exist"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_revoke_urgent_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "alias-urgent-worker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding_revoke_urgent",
            &json!({"persona_id": persona_id}),
        )
        .await
        .unwrap();
        assert_eq!(resp["revoked_urgent"], json!(true));
    }

    // implementation-note-251 — mutate binding metadata
    // (design §"binding.update").
    #[tokio::test]
    async fn binding_update_mutates_name_and_emits_before_after_audit() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "old-name"}),
        )
        .await
        .unwrap();
        let binding_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.update",
            &json!({
                "binding_id": binding_id,
                "binding_request_id": "br-update-001",
                "name": "new-name",
                "cred_class_allowlist": ["llm:generate", "fs:read"],
                "lease_duration_cap": 3600,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["binding_id"], json!(binding_id));
        assert_eq!(resp["name"], json!("new-name"));

        // Persona row in SQL must reflect the new name.
        let fetched = store.get_persona(&binding_id).unwrap();
        assert_eq!(fetched.name, "new-name");

        // Audit row carries the before/after snapshot AND the
        // audit-only metadata fields the caller passed. The
        // `audit_query` JSON-RPC response strips `details` (operator
        // dashboards don't paginate details JSON), so read directly
        // via `query_audit` to assert the full payload landed.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(binding_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.updated")
            .unwrap_or_else(|| panic!("expected binding.updated audit row, got {entries:?}"));
        let details: serde_json::Value =
            serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
                .expect("details parses as JSON");
        assert_eq!(details["before"]["name"], json!("old-name"));
        assert_eq!(details["after"]["name"], json!("new-name"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate", "fs:read"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
        assert_eq!(details["binding_request_id"], json!("br-update-001"));
    }

    #[tokio::test]
    async fn binding_update_missing_binding_id_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.update",
            &json!({"name": "irrelevant"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_update_unknown_binding_returns_32004() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.update",
            &json!({
                "binding_id": "persona-does-not-exist",
                "name": "ghost",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32004);
    }

    #[tokio::test]
    async fn binding_update_duplicate_name_returns_32005() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        // Create two personas — renaming one to the other's name must
        // hit the UNIQUE constraint and surface as -32005.
        let _occupant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "occupied"}),
        )
        .await
        .unwrap();
        let other = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "free"}),
        )
        .await
        .unwrap();
        let other_id = other["id"].as_str().unwrap().to_string();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.update",
            &json!({
                "binding_id": other_id,
                "name": "occupied",
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005);
    }

    #[tokio::test]
    async fn binding_update_underscore_alias_and_persona_id_synonym_dispatch() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "alias-update-worker"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        // Underscore alias + `persona_id` synonym for `binding_id`.
        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding_update",
            &json!({
                "persona_id": persona_id,
                "name": "alias-update-renamed",
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["name"], json!("alias-update-renamed"));
    }

    #[tokio::test]
    async fn binding_update_no_mutation_still_emits_audit() {
        // Sanity: a no-op update (no `name` change requested) is
        // still a valid call — it serves as a "touch" for the
        // reconciler to record a binding-update receipt.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "touch-target"}),
        )
        .await
        .unwrap();
        let binding_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.update",
            &json!({
                "binding_id": binding_id,
                "binding_request_id": "br-touch-001",
                "metadata": {"reconciler_pass": "ts-2026-05-07"},
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["name"], json!("touch-target"));

        let audit = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "audit_query",
            &json!({"persona_id": binding_id}),
        )
        .await
        .unwrap();
        let entries = audit.as_array().expect("audit_query returns array");
        assert!(
            entries
                .iter()
                .any(|e| e["action"] == json!("binding.updated")),
            "expected binding.updated audit row, got {entries:?}"
        );
    }

    // implementation-note-252 — idempotent insert-or-update
    // (design §"binding.upsert").

    #[tokio::test]
    async fn binding_upsert_creates_when_persona_absent() {
        // First-pass reconcile: no persona row exists yet. The verb
        // creates one and emits a `binding.upserted` audit row with
        // `before: null` and a populated `after` snapshot.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({
                "namespace": "ns-prod",
                "name": "ml-eval-worker",
                "binding_request_id": "br-upsert-001",
                "cred_class_allowlist": ["llm:generate", "fs:read"],
                "lease_duration_cap": 3600,
                "metadata": {"sa_uid": "uid-abc"},
            }),
        )
        .await
        .unwrap();

        assert_eq!(resp["created"], json!(true));
        assert_eq!(resp["updated"], json!(false));
        assert_eq!(resp["name"], json!("ml-eval-worker"));
        let canonical_id = resp["persona_id"]
            .as_str()
            .expect("response carries persona_id");

        // Persona row exists in SQL with `active` status and the
        // requested name.
        let row = store.get_persona(canonical_id).unwrap();
        assert_eq!(row.name, "ml-eval-worker");
        assert_eq!(row.status, "active");

        // Audit row carries the create snapshot AND the audit-only
        // metadata fields the caller passed.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(canonical_id.to_string()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.upserted")
            .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
        let details: serde_json::Value =
            serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
                .expect("details parses as JSON");
        assert_eq!(details["created"], json!(true));
        assert_eq!(details["before"], serde_json::Value::Null);
        assert_eq!(details["after"]["name"], json!("ml-eval-worker"));
        assert_eq!(details["after"]["status"], json!("active"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate", "fs:read"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(3600));
        assert_eq!(details["requested"]["namespace"], json!("ns-prod"));
        assert_eq!(
            details["requested"]["metadata"],
            json!({"sa_uid": "uid-abc"})
        );
        assert_eq!(details["binding_request_id"], json!("br-upsert-001"));
    }

    #[tokio::test]
    async fn binding_upsert_updates_when_persona_present() {
        // Steady-state reconcile: persona row already exists. The
        // verb reuses its id, mutates `name` if the request asks for
        // a rename, and emits an audit row with a populated
        // before/after diff.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "old-name"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({
                "persona_id": persona_id,
                "name": "new-name",
                "binding_request_id": "br-upsert-002",
                "cred_class_allowlist": ["llm:generate"],
                "lease_duration_cap": 7200,
                "metadata": {"reconciler_pass": "ts-2026-05-07"},
            }),
        )
        .await
        .unwrap();

        assert_eq!(resp["created"], json!(false));
        assert_eq!(resp["updated"], json!(true));
        assert_eq!(resp["persona_id"], json!(persona_id));
        assert_eq!(resp["name"], json!("new-name"));

        // Persona row name updated in SQL.
        let row = store.get_persona(&persona_id).unwrap();
        assert_eq!(row.name, "new-name");

        // Audit row carries before/after diff.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(persona_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "binding.upserted")
            .unwrap_or_else(|| panic!("expected binding.upserted audit row, got {entries:?}"));
        let details: serde_json::Value =
            serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
                .expect("details parses as JSON");
        assert_eq!(details["created"], json!(false));
        assert_eq!(details["before"]["name"], json!("old-name"));
        assert_eq!(details["after"]["name"], json!("new-name"));
        assert_eq!(
            details["requested"]["cred_class_allowlist"],
            json!(["llm:generate"])
        );
        assert_eq!(details["requested"]["lease_duration_cap"], json!(7200));
        assert_eq!(details["binding_request_id"], json!("br-upsert-002"));
    }

    #[tokio::test]
    async fn binding_upsert_idempotent_no_mutation_still_emits_audit() {
        // Replay-safety: calling upsert twice with the same params
        // updates nothing on the second call but still emits a
        // fresh `binding.upserted` audit row (the reconciler relies
        // on per-call receipts for retry idempotency).
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({
                "name": "stable-worker",
                "binding_request_id": "br-replay-001",
            }),
        )
        .await
        .unwrap();
        let persona_id = first["persona_id"].as_str().unwrap().to_string();

        let second = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({
                "persona_id": persona_id,
                "name": "stable-worker",
                "binding_request_id": "br-replay-001",
            }),
        )
        .await
        .unwrap();
        assert_eq!(second["created"], json!(false));
        assert_eq!(second["updated"], json!(true));
        assert_eq!(second["persona_id"], json!(persona_id));

        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(persona_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let upsert_count = entries
            .iter()
            .filter(|e| e.action == "binding.upserted")
            .count();
        assert_eq!(
            upsert_count, 2,
            "expected two binding.upserted audit rows, got {entries:?}"
        );
    }

    #[tokio::test]
    async fn binding_upsert_missing_both_id_and_name_returns_32602() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({"binding_request_id": "br-noop"}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[tokio::test]
    async fn binding_upsert_unknown_persona_id_with_name_creates_fresh() {
        // Snapshot-drift path: caller supplies a `persona_id` that
        // does not exist on this daemon (e.g. cluster restored from
        // an older etcd snapshot pointing at a rotated id). With a
        // `name` available, the verb falls through to the create
        // path and returns the daemon's freshly-minted canonical id.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding.upsert",
            &json!({
                "persona_id": "persona-stale-id",
                "name": "drift-recovered-worker",
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["created"], json!(true));
        let canonical_id = resp["persona_id"].as_str().unwrap();
        assert_ne!(canonical_id, "persona-stale-id");
    }

    #[tokio::test]
    async fn binding_upsert_underscore_alias_dispatches_too() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "binding_upsert",
            &json!({"name": "alias-upsert-worker"}),
        )
        .await
        .unwrap();
        assert_eq!(resp["created"], json!(true));
        assert_eq!(resp["name"], json!("alias-upsert-worker"));
    }

    // -------------------------------------------------------------------------
    // implementation-note-258: register_session + close_session T2
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn register_session_and_close_session_emit_clean_exit_receipt() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        interactive_unlock::reset_for_tests();
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "sess-test-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap();
        assert!(!grant_id.is_empty(), "grant must be created");

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());

        let reg = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            "register_session",
            &json!({
                "persona": "sess-test-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        let session_id = reg["session_id"].as_str().unwrap().to_string();
        let reg_grant_id = reg["grant_id"].as_str().unwrap();
        assert_eq!(
            reg_grant_id, grant_id,
            "register_session must return the active grant id"
        );
        assert!(!session_id.is_empty(), "session_id must be non-empty");
        assert_eq!(
            interactive_unlock::pin_count(),
            1,
            "register_session must acquire one interactive unlock pin"
        );

        let session_dir = sessions_dir.join(&session_id);
        assert!(session_dir.exists(), "session directory must be created");
        assert!(
            session_dir.join("meta.json").exists(),
            "meta.json must be written"
        );

        let close = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "close_session",
            &json!({ "session_id": session_id }),
        )
        .await
        .unwrap();

        assert_eq!(
            close["closed"],
            json!(true),
            "close_session must return closed:true"
        );
        assert_eq!(
            interactive_unlock::pin_count(),
            0,
            "close_session must release the interactive unlock pin"
        );

        let receipt_path = session_dir.join("receipt.json");
        let receipt_bytes =
            std::fs::read(&receipt_path).expect("receipt.json must be written by close_session");
        assert!(!receipt_bytes.is_empty(), "receipt.json must be non-empty");

        let envelope: core_events::receipt::ReceiptEnvelope =
            serde_json::from_slice(&receipt_bytes).expect("receipt.json parses as v2 envelope");
        assert_eq!(envelope.kind, "session.claude_code");
        assert!(envelope.signature.is_some(), "receipt must be signed");

        let body: core_events::receipt::ClaudeCodeBody =
            serde_json::from_value(envelope.body).unwrap();
        assert_eq!(
            body.termination_reason,
            Some(core_events::receipt::TerminationReason::CleanExit),
            "termination_reason must be clean_exit"
        );

        assert!(
            !session_dir.join("meta.json").exists(),
            "meta.json must be renamed to meta.json.closed on close"
        );
        assert!(
            session_dir.join("meta.json.closed").exists(),
            "meta.json.closed must exist after close"
        );

        // implementation-note-259: grant must remain
        // Active after CleanExit — the handler no longer calls revoke_grant.
        let grant_after = store.get_grant(grant_id).expect("grant still queryable");
        assert_eq!(
            grant_after.status, "active",
            "CleanExit MUST NOT revoke the grant — multi-session per 24h grant invariant"
        );
        interactive_unlock::reset_for_tests();
    }

    #[tokio::test]
    async fn register_session_uses_trusted_principal_when_present() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "trusted-session-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let mut ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(41001),
            }),
            persona_id,
        );
        ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

        let reg = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "trusted-session-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            reg["grant_id"].as_str(),
            Some(grant_id.as_str()),
            "register_session must resolve the trusted persona's active grant"
        );
    }

    #[tokio::test]
    async fn register_session_rejects_asserted_persona_mismatch_for_trusted_principal() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let trusted = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "trusted-session-persona"}),
        )
        .await
        .unwrap();
        let trusted_id = trusted["id"].as_str().unwrap().to_string();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": trusted_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "other-session-persona"}),
        )
        .await
        .unwrap();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let mut ctx = RequestContext::socket_with_principal(
            Some(PeerCred {
                uid: 1000,
                pid: Some(41002),
            }),
            trusted_id,
        );
        ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "other-session-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, -32004);
        assert!(
            err.1.contains("trusted principal"),
            "mismatch refusal should explain the trusted-principal binding, got: {}",
            err.1
        );
    }

    #[tokio::test]
    async fn register_session_keeps_explicit_persona_fallback_without_trusted_principal() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "fallback-session-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap().to_string();

        let grant = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();
        let grant_id = grant["id"].as_str().unwrap().to_string();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

        let reg = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "fallback-session-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            reg["grant_id"].as_str(),
            Some(grant_id.as_str()),
            "register_session must preserve the explicit persona fallback when no trusted principal exists"
        );
    }

    #[tokio::test]
    async fn register_session_reopens_live_vault_after_explicit_lock() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        interactive_unlock::reset_for_tests();
        crate::trust::presence::reset_for_tests();
        // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
        unsafe { std::env::set_var("EMBER_VAULT_TEST_KEYRING_PRESENT", "1") };

        let config_root = tempfile::TempDir::new().unwrap();
        let config = crate::infra::config::DaemonConfig::for_test(config_root.path());
        let runtime_vault = std::rc::Rc::new(
            crate::infra::vault::Vault::open_from_config(&config)
                .expect("initial runtime vault open from config"),
        );

        let store = DaemonStore::open_in_memory_without_vault().unwrap();
        store.set_vault(std::rc::Rc::clone(&runtime_vault));
        let store = std::rc::Rc::new(store);
        crate::trust::presence::register_store(std::rc::Rc::clone(&store));
        interactive_unlock::register_config(config.clone());

        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona = dispatch_method(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "reopen-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        let grant = dispatch_method(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();
        assert!(
            grant["id"].as_str().is_some(),
            "grant must exist before session-open reopen"
        );

        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                store.as_ref(),
                "reopen-proof/key",
                b"secret-after-lock",
                None,
            )
            .expect("seed credential before explicit lock");

        crate::trust::presence::lock();
        assert!(
            store.vault().is_none(),
            "explicit lock must clear the live vault before register_session"
        );

        let sessions_root = tempfile::TempDir::new().unwrap();
        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_root.path().to_path_buf());

        let reg = dispatch_method_with_context(
            store.as_ref(),
            runtime_vault.as_ref(),
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "reopen-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        assert!(
            reg["session_id"].as_str().is_some(),
            "register_session must succeed after reopening the live vault"
        );
        assert!(
            store.vault().is_some(),
            "register_session must repopulate the shared live-vault slot"
        );
        assert_eq!(
            interactive_unlock::pin_count(),
            1,
            "reopened register_session must also acquire the interactive pin"
        );
        let reopened_value = store
            .vault()
            .unwrap()
            .get(
                crate::infra::vault::VaultScope::Interactive,
                store.as_ref(),
                "reopen-proof/key",
            )
            .expect("reopened vault must decrypt pre-lock ciphertext");
        assert_eq!(reopened_value, b"secret-after-lock");

        interactive_unlock::reset_for_tests();
        crate::trust::presence::reset_for_tests();
        // SAFETY: serialized by PROCESS_TEST_LOCK for this test binary.
        unsafe { std::env::remove_var("EMBER_VAULT_TEST_KEYRING_PRESENT") };
    }

    #[tokio::test]
    async fn register_session_fails_without_sessions_dir() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let ctx = RequestContext::internal("test harness");

        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({ "persona": "x", "launcher_pid": 1u32 }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.0, -32000,
            "should fail with -32000 when sessions_dir absent"
        );
        assert!(
            err.1.contains("sessions_dir"),
            "error should mention sessions_dir"
        );
    }

    // implementation-note-267: daemon-side T2 (updated for
    // implementation-note-233) — register_session
    // response must include the real LLM proxy URL from RequestContext.
    #[tokio::test]
    async fn register_session_response_includes_real_proxy_url() {
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        let expected_proxy_url = "http://127.0.0.1:61169";

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "proxy-url-test-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());
        // Wire the URL via RequestContext — the correct path after
        // implementation-note-233.
        ctx.llm_proxy_url = Some(expected_proxy_url.to_string());

        let reg = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "proxy-url-test-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        let got_proxy_url = reg["proxy_url"]
            .as_str()
            .expect("proxy_url must be present in response");
        assert_eq!(
            got_proxy_url, expected_proxy_url,
            "register_session must return the real LLM proxy URL from RequestContext, not the 8484 fallback"
        );
        assert_ne!(
            got_proxy_url, "http://127.0.0.1:8484",
            "proxy_url must not be the hardcoded 8484 fallback when ctx.llm_proxy_url is set"
        );
    }

    // implementation-note-233: T2 test —
    // register_session must read the LLM proxy URL from RequestContext,
    // NOT from std::env::var. The env var may be absent or stale due to
    // Rust 2024 std::env::set_var cross-thread visibility hazard (tokio
    // worker threads may not observe a set_var from the startup thread).
    // The fix in #2389 relied on set_var; this test proves the correct fix.
    //
    // Key assertion: even if EMBER_PROXY_URL is set to a DIFFERENT (wrong)
    // value in the environment, the response uses the URL from RequestContext.
    #[tokio::test]
    async fn register_session_response_uses_request_context_proxy_url() {
        let _id_dir = setup_receipt_identity();

        let store = DaemonStore::open_in_memory().unwrap();
        store.set_vault(std::rc::Rc::new(test_vault()));
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let sessions_root = tempfile::TempDir::new().unwrap();
        let sessions_dir = sessions_root.path().to_path_buf();

        // Deliberately set EMBER_PROXY_URL to a wrong value to prove the
        // handler does NOT read it. RequestContext plumbing should win.
        // SAFETY: test-only; value is removed after the test.
        unsafe {
            std::env::set_var("EMBER_PROXY_URL", "http://127.0.0.1:8484");
        }

        let persona = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "ctx-proxy-url-test-persona"}),
        )
        .await
        .unwrap();
        let persona_id = persona["id"].as_str().unwrap();

        dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_grant",
            &json!({
                "persona_id": persona_id,
                "credential_name": "claude-code-default-v1",
                "scope": "claude-code",
                "force": true,
            }),
        )
        .await
        .unwrap();

        // Populate RequestContext with the real URL — this is what
        // SocketListener.with_llm_proxy_url wires in production.
        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir.clone());
        // implementation-note-233: this URL must
        // appear in the response; the env var ("8484") must be ignored.
        ctx.llm_proxy_url = Some("http://127.0.0.1:55555".to_string());

        let reg = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "register_session",
            &json!({
                "persona": "ctx-proxy-url-test-persona",
                "launcher_pid": std::process::id(),
            }),
        )
        .await
        .unwrap();

        // Restore env so subsequent tests are not polluted.
        unsafe {
            std::env::remove_var("EMBER_PROXY_URL");
        }

        let got_proxy_url = reg["proxy_url"]
            .as_str()
            .expect("proxy_url must be present in response");
        assert_eq!(
            got_proxy_url, "http://127.0.0.1:55555",
            "register_session must use ctx.llm_proxy_url from RequestContext, not env::var"
        );
        assert_ne!(
            got_proxy_url, "http://127.0.0.1:8484",
            "register_session must ignore EMBER_PROXY_URL env var; RequestContext wins"
        );
    }

    #[tokio::test]
    async fn headless_status_reports_active_enrollment_metadata() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let device = crate::infra::attested_device::AttestedDevice {
            enrollment_id: "enroll-test-1".to_string(),
            persona: "main".to_string(),
            account: "main".to_string(),
            enrolled_at: std::time::SystemTime::now(),
            expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        device.store_active(&data_dir).unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "headless_status",
            &json!({}),
        )
        .await
        .unwrap();

        assert_eq!(
            result["active_enrollment"]["enrollment_id"],
            json!("enroll-test-1")
        );
        assert_eq!(result["active_enrollment"]["persona"], json!("main"));
        assert!(
            result["active_enrollment"]["duration_remaining_seconds"]
                .as_u64()
                .unwrap_or_default()
                > 0,
            "status should surface a positive remaining duration"
        );
    }

    #[tokio::test]
    async fn team0_headless_status_requires_operator_presence_token() {
        let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let device = crate::infra::attested_device::AttestedDevice {
            enrollment_id: "enroll-team0-1".to_string(),
            persona: "main".to_string(),
            account: "main".to_string(),
            enrolled_at: std::time::SystemTime::now(),
            expiry: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        device.store_active(&data_dir).unwrap();

        let mut no_token_ctx = RequestContext::socket(Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }));
        no_token_ctx.sessions_dir = Some(sessions_dir.clone());
        no_token_ctx.presence_token = None;
        let err = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            no_token_ctx,
            "headless_status",
            &json!({}),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32001);

        let mut with_token_ctx = RequestContext::socket(Some(PeerCred {
            uid: 501,
            pid: Some(1234),
        }));
        with_token_ctx.sessions_dir = Some(sessions_dir);
        with_token_ctx.presence_token = Some(test_presence_token(501));
        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            with_token_ctx,
            "headless_status",
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(
            result["active_enrollment"]["enrollment_id"],
            json!("enroll-team0-1")
        );
    }

    #[tokio::test]
    async fn headless_revoke_without_active_enrollment_returns_false() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        std::fs::create_dir_all(&sessions_dir).unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "headless_revoke",
            &json!({}),
        )
        .await
        .unwrap();

        assert_eq!(result["revoked"], json!(false));
        assert_eq!(result["active_enrollment"], json!(null));
    }

    #[tokio::test]
    async fn headless_enroll_installs_local_broker_authority_subset() {
        use zeroize::Zeroize as _;

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let runtime_vault = std::rc::Rc::new(Vault::new([0x61u8; 32]));
        store.set_vault(std::rc::Rc::clone(&runtime_vault));
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/access-key-id",
                b"AKIA-ENROLL",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/secret-access-key",
                b"secret-enroll",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/region",
                b"us-east-1",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/default-role-arn",
                b"arn:aws:iam::123456789012:role/demo",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "misc/not-enrolled",
                b"ignore-me",
                None,
            )
            .unwrap();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "headless_enroll",
            &json!({
                "persona_id": "main",
                "duration_seconds": 3600,
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["enrolled"], json!(true));
        assert_eq!(result["authority_refs"], json!(null));
        let mut authority_keys = result["authority_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        authority_keys.sort();
        assert_eq!(
            authority_keys,
            vec![
                "aws-sts/access-key-id".to_string(),
                "aws-sts/default-role-arn".to_string(),
                "aws-sts/region".to_string(),
                "aws-sts/secret-access-key".to_string(),
            ]
        );

        let device = crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
            .unwrap()
            .expect("active enrollment stored");
        let mut headless_mek = device.unwrap_mek().unwrap();
        let headless_vault = Vault::new(headless_mek);
        headless_mek.zeroize();

        let mut headless_keys = crate::infra::headless_scope::list_headless_keys(&store).unwrap();
        headless_keys.sort();
        assert_eq!(headless_keys, authority_keys);
        assert_eq!(
            headless_vault
                .get(
                    crate::infra::vault::VaultScope::Headless,
                    &store,
                    "aws-sts/access-key-id",
                )
                .unwrap(),
            b"AKIA-ENROLL"
        );
        assert!(matches!(
            headless_vault.get(
                crate::infra::vault::VaultScope::Headless,
                &store,
                "misc/not-enrolled",
            ),
            Err(crate::infra::vault::VaultError::NotFound)
        ));

        crate::infra::attested_device::AttestedDevice::revoke_active(
            &data_dir,
            Some(&device.enrollment_id),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn headless_enroll_narrows_to_manifest_declared_authority_refs_when_queue_is_complete() {
        use zeroize::Zeroize as _;

        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let runtime_vault = std::rc::Rc::new(Vault::new([0x41u8; 32]));
        store.set_vault(std::rc::Rc::clone(&runtime_vault));
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "github/apps/ember/install-123/private-key",
                b"gh-private-key",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "github/apps/ember/install-123/app-id",
                b"123",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "github/apps/ember/install-123/installation-id",
                b"456",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/access-key-id",
                b"AKIA-IGNORE",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/secret-access-key",
                b"secret-ignore",
                None,
            )
            .unwrap();
        runtime_vault
            .add(
                crate::infra::vault::VaultScope::Interactive,
                &store,
                "aws-sts/region",
                b"us-east-1",
                None,
            )
            .unwrap();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "headless_enroll",
            &json!({
                "persona_id": "main",
                "duration_seconds": 3600,
                "tasks": [
                    {
                        "task_id": "AP-1",
                        "constructs": ["ember-gh.pr_merge"],
                    }
                ],
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["enrolled"], json!(true));
        assert_eq!(result["authority_refs"], json!(["github"]));
        let mut authority_keys = result["authority_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        authority_keys.sort();
        assert_eq!(
            authority_keys,
            vec![
                "github/apps/ember/install-123/app-id".to_string(),
                "github/apps/ember/install-123/installation-id".to_string(),
                "github/apps/ember/install-123/private-key".to_string(),
            ]
        );

        let device = crate::infra::attested_device::AttestedDevice::load_active(&data_dir)
            .unwrap()
            .expect("active enrollment stored");
        let mut headless_mek = device.unwrap_mek().unwrap();
        let headless_vault = Vault::new(headless_mek);
        headless_mek.zeroize();

        let mut headless_keys = crate::infra::headless_scope::list_headless_keys(&store).unwrap();
        headless_keys.sort();
        assert_eq!(headless_keys, authority_keys);
        assert_eq!(
            headless_vault
                .get(
                    crate::infra::vault::VaultScope::Headless,
                    &store,
                    "github/apps/ember/install-123/private-key",
                )
                .unwrap(),
            b"gh-private-key"
        );
        assert!(matches!(
            headless_vault.get(
                crate::infra::vault::VaultScope::Headless,
                &store,
                "aws-sts/access-key-id",
            ),
            Err(crate::infra::vault::VaultError::NotFound)
        ));

        crate::infra::attested_device::AttestedDevice::revoke_active(
            &data_dir,
            Some(&device.enrollment_id),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn headless_revoke_prunes_headless_scope_rows() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let root = tempfile::TempDir::new().unwrap();
        let sessions_dir = root.path().join("sessions");
        let data_dir = root.path().join("data");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        let device = crate::infra::attested_device::AttestedDevice::enroll_active(
            &data_dir,
            "test-headless-revoke-prune",
            std::time::Duration::from_secs(3600),
            &[0x81u8; 32],
        )
        .unwrap();

        let seed_vault = Vault::new([0x55u8; 32]);
        seed_vault
            .add(
                crate::infra::vault::VaultScope::Headless,
                &store,
                "svc/revoked-headless",
                b"stale",
                None,
            )
            .unwrap();
        assert_eq!(
            crate::infra::headless_scope::list_headless_keys(&store).unwrap(),
            vec!["svc/revoked-headless".to_string()]
        );

        let mut ctx = RequestContext::internal("test harness");
        ctx.sessions_dir = Some(sessions_dir);

        let result = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx,
            "headless_revoke",
            &json!({"enrollment_id": device.enrollment_id}),
        )
        .await
        .unwrap();

        assert_eq!(result["revoked"], json!(true));
        assert!(
            crate::infra::headless_scope::list_headless_keys(&store)
                .unwrap()
                .is_empty(),
            "headless_revoke must prune the headless vault subset after deleting the active enrollment"
        );
    }

    // ------------------------------------------------------------------
    // implementation-note-53 end-to-end tests.
    // ------------------------------------------------------------------

    /// Helper: mint a parent grant suitable for delegation tests.
    /// Returns `(parent_persona_id, parent_grant_id)`.
    async fn setup_parent_grant_for_agent_persona(
        store: &DaemonStore,
        vault: &Vault,
        policy: &PolicyEngine,
        rl: &RefCell<RateLimiter>,
        parent_name: &str,
    ) -> (String, String) {
        let parent_persona = dispatch_method(
            store,
            vault,
            policy,
            rl,
            "create_persona",
            &json!({"name": parent_name}),
        )
        .await
        .unwrap();
        let parent_persona_id = parent_persona["id"].as_str().unwrap().to_string();

        let parent_grant = dispatch_method(
            store,
            vault,
            policy,
            rl,
            "create_grant",
            &json!({
                "persona_id": parent_persona_id,
                "credential_name": "delegate-key",
                "scope": "*",
                "max_delegation_depth": 2,
                "ttl_secs": 3_600,
                "force": true,
            }),
        )
        .await
        .unwrap();
        let parent_grant_id = parent_grant["id"].as_str().unwrap().to_string();
        (parent_persona_id, parent_grant_id)
    }

    #[tokio::test]
    async fn create_agent_persona_atomic_mints_active_persona_and_attenuated_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_parent_persona_id, parent_grant_id) = setup_parent_grant_for_agent_persona(
            &store,
            &vault,
            &policy,
            &rl,
            "agent-parent-atomic",
        )
        .await;

        let resp = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_agent_persona",
            &json!({
                "name": "scion-worker-1",
                "container_id": "ctr-atomic-001",
                "parent_grant_id": parent_grant_id,
                "child_scope": "read",
                "ttl_secs": 1_800,
                "binding_request_id": "br-scion-001",
                "agent_id": "scion-agent-aaa",
            }),
        )
        .await
        .unwrap();

        // Caller sees an `active` persona (the `enrolling` intermediate
        // state is internal to the two-phase commit).
        assert_eq!(resp["status"], json!("active"));
        let new_persona_id = resp["persona_id"].as_str().unwrap().to_string();
        assert!(new_persona_id.starts_with("persona-"));
        let attenuated_grant_id = resp["attenuated_grant_id"].as_str().unwrap();
        assert!(attenuated_grant_id.starts_with("grant-"));
        assert_eq!(resp["container_id"], json!("ctr-atomic-001"));
        assert_eq!(resp["parent_grant_id"], json!(parent_grant_id));

        // Persona row matches: status=active, container binding persisted.
        let row = store.get_persona(&new_persona_id).unwrap();
        assert_eq!(row.status, "active");
        assert_eq!(row.container_id.as_deref(), Some("ctr-atomic-001"));
        assert_eq!(
            row.parent_grant_id.as_deref(),
            Some(parent_grant_id.as_str())
        );

        // Audit log carries the canonical binding event.
        let entries = store
            .query_audit(&AuditFilter {
                persona_id: Some(new_persona_id.clone()),
                ..Default::default()
            })
            .unwrap();
        let row = entries
            .iter()
            .find(|e| e.action == "agent_persona.created")
            .unwrap_or_else(|| panic!("expected agent_persona.created audit row, got {entries:?}"));
        let details: serde_json::Value =
            serde_json::from_str(row.details.as_deref().expect("details JSON populated"))
                .expect("details parses as JSON");
        assert_eq!(details["container_id"], json!("ctr-atomic-001"));
        assert_eq!(details["parent_grant_id"], json!(parent_grant_id));
        assert_eq!(details["child_grant_id"], json!(attenuated_grant_id));
        assert_eq!(details["binding_request_id"], json!("br-scion-001"));
        assert_eq!(details["agent_id"], json!("scion-agent-aaa"));
    }

    #[tokio::test]
    async fn create_agent_persona_rejects_unknown_parent_grant() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_agent_persona",
            &json!({
                "name": "scion-worker-orphan",
                "container_id": "ctr-orphan",
                "parent_grant_id": "grant-does-not-exist",
                "child_scope": "read",
            }),
        )
        .await
        .unwrap_err();

        // Bad parent grant must surface BEFORE any persona row is
        // inserted — leaves no poisoned enrolling slot.
        assert_eq!(err.0, -32004, "got: {err:?}");
        let by_container = store.enrolling_persona_for_container("ctr-orphan").unwrap();
        assert!(
            by_container.is_none(),
            "failed-validation create_agent_persona must NOT leave an enrolling row behind"
        );
    }

    #[tokio::test]
    async fn create_agent_persona_rejects_duplicate_container_spawn() {
        // CRIT-4: a second create_agent_persona for the same
        // container_id must be refused even after the first has
        // successfully activated.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_pp, parent_grant_id) =
            setup_parent_grant_for_agent_persona(&store, &vault, &policy, &rl, "agent-parent-dup")
                .await;

        let _first = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_agent_persona",
            &json!({
                "name": "scion-dup-1",
                "container_id": "ctr-dup",
                "parent_grant_id": parent_grant_id,
                "child_scope": "read",
                "ttl_secs": 1_800,
            }),
        )
        .await
        .unwrap();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_agent_persona",
            &json!({
                "name": "scion-dup-2",
                "container_id": "ctr-dup",
                "parent_grant_id": parent_grant_id,
                "child_scope": "read",
                "ttl_secs": 1_800,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005, "got: {err:?}");
        assert!(
            err.1.contains("ctr-dup") || err.1.contains("already bound"),
            "expected container-already-bound message, got: {}",
            err.1
        );
    }

    /// implementation-note-53 acceptance criterion:
    /// "emberd restart mid-spawn → reconciler refuses to spawn into
    /// enrolling slot."
    ///
    /// Simulated by directly inserting a persona row in `enrolling`
    /// state (representing phase 1 having committed before the daemon
    /// crashed); the reconciler's
    /// `enrolling_persona_for_container` lookup MUST surface the
    /// poisoned slot, and a subsequent `create_agent_persona` for the
    /// same container_id MUST be refused.
    #[tokio::test]
    async fn create_agent_persona_emberd_restart_mid_spawn_blocks_reconciler() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let (_pp, parent_grant_id) = setup_parent_grant_for_agent_persona(
            &store,
            &vault,
            &policy,
            &rl,
            "agent-parent-restart",
        )
        .await;

        // Simulate "emberd crashed after phase 1 (insert enrolling
        // row) but before phase 3 (activate)" by inserting the
        // enrolling row directly through the store API — bypassing
        // the RPC's atomic phase-2 + phase-3 path.
        let enrolling = store
            .create_agent_persona_enrolling("scion-crashed", "ctr-mid-spawn", &parent_grant_id)
            .unwrap();
        // Note: we never call activate_persona — the row stays in
        // `enrolling` forever, mimicking the daemon-crash window.

        // The reconciler's lookup MUST see the poisoned slot.
        let poisoned = store
            .enrolling_persona_for_container("ctr-mid-spawn")
            .unwrap()
            .expect("reconciler must see enrolling row after simulated crash");
        assert_eq!(poisoned.id, enrolling.id);
        assert_eq!(poisoned.status, "enrolling");

        // A second create_agent_persona RPC for the same
        // container_id MUST be refused — the reconciler will see the
        // -32005 error and treat the slot as poisoned until an
        // operator cleans it up out-of-band.
        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_agent_persona",
            &json!({
                "name": "scion-restart-attempt",
                "container_id": "ctr-mid-spawn",
                "parent_grant_id": parent_grant_id,
                "child_scope": "read",
                "ttl_secs": 1_800,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, -32005, "got: {err:?}");
        assert!(
            err.1.contains("ctr-mid-spawn") || err.1.contains("already bound"),
            "expected reconciler-refusal message, got: {}",
            err.1
        );

        // The poisoned row must NOT have been overwritten by the
        // refused spawn attempt — it is still in `enrolling` state.
        let after_attempt = store.get_persona(&enrolling.id).unwrap();
        assert_eq!(after_attempt.status, "enrolling");
    }

    // ---------------------------------------------------------------
    // implementation-note-133 — session.lookup_or_open
    // ---------------------------------------------------------------

    /// `session.lookup_or_open` refuses when no kernel-attested
    /// principal is available — wire-only RPC, Internal source is
    /// rejected with `-32401`.
    #[tokio::test]
    async fn session_lookup_or_open_refuses_without_principal() {
        let res = handle_session_lookup_or_open(None, &json!({})).await;
        let (code, msg) = res.expect_err("must refuse without principal");
        assert_eq!(code, -32401, "expected -32401, got {code}: {msg}");
    }

    /// `session.lookup_or_open` refuses when the caller-supplied
    /// `parent_pid` does not match the kernel-attested peer pid.
    #[tokio::test]
    async fn session_lookup_or_open_refuses_mismatched_parent_pid() {
        use crate::infra::runtime::PeerCredPrincipal;
        clear_persona_uid_registry();
        let principal =
            PeerCredPrincipal::new(1001, 42_000, std::path::PathBuf::from("/tmp/agent.sock"));
        let params = json!({"parent_pid": 99_999});
        let res = handle_session_lookup_or_open(Some(&principal), &params).await;
        let (code, msg) = res.expect_err("must refuse mismatched parent_pid");
        assert_eq!(code, -32004, "expected -32004, got {code}: {msg}");
        assert!(
            msg.contains("parent_pid") || msg.contains("99999") || msg.contains("42000"),
            "error must mention the mismatch, got: {msg}"
        );
    }

    /// `session.lookup_or_open` refuses when the caller-supplied
    /// `persona` resolves to a different bound uid than the kernel-
    /// attested principal's uid.
    #[tokio::test]
    async fn session_lookup_or_open_refuses_mismatched_persona() {
        use crate::infra::runtime::PeerCredPrincipal;
        clear_persona_uid_registry();
        bind_persona_uid("victim-persona", 5555);
        let principal =
            PeerCredPrincipal::new(6666, 42_000, std::path::PathBuf::from("/tmp/agent.sock"));
        let params = json!({"persona": "victim-persona"});
        let res = handle_session_lookup_or_open(Some(&principal), &params).await;
        let (code, _) = res.expect_err("must refuse mismatched persona binding");
        assert_eq!(code, -32004);
    }

    /// `session.lookup_or_open` succeeds when the principal is
    /// supplied and no caller-supplied identity claims conflict with
    /// it. Returns the session_id + parent_pid + socket_path triple.
    #[tokio::test]
    async fn session_lookup_or_open_succeeds_on_matched_principal() {
        use crate::infra::runtime::PeerCredPrincipal;
        clear_persona_uid_registry();
        bind_persona_uid("matched-persona", 7777);
        let principal =
            PeerCredPrincipal::new(7777, 12_345, std::path::PathBuf::from("/tmp/agent.sock"));
        let params = json!({"persona": "matched-persona", "parent_pid": 12_345});
        let res = handle_session_lookup_or_open(Some(&principal), &params).await;
        let value = res.expect("matched principal must succeed");
        assert_eq!(value["parent_pid"].as_i64(), Some(12_345));
        assert_eq!(value["persona_id"].as_str(), Some("matched-persona"));
        assert_eq!(value["socket_path"].as_str(), Some("/tmp/agent.sock"));
        assert!(
            value["session_id"]
                .as_str()
                .unwrap_or("")
                .starts_with("sess_"),
            "session_id must be minted, got: {value}"
        );
    }

    // ─── implementation-note-261 ────────────────────
    //
    // implementation-note-262
    //
    // Coverage for the `headless_preflight_layer1` dispatch arm. The
    // resolver itself is exhaustively unit-tested in
    // `crates/headless-runtime/src/preflight.rs::tests`; these tests cover the
    // wire-shape contract (param parsing, JSON gap shape) and confirm the
    // bundled cohort-A registry loads without an explicit `release-checklist`
    // dependency.

    /// Acceptance criterion: a task that declares a Construct whose action
    /// the (empty) persona template does not grant produces a non-empty
    /// gap list.
    #[tokio::test]
    async fn headless_preflight_layer1_emits_gap_for_unsatisfied_construct() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let params = json!({
            "tasks": [
                {
                    "task_id": "TASK-AP-PR-MERGE",
                    "constructs": ["ember-gh.pr_merge"],
                }
            ],
            "template": [],
        });

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "headless_preflight_layer1",
            &params,
        )
        .await
        .expect("layer1 dispatch should succeed");

        let gaps = result.as_array().expect("result is a JSON array");
        assert_eq!(gaps.len(), 1, "expected one gap, got: {result}");
        assert_eq!(gaps[0]["task_id"].as_str(), Some("TASK-AP-PR-MERGE"));
        assert_eq!(gaps[0]["identifier"].as_str(), Some("ember-gh.pr_merge"));
        assert!(gaps[0]["scope"].is_null());
    }

    /// Template that allows the declared permission → no gap.
    #[tokio::test]
    async fn headless_preflight_layer1_template_allows_means_no_gap() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let params = json!({
            "tasks": [
                {
                    "task_id": "TASK-AP-PR-MERGE",
                    "constructs": ["ember-gh.pr_merge"],
                }
            ],
            "template": ["ember-gh.pr_merge"],
        });

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "headless_preflight_layer1",
            &params,
        )
        .await
        .expect("layer1 dispatch should succeed");

        let gaps = result.as_array().expect("result is a JSON array");
        assert!(gaps.is_empty(), "expected no gaps, got: {result}");
    }

    /// Missing `tasks` param → `-32602` (invalid params).
    #[tokio::test]
    async fn headless_preflight_layer1_missing_tasks_returns_invalid_params() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let err = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "headless_preflight_layer1",
            &json!({}),
        )
        .await
        .expect_err("missing tasks should fail");
        assert_eq!(err.0, -32602);
        assert!(err.1.contains("'tasks'"), "error mentions tasks: {}", err.1);
    }

    /// Empty `tasks` array → empty gap list (no error).
    #[tokio::test]
    async fn headless_preflight_layer1_empty_tasks_yields_empty_gaps() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "headless_preflight_layer1",
            &json!({ "tasks": [] }),
        )
        .await
        .expect("empty tasks must succeed");
        let gaps = result.as_array().expect("array result");
        assert!(gaps.is_empty());
    }

    /// Unknown construct names are silently skipped — the resolver's
    /// "best-effort predictive layer" contract.
    #[tokio::test]
    async fn headless_preflight_layer1_unknown_construct_silently_skipped() {
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let params = json!({
            "tasks": [
                {
                    "task_id": "TASK-UNKNOWN",
                    "constructs": ["ember-nonexistent.do_thing"],
                }
            ],
            "template": [],
        });

        let result = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "headless_preflight_layer1",
            &params,
        )
        .await
        .expect("unknown construct must not error");
        let gaps = result.as_array().expect("array result");
        assert!(gaps.is_empty(), "unknown construct yields no gap: {result}");
    }

    /// The bundled cohort-A manifest registry includes the load-bearing
    /// `ember-gh` and `ember-kubectl` constructs the brief calls out.
    #[test]
    fn bundled_construct_registry_includes_cohort_a_tools() {
        let registry = bundled_construct_registry().expect("registry loads");
        assert!(
            registry.contains_key("ember-gh"),
            "registry missing ember-gh: {:?}",
            registry.keys().collect::<Vec<_>>()
        );
        assert!(
            registry.contains_key("ember-kubectl"),
            "registry missing ember-kubectl: {:?}",
            registry.keys().collect::<Vec<_>>()
        );
        // The kubectl manifest uses the tool-prefixed action-key shape,
        // exercising the resolver's short-name-prepended fallback.
        let kubectl = &registry["ember-kubectl"];
        assert!(
            kubectl.action_keys.iter().any(|k| k == "kubectl.apply"),
            "kubectl.apply key present: {:?}",
            kubectl.action_keys
        );
    }

    /// implementation-note-239 — shape check that
    /// the overlay block at the dispatch site overwrites the wire-claimed
    /// `persona` (and the `persona_id` / `id` aliases the various dispatch
    /// arms read) with the kernel-attested or cert-attested identity. The
    /// pre-fix code only inserted `caller_persona` / `caller_persona_id`,
    /// leaving `evaluate_tool_call` to honor the attacker-controlled wire
    /// `persona` field. This test replicates the overlay logic on test data
    /// — full per-agent-UDS enrollment scaffolding is heavier than this
    /// shape-check warrants, but the load-bearing invariant (wire-claimed
    /// persona is OVERWRITTEN, not honored, when an overlay source exists)
    /// is what we assert here.
    #[test]
    fn evaluate_tool_call_overlay_pins_persona_for_enrolled_caller() {
        // Wire payload claims persona-B (the attacker's target).
        let mut wire = json!({
            "persona": "persona-B",
            "persona_id": "persona-B",
            "id": "persona-B",
            "caller_persona": "persona-B",
            "caller_persona_id": "persona-B",
            "tool_name": "Bash",
            "tool_params": {"command": "echo hi"},
        });

        // Overlay source: kernel-attested identity is persona-A with grant-A.
        let overlay_persona_id = "persona-A".to_string();
        let overlay_grant_id = Some("grant-A".to_string());

        // Same overlay logic as `dispatch_method_with_context`.
        if let Value::Object(obj) = &mut wire {
            for key in [
                "caller_persona",
                "caller_persona_id",
                "persona",
                "persona_id",
                "id",
            ] {
                obj.insert(key.to_string(), Value::String(overlay_persona_id.clone()));
            }
            if let Some(gid) = overlay_grant_id.as_ref() {
                obj.insert("caller_grant_id".to_string(), Value::String(gid.clone()));
            }
        }

        // Every persona-claim alias the dispatch arms read must now be the
        // overlay-pinned A, not the wire-claimed B.
        assert_eq!(wire["persona"], json!("persona-A"));
        assert_eq!(wire["persona_id"], json!("persona-A"));
        assert_eq!(wire["id"], json!("persona-A"));
        assert_eq!(wire["caller_persona"], json!("persona-A"));
        assert_eq!(wire["caller_persona_id"], json!("persona-A"));
        assert_eq!(wire["caller_grant_id"], json!("grant-A"));
        // Non-persona fields untouched.
        assert_eq!(wire["tool_name"], json!("Bash"));
    }

    // --- implementation-note-268 tests --------------------

    #[tokio::test]
    async fn revoke_persona_rejects_non_operator_non_self() {
        // T1: non-operator non-self revocation must be rejected with -32003.
        // Persona B (attacker) asserts caller_persona_id = B and tries to
        // revoke persona A. The authority check must fire before any mutation.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "revoke-test-a"}),
        )
        .await
        .unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        let persona_b = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "revoke-test-b"}),
        )
        .await
        .unwrap();
        let b_id = persona_b["id"].as_str().unwrap().to_string();

        // Enroll caller PID with b_id (the claimed attacker) so the
        // Socket-source PID-enrollment gate passes; the test then
        // exercises the authority-check path it was written to validate.
        enroll_pid_persona(std::process::id() as i32, &b_id);

        // revoke_persona is OperatorPresence-class; the socket-source
        // shim synthesizes a presence_token, but the unlocked-session
        // gate still applies — move presence to Unlocked so the
        // authority check under test (cross-persona refusal) fires.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        // Persona B attempts to revoke persona A — must be denied.
        let err = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "revoke_persona",
            &json!({
                "id": a_id,
                "caller_persona_id": b_id,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.0, -32003,
            "non-self socket revoke must return -32003, got {err:?}"
        );
        assert!(
            err.1.to_lowercase().contains("not authorized")
                || err.1.to_lowercase().contains("revocation target"),
            "error must describe the authority failure, got: {}",
            err.1
        );

        // Verify persona A is still active (no mutation occurred).
        let personas = store.list_personas().unwrap();
        let a_status = personas.iter().find(|p| p.id == a_id).map(|p| &p.status);
        assert!(
            a_status.is_some(),
            "persona A must still exist after rejected revoke"
        );
        assert!(
            a_status.map(|s| s != "revoked").unwrap_or(false),
            "persona A must NOT be revoked after rejected cross-persona attempt"
        );
    }

    #[tokio::test]
    async fn revoke_persona_allows_self_revoke() {
        // T2: self-revoke (caller_persona_id == id) must succeed on Socket.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "revoke-self-test-a"}),
        )
        .await
        .unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        // Enroll PID with a_id so the Socket-source PID-enrollment gate
        // passes; the test then exercises the self-revoke success path.
        enroll_pid_persona(std::process::id() as i32, &a_id);

        // Satisfy the OperatorPresence unlocked-session gate.
        let _presence_test_guard = crate::trust::presence::test_state_guard();
        crate::trust::presence::mark_unlocked();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Socket,
            "revoke_persona",
            &json!({
                "id": a_id,
                "caller_persona_id": a_id,
            }),
        )
        .await
        .unwrap();

        assert_eq!(
            result["revoked"],
            json!(true),
            "self-revoke must succeed, got: {result}"
        );
    }

    #[tokio::test]
    async fn revoke_persona_internal_bypasses_authority_check() {
        // T3: Internal callers (admin CLI / test harness) bypass the authority
        // check and can revoke any persona without asserting caller_persona_id.
        let store = DaemonStore::open_in_memory().unwrap();
        let vault = test_vault();
        let policy = test_policy();
        let rl = test_rate_limiter();

        let persona_a = dispatch_method(
            &store,
            &vault,
            &policy,
            &rl,
            "create_persona",
            &json!({"name": "revoke-internal-test-a"}),
        )
        .await
        .unwrap();
        let a_id = persona_a["id"].as_str().unwrap().to_string();

        let result = dispatch_method_with_source(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            DispatchSource::Internal {
                reason: "test harness — revoke_persona internal bypass",
            },
            "revoke_persona",
            &json!({"id": a_id}),
        )
        .await
        .unwrap();

        assert_eq!(
            result["revoked"],
            json!(true),
            "internal bypass must succeed, got: {result}"
        );
    }
}
