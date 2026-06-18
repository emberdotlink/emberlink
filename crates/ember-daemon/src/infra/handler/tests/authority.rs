use super::*;
use serde_json::json;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE: Phase B's
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
fn audit_repair_chain_prepare_is_connectonly_and_quarantine_allowed() {
    assert_eq!(
        authority_class_for_method("audit_repair_chain_prepare"),
        Some(AuthorityClass::ConnectOnly),
        "prepare is read-only; commit remains audit_repair_chain"
    );
    assert!(
        quarantine_allowed_method("audit_repair_chain_prepare"),
        "prepare must be available while the daemon is quarantined"
    );
}

#[test]
fn receipt_dot_reads_are_connectonly_and_quarantine_allowed() {
    for method in ["receipt.list", "receipt.get"] {
        assert_eq!(
            authority_class_for_method(method),
            Some(AuthorityClass::ConnectOnly),
            "{method} is a read-only receipt table RPC"
        );
        assert!(
            quarantine_allowed_method(method),
            "{method} must remain available while the daemon is quarantined"
        );
    }
}

#[test]
fn vault_unlock_targets_mint_scoped_presence() {
    assert_eq!(
        presence_scope_for_unlock_target("vault_unlock")
            .as_ref()
            .map(|scope| scope.as_str()),
        Some(PRESENCE_SCOPE_CLASS_VAULT)
    );
    assert_eq!(
        presence_scope_for_unlock_target("register_session")
            .as_ref()
            .map(|scope| scope.as_str()),
        Some(PRESENCE_SCOPE_CLASS_SESSION_RUNTIME)
    );
    assert_eq!(
        presence_scope_for_unlock_target("create_persona")
            .as_ref()
            .map(|scope| scope.as_str()),
        Some("create_persona")
    );
    assert!(
        presence_scope_for_unlock_target("ping").is_none(),
        "connect-only methods must not become unlock targets"
    );
}

#[test]
fn class_scopes_cover_only_their_intended_operator_lanes() {
    let vault_scope = crate::auth::presence_token::ScopeKey::new(PRESENCE_SCOPE_CLASS_VAULT);
    assert!(presence_scope_allows_method(&vault_scope, "vault_unlock"));
    assert!(presence_scope_allows_method(&vault_scope, "vault_list"));
    assert!(presence_scope_allows_method(&vault_scope, "vault_add"));
    assert!(presence_scope_allows_method(&vault_scope, "vault_put"));
    assert!(
        !presence_scope_allows_method(&vault_scope, "create_persona"),
        "vault scope must not spill into general operator actions"
    );
    assert!(
        !presence_scope_allows_method(&vault_scope, "broker_exec"),
        "vault scope must not spill into session runtime actions"
    );

    let runtime_scope =
        crate::auth::presence_token::ScopeKey::new(PRESENCE_SCOPE_CLASS_SESSION_RUNTIME);
    assert!(presence_scope_allows_method(
        &runtime_scope,
        "register_session"
    ));
    assert!(presence_scope_allows_method(&runtime_scope, "broker_exec"));
    assert!(presence_scope_allows_method(&runtime_scope, "broker_list"));
    assert!(
        !presence_scope_allows_method(&runtime_scope, "vault_list"),
        "session runtime scope must not reopen the vault lane"
    );
    assert!(
        !presence_scope_allows_method(&runtime_scope, "create_persona"),
        "session runtime scope must not spill into grant or persona admin"
    );
}

#[tokio::test]
async fn team0_connectonly_global_diagnostics_do_not_require_trusted_principal() {
    let _tier = DeploymentTierGuard::set(crate::infra::config::DeploymentTier::Team0);
    clear_pid_persona_registry();
    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    let ctx = RequestContext::socket(Some(PeerCred {
        uid: 1000,
        pid: Some(91_009),
    }));

    for (method, params) in [
        ("audit_verify", json!({})),
        ("vault_status", json!(null)),
        ("trust.list", json!(null)),
    ] {
        dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            method,
            &params,
        )
        .await
        .unwrap_or_else(|err| {
            panic!("{method} should stay global on team0 without trusted principal, got {err:?}")
        });
    }

    for (method, params) in [
        ("broker.registry_status", json!(null)),
        ("broker.github_status", json!(null)),
        ("trust.show", json!(null)),
        ("trust.explain", json!(null)),
    ] {
        if let Err(err) = dispatch_method_with_context(
            &store,
            &vault,
            &policy,
            &rl,
            None,
            ctx.clone(),
            method,
            &params,
        )
        .await
        {
            assert_ne!(
                err.0, -32004,
                "{method} must not fail through ConnectOnly persona scoping"
            );
            assert!(
                !err.1.contains("trusted principal"),
                "{method} must not require trusted-principal scoping: {}",
                err.1
            );
        }
    }
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
        "audit_repair_chain_prepare",
        "audit_query",
        "audit.query",
        "receipt_query",
        "receipt.list",
        "receipt.get",
        "status",
        "list_receipts",
        "get_receipt",
        "list_personas",
        "list_grants",
        "list_pending_approvals",
        "list_standing_grants",
        "grant_status",
        "recover_grant_rebuild_chain_status",
        "grant_budget_status",
        "evaluate_grant",
        "headless_preflight_gaps",
        "recovery_action_receipt",
        "vault_status",
        "vault_rotate_plan",
        "vault_export_sealed",
        "vault_import_sealed",
        "await_approval",
        "telemetry.status",
        "telemetry_status",
        "telemetry.opt_in",
        "telemetry_opt_in",
        "telemetry.opt_out",
        "telemetry_opt_out",
        // OperatorPresence arms
        "create_persona",
        "build_init_first_grant_receipt",
        "persona_signer",
        "revoke_persona",
        "audit_log_query",
        "audit_explain",
        "grant_summary",
        "detect_anomalies",
        "headless_status",
        "receipt_tree",
        "list_operator_grants",
        "list_all_grants",
        "create_grant",
        "create_composite_grant",
        "delegate_grant",
        "sandbox_create",
        "sandbox_list",
        "sandbox_stop",
        "sandbox_delete",
        "sandbox_exec",
        "sandbox_run",
        "revoke_grant",
        "recover_grant_abandon",
        "recover_persona_abandon",
        "extend_grant",
        "grant.extend",
        "revoke_statement",
        "evaluate_tool_call",
        "use_credential",
        "vault_add",
        "vault_put",
        "vault_list",
        "vault_remove",
        "vault_rotate_execute",
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
        "approval.resolve",
        "approval_resolve",
        "approval.narrow",
        "approval_narrow",
        "grant.expire_stale",
        "expire_grants",
        "create_standing_grant",
        "remove_standing_grant",
        "request_access",
        "broker_issue",
        "broker_revoke",
        "broker_list",
        "broker_resolve",
        "broker_exec",
        "subprocess_audit_log",
        "broker.mint_gh_token",
        "broker_register_pid_watcher",
        "presence/request_proof",
        "presence_request_proof",
        // ADR 200 §3 — presence-intent nonce acquisition (ConnectOnly).
        "presence/request_nonce",
        "presence_request_nonce",
        // ADR 200 §5 operator-bootstrap ceremony (replaced presence/enroll).
        "identity.device.enroll",
        "identity_device_enroll",
        // ADR 206 §6 — recovery-recipient enrollment + multi-recipient KEK_s wrap.
        "identity.recovery.enroll",
        "identity_recovery_enroll",
        "vault.se_add_recipient_wrap",
        "vault_se_add_recipient_wrap",
        // ADR 200 §5 read-only PREPARE half (tap-reduction; ConnectOnly).
        "identity.device.enroll_plan",
        "identity_device_enroll_plan",
        // ADR 200 §5 / AC-2 backup-device enrollment.
        "identity.device.enroll_backup",
        "identity_device_enroll_backup",
        "identity.device.enroll_backup_plan",
        "identity_device_enroll_backup_plan",
        "sops_unwrap_dek",
        "sops.pubkey",
        "sops.wrap",
        "sops.unwrap",
        "register_session",
        "close_session",
        // ADR 194 §5 output 3 — planner save path.
        "save_delegation_template",
        // ADR 158 §C4 — workflow CLI family.
        "delegation_revoke",
        "delegation_list",
        "delegation_show",
        "describe_runtime_attach_target",
        "headless_enroll",
        "headless_revoke",
        // audit_repair_chain_rpc_landed (B4 + adversarial CRIT-2
        // fix 2026-05-22): omitted from this list pre-fix, so the
        // exhaustivity test below did not catch the unclassified
        // dispatcher arm. Added per the maintenance hint at the
        // top of this constant.
        "audit_repair_chain",
        // ADR 216 double-envelope provision + unlock (ConnectOnly).
        "vault.de_provision_begin",
        "vault_de_provision_begin",
        "vault.de_provision_outer",
        "vault_de_provision_outer",
        "vault.de_unlock_begin",
        "vault_de_unlock_begin",
        "vault.de_unlock_complete",
        "vault_de_unlock_complete",
        // V030-EMBER-DEVICE-LIST — read-only enrolled-device inventory (ConnectOnly).
        "identity.device.list",
        "identity_device_list",
        // V030-EMBER-DEVICE-REVOKE — operator-driven revocation; OOB-signed
        // DeviceRevoked event (same posture as enroll_backup), ConnectOnly.
        "identity.device.revoke",
        "identity_device_revoke",
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
    const DISPATCHER_ARM_COUNT_BASELINE: usize = 84;
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

/// Pins the EXACT authority class of every method `authority_class_for_method`
/// classifies — the independent oracle that supersedes the 23 per-method
/// `authority_class_for_*` unit tests. Each of those asserted one method's
/// class; this asserts all 118 in one frozen table, so a silent class
/// DOWNGRADE (e.g. `vault_unlock` OperatorPresence → ConnectOnly = a
/// presence-gate bypass) fails here no matter which method drifts. The
/// sibling `all_classified_methods_match_dispatcher_arms` guards the
/// orthogonal property — that every *dispatched* method is classified at all
/// (the `audit_repair_chain` CRIT-2 bug class) — while this guards that the
/// class is *correct*.
///
/// Non-obvious boundaries this locks (each was previously its own test):
///  - `vault_unlock` = OP, but `vault_unlock_{begin,wait,complete}` = CO
///    (proof-acquisition produces the proof the OP lane consumes; P12-S3).
///  - `presence/{request_nonce,complete_*}` + `identity.device.enroll_plan` = CO
///    (read/acquire halves); `identity.device.enroll` + `presence/request_proof` = OP.
///  - `delegation_revoke` = CO ("revoke is always safe", ADR 158 §C4),
///    but `delegate_grant` / `save_delegation_template` = OP.
///  - `subprocess_audit_log` = CO (vendor-whitelisted action string only).
///  - `audit_repair_chain` = OP (CRIT-2 fix 2026-05-22; CO/None = audit-tail wipe).
#[test]
fn every_classified_method_pins_its_exact_authority_class() {
    use AuthorityClass::{ConnectOnly as CO, OperatorPresence as OP};
    // Source of truth: the arms of `authority_class_for_method` above. Frozen
    // here as literals so a future edit to that match must edit this table in
    // lockstep — surfacing the security-relevant change to a reviewer.
    const EXPECTED: &[(&str, AuthorityClass)] = &[
        // ---- ConnectOnly (read / proof-acquisition / always-safe-revoke) ----
        ("ping", CO),
        ("audit_verify", CO),
        ("audit_query", CO),
        ("audit.query", CO),
        ("receipt_query", CO),
        ("receipt.list", CO),
        ("receipt.get", CO),
        ("list_personas", CO),
        ("list_grants", CO),
        ("list_pending_approvals", CO),
        ("list_receipts", CO),
        ("get_receipt", CO),
        ("list_standing_grants", CO),
        ("grant_status", CO),
        ("recover_grant_rebuild_chain_status", CO),
        ("grant_budget_status", CO),
        ("evaluate_grant", CO),
        ("daemon_persona", CO),
        ("presence_token_mint", CO),
        ("poll_notifications", CO),
        ("await_approval", CO),
        ("headless_preflight_gaps", CO),
        ("catalog.search_actions", CO),
        ("catalog_search_actions", CO),
        ("preflight_authority_coverage", CO),
        ("vault_status", CO),
        ("vault_rotate_plan", CO),
        ("vault_export_sealed", CO),
        ("vault_import_sealed", CO),
        ("broker.github_status", CO),
        ("broker_github_status", CO),
        ("broker.registry_status", CO),
        ("broker_registry_status", CO),
        ("trust.list", CO),
        ("trust_list", CO),
        ("trust.show", CO),
        ("trust_show", CO),
        ("trust.explain", CO),
        ("trust_explain", CO),
        ("refresh_cert", CO),
        ("status", CO),
        ("telemetry.status", CO),
        ("telemetry_status", CO),
        ("telemetry.opt_in", CO),
        ("telemetry_opt_in", CO),
        ("telemetry.opt_out", CO),
        ("telemetry_opt_out", CO),
        ("subprocess_audit_log", CO),
        ("presence/request_nonce", CO),
        ("presence_request_nonce", CO),
        ("delegation_revoke", CO),
        ("delegation_list", CO),
        ("delegation_show", CO),
        ("recovery_action_receipt", CO),
        ("describe_runtime_attach_target", CO),
        ("identity.device.enroll_plan", CO),
        ("identity_device_enroll_plan", CO),
        ("identity.device.enroll_backup_plan", CO),
        ("identity_device_enroll_backup_plan", CO),
        ("identity.device.enroll_backup", CO),
        ("identity_device_enroll_backup", CO),
        // ADR 206 slice 4 C — genesis-self-anchored (SE sig verified at COMMIT
        // append time), reclassified OperatorPresence → ConnectOnly.
        ("identity.device.enroll", CO),
        ("identity_device_enroll", CO),
        // ADR 206 §6 — recovery-recipient enroll + multi-recipient KEK_s wrap:
        // genesis-self-anchored / operator-session-gated, ConnectOnly like siblings.
        ("identity.recovery.enroll", CO),
        ("identity_recovery_enroll", CO),
        ("vault.se_add_recipient_wrap", CO),
        ("vault_se_add_recipient_wrap", CO),
        ("report_session_leaf", CO),
        // ---- OperatorPresence (mint / mutate / vault / broker / sensitive) ----
        ("create_persona", OP),
        ("build_init_first_grant_receipt", OP),
        ("persona_signer", OP),
        ("revoke_persona", OP),
        ("audit_log_query", OP),
        ("audit_explain", OP),
        ("grant_summary", OP),
        ("detect_anomalies", OP),
        ("receipt_tree", OP),
        ("list_operator_grants", OP),
        ("list_all_grants", OP),
        ("headless_status", OP),
        ("create_grant", OP),
        ("create_composite_grant", OP),
        ("delegate_grant", OP),
        ("revoke_grant", OP),
        ("recover_grant_abandon", OP),
        ("recover_persona_abandon", OP),
        ("extend_grant", OP),
        ("grant.extend", OP),
        ("revoke_statement", OP),
        ("evaluate_tool_call", OP),
        ("use_credential", OP),
        ("vault_add", OP),
        ("vault_put", OP),
        ("vault_list", OP),
        ("vault_remove", OP),
        ("vault_lock", OP),
        ("vault_unlock", OP),
        ("vault_get", OP),
        ("vault_migrate_acl", OP),
        ("vault_rotate_execute", OP),
        ("sandbox_create", OP),
        ("sandbox_list", OP),
        ("sandbox_stop", OP),
        ("sandbox_delete", OP),
        ("sandbox_exec", OP),
        ("sandbox_run", OP),
        ("local_state_key_get", OP),
        ("local_state_key_set", OP),
        ("local_state_key_rotate_and_reencrypt", OP),
        ("binary_pin_generate", OP),
        ("submit_approval", OP),
        ("propose_grant", OP),
        ("resolve_approval", OP),
        ("approval.resolve", OP),
        ("approval_resolve", OP),
        ("approval.narrow", OP),
        ("approval_narrow", OP),
        ("grant.expire_stale", OP),
        ("expire_grants", OP),
        ("create_standing_grant", OP),
        ("remove_standing_grant", OP),
        ("request_access", OP),
        ("broker_issue", OP),
        ("broker_revoke", OP),
        ("broker_list", OP),
        ("broker_resolve", OP),
        ("broker_exec", OP),
        ("broker.mint_gh_token", OP),
        ("broker_register_pid_watcher", OP),
        ("presence/request_proof", OP),
        ("presence_request_proof", OP),
        ("sops_unwrap_dek", OP),
        ("sops.pubkey", OP),
        ("sops.wrap", OP),
        ("sops.unwrap", OP),
        ("register_session", OP),
        ("close_session", OP),
        ("save_delegation_template", OP),
        ("headless_enroll", OP),
        ("headless_revoke", OP),
        ("audit_repair_chain", OP),
        // ADR 216 double-envelope provision + unlock (ConnectOnly).
        ("vault.de_provision_begin", CO),
        ("vault_de_provision_begin", CO),
        ("vault.de_provision_outer", CO),
        ("vault_de_provision_outer", CO),
        ("vault.de_unlock_begin", CO),
        ("vault_de_unlock_begin", CO),
        ("vault.de_unlock_complete", CO),
        ("vault_de_unlock_complete", CO),
        // V030-EMBER-DEVICE-LIST — read-only enrolled-device inventory (ConnectOnly).
        ("identity.device.list", CO),
        ("identity_device_list", CO),
        ("identity.device.revoke", CO),
        ("identity_device_revoke", CO),
    ];
    for (method, expected) in EXPECTED {
        assert_eq!(
            authority_class_for_method(method),
            Some(*expected),
            "authority-class drift for `{method}`: this mapping is a security \
                 boundary — change it intentionally (and update this table) or you \
                 have found a regression",
        );
    }
    // A duplicate row with a wrong class would hide behind the first match;
    // forbid duplicates so every entry is load-bearing.
    let mut names: Vec<&str> = EXPECTED.iter().map(|(m, _)| *m).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate method in EXPECTED table");
}

// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE: `RequestContext::
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
    // ADR 152's team0+/ent0 deployment populates this later.
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

// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE: dispatch gate
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

// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE: Socket source
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

// META-AP-DAEMON-PER-METHOD-AUTHORITY-B-ENFORCE: positive path —
// Socket source with a peer + bridge env on (set by the test
// shim) passes the gate for an OperatorPresence-class method.
// Downstream errors (param validation etc.) are NOT -32001 —
// the gate let the call through.
//
// Optional attached presence-token validates on the installed path
// when a caller provides one explicitly.
#[tokio::test]
async fn dispatch_socket_with_peer_passes_authority_gate_for_operator_presence() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::trust::presence::mark_unlocked();

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

// ADR 206 slice 4 C: tokenless local UDS calls no longer satisfy
// OperatorPresence when the §4 unlock window is LOCKED (the forgeable native
// auto-unlock-on-first-op path is retired — there is no auto-reopen).
#[tokio::test]
async fn dispatch_dev0_rejects_operator_presence_without_token() {
    // Pin the §4 window LOCKED so the tokenless call fails closed (no token,
    // no session scope, locked window → default-deny).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::lock();

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
    assert!(err.1.contains("locked"));
}

#[tokio::test]
async fn dispatch_team0_rejects_operator_presence_without_token() {
    // ADR 206 slice 4 C: pin the §4 window LOCKED so the tokenless call fails
    // closed (no token, no session scope, locked window → default-deny).
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::lock();

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
    assert!(err.1.contains("locked"));
}

#[tokio::test]
async fn dispatch_vault_unlock_and_register_session_fail_closed_when_window_locked() {
    // ADR 206 slice 4 C: `vault_unlock` + `register_session` are
    // OperatorPresence (not token-optional). With NO presence token and a
    // LOCKED §4 unlock window they fail closed — the retired native
    // auto-unlock no longer reopens on first op.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::lock();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    for (method, params) in [
        ("vault_unlock", json!({"requested_method": "vault_unlock"})),
        (
            "register_session",
            json!({"persona": "missing-token-session", "launcher_pid": 1u32}),
        ),
    ] {
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
            presence_token: None,
            bypass_binary_pin_gate_for_test: false,
        };

        let err =
            dispatch_method_with_context(&store, &vault, &policy, &rl, None, ctx, method, &params)
                .await
                .unwrap_err();
        assert_eq!(err.0, -32001, "{method} must fail at authority gate");
        assert!(
            err.1.contains("locked"),
            "{method} must fail closed on a locked §4 window, got {err:?}"
        );
    }
}

#[tokio::test]
async fn dispatch_se_unlock_methods_use_connect_only_not_operator_presence_gate() {
    // ADR 206 slice 4 C: the forgeable native/managed/lazy vault-unlock
    // ceremony is retired. The §4 presence-as-decryption unlock RPCs
    // (`vault.se_provision` / `vault.se_unlock_begin` /
    // `vault.se_unlock_complete`) are the only operator-presence unlock
    // acquisition surface now, and they are ConnectOnly: the operator-session
    // `se_unwrap` tap IS the presence proof, validated by the per-open AEAD.
    //
    // Invariant: dispatching a §4 unlock RPC without a presence_token must NOT
    // fail through the OperatorPresence gate (no -32001 "missing"/"locked").
    // They validate their own params inside the handler arm, so a malformed
    // request surfaces a param/handler error, never the authority gate.
    let _presence_test_guard = crate::trust::presence::test_state_guard();

    let store = DaemonStore::open_in_memory().unwrap();
    let vault = test_vault();
    let policy = test_policy();
    let rl = test_rate_limiter();
    ensure_test_authority_bridge_env();

    let se_unlock_methods = [
        // The DOT form is what the CLI actually sends (ember.rs) — it was
        // missing from the daemon arm, so the §4 RPCs returned "Method not
        // found" end-to-end despite slash/underscore passing this test.
        ("vault.se_unlock_begin", json!({})),
        ("vault/se_unlock_begin", json!({})),
        ("vault_se_unlock_begin", json!({})),
    ];

    // Exercise both presence states. A locked daemon (cold start, no cached
    // token) and an unlocked daemon must both let the §4 read flow through
    // without the OperatorPresence gate.
    for state_label in ["locked", "unlocked"] {
        if state_label == "unlocked" {
            crate::trust::presence::mark_unlocked();
        } else {
            crate::trust::presence::lock();
        }

        for (method, params) in &se_unlock_methods {
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
                presence_token: None,
                bypass_binary_pin_gate_for_test: false,
            };

            let result = dispatch_method_with_context(
                &store, &vault, &policy, &rl, None, ctx, method, params,
            )
            .await;
            if let Err((code, msg)) = result {
                assert!(
                    !(code == -32001 && (msg.contains("missing") || msg.contains("locked"))),
                    "[{state_label}] §4 unlock method {method} was rejected by the \
                         operator-presence gate (code={code}, msg={msg:?})"
                );
            }
        }
    }
}

#[test]
fn only_privilege_reduction_methods_are_token_optional_operator_presence() {
    assert!(operator_presence_token_optional_method("vault_lock"));
    assert!(operator_presence_token_optional_method("close_session"));
    assert!(!operator_presence_token_optional_method("vault_unlock"));
    assert!(!operator_presence_token_optional_method("register_session"));
    assert!(!operator_presence_token_optional_method("create_persona"));
}

#[tokio::test]
async fn dispatch_team0_accepts_operator_presence_with_token() {
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::trust::presence::mark_unlocked();

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
async fn dispatch_operator_presence_locked_window_fails_closed_even_with_token() {
    // ADR 206 slice 4 C fail-closed invariant: the forgeable native/managed/
    // lazy auto-unlock-on-first-op path is retired. An OperatorPresence method
    // dispatched while the §4 presence-as-decryption unlock window is LOCKED
    // MUST fail closed — even when the caller presents a valid presence_token.
    // There is NO auto-reopen; the operator must run `ember vault se-unlock`.
    //
    // Serialize against sibling tests that flip MANAGER via mark_unlocked —
    // this test pins state to Locked.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::trust::presence::lock();
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
    assert_eq!(
        err.0, -32001,
        "locked §4 window must fail at the authority gate"
    );
    assert!(
        err.1.contains("locked"),
        "locked operator-presence call must fail closed with a 'locked' reason; got {err:?}"
    );
}

#[tokio::test]
async fn dispatch_operator_presence_unlocked_window_authorizes_with_token() {
    // Companion to the fail-closed test: with the §4 window OPEN
    // (mark_unlocked) and a valid presence_token, the same OperatorPresence
    // method passes the authority gate (it proceeds past -32001 into the
    // handler arm). Proves the gate is not blanket-deny — it tracks the
    // window state.
    let _presence_test_guard = crate::trust::presence::test_state_guard();
    crate::trust::presence::reset_for_tests();
    crate::trust::presence::mark_unlocked();
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
        &json!({"name": "unlocked-presence-session"}),
    )
    .await;

    // The authority gate must NOT reject this with -32001; the open §4 window
    // plus a valid token authorizes the op. (Whatever the handler arm returns
    // beyond the gate is out of scope for this test.)
    if let Err((code, msg)) = &result {
        assert_ne!(
            *code, -32001,
            "open §4 window + valid token must pass the authority gate; got {msg}"
        );
    }
}

// META-AP-DAEMON-PER-METHOD-AUTHORITY-D-4-HANDLER-VALIDATE:
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

// P10-S3 — preflight_authority_coverage dispatch wire path. These drive the
// real handler (param parse → list_active_grants → classify → JSON) against
// an in-memory store with no grants, so every uncovered action lands in the
// posture-derived bucket. The covered-path verdict + the catalog-mirroring
// statement matcher are unit-tested in `preflight_authority_coverage_tests`.

// ------------------------------------------------------------------
// quarantine_serve_mode_binds_socket (ADR 174 v2 §1 / R1 D6)
// ------------------------------------------------------------------

#[test]
fn quarantine_authority_labels_are_stable() {
    assert_eq!(
        QuarantineAuthority::StartupAuditChainBreak.as_str(),
        "startup_audit_chain_break"
    );
    assert_eq!(
        QuarantineAuthority::MidServeAuditChainBreak.as_str(),
        "mid_serve_audit_chain_break"
    );
}

#[test]
fn enter_quarantine_into_records_authority_reason_and_flips_flag() {
    // T1 per acceptance: enter_quarantine on StartupAuditChainBreak →
    // flag set, reason stored, authority queryable. Parameterised so
    // the test doesn't contaminate the process-global latch.
    let flag = AtomicBool::new(false);
    let reason_cell = OnceLock::new();
    let authority_cell = OnceLock::new();

    enter_quarantine_into(
        &flag,
        &reason_cell,
        &authority_cell,
        QuarantineAuthority::StartupAuditChainBreak,
        "audit chain break at row 291".to_string(),
    );

    assert!(flag.load(Ordering::Acquire), "quarantine flag must flip");
    assert_eq!(
        reason_cell.get().map(String::as_str),
        Some("audit chain break at row 291")
    );
    assert_eq!(
        authority_cell.get().copied(),
        Some(QuarantineAuthority::StartupAuditChainBreak)
    );
}

#[test]
fn enter_quarantine_into_first_entry_wins() {
    // Idempotency: subsequent calls do NOT overwrite the first-recorded
    // reason or authority. Recovery is daemon-restart, not in-process
    // re-entry — see ADR 174 v2.
    let flag = AtomicBool::new(false);
    let reason_cell = OnceLock::new();
    let authority_cell = OnceLock::new();

    enter_quarantine_into(
        &flag,
        &reason_cell,
        &authority_cell,
        QuarantineAuthority::StartupAuditChainBreak,
        "first-recorded reason".to_string(),
    );
    enter_quarantine_into(
        &flag,
        &reason_cell,
        &authority_cell,
        QuarantineAuthority::MidServeAuditChainBreak,
        "second call — should be ignored".to_string(),
    );

    assert_eq!(
        reason_cell.get().map(String::as_str),
        Some("first-recorded reason"),
        "OnceLock must preserve the first reason"
    );
    assert_eq!(
        authority_cell.get().copied(),
        Some(QuarantineAuthority::StartupAuditChainBreak),
        "OnceLock must preserve the first authority"
    );
}
