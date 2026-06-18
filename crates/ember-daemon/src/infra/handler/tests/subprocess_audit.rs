use super::*;

// -----------------------------------------------------------------------
// META-AP-EMBER-INIT-CLAUDE-CODE-GRADIENT-WARNING (Tier 1) —
// subprocess_audit_log tests. Anchor:
// subprocess_audit_log_routes_through_chain
// -----------------------------------------------------------------------

#[test]
fn subprocess_audit_log_is_connect_only() {
    // The whole point of Tier 1: ANY peer-cred caller (the shim runs as
    // the operator uid; it's already in ember-clients) can record an
    // unsessioned subprocess invocation. OperatorPresence would defeat
    // the design — there's no session at this point.
    assert_eq!(
        authority_class_for_method("subprocess_audit_log"),
        Some(AuthorityClass::ConnectOnly)
    );
}

#[test]
fn subprocess_audit_log_is_not_read_class() {
    // The chain extension is a write. The dispatch-layer quarantine
    // gate (~line 2445) refuses any non-read-class method while
    // quarantined; this assertion pins that subprocess_audit_log
    // remains write-class so the gate keeps firing.
    assert!(
        !is_read_class_method("subprocess_audit_log"),
        "subprocess_audit_log must NOT be read-class — chain writes \
             must refuse while quarantined"
    );
}

#[test]
fn subprocess_audit_log_happy_path_extends_chain() {
    let store = DaemonStore::open_in_memory().unwrap();

    let result = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "git",
            "verb": "git.push",
            "outcome": "ambient_credential_used",
            "argv_summary": "push origin main",
        }),
        None,
    )
    .expect("happy path must succeed");

    assert_eq!(result["logged"], json!(true));
    let id = result["id"].as_i64().expect("id must be i64");
    assert!(id > 0, "audit_log row id must be positive");

    // Verify the row landed with the daemon-built action prefix —
    // the caller never controls the action string.
    let (action, outcome): (String, String) = store
        .conn()
        .query_row(
            "SELECT action, outcome FROM audit_log WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(action, "subprocess.git.invoke_no_session");
    assert_eq!(outcome, "ambient_credential_used");

    // Chain verifier walks the new tail without error.
    use crate::infra::audit::{VerifyOutcome, run_audit_verify};
    let outcome = run_audit_verify(store.conn(), None, None).unwrap();
    assert!(
        matches!(outcome, VerifyOutcome::Ok { .. }),
        "chain must verify after subprocess_audit_log: {outcome:?}"
    );
}

#[test]
fn subprocess_audit_log_accepts_denied_no_session_outcome() {
    let store = DaemonStore::open_in_memory().unwrap();

    let result = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "gh",
            "verb": "gh.pr.create",
            "outcome": "denied_no_session",
            "argv_summary": "pr create",
        }),
        None,
    )
    .expect("denied_no_session must be accepted");

    assert_eq!(result["logged"], json!(true));
    let id = result["id"].as_i64().expect("id must be i64");
    let outcome: String = store
        .conn()
        .query_row(
            "SELECT outcome FROM audit_log WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outcome, "denied_no_session");
}

#[test]
fn subprocess_audit_log_rejects_unknown_vendor() {
    let store = DaemonStore::open_in_memory().unwrap();
    let err = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "etc-passwd",
            "verb": "cat",
            "outcome": "ambient_credential_used",
            "argv_summary": "/etc/passwd",
        }),
        None,
    )
    .expect_err("unknown vendor must be rejected");
    assert_eq!(err.0, -32602, "got: {err:?}");
    assert!(
        err.1.contains("etc-passwd") && err.1.contains("whitelist"),
        "error must name the rejected vendor: {}",
        err.1
    );
}

#[test]
fn subprocess_audit_log_rejects_unknown_outcome() {
    let store = DaemonStore::open_in_memory().unwrap();
    let err = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "gh",
            "verb": "gh.pr.create",
            "outcome": "credential_provisioned",
            "argv_summary": "pr create",
        }),
        None,
    )
    .expect_err("non-allowlist outcome must be rejected");
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("outcome"), "got: {}", err.1);
}

#[test]
fn subprocess_audit_log_rejects_oversized_verb() {
    let store = DaemonStore::open_in_memory().unwrap();
    let err = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "git",
            "verb": "x".repeat(129),
            "outcome": "ambient_credential_used",
            "argv_summary": "",
        }),
        None,
    )
    .expect_err("oversized verb must be rejected");
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("verb"), "got: {}", err.1);
}

#[test]
fn subprocess_audit_log_rejects_oversized_argv_summary() {
    let store = DaemonStore::open_in_memory().unwrap();
    let err = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "git",
            "verb": "git.push",
            "outcome": "ambient_credential_used",
            "argv_summary": "x".repeat(257),
        }),
        None,
    )
    .expect_err("oversized argv_summary must be rejected");
    assert_eq!(err.0, -32602);
    assert!(err.1.contains("argv_summary"), "got: {}", err.1);
}

#[test]
fn subprocess_audit_log_rejects_non_ascii_verb() {
    let store = DaemonStore::open_in_memory().unwrap();
    let err = handle_subprocess_audit_log(
        &store,
        &json!({
            "vendor": "git",
            "verb": "git\npush",
            "outcome": "ambient_credential_used",
            "argv_summary": "",
        }),
        None,
    )
    .expect_err("control-char verb must be rejected");
    assert_eq!(err.0, -32602);
}

#[test]
fn subprocess_audit_log_dispatch_arm_classified() {
    // Checkpoint-style guard: a future refactor that drops the method
    // from the DISPATCHED_METHODS list would let the dispatcher arm
    // silently rot into a -32601. The exhaustivity test catches
    // dropped classification, but this also pins the explicit class.
    assert_eq!(
        authority_class_for_method("subprocess_audit_log"),
        Some(AuthorityClass::ConnectOnly)
    );
}
