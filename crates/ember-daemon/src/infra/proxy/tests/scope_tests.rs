use super::*;

// ------------------------------------------------------------------
// Scope enforcement tests (69E.5)
// ------------------------------------------------------------------

#[tokio::test]
async fn scope_read_denies_post() {
    let state = make_state();

    let persona = state.store.create_persona("scope-read-post").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "gh-token",
            b"ghp_secret",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "gh-token", "*:read", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://api.github.com/repos/emberdotlink/emberlink/issues",
        Some(&persona.id),
        Some("gh-token"),
        Some("https://api.github.com"),
    );

    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Per ADR 073 a POST to a github endpoint under a read-only
    // statement has zero applicable statements (the statement's
    // action is "read", the request's action is "github:push"),
    // so this denies at the statement-resolution layer. The body
    // must not leak the selector string.
    let err = json["error"].as_str().unwrap_or("");
    assert_eq!(
        err, "no_applicable_statement",
        "unexpected error shape: {err}"
    );
    // The response must NOT leak the scope string.
    let body_str = std::str::from_utf8(&body).unwrap();
    assert!(
        !body_str.contains("read"),
        "response body leaked scope detail: {body_str}"
    );
}

#[tokio::test]
async fn scope_read_allows_get() {
    // The check function itself is the load-bearing piece; the full
    // forward path doesn't need to work in tests.
    let uri: hyper::Uri = "https://api.github.com/repos/emberdotlink/emberlink"
        .parse()
        .unwrap();
    assert!(check_scope("*:read", &hyper::Method::GET, &uri).is_ok());
    assert!(check_scope("*:read", &hyper::Method::HEAD, &uri).is_ok());
    // V0 scope grammar requires provider:action — bare action is gone.
    assert!(check_scope("read", &hyper::Method::GET, &uri).is_err());
}

#[tokio::test]
async fn scope_github_push_specific_repo() {
    // Allowed: push to the exact repo.
    let ok_uri: hyper::Uri = "https://api.github.com/repos/emberdotlink/emberlink/issues"
        .parse()
        .unwrap();
    assert!(
        check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &ok_uri
        )
        .is_ok()
    );

    // Denied: push to a different repo.
    let bad_uri: hyper::Uri = "https://api.github.com/repos/other/repo/issues"
        .parse()
        .unwrap();
    assert!(
        check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &bad_uri
        )
        .is_err()
    );

    // Also denied: the host isn't github.
    let wrong_host: hyper::Uri = "https://api.example.com/repos/emberdotlink/emberlink/issues"
        .parse()
        .unwrap();
    assert!(
        check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::POST,
            &wrong_host
        )
        .is_err()
    );

    // Also denied: a read-tier method with a push-only scope.
    assert!(
        check_scope(
            "github:push:emberdotlink/emberlink",
            &hyper::Method::GET,
            &ok_uri
        )
        .is_err()
    );
}

#[tokio::test]
async fn scope_wildcard_allows_anything() {
    let uri: hyper::Uri = "https://api.example.com/anything".parse().unwrap();
    assert!(check_scope("*", &hyper::Method::GET, &uri).is_ok());
    assert!(check_scope("*", &hyper::Method::POST, &uri).is_ok());
    assert!(check_scope("*:*", &hyper::Method::DELETE, &uri).is_ok());
    assert!(check_scope("*:*:*", &hyper::Method::PATCH, &uri).is_ok());
}

#[tokio::test]
async fn scope_unknown_format_denies() {
    let uri: hyper::Uri = "https://api.github.com/repos/a/b".parse().unwrap();

    // Empty scope.
    assert!(check_scope("", &hyper::Method::GET, &uri).is_err());
    // Whitespace-only.
    assert!(check_scope("   ", &hyper::Method::GET, &uri).is_err());
    // Trailing/double colons (empty segments).
    assert!(check_scope("garbled::::", &hyper::Method::GET, &uri).is_err());
    assert!(check_scope("github::push", &hyper::Method::POST, &uri).is_err());
    // Too many segments.
    assert!(check_scope("a:b:c:d:e", &hyper::Method::GET, &uri).is_err());
    // Unknown provider.
    assert!(check_scope("quux:read", &hyper::Method::GET, &uri).is_err());
    // Unknown action.
    assert!(check_scope("github:frobnicate", &hyper::Method::POST, &uri).is_err());
    // Unknown HTTP method (CONNECT/TRACE etc.) fails closed even under "*".
    assert!(check_scope("*", &hyper::Method::CONNECT, &uri).is_err());
}

#[tokio::test]
async fn scope_read_denies_post_e2e_logs_denial() {
    // End-to-end: denial also writes an audit entry when no statement
    // covers the request.
    let state = make_state();
    let persona = state.store.create_persona("scope-audit").unwrap();
    state
        .vault
        .add(VaultScope::Interactive, &state.store, "tok", b"s", None)
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "tok", "*:read", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://api.github.com/repos/a/b/issues",
        Some(&persona.id),
        Some("tok"),
        Some("https://api.github.com"),
    );

    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.action == "credential.access"
                && e.outcome == "denied_no_applicable_statement")
    );
}

#[tokio::test]
async fn successful_request_logs_audit_event() {
    let state = make_state();

    let persona = state.store.create_persona("audit-agent").unwrap();
    state
        .vault
        .add(
            VaultScope::Interactive,
            &state.store,
            "audit-token",
            b"tok_secret",
            None,
        )
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "audit-token", "generic:read", None)
        .unwrap();

    let req = proxy_request_with_headers(
        Some(&persona.id),
        Some("audit-token"),
        Some("https://api.example.com"),
    );

    let resp = call(Arc::clone(&state), req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let entries = state
        .store
        .query_audit(&crate::infra::audit::AuditFilter::default())
        .unwrap();
    // grant.minted from create_grant + credential.access from the proxy request = 2
    assert_eq!(entries.len(), 2);
    // query_audit orders by timestamp DESC; credential.access is most recent
    assert_eq!(entries[0].action, "credential.access");
    assert_eq!(entries[0].outcome, "allowed");
    assert_eq!(entries[0].credential.as_deref(), Some("audit-token"));
    assert_eq!(entries[1].action, "grant.minted");
}

// ------------------------------------------------------------------
// Subtarget (branch-pattern) enforcement tests (69E.5b)
// ------------------------------------------------------------------

#[tokio::test]
async fn scope_subtarget_branches_path_glob_match() {
    // feat/* glob matches feat/foo branch.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/feat/foo"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
        "feat/* should match feat/foo via /branches/ path"
    );
}

#[tokio::test]
async fn scope_subtarget_branches_path_glob_mismatch() {
    // feat/* glob does NOT match main.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_err(),
        "feat/* should not match main branch"
    );
}

#[tokio::test]
async fn scope_subtarget_git_refs_heads_glob_match() {
    // feat/* glob matches feat/anything via /git/refs/heads/.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/git/refs/heads/feat/anything"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:feat/*", &hyper::Method::PATCH, &uri).is_ok(),
        "feat/* should match feat/anything via /git/refs/heads/"
    );
}

#[tokio::test]
async fn scope_subtarget_non_branch_path_denied() {
    // Path has no branch in it — should fail closed.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/issues".parse().unwrap();
    let result = check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri);
    assert!(
        result.is_err(),
        "scope with subtarget must fail closed when path has no /branches/ or /git/refs/heads/"
    );
    let err_msg = result.unwrap_err().message;
    assert!(
        err_msg.contains("/branches/") || err_msg.contains("/git/refs/heads/"),
        "error message should explain why: {err_msg}"
    );
}

#[tokio::test]
async fn scope_subtarget_exact_match() {
    let main_uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
        .parse()
        .unwrap();
    let dev_uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/develop"
        .parse()
        .unwrap();

    // Exact match succeeds.
    assert!(
        check_scope("github:push:x/y:main", &hyper::Method::DELETE, &main_uri).is_ok(),
        "exact subtarget 'main' should match /branches/main"
    );
    // Exact match fails on a different branch.
    assert!(
        check_scope("github:push:x/y:main", &hyper::Method::DELETE, &dev_uri).is_err(),
        "exact subtarget 'main' should not match /branches/develop"
    );
}

#[tokio::test]
async fn scope_subtarget_empty_segment_rejected() {
    // A trailing colon (empty subtarget) must be rejected as a malformed scope.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main"
        .parse()
        .unwrap();
    let result = check_scope("github:push:x/y:", &hyper::Method::POST, &uri);
    assert!(
        result.is_err(),
        "empty subtarget segment (trailing colon) must be rejected"
    );
    let err_msg = result.unwrap_err().message;
    assert!(
        err_msg.contains("malformed"),
        "error should say malformed: {err_msg}"
    );
}

#[tokio::test]
async fn scope_subtarget_protection_subresource() {
    // /branches/{branch}/protection — branch is still the segment after /branches/.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/main/protection"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:main", &hyper::Method::PUT, &uri).is_ok(),
        "subtarget 'main' should match /branches/main/protection"
    );
}

// ------------------------------------------------------------------
// Percent-encoded branch name tests (adversarial review finding)
// ------------------------------------------------------------------

#[tokio::test]
async fn scope_subtarget_percent_encoded_slash_in_branch() {
    // feat%2Ffoo in the URI path should match the glob feat/* after decoding.
    // hyper parses the raw path; `%2F` is NOT decoded to `/` by `uri.path()`.
    // We must decode it ourselves before matching.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/feat%2Ffoo"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
        "feat/* should match branch feat/foo delivered as feat%2Ffoo in path"
    );
}

#[tokio::test]
async fn scope_subtarget_heavily_percent_encoded_branch() {
    // %66eat%2Fbar decodes to feat/bar, which should match feat/*.
    let uri: hyper::Uri = "https://api.github.com/repos/x/y/branches/%66eat%2Fbar"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:x/y:feat/*", &hyper::Method::POST, &uri).is_ok(),
        "feat/* should match branch feat/bar delivered as %66eat%2Fbar in path"
    );
}

// ------------------------------------------------------------------
// 69E.5b required acceptance tests
// ------------------------------------------------------------------

#[tokio::test]
async fn subtarget_glob_allows_matching_branch() {
    // feat/* matches feat/foo on POST /branches/feat/foo.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/feat/foo"
        .parse()
        .unwrap();
    assert!(check_scope("github:push:owner/repo:feat/*", &hyper::Method::POST, &uri).is_ok(),);
}

#[tokio::test]
async fn subtarget_glob_denies_main_branch_when_scope_limits_to_feat() {
    // feat/* does NOT match main.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/main"
        .parse()
        .unwrap();
    assert!(check_scope("github:push:owner/repo:feat/*", &hyper::Method::POST, &uri).is_err(),);
}

#[tokio::test]
async fn subtarget_glob_allows_nested_via_double_star() {
    // release/** matches release/v2/hotfix via /git/refs/heads/.
    let uri: hyper::Uri =
        "https://api.github.com/repos/owner/repo/git/refs/heads/release/v2/hotfix"
            .parse()
            .unwrap();
    assert!(
        check_scope(
            "github:push:owner/repo:release/**",
            &hyper::Method::POST,
            &uri,
        )
        .is_ok(),
        "release/** should match release/v2/hotfix"
    );

    // Single-star should NOT match nested paths: release/* matches
    // release/v2 but not release/v2/hotfix.
    let nested: hyper::Uri =
        "https://api.github.com/repos/owner/repo/git/refs/heads/release/v2/hotfix"
            .parse()
            .unwrap();
    assert!(
        check_scope(
            "github:push:owner/repo:release/*",
            &hyper::Method::POST,
            &nested,
        )
        .is_err(),
        "release/* must NOT match release/v2/hotfix — that's the point of **",
    );
}

#[tokio::test]
async fn subtarget_no_glob_falls_through_to_target_match() {
    // A scope with no subtarget (three segments) must allow any branch
    // once the target (owner/repo) matches.
    let uri_main: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/main"
        .parse()
        .unwrap();
    let uri_feat: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/feat/foo"
        .parse()
        .unwrap();
    let uri_issues: hyper::Uri = "https://api.github.com/repos/owner/repo/issues"
        .parse()
        .unwrap();

    for uri in [&uri_main, &uri_feat, &uri_issues] {
        assert!(
            check_scope("github:push:owner/repo", &hyper::Method::POST, uri).is_ok(),
            "scope without subtarget must allow {uri}",
        );
    }
}

#[tokio::test]
async fn subtarget_contents_endpoint_uses_ref_query_param() {
    // PUT /repos/owner/repo/contents/file.txt?ref=feat/foo
    // — branch is the ref query param, not anywhere in the path.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/contents/file.txt?ref=feat/foo"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:owner/repo:feat/*", &hyper::Method::PUT, &uri).is_ok(),
        "feat/* should match ?ref=feat/foo on /contents/ endpoint"
    );
}

#[tokio::test]
async fn subtarget_denies_contents_with_main_ref() {
    // Same scope, but ?ref=main — should deny.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/contents/file.txt?ref=main"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:owner/repo:feat/*", &hyper::Method::PUT, &uri).is_err(),
        "feat/* must not match ?ref=main on /contents/ endpoint"
    );
}

#[tokio::test]
async fn subtarget_contents_percent_encoded_ref() {
    // ?ref=feat%2Ffoo decodes to feat/foo, matching feat/*.
    let uri: hyper::Uri =
        "https://api.github.com/repos/owner/repo/contents/file.txt?ref=feat%2Ffoo"
            .parse()
            .unwrap();
    assert!(
        check_scope("github:push:owner/repo:feat/*", &hyper::Method::PUT, &uri).is_ok(),
        "percent-encoded ref value must decode before matching"
    );
}

#[tokio::test]
async fn subtarget_contents_no_ref_query_denies() {
    // /contents/ without ?ref= — we cannot determine which branch is
    // targeted, so fail closed.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/contents/file.txt"
        .parse()
        .unwrap();
    assert!(
        check_scope("github:push:owner/repo:feat/*", &hyper::Method::PUT, &uri).is_err(),
        "missing ?ref= must fail closed when scope has subtarget"
    );
}

// ------------------------------------------------------------------
// Glob semantics — unit tests now live in
// `core-proxy-forward::r#match::tests` (ARCH-PROXY-MATCH-EXTRACT).
// The two end-to-end scope tests below stay here because they exercise
// `check_scope` against a full `hyper::Uri`, not the matcher alone.
// ------------------------------------------------------------------

#[test]
fn subtarget_violation_carries_subtarget_audit_outcome() {
    // The ScopeViolation returned by a subtarget mismatch reports the
    // `denied_subtarget_scope` audit outcome, distinct from the generic
    // `denied_scope` used elsewhere. This is how the audit log
    // distinguishes a branch-scope denial from any other scope reason.
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/main"
        .parse()
        .unwrap();
    let violation =
        check_scope("github:push:owner/repo:feat/*", &hyper::Method::POST, &uri).unwrap_err();
    assert_eq!(violation.kind, ScopeViolationKind::Subtarget);
    assert_eq!(violation.audit_outcome(), "denied_subtarget_scope");

    // Also verify a generic (non-subtarget) violation reports the legacy
    // outcome. Use a read-tier scope hitting a write method — not a
    // subtarget reason.
    let generic_uri: hyper::Uri = "https://api.github.com/repos/owner/repo/issues"
        .parse()
        .unwrap();
    let generic = check_scope("read", &hyper::Method::POST, &generic_uri).unwrap_err();
    assert_eq!(generic.kind, ScopeViolationKind::General);
    assert_eq!(generic.audit_outcome(), "denied_scope");
}

// ------------------------------------------------------------------
// P69E.5c — Composite selector subtarget routing
// ------------------------------------------------------------------
//
// A 4-segment legacy scope (`github:push:owner/repo:feat/*`) used to
// build a flat `ResourceSelector::Glob { pattern: "owner/repo:feat/*" }`,
// which a request resource like `owner/repo` could never match — the
// resolver always returned `NoApplicable` and the deny path emitted
// `denied_no_applicable_statement` instead of the more-specific
// `denied_subtarget_scope`. The fix: emit a structured
// `GlobWithSubtarget` and route the resolver to verify the subtarget
// glob against the request URI's branch.

fn grant_with_subtarget_scope(scope: &str) -> core_grant_types::AccessGrant {
    use core_event_types::PresentationAudienceKind;
    use core_grant_types::{
        AccessGrant, AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile,
        ResourceSelector, ResourceType, SignedBlock, Statement, Usage,
    };
    // Mirror what `scope_to_actions_and_selector` produces for the
    // 4-segment shape — a single statement with `GlobWithSubtarget`.
    let parts: Vec<&str> = scope.split(':').collect();
    assert_eq!(parts.len(), 4, "test fixture requires 4-segment scope");
    let stmt = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec![format!("{}:{}", parts[0], parts[1])],
        resource: ResourceSelector::GlobWithSubtarget {
            primary_glob: parts[2].into(),
            subtarget_glob: parts[3].into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let block = Block {
        statements: vec![stmt],
        nbf: None,
        expires_at: None,
        issued_by: "persona-sub".into(),
        issued_at: 0,
        approval: None,
        note: None,
    };
    AccessGrant {
        id: "grant-sub".into(),
        version: 1,
        issuing_persona_id: "persona-sub".into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "agent".into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks: vec![SignedBlock {
            block,
            pubkey_next: "x".into(),
            signature: "x".into(),
        }],
        attestation: AttestationBinding::default(),
        created_at: 0,
        updated_at: 0,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

#[test]
fn subtarget_present_in_scope_routes_to_subtarget_match() {
    // Scope `github:push:owner/repo:feat/*` against a request that
    // targets `owner/repo` on branch `feat/foo`. The primary glob
    // `owner/repo` matches the resource AND `feat/*` matches the
    // branch — resolver should return `Match`, not `SubtargetMiss`
    // and not `NoApplicable`.
    let grant = grant_with_subtarget_scope("github:push:owner/repo:feat/*");
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/feat/foo"
        .parse()
        .unwrap();
    let outcome = resolve_statement_for_request_with_uri(&grant, "github:push", "owner/repo", &uri);
    match outcome {
        ResolveOutcome::Match { stmt, .. } => {
            assert_eq!(stmt.sid, "S0");
        }
        other => panic!("expected Match for primary+subtarget hit, got {:?}", other),
    }
}

#[test]
fn subtarget_miss_returns_denied_subtarget_scope_not_no_applicable_statement() {
    // Same scope, but the request branch `main` does NOT satisfy
    // `feat/*`. Pre-fix the resolver returned `NoApplicable` because
    // the flat glob could not match the colon-joined pattern at all;
    // post-fix the resolver routes through the structured
    // `GlobWithSubtarget` and reports `SubtargetMiss` so the deny
    // path can emit `denied_subtarget_scope`.
    let grant = grant_with_subtarget_scope("github:push:owner/repo:feat/*");
    let uri: hyper::Uri = "https://api.github.com/repos/owner/repo/branches/main"
        .parse()
        .unwrap();
    let outcome = resolve_statement_for_request_with_uri(&grant, "github:push", "owner/repo", &uri);
    match outcome {
        ResolveOutcome::SubtargetMiss { subtarget_glob } => {
            assert_eq!(subtarget_glob, "feat/*");
        }
        ResolveOutcome::NoApplicable => panic!(
            "regression: subtarget mismatch fell through to NoApplicable; \
             the audit log would emit denied_no_applicable_statement \
             instead of denied_subtarget_scope"
        ),
        ResolveOutcome::Match { .. } => {
            panic!("subtarget did not match branch — should not be Match");
        }
        ResolveOutcome::UnevaluableCondition { .. } => {
            panic!("unconditioned subtarget statement should not be UnevaluableCondition");
        }
    }
}

// ------------------------------------------------------------------
// Per-Statement resolution tests (ADR 073 / P69K-A2)
// ------------------------------------------------------------------

#[test]
fn resolve_statement_picks_first_applicable() {
    use core_event_types::PresentationAudienceKind;
    use core_grant_types::{
        AccessGrant, AttestationBinding, Block, GrantMode, GrantStatus, RecipientProfile,
        ResourceSelector, ResourceType, SignedBlock, Statement, Usage,
    };
    // V0: Statement actions are fully qualified (`provider:action`).
    // Bare-action tolerance was a back-compat wart and is gone.
    let stmt_read = Statement {
        sid: "S0".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:read".into()],
        resource: ResourceSelector::Glob {
            pattern: "emberdotlink/*".into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let stmt_push = Statement {
        sid: "S1".into(),
        resource_type: ResourceType::Credential,
        actions: vec!["github:push".into()],
        resource: ResourceSelector::Exact {
            value: "emberdotlink/widgets".into(),
        },
        budget: None,
        usage: Usage::default(),
        conditions: Vec::new(),
        can_delegate: None,
    };
    let block = Block {
        statements: vec![stmt_read, stmt_push],
        nbf: None,
        expires_at: None,
        issued_by: "persona-a".into(),
        issued_at: 0,
        approval: None,
        note: None,
    };
    let grant = AccessGrant {
        id: "grant-x".into(),
        version: 1,
        issuing_persona_id: "persona-a".into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: "agent".into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks: vec![SignedBlock {
            block,
            pubkey_next: "x".into(),
            signature: "x".into(),
        }],
        attestation: AttestationBinding::default(),
        created_at: 0,
        updated_at: 0,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    };
    // github:read matches stmt_read via glob.
    let hit = resolve_statement_for_request(&grant, "github:read", "emberdotlink/ember");
    assert!(hit.is_some(), "github:read should match stmt_read");
    assert_eq!(hit.unwrap().1.sid, "S0");
    // github:push on the exact resource matches stmt_push.
    let hit = resolve_statement_for_request(&grant, "github:push", "emberdotlink/widgets");
    assert!(
        hit.is_some(),
        "github:push on widgets should match stmt_push"
    );
    assert_eq!(hit.unwrap().1.sid, "S1");
    // github:push to a different repo matches nothing — read glob is
    // action=read only and push selector is exact.
    let hit = resolve_statement_for_request(&grant, "github:push", "emberdotlink/other");
    assert!(hit.is_none(), "other repo with push must have no match");
}

#[tokio::test]
async fn per_statement_denies_unmatched_action() {
    // A read-scoped grant with a path-style selector. POST under
    // read action produces no applicable statement → deny.
    let state = make_state();
    let persona = state.store.create_persona("per-stmt-1").unwrap();
    state
        .vault
        .add(VaultScope::Interactive, &state.store, "tok", b"s", None)
        .unwrap();
    state
        .store
        .create_grant(&persona.id, "tok", "generic:read:/api/foo", None)
        .unwrap();

    let req = proxy_request_with_method_and_uri(
        "POST",
        "https://example.com/api/foo",
        Some(&persona.id),
        Some("tok"),
        Some("https://example.com"),
    );
    let resp = call(state, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_applicable_statement");
}
