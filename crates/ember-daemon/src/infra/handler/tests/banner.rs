use super::*;
use crate::trust::approval::ApprovalRequestInfo;

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
        // META-AP-DAEMON-APPROVAL-FLOW-DROPS-DELEGATION-FIELDS-FIXED —
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
        // META-AP-DAEMON-APPROVAL-FLOW-DROPS-DELEGATION-FIELDS-FIXED —
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
