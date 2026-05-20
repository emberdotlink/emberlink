//! T2 — each bundled workflow template under `lib/ember/workflow-templates/`
//! parses, validates, and rejects out-of-scope actions.
//!
//! Verifies the templates that ship with the install pipeline (design
//! §Component 3 copies these to `/usr/local/lib/ember/workflow-templates/`).
//! If a template is added or its scope edited and the assertions below no
//! longer hold, fix the template or this test — both are load-bearing.
//!
//! Anchor: onboarding_workflow_templates_landed.

use ember_construct::WorkflowTemplate;

const TEMPLATE_DIR: &str = "../../lib/ember/workflow-templates";

fn load(name: &str) -> WorkflowTemplate {
    let path = format!("{TEMPLATE_DIR}/{name}.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    WorkflowTemplate::parse(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

#[test]
fn emberd_development_template_loads() {
    let t = load("emberd-development");
    assert_eq!(t.name, "emberd-development");
    assert!(
        t.allows("git.push"),
        "emberd-development must allow git.push"
    );
    assert!(t.allows("gh.pr_create"));
    assert!(t.allows("cargo.build"));
    assert!(
        !t.allows("trust.rotate"),
        "emberd-development must exclude trust.*"
    );
    assert!(!t.allows("gh.repo_delete"));
    assert!(!t.allows("ember-scion.start"));
}

#[test]
fn landing_page_edits_template_loads() {
    let t = load("landing-page-edits");
    assert_eq!(t.name, "landing-page-edits");
    assert!(t.allows("gh.pr_create"));
    assert!(t.allows("wrangler.deploy"));
    assert!(!t.allows("kubectl.apply"));
    assert!(!t.allows("trust.rotate"));
}

#[test]
fn infra_iteration_template_loads() {
    let t = load("infra-iteration");
    assert_eq!(t.name, "infra-iteration");
    assert!(t.allows("kubectl.apply"));
    assert!(t.allows("pulumi.up"));
    assert!(!t.allows("pulumi.destroy"));
    assert!(!t.allows("trust.rotate"));
}

#[test]
fn read_only_template_loads_and_forbids_writes() {
    let t = load("read-only");
    assert_eq!(t.name, "read-only");
    assert!(t.allows("git.log"));
    assert!(t.allows("kubectl.get"));
    assert!(!t.allows("git.push"), "read-only must forbid writes");
    assert!(!t.allows("kubectl.apply"));
}

#[test]
fn checkpoint_template_includes_spawn_capability() {
    let t = load("headless");
    assert_eq!(t.name, "headless");
    let cap = t
        .capability
        .get("spawn_subagent")
        .expect("headless must declare spawn_subagent capability");
    assert_eq!(cap.max_depth, Some(3));
    assert!(t.allows("ember-scion.start"));
    assert!(!t.allows("trust.rotate"));
    assert!(!t.allows("gh.repo_delete"));
}

#[test]
fn trust_management_template_is_security_first() {
    let t = load("trust-management");
    assert_eq!(t.name, "trust-management");
    assert!(t.allows("trust.list"));
    assert!(t.allows("trust.rotate"));
    assert!(
        !t.allows("git.push"),
        "trust-management must exclude everything non-trust"
    );
    assert!(!t.allows("gh.pr_create"));
    assert!(!t.allows("kubectl.apply"));
}

#[test]
fn template_name_matches_filename_stem() {
    for name in [
        "emberd-development",
        "landing-page-edits",
        "infra-iteration",
        "read-only",
        "headless",
        "trust-management",
    ] {
        let t = load(name);
        assert_eq!(
            t.name, name,
            "template name field must match its filename stem"
        );
    }
}
