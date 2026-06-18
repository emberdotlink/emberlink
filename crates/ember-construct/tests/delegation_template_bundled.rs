//! T2 — each bundled delegation template under `lib/ember/delegation-templates/`
//! parses, validates, and rejects out-of-scope actions.
//!
//! Verifies the templates that ship with the install pipeline (ADR 157
//! §Component 3 copies these to `/usr/local/lib/ember/delegation-templates/`).
//! If a template is added or its scope edited and the assertions below no
//! longer hold, fix the template or this test — both are load-bearing.
//!
//! Anchor: onboarding_delegation_templates_landed.

use core_event_types::ActionRef;
use ember_construct::DelegationTemplate;

const TEMPLATE_DIR: &str = "../../lib/ember/delegation-templates";

fn load(name: &str) -> DelegationTemplate {
    let path = format!("{TEMPLATE_DIR}/{name}.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    DelegationTemplate::parse(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn action_ref(plugin: &str, action: &str) -> ActionRef {
    ActionRef::new(plugin, action, "v1")
}

#[test]
fn emberd_development_template_loads() {
    let t = load("emberd-development");
    assert_eq!(t.name, "emberd-development");
    assert!(
        t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-git",
            "push"
        )),
        "emberd-development must allow git.push"
    );
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_create"
    )));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-cargo",
        "build"
    )));
    assert!(
        !t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-trust",
            "rotate"
        )),
        "emberd-development must exclude trust.*"
    );
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-gh",
        "repo_delete"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-scion",
        "start"
    )));
}

#[test]
fn landing_page_edits_template_loads() {
    let t = load("landing-page-edits");
    assert_eq!(t.name, "landing-page-edits");
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_create"
    )));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-wrangler",
        "deploy"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-kubectl",
        "apply"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-trust",
        "rotate"
    )));
}

#[test]
fn infra_iteration_template_loads() {
    let t = load("infra-iteration");
    assert_eq!(t.name, "infra-iteration");
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-kubectl",
        "apply"
    )));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-pulumi",
        "up"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-pulumi",
        "destroy"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-trust",
        "rotate"
    )));
}

#[test]
fn read_only_template_loads_and_forbids_writes() {
    let t = load("read-only");
    assert_eq!(t.name, "read-only");
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-git",
        "log"
    )));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-kubectl",
        "get"
    )));
    assert!(
        !t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-git",
            "push"
        )),
        "read-only must forbid writes"
    );
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-kubectl",
        "apply"
    )));
}

#[test]
fn autopilot_template_includes_spawn_capability() {
    let t = load("autopilot");
    assert_eq!(t.name, "autopilot");
    let cap = t
        .capability
        .get("spawn_subagent")
        .expect("autopilot must declare spawn_subagent capability");
    assert_eq!(cap.max_depth, Some(3));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-scion",
        "start"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-trust",
        "rotate"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-gh",
        "repo_delete"
    )));
}

#[test]
fn trust_management_template_is_security_first() {
    let t = load("trust-management");
    assert_eq!(t.name, "trust-management");
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-trust",
        "list"
    )));
    assert!(t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-trust",
        "rotate"
    )));
    assert!(
        !t.allows(&action_ref(
            "registry.ember.systems/ember-systems/ember-git",
            "push"
        )),
        "trust-management must exclude everything non-trust"
    );
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-gh",
        "pr_create"
    )));
    assert!(!t.allows(&action_ref(
        "registry.ember.systems/ember-systems/ember-kubectl",
        "apply"
    )));
}

#[test]
fn template_name_matches_filename_stem() {
    for name in [
        "emberd-development",
        "landing-page-edits",
        "infra-iteration",
        "read-only",
        "autopilot",
        "trust-management",
    ] {
        let t = load(name);
        assert_eq!(
            t.name, name,
            "template name field must match its filename stem"
        );
    }
}
