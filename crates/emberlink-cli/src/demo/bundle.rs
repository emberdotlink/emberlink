//! `ember demo bundle` — mint the locked May-3 4-statement composite-grant
//! bundle (implementation-note-111).
//!
//! Submits ONE composite-approval entry with the four locked statements:
//!   - [0] credential:read   on `anthropic-key`
//!   - [1] llm:generate      on `anthropic/*` (1M tokens, 5 cents)
//!   - [2] time:wall_clock   on *             (90s)
//!   - [3] credential:read   on `github-token`
//!
//! implementation-note-94: tokens cap is sized as defense-in-depth (1M
//! is well above any 90-second realistic session). The cents cap (5¢) is the
//! load-bearing enforcement axis — the voiceover names it. Pre-flight token
//! estimation in `pricing::estimate_call_tokens` was previously tripping on
//! call 3 with a 10K-token cap, masking whether cents enforcement actually
//! worked.
//!
//! The CLI talks to the daemon's SQLite store in-process — no socket round
//! trip — mirroring the existing `ember sandbox run` composite-mint path
//! at `bin/ember.rs:3853` (`store.propose_grant(...)`).

use core_types::{Budget, ResourceSelector, ResourceType, Statement, Usage};
use ember_daemon::infra::config::DaemonConfig;
use ember_daemon::infra::store::DaemonStore;

/// Mint the locked 4-statement composite-grant bundle for the May-3 demo.
///
/// Resolves the first active persona from the store, submits a single
/// `propose_grant` entry that bundles all four statements, and
/// prints the operator-facing approval-id summary.
pub fn cmd_demo_bundle(config: &DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    config
        .ensure_dirs()
        .map_err(|e| format!("failed to create directories: {e}"))?;

    let db_path = config.data_dir.join("daemon.db");
    let store = DaemonStore::open(&db_path)
        .map_err(|e| format!("failed to open daemon store at {}: {e}", db_path.display()))?;

    // Resolve the first active persona. The demo flow seeds exactly one
    // persona via `qember.sh demo up`; if none is found the demo
    // environment was not bootstrapped.
    let personas = store
        .list_personas()
        .map_err(|e| format!("failed to list personas: {e}"))?;
    let persona = personas
        .iter()
        .find(|p| p.status == "active")
        .ok_or_else(|| {
            "no active persona found — run `qember.sh demo up` to bootstrap the demo environment"
                .to_string()
        })?;

    let statements = locked_bundle_statements();

    let req = store
        .propose_grant(
            &persona.id,
            "anthropic-key",
            "composite",
            Some(75),
            "credential.access",
            "medium",
            statements,
        )
        .map_err(|e| format!("propose_grant failed: {e}"))?;

    println!("Grant requested. Awaiting your decision.");
    println!();
    println!("  Approval ID: {}", req.id);
    println!();
    println!("  Statements (one bundle, one biometric, one decision):");
    println!("    s0  credential:read  anthropic-key");
    println!("    s1  llm:generate     anthropic/*       (1M tokens, 5¢)");
    println!("    s2  time:wall_clock  *                 (75 seconds)");
    println!("    s3  credential:read  github-token");
    println!();
    println!("Approve at http://localhost:3141 with Touch ID,");
    println!("or run 'ember approval approve {}' from this terminal.", req.id);

    Ok(())
}

/// The four locked statements of the May-3 composite-grant demo bundle.
/// Pulled out as a separate function so future smoke tests can assert
/// shape without re-running the full submit path.
fn locked_bundle_statements() -> Vec<Statement> {
    vec![
        Statement {
            sid: "s0-anthropic".to_string(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: "anthropic-key".to_string(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        },
        Statement {
            sid: "s1-session".to_string(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".to_string(),
            },
            budget: Some(Budget {
                tokens: Some(1_000_000),
                cents: Some(5),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
        },
        Statement {
            sid: "s2-time".to_string(),
            resource_type: ResourceType::Time,
            actions: vec!["time:wall_clock".to_string()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(75),
                ..Budget::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
        },
        Statement {
            sid: "s3-github".to_string(),
            resource_type: ResourceType::Credential,
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: "github-token".to_string(),
            },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_bundle_has_four_statements_with_expected_shape() {
        let stmts = locked_bundle_statements();
        assert_eq!(stmts.len(), 4, "bundle must have exactly 4 statements");

        // [0] credential:read on anthropic-key
        assert_eq!(stmts[0].sid, "s0-anthropic");
        assert_eq!(stmts[0].resource_type, ResourceType::Credential);
        assert_eq!(stmts[0].actions, vec!["credential:read".to_string()]);
        assert!(matches!(
            &stmts[0].resource,
            ResourceSelector::Exact { value } if value == "anthropic-key"
        ));
        assert!(stmts[0].budget.is_none());

        // [1] llm:generate on anthropic/* (10000 tokens, 5 cents)
        assert_eq!(stmts[1].sid, "s1-session");
        assert_eq!(stmts[1].resource_type, ResourceType::Session);
        assert_eq!(stmts[1].actions, vec!["llm:generate".to_string()]);
        assert!(matches!(
            &stmts[1].resource,
            ResourceSelector::Glob { pattern } if pattern == "anthropic/*"
        ));
        let budget1 = stmts[1].budget.as_ref().expect("session budget");
        assert_eq!(budget1.tokens, Some(1_000_000));
        assert_eq!(budget1.cents, Some(5));

        // [2] time:wall_clock on * (75s — locked 2026-05-04 after live-take
        // tuning. Timer starts on grant-approval (not first-redemption).
        // 45s expired before Beat 7, 90s left dead air, 80s closer, 75s lands.)
        assert_eq!(stmts[2].sid, "s2-time");
        assert_eq!(stmts[2].resource_type, ResourceType::Time);
        assert_eq!(stmts[2].actions, vec!["time:wall_clock".to_string()]);
        assert!(matches!(&stmts[2].resource, ResourceSelector::Any));
        let budget2 = stmts[2].budget.as_ref().expect("time budget");
        assert_eq!(budget2.wall_clock_secs, Some(75));

        // [3] credential:read on github-token
        assert_eq!(stmts[3].sid, "s3-github");
        assert_eq!(stmts[3].resource_type, ResourceType::Credential);
        assert_eq!(stmts[3].actions, vec!["credential:read".to_string()]);
        assert!(matches!(
            &stmts[3].resource,
            ResourceSelector::Exact { value } if value == "github-token"
        ));
        assert!(stmts[3].budget.is_none());
    }
}
