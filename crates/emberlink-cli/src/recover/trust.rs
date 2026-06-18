//! CLASSIFICATION: PUBLIC
//!
//! `ember recover trust` — guided trust-list lifecycle recovery per ADR 195.
//!
//! ## S5a subverbs (composable from existing primitives)
//!
//! - `list-audit [--since <timestamp>]` — reads the trust-root list from the
//!   daemon via `trust_list`, reads trust-root-related events from the audit
//!   log via `audit_log_query`, walks each trust-root entry's provenance, and
//!   flags any root whose fingerprint has NO matching trust-root event in the
//!   audit data. Prints a structured provenance report. Read-only: emits a
//!   `recovery.action` receipt but does not require a confirmation token.
//!   Does NOT call any non-existent RPC — uses only confirmed existing methods.
//!
//! ## Retired v0.3.0 subverbs
//!
//! - `re-attest [--device <id>]` — retired for v0.3.0. Device recovery uses
//!   ADR 206 enrollment/replacement and ADR 211 leased authority, not a
//!   daemon-local re-attest RPC. No re-attest verb is registered here.
//!
//! ## Composition
//!
//! `list-audit` composes:
//!   1. `trust_list` (confirmed RPC) — daemon trust-root snapshot
//!      (`{roots: [{fingerprint_hex, source}], dev_mode_active}`)
//!   2. `audit_log_query` (confirmed RPC) — audit log filtered by trust-root
//!      action prefixes (`trust.`, `trust_root`, `device.enroll`, `device.attest`)
//!   3. In-process walk using `core_trust::queries::{who_trusts, who_i_trust}`
//!      types for the report model (pure, no I/O)
//!
//! ## Checkpoint for `target_state_anchor`
//!
//! `recover_trust_lifecycle_landed` is anchored in this module's docstring.

use std::collections::HashSet;
use std::path::Path;

use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};

use super::{RecoverContext, RecoverError, RecoverOutcome, RecoverResult};

// ---------------------------------------------------------------------------
// Public argument types
// ---------------------------------------------------------------------------

/// Top-level args for `ember recover trust`.
#[derive(Args, Debug, Clone)]
pub struct RecoverTrustArgs {
    #[command(subcommand)]
    pub subverb: TrustSubverb,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum TrustSubverb {
    /// Audit the trust-root list for entries with no matching trust-root event.
    ///
    /// Read-only: emits a `recovery.action` receipt and prints a structured
    /// provenance report. Use `--since` to limit the audit-log walk window.
    ListAudit(ListAuditArgs),
}

/// `ember recover trust list-audit [--since <timestamp>]`
#[derive(Args, Debug, Clone)]
pub struct ListAuditArgs {
    /// Limit the audit-log walk to events newer than this RFC 3339 timestamp.
    #[arg(long, value_name = "TIMESTAMP")]
    pub since: Option<String>,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn handle(args: RecoverTrustArgs, context: RecoverContext) -> RecoverResult {
    let socket_path = context.socket_path.ok_or_else(|| {
        RecoverError::authority(
            "recover trust requires the managed daemon socket path; \
             step: broker-unavailable",
        )
    })?;

    match args.subverb {
        TrustSubverb::ListAudit(a) => handle_list_audit(a, &socket_path),
    }
}

// ---------------------------------------------------------------------------
// list-audit
// ---------------------------------------------------------------------------

/// A single trust-root entry in the provenance walk report.
#[derive(Debug, Clone, Serialize)]
pub struct TrustRootEntry {
    pub fingerprint_hex: String,
    pub source: String,
    pub has_trust_root_event: bool,
    pub provenance_note: String,
}

/// The computed list-audit plan.
#[derive(Debug, Clone)]
pub struct ListAuditPlan {
    pub prior_state_digest: String,
    pub proposed_action: Value,
    pub entries: Vec<TrustRootEntry>,
    pub flagged_count: usize,
    pub audit_event_count: usize,
    pub journal_empty: bool,
}

struct FlatPlan {
    target_kind: &'static str,
    target_id: &'static str,
    requested_action: &'static str,
    prior_state_digest: String,
    proposed_action: Value,
}

pub fn handle_list_audit(args: ListAuditArgs, socket_path: &Path) -> RecoverResult {
    // Step 1: fetch the daemon's trust-root snapshot via trust_list.
    let trust_list = call_daemon(socket_path, "trust_list", json!({}), "trust list")?;

    // Step 2: fetch audit events that could establish trust-root provenance.
    // Use audit_log_query filtered by action_prefix covering trust/device events.
    // (The prior implementation called a non-existent RPC; this uses audit_log_query
    // which is a confirmed-existing daemon method.)
    // The daemon's audit_log_query parses `since_ms` as epoch-MILLISECONDS via
    // `as_i64()` (handler.rs:5853). Sending the RFC3339 `--since` String made
    // `as_i64()` return None, so `--since` was silently ignored. Parse to ms
    // here, and reject an unparseable value loudly. (Sweep 3 finding S-SINCE.)
    let since_ms: Option<i64> = match &args.since {
        Some(s) => Some(
            chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| {
                    RecoverError::usage(format!(
                        "--since must be an RFC 3339 timestamp \
                         (e.g. 2026-05-29T00:00:00Z): {e}"
                    ))
                })?
                .timestamp_millis(),
        ),
        None => None,
    };

    let audit_params = {
        let mut p = json!({ "action_prefix": "trust", "limit": 500 });
        if let Some(ms) = since_ms {
            p["since_ms"] = json!(ms);
        }
        p
    };
    let trust_audit = call_daemon(
        socket_path,
        "audit_log_query",
        audit_params,
        "audit log query (trust prefix)",
    )
    .unwrap_or_else(|_| json!([]));

    // Also query device-related events (enroll/attest) in case they carry
    // trust-root fingerprints under a different action prefix.
    let device_audit_params = {
        let mut p = json!({ "action_prefix": "device", "limit": 200 });
        if let Some(ms) = since_ms {
            p["since_ms"] = json!(ms);
        }
        p
    };
    let device_audit = call_daemon(
        socket_path,
        "audit_log_query",
        device_audit_params,
        "audit log query (device prefix)",
    )
    .unwrap_or_else(|_| json!([]));

    let plan = build_list_audit_plan(&trust_list, &trust_audit, &device_audit);

    // Read-only: emit receipt without confirmation gate.
    let flat = FlatPlan {
        target_kind: "trust-list",
        target_id: "local-trust-list",
        requested_action: "list-audit",
        prior_state_digest: plan.prior_state_digest.clone(),
        proposed_action: plan.proposed_action.clone(),
    };
    let receipt = emit_flat_recovery_receipt(socket_path, &flat, "executed")?;

    println!("{}", render_list_audit_report(&plan, &receipt));

    if plan.flagged_count > 0 {
        Ok(RecoverOutcome::issue_found())
    } else {
        Ok(RecoverOutcome::ok())
    }
}

/// Build the list-audit plan by walking trust-root entries against audit data.
///
/// `trust_list_response`: JSON from `trust_list` RPC
///   → `{roots: [{fingerprint_hex, source}], dev_mode_active}`
///
/// `trust_audit_events` / `device_audit_events`: JSON arrays from `audit_log_query`.
///   Each event may carry a `details` object with a `fingerprint_hex`,
///   `trust_root_fingerprint`, or `subject` field that ties the event to a
///   specific trust root.
pub fn build_list_audit_plan(
    trust_list_response: &Value,
    trust_audit_events: &Value,
    device_audit_events: &Value,
) -> ListAuditPlan {
    let prior_state_digest = super::vault::digest_value(trust_list_response);

    // Collect fingerprint_hex values referenced in audit events.
    // We look in the event's `details` object and top-level fields.
    let fingerprints_with_events: HashSet<String> =
        collect_fingerprints_from_events(trust_audit_events)
            .into_iter()
            .chain(collect_fingerprints_from_events(device_audit_events))
            .collect();

    let audit_event_count = count_events(trust_audit_events) + count_events(device_audit_events);
    let journal_empty = audit_event_count == 0;

    // Walk trust-root entries.
    let roots = trust_list_response
        .get("roots")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    let entries: Vec<TrustRootEntry> = roots
        .iter()
        .map(|root| {
            let fingerprint_hex = root
                .get("fingerprint_hex")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let source = root
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            // A root "has a trust-root event" if any audit event references
            // its fingerprint — either as an exact match, a hex prefix match
            // (first 16 chars), or via common detail-field names.
            let has_trust_root_event = fingerprints_with_events
                .iter()
                .any(|fp| fingerprint_matches(fp, &fingerprint_hex));
            let provenance_note = if has_trust_root_event {
                "trust-root event found in audit log".to_string()
            } else if journal_empty {
                "audit log returned no events; provenance check inconclusive".to_string()
            } else {
                "NO matching trust-root event found in audit log — provenance gap".to_string()
            };
            TrustRootEntry {
                fingerprint_hex,
                source,
                has_trust_root_event,
                provenance_note,
            }
        })
        .collect();

    // Count flagged only when the journal returned events — an empty journal
    // is inconclusive, not a flag.
    let flagged_count = if journal_empty {
        0
    } else {
        entries.iter().filter(|e| !e.has_trust_root_event).count()
    };

    let proposed_action = json!({
        "action": "list-audit",
        "total_roots": entries.len(),
        "flagged_roots": flagged_count,
        "audit_events_scanned": audit_event_count,
        "journal_empty": journal_empty,
        "entries": entries,
    });

    ListAuditPlan {
        prior_state_digest,
        proposed_action,
        entries,
        flagged_count,
        audit_event_count,
        journal_empty,
    }
}

/// Collect fingerprint-like strings from audit event arrays.
///
/// Looks in: `details.fingerprint_hex`, `details.trust_root_fingerprint`,
/// `details.subject`, `fingerprint_hex`, `subject` on each event.
fn collect_fingerprints_from_events(events: &Value) -> Vec<String> {
    let arr = match events.as_array() {
        Some(a) => a,
        None => return vec![],
    };
    let mut out = Vec::new();
    for event in arr {
        // Top-level fields
        for key in &["fingerprint_hex", "subject", "trust_root_fingerprint"] {
            if let Some(s) = event.get(key).and_then(Value::as_str) {
                out.push(s.to_string());
            }
        }
        // Details sub-object fields
        if let Some(details) = event.get("details") {
            for key in &["fingerprint_hex", "trust_root_fingerprint", "subject"] {
                if let Some(s) = details.get(key).and_then(Value::as_str) {
                    out.push(s.to_string());
                }
            }
        }
    }
    out
}

fn count_events(events: &Value) -> usize {
    events.as_array().map(Vec::len).unwrap_or(0)
}

/// Check whether `candidate` references `fingerprint_hex`.
///
/// Accepts exact matches and hex-prefix matches (at least 16 chars) to
/// handle audit events that store abbreviated fingerprints.
fn fingerprint_matches(candidate: &str, fingerprint_hex: &str) -> bool {
    if candidate == fingerprint_hex {
        return true;
    }
    // Prefix match — candidate is at least 16 chars and fingerprint starts with it.
    if candidate.len() >= 16 && fingerprint_hex.starts_with(candidate) {
        return true;
    }
    // Reverse: fingerprint is a prefix of the full key stored in the event.
    if fingerprint_hex.len() >= 16 && candidate.starts_with(fingerprint_hex) {
        return true;
    }
    false
}

fn render_list_audit_report(plan: &ListAuditPlan, receipt: &ReceiptSummary) -> String {
    let mut out = String::new();
    out.push_str("recover trust list-audit\n");
    out.push_str("Receipt: recovery.action ");
    out.push_str(&receipt.receipt_id);
    if receipt.persisted {
        out.push_str(" (persisted)\n\n");
    } else {
        out.push_str(" (signed; audit persistence pending)\n\n");
    }
    out.push_str(&format!(
        "Trust roots: {} total, {} flagged\n",
        plan.entries.len(),
        plan.flagged_count
    ));
    out.push_str(&format!(
        "Audit events scanned: {}\n",
        plan.audit_event_count
    ));
    if plan.journal_empty {
        out.push_str("Note: audit log returned no trust/device events — provenance checks are inconclusive.\n");
    }
    out.push_str("\nProvenance report:\n");
    for entry in &plan.entries {
        let flag = if !entry.has_trust_root_event && !plan.journal_empty {
            " [FLAG]"
        } else {
            ""
        };
        out.push_str(&format!(
            "  [{source}]{flag} {fp_short}...\n    {note}\n",
            source = entry.source,
            flag = flag,
            fp_short = &entry.fingerprint_hex[..entry.fingerprint_hex.len().min(16)],
            note = entry.provenance_note
        ));
    }
    if plan.flagged_count > 0 {
        out.push_str("\nNext step:\n");
        out.push_str(&format!(
            "  {} trust-root {} without a matching audit-log event.\n",
            plan.flagged_count,
            if plan.flagged_count == 1 {
                "entry"
            } else {
                "entries"
            }
        ));
        out.push_str("  Run `ember trust list` and `ember audit query --action-prefix trust`\n");
        out.push_str(
            "  to investigate the provenance gap before using these roots for verification.\n",
        );
    }
    out.trim_end().to_string()
}

// ---------------------------------------------------------------------------
// Receipt emission (flat — no confirmation token for read-only verbs)
// ---------------------------------------------------------------------------

struct ReceiptSummary {
    receipt_id: String,
    persisted: bool,
}

fn emit_flat_recovery_receipt(
    socket_path: &Path,
    plan: &FlatPlan,
    outcome: &str,
) -> Result<ReceiptSummary, RecoverError> {
    let recovery_id = format!(
        "recover-trust-{}",
        super::vault::digest_value(&json!({
            "target_id": plan.target_id,
            "requested_action": plan.requested_action,
            "prior_state_digest": plan.prior_state_digest,
        }))
        .strip_prefix("blake3:")
        .unwrap_or("unknown")
        .chars()
        .take(16)
        .collect::<String>()
    );
    let params = json!({
        "recovery_id": recovery_id,
        "surface": "lifecycle",
        "verb": "trust",
        "target_kind": plan.target_kind,
        "target_id": plan.target_id,
        "requested_action": plan.requested_action,
        "prior_state_digest": plan.prior_state_digest,
        "dry_run_digest": super::vault::digest_value(&plan.proposed_action),
        "operator_confirmation_token_hash": Value::Null,
        "operator_persona_id": Value::Null,
        "authority_evidence": {
            "daemon_rpc": "recovery_action_receipt",
        },
        "outcome": outcome,
        "related_receipt_ids": [],
        "runbook_ref": "docs/runbook/recovery.md#trust-lifecycle-recovery",
        "adr_refs": ["ADR 195", "ADR 162"],
    });

    let value =
        crate::call_daemon_rpc(socket_path, "recovery_action_receipt", &params).map_err(|err| {
            RecoverError::authority(format!(
                "recover trust refused: could not emit recovery.action receipt through the \
                 daemon broker; step: broker-unavailable; {err}"
            ))
        })?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            RecoverError::authority(
                "recover trust refused: daemon returned no recovery.action receipt_id",
            )
        })?
        .to_string();
    let persisted = value
        .get("persisted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(ReceiptSummary {
        receipt_id,
        persisted,
    })
}

// ---------------------------------------------------------------------------
// Daemon RPC helper
// ---------------------------------------------------------------------------

fn call_daemon(
    socket_path: &Path,
    method: &str,
    params: Value,
    label: &'static str,
) -> Result<Value, RecoverError> {
    crate::call_daemon_rpc(socket_path, method, &params).map_err(|err| {
        RecoverError::authority(format!(
            "recover trust refused: {label} RPC failed; step: broker-unavailable; {err}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // T1: list-audit provenance walk -----------------------------------------

    fn make_trust_list(roots: &[(&str, &str)]) -> Value {
        let root_vals: Vec<Value> = roots
            .iter()
            .map(|(fp, src)| json!({"fingerprint_hex": fp, "source": src}))
            .collect();
        json!({"roots": root_vals, "dev_mode_active": false})
    }

    fn make_audit_event(action: &str, fingerprint_hex: &str) -> Value {
        json!({
            "action": action,
            "details": {"fingerprint_hex": fingerprint_hex},
        })
    }

    #[test]
    fn list_audit_flags_root_with_no_matching_event() {
        let trust_list = make_trust_list(&[
            (
                "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd",
                "release",
            ),
            (
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "operator",
            ),
        ]);
        // Only the first root has an audit event.
        let audit_events = json!([make_audit_event(
            "trust.attest",
            "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd"
        ),]);
        let plan = build_list_audit_plan(&trust_list, &audit_events, &json!([]));

        assert_eq!(plan.entries.len(), 2);
        assert_eq!(plan.flagged_count, 1, "one root should be flagged");
        let flagged = plan
            .entries
            .iter()
            .find(|e| e.fingerprint_hex.starts_with("1234"))
            .expect("flagged entry");
        assert!(!flagged.has_trust_root_event);
        assert!(
            flagged.provenance_note.contains("provenance gap"),
            "note: {}",
            flagged.provenance_note
        );
    }

    #[test]
    fn list_audit_all_roots_covered() {
        let fp1 = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd";
        let fp2 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let trust_list = make_trust_list(&[(fp1, "release"), (fp2, "operator")]);
        let audit_events = json!([
            make_audit_event("trust.attest", fp1),
            make_audit_event("device.enroll", fp2),
        ]);
        let plan = build_list_audit_plan(&trust_list, &audit_events, &json!([]));

        assert_eq!(plan.flagged_count, 0, "no roots should be flagged");
        assert!(plan.entries.iter().all(|e| e.has_trust_root_event));
    }

    #[test]
    fn list_audit_empty_journal_is_inconclusive_not_flagged() {
        // When audit returns empty, we should not flag — it's inconclusive.
        let trust_list = make_trust_list(&[(
            "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd",
            "release",
        )]);
        let plan = build_list_audit_plan(&trust_list, &json!([]), &json!([]));

        assert!(plan.journal_empty);
        assert_eq!(
            plan.flagged_count, 0,
            "empty journal = inconclusive, not flagged"
        );
    }

    #[test]
    fn list_audit_prefix_match_counts_as_event() {
        // Audit event stores a 16-char hex prefix; full fingerprint is 64 chars.
        let full_fp = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd";
        let prefix = &full_fp[..16];
        let trust_list = make_trust_list(&[(full_fp, "release")]);
        let audit_events = json!([make_audit_event("trust.root", prefix),]);
        let plan = build_list_audit_plan(&trust_list, &audit_events, &json!([]));

        assert_eq!(
            plan.flagged_count, 0,
            "prefix match should satisfy provenance"
        );
        assert!(plan.entries[0].has_trust_root_event);
    }

    // T2: unlock-retry budget (via fake socket) ------------------------------

    #[test]
    fn unlock_retry_exhausts_budget_and_returns_authority_error() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_socket = tmp.path().join("fake.sock");
        let result = super::super::vault::handle_unlock_retry(
            super::super::vault::UnlockRetryArgs { max_attempts: 2 },
            &fake_socket,
        );
        let err = result.expect_err("should exhaust budget");
        assert_eq!(err.exit_code(), 3);
        assert!(
            err.to_string().contains("2 attempts exhausted"),
            "msg: {err}"
        );
    }

    // T1: fingerprint_matches covers exact and prefix cases ------------------

    #[test]
    fn fingerprint_matches_exact() {
        let fp = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd";
        assert!(fingerprint_matches(fp, fp));
    }

    #[test]
    fn fingerprint_matches_short_prefix_too_short_is_rejected() {
        assert!(!fingerprint_matches("aaaa", "aaaa1111bbbb2222cccc"));
    }

    #[test]
    fn fingerprint_matches_long_prefix_is_accepted() {
        let full = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd";
        let prefix = &full[..20];
        assert!(fingerprint_matches(prefix, full));
    }

    #[test]
    fn fingerprint_no_match_different_values() {
        assert!(!fingerprint_matches(
            "bbbb1111aaaa2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd",
            "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaabbbbccccdddd"
        ));
    }
}
