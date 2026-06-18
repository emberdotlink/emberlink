//! Session lifecycle transitions — `terminated_dirty` shape (H1 dirty-exit).
//!
//! H1 invariant (cohort-A test plan): every grant terminates in a signed
//! Receipt across all four termination paths. Coverage post-M3 follow-up
//! (COHORT-A-V03-V2-RECEIPT-COVERAGE-OTHER-LANES, v2_receipt_coverage_audit_v030_2026_05_09):
//!
//! | Path               | Location                                | TerminationReason |
//! |--------------------|----------------------------------------|-------------------|
//! | Dirty-exit         | This module (`transition_to_terminated_dirty_at`) | `HeartbeatLost` |
//! | Clean-exit         | `infra::handler` (`close_session` RPC arm)        | `CleanExit`      |
//! | TTL-expiry         | `session_watcher::close_session`                  | `TtlExpired`     |
//! | Explicit-revoke    | `infra::handler` (`revoke_grant` RPC arm)         | `ExplicitRevoke` |
//!
//! All four paths use `issue_cohort_a_receipt` + `DaemonPersonaSigner` — the
//! canonical atomic builder per ADR 116. H1 is now unambiguously green for
//! all four termination shapes.
//!
//! This module owns the **dirty-exit** transition. The clean-exit path
//! (launcher sends `session.close`) and TTL/revoke paths each emit their
//! own Receipt + grant-revocation; the dirty-exit path here mirrors the
//! same pieces in the same order:
//!
//! 1. **Issue + sign a v2 `session.claude_code` Receipt** with
//!    `termination_reason: heartbeat_lost`, `last_heartbeat_at`, and
//!    `pid_alive_at_check`. Receipt assembly uses
//!    [`crate::infra::receipt::issue::issue_cohort_a_receipt`] — the
//!    canonical builder for cohort-A v2 Receipts. Signing uses
//!    [`core_events::receipt::sign::sign_receipt_v2`] via a
//!    [`DaemonPersonaSigner`] adapter so the v1 `DaemonPersona` key signs
//!    the v2 envelope. **No bespoke hashing or signature logic** —
//!    duplicating the canonical path is the regression vector AUDIT
//!    Decision 4 forbids.
//! 2. **Persist the Receipt** to `<session_dir>/receipt.json` (the
//!    SessionStore sidecar reserved for this exact purpose).
//! 3. **Close the session** via [`SessionStore::close`] (renames
//!    `meta.json` → `meta.json.closed`).
//! 4. **Revoke the broker grant** via [`crate::trust::grant::DaemonGrantStore::revoke_grant`]
//!    — which emits the v1 grant Receipt + cascades to children.
//! 5. **Audit-log a `session.terminated_dirty` event** so dashboards and
//!    operators see the transition in the live event stream.
//!
//! Transactional boundary: SQLite-side mutations (audit-log + grant revoke)
//! are each their own transaction; the filesystem-side mutations
//! (Receipt-write + meta.json rename) are ordered so that even on partial
//! failure the audit trail is intact (Receipt persisted before grant
//! revocation, grant revocation before audit-log noting the dirty-exit).

use std::path::Path;

use chrono::{DateTime, Utc};
use core_crypto::{PublicKey, Signature, Signer};
use core_events::receipt::{ReceiptEnvelope, TerminationAuthority, TerminationReason};
use core_state::sessions::{SessionMeta, SessionStore};
use thiserror::Error;
use tracing::warn;

use crate::infra::claim_journal::{
    close_session_scope_best_effort, close_summary_audit_fields,
    summarize_session_scope_best_effort,
};
use crate::infra::receipt::{
    DaemonPersona, current_identity,
    issue::{TerminationMeta, issue_cohort_a_receipt},
};
use crate::infra::store::{DaemonStore, StoreError};

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("daemon identity not initialised — cannot sign Receipt")]
    IdentityMissing,
    #[error("issue cohort-a Receipt: {0}")]
    Issue(#[from] crate::infra::receipt::issue::IssueError),
    #[error("serialize Receipt JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("persist Receipt to {path}: {source}")]
    Persist {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("close session in SessionStore: {0}")]
    Close(#[source] std::io::Error),
    #[error("revoke grant in DaemonStore: {0}")]
    Revoke(#[source] StoreError),
    #[error("audit-log session.terminated_dirty event: {0}")]
    Audit(#[source] StoreError),
}

/// Adapter — exposes [`DaemonPersona`]'s Ed25519 signing key as a
/// [`core_crypto::Signer`] so `issue_cohort_a_receipt` can sign via
/// `daemon_persona_sign_receipt` per ADR 116.
///
/// The v1 `DaemonPersona` predates the `core_crypto::Signer` trait and
/// owns its own raw `ed25519_dalek::SigningKey`. Rather than rebuild the
/// v1 storage path or duplicate the trait machinery, we adapt at the
/// issue-call boundary. Lifetime-bound to a `&DaemonPersona` borrow — the
/// daemon's persona key lives for the entire process.
pub(crate) struct DaemonPersonaSigner<'a> {
    persona: &'a DaemonPersona,
}

impl<'a> DaemonPersonaSigner<'a> {
    pub(crate) fn new(persona: &'a DaemonPersona) -> Self {
        Self { persona }
    }
}

impl<'a> Signer for DaemonPersonaSigner<'a> {
    fn sign(&self, payload: &[u8]) -> Signature {
        // `DaemonPersona::sign` returns the raw 64-byte signature; the
        // `core_crypto::Signature` wire form is `ed25519sig:<128-hex>`.
        let raw = self.persona.sign(payload);
        Signature(format!("ed25519sig:{}", hex::encode(*raw)))
    }

    fn public_key(&self) -> PublicKey {
        // `DaemonPersona::pubkey_hex` returns the 64-char hex; `core_crypto`
        // expects the `ed25519:<hex>` wire form.
        PublicKey(format!("ed25519:{}", self.persona.pubkey_hex()))
    }
}

// ---------------------------------------------------------------------------
// Path-explicit variant — used by the watcher (which holds the sessions_dir)
// ---------------------------------------------------------------------------

/// Same as [`transition_to_terminated_dirty`] but takes the sessions_dir
/// path explicitly. The heartbeat watcher uses this variant because it
/// already holds the path; the transactional shape is identical.
pub fn transition_to_terminated_dirty_at(
    daemon_store: &DaemonStore,
    session_store: &SessionStore,
    sessions_dir: &Path,
    session: &SessionMeta,
    last_heartbeat_at: DateTime<Utc>,
    pid_alive_at_check: bool,
) -> Result<ReceiptEnvelope, LifecycleError> {
    let identity = current_identity().ok_or(LifecycleError::IdentityMissing)?;
    let signer = DaemonPersonaSigner::new(identity);
    let claim_summary = summarize_session_scope_best_effort(
        daemon_store,
        &session.session_id,
        "transition_to_terminated_dirty_at",
    );

    // 1. Build + sign envelope atomically (ADR 116 — signing inside issue).
    //    Termination metadata is passed via TerminationMeta so the signed
    //    body is complete at issuance time — no post-signing body mutation.
    let envelope = if let Some(summary) = claim_summary.as_ref() {
        crate::infra::receipt::issue::issue_cohort_a_receipt_from_closed_scope(
            &session.session_id,
            summary,
            None,
            TerminationAuthority::DaemonPersona,
            &identity.pubkey_hex(),
            Some(TerminationMeta {
                reason: TerminationReason::HeartbeatLost,
                last_heartbeat_at: Some(last_heartbeat_at.to_rfc3339()),
                pid_alive_at_check: Some(pid_alive_at_check),
            }),
            &signer,
        )
    } else {
        issue_cohort_a_receipt(
            &session.session_id,
            Vec::new(),
            None,
            TerminationAuthority::DaemonPersona,
            &identity.pubkey_hex(),
            Some(TerminationMeta {
                reason: TerminationReason::HeartbeatLost,
                last_heartbeat_at: Some(last_heartbeat_at.to_rfc3339()),
                pid_alive_at_check: Some(pid_alive_at_check),
            }),
            &signer,
        )
    }?;

    // 2. Persist Receipt sidecar.
    let session_dir = sessions_dir.join(&session.session_id);
    let receipt_path = session_dir.join("receipt.json");
    let receipt_json = serde_json::to_vec_pretty(&envelope)?;
    std::fs::write(&receipt_path, &receipt_json).map_err(|e| LifecycleError::Persist {
        path: receipt_path.display().to_string(),
        source: e,
    })?;

    // 3. Close session.
    session_store
        .close(&session.session_id)
        .map_err(LifecycleError::Close)?;
    let _ = crate::infra::interactive_unlock::release_session_pin(&session.session_id);
    let claim_summary = close_session_scope_best_effort(
        daemon_store,
        &session.session_id,
        "transition_to_terminated_dirty_at",
    )
    .or(claim_summary);
    let remaining_attachments = session_store
        .count_other_open_attachments(session)
        .map_err(LifecycleError::Close)?;
    let terminate_runtime = session.is_runtime_attachment() && remaining_attachments == 0;
    let runtime_kept_alive = session.is_runtime_attachment() && remaining_attachments > 0;

    // 4. Revoke broker grant — reuses clean-exit path, which emits the v1
    //    grant Receipt + cascades to children.
    if terminate_runtime {
        if let Err(e) = daemon_store.revoke_persona(&session.persona) {
            match e {
                StoreError::NotFound => {
                    warn!(
                        session_id = %session.session_id,
                        runtime_persona_id = %session.persona,
                        "lifecycle: runtime persona absent at dirty-exit revoke — likely already terminal"
                    );
                }
                other => return Err(LifecycleError::Revoke(other)),
            }
        }
    } else if !session.is_runtime_attachment()
        && let Err(e) = daemon_store.revoke_grant(&session.grant_id)
    {
        match e {
            StoreError::NotFound => {
                warn!(
                    session_id = %session.session_id,
                    grant_id = %session.grant_id,
                    "lifecycle: grant absent at dirty-exit revoke — likely already terminal"
                );
            }
            other => return Err(LifecycleError::Revoke(other)),
        }
    }

    // 5. Audit-log the dirty-exit event.
    let mut details = format!(
        "session_id={} grant_id={} last_heartbeat_at={} pid_alive_at_check={} remaining_attachments={} runtime_terminated={} runtime_kept_alive={}",
        session.session_id,
        session.grant_id,
        last_heartbeat_at.to_rfc3339(),
        pid_alive_at_check,
        remaining_attachments,
        terminate_runtime,
        runtime_kept_alive
    );
    if let Some(summary) = claim_summary.as_ref() {
        details.push(' ');
        details.push_str(&close_summary_audit_fields(summary));
    }
    daemon_store
        .log_event(
            None,
            "session.terminated_dirty",
            None,
            "heartbeat_lost",
            Some(&details),
        )
        .map_err(LifecycleError::Audit)?;

    Ok(envelope)
}
