//! Atomic Receipt v2 kinds. ADR 118 §"Body shape per kind".
//!
//! Each constant is the locked `kind` discriminator placed on
//! `ReceiptEnvelope.kind`. Body structs round-trip cleanly through serde_json
//! and slot into `ReceiptEnvelope.body`.

use core_grant_types::grant_chain::{
    Action, Budget, Condition, ResourceSelector, ResourceType, Statement, StatementId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ===== Kind discriminator constants (locked, must NOT change) =====

pub const RECEIPT_KIND_BROKER_MINT: &str = "broker.mint";
pub const RECEIPT_KIND_KMS_ENCRYPT: &str = "kms.encrypt";
pub const RECEIPT_KIND_KMS_DECRYPT: &str = "kms.decrypt";
pub const RECEIPT_KIND_SERVICE_INSTALLED_V1: &str = "service.installed.v1";
pub const RECEIPT_KIND_SERVICE_UNINSTALLED_V1: &str = "service.uninstalled.v1";
pub const RECEIPT_KIND_BINDING_REGISTERED: &str = "binding.registered";
pub const RECEIPT_KIND_BINDING_UPDATED: &str = "binding.updated";
pub const RECEIPT_KIND_BINDING_REVOKED: &str = "binding.revoked";
pub const RECEIPT_KIND_BINDING_DELETED: &str = "binding.deleted";
/// ADR 118 Extension 4 / ADR 173 Component 7 — emitted after a successful
/// bridge client-cert refresh and persona-row cert-pin replacement.
pub const RECEIPT_KIND_BRIDGE_CERT_REFRESHED: &str = "bridge.cert_refreshed";
/// ADR 118 Extension 5 / ADR 173 Component 7 — emitted for terminal
/// refresh_cert failures. Rate-limited calls do not emit this Receipt.
pub const RECEIPT_KIND_BRIDGE_CERT_REFRESH_FAILED: &str = "bridge.cert_refresh_failed";
/// ADR 118 Extension 6 / ADR 173 M4 — emitted immediately after a successful
/// `refresh_cert` RPC commits the new persona-row cert pin. Marks the
/// previous cert fingerprint as superseded so audit can correlate
/// refresh → old-cert-deprecated. Lossy-acceptable; event-log/audit trail
/// only (paired with the signed `bridge.cert_refreshed` receipt — this kind
/// records the deprecation half of the lifecycle pair).
///
/// Anchor: `daemon_bridge_cert_superseded_event_emitted`.
pub const RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED: &str = "bridge.cert_superseded";
pub const RECEIPT_KIND_RECOVERY_ACTION: &str = "recovery.action";
pub const RECEIPT_KIND_SEAL_UNSEALED: &str = "seal.unsealed";
pub const RECEIPT_KIND_SNAPSHOT_EMITTED: &str = "snapshot.emitted";
pub const RECEIPT_KIND_IDENTITY_ROTATED: &str = "identity.rotated";
pub const RECEIPT_KIND_PAYMENT_EVALUATED: &str = "payment.evaluated";
pub const RECEIPT_KIND_PAYMENT_SETTLED: &str = "payment.settled";
/// Signed per-upstream-call receipt for the `proxy_call` observability event.
/// The forwarding runtime must use the resulting canonical `receipt_id` rather
/// than deriving a demo-grade hash at the event site.
pub const RECEIPT_KIND_PROXY_CALL: &str = "proxy.call";
pub const RECEIPT_KIND_HEADLESS_ENROLLMENT: &str = "headless_enrollment";
pub const RECEIPT_KIND_HEADLESS_REVOCATION: &str = "headless_revocation";
/// Co-signed attestation that bridges between identity-key epochs at
/// MEK rotation time. Per ADR 118 Receipt v2 chain-continuity rule +
/// ADR 133 catalog discipline. Anchor:
/// `identity_rotation_witness_body_landed`.
pub const RECEIPT_KIND_IDENTITY_ROTATION_WITNESS: &str = "identity.rotation_witness";
/// ADR 198 D7 — emitted by the daemon `vault_rotate_execute` primitive
/// once a vault Master Encryption Key rotation commits. Distinct from
/// [`RECEIPT_KIND_IDENTITY_ROTATION_WITNESS`] (which bridges Ed25519
/// daemon-identity epochs); an MEK is a symmetric key with no public
/// half, so overloading the identity witness would distort its
/// epoch-bridging contract. Body shape: [`VaultMekRotationBody`].
pub const RECEIPT_KIND_VAULT_MEK_ROTATION: &str = "vault.mek_rotation";
pub const RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE: &str = "local_state.key_resolve";
pub const RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION: &str = "local_state.key_rotation";
/// emberd emits this kind on every
/// `ExecFrame::Exit` arriving from the in-container `ember-exec`
/// sidecar. The body shape ([`ExecCompletionBody`]) carries the seven
/// fields ADR 118 §"Body shape per kind" pins for the in-container
/// exec audit trail: `persona_id`, `grant_id`, `binary_path`,
/// `binary_blake3`, `target_uid`, `exit_code`, `materialized_at`.
pub const RECEIPT_KIND_EXEC_COMPLETION: &str = "exec.completion";

/// cordon_phase1_receipt_mint_retrofitted — Phase 1 cordon migration deferred
/// receipt obligation per ADR 174 v2 §5 + ADR 176 §4. Minted by
/// `cordon_migration_phase1_destructive` atomically with the
/// `audit.chain_v1_segment_bridge_unattested` row insert; Phase 2 will
/// re-issue this kind with `_attested` + operator signature.
/// Catalog cross-reference: receipt-kind catalog extension pending.
pub const RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED: &str =
    "audit.chain_v1_segment_bridge_unattested";

/// audit_repair_chain_rpc_landed — repair tombstone row kind emitted by
/// `audit.repair_chain` on a successful truncate-after-row, per ADR 174 v2
/// §2 (the "tombstone row whose `prev_hash = audit_log[break-1].row_hash`
/// and whose body carries the repair payload + receipt_id"). The
/// tombstone row uses this action name; the receipt minted alongside
/// the truncate is `RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE` (below).
/// Catalog cross-reference: receipt-kind catalog extension pending.
pub const RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE: &str = "audit.chain_repair_tombstone";

/// audit_repair_chain_rpc_landed — repair-finalize Receipt kind emitted on a
/// successful `audit.repair_chain` truncate-after-row per ADR 174 v2 §6.
/// The body carries the operator co-signature, the new chain tip, the
/// truncated-row count, and the tombstone row id so a downstream verifier
/// can re-bind the repair to the audit chain. Catalog cross-reference:
/// receipt-kind catalog extension pending.
pub const RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE: &str = "audit.chain_repair_finalize";

/// receipt_kind_catalog_audit_chain_v2 — Phase 2 attestation companion to
/// `audit.chain_v1_segment_bridge_unattested`. Minted by
/// `ember audit migrate-chain --acknowledge` when the operator attests the
/// cordon migration; references the Phase 1 receipt by id. Per ADR 176 §4 +
/// autogrill ESC-8.
pub const RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_ATTESTED: &str =
    "audit.chain_v1_segment_bridge_attested";

/// receipt_kind_catalog_audit_chain_v2 — operator declined the cordon
/// migration. Minted by `ember audit migrate-chain --refuse-and-quarantine`.
/// References the Phase 1 receipt by id and carries the refusal reason +
/// operator co-signature.
pub const RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_REFUSED: &str =
    "audit.chain_v1_segment_bridge_refused";

/// receipt_kind_catalog_audit_chain_v2 — daemon restored its event store
/// from an operator-supplied dump (Option E forward-migrate inside restore).
/// Carries the dump + pre-restore-backup integrity anchors and the cordon
/// outcome. Per autogrill restore-from-dump D9.
pub const RECEIPT_KIND_AUDIT_RESTORE_FROM_DUMP: &str = "audit.restore_from_dump";

/// `authority_delegated_hop_receipt_v2` — emitted per delegation hop when a
/// grant is attenuated and re-issued to a child principal (BKR-4/BKR-5 derive-
/// from-grant chain-walk). Records the parent→child narrowing so an external
/// verifier can re-attenuate the chain without trusting the daemon. Per the
/// v0.3.0 buildout §9B cross-lane receipt contract (P23-LEAD ↔ MUS, 2026-05-31)
/// and ADR 200 §4 `(persona_id, device_id)` custody discipline. Body shape:
/// [`AuthorityDelegatedBody`]. A narrowing hop is Routine by construction
/// (child ≤ parent every axis) and carries no fresh presence
/// (`presence_basis = inherited:narrowing:no-presence`); a hop that re-widens
/// or re-authorizes carries a presence-proof reference instead.
pub const RECEIPT_KIND_AUTHORITY_DELEGATED: &str = "authority.delegated";
/// v0.3.0 authority-decision Receipt for a grant issued from
/// a fresh operator presence proof. The daemon signs the envelope for storage
/// integrity; the body carries the operator-device P-256 proof so
/// `trust explain` can verify the authority root without accepting a
/// daemon-forgeable flag.
pub const RECEIPT_KIND_AUTHORITY_GRANT_ISSUED: &str = "authority.grant_issued";

// ===== Body structs =====

/// A usage-stripped projection of a grant [`Statement`] for recording in a
/// durable, signed authority receipt (`broker.mint` scope fields,
/// `authority.delegated`).
///
/// A receipt records an **authority decision**, not consumption. A full
/// [`Statement`] carries a mutable `usage` tally (tokens/cents/requests spent)
/// that is runtime state, not authority — baking it into a signed receipt would
/// let a verifier conflate consumption with authority and would freeze a moving
/// counter into an immutable artifact. This projection keeps exactly the
/// authority axes — `sid`, `resource_type`, `actions`, `resource`, `budget`
/// (the ceiling), `conditions` — and drops `usage`, so an external verifier can
/// re-attenuate the chain (re-run subset/`enforce_subset`) without consumption
/// noise. (`core-grant-types::StatementProposal` is the analogous pre-mint
/// usage-stripped sibling.)
///
/// [`From<&Statement>`] makes population mechanical for the BKR-5 mint path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatementProjection {
    pub sid: StatementId,
    pub resource_type: ResourceType,
    pub actions: Vec<Action>,
    pub resource: ResourceSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl From<&Statement> for StatementProjection {
    fn from(s: &Statement) -> Self {
        // Authority axes only; `usage` is deliberately dropped (see type docs).
        StatementProjection {
            sid: s.sid.clone(),
            resource_type: s.resource_type,
            actions: s.actions.clone(),
            resource: s.resource.clone(),
            budget: s.budget.clone(),
            conditions: s.conditions.clone(),
        }
    }
}

/// Body for `broker.mint` — broker minted a scoped, time-bounded credential lease.
///
/// # Authority-projection fields (v0.3.0 buildout §9B, BKR-5)
///
/// The broker derives the native credential **from the matched grant
/// `Statement`** (post-BKR-1, `req.scope` is no longer an authority input).
/// The three scope fields below record the three *distinct* authority truths
/// that an external verifier needs to re-attenuate the mint — replacing the
/// prior untruth where the materialization audit event echoed
/// `requested_scope == granted_scope == req.scope`
/// (`broker/handler/materialization.rs::emit_materialization_audit_event`):
///
/// - `granted_scope` — what the matched grant authorizes (the *ceiling*).
/// - `requested_scope` — what `action_ref` selected (≤ `granted_scope`).
/// - `minted_scope` — the leaf the **projector claims** it materialized (the
///   projector-claim half; ADR 204 names this `minted_native`).
/// - `mint_stamp` — the **provider's authoritative** scope echo, lowered to
///   its abstract upper bound (`native_upper_bound(echo)`) — the provider-truth
///   half, recorded **distinctly** from `minted_scope` so an offline verifier
///   can detect a projector that minted wider than it claimed (ADR 204
///   amendment 2 / I7). github echoes granted permissions+repositories; STS the
///   assumed-role ARN; cloudflare the policy.
/// - `mint_stamp_kind` — variant-derived discriminator (ADR 213 §D4 /
///   §AC-3): `Some("permissions")` for G1 (granular permission bound
///   stamped by the provider), `Some("identity")` for G2 (identity-only
///   stamp; the effective ceiling is the bound identity's RBAC, not the
///   request need), `Some("unbounded")` / `Some("opaque")` /
///   `Some("unwired")` for the three G3 sources (request shape carries no
///   narrow bound / provider has no stamp API by design / adapter hasn't
///   wired stamp capture yet); `None` on legacy/unpopulated receipts.
///   Replaces the legacy `provider_scope_attestable: Option<bool>` which
///   lost the G1-vs-G2 distinction (D4 follow-up to #5734).
/// - `chain_ref` — the grant/delegation chain id the leaf descends from
///   (ties the minted leaf back to its root authority; pairs with the
///   `authority.delegated` hop receipts on the same chain).
///
/// Each scope is a `Vec<StatementProjection>` (a grant block carries one-or-more
/// IAM-shaped clauses), recorded **structurally** rather than as an opaque
/// provider-native JSON blob so an external verifier re-runs the same
/// subset/`enforce_subset` logic the daemon did. The projection keeps only the
/// authority axes (`actions`/`resource`/`budget`/`conditions`) and drops the
/// `Statement.usage` runtime tally — a signed receipt records authority, not
/// consumption (see [`StatementProjection`]).
///
/// All four are `#[serde(default)]` + skip-when-empty: this is the **schema**
/// (G5a). Population is BKR-5 (the broker mint path); pre-BKR-5 receipts omit
/// them and round-trip byte-identically (no receipt-id/hash change).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerMintBody {
    pub vault_key: String,
    pub scope_template_id: String,
    pub scope_resolved: Vec<String>,
    pub ttl_seconds: u64,
    pub expires_at: String,
    pub revoke_token_hash: String,
    /// What the matched grant authorizes — the ceiling. See type-level docs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scope: Vec<StatementProjection>,
    /// What `action_ref` selected (≤ `granted_scope`). See type-level docs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scope: Vec<StatementProjection>,
    /// The leaf the projector **claims** it materialized (`minted_native`, the
    /// projector-claim half). See type-level docs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub minted_scope: Vec<StatementProjection>,
    /// The provider's stamp on this mint as its abstract upper bound
    /// (`native_upper_bound(stamp)`) — the provider-truth half, distinct
    /// from `minted_scope` so a verifier can catch a projector that minted
    /// wider than claimed (ADR 204 amendment 2 / I7). Empty ⇒ no stamp
    /// recorded (legacy, or a payload-less G3 variant — see
    /// `mint_stamp_kind`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mint_stamp: Vec<StatementProjection>,
    /// Variant-derived discriminator for the provider's stamp
    /// grade (ADR 213 §D4 / §AC-3): `Some("permissions")` for G1 (the
    /// provider stamped a granular permission bound the daemon clamp
    /// verified ⊆ minted), `Some("identity")` for G2 (the provider stamped
    /// only WHICH identity was minted; effective ceiling is the bound
    /// identity's own RBAC), `Some("unbounded")` / `Some("opaque")` /
    /// `Some("unwired")` for the three G3 sources, and `None` on
    /// legacy/unpopulated receipts. Replaces the legacy
    /// `provider_scope_attestable: Option<bool>` which lost the G1-vs-G2
    /// distinction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint_stamp_kind: Option<String>,
    /// Grant/delegation chain id the minted leaf descends from. See type-level docs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chain_ref: String,
}

/// Body for `kms.encrypt` and `kms.decrypt` — KMS envelope operation.
/// `operation` discriminates between the two.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KmsBody {
    pub key_id: String,
    pub operation: String, // "encrypt" or "decrypt"
    pub ciphertext_hash: String,
    pub envelope_format: String,
}

/// Body for `service.installed.v1` — operator installed a catalog service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInstalledBody {
    pub plugin_address: String,
    pub plugin_version: String,
    pub publisher_id: String,
    pub installed_by_persona_id: String,
    pub installation_policy: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_label: Option<String>,
}

/// Body for `service.uninstalled.v1` — operator uninstalled a catalog service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceUninstalledBody {
    pub plugin_address: String,
    pub plugin_version: String,
    pub publisher_id: String,
    pub uninstalled_by_persona_id: String,
    pub uninstall_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_label: Option<String>,
}

/// Body for `binding.{registered,updated,revoked,deleted}` — service-account-to-Persona binding lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingBody {
    pub namespace: String,
    pub sa_name: String,
    pub persona_id: String,
    pub persona_display_name: String,
    pub scopes_granted: Vec<String>,
    pub binding_request_id: String,
}

/// Body for `recovery.action` — daemon-mediated recovery lifecycle evidence
/// per ADR 133 and ADR 195.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryActionBody {
    pub recovery_id: String,
    pub surface: String,
    pub verb: String,
    pub target_kind: String,
    pub target_id: String,
    pub requested_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_journal_sha: Option<String>,
    pub prior_state_digest: String,
    pub dry_run_digest: String,
    pub operator_confirmation_token_hash: Option<String>,
    pub operator_persona_id: Option<String>,
    pub authority_evidence: Value,
    pub outcome: String,
    #[serde(default)]
    pub related_receipt_ids: Vec<String>,
    pub runbook_ref: String,
    #[serde(default)]
    pub adr_refs: Vec<String>,
    pub recorded_at_epoch_secs: u64,
}

impl RecoveryActionBody {
    pub const OUTCOMES: [&'static str; 4] = ["planned", "executed", "refused", "aborted"];
    pub const SURFACES: [&'static str; 2] = ["failure_class", "lifecycle"];

    pub fn validate(&self) -> Result<(), &'static str> {
        fn require_non_empty(value: &str, field: &'static str) -> Result<(), &'static str> {
            if value.trim().is_empty() {
                return Err(field);
            }
            Ok(())
        }

        require_non_empty(&self.recovery_id, "recovery_id must be non-empty")?;
        require_non_empty(&self.surface, "surface must be non-empty")?;
        if !Self::SURFACES.contains(&self.surface.as_str()) {
            return Err("surface must be failure_class or lifecycle");
        }
        require_non_empty(&self.verb, "verb must be non-empty")?;
        require_non_empty(&self.target_kind, "target_kind must be non-empty")?;
        require_non_empty(&self.target_id, "target_id must be non-empty")?;
        require_non_empty(&self.requested_action, "requested_action must be non-empty")?;
        require_non_empty(
            &self.prior_state_digest,
            "prior_state_digest must be non-empty",
        )?;
        require_non_empty(&self.dry_run_digest, "dry_run_digest must be non-empty")?;
        if let Some(value) = &self.operator_confirmation_token_hash {
            require_non_empty(value, "operator_confirmation_token_hash must be non-empty")?;
        }
        if let Some(value) = &self.operator_persona_id {
            require_non_empty(value, "operator_persona_id must be non-empty")?;
        }
        if !self.authority_evidence.is_object() && !self.authority_evidence.is_null() {
            return Err("authority_evidence must be an object or null");
        }
        require_non_empty(&self.outcome, "outcome must be non-empty")?;
        if !Self::OUTCOMES.contains(&self.outcome.as_str()) {
            return Err("outcome must be planned, executed, refused, or aborted");
        }
        require_non_empty(&self.runbook_ref, "runbook_ref must be non-empty")?;
        Ok(())
    }
}

/// Body for `seal.unsealed` — sealed snapshot was opened for recovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealUnsealedBody {
    pub snapshot_id: String,
    pub unsealed_at: String,
    pub recovery_authority: String,
}

/// Body for `snapshot.emitted` — daemon emitted a periodic snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotEmittedBody {
    pub snapshot_id: String,
    pub snapshot_hash: String,
    pub emitted_at: String,
    pub content_addressed_uri: String,
}

/// Body for `identity.rotated` — daemon Persona key rotated (per ADR 116).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRotatedBody {
    pub old_persona_id: String,
    pub new_persona_id: String,
    pub rotated_at: String,
    pub rotation_authority: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentEvaluatedState {
    Allowed,
    Denied,
    EscalationRequired,
    Reserved,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentSettledState {
    Committed,
    Voided,
    Expired,
}

/// Body for `payment.evaluated` — daemon-side spend-attempt authorization
/// decision. `state = reserved` is the soft-allow path that consumes
/// effective capacity until a later `payment.settled` row resolves it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentEvaluatedBody {
    pub state: PaymentEvaluatedState,
    pub attempt_id: String,
    pub statement_sid: String,
    pub amount_cents: u64,
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body for `payment.settled` — terminal resolution of a prior
/// `payment.evaluated { state = reserved }` attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentSettledBody {
    pub state: PaymentSettledState,
    pub attempt_id: String,
    pub statement_sid: String,
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_amount_cents: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body for `proxy.call` — one upstream request observed by the proxy after
/// metering. This is a consumption receipt, so it deliberately carries the
/// metered token split instead of a usage-stripped authority projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyCallBody {
    pub persona_id: String,
    pub grant_id: String,
    pub statement_sid: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub tokens_total: u64,
    pub outcome: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadlessDelegatedMaterial {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_passthrough: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadlessEnrollmentBody {
    pub enrollment_id: String,
    pub peer_uid: u32,
    pub persona: String,
    pub duration_seconds: u64,
    pub expiry_unix: i64,
    pub unlock_method: String,
    pub template_snapshot_hash: String,
    pub delegated_authority_refs: Vec<String>,
    pub delegated_material: HeadlessDelegatedMaterial,
    pub attested_device_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadlessRevocationBody {
    pub peer_uid: u32,
    pub persona: String,
    pub enrollment_id: String,
    pub template_snapshot_hash: String,
    pub reason: String,
}

/// Body for `identity.rotation_witness` — co-signed attestation that
/// bridges between identity-key epochs at MEK rotation time. Per
/// ADR 118 Receipt v2 chain-continuity rule + ADR 133 catalog
/// discipline.
///
/// Anchor: `identity_rotation_witness_body_landed`.
///
/// **Pre:** `prev_epoch_root_id != next_epoch_root_id` — the bridge
/// must connect distinct epochs; an identity-rotation witness would
/// defeat the chain-continuity purpose.
///
/// **Pre:** `signature_by_prev_root` non-empty AND
/// `signature_by_next_root` non-empty — co-signature is required to
/// bind both epochs; a one-sided witness cannot bridge.
///
/// **Post:** round-trips through JCS canonicalization → blake3
/// receipt-id derivation → serde deserialization preserving all
/// fields byte-for-byte (verified by T1 property test).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityRotationWitnessBody {
    /// Identity-root ID prior to the rotation.
    pub prev_epoch_root_id: String,
    /// Identity-root ID after the rotation.
    pub next_epoch_root_id: String,
    /// Timestamp of the rotation (epoch seconds, UTC).
    pub rotated_at_epoch_secs: u64,
    /// Signature over the rotation by the *previous* epoch root key.
    pub signature_by_prev_root: String,
    /// Signature over the rotation by the *next* epoch root key.
    pub signature_by_next_root: String,
    /// Optional human-readable rotation reason (e.g., `"scheduled"`,
    /// `"key-compromise"`, `"operator-init"`).
    pub rotation_reason: Option<String>,
}

impl IdentityRotationWitnessBody {
    /// Validate the body's `Pre:` invariants documented on the struct.
    ///
    /// Returns `Ok(())` when:
    /// - `prev_epoch_root_id != next_epoch_root_id`
    /// - `signature_by_prev_root` is non-empty
    /// - `signature_by_next_root` is non-empty
    ///
    /// Returns `Err(&'static str)` naming the violated invariant
    /// otherwise. The error strings are stable and may be matched in
    /// tests.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.prev_epoch_root_id == self.next_epoch_root_id {
            return Err("prev_epoch_root_id must differ from next_epoch_root_id");
        }
        if self.signature_by_prev_root.is_empty() {
            return Err("signature_by_prev_root must be non-empty");
        }
        if self.signature_by_next_root.is_empty() {
            return Err("signature_by_next_root must be non-empty");
        }
        Ok(())
    }
}

/// Body for `vault.mek_rotation` — daemon committed a vault Master
/// Encryption Key rotation (ADR 198 D7). Records the structured facts the
/// witness pins: the `mode`, the prev/new `key_epoch`, how many wrapped
/// DEKs were re-wrapped under the new MEK in the rotation transaction, the
/// prev/new advisory blake3 MEK fingerprints (of the *rotated scope's*
/// MEK — Interactive for `rekey`/`change_passphrase`, Headless for
/// `rotate_headless`), and the path to the sealed EMVS snapshot taken
/// before the mutate (D4).
///
/// **Honest scope (ADR 198 D6):** an MEK rotation re-protects *at-rest*
/// vault material. It does NOT revoke already-minted tokens, active
/// grants, or the upstream credentials themselves. That caveat is surfaced
/// in the CLI/RPC output, not encoded as a body field — the body carries
/// only the structured, verifiable facts of the at-rest re-protection.
///
/// **Pre:** `mode` is one of `rekey` / `change_passphrase` /
/// `rotate_headless`; `new_key_epoch == prev_key_epoch + 1`; both
/// fingerprints non-empty and differ (the rotated scope's MEK always
/// changes); `snapshot_path` non-empty.
///
/// **Post:** round-trips through JCS canonicalization → blake3 receipt-id
/// derivation → serde deserialization preserving all fields byte-for-byte
/// (verified by T1 property test).
///
/// Anchor: `vault_mek_rotation_body_landed`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMekRotationBody {
    /// Rotation mode: `"rekey"` | `"change_passphrase"` | `"rotate_headless"`.
    pub mode: String,
    /// `vault_meta.key_epoch` before the rotation.
    pub prev_key_epoch: u64,
    /// `vault_meta.key_epoch` after the rotation (`== prev_key_epoch + 1`).
    pub new_key_epoch: u64,
    /// Number of wrapped DEKs re-wrapped under the new MEK in the rotation
    /// transaction (in-scope credential rows + persona-secret rows).
    pub rewrap_count: u64,
    /// blake3(MEK) advisory fingerprint of the rotated scope's MEK BEFORE
    /// the rotation.
    pub prev_mek_fingerprint: String,
    /// blake3(MEK) advisory fingerprint of the rotated scope's MEK AFTER
    /// the rotation.
    pub new_mek_fingerprint: String,
    /// Path to the sealed EMVS snapshot taken before the mutate (ADR 198 D4).
    pub snapshot_path: String,
    /// Rotation timestamp (epoch seconds, UTC).
    pub rotated_at_epoch_secs: u64,
}

impl VaultMekRotationBody {
    /// The three sanctioned rotation modes (ADR 198 D5).
    pub const MODES: [&'static str; 3] = ["rekey", "change_passphrase", "rotate_headless"];

    /// Validate the body's `Pre:` invariants documented on the struct.
    ///
    /// Returns `Ok(())` when:
    /// - `mode` is one of [`VaultMekRotationBody::MODES`]
    /// - `new_key_epoch == prev_key_epoch + 1` (monotonic, single step)
    /// - `prev_mek_fingerprint` and `new_mek_fingerprint` are both
    ///   non-empty and differ (the rotated scope's MEK actually changed)
    /// - `snapshot_path` is non-empty
    ///
    /// Returns `Err(&'static str)` naming the violated invariant
    /// otherwise. The error strings are stable and may be matched in tests.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !Self::MODES.contains(&self.mode.as_str()) {
            return Err("mode must be one of rekey / change_passphrase / rotate_headless");
        }
        if self.new_key_epoch != self.prev_key_epoch + 1 {
            return Err("new_key_epoch must equal prev_key_epoch + 1 (monotonic single step)");
        }
        if self.prev_mek_fingerprint.is_empty() {
            return Err("prev_mek_fingerprint must be non-empty");
        }
        if self.new_mek_fingerprint.is_empty() {
            return Err("new_mek_fingerprint must be non-empty");
        }
        if self.prev_mek_fingerprint == self.new_mek_fingerprint {
            return Err("prev_mek_fingerprint must differ from new_mek_fingerprint");
        }
        if self.snapshot_path.is_empty() {
            return Err("snapshot_path must be non-empty");
        }
        Ok(())
    }
}

/// Body for `local_state.key_resolve` — daemon vended the per-caller
/// local-state content key. Emitted per `daemon-sole-keychain-client`
/// proposal §"Three new daemon socket methods" + ADR 131 separate-uid
/// authorization substrate.
///
/// `resolved_or_generated` discriminates whether the key was already in
/// the daemon vault (`"resolved"`) or generated fresh on this call
/// (`"generated"`). The latter signals a first-touch or migration boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalStateKeyResolveBody {
    pub peer_uid: u32,
    pub caller: String,
    pub vault_namespace: String,
    pub resolved_or_generated: String,
}

/// Body for `local_state.key_rotation` — daemon-side atomic rotation of
/// a per-caller local-state content key. `old_key_hash` / `new_key_hash`
/// are blake3 hashes of the key material (never the keys themselves).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalStateKeyRotationBody {
    pub peer_uid: u32,
    pub caller: String,
    pub vault_namespace: String,
    pub old_key_hash: String,
    pub new_key_hash: String,
}

/// Body for `exec.completion` — emberd-side Receipt v2 emission on every
/// `ExecFrame::Exit` arriving from the in-container `ember-exec` sidecar.
///
/// emberd (not ember-exec) is
/// the receipt signer; the in-container sidecar reports the child's
/// exit code over the UDS frame protocol, and emberd composes the
/// signed v2 envelope.
///
/// Field provenance:
///
/// - `persona_id` — the persona under which `broker.resolve` issued the
///   spawn handle (the caller persona that authorised this exec).
/// - `grant_id` — the standing parent grant that authorised the exec.
/// - `binary_path` — absolute path inside the container of the binary
///   that was just executed.
/// - `binary_blake3` — the hex-encoded blake3 content hash emberd
///   verified BEFORE sending the `SpawnDirective` to the in-container
///   sidecar. Recorded as the receipt's authoritative hash so audit
///   chains preserve "the bytes the daemon actually approved", not a
///   recomputation by an untrusted post-execve verifier.
/// - `target_uid` — the unprivileged uid the in-container sidecar
///   dropped to before `execve` (subtask B's `drop_privileges`).
/// - `exit_code` — the child's exit status as reported by
///   `ExecFrame::Exit { code }`.
/// - `materialized_at` — RFC3339 wall-clock at which emberd composed
///   the receipt (i.e. when the Exit frame arrived, NOT the in-container
///   child's own clock — ember-exec is not a trust root for time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecCompletionBody {
    pub persona_id: String,
    pub grant_id: String,
    pub binary_path: String,
    pub binary_blake3: String,
    pub target_uid: u32,
    pub exit_code: i32,
    pub materialized_at: String,
}

/// cordon_phase1_receipt_mint_retrofitted — body for
/// `audit.chain_v1_segment_bridge_unattested`. Carries the pre-migration
/// BLAKE3 anchor + the destroyed-row ids + the bridge row's chain anchors
/// per ADR 174 v2 §5 + ADR 176 §4. Daemon-signed only at Phase 1; Phase 2
/// re-mints the kind suffixed `_attested` with an operator signature.
///
/// Field provenance:
/// - `pre_migration_chain_tip_hash` — BLAKE3 of the last chained
///   `audit_log` row before the cordon ran (the v1 genesis row's
///   `row_hash` on the operator's host, since the operator's tail was the
///   buggy half-write block that gets destroyed).
/// - `destroyed_row_ids` — the ids of the audit_log rows the cordon
///   excluded by id-boundary from the INSERT-SELECT carryover. Empty on
///   the no-cordon recreate paths (`carry_all_segment_zero` and
///   `no_data`); populated on the operator's-host destructive path.
/// - `bridge_segment_genesis` — the bridge row's own anchor data
///   (segment_id, prev_hash, row_hash) so a verifier walking from the
///   receipt can re-bind it to the in-DB bridge row by primary key.
/// - `migration_timestamp` — RFC3339 wall-clock at which the cordon
///   executed (matches the bridge row's `timestamp` column).
/// - `daemon_identity_root_fingerprint` — blake3 fingerprint of the
///   daemon's signing pubkey, so a post-rotation forensic walk can
///   resolve the signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainV1SegmentBridgeUnattestedBody {
    pub pre_migration_chain_tip_hash: String,
    pub destroyed_row_ids: Vec<i64>,
    pub bridge_segment_genesis: BridgeSegmentGenesis,
    pub migration_timestamp: String,
    pub daemon_identity_root_fingerprint: String,
}

/// cordon_phase1_receipt_mint_retrofitted — bridge row's chain anchors
/// embedded in the bridge receipt's body. Mirrors the on-disk row at
/// `(segment_id = 1, is_segment_genesis = 1)`. Per ADR 176 §3 + §4.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeSegmentGenesis {
    pub segment_id: u64,
    pub prev_hash: String,
    pub row_hash: String,
}

/// audit_repair_chain_rpc_landed — body for `audit.chain_repair_finalize`
/// minted on a successful `audit.repair_chain` truncate-after-row. Carries
/// the operator co-signature + repair-anchors so a verifier can re-bind
/// the repair to the audit chain post-restart. Per ADR 174 v2 §6.
///
/// Field provenance:
/// - `repair_id` — opaque id identifying this repair episode (UUID).
/// - `from_row_id` — the id passed as `RepairIntent.from_row_id`; rows
///   with `id > from_row_id` were destroyed.
/// - `truncated_row_count` — count of rows DELETE'd in the truncate
///   step.
/// - `tombstone_row_id` — id of the `audit.chain_repair_tombstone` row
///   inserted at `from_row_id + 1` (the new chain tip).
/// - `new_chain_tip_hash` — `row_hash` of the tombstone row.
/// - `pre_repair_chain_tip_hash` — `row_hash` of the row at
///   `from_row_id` BEFORE the truncate (the new chain tip's
///   `prev_hash`); the bytes the operator co-signed.
/// - `operator_signature` — Ed25519 signature by an enrolled operator
///   persona's identity-root over the canonical
///   `(from_row_id, pre_repair_chain_tip_hash,
///   daemon_identity_root_fingerprint)` tuple.
/// - `signing_device_id` — the `presence`-class Device whose key produced
///   `operator_signature` (the custody — *with which key*; ADR 200 §4 / P23-S5).
///   Every signature records the `(persona, device)` pair so an external verifier
///   distinguishes a daemon-forgeable persona-key co-sign from a hardware
///   presence-Device co-sign. `#[serde(default)]` for tolerant decode of
///   pre-S5 repair receipts (empty = unattributed).
/// - `daemon_identity_root_fingerprint` — blake3 fingerprint of the
///   daemon's signing pubkey at repair time.
/// - `repair_timestamp` — RFC3339 wall-clock when the repair ran.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainRepairFinalizeBody {
    pub repair_id: String,
    pub from_row_id: i64,
    pub truncated_row_count: u64,
    pub tombstone_row_id: i64,
    pub new_chain_tip_hash: String,
    pub pre_repair_chain_tip_hash: String,
    pub operator_signature: String,
    #[serde(default)]
    pub signing_device_id: String,
    pub daemon_identity_root_fingerprint: String,
    pub repair_timestamp: String,
}

/// receipt_kind_catalog_audit_chain_v2 — body for
/// `audit.chain_v1_segment_bridge_attested` (Phase 2). The operator
/// attested the Phase 1 cordon migration. Carries the bridge anchors
/// (mirrors the Phase 1 body so a verifier can re-bind to the in-DB row),
/// a back-reference to the Phase 1 receipt id (`attests_receipt`), and the
/// operator co-signature over the attestation.
///
/// Field provenance:
/// - `attests_receipt` — the `receipt_id` of the Phase 1
///   `audit.chain_v1_segment_bridge_unattested` receipt this attests.
/// - `bridge_segment_genesis` — the bridge row's on-disk anchors (same as
///   the Phase 1 body) so attestation re-binds to the same row.
/// - `operator_persona_id` — the enrolled operator persona that attested
///   (the principal — *who* authorized).
/// - `signing_device_id` — the `presence`-class Device whose key produced
///   `operator_signature` (the custody — *with which key*). ADR 200 §4: every
///   signature records the `(persona_id, device_id)` pair so an external
///   verifier distinguishes daemon-self-rooted from operator-authorized actions.
/// - `operator_signature` — operator co-signature over the attestation tuple
///   (hex), verified against the `signing_device_id` Device's public key.
/// - `attestation_timestamp` — RFC3339 wall-clock at attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainV1SegmentBridgeAttestedBody {
    pub attests_receipt: String,
    pub bridge_segment_genesis: BridgeSegmentGenesis,
    pub operator_persona_id: String,
    pub signing_device_id: String,
    pub operator_signature: String,
    pub attestation_timestamp: String,
}

/// receipt_kind_catalog_audit_chain_v2 — body for
/// `audit.chain_v1_segment_bridge_refused`. The operator declined the
/// cordon migration via `ember audit migrate-chain --refuse-and-quarantine`.
///
/// Field provenance:
/// - `phase1_receipt_id` — the Phase 1 `_unattested` receipt being refused.
/// - `operator_persona_id` — the enrolled operator persona that refused (the
///   principal — *who*).
/// - `signing_device_id` — the `presence`-class Device whose key produced
///   `operator_signature` (the custody — *with which key*; ADR 200 §4).
/// - `operator_signature` — operator co-signature over the refusal tuple (hex),
///   verified against the `signing_device_id` Device's public key.
/// - `reason` — operator-supplied human-readable refusal reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditChainV1SegmentBridgeRefusedBody {
    pub phase1_receipt_id: String,
    pub operator_persona_id: String,
    pub signing_device_id: String,
    pub operator_signature: String,
    pub reason: String,
}

/// receipt_kind_catalog_audit_chain_v2 — body for `audit.restore_from_dump`
/// (Option E: forward-migrate inside restore). Per autogrill
/// restore-from-dump D9 (10-field body).
///
/// Field provenance:
/// - `dump_path` / `dump_sha256` — the operator-supplied dump and its
///   integrity digest.
/// - `pre_restore_backup_path` / `pre_restore_sha256` — the backup of the
///   prior store taken before the restore, and its digest.
/// - `from_journal_offset` — the receipts.log offset the restore resumed
///   from.
/// - `cordon_fired` — whether the post-restore open triggered a cordon
///   migration (legacy dump shape).
/// - `bridge_row_id` / `bridge_receipt_id` — set when `cordon_fired`; the
///   resulting bridge row + its Phase 1 receipt id (None otherwise).
/// - `operator_persona_id` — the enrolled operator persona that authorized the
///   restore (the principal — *who*).
/// - `signing_device_id` — the `presence`-class Device whose key produced
///   `operator_signature` (the custody — *with which key*; ADR 200 §4).
/// - `operator_signature` — operator co-signature (hex), verified against the
///   `signing_device_id` Device's public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRestoreFromDumpBody {
    pub dump_path: String,
    pub dump_sha256: String,
    pub pre_restore_backup_path: String,
    pub pre_restore_sha256: String,
    pub from_journal_offset: u64,
    pub cordon_fired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_row_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_receipt_id: Option<String>,
    pub operator_persona_id: String,
    pub signing_device_id: String,
    pub operator_signature: String,
}

/// One authority axis narrowed at a delegation hop. See [`AttenuationSummary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttenuationAxis {
    Actions,
    Resource,
    Budget,
    Ttl,
    Conditions,
    Principal,
}

/// Structured summary of how a delegation hop narrowed the parent authority.
///
/// `axes_narrowed` lists which authority axes the child tightened relative to
/// the parent (empty == pass-through: child == parent on every axis). Recorded
/// structurally rather than as free text so a verifier can cross-check the
/// claimed narrowing against the `granted`/`minted` scope projections on the
/// chain (buildout §9B). Population is BKR-4/BKR-5.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttenuationSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub axes_narrowed: Vec<AttenuationAxis>,
}

/// The locked wire string for [`PresenceBasis::InheritedNarrowing`].
pub const PRESENCE_BASIS_INHERITED_NARROWING: &str = "inherited:narrowing:no-presence";

/// The presence basis for a delegation hop (`authority.delegated`).
///
/// A narrowing-only hop (child ≤ parent on every axis) requires **no fresh
/// presence** — authority is inherited from the parent and merely attenuated,
/// so it routes the Routine/capability lane and never fires the G1 presence
/// gate. Any hop that is not pure narrowing must reference the presence proof
/// that authorized it.
///
/// Wire form (buildout §9B): [`PresenceBasis::InheritedNarrowing`] serializes to
/// the exact string [`PRESENCE_BASIS_INHERITED_NARROWING`]; [`PresenceBasis::
/// PresenceProof`] serializes to the bare proof-reference string. (A proof
/// reference equal to the literal would round-trip to `InheritedNarrowing`; the
/// literal's colons + `no-presence` token make a real collision implausible.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", from = "String")]
pub enum PresenceBasis {
    /// Narrowing-only hop; no presence required (Routine lane).
    InheritedNarrowing,
    /// A presence proof authorized this hop; carries its reference.
    PresenceProof(String),
}

impl From<PresenceBasis> for String {
    fn from(b: PresenceBasis) -> String {
        match b {
            PresenceBasis::InheritedNarrowing => PRESENCE_BASIS_INHERITED_NARROWING.to_string(),
            PresenceBasis::PresenceProof(r) => r,
        }
    }
}

impl From<String> for PresenceBasis {
    fn from(s: String) -> PresenceBasis {
        if s == PRESENCE_BASIS_INHERITED_NARROWING {
            PresenceBasis::InheritedNarrowing
        } else {
            PresenceBasis::PresenceProof(s)
        }
    }
}

/// Body for `authority.delegated` — one delegation hop in a derive-from-grant
/// chain-walk (BKR-4/BKR-5). See [`RECEIPT_KIND_AUTHORITY_DELEGATED`].
///
/// Field provenance (buildout §9B):
/// - `parent_grant_ref` — the parent grant/block this hop attenuates.
/// - `child_principal_id` — the principal the attenuated authority is issued to.
/// - `attenuation` — structured summary of the axes narrowed (parent→child).
/// - `depth` — hop depth from the root authority (root block = 0).
/// - `presence_basis` — `inherited:narrowing:no-presence` for a narrowing hop,
///   else a reference to the presence proof that authorized it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDelegatedBody {
    pub parent_grant_ref: String,
    pub child_principal_id: String,
    #[serde(default)]
    pub attenuation: AttenuationSummary,
    pub depth: u32,
    pub presence_basis: PresenceBasis,
}

/// The nonce-bound operator presence proof that authorized an authority
/// decision. The signature is the wire `_presence_proof.signature` over
/// `canonical_presence_intent_bytes(method, op_id, nonce, daemon_fingerprint,
/// params_digest)`, verified against `signing_device_id` in the operator
/// identity event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityPresenceProof {
    pub method: String,
    pub op_id: String,
    pub nonce: String,
    pub daemon_fingerprint: String,
    pub params_digest: String,
    pub signature: String,
}

/// Body for `authority.grant_issued` — root grant
/// issuance backed by a fresh operator presence proof. The scope is recorded as
/// structured statements so an external verifier can re-check the grant ceiling
/// instead of trusting a lossy display string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityGrantIssuedBody {
    pub grant_id: String,
    pub grantee_principal_id: String,
    pub credential_name: String,
    pub request_params: Value,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted_scope: Vec<StatementProjection>,
    pub operator_root_id: String,
    pub operator_persona_id: String,
    pub signing_device_id: String,
    pub presence_proof: AuthorityPresenceProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::envelope::{ReceiptEnvelope, ReceiptVersion, TerminationAuthority};
    use crate::receipt::sign::{sign_receipt_v2, verify_receipt_v2};
    use core_crypto::{FixtureSigner, FixtureVerifier, Signer};

    #[test]
    fn kind_constants_match_adr_118() {
        assert_eq!(RECEIPT_KIND_BROKER_MINT, "broker.mint");
        assert_eq!(RECEIPT_KIND_KMS_ENCRYPT, "kms.encrypt");
        assert_eq!(RECEIPT_KIND_KMS_DECRYPT, "kms.decrypt");
        assert_eq!(RECEIPT_KIND_SERVICE_INSTALLED_V1, "service.installed.v1");
        assert_eq!(
            RECEIPT_KIND_SERVICE_UNINSTALLED_V1,
            "service.uninstalled.v1"
        );
        assert_eq!(RECEIPT_KIND_BINDING_REGISTERED, "binding.registered");
        assert_eq!(RECEIPT_KIND_BINDING_UPDATED, "binding.updated");
        assert_eq!(RECEIPT_KIND_BINDING_REVOKED, "binding.revoked");
        assert_eq!(RECEIPT_KIND_BINDING_DELETED, "binding.deleted");
        assert_eq!(RECEIPT_KIND_RECOVERY_ACTION, "recovery.action");
        assert_eq!(RECEIPT_KIND_SEAL_UNSEALED, "seal.unsealed");
        assert_eq!(RECEIPT_KIND_SNAPSHOT_EMITTED, "snapshot.emitted");
        assert_eq!(RECEIPT_KIND_IDENTITY_ROTATED, "identity.rotated");
        assert_eq!(
            RECEIPT_KIND_LOCAL_STATE_KEY_RESOLVE,
            "local_state.key_resolve"
        );
        assert_eq!(
            RECEIPT_KIND_LOCAL_STATE_KEY_ROTATION,
            "local_state.key_rotation"
        );
        assert_eq!(RECEIPT_KIND_EXEC_COMPLETION, "exec.completion");
        assert_eq!(
            RECEIPT_KIND_IDENTITY_ROTATION_WITNESS,
            "identity.rotation_witness"
        );
        assert_eq!(RECEIPT_KIND_VAULT_MEK_ROTATION, "vault.mek_rotation");
        // cordon_phase1_receipt_mint_retrofitted +
        // audit_repair_chain_rpc_landed — locked kind names per ADR
        // 174 v2 §§5/6 + ADR 176 §4.
        assert_eq!(
            RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_UNATTESTED,
            "audit.chain_v1_segment_bridge_unattested"
        );
        assert_eq!(
            RECEIPT_KIND_AUDIT_CHAIN_REPAIR_TOMBSTONE,
            "audit.chain_repair_tombstone"
        );
        assert_eq!(
            RECEIPT_KIND_AUDIT_CHAIN_REPAIR_FINALIZE,
            "audit.chain_repair_finalize"
        );
        // receipt_kind_catalog_audit_chain_v2 — the 3 kinds completing the
        // audit chain v2 bundle (the 2 above shipped piecemeal in #4435).
        assert_eq!(
            RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_ATTESTED,
            "audit.chain_v1_segment_bridge_attested"
        );
        assert_eq!(
            RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_REFUSED,
            "audit.chain_v1_segment_bridge_refused"
        );
        assert_eq!(
            RECEIPT_KIND_AUDIT_RESTORE_FROM_DUMP,
            "audit.restore_from_dump"
        );
        assert_eq!(RECEIPT_KIND_PROXY_CALL, "proxy.call");
        // ADR 118 Extension 6 / ADR 173 M4 — bridge cert supersede event
        // (`daemon_bridge_cert_superseded_event_emitted`).
        assert_eq!(
            RECEIPT_KIND_BRIDGE_CERT_SUPERSEDED,
            "bridge.cert_superseded"
        );
    }

    #[test]
    fn audit_chain_v1_segment_bridge_body_round_trips() {
        let body = AuditChainV1SegmentBridgeUnattestedBody {
            pre_migration_chain_tip_hash:
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            destroyed_row_ids: vec![295, 296, 297],
            bridge_segment_genesis: BridgeSegmentGenesis {
                segment_id: 1,
                prev_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .into(),
                row_hash: "3333333333333333333333333333333333333333333333333333333333333333".into(),
            },
            migration_timestamp: "2026-05-22T12:00:00Z".into(),
            daemon_identity_root_fingerprint:
                "4444444444444444444444444444444444444444444444444444444444444444".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: AuditChainV1SegmentBridgeUnattestedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn audit_chain_repair_finalize_body_round_trips() {
        let body = AuditChainRepairFinalizeBody {
            repair_id: "repair-aaaa-bbbb-cccc".into(),
            from_row_id: 290,
            truncated_row_count: 3,
            tombstone_row_id: 291,
            new_chain_tip_hash: "5555555555555555555555555555555555555555555555555555555555555555"
                .into(),
            pre_repair_chain_tip_hash:
                "6666666666666666666666666666666666666666666666666666666666666666".into(),
            operator_signature: "p256sig:deadbeef".into(),
            signing_device_id: "device-operator-presence".into(),
            daemon_identity_root_fingerprint:
                "7777777777777777777777777777777777777777777777777777777777777777".into(),
            repair_timestamp: "2026-05-22T13:00:00Z".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: AuditChainRepairFinalizeBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);

        // `signing_device_id` decodes tolerantly when absent (pre-S5 receipts).
        let mut legacy = serde_json::to_value(&body).unwrap();
        legacy.as_object_mut().unwrap().remove("signing_device_id");
        let decoded: AuditChainRepairFinalizeBody = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.signing_device_id, "");
    }

    #[test]
    fn audit_chain_v1_segment_bridge_attested_body_round_trips() {
        let body = AuditChainV1SegmentBridgeAttestedBody {
            attests_receipt: "rcpt-phase1-aaaa".into(),
            bridge_segment_genesis: BridgeSegmentGenesis {
                segment_id: 1,
                prev_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .into(),
                row_hash: "3333333333333333333333333333333333333333333333333333333333333333".into(),
            },
            operator_persona_id: "persona-op-1".into(),
            signing_device_id: "device-yubikey-1".into(),
            operator_signature: "ed25519sig:cafe".into(),
            attestation_timestamp: "2026-05-29T12:00:00Z".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        // ADR 200 §4: both the principal and the signing device are recorded.
        assert_eq!(v["operator_persona_id"], "persona-op-1");
        assert_eq!(v["signing_device_id"], "device-yubikey-1");
        let back: AuditChainV1SegmentBridgeAttestedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn audit_chain_v1_segment_bridge_refused_body_round_trips() {
        let body = AuditChainV1SegmentBridgeRefusedBody {
            phase1_receipt_id: "rcpt-phase1-bbbb".into(),
            operator_persona_id: "persona-op-1".into(),
            signing_device_id: "device-yubikey-1".into(),
            operator_signature: "ed25519sig:beef".into(),
            reason: "operator declined: legacy block under investigation".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: AuditChainV1SegmentBridgeRefusedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn audit_restore_from_dump_body_round_trips() {
        // With and without the optional cordon fields.
        let with_cordon = AuditRestoreFromDumpBody {
            dump_path: "/tmp/dump.sqlite".into(),
            dump_sha256: "aa".repeat(32),
            pre_restore_backup_path: "/var/ember/backup.sqlite".into(),
            pre_restore_sha256: "bb".repeat(32),
            from_journal_offset: 4096,
            cordon_fired: true,
            bridge_row_id: Some(295),
            bridge_receipt_id: Some("rcpt-bridge-cccc".into()),
            operator_persona_id: "persona-op-1".into(),
            signing_device_id: "device-yubikey-1".into(),
            operator_signature: "ed25519sig:f00d".into(),
        };
        let v = serde_json::to_value(&with_cordon).unwrap();
        let back: AuditRestoreFromDumpBody = serde_json::from_value(v).unwrap();
        assert_eq!(with_cordon, back);

        let no_cordon = AuditRestoreFromDumpBody {
            cordon_fired: false,
            bridge_row_id: None,
            bridge_receipt_id: None,
            ..with_cordon.clone()
        };
        let v2 = serde_json::to_value(&no_cordon).unwrap();
        // Optional cordon fields omitted from the wire form when None.
        assert!(v2.get("bridge_row_id").is_none());
        let back2: AuditRestoreFromDumpBody = serde_json::from_value(v2).unwrap();
        assert_eq!(no_cordon, back2);
    }

    /// receipt_kind_catalog_audit_chain_v2 — the new kinds sign + verify
    /// through the standard envelope path (no per-kind registration; the
    /// daemon signs the whole envelope, body is opaque Value).
    #[test]
    fn audit_chain_v2_bundle_kinds_sign_and_verify() {
        let signer = FixtureSigner::new("audit-chain-v2-bundle");
        let pk = signer.public_key();
        for (kind, body) in [
            (
                RECEIPT_KIND_AUDIT_CHAIN_V1_SEGMENT_BRIDGE_REFUSED,
                serde_json::to_value(AuditChainV1SegmentBridgeRefusedBody {
                    phase1_receipt_id: "rcpt-1".into(),
                    operator_persona_id: "op".into(),
                    signing_device_id: "dev-1".into(),
                    operator_signature: "sig".into(),
                    reason: "no".into(),
                })
                .unwrap(),
            ),
            (
                RECEIPT_KIND_AUDIT_RESTORE_FROM_DUMP,
                serde_json::to_value(AuditRestoreFromDumpBody {
                    dump_path: "/tmp/d".into(),
                    dump_sha256: "aa".repeat(32),
                    pre_restore_backup_path: "/tmp/b".into(),
                    pre_restore_sha256: "bb".repeat(32),
                    from_journal_offset: 0,
                    cordon_fired: false,
                    bridge_row_id: None,
                    bridge_receipt_id: None,
                    operator_persona_id: "op".into(),
                    signing_device_id: "dev-1".into(),
                    operator_signature: "sig".into(),
                })
                .unwrap(),
            ),
        ] {
            let mut env = ReceiptEnvelope {
                version: ReceiptVersion::default(),
                kind: kind.to_string(),
                receipt_id: String::new(),
                daemon_root_id: "root-fixture".into(),
                traceparent: None,
                termination_authority: TerminationAuthority::DaemonPersona,
                presence_kind: None,
                body,
                signature: None,
                calling_principal: None,
                presence_reason: None,
                handle_id: None,
                challenge_hash: None,
                verifier_aaguid: None,
            };
            sign_receipt_v2(&mut env, &signer).expect("sign");
            verify_receipt_v2(&env, &pk, &FixtureVerifier).expect("verify");
        }
    }

    #[test]
    fn local_state_key_resolve_body_round_trips() {
        let body = LocalStateKeyResolveBody {
            peer_uid: 501,
            caller: "cli".into(),
            vault_namespace: "local-state/cli".into(),
            resolved_or_generated: "generated".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: LocalStateKeyResolveBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn local_state_key_rotation_body_round_trips() {
        let body = LocalStateKeyRotationBody {
            peer_uid: 501,
            caller: "gui".into(),
            vault_namespace: "local-state/gui".into(),
            old_key_hash: "blake3:olddead".into(),
            new_key_hash: "blake3:newbeef".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: LocalStateKeyRotationBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    fn sample_recovery_action_body() -> RecoveryActionBody {
        RecoveryActionBody {
            recovery_id: "recover-diagnose-test".into(),
            surface: "lifecycle".into(),
            verb: "diagnose".into(),
            target_kind: "local-machine".into(),
            target_id: "local-machine".into(),
            requested_action: "ember recover diagnose".into(),
            prior_journal_sha: None,
            prior_state_digest: "blake3:1111111111111111".into(),
            dry_run_digest: "blake3:2222222222222222".into(),
            operator_confirmation_token_hash: None,
            operator_persona_id: None,
            authority_evidence: serde_json::json!({
                "daemon_rpc": "recovery_action_receipt",
                "authority_class": "ConnectOnly",
                "receipt_scope": "recover-diagnose",
            }),
            outcome: "planned".into(),
            related_receipt_ids: Vec::new(),
            runbook_ref: "docs/runbook/recovery.md#recovery-lifecycle-plane".into(),
            adr_refs: vec!["ADR 195".into()],
            recorded_at_epoch_secs: 1_800_000_000,
        }
    }

    #[test]
    fn recovery_action_body_round_trips() {
        let body = sample_recovery_action_body();
        assert!(body.validate().is_ok());
        let v = serde_json::to_value(&body).unwrap();
        let back: RecoveryActionBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn recovery_action_body_rejects_empty_required_fields() {
        let mut body = sample_recovery_action_body();
        body.requested_action.clear();
        assert_eq!(body.validate(), Err("requested_action must be non-empty"));
    }

    #[test]
    fn recovery_action_body_rejects_unknown_outcome() {
        let mut body = sample_recovery_action_body();
        body.outcome = "maybe".into();
        assert_eq!(
            body.validate(),
            Err("outcome must be planned, executed, refused, or aborted")
        );
    }

    #[test]
    fn broker_mint_body_round_trips() {
        // Back-compat case: the BKR-5 scope-projection fields are unset
        // (pre-population). They must be omitted from the wire and round-trip
        // to the same empty value so existing receipts hash identically.
        let body = BrokerMintBody {
            vault_key: "anthropic-key".into(),
            scope_template_id: "tier0-default".into(),
            scope_resolved: vec!["llm:generate".into(), "credential:read".into()],
            ttl_seconds: 1800,
            expires_at: "2026-05-02T20:00:00Z".into(),
            revoke_token_hash: "blake3:abc123".into(),
            granted_scope: vec![],
            requested_scope: vec![],
            minted_scope: vec![],
            mint_stamp: vec![],
            mint_stamp_kind: None,
            chain_ref: String::new(),
        };
        let v = serde_json::to_value(&body).unwrap();
        // The scope-projection + amendment-2 fields are skip-when-empty/None:
        // absent from the JSON object, so pre-population receipts hash identically.
        assert!(v.get("granted_scope").is_none());
        assert!(v.get("requested_scope").is_none());
        assert!(v.get("minted_scope").is_none());
        assert!(v.get("mint_stamp").is_none());
        assert!(v.get("mint_stamp_kind").is_none());
        // The legacy bool field name MUST NOT serialize under either spelling —
        // AC-3 requires the bool removed and unread; round-tripping under the
        // old name would let a downstream reader keep the old shape.
        assert!(v.get("provider_scope_attestable").is_none());
        assert!(v.get("chain_ref").is_none());
        let back: BrokerMintBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    /// Test-only `Statement` fixture (mirrors core-grant-types' own test shape).
    /// Carries a non-default `usage` so the projection's usage-drop is provable.
    fn sample_statement(sid: &str, action: &str) -> Statement {
        use core_grant_types::grant_chain::{Budget, ResourceSelector, ResourceType, Usage};
        Statement {
            sid: sid.into(),
            resource_type: ResourceType::Credential,
            actions: vec![action.into()],
            resource: ResourceSelector::Glob {
                pattern: "emberdotlink/*".into(),
            },
            budget: Some(Budget {
                requests: Some(100),
                ..Budget::default()
            }),
            usage: Usage {
                requests: 42,
                ..Usage::default()
            },
            conditions: Vec::new(),
            can_delegate: None,
        }
    }

    #[test]
    fn statement_projection_drops_usage_keeps_authority() {
        let stmt = sample_statement("GhPush", "git.push");
        let proj = StatementProjection::from(&stmt);
        // Authority axes carry through verbatim.
        assert_eq!(proj.sid, stmt.sid);
        assert_eq!(proj.resource_type, stmt.resource_type);
        assert_eq!(proj.actions, stmt.actions);
        assert_eq!(proj.resource, stmt.resource);
        assert_eq!(proj.budget, stmt.budget);
        assert_eq!(proj.conditions, stmt.conditions);
        // The runtime usage tally is NOT representable on the projection — a
        // signed receipt records authority, not consumption.
        let v = serde_json::to_value(&proj).unwrap();
        assert!(
            v.get("usage").is_none(),
            "usage must not leak into the receipt"
        );
        assert_eq!(v["budget"]["requests"], 100); // the ceiling survives
    }

    #[test]
    fn broker_mint_body_with_scope_projections_round_trips() {
        // BKR-5 population case: the three scopes are distinct authority
        // projections (granted ⊇ requested ⊇ minted) plus a chain ref. Built via
        // the `From<&Statement>` path the mint lane uses.
        let granted = [
            sample_statement("GhPush", "git.push"),
            sample_statement("GhPr", "gh.pr_create"),
        ];
        let minted = [sample_statement("GhPush", "git.push")];
        let body = BrokerMintBody {
            vault_key: "github-app-key".into(),
            scope_template_id: "github-default".into(),
            scope_resolved: vec!["git.push".into()],
            ttl_seconds: 600,
            expires_at: "2026-05-31T20:00:00Z".into(),
            revoke_token_hash: "blake3:rev".into(),
            granted_scope: granted.iter().map(StatementProjection::from).collect(),
            requested_scope: minted.iter().map(StatementProjection::from).collect(),
            minted_scope: minted.iter().map(StatementProjection::from).collect(),
            // provider-truth half: distinct from minted_scope (projector claim).
            mint_stamp: minted.iter().map(StatementProjection::from).collect(),
            // ADR 213 §D4 / §AC-3: github echoes a granular permission bound,
            // so this materialization records the G1 ("scope") attestation
            // discriminator. Replaces the legacy `provider_scope_attestable:
            // Some(true)` which lost the G1-vs-G2 distinction.
            mint_stamp_kind: Some("permissions".to_string()),
            chain_ref: "grant-chain-abc123".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        // Four distinct truths, present on the wire when populated.
        assert_eq!(v["granted_scope"].as_array().unwrap().len(), 2);
        assert_eq!(v["requested_scope"].as_array().unwrap().len(), 1);
        assert_eq!(v["minted_scope"].as_array().unwrap().len(), 1);
        // mint_stamp recorded distinctly from minted_scope (amendment 2 / I7).
        assert_eq!(v["mint_stamp"].as_array().unwrap().len(), 1);
        assert_eq!(v["mint_stamp_kind"], "permissions");
        // Defense-in-depth: the legacy bool field name must NOT appear on the wire.
        assert!(v.get("provider_scope_attestable").is_none());
        assert_eq!(v["chain_ref"], "grant-chain-abc123");
        // No usage leaked anywhere in the scope projections.
        assert!(v["granted_scope"][0].get("usage").is_none());
        let back: BrokerMintBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn authority_delegated_body_inherited_narrowing_round_trips() {
        assert_eq!(RECEIPT_KIND_AUTHORITY_DELEGATED, "authority.delegated");
        let body = AuthorityDelegatedBody {
            parent_grant_ref: "grant-root-1".into(),
            child_principal_id: "persona-child-9".into(),
            attenuation: AttenuationSummary {
                axes_narrowed: vec![AttenuationAxis::Actions, AttenuationAxis::Ttl],
            },
            depth: 1,
            presence_basis: PresenceBasis::InheritedNarrowing,
        };
        let v = serde_json::to_value(&body).unwrap();
        // A narrowing hop's presence_basis is the locked literal string.
        assert_eq!(v["presence_basis"], PRESENCE_BASIS_INHERITED_NARROWING);
        assert_eq!(v["presence_basis"], "inherited:narrowing:no-presence");
        assert_eq!(v["attenuation"]["axes_narrowed"][0], "actions");
        assert_eq!(v["attenuation"]["axes_narrowed"][1], "ttl");
        assert_eq!(v["depth"], 1);
        let back: AuthorityDelegatedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn authority_grant_issued_body_round_trips_proof_material() {
        assert_eq!(
            RECEIPT_KIND_AUTHORITY_GRANT_ISSUED,
            "authority.grant_issued"
        );
        let body = AuthorityGrantIssuedBody {
            grant_id: "grant-root-1".into(),
            grantee_principal_id: "persona-runtime".into(),
            credential_name: "github".into(),
            request_params: serde_json::json!({"persona_id": "persona-runtime"}),
            issued_at: "2026-06-17T00:00:00Z".into(),
            expires_at: Some("2026-06-17T04:00:00Z".into()),
            granted_scope: Vec::new(),
            operator_root_id: "root-operator-abc".into(),
            operator_persona_id: "persona-operator-abc".into(),
            signing_device_id: "device-operator-abc".into(),
            presence_proof: AuthorityPresenceProof {
                method: "create_composite_grant".into(),
                op_id: "op-1".into(),
                nonce: "nonce-1".into(),
                daemon_fingerprint: "daemon-fp".into(),
                params_digest: "sha256:abc".into(),
                signature: "p256sig:abcd".into(),
            },
        };
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["operator_root_id"], "root-operator-abc");
        assert_eq!(value["signing_device_id"], "device-operator-abc");
        assert_eq!(value["presence_proof"]["method"], "create_composite_grant");
        let back: AuthorityGrantIssuedBody = serde_json::from_value(value).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn authority_delegated_body_presence_proof_round_trips() {
        let body = AuthorityDelegatedBody {
            parent_grant_ref: "grant-root-1".into(),
            child_principal_id: "persona-child-9".into(),
            attenuation: AttenuationSummary::default(),
            depth: 0,
            presence_basis: PresenceBasis::PresenceProof("presence-proof-ref-xyz".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        // A presence-authorized hop carries the bare proof reference.
        assert_eq!(v["presence_basis"], "presence-proof-ref-xyz");
        // Empty attenuation (pass-through) omits the axes array.
        assert!(v["attenuation"].get("axes_narrowed").is_none());
        let back: AuthorityDelegatedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
        assert_eq!(
            back.presence_basis,
            PresenceBasis::PresenceProof("presence-proof-ref-xyz".into())
        );
    }

    #[test]
    fn presence_basis_string_form_is_total_and_reversible() {
        // The inherited literal and any other string each round-trip through
        // the String wire form a verifier reads.
        let inherited: PresenceBasis = String::from(PRESENCE_BASIS_INHERITED_NARROWING).into();
        assert_eq!(inherited, PresenceBasis::InheritedNarrowing);
        let proof: PresenceBasis = String::from("some-other-ref").into();
        assert_eq!(proof, PresenceBasis::PresenceProof("some-other-ref".into()));
        assert_eq!(
            String::from(PresenceBasis::InheritedNarrowing),
            PRESENCE_BASIS_INHERITED_NARROWING
        );
    }

    #[test]
    fn kms_body_round_trips() {
        let body = KmsBody {
            key_id: "kek-default".into(),
            operation: "encrypt".into(),
            ciphertext_hash: "blake3:def456".into(),
            envelope_format: "AES-256-GCM-Ed25519".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: KmsBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn service_installed_body_round_trips() {
        let body = ServiceInstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            installed_by_persona_id: "persona-installer-001".into(),
            installation_policy: serde_json::json!({
                "lane": "buyer",
                "approval": "explicit"
            }),
            service_label: Some("GitHub".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: ServiceInstalledBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn service_uninstalled_body_round_trips() {
        let body = ServiceUninstalledBody {
            plugin_address: "registry.ember.systems/ember-systems/ember-gh".into(),
            plugin_version: "0.3.0".into(),
            publisher_id: "publisher-root-001".into(),
            uninstalled_by_persona_id: "persona-installer-001".into(),
            uninstall_reason: "operator_removed".into(),
            service_label: Some("GitHub".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: ServiceUninstalledBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn binding_body_round_trips() {
        let body = BindingBody {
            namespace: "ns-prod".into(),
            sa_name: "ml-eval".into(),
            persona_id: "persona-001".into(),
            persona_display_name: "ML Eval Worker".into(),
            scopes_granted: vec!["llm:generate".into()],
            binding_request_id: "br-001".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: BindingBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn seal_unsealed_body_round_trips() {
        let body = SealUnsealedBody {
            snapshot_id: "snap-001".into(),
            unsealed_at: "2026-05-02T20:00:00Z".into(),
            recovery_authority: "operator-biometric".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: SealUnsealedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn snapshot_emitted_body_round_trips() {
        let body = SnapshotEmittedBody {
            snapshot_id: "snap-002".into(),
            snapshot_hash: "blake3:ghi789".into(),
            emitted_at: "2026-05-02T20:00:00Z".into(),
            content_addressed_uri: "blob:tz-content/blake3/ghi789".into(),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: SnapshotEmittedBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn end_to_end_broker_mint_sign_verify() {
        let signer = FixtureSigner::new("receipt-v2-atomic-broker");
        let pk = signer.public_key();
        let body = BrokerMintBody {
            vault_key: "anthropic-key".into(),
            scope_template_id: "tier0-default".into(),
            scope_resolved: vec!["llm:generate".into()],
            ttl_seconds: 1800,
            expires_at: "2026-05-02T20:00:00Z".into(),
            revoke_token_hash: "blake3:abc".into(),
            granted_scope: vec![],
            requested_scope: vec![],
            minted_scope: vec![],
            mint_stamp: vec![],
            mint_stamp_kind: None,
            chain_ref: String::new(),
        };
        let mut env = ReceiptEnvelope {
            version: ReceiptVersion::default(),
            kind: RECEIPT_KIND_BROKER_MINT.to_string(),
            receipt_id: String::new(),
            daemon_root_id: "daemon-fixture".into(),
            traceparent: None,
            termination_authority: TerminationAuthority::UserSession,
            presence_kind: None,
            body: serde_json::to_value(&body).unwrap(),
            signature: None,
            calling_principal: None,
            presence_reason: None,
            handle_id: None,
            challenge_hash: None,
            verifier_aaguid: None,
        };
        sign_receipt_v2(&mut env, &signer).unwrap();
        verify_receipt_v2(&env, &pk, &core_crypto::FixtureVerifier).unwrap();
    }

    #[test]
    fn identity_rotation_witness_body_round_trips() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abcdef".into(),
            signature_by_next_root: "ed25519sig:fedcba".into(),
            rotation_reason: Some("scheduled".into()),
        };
        let v = serde_json::to_value(&body).unwrap();
        let back: IdentityRotationWitnessBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
    }

    #[test]
    fn identity_rotation_witness_rejects_same_epoch_ids() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-same".into(),
            next_epoch_root_id: "persona-epoch-same".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abc".into(),
            signature_by_next_root: "ed25519sig:def".into(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("identity rotation between equal epoch ids must be rejected");
        assert!(
            err.contains("prev_epoch_root_id"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn identity_rotation_witness_rejects_empty_prev_signature() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: String::new(),
            signature_by_next_root: "ed25519sig:def".into(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("empty signature_by_prev_root must be rejected");
        assert!(
            err.contains("signature_by_prev_root"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn identity_rotation_witness_rejects_empty_next_signature() {
        let body = IdentityRotationWitnessBody {
            prev_epoch_root_id: "persona-epoch-old".into(),
            next_epoch_root_id: "persona-epoch-new".into(),
            rotated_at_epoch_secs: 1_715_000_000,
            signature_by_prev_root: "ed25519sig:abc".into(),
            signature_by_next_root: String::new(),
            rotation_reason: None,
        };
        let err = body
            .validate()
            .expect_err("empty signature_by_next_root must be rejected");
        assert!(
            err.contains("signature_by_next_root"),
            "error must name the violated invariant; got {err}"
        );
    }

    fn sample_vault_mek_rotation() -> VaultMekRotationBody {
        VaultMekRotationBody {
            mode: "rekey".into(),
            prev_key_epoch: 0,
            new_key_epoch: 1,
            rewrap_count: 7,
            prev_mek_fingerprint: "blake3:aaaa".into(),
            new_mek_fingerprint: "blake3:bbbb".into(),
            snapshot_path: "/var/lib/ember/vault-snapshot-2026.emvs".into(),
            rotated_at_epoch_secs: 1_715_000_000,
        }
    }

    #[test]
    fn vault_mek_rotation_body_round_trips() {
        let body = sample_vault_mek_rotation();
        let v = serde_json::to_value(&body).unwrap();
        let back: VaultMekRotationBody = serde_json::from_value(v).unwrap();
        assert_eq!(body, back);
        assert!(body.validate().is_ok());
    }

    #[test]
    fn vault_mek_rotation_accepts_all_three_modes() {
        for mode in VaultMekRotationBody::MODES {
            let body = VaultMekRotationBody {
                mode: mode.into(),
                ..sample_vault_mek_rotation()
            };
            assert!(body.validate().is_ok(), "mode {mode} must validate");
        }
    }

    #[test]
    fn vault_mek_rotation_rejects_unknown_mode() {
        let body = VaultMekRotationBody {
            mode: "delete-everything".into(),
            ..sample_vault_mek_rotation()
        };
        let err = body.validate().expect_err("unknown mode must be rejected");
        assert!(
            err.contains("mode"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn vault_mek_rotation_rejects_non_monotonic_epoch() {
        // Same epoch (no advance) and skipping an epoch are both rejected.
        for (prev, new) in [(2u64, 2u64), (2, 4), (5, 0)] {
            let body = VaultMekRotationBody {
                prev_key_epoch: prev,
                new_key_epoch: new,
                ..sample_vault_mek_rotation()
            };
            let err = body
                .validate()
                .expect_err("non-monotonic-single-step epoch must be rejected");
            assert!(
                err.contains("key_epoch"),
                "error must name the violated invariant; got {err}"
            );
        }
    }

    #[test]
    fn vault_mek_rotation_rejects_unchanged_fingerprint() {
        let body = VaultMekRotationBody {
            prev_mek_fingerprint: "blake3:same".into(),
            new_mek_fingerprint: "blake3:same".into(),
            ..sample_vault_mek_rotation()
        };
        let err = body
            .validate()
            .expect_err("an unchanged MEK fingerprint must be rejected (no real rotation)");
        assert!(
            err.contains("fingerprint"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn vault_mek_rotation_rejects_empty_snapshot_path() {
        let body = VaultMekRotationBody {
            snapshot_path: String::new(),
            ..sample_vault_mek_rotation()
        };
        let err = body
            .validate()
            .expect_err("empty snapshot_path must be rejected (ADR 198 D4 snapshot-before-mutate)");
        assert!(
            err.contains("snapshot_path"),
            "error must name the violated invariant; got {err}"
        );
    }

    #[test]
    fn payment_evaluated_body_round_trips() {
        let body = PaymentEvaluatedBody {
            state: PaymentEvaluatedState::Reserved,
            attempt_id: "attempt-123".into(),
            statement_sid: "pay-main".into(),
            amount_cents: 49,
            vendor: "clearbit".into(),
            condition_path: Some("conditions[1].range(amount_cents)".into()),
            approval_request_id: None,
            reserved_until: Some("2026-05-26T12:00:00Z".into()),
            reason: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        let back: PaymentEvaluatedBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn payment_settled_body_round_trips() {
        let body = PaymentSettledBody {
            state: PaymentSettledState::Committed,
            attempt_id: "attempt-123".into(),
            statement_sid: "pay-main".into(),
            vendor: "clearbit".into(),
            final_amount_cents: Some(49),
            rail_reference: Some("rail-abc".into()),
            reason: None,
        };
        let json = serde_json::to_string(&body).unwrap();
        let back: PaymentSettledBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn proxy_call_body_round_trips() {
        let body = ProxyCallBody {
            persona_id: "persona-worker".into(),
            grant_id: "grant-123".into(),
            statement_sid: "S1".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            status: 200,
            tokens_in: 120,
            tokens_out: 192,
            tokens_total: 312,
            outcome: "complete".into(),
            observed_at: "2026-06-18T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&body).unwrap();
        let back: ProxyCallBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, body);
    }
}

#[cfg(test)]
mod proptests {
    //! T1 property tests for `IdentityRotationWitnessBody`.
    //!
    //! Every new body shape on a `core-*` crate ships at least one pure
    //! property test that exercises the documented Pre/Post conditions. Here the Post
    //! contract is "JCS canonicalize → serde round-trip preserves all
    //! fields"; the Pre contract is validated by the
    //! `validate_round_trip_witness_passes_validate` property.
    //!
    //! Anchor: `identity_rotation_witness_body_landed`.
    use super::*;
    use core_crypto::canonicalize_jcs;
    use proptest::prelude::*;

    fn arb_witness() -> impl Strategy<Value = IdentityRotationWitnessBody> {
        // Generate distinct prev/next epoch ids so the body is valid;
        // negative cases are covered by the unit tests above.
        (
            "[a-z0-9-]{1,32}",
            "[a-z0-9-]{1,32}",
            any::<u64>(),
            "ed25519sig:[a-f0-9]{2,64}",
            "ed25519sig:[a-f0-9]{2,64}",
            prop::option::of("[a-z_-]{1,32}"),
        )
            .prop_filter("prev/next epoch ids must differ", |t| t.0 != t.1)
            .prop_map(
                |(prev, next, ts, sig_p, sig_n, reason)| IdentityRotationWitnessBody {
                    prev_epoch_root_id: prev,
                    next_epoch_root_id: next,
                    rotated_at_epoch_secs: ts,
                    signature_by_prev_root: sig_p,
                    signature_by_next_root: sig_n,
                    rotation_reason: reason,
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Post-condition: JCS canonicalization is stable across the
        /// serde round-trip. Encoding the body, deserializing the JSON
        /// form, and re-encoding must produce byte-identical JCS
        /// output. Drift here invalidates persisted receipt-ids.
        #[test]
        fn jcs_round_trip_is_stable(body in arb_witness()) {
            let v1 = serde_json::to_value(&body).expect("serialize");
            let jcs1 = canonicalize_jcs(&v1).expect("jcs1");
            let back: IdentityRotationWitnessBody =
                serde_json::from_value(v1).expect("deserialize");
            prop_assert_eq!(&body, &back);
            let v2 = serde_json::to_value(&back).expect("re-serialize");
            let jcs2 = canonicalize_jcs(&v2).expect("jcs2");
            prop_assert_eq!(jcs1, jcs2);
        }

        /// Pre-condition: every body produced by the arb_witness
        /// generator satisfies `validate()`. This pins the generator
        /// to the valid region so the round-trip property does not
        /// accidentally exercise invariant-violating inputs.
        #[test]
        fn arb_witness_passes_validate(body in arb_witness()) {
            prop_assert!(body.validate().is_ok());
        }
    }

    fn arb_vault_mek_rotation() -> impl Strategy<Value = VaultMekRotationBody> {
        // Generate distinct prev/new fingerprints + a monotonic single-step
        // epoch so the body is valid; negative cases are covered by the unit
        // tests above.
        (
            prop::sample::select(VaultMekRotationBody::MODES.to_vec()),
            0u64..u64::MAX,
            any::<u64>(),
            "blake3:[a-f0-9]{2,64}",
            "blake3:[a-f0-9]{2,64}",
            "/[a-z0-9/._-]{1,64}",
            any::<u64>(),
        )
            .prop_filter("prev/new fingerprints must differ", |t| t.3 != t.4)
            .prop_map(|(mode, prev_epoch, rewrap, fp_prev, fp_new, snap, ts)| {
                VaultMekRotationBody {
                    mode: mode.to_string(),
                    prev_key_epoch: prev_epoch,
                    new_key_epoch: prev_epoch + 1,
                    rewrap_count: rewrap,
                    prev_mek_fingerprint: fp_prev,
                    new_mek_fingerprint: fp_new,
                    snapshot_path: snap,
                    rotated_at_epoch_secs: ts,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Post-condition: JCS canonicalization is stable across the serde
        /// round-trip for `VaultMekRotationBody` (mirrors the witness
        /// property — drift invalidates persisted receipt-ids).
        ///
        /// Anchor: `vault_mek_rotation_body_landed`.
        #[test]
        fn vault_mek_rotation_jcs_round_trip_is_stable(body in arb_vault_mek_rotation()) {
            let v1 = serde_json::to_value(&body).expect("serialize");
            let jcs1 = canonicalize_jcs(&v1).expect("jcs1");
            let back: VaultMekRotationBody =
                serde_json::from_value(v1).expect("deserialize");
            prop_assert_eq!(&body, &back);
            let v2 = serde_json::to_value(&back).expect("re-serialize");
            let jcs2 = canonicalize_jcs(&v2).expect("jcs2");
            prop_assert_eq!(jcs1, jcs2);
        }

        /// Pre-condition: every body produced by the generator satisfies
        /// `validate()`. Pins the generator to the valid region.
        #[test]
        fn arb_vault_mek_rotation_passes_validate(body in arb_vault_mek_rotation()) {
            prop_assert!(body.validate().is_ok());
        }
    }
}
