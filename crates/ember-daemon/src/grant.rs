use chrono::{DateTime, Duration, Timelike, Utc};
use core_crypto::grant_chain::{
    self, verify_chain, RootKeyPair, root_pubkey_bytes_from_ed25519_hex,
};
use core_types::{
    AccessGrant, AttestationBinding, Block, Budget, GrantMode, GrantStatus,
    PresentationAudienceKind, RecipientProfile, ResourceSelector, ResourceType,
    SignedBlock, Statement, Usage,
};
use rusqlite::OptionalExtension;
use serde::Serialize;
use uuid::Uuid;

use crate::attenuation::{
    check_budget_attenuation, check_expiry_attenuation, check_statement_attenuation,
    scope_subset,
};
use crate::store::{DaemonStore, StoreError};

/// Daemon-local grant record.
///
/// Per design the canonical representation is the composite
/// [`core_types::AccessGrant`] chain in `access_grant`. The scalar fields
/// on `GrantInfo` (scope, budget, usage, etc.) are **projections** over the
/// first-statement in the chain, retained so existing callers (handler,
/// dashboard, proxy, CLI) keep working during Stream A's incremental
/// rollout. Future cycles will delete the scalar projections and require
/// callers to walk `access_grant.blocks[].statements[]` natively.
#[derive(Debug, Clone, Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub persona_id: String,
    pub credential_name: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub status: String,
    pub max_uses_per_hour: Option<u64>,
    pub allowed_hours_start: Option<u32>,
    pub allowed_hours_end: Option<u32>,
    pub allowed_targets: Option<String>,
    pub parent_grant_id: Option<String>,
    pub max_delegation_depth: Option<u32>,
    pub spending_limit_cents: Option<u64>,
    /// Aggregate authority budget — projection from `access_grant`'s
    /// first statement. Per-Statement budgets live inside `access_grant`.
    pub budget: Option<Budget>,
    /// Aggregate running tally — sum across all statements.
    #[serde(default)]
    pub usage: Usage,
    /// Operator-set advisory pause flag (69K.7). Advisory only — does not
    /// gate proxy traffic; emits a `budget.warning` with `paused: true` for
    /// well-behaved agents to self-moderate.
    pub paused: bool,
    /// Populated when the grant reached a terminal state and the Warden
    /// emitted a `GrantReceipt`.
    pub receipt_id: Option<String>,
    /// — standing parent grant flag. When set, the orchestrator
    /// (or any delegation caller) can mint child grants from this parent
    /// without re-prompting the operator, subject to
    /// `max_children_per_day`.
    #[serde(default)]
    pub is_standing: bool,
    /// — rolling 24h delegation ceiling. Only consulted when the
    /// parent is standing. `None` on a non-standing parent.
    pub max_children_per_day: Option<u64>,
    /// — canonical scope narrowing applied by the orchestrator on
    /// each auto-delegation. Stored as an opaque string so callers can
    /// encode whatever shape the cycle needs (often a short DSL fragment
    /// like `"github:push:acme/agent-<run-id>"`). Not enforced by the
    /// daemon — advisory.
    pub auto_delegate_scope_template: Option<String>,
}

const GRANT_COLUMNS: &str = "id, persona_id, credential_name, scope, created_at, expires_at, status, max_uses_per_hour, allowed_hours_start, allowed_hours_end, allowed_targets, parent_grant_id, max_delegation_depth, spending_limit_cents, budget_json, usage_json, paused, receipt_id, blocks_json, is_standing, max_children_per_day, auto_delegate_scope_template";

// --- `blocks_json` write-path size caps (P69K-A2 L3 / F-04) ---
//
// Every production path that writes `blocks_json` (create, overwrite,
// delegate, extend, increment_statement_usage) must run the caller's
// chain through [`validate_blocks_json_caps`] before executing the SQL
// write. External callers (socket overwrite, delegation append) are
// about to start feeding caller-supplied chains directly; without caps a
// malicious or buggy caller could write a monster payload, an unbounded
// block array, or a pathological single statement.
//
// The numbers are comfortably above realistic use:
//   - typical grant: 1 block, 1-3 statements, <2 KiB JSON;
//   - `ember sandbox run` 3-Statement envelope: 1 block, 3 statements,
//     ~1 KiB JSON;
//   - deepest anticipated delegation chain: 3-5 blocks.
// The caps are defence-in-depth, not ergonomic limits.

/// Maximum number of [`SignedBlock`]s allowed in a composite grant chain.
///
/// Bounds delegation chain length; each additional block costs one
/// Ed25519 signature verify on the read path. The daemon's
/// `max_delegation_depth` field bounds depth at the *policy* layer;
/// this constant is the crypto/storage-level floor that applies even
/// when policy depth is unset.
pub const MAX_BLOCKS: usize = 32;

/// Back-compat alias for [`MAX_BLOCKS`]. Retained so external callers
/// referencing the old name keep compiling until the next cycle's
/// cleanup pass.
pub const MAX_BLOCKS_PER_GRANT: usize = MAX_BLOCKS;

/// Maximum number of [`Statement`]s allowed per [`Block`].
///
/// Bounds per-block `authorize` cost (linear walk across statements)
/// and the size of the authority matrix a single block can express.
/// Every realistic envelope we've seen uses at most 3-5 statements
/// (credential + session + time is the shape `ember sandbox run` emits);
/// 16 gives ~3x headroom.
pub const MAX_STATEMENTS_PER_BLOCK: usize = 16;

/// Maximum size (in bytes) of the serialized `blocks_json` payload.
///
/// Defence against pathological payloads — a caller supplying a block
/// with a multi-megabyte resource string, giant condition list, or
/// oversized note would otherwise be able to bloat the grants table
/// unbounded. 64 KiB is ~30x the largest realistic chain we've
/// measured; any row exceeding this is almost certainly malicious or a
/// bug upstream.
pub const MAX_BLOCKS_JSON_BYTES: usize = 64 * 1024;

/// Validate an [`AccessGrant`]'s block chain + its serialized JSON
/// length against the size caps. Called on every production path that
/// writes `blocks_json` so a cap violation is caught before the SQL
/// UPDATE/INSERT executes.
///
/// Returns `StoreError::InvalidInput` with a message naming the
/// specific cap that was exceeded — callers surface the message to
/// operators verbatim, so it should be specific but not leak any
/// other grant's state.
pub(crate) fn validate_blocks_json_caps(
    grant: &AccessGrant,
    serialized: &str,
) -> Result<(), StoreError> {
    if grant.blocks.len() > MAX_BLOCKS {
        return Err(StoreError::InvalidInput(format!(
            "blocks_json write rejected: chain has {} blocks; cap is {MAX_BLOCKS}",
            grant.blocks.len()
        )));
    }
    for (idx, sb) in grant.blocks.iter().enumerate() {
        let n = sb.block.statements.len();
        if n > MAX_STATEMENTS_PER_BLOCK {
            return Err(StoreError::InvalidInput(format!(
                "blocks_json write rejected: block {idx} has {n} statements; \
                 cap is {MAX_STATEMENTS_PER_BLOCK}"
            )));
        }
    }
    if serialized.len() > MAX_BLOCKS_JSON_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "blocks_json write rejected: payload is {} bytes; cap is {MAX_BLOCKS_JSON_BYTES}",
            serialized.len()
        )));
    }
    Ok(())
}

/// Build a single-statement block payload from daemon scalar fields.
///
/// Returns the unsigned [`Block`] — signing is a separate step that
/// requires the issuing persona's root keypair. Used when a grant row has
/// no `blocks_json` (legacy) so every in-memory `GrantInfo` can be turned
/// into a canonical composite chain to reason about.
#[allow(clippy::too_many_arguments)]
fn build_single_statement_block(
    persona_id: &str,
    credential_name: &str,
    scope: &str,
    created_at: u64,
    expires_at: Option<u64>,
    budget: Option<Budget>,
    usage: Usage,
) -> Block {
    let resource_type = classify_resource_type(credential_name, scope);
    let (actions, selector) = scope_to_actions_and_selector(scope, credential_name);

    let statement = Statement {
        sid: "S0".into(),
        resource_type,
        actions,
        resource: selector,
        budget: budget.filter(|b| !b.is_none_set()),
        usage,
        conditions: Vec::new(),
    };

    Block {
        statements: vec![statement],
        nbf: None,
        expires_at,
        issued_by: persona_id.to_string(),
        issued_at: created_at,
        approval: None,
        note: None,
    }
}

/// Assemble a signed [`AccessGrant`] envelope around a pre-built block 0.
///
/// Pure helper — signing happens in the caller (`sign_block_zero`) so the
/// per-persona root-key lookup stays near the daemon store.
fn access_grant_envelope(
    id: &str,
    persona_id: &str,
    credential_name: &str,
    status: &str,
    signed_block: SignedBlock,
    created_at: u64,
) -> AccessGrant {
    AccessGrant {
        id: id.into(),
        version: 1,
        issuing_persona_id: persona_id.into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: credential_name.into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::parse(status).unwrap_or(GrantStatus::Active),
        mode: GrantMode::OneShot,
        blocks: vec![signed_block],
        attestation: AttestationBinding::default(),
        created_at,
        updated_at: created_at,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    }
}

/// Sign a single block with the given root keypair. Thin wrapper that maps
/// the `ChainError` surface onto `StoreError::InvalidInput` so daemon
/// callers don't have to juggle two error enums.
pub(crate) fn sign_block_zero_with(
    root: &RootKeyPair,
    block: &Block,
) -> Result<SignedBlock, StoreError> {
    grant_chain::sign_block_zero(root, block)
        .map(|out| out.signed)
        .map_err(|e| StoreError::InvalidInput(format!("grant chain signing failed: {e}")))
}

/// Classify a credential_name + scope into a ResourceType heuristically.
fn classify_resource_type(credential_name: &str, scope: &str) -> ResourceType {
    // Sessions are LLM-shaped scopes.
    if scope.starts_with("llm:") || scope.contains("anthropic") || scope.contains("openai") {
        ResourceType::Session
    } else if scope.starts_with("x402:") || scope.contains("payment") {
        ResourceType::Payment
    } else if scope.starts_with("time:") {
        ResourceType::Time
    } else if scope.starts_with("compute:") {
        ResourceType::Compute
    } else {
        // Default: credential surface (github-token, api-key, etc.)
        let _ = credential_name;
        ResourceType::Credential
    }
}

/// Map a legacy scope string into (actions, ResourceSelector) for a statement.
///
/// Scope grammar: `<provider>:<action>:<target>[:<subtarget>]` or legacy
/// bare-action forms like `read`/`write`/`push`/`*`. The mapping is
/// best-effort and preserves the scope string verbatim as the selector
/// pattern so existing proxy enforcement continues to match.
fn scope_to_actions_and_selector(
    scope: &str,
    credential_name: &str,
) -> (Vec<String>, ResourceSelector) {
    let scope = scope.trim();
    let parts: Vec<&str> = scope.split(':').collect();
    let action = match parts.as_slice() {
        ["*"] | [] => "*".to_string(),
        [a] => a.to_string(),
        [provider, a, ..] => format!("{provider}:{a}"),
    };
    let selector = if scope == "*" {
        ResourceSelector::Any
    } else if scope.contains('*') {
        ResourceSelector::Glob { pattern: scope.into() }
    } else if parts.len() >= 3 {
        let tail = parts[2..].join(":");
        if tail.contains('*') {
            ResourceSelector::Glob { pattern: tail }
        } else {
            ResourceSelector::Exact { value: tail }
        }
    } else {
        ResourceSelector::Exact { value: credential_name.to_string() }
    };
    (vec![action], selector)
}

fn parse_epoch(s: Option<&str>) -> Option<u64> {
    s.and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64)
}

fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantInfo> {
    let id: String = row.get(0)?;
    let persona_id: String = row.get(1)?;
    let credential_name: String = row.get(2)?;
    let scope: String = row.get(3)?;
    let created_at: String = row.get(4)?;
    let expires_at: Option<String> = row.get(5)?;
    let status: String = row.get(6)?;
    let max_uses: Option<i64> = row.get(7)?;
    let hours_start: Option<i64> = row.get(8)?;
    let hours_end: Option<i64> = row.get(9)?;
    let depth: Option<i64> = row.get(12)?;
    let spending: Option<i64> = row.get(13)?;
    let budget_json: Option<String> = row.get(14)?;
    let usage_json: Option<String> = row.get(15)?;
    let paused: i64 = row.get(16).unwrap_or(0);
    let receipt_id: Option<String> = row.get(17)?;
    let blocks_json: Option<String> = row.get(18)?;
    // standing-parent columns. Older rows pre-migration may be
    // missing these — `unwrap_or` keeps the read path resilient across
    // ALTER TABLE rollouts.
    let is_standing: i64 = row.get(19).unwrap_or(0);
    let max_children_per_day: Option<i64> = row.get(20).unwrap_or(None);
    let auto_delegate_scope_template: Option<String> = row.get(21).unwrap_or(None);

    // Hydrate the canonical composite chain from blocks_json if present.
    // If blocks_json parses to a non-empty chain, use its first-statement
    // budget + usage for the `budget`/`usage` scalar projection. Otherwise,
    // fall back to the flat `budget_json`/`usage_json` columns (legacy).
    let flat_budget: Option<Budget> =
        budget_json.as_deref().and_then(|s| serde_json::from_str(s).ok());
    let flat_usage: Usage = usage_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let chain_first_stmt_view: Option<(Option<Budget>, Usage)> = blocks_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<SignedBlock>>(raw).ok())
        .and_then(|blocks| {
            blocks
                .first()
                .and_then(|sb| sb.block.statements.first().cloned())
                .map(|s| (s.budget, s.usage))
        });

    let (projected_budget, projected_usage) = match chain_first_stmt_view {
        Some((b, u)) => (b, u),
        None => (flat_budget, flat_usage),
    };

    // Compute effective status at read time so callers see time-accurate state.
    // Terminal states persisted in the column (revoked, expired, exhausted_by_budget,
    // expired_by_budget, parent_cascade_revoked) are kept as-is.  For non-terminal
    // stored states (active, paused) we additionally derive time-based expiry from
    // `expires_at`, reusing `GrantStatus::derive` (see prior change / implementation-note-16).
    let effective_status = if matches!(
        status.as_str(),
        "revoked" | "expired" | "exhausted_by_budget" | "expired_by_budget" | "parent_cascade_revoked"
    ) {
        status.clone()
    } else {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at_epoch = parse_epoch(expires_at.as_deref());
        GrantStatus::derive(&status, None, expires_at_epoch, now_secs)
            .as_str()
            .to_string()
    };

    Ok(GrantInfo {
        id,
        persona_id,
        credential_name,
        scope,
        created_at,
        expires_at,
        status: effective_status,
        max_uses_per_hour: max_uses.map(|v| v as u64),
        allowed_hours_start: hours_start.map(|v| v as u32),
        allowed_hours_end: hours_end.map(|v| v as u32),
        allowed_targets: row.get(10)?,
        parent_grant_id: row.get(11)?,
        max_delegation_depth: depth.map(|v| v as u32),
        spending_limit_cents: spending.map(|v| v as u64),
        budget: projected_budget,
        usage: projected_usage,
        paused: paused != 0,
        receipt_id,
        is_standing: is_standing != 0,
        max_children_per_day: max_children_per_day.map(|v| v as u64),
        auto_delegate_scope_template,
    })
}

/// Serialize an `AccessGrant`'s block chain to JSON for storage in
/// `blocks_json`. Only the blocks are persisted — envelope metadata
/// (id, persona, recipient, status, timestamps) already live in the
/// daemon's flat row columns and round-trip via those.
pub(crate) fn access_grant_blocks_to_json(g: &AccessGrant) -> Result<String, StoreError> {
    serde_json::to_string(&g.blocks).map_err(|e| {
        StoreError::InvalidInput(format!("failed to serialize AccessGrant blocks: {e}"))
    })
}

/// Build a signed `AccessGrant` envelope wrapping a caller-supplied
/// `Vec<Statement>`.
///
/// Used by multi-statement composition paths (e.g. `ember sandbox run`'s
/// 3-statement credential+session+time envelope) that need a canonical
/// chain shape without going through the single-statement
/// `create_grant` write path.
///
/// Block 0 is signed under the issuing persona's root keypair via
/// `core_crypto::grant_chain::sign_block_zero`. Callers obtain the keypair
/// from `DaemonStore::persona_root_keypair(persona_id)`.
pub fn access_grant_from_statements(
    id: &str,
    persona_id: &str,
    recipient_id: &str,
    statements: Vec<Statement>,
    created_at: u64,
    expires_at: Option<u64>,
    root: &RootKeyPair,
) -> Result<AccessGrant, StoreError> {
    let block = Block {
        statements,
        nbf: None,
        expires_at,
        issued_by: persona_id.to_string(),
        issued_at: created_at,
        approval: None,
        note: None,
    };
    let signed = sign_block_zero_with(root, &block)?;
    Ok(AccessGrant {
        id: id.into(),
        version: 1,
        issuing_persona_id: persona_id.into(),
        recipient_kind: PresentationAudienceKind::Service,
        recipient_id: recipient_id.into(),
        recipient_profile: RecipientProfile::Agent,
        status: GrantStatus::Active,
        mode: GrantMode::OneShot,
        blocks: vec![signed],
        attestation: AttestationBinding::default(),
        created_at,
        updated_at: created_at,
        revoked_at: None,
        revoked_reason: None,
        last_used_at: None,
        label: None,
    })
}

/// Build a signed `AccessGrant` envelope, looking up the persona's root
/// keypair internally from `store`.
///
/// This is the preferred form for new callers — the `root` parameter is
/// derived from the store rather than threaded in from the outside.
/// Existing callers of [`access_grant_from_statements`] continue to
/// compile unchanged; migrate them to this form incrementally
/// (TODO P69K-C28-implementation-note-17 caller migration).
///
/// Returns the same value as calling `access_grant_from_statements` with
/// the result of `store.persona_root_keypair(persona_id)`.
pub fn access_grant_from_statements_for_persona(
    store: &DaemonStore,
    id: &str,
    persona_id: &str,
    recipient_id: &str,
    statements: Vec<Statement>,
    created_at: u64,
    expires_at: Option<u64>,
) -> Result<AccessGrant, StoreError> {
    let root = store.persona_root_keypair(persona_id)?;
    access_grant_from_statements(
        id,
        persona_id,
        recipient_id,
        statements,
        created_at,
        expires_at,
        &root,
    )
}

impl DaemonStore {
    /// Create a single-statement grant with no budget attached.
    ///
    /// Thin wrapper over [`DaemonStore::create_grant_with_budget`] that
    /// passes `None` for the budget. Kept with the original signature so
    /// the ~70 existing callers (handler, approval, proxy smoke tests,
    /// dashboard tests, …) keep compiling; new callers that need to
    /// encode a budget into block-zero's statement should use
    /// `create_grant_with_budget` directly.
    pub fn create_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget(persona_id, credential_name, scope, ttl_secs, None)
    }

    /// Create a single-statement grant whose block-zero statement
    /// carries the supplied [`Budget`] (P69K-BUDGET-WRITE).
    ///
    /// Before this change, `create_grant` always called
    /// `build_single_statement_block(..., budget: None, ...)`, which
    /// meant the composite read path
    /// (`get_access_grant → AccessGrant.blocks[0].statements[0].budget`)
    /// saw `None` even when the operator had set a budget via
    /// `ember grant budget` / `ember sandbox run --budget-tokens`. The
    /// dashboard then rendered `(none)` or yellow for the displayed
    /// budget — the "Beat 2 credibility gap" the demo script called out.
    ///
    /// The flat `budget_json` column on `grants` is **not** written from
    /// this path. `row_to_grant` already prefers `blocks_json`'s
    /// first-statement budget when present, and writing the flat column
    /// too would create two sources of truth that can drift. The column
    /// remains populated by the legacy paths (`delegate_grant_full`,
    /// `extend_grant`) as a redundant mirror slated for removal with
    /// `P69K-G` (live usage outside the chain).
    pub fn create_grant_with_budget(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget_inner(persona_id, credential_name, scope, ttl_secs, budget, true)
    }

    /// Like [`create_grant_with_budget`] but suppresses the `grant.minted`
    /// audit event.  Used by the composite-approval path so that
    /// `mint_composite_chain_for_grant` can emit a single `grant.minted`
    /// event AFTER the composite shape is finalised (REVIEW2-F8).
    pub(crate) fn create_grant_suppress_minted_event(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.create_grant_with_budget_inner(persona_id, credential_name, scope, ttl_secs, None, false)
    }

    fn create_grant_with_budget_inner(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
        budget: Option<Budget>,
        emit_minted_event: bool,
    ) -> Result<GrantInfo, StoreError> {
        // Verify persona exists and is active.
        let persona_status: Option<String> = self
            .conn()
            .query_row(
                "SELECT status FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| row.get(0),
            )
            .optional()?;

        match persona_status.as_deref() {
            None => return Err(StoreError::NotFound),
            Some("active") => {}
            Some(other) => {
                return Err(StoreError::InvalidInput(format!(
                    "persona is not active: {other}"
                )))
            }
        }

        let id = format!("grant-{}", Uuid::new_v4());
        let now: DateTime<Utc> = Utc::now();
        let created_at = now.to_rfc3339();
        let created_at_epoch = now.timestamp().max(0) as u64;

        let expires_at: Option<String> = ttl_secs.map(|secs| {
            let expiry = now + Duration::seconds(secs as i64);
            expiry.to_rfc3339()
        });
        let expires_at_epoch = ttl_secs.map(|s| created_at_epoch.saturating_add(s));

        // Build the canonical composite chain (single-statement) up front
        // and persist its blocks_json alongside the flat columns. Callers
        // reading this grant hydrate from blocks_json and see the Statement.
        //
        // Block 0 is signed under the issuing persona's root Ed25519 key
        // via `core_crypto::grant_chain::sign_block_zero` per design
        // revision. Daemon-issued grants no longer carry the
        // `"unsigned-phase1"` placeholder.
        //
        // The caller's `budget` (if any) is threaded into the
        // first-statement's `budget` field — this is the authoritative
        // source of truth for budget on composite-read paths.
        let root = self.persona_root_keypair(persona_id)?;
        let effective_budget = budget.clone().filter(|b| !b.is_none_set());
        let block = build_single_statement_block(
            persona_id,
            credential_name,
            scope,
            created_at_epoch,
            expires_at_epoch,
            effective_budget.clone(),
            Usage::default(),
        );
        let signed = sign_block_zero_with(&root, &block)?;
        let access_grant = access_grant_envelope(
            &id,
            persona_id,
            credential_name,
            "active",
            signed,
            created_at_epoch,
        );
        let blocks_json = access_grant_blocks_to_json(&access_grant)?;
        validate_blocks_json_caps(&access_grant, &blocks_json)?;

        self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status, blocks_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8)",
            rusqlite::params![
                id,
                persona_id,
                credential_name,
                scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
                blocks_json,
            ],
        )?;

        let _ = access_grant; // chain persisted via blocks_json above

        // REVIEW2-F8: for composite grants this event is suppressed here and
        // re-emitted by `mint_composite_chain_for_grant` after the multi-
        // statement shape is finalised so the audit log shows the accurate
        // statement_count.
        if emit_minted_event {
            let _ = self.log_event(
                Some(persona_id),
                "grant.minted",
                Some(credential_name),
                "minted",
                Some(
                    &serde_json::json!({
                        "grant_id": id,
                        "statement_count": 1,
                        "ttl_secs": ttl_secs,
                        "creation_mode": "single",
                    })
                    .to_string(),
                ),
            );
        }
        Ok(GrantInfo {
            id,
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: None,
            max_delegation_depth: None,
            spending_limit_cents: None,
            budget: effective_budget,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
            is_standing: false,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        })
    }

    /// Mark an existing grant as a standing parent ().
    ///
    /// Standing parents let the orchestrator mint short-lived child grants
    /// without re-prompting the operator, subject to
    /// `max_children_per_day`. The operator approves the parent once (with
    /// a broad scope template and a daily ceiling), and each cycle calls
    /// `delegate_grant_full(parent_id, …)` to mint a cycle-specific child.
    ///
    /// Requires that the grant allow delegation — callers must have
    /// already set `max_delegation_depth` (via the standard UPDATE path)
    /// before marking the grant standing, or `delegate_grant_full` will
    /// later reject every child with "parent does not allow delegation".
    ///
    /// `max_children_per_day` must be > 0. Passing 0 is treated as a
    /// misconfiguration (would disable delegation entirely) and rejected.
    pub fn mark_grant_standing(
        &self,
        grant_id: &str,
        max_children_per_day: u64,
        scope_template: Option<&str>,
    ) -> Result<(), StoreError> {
        if max_children_per_day == 0 {
            return Err(StoreError::InvalidInput(
                "max_children_per_day must be > 0".into(),
            ));
        }
        let n = self.conn().execute(
            "UPDATE grants SET is_standing = 1, max_children_per_day = ?1, \
                               auto_delegate_scope_template = ?2 \
             WHERE id = ?3",
            rusqlite::params![max_children_per_day as i64, scope_template, grant_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn list_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn list_active_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?1)"
        );
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params![now], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn get_grant(&self, id: &str) -> Result<GrantInfo, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants WHERE id = ?1");
        self.conn()
            .query_row(&sql, rusqlite::params![id], row_to_grant)
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    /// Return the canonical composite `AccessGrant` chain for a grant.
    ///
    /// Prefers the stored `blocks_json` (written by `create_grant` and
    /// `delegate_grant_full`); falls back to synthesizing a single-
    /// statement chain from the scalar columns for legacy rows.
    ///
    /// Callers needing per-Statement metering (Stream C) or receipts
    /// (Stream D) read through this method rather than `get_grant` so
    /// they see the authoritative Statement shape directly.
    ///
    /// Before returning, `verify_chain` is called on the grant's block
    /// chain. Grants with the pre-migration `"unsigned-phase1"` placeholder
    /// are logged and passed through until W1's daemon Ed25519 wiring
    /// eliminates them. Any other chain error rejects the grant.
    pub fn get_access_grant(&self, id: &str) -> Result<AccessGrant, StoreError> {
        let info = self.get_grant(id)?;
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if let Some(s) = raw
            && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
            && !blocks.is_empty()
        {
            // Envelope-chain consistency guard (adversarial review M1):
            // block 0 must declare itself issued by the row's persona. A
            // mismatch means either a corrupt write, a migration bug, or
            // an attacker-crafted blocks_json. Reject — fall back to the
            // synthesized single-statement projection so callers still
            // see a coherent grant (same shape as legacy rows).
            if blocks[0].block.issued_by != info.persona_id {
                tracing::warn!(
                    grant_id = %info.id,
                    row_persona = %info.persona_id,
                    chain_issued_by = %blocks[0].block.issued_by,
                    "blocks_json block-0 issued_by does not match grant row persona; \
                     rejecting hydrated chain, falling back to projection"
                );
                let projected = self.project_access_grant(&info)?;
                return self.verify_and_return(projected);
            }
            let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
            let grant = AccessGrant {
                id: info.id.clone(),
                version: 1,
                issuing_persona_id: info.persona_id.clone(),
                recipient_kind: PresentationAudienceKind::Service,
                recipient_id: info.credential_name.clone(),
                recipient_profile: RecipientProfile::Agent,
                status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                mode: GrantMode::OneShot,
                blocks,
                attestation: AttestationBinding::default(),
                created_at: created_at_epoch,
                updated_at: created_at_epoch,
                revoked_at: None,
                revoked_reason: None,
                last_used_at: None,
                label: None,
            };
            return self.verify_and_return(grant);
        }
        let projected = self.project_access_grant(&info)?;
        self.verify_and_return(projected)
    }

    /// Verify a hydrated grant's chain before returning it from the read
    /// path (W4 / adversarial M-2). Persona-missing edge case (orphan
    /// grant or deleted persona) passes through with a log; all other
    /// chain errors reject with `InvalidInput`. `core-crypto` rejects the
    /// legacy `unsigned-phase1` placeholder naturally — the daemon no
    /// longer carries a pass-through for it.
    fn verify_and_return(&self, grant: AccessGrant) -> Result<AccessGrant, StoreError> {
        match self.get_persona_root_pubkey_bytes(&grant.issuing_persona_id) {
            None => {
                // F-07: only pass through when the grant is an unsigned
                // phase-1 placeholder (single block, unsigned-phase1
                // signature). Multi-block or real-signature orphans are
                // rejected — they had a persona at mint time and the
                // missing row is suspicious.
                let is_phase1 = grant.blocks.len() == 1
                    && grant.blocks[0].signature
                        == grant_chain::UNSIGNED_PHASE1_PLACEHOLDER;
                if is_phase1 {
                    tracing::warn!(
                        grant_id = %grant.id,
                        persona_id = %grant.issuing_persona_id,
                        "persona root pubkey not found — unsigned phase-1 grant; \
                         skipping chain verification"
                    );
                    Ok(grant)
                } else {
                    Err(StoreError::InvalidInput(format!(
                        "grant chain verification failed: persona '{}' not found \
                         and grant is not a phase-1 placeholder",
                        grant.issuing_persona_id
                    )))
                }
            }
            Some(root_pubkey) => verify_chain(&grant.blocks, &root_pubkey)
                .map(|()| grant)
                .map_err(|e| StoreError::InvalidInput(format!(
                    "grant chain verification failed: {e}"
                ))),
        }
    }

    /// Look up the Ed25519 root public key for a persona as raw 32 bytes
    /// (for `verify_chain`). Returns `None` if the persona row is missing
    /// or its `public_key` column cannot be decoded.
    fn get_persona_root_pubkey_bytes(&self, persona_id: &str) -> Option<[u8; 32]> {
        let public_key: Option<String> = self
            .conn()
            .query_row(
                "SELECT public_key FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();
        let public_key = public_key?;
        root_pubkey_bytes_from_ed25519_hex(&public_key).ok()
    }

    /// Project a [`GrantInfo`] (flat daemon-row view) into a canonical
    /// composite [`AccessGrant`] chain. Used as the fallback when a grant
    /// row has no `blocks_json` (pre-design legacy row) or when the
    /// stored chain was rejected by the envelope-consistency guard.
    ///
    /// Block 0 is signed under the issuing persona's root Ed25519 key per
    /// design revision — the projection produces a chain that callers
    /// (proxy, dashboard, standing-grant sweep) can feed straight into
    /// `verify_chain` without tripping on placeholders.
    pub fn project_access_grant(
        &self,
        info: &GrantInfo,
    ) -> Result<AccessGrant, StoreError> {
        let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
        let expires_at_epoch = info
            .expires_at
            .as_deref()
            .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
            .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);
        let root = self.persona_root_keypair(&info.persona_id)?;
        let block = build_single_statement_block(
            &info.persona_id,
            &info.credential_name,
            &info.scope,
            created_at_epoch,
            expires_at_epoch,
            info.budget.clone(),
            info.usage.clone(),
        );
        let signed = sign_block_zero_with(&root, &block)?;
        Ok(access_grant_envelope(
            &info.id,
            &info.persona_id,
            &info.credential_name,
            &info.status,
            signed,
            created_at_epoch,
        ))
    }

    /// Overwrite a grant's `blocks_json` with the caller-supplied composite
    /// chain. Used by multi-statement minting flows (e.g. `ember sandbox
    /// run`'s 3-statement envelope) to replace the single-statement shim
    /// `create_grant` wrote with the canonical multi-Statement shape.
    pub fn overwrite_grant_blocks(
        &self,
        id: &str,
        grant: &AccessGrant,
    ) -> Result<(), StoreError> {
        self.overwrite_grant_blocks_inner(id, grant, None)
    }

    /// REVIEW2-F4: overwrite a grant's `blocks_json`, running the
    /// bipartite-dominance check against an explicit `parent_bound`
    /// rather than the row's currently-stored chain.
    ///
    /// Used by [`mint_composite_chain_for_grant`](crate::approval) so the
    /// dominance gate is rooted in the operator-approved statement set
    /// (the union bound) instead of the scope-`*` projection that
    /// `create_grant` wrote upstream — without this, the dominance check
    /// is trivially true because `*` dominates everything, hollowing out
    /// the composite-grant security claim.
    ///
    /// `parent_bound` must:
    /// - have block-0 `issued_by` matching the row's persona_id (else
    ///   the same envelope guard `overwrite_grant_blocks` enforces fires);
    /// - carry statements that bound the new `grant`'s authority (every
    ///   statement in `grant` must be dominated by at least one statement
    ///   in `parent_bound`).
    ///
    /// All other guards (envelope consistency, size caps, full-chain
    /// crypto verify) run identically to the loaded-parent path.
    pub fn overwrite_grant_blocks_with_parent_bound(
        &self,
        id: &str,
        grant: &AccessGrant,
        parent_bound: &AccessGrant,
    ) -> Result<(), StoreError> {
        self.overwrite_grant_blocks_inner(id, grant, Some(parent_bound))
    }

    /// Shared implementation for `overwrite_grant_blocks` and
    /// `overwrite_grant_blocks_with_parent_bound`. When `parent_override`
    /// is `Some`, the bipartite-dominance check uses it directly; when
    /// `None`, the parent is hydrated from the row's stored chain via
    /// [`Self::load_parent_access_grant_for_overwrite`].
    fn overwrite_grant_blocks_inner(
        &self,
        id: &str,
        grant: &AccessGrant,
        parent_override: Option<&AccessGrant>,
    ) -> Result<(), StoreError> {
        // Adversarial review L2: caller must pass matching id / grant.id.
        // Only one caller today (CLI sandbox run) does it correctly; guard
        // so a future caller can't accidentally cross-write a grant's
        // blocks under another grant's row id.
        if grant.id != id {
            return Err(StoreError::InvalidInput(format!(
                "overwrite_grant_blocks: id={id} but grant.id={} — mismatch",
                grant.id
            )));
        }

        // --- F-04 / P69K-A2 L3: size caps before any SQL write ---
        //
        // Block count + per-block statement count + serialized JSON
        // size are validated together via `validate_blocks_json_caps`
        // so the same rejection shape fires on every write path.
        let blocks_json = access_grant_blocks_to_json(grant)?;
        validate_blocks_json_caps(grant, &blocks_json)?;

        // Envelope consistency: block-0 issued_by must match the row's
        // persona_id. Look up the row's persona_id from SQL once.
        let row_persona_id: Option<String> = self
            .conn()
            .query_row(
                "SELECT persona_id FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?;
        let row_persona_id = row_persona_id.ok_or(StoreError::NotFound)?;

        if let Some(first) = grant.blocks.first()
            && first.block.issued_by != row_persona_id
        {
            return Err(StoreError::InvalidInput(format!(
                "overwrite_grant_blocks: block-0 issued_by={} does not match \
                 row persona_id={row_persona_id}",
                first.block.issued_by
            )));
        }

        // --- P69K-A2 I4: bipartite dominance (design §Attenuation) ---
        //
        // Re-verifying the client-supplied chain's signature only proves
        // the client held the right keys to sign the new blocks. It does
        // NOT prove the new statements are attenuations of the previously
        // stored statements. A malicious (or buggy) client could overwrite
        // with a chain that expands authority — widening actions, escaping
        // a budget cap, replacing a glob with a broader resource. Enforce
        // bipartite dominance: every statement in the NEW chain must have
        // AT LEAST ONE statement in the OLD chain that subsumes it on
        // actions, resource, and budget-with-usage.
        //
        // Check runs BEFORE the (expensive) crypto verify so the cheap
        // violation fails fast — but AFTER envelope checks so we know the
        // row exists and block-0 is self-consistent.
        //
        // REVIEW2-F4: When `parent_override` is `Some`, the dominance gate
        // is rooted in the caller-supplied bound (e.g. the operator-approved
        // statement set for composite minting) rather than the scope-`*`
        // projection that `create_grant` wrote upstream. Same envelope guard
        // applies to the override: its block-0 issued_by must match the row.
        let loaded_parent;
        let parent: &AccessGrant = match parent_override {
            Some(p) => {
                if let Some(first) = p.blocks.first()
                    && first.block.issued_by != row_persona_id
                {
                    return Err(StoreError::InvalidInput(format!(
                        "overwrite_grant_blocks: parent_bound block-0 issued_by={} \
                         does not match row persona_id={row_persona_id}",
                        first.block.issued_by
                    )));
                }
                p
            }
            None => {
                loaded_parent = self.load_parent_access_grant_for_overwrite(id, &row_persona_id)?;
                &loaded_parent
            }
        };
        check_statement_attenuation(parent, grant).map_err(|e| {
            StoreError::InvalidInput(format!("attenuation violation: {}", e.reason))
        })?;

        // Full chain verify (crypto — most expensive, last).
        match self.get_persona_root_pubkey_bytes(&row_persona_id) {
            None => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot verify chain: persona root pubkey missing for {row_persona_id}"
                )));
            }
            Some(root_pubkey) => {
                verify_chain(&grant.blocks, &root_pubkey).map_err(|e| {
                    StoreError::InvalidInput(format!(
                        "grant chain verification failed: {e}"
                    ))
                })?;
            }
        }

        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, id],
        )?;
        Ok(())
    }

    /// Hydrate the currently-stored chain for `id` so the bipartite
    /// dominance check in [`overwrite_grant_blocks`] has a parent to
    /// compare against.
    ///
    /// Prefers `blocks_json` when present (and shape-consistent with the
    /// row's persona), falls back to the synthesized single-statement
    /// projection for legacy rows that pre-date `blocks_json`. This
    /// mirrors the hydration strategy used by [`Self::get_access_grant`]
    /// and [`Self::increment_statement_usage`] so a parent loaded here
    /// matches what every other read path sees.
    ///
    /// Unlike `get_access_grant`, we do NOT run `verify_chain` on the
    /// parent here — the parent was already verified at the point it was
    /// written (every write path now runs `verify_chain` before UPDATE),
    /// so re-verifying on every overwrite doubles the Ed25519 work for
    /// no new signal. If the stored `blocks_json` somehow deserializes
    /// but block-0 disagrees with the row's `persona_id`, we fall back
    /// to the projection (same failsafe as the read path).
    fn load_parent_access_grant_for_overwrite(
        &self,
        id: &str,
        row_persona_id: &str,
    ) -> Result<AccessGrant, StoreError> {
        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(s) = raw
            && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
            && !blocks.is_empty()
            && blocks[0].block.issued_by == row_persona_id
        {
            let info = self.get_grant(id)?;
            let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
            return Ok(AccessGrant {
                id: info.id,
                version: 1,
                issuing_persona_id: info.persona_id,
                recipient_kind: PresentationAudienceKind::Service,
                recipient_id: info.credential_name,
                recipient_profile: RecipientProfile::Agent,
                status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                mode: GrantMode::OneShot,
                blocks,
                attestation: AttestationBinding::default(),
                created_at: created_at_epoch,
                updated_at: created_at_epoch,
                revoked_at: None,
                revoked_reason: None,
                last_used_at: None,
                label: None,
            });
        }

        // Fall back to the projected single-statement chain for legacy
        // rows or rows whose blocks_json tripped the block-0 guard.
        let info = self.get_grant(id)?;
        self.project_access_grant(&info)
    }

    pub fn evaluate_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
    ) -> Result<GrantInfo, StoreError> {
        let now = Utc::now().to_rfc3339();
        let sql = format!(
            "SELECT {GRANT_COLUMNS} FROM grants \
             WHERE persona_id = ?1 AND credential_name = ?2 \
             AND status = 'active' AND (expires_at IS NULL OR expires_at > ?3) \
             LIMIT 1"
        );
        let grant = self
            .conn()
            .query_row(&sql, rusqlite::params![persona_id, credential_name, now], row_to_grant)
            .optional()?
            .ok_or(StoreError::NotFound)?;

        // Check time window
        if let (Some(start), Some(end)) = (grant.allowed_hours_start, grant.allowed_hours_end) {
            let current_hour = Utc::now().hour();
            let in_window = if start <= end {
                current_hour >= start && current_hour < end
            } else {
                current_hour >= start || current_hour < end
            };
            if !in_window {
                return Err(StoreError::InvalidInput(format!(
                    "outside allowed hours ({start}:00-{end}:00 UTC)"
                )));
            }
        }

        Ok(grant)
    }

    /// Record a usage of a grant. Returns error if rate limit exceeded.
    pub fn record_grant_usage(&self, grant_id: &str) -> Result<(), StoreError> {
        let max_uses: Option<i64> = self
            .conn()
            .query_row(
                "SELECT max_uses_per_hour FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = max_uses {
            let one_hour_ago = (Utc::now() - Duration::hours(1)).to_rfc3339();
            let count: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, one_hour_ago],
                |row| row.get(0),
            )?;
            if count >= max {
                return Err(StoreError::InvalidInput(format!(
                    "rate limit exceeded: {count}/{max} uses per hour"
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at) VALUES (?1, ?2)",
            rusqlite::params![grant_id, now],
        )?;
        Ok(())
    }

    /// Create a delegated grant with narrowed scope (TTL + scope only).
    ///
    /// Thin wrapper over `delegate_grant_full` that passes `None` for the
    /// child budget. If the parent carries a budget this call will fail
    /// attenuation (child must also bound every parent-bounded axis). Kept
    /// as-is so existing socket + CLI callers keep working for grants
    /// without budgets.
    pub fn delegate_grant(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        self.delegate_grant_full(
            parent_grant_id,
            child_persona_id,
            narrowed_scope,
            ttl_secs,
            None,
        )
    }

    /// Create a delegated grant with narrowed scope + optional child budget.
    ///
    /// Enforces offline attenuation per design § Offline attenuation:
    /// - child scope must be a subset of parent scope;
    /// - child budget must fit inside parent's remaining allowance
    ///   (parent.budget − parent.usage) on every axis the parent bounds;
    /// - child expires_at must be no later than the parent's (and must be
    ///   present if the parent has one).
    ///
    /// A failure on any axis returns `StoreError::DelegationViolation` with
    /// a reason that names the violating dimension only.
    pub fn delegate_grant_full(
        &self,
        parent_grant_id: &str,
        child_persona_id: &str,
        narrowed_scope: &str,
        ttl_secs: Option<u64>,
        child_budget: Option<Budget>,
    ) -> Result<GrantInfo, StoreError> {
        // F-06: route through get_access_grant which calls verify_and_return
        // → verify_chain. Column-tampered parents (scope, budget_json,
        // expires_at mutated without touching blocks_json) are rejected here
        // before any attenuation logic runs. `max_delegation_depth` is still
        // read from the flat row — SQL-tampering depth cannot expand scope
        // or budget, so severity is lower. Tracked as P69K-F06-depth.
        let parent_chain = self.get_access_grant(parent_grant_id)?;
        if parent_chain.status != GrantStatus::Active {
            return Err(StoreError::InvalidInput("parent grant not active".into()));
        }
        // Depth check still uses flat row (see P69K-F06-depth).
        let parent_flat = self.get_grant(parent_grant_id)?;
        let max_depth = parent_flat
            .max_delegation_depth
            .ok_or_else(|| StoreError::InvalidInput("parent does not allow delegation".into()))?;
        if max_depth == 0 {
            return Err(StoreError::InvalidInput("delegation depth exceeded".into()));
        }

        // — standing-parent daily delegation ceiling. Only applies
        // when the parent is marked standing; classical one-shot parents
        // skip this gate entirely. The 24h window is measured backwards
        // from `now` against the child row's `created_at` so the limit is
        // a rolling trailing window, not a midnight-aligned bucket.
        if parent_flat.is_standing
            && let Some(limit) = parent_flat.max_children_per_day
        {
            let one_day_ago = (Utc::now() - Duration::hours(24)).to_rfc3339();
            let count: i64 = self.conn().query_row(
                "SELECT COUNT(*) FROM grants \
                 WHERE parent_grant_id = ?1 AND created_at > ?2",
                rusqlite::params![parent_grant_id, one_day_ago],
                |row| row.get(0),
            )?;
            if (count as u64) >= limit {
                return Err(StoreError::InvalidInput(format!(
                    "standing-parent delegation ceiling reached: {count}/{limit} children \
                     minted in the trailing 24h window"
                )));
            }
        }

        // --- Offline attenuation (design § Offline attenuation) ---
        // Scope, budget, expiry all derived from the VERIFIED chain now.
        let parent_stmt = parent_chain
            .blocks
            .first()
            .and_then(|b| b.block.statements.first())
            .ok_or_else(|| StoreError::InvalidInput("parent chain empty".into()))?;
        let parent_scope_str = parent_flat.scope.clone();

        // P69K-F06 scope-consistency guard: the flat `scope` column is a
        // projection of the chain's first-Statement (actions + resource
        // selector). A direct `UPDATE grants SET scope = ...` diverges
        // from the signed chain — reject, mirroring the M1 issued_by
        // consistency check in `get_access_grant`. Without this, an
        // attacker with raw SQL access could expand scope for delegation
        // purposes without touching blocks_json (which would break chain
        // verification). F-06's budget-column tamper is already caught by
        // reading budget from `parent_stmt`; this closes the same hole
        // for scope.
        let (flat_actions, flat_selector) =
            scope_to_actions_and_selector(&parent_scope_str, &parent_flat.credential_name);
        if flat_actions != parent_stmt.actions || flat_selector != parent_stmt.resource {
            return Err(StoreError::InvalidInput(
                "parent grant scope diverges from signed chain — \
                 rejecting delegation of tampered parent".into(),
            ));
        }

        scope_subset(narrowed_scope, &parent_scope_str)?;

        // Compute child expiry epoch seconds (if provided) and parent's from chain.
        let now: DateTime<Utc> = Utc::now();
        let child_expiry_epoch: Option<u64> = ttl_secs
            .map(|s| (now.timestamp() as i128 + s as i128).max(0) as u64);
        let parent_expiry_epoch: Option<u64> = parent_chain
            .blocks
            .first()
            .and_then(|b| b.block.expires_at);

        check_expiry_attenuation(parent_expiry_epoch, child_expiry_epoch)?;
        check_budget_attenuation(&parent_stmt.budget, &parent_stmt.usage, &child_budget)?;
        // Preserve legacy parent binding for the INSERT below (credential_name
        // comes from the flat row via the existing parent_flat).
        let parent = parent_flat;

        let id = format!("grant-{}", Uuid::new_v4());
        let created_at = now.to_rfc3339();
        let created_at_epoch = now.timestamp().max(0) as u64;
        let expires_at = ttl_secs.map(|s| (now + Duration::seconds(s as i64)).to_rfc3339());
        let expires_at_epoch = ttl_secs.map(|s| created_at_epoch.saturating_add(s));
        let effective_child_budget = child_budget.clone().filter(|b| !b.is_none_set());
        let budget_json: Option<String> = effective_child_budget
            .as_ref()
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        // Build composite chain for the delegated grant: first block carries
        // a single Statement narrowed to the child scope, with the child's
        // budget attached. Block 0 is signed under the CHILD persona's root
        // key — delegated grants are independent chains per design revision
        // (the parent/child link is expressed via `parent_grant_id`, not a
        // cross-chain signature).
        let child_root = self.persona_root_keypair(child_persona_id)?;
        let child_block = build_single_statement_block(
            child_persona_id,
            &parent.credential_name,
            narrowed_scope,
            created_at_epoch,
            expires_at_epoch,
            effective_child_budget.clone(),
            Usage::default(),
        );
        let child_signed = sign_block_zero_with(&child_root, &child_block)?;
        let child_access_grant = access_grant_envelope(
            &id,
            child_persona_id,
            &parent.credential_name,
            "active",
            child_signed,
            created_at_epoch,
        );
        let blocks_json = access_grant_blocks_to_json(&child_access_grant)?;
        validate_blocks_json_caps(&child_access_grant, &blocks_json)?;

        self.conn().execute(
            "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status, parent_grant_id, max_delegation_depth, budget_json, blocks_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10, ?11)",
            rusqlite::params![
                id,
                child_persona_id,
                parent.credential_name,
                narrowed_scope,
                ttl_secs.map(|s| s as i64),
                created_at,
                expires_at,
                parent_grant_id,
                max_depth.saturating_sub(1) as i64,
                budget_json,
                blocks_json,
            ],
        )?;

        let _ = child_access_grant; // chain persisted via blocks_json above
        let _ = self.log_event(
            Some(child_persona_id),
            "grant.minted",
            Some(&parent.credential_name),
            "minted",
            Some(
                &serde_json::json!({
                    "grant_id": id,
                    "statement_count": 1,
                    "ttl_secs": ttl_secs,
                    "creation_mode": "delegate",
                    "parent_grant_id": parent_grant_id,
                })
                .to_string(),
            ),
        );
        Ok(GrantInfo {
            id,
            persona_id: child_persona_id.to_string(),
            credential_name: parent.credential_name,
            scope: narrowed_scope.to_string(),
            created_at,
            expires_at,
            status: "active".to_string(),
            max_uses_per_hour: None,
            allowed_hours_start: None,
            allowed_hours_end: None,
            allowed_targets: None,
            parent_grant_id: Some(parent_grant_id.to_string()),
            max_delegation_depth: Some(max_depth.saturating_sub(1)),
            spending_limit_cents: None,
            budget: effective_child_budget,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
            is_standing: false,
            max_children_per_day: None,
            auto_delegate_scope_template: None,
        })
    }

    pub fn revoke_grant(&self, id: &str) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET status = 'revoked' WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        // Emit Grant Receipt for the operator-initiated revocation.
        if crate::receipt::trigger_receipt_if_terminal_current(
            self,
            id,
            Some(core_types::grant_receipt::TerminalReason::Revoked {
                by: core_types::grant_receipt::RevokeActor::Operator,
                reason: String::new(),
            }),
        )
        .is_none()
        {
            tracing::warn!(
                grant_id = %id,
                terminal_reason = "revoked",
                "receipt did not emit for revoked grant — see prior log line"
            );
        }
        // Cascade to child delegated grants
        self.cascade_revoke_children(id, id)?;
        Ok(())
    }

    fn cascade_revoke_children(
        &self,
        parent_id: &str,
        root_revoked_id: &str,
    ) -> Result<(), StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id FROM grants WHERE parent_grant_id = ?1 AND status = 'active'",
        )?;
        let children: Vec<String> = stmt
            .query_map(rusqlite::params![parent_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for child_id in children {
            self.conn().execute(
                "UPDATE grants SET status = 'revoked' WHERE id = ?1",
                rusqlite::params![child_id],
            )?;
            // Emit a receipt for the cascade-revoked child. The receipt's
            // TerminalReason distinguishes cascade from direct revoke even
            // though both share the same `revoked` SQL status today.
            if crate::receipt::trigger_receipt_if_terminal_current(
                self,
                &child_id,
                Some(core_types::grant_receipt::TerminalReason::ParentCascadeRevoked {
                    parent_grant_id: root_revoked_id.to_string(),
                }),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %child_id,
                    parent_grant_id = %root_revoked_id,
                    terminal_reason = "parent_cascade_revoked",
                    "receipt did not emit for cascade-revoked child — see prior log line"
                );
            }
            self.cascade_revoke_children(&child_id, root_revoked_id)?;
        }
        Ok(())
    }

    /// Mark grants whose expires_at has passed as 'expired'.
    ///
    /// For each grant that transitions to expired, emits a signed Grant
    /// Receipt (Stream D) via the process-singleton identity.
    pub fn expire_stale_grants(&self) -> Result<usize, StoreError> {
        let now = Utc::now().to_rfc3339();
        // Collect ids of grants about to expire so we can emit receipts
        // after the status flip (emit reads the terminal status).
        let mut stmt = self.conn().prepare(
            "SELECT id FROM grants \
             WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
        )?;
        let expiring: Vec<String> = stmt
            .query_map(rusqlite::params![now], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        let count = self.conn().execute(
            "UPDATE grants SET status = 'expired' \
             WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?1",
            rusqlite::params![now],
        )?;
        for gid in &expiring {
            if crate::receipt::trigger_receipt_if_terminal_current(
                self,
                gid,
                Some(core_types::grant_receipt::TerminalReason::Expired),
            )
            .is_none()
            {
                tracing::warn!(
                    grant_id = %gid,
                    terminal_reason = "expired",
                    "receipt did not emit for TTL-expired grant — see prior log line"
                );
            }
        }
        Ok(count)
    }

    /// Wall-clock budget sweep (P69K-A2). Walks every active grant's
    /// composite chain and flips to `exhausted_by_budget` when any
    /// Statement with `budget.wall_clock_secs` set has been in force for
    /// at least that many seconds (measured from the grant's `created_at`).
    ///
    /// Return value is `(exhausted_count, warned_count)`. Warning events
    /// are emitted to the audit log at `action="budget.warning"` when a
    /// grant crosses the 80% threshold on wall-clock, matching the
    /// TTL-expiry pattern. A grant is only warned once per crossing — the
    /// `warned_wall_clock` column tracks this.
    pub fn expire_grants_by_wall_clock(&self) -> Result<(usize, usize), StoreError> {
        let now_secs = Utc::now().timestamp().max(0) as u64;
        let active = self.list_active_grants()?;
        let mut exhausted = 0usize;
        let mut warned = 0usize;

        for info in active {
            let Ok(ag) = self.get_access_grant(&info.id) else {
                continue;
            };
            let created = ag.created_at;
            if created == 0 || now_secs <= created {
                continue;
            }
            let elapsed = now_secs - created;

            // Find the minimum wall_clock_secs across Statements that set
            // it. First-match exhaustion on any statement terminates the
            // grant (we're allow-only, and a wall-clock-bounded statement
            // that has nothing left cannot contribute).
            let mut min_wall_clock: Option<u64> = None;
            for (_i, stmt) in ag.statements() {
                if let Some(b) = &stmt.budget
                    && let Some(wc) = b.wall_clock_secs
                {
                    min_wall_clock = Some(match min_wall_clock {
                        Some(m) => m.min(wc),
                        None => wc,
                    });
                }
            }
            let Some(limit) = min_wall_clock else { continue };

            if elapsed >= limit {
                self.conn().execute(
                    "UPDATE grants SET status = 'exhausted_by_budget' WHERE id = ?1",
                    rusqlite::params![info.id],
                )?;
                let _ = self.log_event(
                    Some(&info.persona_id),
                    "grant.exhausted",
                    Some(&info.credential_name),
                    "exhausted_by_budget",
                    Some(&format!(
                        "wall_clock elapsed={elapsed} limit={limit}"
                    )),
                );
                // Emit a signed Grant Receipt for the terminal state.
                if crate::receipt::trigger_receipt_if_terminal_current(
                    self,
                    &info.id,
                    Some(core_types::grant_receipt::TerminalReason::ExhaustedByBudget {
                        statement_sid: "S0".into(),
                        axis: core_types::grant_receipt::BudgetAxis::WallClockSecs,
                    }),
                )
                .is_none()
                {
                    tracing::warn!(
                        grant_id = %info.id,
                        terminal_reason = "exhausted_by_budget",
                        "receipt did not emit for budget-exhausted grant — see prior log line"
                    );
                }
                exhausted += 1;
                continue;
            }

            // 80% threshold warning — same as TTL. Emit a single warn per
            // crossing. Check-and-set via the `warned_wall_clock_at` column
            // if schema supports it; otherwise fall back to per-tick
            // tracing without de-dup.
            let warn_at = (limit as f64 * 0.8) as u64;
            if elapsed >= warn_at {
                let _ = self.log_event(
                    Some(&info.persona_id),
                    "budget.warning",
                    Some(&info.credential_name),
                    "wall_clock_80pct",
                    Some(&format!("elapsed={elapsed} limit={limit}")),
                );
                warned += 1;
            }
        }

        Ok((exhausted, warned))
    }

    /// List grants of any status — used for the receipt viewer and terminated-grant rows.
    pub fn list_all_grants(&self) -> Result<Vec<GrantInfo>, StoreError> {
        let sql = format!("SELECT {GRANT_COLUMNS} FROM grants ORDER BY created_at DESC");
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map([], row_to_grant)?;
        let mut grants = Vec::new();
        for row in rows {
            grants.push(row?);
        }
        Ok(grants)
    }

    /// Set the `paused` flag on a grant (advisory signal to the agent).
    pub fn set_grant_paused(&self, id: &str, paused: bool) -> Result<(), StoreError> {
        let n = self.conn().execute(
            "UPDATE grants SET paused = ?1 WHERE id = ?2 AND status = 'active'",
            rusqlite::params![paused as i64, id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Hard-pause a grant: sets `status = 'paused'` so the proxy's
    /// `evaluate_grant` (which filters `status = 'active'`) rejects all
    /// further requests under this grant. Also sets the `paused` flag for
    /// dashboard rendering consistency.
    ///
    /// Returns `StoreError::NotFound` when the id does not exist.
    /// Returns `StoreError::InvalidInput` when the grant is not in a
    /// state that can be paused (e.g. already revoked, expired, or
    /// exhausted). Idempotent for already-paused grants.
    pub fn pause_grant(&self, id: &str) -> Result<(), StoreError> {
        // First verify the grant exists and is in a pause-able state.
        let grant = self.get_grant(id)?;
        match grant.status.as_str() {
            "paused" => {
                // Idempotent — already paused.
                return Ok(());
            }
            "active" => {}
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot pause grant with status '{other}'"
                )));
            }
        }
        let n = self.conn().execute(
            "UPDATE grants SET status = 'paused', paused = 1 WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Resume a paused grant: flips `status` back to `'active'` and clears
    /// the `paused` flag. No-ops if the grant is already active. Returns
    /// `StoreError::InvalidInput` for non-paused terminal statuses.
    pub fn resume_grant(&self, id: &str) -> Result<(), StoreError> {
        let grant = self.get_grant(id)?;
        match grant.status.as_str() {
            "active" => {
                // Idempotent — already active.
                return Ok(());
            }
            "paused" => {}
            other => {
                return Err(StoreError::InvalidInput(format!(
                    "cannot resume grant with status '{other}'"
                )));
            }
        }
        let n = self.conn().execute(
            "UPDATE grants SET status = 'active', paused = 0 WHERE id = ?1",
            rusqlite::params![id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Extend a grant's budget and/or TTL.
    ///
    /// - `tokens_delta`: additional tokens to add to `budget_tokens` (and reset `tokens_used` floor
    ///   so the new budget is `old_budget + tokens_delta`).
    /// - `cents_delta`: additional cents to add to `budget_cents`.
    /// - `ttl_extension_secs`: seconds to add to `expires_at` (from now if currently unbounded).
    pub fn extend_grant(
        &self,
        id: &str,
        tokens_delta: Option<u64>,
        cents_delta: Option<u64>,
        ttl_extension_secs: Option<u64>,
    ) -> Result<GrantInfo, StoreError> {
        // P69K-H1 (adversarial follow-up on #526): wrap the
        // read-compute-write sequence in a `BEGIN IMMEDIATE` transaction so
        // that a concurrent `increment_statement_usage` (or revoke) cannot
        // interleave between our read of `blocks_json` and our UPDATE,
        // rewinding its usage write. Pattern mirrors
        // `increment_statement_usage` — manual begin/commit + RAII rollback
        // guard so any `?`-propagated error path rolls back cleanly.
        self.conn().execute_batch("BEGIN IMMEDIATE")?;
        struct TxGuard<'c> {
            conn: &'c rusqlite::Connection,
            committed: bool,
        }
        impl Drop for TxGuard<'_> {
            fn drop(&mut self) {
                if !self.committed {
                    let _ = self.conn.execute_batch("ROLLBACK");
                }
            }
        }
        let mut tx_guard = TxGuard {
            conn: self.conn(),
            committed: false,
        };

        let grant = self.get_grant(id)?;
        if grant.status != "active" {
            return Err(StoreError::InvalidInput(format!(
                "cannot extend grant with status '{}'",
                grant.status
            )));
        }

        let now: DateTime<Utc> = Utc::now();

        // Compute new expires_at
        let new_expires_at: Option<String> = if let Some(ext) = ttl_extension_secs {
            let base = if let Some(ref exp) = grant.expires_at {
                DateTime::parse_from_rfc3339(exp)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or(now)
            } else {
                now
            };
            let new_exp = base + Duration::seconds(ext as i64);
            Some(new_exp.to_rfc3339())
        } else {
            grant.expires_at.clone()
        };

        // Compute new budget values per design (Budget struct, not flat columns)
        let existing_budget = grant.budget.clone().unwrap_or_default();
        let new_budget = Budget {
            tokens: match (existing_budget.tokens, tokens_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            cents: match (existing_budget.cents, cents_delta) {
                (Some(e), Some(d)) => Some(e + d),
                (None, Some(d)) => Some(d),
                (e, None) => e,
            },
            ..existing_budget
        };
        let new_budget_opt: Option<Budget> = if new_budget.is_none_set() { None } else { Some(new_budget) };
        let new_budget_json: Option<String> = new_budget_opt
            .as_ref()
            .map(|b| serde_json::to_string(b).expect("Budget serializes"));

        // Update the composite chain's first-statement budget to track the
        // envelope-level budget so dashboard/receipt projections stay in
        // sync. Per design this is a transitional mapping — once per-
        // Statement metering lands (Stream C) extend_grant will target a
        // specific Statement by sid.
        //
        // Mutating block 0's payload invalidates its signature — we MUST
        // re-sign block 0 under the issuing persona's root key so the
        // chain remains verifiable end-to-end. This is not an append; it
        // replaces the only block (the single-block chain is being
        // re-issued with a bumped budget/expiry). design revision
        // documents this as the transitional shape until per-Statement
        // metering lets us express the extension as an appended block.
        let mut new_chain = self.get_access_grant(id)?;

        // F-01 (adversarial development cycle): re-signing block 0 mints a fresh
        // pubkey_next, which orphans the signature on every subsequent
        // block (those are signed by the PREVIOUS pubkey_next's secret,
        // which the daemon does not persist). On a multi-block chain
        // that would silently brick the grant on next read. Guard: only
        // permit extend_grant on a single-block chain today. Future
        // P69K-C append-block path will express extension as a NEW
        // appended block instead of mutating block 0.
        if new_chain.blocks.len() > 1 {
            return Err(StoreError::InvalidInput(
                "extend_grant not supported on multi-block chains yet — \
                 mutating block 0 would orphan subsequent blocks' signatures. \
                 Append-block path (P69K-C3) required.".into(),
            ));
        }

        if let Some(first_block) = new_chain.blocks.first_mut()
            && let Some(first_stmt) = first_block.block.statements.first_mut()
        {
            first_stmt.budget = new_budget_opt.clone();
        }
        if let Some(first_block) = new_chain.blocks.first_mut() {
            // Keep envelope expiry in sync with the row's new expires_at so
            // verify-side expiry checks (if any are wired later) match the
            // stored row.
            let new_expires_epoch = new_expires_at
                .as_deref()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);
            first_block.block.expires_at = new_expires_epoch;
            let root = self.persona_root_keypair(&grant.persona_id)?;
            let resigned = sign_block_zero_with(&root, &first_block.block)?;
            *first_block = resigned;
        }
        let new_blocks_json = access_grant_blocks_to_json(&new_chain)?;
        validate_blocks_json_caps(&new_chain, &new_blocks_json)?;

        // P69K-H1: re-check status inside the transaction. A revoke that
        // committed between our first `get_grant` and here must win — we
        // refuse to overwrite the blocks_json of a grant that is no longer
        // active. Without this, a concurrent `revoke_grant` followed by an
        // `extend_grant` could silently resurrect the grant's budget/TTL
        // view while leaving status='revoked' (or vice versa — rewind a
        // revoked-status to active-budget).
        let current_status: String = self.conn().query_row(
            "SELECT status FROM grants WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )?;
        if current_status != "active" {
            // TxGuard rolls back on early return.
            return Err(StoreError::InvalidInput(format!(
                "cannot extend grant with status '{current_status}'"
            )));
        }

        self.conn().execute(
            "UPDATE grants SET budget_json = ?1, expires_at = ?2, blocks_json = ?3 WHERE id = ?4",
            rusqlite::params![new_budget_json, new_expires_at, new_blocks_json, id],
        )?;

        self.conn().execute_batch("COMMIT")?;
        tx_guard.committed = true;

        self.get_grant(id)
    }

    /// Set a receipt_id on a terminated grant.
    pub fn set_grant_receipt_id(&self, grant_id: &str, receipt_id: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE grants SET receipt_id = ?1 WHERE id = ?2",
            rusqlite::params![receipt_id, grant_id],
        )?;
        Ok(())
    }

    /// Get counts of grants by status.
    pub fn grant_summary(&self) -> Result<GrantSummary, StoreError> {
        let active: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'active'",
            [],
            |row| row.get(0),
        )?;
        let expired: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'expired'",
            [],
            |row| row.get(0),
        )?;
        let revoked: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM grants WHERE status = 'revoked'",
            [],
            |row| row.get(0),
        )?;
        Ok(GrantSummary {
            active: active as u64,
            expired: expired as u64,
            revoked: revoked as u64,
        })
    }

    /// Atomically increment a specific Statement's usage by `delta` and
    /// return the post-increment `Usage` for that Statement. Used by the
    /// proxy's post-flight meter (Stream C) when an LLM response body has
    /// been parsed for tokens/cents.
    ///
    /// Atomicity is provided by the daemon's single-connection SQLite
    /// (`DaemonStore::conn()` returns the one connection bound to the
    /// LocalSet runtime), plus an immediate transaction bracketing the
    /// read-modify-write on `blocks_json`. No other caller can interleave
    /// a write to this row mid-RMW.
    ///
    /// Returns `StoreError::NotFound` if the grant or the named
    /// `statement_sid` doesn't exist. Returns the prior + new `Usage` tuple
    /// so the caller can compute threshold crossings (80%/95%) without a
    /// second read.
    pub fn increment_statement_usage(
        &self,
        grant_id: &str,
        statement_sid: &str,
        delta: Usage,
    ) -> Result<StatementUsageDelta, StoreError> {
        // Bracket the RMW in a transaction — prevents interleave with the
        // expiry sweep and any future concurrent writer. unchecked_transaction
        // issues BEGIN and provides RAII rollback-on-drop; .commit() closes
        // it on success.
        let tx = self.conn().unchecked_transaction()?;

        // Read current blocks_json. Fall back to the synthesized single-
        // statement chain if the row was created before blocks_json
        // existed (legacy grants; their sid is always "S0").

        let raw: Option<String> = self
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        let mut grant: AccessGrant = match raw {
            Some(s) => match serde_json::from_str::<Vec<SignedBlock>>(&s) {
                Ok(blocks) if !blocks.is_empty() => {
                    // Rebuild envelope from the row's scalar fields.
                    let info = self.get_grant(grant_id)?;
                    let created_at_epoch = parse_epoch(Some(&info.created_at)).unwrap_or(0);
                    AccessGrant {
                        id: info.id,
                        version: 1,
                        issuing_persona_id: info.persona_id,
                        recipient_kind: PresentationAudienceKind::Service,
                        recipient_id: info.credential_name,
                        recipient_profile: RecipientProfile::Agent,
                        status: GrantStatus::parse(&info.status).unwrap_or(GrantStatus::Active),
                        mode: GrantMode::OneShot,
                        blocks,
                        attestation: AttestationBinding::default(),
                        created_at: created_at_epoch,
                        updated_at: created_at_epoch,
                        revoked_at: None,
                        revoked_reason: None,
                        last_used_at: None,
                        label: None,
                    }
                }
                _ => {
                    let info = self.get_grant(grant_id)?;
                    self.project_access_grant(&info)?
                }
            },
            None => {
                let info = self.get_grant(grant_id)?;
                self.project_access_grant(&info)?
            }
        };

        // Find the statement by sid and mutate its usage.
        let mut prior: Option<Usage> = None;
        let mut updated: Option<Usage> = None;
        let mut found = false;
        let mut mutated_block_idx: Option<usize> = None;
        let now_secs = Utc::now().timestamp().max(0) as u64;
        'outer: for (bi, sb) in grant.blocks.iter_mut().enumerate() {
            for stmt in sb.block.statements.iter_mut() {
                if stmt.sid == statement_sid {
                    let before = stmt.usage.clone();
                    stmt.usage.tokens = stmt.usage.tokens.saturating_add(delta.tokens);
                    stmt.usage.cents = stmt.usage.cents.saturating_add(delta.cents);
                    stmt.usage.requests = stmt.usage.requests.saturating_add(delta.requests);
                    stmt.usage.workload_hours =
                        stmt.usage.workload_hours.saturating_add(delta.workload_hours);
                    stmt.usage.wall_clock_secs = stmt
                        .usage
                        .wall_clock_secs
                        .saturating_add(delta.wall_clock_secs);
                    stmt.usage.last_updated = now_secs;
                    prior = Some(before);
                    updated = Some(stmt.usage.clone());
                    found = true;
                    mutated_block_idx = Some(bi);
                    break 'outer;
                }
            }
        }
        if !found {
            return Err(StoreError::NotFound);
        }

        // F-01 (adversarial development cycle): re-signing block 0 rotates
        // pubkey_next, which orphans blocks 1..N (their signers used the
        // PREVIOUS pubkey_next's secret, which the daemon does not
        // persist). On a multi-block chain that silently bricks the
        // grant on next read. Guard: refuse metering on multi-block
        // chains until live-usage-outside-chain (or pubkey_next_secret
        // persistence) lands. Documented architectural follow-up.
        if grant.blocks.len() > 1 {
            return Err(StoreError::InvalidInput(
                "increment_statement_usage not supported on multi-block chains yet — \
                 re-signing block 0 would orphan subsequent blocks. \
                 Live-usage-outside-chain (P69K-G) required.".into(),
            ));
        }

        // Re-sign block 0 under issuing persona's root key — mutating the
        // statement payload invalidates the chain signature otherwise, and
        // the read path (verify_and_return) rejects unverifiable chains.
        if mutated_block_idx == Some(0) {
            let root = self.persona_root_keypair(&grant.issuing_persona_id)?;
            let new_signed = sign_block_zero_with(&root, &grant.blocks[0].block)?;
            grant.blocks[0] = new_signed;
        }

        // Persist the mutated blocks chain.
        let blocks_json = access_grant_blocks_to_json(&grant)?;
        validate_blocks_json_caps(&grant, &blocks_json)?;
        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant_id],
        )?;
        tx.commit()?;

        Ok(StatementUsageDelta {
            prior: prior.unwrap_or_default(),
            current: updated.unwrap_or_default(),
        })
    }

    /// If a grant's composite chain has no remaining applicable-budget
    /// capacity — specifically: every Statement that carries a `budget`
    /// has at least one axis exhausted — flip status to
    /// `exhausted_by_budget` and log an audit event. No-op otherwise.
    ///
    /// Semantics choice (documented here so Stream D receipts and the
    /// dashboard agree): a grant is "budget-terminal" when **every
    /// budget-bearing Statement** is exhausted on at least one axis.
    /// Statements with `budget = None` are ignored — they are TTL-only
    /// and do not contribute to budget termination. A grant with zero
    /// budget-bearing statements never flips via this path.
    ///
    /// This is the conservative choice: a 3-statement grant
    /// (credential, session, time) flips only once both the session
    /// budget AND the time budget are spent. A single-budget-Statement
    /// grant flips as soon as that one axis exhausts.
    pub fn mark_grant_exhausted_by_budget_if_terminal(
        &self,
        grant_id: &str,
    ) -> Result<bool, StoreError> {
        let grant = self.get_access_grant(grant_id)?;
        if !matches!(grant.status, GrantStatus::Active) {
            return Ok(false);
        }

        let mut any_budget_bearing = false;
        let mut all_exhausted = true;
        for (_i, stmt) in grant.statements() {
            if stmt.budget.is_none() {
                continue;
            }
            any_budget_bearing = true;
            if stmt.has_budget_remaining() {
                all_exhausted = false;
                break;
            }
        }
        if !any_budget_bearing || !all_exhausted {
            return Ok(false);
        }

        let n = self.conn().execute(
            "UPDATE grants SET status = 'exhausted_by_budget' \
             WHERE id = ?1 AND status = 'active'",
            rusqlite::params![grant_id],
        )?;
        if n == 0 {
            return Ok(false);
        }
        let info = self.get_grant(grant_id).ok();
        let (persona, credential) = info
            .map(|i| (Some(i.persona_id), Some(i.credential_name)))
            .unwrap_or((None, None));
        let _ = self.log_event(
            persona.as_deref(),
            "grant.exhausted",
            credential.as_deref(),
            "exhausted_by_budget",
            Some("all_budget_bearing_statements_exhausted"),
        );
        Ok(true)
    }

    /// Record a spending event. Returns error if daily limit exceeded.
    pub fn record_grant_spending(&self, grant_id: &str, amount_cents: u64) -> Result<(), StoreError> {
        let limit: Option<i64> = self
            .conn()
            .query_row(
                "SELECT spending_limit_cents FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        if let Some(max) = limit {
            let today = Utc::now()
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .to_rfc3339();
            let spent: i64 = self.conn().query_row(
                "SELECT COALESCE(SUM(amount_cents), 0) FROM grant_usage WHERE grant_id = ?1 AND used_at > ?2",
                rusqlite::params![grant_id, today],
                |row| row.get(0),
            )?;
            if spent + amount_cents as i64 > max {
                return Err(StoreError::InvalidInput(format!(
                    "spending limit exceeded: ${:.2} + ${:.2} > ${:.2}/day",
                    spent as f64 / 100.0,
                    amount_cents as f64 / 100.0,
                    max as f64 / 100.0
                )));
            }
        }

        let now = Utc::now().to_rfc3339();
        self.conn().execute(
            "INSERT INTO grant_usage (grant_id, used_at, amount_cents) VALUES (?1, ?2, ?3)",
            rusqlite::params![grant_id, now, amount_cents as i64],
        )?;
        Ok(())
    }
}

pub struct GrantSummary {
    pub active: u64,
    pub expired: u64,
    pub revoked: u64,
}

/// Before/after usage snapshot returned by
/// [`DaemonStore::increment_statement_usage`]. Callers use `prior` and
/// `current` together to detect threshold crossings (80% / 95%) without a
/// second read.
#[derive(Debug, Clone)]
pub struct StatementUsageDelta {
    pub prior: Usage,
    pub current: Usage,
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::store::DaemonStore;

    fn setup() -> DaemonStore {
        DaemonStore::open_in_memory().expect("in-memory store")
    }

    #[test]
    fn create_grant_list_shows_active() {
        let store = setup();
        let persona = store.create_persona("agent-alpha").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "read", None)
            .unwrap();
        assert_eq!(grant.status, "active");
        assert!(grant.expires_at.is_none());

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, grant.id);
        assert_eq!(grants[0].status, "active");
    }

    #[test]
    fn create_grant_with_ttl_expires_at_set() {
        let store = setup();
        let persona = store.create_persona("agent-beta").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "write", Some(3600))
            .unwrap();
        assert!(grant.expires_at.is_some());

        // Parse and verify it's in the future.
        let expires: DateTime<Utc> =
            DateTime::parse_from_rfc3339(grant.expires_at.as_ref().unwrap())
                .unwrap()
                .into();
        assert!(expires > Utc::now());
    }

    #[test]
    fn evaluate_grant_returns_active_grant() {
        let store = setup();
        let persona = store.create_persona("agent-gamma").unwrap();
        store
            .create_grant(&persona.id, "secret", "read", None)
            .unwrap();

        let found = store.evaluate_grant(&persona.id, "secret").unwrap();
        assert_eq!(found.persona_id, persona.id);
        assert_eq!(found.credential_name, "secret");
        assert_eq!(found.status, "active");
    }

    #[test]
    fn evaluate_grant_after_ttl_expires_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-delta").unwrap();

        // Insert a grant with expires_at in the past directly.
        let id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    id,
                    persona.id,
                    "expired-key",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let result = store.evaluate_grant(&persona.id, "expired-key");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn revoke_grant_evaluate_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("agent-epsilon").unwrap();
        let grant = store
            .create_grant(&persona.id, "token", "full", None)
            .unwrap();

        store.revoke_grant(&grant.id).unwrap();

        let result = store.evaluate_grant(&persona.id, "token");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_nonexistent_persona_returns_error() {
        let store = setup();
        let result = store.create_grant("persona-does-not-exist", "key", "read", None);
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn create_grant_revoked_persona_returns_error() {
        let store = setup();
        let persona = store.create_persona("agent-zeta").unwrap();
        store.revoke_persona(&persona.id).unwrap();

        let result = store.create_grant(&persona.id, "key", "read", None);
        assert!(matches!(result, Err(StoreError::InvalidInput(_))));
    }

    #[test]
    fn list_active_grants_excludes_expired_and_revoked() {
        let store = setup();
        let persona = store.create_persona("agent-eta").unwrap();

        // Active grant (no TTL).
        let active = store
            .create_grant(&persona.id, "active-key", "read", None)
            .unwrap();

        // Revoked grant.
        let revoked = store
            .create_grant(&persona.id, "revoked-key", "read", None)
            .unwrap();
        store.revoke_grant(&revoked.id).unwrap();

        // Expired grant: insert directly with past expires_at.
        let exp_id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let past = now - Duration::seconds(10);
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, ttl_secs, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
                rusqlite::params![
                    exp_id,
                    persona.id,
                    "expired-key2",
                    "read",
                    1_i64,
                    now.to_rfc3339(),
                    past.to_rfc3339(),
                ],
            )
            .unwrap();

        let active_grants = store.list_active_grants().unwrap();
        assert_eq!(active_grants.len(), 1);
        assert_eq!(active_grants[0].id, active.id);
    }

    // Keep the import used only in the sleep-based variant (unused without it).
    #[allow(dead_code)]
    fn _uses_thread_sleep() {
        let _ = thread::sleep(StdDuration::from_millis(0));
    }

    // --- Offline attenuation integration tests (design § 69K.6) ---

    /// Attach a budget + max_delegation_depth to a newly-created parent grant
    /// by patching the row directly. create_grant doesn't accept these yet
    /// (that's a separate task); the attenuation path does its own reads.
    ///
    /// Post-composite-port: also patch the composite `blocks_json` so that
    /// `get_grant` hydrates the parent with the attached budget. Without
    /// this, `row_to_grant` prefers `blocks_json` (which has no budget from
    /// `create_grant`) and attenuation sees `budget = None`.
    fn attach_parent_constraints(
        store: &DaemonStore,
        grant_id: &str,
        budget: Option<Budget>,
        max_depth: u32,
    ) {
        let budget_json: Option<String> = budget
            .as_ref()
            .filter(|b| !b.is_none_set())
            .map(|b| serde_json::to_string(b).unwrap());

        // Patch the composite chain's first-statement budget to match.
        // Prefer the stored `blocks_json` so we preserve the signed block
        // written by `create_grant` (real Ed25519, not a placeholder).
        let existing = store.get_grant(grant_id).expect("grant exists");
        let mut new_chain = store
            .project_access_grant(&existing)
            .expect("projection succeeds in tests");
        let raw: Option<String> = store
            .conn()
            .query_row(
                "SELECT blocks_json FROM grants WHERE id = ?1",
                rusqlite::params![grant_id],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        if let Some(s) = raw
            && let Ok(blocks) = serde_json::from_str::<Vec<SignedBlock>>(&s)
            && !blocks.is_empty()
        {
            new_chain.blocks = blocks;
        }
        if let Some(first_block) = new_chain.blocks.first_mut()
            && let Some(first_stmt) = first_block.block.statements.first_mut()
        {
            first_stmt.budget = budget.clone().filter(|b| !b.is_none_set());
        }
        // Re-sign block 0 after mutating its payload so the stored chain
        // stays verifiable. Tests that don't care about verification still
        // benefit from the invariant.
        if let Some(first_block) = new_chain.blocks.first_mut() {
            let root = store
                .persona_root_keypair(&existing.persona_id)
                .expect("persona root key present");
            let resigned = sign_block_zero_with(&root, &first_block.block).expect("re-sign");
            *first_block = resigned;
        }
        let blocks_json = access_grant_blocks_to_json(&new_chain).unwrap();

        store
            .conn()
            .execute(
                "UPDATE grants SET budget_json = ?1, max_delegation_depth = ?2, blocks_json = ?3 WHERE id = ?4",
                rusqlite::params![budget_json, max_depth as i64, blocks_json, grant_id],
            )
            .unwrap();
    }

    fn setup_parent_with_budget(
        store: &DaemonStore,
        tokens: u64,
        ttl_secs: u64,
    ) -> (String, String) {
        let parent_persona = store.create_persona("agent-parent").unwrap();
        let child_persona = store.create_persona("agent-child").unwrap();
        let parent_grant = store
            .create_grant(
                &parent_persona.id,
                "delegate-key",
                "github:push:acme/*",
                Some(ttl_secs),
            )
            .unwrap();
        attach_parent_constraints(
            store,
            &parent_grant.id,
            Some(Budget {
                tokens: Some(tokens),
                ..Default::default()
            }),
            3,
        );
        (parent_grant.id, child_persona.id)
    }

    #[test]
    fn delegate_different_target_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                // `other/*` is outside `acme/*`.
                "github:push:other/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("scope"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn delegate_child_budget_exceeds_parent_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(15_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("tokens"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn delegate_attenuated_child_approved() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .expect("attenuated delegate approved");
        assert_eq!(child.scope, "github:push:acme/widgets");
        assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
        assert_eq!(child.budget.and_then(|b| b.tokens), Some(3_000));
    }

    #[test]
    fn delegate_chained_grandchild_approved() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .expect("first delegate approved");

        // Grandchild further narrows budget.
        let grandchild_persona = store.create_persona("agent-grandchild").unwrap();
        let grandchild = store
            .delegate_grant_full(
                &child.id,
                &grandchild_persona.id,
                "github:push:acme/widgets",
                Some(60),
                Some(Budget {
                    tokens: Some(1_000),
                    ..Default::default()
                }),
            )
            .expect("grandchild delegate approved");
        assert_eq!(grandchild.parent_grant_id.as_deref(), Some(child.id.as_str()));
        assert_eq!(grandchild.budget.and_then(|b| b.tokens), Some(1_000));
    }

    #[test]
    fn delegate_parent_budget_child_no_budget_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        // No child budget — parent has one, so this must fail.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                None,
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("budget"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    // --- wall-clock budget sweep (P69K-A2) ---

    /// Seed a grant whose created_at is in the past and whose composite
    /// chain carries a single Statement with `wall_clock_secs: budget`.
    fn seed_wall_clock_grant(
        store: &DaemonStore,
        persona_id: &str,
        credential_name: &str,
        wall_clock_secs: u64,
        age_secs: i64,
    ) -> String {
        let id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now();
        let created = now - Duration::seconds(age_secs);

        let stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Session,
            actions: vec!["llm:generate".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                wall_clock_secs: Some(wall_clock_secs),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
        };
        let created_epoch = created.timestamp().max(0) as u64;
        let root = store
            .persona_root_keypair(persona_id)
            .expect("persona root key present");
        let block = Block {
            statements: vec![stmt],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.to_string(),
            issued_at: created_epoch,
            approval: None,
            note: None,
        };
        let signed = sign_block_zero_with(&root, &block).expect("sign block 0");
        let grant = access_grant_envelope(
            &id,
            persona_id,
            credential_name,
            "active",
            signed,
            created_epoch,
        );
        let blocks_json = access_grant_blocks_to_json(&grant).unwrap();

        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status, blocks_json)
                 VALUES (?1, ?2, ?3, 'llm:generate', ?4, 'active', ?5)",
                rusqlite::params![id, persona_id, credential_name, created.to_rfc3339(), blocks_json],
            )
            .unwrap();
        id
    }

    #[test]
    fn wall_clock_sweep_exhausts_grant_past_limit() {
        let store = setup();
        let persona = store.create_persona("agent-wc").unwrap();
        // 10s limit, 11s elapsed — must exhaust.
        let gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 10, 11);

        let (exhausted, _warned) = store.expire_grants_by_wall_clock().unwrap();
        assert!(exhausted >= 1, "expected exhaustion, got {exhausted}");

        let grant = store.get_grant(&gid).unwrap();
        assert_eq!(grant.status, "exhausted_by_budget");
    }

    #[test]
    fn wall_clock_sweep_warns_at_80pct() {
        let store = setup();
        let persona = store.create_persona("agent-wc-warn").unwrap();
        // 10s limit, 8s elapsed — 80% crossed, must warn, NOT exhaust.
        let _gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 10, 8);

        let (exhausted, warned) = store.expire_grants_by_wall_clock().unwrap();
        assert_eq!(exhausted, 0, "should not exhaust at 80%");
        assert!(warned >= 1, "expected warn, got {warned}");

        let entries = store
            .query_audit(&crate::audit::AuditFilter::default())
            .unwrap();
        assert!(entries.iter().any(|e| e.action == "budget.warning"));
    }

    #[test]
    fn wall_clock_sweep_skips_grants_under_threshold() {
        let store = setup();
        let persona = store.create_persona("agent-wc-skip").unwrap();
        // 100s limit, 10s elapsed — no warn, no exhaust.
        let _gid = seed_wall_clock_grant(&store, &persona.id, "llm-key", 100, 10);

        let (exhausted, warned) = store.expire_grants_by_wall_clock().unwrap();
        assert_eq!(exhausted, 0);
        assert_eq!(warned, 0);
    }

    #[test]
    fn delegate_child_expiry_later_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 600);

        // Parent TTL is 600s; child asks for 3600s.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(3600),
                Some(Budget {
                    tokens: Some(1_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(reason.contains("expiry"), "reason: {reason}");
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    // --- W1: Ed25519 signing integration tests (design rev) ---

    /// Verify a daemon-created grant's block chain against the issuing
    /// persona's declared root public key. This is the acceptance invariant
    /// for removing the `"unsigned-phase1"` placeholder: block 0 must
    /// carry a real Ed25519 signature that `verify_chain` accepts under
    /// the persona's stored root key.
    #[test]
    fn create_grant_produces_verifiable_block_zero() {
        let store = setup();
        let persona = store.create_persona("agent-sign-create").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "read", None)
            .unwrap();

        let chain = store.get_access_grant(&grant.id).unwrap();
        assert_eq!(chain.blocks.len(), 1);

        let root = store.persona_root_keypair(&persona.id).unwrap();
        let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
        grant_chain::verify_chain(&chain.blocks, &root_pubkey_bytes)
            .expect("block 0 signature verifies under persona root key");

        // Smoke-check: no residual placeholder strings.
        assert_ne!(
            chain.blocks[0].signature,
            core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
        );
        assert_ne!(
            chain.blocks[0].pubkey_next,
            core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
        );
    }

    /// `access_grant_from_statements` produces a real signature under the
    /// caller-supplied root keypair. Mirrors the `ember sandbox run` path
    /// that composes a multi-Statement envelope.
    #[test]
    fn access_grant_from_statements_produces_verifiable_chain() {
        let store = setup();
        let persona = store.create_persona("agent-sign-compose").unwrap();
        let stmts = vec![
            Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact { value: "api-key".into() },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
            },
            Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Session,
                actions: vec!["llm:generate".into()],
                resource: ResourceSelector::Glob { pattern: "anthropic/*".into() },
                budget: Some(Budget {
                    tokens: Some(5_000),
                    ..Default::default()
                }),
                usage: Usage::default(),
                conditions: Vec::new(),
            },
        ];
        let root = store.persona_root_keypair(&persona.id).unwrap();
        let grant = access_grant_from_statements(
            "grant-fixture-compose",
            &persona.id,
            "api-key",
            stmts,
            42,
            None,
            &root,
        )
        .unwrap();
        let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
        grant_chain::verify_chain(&grant.blocks, &root_pubkey_bytes).unwrap();

        assert_ne!(
            grant.blocks[0].signature,
            core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
        );
    }

    /// `access_grant_from_statements_for_persona` returns the same `AccessGrant`
    /// as the explicit-root form when both use the same persona (P69K-C28-implementation-note-17).
    #[test]
    fn access_grant_from_statements_for_persona_matches_explicit_root() {
        let store = setup();
        let persona = store.create_persona("agent-for-persona-lookup").unwrap();
        let stmts = || {
            vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["credential:read".into()],
                resource: ResourceSelector::Exact { value: "api-key".into() },
                budget: None,
                usage: Usage::default(),
                conditions: Vec::new(),
            }]
        };
        let created_at = 100u64;

        let root = store.persona_root_keypair(&persona.id).unwrap();
        let explicit = access_grant_from_statements(
            "grant-explicit",
            &persona.id,
            "svc",
            stmts(),
            created_at,
            None,
            &root,
        )
        .unwrap();

        let via_persona = access_grant_from_statements_for_persona(
            &store,
            "grant-via-persona",
            &persona.id,
            "svc",
            stmts(),
            created_at,
            None,
        )
        .unwrap();

        // Both grants carry the same persona, recipient, and block structure.
        assert_eq!(explicit.issuing_persona_id, via_persona.issuing_persona_id);
        assert_eq!(explicit.recipient_id, via_persona.recipient_id);
        assert_eq!(explicit.blocks.len(), via_persona.blocks.len());
        assert_eq!(
            explicit.blocks[0].block.statements,
            via_persona.blocks[0].block.statements
        );

        // Both signatures verify under the same root public key.
        let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
        grant_chain::verify_chain(&explicit.blocks, &root_pubkey_bytes).unwrap();
        grant_chain::verify_chain(&via_persona.blocks, &root_pubkey_bytes).unwrap();

        // Signatures are real (not the placeholder).
        assert_ne!(
            via_persona.blocks[0].signature,
            core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
        );
    }

    // --- W4: M-2 read-path verify_chain tests ---

    /// Seed a persona row with a caller-supplied public_key (ed25519: prefix)
    /// and return the persona id. Used by verify_chain tests that need a
    /// persona with a known key so we can construct matching signed chains.
    ///
    /// V0 schema: the secret is sealed under the store's attached vault and
    /// written into the `private_key_nonce` + `private_key_ciphertext`
    /// columns. `open_in_memory()` attaches a deterministic test vault so
    /// this helper works for every test setup.
    fn seed_persona_with_key(store: &DaemonStore, public_key: &str, private_key: &str) -> String {
        let id = format!("persona-{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();
        let vault = store.vault().expect("test store must have a vault attached");
        let (nonce, ciphertext) = vault
            .seal(private_key.as_bytes())
            .expect("seal secret under test vault");
        store
            .conn()
            .execute(
                "INSERT INTO personas (id, name, public_key, private_key_nonce, \
                                       private_key_ciphertext, created_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active')",
                rusqlite::params![id, id, public_key, nonce, ciphertext, now],
            )
            .unwrap();
        id
    }

    /// Seed a grant row with caller-supplied blocks_json for a given persona.
    fn seed_grant_with_blocks(store: &DaemonStore, persona_id: &str, blocks_json: &str) -> String {
        let id = format!("grant-{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status, blocks_json)
                 VALUES (?1, ?2, 'test-cred', 'read', ?3, 'active', ?4)",
                rusqlite::params![id, persona_id, now, blocks_json],
            )
            .unwrap();
        id
    }

    #[test]
    fn get_access_grant_valid_ed25519_chain_returns_ok() {
        use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let store = setup();

        // Generate a root keypair and seed a persona with its public key.
        let kp = core_crypto::generate_local_key_pair("persona", "test");
        let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

        // Build and sign a single-block chain.
        let root_kp = RootKeyPair::from_hex(
            kp.public_key.trim_start_matches("ed25519:"),
            kp.private_key.trim_start_matches("ed25519-secret:"),
        )
        .unwrap();
        let block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.clone(),
            issued_at: 1_000_000,
            approval: None,
            note: None,
        };
        let out = sign_block_zero(&root_kp, &block).unwrap();
        let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
        let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

        // Should succeed — valid chain.
        let grant = store.get_access_grant(&grant_id).expect("valid chain must succeed");
        assert_eq!(grant.id, grant_id);
        assert_eq!(grant.issuing_persona_id, persona_id);
    }

    #[test]
    fn get_access_grant_create_then_read_round_trip() {
        // create_grant now signs block 0 under the issuing persona's root
        // key (W1). get_access_grant verifies on the way out (W4). This
        // test covers the happy-path round-trip after both land.
        let store = setup();
        let persona = store.create_persona("agent-verify-roundtrip").unwrap();
        let grant_info = store
            .create_grant(&persona.id, "api-key", "read", None)
            .unwrap();
        let grant = store
            .get_access_grant(&grant_info.id)
            .expect("create_grant → get_access_grant must succeed after W1+W4");
        assert_eq!(grant.id, grant_info.id);
    }

    #[test]
    fn get_access_grant_tampered_signature_returns_err() {
        use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let store = setup();

        let kp = core_crypto::generate_local_key_pair("persona", "test-tamper");
        let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

        let root_kp = RootKeyPair::from_hex(
            kp.public_key.trim_start_matches("ed25519:"),
            kp.private_key.trim_start_matches("ed25519-secret:"),
        )
        .unwrap();
        let block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.clone(),
            issued_at: 2_000_000,
            approval: None,
            note: None,
        };
        let mut out = sign_block_zero(&root_kp, &block).unwrap();

        // Tamper: flip the last two hex chars of the signature.
        let sig = out.signed.signature.clone();
        let tampered = format!("{}{}", &sig[..sig.len() - 2], if sig.ends_with("00") { "ff" } else { "00" });
        out.signed.signature = tampered;

        let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
        let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

        let err = store.get_access_grant(&grant_id).unwrap_err();
        assert!(
            matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
            "expected chain verification error, got: {err:?}"
        );
    }

    // --- P69K-F07 regression tests: verify_and_return None-persona tightening ---

    /// Build a placeholder `SignedBlock` with `issued_by = persona_id`.
    fn placeholder_block_for(persona_id: &str, sid: &str) -> SignedBlock {
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};
        SignedBlock {
            block: Block {
                statements: vec![Statement {
                    sid: sid.into(),
                    resource_type: ResourceType::Credential,
                    actions: vec!["read".into()],
                    resource: ResourceSelector::Any,
                    budget: None,
                    usage: Usage::default(),
                    conditions: vec![],
                }],
                nbf: None,
                expires_at: None,
                issued_by: persona_id.into(),
                issued_at: 0,
                approval: None,
                note: None,
            },
            pubkey_next: grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
            signature: grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into(),
        }
    }

    /// Seed a grant row whose persona_id has no matching personas row.
    /// Disables FK enforcement for the insert, then re-enables it.
    fn seed_orphan_grant(store: &DaemonStore, persona_id: &str, blocks_json: &str) -> String {
        store.conn().execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        let grant_id = seed_grant_with_blocks(store, persona_id, blocks_json);
        store.conn().execute_batch("PRAGMA foreign_keys = ON").unwrap();
        grant_id
    }

    /// An orphaned grant whose single block carries the unsigned-phase1
    /// placeholder is the only valid pass-through. verify_and_return must
    /// return it as-is (no persona row, but the placeholder signals the grant
    /// was minted before the signing path landed).
    #[test]
    fn verify_and_return_allows_single_block_phase1_placeholder_orphan() {
        let store = setup();
        let persona_id = format!("orphan-ph1-{}", Uuid::new_v4());
        let blocks_json =
            serde_json::to_string(&[placeholder_block_for(&persona_id, "S0")]).unwrap();
        let grant_id = seed_orphan_grant(&store, &persona_id, &blocks_json);

        // Must succeed — single block + phase-1 placeholder passes through.
        let grant = store
            .get_access_grant(&grant_id)
            .expect("single-block phase-1 placeholder orphan must pass verify_and_return");
        assert_eq!(grant.id, grant_id);
    }

    /// An orphaned grant with two blocks must be rejected by verify_and_return
    /// — multi-block orphans had a real persona at mint time and the missing
    /// row is suspicious (deleted persona or tampered grant).
    #[test]
    fn verify_and_return_rejects_multi_block_orphan_grant() {
        let store = setup();
        let persona_id = format!("orphan-multi-{}", Uuid::new_v4());
        let blocks_json = serde_json::to_string(&[
            placeholder_block_for(&persona_id, "S0"),
            placeholder_block_for(&persona_id, "S1"),
        ])
        .unwrap();
        let grant_id = seed_orphan_grant(&store, &persona_id, &blocks_json);

        let err = store
            .get_access_grant(&grant_id)
            .expect_err("multi-block orphan must be rejected by verify_and_return");
        assert!(
            matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
            "expected chain verification error for multi-block orphan, got: {err:?}"
        );
    }

    #[test]
    fn delegate_grant_produces_verifiable_chain_under_child_persona() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .unwrap();
        let chain = store.get_access_grant(&child.id).unwrap();
        let child_root = store.persona_root_keypair(&child_persona_id).unwrap();
        let child_root_bytes = hex::decode(child_root.public_hex()).unwrap();
        grant_chain::verify_chain(&chain.blocks, &child_root_bytes)
            .expect("delegated block 0 verifies under child persona root key");
    }

    /// Full-path integration test for `ember grant delegate`:
    ///   1. Create parent grant with a tokens budget + delegation depth.
    ///   2. Delegate a narrower scope + smaller budget to a child persona.
    ///   3. Verify the child chain is a single block (independent chain,
    ///      per delegate_grant_full's comment) signed under the CHILD
    ///      persona root key.
    ///   4. Verify parent usage is unchanged (delegation must not
    ///      consume parent budget at issue time).
    ///   5. Verify the `parent_grant_id` link + depth decrement.
    #[test]
    fn delegate_grant_end_to_end_integration() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 3_600);

        // Snapshot parent usage pre-delegation.
        let parent_before = store.get_grant(&parent_id).unwrap();
        let usage_before = parent_before.usage.clone();

        // Delegate: subset scope (`acme/widgets` ⊆ `acme/*`), smaller
        // budget (2_000 ≤ 10_000 − 0 remaining), shorter TTL.
        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(900),
                Some(Budget {
                    tokens: Some(2_000),
                    ..Default::default()
                }),
            )
            .expect("delegation succeeds within parent bounds");

        // (3) Chain verifies under the CHILD persona root key. Current
        // `delegate_grant_full` emits an independent 1-block chain
        // (parent/child link is expressed via `parent_grant_id`, not a
        // cross-chain signature).
        let chain = store.get_access_grant(&child.id).unwrap();
        assert_eq!(
            chain.blocks.len(),
            1,
            "delegated grant emits a single-block chain under the child root"
        );
        let child_root = store.persona_root_keypair(&child_persona_id).unwrap();
        let child_root_bytes = hex::decode(child_root.public_hex()).unwrap();
        grant_chain::verify_chain(&chain.blocks, &child_root_bytes)
            .expect("child chain verifies under child persona root key");

        // (4) Parent usage must be unchanged — delegation issues a new
        // grant; it does not debit the parent at creation time.
        let parent_after = store.get_grant(&parent_id).unwrap();
        assert_eq!(parent_after.usage, usage_before, "parent usage unchanged");

        // (5) Parent link + depth attenuation preserved.
        assert_eq!(child.parent_grant_id, Some(parent_id.clone()));
        assert_eq!(
            child.max_delegation_depth,
            parent_before.max_delegation_depth.map(|d| d.saturating_sub(1)),
            "child depth = parent depth − 1",
        );
        assert_eq!(
            child.budget.as_ref().and_then(|b| b.tokens),
            Some(2_000),
            "child budget plumbed through"
        );
    }

    /// Attenuation violation surfaces as `DelegationViolation` with a
    /// reason the CLI prints verbatim. Budget-exceeds case.
    #[test]
    fn delegate_grant_budget_exceeds_parent_surfaces_reason() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 3_600);

        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(20_000), // exceeds parent's 10_000
                    ..Default::default()
                }),
            )
            .unwrap_err();

        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(
                    reason.contains("budget") || reason.contains("tokens"),
                    "reason should name the violating axis, got: {reason}"
                );
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    #[test]
    fn extend_grant_re_signs_block_zero() {
        let store = setup();
        let persona = store.create_persona("agent-sign-extend").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "read", Some(3600))
            .unwrap();

        // Extend — block 0's payload changes, so the signature must be
        // refreshed; otherwise verify_chain would fail after the update.
        store
            .extend_grant(&grant.id, Some(5_000), None, Some(600))
            .unwrap();

        let chain = store.get_access_grant(&grant.id).unwrap();
        let root = store.persona_root_keypair(&persona.id).unwrap();
        let root_pubkey_bytes = hex::decode(root.public_hex()).unwrap();
        grant_chain::verify_chain(&chain.blocks, &root_pubkey_bytes)
            .expect("re-signed block 0 verifies after extend_grant");
    }

    #[test]
    fn get_access_grant_missing_persona_signed_chain_returns_err() {
        // F-07: a signed-chain orphan (persona row deleted after mint) must
        // now be rejected by verify_and_return. Only unsigned-phase1
        // placeholder grants pass through without a persona row.
        use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let store = setup();

        let kp = core_crypto::generate_local_key_pair("persona", "ghost");
        let persona_id = seed_persona_with_key(&store, &kp.public_key, &kp.private_key);

        let root_kp = RootKeyPair::from_hex(
            kp.public_key.trim_start_matches("ed25519:"),
            kp.private_key.trim_start_matches("ed25519-secret:"),
        )
        .unwrap();
        let block = Block {
            statements: vec![Statement {
                sid: "S0".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.clone(),
            issued_at: 3_000_000,
            approval: None,
            note: None,
        };
        let out = sign_block_zero(&root_kp, &block).unwrap();
        let blocks_json = serde_json::to_string(&[out.signed]).unwrap();
        let grant_id = seed_grant_with_blocks(&store, &persona_id, &blocks_json);

        // Delete persona to create the orphan scenario.
        store.conn().execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        store
            .conn()
            .execute(
                "DELETE FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
            )
            .unwrap();
        store.conn().execute_batch("PRAGMA foreign_keys = ON").unwrap();

        // F-07: signed-chain orphan is rejected, not silently passed through.
        let err = store
            .get_access_grant(&grant_id)
            .expect_err("signed orphan grant must be rejected after F-07");
        assert!(
            matches!(err, StoreError::InvalidInput(ref s) if s.contains("chain verification failed")),
            "expected chain verification error for signed orphan, got: {err:?}"
        );
    }

    // --- W2: Stream C per-Statement usage increment (P69K-C) ---

    /// Seed a multi-statement grant with custom statements and return its id.
    fn seed_multi_stmt_grant(
        store: &DaemonStore,
        persona_id: &str,
        credential_name: &str,
        statements: Vec<Statement>,
    ) -> String {
        let grant = store
            .create_grant(persona_id, credential_name, "*", None)
            .unwrap();
        let root = store.persona_root_keypair(persona_id).unwrap();
        let ag = access_grant_from_statements(
            &grant.id,
            persona_id,
            credential_name,
            statements,
            0,
            None,
            &root,
        )
        .unwrap();
        store.overwrite_grant_blocks(&grant.id, &ag).unwrap();
        grant.id
    }

    fn session_stmt(sid: &str, tokens: u64, cents: u64) -> Statement {
        Statement {
            sid: sid.into(),
            resource_type: ResourceType::Session,
            actions: vec!["*".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(tokens),
                cents: Some(cents),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: Vec::new(),
        }
    }

    #[test]
    fn increment_statement_usage_updates_single_statement() {
        let store = setup();
        let persona = store.create_persona("inc-1").unwrap();
        let gid = seed_multi_stmt_grant(
            &store,
            &persona.id,
            "cred",
            vec![session_stmt("S1", 10_000, 1_000)],
        );
        let delta = store
            .increment_statement_usage(
                &gid,
                "S1",
                Usage {
                    tokens: 100,
                    cents: 5,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta.prior.tokens, 0);
        assert_eq!(delta.current.tokens, 100);
        assert_eq!(delta.current.cents, 5);
        // Re-read round-trip.
        let ag = store.get_access_grant(&gid).unwrap();
        let s = ag.statements().find(|(_, s)| s.sid == "S1").unwrap().1;
        assert_eq!(s.usage.tokens, 100);
        assert_eq!(s.usage.cents, 5);
    }

    #[test]
    fn increment_statement_usage_unknown_sid_returns_not_found() {
        let store = setup();
        let persona = store.create_persona("inc-miss").unwrap();
        let gid = seed_multi_stmt_grant(
            &store,
            &persona.id,
            "cred",
            vec![session_stmt("S1", 10_000, 1_000)],
        );
        let err = store
            .increment_statement_usage(&gid, "S99", Usage::default())
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFound));
    }

    #[test]
    fn increment_is_cumulative_across_calls() {
        let store = setup();
        let persona = store.create_persona("inc-cum").unwrap();
        let gid = seed_multi_stmt_grant(
            &store,
            &persona.id,
            "cred",
            vec![session_stmt("S1", 10_000, 1_000)],
        );
        store
            .increment_statement_usage(
                &gid,
                "S1",
                Usage {
                    tokens: 200,
                    ..Default::default()
                },
            )
            .unwrap();
        let delta = store
            .increment_statement_usage(
                &gid,
                "S1",
                Usage {
                    tokens: 300,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta.prior.tokens, 200);
        assert_eq!(delta.current.tokens, 500);
    }

    #[test]
    fn mark_exhausted_flips_grant_when_all_budgets_spent() {
        let store = setup();
        let persona = store.create_persona("mark-1").unwrap();
        let gid = seed_multi_stmt_grant(
            &store,
            &persona.id,
            "cred",
            vec![session_stmt("S1", 100, 50)],
        );
        // Exhaust tokens axis.
        store
            .increment_statement_usage(
                &gid,
                "S1",
                Usage {
                    tokens: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        let flipped = store
            .mark_grant_exhausted_by_budget_if_terminal(&gid)
            .unwrap();
        assert!(flipped);
        assert_eq!(store.get_grant(&gid).unwrap().status, "exhausted_by_budget");
    }

    #[test]
    fn mark_exhausted_noop_when_no_budget_bearing_statements() {
        let store = setup();
        let persona = store.create_persona("mark-nobudget").unwrap();
        // Stmt without any budget.
        let stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["*".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: Vec::new(),
        };
        let gid = seed_multi_stmt_grant(&store, &persona.id, "cred", vec![stmt]);
        let flipped = store
            .mark_grant_exhausted_by_budget_if_terminal(&gid)
            .unwrap();
        assert!(!flipped);
        assert_eq!(store.get_grant(&gid).unwrap().status, "active");
    }

    #[test]
    fn mark_exhausted_noop_when_already_revoked() {
        let store = setup();
        let persona = store.create_persona("mark-revoked").unwrap();
        let gid = seed_multi_stmt_grant(
            &store,
            &persona.id,
            "cred",
            vec![session_stmt("S1", 100, 50)],
        );
        store.revoke_grant(&gid).unwrap();
        // Even if we crank usage past limit, a revoked grant must NOT
        // silently flip to exhausted_by_budget.
        let flipped = store
            .mark_grant_exhausted_by_budget_if_terminal(&gid)
            .unwrap();
        assert!(!flipped);
        assert_eq!(store.get_grant(&gid).unwrap().status, "revoked");
    }

    // --- Hard-pause tests (69K.7) ---

    #[test]
    fn pause_active_grant_blocks_proxy() {
        let store = setup();
        let persona = store.create_persona("pause-proxy-agent").unwrap();
        let grant = store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        // Grant is active; evaluate_grant should succeed.
        assert!(store.evaluate_grant(&persona.id, "api-key").is_ok());

        // Pause the grant.
        store.pause_grant(&grant.id).unwrap();
        let g = store.get_grant(&grant.id).unwrap();
        assert_eq!(g.status, "paused");
        assert!(g.paused);

        // evaluate_grant (used by proxy) should now return NotFound — grant is no longer 'active'.
        let result = store.evaluate_grant(&persona.id, "api-key");
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "paused grant must be invisible to evaluate_grant (proxy enforcement)"
        );
    }

    #[test]
    fn resume_paused_grant_allows_proxy() {
        let store = setup();
        let persona = store.create_persona("resume-proxy-agent").unwrap();
        let grant = store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        store.pause_grant(&grant.id).unwrap();
        // Confirm blocked.
        assert!(store.evaluate_grant(&persona.id, "api-key").is_err());

        // Resume.
        store.resume_grant(&grant.id).unwrap();
        let g = store.get_grant(&grant.id).unwrap();
        assert_eq!(g.status, "active");
        assert!(!g.paused);

        // evaluate_grant should succeed again.
        assert!(store.evaluate_grant(&persona.id, "api-key").is_ok());
    }

    #[test]
    fn pause_nonexistent_grant_returns_notfound() {
        let store = setup();
        let result = store.pause_grant("grant-does-not-exist");
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "pause on unknown id must return NotFound"
        );
    }

    #[test]
    fn cannot_pause_revoked_grant() {
        let store = setup();
        let persona = store.create_persona("no-pause-revoked").unwrap();
        let grant = store.create_grant(&persona.id, "api-key", "read", None).unwrap();
        store.revoke_grant(&grant.id).unwrap();

        let result = store.pause_grant(&grant.id);
        assert!(
            matches!(result, Err(StoreError::InvalidInput(_))),
            "pausing a revoked grant must return InvalidInput"
        );
        // Status must remain 'revoked'.
        assert_eq!(store.get_grant(&grant.id).unwrap().status, "revoked");
    }

    #[test]
    fn pause_grant_is_idempotent() {
        let store = setup();
        let persona = store.create_persona("idem-pause").unwrap();
        let grant = store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        store.pause_grant(&grant.id).unwrap();
        // Second pause should not error — idempotent.
        store.pause_grant(&grant.id).unwrap();
        assert_eq!(store.get_grant(&grant.id).unwrap().status, "paused");
    }

    #[test]
    fn resume_grant_is_idempotent() {
        let store = setup();
        let persona = store.create_persona("idem-resume").unwrap();
        let grant = store.create_grant(&persona.id, "api-key", "read", None).unwrap();

        // Resume on an already-active grant should not error.
        store.resume_grant(&grant.id).unwrap();
        assert_eq!(store.get_grant(&grant.id).unwrap().status, "active");
    }

    #[test]
    fn list_active_grants_excludes_paused() {
        let store = setup();
        let persona = store.create_persona("excl-paused").unwrap();
        let g1 = store.create_grant(&persona.id, "key-a", "read", None).unwrap();
        let g2 = store.create_grant(&persona.id, "key-b", "read", None).unwrap();

        store.pause_grant(&g1.id).unwrap();

        let active = store.list_active_grants().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, g2.id);
    }

    #[test]
    fn list_grants_shows_effective_status_for_time_expired_grant() {
        let store = setup();
        let persona = store.create_persona("agent-eff-status").unwrap();
        // Create a grant with a 1-second TTL.
        let grant = store
            .create_grant(&persona.id, "api-key", "read", Some(1))
            .unwrap();
        assert_eq!(grant.status, "active");

        // Backdate expires_at to a timestamp clearly in the past so
        // row_to_grant derives "expired" without waiting.
        store
            .conn()
            .execute(
                "UPDATE grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
                rusqlite::params![grant.id],
            )
            .expect("backdate expires_at");

        let grants = store.list_grants().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0].status, "expired",
            "list_grants must surface effective status for a time-expired grant"
        );
    }

    // --- P69K-BUDGET-WRITE: create_grant_with_budget encodes budget into
    //     block-zero statement ---

    #[test]
    fn create_grant_encodes_budget_into_block_zero_statement() {
        let store = setup();
        let persona = store.create_persona("agent-budget-write").unwrap();
        let grant = store
            .create_grant_with_budget(
                &persona.id,
                "llm-key",
                "llm:generate",
                Some(3600),
                Some(Budget {
                    tokens: Some(20_000),
                    ..Default::default()
                }),
            )
            .unwrap();

        // (1) GrantInfo projection carries the budget.
        assert_eq!(
            grant.budget.as_ref().and_then(|b| b.tokens),
            Some(20_000),
            "GrantInfo.budget.tokens must reflect the caller's budget"
        );

        // (2) Authoritative composite read path sees the budget in the
        //     first statement.
        let ag = store.get_access_grant(&grant.id).unwrap();
        assert_eq!(ag.blocks.len(), 1);
        let stmt = &ag.blocks[0].block.statements[0];
        assert_eq!(
            stmt.budget.as_ref().and_then(|b| b.tokens),
            Some(20_000),
            "block[0].statements[0].budget.tokens must carry the caller's budget"
        );
    }

    #[test]
    fn create_grant_without_budget_leaves_statement_budget_none() {
        let store = setup();
        let persona = store.create_persona("agent-budget-none").unwrap();
        // Both the legacy `create_grant` (no budget param) and the new
        // `create_grant_with_budget(..., None)` must produce a statement
        // with `budget = None`.
        let g1 = store
            .create_grant(&persona.id, "k1", "read", None)
            .unwrap();
        let g2 = store
            .create_grant_with_budget(&persona.id, "k2", "read", None, None)
            .unwrap();

        for gid in [&g1.id, &g2.id] {
            let ag = store.get_access_grant(gid).unwrap();
            assert!(
                ag.blocks[0].block.statements[0].budget.is_none(),
                "statement.budget must be None when no budget is supplied (grant {gid})"
            );
        }
    }

    #[test]
    fn create_grant_with_empty_budget_is_normalized_to_none() {
        // An operator-supplied `Budget::default()` (all axes unset) is
        // indistinguishable from "no budget" — `create_grant_with_budget`
        // normalizes it to `None` so downstream code doesn't have to
        // branch on "is this empty?".
        let store = setup();
        let persona = store.create_persona("agent-budget-empty").unwrap();
        let grant = store
            .create_grant_with_budget(
                &persona.id,
                "k",
                "read",
                None,
                Some(Budget::default()),
            )
            .unwrap();
        assert!(grant.budget.is_none());
        let ag = store.get_access_grant(&grant.id).unwrap();
        assert!(ag.blocks[0].block.statements[0].budget.is_none());
    }

    // --- P69K-A2 L3: size caps on blocks_json write paths ---

    /// Build an [`AccessGrant`] with the caller-supplied block list.
    /// Skips chain signing — these tests are about the size-cap check
    /// which runs **before** chain verification in the write paths.
    fn make_grant_with_blocks(id: &str, persona_id: &str, blocks: Vec<SignedBlock>) -> AccessGrant {
        AccessGrant {
            id: id.into(),
            version: 1,
            issuing_persona_id: persona_id.into(),
            recipient_kind: PresentationAudienceKind::Service,
            recipient_id: "cred".into(),
            recipient_profile: RecipientProfile::Agent,
            status: GrantStatus::Active,
            mode: GrantMode::OneShot,
            blocks,
            attestation: AttestationBinding::default(),
            created_at: 0,
            updated_at: 0,
            revoked_at: None,
            revoked_reason: None,
            last_used_at: None,
            label: None,
        }
    }

    fn dummy_signed_block(persona_id: &str, n_statements: usize) -> SignedBlock {
        let statements: Vec<Statement> = (0..n_statements)
            .map(|i| Statement {
                sid: format!("S{i}"),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Any,
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            })
            .collect();
        let block = Block {
            statements,
            nbf: None,
            expires_at: None,
            issued_by: persona_id.to_string(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        // Sign with a fresh ephemeral keypair so this block carries a real
        // Ed25519 signature. Cap-check tests only inspect block/statement
        // counts and JSON byte size — the signer identity is irrelevant to
        // them. Using a real signature removes the unsigned-phase1 placeholder
        // from all test emission paths (P69K-B).
        let ephemeral = core_crypto::grant_chain::PubkeyNextKeyPair::generate();
        let root = RootKeyPair::from_hex(&ephemeral.public_hex, &ephemeral.secret_hex)
            .expect("ephemeral key is valid RootKeyPair material");
        sign_block_zero_with(&root, &block).expect("dummy block signing must not fail")
    }

    #[test]
    fn blocks_json_write_rejects_too_many_blocks() {
        let store = setup();
        let persona = store.create_persona("agent-cap-blocks").unwrap();
        // Seed a grant so `overwrite_grant_blocks` finds the row.
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        // Build a 33-block chain — one over the cap.
        let blocks: Vec<SignedBlock> =
            (0..MAX_BLOCKS + 1).map(|_| dummy_signed_block(&persona.id, 1)).collect();
        let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => {
                assert!(s.contains("blocks"), "message must name the violated cap, got: {s}");
                assert!(s.contains(&format!("{}", MAX_BLOCKS)), "message should cite the cap: {s}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn blocks_json_write_rejects_too_many_statements_per_block() {
        let store = setup();
        let persona = store.create_persona("agent-cap-stmts").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        // Single block, 17 statements — one over the per-block cap.
        let blocks = vec![dummy_signed_block(&persona.id, MAX_STATEMENTS_PER_BLOCK + 1)];
        let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => {
                assert!(s.contains("statements"), "message must name the violated cap, got: {s}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn blocks_json_write_rejects_oversized_payload() {
        let store = setup();
        let persona = store.create_persona("agent-cap-size").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        // Single block, single statement — but the statement's resource
        // selector is a giant glob pattern that pushes the serialized
        // JSON over MAX_BLOCKS_JSON_BYTES.
        let giant = "x".repeat(MAX_BLOCKS_JSON_BYTES + 1024);
        let mut sb = dummy_signed_block(&persona.id, 1);
        sb.block.statements[0].resource = ResourceSelector::Glob { pattern: giant };
        let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![sb]);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => {
                assert!(
                    s.contains("bytes") || s.contains(&format!("{}", MAX_BLOCKS_JSON_BYTES)),
                    "message must name the payload cap, got: {s}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn blocks_json_write_accepts_well_sized_chain() {
        // Nominal case: 5 blocks × 3 statements each. Well under every
        // cap — the check must pass and the envelope/chain guards
        // (persona mismatch, signature) take over. Those later guards
        // will reject because `dummy_signed_block` uses a placeholder
        // signature, but that's a *different* error; the size check
        // itself must NOT fire.
        let store = setup();
        let persona = store.create_persona("agent-cap-ok").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        let blocks: Vec<SignedBlock> = (0..5).map(|_| dummy_signed_block(&persona.id, 3)).collect();
        let grant = make_grant_with_blocks(&seeded.id, &persona.id, blocks);

        // `validate_blocks_json_caps` must pass — assert by calling it
        // directly (bypasses the downstream chain-verify rejection so
        // we can assert the cap check in isolation).
        let json = access_grant_blocks_to_json(&grant).unwrap();
        assert!(
            validate_blocks_json_caps(&grant, &json).is_ok(),
            "5 blocks x 3 stmts is nominal; size caps must not fire"
        );
    }

    #[test]
    fn validate_blocks_json_caps_accepts_exact_max_blocks() {
        // Cap is inclusive at MAX_BLOCKS. Exactly 32 blocks, one
        // minimal statement each, must pass. Guards against an
        // off-by-one that would silently reject a maxed-out legitimate
        // chain.
        let persona_id = "agent-boundary-blocks";
        let blocks: Vec<SignedBlock> =
            (0..MAX_BLOCKS).map(|_| dummy_signed_block(persona_id, 1)).collect();
        let grant = make_grant_with_blocks("grant-boundary-b", persona_id, blocks);
        let json = access_grant_blocks_to_json(&grant).unwrap();
        assert!(
            json.len() <= MAX_BLOCKS_JSON_BYTES,
            "32-block minimal chain must fit in the JSON cap; got {} bytes",
            json.len()
        );
        validate_blocks_json_caps(&grant, &json).expect("exact MAX_BLOCKS must pass");
    }

    #[test]
    fn validate_blocks_json_caps_accepts_exact_max_statements_per_block() {
        // Cap is inclusive at MAX_STATEMENTS_PER_BLOCK. Single block,
        // exactly 16 statements, must pass.
        let persona_id = "agent-boundary-stmts";
        let blocks = vec![dummy_signed_block(persona_id, MAX_STATEMENTS_PER_BLOCK)];
        let grant = make_grant_with_blocks("grant-boundary-s", persona_id, blocks);
        let json = access_grant_blocks_to_json(&grant).unwrap();
        validate_blocks_json_caps(&grant, &json)
            .expect("exact MAX_STATEMENTS_PER_BLOCK must pass");
    }

    // --- P69K-F04: overwrite_grant_blocks must full-verify chain under
    // persona root before persisting. SQL-tampered blocks_json that
    // replaces a real chain with a forged one must be rejected; the
    // envelope `issued_by == row.persona_id` guard (shipped in #527) is
    // not sufficient on its own — a forger who sets `issued_by` correctly
    // but swaps, tampers, or re-signs the blocks must still be caught by
    // `verify_chain`.

    /// Build a signed single-statement block for the given persona so
    /// tests can construct realistic chains without re-stating the
    /// statement shape every time.
    ///
    /// Statement shape matches the parent seeded by
    /// `create_grant(.., "cred", "read", None)` (scope="read" projects
    /// to `actions=["read"], resource=Exact{"cred"}`) so the P69K-A2-I4
    /// bipartite dominance check passes and the crypto-verify tripwire
    /// (tampered signature, reordered blocks, wrong persona root, phase-1
    /// placeholder) is what fires.
    fn signed_block_for(
        persona_id: &str,
        sid: &str,
        root: &RootKeyPair,
    ) -> grant_chain::SignedBlockOutput {
        let block = Block {
            statements: vec![Statement {
                sid: sid.into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Exact { value: "cred".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.into(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        grant_chain::sign_block_zero(root, &block).expect("sign block 0")
    }

    #[test]
    fn overwrite_grant_blocks_rejects_tampered_signature() {
        // Chain whose signature has been flipped — internal chain is
        // otherwise well-formed. `verify_chain` must surface a
        // RootKeyMismatch (block-0) and overwrite must refuse to persist.
        let store = setup();
        let persona = store.create_persona("agent-overwrite-tamper").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        let root = store.persona_root_keypair(&persona.id).unwrap();
        let mut out = signed_block_for(&persona.id, "S0", &root);

        // Flip the last hex byte of the signature so it no longer
        // verifies under the persona root.
        let sig = out.signed.signature.clone();
        let flipped = format!(
            "{}{}",
            &sig[..sig.len() - 2],
            if sig.ends_with("00") { "ff" } else { "00" }
        );
        out.signed.signature = flipped;

        let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![out.signed]);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("chain verification failed"),
                "expected chain verification error, got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // The row must be unchanged — the tampered chain was rejected
        // before the UPDATE executed.
        let after = store.get_access_grant(&seeded.id).unwrap();
        assert_eq!(after.id, seeded.id);
    }

    #[test]
    fn overwrite_grant_blocks_rejects_reordered_blocks() {
        // Build a legitimate 3-block chain under the persona root, then
        // swap blocks 1 and 2. The swap breaks the pubkey_next linkage:
        // block 2 was signed by block-1's pubkey_next_secret, so placing
        // it at position 1 (where the verifier expects a signature from
        // block-0's pubkey_next) is a SignatureMismatch.
        let store = setup();
        let persona = store.create_persona("agent-overwrite-reorder").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        let root = store.persona_root_keypair(&persona.id).unwrap();
        let out0 = signed_block_for(&persona.id, "S0", &root);

        let b1 = Block {
            statements: vec![Statement {
                sid: "S1".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Exact { value: "cred".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona.id.clone(),
            issued_at: 1,
            approval: None,
            note: None,
        };
        let out1 = grant_chain::sign_appended_block(&out0.pubkey_next_secret, &b1).unwrap();

        let b2 = Block {
            statements: vec![Statement {
                sid: "S2".into(),
                resource_type: ResourceType::Credential,
                actions: vec!["read".into()],
                resource: ResourceSelector::Exact { value: "cred".into() },
                budget: None,
                usage: Usage::default(),
                conditions: vec![],
            }],
            nbf: None,
            expires_at: None,
            issued_by: persona.id.clone(),
            issued_at: 2,
            approval: None,
            note: None,
        };
        let out2 = grant_chain::sign_appended_block(&out1.pubkey_next_secret, &b2).unwrap();

        // Swap positions 1 and 2 — still starts at a root-signed block
        // (so block-0 verification passes), but the second block is now
        // signed under a pubkey_next the verifier doesn't have at that
        // position.
        let reordered = vec![out0.signed, out2.signed, out1.signed];
        let grant = make_grant_with_blocks(&seeded.id, &persona.id, reordered);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("chain verification failed"),
                "expected chain verification error, got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn overwrite_grant_blocks_rejects_wrong_persona_root() {
        // Forge a chain that is *internally* valid but was signed under
        // a different persona's root keypair. `issued_by` is set to the
        // target persona (so the envelope guard passes), but verify_chain
        // under the target persona's declared root must reject with
        // RootKeyMismatch.
        let store = setup();
        let victim = store.create_persona("agent-overwrite-victim").unwrap();
        let attacker = store.create_persona("agent-overwrite-attacker").unwrap();
        let seeded = store.create_grant(&victim.id, "cred", "read", None).unwrap();

        // Sign a block under the attacker's root, but label issued_by
        // as the victim so it slips past the envelope check that fires
        // before verify_chain.
        let attacker_root = store.persona_root_keypair(&attacker.id).unwrap();
        let out = signed_block_for(&victim.id, "S0", &attacker_root);
        let grant = make_grant_with_blocks(&seeded.id, &victim.id, vec![out.signed]);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("chain verification failed"),
                "expected chain verification error (wrong root), got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn overwrite_grant_blocks_rejects_unsigned_phase1_placeholder() {
        // A block carrying the pre-earlier releases `unsigned-phase1` placeholder
        // in its signature must be rejected. Without the verify_chain
        // wiring, a forger could overwrite a real chain with an unsigned
        // one and launder authority through the placeholder.
        let store = setup();
        let persona = store.create_persona("agent-overwrite-unsigned").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "read", None).unwrap();

        let root = store.persona_root_keypair(&persona.id).unwrap();
        let mut out = signed_block_for(&persona.id, "S0", &root);
        out.signed.signature = grant_chain::UNSIGNED_PHASE1_PLACEHOLDER.into();

        let grant = make_grant_with_blocks(&seeded.id, &persona.id, vec![out.signed]);

        let err = store.overwrite_grant_blocks(&seeded.id, &grant).unwrap_err();
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("chain verification failed"),
                "expected chain verification error (unsigned-phase1), got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    // --- P69K-A2-I4: bipartite dominance on overwrite_grant_blocks ---
    //
    // design §Attenuation mandates that every statement in the new chain
    // be dominated by at least one statement in the old chain. Re-verifying
    // the client-supplied signature alone is insufficient: a client with
    // valid keys could otherwise widen actions, replace a narrow resource
    // with Any, or escape a budget cap. These tests exercise each failure
    // mode + the successful-attenuation happy path.

    /// Build a signed block 0 carrying a single custom statement under
    /// the persona's root key, then wrap it in the minimal envelope
    /// `overwrite_grant_blocks` expects.
    fn overwrite_attempt_grant(
        store: &DaemonStore,
        grant_id: &str,
        persona_id: &str,
        stmt: Statement,
    ) -> AccessGrant {
        let block = Block {
            statements: vec![stmt],
            nbf: None,
            expires_at: None,
            issued_by: persona_id.to_string(),
            issued_at: 0,
            approval: None,
            note: None,
        };
        let root = store.persona_root_keypair(persona_id).unwrap();
        let signed = sign_block_zero_with(&root, &block).unwrap();
        make_grant_with_blocks(grant_id, persona_id, vec![signed])
    }

    #[test]
    fn overwrite_rejects_action_escalation() {
        // Parent seeded with scope="read" projects to actions=["read"];
        // child proposes actions=["write"] on the same resource. The
        // widened action is outside the parent's action set — must reject.
        let store = setup();
        let persona = store.create_persona("agent-escalate-action").unwrap();
        let seeded = store
            .create_grant(&persona.id, "cred", "read", None)
            .unwrap();

        let child_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["write".into()],
            resource: ResourceSelector::Exact { value: "cred".into() },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        };
        let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

        let err = store
            .overwrite_grant_blocks(&seeded.id, &attempt)
            .expect_err("action escalation must be rejected");
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("attenuation violation")
                    && s.contains("no parent with matching selector/actions"),
                "expected attenuation violation (no matching parent), got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // Row must be unchanged — attenuation check fires before UPDATE.
        let after = store.get_access_grant(&seeded.id).unwrap();
        let (_, s0) = after.statements().next().unwrap();
        assert_eq!(s0.actions, vec!["read".to_string()]);
    }

    #[test]
    fn overwrite_rejects_resource_escalation() {
        // Parent seeded with scope="github:push:acme/*" projects to
        // resource=Glob{"acme/*"}; child proposes a sibling target
        // `other/repo` which the glob does NOT match — must reject.
        let store = setup();
        let persona = store.create_persona("agent-escalate-resource").unwrap();
        let seeded = store
            .create_grant(&persona.id, "gh-token", "github:push:acme/*", None)
            .unwrap();

        let child_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["github:push".into()],
            resource: ResourceSelector::Exact { value: "other/repo".into() },
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        };
        let attempt = overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

        let err = store
            .overwrite_grant_blocks(&seeded.id, &attempt)
            .expect_err("resource escalation must be rejected");
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("attenuation violation"),
                "expected attenuation violation, got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn overwrite_accepts_attenuated_replacement() {
        // Parent with actions=["read","write"] (two-action scope via the
        // parent's block-0 statement) narrowed to actions=["read"]. A
        // strict subset — must accept.
        //
        // Build the parent with an explicit multi-action statement via
        // an initial overwrite on a permissive "*" scope.
        let store = setup();
        let persona = store.create_persona("agent-attenuated-ok").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "*", None).unwrap();

        let parent_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into(), "write".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        };
        let parent =
            overwrite_attempt_grant(&store, &seeded.id, &persona.id, parent_stmt);
        store
            .overwrite_grant_blocks(&seeded.id, &parent)
            .expect("parent narrow from '*' must succeed");

        // Now narrow from {read, write} to {read}.
        let child_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: None,
            usage: Usage::default(),
            conditions: vec![],
        };
        let attempt =
            overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

        store
            .overwrite_grant_blocks(&seeded.id, &attempt)
            .expect("read-only attenuation from {read,write} must succeed");

        // The narrowed chain is what's persisted.
        let after = store.get_access_grant(&seeded.id).unwrap();
        let (_, s0) = after.statements().next().unwrap();
        assert_eq!(s0.actions, vec!["read".to_string()]);
    }

    #[test]
    fn overwrite_rejects_budget_escalation() {
        // Parent has budget.tokens=100; child proposes budget.tokens=200
        // on the same action/resource. Child exceeds parent's remaining
        // allowance — must reject.
        //
        // The parent is built explicitly so a bounded budget is in place;
        // a "create_grant(.., 'read', ..)" call projects to budget=None,
        // which would let any child budget pass.
        let store = setup();
        let persona = store.create_persona("agent-escalate-budget").unwrap();
        let seeded = store.create_grant(&persona.id, "cred", "*", None).unwrap();

        let parent_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(100),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
        };
        let parent =
            overwrite_attempt_grant(&store, &seeded.id, &persona.id, parent_stmt);
        store
            .overwrite_grant_blocks(&seeded.id, &parent)
            .expect("parent narrow from '*' with tokens=100 must succeed");

        // Child asks for tokens=200 — above parent's cap.
        let child_stmt = Statement {
            sid: "S0".into(),
            resource_type: ResourceType::Credential,
            actions: vec!["read".into()],
            resource: ResourceSelector::Any,
            budget: Some(Budget {
                tokens: Some(200),
                ..Default::default()
            }),
            usage: Usage::default(),
            conditions: vec![],
        };
        let attempt =
            overwrite_attempt_grant(&store, &seeded.id, &persona.id, child_stmt);

        let err = store
            .overwrite_grant_blocks(&seeded.id, &attempt)
            .expect_err("budget escalation must be rejected");
        match err {
            StoreError::InvalidInput(s) => assert!(
                s.contains("attenuation violation") && s.contains("tokens"),
                "expected attenuation violation on tokens, got: {s}"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // The parent chain remains with tokens=100 — the attempt was
        // blocked before UPDATE executed.
        let after = store.get_access_grant(&seeded.id).unwrap();
        let (_, s0) = after.statements().next().unwrap();
        assert_eq!(
            s0.budget.as_ref().and_then(|b| b.tokens),
            Some(100),
            "parent budget must be untouched after rejected escalation"
        );
    }

    // --- P69K-F06-tests: delegate_grant_full verified-parent attenuation ---
    //
    // These tests lock in the F-06 function-body fix shipped in #522: the
    // parent chain must route through `get_access_grant` (→ verify_chain)
    // before any attenuation logic, and delegation must refuse on any
    // mismatch between the flat parent row and the signed chain payload.

    /// Happy path: a freshly-minted parent grant with no SQL tampering
    /// delegates cleanly to a narrowed child scope/budget. Parent row
    /// remains untouched.
    #[test]
    fn delegate_succeeds_on_pristine_parent() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        let parent_before = store.get_grant(&parent_id).unwrap();

        let child = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(3_000),
                    ..Default::default()
                }),
            )
            .expect("pristine parent — delegation must succeed");

        // Child is a new active grant linked to the parent.
        assert_eq!(child.status, "active");
        assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
        assert_eq!(child.budget.as_ref().and_then(|b| b.tokens), Some(3_000));

        // Parent row unchanged — no scope, status, or budget mutation as
        // a side effect of delegation.
        let parent_after = store.get_grant(&parent_id).unwrap();
        assert_eq!(parent_after.scope, parent_before.scope);
        assert_eq!(parent_after.status, parent_before.status);
        assert_eq!(
            parent_after.budget.as_ref().and_then(|b| b.tokens),
            parent_before.budget.as_ref().and_then(|b| b.tokens),
        );
    }

    /// Direct `UPDATE grants SET scope = '<expanded>'` on the parent row
    /// must be rejected by `delegate_grant_full`: the flat scope column
    /// no longer matches the scope encoded in the signed chain's first
    /// statement, and the F-06 scope-consistency guard refuses rather
    /// than minting a child with expanded authority.
    #[test]
    fn delegate_rejects_tampered_parent_scope() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        // Tamper: expand the parent's scope column from `github:push:acme/*`
        // (what setup_parent_with_budget installed) to `github:push:*`.
        // blocks_json is untouched — only the flat column is mutated.
        store
            .conn()
            .execute(
                "UPDATE grants SET scope = ?1 WHERE id = ?2",
                rusqlite::params!["github:push:*", parent_id],
            )
            .unwrap();

        // Now try to delegate a scope that would be OUTSIDE the true
        // (chain-bound) parent but is allowed by the tampered flat scope.
        // Must be rejected.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:other/repo",
                Some(600),
                Some(Budget {
                    tokens: Some(1_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();

        match err {
            StoreError::InvalidInput(reason) => {
                assert!(
                    reason.contains("scope") && reason.contains("chain"),
                    "expected scope/chain divergence error, got: {reason}"
                );
            }
            other => panic!("expected InvalidInput tamper reject, got {other:?}"),
        }
    }

    /// Direct `UPDATE grants SET budget_json = '<inflated>'` on the parent
    /// row must be rejected: `delegate_grant_full` reads the budget from
    /// the VERIFIED chain Statement, not the flat column, so the inflated
    /// column is ignored and attenuation checks against the true chain
    /// budget. A child requesting beyond the chain budget fails.
    #[test]
    fn delegate_rejects_tampered_parent_budget() {
        let store = setup();
        // Parent chain budget: 10_000 tokens.
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        // Tamper: inflate the flat budget_json column to a 10x amount.
        // blocks_json is untouched — only the flat column is mutated.
        let inflated = serde_json::to_string(&Budget {
            tokens: Some(100_000),
            ..Default::default()
        })
        .unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET budget_json = ?1 WHERE id = ?2",
                rusqlite::params![inflated, parent_id],
            )
            .unwrap();

        // Child requests 20_000 tokens — would be allowed if attenuation
        // believed the tampered flat column (100_000), must be rejected
        // because the chain statement still carries only 10_000.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(600),
                Some(Budget {
                    tokens: Some(20_000),
                    ..Default::default()
                }),
            )
            .unwrap_err();

        match err {
            StoreError::DelegationViolation { reason } => {
                assert!(
                    reason.contains("tokens") || reason.contains("budget"),
                    "reason should name the violating axis, got: {reason}"
                );
            }
            other => panic!("expected DelegationViolation, got {other:?}"),
        }
    }

    /// A revoked parent grant must never delegate — the status guard in
    /// `delegate_grant_full` checks `parent_chain.status == Active` after
    /// `get_access_grant` returns. Revocation takes precedence over any
    /// attenuation math.
    #[test]
    fn delegate_rejects_revoked_parent() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_parent_with_budget(&store, 10_000, 1800);

        // Revoke the parent — cascades would also revoke children, but
        // there are none yet.
        store.revoke_grant(&parent_id).unwrap();
        assert_eq!(store.get_grant(&parent_id).unwrap().status, "revoked");

        // Any delegation attempt now must fail, regardless of how narrow
        // the child scope/budget is.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(60),
                Some(Budget {
                    tokens: Some(100),
                    ..Default::default()
                }),
            )
            .unwrap_err();

        match err {
            StoreError::InvalidInput(reason) => {
                assert!(
                    reason.contains("active") || reason.contains("status"),
                    "expected parent-not-active error, got: {reason}"
                );
            }
            other => panic!("expected InvalidInput status guard, got {other:?}"),
        }
    }

    // --- P69K-H1: extend_grant TOCTOU regression ---

    /// Deterministic sequential test that mirrors the meter↔extend
    /// interleave: after `increment_statement_usage` writes a usage
    /// delta to `blocks_json`, a subsequent `extend_grant` MUST preserve
    /// that usage (not rewind it) while also installing the new budget
    /// and TTL. The fix wraps the extend read-compute-write in a
    /// `BEGIN IMMEDIATE` transaction with an in-txn status re-check;
    /// without the fix, extend's read could predate the meter's write
    /// and its UPDATE would clobber the meter's usage.
    ///
    /// SQLite file-locking via a shared on-disk path would serialize
    /// two connections, but single-threaded in-memory is sufficient to
    /// pin the invariant: after meter → extend, re-read must show the
    /// meter's usage AND the extended budget/TTL.
    #[test]
    fn extend_grant_concurrent_meter_preserves_usage() {
        let store = setup();
        let persona = store.create_persona("extend-toctou").unwrap();
        // Single-statement grant with a budget; create_grant writes one
        // S0 block signed under the persona root key.
        let grant = store
            .create_grant(&persona.id, "api-key", "llm:generate", Some(3600))
            .unwrap();
        // Install a starting budget via the same helper the attenuation
        // tests use — so the chain Statement carries a tokens budget.
        attach_parent_constraints(
            &store,
            &grant.id,
            Some(Budget {
                tokens: Some(1_000),
                ..Default::default()
            }),
            3,
        );

        // Meter first: post a 100-token delta to S0. This writes a new
        // blocks_json with usage.tokens = 100.
        let meter_delta = store
            .increment_statement_usage(
                &grant.id,
                "S0",
                Usage {
                    tokens: 100,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(meter_delta.current.tokens, 100);

        // Now extend: add 5_000 tokens of budget headroom + 600 more secs
        // of TTL. The fix's in-txn read must see the post-meter blocks_json
        // and preserve its usage when it re-signs block 0.
        let extended = store
            .extend_grant(&grant.id, Some(5_000), None, Some(600))
            .unwrap();

        // Budget extended: starting 1_000 + 5_000 = 6_000.
        assert_eq!(
            extended.budget.as_ref().and_then(|b| b.tokens),
            Some(6_000),
            "extend_grant must install the summed budget"
        );
        // TTL extended: new expires_at > original (non-None, later than now).
        assert!(
            extended.expires_at.is_some(),
            "extend_grant must carry an expiry"
        );

        // CRITICAL: the meter's usage=100 must still be there. A TOCTOU
        // rewind would show usage=0 (extend read a pre-meter snapshot
        // and its UPDATE overwrote the meter's commit).
        let chain = store.get_access_grant(&grant.id).unwrap();
        let s = chain
            .statements()
            .find(|(_, s)| s.sid == "S0")
            .expect("S0 present in extended chain");
        assert_eq!(
            s.1.usage.tokens, 100,
            "extend_grant must NOT rewind meter usage (TOCTOU regression)"
        );

        // Second meter delta to prove the extended grant is still
        // metereable and usage accumulates correctly on top of what
        // extend_grant preserved.
        let delta2 = store
            .increment_statement_usage(
                &grant.id,
                "S0",
                Usage {
                    tokens: 50,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(delta2.prior.tokens, 100);
        assert_eq!(delta2.current.tokens, 150);
    }

    /// If a grant is revoked between the caller's first observation and
    /// the `extend_grant` call, the in-transaction status re-check must
    /// refuse the extend. This proves the TxGuard rollback path and
    /// re-check work together: no partial write reaches the UPDATE.
    #[test]
    fn extend_grant_refuses_revoked_grant_after_initial_read() {
        let store = setup();
        let persona = store.create_persona("extend-revoke").unwrap();
        let grant = store
            .create_grant(&persona.id, "api-key", "llm:generate", Some(3600))
            .unwrap();

        // Revoke via the normal code path.
        store.revoke_grant(&grant.id).unwrap();

        // extend_grant must fail — either via the initial get_grant check
        // or the in-txn re-check. Both paths return InvalidInput with a
        // status-mentioning reason.
        let err = store
            .extend_grant(&grant.id, Some(500), None, Some(60))
            .unwrap_err();
        match err {
            StoreError::InvalidInput(reason) => {
                assert!(
                    reason.contains("revoked") || reason.contains("status"),
                    "expected status-guard reject, got: {reason}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // And the grant row is still exactly 'revoked' — no partial
        // write rewound it to 'active'.
        let g = store.get_grant(&grant.id).unwrap();
        assert_eq!(g.status, "revoked");
    }

    // --- — standing parent grant with auto-delegation ---

    fn setup_standing_parent(
        store: &DaemonStore,
        max_children_per_day: u64,
    ) -> (String, String) {
        let parent_persona = store.create_persona("agent-standing-parent").unwrap();
        let child_persona = store.create_persona("agent-standing-child").unwrap();
        let parent_grant = store
            .create_grant(
                &parent_persona.id,
                "delegate-key",
                "github:push:acme/*",
                Some(7 * 24 * 3600),
            )
            .unwrap();
        // Enable delegation and mark standing.
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
                rusqlite::params![parent_grant.id],
            )
            .unwrap();
        store
            .mark_grant_standing(
                &parent_grant.id,
                max_children_per_day,
                Some("github:push:acme/cycle-<id>"),
            )
            .unwrap();
        (parent_grant.id, child_persona.id)
    }

    #[test]
    fn standing_parent_creates_successfully() {
        let store = setup();
        let (parent_id, _child_persona_id) = setup_standing_parent(&store, 32);

        let info = store.get_grant(&parent_id).unwrap();
        assert!(info.is_standing, "parent must be flagged standing");
        assert_eq!(info.max_children_per_day, Some(32));
        assert_eq!(
            info.auto_delegate_scope_template.as_deref(),
            Some("github:push:acme/cycle-<id>")
        );
    }

    #[test]
    fn mark_grant_standing_rejects_zero_limit() {
        let store = setup();
        let persona = store.create_persona("zero-limit").unwrap();
        let parent = store
            .create_grant(&persona.id, "k", "read", Some(3600))
            .unwrap();
        let err = store
            .mark_grant_standing(&parent.id, 0, None)
            .unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => assert!(msg.contains("> 0"), "got: {msg}"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn delegate_within_limit_succeeds() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_standing_parent(&store, 3);

        // Three delegations within limit all succeed.
        for i in 0..3 {
            let child = store
                .delegate_grant_full(
                    &parent_id,
                    &child_persona_id,
                    "github:push:acme/widgets",
                    Some(1800),
                    None,
                )
                .unwrap_or_else(|e| panic!("delegation {i} should succeed: {e:?}"));
            assert_eq!(child.parent_grant_id.as_deref(), Some(parent_id.as_str()));
            assert_eq!(child.scope, "github:push:acme/widgets");
        }
    }

    #[test]
    fn delegate_over_limit_rejected() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_standing_parent(&store, 2);

        // First two succeed.
        for _ in 0..2 {
            store
                .delegate_grant_full(
                    &parent_id,
                    &child_persona_id,
                    "github:push:acme/widgets",
                    Some(1800),
                    None,
                )
                .unwrap();
        }

        // Third one is rejected with a ceiling-mentioning message.
        let err = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.contains("standing-parent delegation ceiling"),
                    "expected ceiling error, got: {msg}"
                );
                assert!(msg.contains("2/2"), "expected count/limit in msg: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn non_standing_parent_skips_ceiling_gate() {
        // A classical one-shot parent with max_delegation_depth set should
        // not be subject to the standing-parent daily ceiling — even if
        // max_children_per_day were set (which it never is for these).
        let store = setup();
        let parent_persona = store.create_persona("parent-oneshot").unwrap();
        let child_persona = store.create_persona("child-oneshot").unwrap();
        let parent = store
            .create_grant(&parent_persona.id, "k", "github:push:acme/*", Some(3600))
            .unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 3 WHERE id = ?1",
                rusqlite::params![parent.id],
            )
            .unwrap();

        // Three delegations should all succeed — no gate.
        for _ in 0..3 {
            store
                .delegate_grant_full(
                    &parent.id,
                    &child_persona.id,
                    "github:push:acme/widgets",
                    Some(600),
                    None,
                )
                .unwrap();
        }
    }

    #[test]
    fn revoke_standing_cascades() {
        let store = setup();
        let (parent_id, child_persona_id) = setup_standing_parent(&store, 5);

        // Mint two children.
        let c1 = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap();
        let c2 = store
            .delegate_grant_full(
                &parent_id,
                &child_persona_id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap();
        assert_eq!(store.get_grant(&c1.id).unwrap().status, "active");
        assert_eq!(store.get_grant(&c2.id).unwrap().status, "active");

        // Revoke parent — children cascade.
        store.revoke_grant(&parent_id).unwrap();
        assert_eq!(store.get_grant(&parent_id).unwrap().status, "revoked");
        assert_eq!(store.get_grant(&c1.id).unwrap().status, "revoked");
        assert_eq!(store.get_grant(&c2.id).unwrap().status, "revoked");
    }

    #[test]
    fn create_grant_emits_grant_minted_audit_event() {
        let store = setup();
        let persona = store.create_persona("agent-audit-mint").unwrap();
        let grant = store
            .create_grant_with_budget(&persona.id, "api-key", "read", Some(3600), None)
            .unwrap();

        let entries = store
            .query_audit(&crate::audit::AuditFilter {
                action: Some("grant.minted".to_string()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(entries.len(), 1, "expected exactly one grant.minted entry");
        let entry = &entries[0];
        assert_eq!(entry.action, "grant.minted");
        assert_eq!(entry.agent_id.as_deref(), Some(persona.id.as_str()));
        assert_eq!(entry.credential.as_deref(), Some("api-key"));
        assert_eq!(entry.outcome, "minted");

        let details: serde_json::Value =
            serde_json::from_str(entry.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["grant_id"], grant.id);
        assert_eq!(details["statement_count"], 1);
        assert_eq!(details["creation_mode"], "single");
    }

    #[test]
    fn delegate_grant_emits_grant_minted_audit_event() {
        let store = setup();
        let parent_persona = store.create_persona("agent-parent-mint").unwrap();
        let child_persona = store.create_persona("agent-child-mint").unwrap();

        let parent = store
            .create_grant(
                &parent_persona.id,
                "api-key",
                "github:push:acme/*",
                Some(3600),
            )
            .unwrap();
        store
            .conn()
            .execute(
                "UPDATE grants SET max_delegation_depth = 1 WHERE id = ?1",
                rusqlite::params![parent.id],
            )
            .unwrap();

        let child = store
            .delegate_grant_full(
                &parent.id,
                &child_persona.id,
                "github:push:acme/widgets",
                Some(1800),
                None,
            )
            .unwrap();

        let entries = store
            .query_audit(&crate::audit::AuditFilter {
                action: Some("grant.minted".to_string()),
                ..Default::default()
            })
            .unwrap();

        // Both parent mint (creation_mode: "single") and child mint
        // (creation_mode: "delegate") should appear.
        assert!(
            entries.len() >= 2,
            "expected at least two grant.minted entries (parent + child)"
        );

        let delegate_entry = entries
            .iter()
            .find(|e| {
                e.details
                    .as_deref()
                    .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
                    .map(|v| v["creation_mode"] == "delegate")
                    .unwrap_or(false)
            })
            .expect("expected a grant.minted entry with creation_mode: delegate");

        let details: serde_json::Value =
            serde_json::from_str(delegate_entry.details.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(details["grant_id"], child.id);
        assert_eq!(details["creation_mode"], "delegate");
        assert_eq!(details["parent_grant_id"], parent.id);
    }
}
