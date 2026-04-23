use chrono::{DateTime, Duration, Timelike, Utc};
use core_crypto::grant_chain::{
    self, verify_chain, ChainError, RootKeyPair, root_pubkey_bytes_from_ed25519_hex,
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
    check_budget_attenuation, check_expiry_attenuation, scope_subset,
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
}

const GRANT_COLUMNS: &str = "id, persona_id, credential_name, scope, created_at, expires_at, status, max_uses_per_hour, allowed_hours_start, allowed_hours_end, allowed_targets, parent_grant_id, max_delegation_depth, spending_limit_cents, budget_json, usage_json, paused, receipt_id, blocks_json";

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

    Ok(GrantInfo {
        id,
        persona_id,
        credential_name,
        scope,
        created_at,
        expires_at,
        status,
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

impl DaemonStore {
    pub fn create_grant(
        &self,
        persona_id: &str,
        credential_name: &str,
        scope: &str,
        ttl_secs: Option<u64>,
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
        let root = self.persona_root_keypair(persona_id)?;
        let block = build_single_statement_block(
            persona_id,
            credential_name,
            scope,
            created_at_epoch,
            expires_at_epoch,
            None,
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
            budget: None,
            usage: Usage::default(),
            paused: false,
            receipt_id: None,
        })
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
    /// path (W4 / adversarial M-2). Pre-migration `unsigned-phase1`
    /// placeholders are logged-but-passed-through; all other chain errors
    /// reject with `InvalidInput`. Persona-missing edge case (orphan
    /// grant or deleted persona) also passes through with a log.
    fn verify_and_return(&self, grant: AccessGrant) -> Result<AccessGrant, StoreError> {
        match self.get_persona_root_pubkey_bytes(&grant.issuing_persona_id) {
            None => {
                tracing::warn!(
                    grant_id = %grant.id,
                    persona_id = %grant.issuing_persona_id,
                    "persona root pubkey not found — orphan grant or deleted persona; \
                     skipping chain verification (pre-migration pass-through)"
                );
                Ok(grant)
            }
            Some(root_pubkey) => match verify_chain(&grant.blocks, &root_pubkey) {
                Ok(()) => Ok(grant),
                Err(ChainError::ChainUnsigned { block_index }) => {
                    tracing::warn!(
                        grant_id = %grant.id,
                        block_index,
                        "grant contains unsigned-phase1 placeholder — pre-migration grant; \
                         daemon-side Ed25519 wiring (P69K-B follow-up) eliminates this"
                    );
                    Ok(grant)
                }
                Err(e) => Err(StoreError::InvalidInput(format!(
                    "grant chain verification failed: {e}"
                ))),
            },
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
        let blocks_json = access_grant_blocks_to_json(grant)?;
        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, id],
        )?;
        Ok(())
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
        let parent = self.get_grant(parent_grant_id)?;
        if parent.status != "active" {
            return Err(StoreError::InvalidInput("parent grant not active".into()));
        }
        let max_depth = parent
            .max_delegation_depth
            .ok_or_else(|| StoreError::InvalidInput("parent does not allow delegation".into()))?;
        if max_depth == 0 {
            return Err(StoreError::InvalidInput("delegation depth exceeded".into()));
        }

        // --- Offline attenuation (design § Offline attenuation) ---
        // Scope subset check.
        scope_subset(narrowed_scope, &parent.scope)?;

        // Compute child expiry epoch seconds (if provided) and parent's (if present).
        let now: DateTime<Utc> = Utc::now();
        let child_expiry_epoch: Option<u64> = ttl_secs
            .map(|s| (now.timestamp() as i128 + s as i128).max(0) as u64);
        let parent_expiry_epoch: Option<u64> = parent
            .expires_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc).timestamp().max(0) as u64);

        check_expiry_attenuation(parent_expiry_epoch, child_expiry_epoch)?;
        check_budget_attenuation(&parent.budget, &parent.usage, &child_budget)?;

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
        let _ = crate::receipt::trigger_receipt_if_terminal_current(
            self,
            id,
            Some(core_types::grant_receipt::TerminalReason::Revoked {
                by: core_types::grant_receipt::RevokeActor::Operator,
                reason: String::new(),
            }),
        );
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
            let _ = crate::receipt::trigger_receipt_if_terminal_current(
                self,
                &child_id,
                Some(core_types::grant_receipt::TerminalReason::ParentCascadeRevoked {
                    parent_grant_id: root_revoked_id.to_string(),
                }),
            );
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
            let _ = crate::receipt::trigger_receipt_if_terminal_current(
                self,
                gid,
                Some(core_types::grant_receipt::TerminalReason::Expired),
            );
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
                let _ = crate::receipt::trigger_receipt_if_terminal_current(
                    self,
                    &info.id,
                    Some(core_types::grant_receipt::TerminalReason::ExhaustedByBudget {
                        statement_sid: "S0".into(),
                        axis: core_types::grant_receipt::BudgetAxis::WallClockSecs,
                    }),
                );
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

        self.conn().execute(
            "UPDATE grants SET budget_json = ?1, expires_at = ?2, blocks_json = ?3 WHERE id = ?4",
            rusqlite::params![new_budget_json, new_expires_at, new_blocks_json, id],
        )?;

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
        // Bracket the RMW in an immediate transaction — prevents interleave
        // with the expiry sweep and any future concurrent writer. The
        // `unchecked_transaction` path is what daemon code uses elsewhere
        // via the single-connection LocalSet runtime.
        self.conn()
            .execute_batch("BEGIN IMMEDIATE")?;

        // Read current blocks_json. Fall back to the synthesized single-
        // statement chain if the row was created before blocks_json
        // existed (legacy grants; their sid is always "S0").
        // RAII rollback helper — if we early-return Err after BEGIN, the
        // Drop flushes the pending transaction via `ROLLBACK`.
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

        // Re-sign block 0 under issuing persona's root key — mutating the
        // statement payload invalidates the chain signature otherwise, and
        // the read path (verify_and_return) rejects unverifiable chains.
        // For mutated non-zero blocks (delegated child statements) we would
        // need the intermediate pubkey_next_secret, which the daemon does
        // not persist today; log a warning — chain verify will fail on
        // read. Live-usage-outside-chain is tracked as a follow-up
        // architectural cleanup.
        if mutated_block_idx == Some(0) {
            let root = self.persona_root_keypair(&grant.issuing_persona_id)?;
            let new_signed = sign_block_zero_with(&root, &grant.blocks[0].block)?;
            grant.blocks[0] = new_signed;
        } else if let Some(idx) = mutated_block_idx {
            tracing::warn!(
                grant_id,
                statement_sid,
                block_index = idx,
                "increment_statement_usage mutated a delegated block; re-signing not possible \
                 without pubkey_next_secret — chain verify will fail on next read"
            );
        }

        // Persist the mutated blocks chain.
        let blocks_json = access_grant_blocks_to_json(&grant)?;
        self.conn().execute(
            "UPDATE grants SET blocks_json = ?1 WHERE id = ?2",
            rusqlite::params![blocks_json, grant_id],
        )?;
        self.conn().execute_batch("COMMIT")?;
        tx_guard.committed = true;

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
        let root_pubkey_bytes = hex::decode(&root.public_hex).unwrap();
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
        let root_pubkey_bytes = hex::decode(&root.public_hex).unwrap();
        grant_chain::verify_chain(&grant.blocks, &root_pubkey_bytes).unwrap();

        assert_ne!(
            grant.blocks[0].signature,
            core_crypto::grant_chain::UNSIGNED_PHASE1_PLACEHOLDER
        );
    }

    // --- W4: M-2 read-path verify_chain tests ---

    /// Seed a persona row with a caller-supplied public_key (ed25519: prefix)
    /// and return the persona id. Used by verify_chain tests that need a
    /// persona with a known key so we can construct matching signed chains.
    fn seed_persona_with_key(store: &DaemonStore, public_key: &str, private_key: &str) -> String {
        let id = format!("persona-{}", Uuid::new_v4());
        let now = Utc::now().to_rfc3339();
        store
            .conn()
            .execute(
                "INSERT INTO personas (id, name, public_key, private_key, created_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
                rusqlite::params![id, id, public_key, private_key, now],
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
        let child_root_bytes = hex::decode(&child_root.public_hex).unwrap();
        grant_chain::verify_chain(&chain.blocks, &child_root_bytes)
            .expect("delegated block 0 verifies under child persona root key");
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
        let root_pubkey_bytes = hex::decode(&root.public_hex).unwrap();
        grant_chain::verify_chain(&chain.blocks, &root_pubkey_bytes)
            .expect("re-signed block 0 verifies after extend_grant");
    }

    #[test]
    fn get_access_grant_missing_persona_returns_ok_with_passthrough() {
        use core_crypto::grant_chain::{RootKeyPair, sign_block_zero};
        use core_types::{Block, ResourceSelector, ResourceType, Statement, Usage};

        let store = setup();

        // Create a persona, use its key to build a signed chain, then delete
        // the persona row to simulate an orphan grant (persona deprovisioned
        // after the grant was created). The FK constraint is satisfied at
        // insert time; the delete leaves the grant row "dangling."
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

        // Disable FK enforcement so delete succeeds with dangling grant
        // reference, then restore.
        store.conn().execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        store
            .conn()
            .execute(
                "DELETE FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
            )
            .unwrap();
        store.conn().execute_batch("PRAGMA foreign_keys = ON").unwrap();

        let grant = store
            .get_access_grant(&grant_id)
            .expect("orphan grant must pass through, not be rejected");
        assert_eq!(grant.id, grant_id);
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
}
