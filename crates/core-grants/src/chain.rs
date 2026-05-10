// implementation-note-14 — chain-builder helpers lifted from ember-daemon::trust::grant (design §1 concern 3)

use core_crypto::grant_chain::{self, RootKeyPair};
use core_types::{
    AccessGrant, AttestationBinding, Block, Budget, GrantMode, GrantStatus,
    PresentationAudienceKind, RecipientProfile, ResourceSelector, ResourceType,
    SignedBlock, Statement, Usage,
};

/// Error type bridged from `StoreError` context — re-used here so callers
/// that want a standalone chain builder don't need to depend on `ember-daemon`.
#[derive(Debug, thiserror::Error)]
pub enum ChainBuildError {
    #[error("grant chain signing failed: {0}")]
    SigningFailed(String),
}

/// Build a single-statement [`Block`] from the supplied grant metadata.
///
/// Pure helper — no I/O, no key material. The signing step lives in
/// [`sign_block_zero_with`].
pub fn build_single_statement_block(
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
/// Pure helper — signing happens in the caller ([`sign_block_zero_with`]) so
/// the per-persona root-key lookup stays near the daemon store.
pub fn access_grant_envelope(
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

/// Sign a single block with the given root keypair.
///
/// Thin wrapper that maps the `ChainError` surface onto [`ChainBuildError`]
/// so callers don't need to juggle `core_crypto`'s error type directly.
pub fn sign_block_zero_with(
    root: &RootKeyPair,
    block: &Block,
) -> Result<SignedBlock, ChainBuildError> {
    grant_chain::sign_block_zero(root, block)
        .map(|out| out.signed)
        .map_err(|e| ChainBuildError::SigningFailed(e.to_string()))
}

/// Build a signed [`AccessGrant`] envelope wrapping a caller-supplied
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
) -> Result<AccessGrant, ChainBuildError> {
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

/// Classify a credential_name + scope into a [`ResourceType`] heuristically.
pub fn classify_resource_type(credential_name: &str, scope: &str) -> ResourceType {
    if scope.starts_with("llm:") || scope.contains("anthropic") || scope.contains("openai") {
        ResourceType::Session
    } else if scope.starts_with("x402:") || scope.contains("payment") {
        ResourceType::Payment
    } else if scope.starts_with("time:") {
        ResourceType::Time
    } else if scope.starts_with("compute:") {
        ResourceType::Compute
    } else {
        let _ = credential_name;
        ResourceType::Credential
    }
}

/// Map a legacy scope string into (actions, [`ResourceSelector`]) for a statement.
///
/// Scope grammar: `<provider>:<action>:<target>[:<subtarget>]` or legacy
/// bare-action forms like `read`/`write`/`push`/`*`. The mapping is
/// best-effort and preserves the scope string verbatim as the selector
/// pattern so existing proxy enforcement continues to match.
///
/// 4-segment scopes (`<provider>:<action>:<target>:<subtarget>`) emit a
/// structured [`ResourceSelector::GlobWithSubtarget`]: `primary_glob` is
/// the third segment (the resource — `owner/repo`) and `subtarget_glob` is
/// the fourth (a branch-path glob like `feat/*`). This routes the per-
/// Statement resolver to a primary match plus a secondary subtarget check,
/// so a primary-match-but-subtarget-miss denies with
/// `denied_subtarget_scope` instead of the catch-all
/// `denied_no_applicable_statement` (P69E.5c).
pub fn scope_to_actions_and_selector(
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
    } else if parts.len() == 4 && !parts.iter().any(|p| p.is_empty()) {
        ResourceSelector::GlobWithSubtarget {
            primary_glob: parts[2].to_string(),
            subtarget_glob: parts[3].to_string(),
        }
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
