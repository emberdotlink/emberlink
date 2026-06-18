use super::*;

pub(super) const CLAUDE_CODE_DEFAULT_SCOPE: &str = "claude-code-default-v1";
pub(super) const CODEX_DEFAULT_SCOPE: &str = "codex-default-v1";
pub(super) const CURSOR_DEFAULT_SCOPE: &str = "cursor-default-v1";
pub(super) const GEMINI_DEFAULT_SCOPE: &str = "gemini-default-v1";
/// Vault credential name for the gemini Code Assist ("Sign in with Google")
/// OAuth blob (ADR 215 §2). Unlike codex's account/subject-keyed credential,
/// the gemini Code Assist lane uses a single fixed name — `ember init --for
/// gemini` imports `~/.gemini/oauth_creds.json` into exactly this slug.
pub(super) const GEMINI_CODE_ASSIST_RUNTIME_CREDENTIAL: &str = "google/code-assist-oauth";
/// Vault credential prefix for Codex's ChatGPT plan/subscription OAuth token
/// blob (P22-S2). Concrete credentials are keyed by the ChatGPT account plus
/// user/token identity derived from the captured token, for example
/// `openai/plan/chatgpt-oauth/acct_123/user_456`. `ember init --for codex`
/// imports `~/.codex/auth.json` into a keyed slug under this prefix. Symmetric
/// with the Claude `anthropic/plan/claude-oauth/<fingerprint>` lane.
pub(super) const CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PREFIX: &str =
    "openai/plan/chatgpt-oauth/";
pub(super) const CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PATTERN: &str =
    "openai/plan/chatgpt-oauth/<account>/<subject>";
/// Vault credential prefix for the Anthropic API-key fallback lane. Concrete
/// credentials are keyed by a short fingerprint of the key value, for example
/// `anthropic/api/key/fp-ab12cd34ef56...`.
pub(super) const CLAUDE_CODE_ANTHROPIC_API_KEY_RUNTIME_CREDENTIAL_PREFIX: &str =
    "anthropic/api/key/";
/// Vault credential prefix for the preferred Claude plan/subscription OAuth
/// lane (the `sk-ant-oat01-…` token from `claude setup-token`). Concrete
/// credentials are keyed by a short fingerprint of the token value, for example
/// `anthropic/plan/claude-oauth/fp-ab12cd34ef56...`.
pub(super) const CLAUDE_CODE_ANTHROPIC_PLAN_OAUTH_RUNTIME_CREDENTIAL_PREFIX: &str =
    "anthropic/plan/claude-oauth/";
pub(super) const CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN: &str =
    "anthropic/plan/claude-oauth/* or anthropic/api/key/*";
pub(super) const CLAUDE_CODE_OAUTH_TOKEN_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN";
pub(super) const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// Stable per-kind domain strings for [`short_secret_fingerprint`]. A distinct
/// domain per credential kind keeps fingerprints from colliding across lanes
/// even if the same secret bytes were (impossibly) reused.
const ANTHROPIC_PLAN_OAUTH_FINGERPRINT_DOMAIN: &str = "anthropic-plan-claude-oauth";
const ANTHROPIC_API_KEY_FINGERPRINT_DOMAIN: &str = "anthropic-api-key";
const OPENAI_CHATGPT_OAUTH_FINGERPRINT_DOMAIN: &str = "openai-chatgpt-oauth";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnthropicRuntimeCredentialKind {
    ApiKey,
    OAuthToken,
}

impl AnthropicRuntimeCredentialKind {
    pub(super) fn credential_prefix(self) -> &'static str {
        match self {
            Self::ApiKey => CLAUDE_CODE_ANTHROPIC_API_KEY_RUNTIME_CREDENTIAL_PREFIX,
            Self::OAuthToken => CLAUDE_CODE_ANTHROPIC_PLAN_OAUTH_RUNTIME_CREDENTIAL_PREFIX,
        }
    }

    fn fingerprint_domain(self) -> &'static str {
        match self {
            Self::ApiKey => ANTHROPIC_API_KEY_FINGERPRINT_DOMAIN,
            Self::OAuthToken => ANTHROPIC_PLAN_OAUTH_FINGERPRINT_DOMAIN,
        }
    }

    pub(super) fn env_var(self) -> &'static str {
        match self {
            Self::ApiKey => ANTHROPIC_API_KEY_ENV,
            Self::OAuthToken => CLAUDE_CODE_OAUTH_TOKEN_ENV,
        }
    }

    pub(super) fn metadata(self) -> &'static str {
        match self {
            Self::ApiKey => "anthropic api key (claude code runtime)",
            Self::OAuthToken => "claude subscription oauth token (claude code runtime)",
        }
    }
}

/// A resolved Anthropic runtime credential: its kind plus the concrete,
/// fingerprint-keyed vault credential name (e.g.
/// `anthropic/plan/claude-oauth/ab12…`). Credential names are dynamic — derived
/// from the secret value, not a fixed slug — so callers carry the full name
/// rather than reconstructing it from a `Kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AnthropicRuntimeCredentialRef {
    pub(super) kind: AnthropicRuntimeCredentialKind,
    pub(super) credential_name: String,
}

impl AnthropicRuntimeCredentialRef {
    pub(super) fn credential_name(&self) -> &str {
        &self.credential_name
    }
}

/// Hex of the first 12 bytes of `Sha256(domain ‖ 0x00 ‖ secret)` (24 hex
/// chars). Stable + deterministic for a given (domain, secret) pair; the
/// domain separator keeps lanes from colliding. Used to key model-auth vault
/// credentials by the secret they hold without ever storing the secret in the
/// name.
pub(super) fn short_secret_fingerprint(domain: &str, secret: &str) -> String {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..12])
}

/// Sanitize a raw account/subject identity into a single vault-credential path
/// segment that satisfies the daemon's vault-name grammar
/// (`^[a-z][a-z0-9-]*$`, see `ember_daemon::infra::vault::validate_credential_name`):
/// lowercase, fold every char outside `[a-z0-9]` to a single `-`, trim leading/
/// trailing `-`, and guarantee a leading ASCII letter. Real ChatGPT account ids
/// (UUIDs — often digit-leading) and OIDC `sub` values (uppercase, `_`, `.`)
/// would otherwise be rejected by `vault.add`, dead-ending `ember init` at the
/// store step on a name the operator cannot change (review finding F3/F7).
pub(super) fn credential_identity_segment(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
        // Grammar requires a leading [a-z]; a digit-leading id (e.g. a UUID) gets
        // a stable letter tag rather than being rejected.
        format!("id-{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Derive the fingerprint-keyed Anthropic runtime credential name for a given
/// secret value (the `sk-ant-oat01-…` OAuth token or the `sk-ant-…` API key).
pub(super) fn anthropic_runtime_credential_from_value(
    kind: AnthropicRuntimeCredentialKind,
    value: &str,
) -> AnthropicRuntimeCredentialRef {
    let fingerprint = short_secret_fingerprint(kind.fingerprint_domain(), value);
    AnthropicRuntimeCredentialRef {
        kind,
        // `fp-` lead guarantees the final path segment starts with an ASCII
        // letter; a bare hex fingerprint starts with a digit ~62.5% of the time,
        // which the daemon vault-name grammar (`^[a-z]…`) rejects (review finding
        // F2/F5). Mirrors the Codex `token-<fp>` precedent.
        credential_name: format!("{}fp-{fingerprint}", kind.credential_prefix()),
    }
}

/// Derive the keyed Codex/OpenAI ChatGPT-plan vault credential name from a
/// parsed token blob: `openai/plan/chatgpt-oauth/<account>/<subject>`. The
/// account comes from the ChatGPT account id; the subject from the id_token
/// `sub` claim. Either absent segment falls back so a slug is always producible
/// (account → `unknown-account`; subject → a token fingerprint).
pub(super) fn codex_openai_chatgpt_runtime_credential_name(
    blob: &ember_daemon::infra::codex_oauth::CodexTokenBlob,
) -> String {
    let account = ember_daemon::infra::codex_oauth::account_id(blob)
        .as_deref()
        .map(credential_identity_segment)
        .unwrap_or_else(|| "unknown-account".to_string());
    let subject = ember_daemon::infra::codex_oauth::subject(blob)
        .as_deref()
        .map(credential_identity_segment)
        .unwrap_or_else(|| {
            format!(
                "token-{}",
                short_secret_fingerprint(
                    OPENAI_CHATGPT_OAUTH_FINGERPRINT_DOMAIN,
                    &blob.access_token
                )
            )
        });
    format!("{CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PREFIX}{account}/{subject}")
}

/// Whether a vault credential name is a keyed Codex/OpenAI ChatGPT-plan slug.
pub(super) fn is_codex_openai_chatgpt_runtime_credential_name(credential_name: &str) -> bool {
    credential_name.starts_with(CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PREFIX)
}

#[derive(Debug, Clone)]
pub(super) struct CompositeGrantCreateSpec {
    pub(super) persona_id: String,
    pub(super) credential_name: String,
    pub(super) scope: String,
    pub(super) ttl_secs: Option<u64>,
    pub(super) max_delegation_depth: Option<u32>,
    pub(super) statements: Vec<StatementProposal>,
}

impl CompositeGrantCreateSpec {
    pub(super) fn daemon_request(&self) -> serde_json::Value {
        serde_json::json!({
            "persona_id": self.persona_id,
            "credential_name": self.credential_name,
            "scope": self.scope,
            "ttl_secs": self.ttl_secs,
            "max_delegation_depth": self.max_delegation_depth,
            "statements": self.statements,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AnthropicRuntimeCredentialAvailability {
    Absent,
    ExistingVaultEntry(AnthropicRuntimeCredentialRef),
    StoredFromEnv(AnthropicRuntimeCredentialRef),
    /// Captured into the vault by driving the provider's own login flow
    /// (`claude setup-token`) during `ember init` — the "no manual `vault add`"
    /// path (ARCH-CLI-ONBOARD-FRONT-LOAD model-auth capture).
    CapturedFromLogin(AnthropicRuntimeCredentialRef),
}

impl AnthropicRuntimeCredentialAvailability {
    /// The resolved full vault credential name, when a runtime credential is
    /// available. `Absent` carries no credential.
    pub(super) fn credential_name(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::ExistingVaultEntry(credential)
            | Self::StoredFromEnv(credential)
            | Self::CapturedFromLogin(credential) => Some(credential.credential_name()),
        }
    }
}

/// Extract the Claude plan/subscription OAuth token from `claude setup-token`
/// output. The CLI prints the token (an `sk-ant-oat01-…` value) to stdout;
/// surrounding banner/instruction text goes to stderr. Pure so the brittle
/// "find the token" parse can be unit-tested without the `claude` binary —
/// the subprocess spawn lives in the `ember.rs` capture driver.
pub(super) fn extract_anthropic_oauth_token(output: &str) -> Option<String> {
    output
        .split_whitespace()
        // Strip any punctuation the CLI might wrap the token in BEFORE the
        // prefix check — a leading quote would otherwise defeat `starts_with`.
        .map(|tok| tok.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')))
        .find(|tok| tok.starts_with("sk-ant-") && tok.len() > "sk-ant-".len())
        .map(str::to_string)
}

/// Extract the ChatGPT plan OAuth `tokens` blob from a `~/.codex/auth.json`
/// document, serialized as the compact JSON string stored at vault slug
/// `openai/chatgpt-oauth`. Mirrors the daemon's `codex_oauth::parse_token_blob`
/// (`ember-daemon`): prefer a top-level `access_token`, else descend into
/// `.tokens`, and require a non-empty `access_token` to be a usable credential.
/// Stores the bare-`tokens` shape (what the daemon re-serializes to). Pure — the
/// `codex login` spawn + file read live in the `ember.rs` capture driver.
pub(super) fn extract_codex_tokens_blob(auth_json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(auth_json).ok()?;
    let tokens = if parsed.get("access_token").is_some() {
        parsed
    } else {
        parsed.get("tokens")?.clone()
    };
    let access_token = tokens.get("access_token").and_then(|v| v.as_str())?;
    if access_token.is_empty() {
        return None;
    }
    serde_json::to_string(&tokens).ok()
}

#[derive(Debug, Clone)]
pub(super) struct ClaudeCodeGrantProvisioning {
    pub(super) id: String,
    pub(super) expires_at: Option<String>,
    pub(super) created: bool,
    pub(super) brokered_anthropic_runtime: bool,
}

#[derive(Debug, Clone)]
pub(super) struct CodexGrantProvisioning {
    pub(super) id: String,
    pub(super) expires_at: Option<String>,
    pub(super) created: bool,
}

#[derive(Debug, Clone)]
pub(super) struct CursorGrantProvisioning {
    pub(super) id: String,
    pub(super) expires_at: Option<String>,
    pub(super) created: bool,
}

#[derive(Debug, Clone)]
pub(super) struct GeminiGrantProvisioning {
    pub(super) id: String,
    pub(super) expires_at: Option<String>,
    pub(super) created: bool,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GrantBudgetStatusView {
    pub(super) id: String,
    pub(super) persona_id: String,
    pub(super) status: String,
    pub(super) expires_at: Option<String>,
    #[serde(default)]
    pub(super) statements: Vec<GrantBudgetStatusStatementView>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct GrantStatusView {
    pub(super) kind: String,
    pub(super) id: String,
    pub(super) persona_id: String,
    pub(super) credential_name: String,
    pub(super) scope: String,
    pub(super) status: String,
    pub(super) expires_at: Option<String>,
    pub(super) created_at: Option<String>,
    #[serde(default)]
    pub(super) statements: Vec<GrantStatusStatementView>,
    #[serde(default)]
    pub(super) revoked_sids: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct GrantStatusStatementView {
    pub(super) sid: String,
    pub(super) resource_type: String,
    #[serde(default)]
    pub(super) actions: Vec<String>,
    pub(super) resource: ResourceSelector,
    pub(super) budget: Option<Budget>,
    pub(super) usage: core_grant_types::Usage,
    #[serde(default)]
    pub(super) conditions: Vec<Condition>,
    #[serde(default)]
    pub(super) reserved_cents: u64,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GrantBudgetStatusStatementView {
    pub(super) sid: String,
    pub(super) resource_type: String,
    pub(super) resource: ResourceSelector,
    pub(super) budget: Option<Budget>,
    pub(super) usage: core_grant_types::Usage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum GrantSurfaceKind {
    Spend,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct SpendGrantListRow {
    pub(super) id: String,
    pub(super) persona_id: String,
    pub(super) vendor: String,
    pub(super) threshold_cents: Option<u64>,
    pub(super) hard_cap_cents: Option<u64>,
    pub(super) used_cents: u64,
    pub(super) reserved_cents: u64,
    pub(super) status: String,
    pub(super) expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrantCreateSpec {
    pub(super) persona: String,
    pub(super) credential: String,
    pub(super) scope: String,
    pub(super) ttl_secs: Option<u64>,
    pub(super) max_uses_per_hour: Option<u64>,
    pub(super) allowed_hours_start: Option<u32>,
    pub(super) allowed_hours_end: Option<u32>,
    pub(super) allowed_targets: Option<Vec<String>>,
    pub(super) max_delegation_depth: Option<u32>,
    pub(super) budget: Option<Budget>,
    pub(super) max_children_per_day: Option<u64>,
    pub(super) auto_delegate_scope_template: Option<String>,
}

impl GrantCreateSpec {
    pub(super) fn daemon_request(&self) -> serde_json::Value {
        serde_json::json!({
            "persona_id": self.persona,
            "credential_name": self.credential,
            "scope": self.scope,
            "ttl_secs": self.ttl_secs,
            "max_uses_per_hour": self.max_uses_per_hour,
            "allowed_hours_start": self.allowed_hours_start,
            "allowed_hours_end": self.allowed_hours_end,
            "allowed_targets": self.allowed_targets,
            "max_delegation_depth": self.max_delegation_depth,
            "budget": self.budget,
            "max_children_per_day": self.max_children_per_day,
            "auto_delegate_scope_template": self.auto_delegate_scope_template,
        })
    }

    pub(super) fn allowed_targets_display(&self) -> Option<String> {
        self.allowed_targets
            .as_ref()
            .map(|targets| targets.join(","))
    }
}

pub(super) fn print_created_grant(spec: &GrantCreateSpec, id: &str, expires_at: Option<&str>) {
    println!("Created grant");
    println!("  ID:         {id}");
    println!("  Persona:    {}", spec.persona);
    println!("  Credential: {}", spec.credential);
    println!("  Scope:      {}", spec.scope);
    if let Some(exp) = expires_at {
        println!("  Expires:    {exp}");
    } else {
        println!("  Expires:    never");
    }
    if let Some(rl) = spec.max_uses_per_hour {
        println!("  Rate limit: {rl}/hour");
    }
    if let Some(hs) = spec.allowed_hours_start {
        println!(
            "  Hours:      {hs}:00-{}:00 UTC",
            spec.allowed_hours_end.unwrap_or(0)
        );
    }
    if let Some(targets) = spec.allowed_targets_display() {
        println!("  Targets:    {targets}");
    }
    if let Some(depth) = spec.max_delegation_depth {
        println!("  Delegation: max depth {depth}");
    }
    if let Some(ref budget) = spec.budget {
        if let Some(tokens) = budget.tokens {
            println!("  Budget:     {} tokens", tokens);
        }
        if let Some(cents) = budget.cents {
            println!("  Budget:     ${:.2}", cents as f64 / 100.0);
        }
        if let Some(requests) = budget.requests {
            println!("  Budget:     {} requests", requests);
        }
        if let Some(seconds) = budget.wall_clock_secs {
            println!("  Budget:     {}s wall-clock", seconds);
        }
    }
    if let Some(limit) = spec.max_children_per_day {
        println!("  Standing:   yes (max {limit}/day)");
        if let Some(ref tpl) = spec.auto_delegate_scope_template {
            println!("  Auto-scope: {tpl}");
        }
    }
}

pub(super) fn print_created_spend_grant(
    persona: &str,
    vendor: &str,
    threshold_cents: Option<u64>,
    hard_cap_cents: Option<u64>,
    id: &str,
    expires_at: Option<&str>,
) {
    println!("Created spend grant");
    println!("  ID:         {id}");
    println!("  Persona:    {persona}");
    println!("  Vendor:     {vendor}");
    println!("  Threshold:  {}", format_cents_display(threshold_cents));
    println!("  Hard cap:   {}", format_cents_display(hard_cap_cents));
    if let Some(exp) = expires_at {
        println!("  Expires:    {exp}");
    } else {
        println!("  Expires:    never");
    }
}

pub(super) fn build_spend_grant_create_spec(
    persona: &str,
    vendor: &str,
    threshold_cents: Option<u64>,
    hard_cap_cents: Option<u64>,
    ttl_secs: Option<u64>,
) -> CompositeGrantCreateSpec {
    let mut conditions = vec![Condition::MerchantAllowlist {
        merchants: vec![vendor.to_string()],
    }];
    if let Some(max) = threshold_cents {
        conditions.push(Condition::Range {
            field: "amount_cents".to_string(),
            min: Some(0),
            max: Some(max as i64),
        });
    }
    CompositeGrantCreateSpec {
        persona_id: persona.to_string(),
        credential_name: format!("payment/{vendor}"),
        scope: "payment:charge".to_string(),
        ttl_secs,
        max_delegation_depth: None,
        statements: vec![StatementProposal {
            resource_type: ResourceType::Payment,
            credential_name: format!("payment/{vendor}"),
            actions: vec!["payment:charge".to_string()],
            resource: ResourceSelector::Any,
            budget: hard_cap_cents.map(|cents| Budget {
                cents: Some(cents),
                ..Default::default()
            }),
            conditions,
        }],
    }
}

pub(super) fn grant_supports_runtime_persona_delegation(grant: &serde_json::Value) -> bool {
    grant
        .get("max_delegation_depth")
        .and_then(|value| value.as_u64())
        .is_some_and(|depth| depth > 0)
}

/// Create a grant via the daemon's `create_grant` RPC.
///
/// grant_actions_migrated_to_rpc_complete: prior to META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-GRANT
/// this helper carried an `open_store(config)` local-fallback branch. Under
/// ADR 131's separate-uid posture the daemon owns the SQLite DB and the
/// operator cannot open it for writing — so the local fallback was
/// silently-broken-by-design. Route through the daemon socket only;
/// `call_daemon_method` surfaces a clear error if the socket is missing.
pub(super) fn run_grant_create(
    config: &DaemonConfig,
    spec: &GrantCreateSpec,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result =
        emberlink_cli::call_daemon_method(&socket_path, "create_grant", &spec.daemon_request())?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

/// Create a multi-statement grant via the daemon's `create_composite_grant`
/// RPC.
pub(super) fn run_grant_create_composite(
    config: &DaemonConfig,
    spec: &CompositeGrantCreateSpec,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "create_composite_grant",
        &spec.daemon_request(),
    )?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

pub(super) fn claude_code_anthropic_runtime_credential_kind_from_name(
    credential_name: &str,
) -> Option<AnthropicRuntimeCredentialKind> {
    if credential_name.starts_with(CLAUDE_CODE_ANTHROPIC_PLAN_OAUTH_RUNTIME_CREDENTIAL_PREFIX) {
        Some(AnthropicRuntimeCredentialKind::OAuthToken)
    } else if credential_name.starts_with(CLAUDE_CODE_ANTHROPIC_API_KEY_RUNTIME_CREDENTIAL_PREFIX) {
        Some(AnthropicRuntimeCredentialKind::ApiKey)
    } else {
        None
    }
}

/// Lane preference rank for an Anthropic runtime credential name (lower = more
/// preferred): plan OAuth beats the API-key fallback.
fn anthropic_runtime_credential_rank(credential_name: &str) -> Option<u8> {
    match claude_code_anthropic_runtime_credential_kind_from_name(credential_name)? {
        AnthropicRuntimeCredentialKind::OAuthToken => Some(0),
        AnthropicRuntimeCredentialKind::ApiKey => Some(1),
    }
}

pub(super) fn preferred_existing_claude_code_anthropic_runtime_credential(
    entries: &[serde_json::Value],
) -> Option<AnthropicRuntimeCredentialRef> {
    entries
        .iter()
        .filter_map(|entry| entry.get("name").and_then(|v| v.as_str()))
        .filter_map(|credential_name| {
            let kind = claude_code_anthropic_runtime_credential_kind_from_name(credential_name)?;
            let rank = anthropic_runtime_credential_rank(credential_name)?;
            Some((
                rank,
                AnthropicRuntimeCredentialRef {
                    kind,
                    credential_name: credential_name.to_string(),
                },
            ))
        })
        .min_by_key(|(rank, _credential)| *rank)
        .map(|(_rank, credential)| credential)
}

pub(super) fn preferred_env_claude_code_anthropic_runtime_credential()
-> Option<(AnthropicRuntimeCredentialKind, String)> {
    [
        AnthropicRuntimeCredentialKind::OAuthToken,
        AnthropicRuntimeCredentialKind::ApiKey,
    ]
    .into_iter()
    .find_map(|kind| {
        let value = std::env::var(kind.env_var()).ok()?;
        let value = value.trim_end_matches(['\r', '\n']);
        if value.trim().is_empty() {
            return None;
        }
        Some((kind, value.to_string()))
    })
}

pub(super) fn build_claude_code_anthropic_runtime_statements(
    credential_name: &str,
) -> Vec<StatementProposal> {
    // Runtime grants cover the model gateway and the operation-authority
    // ceiling that delegated construct actions narrow from at session open.
    vec![
        StatementProposal {
            resource_type: ResourceType::Credential,
            credential_name: credential_name.to_string(),
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: credential_name.to_string(),
            },
            budget: None,
            conditions: vec![],
        },
        github_operation_authority_statement(),
        StatementProposal {
            resource_type: ResourceType::Session,
            credential_name: credential_name.to_string(),
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "anthropic/*".to_string(),
            },
            budget: None,
            conditions: vec![],
        },
    ]
}

/// Codex GPT-plan gateway statements (P22-S2), symmetric with
/// [`build_claude_code_anthropic_runtime_statements`]: a `credential:read` on
/// the exact keyed OpenAI credential, the dev0 GitHub operation ceiling used by
/// delegated `ember-gh` constructs, plus an `llm:generate` session statement
/// scoped to the `openai/*` glob. The proxy classifies
/// `chatgpt.com/backend-api/codex/responses` as `llm:generate` /
/// `openai/backend-api/codex/responses` (see `core-proxy-forward::match`), which
/// this glob covers.
pub(super) fn build_codex_openai_runtime_statements(
    credential_name: &str,
) -> Vec<StatementProposal> {
    vec![
        StatementProposal {
            resource_type: ResourceType::Credential,
            credential_name: credential_name.to_string(),
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: credential_name.to_string(),
            },
            budget: None,
            conditions: vec![],
        },
        github_operation_authority_statement(),
        StatementProposal {
            resource_type: ResourceType::Session,
            credential_name: credential_name.to_string(),
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "openai/*".to_string(),
            },
            budget: None,
            conditions: vec![],
        },
    ]
}

/// Gemini Code Assist gateway statements (ADR 215 §2), symmetric with
/// [`build_codex_openai_runtime_statements`]: a `credential:read` on the
/// `google/code-assist-oauth` OAuth credential, the dev0 GitHub operation
/// ceiling used by delegated `ember-gh` constructs, plus an `llm:generate`
/// session statement scoped to the `google/*` glob. The proxy classifies
/// `cloudcode-pa.googleapis.com` Code Assist calls as `llm:generate` /
/// `google/v1internal:<method>` (see `core-proxy-forward::match`), which this
/// glob covers.
///
/// NOTE (metering follow-up `ARCH-GEMINI-METERING-BEFORE-BUDGETED-GRANTS`): the
/// statements are deliberately UN-budgeted (`budget: None`). The loopback engine
/// fails budgeted `google/*` grants closed because gemini usage is not yet
/// token-metered; do not attach a budget here until metering lands.
pub(super) fn build_gemini_google_runtime_statements(
    credential_name: &str,
) -> Vec<StatementProposal> {
    vec![
        StatementProposal {
            resource_type: ResourceType::Credential,
            credential_name: credential_name.to_string(),
            actions: vec!["credential:read".to_string()],
            resource: ResourceSelector::Exact {
                value: credential_name.to_string(),
            },
            budget: None,
            conditions: vec![],
        },
        github_operation_authority_statement(),
        StatementProposal {
            resource_type: ResourceType::Session,
            credential_name: credential_name.to_string(),
            actions: vec!["llm:generate".to_string()],
            resource: ResourceSelector::Glob {
                pattern: "google/*".to_string(),
            },
            budget: None,
            conditions: vec![],
        },
    ]
}

fn github_operation_authority_statement() -> StatementProposal {
    StatementProposal {
        resource_type: ResourceType::Credential,
        credential_name: String::new(),
        actions: vec!["github:*".to_string()],
        resource: ResourceSelector::Glob {
            pattern: "*".to_string(),
        },
        budget: None,
        conditions: vec![],
    }
}

pub(super) fn grant_status_supports_anthropic_gateway(
    status: &serde_json::Value,
    credential_name: &str,
) -> bool {
    if !grant_status_has_live_lease(status) {
        return false;
    }

    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    let has_matching_credential_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "credential:read")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("exact")
                    && resource.get("value").and_then(|v| v.as_str()) == Some(credential_name)
            })
    });

    let has_anthropic_session_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("session")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "llm:generate")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("anthropic/*")
            })
    });

    has_matching_credential_statement
        && has_anthropic_session_statement
        && grant_status_has_github_operation_ceiling(status)
}

pub(super) fn grant_status_supports_any_anthropic_gateway(status: &serde_json::Value) -> bool {
    if !grant_status_has_live_lease(status) {
        return false;
    }

    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    let has_any_credential_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "credential:read")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("exact")
                    && resource
                        .get("value")
                        .and_then(|v| v.as_str())
                        .is_some_and(|value| !value.is_empty())
            })
    });

    let has_anthropic_session_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("session")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "llm:generate")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("anthropic/*")
            })
    });

    has_any_credential_statement
        && has_anthropic_session_statement
        && grant_status_has_github_operation_ceiling(status)
}

pub(super) fn grant_status_supports_codex_openai_gateway(
    status: &serde_json::Value,
    credential_name: &str,
) -> bool {
    if !grant_status_has_live_lease(status) {
        return false;
    }

    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    let has_matching_credential_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "credential:read")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("exact")
                    && resource.get("value").and_then(|v| v.as_str()) == Some(credential_name)
            })
    });

    let has_openai_session_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("session")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "llm:generate")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("openai/*")
            })
    });

    has_matching_credential_statement
        && has_openai_session_statement
        && grant_status_has_github_operation_ceiling(status)
}

pub(super) fn grant_status_supports_gemini_google_gateway(
    status: &serde_json::Value,
    credential_name: &str,
) -> bool {
    if !grant_status_has_live_lease(status) {
        return false;
    }

    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    let has_matching_credential_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "credential:read")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("exact")
                    && resource.get("value").and_then(|v| v.as_str()) == Some(credential_name)
            })
    });

    let has_google_session_statement = statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("session")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "llm:generate")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("google/*")
            })
    });

    has_matching_credential_statement
        && has_google_session_statement
        && grant_status_has_github_operation_ceiling(status)
}

fn grant_status_has_live_lease(status: &serde_json::Value) -> bool {
    status
        .get("live_lease")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn grant_status_has_github_operation_ceiling(status: &serde_json::Value) -> bool {
    let Some(statements) = status.get("statements").and_then(|v| v.as_array()) else {
        return false;
    };

    statements.iter().any(|stmt| {
        stmt.get("resource_type").and_then(|v| v.as_str()) == Some("credential")
            && stmt
                .get("actions")
                .and_then(|v| v.as_array())
                .is_some_and(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| action.as_str())
                        .any(|action| action == "github:*")
                })
            && stmt.get("resource").is_some_and(|resource| {
                resource.get("kind").and_then(|v| v.as_str()) == Some("glob")
                    && resource.get("pattern").and_then(|v| v.as_str()) == Some("*")
            })
    })
}

pub(super) fn ensure_claude_code_anthropic_runtime_credential(
    config: &DaemonConfig,
) -> Result<AnthropicRuntimeCredentialAvailability, core_types::ValidationError> {
    // Claude onboarding is an explicit operator flow. If the managed vault is
    // locked, it is better to satisfy presence and discover the stored
    // runtime credential than to silently degrade back to the API-key/ambient
    // lane after `ember init --for claude` imported a keyed Anthropic runtime
    // credential.
    let (_, entries) = run_vault_list(config, None)?;
    if let Some(credential) = preferred_existing_claude_code_anthropic_runtime_credential(&entries)
    {
        return Ok(AnthropicRuntimeCredentialAvailability::ExistingVaultEntry(
            credential,
        ));
    }

    let Some((kind, credential_value)) = preferred_env_claude_code_anthropic_runtime_credential()
    else {
        return Ok(AnthropicRuntimeCredentialAvailability::Absent);
    };

    let credential = anthropic_runtime_credential_from_value(kind, &credential_value);
    let _stored = run_vault_store(
        config,
        "vault_add",
        credential.credential_name(),
        credential_value.as_bytes(),
        Some(kind.metadata()),
        false,
    )?;
    Ok(AnthropicRuntimeCredentialAvailability::StoredFromEnv(
        credential,
    ))
}

#[cfg(test)]
pub(super) fn render_claude_runtime_auth_status(
    availability: &AnthropicRuntimeCredentialAvailability,
    ember_cmd: &str,
) -> String {
    format!(
        "  Claude:   {}",
        claude_runtime_auth_summary(availability, ember_cmd)
    )
}

pub(super) fn claude_runtime_auth_summary(
    availability: &AnthropicRuntimeCredentialAvailability,
    ember_cmd: &str,
) -> String {
    match availability {
        AnthropicRuntimeCredentialAvailability::StoredFromEnv(credential) => {
            format!(
                "stored {} from {}",
                credential.credential_name(),
                credential.kind.env_var()
            )
        }
        AnthropicRuntimeCredentialAvailability::CapturedFromLogin(credential) => {
            format!("captured {} via plan sign-in", credential.credential_name())
        }
        AnthropicRuntimeCredentialAvailability::ExistingVaultEntry(credential) => {
            format!("reusing {} from vault", credential.credential_name())
        }
        AnthropicRuntimeCredentialAvailability::Absent => format!(
            "runtime auth remains ambient; preferred plan-backed path: run `claude setup-token` to materialize {CLAUDE_CODE_OAUTH_TOKEN_ENV}, then rerun `{ember_cmd} init --for claude` to import it under {CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN}; {ANTHROPIC_API_KEY_ENV} remains the fallback API-key lane"
        ),
    }
}

fn claude_code_runtime_missing_message() -> String {
    format!(
        "Claude sessions use Ember's brokered Anthropic lane, but the vault has no {CLAUDE_CODE_ANTHROPIC_RUNTIME_CREDENTIAL_PATTERN} credential. Run `claude setup-token`, or set {ANTHROPIC_API_KEY_ENV}, then rerun `ember init --for claude` to import it. Local-only {CLAUDE_CODE_DEFAULT_SCOPE} grants are not valid model-auth grants."
    )
}

// Summary-rendering signature plumbs many display fields; refactor would touch callers.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_claude_init_summary(
    persona_name: &str,
    persona_created: bool,
    template_path: &Path,
    template_written: bool,
    shadow_root: &Path,
    anthropic_runtime: AnthropicRuntimeCredentialAvailability,
    grant: &ClaudeCodeGrantProvisioning,
    settings_path: &Path,
    github_posture: &emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture,
    github_note: Option<&str>,
    launcher_boundary: Option<&emberlink_cli::onboarding::claude_code::LauncherBoundaryNote>,
    ember_cmd: &str,
) -> String {
    use emberlink_cli::onboarding::claude_code::GitHubOnboardingPosture;

    let (title, summary) = match github_posture {
        GitHubOnboardingPosture::AppConfiguredReal => (
            "Claude ready",
            "Claude is ready to launch through Ember. Run GitHub or Git as usual, then verify the receipt.",
        ),
        GitHubOnboardingPosture::PatConfigured => (
            "Claude ready with caveats",
            "Claude can launch through Ember, but GitHub is still on the degraded PAT fallback lane.",
        ),
        GitHubOnboardingPosture::AppBroken(_) => (
            "Claude needs one more fix",
            "Claude can launch through Ember, but brokered GitHub actions need repair first.",
        ),
        GitHubOnboardingPosture::AppConfiguredMock | GitHubOnboardingPosture::AppNotConfigured => (
            "Claude needs one more step",
            "Claude can launch through Ember, but GitHub setup is needed before brokered GitHub actions.",
        ),
    };

    let expires = grant.expires_at.as_deref().unwrap_or("never");
    let grant_line = match (grant.created, grant.brokered_anthropic_runtime) {
        (true, true) => format!("Grant: created {} (Anthropic brokered)", grant.id),
        (false, true) => format!(
            "Grant: reused {} until {expires} (Anthropic brokered)",
            grant.id
        ),
        (true, false) => format!("Grant: created {} (ambient Claude auth)", grant.id),
        (false, false) => format!("Grant: reused {} until {expires}", grant.id),
    };
    let github_line = match github_posture {
        GitHubOnboardingPosture::AppConfiguredReal => "GitHub: App lane ready".to_string(),
        GitHubOnboardingPosture::PatConfigured => {
            "GitHub: degraded PAT fallback active".to_string()
        }
        GitHubOnboardingPosture::AppConfiguredMock => {
            "GitHub: mock-only broker still active".to_string()
        }
        GitHubOnboardingPosture::AppBroken(detail) => {
            format!("GitHub: App setup is broken ({detail})")
        }
        GitHubOnboardingPosture::AppNotConfigured => "GitHub: App setup still needed".to_string(),
    };

    let mut sections = vec![UiSection {
        heading: "Configured",
        lines: vec![
            format!(
                "Persona: {} {}",
                if persona_created { "created" } else { "reused" },
                persona_name
            ),
            format!(
                "Template: {} {}",
                if template_written { "wrote" } else { "kept" },
                template_path.display()
            ),
            format!("Shadow PATH: ready {}", shadow_root.display()),
            format!("Settings: deny rules in {}", settings_path.display()),
            format!(
                "Runtime auth: {}",
                claude_runtime_auth_summary(&anthropic_runtime, ember_cmd)
            ),
            grant_line,
            github_line,
        ],
    }];

    if let Some(note) = github_note {
        sections.push(UiSection {
            heading: "Attention",
            lines: vec![note.to_string()],
        });
    }

    match github_posture {
        GitHubOnboardingPosture::AppConfiguredReal => {
            sections.push(UiSection {
                heading: "Next",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} claude"),
                        "Open the managed Claude session",
                    ),
                    command_row(
                        format!("{ember_cmd} receipt list"),
                        "Find the receipt after the first brokered action",
                    ),
                ],
            });
        }
        GitHubOnboardingPosture::PatConfigured => {
            sections.push(UiSection {
                heading: "Fix now",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup"),
                    "Upgrade from PAT fallback to the App lane",
                )],
            });
            sections.push(UiSection {
                heading: "Also",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} claude"),
                        "Launch now if the degraded lane is acceptable",
                    ),
                    command_row(
                        format!("{ember_cmd} receipt list"),
                        "Find the receipt after the first brokered action",
                    ),
                    command_row("ember explain github setup", "Read the App setup contract"),
                ],
            });
        }
        GitHubOnboardingPosture::AppConfiguredMock
        | GitHubOnboardingPosture::AppBroken(_)
        | GitHubOnboardingPosture::AppNotConfigured => {
            sections.push(UiSection {
                heading: "Fix now",
                lines: vec![command_row(
                    format!("{ember_cmd} github setup"),
                    "Configure or repair the GitHub App lane",
                )],
            });
            sections.push(UiSection {
                heading: "Also",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} claude"),
                        "Launch now if you do not need GitHub-brokered actions yet",
                    ),
                    command_row("ember explain github setup", "Read the App setup contract"),
                ],
            });
        }
    }

    if let Some(note) = launcher_boundary {
        sections.push(UiSection {
            heading: "Boundary",
            lines: vec![note.detail.clone(), note.repair_guidance.clone()],
        });
    }

    render_compact_card(title, summary, &[], &sections)
}

pub(super) fn render_codex_init_summary(
    persona_name: &str,
    persona_created: bool,
    template_path: &Path,
    template_written: bool,
    grant: &CodexGrantProvisioning,
    ember_cmd: &str,
) -> String {
    let expires = grant.expires_at.as_deref().unwrap_or("never");
    let grant_line = if grant.created {
        format!("Grant: created {} (24h launcher grant)", grant.id)
    } else {
        format!("Grant: reused {} until {expires}", grant.id)
    };

    render_compact_card(
        "Codex ready",
        "Codex is ready to launch through Ember. Run as usual, then verify the receipt.",
        &[],
        &[
            UiSection {
                heading: "Configured",
                lines: vec![
                    format!(
                        "Persona: {} {}",
                        if persona_created { "created" } else { "reused" },
                        persona_name
                    ),
                    format!(
                        "Template: {} {}",
                        if template_written { "wrote" } else { "kept" },
                        template_path.display()
                    ),
                    grant_line,
                    "Auth: remains managed by Codex (`codex login` / `codex login status`)"
                        .to_string(),
                ],
            },
            UiSection {
                heading: "Next",
                lines: vec![command_row(
                    format!("{ember_cmd} codex"),
                    "Open the managed Codex session",
                )],
            },
            UiSection {
                heading: "Also",
                lines: vec![
                    command_row("codex login status", "Check Codex's own auth state"),
                    command_row(
                        "codex login --device-auth",
                        "Use the headless sign-in lane when browser auth is unavailable",
                    ),
                    command_row(
                        format!("{ember_cmd} receipt list"),
                        "Find the receipt after the first brokered action",
                    ),
                ],
            },
        ],
    )
}

pub(super) fn render_cursor_init_summary(
    persona_name: &str,
    persona_created: bool,
    template_path: &Path,
    template_written: bool,
    grant: &CursorGrantProvisioning,
    ember_cmd: &str,
) -> String {
    let expires = grant.expires_at.as_deref().unwrap_or("never");
    let grant_line = if grant.created {
        format!("Grant: created {} (local-only launcher grant)", grant.id)
    } else {
        format!("Grant: reused {} until {expires}", grant.id)
    };

    render_compact_card(
        "Cursor ready",
        "Cursor is wired through Ember's managed host launcher path on this machine.",
        &[],
        &[
            UiSection {
                heading: "Configured",
                lines: vec![
                    format!(
                        "Persona: {} {}",
                        if persona_created { "created" } else { "reused" },
                        persona_name
                    ),
                    format!(
                        "Template: {} {}",
                        if template_written { "wrote" } else { "kept" },
                        template_path.display()
                    ),
                    grant_line,
                    "Auth: Cursor account/model auth remains Cursor-owned on this baseline lane"
                        .to_string(),
                    "Model spend: not brokered by Ember unless a future Cursor mediation mode is designed"
                        .to_string(),
                ],
            },
            UiSection {
                heading: "Next",
                lines: vec![command_row(
                    format!("{ember_cmd} cursor"),
                    "Launch the baseline Cursor host path",
                )],
            },
            UiSection {
                heading: "Also",
                lines: vec![
                    command_row(
                        "curl https://cursor.com/install -fsS | bash",
                        "Install Cursor CLI if `cursor-agent` or `cursor` is not on PATH",
                    ),
                    command_row(
                        format!("{ember_cmd} explain cursor"),
                        "Review the Cursor governance boundary",
                    ),
                    command_row(
                        format!("{ember_cmd} receipt list"),
                        "Find the receipt after the first mediated action",
                    ),
                ],
            },
        ],
    )
}

pub(super) fn render_gemini_init_summary(
    persona_name: &str,
    persona_created: bool,
    credential_summary: &str,
    grant: &GeminiGrantProvisioning,
    ember_cmd: &str,
) -> String {
    let expires = grant.expires_at.as_deref().unwrap_or("never");
    let grant_line = if grant.created {
        format!("Grant: created {} (brokered Code Assist gateway)", grant.id)
    } else {
        format!("Grant: reused {} until {expires}", grant.id)
    };

    render_compact_card(
        "Gemini ready",
        "The Gemini CLI is wired through Ember's brokered Google Code Assist lane on this machine.",
        &[],
        &[
            UiSection {
                heading: "Configured",
                lines: vec![
                    format!(
                        "Persona: {} {}",
                        if persona_created { "created" } else { "reused" },
                        persona_name
                    ),
                    credential_summary.to_string(),
                    grant_line,
                    "Auth: the durable Google refresh token stays daemon-only; the proxy injects a refreshed Bearer server-side"
                        .to_string(),
                ],
            },
            UiSection {
                heading: "Next",
                lines: vec![command_row(
                    format!("{ember_cmd} gemini"),
                    "Launch the Gemini CLI on the brokered host path",
                )],
            },
            UiSection {
                heading: "Also",
                lines: vec![
                    command_row(
                        format!("{ember_cmd} receipt list"),
                        "Find the receipt after the first brokered action",
                    ),
                ],
            },
        ],
    )
}

#[derive(Debug, Clone)]
pub(super) struct FirstGrantReceiptSummaryView {
    pub(super) path: PathBuf,
    pub(super) signature_prefix: String,
    pub(super) hash_prefix: String,
    pub(super) reused_existing: bool,
}

pub(super) fn summarize_first_grant_receipt(
    path: PathBuf,
    file: &emberlink_cli::onboarding::first_grant::FirstGrantReceiptFile,
    reused_existing: bool,
) -> FirstGrantReceiptSummaryView {
    FirstGrantReceiptSummaryView {
        path,
        signature_prefix: file
            .receipt
            .signature
            .as_deref()
            .and_then(|sig| sig.get(..24))
            .unwrap_or("")
            .to_string(),
        hash_prefix: file
            .evidence
            .hash
            .get(..28)
            .unwrap_or(&file.evidence.hash)
            .to_string(),
        reused_existing,
    }
}

// Summary-rendering signature plumbs many display fields; refactor would touch callers.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_basic_init_summary(
    config_path: &Path,
    policy_path: &Path,
    database_path: &Path,
    persona_id: &str,
    persona_name: &str,
    vault_status: &str,
    daemon_socket_live: bool,
    socket_path: &Path,
    receipt: Option<&FirstGrantReceiptSummaryView>,
    ember_cmd: &str,
) -> String {
    let (title, summary) = if daemon_socket_live {
        (
            "Ember ready",
            "Core Ember state is ready. Choose an agent lane, launch through Ember, then verify the receipt.",
        )
    } else {
        (
            "Ember initialized in local fallback mode",
            "Core Ember state is initialized, but this environment skipped the managed daemon path.",
        )
    };

    let daemon_line = if daemon_socket_live {
        format!("Daemon: running {}", socket_path.display())
    } else {
        "Daemon: local fallback only (managed path not started)".to_string()
    };

    let mut sections = vec![UiSection {
        heading: "Configured",
        lines: vec![
            format!("Root: {} ({})", persona_id, persona_name),
            format!("Config: {}", config_path.display()),
            format!("Policy: {}", policy_path.display()),
            format!("Database: {}", database_path.display()),
            format!("Vault: {vault_status}"),
            daemon_line,
        ],
    }];

    if let Some(receipt) = receipt {
        sections.push(UiSection {
            heading: "First proof",
            lines: vec![
                format!(
                    "First receipt: {} {}",
                    if receipt.reused_existing {
                        "kept"
                    } else {
                        "wrote"
                    },
                    receipt.path.display()
                ),
                format!("Signature: {}...", receipt.signature_prefix),
                format!("Hash: {}", receipt.hash_prefix),
            ],
        });
    }

    if daemon_socket_live {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    format!("{ember_cmd} init --for claude"),
                    "Set up Claude as a managed agent lane",
                ),
                command_row(
                    format!("{ember_cmd} init --for codex"),
                    "Set up Codex as a managed agent lane",
                ),
                command_row(
                    format!("{ember_cmd} init --for cursor"),
                    "Set up Cursor as a managed agent lane",
                ),
                command_row(
                    format!("{ember_cmd} status"),
                    "Check current posture before you launch",
                ),
            ],
        });
    } else {
        sections.push(UiSection {
            heading: "Next",
            lines: vec![
                command_row(
                    format!("sudo {ember_cmd} daemon install"),
                    "Move onto the managed daemon path on a normal host",
                ),
                command_row(
                    format!("{ember_cmd} status"),
                    "Inspect the current local-fallback posture",
                ),
            ],
        });
    }

    if let Some(receipt) = receipt {
        sections.push(UiSection {
            heading: "Verify",
            lines: vec![
                command_row(
                    format!(
                        "{ember_cmd} receipt verify {} --pubkey <your-pubkey-hex>",
                        receipt.path.display()
                    ),
                    "Verify the first receipt offline",
                ),
                format!(
                    "Witness flow: {}",
                    emberlink_cli::onboarding::first_grant::INIT_FIRST_GRANT_RECEIPT_EMIT_SENTINEL
                ),
            ],
        });
    }

    render_compact_card(title, summary, &[], &sections)
}

pub(super) fn ensure_claude_code_runtime_grant(
    config: &DaemonConfig,
    persona_id: &str,
    anthropic_credential_name: Option<&str>,
) -> Result<ClaudeCodeGrantProvisioning, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants = grants_value.as_array().unwrap_or(&empty_grants);
    let mut preferred_brokered_grant: Option<(u8, ClaudeCodeGrantProvisioning)> = None;

    for grant in grants.iter().filter(|grant| {
        grant.get("scope").and_then(|v| v.as_str()) == Some(CLAUDE_CODE_DEFAULT_SCOPE)
            && grant_supports_runtime_persona_delegation(grant)
    }) {
        let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let status = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({"id": grant_id}),
        )?;
        let grant_provisioning = ClaudeCodeGrantProvisioning {
            id: grant_id.to_string(),
            expires_at: grant
                .get("expires_at")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            created: false,
            brokered_anthropic_runtime: true,
        };

        if let Some(credential_name) = anthropic_credential_name {
            if grant.get("credential_name").and_then(|v| v.as_str()) == Some(credential_name)
                && grant_status_supports_anthropic_gateway(&status, credential_name)
            {
                preferred_brokered_grant.get_or_insert((0, grant_provisioning));
                continue;
            }
        } else if grant_status_supports_any_anthropic_gateway(&status) {
            let rank = match grant
                .get("credential_name")
                .and_then(|v| v.as_str())
                .and_then(claude_code_anthropic_runtime_credential_kind_from_name)
            {
                Some(AnthropicRuntimeCredentialKind::OAuthToken) => 0_u8,
                Some(AnthropicRuntimeCredentialKind::ApiKey) => 1_u8,
                None => 2_u8,
            };
            let should_replace = preferred_brokered_grant
                .as_ref()
                .is_none_or(|(best_rank, _)| rank < *best_rank);
            if should_replace {
                preferred_brokered_grant = Some((rank, grant_provisioning));
            }
        }
    }

    if let Some((_rank, grant)) = preferred_brokered_grant {
        return Ok(grant);
    }

    if let Some(credential_name) = anthropic_credential_name {
        let spec = CompositeGrantCreateSpec {
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: CLAUDE_CODE_DEFAULT_SCOPE.to_string(),
            ttl_secs: Some(emberlink_cli::onboarding::claude_code::DEFAULT_GRANT_TTL_SECS),
            max_delegation_depth: Some(1),
            statements: build_claude_code_anthropic_runtime_statements(credential_name),
        };
        let (_, created) = run_grant_create_composite(config, &spec)?;
        return finalize_claude_code_runtime_grant_response(config, created, true, persona_id);
    }

    Err(core_types::ValidationError::new(
        claude_code_runtime_missing_message(),
    ))
}

pub(super) fn finalize_claude_code_runtime_grant_response(
    config: &DaemonConfig,
    response: serde_json::Value,
    brokered_anthropic_runtime: bool,
    target_persona_id: &str,
) -> Result<ClaudeCodeGrantProvisioning, core_types::ValidationError> {
    if response.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = response
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon create_grant returned pending_approval without approval_id",
                )
            })?;
        let caller_persona_id =
            resolve_claude_code_grant_approver_persona_id(config, target_persona_id)?;
        let (_, resolved) = run_approval_resolve_with_caller(
            config,
            approval_id,
            &ApprovalOutcome::Approved,
            Some(&caller_persona_id),
        )?;
        let grant_id = resolved.result_grant_id.ok_or_else(|| {
            core_types::ValidationError::new(
                "approving claude-code init grant did not return result_grant_id",
            )
        })?;
        return Ok(ClaudeCodeGrantProvisioning {
            id: grant_id,
            expires_at: None,
            created: true,
            brokered_anthropic_runtime,
        });
    }

    let grant_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "daemon create_grant returned success without a grant id",
            )
        })?;
    Ok(ClaudeCodeGrantProvisioning {
        id: grant_id.to_string(),
        expires_at: response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created: true,
        brokered_anthropic_runtime,
    })
}

/// The keyed Codex/OpenAI ChatGPT-plan vault credential name currently stored
/// (any slug under `openai/plan/chatgpt-oauth/`), if present. Credential names
/// are dynamic — keyed by account/subject — so callers resolve the concrete
/// name rather than matching a fixed slug. Gates the GPT-plan composite grant —
/// symmetric with the Claude `anthropic/plan/claude-oauth/*` presence check.
pub(super) fn preferred_existing_codex_openai_runtime_credential_name(
    config: &DaemonConfig,
) -> Option<String> {
    let (_, entries) = run_vault_list(config, None).ok()?;
    preferred_existing_codex_openai_runtime_credential(&entries)
}

pub(super) fn preferred_existing_codex_openai_runtime_credential(
    entries: &[serde_json::Value],
) -> Option<String> {
    entries
        .iter()
        .filter_map(|entry| entry.get("name").and_then(|v| v.as_str()))
        .find(|name| is_codex_openai_chatgpt_runtime_credential_name(name))
        .map(str::to_string)
}

fn codex_openai_runtime_missing_message() -> String {
    format!(
        "Codex sessions use Ember's brokered OpenAI Responses lane, but the vault has no {CODEX_OPENAI_CHATGPT_RUNTIME_CREDENTIAL_PATTERN} credential. Run `codex login` if ~/.codex/auth.json is missing, then rerun `ember init --for codex` to import it. Local-only {CODEX_DEFAULT_SCOPE} grants are not valid model-auth grants."
    )
}

pub(super) fn ensure_codex_runtime_grant(
    config: &DaemonConfig,
    persona_id: &str,
    openai_credential_name: Option<&str>,
) -> Result<CodexGrantProvisioning, core_types::ValidationError> {
    // Resolve the keyed credential name lazily when the caller did not supply
    // one (e.g. an operator who declined inline capture but already has a
    // stored credential).
    let resolved_credential_name = match openai_credential_name {
        Some(name) => Some(name.to_string()),
        None => preferred_existing_codex_openai_runtime_credential_name(config),
    };

    let socket_path = config.socket_dir.join("daemon.sock");
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants = grants_value.as_array().unwrap_or(&empty_grants);

    if let Some(credential_name) = resolved_credential_name.as_deref() {
        // Prefer reusing the brokered GPT-plan gateway grant for this keyed
        // credential. This is the lane the proxy injects on; the
        // register-session lane selector picks it for codex sessions.
        for grant in grants.iter().filter(|grant| {
            grant
                .get("credential_name")
                .and_then(|v| v.as_str())
                .is_some_and(|name| name == credential_name)
                && grant_supports_runtime_persona_delegation(grant)
        }) {
            let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let status = emberlink_cli::call_daemon_method(
                &socket_path,
                "grant_status",
                &serde_json::json!({"id": grant_id}),
            )?;
            if grant_status_supports_codex_openai_gateway(&status, credential_name) {
                return Ok(CodexGrantProvisioning {
                    id: grant_id.to_string(),
                    expires_at: grant
                        .get("expires_at")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    created: false,
                });
            }
        }

        // No reusable grant, but the keyed ChatGPT-plan credential is stored.
        // Mint the brokered GPT-plan gateway grant (credential:read on the keyed
        // credential + llm:generate on `openai/*`), symmetric with the Claude
        // anthropic lane.
        let spec = CompositeGrantCreateSpec {
            persona_id: persona_id.to_string(),
            credential_name: credential_name.to_string(),
            scope: CODEX_DEFAULT_SCOPE.to_string(),
            ttl_secs: Some(emberlink_cli::onboarding::codex::DEFAULT_GRANT_TTL_SECS),
            max_delegation_depth: Some(1),
            statements: build_codex_openai_runtime_statements(credential_name),
        };
        let (_, created) = run_grant_create_composite(config, &spec)?;
        return finalize_codex_runtime_grant_response(config, created, persona_id);
    }

    Err(core_types::ValidationError::new(
        codex_openai_runtime_missing_message(),
    ))
}

pub(super) fn finalize_codex_runtime_grant_response(
    config: &DaemonConfig,
    response: serde_json::Value,
    target_persona_id: &str,
) -> Result<CodexGrantProvisioning, core_types::ValidationError> {
    if response.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = response
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon create_grant returned pending_approval without approval_id",
                )
            })?;
        let caller_persona_id =
            resolve_claude_code_grant_approver_persona_id(config, target_persona_id)?;
        let (_, resolved) = run_approval_resolve_with_caller(
            config,
            approval_id,
            &ApprovalOutcome::Approved,
            Some(&caller_persona_id),
        )?;
        let grant_id = resolved.result_grant_id.ok_or_else(|| {
            core_types::ValidationError::new(
                "approving codex init grant did not return result_grant_id",
            )
        })?;
        return Ok(CodexGrantProvisioning {
            id: grant_id,
            expires_at: None,
            created: true,
        });
    }

    let grant_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "daemon create_grant returned success without a grant id",
            )
        })?;
    Ok(CodexGrantProvisioning {
        id: grant_id.to_string(),
        expires_at: response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created: true,
    })
}

fn gemini_code_assist_runtime_missing_message() -> String {
    format!(
        "Gemini sessions use Ember's brokered Google Code Assist lane, but the vault has no {GEMINI_CODE_ASSIST_RUNTIME_CREDENTIAL} credential. Sign in with Google in the Gemini CLI on the host (run `gemini` once, choose \"Login with Google\"), then run `ember init --for gemini` to import `~/.gemini/oauth_creds.json`. Local-only {GEMINI_DEFAULT_SCOPE} grants are not valid model-auth grants."
    )
}

/// Whether the fixed `google/code-assist-oauth` credential is present in the
/// vault. Gates the gemini Code Assist composite grant — symmetric with the
/// codex `openai/plan/chatgpt-oauth/*` presence check, but a single fixed name.
pub(super) fn gemini_code_assist_runtime_credential_present(config: &DaemonConfig) -> bool {
    run_vault_list(config, None)
        .ok()
        .map(|(_, entries)| {
            entries.iter().any(|entry| {
                entry.get("name").and_then(|v| v.as_str())
                    == Some(GEMINI_CODE_ASSIST_RUNTIME_CREDENTIAL)
            })
        })
        .unwrap_or(false)
}

pub(super) fn ensure_gemini_runtime_grant(
    config: &DaemonConfig,
    persona_id: &str,
) -> Result<GeminiGrantProvisioning, core_types::ValidationError> {
    let credential_name = GEMINI_CODE_ASSIST_RUNTIME_CREDENTIAL;
    if !gemini_code_assist_runtime_credential_present(config) {
        return Err(core_types::ValidationError::new(
            gemini_code_assist_runtime_missing_message(),
        ));
    }

    let socket_path = config.socket_dir.join("daemon.sock");
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants = grants_value.as_array().unwrap_or(&empty_grants);

    // Prefer reusing the brokered Code Assist gateway grant for this credential —
    // the lane the proxy injects on; the register-session lane selector picks it
    // for gemini sessions.
    for grant in grants.iter().filter(|grant| {
        grant
            .get("credential_name")
            .and_then(|v| v.as_str())
            .is_some_and(|name| name == credential_name)
            && grant_supports_runtime_persona_delegation(grant)
    }) {
        let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let status = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({"id": grant_id}),
        )?;
        if grant_status_supports_gemini_google_gateway(&status, credential_name) {
            return Ok(GeminiGrantProvisioning {
                id: grant_id.to_string(),
                expires_at: grant
                    .get("expires_at")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                created: false,
            });
        }
    }

    // No reusable grant, but the Code Assist OAuth credential is stored. Mint the
    // brokered gateway grant (credential:read on `google/code-assist-oauth` +
    // llm:generate on `google/*`), symmetric with the codex OpenAI lane.
    let spec = CompositeGrantCreateSpec {
        persona_id: persona_id.to_string(),
        credential_name: credential_name.to_string(),
        scope: GEMINI_DEFAULT_SCOPE.to_string(),
        ttl_secs: Some(emberlink_cli::onboarding::gemini::DEFAULT_GRANT_TTL_SECS),
        max_delegation_depth: Some(1),
        statements: build_gemini_google_runtime_statements(credential_name),
    };
    let (_, created) = run_grant_create_composite(config, &spec)?;
    finalize_gemini_runtime_grant_response(config, created, persona_id)
}

pub(super) fn finalize_gemini_runtime_grant_response(
    config: &DaemonConfig,
    response: serde_json::Value,
    target_persona_id: &str,
) -> Result<GeminiGrantProvisioning, core_types::ValidationError> {
    if response.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = response
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon create_grant returned pending_approval without approval_id",
                )
            })?;
        let caller_persona_id =
            resolve_claude_code_grant_approver_persona_id(config, target_persona_id)?;
        let (_, resolved) = run_approval_resolve_with_caller(
            config,
            approval_id,
            &ApprovalOutcome::Approved,
            Some(&caller_persona_id),
        )?;
        let grant_id = resolved.result_grant_id.ok_or_else(|| {
            core_types::ValidationError::new(
                "approving gemini init grant did not return result_grant_id",
            )
        })?;
        return Ok(GeminiGrantProvisioning {
            id: grant_id,
            expires_at: None,
            created: true,
        });
    }

    let grant_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "daemon create_grant returned success without a grant id",
            )
        })?;
    Ok(GeminiGrantProvisioning {
        id: grant_id.to_string(),
        expires_at: response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created: true,
    })
}

pub(super) fn ensure_cursor_runtime_grant(
    config: &DaemonConfig,
    persona_id: &str,
) -> Result<CursorGrantProvisioning, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let grants_value = emberlink_cli::call_daemon_method(
        &socket_path,
        "list_grants",
        &serde_json::json!({"persona_id": persona_id}),
    )?;
    let empty_grants: Vec<serde_json::Value> = Vec::new();
    let grants = grants_value.as_array().unwrap_or(&empty_grants);

    for grant in grants.iter().filter(|grant| {
        grant.get("scope").and_then(|v| v.as_str()) == Some(CURSOR_DEFAULT_SCOPE)
            && grant.get("status").and_then(|v| v.as_str()) == Some("active")
            && grant_supports_runtime_persona_delegation(grant)
    }) {
        let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let status = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({"id": grant_id}),
        )?;
        if !grant_status_has_live_lease(&status) {
            continue;
        }
        return Ok(CursorGrantProvisioning {
            id: grant_id.to_string(),
            expires_at: grant
                .get("expires_at")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            created: false,
        });
    }

    let spec = GrantCreateSpec {
        persona: persona_id.to_string(),
        credential: CURSOR_DEFAULT_SCOPE.to_string(),
        scope: CURSOR_DEFAULT_SCOPE.to_string(),
        ttl_secs: Some(emberlink_cli::onboarding::cursor::DEFAULT_GRANT_TTL_SECS),
        max_uses_per_hour: None,
        allowed_hours_start: None,
        allowed_hours_end: None,
        allowed_targets: None,
        max_delegation_depth: Some(1),
        budget: None,
        max_children_per_day: None,
        auto_delegate_scope_template: None,
    };
    let (_, created) = run_grant_create(config, &spec)?;
    finalize_cursor_runtime_grant_response(config, created, persona_id)
}

pub(super) fn finalize_cursor_runtime_grant_response(
    config: &DaemonConfig,
    response: serde_json::Value,
    target_persona_id: &str,
) -> Result<CursorGrantProvisioning, core_types::ValidationError> {
    if response.get("status").and_then(|v| v.as_str()) == Some("pending_approval") {
        let approval_id = response
            .get("approval_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                core_types::ValidationError::new(
                    "daemon create_grant returned pending_approval without approval_id",
                )
            })?;
        let caller_persona_id =
            resolve_claude_code_grant_approver_persona_id(config, target_persona_id)?;
        let (_, resolved) = run_approval_resolve_with_caller(
            config,
            approval_id,
            &ApprovalOutcome::Approved,
            Some(&caller_persona_id),
        )?;
        let grant_id = resolved.result_grant_id.ok_or_else(|| {
            core_types::ValidationError::new(
                "approving cursor init grant did not return result_grant_id",
            )
        })?;
        return Ok(CursorGrantProvisioning {
            id: grant_id,
            expires_at: None,
            created: true,
        });
    }

    let grant_id = response
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            core_types::ValidationError::new(
                "daemon create_grant returned success without a grant id",
            )
        })?;
    Ok(CursorGrantProvisioning {
        id: grant_id.to_string(),
        expires_at: response
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        created: true,
    })
}

/// List grants on the current authority surface.
pub(super) fn run_grant_list(
    config: &DaemonConfig,
    active_only: bool,
) -> Result<(GrantActionDispatch, Vec<serde_json::Value>), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "list_operator_grants",
            &serde_json::json!({ "active_only": active_only }),
        )?;
        let list = result.as_array().cloned().ok_or_else(|| {
            core_types::ValidationError::new("daemon list_operator_grants: expected array")
        })?;
        Ok((GrantActionDispatch::DaemonRpc, list))
    } else {
        let store = open_store(config);
        let grants = if active_only {
            store.list_active_grants()
        } else {
            store.list_grants()
        }
        .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        let list = grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "id": g.id,
                    "persona_id": g.persona_id,
                    "credential_name": g.credential_name,
                    "scope": g.scope,
                    "status": g.status,
                    "expires_at": g.expires_at,
                })
            })
            .collect();
        Ok((GrantActionDispatch::LocalFallback, list))
    }
}

pub(super) fn grant_status_view_from_local(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<GrantStatusView, core_types::ValidationError> {
    let store = open_store(config);
    let grant = store
        .get_grant(grant_id)
        .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
    let access = store
        .get_access_grant(grant_id)
        .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
    let statements = access
        .statements()
        .map(|(_, stmt)| GrantStatusStatementView {
            sid: stmt.sid.clone(),
            resource_type: stmt.resource_type.as_str().to_string(),
            actions: stmt.actions.clone(),
            resource: stmt.resource.clone(),
            budget: stmt.budget.clone(),
            usage: stmt.usage.clone(),
            conditions: stmt.conditions.clone(),
            reserved_cents: 0,
        })
        .collect();
    Ok(GrantStatusView {
        kind: "grant".to_string(),
        id: grant.id,
        persona_id: grant.persona_id,
        credential_name: grant.credential_name,
        scope: grant.scope,
        status: grant.status.as_str().to_string(),
        expires_at: grant.expires_at,
        created_at: Some(grant.created_at),
        statements,
        revoked_sids: Vec::new(),
    })
}

pub(super) fn run_grant_status(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<(GrantActionDispatch, GrantStatusView), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({ "id": grant_id }),
        )?;
        if result.get("kind").and_then(|v| v.as_str()) != Some("grant") {
            return Err(core_types::ValidationError::new(
                "daemon grant_status: expected a grant result",
            ));
        }
        let view: GrantStatusView = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon grant_status: {e}")))?;
        Ok((GrantActionDispatch::DaemonRpc, view))
    } else {
        Ok((
            GrantActionDispatch::LocalFallback,
            grant_status_view_from_local(config, grant_id)?,
        ))
    }
}

pub(super) fn payment_statement_from_status(
    view: &GrantStatusView,
) -> Option<&GrantStatusStatementView> {
    view.statements
        .iter()
        .find(|stmt| stmt.resource_type == ResourceType::Payment.as_str())
}

pub(super) fn payment_threshold_cents(stmt: &GrantStatusStatementView) -> Option<u64> {
    stmt.conditions
        .iter()
        .find_map(|condition| match condition {
            Condition::Range { field, max, .. } if field == "amount_cents" => {
                max.and_then(|value| u64::try_from(value).ok())
            }
            _ => None,
        })
}

pub(super) fn payment_vendor_display(stmt: &GrantStatusStatementView) -> String {
    for condition in &stmt.conditions {
        if let Condition::MerchantAllowlist { merchants } = condition
            && !merchants.is_empty()
        {
            return merchants.join(",");
        }
    }
    resource_selector_display(&stmt.resource)
}

pub(super) fn spend_grant_row_from_status(view: &GrantStatusView) -> Option<SpendGrantListRow> {
    let stmt = payment_statement_from_status(view)?;
    Some(SpendGrantListRow {
        id: view.id.clone(),
        persona_id: view.persona_id.clone(),
        vendor: payment_vendor_display(stmt),
        threshold_cents: payment_threshold_cents(stmt),
        hard_cap_cents: stmt.budget.as_ref().and_then(|budget| budget.cents),
        used_cents: stmt.usage.cents,
        reserved_cents: stmt.reserved_cents,
        status: view.status.clone(),
        expires_at: view.expires_at.clone(),
    })
}

pub(super) fn run_spend_grant_list(
    config: &DaemonConfig,
    active_only: bool,
) -> Result<(GrantActionDispatch, Vec<SpendGrantListRow>), core_types::ValidationError> {
    let (dispatch, grants) = run_grant_list(config, active_only)?;
    let mut rows = Vec::new();
    for grant in grants {
        let Some(grant_id) = grant.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let (_, status) = run_grant_status(config, grant_id)?;
        if let Some(row) = spend_grant_row_from_status(&status) {
            rows.push(row);
        }
    }
    Ok((dispatch, rows))
}

pub(super) fn read_attempt_toml(
    path: &Path,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let json = serde_json::to_value(value)
        .map_err(|e| format!("convert {} to JSON: {e}", path.display()))?;
    let mut params = json
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{} must contain a TOML table at the root", path.display()))?;
    params.entry("attempt_id".to_string()).or_insert_with(|| {
        serde_json::json!(format!(
            "cli-attempt-{}",
            chrono::Utc::now().timestamp_millis()
        ))
    });
    Ok(params)
}

pub(super) fn run_grant_evaluate(
    config: &DaemonConfig,
    grant_id: &str,
    attempt_path: &Path,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let (_, status) = run_grant_status(config, grant_id)?;
    let stmt = payment_statement_from_status(&status).ok_or_else(|| {
        core_types::ValidationError::new(
            "grant evaluate currently supports payment/spend grants only".to_string(),
        )
    })?;
    let tool_name = stmt
        .actions
        .first()
        .cloned()
        .unwrap_or_else(|| "payment:charge".to_string());
    let params = read_attempt_toml(attempt_path).map_err(core_types::ValidationError::new)?;
    let result = emberlink_cli::call_daemon_method(
        &socket_path,
        "evaluate_tool_call",
        &serde_json::json!({
            "persona": status.persona_id,
            "tool_name": tool_name,
            "grant_id": grant_id,
            "params": params,
        }),
    )?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

/// Delegate a grant via the daemon's `delegate_grant` RPC.
///
/// Local fallback removed per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-GRANT;
/// see the `grant_actions_migrated_to_rpc_complete` note on
/// [`run_grant_create`].
pub(super) fn run_grant_delegate(
    config: &DaemonConfig,
    parent_grant_id: &str,
    child_persona_id: &str,
    scope: &str,
    ttl_secs: Option<u64>,
    budget: Option<Budget>,
) -> Result<(GrantActionDispatch, serde_json::Value), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let status = emberlink_cli::call_daemon_method(
        &socket_path,
        "grant_status",
        &serde_json::json!({ "id": parent_grant_id }),
    )?;
    let caller_persona_id = status
        .get("persona_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            core_types::ValidationError::new("daemon grant_status: missing parent grant persona_id")
        })?;
    let request = serde_json::json!({
        "parent_grant_id": parent_grant_id,
        "child_persona_id": child_persona_id,
        "scope": scope,
        "ttl_secs": ttl_secs,
        "budget": budget,
        "caller_persona_id": caller_persona_id,
    });
    let result = emberlink_cli::call_daemon_method(&socket_path, "delegate_grant", &request)?;
    Ok((GrantActionDispatch::DaemonRpc, result))
}

/// Expire stale grants via the daemon's `expire_grants` RPC.
///
/// grant_expire_rpc_only_landed: ADR 131 keeps the operator CLI off direct
/// daemon-db writes under the separate-uid posture. Missing daemon socket is an
/// operational error, not permission to reopen the local store.
pub(super) fn run_grant_expire(
    config: &DaemonConfig,
) -> Result<(GrantActionDispatch, u64), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    let result =
        emberlink_cli::call_daemon_method(&socket_path, "expire_grants", &serde_json::Value::Null)?;
    let count = result
        .get("expired_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            core_types::ValidationError::new("daemon expire_grants: missing expired_count")
        })?;
    Ok((GrantActionDispatch::DaemonRpc, count))
}

/// Extend a grant via the daemon's `extend_grant` RPC.
///
/// Local fallback removed per META-AP-EMBER-CLI-OPEN-STORE-MIGRATE-GRANT;
/// see the `grant_actions_migrated_to_rpc_complete` note on
/// [`run_grant_create`].
pub(super) fn run_grant_extend(
    config: &DaemonConfig,
    grant_id: &str,
    add_tokens: Option<u64>,
    add_cents: Option<u64>,
    add_ttl_secs: Option<u64>,
) -> Result<GrantActionDispatch, core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    emberlink_cli::call_daemon_method(
        &socket_path,
        "extend_grant",
        &serde_json::json!({
            "grant_id": grant_id,
            "add_tokens": add_tokens,
            "add_cents": add_cents,
            "add_ttl_secs": add_ttl_secs,
        }),
    )?;
    Ok(GrantActionDispatch::DaemonRpc)
}

pub(super) fn render_grant_budget_from_status(view: &GrantBudgetStatusView) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let now = chrono::Utc::now();
    let now_secs = now.timestamp().max(0) as u64;

    let _ = writeln!(out, "Grant {}", view.id);
    let _ = writeln!(out, "  Persona: {}", view.persona_id);
    let _ = writeln!(out, "  Status:  {}", view.status);

    match &view.expires_at {
        Some(exp) => match chrono::DateTime::parse_from_rfc3339(exp) {
            Ok(dt) => {
                let remaining = dt.with_timezone(&chrono::Utc).timestamp() - now.timestamp();
                if remaining > 0 {
                    let _ = writeln!(out, "  TTL:     {}m remaining", remaining / 60);
                } else {
                    let _ = writeln!(out, "  TTL:     expired");
                }
            }
            Err(_) => {
                let _ = writeln!(out, "  TTL:     {exp}");
            }
        },
        None => {
            let _ = writeln!(out, "  TTL:     never");
        }
    }

    let is_composite = view.statements.len() > 1;
    for stmt in &view.statements {
        if is_composite {
            let _ = writeln!(
                out,
                "  Statement {}  {}  {}",
                stmt.sid,
                stmt.resource_type,
                resource_selector_display(&stmt.resource),
            );
        }
        let indent = if is_composite { "    " } else { "  " };

        match &stmt.budget {
            None => {
                let _ = writeln!(out, "{indent}Budget:  (none)");
            }
            Some(b) => {
                let _ = writeln!(out, "{indent}Budget:");
                if let Some(cap) = b.tokens {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("tokens:", stmt.usage.tokens, cap)
                    );
                }
                if let Some(cap) = b.cents {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("cents:", stmt.usage.cents, cap)
                    );
                }
                if let Some(cap) = b.requests {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("requests:", stmt.usage.requests, cap)
                    );
                }
                if let Some(cap) = b.wall_clock_secs {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("wall-clock:", stmt.usage.wall_clock_secs, cap)
                    );
                }

                let last_updated = stmt.usage.last_updated;
                let age_secs = if last_updated > 0 && now_secs >= last_updated {
                    now_secs - last_updated
                } else {
                    u64::MAX
                };
                let stale = age_secs > 300 || last_updated == 0;

                if !stale {
                    let minutes_elapsed = (age_secs as f64 / 60.0).max(0.001);
                    let _ = writeln!(out, "{indent}Runway:");
                    if let Some(cap) = b.tokens {
                        let used = stmt.usage.tokens;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  tokens:      ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  tokens:      —");
                        }
                    }
                    if let Some(cap) = b.cents {
                        let used = stmt.usage.cents;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  cents:       ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  cents:       —");
                        }
                    }
                } else if !is_composite {
                    let _ = writeln!(out, "{indent}Runway:  —");
                }
            }
        }
    }

    out
}

pub(super) fn run_grant_budget(
    config: &DaemonConfig,
    grant_id: &str,
) -> Result<(GrantActionDispatch, String), core_types::ValidationError> {
    let socket_path = config.socket_dir.join("daemon.sock");
    if socket_path.exists() {
        let result = emberlink_cli::call_daemon_method(
            &socket_path,
            "grant_status",
            &serde_json::json!({ "id": grant_id }),
        )?;
        if result.get("kind").and_then(|v| v.as_str()) != Some("grant") {
            return Err(core_types::ValidationError::new(
                "daemon grant_status: expected a grant result",
            ));
        }
        let view: GrantBudgetStatusView = serde_json::from_value(result)
            .map_err(|e| core_types::ValidationError::new(format!("daemon grant_status: {e}")))?;
        Ok((
            GrantActionDispatch::DaemonRpc,
            render_grant_budget_from_status(&view),
        ))
    } else {
        let store = open_store(config);
        let grant = store
            .get_access_grant(grant_id)
            .map_err(|e| core_types::ValidationError::new(e.to_string()))?;
        Ok((
            GrantActionDispatch::LocalFallback,
            render_grant_budget(&grant),
        ))
    }
}

/// Parse a decimal USD string like "0.50" into integer cents (50).
/// Input is dollars; output is cents. Rejects negative values and non-numeric input.
pub(super) fn parse_usd_to_cents(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.starts_with('-') {
        return Err("negative budget not allowed".to_string());
    }
    // Try parsing as a float and convert to integer cents.
    let val: f64 = trimmed
        .parse()
        .map_err(|_| format!("invalid decimal value '{s}'"))?;
    if val < 0.0 {
        return Err("negative budget not allowed".to_string());
    }
    // Round to nearest cent.
    Ok((val * 100.0).round() as u64)
}

/// Build a Budget from optional flag values. Returns None if no flag was set.
pub(super) fn build_budget(
    tokens: Option<u64>,
    cents: Option<u64>,
    requests: Option<u64>,
    wall_clock_secs: Option<u64>,
) -> Option<Budget> {
    if tokens.is_none() && cents.is_none() && requests.is_none() && wall_clock_secs.is_none() {
        return None;
    }
    Some(Budget {
        tokens,
        cents,
        requests,
        wall_clock_secs,
        ..Budget::default()
    })
}

/// Build the composite grant envelope for `ember sandbox run`.
///
/// Statement layout (per SESSION-composite-plan.md §Stream E + BKR-4 PR-A):
///   1. Credential (custody) — `credential:read` on `<credential_resource>`, no budget.
///   2. Credential (github authority) — `github:*` on `*`, no budget. The dev0
///      durable persona's full GitHub entitlement ceiling, delegable downward.
///   3. Session    — `llm:generate` on `anthropic/*`, `budget.tokens = budget_tokens`.
///   4. Time       — `time:wall_clock` on `*`, `budget.wall_clock_secs = budget_seconds`.
///
/// Statements 1 and 2 are deliberately distinct: custody (`credential:read` — may
/// access the github token) is orthogonal to operation authority (`github:*` —
/// which github operations are permitted), per ADR 201. Statement 2 expresses the
/// dev0 ceiling in the canonical `provider:object:verb` algebra so the future
/// use-time gate (BKR-4 PR-B) has a target for `need ⊆ grant`; `github:*` subsumes
/// any `github:<object>:<verb>` child via the anchored provider wildcard in
/// `core_grants::scope::actions_subset`. Resource `*` = all of the single owner's
/// repos (operator decision 2026-06-04: dev0 is their own github admin / has a
/// github app scoped to them; durable persona has full use, delegates downward;
/// construct/secondary personas attenuate to subsets). Delegability is governed at
/// the GRANT level (`max_delegation_depth` on the grant), not per-statement —
/// `StatementProposal` carries no `can_delegate` field, and the runtime mirror
/// (`mirror_composite_parent_grant_to_runtime_persona`) clones block 0 and
/// decrements the grant-level depth, so every statement in this envelope (incl.
/// `github:*`) is delegable iff the grant is.
///
/// When `credential_resource` is `None` the function returns an empty `Vec` so the
/// caller can skip grant creation for demo invocations that omit the flag.
/// When any budget flag is absent the corresponding budget axis is simply not set
/// (TTL-only for that statement).
pub(super) fn build_composite_grant_statements(
    credential_resource: Option<&str>,
    budget_tokens: Option<u64>,
    budget_cents: Option<u64>,
    budget_seconds: Option<u64>,
) -> Vec<StatementProposal> {
    let Some(cred_resource) = credential_resource else {
        return vec![];
    };

    // Statement 1: Credential custody — credential:read on the named object.
    // ADR 201: may access the github token (distinct from operation authority).
    let credential_stmt = StatementProposal {
        resource_type: ResourceType::Credential,
        credential_name: cred_resource.to_string(),
        actions: vec!["credential:read".to_string()],
        resource: ResourceSelector::Exact {
            value: cred_resource.to_string(),
        },
        budget: None,
        conditions: vec![],
    };

    // Statement 2: GitHub operation authority — github:* on *. The dev0 durable
    // persona's full GHA entitlement ceiling in the canonical provider:object:verb
    // algebra (operator decision 2026-06-04). Distinct from the custody statement
    // above (authority ⊥ custody, ADR 201). Delegable downward via the grant-level
    // max_delegation_depth; attenuates to subsets (github:contents:read, etc.) for
    // construct/runtime/secondary personas. The future use-time gate (BKR-4 PR-B)
    // checks each action's manifest need ⊆ this github:* via actions_subset's
    // anchored provider wildcard. ResourceType::Credential because there is no
    // dedicated github-operation ResourceType variant and the attenuation gate
    // matches on actions+selector only (resource_type is gate-irrelevant metadata).
    let github_authority_stmt = StatementProposal {
        resource_type: ResourceType::Credential,
        credential_name: String::new(),
        actions: vec!["github:*".to_string()],
        resource: ResourceSelector::Glob {
            pattern: "*".to_string(),
        },
        budget: None,
        conditions: vec![],
    };

    // Statement 2: Session — llm:generate on anthropic/*, token + cent budget.
    let session_budget = if budget_tokens.is_some() || budget_cents.is_some() {
        Some(Budget {
            tokens: budget_tokens,
            cents: budget_cents,
            ..Budget::default()
        })
    } else {
        None
    };
    let session_stmt = StatementProposal {
        resource_type: ResourceType::Session,
        credential_name: String::new(),
        actions: vec!["llm:generate".to_string()],
        resource: ResourceSelector::Glob {
            pattern: "anthropic/*".to_string(),
        },
        budget: session_budget,
        conditions: vec![],
    };

    // Statement 3: Time — time:wall_clock on *, wall_clock_secs budget.
    let time_budget = budget_seconds.map(|secs| Budget {
        wall_clock_secs: Some(secs),
        ..Budget::default()
    });
    let time_stmt = StatementProposal {
        resource_type: ResourceType::Time,
        credential_name: String::new(),
        actions: vec!["time:wall_clock".to_string()],
        resource: ResourceSelector::Any,
        budget: time_budget,
        conditions: vec![],
    };

    vec![
        credential_stmt,
        github_authority_stmt,
        session_stmt,
        time_stmt,
    ]
}

/// Parse a duration string (15s, 5m, 2h, 1d, or bare integer seconds).
pub(super) fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))
    } else if let Some(n) = s.strip_suffix('m') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(60)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('h') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(3600)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else if let Some(n) = s.strip_suffix('d') {
        let v = n
            .parse::<u64>()
            .map_err(|_| format!("invalid duration '{s}'"))?;
        v.checked_mul(86400)
            .ok_or_else(|| format!("duration overflow '{s}'"))
    } else {
        s.parse::<u64>().map_err(|_| {
            format!("invalid duration '{s}' (expected e.g. 15s, 5m, 2h, 1d, or bare seconds)")
        })
    }
}

/// Format a duration in seconds to a human-readable string.
pub(super) fn format_duration(secs: u64) -> String {
    if secs.is_multiple_of(86400) {
        format!("{}d", secs / 86400)
    } else if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

/// Pretty-print a receipt to stdout in human-readable form.
pub(super) fn print_receipt_summary(r: &core_grant_types::grant_receipt::GrantReceipt) {
    use core_grant_types::grant_receipt::{RevokeActor, TerminalReason};

    println!("Grant Receipt {}", r.id);
    println!("  Grant:       {}", r.grant_id);
    println!("  Persona:     {}", r.summary.persona_id);
    println!("  Owner:       {}", r.summary.human_owner);
    println!("  Service:     {}", r.summary.service);
    println!("  Resource:    {}", r.summary.resource);
    println!();
    println!("  Lifecycle:");
    println!("    Issued at:     epoch {}", r.lifecycle.issued_at);
    if let Some(lu) = r.lifecycle.last_used_at {
        println!("    Last used:     epoch {lu}");
    } else {
        println!("    Last used:     never");
    }
    println!("    Terminated at: epoch {}", r.lifecycle.terminated_at);
    let reason_str = match &r.lifecycle.terminal_reason {
        TerminalReason::Expired => "expired (TTL)".to_string(),
        TerminalReason::Revoked { by, reason } => {
            let actor = match by {
                RevokeActor::Operator => "operator",
                RevokeActor::Agent => "agent",
                RevokeActor::ParentCascade => "parent cascade",
            };
            if reason.is_empty() {
                format!("revoked by {actor}")
            } else {
                format!("revoked by {actor}: {reason}")
            }
        }
        TerminalReason::Abandoned { reason } => {
            if reason.is_empty() {
                "abandoned".to_string()
            } else {
                format!("abandoned: {reason}")
            }
        }
        TerminalReason::ExhaustedByBudget {
            statement_sid,
            axis,
        } => {
            format!("exhausted_by_budget on statement {statement_sid} axis={axis:?}")
        }
        TerminalReason::ParentCascadeRevoked { parent_grant_id } => {
            format!("parent_cascade_revoked (parent={parent_grant_id})")
        }
    };
    println!("    Terminal reason: {reason_str}");
    println!();
    println!("  Per-Statement usage:");
    if r.per_statement_usage.is_empty() {
        println!("    (none)");
    } else {
        for (sid, u) in &r.per_statement_usage {
            println!(
                "    {sid:<8} tokens={:<8} cents={:<6} requests={:<6} wall_clock={}s",
                u.tokens, u.cents, u.requests, u.wall_clock_secs
            );
        }
    }
    println!();
    println!("  Evidence:");
    println!("    Signer pubkey: {}", r.evidence.signer_pubkey);
    println!("    Hash:          {}", r.evidence.hash);
    println!("    Signature:     {}", r.evidence.sig);
    println!("    Canonical v{}", r.evidence.canonical_version);
    println!();
    println!("  Chain snapshot: {} block(s)", r.approved_chain.len());
    println!("  Approval chain: {} event(s)", r.approval_chain.len());
    println!(
        "  Actions observed: {} entry(ies)",
        r.actions_observed.len()
    );
}

/// Format a budget axis line: `label: <used> / <cap> (<pct>%)`.
pub(super) fn fmt_budget_line(label: &str, used: u64, cap: u64) -> String {
    let pct = (used * 100).checked_div(cap).unwrap_or(0);
    format!("    {label:<12} {:>9} / {:>9} ({pct}%)", used, cap)
}

/// Convert a `ResourceSelector` to a compact display string.
pub(super) fn resource_selector_display(sel: &ResourceSelector) -> String {
    match sel {
        ResourceSelector::Exact { value } => value.clone(),
        ResourceSelector::Glob { pattern } => pattern.clone(),
        ResourceSelector::GlobWithSubtarget {
            primary_glob,
            subtarget_glob,
        } => {
            format!("{primary_glob}:{subtarget_glob}")
        }
        ResourceSelector::Regex { pattern } => format!("/{pattern}/"),
        ResourceSelector::Any => "*".to_string(),
    }
}

/// Render per-Statement budget and usage for a composite (or legacy) grant.
///
/// Pure function over `&AccessGrant` — testable without I/O.
pub(super) fn render_grant_budget(grant: &AccessGrant) -> String {
    use std::fmt::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut out = String::new();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let _ = writeln!(out, "Grant {}", grant.id);
    let _ = writeln!(out, "  Persona: {}", grant.issuing_persona_id);
    let _ = writeln!(
        out,
        "  Status:  {}",
        grant.effective_status(now_secs).as_str()
    );

    // Effective TTL from the earliest block expiry.
    match grant.effective_expires_at() {
        Some(exp_epoch) => {
            let remaining = exp_epoch as i64 - now_secs as i64;
            if remaining > 0 {
                let _ = writeln!(out, "  TTL:     {}m remaining", remaining / 60);
            } else {
                let _ = writeln!(out, "  TTL:     expired");
            }
        }
        None => {
            let _ = writeln!(out, "  TTL:     never");
        }
    }

    // Per-Statement budget rows.
    let statements: Vec<(usize, &Statement)> = grant.statements().collect();
    let is_composite = statements.len() > 1;

    for (_bi, stmt) in &statements {
        if is_composite {
            let _ = writeln!(
                out,
                "  Statement {}  {}  {}",
                stmt.sid,
                stmt.resource_type.as_str(),
                resource_selector_display(&stmt.resource),
            );
        }
        let indent = if is_composite { "    " } else { "  " };

        match &stmt.budget {
            None => {
                let _ = writeln!(out, "{indent}Budget:  (none)");
            }
            Some(b) => {
                let _ = writeln!(out, "{indent}Budget:");
                if let Some(cap) = b.tokens {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("tokens:", stmt.usage.tokens, cap)
                    );
                }
                if let Some(cap) = b.cents {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("cents:", stmt.usage.cents, cap)
                    );
                }
                if let Some(cap) = b.requests {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("requests:", stmt.usage.requests, cap)
                    );
                }
                if let Some(cap) = b.wall_clock_secs {
                    let _ = writeln!(
                        out,
                        "  {}",
                        fmt_budget_line("wall-clock:", stmt.usage.wall_clock_secs, cap)
                    );
                }

                // Runway (rate-based estimate) — only when usage is fresh (<5 min).
                let last_updated = stmt.usage.last_updated;
                let age_secs = if last_updated > 0 && now_secs >= last_updated {
                    now_secs - last_updated
                } else {
                    u64::MAX
                };
                let stale = age_secs > 300 || last_updated == 0;

                if !stale {
                    let minutes_elapsed = (age_secs as f64 / 60.0).max(0.001);
                    let _ = writeln!(out, "{indent}Runway:");
                    if let Some(cap) = b.tokens {
                        let used = stmt.usage.tokens;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  tokens:      ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  tokens:      —");
                        }
                    }
                    if let Some(cap) = b.cents {
                        let used = stmt.usage.cents;
                        if used > 0 && cap > used {
                            let remaining_min =
                                (cap - used) as f64 / (used as f64 / minutes_elapsed);
                            let _ = writeln!(
                                out,
                                "  {indent}  cents:       ~{}m",
                                remaining_min.round() as u64
                            );
                        } else {
                            let _ = writeln!(out, "  {indent}  cents:       —");
                        }
                    }
                } else if !is_composite {
                    let _ = writeln!(out, "{indent}Runway:  —");
                }
            }
        }
    }

    out
}
