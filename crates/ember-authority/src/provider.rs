use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Arc,
};

use crate::{
    model::{
        MaterializationId, Need, OperationId, PermissionLevel, ProviderEvidence,
        ProviderGeneration, ProviderInstanceId, RepositoryResource,
    },
    principal::AuthorityDecision,
    recovery::{RecoveryContext, RecoveryError, RecoveryJournal, SecretString},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_USER_AGENT: &str = concat!("ember-authority/", env!("CARGO_PKG_VERSION"));
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60 + 60;
pub const MAX_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The complete authority-derived request passed to a provider adapter.
/// Provider coordinates never come from action input.
pub struct MintRequest<'a> {
    pub provider_instance: &'a ProviderInstanceId,
    pub generation: &'a ProviderGeneration,
    pub provider: &'a str,
    pub app_slug: &'a str,
    pub app_id: u64,
    pub installation_id: u64,
    pub repository: &'a RepositoryResource,
    pub permissions: &'a BTreeMap<String, PermissionLevel>,
    pub now_unix: i64,
}

/// Provider claims returned with a minted credential. The registry accepts the
/// credential only when this echo exactly matches its daemon-owned request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialEcho {
    pub provider_instance: ProviderInstanceId,
    pub generation: ProviderGeneration,
    pub provider: String,
    pub app_slug: String,
    pub app_id: u64,
    pub installation_id: u64,
    pub repositories: Vec<RepositoryResource>,
    pub permissions: BTreeMap<String, PermissionLevel>,
    pub expires_at_unix: i64,
}

/// Adapter result whose secret is erased unless ownership is transferred to a
/// validated `MintedCredential`.
pub struct AdapterMint {
    token: SecretString,
    pub echo: CredentialEcho,
}

impl AdapterMint {
    pub fn new(token: String, echo: CredentialEcho) -> Self {
        Self {
            token: SecretString::new(token),
            echo,
        }
    }
}

/// Narrow provider seam. Implementations mint exactly what `MintRequest`
/// describes and revoke a supplied token at the provider.
pub trait ProviderAdapter: Send + Sync {
    fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError>;
    fn revoke(&self, token: &str) -> Result<(), AdapterError>;
}

#[derive(Debug, Error)]
#[error("provider adapter failed: {message}")]
pub struct AdapterError {
    message: String,
    quarantine_instance: bool,
}

impl AdapterError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            quarantine_instance: false,
        }
    }

    pub fn requiring_quarantine(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            quarantine_instance: true,
        }
    }

    fn quarantines_instance(&self) -> bool {
        self.quarantine_instance
    }
}

/// Daemon configuration for one provider installation.
pub struct ProviderInstance {
    id: ProviderInstanceId,
    generation: ProviderGeneration,
    provider: String,
    app_slug: String,
    app_id: u64,
    installation_id: u64,
    repositories: BTreeSet<RepositoryResource>,
    permissions: BTreeMap<String, PermissionLevel>,
    adapter: Arc<dyn ProviderAdapter>,
    quarantine_reason: Option<String>,
}

impl ProviderInstance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        app_slug: impl Into<String>,
        app_id: u64,
        installation_id: u64,
        repositories: impl IntoIterator<Item = RepositoryResource>,
        permissions: BTreeMap<String, PermissionLevel>,
        adapter: Arc<dyn ProviderAdapter>,
    ) -> Self {
        Self::with_identity(
            ProviderInstanceId::new(),
            ProviderGeneration::new(),
            provider,
            app_slug,
            app_id,
            installation_id,
            repositories,
            permissions,
            adapter,
        )
    }

    /// Reconstructs a daemon-persisted instance identity so recovery entries
    /// remain routable across daemon restarts.
    #[allow(clippy::too_many_arguments)]
    pub fn with_identity(
        id: ProviderInstanceId,
        generation: ProviderGeneration,
        provider: impl Into<String>,
        app_slug: impl Into<String>,
        app_id: u64,
        installation_id: u64,
        repositories: impl IntoIterator<Item = RepositoryResource>,
        permissions: BTreeMap<String, PermissionLevel>,
        adapter: Arc<dyn ProviderAdapter>,
    ) -> Self {
        Self {
            id,
            generation,
            provider: provider.into(),
            app_slug: app_slug.into(),
            app_id,
            installation_id,
            repositories: repositories.into_iter().collect(),
            permissions,
            adapter,
            quarantine_reason: None,
        }
    }

    pub fn id(&self) -> &ProviderInstanceId {
        &self.id
    }

    pub fn generation(&self) -> &ProviderGeneration {
        &self.generation
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantine_reason.is_some()
    }

    pub fn quarantine_reason(&self) -> Option<&str> {
        self.quarantine_reason.as_deref()
    }

    fn is_eligible(&self, need: &Need) -> bool {
        !self.is_quarantined()
            && self.provider == need.provider
            && self.repositories.contains(&need.repository)
            && need.permissions.iter().all(|(name, required)| {
                self.permissions
                    .get(name)
                    .is_some_and(|available| available >= required)
            })
    }
}

/// A validated, journaled credential. It cannot be cloned and its token is
/// erased on drop.
pub struct MintedCredential {
    materialization_id: MaterializationId,
    evidence: ProviderEvidence,
    token: SecretString,
}

impl MintedCredential {
    pub fn materialization_id(&self) -> &MaterializationId {
        &self.materialization_id
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }

    pub(crate) fn token(&self) -> &str {
        self.token.expose()
    }
}

#[derive(Default)]
pub struct ProviderRegistry {
    instances: BTreeMap<ProviderInstanceId, ProviderInstance>,
}

impl ProviderRegistry {
    pub fn register(&mut self, instance: ProviderInstance) -> Result<(), ProviderError> {
        if self.instances.contains_key(&instance.id) {
            return Err(ProviderError::DuplicateInstance);
        }
        self.instances.insert(instance.id.clone(), instance);
        Ok(())
    }

    /// Resolves exactly one eligible daemon-owned instance, seals an intent,
    /// mints, validates the exact echo, and atomically records the token.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &mut self,
        operation_id: &OperationId,
        attribution: &AuthorityDecision,
        action: &str,
        approved_input: &Value,
        need: &Need,
        now_unix: i64,
        journal: &RecoveryJournal,
    ) -> Result<MintedCredential, ProviderError> {
        let eligible = self
            .instances
            .values()
            .filter(|instance| instance.is_eligible(need))
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>();
        let id = match eligible.as_slice() {
            [] => return Err(ProviderError::NoEligibleInstance),
            [id] => id.clone(),
            _ => return Err(ProviderError::AmbiguousInstances),
        };

        let instance = self
            .instances
            .get(&id)
            .expect("resolved provider instance remains registered");
        let adapter = Arc::clone(&instance.adapter);
        let request = MintRequest {
            provider_instance: &instance.id,
            generation: &instance.generation,
            provider: &instance.provider,
            app_slug: &instance.app_slug,
            app_id: instance.app_id,
            installation_id: instance.installation_id,
            repository: &need.repository,
            permissions: &need.permissions,
            now_unix,
        };
        let context = RecoveryContext {
            operation_id: operation_id.clone(),
            persona_id: attribution.persona_id.clone(),
            session_id: attribution.session_id.clone(),
            process_binding_id: attribution.process_binding_id.clone(),
            grant_id: attribution.grant_id.clone(),
            delegation_path: attribution.delegation_path.clone(),
            action: action.to_owned(),
            approved_input: approved_input.clone(),
            need: need.clone(),
            provider: None,
        };
        let materialization_id =
            journal.begin_mint(&context, &instance.id, &instance.generation)?;
        let minted = match instance.adapter.mint(&request) {
            Ok(minted) => minted,
            Err(error) => {
                if error.quarantines_instance() {
                    self.quarantine(
                        &id,
                        "provider adapter left credential materialization unresolved",
                    );
                } else if let Err(journal_error) = journal.settle(&materialization_id) {
                    return Err(ProviderError::Recovery(journal_error));
                }
                return Err(ProviderError::Adapter(error));
            }
        };
        if !echo_is_exact(&request, &minted.echo) {
            if let Err(error) = adapter.revoke(minted.token.expose()) {
                self.quarantine(&id, "compensating revoke failed after echo refusal");
                return Err(ProviderError::CompensatingRevokeFailed(error));
            }
            if let Err(error) = journal.settle(&materialization_id) {
                self.quarantine(&id, "echo-refused materialization settlement failed");
                return Err(ProviderError::Recovery(error));
            }
            return Err(ProviderError::EchoRefused);
        }
        let evidence = ProviderEvidence {
            provider_instance: minted.echo.provider_instance.clone(),
            generation: minted.echo.generation.clone(),
            app_slug: minted.echo.app_slug.clone(),
            app_id: minted.echo.app_id,
            installation_id: minted.echo.installation_id,
            repositories: minted
                .echo
                .repositories
                .iter()
                .map(|repository| repository.full_name().to_owned())
                .collect(),
            permissions: minted.echo.permissions.clone(),
            expires_at_unix: minted.echo.expires_at_unix,
        };
        if let Err(journal_error) =
            journal.record_token(&materialization_id, evidence.clone(), minted.token.expose())
        {
            if let Err(revoke_error) = adapter.revoke(minted.token.expose()) {
                self.quarantine(&id, "compensating revoke failed after journal transition");
                return Err(ProviderError::JournalAndCompensatingRevokeFailed {
                    journal: journal_error,
                    revoke: revoke_error,
                });
            }
            if let Err(settle_error) = journal.settle(&materialization_id) {
                self.quarantine(&id, "mint intent settlement failed after compensation");
                return Err(ProviderError::Recovery(settle_error));
            }
            return Err(ProviderError::Recovery(journal_error));
        }
        Ok(MintedCredential {
            materialization_id,
            evidence,
            token: minted.token,
        })
    }

    /// Revokes a delivered credential. The encrypted recovery entry remains
    /// until the caller has durably stored the operation's terminal result.
    pub fn revoke_credential(&mut self, credential: MintedCredential) -> Result<(), ProviderError> {
        let id = credential.evidence.provider_instance.clone();
        let instance = self
            .instances
            .get(&id)
            .filter(|instance| instance.generation == credential.evidence.generation)
            .ok_or(ProviderError::UnknownInstanceGeneration)?;
        let adapter = Arc::clone(&instance.adapter);
        if let Err(error) = adapter.revoke(credential.token()) {
            self.quarantine(&id, "credential revoke failed");
            return Err(ProviderError::RevokeFailed(error));
        }
        Ok(())
    }

    /// Re-derives provider quarantine from every unresolved journal entry on
    /// each boot. Result-proven revocations are not sent upstream again.
    pub(crate) fn recover(
        &mut self,
        journal: &RecoveryJournal,
        result_proven_revocations: &BTreeSet<MaterializationId>,
    ) -> Result<Vec<RecoveryOutcome>, ProviderError> {
        let mut outcomes = Vec::new();
        for entry in journal.unresolved()? {
            let id = entry.provider_instance().clone();
            let generation = entry.generation().clone();
            let materialization_id = entry.materialization_id().clone();
            let context = entry.context().clone();

            if entry.token().is_some() && result_proven_revocations.contains(&materialization_id) {
                outcomes.push(RecoveryOutcome {
                    context,
                    materialization_id,
                    upstream_revoked: true,
                    settlement_ready: true,
                    quarantined: false,
                    message: "immutable terminal result proves upstream revocation".to_owned(),
                });
                continue;
            }

            let Some(instance) = self.instances.get(&id) else {
                outcomes.push(RecoveryOutcome {
                    context,
                    materialization_id,
                    upstream_revoked: false,
                    settlement_ready: false,
                    quarantined: false,
                    message: "recovery provider instance is not installed".to_owned(),
                });
                continue;
            };
            if instance.generation != generation {
                if entry.is_intent() {
                    self.quarantine(
                        &id,
                        "unresolved mint intent belongs to another provider generation",
                    );
                }
                outcomes.push(RecoveryOutcome {
                    context,
                    materialization_id,
                    upstream_revoked: false,
                    settlement_ready: false,
                    quarantined: entry.is_intent(),
                    message: if entry.is_intent() {
                        "mint outcome is unknown; provider remains quarantined across generation replacement"
                            .to_owned()
                    } else {
                        "token-bearing recovery entry belongs to an unavailable generation"
                            .to_owned()
                    },
                });
                continue;
            }

            let Some(token) = entry.token() else {
                self.quarantine(&id, "unresolved mint intent for this provider generation");
                outcomes.push(RecoveryOutcome {
                    context,
                    materialization_id,
                    upstream_revoked: false,
                    settlement_ready: false,
                    quarantined: true,
                    message: "mint outcome is unknown; exact provider generation quarantined"
                        .to_owned(),
                });
                continue;
            };

            let adapter = Arc::clone(&instance.adapter);
            match adapter.revoke(token) {
                Ok(()) => outcomes.push(RecoveryOutcome {
                    context,
                    materialization_id,
                    upstream_revoked: true,
                    settlement_ready: true,
                    quarantined: false,
                    message: "startup recovery revoked the credential upstream".to_owned(),
                }),
                Err(error) => {
                    self.quarantine(&id, "startup credential revoke failed");
                    outcomes.push(RecoveryOutcome {
                        context,
                        materialization_id,
                        upstream_revoked: false,
                        settlement_ready: false,
                        quarantined: true,
                        message: format!("startup credential revoke failed: {error}"),
                    });
                }
            }
        }
        Ok(outcomes)
    }

    pub fn is_quarantined(&self, id: &ProviderInstanceId) -> bool {
        self.instances
            .get(id)
            .is_some_and(ProviderInstance::is_quarantined)
    }

    fn quarantine(&mut self, id: &ProviderInstanceId, reason: &'static str) {
        if let Some(instance) = self.instances.get_mut(id) {
            instance.quarantine_reason = Some(reason.to_owned());
        }
    }
}

#[derive(Debug)]
pub(crate) struct RecoveryOutcome {
    pub context: RecoveryContext,
    pub materialization_id: MaterializationId,
    pub upstream_revoked: bool,
    pub settlement_ready: bool,
    pub quarantined: bool,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    pub settled: usize,
    pub quarantined: usize,
    pub unresolved: usize,
}

fn echo_is_exact(request: &MintRequest<'_>, echo: &CredentialEcho) -> bool {
    &echo.provider_instance == request.provider_instance
        && &echo.generation == request.generation
        && echo.provider == request.provider
        && echo.app_slug == request.app_slug
        && echo.app_id == request.app_id
        && echo.installation_id == request.installation_id
        && echo.repositories.len() == 1
        && &echo.repositories[0] == request.repository
        && &echo.permissions == request.permissions
        && echo.expires_at_unix > request.now_unix
        && echo.expires_at_unix <= request.now_unix.saturating_add(MAX_TOKEN_LIFETIME_SECONDS)
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider instance is already registered")]
    DuplicateInstance,
    #[error("no eligible provider instance")]
    NoEligibleInstance,
    #[error("multiple eligible provider instances")]
    AmbiguousInstances,
    #[error("provider returned a widened or mismatched credential echo")]
    EchoRefused,
    #[error("provider adapter error: {0}")]
    Adapter(#[from] AdapterError),
    #[error("compensating revoke failed after refusing provider output: {0}")]
    CompensatingRevokeFailed(AdapterError),
    #[error("recovery journal failed: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("recovery journal and compensating revoke both failed")]
    JournalAndCompensatingRevokeFailed {
        journal: RecoveryError,
        revoke: AdapterError,
    },
    #[error("provider instance generation is not registered")]
    UnknownInstanceGeneration,
    #[error("credential revoke failed: {0}")]
    RevokeFailed(AdapterError),
}

/// Minimal request model for an injectable blocking HTTP transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

pub struct HttpRequest<'a> {
    pub method: HttpMethod,
    pub url: &'a str,
    pub bearer_token: &'a str,
    pub body: Option<&'a Value>,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
    pub body_bytes: usize,
}

pub trait BlockingHttp: Send + Sync {
    fn execute(&self, request: HttpRequest<'_>) -> Result<HttpResponse, AdapterError>;
}

#[derive(Default)]
pub struct ReqwestBlockingHttp {
    client: reqwest::blocking::Client,
}

impl BlockingHttp for ReqwestBlockingHttp {
    fn execute(&self, request: HttpRequest<'_>) -> Result<HttpResponse, AdapterError> {
        let builder = match request.method {
            HttpMethod::Get => self.client.get(request.url),
            HttpMethod::Post => self.client.post(request.url),
            HttpMethod::Delete => self.client.delete(request.url),
        }
        .bearer_auth(request.bearer_token)
        .header(reqwest::header::ACCEPT, GITHUB_ACCEPT)
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .header(reqwest::header::USER_AGENT, GITHUB_USER_AGENT);
        let builder = match request.body {
            Some(body) => builder.json(body),
            None => builder,
        };
        let mut response = builder
            .send()
            .map_err(|error| AdapterError::new(format!("GitHub HTTP request failed: {error}")))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_HTTP_RESPONSE_BYTES as u64)
        {
            return Err(AdapterError::new(
                "HTTP response exceeds the hard byte limit",
            ));
        }
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(MAX_HTTP_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AdapterError::new(format!("GitHub HTTP response read failed: {error}"))
            })?;
        if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
            return Err(AdapterError::new(
                "HTTP response exceeds the hard byte limit",
            ));
        }
        let body_bytes = bytes.len();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|error| {
                AdapterError::new(format!(
                    "GitHub HTTP {status} response is not valid JSON: {error}"
                ))
            })?
        };
        Ok(HttpResponse {
            status,
            body,
            body_bytes,
        })
    }
}

pub struct GithubTokenRevoker {
    api_base: String,
    http: Arc<dyn BlockingHttp>,
}

impl GithubTokenRevoker {
    pub fn new() -> Self {
        Self::with_http(
            "https://api.github.com",
            Arc::new(ReqwestBlockingHttp::default()),
        )
    }

    pub fn with_http(api_base: impl Into<String>, http: Arc<dyn BlockingHttp>) -> Self {
        Self {
            api_base: api_base.into().trim_end_matches('/').to_owned(),
            http,
        }
    }

    pub fn revoke(&self, token: &str) -> Result<(), AdapterError> {
        let url = format!("{}/installation/token", self.api_base);
        let response = self.http.execute(HttpRequest {
            method: HttpMethod::Delete,
            url: &url,
            bearer_token: token,
            body: None,
        })?;
        if matches!(response.status, 204 | 401) {
            Ok(())
        } else {
            Err(AdapterError::new(format!(
                "GitHub token revoke returned HTTP {}",
                response.status
            )))
        }
    }
}

impl Default for GithubTokenRevoker {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking GitHub App adapter. Its private key and installation coordinates
/// are daemon configuration; only the exact authority-derived repository and
/// permissions vary per mint.
pub struct GithubAppAdapter {
    app_slug: String,
    app_id: u64,
    installation_id: u64,
    encoding_key: EncodingKey,
    api_base: String,
    http: Arc<dyn BlockingHttp>,
}

fn install_jwt_crypto_provider() {
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

impl GithubAppAdapter {
    pub fn new(
        app_slug: impl Into<String>,
        app_id: u64,
        installation_id: u64,
        private_key_pem: &[u8],
    ) -> Result<Self, AdapterError> {
        Self::with_http(
            app_slug,
            app_id,
            installation_id,
            private_key_pem,
            "https://api.github.com",
            Arc::new(ReqwestBlockingHttp::default()),
        )
    }

    pub fn with_http(
        app_slug: impl Into<String>,
        app_id: u64,
        installation_id: u64,
        private_key_pem: &[u8],
        api_base: impl Into<String>,
        http: Arc<dyn BlockingHttp>,
    ) -> Result<Self, AdapterError> {
        install_jwt_crypto_provider();
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem).map_err(|error| {
            AdapterError::new(format!("GitHub App private key is invalid: {error}"))
        })?;
        Ok(Self {
            app_slug: app_slug.into(),
            app_id,
            installation_id,
            encoding_key,
            api_base: api_base.into().trim_end_matches('/').to_owned(),
            http,
        })
    }

    fn token_url(&self) -> String {
        format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base, self.installation_id
        )
    }

    fn refuse_minted_response(&self, token: &SecretString, reason: String) -> AdapterError {
        match self.revoke(token.expose()) {
            Ok(()) => AdapterError::new(reason),
            Err(revoke_error) => AdapterError::requiring_quarantine(format!(
                "{reason}; compensating revoke failed: {revoke_error}"
            )),
        }
    }
}

#[derive(Serialize)]
struct GithubJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    expires_at: String,
    permissions: BTreeMap<String, PermissionLevel>,
    repositories: Vec<GithubRepository>,
}

#[derive(Deserialize)]
struct GithubRepository {
    full_name: String,
}

fn take_minted_token(response_body: &mut Value) -> Result<SecretString, AdapterError> {
    match response_body
        .as_object_mut()
        .and_then(|object| object.remove("token"))
    {
        Some(Value::String(token)) => Ok(SecretString::new(token)),
        _ => Err(AdapterError::requiring_quarantine(
            "GitHub token mint succeeded without a recoverable token",
        )),
    }
}

impl ProviderAdapter for GithubAppAdapter {
    fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
        if request.provider != "github"
            || request.app_slug != self.app_slug
            || request.app_id != self.app_id
            || request.installation_id != self.installation_id
        {
            return Err(AdapterError::new(
                "mint request does not match configured GitHub App installation",
            ));
        }
        let claims = GithubJwtClaims {
            iat: request.now_unix.saturating_sub(60),
            exp: request.now_unix.saturating_add(9 * 60),
            iss: self.app_id.to_string(),
        };
        let jwt = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key)
            .map_err(|error| {
                AdapterError::new(format!("GitHub App JWT signing failed: {error}"))
            })?;
        let jwt = zeroize::Zeroizing::new(jwt);
        let body = json!({
            "repositories": [request.repository.repository()],
            "permissions": request.permissions,
        });
        let url = self.token_url();
        let response = self
            .http
            .execute(HttpRequest {
                method: HttpMethod::Post,
                url: &url,
                bearer_token: jwt.as_str(),
                body: Some(&body),
            })
            .map_err(|error| {
                AdapterError::requiring_quarantine(format!(
                    "GitHub token mint outcome is unknown: {error}"
                ))
            })?;
        if response.status != 201 {
            return Err(AdapterError::new(format!(
                "GitHub token mint returned HTTP {}",
                response.status
            )));
        }
        let mut response_body = response.body;
        let token = take_minted_token(&mut response_body)?;
        let response: GithubTokenResponse = match serde_json::from_value(response_body) {
            Ok(response) => response,
            Err(error) => {
                return Err(self.refuse_minted_response(
                    &token,
                    format!("GitHub token response schema is invalid: {error}"),
                ));
            }
        };
        let expires_at_unix = match OffsetDateTime::parse(&response.expires_at, &Rfc3339) {
            Ok(expires_at) => expires_at.unix_timestamp(),
            Err(error) => {
                return Err(self.refuse_minted_response(
                    &token,
                    format!("GitHub token expiry is invalid: {error}"),
                ));
            }
        };
        let repositories = response
            .repositories
            .into_iter()
            .map(|repository| {
                format!("github:{}", repository.full_name)
                    .parse::<RepositoryResource>()
                    .map_err(|error| AdapterError::new(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>();
        let repositories = match repositories {
            Ok(repositories) => repositories,
            Err(error) => {
                return Err(self.refuse_minted_response(&token, error.to_string()));
            }
        };
        let echo = CredentialEcho {
            provider_instance: request.provider_instance.clone(),
            generation: request.generation.clone(),
            provider: request.provider.to_owned(),
            app_slug: self.app_slug.clone(),
            app_id: self.app_id,
            installation_id: self.installation_id,
            repositories,
            permissions: response.permissions,
            expires_at_unix,
        };
        Ok(AdapterMint { token, echo })
    }

    fn revoke(&self, token: &str) -> Result<(), AdapterError> {
        GithubTokenRevoker::with_http(self.api_base.clone(), Arc::clone(&self.http)).revoke(token)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        io::{Read as _, Write as _},
        net::TcpListener,
        str::FromStr,
        thread,
    };

    use parking_lot::Mutex;
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey as _, LineEnding},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::model::{DelegationId, GrantId, PersonaId, ProcessBindingId, SessionId};

    struct AdapterDouble {
        minted: Mutex<VecDeque<Result<AdapterMint, AdapterError>>>,
        revoked: Mutex<Vec<String>>,
        fail_revoke: bool,
    }

    impl AdapterDouble {
        fn returning(minted: AdapterMint) -> Self {
            Self {
                minted: Mutex::new(VecDeque::from([Ok(minted)])),
                revoked: Mutex::new(Vec::new()),
                fail_revoke: false,
            }
        }

        fn failing(error: AdapterError) -> Self {
            Self {
                minted: Mutex::new(VecDeque::from([Err(error)])),
                revoked: Mutex::new(Vec::new()),
                fail_revoke: false,
            }
        }

        fn revoker(fail_revoke: bool) -> Self {
            Self {
                minted: Mutex::new(VecDeque::new()),
                revoked: Mutex::new(Vec::new()),
                fail_revoke,
            }
        }
    }

    impl ProviderAdapter for AdapterDouble {
        fn mint(&self, _request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
            self.minted.lock().pop_front().unwrap()
        }

        fn revoke(&self, token: &str) -> Result<(), AdapterError> {
            self.revoked.lock().push(token.to_owned());
            if self.fail_revoke {
                Err(AdapterError::new("injected revoke failure"))
            } else {
                Ok(())
            }
        }
    }

    struct IntentObservingAdapter {
        directory: std::path::PathBuf,
        observed_intent: Mutex<bool>,
    }

    impl ProviderAdapter for IntentObservingAdapter {
        fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
            let journal = RecoveryJournal::open_test_fixture(&self.directory, [10_u8; 32]).unwrap();
            let entries = journal.unresolved().unwrap();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].is_intent());
            assert_eq!(entries[0].provider_instance(), request.provider_instance);
            assert_eq!(entries[0].generation(), request.generation);
            *self.observed_intent.lock() = true;
            Ok(AdapterMint::new(
                "observed-token".to_owned(),
                CredentialEcho {
                    provider_instance: request.provider_instance.clone(),
                    generation: request.generation.clone(),
                    provider: request.provider.to_owned(),
                    app_slug: request.app_slug.to_owned(),
                    app_id: request.app_id,
                    installation_id: request.installation_id,
                    repositories: vec![request.repository.clone()],
                    permissions: request.permissions.clone(),
                    expires_at_unix: request.now_unix + 600,
                },
            ))
        }

        fn revoke(&self, _token: &str) -> Result<(), AdapterError> {
            Ok(())
        }
    }

    struct EchoRefusalObservingAdapter {
        minted: Mutex<Option<AdapterMint>>,
        directory: std::path::PathBuf,
        key: [u8; 32],
        revoked: Mutex<Vec<String>>,
        observed_only_intent: Mutex<bool>,
    }

    impl ProviderAdapter for EchoRefusalObservingAdapter {
        fn mint(&self, _request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
            Ok(self.minted.lock().take().unwrap())
        }

        fn revoke(&self, token: &str) -> Result<(), AdapterError> {
            let journal = RecoveryJournal::open_test_fixture(&self.directory, self.key).unwrap();
            let entries = journal.unresolved().unwrap();
            *self.observed_only_intent.lock() = entries.len() == 1
                && entries[0].is_intent()
                && entries[0].context().provider.is_none();
            self.revoked.lock().push(token.to_owned());
            Ok(())
        }
    }

    fn repository(name: &str) -> RepositoryResource {
        RepositoryResource::from_str(name).unwrap()
    }

    fn permissions() -> BTreeMap<String, PermissionLevel> {
        BTreeMap::from([
            ("contents".to_owned(), PermissionLevel::Write),
            ("metadata".to_owned(), PermissionLevel::Read),
        ])
    }

    fn need() -> Need {
        Need {
            provider: "github".to_owned(),
            repository: repository("github:ember/example"),
            destination_ref: None,
            permissions: permissions(),
        }
    }

    fn test_mint(
        registry: &mut ProviderRegistry,
        journal: &RecoveryJournal,
    ) -> Result<MintedCredential, ProviderError> {
        let decision = AuthorityDecision {
            persona_id: PersonaId::new(),
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            grant_id: GrantId::new(),
            delegation_path: vec![DelegationId::new()],
        };
        registry.mint(
            &OperationId::new(),
            &decision,
            "git.publish-ref/v1",
            &json!({"test": true}),
            &need(),
            1_000,
            journal,
        )
    }
    fn recovery_context(
        operation_id: OperationId,
        id: &ProviderInstanceId,
        generation: &ProviderGeneration,
    ) -> RecoveryContext {
        RecoveryContext {
            operation_id,
            persona_id: PersonaId::new(),
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            grant_id: GrantId::new(),
            delegation_path: vec![DelegationId::new()],
            action: "git.publish-ref/v1".to_owned(),
            approved_input: json!({"test": true}),
            need: need(),
            provider: Some(ProviderEvidence {
                provider_instance: id.clone(),
                generation: generation.clone(),
                app_slug: "ember-app".to_owned(),
                app_id: 41,
                installation_id: 73,
                repositories: vec!["ember/example".to_owned()],
                permissions: permissions(),
                expires_at_unix: 1_300,
            }),
        }
    }
    fn prepare_token(
        journal: &RecoveryJournal,
        context: &RecoveryContext,
        id: &ProviderInstanceId,
        generation: &ProviderGeneration,
        token: &str,
    ) -> MaterializationId {
        let materialization = journal.begin_mint(context, id, generation).unwrap();
        journal
            .record_token(&materialization, context.provider.clone().unwrap(), token)
            .unwrap();
        materialization
    }

    fn instance(adapter: Arc<dyn ProviderAdapter>) -> ProviderInstance {
        ProviderInstance::new(
            "github",
            "ember-app",
            41,
            73,
            [repository("github:ember/example")],
            permissions(),
            adapter,
        )
    }

    fn echo(instance: &ProviderInstance, repositories: Vec<RepositoryResource>) -> CredentialEcho {
        CredentialEcho {
            provider_instance: instance.id.clone(),
            generation: instance.generation.clone(),
            provider: "github".to_owned(),
            app_slug: "ember-app".to_owned(),
            app_id: 41,
            installation_id: 73,
            repositories,
            permissions: permissions(),
            expires_at_unix: 1_600,
        }
    }

    #[test]
    fn mint_adapter_observes_sealed_intent_before_issuing_token() {
        let directory = tempdir().unwrap();
        let adapter = Arc::new(IntentObservingAdapter {
            directory: directory.path().to_path_buf(),
            observed_intent: Mutex::new(false),
        });
        let mut registry = ProviderRegistry::default();
        registry.register(instance(adapter.clone())).unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [10_u8; 32]).unwrap();

        let credential = test_mint(&mut registry, &journal).unwrap();
        assert!(*adapter.observed_intent.lock());
        let entries = journal.unresolved().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].is_intent());
        let materialization = credential.materialization_id().clone();
        registry.revoke_credential(credential).unwrap();
        journal.settle(&materialization).unwrap();
    }

    #[test]
    fn ambiguous_mint_failure_quarantines_and_preserves_intent() {
        let adapter = Arc::new(AdapterDouble::failing(AdapterError::requiring_quarantine(
            "mint outcome unknown",
        )));
        let configured = instance(adapter);
        let id = configured.id.clone();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [11_u8; 32]).unwrap();
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::Adapter(_))
        ));
        assert!(registry.is_quarantined(&id));
        let unresolved = journal.unresolved().unwrap();
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].is_intent());
    }

    #[test]
    fn routing_refuses_zero_or_multiple_eligible_instances() {
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [1_u8; 32]).unwrap();
        let mut registry = ProviderRegistry::default();
        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::NoEligibleInstance)
        ));

        registry
            .register(instance(Arc::new(AdapterDouble::revoker(false))))
            .unwrap();
        registry
            .register(instance(Arc::new(AdapterDouble::revoker(false))))
            .unwrap();
        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::AmbiguousInstances)
        ));
    }

    #[test]
    fn widened_echo_is_refused_and_compensatingly_revoked() {
        let placeholder = Arc::new(AdapterDouble::revoker(false));
        let configured = instance(placeholder);
        let widened = echo(
            &configured,
            vec![
                repository("github:ember/example"),
                repository("github:ember/other"),
            ],
        );
        let adapter = Arc::new(AdapterDouble::returning(AdapterMint::new(
            "widened-token".to_owned(),
            widened,
        )));
        let configured = ProviderInstance {
            adapter: adapter.clone(),
            ..configured
        };
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [2_u8; 32]).unwrap();
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::EchoRefused)
        ));
        assert_eq!(adapter.revoked.lock().as_slice(), ["widened-token"]);
        assert!(journal.unresolved().unwrap().is_empty());
    }

    #[test]
    fn mismatched_app_echo_is_refused_and_compensatingly_revoked() {
        let placeholder = Arc::new(AdapterDouble::revoker(false));
        let configured = instance(placeholder);
        let mut mismatched = echo(&configured, vec![repository("github:ember/example")]);
        mismatched.app_id += 1;
        let adapter = Arc::new(AdapterDouble::returning(AdapterMint::new(
            "mismatched-token".to_owned(),
            mismatched,
        )));
        let configured = ProviderInstance {
            adapter: adapter.clone(),
            ..configured
        };
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [9_u8; 32]).unwrap();
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::EchoRefused)
        ));
        assert_eq!(adapter.revoked.lock().as_slice(), ["mismatched-token"]);
        assert!(journal.unresolved().unwrap().is_empty());
    }

    #[test]
    fn mismatched_permissions_are_revoked_before_evidence_is_journaled() {
        let placeholder = Arc::new(AdapterDouble::revoker(false));
        let configured = instance(placeholder);
        let mut mismatched = echo(&configured, vec![repository("github:ember/example")]);
        mismatched
            .permissions
            .insert("issues".to_owned(), PermissionLevel::Write);
        let directory = tempdir().unwrap();
        let key = [12_u8; 32];
        let adapter = Arc::new(EchoRefusalObservingAdapter {
            minted: Mutex::new(Some(AdapterMint::new(
                "mismatched-permissions-token".to_owned(),
                mismatched,
            ))),
            directory: directory.path().to_path_buf(),
            key,
            revoked: Mutex::new(Vec::new()),
            observed_only_intent: Mutex::new(false),
        });
        let configured = ProviderInstance {
            adapter: adapter.clone(),
            ..configured
        };
        let journal = RecoveryJournal::open_test_fixture(directory.path(), key).unwrap();
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::EchoRefused)
        ));
        assert!(*adapter.observed_only_intent.lock());
        assert_eq!(
            adapter.revoked.lock().as_slice(),
            ["mismatched-permissions-token"]
        );
        assert!(journal.unresolved().unwrap().is_empty());
    }

    #[test]
    fn successful_mint_without_a_token_requires_quarantine() {
        let mut response = Value::Null;
        let Err(error) = take_minted_token(&mut response) else {
            panic!("malformed successful mint was accepted");
        };

        assert!(error.quarantines_instance());
    }

    #[test]
    fn github_http_transport_sends_required_user_agent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let response = ReqwestBlockingHttp::default()
            .execute(HttpRequest {
                method: HttpMethod::Get,
                url: &format!("http://{address}/probe"),
                bearer_token: "redacted",
                body: None,
            })
            .unwrap();
        let request = server.join().unwrap().to_ascii_lowercase();

        assert_eq!(response.status, 200);
        assert!(request.contains(&format!(
            "\r\nuser-agent: {}\r\n",
            GITHUB_USER_AGENT.to_ascii_lowercase()
        )));
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ObservedRequest {
        method: HttpMethod,
        url: String,
        bearer: String,
        body: Option<Value>,
    }

    struct HttpDouble {
        requests: Mutex<Vec<ObservedRequest>>,
        response_status: u16,
        response_body: Value,
    }

    impl BlockingHttp for HttpDouble {
        fn execute(&self, request: HttpRequest<'_>) -> Result<HttpResponse, AdapterError> {
            self.requests.lock().push(ObservedRequest {
                method: request.method,
                url: request.url.to_owned(),
                bearer: request.bearer_token.to_owned(),
                body: request.body.cloned(),
            });
            Ok(HttpResponse {
                status: self.response_status,
                body: self.response_body.clone(),
                body_bytes: 0,
            })
        }
    }

    fn github_adapter(http: Arc<dyn BlockingHttp>) -> GithubAppAdapter {
        let mut rng = rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2_048).unwrap();
        let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        GithubAppAdapter::with_http(
            "ember-app",
            41,
            73,
            private_key_pem.as_bytes(),
            "https://github.invalid/api/v3/",
            http,
        )
        .unwrap()
    }

    #[test]
    fn github_mint_forms_scoped_post_with_app_jwt_and_permissions() {
        let http = Arc::new(HttpDouble {
            requests: Mutex::new(Vec::new()),
            response_status: 201,
            response_body: json!({
                "token": "installation-token",
                "expires_at": "1970-01-01T00:26:40Z",
                "permissions": permissions(),
                "repositories": [{"full_name": "ember/example"}]
            }),
        });
        let adapter = github_adapter(http.clone());
        let provider_instance = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let repository = repository("github:ember/example");
        let permissions = permissions();
        let request = MintRequest {
            provider_instance: &provider_instance,
            generation: &generation,
            provider: "github",
            app_slug: "ember-app",
            app_id: 41,
            installation_id: 73,
            repository: &repository,
            permissions: &permissions,
            now_unix: 1_000,
        };

        let minted = adapter.mint(&request).unwrap();
        assert_eq!(minted.token.expose(), "installation-token");
        assert_eq!(minted.echo.repositories, [repository]);
        assert_eq!(minted.echo.permissions, permissions);
        let requests = http.requests.lock();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(
            requests[0].url,
            "https://github.invalid/api/v3/app/installations/73/access_tokens"
        );
        assert_eq!(requests[0].bearer.split('.').count(), 3);
        assert_eq!(
            requests[0].body,
            Some(json!({
                "repositories": ["example"],
                "permissions": permissions
            }))
        );
    }

    #[test]
    fn github_mint_refuses_wrong_provider_and_app_slug_before_http() {
        let http = Arc::new(HttpDouble {
            requests: Mutex::new(Vec::new()),
            response_status: 500,
            response_body: Value::Null,
        });
        let adapter = GithubAppAdapter {
            app_slug: "ember-app".to_owned(),
            app_id: 41,
            installation_id: 73,
            encoding_key: EncodingKey::from_secret(b"guard-path-does-not-sign"),
            api_base: "https://github.invalid/api/v3".to_owned(),
            http: http.clone(),
        };
        let provider_instance = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let repository = repository("github:ember/example");
        let permissions = permissions();

        for (provider, app_slug) in [("gitlab", "ember-app"), ("github", "different-app")] {
            assert!(
                adapter
                    .mint(&MintRequest {
                        provider_instance: &provider_instance,
                        generation: &generation,
                        provider,
                        app_slug,
                        app_id: 41,
                        installation_id: 73,
                        repository: &repository,
                        permissions: &permissions,
                        now_unix: 1_000,
                    })
                    .is_err()
            );
        }
        assert!(http.requests.lock().is_empty());
    }

    #[test]
    fn github_revoke_forms_real_delete_request_with_token() {
        let http = Arc::new(HttpDouble {
            requests: Mutex::new(Vec::new()),
            response_status: 204,
            response_body: Value::Null,
        });
        let adapter = GithubTokenRevoker::with_http("https://github.invalid/api/v3", http.clone());

        adapter.revoke("installation-token").unwrap();
        assert_eq!(
            http.requests.lock().as_slice(),
            [ObservedRequest {
                method: HttpMethod::Delete,
                url: "https://github.invalid/api/v3/installation/token".to_owned(),
                bearer: "installation-token".to_owned(),
                body: None,
            }]
        );
    }

    #[test]
    fn startup_revokes_but_preserves_evidence_for_kernel_result() {
        let adapter = Arc::new(AdapterDouble::revoker(false));
        let configured = instance(adapter.clone());
        let id = configured.id.clone();
        let generation = configured.generation.clone();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [3_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &generation);
        prepare_token(&journal, &context, &id, &generation, "orphaned-token");
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        let outcomes = registry.recover(&journal, &BTreeSet::new()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].upstream_revoked);
        assert!(!outcomes[0].quarantined);
        assert_eq!(journal.unresolved().unwrap().len(), 1);
        assert_eq!(adapter.revoked.lock().as_slice(), ["orphaned-token"]);
    }

    #[test]
    fn startup_revoke_failure_quarantines_and_preserves_entry() {
        let adapter = Arc::new(AdapterDouble::revoker(true));
        let configured = instance(adapter);
        let id = configured.id.clone();
        let generation = configured.generation.clone();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [4_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &generation);
        prepare_token(&journal, &context, &id, &generation, "still-live");
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        let outcomes = registry.recover(&journal, &BTreeSet::new()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].upstream_revoked);
        assert!(outcomes[0].quarantined);
        assert!(registry.is_quarantined(&id));
        assert_eq!(journal.unresolved().unwrap().len(), 1);
        assert!(matches!(
            test_mint(&mut registry, &journal),
            Err(ProviderError::NoEligibleInstance)
        ));
    }

    #[test]
    fn intent_only_entry_requarantines_exact_generation_on_every_restart() {
        let id = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [5_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &generation);
        journal.begin_mint(&context, &id, &generation).unwrap();
        let adapter = Arc::new(AdapterDouble::revoker(false));

        for _ in 0..2 {
            let configured = ProviderInstance::with_identity(
                id.clone(),
                generation.clone(),
                "github",
                "ember-app",
                41,
                73,
                [repository("github:ember/example")],
                permissions(),
                adapter.clone(),
            );
            let mut registry = ProviderRegistry::default();
            registry.register(configured).unwrap();
            let outcomes = registry.recover(&journal, &BTreeSet::new()).unwrap();
            assert!(outcomes[0].quarantined);
            assert!(!outcomes[0].settlement_ready);
            assert!(registry.is_quarantined(&id));
            assert!(matches!(
                test_mint(&mut registry, &journal),
                Err(ProviderError::NoEligibleInstance)
            ));
        }
        assert!(adapter.revoked.lock().is_empty());
        assert_eq!(journal.unresolved().unwrap().len(), 1);
    }

    #[test]
    fn unavailable_instance_preserves_intent_without_blocking_other_generations() {
        let id = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [6_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &generation);
        journal.begin_mint(&context, &id, &generation).unwrap();
        let mut registry = ProviderRegistry::default();

        let outcomes = registry.recover(&journal, &BTreeSet::new()).unwrap();
        assert!(!outcomes[0].quarantined);
        assert!(!outcomes[0].settlement_ready);
        assert_eq!(journal.unresolved().unwrap().len(), 1);
    }

    #[test]
    fn generation_rotation_preserves_ambiguous_intent_and_quarantines_provider() {
        let id = ProviderInstanceId::new();
        let old_generation = ProviderGeneration::new();
        let new_generation = ProviderGeneration::new();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [7_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &old_generation);
        journal.begin_mint(&context, &id, &old_generation).unwrap();
        let configured = ProviderInstance::with_identity(
            id.clone(),
            new_generation,
            "github",
            "ember-app",
            41,
            73,
            [repository("github:ember/example")],
            permissions(),
            Arc::new(AdapterDouble::revoker(false)),
        );
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        let outcomes = registry.recover(&journal, &BTreeSet::new()).unwrap();
        assert!(!outcomes[0].settlement_ready);
        assert!(!outcomes[0].upstream_revoked);
        assert!(outcomes[0].quarantined);
        assert!(registry.is_quarantined(&id));
        assert_eq!(journal.unresolved().unwrap().len(), 1);
    }

    #[test]
    fn result_proven_token_recovery_skips_duplicate_revoke() {
        let adapter = Arc::new(AdapterDouble::revoker(false));
        let configured = instance(adapter.clone());
        let id = configured.id.clone();
        let generation = configured.generation.clone();
        let directory = tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [8_u8; 32]).unwrap();
        let context = recovery_context(OperationId::new(), &id, &generation);
        let materialization =
            prepare_token(&journal, &context, &id, &generation, "already-revoked");
        let mut registry = ProviderRegistry::default();
        registry.register(configured).unwrap();

        let outcomes = registry
            .recover(&journal, &BTreeSet::from([materialization]))
            .unwrap();
        assert!(outcomes[0].settlement_ready);
        assert!(outcomes[0].upstream_revoked);
        assert!(adapter.revoked.lock().is_empty());
    }
}
