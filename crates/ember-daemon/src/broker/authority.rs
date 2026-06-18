use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::Utc;
use core_broker::{Broker, BrokerError, BrokerProvider, BrokerRequest, BrokeredCredential};
use ember_broker::github_app::GhAppCredentials;
use ember_broker::{
    AwsLongLivedCredentials, AwsStsBroker, AzureCliBroker, AzureServicePrincipal, FlyBroker,
    FlyParentToken, GcpBroker, GcpServiceAccountKey, GitHubBroker, HashiVaultBroker,
    HashiVaultParentToken, OktaBroker, OktaServiceApp, VercelBroker, VercelParentToken,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::broker::handler::DynBroker;
use crate::infra::credential_store::{CredentialStore, StoreError};

const GITHUB_PAT_STORE_KEY: &str = "github-pat";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPrecedence {
    FileFirst,
    VaultFirst,
}

impl CredentialPrecedence {
    pub fn from_env() -> Self {
        if std::env::var("EMBER_VAULT_FIRST").ok().as_deref() == Some("1") {
            Self::VaultFirst
        } else {
            Self::FileFirst
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileFirst => "file-first",
            Self::VaultFirst => "vault-first",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerAuthorityError {
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupProbeMode {
    Plaintext,
    MetadataOnly,
}

#[derive(Clone)]
pub struct BrokerAuthorityResolver {
    store: Arc<dyn CredentialStore>,
    precedence: CredentialPrecedence,
}

static CURRENT_RESOLVER: once_cell::sync::OnceCell<Arc<BrokerAuthorityResolver>> =
    once_cell::sync::OnceCell::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthoritySource {
    App,
    Pat,
}

#[derive(Clone)]
pub enum ResolvedBrokerAuthority {
    GithubApp(GhAppCredentials),
    GithubPat(SecretString),
    AwsSts((AwsLongLivedCredentials, Option<String>)),
    Gcp((GcpServiceAccountKey, Option<String>)),
    AzureCli(AzureServicePrincipal),
    FlyIo(FlyParentToken),
    HashiVault(HashiVaultParentToken),
    Okta(OktaServiceApp),
    Vercel(VercelParentToken),
}

impl ResolvedBrokerAuthority {
    fn provider(&self) -> BrokerProvider {
        match self {
            Self::GithubApp(_) | Self::GithubPat(_) => BrokerProvider::Github,
            Self::AwsSts(_) => BrokerProvider::AwsSts,
            Self::Gcp(_) => BrokerProvider::Gcp,
            Self::AzureCli(_) => BrokerProvider::AzureCli,
            Self::FlyIo(_) => BrokerProvider::FlyIo,
            Self::HashiVault(_) => BrokerProvider::HashiVault,
            Self::Okta(_) => BrokerProvider::Okta,
            Self::Vercel(_) => BrokerProvider::Vercel,
        }
    }
}

impl BrokerAuthorityResolver {
    pub fn new(store: Arc<dyn CredentialStore>, precedence: CredentialPrecedence) -> Self {
        Self { store, precedence }
    }

    pub fn install_current(resolver: Arc<Self>) {
        let _ = CURRENT_RESOLVER.set(resolver);
    }

    pub fn current() -> Option<Arc<Self>> {
        CURRENT_RESOLVER.get().cloned()
    }

    pub fn precedence(&self) -> CredentialPrecedence {
        self.precedence
    }

    pub async fn startup_configured(
        &self,
        provider: BrokerProvider,
        mode: StartupProbeMode,
    ) -> Result<bool, BrokerAuthorityError> {
        match mode {
            StartupProbeMode::Plaintext => self.resolve(provider).await.map(|opt| opt.is_some()),
            StartupProbeMode::MetadataOnly => self.startup_configured_from_metadata(provider).await,
        }
    }

    pub async fn resolve(
        &self,
        provider: BrokerProvider,
    ) -> Result<Option<ResolvedBrokerAuthority>, BrokerAuthorityError> {
        match provider {
            BrokerProvider::Github => self.resolve_github().await,
            BrokerProvider::AwsSts => self
                .resolve_aws_sts()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::AwsSts)),
            BrokerProvider::Gcp => self
                .resolve_gcp()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::Gcp)),
            BrokerProvider::AzureCli => self
                .resolve_azure()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::AzureCli)),
            BrokerProvider::FlyIo => self
                .resolve_fly()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::FlyIo)),
            BrokerProvider::HashiVault => self
                .resolve_hashivault()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::HashiVault)),
            BrokerProvider::Okta => self
                .resolve_okta()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::Okta)),
            BrokerProvider::Vercel => self
                .resolve_vercel()
                .await
                .map(|opt| opt.map(ResolvedBrokerAuthority::Vercel)),
            BrokerProvider::Cloudflare | BrokerProvider::Anthropic | BrokerProvider::Tailscale => {
                Ok(None)
            }
        }
    }

    pub async fn github_authority_source(
        &self,
    ) -> Result<Option<GithubAuthoritySource>, BrokerAuthorityError> {
        Ok(self
            .resolve_github()
            .await?
            .map(|authority| match authority {
                ResolvedBrokerAuthority::GithubApp(_) => GithubAuthoritySource::App,
                ResolvedBrokerAuthority::GithubPat(_) => GithubAuthoritySource::Pat,
                _ => unreachable!("resolve_github only returns github authority"),
            }))
    }

    async fn resolve_github(
        &self,
    ) -> Result<Option<ResolvedBrokerAuthority>, BrokerAuthorityError> {
        let app = match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::github_config::github_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::github_config::load_gh_app_credentials()
                        .map_err(|err| self.file_error(BrokerProvider::Github, err))?,
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::Github, &err);
                        crate::broker::github_config::load_gh_app_credentials()
                            .map_err(|load_err| self.file_error(BrokerProvider::Github, load_err))?
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::github_config::load_gh_app_credentials()
                    .map_err(|err| self.file_error(BrokerProvider::Github, err))?
                {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::github_config::github_config_from_store(&*self.store)
                            .await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::Github, &err);
                                None
                            }
                        }
                    }
                }
            }
        };

        if let Some(creds) = app {
            return Ok(Some(ResolvedBrokerAuthority::GithubApp(creds)));
        }

        Ok(self
            .resolve_github_pat()
            .await?
            .map(ResolvedBrokerAuthority::GithubPat))
    }

    async fn resolve_github_pat(&self) -> Result<Option<SecretString>, BrokerAuthorityError> {
        match self.store.get(GITHUB_PAT_STORE_KEY).await {
            Ok(bytes) => {
                let token = String::from_utf8(bytes).map_err(|e| {
                    BrokerAuthorityError::Message(format!(
                        "{GITHUB_PAT_STORE_KEY} present but not valid UTF-8: {e}"
                    ))
                })?;
                if token.trim().is_empty() {
                    return Err(BrokerAuthorityError::Message(format!(
                        "{GITHUB_PAT_STORE_KEY} present but empty"
                    )));
                }
                Ok(Some(SecretString::from(token)))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(err) => Err(BrokerAuthorityError::Message(format!(
                "provider github PAT fallback load failed under {} precedence: {}",
                self.precedence.as_str(),
                err
            ))),
        }
    }

    async fn resolve_aws_sts(
        &self,
    ) -> Result<Option<(AwsLongLivedCredentials, Option<String>)>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::aws_sts_config::aws_sts_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::aws_sts_config::load_aws_sts_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::AwsSts, &err);
                        crate::broker::aws_sts_config::load_aws_sts_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::aws_sts_config::load_aws_sts_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::aws_sts_config::aws_sts_config_from_store(&*self.store)
                            .await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::AwsSts, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_gcp(
        &self,
    ) -> Result<Option<(GcpServiceAccountKey, Option<String>)>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::gcp_config::gcp_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::gcp_config::load_gcp_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::Gcp, &err);
                        crate::broker::gcp_config::load_gcp_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::gcp_config::load_gcp_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::gcp_config::gcp_config_from_store(&*self.store).await {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::Gcp, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_azure(&self) -> Result<Option<AzureServicePrincipal>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::azure_config::azure_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::azure_config::load_azure_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::AzureCli, &err);
                        crate::broker::azure_config::load_azure_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::azure_config::load_azure_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::azure_config::azure_config_from_store(&*self.store)
                            .await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::AzureCli, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_fly(&self) -> Result<Option<FlyParentToken>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::fly_config::fly_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::fly_config::load_fly_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::FlyIo, &err);
                        crate::broker::fly_config::load_fly_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::fly_config::load_fly_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::fly_config::fly_config_from_store(&*self.store).await {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::FlyIo, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_hashivault(
        &self,
    ) -> Result<Option<HashiVaultParentToken>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::hashivault_config::hashivault_config_from_store(&*self.store)
                    .await
                {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::hashivault_config::load_hashivault_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::HashiVault, &err);
                        crate::broker::hashivault_config::load_hashivault_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::hashivault_config::load_hashivault_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::hashivault_config::hashivault_config_from_store(
                            &*self.store,
                        )
                        .await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::HashiVault, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_okta(&self) -> Result<Option<OktaServiceApp>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::okta_config::okta_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::okta_config::load_okta_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::Okta, &err);
                        crate::broker::okta_config::load_okta_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::okta_config::load_okta_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::okta_config::okta_config_from_store(&*self.store).await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::Okta, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    async fn resolve_vercel(&self) -> Result<Option<VercelParentToken>, BrokerAuthorityError> {
        Ok(match self.precedence {
            CredentialPrecedence::VaultFirst => {
                match crate::broker::vercel_config::vercel_config_from_store(&*self.store).await {
                    Ok(Some(creds)) => Some(creds),
                    Ok(None) => crate::broker::vercel_config::load_vercel_credentials(),
                    Err(err) => {
                        warn_store_fallback(BrokerProvider::Vercel, &err);
                        crate::broker::vercel_config::load_vercel_credentials()
                    }
                }
            }
            CredentialPrecedence::FileFirst => {
                match crate::broker::vercel_config::load_vercel_credentials() {
                    Some(creds) => Some(creds),
                    None => {
                        match crate::broker::vercel_config::vercel_config_from_store(&*self.store)
                            .await
                        {
                            Ok(opt) => opt,
                            Err(err) => {
                                warn_store_absent(BrokerProvider::Vercel, &err);
                                None
                            }
                        }
                    }
                }
            }
        })
    }

    fn file_error(
        &self,
        provider: BrokerProvider,
        err: impl std::fmt::Display,
    ) -> BrokerAuthorityError {
        BrokerAuthorityError::Message(format!(
            "provider {} file credential load failed under {} precedence: {}",
            provider.as_str(),
            self.precedence.as_str(),
            err
        ))
    }

    async fn startup_configured_from_metadata(
        &self,
        provider: BrokerProvider,
    ) -> Result<bool, BrokerAuthorityError> {
        match provider {
            BrokerProvider::Github => self.startup_github_from_metadata().await,
            BrokerProvider::AwsSts => {
                self.startup_simple_from_metadata(
                    provider,
                    &[
                        "aws-sts/access-key-id",
                        "aws-sts/secret-access-key",
                        "aws-sts/region",
                    ],
                    || Ok(crate::broker::aws_sts_config::load_aws_sts_credentials().is_some()),
                )
                .await
            }
            BrokerProvider::Gcp => {
                self.startup_simple_from_metadata(
                    provider,
                    &["gcp/client-email", "gcp/private-key", "gcp/project-id"],
                    || Ok(crate::broker::gcp_config::load_gcp_credentials().is_some()),
                )
                .await
            }
            BrokerProvider::AzureCli => self.startup_azure_from_metadata(provider).await,
            BrokerProvider::FlyIo => {
                self.startup_simple_from_metadata(provider, &["fly/api-token"], || {
                    Ok(crate::broker::fly_config::load_fly_credentials().is_some())
                })
                .await
            }
            BrokerProvider::HashiVault => {
                self.startup_simple_from_metadata(
                    provider,
                    &["hashivault/token", "hashivault/address"],
                    || {
                        Ok(
                            crate::broker::hashivault_config::load_hashivault_credentials()
                                .is_some(),
                        )
                    },
                )
                .await
            }
            BrokerProvider::Okta => {
                self.startup_simple_from_metadata(
                    provider,
                    &[
                        "okta/org-url",
                        "okta/client-id",
                        "okta/private-key-pem",
                        "okta/key-id",
                    ],
                    || Ok(crate::broker::okta_config::load_okta_credentials().is_some()),
                )
                .await
            }
            BrokerProvider::Vercel => {
                self.startup_simple_from_metadata(provider, &["vercel/api-token"], || {
                    Ok(crate::broker::vercel_config::load_vercel_credentials().is_some())
                })
                .await
            }
            BrokerProvider::Cloudflare | BrokerProvider::Anthropic | BrokerProvider::Tailscale => {
                Ok(false)
            }
        }
    }

    async fn startup_simple_from_metadata<F>(
        &self,
        provider: BrokerProvider,
        required_store_keys: &[&str],
        file_loader: F,
    ) -> Result<bool, BrokerAuthorityError>
    where
        F: FnOnce() -> Result<bool, BrokerAuthorityError>,
    {
        match self.precedence {
            CredentialPrecedence::VaultFirst => {
                if store_has_all_metadata_keys(&*self.store, required_store_keys)
                    .await
                    .map_err(|err| self.store_error(provider, err))?
                {
                    Ok(true)
                } else {
                    file_loader()
                }
            }
            CredentialPrecedence::FileFirst => {
                if file_loader()? {
                    Ok(true)
                } else {
                    store_has_all_metadata_keys(&*self.store, required_store_keys)
                        .await
                        .map_err(|err| self.store_error(provider, err))
                }
            }
        }
    }

    async fn startup_github_from_metadata(&self) -> Result<bool, BrokerAuthorityError> {
        match self.precedence {
            CredentialPrecedence::VaultFirst => {
                let store_configured = github_store_configured_from_metadata(&*self.store)
                    .await
                    .map_err(|err| self.store_error(BrokerProvider::Github, err))?;
                if store_configured {
                    Ok(true)
                } else {
                    Ok(crate::broker::github_config::load_gh_app_credentials()
                        .map_err(|err| self.file_error(BrokerProvider::Github, err))?
                        .is_some())
                }
            }
            CredentialPrecedence::FileFirst => {
                let file_configured = crate::broker::github_config::load_gh_app_credentials()
                    .map_err(|err| self.file_error(BrokerProvider::Github, err))?
                    .is_some();
                if file_configured {
                    Ok(true)
                } else {
                    github_store_configured_from_metadata(&*self.store)
                        .await
                        .map_err(|err| self.store_error(BrokerProvider::Github, err))
                }
            }
        }
    }

    async fn startup_azure_from_metadata(
        &self,
        provider: BrokerProvider,
    ) -> Result<bool, BrokerAuthorityError> {
        match self.precedence {
            CredentialPrecedence::VaultFirst => {
                if azure_store_configured_from_metadata(&*self.store)
                    .await
                    .map_err(|err| self.store_error(provider, err))?
                {
                    Ok(true)
                } else {
                    Ok(crate::broker::azure_config::load_azure_credentials().is_some())
                }
            }
            CredentialPrecedence::FileFirst => {
                if crate::broker::azure_config::load_azure_credentials().is_some() {
                    Ok(true)
                } else {
                    azure_store_configured_from_metadata(&*self.store)
                        .await
                        .map_err(|err| self.store_error(provider, err))
                }
            }
        }
    }

    fn store_error(&self, provider: BrokerProvider, err: StoreError) -> BrokerAuthorityError {
        BrokerAuthorityError::Message(format!(
            "provider {} startup metadata check failed under {} precedence: {}",
            provider.as_str(),
            self.precedence.as_str(),
            err
        ))
    }
}

async fn store_has_all_metadata_keys(
    store: &dyn CredentialStore,
    required_keys: &[&str],
) -> Result<bool, StoreError> {
    let keys = store.list_metadata(None).await?;
    Ok(required_keys
        .iter()
        .all(|key| keys.iter().any(|found| found == key)))
}

async fn github_store_configured_from_metadata(
    store: &dyn CredentialStore,
) -> Result<bool, StoreError> {
    let keys = store.list_metadata(Some("github/apps/")).await?;
    let mut triples: std::collections::BTreeMap<String, [bool; 3]> =
        std::collections::BTreeMap::new();
    for key in &keys {
        let Some(suffix) = key.strip_prefix("github/apps/") else {
            continue;
        };
        let parts: Vec<&str> = suffix.split('/').collect();
        if parts.len() != 3 {
            continue;
        }
        let (slug, install, purpose) = (parts[0], parts[1], parts[2]);
        if !install.starts_with("install-") {
            continue;
        }
        let triple_key = format!("{slug}/{install}");
        let slot = triples.entry(triple_key).or_insert([false; 3]);
        match purpose {
            "private-key" => slot[0] = true,
            "app-id" => slot[1] = true,
            "installation-id" => slot[2] = true,
            _ => {}
        }
    }

    // Empty triples set is NOT a "configured = false" signal on its
    // own — the operator may have provisioned a `github-pat` entry
    // without any App-style triple. Fall through to the PAT-fallback
    // probe below so PAT-only deployments resolve as configured.
    // Partial of META-AP-EMBER-DAEMON-BROKEN-TEST-CLUSTER: the
    // `startup_metadata_probe_accepts_github_pat_without_app` T1
    // unit asserts this exact contract.
    // Anchor: `ember_daemon_broken_test_cluster_resolved`.
    if triples.is_empty() {
        return github_pat_store_configured_from_metadata(store).await;
    }

    for (triple_key, slots) in &triples {
        let complete = slots[0] && slots[1] && slots[2];
        let any = slots[0] || slots[1] || slots[2];
        if !complete && any {
            return Err(StoreError::Other(format!(
                "github/apps/{triple_key}: partial credential triple \
                 (private-key={}, app-id={}, installation-id={}); \
                 all three leaves must be present",
                slots[0], slots[1], slots[2]
            )));
        }
        if complete {
            return Ok(true);
        }
    }

    github_pat_store_configured_from_metadata(store).await
}

async fn github_pat_store_configured_from_metadata(
    store: &dyn CredentialStore,
) -> Result<bool, StoreError> {
    let keys = store.list_metadata(None).await?;
    Ok(keys.iter().any(|found| found == GITHUB_PAT_STORE_KEY))
}

async fn azure_store_configured_from_metadata(
    store: &dyn CredentialStore,
) -> Result<bool, StoreError> {
    let keys = store.list_metadata(None).await?;
    let has = |needle: &str| keys.iter().any(|found| found == needle);
    Ok(has("azure/tenant-id")
        && has("azure/client-id")
        && (has("azure/client-secret") || has("azure/oidc-token-path")))
}

// allow(dead_code): broker authority-enrollment helper; no current caller but kept (auth-relevant, reversible).
#[allow(dead_code)]
pub(crate) fn local_store_authority_keys_from_metadata(
    keys: &[String],
) -> Result<Vec<String>, BrokerAuthorityError> {
    local_store_authority_keys_for_refs(
        keys,
        &[
            "github".to_string(),
            "aws_sts".to_string(),
            "gcp".to_string(),
            "azure_cli".to_string(),
            "fly_io".to_string(),
            "hashi_vault".to_string(),
            "okta".to_string(),
            "vercel".to_string(),
        ],
    )
}

pub(crate) fn local_store_authority_keys_for_refs(
    keys: &[String],
    refs: &[String],
) -> Result<Vec<String>, BrokerAuthorityError> {
    use std::collections::{BTreeMap, BTreeSet};

    let has = |needle: &str| keys.iter().any(|found| found == needle);
    let wants = |needle: &str| refs.iter().any(|found| found == needle);
    let mut enrolled = BTreeSet::new();

    if wants("aws_sts")
        && has("aws-sts/access-key-id")
        && has("aws-sts/secret-access-key")
        && has("aws-sts/region")
    {
        enrolled.insert("aws-sts/access-key-id".to_string());
        enrolled.insert("aws-sts/secret-access-key".to_string());
        enrolled.insert("aws-sts/region".to_string());
        if has("aws-sts/session-token") {
            enrolled.insert("aws-sts/session-token".to_string());
        }
        if has("aws-sts/default-role-arn") {
            enrolled.insert("aws-sts/default-role-arn".to_string());
        }
    }

    if wants("gcp") && has("gcp/client-email") && has("gcp/private-key") && has("gcp/project-id") {
        enrolled.insert("gcp/client-email".to_string());
        enrolled.insert("gcp/private-key".to_string());
        enrolled.insert("gcp/project-id".to_string());
        if has("gcp/default-target-service-account") {
            enrolled.insert("gcp/default-target-service-account".to_string());
        }
    }

    if wants("azure_cli")
        && has("azure/tenant-id")
        && has("azure/client-id")
        && (has("azure/client-secret") || has("azure/oidc-token-path"))
    {
        enrolled.insert("azure/tenant-id".to_string());
        enrolled.insert("azure/client-id".to_string());
        if has("azure/client-secret") {
            enrolled.insert("azure/client-secret".to_string());
        }
        if has("azure/oidc-token-path") {
            enrolled.insert("azure/oidc-token-path".to_string());
        }
    }

    if wants("fly_io") && has("fly/api-token") {
        enrolled.insert("fly/api-token".to_string());
        if has("fly/default-org-slug") {
            enrolled.insert("fly/default-org-slug".to_string());
        }
    }

    if wants("hashi_vault") && has("hashivault/token") && has("hashivault/address") {
        enrolled.insert("hashivault/token".to_string());
        enrolled.insert("hashivault/address".to_string());
        if has("hashivault/namespace") {
            enrolled.insert("hashivault/namespace".to_string());
        }
    }

    if wants("okta")
        && has("okta/org-url")
        && has("okta/client-id")
        && has("okta/private-key-pem")
        && has("okta/key-id")
    {
        enrolled.insert("okta/org-url".to_string());
        enrolled.insert("okta/client-id".to_string());
        enrolled.insert("okta/private-key-pem".to_string());
        enrolled.insert("okta/key-id".to_string());
    }

    if wants("vercel") && has("vercel/api-token") {
        enrolled.insert("vercel/api-token".to_string());
        if has("vercel/default-team-id") {
            enrolled.insert("vercel/default-team-id".to_string());
        }
    }

    let github_keys: Vec<String> = if wants("github") {
        keys.iter()
            .filter(|key| key.starts_with("github/apps/"))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    if !github_keys.is_empty() {
        let mut triples: BTreeMap<String, [bool; 3]> = BTreeMap::new();
        for key in &github_keys {
            let Some(suffix) = key.strip_prefix("github/apps/") else {
                continue;
            };
            let parts: Vec<&str> = suffix.split('/').collect();
            if parts.len() != 3 {
                continue;
            }
            let (slug, install, purpose) = (parts[0], parts[1], parts[2]);
            if !install.starts_with("install-") {
                continue;
            }
            let triple_key = format!("{slug}/{install}");
            let slot = triples.entry(triple_key).or_insert([false; 3]);
            match purpose {
                "private-key" => slot[0] = true,
                "app-id" => slot[1] = true,
                "installation-id" => slot[2] = true,
                _ => {}
            }
        }

        for (triple_key, slots) in &triples {
            let complete = slots[0] && slots[1] && slots[2];
            let any = slots[0] || slots[1] || slots[2];
            if !complete && any {
                return Err(BrokerAuthorityError::Message(format!(
                    "github/apps/{triple_key}: partial credential triple \
                     (private-key={}, app-id={}, installation-id={}); \
                     all three leaves must be present",
                    slots[0], slots[1], slots[2]
                )));
            }
            if complete {
                enrolled.insert(format!("github/apps/{triple_key}/private-key"));
                enrolled.insert(format!("github/apps/{triple_key}/app-id"));
                enrolled.insert(format!("github/apps/{triple_key}/installation-id"));
            }
        }
    }

    if wants("github") && has(GITHUB_PAT_STORE_KEY) {
        enrolled.insert(GITHUB_PAT_STORE_KEY.to_string());
    }

    Ok(enrolled.into_iter().collect())
}

fn warn_store_fallback(provider: BrokerProvider, err: &StoreError) {
    tracing::warn!(
        provider = provider.as_str(),
        error = %err,
        "broker authority: credential-store read failed; falling back to env file"
    );
}

fn warn_store_absent(provider: BrokerProvider, err: &StoreError) {
    tracing::warn!(
        provider = provider.as_str(),
        error = %err,
        "broker authority: credential-store fallback read failed; treating as absent"
    );
}

pub struct ReloadingBroker {
    provider: BrokerProvider,
    resolver: Arc<BrokerAuthorityResolver>,
    http: reqwest::Client,
}

impl ReloadingBroker {
    pub fn new(provider: BrokerProvider, resolver: Arc<BrokerAuthorityResolver>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("ember-daemon/broker-authority")
            .build()
            .expect("reqwest client construction must not fail in production");
        Self {
            provider,
            resolver,
            http,
        }
    }

    async fn resolve_authority(&self) -> Result<ResolvedBrokerAuthority, BrokerError> {
        let authority = self
            .resolver
            .resolve(self.provider)
            .await
            .map_err(|err| BrokerError::Other(err.to_string()))?;
        authority.ok_or_else(|| {
            BrokerError::Other(format!(
                "runtime broker authority unavailable for provider {}",
                self.provider.as_str()
            ))
        })
    }

    async fn issue_with_authority(
        &self,
        authority: ResolvedBrokerAuthority,
        req: BrokerRequest,
    ) -> Result<BrokeredCredential, BrokerError> {
        debug_assert_eq!(authority.provider(), self.provider);
        match authority {
            ResolvedBrokerAuthority::GithubApp(creds) => {
                Broker::issue(&GitHubBroker::new(creds), req).await
            }
            ResolvedBrokerAuthority::GithubPat(token) => issue_github_pat(req, token),
            ResolvedBrokerAuthority::AwsSts((creds, default_role_arn)) => {
                Broker::issue(&AwsStsBroker::new(creds, default_role_arn), req).await
            }
            ResolvedBrokerAuthority::Gcp((key, default_target)) => {
                Broker::issue(&GcpBroker::new(key, default_target), req).await
            }
            ResolvedBrokerAuthority::AzureCli(sp) => {
                Broker::issue(&AzureCliBroker::new(sp), req).await
            }
            ResolvedBrokerAuthority::FlyIo(parent) => {
                Broker::issue(&FlyBroker::new(parent), req).await
            }
            ResolvedBrokerAuthority::HashiVault(parent) => {
                Broker::issue(&HashiVaultBroker::new(parent), req).await
            }
            ResolvedBrokerAuthority::Okta(app) => Broker::issue(&OktaBroker::new(app), req).await,
            ResolvedBrokerAuthority::Vercel(parent) => {
                Broker::issue(&VercelBroker::new(parent), req).await
            }
        }
    }

    async fn revoke_upstream(
        &self,
        authority: ResolvedBrokerAuthority,
        materialization_id: &str,
        plaintext: Option<SecretString>,
    ) -> Result<(), BrokerError> {
        match authority {
            ResolvedBrokerAuthority::Gcp(_) => self.revoke_gcp(materialization_id, plaintext).await,
            ResolvedBrokerAuthority::Okta(app) => {
                self.revoke_okta(app, materialization_id, plaintext).await
            }
            ResolvedBrokerAuthority::FlyIo(parent) => {
                self.revoke_fly(parent, materialization_id).await
            }
            ResolvedBrokerAuthority::HashiVault(parent) => {
                self.revoke_hashivault(parent, materialization_id, plaintext)
                    .await
            }
            ResolvedBrokerAuthority::Vercel(parent) => {
                self.revoke_vercel(parent, materialization_id).await
            }
            ResolvedBrokerAuthority::GithubApp(_)
            | ResolvedBrokerAuthority::GithubPat(_)
            | ResolvedBrokerAuthority::AwsSts(_)
            | ResolvedBrokerAuthority::AzureCli(_) => Ok(()),
        }
    }

    async fn revoke_gcp(
        &self,
        materialization_id: &str,
        plaintext: Option<SecretString>,
    ) -> Result<(), BrokerError> {
        let token = required_plaintext(materialization_id, plaintext)?;
        let body = format!("token={}", form_encode(token.expose_secret()));
        let resp = self
            .http
            .post("https://oauth2.googleapis.com/revoke")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(materialization_id = %materialization_id, "GcpBroker: revoke succeeded");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = %status,
                    body = %body,
                    "GcpBroker: upstream revoke returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %err,
                    "GcpBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        Ok(())
    }

    async fn revoke_okta(
        &self,
        app: OktaServiceApp,
        materialization_id: &str,
        plaintext: Option<SecretString>,
    ) -> Result<(), BrokerError> {
        let token = required_plaintext(materialization_id, plaintext)?;
        let org = app.org_url.trim_end_matches('/');
        let token_url = format!("{org}/oauth2/v1/token");
        let revoke_url = format!("{org}/oauth2/v1/revoke");
        let assertion = ember_broker::okta::build_okta_jwt(
            &app.client_id,
            app.private_key_pem.expose_secret(),
            &app.key_id,
            &token_url,
            Utc::now().timestamp(),
            &Uuid::new_v4().to_string(),
        )
        .map_err(|err| BrokerError::Other(format!("okta revoke client assertion: {err}")))?;
        let body = format!(
            "token={}&token_type_hint=access_token&client_assertion_type={}&client_assertion={}",
            form_encode(token.expose_secret()),
            form_encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            form_encode(&assertion),
        );
        let resp = self
            .http
            .post(&revoke_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(materialization_id = %materialization_id, "OktaBroker: revoke succeeded");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = %status,
                    body = %body,
                    "OktaBroker: upstream revoke returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %err,
                    "OktaBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        Ok(())
    }

    async fn revoke_fly(
        &self,
        parent: FlyParentToken,
        materialization_id: &str,
    ) -> Result<(), BrokerError> {
        let token_id = embedded_token_id("fly-", materialization_id)?;
        let body = json!({
            "query": "mutation RevokeApiToken($input: RevokeApiTokenInput!) { revokeApiToken(input: $input) { clientMutationId } }",
            "variables": { "input": { "id": token_id } }
        });
        let resp = self
            .http
            .post("https://api.fly.io/graphql")
            .bearer_auth(parent.token.expose_secret())
            .json(&body)
            .send()
            .await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                let has_errors = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|parsed| parsed.get("errors").and_then(|v| v.as_array()).cloned())
                    .map(|errors| !errors.is_empty())
                    .unwrap_or(false);
                if has_errors {
                    tracing::warn!(
                        materialization_id = %materialization_id,
                        body = %body,
                        "FlyBroker: revokeApiToken returned errors[] (best-effort; TTL still bounds exposure)"
                    );
                } else {
                    tracing::info!(materialization_id = %materialization_id, "FlyBroker: revoke succeeded");
                }
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = %status,
                    body = %body,
                    "FlyBroker: upstream revoke returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %err,
                    "FlyBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        Ok(())
    }

    async fn revoke_hashivault(
        &self,
        parent: HashiVaultParentToken,
        materialization_id: &str,
        plaintext: Option<SecretString>,
    ) -> Result<(), BrokerError> {
        let bundle: VaultBundle = serde_json::from_str(
            required_plaintext(materialization_id, plaintext)?.expose_secret(),
        )
        .map_err(|err| {
            BrokerError::Other(format!(
                "hashivault materialization bundle parse failed for {materialization_id}: {err}"
            ))
        })?;
        let url = format!(
            "{}/v1/auth/token/revoke-self",
            parent.address.trim_end_matches('/')
        );
        let mut req = self
            .http
            .post(&url)
            .header("X-Vault-Token", bundle.token)
            .body(String::new());
        if let Some(namespace) = parent.namespace.as_deref() {
            req = req.header("X-Vault-Namespace", namespace);
        }
        let resp = req.send().await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(
                    materialization_id = %materialization_id,
                    "HashiVaultBroker: revoke-self succeeded"
                );
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    "HashiVaultBroker: revoke-self returned 404 (token already expired/revoked; treating as success)"
                );
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = %status,
                    body = %body,
                    "HashiVaultBroker: upstream revoke-self returned non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %err,
                    "HashiVaultBroker: upstream revoke-self transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        Ok(())
    }

    async fn revoke_vercel(
        &self,
        parent: VercelParentToken,
        materialization_id: &str,
    ) -> Result<(), BrokerError> {
        let token_id = embedded_token_id("vercel-", materialization_id)?;
        let url = format!("https://api.vercel.com/v3/user/tokens/{token_id}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(parent.token.expose_secret())
            .send()
            .await;
        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(materialization_id = %materialization_id, "VercelBroker: revoke succeeded");
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    "VercelBroker: revoke returned 404 (token already expired/revoked; treating as success)"
                );
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    materialization_id = %materialization_id,
                    status = %status,
                    body = %body,
                    "VercelBroker: upstream revoke non-2xx (best-effort; TTL still bounds exposure)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    materialization_id = %materialization_id,
                    error = %err,
                    "VercelBroker: upstream revoke transport failure (best-effort; TTL still bounds exposure)"
                );
            }
        }
        Ok(())
    }
}

impl DynBroker for ReloadingBroker {
    fn provider(&self) -> BrokerProvider {
        self.provider
    }

    fn issue<'a>(
        &'a self,
        req: BrokerRequest,
    ) -> Pin<Box<dyn Future<Output = Result<BrokeredCredential, BrokerError>> + Send + 'a>> {
        Box::pin(async move {
            if req.provider != self.provider {
                return Err(BrokerError::Other(format!(
                    "reloading broker for {} received request for {}",
                    self.provider.as_str(),
                    req.provider.as_str()
                )));
            }
            let authority = self.resolve_authority().await?;
            self.issue_with_authority(authority, req).await
        })
    }

    fn revoke<'a>(
        &'a self,
        materialization_id: &'a str,
        plaintext: Option<SecretString>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BrokerError>> + Send + 'a>> {
        Box::pin(async move {
            match self.provider {
                BrokerProvider::Github => Ok(()),
                BrokerProvider::AwsSts => {
                    tracing::warn!(
                        materialization_id = %materialization_id,
                        "AwsStsBroker: revoke is best-effort — STS credentials are TTL-bound; the vended token remains valid until expiration"
                    );
                    Ok(())
                }
                BrokerProvider::AzureCli => {
                    tracing::warn!(
                        materialization_id = %materialization_id,
                        "AzureCliBroker: revoke is best-effort — Azure AD has no programmatic OAuth revoke for client-credentials; the vended token remains valid until expiration"
                    );
                    Ok(())
                }
                BrokerProvider::Gcp
                | BrokerProvider::FlyIo
                | BrokerProvider::HashiVault
                | BrokerProvider::Okta
                | BrokerProvider::Vercel => {
                    let authority = self.resolve_authority().await?;
                    self.revoke_upstream(authority, materialization_id, plaintext)
                        .await
                }
                BrokerProvider::Cloudflare
                | BrokerProvider::Anthropic
                | BrokerProvider::Tailscale => Err(BrokerError::NotSupported),
            }
        })
    }
}

fn required_plaintext(
    materialization_id: &str,
    plaintext: Option<SecretString>,
) -> Result<SecretString, BrokerError> {
    plaintext.ok_or_else(|| BrokerError::UnknownMaterialization(materialization_id.to_string()))
}

fn issue_github_pat(
    req: BrokerRequest,
    token: SecretString,
) -> Result<BrokeredCredential, BrokerError> {
    if req.provider != BrokerProvider::Github {
        return Err(BrokerError::InvalidScope(format!(
            "GitHub PAT fallback received request for {}",
            req.provider.as_str()
        )));
    }

    let expires_at = SystemTime::now()
        .checked_add(req.ttl.max(Duration::from_secs(1)))
        .unwrap_or(SystemTime::now() + Duration::from_secs(3600));
    let materialization_id = format!("gh-pat-{}", Uuid::new_v4());

    Ok(BrokeredCredential {
        token,
        expires_at,
        materialization_id,
        // GitHub PAT authority path — echo capture is a follow-up.
        // `Unwired` is the G3 variant for "this adapter has not
        // wired echo capture yet" (ADR 213 §D4 — distinct from anthropic's
        // architectural-G3 `Opaque`). A future BKR-5
        // follow-up that calls `GET /user` to enumerate scopes would
        // upgrade this to `MintStamp::Permissions { bound }`.
        mint_stamp: core_broker::MintStamp::Unwired,
    })
}

fn embedded_token_id(prefix: &str, materialization_id: &str) -> Result<String, BrokerError> {
    let suffix = materialization_id.strip_prefix(prefix).ok_or_else(|| {
        BrokerError::Other(format!(
            "unexpected materialization id: {materialization_id}"
        ))
    })?;
    let (token_id, _) = suffix.rsplit_once('-').ok_or_else(|| {
        BrokerError::Other(format!(
            "missing token identifier in materialization id: {materialization_id}"
        ))
    })?;
    if token_id.trim().is_empty() {
        return Err(BrokerError::Other(format!(
            "empty token identifier in materialization id: {materialization_id}"
        )));
    }
    Ok(token_id.to_string())
}

fn form_encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

#[derive(Deserialize)]
struct VaultBundle {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::attested_device::AttestedDevice;
    use crate::infra::credential_store::LocalEncryptedStore;
    use crate::infra::credential_store::test_helpers::MockCredentialStore;
    use crate::infra::credential_store::{CredentialStore, StoreError};
    use crate::infra::store::DaemonStore;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::time::Duration;

    struct MetadataOnlyStore {
        keys: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl CredentialStore for MetadataOnlyStore {
        async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
            Err(StoreError::Unavailable(format!(
                "plaintext reads must stay off in metadata-only test for {key}"
            )))
        }

        async fn put(&self, _key: &str, _value: &[u8]) -> Result<(), StoreError> {
            Err(StoreError::Other("put unsupported".into()))
        }

        async fn list(&self, _prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
            Err(StoreError::Unavailable(
                "list should not be used in metadata-only test".into(),
            ))
        }

        async fn list_metadata(&self, prefix: Option<&str>) -> Result<Vec<String>, StoreError> {
            let keys = self.keys.lock().expect("metadata keys mutex poisoned");
            let prefix = prefix.unwrap_or("");
            Ok(keys
                .iter()
                .filter(|key| prefix.is_empty() || key.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn aws_resolution_reflects_latest_store_contents() {
        let store = Arc::new(MockCredentialStore::new());
        store
            .put("aws-sts/access-key-id", b"AKIA-FIRST")
            .await
            .unwrap();
        store
            .put("aws-sts/secret-access-key", b"secret-one")
            .await
            .unwrap();
        store.put("aws-sts/region", b"us-east-1").await.unwrap();

        let resolver =
            BrokerAuthorityResolver::new(store.clone(), CredentialPrecedence::VaultFirst);
        let first = resolver
            .resolve(BrokerProvider::AwsSts)
            .await
            .unwrap()
            .expect("aws creds present");

        store
            .put("aws-sts/access-key-id", b"AKIA-SECOND")
            .await
            .unwrap();
        let second = resolver
            .resolve(BrokerProvider::AwsSts)
            .await
            .unwrap()
            .expect("aws creds still present");

        let ResolvedBrokerAuthority::AwsSts((first_creds, _)) = first else {
            panic!("expected aws authority");
        };
        let ResolvedBrokerAuthority::AwsSts((second_creds, _)) = second else {
            panic!("expected aws authority");
        };
        assert_eq!(first_creds.access_key_id, "AKIA-FIRST");
        assert_eq!(second_creds.access_key_id, "AKIA-SECOND");
    }

    #[test]
    fn embedded_token_id_parses_trailing_epoch_shape() {
        assert_eq!(
            embedded_token_id("fly-", "fly-tk_org_123-1735689600").unwrap(),
            "tk_org_123"
        );
        assert_eq!(
            embedded_token_id("vercel-", "vercel-tk_personal-1735689600").unwrap(),
            "tk_personal"
        );
    }

    #[tokio::test]
    async fn startup_metadata_probe_detects_aws_without_plaintext_reads() {
        let store = Arc::new(MetadataOnlyStore {
            keys: Mutex::new(vec![
                "aws-sts/access-key-id".to_string(),
                "aws-sts/secret-access-key".to_string(),
                "aws-sts/region".to_string(),
            ]),
        });
        let resolver = BrokerAuthorityResolver::new(store, CredentialPrecedence::VaultFirst);
        assert!(
            resolver
                .startup_configured(BrokerProvider::AwsSts, StartupProbeMode::MetadataOnly)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn startup_metadata_probe_rejects_partial_github_triple() {
        let store = Arc::new(MetadataOnlyStore {
            keys: Mutex::new(vec![
                "github/apps/ember/install-123/app-id".to_string(),
                "github/apps/ember/install-123/private-key".to_string(),
            ]),
        });
        let resolver = BrokerAuthorityResolver::new(store, CredentialPrecedence::VaultFirst);
        let err = resolver
            .startup_configured(BrokerProvider::Github, StartupProbeMode::MetadataOnly)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("partial credential triple"),
            "expected partial-triple error, got: {err}"
        );
    }

    #[tokio::test]
    async fn startup_metadata_probe_accepts_github_pat_without_app() {
        let store = Arc::new(MetadataOnlyStore {
            keys: Mutex::new(vec![GITHUB_PAT_STORE_KEY.to_string()]),
        });
        let resolver = BrokerAuthorityResolver::new(store, CredentialPrecedence::VaultFirst);
        assert!(
            resolver
                .startup_configured(BrokerProvider::Github, StartupProbeMode::MetadataOnly)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn github_resolution_falls_back_to_pat_when_app_absent() {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _guard = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("env lock");

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let missing_env = tmp.path().join("missing.env");
        let missing_pem = tmp.path().join("missing.pem");
        let prev_env = std::env::var("EMBER_APP_ENV_PATH").ok();
        let prev_pem = std::env::var("EMBER_APP_PEM_PATH").ok();
        unsafe {
            std::env::set_var("EMBER_APP_ENV_PATH", &missing_env);
            std::env::set_var("EMBER_APP_PEM_PATH", &missing_pem);
        }

        let store = Arc::new(MockCredentialStore::new());
        store
            .put(GITHUB_PAT_STORE_KEY, b"ghp_test_pat_value")
            .await
            .unwrap();
        let resolver = BrokerAuthorityResolver::new(store, CredentialPrecedence::VaultFirst);

        let authority = resolver
            .resolve(BrokerProvider::Github)
            .await
            .unwrap()
            .expect("PAT fallback authority present");
        let source = resolver
            .github_authority_source()
            .await
            .unwrap()
            .expect("PAT source present");

        let ResolvedBrokerAuthority::GithubPat(token) = authority else {
            panic!("expected PAT-backed github authority");
        };
        unsafe {
            match prev_env {
                Some(v) => std::env::set_var("EMBER_APP_ENV_PATH", v),
                None => std::env::remove_var("EMBER_APP_ENV_PATH"),
            }
            match prev_pem {
                Some(v) => std::env::set_var("EMBER_APP_PEM_PATH", v),
                None => std::env::remove_var("EMBER_APP_PEM_PATH"),
            }
        }
        assert_eq!(token.expose_secret(), "ghp_test_pat_value");
        assert_eq!(source, GithubAuthoritySource::Pat);
    }

    #[tokio::test]
    async fn startup_metadata_probe_accepts_azure_oidc_variant() {
        let store = Arc::new(MetadataOnlyStore {
            keys: Mutex::new(vec![
                "azure/tenant-id".to_string(),
                "azure/client-id".to_string(),
                "azure/oidc-token-path".to_string(),
            ]),
        });
        let resolver = BrokerAuthorityResolver::new(store, CredentialPrecedence::VaultFirst);
        assert!(
            resolver
                .startup_configured(BrokerProvider::AzureCli, StartupProbeMode::MetadataOnly)
                .await
                .unwrap()
        );
    }

    #[test]
    fn local_store_authority_keys_collects_required_and_optional_variants() {
        let mut keys = local_store_authority_keys_from_metadata(&[
            "aws-sts/access-key-id".to_string(),
            "aws-sts/secret-access-key".to_string(),
            "aws-sts/region".to_string(),
            "aws-sts/default-role-arn".to_string(),
            "azure/tenant-id".to_string(),
            "azure/client-id".to_string(),
            "azure/oidc-token-path".to_string(),
            "github/apps/ember/install-123/private-key".to_string(),
            "github/apps/ember/install-123/app-id".to_string(),
            "github/apps/ember/install-123/installation-id".to_string(),
        ])
        .unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "aws-sts/access-key-id".to_string(),
                "aws-sts/default-role-arn".to_string(),
                "aws-sts/region".to_string(),
                "aws-sts/secret-access-key".to_string(),
                "azure/client-id".to_string(),
                "azure/oidc-token-path".to_string(),
                "azure/tenant-id".to_string(),
                "github/apps/ember/install-123/app-id".to_string(),
                "github/apps/ember/install-123/installation-id".to_string(),
                "github/apps/ember/install-123/private-key".to_string(),
            ]
        );
    }

    #[test]
    fn local_store_authority_keys_rejects_partial_github_triple() {
        let err = local_store_authority_keys_from_metadata(&[
            "github/apps/ember/install-123/private-key".to_string(),
            "github/apps/ember/install-123/app-id".to_string(),
        ])
        .unwrap_err();
        assert!(
            err.to_string().contains("partial credential triple"),
            "expected partial-triple error, got: {err}"
        );
    }

    #[test]
    fn local_store_authority_keys_for_refs_narrows_to_requested_provider_family() {
        let mut keys = local_store_authority_keys_for_refs(
            &[
                "aws-sts/access-key-id".to_string(),
                "aws-sts/secret-access-key".to_string(),
                "aws-sts/region".to_string(),
                "github/apps/ember/install-123/private-key".to_string(),
                "github/apps/ember/install-123/app-id".to_string(),
                "github/apps/ember/install-123/installation-id".to_string(),
            ],
            &["github".to_string()],
        )
        .unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "github/apps/ember/install-123/app-id".to_string(),
                "github/apps/ember/install-123/installation-id".to_string(),
                "github/apps/ember/install-123/private-key".to_string(),
            ]
        );
    }

    #[test]
    fn local_store_authority_keys_for_refs_includes_github_pat() {
        let keys = local_store_authority_keys_for_refs(
            &[GITHUB_PAT_STORE_KEY.to_string()],
            &["github".to_string()],
        )
        .unwrap();
        assert_eq!(keys, vec![GITHUB_PAT_STORE_KEY.to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aws_resolution_reads_from_headless_runtime_store_when_interactive_locked() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let persona = "test-broker-authority-headless-aws";
        let store = Rc::new(
            DaemonStore::open_in_memory_without_vault()
                .expect("open in-memory store without vault"),
        );
        let device = AttestedDevice::enroll_active(
            tmp.path(),
            persona,
            Duration::from_secs(3600),
            &[0x91u8; 32],
        )
        .expect("enroll active succeeds");
        let headless =
            LocalEncryptedStore::with_headless_attested_enrollment(Rc::clone(&store), tmp.path());
        headless
            .put("aws-sts/access-key-id", b"AKIA-HEADLESS")
            .await
            .unwrap();
        headless
            .put("aws-sts/secret-access-key", b"secret-headless")
            .await
            .unwrap();
        headless.put("aws-sts/region", b"us-west-2").await.unwrap();

        let runtime_store: Arc<dyn CredentialStore> = Arc::new(
            LocalEncryptedStore::with_runtime_authority(Rc::clone(&store), tmp.path()),
        );
        let resolver =
            BrokerAuthorityResolver::new(runtime_store, CredentialPrecedence::VaultFirst);
        let authority = resolver
            .resolve(BrokerProvider::AwsSts)
            .await
            .unwrap()
            .expect("headless runtime authority should resolve");

        let ResolvedBrokerAuthority::AwsSts((creds, default_role_arn)) = authority else {
            panic!("expected aws authority");
        };
        assert_eq!(creds.access_key_id, "AKIA-HEADLESS");
        assert_eq!(creds.secret_access_key.expose_secret(), "secret-headless");
        assert_eq!(creds.region, "us-west-2");
        assert_eq!(default_role_arn, None);
        assert!(
            store.vault().is_none(),
            "headless runtime authority must not repopulate the shared interactive live-vault slot"
        );

        AttestedDevice::revoke_active(tmp.path(), Some(&device.enrollment_id))
            .expect("revoke active succeeds");
    }
}
