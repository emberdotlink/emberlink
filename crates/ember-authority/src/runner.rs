use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    artifact::VerifiedArtifact,
    git::{GitRunner, GitRunnerError},
    model::{
        ActionFacts, ArtifactRef, GitOid, GitRef, GitRefPublicationInput, GithubCheckFact,
        GithubForkHeadFact, GithubPullRequestCreateInput, GithubPullRequestFact,
        GithubRepositoryFactsInput, Need, ProcessOutcome, RepositoryResource, RunnerEvidence,
    },
    pack::{
        DeliveryLane, GITHUB_PULL_REQUEST_CREATE_ACTION, GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
    },
    provider::{
        BlockingHttp, HttpMethod, HttpRequest, HttpResponse, MAX_HTTP_RESPONSE_BYTES,
        MintedCredential,
    },
};

const GITHUB_API_BASE: &str = "https://api.github.com";
const MAX_ARRAY_ITEMS: usize = 10_000;
const MAX_STRING_BYTES: usize = 4_096;
const MAX_PATH_BYTES: usize = 1_024;
const PAGE_SIZE: usize = 100;

struct FactBudget {
    serialized_bytes: usize,
    nested_items: usize,
}

impl FactBudget {
    fn new(repository: &RepositoryResource, repository_head: &GitOid) -> Result<Self, RunnerError> {
        let empty = ActionFacts::GithubRepositoryFacts {
            repository: repository.clone(),
            repository_head: repository_head.clone(),
            fork_heads: Vec::new(),
            prs: Vec::new(),
        };
        let serialized_bytes = serde_json::to_vec(&empty)
            .map_err(|_| RunnerError::execution("facts cannot be bounded"))?
            .len();
        Ok(Self {
            serialized_bytes,
            nested_items: 0,
        })
    }

    fn charge_outer(
        &mut self,
        value: &impl Serialize,
        has_preceding_item: bool,
    ) -> Result<(), RunnerError> {
        self.charge(value, has_preceding_item, false)
    }

    fn charge_nested(
        &mut self,
        value: &impl Serialize,
        has_preceding_item: bool,
    ) -> Result<(), RunnerError> {
        self.charge(value, has_preceding_item, true)
    }

    fn charge(
        &mut self,
        value: &impl Serialize,
        has_preceding_item: bool,
        nested: bool,
    ) -> Result<(), RunnerError> {
        if nested && self.nested_items == MAX_ARRAY_ITEMS {
            return Err(RunnerError::execution(
                "aggregate nested fact items exceed the hard bound",
            ));
        }
        let value_bytes = serde_json::to_vec(value)
            .map_err(|_| RunnerError::execution("facts cannot be bounded"))?
            .len();
        let charged_bytes = value_bytes
            .checked_add(if has_preceding_item { 1 } else { 0 })
            .and_then(|bytes| self.serialized_bytes.checked_add(bytes))
            .ok_or_else(|| RunnerError::execution("signed fact block size overflowed"))?;
        if charged_bytes > MAX_HTTP_RESPONSE_BYTES {
            return Err(RunnerError::execution(
                "signed fact block exceeds the hard byte limit",
            ));
        }
        self.serialized_bytes = charged_bytes;
        if nested {
            self.nested_items += 1;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerFailureKind {
    Refusal,
    ExecutionFailure,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct RunnerError {
    kind: RunnerFailureKind,
    message: String,
}

impl RunnerError {
    pub fn refusal(message: impl Into<String>) -> Self {
        Self {
            kind: RunnerFailureKind::Refusal,
            message: message.into(),
        }
    }

    pub fn execution(message: impl Into<String>) -> Self {
        Self {
            kind: RunnerFailureKind::ExecutionFailure,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> RunnerFailureKind {
        self.kind
    }
}

pub struct RunnerOutput {
    pub evidence: RunnerEvidence,
    pub facts: Option<ActionFacts>,
    pub succeeded: bool,
    pub message: String,
    pub audit_data: Value,
}

/// One daemon-selected adapter. Implementations parse typed action input,
/// verify that it matches the pack-derived need, and consume a credential only
/// through this in-process seam.
pub trait ActionRunner: Send + Sync {
    fn adapter(&self) -> &'static str;

    fn validate(
        &self,
        action: &str,
        input: &Value,
        need: &Need,
        artifact_required: bool,
        lane: &DeliveryLane,
        mint_adapter: &str,
    ) -> Result<Option<ArtifactRef>, RunnerError>;

    fn run(
        &self,
        action: &str,
        input: &Value,
        artifact: Option<VerifiedArtifact>,
        credential: &MintedCredential,
    ) -> Result<RunnerOutput, RunnerError>;
}

pub(crate) struct RunnerValidation<'a> {
    pub action: &'a str,
    pub input: &'a Value,
    pub need: &'a Need,
    pub artifact_required: bool,
    pub lane: &'a DeliveryLane,
    pub mint_adapter: &'a str,
}

#[derive(Default)]
pub struct RunnerRegistry {
    adapters: BTreeMap<String, Arc<dyn ActionRunner>>,
}

impl RunnerRegistry {
    pub fn register(&mut self, runner: Arc<dyn ActionRunner>) -> Result<(), RunnerError> {
        let adapter = runner.adapter().to_owned();
        if adapter.is_empty() || self.adapters.insert(adapter, runner).is_some() {
            return Err(RunnerError::refusal(
                "runner adapter is invalid or duplicated",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate(
        &self,
        adapter: &str,
        validation: RunnerValidation<'_>,
    ) -> Result<Option<ArtifactRef>, RunnerError> {
        self.adapters
            .get(adapter)
            .ok_or_else(|| RunnerError::refusal("resolved action has no installed runner adapter"))?
            .validate(
                validation.action,
                validation.input,
                validation.need,
                validation.artifact_required,
                validation.lane,
                validation.mint_adapter,
            )
    }

    pub fn run(
        &self,
        adapter: &str,
        action: &str,
        input: &Value,
        artifact: Option<VerifiedArtifact>,
        credential: &MintedCredential,
    ) -> Result<RunnerOutput, RunnerError> {
        self.adapters
            .get(adapter)
            .ok_or_else(|| RunnerError::refusal("resolved action has no installed runner adapter"))?
            .run(action, input, artifact, credential)
    }
}

impl ActionRunner for GitRunner {
    fn adapter(&self) -> &'static str {
        "git.publish-ref/v1"
    }

    fn validate(
        &self,
        action: &str,
        input: &Value,
        need: &Need,
        artifact_required: bool,
        lane: &DeliveryLane,
        mint_adapter: &str,
    ) -> Result<Option<ArtifactRef>, RunnerError> {
        if action != crate::pack::GITHUB_PUBLISH_REF_ACTION
            || !artifact_required
            || lane != &DeliveryLane::SealedExec
            || mint_adapter != "github.app-installation/v1"
        {
            return Err(RunnerError::refusal(
                "sealed Git runner action metadata is invalid",
            ));
        }
        let input: GitRefPublicationInput =
            serde_json::from_value(input.clone()).map_err(|error| {
                RunnerError::refusal(format!("typed action input refused: {error}"))
            })?;
        if input.repository != need.repository
            || need.destination_ref.as_ref() != Some(&input.destination_ref)
        {
            return Err(RunnerError::refusal(
                "typed runner input does not match the pack-derived need",
            ));
        }
        Ok(Some(input.artifact))
    }

    fn run(
        &self,
        action: &str,
        input: &Value,
        artifact: Option<VerifiedArtifact>,
        credential: &MintedCredential,
    ) -> Result<RunnerOutput, RunnerError> {
        if action != crate::pack::GITHUB_PUBLISH_REF_ACTION {
            return Err(RunnerError::refusal("sealed Git runner action is invalid"));
        }
        let input: GitRefPublicationInput =
            serde_json::from_value(input.clone()).map_err(|error| {
                RunnerError::refusal(format!("typed action input refused: {error}"))
            })?;
        let artifact = artifact
            .ok_or_else(|| RunnerError::refusal("sealed Git publication requires an artifact"))?;
        let run = self
            .publish(&input, artifact, credential)
            .map_err(|error| RunnerError::execution(format_git_error(error)))?;
        let succeeded = run.process.exit_code == Some(0);
        let message = if succeeded {
            "Git publication succeeded".to_owned()
        } else {
            format!("Git publication exited {:?}", run.process.exit_code)
        };
        Ok(RunnerOutput {
            evidence: RunnerEvidence {
                adapter: self.adapter().to_owned(),
                executable_digest_sha256: Some(run.executable_digest_sha256.clone()),
                credential_helper_digest_sha256: Some(run.credential_helper_digest_sha256.clone()),
                artifact_digest_sha256: Some(run.artifact_digest_sha256.clone()),
                credential_peer_served_count: Some(run.credential_peer_served_count),
                credential_peer_rejected_count: Some(run.credential_peer_rejected_count),
                process: Some(run.process.clone()),
            },
            facts: None,
            succeeded,
            message,
            audit_data: json!({
                "executable_digest_sha256": run.executable_digest_sha256,
                "credential_helper_digest_sha256": run.credential_helper_digest_sha256,
                "artifact_digest_sha256": run.artifact_digest_sha256,
                "credential_peer_served_count": run.credential_peer_served_count,
                "credential_peer_rejected_count": run.credential_peer_rejected_count,
                "process": run.process,
            }),
        })
    }
}

fn format_git_error(error: GitRunnerError) -> String {
    format!("sealed Git runner failed: {error}")
}

pub struct GithubApiRunner {
    http: Arc<dyn BlockingHttp>,
    api_base: String,
}

struct PullRequestCoordinates<'a> {
    owner: &'a str,
    repository: &'a str,
    head_name: &'a str,
    base_name: &'a str,
}

impl<'a> PullRequestCoordinates<'a> {
    fn from_input(input: &'a GithubPullRequestCreateInput) -> Result<Self, RunnerError> {
        let (owner, repository) = repository_parts(&input.repository)?;
        Ok(Self {
            owner,
            repository,
            head_name: branch_name(&input.head_ref)?,
            base_name: branch_name(&input.base_ref)?,
        })
    }
}

impl GithubApiRunner {
    pub fn new(http: Arc<dyn BlockingHttp>) -> Self {
        Self {
            http,
            api_base: GITHUB_API_BASE.to_owned(),
        }
    }

    #[cfg(test)]
    fn with_api_base(http: Arc<dyn BlockingHttp>, api_base: impl Into<String>) -> Self {
        Self {
            http,
            api_base: api_base.into(),
        }
    }

    fn request(
        &self,
        method: HttpMethod,
        url: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<HttpResponse, RunnerError> {
        let response = self
            .http
            .execute(HttpRequest {
                method,
                url,
                bearer_token: token,
                body,
            })
            .map_err(|error| {
                RunnerError::execution(format!("GitHub API transport failed: {error}"))
            })?;
        let actual_bytes = serde_json::to_vec(&response.body)
            .map_err(|_| RunnerError::execution("GitHub API response cannot be bounded"))?
            .len();
        if response.body_bytes > MAX_HTTP_RESPONSE_BYTES || actual_bytes > MAX_HTTP_RESPONSE_BYTES {
            return Err(RunnerError::execution(
                "GitHub API response exceeds the hard byte limit",
            ));
        }
        Ok(response)
    }

    fn create_pull_request(
        &self,
        input: &GithubPullRequestCreateInput,
        credential: &MintedCredential,
    ) -> Result<ActionFacts, RunnerError> {
        let coordinates = PullRequestCoordinates::from_input(input)?;
        let body = json!({
            "title": input.title,
            "head": coordinates.head_name,
            "base": coordinates.base_name,
            "body": input.body,
        });
        let url = format!(
            "{}/repos/{}/{}/pulls",
            self.api_base, coordinates.owner, coordinates.repository
        );
        let response = self.request(HttpMethod::Post, &url, credential.token(), Some(&body))?;
        match response.status {
            201 => {
                let object = as_object(&response.body, "pull-request creation response")?;
                pull_request_created_facts(input, object)
            }
            422 => {
                let create_failure = github_failure_summary(&response.body, credential.token());
                self.existing_open_pull_request(
                    input,
                    &coordinates,
                    create_failure.as_deref(),
                    credential,
                )
            }
            status => Err(http_status("pull-request creation", status)),
        }
    }

    fn existing_open_pull_request(
        &self,
        input: &GithubPullRequestCreateInput,
        coordinates: &PullRequestCoordinates<'_>,
        create_failure: Option<&str>,
        credential: &MintedCredential,
    ) -> Result<ActionFacts, RunnerError> {
        let mut exact_match = None;
        let mut total_seen = 0_usize;
        let mut page = 1_usize;
        loop {
            let url = format!(
                "{}/repos/{}/{}/pulls?state=open&head={}:{}&base={}&per_page={PAGE_SIZE}&page={page}",
                self.api_base,
                coordinates.owner,
                coordinates.repository,
                coordinates.owner,
                coordinates.head_name,
                coordinates.base_name,
            );
            let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
            if response.status != 200 {
                return Err(http_status(
                    "existing pull-request listing",
                    response.status,
                ));
            }
            let entries = as_array(&response.body, "existing pull-request page")?;
            if entries.len() > PAGE_SIZE
                || total_seen
                    .checked_add(entries.len())
                    .is_none_or(|count| count > MAX_ARRAY_ITEMS)
            {
                return Err(RunnerError::execution(
                    "existing pull-request listing exceeds the hard bound",
                ));
            }
            total_seen += entries.len();
            for entry in entries {
                let object = as_object(entry, "existing pull-request entry")?;
                let body_matches = match field(object, "body")? {
                    Value::Null => input.body.is_empty(),
                    value => {
                        bounded_string(value, MAX_STRING_BYTES, "existing pull-request body")?
                            == input.body
                    }
                };
                if bounded_string(
                    field(object, "state")?,
                    MAX_STRING_BYTES,
                    "existing pull-request state",
                )? != "open"
                    || bounded_string(
                        field(object, "title")?,
                        MAX_STRING_BYTES,
                        "existing pull-request title",
                    )? != input.title
                    || !body_matches
                {
                    return Err(RunnerError::execution(
                        "existing pull-request candidate disagrees with the request",
                    ));
                }
                let facts = pull_request_created_facts(input, object)?;
                if exact_match.replace(facts).is_some() {
                    return Err(RunnerError::execution(
                        "existing pull-request identity is ambiguous",
                    ));
                }
            }
            if entries.len() < PAGE_SIZE {
                break;
            }
            page = next_page(page)?;
        }
        exact_match.ok_or_else(|| {
            let suffix = create_failure
                .map(|failure| format!(": {failure}"))
                .unwrap_or_default();
            RunnerError::execution(format!(
                "no exact open pull request exists for the request{suffix}"
            ))
        })
    }
}

fn pull_request_created_facts(
    input: &GithubPullRequestCreateInput,
    object: &Map<String, Value>,
) -> Result<ActionFacts, RunnerError> {
    let (owner, repository) = repository_parts(&input.repository)?;
    let number = positive_u64(field(object, "number")?, "pull-request number")?;
    let identity = pull_request_identity(object)?;
    require_canonical_identity(
        &identity,
        &input.repository,
        &input.head_ref,
        &input.base_ref,
    )?;
    let html_url = bounded_string(
        field(object, "html_url")?,
        MAX_STRING_BYTES,
        "pull-request URL",
    )?;
    if html_url != format!("https://github.com/{owner}/{repository}/pull/{number}") {
        return Err(RunnerError::execution(
            "GitHub pull-request URL disagrees with the request",
        ));
    }
    Ok(ActionFacts::GithubPullRequestCreated {
        repository: input.repository.clone(),
        number,
        html_url,
        head_ref: input.head_ref.clone(),
        base_ref: input.base_ref.clone(),
    })
}

impl ActionRunner for GithubApiRunner {
    fn adapter(&self) -> &'static str {
        "github.api/v1"
    }

    fn validate(
        &self,
        action: &str,
        input: &Value,
        need: &Need,
        artifact_required: bool,
        lane: &DeliveryLane,
        mint_adapter: &str,
    ) -> Result<Option<ArtifactRef>, RunnerError> {
        if artifact_required
            || lane != &DeliveryLane::Proxy
            || mint_adapter != "github.app-installation/v1"
        {
            return Err(RunnerError::refusal(
                "GitHub API action delivery metadata is invalid",
            ));
        }
        match action {
            GITHUB_PULL_REQUEST_CREATE_ACTION => {
                let input: GithubPullRequestCreateInput = typed(input)?;
                if input.repository != need.repository
                    || need.destination_ref.as_ref() != Some(&input.head_ref)
                {
                    return Err(RunnerError::refusal(
                        "typed runner input does not match the pack-derived need",
                    ));
                }
                branch_name(&input.head_ref)?;
                branch_name(&input.base_ref)?;
            }
            GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION => {
                let input: GithubRepositoryFactsInput = typed(input)?;
                if input.repository != need.repository || need.destination_ref.is_some() {
                    return Err(RunnerError::refusal(
                        "typed runner input does not match the pack-derived need",
                    ));
                }
                branch_name(&input.head_ref)?;
                branch_name(&input.base_ref)?;
            }
            _ => return Err(RunnerError::refusal("GitHub API runner action is invalid")),
        }
        Ok(None)
    }

    fn run(
        &self,
        action: &str,
        input: &Value,
        artifact: Option<VerifiedArtifact>,
        credential: &MintedCredential,
    ) -> Result<RunnerOutput, RunnerError> {
        if artifact.is_some() {
            return Err(RunnerError::refusal(
                "GitHub API action received an unexpected artifact",
            ));
        }
        let facts = match action {
            GITHUB_PULL_REQUEST_CREATE_ACTION => {
                self.create_pull_request(&typed(input)?, credential)?
            }
            GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION => {
                self.reconcile(&typed(input)?, credential)?
            }
            _ => return Err(RunnerError::refusal("GitHub API runner action is invalid")),
        };
        let fact_digest =
            hex::encode(Sha256::digest(serde_jcs::to_vec(&facts).map_err(|_| {
                RunnerError::execution("facts cannot be canonicalized")
            })?));
        let process = ProcessOutcome {
            exit_code: Some(0),
            signal: None,
            stdout_digest: Some(fact_digest),
            stderr_digest: None,
        };
        Ok(RunnerOutput {
            evidence: RunnerEvidence {
                adapter: self.adapter().to_owned(),
                executable_digest_sha256: None,
                credential_helper_digest_sha256: None,
                artifact_digest_sha256: None,
                credential_peer_served_count: None,
                credential_peer_rejected_count: None,
                process: Some(process.clone()),
            },
            facts: Some(facts.clone()),
            succeeded: true,
            message: "GitHub API action succeeded".to_owned(),
            audit_data: json!({"process": process, "facts": facts}),
        })
    }
}

impl GithubApiRunner {
    fn reconcile(
        &self,
        input: &GithubRepositoryFactsInput,
        credential: &MintedCredential,
    ) -> Result<ActionFacts, RunnerError> {
        let (owner, repository) = repository_parts(&input.repository)?;
        let head_name = branch_name(&input.head_ref)?;
        let base_name = branch_name(&input.base_ref)?;
        let url = format!(
            "{}/repos/{owner}/{repository}/git/ref/heads/{head_name}",
            self.api_base
        );
        let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
        if response.status != 200 {
            return Err(http_status("reference lookup", response.status));
        }
        let reference = as_object(&response.body, "reference response")?;
        if bounded_string(field(reference, "ref")?, MAX_STRING_BYTES, "reference")?
            != input.head_ref.as_str()
        {
            return Err(RunnerError::execution(
                "GitHub reference identity disagrees with the request",
            ));
        }
        let repository_head = parse_oid(
            field(
                as_object(field(reference, "object")?, "reference object")?,
                "sha",
            )?,
            "repository head",
        )?;
        let mut fact_budget = FactBudget::new(&input.repository, &repository_head)?;

        let mut candidates = Vec::new();
        let mut page = 1_usize;
        let mut total_pull_entries = 0_usize;
        loop {
            let url = format!(
                "{}/repos/{owner}/{repository}/pulls?state=all&base={base_name}&per_page={PAGE_SIZE}&page={page}",
                self.api_base
            );
            let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
            if response.status != 200 {
                return Err(http_status("pull-request listing", response.status));
            }
            let entries = as_array(&response.body, "pull-request page")?;
            if entries.len() > PAGE_SIZE
                || total_pull_entries
                    .checked_add(entries.len())
                    .is_none_or(|count| count > MAX_ARRAY_ITEMS)
            {
                return Err(RunnerError::execution(
                    "pull-request listing exceeds the total scanned-entry bound",
                ));
            }
            total_pull_entries += entries.len();
            for entry in entries {
                let object = as_object(entry, "pull-request list entry")?;
                let number = positive_u64(field(object, "number")?, "pull-request number")?;
                let head = as_object(field(object, "head")?, "pull-request list head")?;
                if bounded_string(
                    field(head, "ref")?,
                    MAX_STRING_BYTES,
                    "pull-request head ref",
                )? != head_name
                {
                    continue;
                }
                if candidates.len() == MAX_ARRAY_ITEMS || candidates.contains(&number) {
                    return Err(RunnerError::execution(
                        "pull-request candidates are oversized or duplicated",
                    ));
                }
                candidates.push(number);
            }
            if entries.len() < PAGE_SIZE {
                break;
            }
            page = next_page(page)?;
        }

        let mut fork_heads = Vec::new();
        let mut prs = Vec::new();
        let mut identities = BTreeSet::new();
        for number in candidates {
            let url = format!(
                "{}/repos/{owner}/{repository}/pulls/{number}",
                self.api_base
            );
            let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
            if response.status != 200 {
                return Err(http_status("pull-request detail", response.status));
            }
            let object = as_object(&response.body, "pull-request detail")?;
            if positive_u64(field(object, "number")?, "pull-request number")? != number {
                return Err(RunnerError::execution(
                    "pull-request number changed across requests",
                ));
            }
            let identity = pull_request_identity(object)?;
            if identity.head_ref != input.head_ref
                || identity.base_ref != input.base_ref
                || identity.base_repository != input.repository
                || !identities.insert((
                    number,
                    identity.head_repository.clone(),
                    identity.head_sha.clone(),
                ))
            {
                return Err(RunnerError::execution(
                    "pull-request identity conflicts or disagrees with the request",
                ));
            }
            if identity.head_repository != input.repository {
                if fork_heads.len() == MAX_ARRAY_ITEMS {
                    return Err(RunnerError::execution(
                        "fork-head list exceeds the hard bound",
                    ));
                }
                let fork_head = GithubForkHeadFact {
                    number,
                    repository: identity.head_repository,
                    base_ref: identity.base_ref,
                    head_ref: identity.head_ref,
                    head_sha: identity.head_sha,
                };
                fact_budget.charge_outer(&fork_head, !fork_heads.is_empty())?;
                fork_heads.push(fork_head);
                continue;
            }
            if identity.head_sha != repository_head {
                return Err(RunnerError::execution(
                    "pull-request head disagrees with the reconciled reference",
                ));
            }
            let state_value = bounded_string(
                field(object, "state")?,
                MAX_STRING_BYTES,
                "pull-request state",
            )?;
            let state = if !field(object, "merged_at")?.is_null() {
                "merged".to_owned()
            } else if matches!(state_value.as_str(), "open" | "closed") {
                state_value
            } else {
                return Err(RunnerError::execution("pull-request state is invalid"));
            };
            let merge_sha = optional_oid(field(object, "merge_commit_sha")?, "merge SHA")?;
            let changed_files_count = usize::try_from(nonnegative_u64(
                field(object, "changed_files")?,
                "changed-file count",
            )?)
            .map_err(|_| RunnerError::execution("changed-file count is invalid"))?;
            if changed_files_count > MAX_ARRAY_ITEMS {
                return Err(RunnerError::execution(
                    "changed-file count exceeds the hard bound",
                ));
            }
            if prs.len() == MAX_ARRAY_ITEMS {
                return Err(RunnerError::execution(
                    "canonical pull-request list exceeds the hard bound",
                ));
            }
            let mut pull_request = GithubPullRequestFact {
                number,
                state,
                merge_sha,
                base_ref: identity.base_ref,
                head_ref: identity.head_ref,
                head_sha: identity.head_sha,
                changed_files_count: changed_files_count as u64,
                changed_files: Vec::new(),
                checks: Vec::new(),
            };
            fact_budget.charge_outer(&pull_request, !prs.is_empty())?;
            pull_request.changed_files =
                self.pull_files(owner, repository, number, credential, &mut fact_budget)?;
            if pull_request.changed_files.len() != changed_files_count {
                return Err(RunnerError::execution(
                    "fully drained changed-file count disagrees with GitHub",
                ));
            }
            pull_request.checks = self.check_runs(
                owner,
                repository,
                &pull_request.head_sha,
                credential,
                &mut fact_budget,
            )?;
            prs.push(pull_request);
        }

        let facts = ActionFacts::GithubRepositoryFacts {
            repository: input.repository.clone(),
            repository_head,
            fork_heads,
            prs,
        };
        let fact_bytes = serde_json::to_vec(&facts)
            .map_err(|_| RunnerError::execution("facts cannot be bounded"))?
            .len();
        if fact_bytes != fact_budget.serialized_bytes || fact_bytes > MAX_HTTP_RESPONSE_BYTES {
            return Err(RunnerError::execution(
                "signed fact block accounting disagrees with the canonical facts",
            ));
        }
        Ok(facts)
    }

    fn pull_files(
        &self,
        owner: &str,
        repository: &str,
        number: u64,
        credential: &MintedCredential,
        fact_budget: &mut FactBudget,
    ) -> Result<Vec<String>, RunnerError> {
        let mut paths = Vec::new();
        let mut seen = BTreeSet::new();
        let mut page = 1_usize;
        loop {
            let url = format!(
                "{}/repos/{owner}/{repository}/pulls/{number}/files?per_page={PAGE_SIZE}&page={page}",
                self.api_base
            );
            let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
            if response.status != 200 {
                return Err(http_status("changed-file listing", response.status));
            }
            let entries = as_array(&response.body, "changed-file page")?;
            if entries.len() > PAGE_SIZE {
                return Err(RunnerError::execution(
                    "changed-file page exceeds the requested bound",
                ));
            }
            for entry in entries {
                if paths.len() == MAX_ARRAY_ITEMS {
                    return Err(RunnerError::execution(
                        "changed-file list exceeds the hard bound",
                    ));
                }
                let path = bounded_string(
                    field(as_object(entry, "changed-file entry")?, "filename")?,
                    MAX_PATH_BYTES,
                    "changed-file path",
                )?;
                if path.is_empty() || !seen.insert(path.clone()) {
                    return Err(RunnerError::execution(
                        "changed-file path is empty or duplicated",
                    ));
                }
                fact_budget.charge_nested(&path, !paths.is_empty())?;
                paths.push(path);
            }
            if entries.len() < PAGE_SIZE {
                break;
            }
            page = next_page(page)?;
        }
        Ok(paths)
    }
}

impl GithubApiRunner {
    fn check_runs(
        &self,
        owner: &str,
        repository: &str,
        expected_head: &GitOid,
        credential: &MintedCredential,
        fact_budget: &mut FactBudget,
    ) -> Result<Vec<GithubCheckFact>, RunnerError> {
        let mut checks = Vec::new();
        let mut identities = BTreeSet::new();
        let mut total_seen = None;
        let mut page = 1_usize;
        loop {
            let url = format!(
                "{}/repos/{owner}/{repository}/commits/{expected_head}/check-runs?per_page={PAGE_SIZE}&page={page}",
                self.api_base
            );
            let response = self.request(HttpMethod::Get, &url, credential.token(), None)?;
            if response.status != 200 {
                return Err(http_status("check-run listing", response.status));
            }
            let object = as_object(&response.body, "check-run response")?;
            let total = usize::try_from(nonnegative_u64(
                field(object, "total_count")?,
                "check-run count",
            )?)
            .map_err(|_| RunnerError::execution("check-run count is invalid"))?;
            if total > MAX_ARRAY_ITEMS
                || total_seen
                    .replace(total)
                    .is_some_and(|prior| prior != total)
            {
                return Err(RunnerError::execution(
                    "check-run count is oversized or unstable",
                ));
            }
            let entries = as_array(field(object, "check_runs")?, "check-run page")?;
            if entries.len() > PAGE_SIZE
                || checks
                    .len()
                    .checked_add(entries.len())
                    .is_none_or(|count| count > MAX_ARRAY_ITEMS)
            {
                return Err(RunnerError::execution(
                    "check-run page exceeds the hard bound",
                ));
            }
            for entry in entries {
                let object = as_object(entry, "check-run entry")?;
                let database_id = positive_u64(field(object, "id")?, "check-run database ID")?;
                let name =
                    bounded_string(field(object, "name")?, MAX_STRING_BYTES, "check-run name")?;
                let head_sha = parse_oid(field(object, "head_sha")?, "check-run head SHA")?;
                if &head_sha != expected_head
                    || !identities.insert((database_id, name.clone(), head_sha.clone()))
                {
                    return Err(RunnerError::execution(
                        "check identity duplicates or disagrees with the PR head",
                    ));
                }
                let check = GithubCheckFact {
                    database_id,
                    name,
                    head_sha,
                    status: bounded_string(
                        field(object, "status")?,
                        MAX_STRING_BYTES,
                        "check-run status",
                    )?,
                    conclusion: optional_bounded_string(
                        field(object, "conclusion")?,
                        "check-run conclusion",
                    )?,
                    started_at: optional_bounded_string(
                        field(object, "started_at")?,
                        "check-run start time",
                    )?,
                    completed_at: optional_bounded_string(
                        field(object, "completed_at")?,
                        "check-run completion time",
                    )?,
                };
                fact_budget.charge_nested(&check, !checks.is_empty())?;
                checks.push(check);
            }
            if checks.len() >= total {
                if checks.len() != total {
                    return Err(RunnerError::execution(
                        "fully drained check-run count disagrees with GitHub",
                    ));
                }
                break;
            }
            if entries.len() < PAGE_SIZE {
                return Err(RunnerError::execution(
                    "check-run pagination ended before total_count",
                ));
            }
            page = next_page(page)?;
        }
        Ok(checks)
    }
}

struct PullRequestIdentity {
    head_repository: RepositoryResource,
    base_repository: RepositoryResource,
    head_ref: GitRef,
    base_ref: GitRef,
    head_sha: GitOid,
}

fn pull_request_identity(
    response: &Map<String, Value>,
) -> Result<PullRequestIdentity, RunnerError> {
    let head = as_object(field(response, "head")?, "pull-request head")?;
    let base = as_object(field(response, "base")?, "pull-request base")?;
    let head_repository = as_object(field(head, "repo")?, "pull-request head repository")?;
    let base_repository = as_object(field(base, "repo")?, "pull-request base repository")?;
    Ok(PullRequestIdentity {
        head_repository: format!(
            "github:{}",
            bounded_string(
                field(head_repository, "full_name")?,
                MAX_STRING_BYTES,
                "head repository",
            )?
        )
        .parse()
        .map_err(|_| RunnerError::execution("head repository is invalid"))?,
        base_repository: format!(
            "github:{}",
            bounded_string(
                field(base_repository, "full_name")?,
                MAX_STRING_BYTES,
                "base repository",
            )?
        )
        .parse()
        .map_err(|_| RunnerError::execution("base repository is invalid"))?,
        head_ref: format!(
            "refs/heads/{}",
            bounded_string(field(head, "ref")?, MAX_STRING_BYTES, "head ref")?
        )
        .parse()
        .map_err(|_| RunnerError::execution("head ref is invalid"))?,
        base_ref: format!(
            "refs/heads/{}",
            bounded_string(field(base, "ref")?, MAX_STRING_BYTES, "base ref")?
        )
        .parse()
        .map_err(|_| RunnerError::execution("base ref is invalid"))?,
        head_sha: parse_oid(field(head, "sha")?, "head SHA")?,
    })
}

fn require_canonical_identity(
    value: &PullRequestIdentity,
    repository: &RepositoryResource,
    head_ref: &GitRef,
    base_ref: &GitRef,
) -> Result<(), RunnerError> {
    if value.head_repository != *repository
        || value.base_repository != *repository
        || value.head_ref != *head_ref
        || value.base_ref != *base_ref
    {
        return Err(RunnerError::execution(
            "pull-request identity disagrees with the request",
        ));
    }
    Ok(())
}

fn repository_parts(value: &RepositoryResource) -> Result<(&str, &str), RunnerError> {
    value
        .as_str()
        .strip_prefix("github:")
        .and_then(|value| value.split_once('/'))
        .ok_or_else(|| RunnerError::refusal("invalid GitHub repository resource"))
}

fn branch_name(value: &GitRef) -> Result<&str, RunnerError> {
    value
        .as_str()
        .strip_prefix("refs/heads/")
        .ok_or_else(|| RunnerError::refusal("action requires a branch reference"))
}

fn typed<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, RunnerError> {
    serde_json::from_value(value.clone())
        .map_err(|error| RunnerError::refusal(format!("typed action input refused: {error}")))
}

fn as_object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>, RunnerError> {
    value
        .as_object()
        .ok_or_else(|| RunnerError::execution(format!("GitHub {context} is not an object")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, RunnerError> {
    value
        .as_array()
        .ok_or_else(|| RunnerError::execution(format!("GitHub {context} is not an array")))
}

fn field<'a>(value: &'a Map<String, Value>, name: &str) -> Result<&'a Value, RunnerError> {
    value
        .get(name)
        .ok_or_else(|| RunnerError::execution(format!("GitHub response omitted {name}")))
}

fn nonnegative_u64(value: &Value, context: &str) -> Result<u64, RunnerError> {
    value
        .as_u64()
        .ok_or_else(|| RunnerError::execution(format!("GitHub {context} is invalid")))
}

fn positive_u64(value: &Value, context: &str) -> Result<u64, RunnerError> {
    let value = nonnegative_u64(value, context)?;
    if value == 0 {
        Err(RunnerError::execution(format!(
            "GitHub {context} is not positive"
        )))
    } else {
        Ok(value)
    }
}

fn parse_oid(value: &Value, context: &str) -> Result<GitOid, RunnerError> {
    let value = bounded_string(value, 40, context)?;
    if value.len() != 40 {
        return Err(RunnerError::execution(format!(
            "GitHub {context} is invalid"
        )));
    }
    value
        .parse()
        .map_err(|_| RunnerError::execution(format!("GitHub {context} is invalid")))
}

fn optional_oid(value: &Value, context: &str) -> Result<Option<GitOid>, RunnerError> {
    if value.is_null() {
        Ok(None)
    } else {
        parse_oid(value, context).map(Some)
    }
}

fn optional_bounded_string(value: &Value, context: &str) -> Result<Option<String>, RunnerError> {
    if value.is_null() {
        Ok(None)
    } else {
        bounded_string(value, MAX_STRING_BYTES, context).map(Some)
    }
}

fn bounded_string(value: &Value, max_bytes: usize, context: &str) -> Result<String, RunnerError> {
    let value = value
        .as_str()
        .ok_or_else(|| RunnerError::execution(format!("GitHub {context} is not a string")))?;
    if value.len() > max_bytes || value.chars().any(forbidden_response_character) {
        return Err(RunnerError::execution(format!(
            "GitHub {context} violates the string bound"
        )));
    }
    Ok(value.to_owned())
}

fn forbidden_response_character(character: char) -> bool {
    let value = character as u32;
    value <= 0x1f
        || (0x7f..=0x9f).contains(&value)
        || matches!(
            value,
            0x00ad
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x08e2
                | 0x180e
                | 0xfeff
                | 0x110bd
                | 0x110cd
                | 0xe0001
        )
        || (0x0600..=0x0605).contains(&value)
        || (0x0890..=0x0891).contains(&value)
        || (0x200b..=0x200f).contains(&value)
        || (0x202a..=0x202e).contains(&value)
        || (0x2060..=0x2064).contains(&value)
        || (0x2066..=0x206f).contains(&value)
        || (0xfff9..=0xfffb).contains(&value)
        || (0x13430..=0x1343f).contains(&value)
        || (0x1bca0..=0x1bca3).contains(&value)
        || (0x1d173..=0x1d17a).contains(&value)
        || (0xe0020..=0xe007f).contains(&value)
}

fn next_page(value: usize) -> Result<usize, RunnerError> {
    value
        .checked_add(1)
        .ok_or_else(|| RunnerError::execution("GitHub pagination overflow"))
}

fn http_status(context: &str, status: u16) -> RunnerError {
    RunnerError::execution(format!("GitHub {context} returned HTTP {status}"))
}

fn github_failure_summary(body: &Value, token: &str) -> Option<String> {
    let object = body.as_object()?;
    let mut parts = Vec::new();
    for field_name in ["message", "resource", "field", "code"] {
        if let Some(value) = object.get(field_name)
            && let Ok(value) = bounded_string(value, MAX_STRING_BYTES, "failure detail")
        {
            parts.push(value);
        }
    }
    if let Some(errors) = object.get("errors").and_then(Value::as_array) {
        for error in errors.iter().take(4) {
            if let Ok(value) = bounded_string(error, MAX_STRING_BYTES, "failure detail") {
                parts.push(value);
                continue;
            }
            let Some(error) = error.as_object() else {
                continue;
            };
            for field_name in ["resource", "field", "code", "message"] {
                if let Some(value) = error.get(field_name)
                    && let Ok(value) = bounded_string(value, MAX_STRING_BYTES, "failure detail")
                {
                    parts.push(value);
                }
            }
        }
    }
    let mut summary = parts.join("; ");
    if !token.is_empty() {
        summary = summary.replace(token, "[redacted]");
    }
    (!summary.is_empty() && summary.len() <= MAX_STRING_BYTES).then_some(summary)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        fs,
        io::{self, Cursor},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        str::FromStr,
        sync::Arc,
    };

    use crate::{
        artifact::ArtifactStore,
        git::ReviewedExecutable,
        model::{
            DelegationId, GrantId, OperationId, PermissionLevel, PersonaId, ProcessBindingId,
            ProviderGeneration, ProviderInstanceId, RepositoryResource, SessionId,
        },
        pack::GITHUB_PUBLISH_REF_ACTION,
        principal::AuthorityDecision,
        provider::{
            AdapterError, AdapterMint, CredentialEcho, MintRequest, ProviderAdapter,
            ProviderInstance, ProviderRegistry,
        },
        recovery::RecoveryJournal,
    };
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;

    const API_BASE: &str = "https://mock.github.test";
    const TOKEN: &str = "runner-test-bearer-secret";
    const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FORK_HEAD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BRANCH: &str = "ws/widget/builder-1";

    const FAKE_GIT_NONZERO_PUSH: &str = r#"#!/bin/sh
for argument in "$@"; do
  if [ "$argument" = push ]; then
    exit 23
  fi
done
exit 0
"#;
    const FAKE_ASKPASS: &str = "#!/bin/sh\nexit 2\n";

    struct GitActionFixture {
        _root: TempDir,
        store_root: PathBuf,
        runner: GitRunner,
    }

    impl GitActionFixture {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .prefix("runner-git-")
                .tempdir_in(std::env::current_dir().expect("current directory"))
                .expect("create safe test directory");
            let git = write_test_executable(root.path().join("fake-git"), FAKE_GIT_NONZERO_PUSH);
            let askpass = write_test_executable(root.path().join("fake-askpass"), FAKE_ASKPASS);
            let store_root = root.path().join("artifact-store");
            let runner = GitRunner::new(
                reviewed_test_executable(git),
                reviewed_test_executable(askpass),
            )
            .with_credential_peer_fingerprint_for_test(test_peer_fingerprint);
            Self {
                _root: root,
                store_root,
                runner,
            }
        }

        fn verified_artifact(&self) -> (ArtifactRef, VerifiedArtifact) {
            let store = ArtifactStore::new(&self.store_root, 1024 * 1024).unwrap();
            let reference = store.import(Cursor::new(b"fake bundle bytes")).unwrap();
            let artifact = store.open_verified(&reference).unwrap();
            (reference, artifact)
        }
    }

    fn write_test_executable(path: PathBuf, contents: &str) -> PathBuf {
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn reviewed_test_executable(path: PathBuf) -> ReviewedExecutable {
        let digest: [u8; 32] = Sha256::digest(fs::read(&path).unwrap()).into();
        ReviewedExecutable::new(path, digest).unwrap()
    }

    fn test_peer_fingerprint(_path: &Path) -> io::Result<[u8; 32]> {
        Ok([0_u8; 32])
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ObservedRequest {
        method: HttpMethod,
        url: String,
        body: Option<Value>,
    }

    struct MockHttp {
        responses: Mutex<VecDeque<HttpResponse>>,
        requests: Mutex<Vec<ObservedRequest>>,
    }

    impl MockHttp {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ObservedRequest> {
            self.requests.lock().clone()
        }

        fn assert_drained(&self) {
            assert!(self.responses.lock().is_empty());
        }
    }

    impl BlockingHttp for MockHttp {
        fn execute(&self, request: HttpRequest<'_>) -> Result<HttpResponse, AdapterError> {
            assert_eq!(request.bearer_token, TOKEN);
            self.requests.lock().push(ObservedRequest {
                method: request.method,
                url: request.url.to_owned(),
                body: request.body.cloned(),
            });
            let response = self
                .responses
                .lock()
                .pop_front()
                .expect("mock response for every request");
            assert_eq!(
                response.body_bytes,
                serde_json::to_vec(&response.body).unwrap().len()
            );
            Ok(response)
        }
    }

    struct EchoProvider;

    impl ProviderAdapter for EchoProvider {
        fn mint(&self, request: &MintRequest<'_>) -> Result<AdapterMint, AdapterError> {
            Ok(AdapterMint::new(
                TOKEN.to_owned(),
                CredentialEcho {
                    provider_instance: request.provider_instance.clone(),
                    generation: request.generation.clone(),
                    provider: request.provider.to_owned(),
                    app_slug: request.app_slug.to_owned(),
                    app_id: request.app_id,
                    installation_id: request.installation_id,
                    repositories: vec![request.repository.clone()],
                    permissions: request.permissions.clone(),
                    expires_at_unix: request.now_unix + 300,
                },
            ))
        }

        fn revoke(&self, _token: &str) -> Result<(), AdapterError> {
            Ok(())
        }
    }

    fn repository(value: &str) -> RepositoryResource {
        RepositoryResource::from_str(value).unwrap()
    }

    fn git_ref(value: &str) -> GitRef {
        GitRef::from_str(value).unwrap()
    }

    fn oid(value: &str) -> GitOid {
        GitOid::from_str(value).unwrap()
    }

    fn permissions() -> BTreeMap<String, PermissionLevel> {
        BTreeMap::from([
            ("contents".to_owned(), PermissionLevel::Read),
            ("checks".to_owned(), PermissionLevel::Read),
            ("pull_requests".to_owned(), PermissionLevel::Write),
        ])
    }

    fn need(destination_ref: Option<&str>) -> Need {
        Need {
            provider: "github".to_owned(),
            repository: repository("github:ember/example"),
            destination_ref: destination_ref.map(git_ref),
            permissions: permissions(),
        }
    }

    fn publication_input(artifact: ArtifactRef, new_oid: &str) -> Value {
        serde_json::to_value(GitRefPublicationInput {
            repository: repository("github:ember/example"),
            artifact,
            expected_old_oid: oid("1111111111111111111111111111111111111111"),
            new_oid: oid(new_oid),
            destination_ref: git_ref("refs/heads/release"),
        })
        .unwrap()
    }

    fn credential() -> MintedCredential {
        let directory = tempfile::tempdir().unwrap();
        let journal = RecoveryJournal::open_test_fixture(directory.path(), [10_u8; 32]).unwrap();
        let instance_id = ProviderInstanceId::new();
        let generation = ProviderGeneration::new();
        let mut providers = ProviderRegistry::default();
        providers
            .register(ProviderInstance::with_identity(
                instance_id,
                generation,
                "github",
                "ember-app",
                41,
                73,
                [repository("github:ember/example")],
                permissions(),
                Arc::new(EchoProvider),
            ))
            .unwrap();
        let decision = AuthorityDecision {
            persona_id: PersonaId::new(),
            session_id: SessionId::new(),
            process_binding_id: ProcessBindingId::new(),
            grant_id: GrantId::new(),
            delegation_path: vec![DelegationId::new()],
        };
        providers
            .mint(
                &OperationId::new(),
                &decision,
                GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
                &json!({"fixture": true}),
                &need(None),
                1_000,
                &journal,
            )
            .unwrap()
    }

    fn response(status: u16, body: Value) -> HttpResponse {
        let body_bytes = serde_json::to_vec(&body).unwrap().len();
        HttpResponse {
            status,
            body,
            body_bytes,
        }
    }

    fn create_input() -> GithubPullRequestCreateInput {
        GithubPullRequestCreateInput {
            repository: repository("github:ember/example"),
            head_ref: git_ref("refs/heads/ws/widget/builder-1"),
            base_ref: git_ref("refs/heads/main"),
            title: "wb: widget builder-1".to_owned(),
            body: String::new(),
        }
    }

    fn reconcile_input() -> GithubRepositoryFactsInput {
        GithubRepositoryFactsInput {
            repository: repository("github:ember/example"),
            head_ref: git_ref("refs/heads/ws/widget/builder-1"),
            base_ref: git_ref("refs/heads/main"),
        }
    }

    fn identity(number: u64, head_repository: &str, head_sha: &str) -> Value {
        json!({
            "number": number,
            "head": {
                "ref": BRANCH,
                "sha": head_sha,
                "repo": {"full_name": head_repository}
            },
            "base": {
                "ref": "main",
                "repo": {"full_name": "ember/example"}
            }
        })
    }

    fn pull_request(
        number: u64,
        head_repository: &str,
        head_sha: &str,
        changed_files: usize,
    ) -> Value {
        let mut value = identity(number, head_repository, head_sha);
        let object = value.as_object_mut().unwrap();
        object.insert("state".to_owned(), json!("open"));
        object.insert("merged_at".to_owned(), Value::Null);
        object.insert("merge_commit_sha".to_owned(), Value::Null);
        object.insert("changed_files".to_owned(), json!(changed_files));
        value
    }

    fn list_entry(number: u64, head: &str) -> Value {
        json!({"number": number, "head": {"ref": head}})
    }

    fn reference() -> Value {
        json!({
            "ref": "refs/heads/ws/widget/builder-1",
            "object": {"sha": HEAD}
        })
    }

    fn file_page(range: std::ops::Range<usize>) -> Value {
        Value::Array(
            range
                .map(|index| json!({"filename": format!("src/file-{index:03}.rs")}))
                .collect(),
        )
    }

    fn check(id: u64, head_sha: &str, name: String) -> Value {
        json!({
            "id": id,
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "started_at": null,
            "completed_at": null
        })
    }

    fn check_page(total_count: usize, entries: Vec<Value>) -> Value {
        json!({"total_count": total_count, "check_runs": entries})
    }

    fn create_response(head_ref: &str) -> Value {
        json!({
            "number": 17,
            "html_url": "https://github.com/ember/example/pull/17",
            "state": "open",
            "title": "wb: widget builder-1",
            "body": "",
            "head": {
                "ref": head_ref,
                "sha": HEAD,
                "repo": {"full_name": "ember/example"}
            },
            "base": {
                "ref": "main",
                "repo": {"full_name": "ember/example"}
            }
        })
    }

    fn run_create(body: Value) -> (Arc<MockHttp>, Result<RunnerOutput, RunnerError>) {
        run_create_responses(vec![response(201, body)])
    }

    fn run_create_responses(
        responses: Vec<HttpResponse>,
    ) -> (Arc<MockHttp>, Result<RunnerOutput, RunnerError>) {
        let http = Arc::new(MockHttp::new(responses));
        let runner = GithubApiRunner::with_api_base(http.clone(), API_BASE);
        let result = runner.run(
            GITHUB_PULL_REQUEST_CREATE_ACTION,
            &serde_json::to_value(create_input()).unwrap(),
            None,
            &credential(),
        );
        (http, result)
    }

    fn run_reconcile(
        responses: Vec<HttpResponse>,
    ) -> (Arc<MockHttp>, Result<RunnerOutput, RunnerError>) {
        let http = Arc::new(MockHttp::new(responses));
        let runner = GithubApiRunner::with_api_base(http.clone(), API_BASE);
        let result = runner.run(
            GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
            &serde_json::to_value(reconcile_input()).unwrap(),
            None,
            &credential(),
        );
        (http, result)
    }

    fn assert_gets(http: &MockHttp, urls: &[String]) {
        let requests = http.requests();
        assert_eq!(requests.len(), urls.len());
        for (request, url) in requests.iter().zip(urls) {
            assert_eq!(request.method, HttpMethod::Get);
            assert_eq!(&request.url, url);
            assert_eq!(request.body, None);
        }
        http.assert_drained();
    }

    fn assert_create_request(http: &MockHttp) {
        assert_eq!(
            http.requests(),
            vec![ObservedRequest {
                method: HttpMethod::Post,
                url: format!("{API_BASE}/repos/ember/example/pulls"),
                body: Some(json!({
                    "title": "wb: widget builder-1",
                    "head": BRANCH,
                    "base": "main",
                    "body": ""
                })),
            }]
        );
        http.assert_drained();
    }

    fn assert_retry_requests(http: &MockHttp) {
        let requests = http.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(
            requests[0].url,
            format!("{API_BASE}/repos/ember/example/pulls")
        );
        assert_eq!(
            requests[1],
            ObservedRequest {
                method: HttpMethod::Get,
                url: format!(
                    "{API_BASE}/repos/ember/example/pulls?state=open&head=ember:{BRANCH}&base=main&per_page={PAGE_SIZE}&page=1"
                ),
                body: None,
            }
        );
        http.assert_drained();
    }

    fn execution_error(result: Result<RunnerOutput, RunnerError>) -> RunnerError {
        let error = match result {
            Ok(_) => panic!("hostile response was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RunnerFailureKind::ExecutionFailure);
        assert!(!error.to_string().contains(TOKEN));
        error
    }

    fn refusal<T>(result: Result<T, RunnerError>) {
        let error = match result {
            Ok(_) => panic!("invalid metadata was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RunnerFailureKind::Refusal);
        assert!(!error.to_string().contains(TOKEN));
    }

    fn assert_output_secret_free(output: &RunnerOutput) {
        let rendered = format!(
            "{}{}{}{}",
            serde_json::to_string(&output.facts).unwrap(),
            serde_json::to_string(&output.evidence).unwrap(),
            serde_json::to_string(&output.audit_data).unwrap(),
            output.message
        );
        assert!(!rendered.contains(TOKEN));
    }

    #[test]
    fn canonical_pull_request_create_uses_exact_request_and_refuses_mismatch() {
        let (http, result) = run_create(create_response(BRANCH));
        let output = result.unwrap();
        assert!(output.succeeded);
        assert_output_secret_free(&output);
        assert_eq!(
            output.facts,
            Some(ActionFacts::GithubPullRequestCreated {
                repository: repository("github:ember/example"),
                number: 17,
                html_url: "https://github.com/ember/example/pull/17".to_owned(),
                head_ref: git_ref("refs/heads/ws/widget/builder-1"),
                base_ref: git_ref("refs/heads/main"),
            })
        );
        assert_create_request(&http);

        let runner = GithubApiRunner::with_api_base(Arc::new(MockHttp::new(vec![])), API_BASE);
        refusal(runner.validate(
            GITHUB_PULL_REQUEST_CREATE_ACTION,
            &serde_json::to_value(create_input()).unwrap(),
            &need(Some("refs/heads/ws/other/builder-1")),
            false,
            &DeliveryLane::Proxy,
            "github.app-installation/v1",
        ));

        let (http, result) = run_create(create_response("ws/widget/planner-1"));
        let error = execution_error(result);
        assert!(
            error
                .to_string()
                .contains("identity disagrees with the request")
        );
        assert_create_request(&http);
    }

    #[test]
    fn github_runner_accepts_refs_and_pull_request_metadata_outside_workbench_policy() {
        let runner = GithubApiRunner::with_api_base(Arc::new(MockHttp::new(vec![])), API_BASE);
        let mut input = create_input();
        input.head_ref = git_ref("refs/heads/feature/add-widget");
        input.base_ref = git_ref("refs/heads/release");
        input.title = "Add widget".to_owned();
        input.body = "Repository-owned pull request text".to_owned();

        assert_eq!(
            runner
                .validate(
                    GITHUB_PULL_REQUEST_CREATE_ACTION,
                    &serde_json::to_value(&input).unwrap(),
                    &need(Some("refs/heads/feature/add-widget")),
                    false,
                    &DeliveryLane::Proxy,
                    "github.app-installation/v1",
                )
                .unwrap(),
            None
        );
    }

    #[test]
    fn lost_create_response_retry_accepts_only_one_exact_open_pull_request() {
        let mut existing = create_response(BRANCH);
        existing["body"] = Value::Null;
        let responses = vec![
            response(422, json!({"message": "A pull request already exists"})),
            response(200, json!([existing])),
        ];
        let (http, result) = run_create_responses(responses);
        let output = result.unwrap();

        assert!(output.succeeded);
        assert_eq!(
            output.facts,
            Some(ActionFacts::GithubPullRequestCreated {
                repository: repository("github:ember/example"),
                number: 17,
                html_url: "https://github.com/ember/example/pull/17".to_owned(),
                head_ref: git_ref("refs/heads/ws/widget/builder-1"),
                base_ref: git_ref("refs/heads/main"),
            })
        );
        assert_output_secret_free(&output);
        assert_retry_requests(&http);
    }

    #[test]
    fn create_failure_reports_bounded_provider_details_without_the_token() {
        let responses = vec![
            response(
                422,
                json!({
                    "message": format!("Validation Failed {TOKEN}"),
                    "errors": [{
                        "resource": "PullRequest",
                        "field": "head",
                        "code": "custom",
                        "message": "No commits between the requested branches"
                    }]
                }),
            ),
            response(200, json!([])),
        ];
        let (_, result) = run_create_responses(responses);
        let error = execution_error(result).to_string();

        assert!(error.contains("Validation Failed [redacted]"));
        assert!(error.contains("PullRequest; head; custom"));
        assert!(error.contains("No commits between the requested branches"));
        assert!(!error.contains(TOKEN));
    }

    #[test]
    fn create_retry_refuses_zero_ambiguous_closed_malformed_or_mismatched_candidates() {
        let mut closed = create_response(BRANCH);
        closed["state"] = json!("closed");
        let malformed = json!({
            "state": "open",
            "title": "wb: widget builder-1",
        });
        let mut mismatched = create_response(BRANCH);
        mismatched["title"] = json!("wb: other builder-1");
        let mut mismatched_body = create_response(BRANCH);
        mismatched_body["body"] = json!("different authorized content");
        let cases = [
            ("zero", json!([])),
            (
                "ambiguous",
                json!([create_response(BRANCH), create_response(BRANCH)]),
            ),
            ("closed", json!([closed])),
            ("malformed", json!([malformed])),
            ("mismatched", json!([mismatched])),
            ("mismatched-body", json!([mismatched_body])),
        ];

        for (case, page) in cases {
            let responses = vec![
                response(422, json!({"message": "A pull request already exists"})),
                response(200, page),
            ];
            let (http, result) = run_create_responses(responses);
            let error = execution_error(result);
            assert!(!error.to_string().is_empty(), "{case}");
            assert_retry_requests(&http);
        }
    }

    #[test]
    fn reconcile_drains_all_pages_and_separates_canonical_and_fork_heads() {
        let mut pull_page = vec![list_entry(7, BRANCH)];
        pull_page.extend((0..99).map(|index| list_entry(1_000 + index, "other")));
        let check_page_one = (0..100)
            .map(|index| check((index + 1) as u64, HEAD, format!("check-{index:03}")))
            .collect();
        let responses = vec![
            response(200, reference()),
            response(200, Value::Array(pull_page)),
            response(200, json!([list_entry(8, BRANCH)])),
            response(200, pull_request(7, "ember/example", HEAD, 101)),
            response(200, file_page(0..100)),
            response(200, file_page(100..101)),
            response(200, check_page(101, check_page_one)),
            response(
                200,
                check_page(101, vec![check(101, HEAD, "check-100".to_owned())]),
            ),
            response(200, pull_request(8, "contributor/example", FORK_HEAD, 0)),
        ];
        let (http, result) = run_reconcile(responses);
        let output = result.unwrap();
        assert_output_secret_free(&output);
        match output.facts.unwrap() {
            ActionFacts::GithubRepositoryFacts {
                repository: actual_repository,
                repository_head,
                fork_heads,
                prs,
            } => {
                assert_eq!(actual_repository, repository("github:ember/example"));
                assert_eq!(repository_head, oid(HEAD));
                assert_eq!(fork_heads.len(), 1);
                assert_eq!(fork_heads[0].number, 8);
                assert_eq!(
                    fork_heads[0].repository,
                    repository("github:contributor/example")
                );
                assert_eq!(fork_heads[0].head_sha, oid(FORK_HEAD));
                assert_eq!(prs.len(), 1);
                assert_eq!(prs[0].number, 7);
                assert_eq!(prs[0].changed_files_count, 101);
                assert_eq!(prs[0].changed_files.len(), 101);
                assert_eq!(prs[0].changed_files[0], "src/file-000.rs");
                assert_eq!(prs[0].changed_files[100], "src/file-100.rs");
                assert_eq!(prs[0].checks.len(), 101);
                assert_eq!(prs[0].checks[0].database_id, 1);
                assert_eq!(prs[0].checks[100].database_id, 101);
            }
            _ => panic!("unexpected facts"),
        }
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=2"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/7"),
                format!("{API_BASE}/repos/ember/example/pulls/7/files?per_page=100&page=1"),
                format!("{API_BASE}/repos/ember/example/pulls/7/files?per_page=100&page=2"),
                format!(
                    "{API_BASE}/repos/ember/example/commits/{HEAD}/check-runs?per_page=100&page=1"
                ),
                format!(
                    "{API_BASE}/repos/ember/example/commits/{HEAD}/check-runs?per_page=100&page=2"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/8"),
            ],
        );
    }

    #[test]
    fn reconcile_caps_total_scanned_pull_request_entries_before_filtering() {
        let mut responses = vec![response(200, reference())];
        for page in 0..(MAX_ARRAY_ITEMS / PAGE_SIZE) {
            let start = page * PAGE_SIZE;
            let entries = (start..start + PAGE_SIZE)
                .map(|index| list_entry((index + 1) as u64, "unrelated"))
                .collect();
            responses.push(response(200, Value::Array(entries)));
        }
        responses.push(response(
            200,
            json!([list_entry((MAX_ARRAY_ITEMS + 1) as u64, "unrelated")]),
        ));
        let expected_requests = responses.len();

        let (http, result) = run_reconcile(responses);
        let error = execution_error(result);

        assert!(error.to_string().contains("total scanned-entry bound"));
        assert_eq!(http.requests().len(), expected_requests);
        http.assert_drained();
    }

    #[test]
    fn reconcile_refuses_oversized_fact_block_before_draining_all_check_pages() {
        let total_checks = PAGE_SIZE * 22;
        let mut responses = vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH)])),
            response(200, pull_request(7, "ember/example", HEAD, 0)),
            response(200, json!([])),
        ];
        for page in 0..(total_checks / PAGE_SIZE) {
            let start = page * PAGE_SIZE;
            let checks = (start..start + PAGE_SIZE)
                .map(|index| check((index + 1) as u64, HEAD, "x".repeat(MAX_STRING_BYTES)))
                .collect();
            responses.push(response(200, check_page(total_checks, checks)));
        }
        let all_pages_request_count = responses.len();

        let (http, result) = run_reconcile(responses);
        let error = execution_error(result);

        assert!(error.to_string().contains("signed fact block exceeds"));
        assert!(http.requests().len() < all_pages_request_count);
    }

    #[test]
    fn fact_budget_caps_nested_items_across_parent_pull_requests() {
        let mut budget = FactBudget::new(&repository("github:ember/example"), &oid(HEAD)).unwrap();
        for index in 0..MAX_ARRAY_ITEMS {
            budget.charge_nested(&index, index != 0).unwrap();
        }

        let error = budget.charge_nested(&MAX_ARRAY_ITEMS, true).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("aggregate nested fact items exceed")
        );
    }

    #[test]
    fn duplicated_and_malformed_pull_request_identities_fail_closed() {
        let (http, result) = run_reconcile(vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH), list_entry(7, BRANCH)])),
        ]);
        let error = execution_error(result);
        assert!(error.to_string().contains("oversized or duplicated"));
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
            ],
        );

        let (http, result) = run_reconcile(vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH)])),
            response(200, pull_request(7, "ember/example", "not-a-git-oid", 0)),
        ]);
        let error = execution_error(result);
        assert!(error.to_string().contains("head SHA is invalid"));
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/7"),
            ],
        );
    }

    #[test]
    fn changed_file_count_mismatch_fails_after_full_drain() {
        let (http, result) = run_reconcile(vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH)])),
            response(200, pull_request(7, "ember/example", HEAD, 2)),
            response(200, file_page(0..1)),
        ]);
        let error = execution_error(result);
        assert!(error.to_string().contains("changed-file count disagrees"));
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/7"),
                format!("{API_BASE}/repos/ember/example/pulls/7/files?per_page=100&page=1"),
            ],
        );
    }

    #[test]
    fn check_head_sha_mismatch_fails_closed() {
        let (http, result) = run_reconcile(vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH)])),
            response(200, pull_request(7, "ember/example", HEAD, 0)),
            response(200, json!([])),
            response(
                200,
                check_page(1, vec![check(1, FORK_HEAD, "required".to_owned())]),
            ),
        ]);
        let error = execution_error(result);
        assert!(error.to_string().contains("disagrees with the PR head"));
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/7"),
                format!("{API_BASE}/repos/ember/example/pulls/7/files?per_page=100&page=1"),
                format!(
                    "{API_BASE}/repos/ember/example/commits/{HEAD}/check-runs?per_page=100&page=1"
                ),
            ],
        );
    }

    #[test]
    fn check_total_count_cannot_end_pagination_early() {
        let (http, result) = run_reconcile(vec![
            response(200, reference()),
            response(200, json!([list_entry(7, BRANCH)])),
            response(200, pull_request(7, "ember/example", HEAD, 0)),
            response(200, json!([])),
            response(
                200,
                check_page(101, vec![check(1, HEAD, "required".to_owned())]),
            ),
        ]);
        let error = execution_error(result);
        assert!(
            error
                .to_string()
                .contains("pagination ended before total_count")
        );
        assert_gets(
            &http,
            &[
                format!("{API_BASE}/repos/ember/example/git/ref/heads/{BRANCH}"),
                format!(
                    "{API_BASE}/repos/ember/example/pulls?state=all&base=main&per_page=100&page=1"
                ),
                format!("{API_BASE}/repos/ember/example/pulls/7"),
                format!("{API_BASE}/repos/ember/example/pulls/7/files?per_page=100&page=1"),
                format!(
                    "{API_BASE}/repos/ember/example/commits/{HEAD}/check-runs?per_page=100&page=1"
                ),
            ],
        );
    }

    #[test]
    fn oversized_forbidden_and_over_byte_limit_responses_fail_closed() {
        let mut oversized = create_response(BRANCH);
        oversized.as_object_mut().unwrap().insert(
            "html_url".to_owned(),
            json!("x".repeat(MAX_STRING_BYTES + 1)),
        );
        let (http, result) = run_create(oversized);
        assert!(execution_error(result).to_string().contains("string bound"));
        assert_create_request(&http);

        let mut forbidden = create_response(BRANCH);
        forbidden.as_object_mut().unwrap().insert(
            "html_url".to_owned(),
            json!("https://github.com/ember/example/pull/\u{202e}17"),
        );
        let (http, result) = run_create(forbidden);
        assert!(execution_error(result).to_string().contains("string bound"));
        assert_create_request(&http);

        let enormous = json!({"padding": "x".repeat(MAX_HTTP_RESPONSE_BYTES)});
        let (http, result) = run_create(enormous);
        assert!(
            execution_error(result)
                .to_string()
                .contains("hard byte limit")
        );
        assert_create_request(&http);
    }

    #[test]
    fn git_action_runner_reports_nonzero_publish_exit() {
        let fixture = GitActionFixture::new();
        let (reference, artifact) = fixture.verified_artifact();
        let credential = credential();

        let output = ActionRunner::run(
            &fixture.runner,
            GITHUB_PUBLISH_REF_ACTION,
            &publication_input(reference, HEAD),
            Some(artifact),
            &credential,
        )
        .unwrap();

        assert!(!output.succeeded);
        assert_eq!(output.message, "Git publication exited Some(23)");
        assert_eq!(
            output
                .evidence
                .process
                .as_ref()
                .and_then(|process| process.exit_code),
            Some(23)
        );
        assert_eq!(output.evidence.credential_peer_served_count, Some(0));
        assert_eq!(output.evidence.credential_peer_rejected_count, Some(0));
        assert_eq!(output.audit_data["credential_peer_served_count"], 0);
        assert_eq!(output.audit_data["credential_peer_rejected_count"], 0);
    }

    #[test]
    fn git_action_runner_formats_publish_errors_as_execution_failures() {
        let fixture = GitActionFixture::new();
        let (reference, artifact) = fixture.verified_artifact();
        let credential = credential();

        let error = execution_error(ActionRunner::run(
            &fixture.runner,
            GITHUB_PUBLISH_REF_ACTION,
            &publication_input(reference, "0000000000000000000000000000000000000000"),
            Some(artifact),
            &credential,
        ));

        assert_eq!(
            error.to_string(),
            "sealed Git runner failed: new Git object ID may not be zero"
        );
    }

    #[test]
    fn wrong_adapter_action_artifact_lane_and_mint_metadata_are_refusals() {
        let http = Arc::new(MockHttp::new(vec![]));
        let runner = Arc::new(GithubApiRunner::with_api_base(http.clone(), API_BASE));
        let input = serde_json::to_value(create_input()).unwrap();
        refusal(runner.validate(
            "github.pull-request.delete/v1",
            &input,
            &need(Some("refs/heads/ws/widget/builder-1")),
            false,
            &DeliveryLane::Proxy,
            "github.app-installation/v1",
        ));
        refusal(runner.validate(
            GITHUB_PULL_REQUEST_CREATE_ACTION,
            &input,
            &need(Some("refs/heads/ws/widget/builder-1")),
            true,
            &DeliveryLane::Proxy,
            "github.app-installation/v1",
        ));
        refusal(runner.validate(
            GITHUB_PULL_REQUEST_CREATE_ACTION,
            &input,
            &need(Some("refs/heads/ws/widget/builder-1")),
            false,
            &DeliveryLane::SealedExec,
            "github.app-installation/v1",
        ));
        refusal(runner.validate(
            GITHUB_PULL_REQUEST_CREATE_ACTION,
            &input,
            &need(Some("refs/heads/ws/widget/builder-1")),
            false,
            &DeliveryLane::Proxy,
            "github.app-installation/v2",
        ));

        let mut registry = RunnerRegistry::default();
        registry.register(runner).unwrap();
        refusal(registry.validate(
            "github.api/v2",
            RunnerValidation {
                action: GITHUB_PULL_REQUEST_CREATE_ACTION,
                input: &input,
                need: &need(Some("refs/heads/ws/widget/builder-1")),
                artifact_required: false,
                lane: &DeliveryLane::Proxy,
                mint_adapter: "github.app-installation/v1",
            },
        ));
        assert!(http.requests().is_empty());
    }
}
