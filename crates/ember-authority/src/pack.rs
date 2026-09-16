use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use jsonschema::JSONSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{
    ACTION_REQUEST_SCHEMA, ActionRequest, GitRef, GitRefPublicationInput,
    GithubPullRequestCreateInput, GithubRepositoryFactsInput, Need, PackRef, PermissionLevel,
    RepositoryResource,
};

pub const PACK_SCHEMA: &str = "ember.provider-pack/v1";
pub const GITHUB_PACK_ADDRESS: &str = "ember.pack/github";
pub const GITHUB_PACK_VERSION: u32 = 2;
pub const GITHUB_PUBLISH_REF_ACTION: &str = "git.publish-ref/v1";
pub const GITHUB_PULL_REQUEST_CREATE_ACTION: &str = "github.pull-request.create/v1";
pub const GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION: &str = "github.reconcile.repository-facts/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    NativeAttenuation,
    StaticSecret,
    KeyCustody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryLane {
    SealedExec,
    Proxy,
    SignThrough,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeedTemplate {
    pub provider: String,
    pub repository_field: String,
    pub destination_ref_field: Option<String>,
    pub permissions: BTreeMap<String, PermissionLevel>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDefinition {
    pub input_schema: Value,
    pub artifact_required: bool,
    pub need: NeedTemplate,
    pub lane: DeliveryLane,
    pub runner_adapter: String,
    pub mint_adapter: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPack {
    pub schema: String,
    pub address: String,
    pub version: u32,
    pub publisher: String,
    pub credential_class: CredentialClass,
    pub actions: BTreeMap<String, ActionDefinition>,
}

impl ProviderPack {
    pub fn reference(&self) -> PackRef {
        PackRef {
            address: self.address.clone(),
            version: self.version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProviderPack {
    pub pack: ProviderPack,
    pub signer_key_id: String,
    pub signature_base64: String,
}

impl SignedProviderPack {
    pub fn sign(
        pack: ProviderPack,
        signer_key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<Self, PackError> {
        validate_pack_shape(&pack)?;
        let bytes = serde_jcs::to_vec(&pack).map_err(PackError::Canonicalize)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            pack,
            signer_key_id: signer_key_id.into(),
            signature_base64: BASE64.encode(signature.to_bytes()),
        })
    }
}

#[derive(Clone)]
pub struct TrustedPublisher {
    pub publisher: String,
    pub verifying_key: VerifyingKey,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub revoked: bool,
}

#[derive(Default)]
pub struct PackTrustStore {
    publishers: BTreeMap<String, TrustedPublisher>,
}

impl PackTrustStore {
    pub fn insert(&mut self, key_id: impl Into<String>, publisher: TrustedPublisher) {
        self.publishers.insert(key_id.into(), publisher);
    }

    pub fn verify(
        &self,
        signed: SignedProviderPack,
        now_unix: i64,
    ) -> Result<InstalledPack, PackError> {
        validate_pack_shape(&signed.pack)?;
        let trusted = self
            .publishers
            .get(&signed.signer_key_id)
            .ok_or(PackError::UnknownPublisher)?;
        if trusted.revoked
            || now_unix < trusted.not_before_unix
            || now_unix >= trusted.not_after_unix
            || trusted.publisher != signed.pack.publisher
        {
            return Err(PackError::PublisherNotTrusted);
        }
        let canonical = serde_jcs::to_vec(&signed.pack).map_err(PackError::Canonicalize)?;
        let signature_bytes = BASE64
            .decode(&signed.signature_base64)
            .map_err(|_| PackError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| PackError::InvalidSignature)?;
        trusted
            .verifying_key
            .verify_strict(&canonical, &signature)
            .map_err(|_| PackError::InvalidSignature)?;
        let digest_sha256 = hex::encode(Sha256::digest(&canonical));
        Ok(InstalledPack {
            pack: signed.pack,
            signer_key_id: signed.signer_key_id,
            digest_sha256,
        })
    }
}

#[derive(Clone, Debug)]
pub struct InstalledPack {
    pub pack: ProviderPack,
    pub signer_key_id: String,
    pub digest_sha256: String,
}

#[derive(Default)]
pub struct PackRegistry {
    packs: BTreeMap<PackRef, InstalledPack>,
}

impl PackRegistry {
    pub fn install(&mut self, pack: InstalledPack) -> Result<(), PackError> {
        let reference = pack.pack.reference();
        if self.packs.contains_key(&reference) {
            return Err(PackError::AlreadyInstalled);
        }
        self.packs.insert(reference, pack);
        Ok(())
    }

    pub fn resolve(&self, request: &ActionRequest) -> Result<ResolvedAction, PackError> {
        if request.schema != ACTION_REQUEST_SCHEMA {
            return Err(PackError::UnknownRequestSchema);
        }
        let installed = self
            .packs
            .get(&request.pack)
            .ok_or(PackError::UnknownPack)?;
        let action = installed
            .pack
            .actions
            .get(&request.action)
            .ok_or(PackError::UnknownAction)?;
        let compiled = JSONSchema::compile(&action.input_schema)
            .map_err(|error| PackError::InvalidInputSchema(error.to_string()))?;
        if let Err(errors) = compiled.validate(&request.input) {
            let reasons = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            return Err(PackError::InvalidInput(reasons.join("; ")));
        }
        let canonical_input = match request.action.as_str() {
            GITHUB_PUBLISH_REF_ACTION => {
                serde_json::from_value::<GitRefPublicationInput>(request.input.clone())
                    .and_then(serde_json::to_value)
            }
            GITHUB_PULL_REQUEST_CREATE_ACTION => {
                serde_json::from_value::<GithubPullRequestCreateInput>(request.input.clone())
                    .and_then(serde_json::to_value)
            }
            GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION => {
                serde_json::from_value::<GithubRepositoryFactsInput>(request.input.clone())
                    .and_then(serde_json::to_value)
            }
            _ => Ok(request.input.clone()),
        }
        .map_err(|error| PackError::InvalidInput(error.to_string()))?;
        let repository_value = canonical_input
            .get(&action.need.repository_field)
            .and_then(Value::as_str)
            .ok_or(PackError::NeedDerivation)?;
        let repository = repository_value
            .parse::<RepositoryResource>()
            .map_err(|_| PackError::NeedDerivation)?;
        let destination_ref = action
            .need
            .destination_ref_field
            .as_ref()
            .map(|field| {
                canonical_input
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(PackError::NeedDerivation)?
                    .parse::<GitRef>()
                    .map_err(|_| PackError::NeedDerivation)
            })
            .transpose()?;
        Ok(ResolvedAction {
            pack: installed.clone(),
            key: request.action.clone(),
            input: canonical_input,
            need: Need {
                provider: action.need.provider.clone(),
                repository,
                destination_ref,
                permissions: action.need.permissions.clone(),
            },
            lane: action.lane.clone(),
            runner_adapter: action.runner_adapter.clone(),
            artifact_required: action.artifact_required,
            mint_adapter: action.mint_adapter.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedAction {
    pub pack: InstalledPack,
    pub key: String,
    pub input: Value,
    pub need: Need,
    pub lane: DeliveryLane,
    pub runner_adapter: String,
    pub artifact_required: bool,
    pub mint_adapter: String,
}

pub fn github_pack_v2(publisher: impl Into<String>) -> ProviderPack {
    let publish_permissions = BTreeMap::from([
        ("contents".to_owned(), PermissionLevel::Write),
        ("metadata".to_owned(), PermissionLevel::Read),
    ]);
    let publish = ActionDefinition {
        input_schema: json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "required": [
                "repository",
                "artifact",
                "expected_old_oid",
                "new_oid",
                "destination_ref"
            ],
            "properties": {
                "repository": {
                    "type": "string",
                    "pattern": "^github:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$",
                    "maxLength": 147
                },
                "artifact": {
                    "type": "string",
                    "pattern": "^artifact:sha256:[0-9a-f]{64}$"
                },
                "expected_old_oid": {
                    "type": "string",
                    "pattern": "^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
                },
                "new_oid": {
                    "type": "string",
                    "pattern": "^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
                },
                "destination_ref": {
                    "type": "string",
                    "pattern": "^refs/(?:heads|tags)/.+$",
                    "maxLength": 255
                }
            }
        }),
        artifact_required: true,
        need: NeedTemplate {
            provider: "github".to_owned(),
            repository_field: "repository".to_owned(),
            destination_ref_field: Some("destination_ref".to_owned()),
            permissions: publish_permissions,
        },
        lane: DeliveryLane::SealedExec,
        runner_adapter: "git.publish-ref/v1".to_owned(),
        mint_adapter: "github.app-installation/v1".to_owned(),
    };

    let pull_request = ActionDefinition {
        input_schema: json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "head_ref", "base_ref", "title", "body"],
            "properties": {
                "repository": {
                    "type": "string",
                    "pattern": "^github:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$",
                    "maxLength": 147
                },
                "head_ref": {
                    "type": "string",
                    "pattern": "^refs/heads/.+$",
                    "maxLength": 255
                },
                "base_ref": {"const": "refs/heads/main"},
                "title": {
                    "type": "string",
                    "pattern": "^wb: [a-z0-9][a-z0-9-]* (?:planner|builder)-[1-9][0-9]*$",
                    "maxLength": 4096
                },
                "body": {"const": ""}
            }
        }),
        artifact_required: false,
        need: NeedTemplate {
            provider: "github".to_owned(),
            repository_field: "repository".to_owned(),
            destination_ref_field: Some("head_ref".to_owned()),
            permissions: BTreeMap::from([
                ("contents".to_owned(), PermissionLevel::Read),
                ("metadata".to_owned(), PermissionLevel::Read),
                ("pull_requests".to_owned(), PermissionLevel::Write),
            ]),
        },
        lane: DeliveryLane::Proxy,
        runner_adapter: "github.api/v1".to_owned(),
        mint_adapter: "github.app-installation/v1".to_owned(),
    };

    let reconcile = ActionDefinition {
        input_schema: json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": false,
            "required": ["repository", "head_ref", "base_ref"],
            "properties": {
                "repository": {
                    "type": "string",
                    "pattern": "^github:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$",
                    "maxLength": 147
                },
                "head_ref": {
                    "type": "string",
                    "pattern": "^refs/heads/.+$",
                    "maxLength": 255
                },
                "base_ref": {"const": "refs/heads/main"}
            }
        }),
        artifact_required: false,
        need: NeedTemplate {
            provider: "github".to_owned(),
            repository_field: "repository".to_owned(),
            destination_ref_field: None,
            permissions: BTreeMap::from([
                ("checks".to_owned(), PermissionLevel::Read),
                ("contents".to_owned(), PermissionLevel::Read),
                ("metadata".to_owned(), PermissionLevel::Read),
                ("pull_requests".to_owned(), PermissionLevel::Read),
            ]),
        },
        lane: DeliveryLane::Proxy,
        runner_adapter: "github.api/v1".to_owned(),
        mint_adapter: "github.app-installation/v1".to_owned(),
    };

    ProviderPack {
        schema: PACK_SCHEMA.to_owned(),
        address: GITHUB_PACK_ADDRESS.to_owned(),
        version: GITHUB_PACK_VERSION,
        publisher: publisher.into(),
        credential_class: CredentialClass::NativeAttenuation,
        actions: BTreeMap::from([
            (GITHUB_PUBLISH_REF_ACTION.to_owned(), publish),
            (GITHUB_PULL_REQUEST_CREATE_ACTION.to_owned(), pull_request),
            (
                GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION.to_owned(),
                reconcile,
            ),
        ]),
    }
}

fn validate_pack_shape(pack: &ProviderPack) -> Result<(), PackError> {
    if pack.schema != PACK_SCHEMA
        || pack.address.is_empty()
        || pack.address.len() > 200
        || pack.version == 0
        || pack.publisher.is_empty()
        || pack.credential_class != CredentialClass::NativeAttenuation
        || pack.actions.is_empty()
    {
        return Err(PackError::InvalidPack);
    }
    for (key, action) in &pack.actions {
        if key.is_empty()
            || key.len() > 200
            || action.need.provider.is_empty()
            || action.need.permissions.is_empty()
            || action.runner_adapter.is_empty()
            || action.mint_adapter.is_empty()
        {
            return Err(PackError::InvalidPack);
        }
        JSONSchema::compile(&action.input_schema)
            .map_err(|error| PackError::InvalidInputSchema(error.to_string()))?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("pack shape is invalid")]
    InvalidPack,
    #[error("pack input schema is invalid: {0}")]
    InvalidInputSchema(String),
    #[error("pack canonicalization failed: {0}")]
    Canonicalize(serde_json::Error),
    #[error("pack signer is unknown")]
    UnknownPublisher,
    #[error("pack publisher is outside its trust window or revoked")]
    PublisherNotTrusted,
    #[error("pack signature is invalid")]
    InvalidSignature,
    #[error("pack address and version are already installed")]
    AlreadyInstalled,
    #[error("request schema is unknown")]
    UnknownRequestSchema,
    #[error("pack is not installed")]
    UnknownPack,
    #[error("action is not installed")]
    UnknownAction,
    #[error("typed action input is invalid: {0}")]
    InvalidInput(String),
    #[error("pack could not derive a complete need")]
    NeedDerivation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ACTION_REQUEST_SCHEMA, ActionRequest};

    fn signed_pack() -> (SigningKey, SignedProviderPack) {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let signed =
            SignedProviderPack::sign(github_pack_v2("did:key:test"), "root", &key).unwrap();
        (key, signed)
    }

    fn registry_with_github_pack() -> PackRegistry {
        let (key, signed) = signed_pack();
        let mut trust = PackTrustStore::default();
        trust.insert(
            "root",
            TrustedPublisher {
                publisher: "did:key:test".to_owned(),
                verifying_key: key.verifying_key(),
                not_before_unix: 10,
                not_after_unix: 20,
                revoked: false,
            },
        );
        let mut registry = PackRegistry::default();
        registry.install(trust.verify(signed, 15).unwrap()).unwrap();
        registry
    }

    #[test]
    fn verifies_signature_and_derives_need_from_typed_input() {
        let (key, signed) = signed_pack();
        let mut trust = PackTrustStore::default();
        trust.insert(
            "root",
            TrustedPublisher {
                publisher: "did:key:test".to_owned(),
                verifying_key: key.verifying_key(),
                not_before_unix: 10,
                not_after_unix: 20,
                revoked: false,
            },
        );
        let installed = trust.verify(signed, 15).unwrap();
        let mut registry = PackRegistry::default();
        registry.install(installed).unwrap();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_PUBLISH_REF_ACTION,
            "input": {
                "repository": "github:EmberDotLink/Ember",
                "artifact": format!("artifact:sha256:{}", "a".repeat(64)),
                "expected_old_oid": "0".repeat(40),
                "new_oid": "a".repeat(40),
                "destination_ref": "refs/heads/ws/test"
            }
        }))
        .unwrap();
        let resolved = registry.resolve(&request).unwrap();
        assert_eq!(
            resolved.need,
            Need {
                provider: "github".to_owned(),
                repository: "github:emberdotlink/ember".parse().unwrap(),
                destination_ref: Some("refs/heads/ws/test".parse().unwrap()),
                permissions: BTreeMap::from([
                    ("contents".to_owned(), PermissionLevel::Write),
                    ("metadata".to_owned(), PermissionLevel::Read),
                ]),
            }
        );
        assert_eq!(
            resolved.input,
            json!({
                "repository": "github:emberdotlink/ember",
                "artifact": format!("artifact:sha256:{}", "a".repeat(64)),
                "expected_old_oid": "0".repeat(40),
                "new_oid": "a".repeat(40),
                "destination_ref": "refs/heads/ws/test",
            })
        );
        assert_eq!(resolved.key, GITHUB_PUBLISH_REF_ACTION);
    }

    #[test]
    fn resolves_pull_request_with_head_need_and_canonical_input() {
        let registry = registry_with_github_pack();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_PULL_REQUEST_CREATE_ACTION,
            "input": {
                "repository": "github:Acme/Planning",
                "head_ref": "refs/heads/ws/alpha/planner-7",
                "base_ref": "refs/heads/main",
                "title": "wb: alpha planner-7",
                "body": "",
            }
        }))
        .unwrap();

        let resolved = registry.resolve(&request).unwrap();

        assert_eq!(
            resolved.need,
            Need {
                provider: "github".to_owned(),
                repository: "github:acme/planning".parse().unwrap(),
                destination_ref: Some("refs/heads/ws/alpha/planner-7".parse().unwrap()),
                permissions: BTreeMap::from([
                    ("contents".to_owned(), PermissionLevel::Read),
                    ("metadata".to_owned(), PermissionLevel::Read),
                    ("pull_requests".to_owned(), PermissionLevel::Write),
                ]),
            }
        );
        assert_eq!(
            resolved.input,
            json!({
                "repository": "github:acme/planning",
                "head_ref": "refs/heads/ws/alpha/planner-7",
                "base_ref": "refs/heads/main",
                "title": "wb: alpha planner-7",
                "body": "",
            })
        );
        assert_eq!(resolved.key, GITHUB_PULL_REQUEST_CREATE_ACTION);
    }

    #[test]
    fn pull_request_title_and_body_constraints_fail_closed() {
        let registry = registry_with_github_pack();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_PULL_REQUEST_CREATE_ACTION,
            "input": {
                "repository": "github:acme/planning",
                "head_ref": "refs/heads/ws/alpha/planner-7",
                "base_ref": "refs/heads/main",
                "title": "wb: alpha planner-7",
                "body": "",
            }
        }))
        .unwrap();

        let mut invalid_title = request.clone();
        invalid_title.input["title"] = Value::String("unreviewed title".to_owned());
        assert!(matches!(
            registry.resolve(&invalid_title),
            Err(PackError::InvalidInput(_))
        ));

        let mut nonempty_body = request;
        nonempty_body.input["body"] = Value::String("attacker-controlled body".to_owned());
        assert!(matches!(
            registry.resolve(&nonempty_body),
            Err(PackError::InvalidInput(_))
        ));
    }

    #[test]
    fn resolves_reconcile_without_destination_need_and_canonical_input() {
        let registry = registry_with_github_pack();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION,
            "input": {
                "repository": "github:Acme/Planning",
                "head_ref": "refs/heads/ws/alpha/builder-3",
                "base_ref": "refs/heads/main",
            }
        }))
        .unwrap();

        let resolved = registry.resolve(&request).unwrap();

        assert_eq!(
            resolved.need,
            Need {
                provider: "github".to_owned(),
                repository: "github:acme/planning".parse().unwrap(),
                destination_ref: None,
                permissions: BTreeMap::from([
                    ("checks".to_owned(), PermissionLevel::Read),
                    ("contents".to_owned(), PermissionLevel::Read),
                    ("metadata".to_owned(), PermissionLevel::Read),
                    ("pull_requests".to_owned(), PermissionLevel::Read),
                ]),
            }
        );
        assert_eq!(
            resolved.input,
            json!({
                "repository": "github:acme/planning",
                "head_ref": "refs/heads/ws/alpha/builder-3",
                "base_ref": "refs/heads/main",
            })
        );
        assert_eq!(resolved.key, GITHUB_RECONCILE_REPOSITORY_FACTS_ACTION);
    }

    #[test]
    fn pull_request_need_includes_ref_read_access() {
        let (key, signed) = signed_pack();
        let mut trust = PackTrustStore::default();
        trust.insert(
            "root",
            TrustedPublisher {
                publisher: "did:key:test".to_owned(),
                verifying_key: key.verifying_key(),
                not_before_unix: 10,
                not_after_unix: 20,
                revoked: false,
            },
        );
        let installed = trust.verify(signed, 15).unwrap();
        let mut registry = PackRegistry::default();
        registry.install(installed).unwrap();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_PULL_REQUEST_CREATE_ACTION,
            "input": {
                "repository": "github:acme/planning",
                "head_ref": "refs/heads/ws/widget/planner-1",
                "base_ref": "refs/heads/main",
                "title": "wb: widget planner-1",
                "body": ""
            }
        }))
        .unwrap();

        let resolved = registry.resolve(&request).unwrap();
        assert_eq!(
            resolved.need.permissions,
            BTreeMap::from([
                ("contents".to_owned(), PermissionLevel::Read),
                ("metadata".to_owned(), PermissionLevel::Read),
                ("pull_requests".to_owned(), PermissionLevel::Write),
            ])
        );
    }

    #[test]
    fn unsupported_credential_classes_are_refused() {
        let mut pack = github_pack_v2("did:key:test");
        pack.credential_class = CredentialClass::StaticSecret;
        assert!(matches!(
            validate_pack_shape(&pack),
            Err(PackError::InvalidPack)
        ));

        pack.credential_class = CredentialClass::KeyCustody;
        assert!(matches!(
            validate_pack_shape(&pack),
            Err(PackError::InvalidPack)
        ));
    }

    #[test]
    fn signature_tampering_and_extra_input_fail_closed() {
        let (key, mut signed) = signed_pack();
        signed
            .pack
            .actions
            .get_mut(GITHUB_PUBLISH_REF_ACTION)
            .unwrap()
            .runner_adapter = "attacker".to_owned();
        let mut trust = PackTrustStore::default();
        trust.insert(
            "root",
            TrustedPublisher {
                publisher: "did:key:test".to_owned(),
                verifying_key: key.verifying_key(),
                not_before_unix: 0,
                not_after_unix: 100,
                revoked: false,
            },
        );
        assert!(matches!(
            trust.verify(signed, 1),
            Err(PackError::InvalidSignature)
        ));

        let (_, signed) = signed_pack();
        let installed = trust.verify(signed, 1).unwrap();
        let mut registry = PackRegistry::default();
        registry.install(installed).unwrap();
        let request: ActionRequest = serde_json::from_value(json!({
            "schema": ACTION_REQUEST_SCHEMA,
            "pack": {"address": GITHUB_PACK_ADDRESS, "version": GITHUB_PACK_VERSION},
            "action": GITHUB_PUBLISH_REF_ACTION,
            "input": {
                "repository": "github:emberdotlink/ember",
                "artifact": format!("artifact:sha256:{}", "a".repeat(64)),
                "expected_old_oid": "0".repeat(40),
                "new_oid": "1".repeat(40),
                "destination_ref": "refs/heads/ws/test",
                "cwd": "/tmp/attacker"
            }
        }))
        .unwrap();
        assert!(matches!(
            registry.resolve(&request),
            Err(PackError::InvalidInput(_))
        ));
    }
}
