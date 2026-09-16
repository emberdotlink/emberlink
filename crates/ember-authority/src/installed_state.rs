//! Strict RFC 8785 wire types shared by installation and daemon loading.
//!
//! Persona authority and launch policy are deliberately separate: a reviewed
//! executable may start or host a Session, but executable identity never
//! creates or selects Persona authority.

use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

use crate::principal::MAX_PERSONAS;

pub(crate) const DAEMON_CONFIG_SCHEMA: &str = "ember.daemon-config/v4";
pub(crate) const INSTALLED_AUTHORITY_STATE_SCHEMA: &str = "ember.installed-authority-state/v4";
pub(crate) const INSTALLED_STATE_ACTIVATION: &str = "load-owner-private-installed-state-v4";
pub(crate) const ACTIVATION_MARKER_SCHEMA: &str = "ember.authority-activation/v4";
pub const INSTALL_REQUEST_SCHEMA: &str = "ember.authority-install-request/v4";
pub const INSTALL_RESULT_SCHEMA: &str = "ember.authority-install-result/v3";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub schema: String,
    pub state_directory: PathBuf,
    pub daemon_uid: u32,
    pub personas: Vec<PersonaWire>,
    pub launch_policy: LaunchPolicyWire,
    pub reviewed_executables: ReviewedExecutablesWire,
    pub founder_key: FounderKeyInput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaWire {
    pub persona_id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedExecutableWire {
    pub path: PathBuf,
    pub digest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedExecutablesWire {
    pub git: ReviewedExecutableWire,
    pub askpass: ReviewedExecutableWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicyWire {
    /// Installer-provisioned group shared by the daemon and authorized clients.
    pub client_gid: u32,
    pub launchers: Vec<LauncherIdentityWire>,
    pub session_executables: Vec<SessionExecutableIdentityWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherIdentityWire {
    pub uid: u32,
    pub gid: u32,
    pub executable: ReviewedExecutableWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionExecutableIdentityWire {
    pub persona_id: String,
    pub uid: u32,
    pub gid: u32,
    pub executable: ReviewedExecutableWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum FounderKeyInput {
    Enroll { policy: FounderPolicyInput },
    Lookup { public_key_path: PathBuf },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FounderPolicyInput {
    UserPresence,
    BiometryCurrentSet,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallResult {
    pub schema: String,
    pub state_directory: PathBuf,
    pub daemon_config_path: PathBuf,
    pub installed_state_path: PathBuf,
    pub installation_proof_path: PathBuf,
    pub founder_public_key_path: PathBuf,
    pub signed_pack_path: PathBuf,
    pub activation_marker_path: PathBuf,
    pub daemon_config_sha256: String,
    pub installed_state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonConfigWire {
    pub(crate) schema: String,
    pub(crate) daemon_uid: u32,
    pub(crate) socket: SocketWire,
    pub(crate) storage: StorageWire,
    pub(crate) custody: DaemonCustodyWire,
    pub(crate) operational_evidence: OperationalEvidenceWire,
    pub(crate) trust_roots: Vec<TrustRootWire>,
    pub(crate) signed_pack_paths: Vec<PathBuf>,
    pub(crate) reviewed_executables: ReviewedExecutablesWire,
    pub(crate) launch_policy: LaunchPolicyWire,
    pub(crate) installed_authority: InstalledAuthorityWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SocketWire {
    pub(crate) path: PathBuf,
    pub(crate) mode: u32,
    pub(crate) max_header_bytes: u32,
    pub(crate) max_artifact_bytes: u64,
    pub(crate) io_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StorageWire {
    pub(crate) artifact_root: PathBuf,
    pub(crate) audit_root: PathBuf,
    pub(crate) audit_high_water_path: PathBuf,
    pub(crate) recovery_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonCustodyWire {
    pub(crate) recovery_key_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationalEvidenceWire {
    pub(crate) private_key_path: PathBuf,
    pub(crate) payload_seal_key_path: PathBuf,
    pub(crate) generation_id_hex: String,
    pub(crate) public_key_hex: String,
    pub(crate) vault_id_hex: String,
    pub(crate) device_id_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustRootWire {
    pub(crate) key_id: String,
    pub(crate) publisher: String,
    pub(crate) verifying_key_hex: String,
    pub(crate) not_before_unix: i64,
    pub(crate) not_after_unix: i64,
    pub(crate) revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledAuthorityWire {
    pub(crate) state_path: PathBuf,
    pub(crate) proof_path: PathBuf,
    pub(crate) enrolled_public_key_path: PathBuf,
    pub(crate) nonce_store_root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorityStateWire {
    pub(crate) schema: String,
    pub(crate) activation: String,
    pub(crate) daemon_config_sha256: String,
    pub(crate) personas: Vec<PersonaWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationMarkerWire {
    pub(crate) schema: String,
    pub(crate) daemon_config_sha256: String,
    pub(crate) installed_state_sha256: String,
}

pub(crate) fn decode_install_request(bytes: &[u8]) -> Result<InstallRequest, InstalledStateError> {
    let request: InstallRequest = decode_jcs(bytes)?;
    if request.schema != INSTALL_REQUEST_SCHEMA {
        return Err(InstalledStateError::WrongSchema);
    }
    Ok(request)
}

pub(crate) fn decode_daemon_config(bytes: &[u8]) -> Result<DaemonConfigWire, InstalledStateError> {
    let config: DaemonConfigWire = decode_jcs(bytes)?;
    config.validate()?;
    Ok(config)
}

pub(crate) fn decode_authority_state(
    bytes: &[u8],
) -> Result<AuthorityStateWire, InstalledStateError> {
    let state: AuthorityStateWire = decode_jcs(bytes)?;
    state.validate()?;
    Ok(state)
}

pub(crate) fn decode_activation_marker(
    bytes: &[u8],
) -> Result<ActivationMarkerWire, InstalledStateError> {
    let marker: ActivationMarkerWire = decode_jcs(bytes)?;
    marker.validate()?;
    Ok(marker)
}

fn decode_jcs<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, InstalledStateError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if serde_jcs::to_vec(&value)? != bytes {
        return Err(InstalledStateError::NonCanonical);
    }
    Ok(serde_json::from_value(value)?)
}

impl DaemonConfigWire {
    pub(crate) fn validate(&self) -> Result<(), InstalledStateError> {
        if self.schema != DAEMON_CONFIG_SCHEMA
            || self.daemon_uid == 0
            || self.socket.mode != 0o660
            || self.socket.max_header_bytes == 0
            || self.socket.max_artifact_bytes == 0
            || self.socket.io_timeout_seconds == 0
            || self.trust_roots.is_empty()
            || self.signed_pack_paths.is_empty()
            || !is_lower_sha256(&self.operational_evidence.generation_id_hex)
            || !is_lower_sha256(&self.operational_evidence.public_key_hex)
            || !is_lower_sha256(&self.operational_evidence.vault_id_hex)
            || !is_lower_sha256(&self.operational_evidence.device_id_hex)
        {
            return Err(InstalledStateError::InvalidState);
        }
        for path in self.paths() {
            validate_clean_absolute(path)?;
        }
        validate_reviewed_executable_shape(&self.reviewed_executables.git)?;
        validate_reviewed_executable_shape(&self.reviewed_executables.askpass)?;
        validate_launch_policy_shape(&self.launch_policy, None)?;
        Ok(())
    }

    fn paths(&self) -> Vec<&Path> {
        let mut paths = vec![
            self.socket.path.as_path(),
            self.storage.artifact_root.as_path(),
            self.storage.audit_root.as_path(),
            self.storage.audit_high_water_path.as_path(),
            self.storage.recovery_root.as_path(),
            self.custody.recovery_key_path.as_path(),
            self.operational_evidence.private_key_path.as_path(),
            self.operational_evidence.payload_seal_key_path.as_path(),
            self.installed_authority.state_path.as_path(),
            self.installed_authority.proof_path.as_path(),
            self.installed_authority.enrolled_public_key_path.as_path(),
            self.installed_authority.nonce_store_root.as_path(),
        ];
        paths.extend(self.signed_pack_paths.iter().map(PathBuf::as_path));
        paths
    }
}

impl AuthorityStateWire {
    pub(crate) fn validate(&self) -> Result<(), InstalledStateError> {
        if self.schema != INSTALLED_AUTHORITY_STATE_SCHEMA
            || self.activation != INSTALLED_STATE_ACTIVATION
            || !is_lower_sha256(&self.daemon_config_sha256)
        {
            return Err(InstalledStateError::InvalidState);
        }
        validate_personas(&self.personas)
    }
}

impl ActivationMarkerWire {
    pub(crate) fn validate(&self) -> Result<(), InstalledStateError> {
        if self.schema != ACTIVATION_MARKER_SCHEMA
            || !is_lower_sha256(&self.daemon_config_sha256)
            || !is_lower_sha256(&self.installed_state_sha256)
        {
            return Err(InstalledStateError::InvalidState);
        }
        Ok(())
    }
}

pub(crate) fn validate_personas(personas: &[PersonaWire]) -> Result<(), InstalledStateError> {
    if personas.is_empty() || personas.len() > MAX_PERSONAS {
        return Err(InstalledStateError::InvalidState);
    }
    let mut persona_ids = BTreeSet::new();
    let mut persona_names = BTreeSet::new();
    for persona in personas {
        if parse_non_nil_uuid(&persona.persona_id).is_none()
            || persona.name.is_empty()
            || persona.name.len() > 100
            || persona.name.trim() != persona.name
            || !persona_ids.insert(persona.persona_id.as_str())
            || !persona_names.insert(persona.name.as_str())
        {
            return Err(InstalledStateError::InvalidState);
        }
    }
    Ok(())
}

pub(crate) fn validate_launch_policy_shape(
    policy: &LaunchPolicyWire,
    persona_ids: Option<&BTreeSet<&str>>,
) -> Result<(), InstalledStateError> {
    let Some(founder) = policy.launchers.first() else {
        return Err(InstalledStateError::InvalidState);
    };
    if policy.session_executables.is_empty()
        || policy
            .launchers
            .iter()
            .any(|launcher| launcher.uid != founder.uid || launcher.gid != founder.gid)
        || policy
            .session_executables
            .iter()
            .any(|session| session.uid != founder.uid || session.gid != founder.gid)
    {
        return Err(InstalledStateError::InvalidState);
    }
    let mut launchers = BTreeSet::new();
    for launcher in &policy.launchers {
        validate_reviewed_executable_shape(&launcher.executable)?;
        if !launchers.insert((
            launcher.uid,
            launcher.gid,
            launcher.executable.path.as_path(),
            launcher.executable.digest_sha256.as_str(),
        )) {
            return Err(InstalledStateError::InvalidState);
        }
    }
    let mut sessions = BTreeSet::new();
    for session in &policy.session_executables {
        validate_reviewed_executable_shape(&session.executable)?;
        if parse_non_nil_uuid(&session.persona_id).is_none()
            || persona_ids.is_some_and(|ids| !ids.contains(session.persona_id.as_str()))
            || !sessions.insert((
                session.persona_id.as_str(),
                session.uid,
                session.gid,
                session.executable.path.as_path(),
                session.executable.digest_sha256.as_str(),
            ))
        {
            return Err(InstalledStateError::InvalidState);
        }
    }
    Ok(())
}

pub(crate) fn validate_reviewed_executable_shape(
    executable: &ReviewedExecutableWire,
) -> Result<(), InstalledStateError> {
    validate_clean_absolute(&executable.path)?;
    if !is_lower_sha256(&executable.digest_sha256) {
        return Err(InstalledStateError::InvalidState);
    }
    Ok(())
}

pub(crate) fn validate_clean_absolute(path: &Path) -> Result<(), InstalledStateError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(InstalledStateError::InvalidState);
    }
    Ok(())
}

pub(crate) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_non_nil_uuid(value: &str) -> Option<Uuid> {
    let parsed = Uuid::parse_str(value).ok()?;
    (!parsed.is_nil() && parsed.to_string() == value).then_some(parsed)
}

#[derive(Debug, Error)]
pub(crate) enum InstalledStateError {
    #[error("wire bytes are not strict RFC 8785 JSON")]
    NonCanonical,
    #[error("wire schema is not the current installed-state schema")]
    WrongSchema,
    #[error("installed authority state is malformed")]
    InvalidState,
    #[error("JSON encoding is malformed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state_value() -> serde_json::Value {
        json!({
            "schema": INSTALLED_AUTHORITY_STATE_SCHEMA,
            "activation": INSTALLED_STATE_ACTIVATION,
            "daemon_config_sha256": "a".repeat(64),
            "personas": [{
                "persona_id": Uuid::from_u128(1).to_string(),
                "name": "writer"
            }]
        })
    }

    #[test]
    fn prior_unknown_and_saved_grant_authority_states_are_rejected() {
        for schema in [
            "ember.installed-authority-state/v1",
            "ember.installed-authority-state/v2",
            "ember.installed-authority-state/v3",
        ] {
            let mut prior = state_value();
            prior["schema"] = json!(schema);
            assert!(matches!(
                decode_authority_state(&serde_jcs::to_vec(&prior).unwrap()),
                Err(InstalledStateError::InvalidState)
            ));
        }

        let mut unknown = state_value();
        unknown["legacy_binding"] = json!(Uuid::new_v4());
        assert!(matches!(
            decode_authority_state(&serde_jcs::to_vec(&unknown).unwrap()),
            Err(InstalledStateError::Json(_))
        ));

        let mut saved_bundle = state_value();
        saved_bundle["grants"] = json!([]);
        assert!(matches!(
            decode_authority_state(&serde_jcs::to_vec(&saved_bundle).unwrap()),
            Err(InstalledStateError::Json(_))
        ));
    }

    #[test]
    fn malformed_generic_authority_state_is_rejected() {
        let mut duplicate_persona = state_value();
        let persona = duplicate_persona["personas"][0].clone();
        duplicate_persona["personas"]
            .as_array_mut()
            .unwrap()
            .push(persona);
        assert!(matches!(
            decode_authority_state(&serde_jcs::to_vec(&duplicate_persona).unwrap()),
            Err(InstalledStateError::InvalidState)
        ));
    }

    #[test]
    fn authority_state_capacity_is_enforced_before_activation() {
        let mut excessive_personas = state_value();
        let persona = excessive_personas["personas"][0].clone();
        let personas = excessive_personas["personas"].as_array_mut().unwrap();
        personas.clear();
        for ordinal in 0..=MAX_PERSONAS {
            let mut item = persona.clone();
            let persona_id = if ordinal == 0 {
                1
            } else {
                100 + ordinal as u128
            };
            item["persona_id"] = json!(Uuid::from_u128(persona_id).to_string());
            item["name"] = json!(format!("persona-{ordinal}"));
            personas.push(item);
        }
        assert!(matches!(
            decode_authority_state(&serde_jcs::to_vec(&excessive_personas).unwrap()),
            Err(InstalledStateError::InvalidState)
        ));
    }
}
