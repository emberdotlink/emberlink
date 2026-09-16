use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    time::Duration,
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub(crate) const MAX_PERSONAS: usize = 256;
pub(crate) const MAX_GRANTS: usize = 4_096;
pub(crate) const MAX_ACTIVE_SESSIONS: usize = 1_024;
pub(crate) const MAX_ACTIVE_DELEGATIONS: usize = 4_096;
pub(crate) const MAX_ACTIVE_BINDINGS: usize = MAX_ACTIVE_SESSIONS;
pub(crate) const MAX_SELECTED_GRANT_TTL_SECONDS: u64 = 24 * 60 * 60;

use crate::{
    catalog::{
        CredentialId, CustodyProfile, GithubAppSubject, Kind, MaterialKeyReference,
        RevisionCommitment, RevisionId,
    },
    model::{
        DelegationId, GitRef, GrantId, Need, PackRef, PermissionLevel, PersonaId, ProcessBindingId,
        RepositoryResource, SessionId,
    },
};

/// A SHA-256 digest measured over a daemon-reviewed executable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExecutableDigest([u8; 32]);

impl ExecutableDigest {
    pub fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_sha256_hex(value: &str) -> Result<Self, AuthorityError> {
        let bytes = hex::decode(value).map_err(|_| AuthorityError::InvalidExecutableDigest)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuthorityError::InvalidExecutableDigest)?;
        Ok(Self(bytes))
    }

    pub fn to_sha256_hex(self) -> String {
        hex::encode(self.0)
    }
}
/// Exact process coordinates measured by the daemon and trusted launcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessOrigin {
    pid: u32,
    pid_version: u64,
    euid: u32,
    egid: u32,
    executable_digest: ExecutableDigest,
}

impl ProcessOrigin {
    pub fn new(
        pid: u32,
        pid_version: u64,
        euid: u32,
        egid: u32,
        executable_digest: ExecutableDigest,
    ) -> Result<Self, AuthorityError> {
        if pid == 0 || pid_version == 0 {
            return Err(AuthorityError::InvalidObservedProcess);
        }
        Ok(Self {
            pid,
            pid_version,
            euid,
            egid,
            executable_digest,
        })
    }
}

/// Presence-sensitive root authority transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresenceOperation {
    InstallPersona,
    InstallGrant {
        persona: PersonaId,
    },
    AttachSelectedGrants {
        session: SessionId,
        grants: Vec<GrantSummary>,
        delegation_ids: Vec<DelegationId>,
        requested_ttl_seconds: u64,
    },
    EnrollCredential {
        credential_id: CredentialId,
        revision_id: RevisionId,
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
        commitment: RevisionCommitment,
        key_reference: MaterialKeyReference,
    },
    RotateCredential {
        credential_id: CredentialId,
        current_revision_id: RevisionId,
        current_commitment: RevisionCommitment,
        new_revision_id: RevisionId,
        new_commitment: RevisionCommitment,
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
        key_reference: MaterialKeyReference,
    },
    DeleteCredential {
        credential_id: CredentialId,
        current_revision_id: RevisionId,
        current_commitment: RevisionCommitment,
        kind: Kind,
        subject: GithubAppSubject,
        custody_profile: CustodyProfile,
    },
}

pub trait PresenceVerifier {
    fn verify_presence(&mut self, operation: &PresenceOperation) -> bool;
}

/// Immutable authority ceiling owned by one Persona.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantInstallation {
    persona: PersonaId,
    scope: Scope,
}

impl GrantInstallation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        persona: PersonaId,
        pack: PackRef,
        action: impl Into<String>,
        provider: impl Into<String>,
        repository: RepositoryResource,
        destination_ref_prefix: Option<String>,
        permissions: BTreeMap<String, PermissionLevel>,
        not_before_unix: i64,
        expires_at_unix: i64,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            persona,
            scope: Scope::new(
                pack,
                action,
                provider,
                repository,
                destination_ref_prefix,
                permissions,
                not_before_unix,
                expires_at_unix,
            )?,
        })
    }
}

/// One installed Grant selected for Session attachment, optionally narrowed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantSelection {
    grant_id: GrantId,
    destination_ref_prefix: Option<String>,
    permissions: Option<BTreeMap<String, PermissionLevel>>,
}

impl GrantSelection {
    pub fn whole(grant_id: GrantId) -> Self {
        Self {
            grant_id,
            destination_ref_prefix: None,
            permissions: None,
        }
    }

    pub fn narrowed(
        grant_id: GrantId,
        destination_ref_prefix: Option<String>,
        permissions: Option<BTreeMap<String, PermissionLevel>>,
    ) -> Self {
        Self {
            grant_id,
            destination_ref_prefix,
            permissions,
        }
    }

    pub fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Scope {
    pack: PackRef,
    action: String,
    provider: String,
    repository: RepositoryResource,
    destination_ref_prefix: Option<String>,
    permissions: BTreeMap<String, PermissionLevel>,
    not_before_unix: i64,
    expires_at_unix: i64,
}

impl Scope {
    #[allow(clippy::too_many_arguments)]
    fn new(
        pack: PackRef,
        action: impl Into<String>,
        provider: impl Into<String>,
        repository: RepositoryResource,
        destination_ref_prefix: Option<String>,
        permissions: BTreeMap<String, PermissionLevel>,
        not_before_unix: i64,
        expires_at_unix: i64,
    ) -> Result<Self, AuthorityError> {
        let action = action.into();
        let provider = provider.into();
        if action.is_empty()
            || provider.is_empty()
            || not_before_unix >= expires_at_unix
            || destination_ref_prefix
                .as_deref()
                .is_some_and(|prefix| !valid_ref_prefix(prefix))
        {
            return Err(AuthorityError::InvalidAuthorityScope);
        }
        Ok(Self {
            pack,
            action,
            provider,
            repository,
            destination_ref_prefix,
            permissions,
            not_before_unix,
            expires_at_unix,
        })
    }

    fn admits(&self, pack: &PackRef, action: &str, need: &Need, now_unix: i64) -> bool {
        now_unix >= self.not_before_unix
            && now_unix < self.expires_at_unix
            && self.pack == *pack
            && self.action == action
            && self.provider == need.provider
            && self.repository == need.repository
            && destination_ref_fits(
                need.destination_ref.as_ref(),
                self.destination_ref_prefix.as_deref(),
            )
            && permissions_fit(&need.permissions, &self.permissions)
    }

    fn matches_coordinates(
        &self,
        pack: &PackRef,
        action: &str,
        need: &Need,
        now_unix: i64,
    ) -> bool {
        now_unix >= self.not_before_unix
            && now_unix < self.expires_at_unix
            && self.pack == *pack
            && self.action == action
            && self.provider == need.provider
            && self.repository == need.repository
            && destination_ref_fits(
                need.destination_ref.as_ref(),
                self.destination_ref_prefix.as_deref(),
            )
    }
}

#[derive(Clone, Debug, Default)]
struct PersonaRecord;

#[derive(Clone, Debug)]
struct GrantRecord {
    persona: PersonaId,
    scope: Scope,
    revoked: bool,
}
/// Immutable, non-secret description of one installed Grant ceiling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GrantSummary {
    grant_id: GrantId,
    persona_id: PersonaId,
    pack: PackRef,
    action: String,
    provider: String,
    repository: RepositoryResource,
    destination_ref_prefix: Option<String>,
    permissions: BTreeMap<String, PermissionLevel>,
    not_before_unix: i64,
    expires_at_unix: i64,
    revoked: bool,
}

impl GrantSummary {
    pub(crate) fn founder_presence_summary(&self) -> String {
        let destination = self.destination_ref_prefix.as_deref().unwrap_or("any ref");
        let permissions = self
            .permissions
            .iter()
            .map(|(name, level)| {
                let level = match level {
                    PermissionLevel::Read => "read",
                    PermissionLevel::Write => "write",
                };
                format!("{name}:{level}")
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}; action={}; destination={}; permissions={}",
            self.repository, self.action, destination, permissions
        )
    }
}

impl fmt::Display for GrantSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Grant {} for Persona {}: pack={}@{}, action={}, provider={}, repository={}, \
             destination_ref_prefix={:?}, permissions={:?}, validity=[{}, {}), revoked={}",
            self.grant_id,
            self.persona_id,
            self.pack.address,
            self.pack.version,
            self.action,
            self.provider,
            self.repository,
            self.destination_ref_prefix,
            self.permissions,
            self.not_before_unix,
            self.expires_at_unix,
            self.revoked,
        )
    }
}

#[derive(Clone, Debug)]
struct SessionRecord {
    persona: PersonaId,
    reviewed_executable: ExecutableDigest,
    registration_commitment: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct DelegationRecord {
    session: SessionId,
    binding: ProcessBindingId,
    grant: GrantId,
    scope: Scope,
    revoked: bool,
}

#[derive(Clone, Debug)]
struct ProcessBindingRecord {
    session: SessionId,
    origin: ProcessOrigin,
    reconnect_commitment: Option<[u8; 32]>,
}

/// One-time secret issued with a Session for its trusted launch report.
/// A binding attempt consumes it regardless of whether the report matches.
pub struct ProcessRegistrationChallenge([u8; 32]);

impl ProcessRegistrationChallenge {
    fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self(bytes)
    }

    fn commitment(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose_to_launcher(&self) -> [u8; 32] {
        self.0
    }
}

impl Zeroize for ProcessRegistrationChallenge {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ProcessRegistrationChallenge {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secret minted only after the exact registered process first connects.
/// It is not serializable, printable, or usable without matching kernel origin.
pub struct ReconnectProof([u8; 32]);

impl ReconnectProof {
    fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self(bytes)
    }

    fn commitment(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose_to_launcher(&self) -> [u8; 32] {
        self.0
    }
}

impl Zeroize for ReconnectProof {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ReconnectProof {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Connection-local proof of a verified, live originating Session.
#[derive(Debug, Eq, PartialEq)]
#[must_use = "dropping SessionContext discards this connection's authority handle"]
pub struct SessionContext {
    authority: Uuid,
    session: SessionId,
    binding: ProcessBindingId,
}

/// Identity established before action-specific Grant admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub persona_id: PersonaId,
    pub session_id: SessionId,
    pub process_binding_id: ProcessBindingId,
}

/// Exact identity and immutable authority path returned by use-time admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDecision {
    pub persona_id: PersonaId,
    pub session_id: SessionId,
    pub process_binding_id: ProcessBindingId,
    pub grant_id: GrantId,
    pub delegation_path: Vec<DelegationId>,
}

/// Persona, Grant, Session, Delegation, and Process Binding state.
pub struct PersonaAuthority {
    authority_id: Uuid,
    personas: HashMap<PersonaId, PersonaRecord>,
    grants: HashMap<GrantId, GrantRecord>,
    sessions: HashMap<SessionId, SessionRecord>,
    delegations: HashMap<DelegationId, DelegationRecord>,
    bindings: HashMap<ProcessBindingId, ProcessBindingRecord>,
}

impl Default for PersonaAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl PersonaAuthority {
    pub fn new() -> Self {
        Self {
            authority_id: Uuid::new_v4(),
            personas: HashMap::new(),
            grants: HashMap::new(),
            sessions: HashMap::new(),
            delegations: HashMap::new(),
            bindings: HashMap::new(),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "E4a leaves installed Persona restoration dormant until the E11 migration"
        )
    )]
    pub(crate) fn restore_persona(&mut self, persona: PersonaId) -> Result<(), AuthorityError> {
        if self.personas.len() >= MAX_PERSONAS && !self.personas.contains_key(&persona) {
            return Err(AuthorityError::PersonaCapacityExceeded);
        }
        self.personas.insert(persona, PersonaRecord);
        Ok(())
    }

    pub fn management(&mut self) -> PersonaManagement<'_> {
        PersonaManagement { authority: self }
    }

    pub fn sessions(&mut self) -> SessionAuthority<'_> {
        SessionAuthority { authority: self }
    }

    pub fn execution(&self) -> SessionExecution<'_> {
        SessionExecution { authority: self }
    }
    pub fn grant_summary(&self, grant: &GrantId) -> Result<GrantSummary, AuthorityError> {
        let record = self.grants.get(grant).ok_or(AuthorityError::UnknownGrant)?;
        Ok(summarize_grant(grant, record))
    }

    pub fn selected_grant_summaries(
        &self,
        selections: &[GrantSelection],
    ) -> Result<Vec<GrantSummary>, AuthorityError> {
        selections
            .iter()
            .map(|selection| {
                let record = self
                    .grants
                    .get(&selection.grant_id)
                    .ok_or(AuthorityError::UnknownGrant)?;
                let scope = narrowed_scope(record, selection)?;
                Ok(summarize_grant_scope(&selection.grant_id, record, &scope))
            })
            .collect()
    }

    fn remove_session_state(&mut self, session: &SessionId) -> Result<(), AuthorityError> {
        if !self.sessions.contains_key(session) {
            return Err(AuthorityError::UnknownSession);
        }
        self.delegations
            .retain(|_, record| record.session != *session);
        self.bindings
            .retain(|_, binding| binding.session != *session);
        self.sessions.remove(session);
        Ok(())
    }

    fn insert_grant(
        &mut self,
        grant: GrantId,
        installation: GrantInstallation,
    ) -> Result<(), AuthorityError> {
        if self.grants.len() >= MAX_GRANTS && !self.grants.contains_key(&grant) {
            return Err(AuthorityError::GrantCapacityExceeded);
        }
        if !self.personas.contains_key(&installation.persona) {
            return Err(AuthorityError::UnknownPersona);
        }
        self.grants.insert(
            grant,
            GrantRecord {
                persona: installation.persona,
                scope: installation.scope,
                revoked: false,
            },
        );
        Ok(())
    }
}

pub struct PersonaManagement<'a> {
    authority: &'a mut PersonaAuthority,
}

impl PersonaManagement<'_> {
    pub fn install_persona(
        &mut self,
        presence: &mut impl PresenceVerifier,
    ) -> Result<PersonaId, AuthorityError> {
        if self.authority.personas.len() >= MAX_PERSONAS {
            return Err(AuthorityError::PersonaCapacityExceeded);
        }
        require_presence(presence, PresenceOperation::InstallPersona)?;
        let persona = PersonaId::new();
        self.authority
            .personas
            .insert(persona.clone(), PersonaRecord);
        Ok(persona)
    }

    pub fn install_grant(
        &mut self,
        presence: &mut impl PresenceVerifier,
        installation: GrantInstallation,
    ) -> Result<GrantId, AuthorityError> {
        require_presence(
            presence,
            PresenceOperation::InstallGrant {
                persona: installation.persona.clone(),
            },
        )?;
        let grant = GrantId::new();
        self.authority.insert_grant(grant.clone(), installation)?;
        Ok(grant)
    }

    pub fn attach_selected_grants(
        &mut self,
        presence: &mut impl PresenceVerifier,
        session: &SessionId,
        grants: Vec<(DelegationId, GrantSelection)>,
        now_unix: i64,
        requested_ttl: Duration,
    ) -> Result<Vec<DelegationId>, AuthorityError> {
        let requested_ttl_seconds = requested_ttl.as_secs();
        if requested_ttl_seconds == 0
            || requested_ttl_seconds > MAX_SELECTED_GRANT_TTL_SECONDS
            || requested_ttl.subsec_nanos() != 0
        {
            return Err(AuthorityError::InvalidRequestedTtl);
        }
        if grants.len() > MAX_ACTIVE_DELEGATIONS {
            return Err(AuthorityError::DelegationCapacityExceeded);
        }
        if grants.is_empty() {
            return Err(AuthorityError::EmptyAttachmentBatch);
        }
        let mut unique_delegations = HashSet::with_capacity(grants.len());
        if grants
            .iter()
            .any(|(delegation, _)| !unique_delegations.insert(delegation.clone()))
        {
            return Err(AuthorityError::DuplicateDelegationAttachment);
        }
        if grants
            .iter()
            .any(|(delegation, _)| self.authority.delegations.contains_key(delegation))
        {
            return Err(AuthorityError::DuplicateDelegationAttachment);
        }
        if grants.len() > MAX_ACTIVE_DELEGATIONS.saturating_sub(self.authority.delegations.len()) {
            return Err(AuthorityError::DelegationCapacityExceeded);
        }
        let session_record = self
            .authority
            .sessions
            .get(session)
            .ok_or(AuthorityError::UnknownSession)?;
        let session_persona = session_record.persona.clone();
        let mut session_bindings = self
            .authority
            .bindings
            .iter()
            .filter(|(_, record)| record.session == *session);
        let binding = session_bindings
            .next()
            .map(|(binding, _)| binding.clone())
            .ok_or(AuthorityError::ProcessBindingRequired)?;
        if session_bindings.next().is_some() {
            return Err(AuthorityError::ProcessBindingRequired);
        }
        let requested_expires_at =
            now_unix.saturating_add(i64::try_from(requested_ttl_seconds).unwrap_or(i64::MAX));
        let mut unique_grants = HashSet::with_capacity(grants.len());
        let mut validated = Vec::with_capacity(grants.len());
        for (delegation, selection) in grants {
            let grant = selection.grant_id.clone();
            if !unique_grants.insert(grant.clone()) {
                return Err(AuthorityError::DuplicateGrantAttachment);
            }
            let record = self
                .authority
                .grants
                .get(&grant)
                .ok_or(AuthorityError::UnknownGrant)?;
            if record.revoked {
                return Err(AuthorityError::GrantRevoked);
            }
            if record.persona != session_persona {
                return Err(AuthorityError::PersonaMismatch);
            }
            let not_before_unix = now_unix.max(record.scope.not_before_unix);
            let expires_at_unix = requested_expires_at.min(record.scope.expires_at_unix);
            if not_before_unix >= expires_at_unix {
                return Err(AuthorityError::InactiveGrant);
            }
            let mut scope = narrowed_scope(record, &selection)?;
            let approved_scope = summarize_grant_scope(&grant, record, &scope);
            scope.not_before_unix = not_before_unix;
            scope.expires_at_unix = expires_at_unix;
            validated.push((delegation, grant.clone(), scope, approved_scope));
        }

        require_presence(
            presence,
            PresenceOperation::AttachSelectedGrants {
                session: session.clone(),
                grants: validated
                    .iter()
                    .map(|(_, _, _, summary)| summary.clone())
                    .collect(),
                delegation_ids: validated
                    .iter()
                    .map(|(delegation, _, _, _)| delegation.clone())
                    .collect(),
                requested_ttl_seconds,
            },
        )?;

        let mut installed = Vec::with_capacity(validated.len());
        for (delegation, grant, scope, _) in validated {
            let previous = self.authority.delegations.insert(
                delegation.clone(),
                DelegationRecord {
                    session: session.clone(),
                    binding: binding.clone(),
                    grant,
                    scope,
                    revoked: false,
                },
            );
            assert!(
                previous.is_none(),
                "validated Delegation ID was overwritten"
            );
            installed.push(delegation);
        }
        Ok(installed)
    }

    /// Revocation is deliberately not presence-gated.
    pub fn revoke_grant(&mut self, grant: &GrantId) -> Result<(), AuthorityError> {
        self.authority
            .grants
            .get_mut(grant)
            .ok_or(AuthorityError::UnknownGrant)?
            .revoked = true;
        Ok(())
    }

    /// Revocation is deliberately not presence-gated.
    pub fn revoke_delegation(&mut self, delegation: &DelegationId) -> Result<(), AuthorityError> {
        self.authority
            .delegations
            .get_mut(delegation)
            .ok_or(AuthorityError::UnknownDelegation)?
            .revoked = true;
        Ok(())
    }
}

pub struct SessionAuthority<'a> {
    authority: &'a mut PersonaAuthority,
}

impl SessionAuthority<'_> {
    pub fn create(
        &mut self,
        persona: &PersonaId,
        reviewed_executable: ExecutableDigest,
    ) -> Result<(SessionId, ProcessRegistrationChallenge), AuthorityError> {
        if !self.authority.personas.contains_key(persona) {
            return Err(AuthorityError::UnknownPersona);
        }
        if self.authority.sessions.len() >= MAX_ACTIVE_SESSIONS {
            return Err(AuthorityError::SessionCapacityExceeded);
        }
        let session = SessionId::new();
        let challenge = ProcessRegistrationChallenge::generate();
        self.authority.sessions.insert(
            session.clone(),
            SessionRecord {
                persona: persona.clone(),
                reviewed_executable,
                registration_commitment: Some(challenge.commitment()),
            },
        );
        Ok((session, challenge))
    }

    pub fn bind_origin(
        &mut self,
        session: &SessionId,
        challenge: &ProcessRegistrationChallenge,
        origin: ProcessOrigin,
    ) -> Result<ProcessBindingId, AuthorityError> {
        let binding_capacity_exceeded = self.authority.bindings.len() >= MAX_ACTIVE_BINDINGS;
        let report_error = {
            let session_record = self
                .authority
                .sessions
                .get_mut(session)
                .ok_or(AuthorityError::UnknownSession)?;
            let expected_commitment = session_record
                .registration_commitment
                .take()
                .ok_or(AuthorityError::ProcessRegistrationChallengeConsumed)?;
            if challenge.commitment() != expected_commitment {
                Some(AuthorityError::ProcessRegistrationChallengeMismatch)
            } else if session_record.reviewed_executable != origin.executable_digest {
                Some(AuthorityError::ExecutableDigestMismatch)
            } else if binding_capacity_exceeded {
                Some(AuthorityError::ProcessBindingCapacityExceeded)
            } else {
                None
            }
        };
        if let Some(error) = report_error {
            self.end_session(session)?;
            return Err(error);
        }

        let binding = ProcessBindingId::new();
        self.authority.bindings.insert(
            binding.clone(),
            ProcessBindingRecord {
                session: session.clone(),
                origin,
                reconnect_commitment: None,
            },
        );
        Ok(binding)
    }

    pub fn connect(
        &mut self,
        session: &SessionId,
        binding: &ProcessBindingId,
        origin: &ProcessOrigin,
        reconnect_proof: Option<&ReconnectProof>,
    ) -> Result<(SessionContext, Option<ReconnectProof>), AuthorityError> {
        let reviewed_executable = self
            .authority
            .sessions
            .get(session)
            .ok_or(AuthorityError::UnknownSession)?
            .reviewed_executable;
        let origin_mismatch = {
            let binding_record = self
                .authority
                .bindings
                .get(binding)
                .ok_or(AuthorityError::UnknownProcessBinding)?;
            binding_record.session != *session
                || binding_record.origin != *origin
                || reviewed_executable != origin.executable_digest
        };
        if origin_mismatch {
            self.end_session(session)?;
            return Err(AuthorityError::OriginMismatch);
        }
        let binding_record = self
            .authority
            .bindings
            .get_mut(binding)
            .ok_or(AuthorityError::UnknownProcessBinding)?;

        let issued_proof = if let Some(commitment) = binding_record.reconnect_commitment {
            let proof = reconnect_proof.ok_or(AuthorityError::ReconnectProofRequired)?;
            if proof.commitment() != commitment {
                return Err(AuthorityError::ReconnectProofMismatch);
            }
            None
        } else {
            if reconnect_proof.is_some() {
                return Err(AuthorityError::UnexpectedReconnectProof);
            }
            let proof = ReconnectProof::generate();
            binding_record.reconnect_commitment = Some(proof.commitment());
            Some(proof)
        };
        Ok((
            SessionContext {
                authority: self.authority.authority_id,
                session: session.clone(),
                binding: binding.clone(),
            },
            issued_proof,
        ))
    }

    /// Process exit is terminal for both the Process Binding and Session.
    pub fn end_origin(&mut self, binding: &ProcessBindingId) -> Result<SessionId, AuthorityError> {
        let session = self
            .authority
            .bindings
            .get(binding)
            .ok_or(AuthorityError::UnknownProcessBinding)?
            .session
            .clone();
        self.authority.remove_session_state(&session)?;
        Ok(session)
    }

    pub fn end_session(&mut self, session: &SessionId) -> Result<(), AuthorityError> {
        self.authority.remove_session_state(session)
    }
}

pub struct SessionExecution<'a> {
    authority: &'a PersonaAuthority,
}

impl SessionExecution<'_> {
    pub fn identify(&self, context: &SessionContext) -> Result<SessionId, AuthorityError> {
        if context.authority != self.authority.authority_id {
            return Err(AuthorityError::UnrecognizedSessionContext);
        }
        if !self.authority.sessions.contains_key(&context.session) {
            return Err(AuthorityError::UnknownSession);
        }
        let binding = self
            .authority
            .bindings
            .get(&context.binding)
            .ok_or(AuthorityError::UnknownProcessBinding)?;
        if binding.session != context.session {
            return Err(AuthorityError::UnrecognizedSessionContext);
        }
        Ok(context.session.clone())
    }

    pub fn identity(&self, context: &SessionContext) -> Result<SessionIdentity, AuthorityError> {
        let session_id = self.identify(context)?;
        let persona_id = self
            .authority
            .sessions
            .get(&session_id)
            .ok_or(AuthorityError::UnknownSession)?
            .persona
            .clone();
        Ok(SessionIdentity {
            persona_id,
            session_id,
            process_binding_id: context.binding.clone(),
        })
    }

    pub fn admit(
        &self,
        context: &SessionContext,
        pack: &PackRef,
        action: &str,
        need: &Need,
        now_unix: i64,
    ) -> Result<AuthorityDecision, AuthorityError> {
        let session_id = self.identify(context)?;
        let session = self
            .authority
            .sessions
            .get(&session_id)
            .ok_or(AuthorityError::UnknownSession)?;

        let coordinate_matches = self
            .authority
            .grants
            .iter()
            .filter(|(_, grant)| {
                !grant.revoked
                    && grant.persona == session.persona
                    && grant
                        .scope
                        .matches_coordinates(pack, action, need, now_unix)
            })
            .collect::<Vec<_>>();
        let applicable_grants = coordinate_matches
            .iter()
            .copied()
            .filter(|(_, grant)| permissions_fit(&need.permissions, &grant.scope.permissions))
            .collect::<Vec<_>>();
        let (grant_id, grant) = match applicable_grants.as_slice() {
            [] if permissions_union_fits(
                &need.permissions,
                coordinate_matches
                    .iter()
                    .map(|(_, grant)| &grant.scope.permissions),
            ) =>
            {
                return Err(AuthorityError::OverlappingGrant);
            }
            [] => return Err(AuthorityError::NoApplicableGrant),
            [(grant_id, grant)] => (*grant_id, *grant),
            _ => return Err(AuthorityError::AmbiguousGrant),
        };

        let delegations = self
            .authority
            .delegations
            .iter()
            .filter(|(_, delegation)| {
                !delegation.revoked
                    && delegation.session == session_id
                    && delegation.binding == context.binding
                    && delegation.grant == *grant_id
                    && delegation.scope.admits(pack, action, need, now_unix)
            })
            .collect::<Vec<_>>();
        let (delegation_id, _) = match delegations.as_slice() {
            [] => return Err(AuthorityError::NoApplicableDelegation),
            [(delegation_id, delegation)] => (*delegation_id, *delegation),
            _ => return Err(AuthorityError::AmbiguousDelegation),
        };
        debug_assert!(grant.scope.admits(pack, action, need, now_unix));
        Ok(AuthorityDecision {
            persona_id: session.persona.clone(),
            session_id,
            process_binding_id: context.binding.clone(),
            grant_id: grant_id.clone(),
            delegation_path: vec![delegation_id.clone()],
        })
    }
}

fn summarize_grant(grant: &GrantId, record: &GrantRecord) -> GrantSummary {
    GrantSummary {
        grant_id: grant.clone(),
        persona_id: record.persona.clone(),
        pack: record.scope.pack.clone(),
        action: record.scope.action.clone(),
        provider: record.scope.provider.clone(),
        repository: record.scope.repository.clone(),
        destination_ref_prefix: record.scope.destination_ref_prefix.clone(),
        permissions: record.scope.permissions.clone(),
        not_before_unix: record.scope.not_before_unix,
        expires_at_unix: record.scope.expires_at_unix,
        revoked: record.revoked,
    }
}

fn summarize_grant_scope(grant: &GrantId, record: &GrantRecord, scope: &Scope) -> GrantSummary {
    GrantSummary {
        grant_id: grant.clone(),
        persona_id: record.persona.clone(),
        pack: scope.pack.clone(),
        action: scope.action.clone(),
        provider: scope.provider.clone(),
        repository: scope.repository.clone(),
        destination_ref_prefix: scope.destination_ref_prefix.clone(),
        permissions: scope.permissions.clone(),
        not_before_unix: scope.not_before_unix,
        expires_at_unix: scope.expires_at_unix,
        revoked: record.revoked,
    }
}

fn narrowed_scope(
    record: &GrantRecord,
    selection: &GrantSelection,
) -> Result<Scope, AuthorityError> {
    let mut scope = record.scope.clone();
    if let Some(prefix) = &selection.destination_ref_prefix {
        if !valid_ref_prefix(prefix)
            || !ref_prefix_contains(record.scope.destination_ref_prefix.as_deref(), Some(prefix))
        {
            return Err(AuthorityError::InvalidAuthorityScope);
        }
        scope.destination_ref_prefix = Some(prefix.clone());
    }
    if let Some(permissions) = &selection.permissions {
        if !permissions_fit(permissions, &record.scope.permissions) {
            return Err(AuthorityError::InvalidAuthorityScope);
        }
        scope.permissions = permissions.clone();
    }
    Ok(scope)
}

fn require_presence(
    verifier: &mut impl PresenceVerifier,
    operation: PresenceOperation,
) -> Result<(), AuthorityError> {
    if verifier.verify_presence(&operation) {
        Ok(())
    } else {
        Err(AuthorityError::PresenceDenied)
    }
}

fn valid_ref_prefix(value: &str) -> bool {
    (value.starts_with("refs/heads/") || value.starts_with("refs/tags/"))
        && value.ends_with('/')
        && value.len() <= 255
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.bytes().any(|byte| {
            byte <= b' ' || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\' | 0x7f)
        })
}

fn ref_prefix_contains(parent: Option<&str>, child: Option<&str>) -> bool {
    match (parent, child) {
        (None, None) => true,
        (Some(parent), Some(child)) => child.starts_with(parent),
        _ => false,
    }
}

fn destination_ref_fits(need: Option<&GitRef>, ceiling: Option<&str>) -> bool {
    match (need, ceiling) {
        (None, None) => true,
        (Some(reference), Some(prefix)) => destination_ref_text_fits(reference.as_str(), prefix),
        _ => false,
    }
}

fn destination_ref_text_fits(reference: &str, prefix: &str) -> bool {
    reference.parse::<GitRef>().is_ok() && reference.starts_with(prefix)
}

fn permissions_fit(
    need: &BTreeMap<String, PermissionLevel>,
    ceiling: &BTreeMap<String, PermissionLevel>,
) -> bool {
    need.iter().all(|(permission, required)| {
        ceiling
            .get(permission)
            .is_some_and(|allowed| required <= allowed)
    })
}

fn permissions_union_fits<'a>(
    need: &BTreeMap<String, PermissionLevel>,
    ceilings: impl IntoIterator<Item = &'a BTreeMap<String, PermissionLevel>>,
) -> bool {
    let mut combined = BTreeMap::new();
    for ceiling in ceilings {
        for (name, level) in ceiling {
            combined
                .entry(name.clone())
                .and_modify(|current| {
                    if *current < *level {
                        *current = *level;
                    }
                })
                .or_insert(*level);
        }
    }
    permissions_fit(need, &combined)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuthorityError {
    #[error("physical presence was not verified")]
    PresenceDenied,
    #[error("executable digest must be a SHA-256 digest")]
    InvalidExecutableDigest,
    #[error("authority scope is malformed or has an empty validity interval")]
    InvalidAuthorityScope,
    #[error("persona is not installed")]
    UnknownPersona,
    #[error("grant is not installed")]
    UnknownGrant,
    #[error("session is not installed")]
    UnknownSession,
    #[error("delegation is not installed")]
    UnknownDelegation,
    #[error("process binding is not installed")]
    UnknownProcessBinding,
    #[error("persona capacity is exhausted")]
    PersonaCapacityExceeded,
    #[error("grant capacity is exhausted")]
    GrantCapacityExceeded,
    #[error("active session capacity is exhausted")]
    SessionCapacityExceeded,
    #[error("active delegation capacity is exhausted")]
    DelegationCapacityExceeded,
    #[error("active process binding capacity is exhausted")]
    ProcessBindingCapacityExceeded,
    #[error("selected Grant attachment contains a duplicate Delegation")]
    DuplicateDelegationAttachment,
    #[error("attachment batch must contain at least one Grant")]
    EmptyAttachmentBatch,
    #[error("attachment batch names the same Grant more than once")]
    DuplicateGrantAttachment,
    #[error("grant is revoked")]
    GrantRevoked,
    #[error("grant has no active interval within the requested attachment lifetime")]
    InactiveGrant,
    #[error("requested Grant lifetime must be a whole number of seconds from 1 through 86400")]
    InvalidRequestedTtl,
    #[error("delegation is revoked or ended")]
    DelegationEnded,
    #[error("session and grant personas differ")]
    PersonaMismatch,
    #[error("session has no unique active process binding")]
    ProcessBindingRequired,
    #[error("observed executable digest does not match the reviewed digest")]
    ExecutableDigestMismatch,
    #[error("observed process identity is invalid")]
    InvalidObservedProcess,
    #[error("process registration challenge was already consumed")]
    ProcessRegistrationChallengeConsumed,
    #[error("process registration challenge does not match")]
    ProcessRegistrationChallengeMismatch,
    #[error("observed process origin does not match the binding")]
    OriginMismatch,
    #[error("reconnect proof is required")]
    ReconnectProofRequired,
    #[error("reconnect proof does not match")]
    ReconnectProofMismatch,
    #[error("reconnect proof is invalid on the initial connection")]
    UnexpectedReconnectProof,
    #[error("session context was not issued by this authority")]
    UnrecognizedSessionContext,
    #[error("no live Grant contains the derived Need")]
    NoApplicableGrant,
    #[error("more than one live Grant contains the derived Need")]
    AmbiguousGrant,
    #[error("the derived Need would require combining overlapping Grants")]
    OverlappingGrant,
    #[error("the admitted Grant has no live process-bound leaf Delegation")]
    NoApplicableDelegation,
    #[error("the admitted Grant has more than one live process-bound leaf Delegation")]
    AmbiguousDelegation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, str::FromStr};

    const NOW: i64 = 1_800_000_000;
    const ACTION: &str = "git.publish-ref/v1";

    struct Present;
    impl PresenceVerifier for Present {
        fn verify_presence(&mut self, _: &PresenceOperation) -> bool {
            true
        }
    }

    fn pack() -> PackRef {
        PackRef {
            address: "github.com/emberdotlink/provider-github".into(),
            version: 2,
        }
    }
    fn repository() -> RepositoryResource {
        RepositoryResource::from_str("github:emberdotlink/ember").unwrap()
    }
    fn permissions(entries: &[(&str, PermissionLevel)]) -> BTreeMap<String, PermissionLevel> {
        entries
            .iter()
            .map(|(name, level)| ((*name).to_owned(), *level))
            .collect()
    }
    fn need(entries: &[(&str, PermissionLevel)]) -> Need {
        Need {
            provider: "github".into(),
            repository: repository(),
            permissions: permissions(entries),
            destination_ref: Some(GitRef::from_str("refs/heads/ws/e3/builder-1").unwrap()),
        }
    }
    fn origin(pid: u32, version: u64, euid: u32, egid: u32, image: u8) -> ProcessOrigin {
        ProcessOrigin::new(
            pid,
            version,
            euid,
            egid,
            ExecutableDigest::from_sha256([image; 32]),
        )
        .unwrap()
    }
    fn installation(
        persona: PersonaId,
        entries: &[(&str, PermissionLevel)],
        expiry: i64,
    ) -> GrantInstallation {
        GrantInstallation::new(
            persona,
            pack(),
            ACTION,
            "github",
            repository(),
            Some("refs/heads/ws/".into()),
            permissions(entries),
            NOW - 1,
            expiry,
        )
        .unwrap()
    }

    struct Fixture {
        authority: PersonaAuthority,
        persona: PersonaId,
        session: SessionId,
        binding: ProcessBindingId,
        context: SessionContext,
    }
    fn fixture() -> Fixture {
        let mut authority = PersonaAuthority::new();
        let persona = authority
            .management()
            .install_persona(&mut Present)
            .unwrap();
        let (session, challenge) = authority
            .sessions()
            .create(&persona, ExecutableDigest::from_sha256([7; 32]))
            .unwrap();
        let process = origin(42, 1, 501, 20, 7);
        let binding = authority
            .sessions()
            .bind_origin(&session, &challenge, process)
            .unwrap();
        let (context, proof) = authority
            .sessions()
            .connect(&session, &binding, &process, None)
            .unwrap();
        assert!(proof.is_some());
        Fixture {
            authority,
            persona,
            session,
            binding,
            context,
        }
    }
    fn install(f: &mut Fixture, entries: &[(&str, PermissionLevel)], expiry: i64) -> GrantId {
        f.authority
            .management()
            .install_grant(
                &mut Present,
                installation(f.persona.clone(), entries, expiry),
            )
            .unwrap()
    }
    fn attach(f: &mut Fixture, grant: &GrantId, ttl: u64) -> DelegationId {
        let delegation = DelegationId::new();
        f.authority
            .management()
            .attach_selected_grants(
                &mut Present,
                &f.session,
                vec![(delegation.clone(), GrantSelection::whole(grant.clone()))],
                NOW,
                Duration::from_secs(ttl),
            )
            .unwrap();
        delegation
    }

    #[test]
    fn registration_reconnect_and_process_lifetime_are_exact() {
        let mut authority = PersonaAuthority::new();
        let persona = authority
            .management()
            .install_persona(&mut Present)
            .unwrap();
        let reviewed = ExecutableDigest::from_sha256([7; 32]);
        let (bad_session, bad_challenge) = authority.sessions().create(&persona, reviewed).unwrap();
        assert_eq!(
            authority.sessions().bind_origin(
                &bad_session,
                &bad_challenge,
                origin(42, 1, 501, 20, 8)
            ),
            Err(AuthorityError::ExecutableDigestMismatch)
        );
        assert_eq!(
            authority.sessions().end_session(&bad_session),
            Err(AuthorityError::UnknownSession)
        );

        let (session, challenge) = authority.sessions().create(&persona, reviewed).unwrap();
        let exact = origin(42, 9, 501, 20, 7);
        let binding = authority
            .sessions()
            .bind_origin(&session, &challenge, exact)
            .unwrap();
        let (context, issued) = authority
            .sessions()
            .connect(&session, &binding, &exact, None)
            .unwrap();
        let proof = issued.unwrap();
        assert!(
            authority
                .sessions()
                .connect(&session, &binding, &exact, Some(&proof))
                .is_ok()
        );
        authority.sessions().end_origin(&binding).unwrap();
        assert_eq!(
            authority.execution().identify(&context),
            Err(AuthorityError::UnknownSession)
        );

        for mismatch in [
            origin(43, 1, 501, 20, 7),
            origin(42, 2, 501, 20, 7),
            origin(42, 1, 502, 20, 7),
            origin(42, 1, 501, 21, 7),
            origin(42, 1, 501, 20, 8),
        ] {
            let mut f = fixture();
            assert!(matches!(
                f.authority
                    .sessions()
                    .connect(&f.session, &f.binding, &mismatch, None),
                Err(AuthorityError::OriginMismatch)
            ));
            assert_eq!(
                f.authority.execution().identify(&f.context),
                Err(AuthorityError::UnknownSession)
            );
        }
    }

    #[test]
    fn admission_derives_exactly_one_grant_and_process_bound_leaf() {
        let mut f = fixture();
        let grant = install(&mut f, &[("contents", PermissionLevel::Write)], NOW + 100);
        let leaf = attach(&mut f, &grant, 60);
        let decision = f
            .authority
            .execution()
            .admit(
                &f.context,
                &pack(),
                ACTION,
                &need(&[("contents", PermissionLevel::Write)]),
                NOW,
            )
            .unwrap();
        assert_eq!(decision.grant_id, grant);
        assert_eq!(decision.delegation_path, vec![leaf]);
        let wrong = SessionContext {
            authority: f.context.authority,
            session: f.context.session.clone(),
            binding: ProcessBindingId::new(),
        };
        assert_eq!(
            f.authority.execution().admit(
                &wrong,
                &pack(),
                ACTION,
                &need(&[("contents", PermissionLevel::Write)]),
                NOW
            ),
            Err(AuthorityError::UnknownProcessBinding)
        );
    }

    #[test]
    fn missing_ambiguous_and_overlapping_needs_refuse() {
        let missing = fixture();
        assert_eq!(
            missing.authority.execution().admit(
                &missing.context,
                &pack(),
                ACTION,
                &need(&[("contents", PermissionLevel::Write)]),
                NOW
            ),
            Err(AuthorityError::NoApplicableGrant)
        );

        let mut ambiguous = fixture();
        for _ in 0..2 {
            let grant = install(
                &mut ambiguous,
                &[("contents", PermissionLevel::Write)],
                NOW + 100,
            );
            attach(&mut ambiguous, &grant, 60);
        }
        assert_eq!(
            ambiguous.authority.execution().admit(
                &ambiguous.context,
                &pack(),
                ACTION,
                &need(&[("contents", PermissionLevel::Write)]),
                NOW
            ),
            Err(AuthorityError::AmbiguousGrant)
        );

        let mut overlap = fixture();
        install(
            &mut overlap,
            &[("contents", PermissionLevel::Write)],
            NOW + 100,
        );
        install(
            &mut overlap,
            &[("metadata", PermissionLevel::Read)],
            NOW + 100,
        );
        assert_eq!(
            overlap.authority.execution().admit(
                &overlap.context,
                &pack(),
                ACTION,
                &need(&[
                    ("contents", PermissionLevel::Write),
                    ("metadata", PermissionLevel::Read)
                ]),
                NOW
            ),
            Err(AuthorityError::OverlappingGrant)
        );
    }

    #[test]
    fn malformed_wire_ref_cannot_cross_the_grant_prefix_boundary() {
        let malicious = "refs/heads/ws/../../../heads/main";
        assert!(!destination_ref_text_fits(malicious, "refs/heads/ws/"));
        assert!(
            serde_json::from_value::<Need>(serde_json::json!({
                "provider": "github",
                "repository": "github:emberdotlink/ember",
                "permissions": {"contents": "write"},
                "destination_ref": malicious
            }))
            .is_err()
        );

        let mut f = fixture();
        let grant = install(&mut f, &[("contents", PermissionLevel::Write)], NOW + 100);
        attach(&mut f, &grant, 60);
        assert!(
            f.authority
                .execution()
                .admit(
                    &f.context,
                    &pack(),
                    ACTION,
                    &need(&[("contents", PermissionLevel::Write)]),
                    NOW
                )
                .is_ok()
        );
    }

    #[test]
    fn sibling_revoke_and_expiry_are_isolated() {
        let mut f = fixture();
        let contents = install(&mut f, &[("contents", PermissionLevel::Write)], NOW + 100);
        let metadata = install(&mut f, &[("metadata", PermissionLevel::Read)], NOW + 5);
        let contents_leaf = attach(&mut f, &contents, 60);
        attach(&mut f, &metadata, 5);
        f.authority
            .management()
            .revoke_delegation(&contents_leaf)
            .unwrap();
        assert_eq!(
            f.authority
                .execution()
                .admit(
                    &f.context,
                    &pack(),
                    ACTION,
                    &need(&[("metadata", PermissionLevel::Read)]),
                    NOW
                )
                .unwrap()
                .grant_id,
            metadata
        );
        assert_eq!(
            f.authority.execution().admit(
                &f.context,
                &pack(),
                ACTION,
                &need(&[("metadata", PermissionLevel::Read)]),
                NOW + 5
            ),
            Err(AuthorityError::NoApplicableGrant)
        );
    }

    #[test]
    fn attachment_requires_a_unique_process_binding() {
        let mut authority = PersonaAuthority::new();
        let persona = authority
            .management()
            .install_persona(&mut Present)
            .unwrap();
        let grant = authority
            .management()
            .install_grant(
                &mut Present,
                installation(
                    persona.clone(),
                    &[("contents", PermissionLevel::Write)],
                    NOW + 10,
                ),
            )
            .unwrap();
        let (session, _) = authority
            .sessions()
            .create(&persona, ExecutableDigest::from_sha256([7; 32]))
            .unwrap();
        assert_eq!(
            authority.management().attach_selected_grants(
                &mut Present,
                &session,
                vec![(DelegationId::new(), GrantSelection::whole(grant))],
                NOW,
                Duration::from_secs(5)
            ),
            Err(AuthorityError::ProcessBindingRequired)
        );
    }

    #[test]
    fn challenge_and_reconnect_proof_zeroize_on_drop() {
        assert!(std::mem::needs_drop::<ProcessRegistrationChallenge>());
        assert!(std::mem::needs_drop::<ReconnectProof>());
    }
}
