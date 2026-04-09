use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use core_crypto::FixtureSigner;
use core_identity::{
    device_added_event, device_encryption_key_rotated_event, device_frozen_event,
    device_key_rotated_event, device_replaced_event, root_key_rotated_event,
};
use core_personas::persona_key_rotated_event;
use core_recovery::{
    guardian_enrolled_event, recovery_approved_event, recovery_contested_event,
    recovery_executed_event, recovery_rejected_event, recovery_requested_event,
};
use core_state::IdentityAuthorizer;
use core_storage::{
    create_presentation_template, grant_manifest_access, publish_manifest, replace_manifest_access,
    revoke_manifest_access, rewrap_manifest_access, storage_ledger_updated_event,
    storage_manifest_published_event,
};
use core_sync::{
    PortableInvite, PortableRelaySubmission, PortableSyncBatch, endpoint_rotated_event,
    filter_batch_by_profile, parse_relay_transport_hint, plan_pull_batch, relay_hint_updated_event,
    relevant_event_ids_for_context, wrap_for_relay,
};
use core_trust::{derive_score, trust_attested_event, trust_revoked_event};
use core_types::{
    AdmissionToken, ContentPublishedEvent, ContentVisibility, EventBody, MessageSentEvent,
    SignerBinding, SurvivalMode, SyncProfile, TrustThreshold, Validate, ValidationError,
};

use super::*;

/// Extract --limit N from a token slice. Returns 0 (no limit) if not found.
fn parse_limit_arg(tokens: &[&str]) -> usize {
    for pair in tokens.windows(2) {
        if pair[0] == "--limit" {
            return pair[1].parse().unwrap_or(0);
        }
    }
    0
}

impl DemoApp {
    pub fn handle_command(&mut self, input: &str) -> String {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            return String::new();
        }

        match tokens.as_slice() {
            ["quit"] | ["exit"] | ["q"] => "EXIT".to_string(),
            ["help"] | ["-h"] | ["--help"] => self.render_help(),
            ["status"] | ["whoami"] => self.render_status(),
            ["init", rest @ ..] => self.handle_init(rest),
            ["invite", "create", rest @ ..] => self.handle_invite_create(rest),
            ["invite", "accept", rest @ ..] => self.handle_invite_accept(rest),
            ["invite", ..] => "Usage: invite create | invite accept <file>\n".to_string(),
            ["reset"] => match self.reset_state() {
                Ok(message) => message,
                Err(err) => format!("Failed to reset state: {}\n", err),
            },
            ["inspect", rest @ ..] => self.handle_inspect(rest),
            ["compare", rest @ ..] => self.handle_compare(rest),
            ["show", "broker"] | ["broker"] => self.render_broker(false),
            ["show", "broker", "--disclose-links"] | ["broker", "--disclose-links"] => {
                self.render_broker(true)
            }
            ["show", "trust", rest @ ..] | ["trust", rest @ ..] => self.handle_trust(rest),
            ["show", "messages", rest @ ..]
            | ["messages", rest @ ..]
            | ["message", "list", rest @ ..] => {
                self.render_messages_with_limit(parse_limit_arg(rest))
            }
            ["show", "disclosures", rest @ ..] | ["disclosures", rest @ ..] => {
                self.render_disclosures_with_limit(parse_limit_arg(rest))
            }
            ["show", "disclosure", message_ref] | ["disclosure", message_ref] => {
                self.render_disclosure_message(message_ref)
            }
            ["show", "content"] | ["content"] | ["content", "list"] => self.render_content(),
            ["show", "content", "--limit", n]
            | ["content", "--limit", n]
            | ["content", "list", "--limit", n] => {
                self.render_content_with_limit(n.parse().unwrap_or(0))
            }
            ["show", "recovery"] | ["recovery"] => self.render_recovery(),
            ["disclose", rest @ ..] => self.handle_disclose(rest),
            ["claim", rest @ ..] => self.handle_claim(rest),
            ["service", rest @ ..] => self.handle_service(rest),
            ["passkey", rest @ ..] => self.handle_passkey(rest),
            ["import", rest @ ..] => self.handle_import(rest),
            ["show", "vault", rest @ ..] | ["vault", rest @ ..] => self.handle_vault(rest),
            ["show", "storage", rest @ ..] | ["storage", rest @ ..] => self.handle_storage(rest),
            ["show", "sync", rest @ ..] | ["sync", rest @ ..] => self.handle_sync(rest),
            ["show", "state"] | ["state"] => self.render_state(),
            ["show", "keys"] | ["keys"] | ["list", "keys"] => self.render_keys(),
            ["show", "root", root_ref] | ["root", "show", root_ref] => self.render_root(root_ref),
            ["show", "device", device_ref] | ["device", "show", device_ref] => {
                self.render_device(device_ref)
            }
            ["show", "persona", persona_ref] | ["persona", "show", persona_ref] => {
                self.render_persona(persona_ref)
            }
            ["list", "roots"] | ["roots", "list"] | ["root", "list"] => self.render_roots(),
            ["list", "devices"] | ["devices", "list"] | ["device", "list"] => self.render_devices(),
            ["list", "personas"] | ["personas", "list"] | ["persona", "list"] => {
                self.render_personas()
            }
            _ => self.handle_structured_command(&tokens),
        }
    }

    pub(crate) fn create_root_command(
        &mut self,
        display_name: &str,
    ) -> Result<String, ValidationError> {
        let root_id = self.allocate_subject_id("root");
        self.add_root_with_id(&root_id, display_name)?;
        Ok(format!("created root\t{}\t{}\n", root_id, display_name))
    }

    pub(crate) fn create_persona_command(
        &mut self,
        root_ref: &str,
        label: &str,
        disclosure_profile: Option<String>,
    ) -> Result<String, ValidationError> {
        let root_id = self.require_root(root_ref)?;

        let persona_id = self.allocate_subject_id("persona");
        let profile_label = disclosure_profile
            .as_deref()
            .unwrap_or("(none)")
            .to_string();
        let granted_devices = self.add_persona_with_id(
            &persona_id,
            &root_id,
            label,
            disclosure_profile,
            SurvivalMode::Strict,
        )?;
        Ok(format!(
            "created persona\t{}\t{}\t{}\t{}\taccess:{}\n",
            persona_id,
            root_id,
            label,
            profile_label,
            comma_or_none(&granted_devices)
        ))
    }

    pub(crate) fn create_device_command(
        &mut self,
        root_ref: &str,
        label: &str,
    ) -> Result<String, ValidationError> {
        let root_id = self.require_root(root_ref)?;

        let device_id = self.allocate_subject_id("device");
        self.add_device_with_id(&device_id, &root_id, label, true)?;
        Ok(format!(
            "created device\t{}\t{}\t{}\n",
            device_id, root_id, label
        ))
    }

    pub(crate) fn send_message_command(
        &mut self,
        sender_ref: &str,
        recipient_ref: &str,
        ciphertext_hex: &str,
    ) -> Result<String, ValidationError> {
        let sender = self.require_persona(sender_ref)?.clone();
        let sender_id = sender.id.clone();
        let sender_signer = self.persona_signer(&sender_id)?;
        let recipient_id = self
            .resolve_persona(recipient_ref)
            .map(|persona| persona.id.clone())
            .unwrap_or_else(|| recipient_ref.to_string());
        let message_id = self.allocate_subject_id("message");

        self.append_live_event(
            self.allocate_event_id("message-sent"),
            EventBody::MessageSent(MessageSentEvent {
                message_id: message_id.clone(),
                sender_persona_id: sender_id.clone(),
                recipient_persona_id: recipient_id.clone(),
                ciphertext_hex: ciphertext_hex.to_string(),
            }),
            SignerBinding::persona(&sender_id, sender.active_key.key_id.clone()),
            &sender_signer,
        )?;
        self.persist_to_disk()?;

        Ok(format!(
            "sent message\t{}\t{}\t{}\n",
            message_id, sender_id, recipient_id
        ))
    }

    pub(crate) fn publish_content_command(
        &mut self,
        author_ref: &str,
        content_type: &str,
        payload_hex: &str,
        visibility: ContentVisibility,
    ) -> Result<String, ValidationError> {
        let author = self.require_persona(author_ref)?.clone();
        let author_id = author.id.clone();
        let author_signer = self.persona_signer(&author_id)?;
        let content_id = self.allocate_subject_id("content");

        self.append_live_event(
            self.allocate_event_id("content-published"),
            EventBody::ContentPublished(ContentPublishedEvent {
                content_id: content_id.clone(),
                author_persona_id: author_id.clone(),
                content_type: content_type.to_string(),
                payload_hex: payload_hex.to_string(),
                visibility,
            }),
            SignerBinding::persona(&author_id, author.active_key.key_id.clone()),
            &author_signer,
        )?;
        self.persist_to_disk()?;

        Ok(format!(
            "published content\t{}\t{}\t{}\t{}\n",
            content_id,
            author_id,
            content_type,
            visibility.as_str()
        ))
    }

    pub(crate) fn issue_relay_admission_token(
        &self,
        source_persona_id: &str,
        issuer_ref: &str,
        threshold: TrustThreshold,
        expires_in_secs: u64,
    ) -> Result<AdmissionToken, ValidationError> {
        let issuer_id = self
            .resolve_persona(issuer_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown issuer persona: {issuer_ref}")))?;
        let trust_score = derive_score(&self.trust_attestations, source_persona_id, "professional")
            .map(|statement| statement.normalized_score)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "no trust score available for source persona: {source_persona_id}"
                ))
            })?;
        if !threshold.is_met_by(trust_score) {
            return Err(ValidationError::new(format!(
                "source persona trust score {:.2} does not meet threshold {:.2}",
                trust_score,
                threshold.value()
            )));
        }

        let issued_at = now_epoch_secs();
        let expires_at = issued_at.saturating_add(expires_in_secs.max(1));
        let signer = self.persona_signer(&issuer_id)?;
        let mut token = AdmissionToken {
            token_id: generate_random_identifier("admission-token"),
            persona_id: source_persona_id.to_string(),
            issuer_persona_id: issuer_id,
            issued_at,
            expires_at,
            threshold_met: threshold,
            issuer_signature_hex: String::new(),
        };
        token.issuer_signature_hex = signer.sign(&token.signing_payload()).0;
        Ok(token)
    }

    pub(crate) fn append_trust_attestation(
        &mut self,
        attestation_id: &str,
        attester_persona_id: &str,
        subject_persona_id: &str,
        domain: &str,
        score: f32,
        recipient_bound: Option<String>,
    ) -> Result<(), ValidationError> {
        let attester = self.resolve_persona(attester_persona_id).ok_or_else(|| {
            ValidationError::new(format!("unknown attester persona: {attester_persona_id}"))
        })?;
        let signer = self.persona_signer(attester_persona_id)?;
        let event = trust_attested_event(
            self.allocate_event_id("trust-attested"),
            TrustAttestation {
                id: attestation_id.to_string(),
                attester: attester_persona_id.to_string(),
                subject: subject_persona_id.to_string(),
                domain: domain.to_string(),
                score,
                recipient_bound,
            },
            SignerBinding::persona(attester_persona_id, &attester.active_key.key_id),
            &signer,
        )?;
        self.event_store.append_with_authorizer(
            event,
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        )?;
        self.hydrate_identity_state();
        Ok(())
    }

    pub(crate) fn attest_trust_command(
        &mut self,
        attester_ref: &str,
        subject_ref: &str,
        domain: &str,
        score: f32,
        recipient_bound: Option<String>,
    ) -> Result<String, ValidationError> {
        let attester_id = self
            .resolve_persona(attester_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| {
                ValidationError::new(format!("unknown attester persona: {attester_ref}"))
            })?;
        let subject_id = self
            .resolve_persona(subject_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| {
                ValidationError::new(format!("unknown subject persona: {subject_ref}"))
            })?;
        let attestation_id = self.allocate_subject_id("trust");
        self.append_trust_attestation(
            &attestation_id,
            &attester_id,
            &subject_id,
            domain,
            score,
            recipient_bound.clone(),
        )?;
        self.persist_to_disk()?;
        Ok(format!(
            "attested trust\t{}\t{}\t{}\t{}\t{:.2}\t{}\n",
            attestation_id,
            attester_id,
            subject_id,
            domain,
            score,
            recipient_bound.unwrap_or_else(|| "(public)".to_string())
        ))
    }

    pub(crate) fn revoke_trust_command(
        &mut self,
        attestation_id: &str,
        attester_ref: &str,
    ) -> Result<String, ValidationError> {
        let attester = self.resolve_persona(attester_ref).ok_or_else(|| {
            ValidationError::new(format!("unknown attester persona: {attester_ref}"))
        })?;
        let attester_id = attester.id.clone();
        let attester_key_id = attester.active_key.key_id.clone();
        let signer = self.persona_signer(&attester_id)?;
        let previous_event_id = self
            .event_store
            .events()
            .iter()
            .rev()
            .find_map(|event| match &event.body {
                EventBody::TrustAttested(body) if body.attestation_id == attestation_id => {
                    Some(event.event_id.clone())
                }
                _ => None,
            })
            .ok_or_else(|| {
                ValidationError::new(format!("unknown trust attestation: {attestation_id}"))
            })?;
        let event = trust_revoked_event(
            self.allocate_event_id("trust-revoked"),
            attestation_id,
            &attester_id,
            previous_event_id,
            SignerBinding::persona(&attester_id, &attester_key_id),
            &signer,
        )?;
        self.event_store.append_with_authorizer(
            event,
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        )?;
        self.hydrate_identity_state();
        self.persist_to_disk()?;
        Ok(format!(
            "revoked trust\t{}\t{}\n",
            attestation_id, attester_id
        ))
    }

    pub(crate) fn enroll_guardian_command(
        &mut self,
        root_ref: &str,
        guardian_id: &str,
        label: &str,
    ) -> Result<String, ValidationError> {
        let root_id = self
            .resolve_root(root_ref)
            .map(|root| root.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_ref}")))?;

        let guardian_key_id = format!("guardian-key-{guardian_id}");

        let signer = self.root_signer(&root_id)?;
        self.append_live_event(
            self.allocate_event_id("guardian-enrolled"),
            guardian_enrolled_event(&root_id, guardian_id, label, &guardian_key_id),
            SignerBinding::root(&root_id, self.root_active_key_id(&root_id)?),
            &signer,
        )?;
        self.persist_to_disk()?;

        Ok(format!(
            "enrolled guardian\t{}\troot={}\tkey={}\n",
            guardian_id, root_id, guardian_key_id
        ))
    }

    pub(crate) fn create_recovery_request_command(
        &mut self,
        root_ref: &str,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let root_id = self
            .resolve_root(root_ref)
            .map(|root| root.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_ref}")))?;
        let target_device = self
            .resolve_device(device_ref)
            .cloned()
            .ok_or_else(|| ValidationError::new(format!("unknown active device: {device_ref}")))?;
        if target_device.root_id != root_id {
            return Err(ValidationError::new(
                "target device does not belong to requested root",
            ));
        }

        let request_id = self.allocate_subject_id("recovery");
        let notified_devices = self
            .devices
            .iter()
            .filter(|device| {
                device.root_id == root_id && device.device_id != target_device.device_id
            })
            .map(|device| device.device_id.clone())
            .collect::<Vec<_>>();

        let signer = self.root_signer(&root_id)?;
        self.append_live_event(
            self.allocate_event_id("recovery-requested"),
            recovery_requested_event(&request_id, &root_id, &target_device.device_id),
            SignerBinding::root(&root_id, self.root_active_key_id(&root_id)?),
            &signer,
        )?;
        self.recovery_session = Some(RecoverySession {
            request_id: request_id.clone(),
            root_id: root_id.clone(),
            target_device_id: target_device.device_id.clone(),
            replacement_device_id: None,
            state: "requested".into(),
            approvals: Vec::new(),
            notified_devices,
        });
        self.persist_to_disk()?;

        Ok(format!(
            "created recovery request\t{}\t{}\t{}\n",
            request_id, root_id, target_device.device_id
        ))
    }

    pub(crate) fn approve_recovery_command(
        &mut self,
        guardian_id: &str,
    ) -> Result<String, ValidationError> {
        let Some(request_id) = self
            .recovery_session
            .as_ref()
            .map(|session| session.request_id.clone())
        else {
            return Err(ValidationError::new("no active recovery request"));
        };

        let guardian_key_id = format!("guardian-key-{guardian_id}");
        let guardian_signer = AppSigner::Fixture(FixtureSigner::new(&guardian_key_id));
        self.append_live_event(
            self.allocate_event_id("recovery-approved"),
            recovery_approved_event(&request_id, guardian_id),
            SignerBinding::guardian(guardian_id, guardian_key_id),
            &guardian_signer,
        )?;

        let Some(session) = &mut self.recovery_session else {
            return Err(ValidationError::new("no active recovery request"));
        };
        if !session
            .approvals
            .iter()
            .any(|existing| existing == guardian_id)
        {
            session.approvals.push(guardian_id.to_string());
        }
        if session.approvals.len() >= self.recovery_policy.guardian_threshold as usize {
            session.state = "approved".into();
        }
        let approval_count = session.approvals.len();
        let threshold = self.recovery_policy.guardian_threshold;
        let guardian_id = guardian_id.to_string();
        let _ = session;
        self.persist_to_disk()?;

        Ok(format!(
            "approved recovery\t{}\t{}\t{}/{}\n",
            request_id, guardian_id, approval_count, threshold
        ))
    }

    pub(crate) fn contest_recovery_command(
        &mut self,
        guardian_id: &str,
        reason: &str,
    ) -> Result<String, ValidationError> {
        let Some(request_id) = self
            .recovery_session
            .as_ref()
            .map(|session| session.request_id.clone())
        else {
            return Err(ValidationError::new("no active recovery request"));
        };

        let guardian_key_id = format!("guardian-key-{guardian_id}");
        let guardian_signer = AppSigner::Fixture(FixtureSigner::new(&guardian_key_id));
        self.append_live_event(
            self.allocate_event_id("recovery-contested"),
            recovery_contested_event(&request_id, guardian_id, reason, now_epoch_secs()),
            SignerBinding::guardian(guardian_id, guardian_key_id),
            &guardian_signer,
        )?;

        if let Some(session) = &mut self.recovery_session {
            session.state = "contested".into();
        }
        self.persist_to_disk()?;

        Ok(format!(
            "contested recovery\t{}\t{}\t{}\n",
            request_id, guardian_id, reason
        ))
    }

    pub(crate) fn reject_recovery_command(
        &mut self,
        reason: &str,
    ) -> Result<String, ValidationError> {
        let Some(session) = self.recovery_session.clone() else {
            return Err(ValidationError::new("no active recovery request"));
        };
        let root_signer = self.root_signer(&session.root_id)?;
        let root_key_id = self.root_active_key_id(&session.root_id)?;
        self.append_live_event(
            self.allocate_event_id("recovery-rejected"),
            recovery_rejected_event(&session.request_id, &session.root_id, reason),
            SignerBinding::root(&session.root_id, root_key_id),
            &root_signer,
        )?;

        if let Some(active) = &mut self.recovery_session {
            active.state = "rejected".into();
        }
        self.persist_to_disk()?;

        Ok(format!(
            "rejected recovery\t{}\t{}\n",
            session.request_id, reason
        ))
    }

    pub(crate) fn execute_recovery_command(
        &mut self,
        replacement_device_ref: Option<&str>,
    ) -> Result<String, ValidationError> {
        let Some(session) = self.recovery_session.clone() else {
            return Err(ValidationError::new("no active recovery request"));
        };
        if session.approvals.len() < self.recovery_policy.guardian_threshold as usize {
            return Err(ValidationError::new("guardian threshold not yet met"));
        }

        let replacement_device = if let Some(device_ref) = replacement_device_ref {
            let device = self.resolve_device(device_ref).cloned().ok_or_else(|| {
                ValidationError::new(format!("unknown active device: {device_ref}"))
            })?;
            if device.root_id != session.root_id {
                return Err(ValidationError::new(
                    "replacement device does not belong to recovery root",
                ));
            }
            if device.device_id == session.target_device_id {
                return Err(ValidationError::new(
                    "replacement device must differ from the target device",
                ));
            }
            Some(device)
        } else {
            None
        };

        let root_signer = self.root_signer(&session.root_id)?;
        let root_key_id = self.root_active_key_id(&session.root_id)?;
        if let Some(replacement_device) = &replacement_device {
            self.append_live_event(
                self.allocate_event_id("device-replaced"),
                device_replaced_event(
                    &session.root_id,
                    &session.target_device_id,
                    &replacement_device.device_id,
                ),
                SignerBinding::root(&session.root_id, root_key_id.clone()),
                &root_signer,
            )?;
        }
        self.append_live_event(
            self.allocate_event_id("recovery-executed"),
            recovery_executed_event(&session.request_id, core_types::RecoveryScope::FreezeDevice),
            SignerBinding::root(&session.root_id, root_key_id.clone()),
            &root_signer,
        )?;
        self.append_live_event(
            self.allocate_event_id("device-frozen"),
            device_frozen_event(
                &session.root_id,
                &session.target_device_id,
                "recovery-executed",
            ),
            SignerBinding::root(&session.root_id, root_key_id),
            &root_signer,
        )?;
        let vault_namespaces = self.vault_namespaces_for_root(&session.root_id)?;
        if let Some(replacement_device) = &replacement_device {
            self.event_store
                .restore_persona_access_to_replacement_device(
                    &session.target_device_id,
                    &replacement_device.device_id,
                )?;
            for namespace in &vault_namespaces {
                self.event_store
                    .restore_local_vault_access_to_replacement_device(
                        namespace,
                        &session.target_device_id,
                        &replacement_device.device_id,
                    )?;
            }
        } else {
            for namespace in &vault_namespaces {
                self.event_store
                    .revoke_local_vault_access_for_inactive_device(
                        namespace,
                        &session.target_device_id,
                    )?;
            }
        }
        if let Some(mut manifest) = self.event_store.file_manifest(&self.storage_manifest.id) {
            if let Some(replacement_device) = &replacement_device {
                let manifest_id = manifest.id.clone();
                let replacement_access = self
                    .wrap_manifest_access_for_device(&manifest_id, &replacement_device.device_id)?;
                replace_manifest_access(
                    &mut manifest,
                    &session.target_device_id,
                    replacement_access,
                )?;
            } else {
                revoke_manifest_access(&mut manifest, &session.target_device_id)?;
            }
            self.publish_storage_manifest_event(
                &session.root_id,
                manifest,
                "storage-manifest-published",
            )?;
        }

        let index = self
            .devices
            .iter()
            .position(|device| device.device_id == session.target_device_id)
            .ok_or_else(|| ValidationError::new("target device is no longer active"))?;
        let mut frozen = self.devices.remove(index);
        frozen.active = false;
        self.revoked_devices.push(frozen.clone());

        if let Some(active) = &mut self.recovery_session {
            active.replacement_device_id = replacement_device
                .as_ref()
                .map(|device| device.device_id.clone());
            active.state = "executed".into();
        }
        self.persist_to_disk()?;

        if let Some(replacement_device) = replacement_device {
            Ok(format!(
                "executed recovery\t{}\tfroze {}\trestored-to {}\n",
                session.request_id, session.target_device_id, replacement_device.device_id
            ))
        } else {
            Ok(format!(
                "executed recovery\t{}\tfroze {}\n",
                session.request_id, session.target_device_id
            ))
        }
    }

    pub(crate) fn rotate_root_key_command(
        &mut self,
        root_ref: &str,
    ) -> Result<String, ValidationError> {
        let root_id = self
            .resolve_root(root_ref)
            .map(|root| root.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_ref}")))?;
        let index = self
            .roots
            .iter()
            .position(|root| root.id == root_id)
            .ok_or_else(|| ValidationError::new(format!("unknown root: {root_ref}")))?;

        let previous_key_id = self.roots[index].active_key.key_id.clone();
        let signer = self.root_signer(&root_id)?;
        let next_version = self.next_key_version("root", &root_id);
        let key_pair = generate_local_key_pair_version("root", &root_id, next_version);
        let new_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        self.append_live_event(
            self.allocate_event_id("root-key-rotated"),
            root_key_rotated_event(&root_id, &previous_key_id, new_key.clone()),
            SignerBinding::root(&root_id, previous_key_id),
            &signer,
        )?;
        self.roots[index].active_key = new_key;
        let rotated = self.roots[index].clone();
        self.register_local_key(LocalKeyRecord {
            owner_kind: "root".into(),
            owner_id: rotated.id.clone(),
            key_pair,
        });
        self.persist_to_disk()?;

        Ok(format!(
            "rotated root key\t{}\t{}\n",
            rotated.id, rotated.active_key.key_id
        ))
    }

    pub(crate) fn rotate_persona_key_command(
        &mut self,
        persona_ref: &str,
    ) -> Result<String, ValidationError> {
        let persona_id = self
            .resolve_persona(persona_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;
        let index = self
            .personas
            .iter()
            .position(|persona| persona.id == persona_id)
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;

        let previous_key_id = self.personas[index].active_key.key_id.clone();
        let signer = self.persona_signer(&persona_id)?;
        let next_version = self.next_key_version("persona", &persona_id);
        let key_pair = generate_local_key_pair_version("persona", &persona_id, next_version);
        let new_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let root_id = self.personas[index].root_id.clone();
        self.append_live_event(
            self.allocate_event_id("persona-key-rotated"),
            persona_key_rotated_event(&root_id, &persona_id, &previous_key_id, new_key.clone()),
            SignerBinding::persona(&persona_id, previous_key_id),
            &signer,
        )?;
        self.personas[index].active_key = new_key;
        let rotated = self.personas[index].clone();
        self.register_local_key(LocalKeyRecord {
            owner_kind: "persona".into(),
            owner_id: rotated.id.clone(),
            key_pair,
        });
        self.persist_to_disk()?;

        Ok(format!(
            "rotated persona key\t{}\t{}\n",
            rotated.id, rotated.active_key.key_id
        ))
    }

    pub(crate) fn revoke_device_command(
        &mut self,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let device_id = self
            .resolve_device(device_ref)
            .map(|device| device.device_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;

        let index = self
            .devices
            .iter()
            .position(|device| device.device_id == device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;
        let removed = self.devices[index].clone();
        self.append_device_revoked_event(&removed)?;
        let mut removed = self.devices.remove(index);
        removed.active = false;
        self.revoked_devices.push(removed.clone());
        self.persist_to_disk()?;

        Ok(format!(
            "revoked device\t{}\t{}\n",
            removed.device_id, removed.label
        ))
    }

    pub(crate) fn rotate_device_key_command(
        &mut self,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let device_id = self
            .resolve_device(device_ref)
            .map(|device| device.device_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;
        let index = self
            .devices
            .iter()
            .position(|device| device.device_id == device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;

        let previous_key_id = self.devices[index].active_key.key_id.clone();
        let signer = self.device_signer(&device_id)?;
        let next_version = self.next_key_version("device", &device_id);
        let key_pair = generate_local_key_pair_version("device", &device_id, next_version);
        let new_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let root_id = self.devices[index].root_id.clone();
        self.append_live_event(
            self.allocate_event_id("device-key-rotated"),
            device_key_rotated_event(&root_id, &device_id, &previous_key_id, new_key.clone()),
            SignerBinding::device(&device_id, previous_key_id),
            &signer,
        )?;
        self.devices[index].active_key = new_key;
        let rotated = self.devices[index].clone();
        self.register_local_key(LocalKeyRecord {
            owner_kind: "device".into(),
            owner_id: rotated.device_id.clone(),
            key_pair,
        });
        self.persist_to_disk()?;

        Ok(format!(
            "rotated device key\t{}\t{}\n",
            rotated.device_id, rotated.active_key.key_id
        ))
    }

    pub(crate) fn rotate_device_encryption_key_command(
        &mut self,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let device_id = self
            .resolve_device(device_ref)
            .map(|device| device.device_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;
        let index = self
            .devices
            .iter()
            .position(|device| device.device_id == device_id)
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;

        let previous_encryption_key_id = self.devices[index].active_encryption_key.key_id.clone();
        self.prime_manifest_keys_for_device(&device_id)?;
        let signer = self.device_signer(&device_id)?;
        let signing_key_id = self.devices[index].active_key.key_id.clone();
        let next_version = self
            .event_store
            .materialized()
            .device_encryption_key_history
            .get(&device_id)
            .map(|history| history.len() as u32 + 1)
            .unwrap_or(2);
        let key_pair =
            generate_local_encryption_key_pair_version("device", &device_id, next_version);
        let new_encryption_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let root_id = self.devices[index].root_id.clone();
        self.append_live_event(
            self.allocate_event_id("device-encryption-key-rotated"),
            device_encryption_key_rotated_event(
                &root_id,
                &device_id,
                &previous_encryption_key_id,
                new_encryption_key.clone(),
            ),
            SignerBinding::device(&device_id, signing_key_id),
            &signer,
        )?;
        self.devices[index].active_encryption_key = new_encryption_key.clone();
        self.event_store
            .upsert_local_device_encryption_key(&device_id, &key_pair)?;
        self.rewrap_manifest_access_for_device(&device_id)?;
        self.persist_to_disk()?;

        Ok(format!(
            "rotated device encryption key\t{}\t{}\n",
            device_id, new_encryption_key.key_id
        ))
    }

    pub(crate) fn prime_manifest_keys_for_device(
        &mut self,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        self.event_store.prime_manifest_keys_for_device(device_id)?;
        Ok(())
    }

    pub(crate) fn rewrap_manifest_access_for_device(
        &mut self,
        device_id: &str,
    ) -> Result<(), ValidationError> {
        for mut manifest in self.event_store.file_manifests() {
            if !manifest
                .authorized_devices
                .iter()
                .any(|access| access.device_id == device_id)
            {
                continue;
            }
            let manifest_id = manifest.id.clone();
            let root_id = self.storage_manifest_root_id(&manifest)?;
            let access = self.wrap_manifest_access_for_device(&manifest_id, device_id)?;
            rewrap_manifest_access(&mut manifest, access)?;
            self.publish_storage_manifest_event(&root_id, manifest, "storage-manifest-published")?;
        }
        Ok(())
    }

    pub(crate) fn publish_endpoint_hint(
        &mut self,
        device_ref: &str,
        transport_hint: &str,
    ) -> Result<String, ValidationError> {
        let device = self
            .resolve_device(device_ref)
            .cloned()
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;
        let signer = self.device_signer(&device.device_id)?;
        let peer_id = self.current_peer_id();
        self.append_live_event(
            self.allocate_event_id("relay-hint-updated"),
            relay_hint_updated_event(&peer_id, &device.device_id, transport_hint),
            SignerBinding::device(&device.device_id, device.active_key.key_id.clone()),
            &signer,
        )?;
        self.persist_to_disk()?;

        Ok(format!(
            "updated endpoint\t{}\t{}\tvia {}\n",
            peer_id, transport_hint, device.device_id
        ))
    }

    pub(crate) fn rotate_endpoint_hint(
        &mut self,
        device_ref: &str,
        transport_hint: &str,
    ) -> Result<String, ValidationError> {
        let device = self
            .resolve_device(device_ref)
            .cloned()
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;
        let peer_id = self.current_peer_id();
        let current_endpoint = self
            .event_store
            .materialized()
            .endpoint(&peer_id)
            .cloned()
            .ok_or_else(|| ValidationError::new("no current endpoint published for local peer"))?;
        if current_endpoint.device_id != device.device_id {
            return Err(ValidationError::new(
                "endpoint rotation must be performed by the device that currently advertises the endpoint",
            ));
        }

        let signer = self.device_signer(&device.device_id)?;
        self.append_live_event(
            self.allocate_event_id("endpoint-rotated"),
            endpoint_rotated_event(
                &peer_id,
                &device.device_id,
                &current_endpoint.transport_hint,
                transport_hint,
            ),
            SignerBinding::device(&device.device_id, device.active_key.key_id.clone()),
            &signer,
        )?;
        self.persist_to_disk()?;

        Ok(format!(
            "rotated endpoint\t{}\t{}\t-> {}\tvia {}\n",
            peer_id, current_endpoint.transport_hint, transport_hint, device.device_id
        ))
    }

    pub(crate) fn add_root_with_id(
        &mut self,
        root_id: &str,
        display_name: &str,
    ) -> Result<(), ValidationError> {
        let key_pair = generate_local_key_pair("root", root_id);
        let signer = AppSigner::from_key_pair(&key_pair).map_err(ValidationError::new)?;
        let public_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let root = create_root(root_id, display_name, public_key);
        self.append_live_event(
            format!("evt-root-created-{root_id}"),
            root_created_event(root_id, display_name, root.active_key.clone()),
            SignerBinding::root(root_id, root.active_key.key_id.clone()),
            &signer,
        )?;
        self.register_local_key(LocalKeyRecord {
            owner_kind: "root".into(),
            owner_id: root.id.clone(),
            key_pair,
        });
        self.roots.push(root);
        self.persist_to_disk()?;
        Ok(())
    }

    pub(crate) fn add_persona_with_id(
        &mut self,
        persona_id: &str,
        root_id: &str,
        label: &str,
        disclosure_profile: Option<String>,
        survival_mode: SurvivalMode,
    ) -> Result<Vec<String>, ValidationError> {
        let key_pair = generate_local_key_pair("persona", persona_id);
        let root_signer = self.root_signer(root_id)?;
        let root_key_id = self.root_active_key_id(root_id)?;
        let public_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let persona = create_persona(
            persona_id,
            root_id,
            label,
            disclosure_profile.clone(),
            survival_mode,
            public_key,
        );
        self.append_live_event(
            format!("evt-persona-created-{persona_id}"),
            persona_created_event(
                root_id,
                persona_id,
                label,
                disclosure_profile,
                survival_mode,
                persona.active_key.clone(),
            ),
            SignerBinding::root(root_id, root_key_id),
            &root_signer,
        )?;
        self.register_local_key(LocalKeyRecord {
            owner_kind: "persona".into(),
            owner_id: persona.id.clone(),
            key_pair,
        });
        self.personas.push(persona);
        let granted_devices =
            self.grant_persona_access_to_active_root_devices(persona_id, root_id)?;
        self.persist_to_disk()?;
        Ok(granted_devices)
    }

    pub(crate) fn add_device_with_id(
        &mut self,
        device_id: &str,
        root_id: &str,
        label: &str,
        active: bool,
    ) -> Result<(), ValidationError> {
        let key_pair = generate_local_key_pair("device", device_id);
        let encryption_key_pair = generate_local_encryption_key_pair("device", device_id);
        let root_signer = self.root_signer(root_id)?;
        let root_key_id = self.root_active_key_id(root_id)?;
        let public_key = PublicKeyMaterial {
            key_id: key_pair.key_id.clone(),
            algorithm: key_pair.algorithm,
            public_key: key_pair.public_key.clone(),
        };
        let encryption_public_key = PublicKeyMaterial {
            key_id: encryption_key_pair.key_id.clone(),
            algorithm: encryption_key_pair.algorithm,
            public_key: encryption_key_pair.public_key.clone(),
        };
        let device = DeviceMembership {
            root_id: root_id.to_string(),
            device_id: device_id.to_string(),
            label: label.to_string(),
            active,
            active_key: public_key,
            active_encryption_key: encryption_public_key,
        };
        self.append_live_event(
            format!("evt-device-added-{device_id}"),
            device_added_event(
                root_id,
                device_id,
                label,
                device.active_key.clone(),
                device.active_encryption_key.clone(),
            ),
            SignerBinding::root(root_id, root_key_id),
            &root_signer,
        )?;
        self.register_local_key(LocalKeyRecord {
            owner_kind: "device".into(),
            owner_id: device.device_id.clone(),
            key_pair,
        });
        self.event_store
            .upsert_local_device_encryption_key(device_id, &encryption_key_pair)?;
        self.devices.push(device);
        self.persist_to_disk()?;
        Ok(())
    }

    pub(crate) fn initialize_runtime_storage_state(&mut self) -> Result<(), ValidationError> {
        if !self.seed_demo || self.roots.is_empty() {
            return self.refresh_storage_manifest_from_runtime();
        }

        let root_id = self.storage_manifest_root_id(&self.storage_manifest)?;
        if !self
            .event_store
            .materialized()
            .storage_relationships_current
            .contains_key(&self.storage_relationship.id)
        {
            self.publish_storage_relationship_event(
                &root_id,
                self.storage_relationship.clone(),
                "storage-relationship-created",
            )?;
        }
        if !self
            .event_store
            .materialized()
            .storage_balances_current
            .contains_key(&self.storage_ledger.relationship_id)
        {
            self.publish_storage_ledger_event(
                &root_id,
                self.storage_ledger.clone(),
                "storage-ledger-updated",
            )?;
        }
        if self
            .event_store
            .file_manifest(&self.storage_manifest.id)
            .is_none()
        {
            self.storage_manifest = self.build_seed_storage_manifest()?;
            self.publish_storage_manifest_event(
                &root_id,
                self.storage_manifest.clone(),
                "storage-manifest-published",
            )?;
        }
        self.initialize_runtime_vault_state()?;
        self.refresh_storage_manifest_from_runtime()
    }

    pub(crate) fn initialize_runtime_vault_state(&mut self) -> Result<(), ValidationError> {
        let namespace = self.seed_vault_namespace();
        if self.event_store.local_vault_catalog(&namespace)?.is_none() {
            let recipients = self.manifest_key_recipients_for_namespace(&namespace)?;
            if recipients.is_empty() {
                return Err(ValidationError::new(
                    "seed vault namespace has no active recipient devices",
                ));
            }
            let structured_record = core_types::StructuredRecordMeta {
                schema_id: "com.emberlink.profile/basic".into(),
                schema_version: "v1".into(),
                encoding: core_types::StructuredEncoding::Json,
                app_namespace: "com.emberlink.profile".into(),
            };
            self.event_store.upsert_local_structured_record(
                &namespace,
                "vault-object-professional-profile",
                "vault-rev-professional-v1",
                "vault-manifest-professional-v1",
                "vault-catalog-persona-professional",
                1,
                "device-root-a-01",
                structured_record.clone(),
                br#"{"full_name":"Jordan Hudson","employment":{"status":"operator","team":"systems"},"skills":["rust","distributed-systems"],"private":{"signal":"local-only:v1"}}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                recipients.clone(),
            )?;
            self.event_store.upsert_local_structured_record(
                &namespace,
                "vault-object-professional-profile",
                "vault-rev-professional-v2",
                "vault-manifest-professional-v2",
                "vault-catalog-persona-professional",
                2,
                "device-root-a-01",
                structured_record,
                br#"{"full_name":"Jordan Hudson","employment":{"status":"operator","team":"systems"},"skills":["rust","distributed-systems","identity-brokering"],"profile":{"headline":"Local-first identity broker"},"private":{"signal":"local-only:v2"}}"#,
                core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
                core_types::RetentionPolicy::KeepLatest,
                recipients,
            )?;
        }
        if self
            .event_store
            .local_presentation_template("template-professional-card")?
            .is_none()
        {
            let template = create_presentation_template(
                "template-professional-card",
                namespace.clone(),
                "vault-object-professional-profile",
                "com.emberlink.profile/basic",
                core_types::PresentationAudienceKind::Service,
                vec![
                    "employment.status".into(),
                    "full_name".into(),
                    "profile.headline".into(),
                    "skills".into(),
                ],
                Some(3600),
            )?;
            self.event_store
                .upsert_local_presentation_template(&template)?;
        }
        if self
            .event_store
            .local_presentation_template("template-professional-peer-card")?
            .is_none()
        {
            let template = create_presentation_template(
                "template-professional-peer-card",
                namespace.clone(),
                "vault-object-professional-profile",
                "com.emberlink.profile/basic",
                core_types::PresentationAudienceKind::Peer,
                vec![
                    "full_name".into(),
                    "profile.headline".into(),
                    "skills".into(),
                ],
                Some(3600),
            )?;
            self.event_store
                .upsert_local_presentation_template(&template)?;
        }
        Ok(())
    }

    pub(crate) fn seed_vault_namespace(&self) -> VaultNamespace {
        VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: "persona-professional".into(),
        }
    }

    pub(crate) fn parse_vault_namespace_arg(
        &self,
        namespace_arg: Option<&str>,
    ) -> Result<VaultNamespace, ValidationError> {
        let Some(namespace_arg) = namespace_arg else {
            return Ok(self.seed_vault_namespace());
        };
        let Some((kind, owner_id)) = namespace_arg.split_once(':') else {
            return Err(ValidationError::new(
                "namespace must use the form root:<id> or persona:<id>",
            ));
        };
        let owner_kind = match kind {
            "root" => core_types::VaultOwnerKind::Root,
            "persona" => core_types::VaultOwnerKind::Persona,
            _ => {
                return Err(ValidationError::new(
                    "namespace kind must be root or persona",
                ));
            }
        };
        let namespace = VaultNamespace {
            owner_kind,
            owner_id: owner_id.into(),
        };
        namespace.validate()?;
        Ok(namespace)
    }

    pub(crate) fn vault_namespaces_for_root(
        &self,
        root_id: &str,
    ) -> Result<Vec<VaultNamespace>, ValidationError> {
        let persona_root = |persona_id: &str| {
            self.personas
                .iter()
                .chain(self.revoked_personas.iter())
                .find(|persona| persona.id == persona_id)
                .map(|persona| persona.root_id.as_str())
        };
        Ok(self
            .event_store
            .local_vault_namespaces()?
            .into_iter()
            .filter(|namespace| match namespace.owner_kind {
                core_types::VaultOwnerKind::Root => namespace.owner_id == root_id,
                core_types::VaultOwnerKind::Persona => {
                    persona_root(&namespace.owner_id) == Some(root_id)
                }
            })
            .collect())
    }

    pub(crate) fn refresh_storage_manifest_from_runtime(&mut self) -> Result<(), ValidationError> {
        if let Some(relationship) = self
            .event_store
            .materialized()
            .storage_relationships_current
            .get(&self.storage_relationship.id)
        {
            self.storage_relationship = relationship.clone();
        }
        if let Some(balance) = self
            .event_store
            .materialized()
            .storage_balances_current
            .get(&self.storage_ledger.relationship_id)
        {
            self.storage_ledger = balance.clone();
        }
        if let Some(manifest) = self.event_store.file_manifest(&self.storage_manifest.id) {
            self.storage_manifest = manifest;
        }
        Ok(())
    }

    pub(crate) fn current_storage_manifest(
        &self,
    ) -> Result<core_types::FileManifest, ValidationError> {
        Ok(self
            .event_store
            .file_manifest(&self.storage_manifest.id)
            .unwrap_or_else(|| self.storage_manifest.clone()))
    }

    pub(crate) fn build_seed_storage_manifest(
        &mut self,
    ) -> Result<core_types::FileManifest, ValidationError> {
        let manifest_id = self.storage_manifest.id.clone();
        let content_key = self.ensure_local_manifest_key(&manifest_id)?;
        let plaintext_chunks: Vec<Vec<u8>> = (0..12)
            .map(|ordinal| {
                if ordinal == 0 {
                    format!("emberlink:manifest:{manifest_id}:root").into_bytes()
                } else {
                    format!("emberlink:manifest:{manifest_id}:chunk:{ordinal:04}").into_bytes()
                }
            })
            .collect();

        let mut encrypted_blocks = Vec::with_capacity(plaintext_chunks.len());
        for (ordinal, plaintext) in plaintext_chunks.iter().enumerate() {
            encrypted_blocks.push(encrypt_block(
                &manifest_id,
                ordinal as u32,
                plaintext,
                &content_key,
            )?);
        }
        for block in &encrypted_blocks {
            self.event_store.upsert_encrypted_block(block)?;
        }

        let manifest = publish_manifest(
            &manifest_id,
            encrypted_blocks[0].chunk.chunk_id.clone(),
            encrypted_blocks
                .iter()
                .map(|block| block.chunk.clone())
                .collect(),
            vec![self.wrap_manifest_access_for_device(&manifest_id, "device-root-a-01")?],
        );
        Ok(manifest)
    }

    pub(crate) fn current_storage_relationship(&self) -> core_types::StorageRelationship {
        match self
            .event_store
            .materialized()
            .storage_relationships_current
            .get(&self.storage_relationship.id)
        {
            Some(relationship) if relationship == &self.storage_relationship => {
                relationship.clone()
            }
            _ => self.storage_relationship.clone(),
        }
    }

    pub(crate) fn current_storage_ledger(&self) -> core_types::StorageLedgerEntry {
        match self
            .event_store
            .materialized()
            .storage_balances_current
            .get(&self.storage_ledger.relationship_id)
        {
            Some(balance) if balance == &self.storage_ledger => balance.clone(),
            _ => self.storage_ledger.clone(),
        }
    }

    pub(crate) fn storage_restore_plan_snapshot(
        &self,
    ) -> Result<
        (
            core_types::StorageRelationship,
            core_types::FileManifest,
            String,
            Vec<ChunkReference>,
        ),
        ValidationError,
    > {
        let relationship = self.current_storage_relationship();
        let manifest = self.current_storage_manifest()?;
        let chunks = if self.event_store.file_manifest(&manifest.id).is_some() {
            let (restore_device_id, chunks) = self
                .event_store
                .plan_storage_restore(&manifest.id, &relationship)?;
            return Ok((relationship, manifest, restore_device_id, chunks));
        } else {
            plan_restore(&relationship, &manifest)?
        };
        let restore_device_id = manifest
            .authorized_devices
            .first()
            .map(|access| access.device_id.clone())
            .ok_or_else(|| ValidationError::new("no authorized restore device"))?;
        Ok((relationship, manifest, restore_device_id, chunks))
    }

    pub(crate) fn storage_open_snapshot(
        &mut self,
        device_ref: Option<&str>,
    ) -> Result<(core_types::FileManifest, String, Vec<Vec<u8>>), ValidationError> {
        let manifest = self.current_storage_manifest()?;
        let device_id = match device_ref {
            Some(device_ref) => self
                .resolve_device(device_ref)
                .map(|device| device.device_id.clone())
                .ok_or_else(|| {
                    ValidationError::new(format!("unknown active device: {device_ref}"))
                })?,
            None => {
                if self.event_store.file_manifest(&manifest.id).is_some() {
                    let (device_id, chunks) =
                        self.event_store.open_manifest_payload(&manifest.id)?;
                    return Ok((manifest, device_id, chunks));
                }
                manifest
                    .authorized_devices
                    .first()
                    .map(|access| access.device_id.clone())
                    .ok_or_else(|| ValidationError::new("no authorized restore device"))?
            }
        };
        if self.event_store.file_manifest(&manifest.id).is_none() {
            return Err(ValidationError::new(
                "current storage manifest is not available in runtime state",
            ));
        }
        let chunks = self
            .event_store
            .manifest_payload_chunks_for_device(&manifest.id, &device_id)?;
        Ok((manifest, device_id, chunks))
    }

    pub(crate) fn device_status_label(&self, device_id: &str) -> &'static str {
        if self
            .devices
            .iter()
            .any(|device| device.device_id == device_id && device.active)
        {
            "active"
        } else if self
            .revoked_devices
            .iter()
            .any(|device| device.device_id == device_id)
        {
            "inactive"
        } else {
            "unknown"
        }
    }

    pub(crate) fn storage_manifest_root_id(
        &self,
        manifest: &core_types::FileManifest,
    ) -> Result<String, ValidationError> {
        if let Some(root_id) = manifest.authorized_devices.iter().find_map(|access| {
            self.devices
                .iter()
                .chain(self.revoked_devices.iter())
                .find(|device| device.device_id == access.device_id)
                .map(|device| device.root_id.clone())
        }) {
            return Ok(root_id);
        }
        self.roots
            .first()
            .map(|root| root.id.clone())
            .ok_or_else(|| ValidationError::new("no root available for storage manifest"))
    }

    pub(crate) fn publish_storage_manifest_event(
        &mut self,
        root_id: &str,
        manifest: core_types::FileManifest,
        event_tag: &str,
    ) -> Result<(), ValidationError> {
        let signer = self.root_signer(root_id)?;
        let root_key_id = self.root_active_key_id(root_id)?;
        self.append_live_event(
            self.allocate_event_id(event_tag),
            storage_manifest_published_event(root_id, &self.storage_relationship.id, manifest),
            SignerBinding::root(root_id, root_key_id),
            &signer,
        )?;
        self.refresh_storage_manifest_from_runtime()
    }

    pub(crate) fn publish_storage_relationship_event(
        &mut self,
        root_id: &str,
        relationship: core_types::StorageRelationship,
        event_tag: &str,
    ) -> Result<(), ValidationError> {
        let signer = self.root_signer(root_id)?;
        let root_key_id = self.root_active_key_id(root_id)?;
        self.append_live_event(
            self.allocate_event_id(event_tag),
            storage_relationship_created_event(root_id, relationship),
            SignerBinding::root(root_id, root_key_id),
            &signer,
        )?;
        self.refresh_storage_manifest_from_runtime()
    }

    pub(crate) fn publish_storage_ledger_event(
        &mut self,
        root_id: &str,
        entry: core_types::StorageLedgerEntry,
        event_tag: &str,
    ) -> Result<(), ValidationError> {
        let signer = self.root_signer(root_id)?;
        let root_key_id = self.root_active_key_id(root_id)?;
        self.append_live_event(
            self.allocate_event_id(event_tag),
            storage_ledger_updated_event(root_id, entry),
            SignerBinding::root(root_id, root_key_id),
            &signer,
        )?;
        self.refresh_storage_manifest_from_runtime()
    }

    pub(crate) fn resolve_root_ref(&self, root_ref: &str) -> Option<String> {
        self.resolve_root(root_ref).map(|root| root.id.clone())
    }

    pub(crate) fn resolve_root(&self, root_ref: &str) -> Option<&IdentityRoot> {
        self.roots
            .iter()
            .find(|root| root.id == root_ref || root.display_name.eq_ignore_ascii_case(root_ref))
    }

    pub(crate) fn resolve_persona(&self, persona_ref: &str) -> Option<&Persona> {
        self.personas
            .iter()
            .find(|persona| persona.id == persona_ref || persona.label == persona_ref)
    }

    pub(crate) fn require_root(&self, root_ref: &str) -> Result<String, ValidationError> {
        self.resolve_root_ref(root_ref).ok_or_else(|| {
            let available: Vec<String> = self
                .roots
                .iter()
                .map(|r| format!("{} ({})", r.id, r.display_name))
                .collect();
            let hint = if available.is_empty() {
                "No roots exist. Run `init --name <name>` to create one.".to_string()
            } else {
                format!("Available roots: {}", available.join(", "))
            };
            ValidationError::not_found("root", &format!("{root_ref}. {hint}"))
        })
    }

    pub(crate) fn require_persona(&self, persona_ref: &str) -> Result<&Persona, ValidationError> {
        self.resolve_persona(persona_ref).ok_or_else(|| {
            let available: Vec<String> = self
                .personas
                .iter()
                .map(|p| format!("{} ({})", p.id, p.label))
                .collect();
            let hint = if available.is_empty() {
                "No personas exist. Run `init --name <name>` or `persona create` to create one."
                    .to_string()
            } else {
                format!("Available personas: {}", available.join(", "))
            };
            ValidationError::not_found("persona", &format!("{persona_ref}. {hint}"))
        })
    }

    #[allow(dead_code)]
    pub(crate) fn require_device(
        &self,
        device_ref: &str,
    ) -> Result<&DeviceMembership, ValidationError> {
        self.resolve_device(device_ref).ok_or_else(|| {
            let available: Vec<String> = self
                .devices
                .iter()
                .map(|d| format!("{} ({})", d.device_id, d.label))
                .collect();
            let hint = if available.is_empty() {
                "No devices exist.".to_string()
            } else {
                format!("Available devices: {}", available.join(", "))
            };
            ValidationError::not_found("device", &format!("{device_ref}. {hint}"))
        })
    }

    pub(crate) fn persona_display_ref(&self, persona_id: &str) -> String {
        if let Some(persona) = self
            .personas
            .iter()
            .find(|persona| persona.id == persona_id)
        {
            format!("{} ({})", persona.id, persona.label)
        } else if let Some(persona) = self
            .revoked_personas
            .iter()
            .find(|persona| persona.id == persona_id)
        {
            format!("{} ({})", persona.id, persona.label)
        } else {
            persona_id.to_string()
        }
    }

    pub(crate) fn resolve_device(&self, device_ref: &str) -> Option<&DeviceMembership> {
        self.devices.iter().find(|device| {
            device.device_id == device_ref || device.label.eq_ignore_ascii_case(device_ref)
        })
    }

    pub(crate) fn resolve_device_any(&self, device_ref: &str) -> Option<&DeviceMembership> {
        self.resolve_device(device_ref).or_else(|| {
            self.revoked_devices.iter().find(|device| {
                device.device_id == device_ref || device.label.eq_ignore_ascii_case(device_ref)
            })
        })
    }

    pub(crate) fn grant_persona_access_to_active_root_devices(
        &mut self,
        persona_id: &str,
        root_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let device_ids: Vec<String> = self
            .devices
            .iter()
            .filter(|device| device.root_id == root_id && device.active)
            .map(|device| device.device_id.clone())
            .collect();
        for device_id in &device_ids {
            self.event_store
                .grant_persona_device_access(persona_id, device_id)?;
        }
        Ok(device_ids)
    }

    pub(crate) fn persona_access_device_ids(
        &self,
        persona_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        Ok(self
            .event_store
            .persona_device_access_for_persona(persona_id)?
            .into_iter()
            .map(|record| record.device_id)
            .collect())
    }

    pub(crate) fn active_persona_access_device_ids(
        &self,
        persona_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let device_ids = self.persona_access_device_ids(persona_id)?;
        Ok(device_ids
            .into_iter()
            .filter(|device_id| {
                self.devices
                    .iter()
                    .any(|device| device.device_id == *device_id && device.active)
            })
            .collect())
    }

    pub(crate) fn persona_access_descriptions(
        &self,
        persona_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let mut lines = Vec::new();
        for device_id in self.persona_access_device_ids(persona_id)? {
            if let Some(device) = self
                .devices
                .iter()
                .find(|device| device.device_id == device_id)
            {
                lines.push(format!("{}\t{}\tactive", device.device_id, device.label));
            } else if let Some(device) = self
                .revoked_devices
                .iter()
                .find(|device| device.device_id == device_id)
            {
                lines.push(format!("{}\t{}\tinactive", device.device_id, device.label));
            } else {
                lines.push(format!("{device_id}\t(unknown device)\tinactive"));
            }
        }
        Ok(lines)
    }

    pub(crate) fn device_access_descriptions(
        &self,
        device_id: &str,
    ) -> Result<Vec<String>, ValidationError> {
        let mut lines = Vec::new();
        for record in self
            .event_store
            .persona_device_access_for_device(device_id)?
        {
            if let Some(persona) = self
                .personas
                .iter()
                .find(|persona| persona.id == record.persona_id)
            {
                lines.push(format!("{}\t{}\tactive", persona.id, persona.label));
            } else if let Some(persona) = self
                .revoked_personas
                .iter()
                .find(|persona| persona.id == record.persona_id)
            {
                lines.push(format!("{}\t{}\trevoked", persona.id, persona.label));
            } else {
                lines.push(format!(
                    "{}\t(unknown persona)\tinactive",
                    record.persona_id
                ));
            }
        }
        Ok(lines)
    }

    pub(crate) fn handle_structured_command(&mut self, tokens: &[&str]) -> String {
        match tokens {
            ["root", "create", rest @ ..] => self.handle_root_create(rest),
            ["root", "rotate-key", rest @ ..] => self.handle_root_rotate_key(rest),
            ["recovery", "guardian-enroll", rest @ ..] => self.handle_guardian_enroll(rest),
            ["recovery", "request", rest @ ..] => self.handle_recovery_request(rest),
            ["recovery", "approve", rest @ ..] => self.handle_recovery_approve(rest),
            ["recovery", "contest", rest @ ..] => self.handle_recovery_contest(rest),
            ["recovery", "reject", rest @ ..] => self.handle_recovery_reject(rest),
            ["recovery", "execute", rest @ ..] => self.handle_recovery_execute(rest),
            ["device", "add", rest @ ..] => self.handle_device_add(rest),
            ["device", "revoke", rest @ ..] => self.handle_device_revoke(rest),
            ["device", "rotate-key", rest @ ..] => self.handle_device_rotate_key(rest),
            ["device", "rotate-encryption-key", rest @ ..] => {
                self.handle_device_rotate_encryption_key(rest)
            }
            ["persona", "create", rest @ ..] => self.handle_persona_create(rest),
            ["persona", "grant-device", rest @ ..] => self.handle_persona_grant_device(rest),
            ["persona", "revoke-device", rest @ ..] => self.handle_persona_revoke_device(rest),
            ["persona", "rotate-key", rest @ ..] => self.handle_persona_rotate_key(rest),
            ["persona", "revoke", rest @ ..] => self.handle_persona_revoke(rest),
            ["export-events", rest @ ..] => self.handle_export_events(rest),
            ["import-events", rest @ ..] => self.handle_import_events(rest),
            ["message", "send", rest @ ..] => self.handle_message_send(rest),
            ["content", "publish", rest @ ..] => self.handle_content_publish(rest),
            ["create-root", rest @ ..] => {
                let name = rest.join(" ");
                if name.is_empty() {
                    "Usage: root create --name <display name>\n".to_string()
                } else {
                    match self.create_root_command(&name) {
                        Ok(message) => message,
                        Err(err) => format!("Failed to create root: {}\n", err),
                    }
                }
            }
            ["create-persona", root_ref, template, label @ ..] => {
                let label = label.join(" ");
                if label.is_empty() {
                    return "Usage: persona create --root <root> --label <label> --template <template>\n"
                        .to_string();
                }
                let profile = match parse_persona_template(template) {
                    Some(template) => disclosure_profile_for_template(template).to_string(),
                    None => {
                        return "Unknown template. Use one of: professional, friends, pseudonymous\n".to_string()
                    }
                };
                match self.create_persona_command(root_ref, &label, Some(profile)) {
                    Ok(message) => message,
                    Err(err) => format!("Failed to create persona: {}\n", err),
                }
            }
            _ => "Unknown command. Run `help` for examples.\n".to_string(),
        }
    }

    fn render_status(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Emberlink identity status").unwrap();
        writeln!(&mut out, "  peer:    {}", self.peer_id).unwrap();
        writeln!(&mut out, "  state:   {}", self.state_location_label()).unwrap();
        writeln!(&mut out, "  events:  {}", self.event_store.event_count()).unwrap();
        writeln!(&mut out).unwrap();

        if self.roots.is_empty() {
            writeln!(&mut out, "No identity roots. Run `init` to get started.").unwrap();
            return out;
        }

        writeln!(&mut out, "Roots ({}):", self.roots.len()).unwrap();
        for root in &self.roots {
            let device_count = self.devices.iter().filter(|d| d.root_id == root.id).count();
            let persona_count = self
                .personas
                .iter()
                .filter(|p| p.root_id == root.id)
                .count();
            writeln!(
                &mut out,
                "  {}\t{}\t{} device(s), {} persona(s)",
                root.id, root.display_name, device_count, persona_count
            )
            .unwrap();
        }

        if !self.personas.is_empty() {
            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Personas ({}):", self.personas.len()).unwrap();
            for persona in &self.personas {
                let profile = persona.disclosure_profile.as_deref().unwrap_or("none");
                writeln!(
                    &mut out,
                    "  {}\t{}\tprofile: {}",
                    persona.id, persona.label, profile
                )
                .unwrap();
            }
        }

        if !self.trust_attestations.is_empty() {
            writeln!(&mut out).unwrap();
            writeln!(
                &mut out,
                "Trust attestations: {}",
                self.trust_attestations.len()
            )
            .unwrap();
        }

        out
    }

    fn render_help(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Emberlink shell").unwrap();
        writeln!(&mut out, "state: {}", self.state_location_label()).unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Getting started").unwrap();
        writeln!(
            &mut out,
            "  status                     Show identity overview"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  init --name <name>         Create a new identity from scratch"
        )
        .unwrap();
        writeln!(&mut out, "                             [--label <persona>] [--template professional|friends|pseudonymous]").unwrap();
        writeln!(
            &mut out,
            "  invite create              Generate invite file for a new user"
        )
        .unwrap();
        writeln!(
            &mut out,
            "                             --persona <id> --relay <addr> [--out <file>]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  invite accept              Join using an invite from another user"
        )
        .unwrap();
        writeln!(
            &mut out,
            "                             --file <path> [--name <name>] [--template ...]"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Identity — Roots").unwrap();
        writeln!(
            &mut out,
            "  root create --name <name>                      Create a new identity root"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  root rotate-key --root <root>                  Rotate root signing key"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  list roots                                     List all roots"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show root <ref>                                Show root details"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Identity — Devices").unwrap();
        writeln!(
            &mut out,
            "  device add --root <root> --label <label>       Add a device"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  device revoke --device <device>                Revoke a device"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  device rotate-key --device <device>            Rotate device signing key"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  device rotate-encryption-key --device <device> Rotate device encryption key"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  list devices                                   List all devices"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show device <ref>                              Show device details"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Identity — Personas").unwrap();
        writeln!(
            &mut out,
            "  persona create --root <root> --label <label> --template <t>"
        )
        .unwrap();
        writeln!(&mut out, "                                                 Create a persona (templates: professional, friends, pseudonymous)").unwrap();
        writeln!(
            &mut out,
            "  persona revoke --persona <persona>             Revoke a persona"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona rotate-key --persona <persona>         Rotate persona key"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona grant-device --persona <p> --device <d>  Grant device access to persona"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona revoke-device --persona <p> --device <d> Revoke device access from persona"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  list personas                                  List all personas"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show persona <ref>                             Show persona details"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Trust").unwrap();
        writeln!(
            &mut out,
            "  show trust                                     Show trust graph"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  trust --recipient <peer>                       Score trust for audience"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  trust attest --from <persona> --to <persona> --domain <d> --score <0.0-1.0>"
        )
        .unwrap();
        writeln!(&mut out, "                                                 [--recipient <peer>]  (recipient-bound attestation)").unwrap();
        writeln!(&mut out, "  trust revoke --attestation <id> --by <persona>").unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Vault & Disclosure").unwrap();
        writeln!(
            &mut out,
            "  disclose --from <persona> --to <persona> --template <template>"
        )
        .unwrap();
        writeln!(&mut out, "                                                 Issue and send a disclosure in one step").unwrap();
        writeln!(
            &mut out,
            "  show vault [--namespace root:<id>|persona:<id>]  Show vault objects and artifacts"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault write-record --object <obj> --schema <s> --app <ns> --json <data>"
        )
        .unwrap();
        writeln!(&mut out, "                                                 [--namespace root:<id>|persona:<id>] [--json-file <path>]").unwrap();
        writeln!(
            &mut out,
            "  vault show-record --object <id>                Show a vault record's contents"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault delete --object <id>                     Tombstone a vault object"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault template add --id <id> --object <obj> --schema <s> --audience peer|service"
        )
        .unwrap();
        writeln!(&mut out, "                     --namespace <ns> --field <path> [--field ...]  [--expires-in <sec>]").unwrap();
        writeln!(
            &mut out,
            "  vault issue --template <t> --recipient <id>    Issue a disclosure artifact"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault show-artifact --artifact <id>            Show an issued artifact"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault send-artifact --artifact <id> --from <persona> --to <persona>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault export-artifact --artifact <id> --out <path>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault inspect-export --file <path>             Inspect an exported artifact file"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  claim list --persona <persona>                 List persona-scoped credential claims"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  claim store --persona <persona> --object <id> --schema <schema> --json <data>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  claim show --persona <persona> --object <id>  Show claim metadata and payload"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  claim disclose --persona <persona> --object <id> --to <persona> --field <path>"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Service bindings (local-only):").unwrap();
        writeln!(
            &mut out,
            "  service bind --persona <p> --kind <k> --label <l> --account <a> [--endpoint <url>]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  service list [--persona <persona>]              List service bindings"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  service unbind --id <binding-id>                Remove a service binding"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Passkeys:").unwrap();
        writeln!(
            &mut out,
            "  passkey register --persona <p> --rp-id <domain> --rp-name <label> [--user <name>]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  passkey list [--persona <persona>]               List registered passkeys"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  passkey authenticate --id <binding-id> [--challenge <b64url>]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  passkey remove --id <binding-id>                 Remove a passkey registration"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Import:").unwrap();
        writeln!(
            &mut out,
            "  import passwords --persona <p> --format bitwarden|1password --file <path>"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
        writeln!(
            &mut out,
            "  vault import-artifact --file <path>            Import artifact from file"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault import-message --message <id>            Import disclosure from a message"
        )
        .unwrap();
        writeln!(&mut out, "  vault revoke --artifact <id> --reason <reason>  Revoke a previously issued disclosure").unwrap();
        writeln!(
            &mut out,
            "  vault store --file <path> --object <id> [--class document|attachment|secret]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "                                                 Store a file in the vault"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault export-file --object <id> --out <path>   Export a vault file to disk"
        )
        .unwrap();
        writeln!(&mut out, "  vault received [--limit N]                     List received artifacts (with verification status)").unwrap();
        writeln!(&mut out, "  vault show-received --artifact <id>            Show received artifact + verification status").unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Messaging & Content").unwrap();
        writeln!(
            &mut out,
            "  show messages [--limit N]                      List messages"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show disclosures [--limit N]                   List disclosure messages"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show disclosure <message-ref>                  Show disclosure details"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show content [--limit N]                       List published content"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  message send --from <persona> --to <persona> --ciphertext <hex>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  content publish --from <persona> --type <kind> --payload <hex>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "                 --visibility public|trust-gated|direct"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Recovery").unwrap();
        writeln!(
            &mut out,
            "  show recovery                                  Show recovery state & guardians"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  recovery guardian-enroll --root <root> --guardian <id> --label <label>"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  recovery request --root <root> --device <device>"
        )
        .unwrap();
        writeln!(&mut out, "  recovery approve --guardian <guardian>").unwrap();
        writeln!(
            &mut out,
            "  recovery contest --guardian <id> --reason <text>"
        )
        .unwrap();
        writeln!(&mut out, "  recovery reject --reason <text>").unwrap();
        writeln!(
            &mut out,
            "  recovery execute [--replacement-device <device>]"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Sync — Quick").unwrap();
        writeln!(
            &mut out,
            "  sync send --to <peer.tsv>                      Send state to peer's relay"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync receive                                   Drain own relay mailbox"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync preview --state <path>                    Preview sync from another node"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync apply --state <path>                      Import state from another node"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync mutual --state <path>                     Bidirectional sync with peer"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync export --out <path> [--for-state <path>]  Export sync batch to file"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync import --file <path>                      Import sync batch from file"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Sync — Relay operations").unwrap();
        writeln!(
            &mut out,
            "  sync endpoint show                             Show relay endpoint config"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync endpoint set --device <d> (--hint <h> | --bind <addr>)"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync endpoint rotate --device <d> (--hint <h> | --bind <addr>)"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-send-state --state <peer.tsv>       Send state via relay"
        )
        .unwrap();
        writeln!(
            &mut out,
            "                        [--source-persona <p>] [--profile full|light]"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-drain-self                          Drain own relay mailbox"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-cycle --state <peer.tsv>            Send + receive in one operation"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-stats --bind <addr>                 Query relay server statistics"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Storage").unwrap();
        writeln!(
            &mut out,
            "  show storage                                   Show storage state"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  storage open [--device <id>]                   Open manifest snapshot"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  storage restore-plan                           Show restore operations needed"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  storage audit                                  Verify storage integrity"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  storage gc-plan [--namespace <ns>]             Plan garbage collection"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  storage gc-apply [--namespace <ns>]            Execute garbage collection"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Inspect & Debug").unwrap();
        writeln!(
            &mut out,
            "  show broker [--disclose-links]                 Show brokerage view"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  show state                                     Show raw materialized state"
        )
        .unwrap();
        writeln!(&mut out, "  list roots | devices | personas | keys").unwrap();
        writeln!(&mut out, "  show root <ref> | device <ref> | persona <ref>").unwrap();
        writeln!(
            &mut out,
            "  inspect --state <path> --screen <screen>       Inspect another node's state"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  compare --state <path>                         Diff with another node"
        )
        .unwrap();
        writeln!(&mut out).unwrap();

        writeln!(&mut out, "Session").unwrap();
        writeln!(&mut out, "  help       Show this help").unwrap();
        writeln!(&mut out, "  reset      Reset to initial state").unwrap();
        writeln!(&mut out, "  quit       Exit shell").unwrap();

        out
    }

    fn handle_init(&mut self, tokens: &[&str]) -> String {
        let mut name = None;
        let mut label = None;
        let mut template = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--name" if i + 1 < tokens.len() => {
                    name = Some(
                        tokens[i + 1..]
                            .iter()
                            .take_while(|t| !t.starts_with("--"))
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    i += 2;
                    // Skip tokens consumed by name
                    while i < tokens.len() && !tokens[i].starts_with("--") {
                        i += 1;
                    }
                }
                "--label" if i + 1 < tokens.len() => {
                    label = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--template" if i + 1 < tokens.len() => {
                    template = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => i += 1,
            }
        }

        let Some(display_name) = name else {
            return "Usage: init --name <your name> [--label <persona-label>] [--template professional|friends|pseudonymous]\n\
                    \n\
                    Creates a fresh identity root, device, and persona.\n\
                    Example: init --name Alice --template professional\n"
                .to_string();
        };

        if display_name.is_empty() {
            return "Name cannot be empty.\n".to_string();
        }

        let mut out = String::new();

        // Create root
        let root_result = match self.create_root_command(&display_name) {
            Ok(msg) => msg,
            Err(err) => return format!("Failed to create root: {err}\n"),
        };
        out.push_str(&root_result);

        // Extract root ID from the result line (format: "created root\t<id>\t<name>\n")
        let root_id = root_result
            .split('\t')
            .nth(1)
            .unwrap_or("unknown")
            .to_string();

        // Create device
        let device_label = format!("{}-device", display_name.to_lowercase().replace(' ', "-"));
        match self.create_device_command(&root_id, &device_label) {
            Ok(msg) => out.push_str(&msg),
            Err(err) => return format!("{out}Failed to create device: {err}\n"),
        }

        // Create persona
        let persona_label = label.unwrap_or_else(|| display_name.to_lowercase().replace(' ', "-"));
        let profile = template
            .as_deref()
            .and_then(parse_persona_template)
            .map(|t| disclosure_profile_for_template(t).to_string());
        match self.create_persona_command(&root_id, &persona_label, profile) {
            Ok(msg) => out.push_str(&msg),
            Err(err) => return format!("{out}Failed to create persona: {err}\n"),
        }

        writeln!(&mut out).unwrap();
        writeln!(
            &mut out,
            "Identity initialized. Run `status` to see your identity."
        )
        .unwrap();
        out
    }

    pub(crate) fn handle_invite_create(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: invite create --persona <persona-id> --relay <bind-address> --out <file>\n\
                     \n\
                     Creates a portable invite file that a new user can accept to bootstrap\n\
                     a connection with you through the specified relay.\n";
        let mut persona_id = None;
        let mut relay_bind = None;
        let mut out_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--relay" if i + 1 < tokens.len() => {
                    relay_bind = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_id) = persona_id else {
            return usage.to_string();
        };
        let Some(relay_bind) = relay_bind else {
            return usage.to_string();
        };

        // Validate persona exists
        let persona = match self.event_store.materialized().persona(&persona_id) {
            Some(p) => p.clone(),
            None => {
                let available: Vec<_> = self
                    .event_store
                    .materialized()
                    .personas_current
                    .keys()
                    .cloned()
                    .collect();
                return format!(
                    "Unknown persona: {persona_id}\nAvailable: {}\n",
                    if available.is_empty() {
                        "(none — run init first)".to_string()
                    } else {
                        available.join(", ")
                    }
                );
            }
        };

        let invite = PortableInvite {
            inviter_name: persona.label.clone(),
            inviter_persona_id: persona_id.clone(),
            relay_bind_address: relay_bind.clone(),
            identity_events: self.event_store.events().to_vec(),
        };

        let out_file = PathBuf::from(
            out_path.unwrap_or_else(|| format!("{}.emberlink-invite", persona.label)),
        );
        match fs::write(&out_file, invite.encode()) {
            Ok(()) => {
                let mut out = String::new();
                writeln!(&mut out, "invite created\t{}", out_file.display()).unwrap();
                writeln!(&mut out, "  persona\t{persona_id}\t{}", persona.label).unwrap();
                writeln!(&mut out, "  relay\t{relay_bind}").unwrap();
                writeln!(&mut out, "  events\t{}", invite.identity_events.len()).unwrap();
                writeln!(&mut out).unwrap();
                writeln!(
                    &mut out,
                    "Share this file with new users. They can join with:"
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "  invite accept --file {} --name <their-name>",
                    out_file.display()
                )
                .unwrap();
                out
            }
            Err(err) => format!("Failed to write invite file: {err}\n"),
        }
    }

    pub(crate) fn handle_invite_accept(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: invite accept --file <invite-file> [--name <your-name>] [--template professional|friends|pseudonymous]\n\
                     \n\
                     Accepts an invite from another user. Creates your identity if needed\n\
                     and imports the inviter's identity for sync.\n";
        let mut file_path = None;
        let mut name = None;
        let mut template = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--name" if i + 1 < tokens.len() => {
                    name = Some(
                        tokens[i + 1..]
                            .iter()
                            .take_while(|t| !t.starts_with("--"))
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    i += 2;
                    while i < tokens.len() && !tokens[i].starts_with("--") {
                        i += 1;
                    }
                }
                "--template" if i + 1 < tokens.len() => {
                    template = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(file_path) = file_path else {
            return usage.to_string();
        };

        // Read and decode invite
        let payload = match fs::read(&file_path) {
            Ok(data) => data,
            Err(err) => return format!("Failed to read invite file: {err}\n"),
        };
        let invite = match PortableInvite::decode(&payload) {
            Ok(inv) => inv,
            Err(err) => return format!("Invalid invite file: {err}\n"),
        };

        let mut out = String::new();
        writeln!(
            &mut out,
            "Invite from: {} ({})",
            invite.inviter_name, invite.inviter_persona_id
        )
        .unwrap();
        writeln!(&mut out, "Relay: {}", invite.relay_bind_address).unwrap();
        writeln!(&mut out, "Events: {}", invite.identity_events.len()).unwrap();
        writeln!(&mut out).unwrap();

        // Create identity if none exists
        let has_identity = !self.event_store.materialized().roots_current.is_empty();
        if !has_identity {
            let Some(my_name) = name else {
                return format!(
                    "{out}You don't have an identity yet. Provide --name <your-name> to create one.\n"
                );
            };
            let init_args: Vec<&str> = if let Some(ref tmpl) = template {
                vec!["--name", &my_name, "--template", tmpl]
            } else {
                vec!["--name", &my_name]
            };
            let init_result = self.handle_init(&init_args);
            out.push_str(&init_result);
        }

        // Import the inviter's events as a sync batch
        let batch_id = generate_random_identifier("invite-batch");
        let peer_id = format!("invite:{}", invite.inviter_persona_id);
        let last_event_id = invite.identity_events.last().map(|e| e.event_id.as_str());
        match self.event_store.import_sync_batch(
            &peer_id,
            &batch_id,
            &invite.identity_events,
            last_event_id,
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        ) {
            Ok(imported) => {
                if let Err(err) = self.persist_to_disk() {
                    writeln!(&mut out, "warning: failed to persist state: {err}").unwrap();
                }
                writeln!(
                    &mut out,
                    "Imported {imported} events from {}",
                    invite.inviter_name
                )
                .unwrap();
            }
            Err(err) => {
                return format!("{out}Failed to import inviter's events: {err}\n");
            }
        }
        writeln!(&mut out).unwrap();
        writeln!(
            &mut out,
            "You can now sync with {} via:",
            invite.inviter_name
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync send --to <{}-state-file>",
            invite.inviter_name.to_lowercase().replace(' ', "-")
        )
        .unwrap();
        writeln!(&mut out, "  sync receive").unwrap();
        out
    }

    pub(crate) fn handle_root_create(&mut self, tokens: &[&str]) -> String {
        let mut name = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--name" if i + 1 < tokens.len() => {
                    name = Some(tokens[i + 1..].join(" "));
                    break;
                }
                value if !value.starts_with('-') => {
                    name = Some(tokens[i..].join(" "));
                    break;
                }
                _ => {}
            }
            i += 1;
        }

        let Some(name) = name else {
            return "Usage: root create --name <display name>\n".to_string();
        };

        match self.create_root_command(&name) {
            Ok(message) => message,
            Err(err) => format!("Failed to create root: {}\n", err),
        }
    }

    pub(crate) fn handle_root_rotate_key(&mut self, tokens: &[&str]) -> String {
        let mut root = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--root" | "-r" if i + 1 < tokens.len() => {
                    root = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(root_ref) = root else {
            return "Usage: root rotate-key --root <root-id-or-name>\n".to_string();
        };

        match self.rotate_root_key_command(&root_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to rotate root key: {}\n", err),
        }
    }

    pub(crate) fn handle_guardian_enroll(&mut self, tokens: &[&str]) -> String {
        let mut root = None;
        let mut guardian_id = None;
        let mut label = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--root" | "-r" if i + 1 < tokens.len() => {
                    root = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--guardian" | "-g" if i + 1 < tokens.len() => {
                    guardian_id = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--label" | "-l" if i + 1 < tokens.len() => {
                    label = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(root_ref) = root else {
            return "Usage: recovery guardian-enroll --root <root> --guardian <guardian-id> --label <label>\n".to_string();
        };
        let Some(gid) = guardian_id else {
            return "Usage: recovery guardian-enroll --root <root> --guardian <guardian-id> --label <label>\n".to_string();
        };
        let lbl = label.unwrap_or_else(|| gid.clone());

        match self.enroll_guardian_command(&root_ref, &gid, &lbl) {
            Ok(message) => message,
            Err(err) => format!("Failed to enroll guardian: {}\n", err),
        }
    }

    pub(crate) fn handle_export_events(&self, tokens: &[&str]) -> String {
        let mut out_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--out" | "-o" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(path) = out_path else {
            return "Usage: export-events --out <path>\n".to_string();
        };

        let data = self.event_store.export_events();
        match fs::write(&path, &data) {
            Ok(()) => format!(
                "exported {} events to {}\n",
                self.event_store.event_count(),
                path
            ),
            Err(err) => format!("Failed to write export file: {err}\n"),
        }
    }

    pub(crate) fn handle_import_events(&mut self, tokens: &[&str]) -> String {
        let mut file_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--file" | "-f" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(path) = file_path else {
            return "Usage: import-events --file <path>\n".to_string();
        };

        let data = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read import file: {err}\n"),
        };

        match self.event_store.import_events(
            &data,
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        ) {
            Ok(imported) => {
                self.hydrate_identity_state();
                self.reconcile_recovery_session_from_state();
                self.refresh_identity_counters();
                if let Err(err) = self.persist_to_disk() {
                    return format!("imported {imported} events but failed to persist: {err}\n");
                }
                format!("imported {imported} events from {path}\n")
            }
            Err(err) => format!("Failed to import events: {err}\n"),
        }
    }

    pub(crate) fn handle_recovery_request(&mut self, tokens: &[&str]) -> String {
        let mut root = None;
        let mut device = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--root" | "-r" if i + 1 < tokens.len() => {
                    root = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--device" | "-d" if i + 1 < tokens.len() => {
                    device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(root_ref) = root else {
            return "Usage: recovery request --root <root> --device <device>\n".to_string();
        };
        let Some(device_ref) = device else {
            return "Usage: recovery request --root <root> --device <device>\n".to_string();
        };

        match self.create_recovery_request_command(&root_ref, &device_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to create recovery request: {}\n", err),
        }
    }

    pub(crate) fn handle_recovery_approve(&mut self, tokens: &[&str]) -> String {
        let mut guardian = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--guardian" | "-g" if i + 1 < tokens.len() => {
                    guardian = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(guardian_id) = guardian else {
            return "Usage: recovery approve --guardian <guardian-id>\n".to_string();
        };

        match self.approve_recovery_command(&guardian_id) {
            Ok(message) => message,
            Err(err) => format!("Failed to approve recovery request: {}\n", err),
        }
    }

    pub(crate) fn handle_recovery_contest(&mut self, tokens: &[&str]) -> String {
        let mut guardian = None;
        let mut reason = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--guardian" | "-g" if i + 1 < tokens.len() => {
                    guardian = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--reason" if i + 1 < tokens.len() => {
                    reason = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(guardian_id) = guardian else {
            return "Usage: recovery contest --guardian <guardian-id> --reason <reason>\n"
                .to_string();
        };
        let Some(reason) = reason else {
            return "Usage: recovery contest --guardian <guardian-id> --reason <reason>\n"
                .to_string();
        };

        match self.contest_recovery_command(&guardian_id, &reason) {
            Ok(message) => message,
            Err(err) => format!("Failed to contest recovery request: {}\n", err),
        }
    }

    pub(crate) fn handle_recovery_reject(&mut self, tokens: &[&str]) -> String {
        let mut reason = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--reason" if i + 1 < tokens.len() => {
                    reason = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(reason) = reason else {
            return "Usage: recovery reject --reason <reason>\n".to_string();
        };

        match self.reject_recovery_command(&reason) {
            Ok(message) => message,
            Err(err) => format!("Failed to reject recovery request: {}\n", err),
        }
    }

    pub(crate) fn handle_storage(&mut self, tokens: &[&str]) -> String {
        match tokens {
            [] => self.render_storage(),
            ["open"] => self.handle_storage_open(None),
            ["open", "--device", device_ref] => self.handle_storage_open(Some(device_ref)),
            ["restore-plan"] => self.render_storage_restore_plan(),
            ["audit"] => self.render_storage_audit(),
            ["gc-plan"] => self.render_storage_gc_plan(None),
            ["gc-apply"] => self.handle_storage_gc_apply(None),
            ["gc-plan", "--namespace", namespace] => {
                self.render_storage_gc_plan(Some(namespace))
            }
            ["gc-apply", "--namespace", namespace] => self.handle_storage_gc_apply(Some(namespace)),
            _ => "Usage: storage [open [--device <id-or-label>]|restore-plan|audit|gc-plan [--namespace root:<id>|persona:<id>] | gc-apply [--namespace root:<id>|persona:<id>]]\n"
                .to_string(),
        }
    }

    fn handle_storage_open(&mut self, device_ref: Option<&str>) -> String {
        match self.storage_open_snapshot(device_ref) {
            Ok((manifest, device_id, chunks)) => {
                let total_bytes: usize = chunks.iter().map(|chunk| chunk.len()).sum();
                let mut out = String::new();
                writeln!(&mut out, "Storage Open").unwrap();
                writeln!(&mut out, "------------").unwrap();
                writeln!(&mut out, "Manifest: {}", manifest.id).unwrap();
                writeln!(&mut out, "Device: {}", device_id).unwrap();
                writeln!(&mut out, "Chunks: {}", chunks.len()).unwrap();
                writeln!(&mut out, "Bytes: {}", total_bytes).unwrap();
                for (ordinal, chunk) in chunks.iter().enumerate() {
                    let preview = String::from_utf8_lossy(chunk);
                    writeln!(
                        &mut out,
                        "  - {}\t{} bytes\t{}",
                        ordinal,
                        chunk.len(),
                        preview
                    )
                    .unwrap();
                }
                out
            }
            Err(err) => format!("Storage open blocked: {}\n", err),
        }
    }

    fn handle_storage_gc_apply(&mut self, namespace_arg: Option<&str>) -> String {
        let namespace = match self.parse_vault_namespace_arg(namespace_arg) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve storage namespace: {}\n", err),
        };
        match self.event_store.apply_local_vault_gc(&namespace) {
            Ok(Some(plan)) => format!(
                "Applied Storage GC\n------------------\nNamespace: {}:{}\nRemoved manifests: {}\nRemoved chunks: {}\n",
                namespace.owner_kind.as_str(),
                namespace.owner_id,
                join_or_none(&plan.collectable_manifest_ids),
                join_or_none(&plan.collectable_chunk_ids),
            ),
            Ok(None) => format!(
                "Applied Storage GC\n------------------\nNamespace: {}:{}\nRemoved manifests: none\nRemoved chunks: none\n",
                namespace.owner_kind.as_str(),
                namespace.owner_id,
            ),
            Err(err) => format!("Failed to apply storage gc: {}\n", err),
        }
    }

    pub(crate) fn handle_vault(&mut self, tokens: &[&str]) -> String {
        match tokens {
            [] => self.render_vault(None),
            ["--namespace", namespace] => self.render_vault(Some(namespace)),
            ["received"] => self.render_received_artifacts(),
            ["received", "--limit", n] => {
                self.render_received_artifacts_with_limit(n.parse().unwrap_or(0))
            }
            ["show-record", rest @ ..] => self.handle_vault_show_record(rest),
            ["show-artifact", rest @ ..] => self.handle_vault_show_artifact(rest),
            ["show-received", rest @ ..] => self.handle_vault_show_received(rest),
            ["write-record", rest @ ..] => self.handle_vault_write_record(rest),
            ["delete", rest @ ..] => self.handle_vault_delete(rest),
            ["template", "add", rest @ ..] => self.handle_vault_template_add(rest),
            ["issue", rest @ ..] => self.handle_vault_issue(rest),
            ["send-artifact", rest @ ..] => self.handle_vault_send_artifact(rest),
            ["export-artifact", rest @ ..] => self.handle_vault_export_artifact(rest),
            ["inspect-export", rest @ ..] => self.handle_vault_inspect_export(rest),
            ["import-artifact", rest @ ..] => self.handle_vault_import_artifact(rest),
            ["import-message", rest @ ..] => self.handle_vault_import_message(rest),
            ["revoke", rest @ ..] => self.handle_vault_revoke(rest),
            ["store", rest @ ..] => self.handle_vault_store(rest),
            ["export-file", rest @ ..] => self.handle_vault_export_file(rest),
            _ => "Usage: vault [--namespace root:<id>|persona:<id> | received | show-record --object <object-id> [--namespace root:<id>|persona:<id>] | show-artifact --artifact <artifact-id> | show-received --artifact <artifact-id> | write-record --object <object-id> --schema <schema-id> --app <app-namespace> [--version <schema-version>] [--namespace root:<id>|persona:<id>] (--json <compact-json> | --json-file <path>) | delete --object <object-id> [--namespace root:<id>|persona:<id>] | template add --id <template-id> --object <object-id> --schema <schema-id> --audience peer|service --namespace root:<id>|persona:<id> --field <path> [--field <path> ...] [--expires-in <seconds>] | issue --template <template-id> --recipient <recipient-id> [--namespace root:<id>|persona:<id>] [--expires-in <seconds>] | send-artifact --artifact <artifact-id> --from <persona> --to <persona-id-or-label> | export-artifact --artifact <artifact-id> --out <path> | inspect-export --file <path> | import-artifact --file <path> | import-message --message <message-id> | revoke --artifact <artifact-id> --reason <reason>]\n".to_string(),
        }
    }

    pub(crate) fn handle_claim(&mut self, tokens: &[&str]) -> String {
        match tokens {
            ["list", rest @ ..] => self.handle_claim_list(rest),
            ["show", rest @ ..] => self.handle_claim_show(rest),
            ["store", rest @ ..] => self.handle_claim_store(rest),
            ["disclose", rest @ ..] => self.handle_claim_disclose(rest),
            _ => "Usage: claim [list --persona <persona> | show --persona <persona> --object <id> | store --persona <persona> --object <id> --schema <schema> [--type self-asserted|peer-attested|service-issued|derived] [--issuer <persona>] [--subject <persona-or-id>] [--expires-at <epoch>] [--external-issuer <id>] [--external-credential-id <id>] (--json <compact-json> | --json-file <path>) | disclose --persona <persona> --object <id> --to <persona> --field <path> [--field <path> ...] [--expires-in <seconds>]]\n".to_string(),
        }
    }

    pub(crate) fn handle_passkey(&mut self, tokens: &[&str]) -> String {
        match tokens {
            ["register", rest @ ..] => self.handle_passkey_register(rest),
            ["list", rest @ ..] => self.handle_passkey_list(rest),
            ["authenticate", rest @ ..] | ["auth", rest @ ..] => {
                self.handle_passkey_authenticate(rest)
            }
            ["remove", rest @ ..] => self.handle_passkey_remove(rest),
            _ => "Usage: passkey [register --persona <p> --rp-id <domain> --rp-name <label> | list | authenticate --id <binding-id> | remove --id <binding-id>]\n".to_string(),
        }
    }

    pub(crate) fn handle_service(&mut self, tokens: &[&str]) -> String {
        match tokens {
            ["bind", rest @ ..] => self.handle_service_bind(rest),
            ["list", rest @ ..] => self.handle_service_list(rest),
            ["unbind", rest @ ..] => self.handle_service_unbind(rest),
            _ => "Usage: service [bind --persona <persona> --kind <adapter-kind> --label <service-label> --account <external-account-id> [--endpoint <url>] | list [--persona <persona>] | unbind --id <binding-id>]\n".to_string(),
        }
    }

    pub(crate) fn handle_import(&mut self, tokens: &[&str]) -> String {
        match tokens {
            ["passwords", rest @ ..] => self.handle_import_passwords(rest),
            _ => "Usage: import [passwords --persona <persona> --format bitwarden|1password --file <path>]\n".to_string(),
        }
    }

    pub(crate) fn handle_sync(&mut self, tokens: &[&str]) -> String {
        match tokens {
            [] => self.render_sync(),
            ["endpoint"] | ["endpoint", "show"] => self.render_sync(),
            ["endpoint", "set", rest @ ..] => self.handle_sync_endpoint_set(rest),
            ["endpoint", "rotate", rest @ ..] => self.handle_sync_endpoint_rotate(rest),
            ["preview", rest @ ..] => self.handle_sync_preview(rest),
            ["preview-file", rest @ ..] => self.handle_sync_preview_file(rest),
            ["apply", rest @ ..] => self.handle_sync_apply(rest),
            ["export", rest @ ..] => self.handle_sync_export(rest),
            ["import", rest @ ..] => self.handle_sync_import(rest),
            ["mutual", rest @ ..] => self.handle_sync_mutual(rest),
            ["relay-pack", rest @ ..] => self.handle_sync_relay_pack(rest),
            ["send", rest @ ..] => self.handle_sync_send(rest),
            ["receive"] => self.handle_sync_receive(),
            ["relay-send", rest @ ..] => self.handle_sync_relay_send(rest),
            ["relay-send-peer", rest @ ..] => self.handle_sync_relay_send_peer(rest),
            ["relay-send-state", rest @ ..] => self.handle_sync_relay_send_state(rest),
            ["relay-submit", rest @ ..] => self.handle_sync_relay_submit(rest),
            ["relay-drain", rest @ ..] => self.handle_sync_relay_drain(rest),
            ["relay-drain-self"] => self.handle_sync_relay_drain_self(&[]),
            ["relay-drain-state", rest @ ..] => self.handle_sync_relay_drain_state(rest),
            ["relay-cycle", rest @ ..] => self.handle_sync_relay_cycle(rest),
            ["relay-stats", rest @ ..] => self.handle_sync_relay_stats(rest),
            ["relay-unpack", rest @ ..] => self.handle_sync_relay_unpack(rest),
            ["relay-inspect", rest @ ..] => self.handle_sync_relay_inspect(rest),
            ["history"] => self.render_sync_history(),
            ["relay-check", rest @ ..] => self.handle_sync_relay_check(rest),
            _ => "Usage: sync [endpoint [show] | endpoint set --device <device> (--hint <transport-hint> | --bind <addr>) | endpoint rotate --device <device> (--hint <transport-hint> | --bind <addr>) | preview --state <path> [--profile full|light] | preview-file --file <path> | apply --state <path> [--profile full|light] | export --out <path> [--profile full|light] [--for-state <path>] | import --file <path> | relay-pack --file <path> --out <path> (--target-peer <peer-id> | --target-state <path>) [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>] | relay-send --bind <addr> (--target-peer <peer-id> | --target-state <path>) [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>] | relay-send-peer --peer <peer-id> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>] | relay-send-state --state <path> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>] | relay-submit --file <path> --bind <addr> | relay-drain --bind <addr> [--peer <peer-id>] | relay-drain-self | relay-drain-state --state <path> | relay-cycle --state <path> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>] | relay-stats --bind <addr> | relay-inspect --file <path> | relay-unpack --file <path> --out <path> | mutual --state <path> [--profile full|light] | history | relay-check --mode <mode> --persona <persona> [--threshold <value>] [--allow persona-a,persona-b]]\n".to_string(),
        }
    }

    pub(crate) fn handle_sync_send(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync send --to <peer-state-file>\n\
                     \n\
                     Sends your latest state to a peer's relay mailbox.\n\
                     Shorthand for: sync relay-send-state --state <path>\n";
        let mut to_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--to" if i + 1 < tokens.len() => {
                    to_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(to_path) = to_path else {
            return usage.to_string();
        };
        self.handle_sync_relay_send_state(&["--state", &to_path])
    }

    pub(crate) fn handle_sync_receive(&mut self) -> String {
        self.handle_sync_relay_drain_self(&[])
    }

    pub(crate) fn handle_sync_endpoint_set(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync endpoint set --device <device> (--hint <transport-hint> | --bind <addr>)\n";
        let Some((device_id, transport_hint)) = self.parse_sync_endpoint_tokens(tokens, usage)
        else {
            return usage.to_string();
        };

        match self.publish_endpoint_hint(&device_id, &transport_hint) {
            Ok(output) => output,
            Err(err) => format!("Failed to publish endpoint hint: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_endpoint_rotate(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync endpoint rotate --device <device> (--hint <transport-hint> | --bind <addr>)\n";
        let Some((device_id, transport_hint)) = self.parse_sync_endpoint_tokens(tokens, usage)
        else {
            return usage.to_string();
        };

        match self.rotate_endpoint_hint(&device_id, &transport_hint) {
            Ok(output) => output,
            Err(err) => format!("Failed to rotate endpoint hint: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_preview(&mut self, tokens: &[&str]) -> String {
        let options = match self.parse_sync_target_options(
            tokens,
            "Usage: sync preview --state <path> [--profile full|light] [--mode open|trust-gated|network-scoped] [--source-persona <persona>] [--threshold <value>] [--allow persona-a,persona-b]\n",
        ) {
            Ok(options) => options,
            Err(message) => return message,
        };

        let admission = match self.evaluate_sync_admission(&options.admission) {
            Ok(value) => value,
            Err(message) => return format!("{message}\n"),
        };

        let SyncAdmissionOutcome {
            trust_score,
            admission,
        } = admission;

        if let RelayAdmission::Reject { reason } = &admission {
            return self.render_sync_admission_blocked(
                "Sync Preview",
                &options,
                trust_score,
                reason,
            );
        }

        match Self::open_existing(PathBuf::from(&options.state_path)) {
            Ok(other) => self.render_sync_preview_with(
                &other,
                &options.state_path,
                options.profile,
                Some((&options.admission, trust_score, &admission)),
            ),
            Err(err) => format!("Failed to preview sync state: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_apply(&mut self, tokens: &[&str]) -> String {
        let options = match self.parse_sync_target_options(
            tokens,
            "Usage: sync apply --state <path> [--profile full|light] [--mode open|trust-gated|network-scoped] [--source-persona <persona>] [--threshold <value>] [--allow persona-a,persona-b]\n",
        ) {
            Ok(options) => options,
            Err(message) => return message,
        };

        let admission = match self.evaluate_sync_admission(&options.admission) {
            Ok(value) => value,
            Err(message) => return format!("{message}\n"),
        };

        if let RelayAdmission::Reject { reason } = &admission.admission {
            return self.render_sync_admission_blocked(
                "Sync Apply",
                &options,
                admission.trust_score,
                reason,
            );
        }

        match Self::open_existing(PathBuf::from(&options.state_path)) {
            Ok(other) => match self.apply_sync_from(&other, &options.state_path, options.profile) {
                Ok(output) => output,
                Err(err) => format!("Failed to apply sync state: {}\n", err),
            },
            Err(err) => format!("Failed to apply sync state: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_preview_file(&mut self, tokens: &[&str]) -> String {
        let (file_path, admission) = match self.parse_sync_import(
            tokens,
            "Usage: sync preview-file --file <path> [--mode open|trust-gated|network-scoped] [--source-persona <persona>] [--threshold <value>] [--allow persona-a,persona-b]\n",
        ) {
            Ok(value) => value,
            Err(message) => return message,
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read sync batch: {err}\n"),
        };
        let batch = match PortableSyncBatch::decode(&payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to decode sync batch: {err}\n"),
        };
        let admission_outcome = match self.evaluate_sync_admission(&admission) {
            Ok(value) => value,
            Err(message) => return format!("{message}\n"),
        };

        if let RelayAdmission::Reject { reason } = &admission_outcome.admission {
            return self.render_sync_file_preview_blocked(
                &file_path,
                &batch,
                &admission,
                admission_outcome.trust_score,
                reason,
            );
        }

        self.render_sync_file_preview(
            &file_path,
            &batch,
            &admission,
            admission_outcome.trust_score,
            &admission_outcome.admission,
        )
    }

    pub(crate) fn handle_sync_mutual(&mut self, tokens: &[&str]) -> String {
        let Some((state_path, profile)) = self.parse_sync_target_and_profile(
            tokens,
            "Usage: sync mutual --state <path> [--profile full|light]\n",
        ) else {
            return "Usage: sync mutual --state <path> [--profile full|light]\n".to_string();
        };

        match Self::open_existing(PathBuf::from(&state_path)) {
            Ok(mut other) => match self.apply_sync_mutual(&mut other, &state_path, profile) {
                Ok(output) => output,
                Err(err) => format!("Failed to apply mutual sync state: {}\n", err),
            },
            Err(err) => format!("Failed to apply mutual sync state: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_relay_pack(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-pack --file <sync-batch-path> --out <relay-submission-path> (--target-peer <peer-id> | --target-state <path>) [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>]\n";
        let mut file_path = None;
        let mut out_path = None;
        let mut target_peer = None;
        let mut target_state = None;
        let mut source_persona = None;
        let mut token_issuer = None;
        let mut threshold = None;
        let mut expires_in_secs = 3600u64;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--target-peer" if i + 1 < tokens.len() => {
                    target_peer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--target-state" if i + 1 < tokens.len() => {
                    target_state = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--source-persona" if i + 1 < tokens.len() => {
                    source_persona = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--token-issuer" if i + 1 < tokens.len() => {
                    token_issuer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in_secs = value,
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(file_path) = file_path else {
            return usage.to_string();
        };
        let Some(out_path) = out_path else {
            return usage.to_string();
        };
        let target_peer_id = match (target_peer, target_state) {
            (Some(peer_id), None) => peer_id,
            (None, Some(state_path)) => match Self::open_existing(PathBuf::from(&state_path)) {
                Ok(peer) => peer.current_peer_id(),
                Err(err) => return format!("Failed to resolve target peer: {}\n", err),
            },
            (Some(_), Some(_)) => return usage.to_string(),
            (None, None) => return usage.to_string(),
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read sync batch: {err}\n"),
        };
        if let Err(err) = PortableSyncBatch::decode(&payload) {
            return format!("Failed to read sync batch: {err}\n");
        }

        let submission = match self.build_portable_relay_submission(
            payload,
            target_peer_id.clone(),
            source_persona.as_deref(),
            token_issuer.as_deref(),
            threshold,
            expires_in_secs,
        ) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build relay submission: {}\n", err),
        };
        if let Some(parent) = Path::new(&out_path).parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            return format!("Failed to create relay submission dir: {err}\n");
        }
        if let Err(err) = fs::write(&out_path, submission.encode()) {
            return format!("Failed to write relay submission: {err}\n");
        }

        format!(
            "packed relay\t{}\tbytes {}\tsource {}\ttarget {}\ttoken {}\tfile {}\n",
            submission.envelope.id,
            submission.envelope.opaque_payload.len(),
            submission.source_persona_id.as_deref().unwrap_or("(none)"),
            target_peer_id,
            if submission.admission_token.is_some() {
                "present"
            } else {
                "none"
            },
            out_path,
        )
    }

    pub(crate) fn handle_sync_relay_send(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-send --bind <addr> (--target-peer <peer-id> | --target-state <path>) [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>]\n";
        let mut bind_address = None;
        let mut target_peer = None;
        let mut target_state = None;
        let mut source_persona = None;
        let mut token_issuer = None;
        let mut threshold = None;
        let mut profile = SyncProfile::Full;
        let mut expires_in_secs = 3600u64;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--bind" if i + 1 < tokens.len() => {
                    bind_address = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--target-peer" if i + 1 < tokens.len() => {
                    target_peer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--target-state" if i + 1 < tokens.len() => {
                    target_state = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = match SyncProfile::parse(tokens[i + 1]) {
                        Some(value) => value,
                        None => return usage.to_string(),
                    };
                    i += 2;
                }
                "--source-persona" if i + 1 < tokens.len() => {
                    source_persona = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--token-issuer" if i + 1 < tokens.len() => {
                    token_issuer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in_secs = value,
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(bind_address) = bind_address else {
            return usage.to_string();
        };
        let (target_peer_id, peer_state_path) = match (target_peer, target_state) {
            (Some(peer_id), None) => (peer_id, None),
            (None, Some(state_path)) => match Self::open_existing(PathBuf::from(&state_path)) {
                Ok(peer) => (peer.current_peer_id(), Some(state_path)),
                Err(err) => return format!("Failed to resolve target peer: {}\n", err),
            },
            (Some(_), Some(_)) => return usage.to_string(),
            (None, None) => return usage.to_string(),
        };

        let batch = match self.build_portable_sync_batch(profile, peer_state_path.as_deref()) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build sync batch: {}\n", err),
        };
        let event_count = batch.events.len();
        let batch_id = batch.batch.id.clone();
        let submission = match self.build_portable_relay_submission(
            batch.encode(),
            target_peer_id.clone(),
            source_persona.as_deref(),
            token_issuer.as_deref(),
            threshold,
            expires_in_secs,
        ) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build relay submission: {}\n", err),
        };
        let response = match self.relay_round_trip(&bind_address, &submission.encode()) {
            Ok(mut frames) => {
                if frames.len() != 1 {
                    return format!(
                        "Unexpected relay response: expected 1 frame, got {}\n",
                        frames.len()
                    );
                }
                match String::from_utf8(frames.remove(0)) {
                    Ok(value) => value,
                    Err(_) => return "Relay returned non-utf8 response\n".to_string(),
                }
            }
            Err(err) => return format!("Failed to send relay submission: {}\n", err),
        };

        format!(
            "relay send\t{}\tbatch {}\tevents {}\ttarget {}\tsource {}\tbind {}\n",
            response,
            batch_id,
            event_count,
            target_peer_id,
            submission.source_persona_id.as_deref().unwrap_or("(none)"),
            bind_address,
        )
    }

    pub(crate) fn handle_sync_relay_send_peer(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-send-peer --peer <peer-id> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>]\n";
        let mut target_peer = None;
        let mut source_persona = None;
        let mut token_issuer = None;
        let mut threshold = None;
        let mut profile = SyncProfile::Full;
        let mut expires_in_secs = 3600u64;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--peer" if i + 1 < tokens.len() => {
                    target_peer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = match SyncProfile::parse(tokens[i + 1]) {
                        Some(value) => value,
                        None => return usage.to_string(),
                    };
                    i += 2;
                }
                "--source-persona" if i + 1 < tokens.len() => {
                    source_persona = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--token-issuer" if i + 1 < tokens.len() => {
                    token_issuer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in_secs = value,
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(target_peer_id) = target_peer else {
            return usage.to_string();
        };
        let bind_address = match self.resolve_relay_bind_for_peer(&target_peer_id) {
            Ok(value) => value,
            Err(err) => return format!("Failed to resolve relay route: {}\n", err),
        };

        let batch = match self.build_portable_sync_batch(profile, None) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build sync batch: {}\n", err),
        };
        let event_count = batch.events.len();
        let batch_id = batch.batch.id.clone();
        let submission = match self.build_portable_relay_submission(
            batch.encode(),
            target_peer_id.clone(),
            source_persona.as_deref(),
            token_issuer.as_deref(),
            threshold,
            expires_in_secs,
        ) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build relay submission: {}\n", err),
        };
        let response = match self.relay_round_trip(&bind_address, &submission.encode()) {
            Ok(mut frames) => {
                if frames.len() != 1 {
                    return format!(
                        "Unexpected relay response: expected 1 frame, got {}\n",
                        frames.len()
                    );
                }
                match String::from_utf8(frames.remove(0)) {
                    Ok(value) => value,
                    Err(_) => return "Relay returned non-utf8 response\n".to_string(),
                }
            }
            Err(err) => return format!("Failed to send relay submission: {}\n", err),
        };

        format!(
            "relay send\t{}\tbatch {}\tevents {}\ttarget {}\tsource {}\tbind {}\n",
            response,
            batch_id,
            event_count,
            target_peer_id,
            submission.source_persona_id.as_deref().unwrap_or("(none)"),
            bind_address,
        )
    }

    pub(crate) fn handle_sync_relay_send_state(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-send-state --state <path> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>]\n";
        let mut state_path = None;
        let mut source_persona = None;
        let mut token_issuer = None;
        let mut threshold = None;
        let mut profile = SyncProfile::Full;
        let mut expires_in_secs = 3600u64;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--state" if i + 1 < tokens.len() => {
                    state_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = match SyncProfile::parse(tokens[i + 1]) {
                        Some(value) => value,
                        None => return usage.to_string(),
                    };
                    i += 2;
                }
                "--source-persona" if i + 1 < tokens.len() => {
                    source_persona = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--token-issuer" if i + 1 < tokens.len() => {
                    token_issuer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in_secs = value,
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(state_path) = state_path else {
            return usage.to_string();
        };
        let target = match Self::open_existing(PathBuf::from(&state_path)) {
            Ok(value) => value,
            Err(err) => return format!("Failed to resolve target state: {}\n", err),
        };
        let target_peer_id = target.current_peer_id();
        let bind_address = match target.resolve_relay_bind_for_peer(&target_peer_id) {
            Ok(value) => value,
            Err(err) => return format!("Failed to resolve relay route: {}\n", err),
        };

        let batch = match self.build_portable_sync_batch(profile, Some(&state_path)) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build sync batch: {}\n", err),
        };
        let event_count = batch.events.len();
        let batch_id = batch.batch.id.clone();
        let submission = match self.build_portable_relay_submission(
            batch.encode(),
            target_peer_id.clone(),
            source_persona.as_deref(),
            token_issuer.as_deref(),
            threshold,
            expires_in_secs,
        ) {
            Ok(value) => value,
            Err(err) => return format!("Failed to build relay submission: {}\n", err),
        };
        let response = match self.execute_relay_submission(&bind_address, &submission.encode()) {
            Ok(value) => value,
            Err(err) => return format!("Failed to send relay submission: {}\n", err),
        };

        format!(
            "relay send\t{}\tbatch {}\tevents {}\ttarget {}\tsource {}\tbind {}\tstate {}\n",
            response,
            batch_id,
            event_count,
            target_peer_id,
            submission.source_persona_id.as_deref().unwrap_or("(none)"),
            bind_address,
            state_path,
        )
    }

    pub(crate) fn handle_sync_relay_submit(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-submit --file <relay-submission-path> --bind <addr>\n";
        let Some((file_path, bind_address)) = self.parse_sync_relay_file_and_bind(tokens, usage)
        else {
            return usage.to_string();
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read relay submission: {err}\n"),
        };
        let submission = match PortableRelaySubmission::decode(&payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to decode relay submission: {err}\n"),
        };
        let response = match self.execute_relay_submission(&bind_address, &payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to submit relay payload: {}\n", err),
        };

        format!(
            "relay submit\t{}\ttarget {}\tsource {}\tbind {}\tfile {}\n",
            response,
            submission.target_peer_id.as_deref().unwrap_or("(none)"),
            submission.source_persona_id.as_deref().unwrap_or("(none)"),
            bind_address,
            file_path,
        )
    }

    pub(crate) fn handle_sync_relay_drain(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-drain --bind <addr> [--peer <peer-id>]\n";
        let Some((bind_address, peer_id)) = self.parse_sync_relay_drain(tokens, usage) else {
            return usage.to_string();
        };

        match self.drain_relay_mailbox(&bind_address, &peer_id) {
            Ok(output) => output,
            Err(err) => format!("Failed to drain relay mailbox: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_relay_drain_self(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-drain-self\n";
        if !tokens.is_empty() {
            return usage.to_string();
        }

        let peer_id = self.current_peer_id();
        let bind_address = match self.resolve_relay_bind_for_peer(&peer_id) {
            Ok(value) => value,
            Err(err) => return format!("Failed to resolve relay route: {}\n", err),
        };
        match self.drain_relay_mailbox(&bind_address, &peer_id) {
            Ok(output) => output,
            Err(err) => format!("Failed to drain relay mailbox: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_relay_drain_state(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-drain-state --state <path>\n";
        let Some(state_path) = self.parse_sync_state_arg(tokens, usage) else {
            return usage.to_string();
        };

        match self.drain_relay_for_state_path(&state_path) {
            Ok(output) => output,
            Err(err) => format!("{err}\n"),
        }
    }

    pub(crate) fn handle_sync_relay_cycle(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-cycle --state <path> [--profile full|light] [--source-persona <persona>] [--token-issuer <persona>] [--threshold <value>] [--expires-in <seconds>]\n";
        let Some(state_path) = self.parse_sync_state_arg(tokens, usage) else {
            return usage.to_string();
        };

        let send_output = self.handle_sync_relay_send_state(tokens);
        if send_output.starts_with("Failed ") || send_output.starts_with("Usage:") {
            return send_output;
        }
        let drain_output = match self.drain_relay_for_state_path(&state_path) {
            Ok(output) => output,
            Err(err) => return format!("{err}\n"),
        };

        format!(
            "relay cycle\t{}\n{}\n{}",
            state_path,
            send_output.trim_end(),
            drain_output.trim_end()
        )
    }

    pub(crate) fn import_relay_mailbox_frames(
        &mut self,
        peer_id: &str,
        mut frames: Vec<Vec<u8>>,
    ) -> Result<(usize, usize, usize), ValidationError> {
        if frames.is_empty() {
            return Err(ValidationError::new("relay returned no drain header"));
        }

        let header = String::from_utf8(frames.remove(0))
            .map_err(|_| ValidationError::new("relay returned non-utf8 drain header"))?;
        let (drain_peer_id, expected_count) =
            parse_relay_drain_header(&header).ok_or_else(|| {
                ValidationError::new(format!("relay returned invalid drain header: {header}"))
            })?;
        if drain_peer_id != peer_id {
            return Err(ValidationError::new(format!(
                "relay drained mailbox for unexpected peer: expected {}, got {}",
                peer_id, drain_peer_id
            )));
        }
        if frames.len() != expected_count {
            return Err(ValidationError::new(format!(
                "relay returned {} submissions but header announced {}",
                frames.len(),
                expected_count
            )));
        }

        let mut imported_batches = 0usize;
        let mut imported_events = 0usize;
        for frame in frames {
            let submission = PortableRelaySubmission::decode(&frame)
                .map_err(|err| ValidationError::new(format!("decode relay submission: {err}")))?;
            let batch = PortableSyncBatch::decode(&submission.envelope.opaque_payload)
                .map_err(|err| ValidationError::new(format!("decode sync batch: {err}")))?;
            let imported = self.event_store.import_sync_batch(
                &batch.source_peer_id,
                &batch.batch.id,
                &batch.events,
                batch.cursor_event_id.as_deref(),
                &self.verifier,
                &IdentityAuthorizer,
                now_epoch_secs(),
            )?;
            imported_batches += 1;
            imported_events += imported;
        }

        self.hydrate_identity_state();
        self.reconcile_recovery_session_from_state();
        self.refresh_identity_counters();
        self.persist_to_disk()?;

        Ok((expected_count, imported_batches, imported_events))
    }

    pub(crate) fn handle_sync_relay_stats(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: sync relay-stats --bind <addr>\n";
        let Some(bind_address) = self.parse_sync_relay_bind_arg(tokens, usage) else {
            return usage.to_string();
        };

        let response = match self.relay_round_trip(&bind_address, b"STATS") {
            Ok(mut frames) => {
                if frames.len() != 1 {
                    return format!(
                        "Unexpected relay response: expected 1 frame, got {}\n",
                        frames.len()
                    );
                }
                match String::from_utf8(frames.remove(0)) {
                    Ok(value) => value,
                    Err(_) => return "Relay returned non-utf8 response\n".to_string(),
                }
            }
            Err(err) => return format!("Failed to fetch relay stats: {}\n", err),
        };

        format!("relay stats\tbind {}\t{}\n", bind_address, response)
    }

    pub(crate) fn handle_sync_relay_unpack(&mut self, tokens: &[&str]) -> String {
        let Some((file_path, out_path)) = self.parse_sync_file_pair(
            tokens,
            "Usage: sync relay-unpack --file <relay-submission-path> --out <sync-batch-path>\n",
        ) else {
            return "Usage: sync relay-unpack --file <relay-submission-path> --out <sync-batch-path>\n"
                .to_string();
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read relay submission: {err}\n"),
        };
        let submission = match PortableRelaySubmission::decode(&payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to decode relay submission: {err}\n"),
        };
        if let Err(err) = PortableSyncBatch::decode(&submission.envelope.opaque_payload) {
            return format!("Failed to decode inner sync batch: {err}\n");
        }
        if let Some(parent) = Path::new(&out_path).parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            return format!("Failed to create sync batch dir: {err}\n");
        }
        if let Err(err) = fs::write(&out_path, &submission.envelope.opaque_payload) {
            return format!("Failed to write unpacked sync batch: {err}\n");
        }

        format!(
            "unpacked relay\t{}\tbytes {}\tfile {}\n",
            submission.envelope.id,
            submission.envelope.opaque_payload.len(),
            out_path
        )
    }

    pub(crate) fn handle_sync_relay_inspect(&mut self, tokens: &[&str]) -> String {
        let Some(file_path) = self.parse_sync_file_arg(
            tokens,
            "Usage: sync relay-inspect --file <relay-submission-path>\n",
        ) else {
            return "Usage: sync relay-inspect --file <relay-submission-path>\n".to_string();
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read relay submission: {err}\n"),
        };
        let submission = match PortableRelaySubmission::decode(&payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to decode relay submission: {err}\n"),
        };

        let mut out = String::new();
        writeln!(&mut out, "Relay Submission").unwrap();
        writeln!(&mut out, "----------------").unwrap();
        writeln!(&mut out, "File: {}", file_path).unwrap();
        writeln!(&mut out, "Envelope: {}", submission.envelope.id).unwrap();
        writeln!(
            &mut out,
            "Source persona: {}",
            submission.source_persona_id.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        writeln!(
            &mut out,
            "Target peer: {}",
            submission.target_peer_id.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        writeln!(
            &mut out,
            "Opaque bytes: {}",
            submission.envelope.opaque_payload.len()
        )
        .unwrap();
        if let Some(token) = submission.admission_token {
            writeln!(&mut out, "Admission token: present").unwrap();
            writeln!(&mut out, "Token issuer: {}", token.issuer_persona_id).unwrap();
            writeln!(&mut out, "Token subject: {}", token.persona_id).unwrap();
            writeln!(
                &mut out,
                "Token threshold: {:.2}",
                token.threshold_met.value()
            )
            .unwrap();
            writeln!(&mut out, "Token expires: {}", token.expires_at).unwrap();
        } else {
            writeln!(&mut out, "Admission token: none").unwrap();
        }
        out
    }

    pub(crate) fn handle_sync_export(&mut self, tokens: &[&str]) -> String {
        let Some(options) = self.parse_sync_export(
            tokens,
            "Usage: sync export --out <path> [--profile full|light] [--for-state <path>]\n",
        ) else {
            return "Usage: sync export --out <path> [--profile full|light] [--for-state <path>]\n"
                .to_string();
        };

        match self.export_sync_batch(Path::new(&options.out_path), &options) {
            Ok(output) => output,
            Err(err) => format!("Failed to export sync batch: {}\n", err),
        }
    }

    pub(crate) fn handle_sync_import(&mut self, tokens: &[&str]) -> String {
        let (file_path, admission) = match self.parse_sync_import(
            tokens,
            "Usage: sync import --file <path> [--mode open|trust-gated|network-scoped] [--source-persona <persona>] [--threshold <value>] [--allow persona-a,persona-b]\n",
        ) {
            Ok(value) => value,
            Err(message) => return message,
        };

        let payload = match fs::read(&file_path) {
            Ok(value) => value,
            Err(err) => return format!("Failed to read sync batch: {err}\n"),
        };
        let batch = match PortableSyncBatch::decode(&payload) {
            Ok(value) => value,
            Err(err) => return format!("Failed to decode sync batch: {err}\n"),
        };
        let admission_outcome = match self.evaluate_sync_admission(&admission) {
            Ok(value) => value,
            Err(message) => return format!("{message}\n"),
        };

        if let RelayAdmission::Reject { reason } = &admission_outcome.admission {
            return self.render_sync_import_blocked(
                &file_path,
                &batch,
                &admission,
                admission_outcome.trust_score,
                reason,
            );
        }

        match self.event_store.import_sync_batch(
            &batch.source_peer_id,
            &batch.batch.id,
            &batch.events,
            batch.cursor_event_id.as_deref(),
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        ) {
            Ok(imported) => {
                self.hydrate_identity_state();
                self.reconcile_recovery_session_from_state();
                self.refresh_identity_counters();
                if let Err(err) = self.persist_to_disk() {
                    return format!("Failed to persist imported sync batch: {}\n", err);
                }
                format!(
                    "imported sync\t{}\tfrom {}\tprofile {}\timported {}\tcursor {}\tfile {}\n",
                    batch.batch.id,
                    batch.source_peer_id,
                    batch.profile.as_str(),
                    imported,
                    batch.cursor_event_id.as_deref().unwrap_or("(none)"),
                    file_path
                )
            }
            Err(err) => format!("Failed to import sync batch: {}\n", err),
        }
    }

    pub(crate) fn apply_sync_from(
        &mut self,
        other: &Self,
        other_state_path: &str,
        profile: SyncProfile,
    ) -> Result<String, ValidationError> {
        let peer_id = other.current_peer_id();
        let cursor = self.event_store.peer_cursor(&peer_id)?;
        let remote_event_ids = other.event_store.event_ids();
        let raw_batch = plan_pull_batch(
            &cursor,
            generate_random_identifier("sync-batch"),
            &remote_event_ids,
            |id| self.event_store.has_event(id),
        );
        let relevant_remote_ids =
            relevant_event_ids_for_context(other.event_store.events(), &self.light_sync_context());
        let batch = filter_batch_by_profile(&raw_batch, profile, &relevant_remote_ids);
        let remote_events = other.event_store.events_by_ids(&batch.event_ids);
        let cursor_event_id = self.next_sync_cursor_event_id(
            cursor.last_event_id.as_deref(),
            &remote_event_ids,
            |id| self.event_store.has_event(id),
            &batch.event_ids,
        );
        let imported = self.event_store.import_sync_batch(
            &peer_id,
            &batch.id,
            &remote_events,
            cursor_event_id.as_deref(),
            &self.verifier,
            &IdentityAuthorizer,
            now_epoch_secs(),
        )?;
        self.hydrate_identity_state();
        self.reconcile_recovery_session_from_state();
        self.refresh_identity_counters();
        self.persist_to_disk()?;

        let auto_imported = self.auto_import_disclosure_messages();

        let mut output = format!(
            "applied sync\t{}\tfrom {}\tprofile {}\timported {}\tcursor {}\n",
            batch.id,
            other_state_path,
            profile.as_str(),
            imported,
            cursor_event_id.as_deref().unwrap_or("(none)")
        );
        if auto_imported > 0 {
            use std::fmt::Write;
            let _ = writeln!(output, "auto-imported {} disclosure(s)", auto_imported);
        }
        Ok(output)
    }

    pub(crate) fn apply_sync_mutual(
        &mut self,
        other: &mut Self,
        other_state_path: &str,
        profile: SyncProfile,
    ) -> Result<String, ValidationError> {
        let local_state_path = self.state_location_label();
        let pushed = other.apply_sync_from(self, &local_state_path, profile)?;
        let pulled = self.apply_sync_from(other, other_state_path, profile)?;

        Ok(format!("mutual sync\n{}\n{}", pushed.trim_end(), pulled))
    }

    pub(crate) fn export_sync_batch(
        &self,
        out_file: &Path,
        options: &SyncExportOptions,
    ) -> Result<String, ValidationError> {
        if let Some(parent) = out_file.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| ValidationError::new(format!("create sync export dir: {err}")))?;
        }

        let batch =
            self.build_portable_sync_batch(options.profile, options.peer_state_path.as_deref())?;
        fs::write(out_file, batch.encode())
            .map_err(|err| ValidationError::new(format!("write sync export file: {err}")))?;

        let mut output = format!(
            "exported sync\t{}\tfrom {}\tprofile {}\tevents {}\tcursor {}\tfile {}",
            batch.batch.id,
            batch.source_peer_id,
            batch.profile.as_str(),
            batch.events.len(),
            batch.cursor_event_id.as_deref().unwrap_or("(none)"),
            out_file.display()
        );
        if let Some(peer_state_path) = &options.peer_state_path {
            output.push_str("\tfor ");
            output.push_str(peer_state_path);
        }
        output.push('\n');

        Ok(output)
    }

    pub(crate) fn build_portable_sync_batch(
        &self,
        profile: SyncProfile,
        peer_state_path: Option<&str>,
    ) -> Result<PortableSyncBatch, ValidationError> {
        let all_events = self.event_store.events();
        let all_event_ids = self.event_store.event_ids();
        let current_cursor = if let Some(peer_state_path) = peer_state_path {
            let peer_state_file = PathBuf::from(peer_state_path);
            let peer_sqlite_file = sqlite_path_for_local_state(&peer_state_file);
            if peer_state_file.exists() || peer_sqlite_file.exists() {
                let peer = Self::open_existing(peer_state_file)?;
                let source_peer_id = self.current_peer_id();
                Some(peer.event_store.peer_cursor(&source_peer_id)?.last_event_id)
            } else {
                None
            }
        } else {
            None
        };
        let raw_batch = if peer_state_path.is_some() {
            let source_peer_id = self.current_peer_id();
            let cursor = core_types::PeerCursor {
                peer_id: source_peer_id,
                last_event_id: current_cursor.clone().flatten(),
            };
            plan_pull_batch(
                &cursor,
                generate_random_identifier("sync-batch"),
                &all_event_ids,
                |_| false,
            )
        } else {
            core_sync::new_batch(
                generate_random_identifier("sync-batch"),
                all_event_ids.clone(),
            )
        };
        let relevant_ids = relevant_event_ids_for_context(all_events, &self.light_sync_context());
        let batch = filter_batch_by_profile(&raw_batch, profile, &relevant_ids);
        let events = self.event_store.events_by_ids(&batch.event_ids);
        let cursor_event_id = self.next_sync_cursor_event_id(
            current_cursor.as_ref().and_then(|value| value.as_deref()),
            &all_event_ids,
            |_| false,
            &batch.event_ids,
        );

        Ok(PortableSyncBatch {
            source_peer_id: self.current_peer_id(),
            profile,
            cursor_event_id,
            batch,
            events,
        })
    }

    pub(crate) fn build_portable_relay_submission(
        &self,
        payload: Vec<u8>,
        target_peer_id: String,
        source_persona: Option<&str>,
        token_issuer: Option<&str>,
        threshold: Option<f32>,
        expires_in_secs: u64,
    ) -> Result<PortableRelaySubmission, ValidationError> {
        let source_persona_id = source_persona.map(|value| {
            self.resolve_persona(value)
                .map(|persona| persona.id.clone())
                .unwrap_or_else(|| value.to_string())
        });
        let threshold = match threshold {
            Some(value) => Some(TrustThreshold::new(value)?),
            None => None,
        };
        if threshold.is_some() && source_persona_id.is_none() {
            return Err(ValidationError::new(
                "relay token generation requires --source-persona",
            ));
        }
        let admission_token = match (source_persona_id.as_deref(), threshold, token_issuer) {
            (Some(source_id), Some(threshold), Some(issuer_ref)) => {
                Some(self.issue_relay_admission_token(
                    source_id,
                    issuer_ref,
                    threshold,
                    expires_in_secs,
                )?)
            }
            (Some(source_id), Some(threshold), None) => Some(self.issue_relay_admission_token(
                source_id,
                source_id,
                threshold,
                expires_in_secs,
            )?),
            (None, Some(_), _) => {
                return Err(ValidationError::new(
                    "relay token generation requires --source-persona",
                ));
            }
            (_, None, Some(_)) => {
                return Err(ValidationError::new(
                    "relay token generation requires --threshold",
                ));
            }
            _ => None,
        };

        Ok(PortableRelaySubmission {
            source_persona_id,
            target_peer_id: Some(target_peer_id),
            envelope: wrap_for_relay(generate_random_identifier("relay-envelope"), payload),
            admission_token,
        })
    }

    pub(crate) fn resolve_relay_bind_for_peer(
        &self,
        peer_id: &str,
    ) -> Result<String, ValidationError> {
        let endpoint = self
            .event_store
            .materialized()
            .endpoint(peer_id)
            .ok_or_else(|| {
                ValidationError::new(format!("no published endpoint for peer: {peer_id}"))
            })?;
        let route = parse_relay_transport_hint(&endpoint.transport_hint)?;
        if route.peer_id != endpoint.peer_id {
            return Err(ValidationError::new(format!(
                "endpoint transport hint peer mismatch: expected {}, got {}",
                endpoint.peer_id, route.peer_id
            )));
        }
        Ok(route.bind_address)
    }

    pub(crate) fn execute_relay_submission(
        &self,
        bind_address: &str,
        payload: &[u8],
    ) -> Result<String, ValidationError> {
        let mut frames = self.relay_round_trip(bind_address, payload)?;
        if frames.len() != 1 {
            return Err(ValidationError::new(format!(
                "unexpected relay response: expected 1 frame, got {}",
                frames.len()
            )));
        }
        String::from_utf8(frames.remove(0))
            .map_err(|_| ValidationError::new("relay returned non-utf8 response"))
    }

    pub(crate) fn drain_relay_mailbox(
        &mut self,
        bind_address: &str,
        peer_id: &str,
    ) -> Result<String, ValidationError> {
        let request = format!("DRAIN {peer_id}");
        let frames = self.relay_round_trip(bind_address, request.as_bytes())?;
        let (expected_count, imported_batches, imported_events) =
            self.import_relay_mailbox_frames(peer_id, frames)?;

        let auto_imported = self.auto_import_disclosure_messages();

        let mut output = format!(
            "relay drain\tpeer {}\tqueued {}\tbatches {}\timported {}\tbind {}\n",
            peer_id, expected_count, imported_batches, imported_events, bind_address,
        );
        if auto_imported > 0 {
            use std::fmt::Write;
            let _ = writeln!(output, "auto-imported {} disclosure(s)", auto_imported);
        }
        Ok(output)
    }

    pub(crate) fn drain_relay_for_state_path(&self, state_path: &str) -> Result<String, String> {
        let mut target = Self::open_existing(PathBuf::from(state_path))
            .map_err(|err| format!("Failed to open target state: {}", err))?;
        let output = target.handle_sync_relay_drain_self(&[]);
        if output.starts_with("Failed ") || output.starts_with("Usage:") {
            Err(output.trim_end().to_string())
        } else {
            Ok(format!("relay drain state\t{}\t{}", state_path, output))
        }
    }

    pub(crate) fn handle_trust(&mut self, tokens: &[&str]) -> String {
        if let ["attest", rest @ ..] = tokens {
            return self.handle_trust_attest(rest);
        }
        if let ["revoke", rest @ ..] = tokens {
            return self.handle_trust_revoke(rest);
        }

        let mut recipient = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--recipient" if i + 1 < tokens.len() => {
                    recipient = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        self.render_trust_for_recipient(recipient.as_deref())
    }

    pub(crate) fn handle_trust_attest(&mut self, tokens: &[&str]) -> String {
        let mut from = None;
        let mut to = None;
        let mut domain = None;
        let mut score = None;
        let mut recipient = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--from" if i + 1 < tokens.len() => {
                    from = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--to" if i + 1 < tokens.len() => {
                    to = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--domain" if i + 1 < tokens.len() => {
                    domain = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--score" if i + 1 < tokens.len() => {
                    score = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                }
                "--recipient" if i + 1 < tokens.len() => {
                    recipient = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return "Usage: trust attest --from <persona> --to <persona> --domain <domain> --score <0..1> [--recipient <peer>]\n".to_string(),
            }
        }

        let (Some(from), Some(to), Some(domain), Some(score)) = (from, to, domain, score) else {
            return "Usage: trust attest --from <persona> --to <persona> --domain <domain> --score <0..1> [--recipient <peer>]\n".to_string();
        };

        match self.attest_trust_command(&from, &to, &domain, score, recipient) {
            Ok(message) => message,
            Err(err) => format!("Failed to attest trust: {}\n", err),
        }
    }

    pub(crate) fn handle_trust_revoke(&mut self, tokens: &[&str]) -> String {
        let mut attestation = None;
        let mut by = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--attestation" if i + 1 < tokens.len() => {
                    attestation = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--by" if i + 1 < tokens.len() => {
                    by = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return "Usage: trust revoke --attestation <id> --by <persona>\n".to_string(),
            }
        }

        let (Some(attestation), Some(by)) = (attestation, by) else {
            return "Usage: trust revoke --attestation <id> --by <persona>\n".to_string();
        };

        match self.revoke_trust_command(&attestation, &by) {
            Ok(message) => message,
            Err(err) => format!("Failed to revoke trust: {}\n", err),
        }
    }

    pub(crate) fn handle_recovery_execute(&mut self, tokens: &[&str]) -> String {
        let mut replacement_device = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--replacement-device" if i + 1 < tokens.len() => {
                    replacement_device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        match self.execute_recovery_command(replacement_device.as_deref()) {
            Ok(message) => message,
            Err(err) => format!("Failed to execute recovery request: {}\n", err),
        }
    }

    pub(crate) fn handle_persona_create(&mut self, tokens: &[&str]) -> String {
        let mut root = None;
        let mut label = None;
        let mut template = None;
        let mut profile = None;

        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--root" | "-r" if i + 1 < tokens.len() => {
                    root = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--label" | "-l" if i + 1 < tokens.len() => {
                    label = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--template" | "-t" if i + 1 < tokens.len() => {
                    template = parse_persona_template(tokens[i + 1]);
                    if template.is_none() {
                        return "Unknown template. Use one of: professional, friends, pseudonymous\n".to_string();
                    }
                    i += 2;
                    continue;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => {
                    i += 1;
                }
            }
        }

        let Some(root) = root else {
            return "Usage: persona create --root <root> --label <label> (--template <template> | --profile <profile>)\n"
                .to_string();
        };
        let Some(label) = label else {
            return "Usage: persona create --root <root> --label <label> (--template <template> | --profile <profile>)\n"
                .to_string();
        };
        if template.is_some() && profile.is_some() {
            return "Choose either --template or --profile, not both\n".to_string();
        }
        let disclosure_profile = if let Some(template) = template {
            Some(disclosure_profile_for_template(template).to_string())
        } else {
            profile
        };
        let Some(disclosure_profile) = disclosure_profile else {
            return "Usage: persona create --root <root> --label <label> (--template <template> | --profile <profile>)\n"
                .to_string();
        };

        match self.create_persona_command(&root, &label, Some(disclosure_profile)) {
            Ok(message) => message,
            Err(err) => format!("Failed to create persona: {}\n", err),
        }
    }

    pub(crate) fn handle_persona_rotate_key(&mut self, tokens: &[&str]) -> String {
        let mut persona = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" | "-p" if i + 1 < tokens.len() => {
                    persona = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(persona_ref) = persona else {
            return "Usage: persona rotate-key --persona <persona-id-or-label>\n".to_string();
        };

        match self.rotate_persona_key_command(&persona_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to rotate persona key: {}\n", err),
        }
    }

    pub(crate) fn handle_persona_grant_device(&mut self, tokens: &[&str]) -> String {
        let (persona, device) = match self.parse_persona_device_pair(
            tokens,
            "Usage: persona grant-device --persona <persona> --device <device>\n",
        ) {
            Ok(pair) => pair,
            Err(message) => return message,
        };

        match self.grant_persona_device_access_command(&persona, &device) {
            Ok(message) => message,
            Err(err) => format!("Failed to grant persona device access: {}\n", err),
        }
    }

    pub(crate) fn handle_persona_revoke_device(&mut self, tokens: &[&str]) -> String {
        let (persona, device) = match self.parse_persona_device_pair(
            tokens,
            "Usage: persona revoke-device --persona <persona> --device <device>\n",
        ) {
            Ok(pair) => pair,
            Err(message) => return message,
        };

        match self.revoke_persona_device_access_command(&persona, &device) {
            Ok(message) => message,
            Err(err) => format!("Failed to revoke persona device access: {}\n", err),
        }
    }

    pub(crate) fn handle_device_add(&mut self, tokens: &[&str]) -> String {
        let mut root = None;
        let mut label = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--root" | "-r" if i + 1 < tokens.len() => {
                    root = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--label" | "-l" if i + 1 < tokens.len() => {
                    label = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(root) = root else {
            return "Usage: device add --root <root> --label <label>\n".to_string();
        };
        let Some(label) = label else {
            return "Usage: device add --root <root> --label <label>\n".to_string();
        };

        match self.create_device_command(&root, &label) {
            Ok(message) => message,
            Err(err) => format!("Failed to create device: {}\n", err),
        }
    }

    pub(crate) fn handle_device_revoke(&mut self, tokens: &[&str]) -> String {
        let mut device = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--device" | "-d" if i + 1 < tokens.len() => {
                    device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(device_ref) = device else {
            return "Usage: device revoke --device <device-id-or-label>\n".to_string();
        };

        match self.revoke_device_command(&device_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to revoke device: {}\n", err),
        }
    }

    pub(crate) fn handle_device_rotate_key(&mut self, tokens: &[&str]) -> String {
        let mut device = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--device" | "-d" if i + 1 < tokens.len() => {
                    device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(device_ref) = device else {
            return "Usage: device rotate-key --device <device-id-or-label>\n".to_string();
        };

        match self.rotate_device_key_command(&device_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to rotate device key: {}\n", err),
        }
    }

    pub(crate) fn handle_device_rotate_encryption_key(&mut self, tokens: &[&str]) -> String {
        let mut device = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--device" | "-d" if i + 1 < tokens.len() => {
                    device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(device_ref) = device else {
            return "Usage: device rotate-encryption-key --device <device-id-or-label>\n"
                .to_string();
        };

        match self.rotate_device_encryption_key_command(&device_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to rotate device encryption key: {}\n", err),
        }
    }

    pub(crate) fn handle_persona_revoke(&mut self, tokens: &[&str]) -> String {
        let mut persona = None;

        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" | "-p" if i + 1 < tokens.len() => {
                    persona = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(persona_ref) = persona else {
            return "Usage: persona revoke --persona <persona-id-or-label>\n".to_string();
        };

        match self.revoke_persona_command(&persona_ref) {
            Ok(message) => message,
            Err(err) => format!("Failed to revoke persona: {}\n", err),
        }
    }

    pub(crate) fn revoke_persona_command(
        &mut self,
        persona_ref: &str,
    ) -> Result<String, ValidationError> {
        let persona_id = self
            .resolve_persona(persona_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;

        let removed = revoke_persona(&mut self.personas, &persona_id)
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;
        self.revoked_personas.push(removed.clone());
        self.append_persona_revoked_event(&removed)?;
        self.persist_to_disk()?;

        Ok(format!(
            "revoked persona\t{}\t{}\n",
            removed.id, removed.label
        ))
    }

    pub(crate) fn parse_persona_device_pair(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Result<(String, String), String> {
        let mut persona = None;
        let mut device = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" | "-p" if i + 1 < tokens.len() => {
                    persona = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--device" | "-d" if i + 1 < tokens.len() => {
                    device = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(persona) = persona else {
            return Err(usage.to_string());
        };
        let Some(device) = device else {
            return Err(usage.to_string());
        };
        Ok((persona, device))
    }

    pub(crate) fn grant_persona_device_access_command(
        &mut self,
        persona_ref: &str,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let persona_id = self
            .resolve_persona(persona_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;
        let device_id = self
            .resolve_device(device_ref)
            .map(|device| device.device_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown active device: {device_ref}")))?;

        self.event_store
            .grant_persona_device_access(&persona_id, &device_id)?;

        let rewrapped = self.wrap_vault_keys_for_new_device(&persona_id, &device_id)?;

        let mut output = format!(
            "granted persona device access\t{}\t{}\n",
            persona_id, device_id
        );
        if rewrapped > 0 {
            use std::fmt::Write;
            let _ = writeln!(
                output,
                "re-wrapped {} vault manifest key(s) for device {}",
                rewrapped, device_id
            );
        }
        Ok(output)
    }

    /// Wrap existing vault manifest keys for a newly granted device.
    /// Returns the number of manifests that were re-wrapped.
    fn wrap_vault_keys_for_new_device(
        &mut self,
        persona_id: &str,
        device_id: &str,
    ) -> Result<usize, ValidationError> {
        let namespace = VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona_id.to_string(),
        };
        let manifests_with_keys = self
            .event_store
            .local_vault_manifests_with_keys(&namespace)?;
        let mut count = 0;
        for (mut manifest, content_key) in manifests_with_keys {
            if manifest
                .authorized_devices
                .iter()
                .any(|a| a.device_id == device_id)
            {
                continue;
            }
            let device = self
                .resolve_device_any(device_id)
                .ok_or_else(|| ValidationError::new(format!("unknown device: {device_id}")))?;
            let access = core_storage::wrap_manifest_key_access(
                &device.device_id,
                &device.active_encryption_key.public_key,
                &content_key,
            )?;
            grant_manifest_access(&mut manifest, access)?;
            self.event_store.upsert_local_file_manifest(&manifest)?;
            count += 1;
        }
        Ok(count)
    }

    pub(crate) fn revoke_persona_device_access_command(
        &mut self,
        persona_ref: &str,
        device_ref: &str,
    ) -> Result<String, ValidationError> {
        let persona_id = self
            .resolve_persona(persona_ref)
            .map(|persona| persona.id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown persona: {persona_ref}")))?;
        let device_id = self
            .resolve_device_any(device_ref)
            .map(|device| device.device_id.clone())
            .ok_or_else(|| ValidationError::new(format!("unknown device: {device_ref}")))?;

        self.event_store
            .revoke_persona_device_access(&persona_id, &device_id)?;

        Ok(format!(
            "revoked persona device access\t{}\t{}\n",
            persona_id, device_id
        ))
    }
}
