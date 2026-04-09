use std::fmt::Write as _;

use crate::activity_support::disclosure_payload_preview;
use core_identity::disclosure_view;
use core_sync::{check_relay_admission, wrap_for_relay};
use core_trust::{derive_score, derive_score_for_recipient, explain};
use core_types::{EventType, RelayAdmission, RelayMode, TrustThreshold};

use super::*;

impl DemoApp {
    pub fn render_home(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Emberlink shell").unwrap();
        writeln!(&mut out, "state:\t{}", self.state_location_label()).unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Show data").unwrap();
        writeln!(&mut out, "  show broker").unwrap();
        writeln!(&mut out, "  show broker --disclose-links").unwrap();
        writeln!(&mut out, "  show trust").unwrap();
        writeln!(&mut out, "  trust --recipient peer-demo").unwrap();
        writeln!(
            &mut out,
            "  trust attest --from persona-professional --to persona-pseudonymous --domain professional --score 0.90"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  trust revoke --attestation trust-1 --by persona-professional"
        )
        .unwrap();
        writeln!(&mut out, "  show messages").unwrap();
        writeln!(&mut out, "  show disclosures").unwrap();
        writeln!(&mut out, "  show disclosure <message-id>").unwrap();
        writeln!(&mut out, "  show content").unwrap();
        writeln!(&mut out, "  show recovery").unwrap();
        writeln!(&mut out, "  show vault").unwrap();
        writeln!(&mut out, "  vault --namespace persona:persona-professional").unwrap();
        writeln!(
            &mut out,
            "  vault issue --template template-professional-card --recipient svc.example"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault issue --template template-professional-peer-card --recipient persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault send-artifact --artifact artifact-... --from persona-professional --to persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault export-artifact --artifact artifact-... --out /tmp/disclosure.artifact"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault inspect-export --file /tmp/disclosure.artifact"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault import-artifact --file /tmp/disclosure.artifact"
        )
        .unwrap();
        writeln!(&mut out, "  vault import-message --message message-...").unwrap();
        writeln!(
            &mut out,
            "  vault revoke --artifact artifact-... --reason credential-expired"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault write-record --namespace persona:persona-professional --object vault-object-custom-profile --schema com.example.profile/custom --app com.example.profile --json {{\"display_name\":\"operator\"}}"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault template add --id template-custom-profile --object vault-object-custom-profile --schema com.example.profile/custom --audience service --namespace persona:persona-professional --field display_name"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault show-record --object vault-object-professional-profile"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  vault delete --object vault-object-custom-profile"
        )
        .unwrap();
        writeln!(&mut out, "  vault show-artifact --artifact artifact-...").unwrap();
        writeln!(&mut out, "  vault received").unwrap();
        writeln!(&mut out, "  vault show-received --artifact artifact-...").unwrap();
        writeln!(&mut out, "  show storage").unwrap();
        writeln!(&mut out, "  storage open").unwrap();
        writeln!(&mut out, "  storage restore-plan").unwrap();
        writeln!(&mut out, "  storage gc-plan").unwrap();
        writeln!(&mut out, "  storage gc-apply").unwrap();
        writeln!(&mut out, "  storage audit").unwrap();
        writeln!(&mut out, "  show sync").unwrap();
        writeln!(
            &mut out,
            "  sync relay-check --mode trust-gated --threshold 0.75 --persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync endpoint set --device device-root-a-01 --bind 127.0.0.1:9100"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync endpoint rotate --device device-root-a-01 --bind 127.0.0.1:9200"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  inspect --state /tmp/client-b.tsv --screen broker"
        )
        .unwrap();
        writeln!(&mut out, "  compare --state /tmp/client-b.tsv").unwrap();
        writeln!(
            &mut out,
            "  sync preview --state /tmp/client-b.tsv --profile light"
        )
        .unwrap();
        writeln!(&mut out, "  sync preview-file --file /tmp/client-b.sync").unwrap();
        writeln!(
            &mut out,
            "  sync apply --state /tmp/client-b.tsv --mode trust-gated --source-persona persona-pseudonymous --threshold 0.75"
        )
        .unwrap();
        writeln!(&mut out, "  sync export --out /tmp/client-a.sync").unwrap();
        writeln!(
            &mut out,
            "  sync export --out /tmp/client-a-for-b.sync --for-state /tmp/client-b.tsv"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync import --file /tmp/client-b.sync --mode trust-gated --source-persona persona-pseudonymous --threshold 0.75"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-pack --file /tmp/client-a.sync --out /tmp/client-a.relay --target-state /tmp/client-b.tsv --source-persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(&mut out, "  sync relay-inspect --file /tmp/client-a.relay").unwrap();
        writeln!(
            &mut out,
            "  sync relay-submit --file /tmp/client-a.relay --bind 127.0.0.1:9100"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-send --bind 127.0.0.1:9100 --target-state /tmp/client-b.tsv --source-persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-send-peer --peer peer-demo-target --source-persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-send-state --state /tmp/client-b.tsv --source-persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(&mut out, "  sync relay-drain --bind 127.0.0.1:9100").unwrap();
        writeln!(&mut out, "  sync relay-drain-self").unwrap();
        writeln!(
            &mut out,
            "  sync relay-drain-state --state /tmp/client-b.tsv"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-cycle --state /tmp/client-b.tsv --source-persona persona-pseudonymous"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  sync relay-unpack --file /tmp/client-a.relay --out /tmp/client-a.sync"
        )
        .unwrap();
        writeln!(&mut out, "  sync mutual --state /tmp/client-b.tsv").unwrap();
        writeln!(&mut out, "  sync history").unwrap();
        writeln!(&mut out, "  show state").unwrap();
        writeln!(&mut out, "  show keys").unwrap();
        writeln!(&mut out, "  show root operator").unwrap();
        writeln!(&mut out, "  show device laptop").unwrap();
        writeln!(&mut out, "  show persona operator@work").unwrap();
        writeln!(&mut out, "  list roots").unwrap();
        writeln!(&mut out, "  list devices").unwrap();
        writeln!(&mut out, "  list personas").unwrap();
        writeln!(&mut out, "  list keys").unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Create data").unwrap();
        writeln!(&mut out, "  root create --name operator").unwrap();
        writeln!(&mut out, "  root rotate-key --root operator").unwrap();
        writeln!(&mut out, "  device add --root operator --label laptop").unwrap();
        writeln!(&mut out, "  device revoke --device laptop").unwrap();
        writeln!(&mut out, "  device rotate-key --device laptop").unwrap();
        writeln!(&mut out, "  device rotate-encryption-key --device laptop").unwrap();
        writeln!(
            &mut out,
            "  persona create --root operator --label operator@work --template professional"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona create --root operator --label alias@elsewhere --profile persona.custom"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona grant-device --persona operator@work --device laptop"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  persona revoke-device --persona operator@work --device laptop"
        )
        .unwrap();
        writeln!(&mut out, "  persona rotate-key --persona operator@work").unwrap();
        writeln!(&mut out, "  persona revoke --persona operator@work").unwrap();
        writeln!(
            &mut out,
            "  message send --from persona-professional --to persona-pseudonymous --ciphertext deadbeef"
        )
        .unwrap();
        writeln!(
            &mut out,
            "  content publish --from persona-professional --type post --payload cafefood --visibility public"
        )
        .unwrap();
        writeln!(&mut out, "  recovery request --root operator --device laptop").unwrap();
        writeln!(&mut out, "  recovery approve --guardian guardian-alex").unwrap();
        writeln!(
            &mut out,
            "  recovery contest --guardian guardian-riley --reason improper-approval"
        )
        .unwrap();
        writeln!(&mut out, "  recovery reject --reason contest-upheld").unwrap();
        writeln!(
            &mut out,
            "  recovery execute --replacement-device replacement-laptop"
        )
        .unwrap();
        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Session").unwrap();
        writeln!(&mut out, "  help").unwrap();
        writeln!(&mut out, "  reset").unwrap();
        writeln!(&mut out, "  quit").unwrap();
        out
    }

    pub fn render_roots(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Roots").unwrap();
        writeln!(&mut out, "-----").unwrap();
        for root in &self.roots {
            writeln!(&mut out, "{}\t{}", root.id, root.display_name).unwrap();
        }
        out
    }

    pub fn render_devices(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Devices").unwrap();
        writeln!(&mut out, "-------").unwrap();
        for device in &self.devices {
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}",
                device.device_id, device.root_id, device.label, device.active
            )
            .unwrap();
        }
        if !self.revoked_devices.is_empty() {
            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Revoked").unwrap();
            writeln!(&mut out, "-------").unwrap();
            for device in &self.revoked_devices {
                writeln!(
                    &mut out,
                    "{}\t{}\t{}\t{}",
                    device.device_id, device.root_id, device.label, device.active
                )
                .unwrap();
            }
        }
        out
    }

    pub fn render_personas(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Personas").unwrap();
        writeln!(&mut out, "--------").unwrap();
        for persona in &self.personas {
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}",
                persona.id,
                persona.root_id,
                persona.label,
                persona_profile_label(persona.disclosure_profile.as_deref())
            )
            .unwrap();
        }
        if !self.revoked_personas.is_empty() {
            writeln!(&mut out).unwrap();
            writeln!(&mut out, "Revoked").unwrap();
            writeln!(&mut out, "-------").unwrap();
            for persona in &self.revoked_personas {
                writeln!(
                    &mut out,
                    "{}\t{}\t{}\t{}",
                    persona.id,
                    persona.root_id,
                    persona.label,
                    persona_profile_label(persona.disclosure_profile.as_deref())
                )
                .unwrap();
            }
        }
        out
    }

    pub fn render_keys(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Keys").unwrap();
        writeln!(&mut out, "----").unwrap();
        for record in &self.local_keys {
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}{}",
                record.owner_kind,
                record.owner_id,
                record.key_pair.key_id,
                short_key(&record.key_pair.public_key),
                if self.is_active_key_record(record) {
                    "\tactive"
                } else {
                    "\thistory"
                }
            )
            .unwrap();
        }
        out
    }

    pub fn render_root(&self, root_ref: &str) -> String {
        let Some(root) = self.resolve_root(root_ref) else {
            return format!("Unknown root: {root_ref}\n");
        };

        let mut out = String::new();
        writeln!(&mut out, "Root").unwrap();
        writeln!(&mut out, "----").unwrap();
        writeln!(&mut out, "id:\t{}", root.id).unwrap();
        writeln!(&mut out, "name:\t{}", root.display_name).unwrap();
        writeln!(
            &mut out,
            "security:\t{}",
            self.root_security_summary(&root.id)
        )
        .unwrap();
        writeln!(&mut out, "key id:\t{}", root.active_key.key_id).unwrap();
        writeln!(
            &mut out,
            "public key:\t{}",
            short_key(&root.active_key.public_key)
        )
        .unwrap();
        writeln!(
            &mut out,
            "local private key:\t{}",
            if self
                .find_local_key("root", &root.id, &root.active_key.key_id)
                .is_some()
            {
                "present"
            } else {
                "missing"
            }
        )
        .unwrap();
        let device_count = self
            .devices
            .iter()
            .filter(|device| device.root_id == root.id)
            .count();
        writeln!(&mut out, "devices:\t{device_count}").unwrap();
        writeln!(&mut out, "personas:").unwrap();
        let mut count = 0usize;
        for persona in self
            .personas
            .iter()
            .filter(|persona| persona.root_id == root.id)
        {
            count += 1;
            writeln!(
                &mut out,
                "  - {}\t{}\t{}",
                persona.id,
                persona.label,
                persona_profile_label(persona.disclosure_profile.as_deref())
            )
            .unwrap();
        }
        if count == 0 {
            writeln!(&mut out, "  - none").unwrap();
        }
        out
    }

    pub fn render_persona(&self, persona_ref: &str) -> String {
        if let Some(persona) = self.resolve_persona(persona_ref) {
            let mut out = String::new();
            writeln!(&mut out, "Persona").unwrap();
            writeln!(&mut out, "-------").unwrap();
            writeln!(&mut out, "id:\t{}", persona.id).unwrap();
            writeln!(&mut out, "root:\t{}", persona.root_id).unwrap();
            writeln!(&mut out, "label:\t{}", persona.label).unwrap();
            writeln!(
                &mut out,
                "disclosure profile:\t{}",
                persona.disclosure_profile.as_deref().unwrap_or("(none)")
            )
            .unwrap();
            writeln!(
                &mut out,
                "client template:\t{}",
                inferred_template_label(persona.disclosure_profile.as_deref())
            )
            .unwrap();
            writeln!(&mut out, "survival:\t{:?}", persona.survival_mode).unwrap();
            writeln!(&mut out, "key id:\t{}", persona.active_key.key_id).unwrap();
            writeln!(
                &mut out,
                "public key:\t{}",
                short_key(&persona.active_key.public_key)
            )
            .unwrap();
            writeln!(&mut out, "local signing devices:").unwrap();
            match self.persona_access_descriptions(&persona.id) {
                Ok(access) if access.is_empty() => {
                    writeln!(&mut out, "  - none").unwrap();
                }
                Ok(access) => {
                    for device in access {
                        writeln!(&mut out, "  - {}", device).unwrap();
                    }
                }
                Err(err) => {
                    writeln!(&mut out, "  - unavailable ({})", err.message).unwrap();
                }
            }
            writeln!(
                &mut out,
                "local key material:\t{}",
                if self
                    .find_local_key("persona", &persona.id, &persona.active_key.key_id)
                    .is_some()
                {
                    "present (device-mediated)"
                } else {
                    "missing"
                }
            )
            .unwrap();
            return out;
        }

        if let Some(persona) = self
            .revoked_personas
            .iter()
            .find(|persona| persona.id == persona_ref || persona.label == persona_ref)
        {
            return format!("Persona {} is revoked\n", persona.id);
        }

        format!("Unknown persona: {persona_ref}\n")
    }

    pub fn render_device(&self, device_ref: &str) -> String {
        let Some(device) = self.resolve_device(device_ref) else {
            if let Some(device) = self.revoked_devices.iter().find(|device| {
                device.device_id == device_ref || device.label.eq_ignore_ascii_case(device_ref)
            }) {
                return format!("Device {} is revoked\n", device.device_id);
            }
            return format!("Unknown device: {device_ref}\n");
        };

        let mut out = String::new();
        writeln!(&mut out, "Device").unwrap();
        writeln!(&mut out, "------").unwrap();
        writeln!(&mut out, "id:\t{}", device.device_id).unwrap();
        writeln!(&mut out, "root:\t{}", device.root_id).unwrap();
        writeln!(&mut out, "label:\t{}", device.label).unwrap();
        writeln!(&mut out, "active:\t{}", device.active).unwrap();
        writeln!(&mut out, "signing key id:\t{}", device.active_key.key_id).unwrap();
        writeln!(
            &mut out,
            "signing public key:\t{}",
            short_key(&device.active_key.public_key)
        )
        .unwrap();
        writeln!(
            &mut out,
            "local signing key:\t{}",
            if self
                .find_local_key("device", &device.device_id, &device.active_key.key_id)
                .is_some()
            {
                "present"
            } else {
                "missing"
            }
        )
        .unwrap();
        writeln!(
            &mut out,
            "encryption key id:\t{}",
            device.active_encryption_key.key_id
        )
        .unwrap();
        writeln!(
            &mut out,
            "encryption public key:\t{}",
            short_key(&device.active_encryption_key.public_key)
        )
        .unwrap();
        writeln!(
            &mut out,
            "local encryption key:\t{}",
            if self
                .find_local_key(
                    "device-encryption",
                    &device.device_id,
                    &device.active_encryption_key.key_id,
                )
                .is_some()
            {
                "present"
            } else {
                "missing"
            }
        )
        .unwrap();
        writeln!(&mut out, "persona signing access:").unwrap();
        match self.device_access_descriptions(&device.device_id) {
            Ok(access) if access.is_empty() => {
                writeln!(&mut out, "  - none").unwrap();
            }
            Ok(access) => {
                for persona in access {
                    writeln!(&mut out, "  - {}", persona).unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "  - unavailable ({})", err.message).unwrap();
            }
        }
        out
    }

    pub fn render_broker(&self, disclose_link: bool) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Identity Broker").unwrap();
        writeln!(&mut out, "---------------").unwrap();

        for root in &self.roots {
            writeln!(&mut out, "Root: {} ({})", root.display_name, root.id).unwrap();
            let mut found_persona = false;
            for persona in self.personas.iter().filter(|p| p.root_id == root.id) {
                found_persona = true;
                writeln!(
                    &mut out,
                    "  - Persona: {} [{} | {}]",
                    persona.label,
                    persona.id,
                    persona_profile_label(persona.disclosure_profile.as_deref())
                )
                .unwrap();
            }
            if !found_persona {
                writeln!(&mut out, "  - Personas: none yet").unwrap();
            }
        }

        let mut linkages = self.linkages.clone();
        if disclose_link {
            for linkage in &mut linkages {
                linkage.disclosed = true;
            }
        }

        writeln!(&mut out).unwrap();
        writeln!(&mut out, "Local-only associations").unwrap();
        if linkages.is_empty() {
            writeln!(&mut out, "  - none").unwrap();
        } else {
            for linkage in &self.linkages {
                writeln!(
                    &mut out,
                    "  - {} <-> {} [LOCAL ONLY]",
                    linkage.source_root_id, linkage.target_root_id
                )
                .unwrap();
            }
        }

        if let Some(primary_root) = self.roots.first() {
            let outward = disclosure_view(&primary_root.id, &self.personas, &linkages);
            writeln!(&mut out).unwrap();
            writeln!(
                &mut out,
                "Disclosure preview for {} (disclose_link = {})",
                primary_root.id, disclose_link
            )
            .unwrap();
            for persona in outward.personas {
                writeln!(&mut out, "  - Visible persona: {}", persona.label).unwrap();
            }
            if outward.disclosed_links.is_empty() {
                writeln!(&mut out, "  - Visible cross-root links: none").unwrap();
            } else {
                for link in outward.disclosed_links {
                    writeln!(
                        &mut out,
                        "  - Visible cross-root link to {}",
                        link.target_root_id
                    )
                    .unwrap();
                }
            }
        }

        out
    }

    pub fn render_trust(&self) -> String {
        self.render_trust_for_recipient(None)
    }

    pub fn render_trust_for_recipient(&self, recipient: Option<&str>) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Trust Scorecard").unwrap();
        writeln!(&mut out, "---------------").unwrap();
        writeln!(&mut out, "Audience: {}", recipient.unwrap_or("public")).unwrap();

        let target = self
            .trust_attestations
            .first()
            .map(|attestation| (attestation.subject.clone(), attestation.domain.clone()));
        let derived = match (target.as_ref(), recipient) {
            (Some((subject, domain)), Some(recipient)) => derive_score_for_recipient(
                &self.trust_attestations,
                subject,
                domain,
                Some(recipient),
            ),
            (Some((subject, domain)), None) => {
                derive_score(&self.trust_attestations, subject, domain)
            }
            (None, _) => None,
        };

        if let Some(derived) = derived {
            let explanation = explain(&derived);
            writeln!(&mut out, "Subject: {}", derived.subject).unwrap();
            writeln!(&mut out, "Domain: {}", derived.domain).unwrap();
            writeln!(
                &mut out,
                "Normalized score: {:.2}",
                derived.normalized_score
            )
            .unwrap();
            writeln!(&mut out, "Summary: {}", explanation.summary).unwrap();
            writeln!(
                &mut out,
                "Redacted summary: {}",
                explanation.redacted_summary
            )
            .unwrap();
        } else {
            writeln!(&mut out, "No derived trust score available yet").unwrap();
        }
        writeln!(
            &mut out,
            "Attestations loaded: {}",
            self.trust_attestations.len()
        )
        .unwrap();
        if self.trust_attestations.is_empty() {
            writeln!(&mut out, "Attestations: none").unwrap();
        } else {
            writeln!(&mut out, "Attestations:").unwrap();
            for attestation in &self.trust_attestations {
                writeln!(
                    &mut out,
                    "  - {}\t{}\t{}\t{}\t{:.2}\t{}",
                    attestation.id,
                    attestation.attester,
                    attestation.subject,
                    attestation.domain,
                    attestation.score,
                    attestation.recipient_bound.as_deref().unwrap_or("(public)")
                )
                .unwrap();
            }
        }

        out
    }

    pub fn render_recovery(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Recovery").unwrap();
        writeln!(&mut out, "--------").unwrap();
        writeln!(
            &mut out,
            "Policy: root {} requires {} guardian approvals",
            self.recovery_policy.root_id, self.recovery_policy.guardian_threshold
        )
        .unwrap();
        if let Some(session) = &self.recovery_session {
            let request_record = self
                .event_store
                .materialized()
                .recovery_requests_current
                .get(&session.request_id);
            writeln!(
                &mut out,
                "Request: {} for device {}",
                session.request_id, session.target_device_id
            )
            .unwrap();
            if let Some(replacement_device_id) = &session.replacement_device_id {
                writeln!(&mut out, "Replacement device: {}", replacement_device_id).unwrap();
            }
            writeln!(&mut out, "State: {}", session.state).unwrap();
            if let Some(request) = request_record {
                if let Some(until) = request.cooldown_until {
                    writeln!(&mut out, "Cooldown until: {}", until).unwrap();
                } else {
                    writeln!(&mut out, "Cooldown until: none").unwrap();
                }
                if let Some(reason) = &request.contest_reason {
                    writeln!(&mut out, "Contest reason: {}", reason).unwrap();
                }
                if let Some(reason) = &request.rejection_reason {
                    writeln!(&mut out, "Rejection reason: {}", reason).unwrap();
                }
            }
            writeln!(
                &mut out,
                "Approvals: {}/{}",
                session.approvals.len(),
                self.recovery_policy.guardian_threshold
            )
            .unwrap();
            for guardian_id in &session.approvals {
                writeln!(&mut out, "  - Approval from {}", guardian_id).unwrap();
            }
            if session.notified_devices.is_empty() {
                writeln!(&mut out, "Notified active devices: none").unwrap();
            } else {
                writeln!(&mut out, "Notified active devices:").unwrap();
                for device_id in &session.notified_devices {
                    writeln!(&mut out, "  - {}", device_id).unwrap();
                }
            }
            writeln!(
                &mut out,
                "Execution scope: freeze target device, preserve root and personas, restore persona access to replacement device when selected"
            )
            .unwrap();
        } else {
            writeln!(&mut out, "Request: none").unwrap();
            writeln!(&mut out, "State: idle").unwrap();
        }
        out
    }

    pub fn render_storage(&self) -> String {
        let mut out = String::new();
        let relationship = self.current_storage_relationship();
        let ledger = self.current_storage_ledger();
        let manifest = match self.current_storage_manifest() {
            Ok(manifest) => manifest,
            Err(err) => {
                writeln!(&mut out, "Reciprocal Storage").unwrap();
                writeln!(&mut out, "------------------").unwrap();
                writeln!(&mut out, "Storage manifest unavailable: {}", err.message).unwrap();
                return out;
            }
        };
        writeln!(&mut out, "Reciprocal Storage").unwrap();
        writeln!(&mut out, "------------------").unwrap();
        writeln!(
            &mut out,
            "Relationship: {} <-> {}",
            relationship.local_peer_id, relationship.remote_peer_id
        )
        .unwrap();
        writeln!(&mut out, "Approved: {}", relationship.approved).unwrap();
        writeln!(
            &mut out,
            "Manifest: {} with {} chunks",
            manifest.id,
            manifest.chunks.len()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Encrypted root: {}",
            manifest.encrypted_root_chunk_id
        )
        .unwrap();
        if manifest.authorized_devices.is_empty() {
            writeln!(&mut out, "Authorized restore devices: none").unwrap();
        } else {
            writeln!(&mut out, "Authorized restore devices:").unwrap();
            for access in &manifest.authorized_devices {
                writeln!(
                    &mut out,
                    "  - {}\t{}",
                    access.device_id,
                    self.device_status_label(&access.device_id)
                )
                .unwrap();
            }
        }
        writeln!(
            &mut out,
            "Ledger delta: {} bytes",
            ledger.stored_bytes_delta
        )
        .unwrap();
        match self.event_store.local_block_coverage(&manifest.id) {
            Ok(Some(coverage)) => {
                writeln!(
                    &mut out,
                    "Local block coverage: {} / {} present",
                    coverage.present_chunks, coverage.total_chunks
                )
                .unwrap();
                if coverage.missing_chunks.is_empty() {
                    writeln!(&mut out, "Missing local blocks: none").unwrap();
                } else {
                    writeln!(
                        &mut out,
                        "Missing local blocks: {}",
                        coverage
                            .missing_chunks
                            .iter()
                            .map(|chunk| chunk.chunk_id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .unwrap();
                }
            }
            Ok(None) => {
                writeln!(&mut out, "Local block coverage: unavailable").unwrap();
            }
            Err(err) => {
                writeln!(&mut out, "Local block coverage: error ({})", err.message).unwrap();
            }
        }
        match self.storage_restore_plan_snapshot() {
            Ok((_, _, restore_device_id, chunks)) => {
                writeln!(&mut out, "Restore device: {}", restore_device_id).unwrap();
                writeln!(&mut out, "Restore determinism: yes").unwrap();
                writeln!(&mut out, "Restore plan chunks: {}", chunks.len()).unwrap();
            }
            Err(err) => {
                writeln!(&mut out, "Restore determinism: blocked").unwrap();
                writeln!(&mut out, "Restore status: {}", err.message).unwrap();
            }
        }
        writeln!(&mut out, "Imbalance visibility: enabled in demo output").unwrap();
        out
    }

    pub fn render_vault(&self, namespace_arg: Option<&str>) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Vault").unwrap();
        writeln!(&mut out, "-----").unwrap();

        let namespace = match self.parse_vault_namespace_arg(namespace_arg) {
            Ok(namespace) => namespace,
            Err(err) => {
                writeln!(&mut out, "Namespace error: {}", err.message).unwrap();
                return out;
            }
        };
        writeln!(
            &mut out,
            "Namespace: {}:{}",
            namespace.owner_kind.as_str(),
            namespace.owner_id
        )
        .unwrap();

        let catalog = match self.event_store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => {
                writeln!(&mut out, "Catalog: none").unwrap();
                return out;
            }
            Err(err) => {
                writeln!(&mut out, "Catalog error: {}", err.message).unwrap();
                return out;
            }
        };
        writeln!(&mut out, "Objects: {}", catalog.objects.len()).unwrap();
        let deleted_objects = catalog
            .objects
            .iter()
            .filter(|object| object.deleted)
            .count();
        writeln!(&mut out, "Deleted objects: {}", deleted_objects).unwrap();
        writeln!(&mut out, "Revisions: {}", catalog.revisions.len()).unwrap();
        writeln!(&mut out, "Catalog objects:").unwrap();
        for object in &catalog.objects {
            let latest_revision = catalog
                .revisions
                .iter()
                .find(|revision| revision.id == object.latest_revision_id);
            writeln!(
                &mut out,
                "  - {}\t{}\tlatest={}\tstatus={}",
                object.id,
                object.class.as_str(),
                object.latest_revision_id,
                if object.deleted { "deleted" } else { "active" }
            )
            .unwrap();
            if let Some(revision) = latest_revision {
                writeln!(
                    &mut out,
                    "    revision manifest={}\tpayload={}",
                    revision.manifest_id,
                    revision.payload_kind.as_str()
                )
                .unwrap();
                if let Some(structured) = &revision.structured_record {
                    writeln!(
                        &mut out,
                        "    schema={}@{}\tencoding={}\tapp={}",
                        structured.schema_id,
                        structured.schema_version,
                        structured.encoding.as_str(),
                        structured.app_namespace
                    )
                    .unwrap();
                }
            }
        }

        let templates = match self.event_store.local_presentation_templates() {
            Ok(templates) => templates
                .into_iter()
                .filter(|template| {
                    template.namespace == namespace
                        && catalog
                            .objects
                            .iter()
                            .any(|object| object.id == template.source_object_id)
                })
                .collect::<Vec<_>>(),
            Err(err) => {
                writeln!(&mut out, "Templates error: {}", err.message).unwrap();
                return out;
            }
        };
        if templates.is_empty() {
            writeln!(&mut out, "Templates: none").unwrap();
        } else {
            writeln!(&mut out, "Templates:").unwrap();
            for template in templates {
                let expires = template
                    .expires_after_secs
                    .map(|seconds| format!("{seconds}s"))
                    .unwrap_or_else(|| "none".to_string());
                writeln!(
                    &mut out,
                    "  - {}\t{}\tfields={}\texpires={}",
                    template.id,
                    template.audience_kind.as_str(),
                    template.field_paths.join(","),
                    expires
                )
                .unwrap();
            }
        }

        let artifacts = match self.event_store.local_presentation_artifacts() {
            Ok(artifacts) => artifacts
                .into_iter()
                .filter(|record| {
                    record.namespace == namespace
                        && catalog
                            .objects
                            .iter()
                            .any(|object| object.id == record.artifact.source_object_id)
                })
                .collect::<Vec<_>>(),
            Err(err) => {
                writeln!(&mut out, "Artifacts error: {}", err.message).unwrap();
                return out;
            }
        };
        if artifacts.is_empty() {
            writeln!(&mut out, "Artifacts: none").unwrap();
        } else {
            writeln!(&mut out, "Artifacts:").unwrap();
            for record in artifacts {
                writeln!(
                    &mut out,
                    "  - {}\t{}\t{}\tmanifest={}\ttemplate={}",
                    record.artifact.id,
                    record.artifact.recipient_kind.as_str(),
                    record.artifact.recipient_id,
                    record.artifact.manifest_id,
                    record.template_id
                )
                .unwrap();
            }
        }

        let received = match self.event_store.local_received_presentation_artifacts() {
            Ok(records) => records,
            Err(err) => {
                writeln!(&mut out, "Received artifacts error: {}", err.message).unwrap();
                return out;
            }
        };
        if received.is_empty() {
            writeln!(&mut out, "Received artifacts: none").unwrap();
        } else {
            writeln!(&mut out, "Received artifacts: {}", received.len()).unwrap();
        }

        out
    }

    pub fn render_received_artifacts(&self) -> String {
        self.render_received_artifacts_with_limit(0)
    }

    pub fn render_received_artifacts_with_limit(&self, limit: usize) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Received Artifacts").unwrap();
        writeln!(&mut out, "------------------").unwrap();

        let records = match self.event_store.local_received_presentation_artifacts() {
            Ok(records) => records,
            Err(err) => {
                writeln!(&mut out, "Load error: {}", err.message).unwrap();
                return out;
            }
        };
        if records.is_empty() {
            writeln!(&mut out, "  - none").unwrap();
            return out;
        }

        let total = records.len();
        let display_records: &[_] = if limit > 0 && total > limit {
            &records[..limit]
        } else {
            &records
        };
        for record in display_records {
            let verification = self.event_store.verify_disclosure_issuer(&record.envelope);
            writeln!(
                &mut out,
                "  - {}\tstatus {}\tverification {}\tissuer {}\t{}\t{}\tschema {}\treceipts {}\tlast-source {}\t{}",
                record.envelope.artifact.id,
                self.presentation_artifact_status_label(&record.envelope.artifact),
                verification.as_str(),
                record.envelope.issuer_persona_id,
                record.envelope.artifact.recipient_kind.as_str(),
                record.envelope.artifact.recipient_id,
                record.envelope.artifact.schema_id,
                record.receipt_count,
                record.last_source_kind.as_str(),
                record.last_source_ref
            )
            .unwrap();
            writeln!(
                &mut out,
                "    payload {}",
                disclosure_payload_preview(&record.envelope.payload_bytes)
            )
            .unwrap();
        }
        if limit > 0 && total > limit {
            writeln!(
                &mut out,
                "  ({total} total, showing {limit}. Use --limit N to see more)"
            )
            .unwrap();
        }

        out
    }

    pub fn render_storage_restore_plan(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Storage Restore Plan").unwrap();
        writeln!(&mut out, "--------------------").unwrap();

        match self.storage_restore_plan_snapshot() {
            Ok((relationship, manifest, restore_device_id, chunks)) => {
                writeln!(&mut out, "Relationship: {}", relationship.id).unwrap();
                writeln!(&mut out, "Manifest: {}", manifest.id).unwrap();
                writeln!(
                    &mut out,
                    "Encrypted root: {}",
                    manifest.encrypted_root_chunk_id
                )
                .unwrap();
                writeln!(&mut out, "Restore device: {}", restore_device_id).unwrap();
                writeln!(&mut out, "Chunks: {}", chunks.len()).unwrap();
                writeln!(
                    &mut out,
                    "Authorized devices: {}",
                    manifest.authorized_devices.len()
                )
                .unwrap();
                for chunk in chunks {
                    writeln!(&mut out, "  - {}\t{}", chunk.manifest_id, chunk.chunk_id).unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "Restore blocked: {}", err.message).unwrap();
            }
        }

        out
    }

    pub fn render_sync(&self) -> String {
        let mut out = String::new();
        let envelope = wrap_for_relay("relay-envelope-demo", vec![0x01, 0xa4, 0xff, 0x09, 0x42]);
        let trust_score = derive_score(
            &self.trust_attestations,
            "persona-pseudonymous",
            "professional",
        )
        .map(|statement| statement.normalized_score);
        let threshold = TrustThreshold::new(0.75).expect("valid threshold");
        let admission = check_relay_admission(
            RelayMode::TrustGated,
            "persona-pseudonymous",
            trust_score,
            Some(threshold),
            &[],
        );

        writeln!(&mut out, "Sync And Relay").unwrap();
        writeln!(&mut out, "--------------").unwrap();
        writeln!(&mut out, "Local peer: {}", self.current_peer_id()).unwrap();
        writeln!(&mut out, "Relay envelope: {}", envelope.id).unwrap();
        writeln!(&mut out, "Opaque bytes: {}", envelope.opaque_payload.len()).unwrap();
        writeln!(&mut out, "Payload semantics: hidden from relay").unwrap();
        writeln!(&mut out, "Relay mode: trust-gated").unwrap();
        writeln!(&mut out, "Threshold: 0.75").unwrap();
        if let Some(endpoint) = self
            .event_store
            .materialized()
            .endpoint(&self.current_peer_id())
        {
            writeln!(
                &mut out,
                "Local endpoint: {}\tvia {}",
                endpoint.transport_hint, endpoint.device_id
            )
            .unwrap();
        } else {
            writeln!(&mut out, "Local endpoint: none published").unwrap();
        }
        writeln!(&mut out, "Admission: {}", relay_admission_label(&admission)).unwrap();
        if let RelayAdmission::Reject { reason } = admission {
            writeln!(&mut out, "Reason: {}", reason).unwrap();
        }
        match self.event_store.peer_cursors() {
            Ok(cursors) if cursors.is_empty() => {
                writeln!(&mut out, "Tracked peers: none").unwrap();
            }
            Ok(cursors) => {
                writeln!(&mut out, "Tracked peers:").unwrap();
                for cursor in cursors {
                    writeln!(
                        &mut out,
                        "  - {}\t{}",
                        cursor.peer_id,
                        cursor.last_event_id.unwrap_or_else(|| "(none)".to_string())
                    )
                    .unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "Tracked peers: unavailable ({})", err.message).unwrap();
            }
        }
        if self.event_store.materialized().endpoints_current.is_empty() {
            writeln!(&mut out, "Known endpoints: none").unwrap();
        } else {
            writeln!(&mut out, "Known endpoints:").unwrap();
            for endpoint in self.event_store.materialized().endpoints_current.values() {
                writeln!(
                    &mut out,
                    "  - {}\t{}\tvia {}",
                    endpoint.peer_id, endpoint.transport_hint, endpoint.device_id
                )
                .unwrap();
            }
        }
        match self.event_store.sync_batches() {
            Ok(batches) if batches.is_empty() => {
                writeln!(&mut out, "Sync batches: none").unwrap();
            }
            Ok(batches) => {
                writeln!(&mut out, "Recent sync batches:").unwrap();
                for batch in batches.iter().rev().take(3) {
                    writeln!(
                        &mut out,
                        "  - {}\t{}\t{}",
                        batch.batch_id,
                        batch.peer_id,
                        batch
                            .last_event_id
                            .clone()
                            .unwrap_or_else(|| "(none)".to_string())
                    )
                    .unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "Sync batches: unavailable ({})", err.message).unwrap();
            }
        }

        out
    }

    pub fn render_sync_history(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Sync History").unwrap();
        writeln!(&mut out, "------------").unwrap();
        match self.event_store.peer_cursors() {
            Ok(cursors) if cursors.is_empty() => {
                writeln!(&mut out, "Tracked peers: none").unwrap();
            }
            Ok(cursors) => {
                writeln!(&mut out, "Tracked peers:").unwrap();
                for cursor in cursors {
                    writeln!(
                        &mut out,
                        "  - {}\t{}",
                        cursor.peer_id,
                        cursor.last_event_id.unwrap_or_else(|| "(none)".to_string())
                    )
                    .unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "Tracked peers: unavailable ({})", err.message).unwrap();
            }
        }
        match self.event_store.sync_batches() {
            Ok(batches) if batches.is_empty() => {
                writeln!(&mut out, "Batches: none").unwrap();
            }
            Ok(batches) => {
                writeln!(&mut out, "Batches:").unwrap();
                for batch in batches {
                    writeln!(
                        &mut out,
                        "  - {}\t{}\t{}",
                        batch.batch_id,
                        batch.peer_id,
                        batch.last_event_id.unwrap_or_else(|| "(none)".to_string())
                    )
                    .unwrap();
                }
            }
            Err(err) => {
                writeln!(&mut out, "Batches: unavailable ({})", err.message).unwrap();
            }
        }
        out
    }

    pub fn render_storage_gc_plan(&self, namespace_arg: Option<&str>) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Storage GC Plan").unwrap();
        writeln!(&mut out, "---------------").unwrap();

        let namespace = match self.parse_vault_namespace_arg(namespace_arg) {
            Ok(namespace) => namespace,
            Err(err) => {
                writeln!(&mut out, "Invalid namespace: {}", err.message).unwrap();
                return out;
            }
        };

        match self.event_store.plan_local_vault_gc(&namespace) {
            Ok(Some(plan)) => {
                writeln!(
                    &mut out,
                    "Namespace: {}:{}",
                    plan.namespace.owner_kind.as_str(),
                    plan.namespace.owner_id
                )
                .unwrap();
                writeln!(&mut out, "Catalog manifest: {}", plan.catalog_manifest_id).unwrap();
                writeln!(
                    &mut out,
                    "Retained revisions: {}",
                    join_or_none(&plan.retained_revision_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Retained manifests: {}",
                    join_or_none(&plan.retained_manifest_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Collectable manifests: {}",
                    join_or_none(&plan.collectable_manifest_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Collectable chunks: {}",
                    join_or_none(&plan.collectable_chunk_ids)
                )
                .unwrap();
            }
            Ok(None) => {
                writeln!(
                    &mut out,
                    "No local vault catalog for {}:{}",
                    namespace.owner_kind.as_str(),
                    namespace.owner_id
                )
                .unwrap();
            }
            Err(err) => {
                writeln!(&mut out, "GC plan unavailable: {}", err.message).unwrap();
            }
        }
        out
    }

    pub fn render_storage_audit(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Storage Audit").unwrap();
        writeln!(&mut out, "-------------").unwrap();

        match self.event_store.audit_local_blocks() {
            Ok(audit) => {
                writeln!(
                    &mut out,
                    "Referenced chunks: {}",
                    join_or_none(&audit.referenced_chunk_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Missing referenced chunks: {}",
                    join_or_none(&audit.missing_referenced_chunk_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Orphaned metadata rows: {}",
                    join_or_none(&audit.orphaned_metadata_chunk_ids)
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "Orphaned sidecar files: {}",
                    join_or_none(&audit.orphaned_file_chunk_ids)
                )
                .unwrap();
            }
            Err(err) => {
                writeln!(&mut out, "Audit unavailable: {}", err.message).unwrap();
            }
        }

        out
    }

    pub fn render_state(&self) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Event State").unwrap();
        writeln!(&mut out, "-----------").unwrap();
        writeln!(&mut out, "State location: {}", self.state_location_label()).unwrap();
        writeln!(&mut out, "Peer id: {}", self.current_peer_id()).unwrap();
        if let Some(data_file) = &self.data_file {
            writeln!(&mut out, "Local state file: {}", data_file.display()).unwrap();
            writeln!(
                &mut out,
                "Event store file: {}",
                sqlite_path_for_local_state(data_file).display()
            )
            .unwrap();
        } else {
            writeln!(&mut out, "Local state file: (ephemeral)").unwrap();
            writeln!(&mut out, "Event store file: (in-memory)").unwrap();
        }
        writeln!(
            &mut out,
            "Appended events: {}",
            self.event_store.event_count()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Message events: {}",
            self.event_store
                .events()
                .iter()
                .filter(|event| event.event_type == EventType::MessageSent)
                .count()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Content events: {}",
            self.event_store
                .events()
                .iter()
                .filter(|event| event.event_type == EventType::ContentPublished)
                .count()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Known endpoints: {}",
            self.event_store.materialized().endpoints_current.len()
        )
        .unwrap();
        writeln!(&mut out, "Roots in memory: {}", self.roots.len()).unwrap();
        writeln!(&mut out, "Devices in memory: {}", self.devices.len()).unwrap();
        writeln!(&mut out, "Revoked devices: {}", self.revoked_devices.len()).unwrap();
        writeln!(&mut out, "Personas in memory: {}", self.personas.len()).unwrap();
        writeln!(
            &mut out,
            "Revoked personas: {}",
            self.revoked_personas.len()
        )
        .unwrap();
        match self.event_store.peer_cursors() {
            Ok(cursors) => {
                writeln!(&mut out, "Tracked peers: {}", cursors.len()).unwrap();
            }
            Err(err) => {
                writeln!(&mut out, "Tracked peers: unavailable ({})", err.message).unwrap();
            }
        }

        if let Some(event) = self
            .event_store
            .events()
            .iter()
            .find(|event| event.event_type == EventType::RootCreated)
        {
            writeln!(
                &mut out,
                "Contains root event:\t{}\t{:?}",
                event.event_id, event.event_type
            )
            .unwrap();
        }

        if let Some(event) = self
            .event_store
            .events()
            .iter()
            .find(|event| event.event_type == EventType::PersonaCreated)
        {
            writeln!(
                &mut out,
                "Contains persona event:\t{}\t{:?}",
                event.event_id, event.event_type
            )
            .unwrap();
        }

        if let Some(event) = self.event_store.events().last() {
            writeln!(
                &mut out,
                "Latest event:\t{}\t{:?}",
                event.event_id, event.event_type
            )
            .unwrap();
        }

        out
    }

    pub fn render_all(&self) -> String {
        [
            self.render_home(),
            self.render_roots(),
            self.render_devices(),
            self.render_personas(),
            self.render_broker(false),
            self.render_messages(),
            self.render_disclosures(),
            self.render_received_artifacts(),
            self.render_content(),
            self.render_trust(),
            self.render_recovery(),
            self.render_vault(None),
            self.render_storage(),
            self.render_keys(),
            self.render_state(),
        ]
        .join("\n")
    }
}
