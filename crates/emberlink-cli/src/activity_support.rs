use std::fmt::Write as _;

use core_event_types::{EventBody, EventType};
use core_storage::{PresentationArtifactEnvelope, decode_presentation_artifact_envelope};
use core_types::ValidationError;

use crate::{DemoApp, parse_content_visibility_arg};

impl DemoApp {
    pub fn render_messages(&self) -> String {
        self.render_messages_with_limit(0)
    }

    pub fn render_messages_with_limit(&self, limit: usize) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Messages").unwrap();
        writeln!(&mut out, "--------").unwrap();

        let message_events: Vec<_> = self
            .app_runtime
            .store
            .events_of_type_rev(EventType::MessageSent)
            .collect();
        let total = message_events.len();

        if total == 0 {
            writeln!(&mut out, "  - none").unwrap();
            return out;
        }

        let display_count = if limit > 0 { limit.min(total) } else { total };
        for event in &message_events[..display_count] {
            if let EventBody::MessageSent(body) = &event.body {
                if let Some(disclosure) = decode_disclosure_artifact_message(&body.ciphertext_hex) {
                    writeln!(
                        &mut out,
                        "  - {}\tfrom {}\tto {}\tdisclosure artifact {}\tschema {}\trecipient {}\tissuer {}\tevent {}",
                        body.message_id,
                        self.persona_display_ref(&body.sender_persona_id),
                        self.persona_display_ref(&body.recipient_persona_id),
                        disclosure.artifact.id,
                        disclosure.artifact.schema_id,
                        disclosure.artifact.recipient_id,
                        self.persona_display_ref(&disclosure.issuer_persona_id),
                        event.event_id,
                    )
                    .unwrap();
                    writeln!(
                        &mut out,
                        "    payload {}",
                        disclosure_payload_preview(&disclosure.payload_bytes)
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut out,
                        "  - {}\tfrom {}\tto {}\tciphertext {} bytes\tevent {}",
                        body.message_id,
                        self.persona_display_ref(&body.sender_persona_id),
                        self.persona_display_ref(&body.recipient_persona_id),
                        body.ciphertext_hex.len() / 2,
                        event.event_id,
                    )
                    .unwrap();
                }
            }
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

    pub fn render_content(&self) -> String {
        self.render_content_with_limit(0)
    }

    pub fn render_content_with_limit(&self, limit: usize) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Content").unwrap();
        writeln!(&mut out, "-------").unwrap();

        let content_events: Vec<_> = self
            .app_runtime
            .store
            .events_of_type_rev(EventType::ContentPublished)
            .collect();
        let total = content_events.len();

        if total == 0 {
            writeln!(&mut out, "  - none").unwrap();
            return out;
        }

        let display_count = if limit > 0 { limit.min(total) } else { total };
        for event in &content_events[..display_count] {
            if let EventBody::ContentPublished(body) = &event.body {
                writeln!(
                    &mut out,
                    "  - {}\tauthor {}\ttype {}\tvisibility {}\tpayload {} bytes\tevent {}",
                    body.content_id,
                    self.persona_display_ref(&body.author_persona_id),
                    body.content_type,
                    body.visibility.as_str(),
                    body.payload_hex.len() / 2,
                    event.event_id,
                )
                .unwrap();
            }
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

    pub fn render_disclosures(&self) -> String {
        self.render_disclosures_with_limit(0)
    }

    pub fn render_disclosures_with_limit(&self, limit: usize) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Disclosures").unwrap();
        writeln!(&mut out, "-----------").unwrap();

        let mut count = 0usize;
        let mut shown = 0usize;
        for event in self
            .app_runtime
            .store
            .events_of_type_rev(EventType::MessageSent)
        {
            if let EventBody::MessageSent(body) = &event.body
                && let Some(disclosure) = decode_disclosure_artifact_message(&body.ciphertext_hex)
            {
                count += 1;
                if limit > 0 && shown >= limit {
                    continue;
                }
                shown += 1;
                writeln!(
                    &mut out,
                    "  - {}\tartifact {}\tstatus {}\tfrom {}\tto {}\tschema {}",
                    body.message_id,
                    disclosure.artifact.id,
                    self.presentation_artifact_status_label(&disclosure.artifact),
                    self.persona_display_ref(&body.sender_persona_id),
                    self.persona_display_ref(&body.recipient_persona_id),
                    disclosure.artifact.schema_id,
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "    payload {}",
                    disclosure_payload_preview(&disclosure.payload_bytes)
                )
                .unwrap();
            }
        }
        if count == 0 {
            writeln!(&mut out, "  - none").unwrap();
        } else if limit > 0 && count > limit {
            writeln!(
                &mut out,
                "  ({count} total, showing {limit}. Use --limit N to see more)"
            )
            .unwrap();
        }

        out
    }

    pub fn render_disclosure_message(&self, message_ref: &str) -> String {
        for event in self
            .app_runtime
            .store
            .events_of_type_rev(EventType::MessageSent)
        {
            if let EventBody::MessageSent(body) = &event.body {
                if body.message_id != message_ref && event.event_id != message_ref {
                    continue;
                }
                if let Some(disclosure) = decode_disclosure_artifact_message(&body.ciphertext_hex) {
                    return format!(
                        "Disclosure\n----------\nMessage: {}\nEvent: {}\nArtifact: {}\nStatus: {}\nFrom: {}\nTo: {}\nIssuer: {}\nIssuer key: {}\nSchema: {}\nRecipient: {}\t{}\nManifest: {}\nPayload:\n{}\n",
                        body.message_id,
                        event.event_id,
                        disclosure.artifact.id,
                        self.presentation_artifact_status_label(&disclosure.artifact),
                        self.persona_display_ref(&body.sender_persona_id),
                        self.persona_display_ref(&body.recipient_persona_id),
                        self.persona_display_ref(&disclosure.issuer_persona_id),
                        disclosure.issuer_key_id,
                        disclosure.artifact.schema_id,
                        disclosure.artifact.recipient_kind.as_str(),
                        disclosure.artifact.recipient_id,
                        disclosure.artifact.manifest_id,
                        format_payload(&disclosure.payload_bytes)
                    );
                }
                return format!("Message {} is not a disclosure artifact\n", message_ref);
            }
        }
        format!("Unknown disclosure message: {message_ref}\n")
    }

    pub(crate) fn message_compare_entries(&self) -> Vec<(String, String)> {
        self.app_runtime
            .store
            .events_of_type(EventType::MessageSent)
            .filter_map(|event| match &event.body {
                EventBody::MessageSent(body) => {
                    let detail = if let Some(disclosure) =
                        decode_disclosure_artifact_message(&body.ciphertext_hex)
                    {
                        format!(
                            "{} -> {}\tdisclosure {}",
                            self.persona_display_ref(&body.sender_persona_id),
                            self.persona_display_ref(&body.recipient_persona_id),
                            disclosure.artifact.id
                        )
                    } else {
                        format!(
                            "{} -> {}",
                            self.persona_display_ref(&body.sender_persona_id),
                            self.persona_display_ref(&body.recipient_persona_id)
                        )
                    };
                    Some((body.message_id.clone(), detail))
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn disclosure_artifact_message_ciphertext(
        &self,
        artifact_id: &str,
        issuer_ref: &str,
    ) -> Result<String, ValidationError> {
        Ok(core_types::bytes_to_hex(
            &self.presentation_artifact_envelope_bytes(artifact_id, issuer_ref)?,
        ))
    }

    pub(crate) fn presentation_artifact_envelope_bytes(
        &self,
        artifact_id: &str,
        issuer_ref: &str,
    ) -> Result<Vec<u8>, ValidationError> {
        let issuer = self
            .resolve_persona(issuer_ref)
            .ok_or_else(|| ValidationError::new(format!("unknown issuer persona: {issuer_ref}")))?;
        let signer = self.persona_signer(&issuer.id)?;
        let envelope = self
            .app_runtime
            .store
            .build_local_presentation_artifact_envelope(artifact_id, &issuer.id, &signer)?;
        Ok(core_storage::encode_presentation_artifact_envelope(
            &envelope,
        ))
    }

    pub(crate) fn content_compare_entries(&self) -> Vec<(String, String)> {
        self.app_runtime
            .store
            .events_of_type(EventType::ContentPublished)
            .filter_map(|event| match &event.body {
                EventBody::ContentPublished(body) => Some((
                    body.content_id.clone(),
                    format!(
                        "{}\t{}\t{}",
                        self.persona_display_ref(&body.author_persona_id),
                        body.content_type,
                        body.visibility.as_str()
                    ),
                )),
                _ => None,
            })
            .collect()
    }

    pub(super) fn handle_message_send(&mut self, tokens: &[&str]) -> String {
        let mut sender = None;
        let mut recipient = None;
        let mut ciphertext = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--from" if i + 1 < tokens.len() => {
                    sender = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--to" if i + 1 < tokens.len() => {
                    recipient = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--ciphertext" if i + 1 < tokens.len() => {
                    ciphertext = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(sender_ref) = sender else {
            return "Usage: message send --from <persona> --to <persona-id-or-label> --ciphertext <hex>\n"
                .to_string();
        };
        let Some(recipient_ref) = recipient else {
            return "Usage: message send --from <persona> --to <persona-id-or-label> --ciphertext <hex>\n"
                .to_string();
        };
        let Some(ciphertext_hex) = ciphertext else {
            return "Usage: message send --from <persona> --to <persona-id-or-label> --ciphertext <hex>\n"
                .to_string();
        };

        match self.send_message_command(&sender_ref, &recipient_ref, &ciphertext_hex) {
            Ok(message) => message,
            Err(err) => format!("Failed to send message: {}\n", err),
        }
    }

    pub(super) fn handle_content_publish(&mut self, tokens: &[&str]) -> String {
        let mut author = None;
        let mut content_type = None;
        let mut payload = None;
        let mut visibility = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--from" if i + 1 < tokens.len() => {
                    author = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--type" if i + 1 < tokens.len() => {
                    content_type = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--payload" if i + 1 < tokens.len() => {
                    payload = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--visibility" if i + 1 < tokens.len() => {
                    visibility = parse_content_visibility_arg(tokens[i + 1]);
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(author_ref) = author else {
            return "Usage: content publish --from <persona> --type <kind> --payload <hex> --visibility <public|trust-gated|direct>\n"
                .to_string();
        };
        let Some(content_type) = content_type else {
            return "Usage: content publish --from <persona> --type <kind> --payload <hex> --visibility <public|trust-gated|direct>\n"
                .to_string();
        };
        let Some(payload_hex) = payload else {
            return "Usage: content publish --from <persona> --type <kind> --payload <hex> --visibility <public|trust-gated|direct>\n"
                .to_string();
        };
        let Some(visibility) = visibility else {
            return "Usage: content publish --from <persona> --type <kind> --payload <hex> --visibility <public|trust-gated|direct>\n"
                .to_string();
        };

        match self.publish_content_command(&author_ref, &content_type, &payload_hex, visibility) {
            Ok(message) => message,
            Err(err) => format!("Failed to publish content: {}\n", err),
        }
    }
}

fn decode_disclosure_artifact_message(
    ciphertext_hex: &str,
) -> Option<PresentationArtifactEnvelope> {
    let bytes = core_types::hex_to_bytes(ciphertext_hex).ok()?;
    decode_presentation_artifact_envelope(&bytes).ok()
}

pub(crate) fn disclosure_payload_preview(payload_bytes: &[u8]) -> String {
    let mut preview = String::from_utf8_lossy(payload_bytes).into_owned();
    if preview.len() > 96 {
        preview.truncate(96);
        preview.push_str("...");
    }
    preview
}

pub(crate) fn format_payload(payload_bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(payload_bytes);
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| text.into_owned())
    } else {
        text.into_owned()
    }
}
