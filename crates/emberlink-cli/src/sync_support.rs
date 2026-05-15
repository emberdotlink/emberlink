use std::fmt::Write as _;
use std::path::PathBuf;

use core_sync::{
    PortableSyncBatch, build_relay_transport_hint, check_relay_admission, filter_batch_by_profile,
    plan_pull_batch, relevant_event_ids_for_context,
};
use core_trust::derive_score;
use core_event_types::{EventBody};
use core_principals::{RelayAdmission, RelayMode, SyncProfile, TrustThreshold};

use crate::{DemoApp, relay_admission_label};

#[derive(Debug, Clone)]
pub(super) struct SyncAdmissionOptions {
    pub(super) mode: RelayMode,
    pub(super) source_persona: Option<String>,
    pub(super) threshold: Option<TrustThreshold>,
    pub(super) allowlist: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct SyncTargetOptions {
    pub(super) state_path: String,
    pub(super) profile: SyncProfile,
    pub(super) admission: SyncAdmissionOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SyncExportOptions {
    pub(super) out_path: String,
    pub(super) profile: SyncProfile,
    pub(super) peer_state_path: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct SyncAdmissionOutcome {
    pub(super) trust_score: Option<f32>,
    pub(super) admission: RelayAdmission,
}

impl DemoApp {
    pub(super) fn handle_compare(&mut self, tokens: &[&str]) -> String {
        let mut state = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--state" if i + 1 < tokens.len() => {
                    state = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(state_path) = state else {
            return "Usage: compare --state <path>\n".to_string();
        };

        match Self::open_existing(PathBuf::from(&state_path)) {
            Ok(other) => self.render_compare_with(&other, &state_path),
            Err(err) => format!("Failed to compare state: {}\n", err),
        }
    }

    pub(super) fn handle_inspect(&mut self, tokens: &[&str]) -> String {
        let mut state = None;
        let mut screen = Some("state".to_string());
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--state" if i + 1 < tokens.len() => {
                    state = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--screen" if i + 1 < tokens.len() => {
                    screen = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(state_path) = state else {
            return "Usage: inspect --state <path> [--screen state|broker|messages|disclosures|content|trust|recovery|vault|storage|sync|roots|devices|personas|keys|all]\n".to_string();
        };
        let Some(screen) = screen else {
            return "Usage: inspect --state <path> [--screen state|broker|messages|disclosures|content|trust|recovery|vault|storage|sync|roots|devices|personas|keys|all]\n".to_string();
        };

        match Self::open_existing(PathBuf::from(state_path)) {
            Ok(mut other) => other.render_inspection_screen(&screen),
            Err(err) => format!("Failed to inspect state: {}\n", err),
        }
    }

    pub(super) fn render_inspection_screen(&mut self, screen: &str) -> String {
        match screen {
            "broker" => self.render_broker(false),
            "messages" => self.render_messages(),
            "disclosures" => self.render_disclosures(),
            "content" => self.render_content(),
            "trust" => self.render_trust(),
            "recovery" => self.render_recovery(),
            "vault" => self.render_vault(None),
            "storage" => self.render_storage(),
            "sync" => self.render_sync(),
            "state" => self.render_state(),
            "roots" => self.render_roots(),
            "devices" => self.render_devices(),
            "personas" => self.render_personas(),
            "keys" => self.render_keys(),
            "all" => self.render_all(),
            other => format!("Unknown inspection screen: {other}\n"),
        }
    }

    pub(super) fn parse_sync_target_options(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Result<SyncTargetOptions, String> {
        let (state_path, profile) = self
            .parse_sync_target_and_profile(tokens, usage)
            .ok_or_else(|| usage.to_string())?;
        let admission = self.parse_sync_admission_options(tokens, usage)?;

        Ok(SyncTargetOptions {
            state_path,
            profile,
            admission,
        })
    }

    pub(super) fn parse_sync_export(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<SyncExportOptions> {
        let mut out_path = None;
        let mut profile = SyncProfile::Full;
        let mut peer_state_path = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = SyncProfile::parse(tokens[i + 1])?;
                    i += 2;
                    continue;
                }
                "--for-state" if i + 1 < tokens.len() => {
                    peer_state_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        out_path
            .map(|out_path| SyncExportOptions {
                out_path,
                profile,
                peer_state_path,
            })
            .or_else(|| {
                let _ = usage;
                None
            })
    }

    pub(super) fn parse_sync_import(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Result<(String, SyncAdmissionOptions), String> {
        let mut file_path = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(file_path) = file_path else {
            return Err(usage.to_string());
        };
        let admission = self.parse_sync_admission_options(tokens, usage)?;
        Ok((file_path, admission))
    }

    pub(super) fn parse_sync_relay_file_and_bind(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<(String, String)> {
        let mut file_path = None;
        let mut bind_address = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--bind" if i + 1 < tokens.len() => {
                    bind_address = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        match (file_path, bind_address) {
            (Some(file_path), Some(bind_address)) => Some((file_path, bind_address)),
            _ => {
                let _ = usage;
                None
            }
        }
    }

    pub(super) fn parse_sync_relay_bind_arg(&self, tokens: &[&str], usage: &str) -> Option<String> {
        let mut bind_address = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--bind" if i + 1 < tokens.len() => {
                    bind_address = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        bind_address.or_else(|| {
            let _ = usage;
            None
        })
    }

    pub(super) fn parse_sync_relay_drain(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<(String, String)> {
        let mut bind_address = None;
        let mut peer_id = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--bind" if i + 1 < tokens.len() => {
                    bind_address = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--peer" if i + 1 < tokens.len() => {
                    peer_id = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        bind_address
            .map(|bind_address| {
                (
                    bind_address,
                    peer_id.unwrap_or_else(|| self.current_peer_id()),
                )
            })
            .or_else(|| {
                let _ = usage;
                None
            })
    }

    pub(super) fn parse_sync_file_pair(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<(String, String)> {
        let mut file_path = None;
        let mut out_path = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        match (file_path, out_path) {
            (Some(file_path), Some(out_path)) => Some((file_path, out_path)),
            _ => {
                let _ = usage;
                None
            }
        }
    }

    pub(super) fn parse_sync_file_arg(&self, tokens: &[&str], usage: &str) -> Option<String> {
        let mut file_path = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        file_path.or_else(|| {
            let _ = usage;
            None
        })
    }

    pub(super) fn parse_sync_state_arg(&self, tokens: &[&str], usage: &str) -> Option<String> {
        let mut state_path = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--state" if i + 1 < tokens.len() => {
                    state_path = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        state_path.or_else(|| {
            let _ = usage;
            None
        })
    }

    pub(super) fn parse_sync_endpoint_tokens(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<(String, String)> {
        let mut device_ref = None;
        let mut transport_hint = None;
        let mut bind_address = None;
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--device" if i + 1 < tokens.len() => {
                    device_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--hint" if i + 1 < tokens.len() => {
                    transport_hint = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--bind" if i + 1 < tokens.len() => {
                    bind_address = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        match (device_ref, transport_hint, bind_address) {
            (Some(device_ref), Some(transport_hint), None) => Some((device_ref, transport_hint)),
            (Some(device_ref), None, Some(bind_address)) => Some((
                device_ref,
                build_relay_transport_hint(bind_address, self.current_peer_id()),
            )),
            _ => {
                let _ = usage;
                None
            }
        }
    }

    pub(super) fn parse_sync_target_and_profile(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Option<(String, SyncProfile)> {
        let mut state = None;
        let mut profile = SyncProfile::Full;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--state" if i + 1 < tokens.len() => {
                    state = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--profile" if i + 1 < tokens.len() => {
                    profile = SyncProfile::parse(tokens[i + 1])?;
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }
        state.map(|value| (value, profile)).or_else(|| {
            let _ = usage;
            None
        })
    }

    pub(super) fn parse_sync_admission_options(
        &self,
        tokens: &[&str],
        usage: &str,
    ) -> Result<SyncAdmissionOptions, String> {
        let mut mode = RelayMode::Open;
        let mut source_persona = None;
        let mut threshold = None;
        let mut allowlist = Vec::new();
        let mut i = 0;

        while i < tokens.len() {
            match tokens[i] {
                "--mode" if i + 1 < tokens.len() => {
                    mode = RelayMode::parse(tokens[i + 1]).ok_or_else(|| usage.to_string())?;
                    i += 2;
                    continue;
                }
                "--source-persona" if i + 1 < tokens.len() => {
                    source_persona = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = Some(
                        TrustThreshold::new(
                            tokens[i + 1]
                                .parse::<f32>()
                                .map_err(|_| usage.to_string())?,
                        )
                        .map_err(|err| format!("Invalid threshold: {}", err))?,
                    );
                    i += 2;
                    continue;
                }
                "--allow" if i + 1 < tokens.len() => {
                    allowlist = tokens[i + 1]
                        .split(',')
                        .filter(|entry| !entry.trim().is_empty())
                        .map(|entry| entry.trim().to_string())
                        .collect();
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        Ok(SyncAdmissionOptions {
            mode,
            source_persona,
            threshold,
            allowlist,
        })
    }

    pub(super) fn evaluate_sync_admission(
        &self,
        options: &SyncAdmissionOptions,
    ) -> Result<SyncAdmissionOutcome, String> {
        match options.mode {
            RelayMode::Open => Ok(SyncAdmissionOutcome {
                trust_score: None,
                admission: RelayAdmission::Accept,
            }),
            RelayMode::TrustGated | RelayMode::NetworkScoped => {
                let source_persona = options.source_persona.as_deref().ok_or_else(|| {
                    "sync admission requires --source-persona for non-open modes".to_string()
                })?;
                let trust_score =
                    derive_score(&self.trust_attestations, source_persona, "professional")
                        .map(|statement| statement.normalized_score);
                Ok(SyncAdmissionOutcome {
                    trust_score,
                    admission: check_relay_admission(
                        options.mode,
                        source_persona,
                        trust_score,
                        options.threshold,
                        &options.allowlist,
                    ),
                })
            }
        }
    }

    pub(super) fn render_sync_admission_blocked(
        &self,
        title: &str,
        options: &SyncTargetOptions,
        trust_score: Option<f32>,
        reason: &str,
    ) -> String {
        let mut out = String::new();
        writeln!(&mut out, "{title}").unwrap();
        writeln!(&mut out, "{}", "-".repeat(title.len())).unwrap();
        writeln!(&mut out, "Other state: {}", options.state_path).unwrap();
        writeln!(&mut out, "Profile: {}", options.profile.as_str()).unwrap();
        writeln!(&mut out, "Mode: {}", options.admission.mode.as_str()).unwrap();
        writeln!(
            &mut out,
            "Source persona: {}",
            options
                .admission
                .source_persona
                .as_deref()
                .unwrap_or("(none)")
        )
        .unwrap();
        match trust_score {
            Some(score) => writeln!(&mut out, "Trust score: {:.2}", score).unwrap(),
            None => writeln!(&mut out, "Trust score: unavailable").unwrap(),
        }
        if let Some(threshold) = options.admission.threshold {
            writeln!(&mut out, "Threshold: {:.2}", threshold.value()).unwrap();
        }
        if !options.admission.allowlist.is_empty() {
            writeln!(
                &mut out,
                "Allowlist: {}",
                options.admission.allowlist.join(",")
            )
            .unwrap();
        }
        writeln!(&mut out, "Admission: reject").unwrap();
        writeln!(&mut out, "Reason: {}", reason).unwrap();
        out
    }

    pub(super) fn render_sync_import_blocked(
        &self,
        file_path: &str,
        batch: &PortableSyncBatch,
        admission: &SyncAdmissionOptions,
        trust_score: Option<f32>,
        reason: &str,
    ) -> String {
        let mut out = String::new();
        writeln!(&mut out, "Sync Import").unwrap();
        writeln!(&mut out, "-----------").unwrap();
        writeln!(&mut out, "File: {}", file_path).unwrap();
        writeln!(&mut out, "Source peer: {}", batch.source_peer_id).unwrap();
        writeln!(&mut out, "Profile: {}", batch.profile.as_str()).unwrap();
        writeln!(&mut out, "Mode: {}", admission.mode.as_str()).unwrap();
        writeln!(
            &mut out,
            "Source persona: {}",
            admission.source_persona.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        match trust_score {
            Some(score) => writeln!(&mut out, "Trust score: {:.2}", score).unwrap(),
            None => writeln!(&mut out, "Trust score: unavailable").unwrap(),
        }
        if let Some(threshold) = admission.threshold {
            writeln!(&mut out, "Threshold: {:.2}", threshold.value()).unwrap();
        }
        if !admission.allowlist.is_empty() {
            writeln!(&mut out, "Allowlist: {}", admission.allowlist.join(",")).unwrap();
        }
        writeln!(&mut out, "Admission: reject").unwrap();
        writeln!(&mut out, "Reason: {}", reason).unwrap();
        out
    }

    pub(super) fn render_sync_file_preview(
        &self,
        file_path: &str,
        batch: &PortableSyncBatch,
        admission: &SyncAdmissionOptions,
        trust_score: Option<f32>,
        relay_admission: &RelayAdmission,
    ) -> String {
        let message_count = batch
            .events
            .iter()
            .filter(|event| matches!(event.body, EventBody::MessageSent(_)))
            .count();
        let content_count = batch
            .events
            .iter()
            .filter(|event| matches!(event.body, EventBody::ContentPublished(_)))
            .count();
        let missing_event_ids: Vec<String> = batch
            .batch
            .event_ids
            .iter()
            .filter(|event_id| !self.app_runtime.store.has_event(event_id))
            .cloned()
            .collect();

        let mut out = String::new();
        writeln!(&mut out, "Sync File Preview").unwrap();
        writeln!(&mut out, "-----------------").unwrap();
        writeln!(&mut out, "File: {}", file_path).unwrap();
        writeln!(&mut out, "Source peer: {}", batch.source_peer_id).unwrap();
        writeln!(&mut out, "Profile: {}", batch.profile.as_str()).unwrap();
        writeln!(&mut out, "Batch: {}", batch.batch.id).unwrap();
        writeln!(&mut out, "Events in batch: {}", batch.batch.event_ids.len()).unwrap();
        writeln!(&mut out, "Message events in batch: {}", message_count).unwrap();
        writeln!(&mut out, "Content events in batch: {}", content_count).unwrap();
        writeln!(&mut out, "Mode: {}", admission.mode.as_str()).unwrap();
        writeln!(
            &mut out,
            "Source persona: {}",
            admission.source_persona.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        match trust_score {
            Some(score) => writeln!(&mut out, "Trust score: {:.2}", score).unwrap(),
            None => writeln!(&mut out, "Trust score: unavailable").unwrap(),
        }
        if let Some(threshold) = admission.threshold {
            writeln!(&mut out, "Threshold: {:.2}", threshold.value()).unwrap();
        }
        if !admission.allowlist.is_empty() {
            writeln!(&mut out, "Allowlist: {}", admission.allowlist.join(",")).unwrap();
        }
        writeln!(
            &mut out,
            "Admission: {}",
            relay_admission_label(relay_admission)
        )
        .unwrap();
        writeln!(
            &mut out,
            "Local known events: {}",
            self.app_runtime.store.event_count()
        )
        .unwrap();
        writeln!(&mut out, "Missing locally: {}", missing_event_ids.len()).unwrap();
        for event_id in &missing_event_ids {
            writeln!(&mut out, "  - {}", event_id).unwrap();
        }
        out
    }

    pub(super) fn render_sync_file_preview_blocked(
        &self,
        file_path: &str,
        batch: &PortableSyncBatch,
        admission: &SyncAdmissionOptions,
        trust_score: Option<f32>,
        reason: &str,
    ) -> String {
        let message_count = batch
            .events
            .iter()
            .filter(|event| matches!(event.body, EventBody::MessageSent(_)))
            .count();
        let content_count = batch
            .events
            .iter()
            .filter(|event| matches!(event.body, EventBody::ContentPublished(_)))
            .count();
        let mut out = String::new();
        writeln!(&mut out, "Sync File Preview").unwrap();
        writeln!(&mut out, "-----------------").unwrap();
        writeln!(&mut out, "File: {}", file_path).unwrap();
        writeln!(&mut out, "Source peer: {}", batch.source_peer_id).unwrap();
        writeln!(&mut out, "Profile: {}", batch.profile.as_str()).unwrap();
        writeln!(&mut out, "Message events in batch: {}", message_count).unwrap();
        writeln!(&mut out, "Content events in batch: {}", content_count).unwrap();
        writeln!(&mut out, "Mode: {}", admission.mode.as_str()).unwrap();
        writeln!(
            &mut out,
            "Source persona: {}",
            admission.source_persona.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        match trust_score {
            Some(score) => writeln!(&mut out, "Trust score: {:.2}", score).unwrap(),
            None => writeln!(&mut out, "Trust score: unavailable").unwrap(),
        }
        if let Some(threshold) = admission.threshold {
            writeln!(&mut out, "Threshold: {:.2}", threshold.value()).unwrap();
        }
        if !admission.allowlist.is_empty() {
            writeln!(&mut out, "Allowlist: {}", admission.allowlist.join(",")).unwrap();
        }
        writeln!(&mut out, "Admission: reject").unwrap();
        writeln!(&mut out, "Reason: {}", reason).unwrap();
        out
    }

    pub(super) fn handle_sync_relay_check(&mut self, tokens: &[&str]) -> String {
        let mut mode = None;
        let mut persona = None;
        let mut threshold = None;
        let mut allow = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--mode" if i + 1 < tokens.len() => {
                    mode = RelayMode::parse(tokens[i + 1]);
                    i += 2;
                    continue;
                }
                "--persona" if i + 1 < tokens.len() => {
                    persona = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                "--threshold" if i + 1 < tokens.len() => {
                    threshold = tokens[i + 1].parse::<f32>().ok();
                    i += 2;
                    continue;
                }
                "--allow" if i + 1 < tokens.len() => {
                    allow = Some(tokens[i + 1].to_string());
                    i += 2;
                    continue;
                }
                _ => i += 1,
            }
        }

        let Some(mode) = mode else {
            return "Usage: sync relay-check --mode <mode> --persona <persona> [--threshold <value>] [--allow persona-a,persona-b]\n".to_string();
        };
        let Some(persona_id) = persona else {
            return "Usage: sync relay-check --mode <mode> --persona <persona> [--threshold <value>] [--allow persona-a,persona-b]\n".to_string();
        };

        let threshold = match threshold {
            Some(value) => match TrustThreshold::new(value) {
                Ok(value) => Some(value),
                Err(err) => return format!("Invalid threshold: {}\n", err),
            },
            None => None,
        };
        let allowlist: Vec<String> = allow
            .as_deref()
            .map(|value| {
                value
                    .split(',')
                    .filter(|entry| !entry.trim().is_empty())
                    .map(|entry| entry.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let trust_score = derive_score(&self.trust_attestations, &persona_id, "professional")
            .map(|statement| statement.normalized_score);
        let admission =
            check_relay_admission(mode, &persona_id, trust_score, threshold, &allowlist);

        let mut out = String::new();
        writeln!(&mut out, "Relay Check").unwrap();
        writeln!(&mut out, "-----------").unwrap();
        writeln!(&mut out, "Mode: {}", mode.as_str()).unwrap();
        writeln!(&mut out, "Persona: {}", persona_id).unwrap();
        if let Some(score) = trust_score {
            writeln!(&mut out, "Trust score: {:.2}", score).unwrap();
        } else {
            writeln!(&mut out, "Trust score: unavailable").unwrap();
        }
        if let Some(value) = threshold {
            writeln!(&mut out, "Threshold: {:.2}", value.value()).unwrap();
        }
        if !allowlist.is_empty() {
            writeln!(&mut out, "Allowlist: {}", allowlist.join(",")).unwrap();
        }
        writeln!(&mut out, "Admission: {}", relay_admission_label(&admission)).unwrap();
        if let RelayAdmission::Reject { reason } = admission {
            writeln!(&mut out, "Reason: {}", reason).unwrap();
        }
        out
    }

    pub(super) fn render_compare_with(&self, other: &Self, other_state_path: &str) -> String {
        let local_index = self.app_runtime.store.event_id_set();
        let other_index = other.app_runtime.store.event_id_set();
        let local_count = self.app_runtime.store.event_count();
        let other_count = other.app_runtime.store.event_count();
        let shared = local_index
            .keys()
            .filter(|id| other_index.contains_key(id.as_str()))
            .count();

        let mut out = String::new();
        writeln!(&mut out, "Client Compare").unwrap();
        writeln!(&mut out, "--------------").unwrap();
        writeln!(&mut out, "Local state: {}", self.state_location_label()).unwrap();
        writeln!(&mut out, "Local peer: {}", self.current_peer_id()).unwrap();
        writeln!(&mut out, "Other state: {}", other_state_path).unwrap();
        writeln!(&mut out, "Other peer: {}", other.current_peer_id()).unwrap();
        writeln!(&mut out, "Local events: {}", local_count).unwrap();
        writeln!(&mut out, "Other events: {}", other_count).unwrap();
        writeln!(&mut out, "Shared events: {}", shared).unwrap();
        writeln!(&mut out, "Missing locally: {}", other_count - shared).unwrap();
        writeln!(&mut out, "Missing in other: {}", local_count - shared).unwrap();

        self.write_compare_section(
            &mut out,
            "roots",
            self.roots
                .iter()
                .map(|root| (root.id.clone(), root.display_name.clone())),
            other
                .roots
                .iter()
                .map(|root| (root.id.clone(), root.display_name.clone())),
        );
        self.write_compare_section(
            &mut out,
            "personas",
            self.personas
                .iter()
                .map(|persona| (persona.id.clone(), persona.label.clone())),
            other
                .personas
                .iter()
                .map(|persona| (persona.id.clone(), persona.label.clone())),
        );
        self.write_compare_section(
            &mut out,
            "devices",
            self.devices
                .iter()
                .map(|device| (device.device_id.clone(), device.label.clone())),
            other
                .devices
                .iter()
                .map(|device| (device.device_id.clone(), device.label.clone())),
        );
        self.write_compare_section(
            &mut out,
            "messages",
            self.message_compare_entries(),
            other.message_compare_entries(),
        );
        self.write_compare_section(
            &mut out,
            "content",
            self.content_compare_entries(),
            other.content_compare_entries(),
        );

        out
    }

    pub(super) fn render_sync_preview_with(
        &self,
        other: &Self,
        other_state_path: &str,
        profile: SyncProfile,
        admission_context: Option<(&SyncAdmissionOptions, Option<f32>, &RelayAdmission)>,
    ) -> String {
        let peer_id = other.current_peer_id();
        let local_cursor =
            self.app_runtime.store
                .peer_cursor(&peer_id)
                .unwrap_or(core_principals::PeerCursor {
                    peer_id: peer_id.clone(),
                    last_event_id: None,
                });
        let other_event_ids = other.app_runtime.store.event_ids();
        let other_to_local_raw =
            plan_pull_batch(&local_cursor, "other-to-local", &other_event_ids, |id| {
                self.app_runtime.store.has_event(id)
            });
        let relevant_remote_ids =
            relevant_event_ids_for_context(other.app_runtime.store.events(), &self.light_sync_context());
        let other_to_local =
            filter_batch_by_profile(&other_to_local_raw, profile, &relevant_remote_ids);

        let reverse_peer_id = self.current_peer_id();
        let other_cursor =
            other
                .app_runtime.store
                .peer_cursor(&reverse_peer_id)
                .unwrap_or(core_principals::PeerCursor {
                    peer_id: reverse_peer_id.clone(),
                    last_event_id: None,
                });
        let local_event_ids = self.app_runtime.store.event_ids();
        let local_to_other_raw =
            plan_pull_batch(&other_cursor, "local-to-other", &local_event_ids, |id| {
                other.app_runtime.store.has_event(id)
            });
        let relevant_local_ids =
            relevant_event_ids_for_context(self.app_runtime.store.events(), &other.light_sync_context());
        let local_to_other =
            filter_batch_by_profile(&local_to_other_raw, profile, &relevant_local_ids);
        let local_to_other_events = self.app_runtime.store.events_by_ids(&local_to_other.event_ids);
        let local_to_other_message_count = local_to_other_events
            .iter()
            .filter(|event| matches!(event.body, EventBody::MessageSent(_)))
            .count();
        let local_to_other_content_count = local_to_other_events
            .iter()
            .filter(|event| matches!(event.body, EventBody::ContentPublished(_)))
            .count();
        let other_to_local_events = other.app_runtime.store.events_by_ids(&other_to_local.event_ids);
        let other_to_local_message_count = other_to_local_events
            .iter()
            .filter(|event| matches!(event.body, EventBody::MessageSent(_)))
            .count();
        let other_to_local_content_count = other_to_local_events
            .iter()
            .filter(|event| matches!(event.body, EventBody::ContentPublished(_)))
            .count();

        let mut out = String::new();
        writeln!(&mut out, "Sync Preview").unwrap();
        writeln!(&mut out, "------------").unwrap();
        writeln!(&mut out, "Local state: {}", self.state_location_label()).unwrap();
        writeln!(&mut out, "Local peer: {}", self.current_peer_id()).unwrap();
        writeln!(&mut out, "Other state: {}", other_state_path).unwrap();
        writeln!(&mut out, "Other peer: {}", other.current_peer_id()).unwrap();
        writeln!(&mut out, "Profile: {}", profile.as_str()).unwrap();
        if let Some((options, trust_score, admission)) = admission_context {
            writeln!(&mut out, "Mode: {}", options.mode.as_str()).unwrap();
            writeln!(
                &mut out,
                "Source persona: {}",
                options.source_persona.as_deref().unwrap_or("(none)")
            )
            .unwrap();
            match trust_score {
                Some(score) => writeln!(&mut out, "Trust score: {:.2}", score).unwrap(),
                None => writeln!(&mut out, "Trust score: unavailable").unwrap(),
            }
            if let Some(threshold) = options.threshold {
                writeln!(&mut out, "Threshold: {:.2}", threshold.value()).unwrap();
            }
            if !options.allowlist.is_empty() {
                writeln!(&mut out, "Allowlist: {}", options.allowlist.join(",")).unwrap();
            }
            writeln!(&mut out, "Admission: {}", relay_admission_label(admission)).unwrap();
            if let RelayAdmission::Reject { reason } = admission {
                writeln!(&mut out, "Reason: {}", reason).unwrap();
            }
        }
        writeln!(
            &mut out,
            "Local cursor for peer: {}",
            local_cursor.last_event_id.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        writeln!(
            &mut out,
            "Other cursor for peer: {}",
            other_cursor.last_event_id.as_deref().unwrap_or("(none)")
        )
        .unwrap();
        writeln!(
            &mut out,
            "Local -> other missing events: {}",
            local_to_other.event_ids.len()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Local -> other message events: {}",
            local_to_other_message_count
        )
        .unwrap();
        writeln!(
            &mut out,
            "Local -> other content events: {}",
            local_to_other_content_count
        )
        .unwrap();
        for event_id in &local_to_other.event_ids {
            writeln!(&mut out, "  - {}", event_id).unwrap();
        }
        writeln!(
            &mut out,
            "Other -> local missing events: {}",
            other_to_local.event_ids.len()
        )
        .unwrap();
        writeln!(
            &mut out,
            "Other -> local message events: {}",
            other_to_local_message_count
        )
        .unwrap();
        writeln!(
            &mut out,
            "Other -> local content events: {}",
            other_to_local_content_count
        )
        .unwrap();
        for event_id in &other_to_local.event_ids {
            writeln!(&mut out, "  - {}", event_id).unwrap();
        }

        out
    }
}
