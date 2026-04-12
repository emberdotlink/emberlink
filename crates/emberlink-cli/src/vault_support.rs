use crate::activity_support::format_payload;

use super::*;

fn mime_from_filename(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" | "text" | "log" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "doc" | "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" | "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn claim_schema_version(schema_id: &str) -> String {
    schema_id
        .rsplit(':')
        .next()
        .filter(|segment| !segment.trim().is_empty())
        .unwrap_or("1.0")
        .to_string()
}

fn claim_app_namespace(schema_id: &str) -> String {
    schema_id
        .split(':')
        .next()
        .filter(|segment| !segment.trim().is_empty())
        .unwrap_or("emberlink")
        .to_string()
}

impl DemoApp {
    pub(crate) fn handle_claim_list(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: claim list --persona <persona-id-or-label>\n";
        let mut persona_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let persona = match self.require_persona(&persona_ref) {
            Ok(persona) => persona,
            Err(err) => return format!("Failed to resolve claim persona: {}\n", err),
        };
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona.id.clone(),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => {
                return format!(
                    "Claims\n------\nPersona: {}\nClaims: none\n",
                    namespace.owner_id
                );
            }
            Err(err) => return format!("Failed to load claim catalog: {}\n", err),
        };

        let mut out = String::new();
        writeln!(&mut out, "Claims").unwrap();
        writeln!(&mut out, "------").unwrap();
        writeln!(&mut out, "Persona: {}", namespace.owner_id).unwrap();
        let claims = catalog
            .objects
            .iter()
            .filter(|object| {
                object.class == core_types::VaultObjectClass::PersonaCredential && !object.deleted
            })
            .collect::<Vec<_>>();
        if claims.is_empty() {
            writeln!(&mut out, "Claims: none").unwrap();
            return out;
        }
        writeln!(&mut out, "Claims: {}", claims.len()).unwrap();
        for object in claims {
            if let Some(revision) = catalog
                .revisions
                .iter()
                .find(|revision| revision.id == object.latest_revision_id)
            {
                let claim = revision.claim.as_ref();
                writeln!(
                    &mut out,
                    "  - {}\ttype={}\tschema={}\tissuer={}\tsubject={}",
                    object.id,
                    claim
                        .map(|claim| claim.claim_type.as_str())
                        .unwrap_or("unknown"),
                    claim
                        .map(|claim| claim.claim_schema.as_str())
                        .unwrap_or("(missing)"),
                    claim
                        .map(|claim| claim.issuer_persona_id.as_str())
                        .unwrap_or("(missing)"),
                    claim
                        .map(|claim| claim.subject_persona_id.as_str())
                        .unwrap_or("(missing)")
                )
                .unwrap();
            }
        }
        out
    }

    pub(crate) fn handle_claim_show(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: claim show --persona <persona-id-or-label> --object <object-id>\n";
        let mut persona_ref = None;
        let mut object_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let persona = match self.require_persona(&persona_ref) {
            Ok(persona) => persona,
            Err(err) => return format!("Failed to resolve claim persona: {}\n", err),
        };
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona.id.clone(),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => return "Claim unavailable: persona has no claim catalog\n".to_string(),
            Err(err) => return format!("Failed to load claim catalog: {}\n", err),
        };
        let Some(object) = catalog.objects.iter().find(|object| object.id == object_id) else {
            return format!("Claim unavailable: unknown object: {object_id}\n");
        };
        if object.class != core_types::VaultObjectClass::PersonaCredential {
            return format!("Claim unavailable: object is not a persona credential: {object_id}\n");
        }
        if object.deleted {
            return format!("Claim unavailable: object deleted: {object_id}\n");
        }
        let Some(revision) = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == object.latest_revision_id)
        else {
            return format!("Claim unavailable: latest revision missing for object: {object_id}\n");
        };
        let Some(claim) = revision.claim.as_ref() else {
            return format!(
                "Claim unavailable: revision missing claim metadata: {}\n",
                revision.id
            );
        };
        let payload = match self
            .app_runtime.store
            .local_manifest_payload_bytes(&revision.manifest_id)
        {
            Ok(payload) => payload,
            Err(err) => return format!("Failed to load claim payload: {}\n", err),
        };
        format!(
            "Claim\n-----\nPersona: {}\nObject: {}\nRevision: {}\nType: {}\nIssuer: {}\nSubject: {}\nSchema: {}\nIssued At: {}\nExpires At: {}\nExternal Issuer: {}\nExternal Credential Id: {}\nPayload:\n{}\n",
            namespace.owner_id,
            object.id,
            revision.id,
            claim.claim_type.as_str(),
            claim.issuer_persona_id,
            claim.subject_persona_id,
            claim.claim_schema,
            claim.issued_at,
            claim
                .expires_at
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            claim.external_issuer.as_deref().unwrap_or("none"),
            claim.external_credential_id.as_deref().unwrap_or("none"),
            String::from_utf8_lossy(&payload)
        )
    }

    pub(crate) fn handle_claim_store(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: claim store --persona <persona-id-or-label> --object <object-id> --schema <schema-id> [--type self-asserted|peer-attested|service-issued|derived] [--issuer <persona-id-or-label>] [--subject <persona-id-or-label-or-id>] [--expires-at <epoch>] [--external-issuer <id>] [--external-credential-id <id>] (--json <compact-json> | --json-file <path>)\n";
        let mut persona_ref = None;
        let mut object_id = None;
        let mut schema_id = None;
        let mut claim_type = Some(core_types::ClaimType::SelfAsserted);
        let mut issuer_ref = None;
        let mut subject_ref = None;
        let mut expires_at = None;
        let mut external_issuer = None;
        let mut external_credential_id = None;
        let mut payload_json = None;
        let mut payload_json_file = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--schema" if i + 1 < tokens.len() => {
                    schema_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--type" if i + 1 < tokens.len() => {
                    claim_type = core_types::ClaimType::parse(tokens[i + 1]);
                    i += 2;
                }
                "--issuer" if i + 1 < tokens.len() => {
                    issuer_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--subject" if i + 1 < tokens.len() => {
                    subject_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--expires-at" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_at = Some(value),
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                "--external-issuer" if i + 1 < tokens.len() => {
                    external_issuer = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--external-credential-id" if i + 1 < tokens.len() => {
                    external_credential_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--json" if i + 1 < tokens.len() => {
                    payload_json = Some(tokens[i + 1].as_bytes().to_vec());
                    i += 2;
                }
                "--json-file" if i + 1 < tokens.len() => {
                    payload_json_file = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let Some(schema_id) = schema_id else {
            return usage.to_string();
        };
        let Some(claim_type) = claim_type else {
            return usage.to_string();
        };
        if payload_json.is_some() == payload_json_file.is_some() {
            return usage.to_string();
        }

        let persona = match self.require_persona(&persona_ref) {
            Ok(persona) => persona,
            Err(err) => return format!("Failed to resolve claim persona: {}\n", err),
        };
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona.id.clone(),
        };
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to store claim: no active authorized devices for persona\n"
                    .to_string();
            }
            Err(err) => return format!("Failed to resolve claim recipients: {}\n", err),
        };
        let created_by_device_id = recipients[0].device_id.clone();
        let payload = match payload_json {
            Some(payload) => payload,
            None => match std::fs::read(payload_json_file.unwrap()) {
                Ok(payload) => payload,
                Err(err) => return format!("Failed to read claim json file: {}\n", err),
            },
        };
        let revision_id = generate_random_identifier("claim-rev");
        let payload_manifest_id = generate_random_identifier("claim-manifest");
        let catalog_manifest_id = generate_random_identifier("vault-catalog");
        let created_at = now_epoch_secs();
        let issuer_persona_id = match issuer_ref {
            Some(ref issuer_ref) => match self.resolve_persona(issuer_ref) {
                Some(persona) => persona.id.clone(),
                None => return format!("Failed to resolve claim issuer persona: {issuer_ref}\n"),
            },
            None => namespace.owner_id.clone(),
        };
        let subject_persona_id = match subject_ref {
            Some(ref subject_ref) => self
                .resolve_persona(subject_ref)
                .map(|persona| persona.id.clone())
                .unwrap_or_else(|| subject_ref.clone()),
            None => namespace.owner_id.clone(),
        };
        let claim = core_types::ClaimMeta {
            claim_type,
            issuer_persona_id,
            subject_persona_id,
            claim_schema: schema_id.clone(),
            issued_at: created_at,
            expires_at,
            external_issuer,
            external_credential_id,
        };

        match self.app_runtime.store.upsert_local_persona_credential(
            &namespace,
            &object_id,
            &revision_id,
            &payload_manifest_id,
            &catalog_manifest_id,
            created_at,
            &created_by_device_id,
            core_types::StructuredRecordMeta {
                schema_id: schema_id.clone(),
                schema_version: claim_schema_version(&schema_id),
                encoding: core_types::StructuredEncoding::Json,
                app_namespace: claim_app_namespace(&schema_id),
            },
            claim,
            &payload,
            core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_types::RetentionPolicy::KeepLatest,
            recipients,
        ) {
            Ok(revision) => {
                if let Err(err) = self.persist_to_disk() {
                    return format!("Stored claim but failed to persist shell state: {}\n", err);
                }
                format!(
                    "stored claim\t{}\t{}\t{}\t{}\n",
                    object_id,
                    revision.id,
                    claim_type.as_str(),
                    schema_id
                )
            }
            Err(err) => format!("Failed to store claim: {}\n", err),
        }
    }

    pub(crate) fn handle_claim_disclose(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: claim disclose --persona <persona-id-or-label> --object <object-id> --to <persona-id-or-label> --field <path> [--field <path> ...] [--expires-in <seconds>]\n";
        let mut persona_ref = None;
        let mut object_id = None;
        let mut recipient_ref = None;
        let mut field_paths = Vec::new();
        let mut expires_in = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--to" if i + 1 < tokens.len() => {
                    recipient_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--field" if i + 1 < tokens.len() => {
                    field_paths.push(tokens[i + 1].to_string());
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in = Some(value),
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let Some(recipient_ref) = recipient_ref else {
            return usage.to_string();
        };
        if field_paths.is_empty() {
            return usage.to_string();
        }

        let persona = match self.require_persona(&persona_ref) {
            Ok(persona) => persona,
            Err(err) => return format!("Failed to resolve claim persona: {}\n", err),
        };
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona.id.clone(),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => {
                return "Failed to disclose claim: persona has no claim catalog\n".to_string();
            }
            Err(err) => return format!("Failed to load claim catalog: {}\n", err),
        };
        let Some(object) = catalog.objects.iter().find(|object| object.id == object_id) else {
            return format!("Failed to disclose claim: unknown object: {object_id}\n");
        };
        if object.class != core_types::VaultObjectClass::PersonaCredential {
            return format!(
                "Failed to disclose claim: object is not a persona credential: {object_id}\n"
            );
        }
        let Some(revision) = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == object.latest_revision_id)
        else {
            return format!(
                "Failed to disclose claim: latest revision missing for object: {object_id}\n"
            );
        };
        let Some(structured_record) = revision.structured_record.as_ref() else {
            return format!(
                "Failed to disclose claim: structured metadata missing for revision: {}\n",
                revision.id
            );
        };

        let template_id = generate_random_identifier("claim-template");
        let namespace_arg = format!("persona:{}", namespace.owner_id);
        let mut template_args = vec![
            "--id".to_string(),
            template_id.clone(),
            "--object".to_string(),
            object_id.clone(),
            "--schema".to_string(),
            structured_record.schema_id.clone(),
            "--audience".to_string(),
            "peer".to_string(),
            "--namespace".to_string(),
            namespace_arg.clone(),
        ];
        for field_path in &field_paths {
            template_args.push("--field".to_string());
            template_args.push(field_path.clone());
        }
        if let Some(expires_in) = expires_in {
            template_args.push("--expires-in".to_string());
            template_args.push(expires_in.to_string());
        }
        let template_refs = template_args.iter().map(String::as_str).collect::<Vec<_>>();
        let template_result = self.handle_vault_template_add(&template_refs);
        if !template_result.contains("added template") {
            return template_result;
        }

        let mut disclose_args = vec![
            "--from".to_string(),
            namespace.owner_id.clone(),
            "--to".to_string(),
            recipient_ref,
            "--template".to_string(),
            template_id,
            "--namespace".to_string(),
            namespace_arg,
        ];
        if let Some(expires_in) = expires_in {
            disclose_args.push("--expires-in".to_string());
            disclose_args.push(expires_in.to_string());
        }
        let disclose_refs = disclose_args.iter().map(String::as_str).collect::<Vec<_>>();
        let disclose_result = self.handle_disclose(&disclose_refs);
        let Some(message_id) = disclose_result.lines().find_map(|line| {
            if !line.starts_with("sent disclosure artifact\t") {
                return None;
            }
            line.split('\t')
                .nth(3)
                .filter(|segment| segment.starts_with("message-"))
                .map(str::to_string)
        }) else {
            return disclose_result;
        };

        let mut out = disclose_result;
        writeln!(&mut out, "sent disclosure\t{}", message_id).unwrap();
        out
    }

    pub(crate) fn handle_vault_show_record(&mut self, tokens: &[&str]) -> String {
        let usage =
            "Usage: vault show-record --object <object-id> [--namespace root:<id>|persona:<id>]\n";
        let mut namespace_arg = None;
        let mut object_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => return "Vault record unavailable: namespace is empty\n".to_string(),
            Err(err) => return format!("Failed to load vault catalog: {}\n", err),
        };
        let Some(object) = catalog.objects.iter().find(|object| object.id == object_id) else {
            return format!("Vault record unavailable: unknown object: {object_id}\n");
        };
        if object.deleted {
            return format!("Vault record unavailable: object deleted: {object_id}\n");
        }
        let Some(revision) = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == object.latest_revision_id)
        else {
            return format!(
                "Vault record unavailable: latest revision missing for object: {}\n",
                object.id
            );
        };
        match self
            .app_runtime.store
            .local_manifest_payload_bytes(&revision.manifest_id)
        {
            Ok(payload) => format!(
                "Vault Record\n------------\nNamespace: {}:{}\nObject: {}\nRevision: {}\nManifest: {}\nPayload:\n{}\n",
                namespace.owner_kind.as_str(),
                namespace.owner_id,
                object.id,
                revision.id,
                revision.manifest_id,
                String::from_utf8_lossy(&payload)
            ),
            Err(err) => format!("Failed to load vault record payload: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_delete(&mut self, tokens: &[&str]) -> String {
        let usage =
            "Usage: vault delete --object <object-id> [--namespace root:<id>|persona:<id>]\n";
        let mut namespace_arg = None;
        let mut object_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to delete vault record: no active authorized devices for namespace\n"
                    .to_string()
            }
            Err(err) => return format!("Failed to resolve vault recipients: {}\n", err),
        };
        let catalog_manifest_id = generate_random_identifier("vault-catalog");

        match self.app_runtime.store.tombstone_local_vault_object(
            &namespace,
            &object_id,
            &catalog_manifest_id,
            now_epoch_secs(),
            recipients,
        ) {
            Ok(()) => {
                if let Err(err) = self.persist_to_disk() {
                    return format!(
                        "Deleted vault record but failed to persist shell state: {}\n",
                        err
                    );
                }
                format!("deleted record\t{}\n", object_id)
            }
            Err(err) => format!("Failed to delete vault record: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_show_artifact(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault show-artifact --artifact <artifact-id>\n";
        let mut artifact_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--artifact" if i + 1 < tokens.len() => {
                    artifact_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(artifact_id) = artifact_id else {
            return usage.to_string();
        };
        let record = match self.app_runtime.store.local_presentation_artifact(&artifact_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return format!("Vault artifact unavailable: unknown artifact: {artifact_id}\n");
            }
            Err(err) => return format!("Failed to load vault artifacts: {}\n", err),
        };
        match self
            .app_runtime.store
            .local_manifest_payload_bytes(&record.artifact.manifest_id)
        {
            Ok(payload) => format!(
                "Vault Artifact\n--------------\nArtifact: {}\nNamespace: {}\t{}\nTemplate: {}\nRecipient: {}\t{}\nManifest: {}\nPayload:\n{}\n",
                record.artifact.id,
                record.namespace.owner_kind.as_str(),
                record.namespace.owner_id,
                record.template_id,
                record.artifact.recipient_kind.as_str(),
                record.artifact.recipient_id,
                record.artifact.manifest_id,
                format_payload(&payload)
            ),
            Err(err) => format!("Failed to load vault artifact payload: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_write_record(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault write-record --object <object-id> --schema <schema-id> --app <app-namespace> [--version <schema-version>] [--namespace root:<id>|persona:<id>] (--json <compact-json> | --json-file <path>)\n";
        let mut namespace_arg = None;
        let mut object_id = None;
        let mut schema_id = None;
        let mut schema_version = Some("v1".to_string());
        let mut app_namespace = None;
        let mut payload_json = None;
        let mut payload_json_file = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--schema" if i + 1 < tokens.len() => {
                    schema_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--version" if i + 1 < tokens.len() => {
                    schema_version = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--app" if i + 1 < tokens.len() => {
                    app_namespace = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--json" if i + 1 < tokens.len() => {
                    payload_json = Some(tokens[i + 1].as_bytes().to_vec());
                    i += 2;
                }
                "--json-file" if i + 1 < tokens.len() => {
                    payload_json_file = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let Some(schema_id) = schema_id else {
            return usage.to_string();
        };
        let Some(schema_version) = schema_version else {
            return usage.to_string();
        };
        let Some(app_namespace) = app_namespace else {
            return usage.to_string();
        };
        if payload_json.is_some() == payload_json_file.is_some() {
            return usage.to_string();
        }

        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to write vault record: no active authorized devices for namespace\n"
                    .to_string();
            }
            Err(err) => return format!("Failed to resolve vault recipients: {}\n", err),
        };
        let catalog_manifest_id = self
            .app_runtime.store
            .plan_local_vault_gc(&namespace)
            .ok()
            .flatten()
            .map(|plan| plan.catalog_manifest_id)
            .unwrap_or_else(|| {
                format!(
                    "vault-catalog-{}-{}",
                    namespace.owner_kind.as_str(),
                    namespace.owner_id
                )
            });
        let created_by_device_id = recipients[0].device_id.clone();
        let payload = match payload_json {
            Some(payload) => payload,
            None => match std::fs::read(payload_json_file.unwrap()) {
                Ok(payload) => payload,
                Err(err) => {
                    return format!("Failed to read vault json file: {}\n", err);
                }
            },
        };
        let revision_id = generate_random_identifier("vault-rev");
        let payload_manifest_id = generate_random_identifier("vault-manifest");
        let created_at = now_epoch_secs();

        match self.app_runtime.store.upsert_local_structured_record(
            &namespace,
            &object_id,
            &revision_id,
            &payload_manifest_id,
            &catalog_manifest_id,
            created_at,
            &created_by_device_id,
            core_types::StructuredRecordMeta {
                schema_id: schema_id.clone(),
                schema_version: schema_version.clone(),
                encoding: core_types::StructuredEncoding::Json,
                app_namespace: app_namespace.clone(),
            },
            &payload,
            core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_types::RetentionPolicy::KeepLatest,
            recipients,
        ) {
            Ok(revision) => {
                if let Err(err) = self.persist_to_disk() {
                    return format!(
                        "Wrote vault record but failed to persist shell state: {}\n",
                        err
                    );
                }
                format!(
                    "wrote record\t{}\t{}\t{}\t{}\n",
                    object_id, revision.id, schema_id, payload_manifest_id
                )
            }
            Err(err) => format!("Failed to write vault record: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_show_received(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault show-received --artifact <artifact-id>\n";
        let mut artifact_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--artifact" if i + 1 < tokens.len() => {
                    artifact_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(artifact_id) = artifact_id else {
            return usage.to_string();
        };

        match self
            .app_runtime.store
            .local_received_presentation_artifact(&artifact_id)
        {
            Ok(Some(record)) => {
                let verification = self.app_runtime.store.verify_disclosure_issuer(&record.envelope);
                format!(
                    "Received Disclosure\n-------------------\nArtifact: {}\nStatus: {}\nVerification: {}\nIssuer: {}\nIssuer key: {}\nRecipient: {}\t{}\nSchema: {}\nManifest: {}\nReceipts: {}\nFirst received: {}\nLast received: {}\nFirst source: {}\t{}\nLast source: {}\t{}\nPayload:\n{}\n",
                    record.envelope.artifact.id,
                    self.presentation_artifact_status_label(&record.envelope.artifact),
                    verification.as_str(),
                    record.envelope.issuer_persona_id,
                    record.envelope.issuer_key_id,
                    record.envelope.artifact.recipient_kind.as_str(),
                    record.envelope.artifact.recipient_id,
                    record.envelope.artifact.schema_id,
                    record.envelope.artifact.manifest_id,
                    record.receipt_count,
                    record.first_received_at,
                    record.last_received_at,
                    record.first_source_kind.as_str(),
                    record.first_source_ref,
                    record.last_source_kind.as_str(),
                    record.last_source_ref,
                    format_payload(&record.envelope.payload_bytes),
                )
            }
            Ok(None) => format!("Unknown received disclosure artifact: {artifact_id}\n"),
            Err(err) => format!("Failed to load received disclosure artifact: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_template_add(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault template add --id <template-id> --object <object-id> --schema <schema-id> --audience peer|service --namespace root:<id>|persona:<id> --field <path> [--field <path> ...] [--expires-in <seconds>]\n";
        let mut template_id = None;
        let mut object_id = None;
        let mut schema_id = None;
        let mut audience_kind = None;
        let mut namespace_arg = None;
        let mut field_paths = Vec::new();
        let mut expires_after_secs = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--id" if i + 1 < tokens.len() => {
                    template_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--schema" if i + 1 < tokens.len() => {
                    schema_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--audience" if i + 1 < tokens.len() => {
                    audience_kind = core_types::PresentationAudienceKind::parse(tokens[i + 1]);
                    i += 2;
                }
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--field" if i + 1 < tokens.len() => {
                    field_paths.push(tokens[i + 1].to_string());
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_after_secs = Some(value),
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(template_id) = template_id else {
            return usage.to_string();
        };
        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let Some(schema_id) = schema_id else {
            return usage.to_string();
        };
        let Some(audience_kind) = audience_kind else {
            return usage.to_string();
        };
        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        if field_paths.is_empty() {
            return usage.to_string();
        }

        match core_storage::create_presentation_template(
            &template_id,
            namespace,
            &object_id,
            &schema_id,
            audience_kind,
            field_paths,
            expires_after_secs,
        ) {
            Ok(template) => match self
                .app_runtime.store
                .upsert_local_presentation_template(&template)
            {
                Ok(()) => {
                    if let Err(err) = self.persist_to_disk() {
                        return format!(
                            "Added vault template but failed to persist shell state: {}\n",
                            err
                        );
                    }
                    format!(
                        "added template\t{}\t{}\t{}\n",
                        template.id,
                        template.source_object_id,
                        template.audience_kind.as_str()
                    )
                }
                Err(err) => format!("Failed to store vault template: {}\n", err),
            },
            Err(err) => format!("Failed to add vault template: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_issue(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault issue --template <template-id> --recipient <recipient-id> [--namespace root:<id>|persona:<id>] [--expires-in <seconds>]\n";
        let mut template_id = None;
        let mut recipient_id = None;
        let mut namespace_arg = None;
        let mut expires_in = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--template" if i + 1 < tokens.len() => {
                    template_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--recipient" if i + 1 < tokens.len() => {
                    recipient_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in = Some(value),
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(template_id) = template_id else {
            return usage.to_string();
        };
        let Some(recipient_id) = recipient_id else {
            return usage.to_string();
        };

        let template = match self.app_runtime.store.local_presentation_template(&template_id) {
            Ok(Some(template)) => template,
            Ok(None) => {
                return format!(
                    "Failed to issue vault artifact: unknown template: {template_id}\n"
                );
            }
            Err(err) => return format!("Failed to load vault template: {}\n", err),
        };
        let namespace = match namespace_arg {
            Some(ref raw) => match self.parse_vault_namespace_arg(Some(raw.as_str())) {
                Ok(namespace) => {
                    if namespace != template.namespace {
                        return format!(
                            "Failed to issue vault artifact: template {} belongs to {}:{}\n",
                            template.id,
                            template.namespace.owner_kind.as_str(),
                            template.namespace.owner_id
                        );
                    }
                    namespace
                }
                Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
            },
            None => template.namespace.clone(),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => {
                return format!(
                    "Failed to issue vault artifact: vault namespace is empty: {}:{}\n",
                    namespace.owner_kind.as_str(),
                    namespace.owner_id
                );
            }
            Err(err) => return format!("Failed to load vault catalog: {}\n", err),
        };
        let Some(object) = catalog
            .objects
            .iter()
            .find(|object| object.id == template.source_object_id && !object.deleted)
        else {
            return format!(
                "Failed to issue vault artifact: template source object not present in namespace: {}\n",
                template.source_object_id
            );
        };
        let issued_at = now_epoch_secs();
        let expires_at = expires_in
            .or(template.expires_after_secs)
            .map(|seconds| issued_at.saturating_add(seconds.max(1)));
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to issue vault artifact: no active authorized devices for namespace\n"
                    .to_string()
            }
            Err(err) => return format!("Failed to resolve vault recipients: {}\n", err),
        };
        let artifact_id = generate_random_identifier("artifact");
        let artifact_manifest_id = generate_random_identifier("manifest-artifact");

        match self.app_runtime.store.issue_local_presentation_artifact(
            &namespace,
            &object.latest_revision_id,
            &template_id,
            &artifact_id,
            &artifact_manifest_id,
            &recipient_id,
            issued_at,
            expires_at,
            recipients,
            None,
        ) {
            Ok(record) => {
                if let Err(err) = self.persist_to_disk() {
                    return format!(
                        "Issued vault artifact but failed to persist shell state: {}\n",
                        err
                    );
                }
                format!(
                    "issued artifact\t{}\t{}\t{}\t{}\n",
                    record.artifact.id,
                    template_id,
                    record.artifact.recipient_id,
                    record.artifact.manifest_id
                )
            }
            Err(err) => format!("Failed to issue vault artifact: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_send_artifact(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault send-artifact --artifact <artifact-id> --from <persona> --to <persona-id-or-label>\n";
        let mut artifact_id = None;
        let mut sender_ref = None;
        let mut recipient_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--artifact" if i + 1 < tokens.len() => {
                    artifact_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--from" if i + 1 < tokens.len() => {
                    sender_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--to" if i + 1 < tokens.len() => {
                    recipient_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(artifact_id) = artifact_id else {
            return usage.to_string();
        };
        let Some(sender_ref) = sender_ref else {
            return usage.to_string();
        };
        let Some(recipient_ref) = recipient_ref else {
            return usage.to_string();
        };

        let target_persona_id = match self.resolve_persona(&recipient_ref) {
            Some(persona) => persona.id.clone(),
            None => {
                return format!(
                    "Failed to send disclosure artifact: unknown persona: {}\n",
                    recipient_ref
                );
            }
        };
        let record = match self.app_runtime.store.local_presentation_artifact(&artifact_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return format!(
                    "Failed to send disclosure artifact: unknown artifact: {}\n",
                    artifact_id
                );
            }
            Err(err) => return format!("Failed to load disclosure artifacts: {}\n", err),
        };
        if record.artifact.recipient_kind != core_types::PresentationAudienceKind::Peer {
            return format!(
                "Failed to send disclosure artifact: artifact {} is not peer-targeted\n",
                record.artifact.id
            );
        }
        if record.artifact.recipient_id != target_persona_id {
            return format!(
                "Failed to send disclosure artifact: artifact recipient {} does not match target {}\n",
                record.artifact.recipient_id, target_persona_id
            );
        }
        let ciphertext_hex =
            match self.disclosure_artifact_message_ciphertext(&record.artifact.id, &sender_ref) {
                Ok(ciphertext_hex) => ciphertext_hex,
                Err(err) => {
                    return format!(
                        "Failed to build disclosure artifact message payload: {}\n",
                        err
                    );
                }
            };
        match self.send_message_command(&sender_ref, &target_persona_id, &ciphertext_hex) {
            Ok(message) => format!(
                "sent disclosure artifact\t{}\t{}",
                record.artifact.id, message
            ),
            Err(err) => format!("Failed to send disclosure artifact: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_export_artifact(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault export-artifact --artifact <artifact-id> --out <path> [--by <persona-id-or-label>]\n";
        let mut artifact_id = None;
        let mut out_path = None;
        let mut issuer_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--artifact" if i + 1 < tokens.len() => {
                    artifact_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--by" if i + 1 < tokens.len() => {
                    issuer_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(artifact_id) = artifact_id else {
            return usage.to_string();
        };
        let Some(out_path) = out_path else {
            return usage.to_string();
        };

        let record = match self.app_runtime.store.local_presentation_artifact(&artifact_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return format!(
                    "Failed to export disclosure artifact: unknown artifact: {}\n",
                    artifact_id
                );
            }
            Err(err) => return format!("Failed to load disclosure artifacts: {}\n", err),
        };
        let issuer_ref = match issuer_ref {
            Some(issuer_ref) => issuer_ref,
            None => match self
                .app_runtime.store
                .default_local_presentation_artifact_issuer_persona_id(&record.artifact.id)
            {
                Ok(Some(persona_id)) => persona_id,
                Ok(None) => {
                    return format!(
                        "Failed to export disclosure artifact: no default issuer for artifact {}; use --by <persona>\n",
                        record.artifact.id
                    );
                }
                Err(err) => return format!("Failed to export disclosure artifact: {}\n", err),
            },
        };
        let envelope =
            match self.presentation_artifact_envelope_bytes(&record.artifact.id, &issuer_ref) {
                Ok(envelope) => envelope,
                Err(err) => {
                    return format!(
                        "Failed to build disclosure artifact export payload: {}\n",
                        err
                    );
                }
            };
        match std::fs::write(&out_path, envelope) {
            Ok(()) => format!(
                "exported disclosure artifact\t{}\t{}\n",
                record.artifact.id, out_path
            ),
            Err(err) => format!("Failed to export disclosure artifact: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_inspect_export(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault inspect-export --file <path>\n";
        let mut file_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(file_path) = file_path else {
            return usage.to_string();
        };

        let envelope = match std::fs::read(&file_path) {
            Ok(bytes) => match core_storage::decode_presentation_artifact_envelope(&bytes) {
                Ok(envelope) => envelope,
                Err(err) => {
                    return format!("Failed to inspect disclosure artifact export: {}\n", err);
                }
            },
            Err(err) => return format!("Failed to read disclosure artifact export: {}\n", err),
        };
        format!(
            "Disclosure Export\n-----------------\nFile: {}\nArtifact: {}\nStatus: {}\nIssuer: {}\nIssuer key: {}\nSignature: valid\nRecipient: {}\t{}\nSchema: {}\nManifest: {}\nPayload:\n{}\n",
            file_path,
            envelope.artifact.id,
            self.presentation_artifact_status_label(&envelope.artifact),
            envelope.issuer_persona_id,
            envelope.issuer_key_id,
            envelope.artifact.recipient_kind.as_str(),
            envelope.artifact.recipient_id,
            envelope.artifact.schema_id,
            envelope.artifact.manifest_id,
            String::from_utf8_lossy(&envelope.payload_bytes)
        )
    }

    pub(crate) fn handle_vault_import_artifact(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault import-artifact --file <path>\n";
        let mut file_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(file_path) = file_path else {
            return usage.to_string();
        };

        let envelope = match std::fs::read(&file_path) {
            Ok(bytes) => match core_storage::decode_presentation_artifact_envelope(&bytes) {
                Ok(envelope) => envelope,
                Err(err) => {
                    return format!("Failed to import disclosure artifact export: {}\n", err);
                }
            },
            Err(err) => return format!("Failed to read disclosure artifact export: {}\n", err),
        };
        if let Err(err) = self
            .app_runtime.store
            .validate_received_presentation_artifact(&envelope)
        {
            return format!("Failed to import disclosure artifact export: {}\n", err);
        }
        match self.app_runtime.store.receive_presentation_artifact(
            &envelope,
            core_state::ReceivedDisclosureSourceKind::ExportFile,
            &file_path,
            now_epoch_secs(),
        ) {
            Ok(record) => format!(
                "imported disclosure artifact\t{}\t{}\t{}\n",
                record.envelope.artifact.id,
                record.last_source_kind.as_str(),
                record.last_source_ref
            ),
            Err(err) => format!("Failed to import disclosure artifact export: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_import_message(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault import-message --message <message-id>\n";
        let mut message_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--message" if i + 1 < tokens.len() => {
                    message_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }
        let Some(message_ref) = message_ref else {
            return usage.to_string();
        };

        let Some((message_id, recipient_persona_id, envelope)) =
            self.disclosure_envelope_from_message_ref(&message_ref)
        else {
            return format!("Unknown disclosure message: {message_ref}\n");
        };
        if envelope.artifact.recipient_kind != core_types::PresentationAudienceKind::Peer {
            return "Failed to import disclosure message: disclosure message is not peer-targeted\n"
                .to_string();
        }
        if envelope.artifact.recipient_id != recipient_persona_id {
            return format!(
                "Failed to import disclosure message: artifact recipient {} does not match message recipient {}\n",
                envelope.artifact.recipient_id, recipient_persona_id
            );
        }
        if let Err(err) = self
            .app_runtime.store
            .validate_received_presentation_artifact(&envelope)
        {
            return format!("Failed to import disclosure message: {}\n", err);
        }
        match self.app_runtime.store.receive_presentation_artifact(
            &envelope,
            core_state::ReceivedDisclosureSourceKind::Message,
            &message_id,
            now_epoch_secs(),
        ) {
            Ok(record) => format!(
                "imported disclosure artifact\t{}\t{}\t{}\n",
                record.envelope.artifact.id,
                record.last_source_kind.as_str(),
                record.last_source_ref
            ),
            Err(err) => format!("Failed to import disclosure message: {}\n", err),
        }
    }

    /// Auto-import any disclosure messages that haven't been imported yet.
    /// Returns the number of newly imported disclosures.
    pub(crate) fn auto_import_disclosure_messages(&mut self) -> usize {
        let mut imported = 0;
        let cursor = self.disclosure_import_cursor;
        let new_messages: Vec<_> = self
            .app_runtime.store
            .events_of_type(core_types::EventType::MessageSent)
            .skip(cursor)
            .collect();
        let scanned = new_messages.len();
        let candidates: Vec<_> = new_messages
            .into_iter()
            .filter_map(|event| {
                if let EventBody::MessageSent(body) = &event.body {
                    let bytes = core_types::hex_to_bytes(&body.ciphertext_hex).ok()?;
                    let envelope =
                        core_storage::decode_presentation_artifact_envelope(&bytes).ok()?;
                    if envelope.artifact.recipient_kind
                        != core_types::PresentationAudienceKind::Peer
                    {
                        return None;
                    }
                    if envelope.artifact.recipient_id != body.recipient_persona_id {
                        return None;
                    }
                    Some((body.message_id.clone(), envelope))
                } else {
                    None
                }
            })
            .collect();
        self.disclosure_import_cursor = cursor + scanned;

        for (message_id, envelope) in candidates {
            if self
                .app_runtime.store
                .local_received_presentation_artifact(&envelope.artifact.id)
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            if self
                .app_runtime.store
                .validate_received_presentation_artifact(&envelope)
                .is_err()
            {
                continue;
            }
            if self
                .app_runtime.store
                .receive_presentation_artifact(
                    &envelope,
                    core_state::ReceivedDisclosureSourceKind::Message,
                    &message_id,
                    now_epoch_secs(),
                )
                .is_ok()
            {
                imported += 1;
            }
        }
        imported
    }

    fn disclosure_envelope_from_message_ref(
        &self,
        message_ref: &str,
    ) -> Option<(String, String, core_storage::PresentationArtifactEnvelope)> {
        for event in self
            .app_runtime.store
            .events_of_type_rev(core_types::EventType::MessageSent)
        {
            if let EventBody::MessageSent(body) = &event.body {
                if body.message_id != message_ref && event.event_id != message_ref {
                    continue;
                }
                let ciphertext_bytes = core_types::hex_to_bytes(&body.ciphertext_hex).ok()?;
                let envelope =
                    core_storage::decode_presentation_artifact_envelope(&ciphertext_bytes).ok()?;
                return Some((
                    body.message_id.clone(),
                    body.recipient_persona_id.clone(),
                    envelope,
                ));
            }
        }
        None
    }

    pub(crate) fn presentation_artifact_status_label(
        &self,
        artifact: &core_types::PresentationArtifact,
    ) -> &'static str {
        match artifact.expires_at {
            Some(expires_at) if expires_at <= now_epoch_secs() => "expired",
            _ => "active",
        }
    }

    pub(crate) fn handle_vault_revoke(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault revoke --artifact <artifact-id> --reason <reason>\n";
        let mut artifact_id = None;
        let mut reason = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--artifact" if i + 1 < tokens.len() => {
                    artifact_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--reason" if i + 1 < tokens.len() => {
                    reason = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(artifact_id) = artifact_id else {
            return usage.to_string();
        };
        let Some(reason) = reason else {
            return usage.to_string();
        };

        // Look up the artifact to find the issuer persona
        let record = match self.app_runtime.store.local_presentation_artifact(&artifact_id) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return format!("Failed to revoke disclosure: unknown artifact: {artifact_id}\n");
            }
            Err(err) => return format!("Failed to load disclosure artifact: {err}\n"),
        };

        // Check not already revoked
        if self.app_runtime.store.is_disclosure_revoked(&artifact_id) {
            return format!("Disclosure artifact {artifact_id} is already revoked\n");
        }

        let issuer_persona_id = match record.default_issuer_persona_id() {
            Some(id) => id.to_string(),
            None => {
                return "Failed to revoke disclosure: cannot determine issuer persona for root-owned artifact\n"
                    .to_string()
            }
        };
        let persona = match self.app_runtime.store.materialized().persona(&issuer_persona_id) {
            Some(persona) => persona.clone(),
            None => {
                return format!(
                    "Failed to revoke disclosure: issuer persona not found: {issuer_persona_id}\n"
                );
            }
        };
        let signer = match self.persona_signer(&issuer_persona_id) {
            Ok(signer) => signer,
            Err(err) => {
                return format!(
                    "Failed to revoke disclosure: cannot sign as issuer persona: {err}\n"
                );
            }
        };

        let revocation_id = generate_random_identifier("revocation");
        if let Err(err) = self.append_live_event(
            self.allocate_event_id("disclosure-revoked"),
            EventBody::DisclosureRevoked(DisclosureRevokedEvent {
                revocation_id: revocation_id.clone(),
                artifact_id: artifact_id.clone(),
                revoker_persona_id: issuer_persona_id.clone(),
                reason: reason.clone(),
            }),
            SignerBinding::persona(&issuer_persona_id, persona.active_key.key_id.clone()),
            &signer,
        ) {
            return format!("Failed to revoke disclosure: {err}\n");
        }

        if let Err(err) = self.persist_to_disk() {
            return format!("Revoked disclosure but failed to persist state: {err}\n");
        }

        format!(
            "revoked disclosure\t{}\t{}\t{}\n",
            revocation_id, artifact_id, reason
        )
    }

    /// Combined command: issue a peer disclosure artifact and send it in one step.
    /// Usage: disclose --from <persona> --to <persona> --template <template-id>
    pub(crate) fn handle_disclose(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: disclose --from <persona> --to <persona> --template <template-id> [--namespace root:<id>|persona:<id>] [--expires-in <seconds>]\n";
        let mut sender_ref = None;
        let mut recipient_ref = None;
        let mut template_id = None;
        let mut namespace_arg = None;
        let mut expires_in = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--from" if i + 1 < tokens.len() => {
                    sender_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--to" if i + 1 < tokens.len() => {
                    recipient_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--template" if i + 1 < tokens.len() => {
                    template_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--expires-in" if i + 1 < tokens.len() => {
                    match tokens[i + 1].parse::<u64>() {
                        Ok(value) => expires_in = Some(value),
                        Err(_) => return usage.to_string(),
                    }
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(sender_ref) = sender_ref else {
            return usage.to_string();
        };
        let Some(recipient_ref) = recipient_ref else {
            return usage.to_string();
        };
        let Some(template_id) = template_id else {
            return usage.to_string();
        };

        // Resolve recipient persona ID
        let target_persona_id = match self.resolve_persona(&recipient_ref) {
            Some(persona) => persona.id.clone(),
            None => recipient_ref.clone(),
        };

        // Build the issue command args
        let mut issue_args = vec![
            "--template",
            &template_id,
            "--recipient",
            &target_persona_id,
        ];
        let ns_val;
        if let Some(ref ns) = namespace_arg {
            ns_val = ns.clone();
            issue_args.push("--namespace");
            issue_args.push(&ns_val);
        }
        let exp_str;
        if let Some(exp) = expires_in {
            exp_str = exp.to_string();
            issue_args.push("--expires-in");
            issue_args.push(&exp_str);
        }

        // Step 1: Issue the artifact
        let issue_result = self.handle_vault_issue(&issue_args);
        if !issue_result.contains("issued artifact") {
            return issue_result;
        }

        // Extract artifact ID from result
        let artifact_id = match issue_result.trim().split('\t').nth(1) {
            Some(id) => id.to_string(),
            None => return format!("Failed to extract artifact ID from: {issue_result}"),
        };

        // Step 2: Send the artifact as a message
        let send_args = [
            "--artifact",
            &artifact_id,
            "--from",
            &sender_ref,
            "--to",
            &target_persona_id,
        ];
        let send_result = self.handle_vault_send_artifact(&send_args);

        let mut out = String::new();
        out.push_str(&issue_result);
        out.push_str(&send_result);
        out
    }

    pub(crate) fn handle_vault_store(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault store --file <path> --object <object-id> [--namespace root:<id>|persona:<id>] [--class document|attachment|secret]\n";
        let mut namespace_arg = None;
        let mut object_id = None;
        let mut file_path = None;
        let mut class_arg = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--class" if i + 1 < tokens.len() => {
                    class_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(file_path) = file_path else {
            return usage.to_string();
        };
        let file_bytes = match std::fs::read(&file_path) {
            Ok(bytes) => bytes,
            Err(err) => return format!("Failed to read file: {err}\n"),
        };
        let file_name = std::path::Path::new(&file_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.clone());

        let object_id = object_id.unwrap_or_else(|| generate_random_identifier("vault-file"));

        let object_class = match class_arg.as_deref() {
            Some("document") | None => core_types::VaultObjectClass::PersonaDocument,
            Some("attachment") => core_types::VaultObjectClass::PersonaAttachment,
            Some("secret") => core_types::VaultObjectClass::PersonaSecret,
            Some(other) => return format!("Unknown vault object class: {other}\n{usage}"),
        };

        let content_type = mime_from_filename(&file_name);

        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to store file: no active authorized devices for namespace\n"
                    .to_string();
            }
            Err(err) => return format!("Failed to resolve vault recipients: {}\n", err),
        };
        let catalog_manifest_id = self
            .app_runtime.store
            .plan_local_vault_gc(&namespace)
            .ok()
            .flatten()
            .map(|plan| plan.catalog_manifest_id)
            .unwrap_or_else(|| {
                format!(
                    "vault-catalog-{}-{}",
                    namespace.owner_kind.as_str(),
                    namespace.owner_id
                )
            });
        let created_by_device_id = recipients[0].device_id.clone();
        let revision_id = generate_random_identifier("vault-rev");
        let payload_manifest_id = generate_random_identifier("vault-manifest");
        let created_at = now_epoch_secs();

        match self.app_runtime.store.store_local_file(
            &namespace,
            &object_id,
            &revision_id,
            &payload_manifest_id,
            &catalog_manifest_id,
            created_at,
            &created_by_device_id,
            &file_name,
            &content_type,
            &file_bytes,
            object_class,
            core_types::DurabilityPolicy::ReplicatedToApprovedPeers,
            core_types::RetentionPolicy::KeepLatest,
            recipients,
        ) {
            Ok(_revision) => {
                if let Err(err) = self.persist_to_disk() {
                    return format!("Stored file but failed to persist: {}\n", err);
                }
                format!(
                    "stored file\t{}\t{}\t{} bytes\n",
                    object_id,
                    file_name,
                    file_bytes.len()
                )
            }
            Err(err) => format!("Failed to store file: {}\n", err),
        }
    }

    pub(crate) fn handle_vault_export_file(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: vault export-file --object <object-id> --out <path> [--namespace root:<id>|persona:<id>]\n";
        let mut namespace_arg = None;
        let mut object_id = None;
        let mut out_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--namespace" if i + 1 < tokens.len() => {
                    namespace_arg = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--object" if i + 1 < tokens.len() => {
                    object_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--out" if i + 1 < tokens.len() => {
                    out_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(object_id) = object_id else {
            return usage.to_string();
        };
        let Some(out_path) = out_path else {
            return usage.to_string();
        };
        let namespace = match self.parse_vault_namespace_arg(namespace_arg.as_deref()) {
            Ok(namespace) => namespace,
            Err(err) => return format!("Failed to resolve vault namespace: {}\n", err),
        };
        let catalog = match self.app_runtime.store.local_vault_catalog(&namespace) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => return "Export failed: namespace is empty\n".to_string(),
            Err(err) => return format!("Failed to load vault catalog: {}\n", err),
        };
        let Some(object) = catalog.objects.iter().find(|object| object.id == object_id) else {
            return format!("Export failed: unknown object: {object_id}\n");
        };
        if object.deleted {
            return format!("Export failed: object deleted: {object_id}\n");
        }
        let Some(revision) = catalog
            .revisions
            .iter()
            .find(|revision| revision.id == object.latest_revision_id)
        else {
            return format!(
                "Export failed: latest revision missing for object: {}\n",
                object.id
            );
        };
        let payload_bytes = match self
            .app_runtime.store
            .local_manifest_payload_bytes(&revision.manifest_id)
        {
            Ok(bytes) => bytes,
            Err(err) => return format!("Failed to decrypt vault payload: {}\n", err),
        };

        // For file payloads, skip the header chunk (first chunk is metadata)
        let file_bytes = if revision.payload_kind == core_types::PayloadKind::BinaryBlob {
            // The payload is [header_chunk, file_content_chunk...]
            // Header format: "emberlink-file-header\nfilename=...\n"
            // We need to split on the header boundary
            let manifest = match self.app_runtime.store.local_file_manifest(&revision.manifest_id) {
                Ok(Some(m)) => m,
                _ => return "Export failed: cannot load manifest\n".to_string(),
            };
            if manifest.chunks.len() >= 2 {
                // Re-read just the file content chunks (skip first chunk which is the header)
                match self
                    .app_runtime.store
                    .local_manifest_payload_chunks(&revision.manifest_id)
                {
                    Ok(chunks) if chunks.len() >= 2 => {
                        chunks[1..].iter().flatten().cloned().collect()
                    }
                    Ok(_) => payload_bytes,
                    Err(_) => payload_bytes,
                }
            } else {
                payload_bytes
            }
        } else {
            payload_bytes
        };

        match std::fs::write(&out_path, &file_bytes) {
            Ok(()) => format!(
                "exported file\t{}\t{}\t{} bytes\n",
                object_id,
                out_path,
                file_bytes.len()
            ),
            Err(err) => format!("Failed to write output file: {}\n", err),
        }
    }

    // --- Service binding commands ---

    pub(crate) fn handle_service_bind(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: service bind --persona <persona> --kind <adapter-kind> --label <service-label> --account <external-account-id> [--endpoint <url>]\n";
        let mut persona_ref = None;
        let mut adapter_kind = None;
        let mut service_label = None;
        let mut external_account_id = None;
        let mut endpoint = String::new();
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--kind" if i + 1 < tokens.len() => {
                    adapter_kind = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--label" if i + 1 < tokens.len() => {
                    service_label = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--account" if i + 1 < tokens.len() => {
                    external_account_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--endpoint" if i + 1 < tokens.len() => {
                    endpoint = tokens[i + 1].to_string();
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(adapter_kind) = adapter_kind else {
            return usage.to_string();
        };
        let Some(service_label) = service_label else {
            return usage.to_string();
        };
        let Some(external_account_id) = external_account_id else {
            return usage.to_string();
        };

        let persona_id = match self.require_persona(&persona_ref) {
            Ok(p) => p.id.clone(),
            Err(err) => return format!("Failed to resolve persona: {}\n", err),
        };

        let binding_id = generate_random_identifier("svc-binding");
        let binding = core_types::ServiceBinding {
            id: binding_id.clone(),
            persona_id: persona_id.clone(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: adapter_kind.clone(),
                service_label: service_label.clone(),
                endpoint,
            },
            external_account_id: external_account_id.clone(),
            created_at: now_epoch_secs(),
        };

        match self.app_runtime.store.upsert_service_binding(&binding) {
            Ok(()) => format!(
                "bound service\t{}\t{}\t{}\t{}\n",
                binding_id, persona_id, adapter_kind, external_account_id
            ),
            Err(err) => format!("Failed to bind service: {}\n", err),
        }
    }

    pub(crate) fn handle_service_list(&mut self, tokens: &[&str]) -> String {
        let mut persona_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => {
                    return "Usage: service list [--persona <persona>]\n".to_string();
                }
            }
        }

        let bindings = if let Some(ref persona_ref) = persona_ref {
            let persona = match self.require_persona(persona_ref) {
                Ok(p) => p,
                Err(err) => return format!("Failed to resolve persona: {}\n", err),
            };
            match self.app_runtime.store.service_bindings_for_persona(&persona.id) {
                Ok(b) => b,
                Err(err) => return format!("Failed to load service bindings: {}\n", err),
            }
        } else {
            match self.app_runtime.store.service_bindings() {
                Ok(b) => b,
                Err(err) => return format!("Failed to load service bindings: {}\n", err),
            }
        };

        if bindings.is_empty() {
            return "No service bindings\n".to_string();
        }

        let mut out = String::new();
        for binding in &bindings {
            let persona_label = self
                .resolve_persona(&binding.persona_id)
                .map(|p| p.label.clone())
                .unwrap_or_default();
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}\t{}",
                binding.id,
                if persona_label.is_empty() {
                    &binding.persona_id
                } else {
                    &persona_label
                },
                binding.descriptor.adapter_kind,
                binding.descriptor.service_label,
                binding.external_account_id,
            )
            .unwrap();
        }
        out
    }

    pub(crate) fn handle_service_unbind(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: service unbind --id <binding-id>\n";
        let mut binding_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--id" if i + 1 < tokens.len() => {
                    binding_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(binding_id) = binding_id else {
            return usage.to_string();
        };

        match self.app_runtime.store.delete_service_binding(&binding_id) {
            Ok(true) => format!("unbound service\t{}\n", binding_id),
            Ok(false) => format!("Service binding not found: {}\n", binding_id),
            Err(err) => format!("Failed to unbind service: {}\n", err),
        }
    }

    // --- Password import ---

    pub(crate) fn handle_import_passwords(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: import passwords --persona <persona> --format bitwarden|1password --file <path>\n";
        let mut persona_ref = None;
        let mut format_str = None;
        let mut file_path = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--format" if i + 1 < tokens.len() => {
                    format_str = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--file" if i + 1 < tokens.len() => {
                    file_path = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(format_str) = format_str else {
            return usage.to_string();
        };
        let Some(file_path) = file_path else {
            return usage.to_string();
        };

        let import_format = match format_str.as_str() {
            "bitwarden" => core_state::PasswordImportFormat::BitwardenCsv,
            "1password" => core_state::PasswordImportFormat::OnePasswordCsv,
            _ => return format!("Unknown import format: {format_str}. Use 'bitwarden' or '1password'.\n"),
        };

        let csv_text = match std::fs::read_to_string(&file_path) {
            Ok(text) => text,
            Err(err) => return format!("Failed to read import file: {}\n", err),
        };

        let persona_id = match self.require_persona(&persona_ref) {
            Ok(p) => p.id.clone(),
            Err(err) => return format!("Failed to resolve persona: {}\n", err),
        };
        let namespace = core_types::VaultNamespace {
            owner_kind: core_types::VaultOwnerKind::Persona,
            owner_id: persona_id.clone(),
        };
        let recipients = match self.manifest_key_recipients_for_namespace(&namespace) {
            Ok(recipients) if !recipients.is_empty() => recipients,
            Ok(_) => {
                return "Failed to import: no active authorized devices for persona\n".to_string();
            }
            Err(err) => return format!("Failed to resolve import recipients: {}\n", err),
        };
        let created_by_device_id = recipients[0].device_id.clone();

        let binding = core_types::ServiceBinding {
            id: generate_random_identifier("svc-binding"),
            persona_id: persona_id.clone(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "password".into(),
                service_label: format_str.clone(),
                endpoint: format!("file://{file_path}"),
            },
            external_account_id: "local-import".into(),
            created_at: now_epoch_secs(),
        };

        let adapter = core_state::PasswordImportAdapter::new(import_format, csv_text);

        use core_types::ServiceAdapter;
        let imported_claims = match adapter.import(&binding) {
            Ok(claims) => claims,
            Err(err) => return format!("Failed to parse import file: {}\n", err),
        };

        if imported_claims.is_empty() {
            return "No credentials found in import file\n".to_string();
        }

        let mut stored = 0usize;
        let mut errors = Vec::new();
        let now = now_epoch_secs();

        for claim in &imported_claims {
            let service_name: String = serde_json::from_str::<serde_json::Value>(&claim.payload_json)
                .ok()
                .and_then(|v| v.get("service_name").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_else(|| format!("credential-{}", stored + 1));

            let object_id = format!(
                "pw-{}",
                service_name
                    .to_ascii_lowercase()
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c } else { '-' })
                    .collect::<String>()
            );
            let revision_id = generate_random_identifier("claim-rev");
            let payload_manifest_id = generate_random_identifier("claim-manifest");
            let catalog_manifest_id = generate_random_identifier("vault-catalog");

            let claim_type = core_types::ClaimType::parse(&claim.claim_type)
                .unwrap_or(core_types::ClaimType::SelfAsserted);
            let schema_id = "emberlink:claim:password:1.0";

            let claim_meta = core_types::ClaimMeta {
                claim_type,
                issuer_persona_id: persona_id.clone(),
                subject_persona_id: persona_id.clone(),
                claim_schema: schema_id.to_string(),
                issued_at: now,
                expires_at: claim.external_expires_at,
                external_issuer: Some(claim.external_issuer.clone()),
                external_credential_id: None,
            };

            match self.app_runtime.store.upsert_local_persona_credential(
                &namespace,
                &object_id,
                &revision_id,
                &payload_manifest_id,
                &catalog_manifest_id,
                now,
                &created_by_device_id,
                core_types::StructuredRecordMeta {
                    schema_id: schema_id.to_string(),
                    schema_version: claim_schema_version(schema_id),
                    encoding: core_types::StructuredEncoding::Json,
                    app_namespace: claim_app_namespace(schema_id),
                },
                claim_meta,
                claim.payload_json.as_bytes(),
                core_types::DurabilityPolicy::LocalOnly,
                core_types::RetentionPolicy::KeepLatest,
                recipients.clone(),
            ) {
                Ok(_) => stored += 1,
                Err(err) => errors.push(format!("{}: {}", service_name, err)),
            }
        }

        if let Err(err) = self.persist_to_disk() {
            return format!("Imported {} credentials but failed to persist: {}\n", stored, err);
        }

        let mut out = format!(
            "imported {stored} of {} credentials from {format_str}\n",
            imported_claims.len()
        );
        for err in &errors {
            writeln!(&mut out, "  error: {err}").unwrap();
        }
        out
    }

    // --- Passkey management ---

    pub(crate) fn handle_passkey_register(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: passkey register --persona <persona> --rp-id <domain> --rp-name <label> [--user <name>] [--origin <url>]\n";
        let mut persona_ref = None;
        let mut rp_id = None;
        let mut rp_name = None;
        let mut user_name = None;
        let mut origin = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--rp-id" if i + 1 < tokens.len() => {
                    rp_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--rp-name" if i + 1 < tokens.len() => {
                    rp_name = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--user" if i + 1 < tokens.len() => {
                    user_name = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--origin" if i + 1 < tokens.len() => {
                    origin = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(persona_ref) = persona_ref else {
            return usage.to_string();
        };
        let Some(rp_id) = rp_id else {
            return usage.to_string();
        };
        let Some(rp_name) = rp_name else {
            return usage.to_string();
        };

        let persona = match self.require_persona(&persona_ref) {
            Ok(p) => p.clone(),
            Err(err) => return format!("Failed to resolve persona: {}\n", err),
        };

        let user_name = user_name.unwrap_or_else(|| persona.label.clone());
        let origin = origin.unwrap_or_else(|| format!("https://{rp_id}"));

        // Get the persona's signing key for the passkey.
        let key_record = match self.find_local_key(
            "persona",
            &persona.id,
            &persona.active_key.key_id,
        ) {
            Some(r) => r.clone(),
            None => {
                return format!(
                    "No local signing key for persona {}\n",
                    persona.id
                );
            }
        };

        let local_signer =
            match core_crypto::LocalKeySigner::from_local_key_pair(&key_record.key_pair) {
                Ok(s) => s,
                Err(err) => return format!("Failed to load signing key: {}\n", err),
            };

        let adapter =
            core_state::PasskeyAdapter::new(local_signer, key_record.key_pair.key_id.clone());

        // Generate a self-test challenge.
        let challenge = core_crypto::sha256_digest_raw(
            generate_random_identifier("passkey-challenge").as_bytes(),
        );

        let (result, meta) = match adapter.register(
            &rp_id,
            &origin,
            persona.id.as_bytes(),
            &user_name,
            &challenge,
        ) {
            Ok(r) => r,
            Err(err) => return format!("Passkey registration failed: {}\n", err),
        };

        // Store as a service binding.
        let binding_id = generate_random_identifier("svc-binding");
        let binding = core_types::ServiceBinding {
            id: binding_id.clone(),
            persona_id: persona.id.clone(),
            descriptor: core_types::ServiceDescriptor {
                adapter_kind: "passkey".into(),
                service_label: rp_name.clone(),
                endpoint: origin.clone(),
            },
            external_account_id: serde_json::to_string(&meta).unwrap_or_default(),
            created_at: now_epoch_secs(),
        };

        match self.app_runtime.store.upsert_service_binding(&binding) {
            Ok(()) => {
                use std::fmt::Write;
                let mut out = String::new();
                writeln!(
                    &mut out,
                    "registered passkey\t{}\t{}\t{}",
                    binding_id, rp_name, rp_id
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "  credential_id: {}",
                    result.credential_id_b64url
                )
                .unwrap();
                writeln!(
                    &mut out,
                    "  persona: {} ({})",
                    persona.id, persona.label
                )
                .unwrap();
                writeln!(&mut out, "  origin: {}", origin).unwrap();
                writeln!(
                    &mut out,
                    "  attestation_object: {} bytes",
                    result.attestation_object.len()
                )
                .unwrap();
                out
            }
            Err(err) => format!("Failed to store passkey binding: {}\n", err),
        }
    }

    pub(crate) fn handle_passkey_list(&mut self, tokens: &[&str]) -> String {
        let mut persona_ref = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--persona" if i + 1 < tokens.len() => {
                    persona_ref = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => {
                    return "Usage: passkey list [--persona <persona>]\n".to_string();
                }
            }
        }

        let persona_id = match &persona_ref {
            Some(pr) => match self.require_persona(pr) {
                Ok(p) => Some(p.id.clone()),
                Err(err) => return format!("Failed to resolve persona: {}\n", err),
            },
            None => None,
        };

        let bindings = match self.app_runtime.store.service_bindings() {
            Ok(b) => b,
            Err(err) => return format!("Failed to load bindings: {}\n", err),
        };

        let passkey_bindings: Vec<_> = bindings
            .iter()
            .filter(|b| b.descriptor.adapter_kind == "passkey")
            .filter(|b| {
                persona_id
                    .as_ref()
                    .is_none_or(|pid| &b.persona_id == pid)
            })
            .collect();

        if passkey_bindings.is_empty() {
            return "No passkeys registered\n".to_string();
        }

        use std::fmt::Write;
        let mut out = String::new();
        writeln!(
            &mut out,
            "{:<24} {:<16} {:<24} {:<6}",
            "BINDING", "RP", "PERSONA", "COUNT"
        )
        .unwrap();

        for binding in passkey_bindings {
            let meta: serde_json::Value =
                serde_json::from_str(&binding.external_account_id).unwrap_or_default();
            let rp_id = meta["rp_id"].as_str().unwrap_or("?");
            let sign_count = meta["sign_count"].as_u64().unwrap_or(0);
            let persona_label = self
                .resolve_persona(&binding.persona_id)
                .map(|p| p.label.as_str())
                .unwrap_or("?");

            writeln!(
                &mut out,
                "{:<24} {:<16} {:<24} {:<6}",
                binding.id, rp_id, persona_label, sign_count
            )
            .unwrap();
        }
        out
    }

    pub(crate) fn handle_passkey_authenticate(&mut self, tokens: &[&str]) -> String {
        let usage =
            "Usage: passkey authenticate --id <binding-id> [--challenge <base64url>]\n";
        let mut binding_id = None;
        let mut challenge_b64 = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--id" if i + 1 < tokens.len() => {
                    binding_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                "--challenge" if i + 1 < tokens.len() => {
                    challenge_b64 = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(binding_id) = binding_id else {
            return usage.to_string();
        };

        let bindings = match self.app_runtime.store.service_bindings() {
            Ok(b) => b,
            Err(err) => return format!("Failed to load bindings: {}\n", err),
        };

        let binding = match bindings.iter().find(|b| b.id == binding_id) {
            Some(b) => b.clone(),
            None => return format!("Passkey binding not found: {}\n", binding_id),
        };

        if binding.descriptor.adapter_kind != "passkey" {
            return format!("Binding {} is not a passkey\n", binding_id);
        }

        let mut meta: core_state::PasskeyBindingMeta =
            match serde_json::from_str(&binding.external_account_id) {
                Ok(m) => m,
                Err(err) => {
                    return format!("Failed to parse passkey metadata: {}\n", err);
                }
            };

        // Get the persona's signing key.
        let persona = match self.require_persona(&binding.persona_id) {
            Ok(p) => p.clone(),
            Err(err) => return format!("Failed to resolve persona: {}\n", err),
        };

        let key_record = match self.find_local_key(
            "persona",
            &persona.id,
            &persona.active_key.key_id,
        ) {
            Some(r) => r.clone(),
            None => {
                return format!(
                    "No local signing key for persona {}\n",
                    persona.id
                );
            }
        };

        let local_signer =
            match core_crypto::LocalKeySigner::from_local_key_pair(&key_record.key_pair) {
                Ok(s) => s,
                Err(err) => return format!("Failed to load signing key: {}\n", err),
            };

        let adapter =
            core_state::PasskeyAdapter::new(local_signer, key_record.key_pair.key_id.clone());

        // Use provided challenge or generate a demo one.
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let challenge_bytes = match &challenge_b64 {
            Some(c) => match URL_SAFE_NO_PAD.decode(c) {
                Ok(bytes) => bytes,
                Err(err) => return format!("Invalid base64url challenge: {}\n", err),
            },
            None => core_crypto::sha256_digest_raw(
                generate_random_identifier("passkey-auth").as_bytes(),
            )
            .to_vec(),
        };

        let origin = &binding.descriptor.endpoint;
        let assertion = match adapter.authenticate(&mut meta, &challenge_bytes, origin) {
            Ok(a) => a,
            Err(err) => return format!("Passkey authentication failed: {}\n", err),
        };

        // Update the binding with incremented sign count.
        let updated_binding = core_types::ServiceBinding {
            external_account_id: serde_json::to_string(&meta).unwrap_or_default(),
            ..binding
        };
        if let Err(err) = self.app_runtime.store.upsert_service_binding(&updated_binding) {
            return format!("Warning: failed to update sign count: {}\n", err);
        }

        // Verify locally.
        let pk = adapter_public_key(&persona);
        let verified = pk.as_ref().is_some_and(|pk_bytes| {
            core_state::verify_passkey_assertion(
                pk_bytes,
                &assertion.authenticator_data,
                &assertion.client_data_json,
                &assertion.signature,
            )
            .unwrap_or(false)
        });

        use std::fmt::Write;
        let mut out = String::new();
        writeln!(
            &mut out,
            "passkey assertion\t{}\tsign_count={}",
            binding_id, meta.sign_count
        )
        .unwrap();
        writeln!(
            &mut out,
            "  authenticator_data: {} bytes",
            assertion.authenticator_data.len()
        )
        .unwrap();
        writeln!(
            &mut out,
            "  signature: {} bytes",
            assertion.signature.len()
        )
        .unwrap();
        writeln!(
            &mut out,
            "  local_verify: {}",
            if verified { "PASS" } else { "FAIL" }
        )
        .unwrap();
        out
    }

    pub(crate) fn handle_passkey_remove(&mut self, tokens: &[&str]) -> String {
        let usage = "Usage: passkey remove --id <binding-id>\n";
        let mut binding_id = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "--id" if i + 1 < tokens.len() => {
                    binding_id = Some(tokens[i + 1].to_string());
                    i += 2;
                }
                _ => return usage.to_string(),
            }
        }

        let Some(binding_id) = binding_id else {
            return usage.to_string();
        };

        match self.app_runtime.store.delete_service_binding(&binding_id) {
            Ok(true) => format!("removed passkey\t{}\n", binding_id),
            Ok(false) => format!("Passkey binding not found: {}\n", binding_id),
            Err(err) => format!("Failed to remove passkey: {}\n", err),
        }
    }
}

fn adapter_public_key(persona: &core_types::Persona) -> Option<[u8; 32]> {
    core_crypto::public_key_raw_bytes(&core_crypto::PublicKey(
        persona.active_key.public_key.clone(),
    ))
    .ok()
}
