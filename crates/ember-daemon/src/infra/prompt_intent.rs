use core_crypto::presence::{PresencePromptClass, PresencePromptIntent, PresencePromptPolicy};
use serde_json::Value;

pub fn unlock_prompt_intent(
    requested_method: &str,
    requested_params: &Value,
) -> PresencePromptIntent {
    unlock_prompt_intent_with_policy(
        requested_method,
        requested_params,
        PresencePromptPolicy::Recoverable,
    )
}

pub fn unlock_prompt_intent_with_policy(
    requested_method: &str,
    requested_params: &Value,
    policy: PresencePromptPolicy,
) -> PresencePromptIntent {
    let (prompt_class, summary, detail_lines) = match requested_method {
        "vault_unlock" => (
            PresencePromptClass::VaultAdmin,
            "Unlock your Ember vault".to_string(),
            Vec::new(),
        ),
        "register_session" => (
            PresencePromptClass::SessionOpen,
            "Start a new Ember session".to_string(),
            persona_detail_lines(requested_params),
        ),
        "launcher_prepare_claude_code" => (
            PresencePromptClass::LaunchTool,
            "Start Claude Code with Ember".to_string(),
            Vec::new(),
        ),
        "create_persona" => (
            PresencePromptClass::Generic,
            "Create an Ember persona".to_string(),
            quoted_detail_line(requested_params, "name", "Persona"),
        ),
        "revoke_persona" => (
            PresencePromptClass::Generic,
            "Revoke an Ember persona".to_string(),
            persona_target_detail_lines(requested_params),
        ),
        "create_grant" => (
            PresencePromptClass::Approval,
            "Create an Ember grant".to_string(),
            grant_detail_lines(requested_params),
        ),
        "create_composite_grant" => (
            PresencePromptClass::Approval,
            "Create an Ember composite grant".to_string(),
            grant_detail_lines(requested_params),
        ),
        "resolve_grant_approval" | "resolve_approval" => (
            PresencePromptClass::Approval,
            "Resolve an Ember approval".to_string(),
            approval_detail_lines(requested_params),
        ),
        "delegate_grant" => (
            PresencePromptClass::Approval,
            "Delegate an Ember grant".to_string(),
            grant_detail_lines(requested_params),
        ),
        "revoke_grant" => (
            PresencePromptClass::Approval,
            "Revoke an Ember grant".to_string(),
            grant_id_detail_lines(requested_params),
        ),
        "grant.extend" | "extend_grant" => (
            PresencePromptClass::Approval,
            "Extend an Ember grant".to_string(),
            grant_id_detail_lines(requested_params),
        ),
        "vault_add" | "vault_put" => (
            PresencePromptClass::VaultAdmin,
            "Store an Ember vault entry".to_string(),
            quoted_detail_line(requested_params, "name", "Vault entry"),
        ),
        "vault_get" => (
            PresencePromptClass::VaultAdmin,
            "Read an Ember vault entry".to_string(),
            quoted_detail_line(requested_params, "name", "Vault entry"),
        ),
        "vault_remove" => (
            PresencePromptClass::VaultAdmin,
            "Remove an Ember vault entry".to_string(),
            quoted_detail_line(requested_params, "name", "Vault entry"),
        ),
        "vault_migrate_acl" => (
            PresencePromptClass::VaultAdmin,
            "Update Ember vault access control".to_string(),
            Vec::new(),
        ),
        "sandbox_create" => (
            PresencePromptClass::Generic,
            "Create an Ember sandbox".to_string(),
            sandbox_detail_lines(requested_params),
        ),
        "sandbox_stop" => (
            PresencePromptClass::Generic,
            "Stop an Ember sandbox".to_string(),
            sandbox_detail_lines(requested_params),
        ),
        "sandbox_delete" => (
            PresencePromptClass::Generic,
            "Delete an Ember sandbox".to_string(),
            sandbox_detail_lines(requested_params),
        ),
        "sandbox_exec" => (
            PresencePromptClass::Generic,
            "Run a command in an Ember sandbox".to_string(),
            sandbox_detail_lines(requested_params),
        ),
        "sandbox_run" => (
            PresencePromptClass::Generic,
            "Start an Ember sandbox workflow".to_string(),
            sandbox_detail_lines(requested_params),
        ),
        "headless_enroll" => (
            PresencePromptClass::Generic,
            "Enable Ember headless access".to_string(),
            Vec::new(),
        ),
        "headless_revoke" => (
            PresencePromptClass::Generic,
            "Revoke Ember headless access".to_string(),
            Vec::new(),
        ),
        "close_session" => (
            PresencePromptClass::SessionOpen,
            "Close an Ember session".to_string(),
            session_detail_lines(requested_params),
        ),
        "binary_pin_generate" => (
            PresencePromptClass::VaultAdmin,
            "Refresh Ember's binary trust pins".to_string(),
            Vec::new(),
        ),
        _ => (
            PresencePromptClass::Generic,
            "Continue this Ember action".to_string(),
            vec![format!("Method: {requested_method}")],
        ),
    };

    PresencePromptIntent::new(policy, prompt_class, summary, detail_lines)
}

fn first_present_string<'a>(requested_params: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| requested_params.get(*key).and_then(|v| v.as_str()))
        .filter(|value| !value.trim().is_empty())
}

fn shorten_id(raw: &str) -> String {
    if let Some(stripped) = raw.strip_prefix("persona-") {
        let short = stripped.chars().take(8).collect::<String>();
        return format!("persona-{short}");
    }
    if raw.len() > 20 {
        return raw.chars().take(20).collect::<String>();
    }
    raw.to_string()
}

fn quoted_detail_line(requested_params: &Value, key: &str, label: &str) -> Vec<String> {
    requested_params
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| vec![format!("{label}: {value}")])
        .unwrap_or_default()
}

fn persona_target_detail_lines(requested_params: &Value) -> Vec<String> {
    let id = requested_params.get("id").and_then(|v| v.as_str());
    let name = requested_params.get("name").and_then(|v| v.as_str());
    match (name, id) {
        (Some(name), Some(id)) if !name.trim().is_empty() && !id.trim().is_empty() => {
            vec![format!("Persona: {name} ({})", shorten_id(id))]
        }
        (Some(name), _) if !name.trim().is_empty() => vec![format!("Persona: {name}")],
        (_, Some(id)) if !id.trim().is_empty() => vec![format!("Persona: {}", shorten_id(id))],
        _ => Vec::new(),
    }
}

fn persona_detail_lines(requested_params: &Value) -> Vec<String> {
    first_present_string(requested_params, &["persona_id", "persona"])
        .map(|persona| vec![format!("Persona: {persona}")])
        .unwrap_or_default()
}

fn grant_id_detail_lines(requested_params: &Value) -> Vec<String> {
    first_present_string(requested_params, &["grant_id", "id", "parent_grant_id"])
        .map(|value| vec![format!("Grant: {}", shorten_id(value))])
        .unwrap_or_default()
}

fn grant_detail_lines(requested_params: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(persona) = first_present_string(requested_params, &["persona_id", "persona"]) {
        lines.push(format!("Persona: {persona}"));
    }
    if let Some(credential) = first_present_string(requested_params, &["credential_name"]) {
        lines.push(format!("Credential: {credential}"));
    }
    if let Some(scope) = first_present_string(requested_params, &["scope"]) {
        lines.push(format!("Scope: {scope}"));
    }
    if lines.is_empty() {
        grant_id_detail_lines(requested_params)
    } else {
        lines
    }
}

fn approval_detail_lines(requested_params: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(id) = first_present_string(requested_params, &["id"]) {
        lines.push(format!("Approval: {}", shorten_id(id)));
    }
    if let Some(decision) = first_present_string(requested_params, &["decision"]) {
        lines.push(format!("Decision: {decision}"));
    }
    lines
}

fn sandbox_detail_lines(requested_params: &Value) -> Vec<String> {
    first_present_string(requested_params, &["name", "id_or_name"])
        .map(|label| vec![format!("Sandbox: {label}")])
        .unwrap_or_default()
}

fn session_detail_lines(requested_params: &Value) -> Vec<String> {
    first_present_string(requested_params, &["session_id"])
        .map(|id| vec![format!("Session: {}", shorten_id(id))])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_prompt_intent_builds_short_native_copy_and_rich_details() {
        let intent = unlock_prompt_intent(
            "create_grant",
            &serde_json::json!({
                "persona_id": "claude-code-default",
                "credential_name": "anthropic-key",
                "scope": "credential:read"
            }),
        );
        assert_eq!(intent.summary, "Create an Ember grant");
        assert_eq!(intent.native_os_reason(), "Create an Ember grant");
        assert_eq!(
            intent.detail_lines,
            vec![
                "Persona: claude-code-default".to_string(),
                "Credential: anthropic-key".to_string(),
                "Scope: credential:read".to_string(),
            ]
        );
    }

    #[test]
    fn launch_prompt_intent_pluralizes_for_coalesced_waiters() {
        let mut intent = unlock_prompt_intent("launcher_prepare_claude_code", &Value::Null);
        intent.increment_pending_count();
        assert_eq!(
            intent.native_os_reason(),
            "Start Claude Code with Ember and continue 1 pending Ember action"
        );
    }

    #[test]
    fn unlock_prompt_intent_accepts_explicit_strict_policy() {
        let intent = unlock_prompt_intent_with_policy(
            "resolve_approval",
            &serde_json::json!({"id": "approval-123"}),
            PresencePromptPolicy::StrictBiometric,
        );
        assert_eq!(intent.policy, PresencePromptPolicy::StrictBiometric);
        assert_eq!(intent.summary, "Resolve an Ember approval");
    }

    // FINDING-A (structural): the operator-intent renderer is allowlist-based —
    // for vault writes it surfaces ONLY the entry name, never the credential
    // `value` / `value_bytes`. This is the single source of truth the CLI Touch
    // ID `localizedReason` is built from, so locking it here prevents any future
    // edit from reintroducing the secret-leak into the human-visible prompt.
    #[test]
    fn vault_add_intent_surfaces_only_the_entry_name_never_the_value() {
        let secret = "sk-ant-oat01-NEVER";
        for method in ["vault_add", "vault_put"] {
            let intent = unlock_prompt_intent(
                method,
                &serde_json::json!({
                    "name": "anthropic/oauth-token",
                    "value": secret,
                    "value_bytes": secret.bytes().collect::<Vec<u8>>(),
                }),
            );
            assert_eq!(intent.summary, "Store an Ember vault entry");
            assert_eq!(
                intent.detail_lines,
                vec!["Vault entry: anthropic/oauth-token".to_string()]
            );
            let rendered = format!(
                "{} {} {}",
                intent.summary,
                intent.native_os_reason(),
                intent.detail_lines.join(" ")
            );
            assert!(
                !rendered.contains(secret),
                "{method} intent leaked the credential value: {rendered}"
            );
        }
    }
}
