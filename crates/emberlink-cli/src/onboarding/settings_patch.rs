use serde_json::{json, Value};

/// The exact `command` string we look for and write. Exposed for tests
/// and for implementation-note-162's `--uninstall` path to remove only what we added.
pub const EMBER_PROXY_HOOK_COMMAND: &str = "ember-proxy hook";

/// Raw tool names that must NOT be invoked outside the shadow PATH shims.
/// Each entry here generates deny rules for common absolute binary paths.
/// The shadow shims live at `~/.ember/shadow/<name>` and are allowed
/// (they do not match any of the denied absolute-path prefixes below).
///
/// Extensible: add a name here and the deny/remove functions pick it up
/// automatically.
pub const RAW_TOOL_DENY_LIST: &[&str] = &["gh", "git", "kubectl"];

/// Absolute-path prefixes at which each tool in `RAW_TOOL_DENY_LIST` is
/// commonly found outside the shadow dir. We deny these explicitly so that
/// even if the shadow PATH is bypassed the raw binaries cannot be exec'd
/// via the Claude Code Bash hook (design §3 step 4).
///
/// The shadow dir itself (`~/.ember/shadow/<tool>`) is NOT listed here, so
/// shim invocations pass through unblocked.
const DENY_PATH_PREFIXES: &[&str] = &[
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/sbin",
    "/snap/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];

/// Build the full set of `permissions.deny` entry strings we own.
/// Format matches the Claude Code permissions schema: `Bash(<path> *)`.
fn deny_entries() -> Vec<String> {
    let mut entries = Vec::new();
    for tool in RAW_TOOL_DENY_LIST {
        for prefix in DENY_PATH_PREFIXES {
            entries.push(format!("Bash({prefix}/{tool} *)"));
        }
    }
    entries
}

/// Add `permissions.deny` entries that block raw invocations of
/// `gh`, `git`, and `kubectl` via absolute paths outside the shadow dir.
///
/// The shadow shims (`~/.ember/shadow/<tool>`) are NOT denied — they are
/// the sanctioned path. Common absolute-path locations (e.g.
/// `/usr/bin/git`, `/opt/homebrew/bin/gh`) are denied so that even if the
/// shadow PATH is overridden mid-session the raw binaries cannot be exec'd
/// through the Claude Code Bash hook.
///
/// Idempotent: already-present entries are not duplicated.
/// Preserves all user-authored deny entries that are not ours.
pub fn add_permissions_deny_outside_shadow(settings: &mut Value) -> Result<(), PatchError> {
    let root = settings
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("non-object"))?;

    let permissions = root
        .entry("permissions")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("permissions is not an object"))?;

    let deny = permissions
        .entry("deny")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(PatchError::RootNotObject("permissions.deny is not an array"))?;

    for entry in deny_entries() {
        let already = deny
            .iter()
            .any(|v| v.as_str() == Some(entry.as_str()));
        if !already {
            deny.push(json!(entry));
        }
    }

    Ok(())
}

/// Remove the `permissions.deny` entries added by
/// `add_permissions_deny_outside_shadow`. Only removes entries we own;
/// user-authored deny entries are preserved. Cleans up empty
/// `permissions.deny` and `permissions` objects that we created, but only
/// when they contain no other entries.
pub fn remove_permissions_deny_outside_shadow(settings: &mut Value) -> Result<(), PatchError> {
    let root = settings
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("non-object"))?;

    let permissions_obj = match root.get_mut("permissions").and_then(|v| v.as_object_mut()) {
        Some(obj) => obj,
        None => return Ok(()),
    };

    let deny = match permissions_obj
        .get_mut("deny")
        .and_then(|v| v.as_array_mut())
    {
        Some(arr) => arr,
        None => return Ok(()),
    };

    let our_entries = deny_entries();
    let before = deny.len();
    deny.retain(|v| {
        let s = v.as_str().unwrap_or("");
        !our_entries.iter().any(|e| e == s)
    });

    if deny.len() == before {
        // Nothing changed — our entries weren't present.
        return Ok(());
    }

    // Clean up: if deny is now empty and we created it (i.e. has no other
    // entries), remove it. Same for the permissions object itself.
    let deny_empty = permissions_obj
        .get("deny")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(false);
    if deny_empty {
        permissions_obj.remove("deny");
    }

    let permissions_empty = permissions_obj.is_empty();
    if permissions_empty {
        root.remove("permissions");
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("invalid JSON in settings.json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("settings.json root must be a JSON object, got {0}")]
    RootNotObject(&'static str),
}

/// Detect whether the settings JSON already contains our PreToolUse hook
/// entry. The check is conservative: matches any hook block under
/// `hooks.PreToolUse[*].hooks[*]` whose `command` exactly equals
/// `EMBER_PROXY_HOOK_COMMAND` and whose `type` is `"command"`.
pub fn has_pretooluse_hook(settings: &Value) -> bool {
    let pretooluse = match settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|v| v.as_array())
    {
        Some(arr) => arr,
        None => return false,
    };
    pretooluse.iter().any(|block| {
        block
            .get("hooks")
            .and_then(|v| v.as_array())
            .map(|inner| {
                inner.iter().any(|h| {
                    h.get("type").and_then(|v| v.as_str()) == Some("command")
                        && h.get("command").and_then(|v| v.as_str())
                            == Some(EMBER_PROXY_HOOK_COMMAND)
                })
            })
            .unwrap_or(false)
    })
}

/// Add our PreToolUse hook entry if missing. No-op if already present.
/// Returns true if a write was made; false if the JSON was already
/// patched.
///
/// Shape we add (matches the `ember-proxy --help` install snippet):
///
/// ```json
/// {
///   "hooks": {
///     "PreToolUse": [
///       {
///         "matcher": "*",
///         "hooks": [
///           { "type": "command", "command": "ember-proxy hook" }
///         ]
///       }
///     ]
///   }
/// }
/// ```
pub fn add_pretooluse_hook(settings: &mut Value) -> Result<bool, PatchError> {
    let root = settings
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("non-object"))?;

    let hooks = root
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("hooks is not an object"))?;

    let pretooluse = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(PatchError::RootNotObject("PreToolUse is not an array"))?;

    // Find or create the wildcard-matcher block
    let block = match pretooluse
        .iter_mut()
        .find(|b| b.get("matcher").and_then(|v| v.as_str()) == Some("*"))
    {
        Some(b) => b,
        None => {
            pretooluse.push(json!({"matcher": "*", "hooks": []}));
            pretooluse.last_mut().unwrap()
        }
    };

    let inner = block
        .get_mut("hooks")
        .and_then(|v| v.as_array_mut())
        .ok_or(PatchError::RootNotObject("wildcard block hooks is not an array"))?;

    // Idempotency: skip if our hook is already there
    if inner.iter().any(|h| {
        h.get("type").and_then(|v| v.as_str()) == Some("command")
            && h.get("command").and_then(|v| v.as_str()) == Some(EMBER_PROXY_HOOK_COMMAND)
    }) {
        return Ok(false);
    }

    inner.push(json!({"type": "command", "command": EMBER_PROXY_HOOK_COMMAND}));
    Ok(true)
}

/// Remove our PreToolUse hook entry — and ONLY ours. Removes any
/// `{type:"command",command:"ember-proxy hook"}` entries from any
/// `hooks.PreToolUse[*].hooks[*]` array. Cleans up empty wrapper
/// arrays/objects we created but leaves user-authored hooks alone.
/// Returns true if a write was made; false if our hook wasn't present.
pub fn remove_pretooluse_hook(settings: &mut Value) -> Result<bool, PatchError> {
    let root = settings
        .as_object_mut()
        .ok_or(PatchError::RootNotObject("non-object"))?;

    let hooks_obj = match root.get_mut("hooks").and_then(|v| v.as_object_mut()) {
        Some(obj) => obj,
        None => return Ok(false),
    };

    let pretooluse = match hooks_obj
        .get_mut("PreToolUse")
        .and_then(|v| v.as_array_mut())
    {
        Some(arr) => arr,
        None => return Ok(false),
    };

    let mut made_change = false;

    // Remove our hook entry from any matching block's inner hooks array
    for block in pretooluse.iter_mut() {
        if let Some(inner) = block.get_mut("hooks").and_then(|v| v.as_array_mut()) {
            let before = inner.len();
            inner.retain(|h| {
                !(h.get("type").and_then(|v| v.as_str()) == Some("command")
                    && h.get("command").and_then(|v| v.as_str()) == Some(EMBER_PROXY_HOOK_COMMAND))
            });
            if inner.len() < before {
                made_change = true;
            }
        }
    }

    if !made_change {
        return Ok(false);
    }

    // Clean up empty wildcard blocks that we created (only if inner hooks is
    // empty AND no other fields beyond "matcher" and "hooks")
    pretooluse.retain(|block| {
        let inner_empty = block
            .get("hooks")
            .and_then(|v| v.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(false);
        if !inner_empty {
            return true;
        }
        // Only drop the block if it has exactly "matcher" and "hooks" (i.e.,
        // nothing user-authored beyond what we may have created)
        let obj = match block.as_object() {
            Some(o) => o,
            None => return true,
        };
        let only_our_keys = obj.keys().all(|k| k == "matcher" || k == "hooks");
        !only_our_keys
    });

    // If PreToolUse is now empty, remove the key
    let pretooluse_empty = hooks_obj
        .get("PreToolUse")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(false);
    if pretooluse_empty {
        hooks_obj.remove("PreToolUse");
    }

    // If hooks object is now empty, remove the key
    let hooks_empty = hooks_obj.is_empty();
    if hooks_empty {
        root.remove("hooks");
    }

    Ok(true)
}

/// Top-level convenience: parse → patch (add) → re-serialize.
/// Used by `ember init --for claude-code` (implementation-note-162).
pub fn patch_settings_json(input: &str) -> Result<String, PatchError> {
    let mut value = if input.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str::<Value>(input)?
    };
    if !value.is_object() {
        return Err(PatchError::RootNotObject(match &value {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => unreachable!(),
        }));
    }
    add_pretooluse_hook(&mut value)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_input_creates_full_structure() {
        let out = patch_settings_json("").expect("patch empty");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn empty_object_input_creates_structure() {
        let out = patch_settings_json("{}").expect("patch {}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn idempotent_double_apply() {
        let once = patch_settings_json("{}").expect("first patch");
        let twice = patch_settings_json(&once).expect("second patch");
        // Re-serialization should produce identical output
        let v1: Value = serde_json::from_str(&once).unwrap();
        let v2: Value = serde_json::from_str(&twice).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn add_returns_false_when_already_present() {
        let mut v = json!({});
        assert!(add_pretooluse_hook(&mut v).unwrap(), "first call writes");
        assert!(!add_pretooluse_hook(&mut v).unwrap(), "second call no-ops");
    }

    #[test]
    fn preserves_existing_unrelated_keys() {
        let input = serde_json::to_string(&json!({
            "theme": "dark",
            "model": "sonnet",
            "mcpServers": {"my-server": {"command": "node", "args": ["x.js"]}},
            "statusline": {"type": "command", "command": "/bin/echo hi"},
            "permissions": {"allow": ["Bash(ls)"]}
        }))
        .unwrap();
        let out = patch_settings_json(&input).expect("patch");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v.get("theme").and_then(|v| v.as_str()), Some("dark"));
        assert_eq!(v.get("model").and_then(|v| v.as_str()), Some("sonnet"));
        assert!(v.get("mcpServers").and_then(|v| v.get("my-server")).is_some());
        assert!(v.get("statusline").is_some());
        assert!(v.get("permissions").is_some());
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn preserves_existing_user_hooks_in_pretooluse() {
        let input = serde_json::to_string(&json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "/usr/local/bin/my-custom-hook"}
                    ]}
                ]
            }
        }))
        .unwrap();
        let out = patch_settings_json(&input).expect("patch");
        let v: Value = serde_json::from_str(&out).unwrap();
        // User's custom hook is still there
        let pretooluse = v
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        let custom_match = pretooluse.iter().any(|b| {
            b.get("matcher").and_then(|m| m.as_str()) == Some("Bash")
                && b.pointer("/hooks/0/command")
                    .and_then(|c| c.as_str())
                    == Some("/usr/local/bin/my-custom-hook")
        });
        assert!(custom_match, "user's Bash hook preserved");
        // Our hook is also there
        assert!(has_pretooluse_hook(&v));
    }

    #[test]
    fn merges_into_existing_wildcard_block() {
        // Pre-existing wildcard hooks block with someone else's command
        let input = serde_json::to_string(&json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*", "hooks": [
                        {"type": "command", "command": "/usr/local/bin/audit"}
                    ]}
                ]
            }
        }))
        .unwrap();
        let out = patch_settings_json(&input).expect("patch");
        let v: Value = serde_json::from_str(&out).unwrap();
        let inner = v
            .pointer("/hooks/PreToolUse/0/hooks")
            .unwrap()
            .as_array()
            .unwrap();
        // Both hooks present in the same wildcard block
        assert_eq!(inner.len(), 2, "should merge, not duplicate the matcher block");
    }

    #[test]
    fn remove_undoes_add() {
        let mut v: Value = json!({});
        assert!(add_pretooluse_hook(&mut v).unwrap());
        assert!(remove_pretooluse_hook(&mut v).unwrap());
        // After removal, JSON should be back to {}
        assert_eq!(v, json!({}));
    }

    #[test]
    fn remove_preserves_user_hooks() {
        let mut v: Value = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "/usr/local/bin/my-custom-hook"}
                    ]}
                ]
            }
        });
        // Add ours, then remove ours
        add_pretooluse_hook(&mut v).unwrap();
        assert!(remove_pretooluse_hook(&mut v).unwrap());
        // User's hook still there
        let pretooluse = v
            .pointer("/hooks/PreToolUse")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(pretooluse.len(), 1);
        assert_eq!(
            pretooluse[0]
                .pointer("/hooks/0/command")
                .unwrap()
                .as_str(),
            Some("/usr/local/bin/my-custom-hook")
        );
    }

    #[test]
    fn rejects_non_object_root() {
        let result = patch_settings_json("[1,2,3]");
        assert!(matches!(result, Err(PatchError::RootNotObject(_))));
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(patch_settings_json("{not json").is_err());
    }

    // --- implementation-note-177 tests ---

    #[test]
    fn add_deny_to_empty_settings() {
        let mut v: Value = json!({});
        add_permissions_deny_outside_shadow(&mut v).expect("add deny");
        let deny = v
            .pointer("/permissions/deny")
            .and_then(|d| d.as_array())
            .expect("permissions.deny must be an array");
        // Every expected tool must appear as at least one entry.
        for tool in RAW_TOOL_DENY_LIST {
            let has_entry = deny
                .iter()
                .any(|e| e.as_str().map(|s| s.contains(tool)).unwrap_or(false));
            assert!(has_entry, "deny list must contain an entry for {tool}");
        }
        // Spot-check that entries reference absolute paths, not the shadow dir.
        for entry in deny {
            let s = entry.as_str().unwrap_or("");
            assert!(
                !s.contains("~/.ember/shadow"),
                "deny entries must not reference the shadow dir: {s}"
            );
        }
    }

    #[test]
    fn add_deny_idempotent() {
        let mut v: Value = json!({});
        add_permissions_deny_outside_shadow(&mut v).expect("first add");
        let count_after_first = v
            .pointer("/permissions/deny")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        add_permissions_deny_outside_shadow(&mut v).expect("second add");
        let count_after_second = v
            .pointer("/permissions/deny")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        assert_eq!(
            count_after_first, count_after_second,
            "second add must not duplicate entries"
        );
    }

    #[test]
    fn remove_deny_round_trips() {
        let mut v: Value = json!({});
        add_permissions_deny_outside_shadow(&mut v).expect("add");
        remove_permissions_deny_outside_shadow(&mut v).expect("remove");
        assert_eq!(v, json!({}), "round-trip must restore original {{}}");
    }

    #[test]
    fn existing_user_deny_entries_preserved() {
        let user_entry = "Bash(/usr/bin/curl *)";
        let mut v: Value = json!({
            "permissions": {
                "deny": [user_entry]
            }
        });
        add_permissions_deny_outside_shadow(&mut v).expect("add");
        // User entry still present.
        let deny = v
            .pointer("/permissions/deny")
            .and_then(|d| d.as_array())
            .expect("deny array");
        assert!(
            deny.iter().any(|e| e.as_str() == Some(user_entry)),
            "user deny entry must survive add"
        );
        remove_permissions_deny_outside_shadow(&mut v).expect("remove");
        let deny_after = v
            .pointer("/permissions/deny")
            .and_then(|d| d.as_array())
            .expect("deny array after remove");
        assert!(
            deny_after.iter().any(|e| e.as_str() == Some(user_entry)),
            "user deny entry must survive remove"
        );
        // Our entries are gone.
        for tool in RAW_TOOL_DENY_LIST {
            for prefix in DENY_PATH_PREFIXES {
                let our_entry = format!("Bash({prefix}/{tool} *)");
                assert!(
                    !deny_after.iter().any(|e| e.as_str() == Some(our_entry.as_str())),
                    "our entry {our_entry} must be removed"
                );
            }
        }
    }
}
