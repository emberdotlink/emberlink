use crate::infra::store::DaemonStore;
use crate::trust::approval::ApprovalRequestInfo;

pub struct Banner {
    pub title: String,
    pub subtitle: String,
    pub body: String,
    pub click_url: String,
}

/// Build the notification banner strings for a pending approval request.
///
/// Kept short to fit macOS banner constraints (~60 chars title, ~50 chars
/// subtitle/body). The scope string is intentionally excluded — it was the
/// primary overflow culprit. The dashboard deep-link (`click_url`) is the
/// canonical control surface for full context.
pub fn build_banner(persona_name: &str, req: &ApprovalRequestInfo) -> Banner {
    let id_prefix: String = req
        .id
        .strip_prefix("approval-")
        .unwrap_or(&req.id)
        .chars()
        .take(8)
        .collect();

    // Title: prefer tool_name when present; fall back to the action string.
    // Cap the action at 40 chars to leave room for "Ember · <name> wants ".
    // Append agent_framework as a parenthesized badge when present.
    let framework_suffix = req
        .agent_framework
        .as_deref()
        .map(|f| {
            let f_short: String = f.chars().take(16).collect();
            format!(" ({f_short})")
        })
        .unwrap_or_default();
    let title = if let Some(ref tool) = req.tool_name {
        let tool_short: String = tool.chars().take(40).collect();
        format!("Ember · {persona_name} · {tool_short}{framework_suffix}")
    } else {
        let action_short: String = req.action.chars().take(40).collect();
        format!("Ember · {persona_name} wants {action_short}{framework_suffix}")
    };

    // Subtitle: credential · TTL · risk — decision-relevant, no scope/id.
    let ttl_part = req
        .ttl_secs
        .map(|s| format!(" · {s}s TTL"))
        .unwrap_or_default();
    let risk_part = if req.risk_level.is_empty() {
        String::new()
    } else {
        format!(" · risk {}", req.risk_level)
    };
    let subtitle_raw = format!("{}{ttl_part}{risk_part}", req.credential_name);
    // Hard-truncate at 50 chars to guard against long credential names.
    let subtitle: String = if subtitle_raw.chars().count() > 50 {
        let mut s: String = subtitle_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        subtitle_raw
    };

    // Body: prefer target_host + target_summary when either is present; then
    // fall back to target_url; otherwise use the click-to-review prompt.
    let body_raw = match (&req.target_host, &req.target_summary, &req.target_url) {
        (Some(host), Some(summary), _) => format!("{host}{summary}"),
        (Some(host), None, _) => host.clone(),
        (None, Some(summary), _) => summary.clone(),
        (None, None, Some(url)) => url.clone(),
        (None, None, None) => format!("Click to review · {id_prefix}"),
    };
    let body: String = if body_raw.chars().count() > 50 {
        let mut s: String = body_raw.chars().take(47).collect();
        s.push_str("...");
        s
    } else {
        body_raw
    };

    let click_url = format!("http://localhost:3141/approvals/{}", req.id);

    Banner {
        title,
        subtitle,
        body,
        click_url,
    }
}

/// Surface a pending approval to the user via the OS notification system.
///
/// Best-effort — errors are silently swallowed. The call is skipped when
/// `EMBER_NO_DESKTOP_NOTIFY=1` is set (useful in CI/tests).
pub(crate) fn notify_require_approval(store: &DaemonStore, req: &ApprovalRequestInfo) {
    #[cfg(test)]
    {
        let _ = (store, req);
        return;
    }
    #[cfg(not(test))]
    {
        if std::env::var("EMBER_NO_DESKTOP_NOTIFY").as_deref() == Ok("1") {
            return;
        }
        let persona_name = store
            .get_persona(&req.persona_id)
            .map(|p| p.name)
            .unwrap_or_else(|_| req.persona_id.chars().take(8).collect());
        let banner = build_banner(&persona_name, req);
        crate::infra::notify::send_notification_with_url(
            &banner.title,
            Some(&banner.subtitle),
            &banner.body,
            Some(&banner.click_url),
        );
    }
}
