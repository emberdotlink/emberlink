/// Send a desktop notification. Best-effort — failures are logged but not fatal.
///
/// ## macOS notifier selection (in order):
///
/// 1. `EMBER_NOTIFIER` env var — path to a custom notifier binary, called
///    as `<path> --title <title> --message <message>` (terminal-notifier
///    compatible).
/// 2. `terminal-notifier` on `$PATH` — preferred on macOS because it has
///    its own signed bundle identity; `display notification` from osascript
///    runs under Script Editor's identity and silently fails (or launches
///    Script Editor on some macOS versions) if Script Editor lacks
///    notification permission in System Settings.
/// 3. `osascript -e 'display notification ...'` — fallback. Captures stderr
///    so a notify-permission failure surfaces in the daemon log instead
///    of mystery-disappearing.
///
/// ## Linux: uses `notify-send`.
///
/// ## Escaping:
///
/// AppleScript string literals are escaped by backslashing both `"` and `\`.
/// Control characters (newlines, tabs) are stripped up front — they can
/// confuse `display notification` and have no use in a notification anyway.
pub fn send_notification(title: &str, message: &str) {
    send_notification_rich(title, None, message);
}

/// Rich variant of `send_notification` that accepts an optional subtitle.
/// macOS `terminal-notifier` and `osascript display notification` both support
/// a subtitle field. On platforms without native subtitle support (the Linux
/// fallback), the subtitle is prefixed onto the message separated by a newline.
pub fn send_notification_rich(title: &str, subtitle: Option<&str>, message: &str) {
    send_notification_with_url(title, subtitle, message, None);
}

/// Full-featured notification with optional click-through URL.
///
/// When `click_url` is `Some`, clicking the macOS notification opens the URL
/// in the default browser. This requires `terminal-notifier` — the osascript
/// fallback does not support `-open` and will log a debug message instead.
///
/// The URL is passed as-is to `terminal-notifier -open <url>`. Callers are
/// responsible for ensuring the URL is well-formed.
pub fn send_notification_with_url(
    title: &str,
    subtitle: Option<&str>,
    message: &str,
    // Used on macOS only; unused on Linux/Windows where terminal-notifier's
    // `-open <url>` flag isn't applicable.
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] click_url: Option<&str>,
) {
    // Suppress real desktop notifications during tests. Without this guard,
    // `cargo test -p ember-daemon` on macOS fires terminal-notifier /
    // osascript for every approval-path test and the user sees phantom
    // notifications pointing at ephemeral test approval IDs. Set
    // EMBER_NOTIFY_DISABLED=1 in test harnesses and CI; unit tests inside
    // this crate get it automatically via cfg!(test).
    if cfg!(test) || std::env::var("EMBER_NOTIFY_DISABLED").is_ok() {
        tracing::debug!(
            title = title,
            "notification suppressed — EMBER_NOTIFY_DISABLED or cfg(test)"
        );
        return;
    }

    let title = sanitize(title);
    let subtitle = subtitle.map(sanitize);
    let message = sanitize(message);

    #[cfg(target_os = "macos")]
    {
        if try_custom_notifier(&title, subtitle.as_deref(), &message) {
            log_sent(&title, subtitle.as_deref(), &message);
            return;
        }
        if try_terminal_notifier(&title, subtitle.as_deref(), &message, click_url) {
            log_sent(&title, subtitle.as_deref(), &message);
            return;
        }
        if click_url.is_some() {
            tracing::debug!(
                "click-through URL not supported on osascript path; install terminal-notifier (brew) for click-through support"
            );
        }
        try_osascript(&title, subtitle.as_deref(), &message);
    }

    #[cfg(target_os = "linux")]
    {
        let combined = match subtitle.as_deref() {
            Some(s) if !s.is_empty() => format!("{s}\n{message}"),
            _ => message.clone(),
        };
        match std::process::Command::new("notify-send")
            .args([title.as_str(), combined.as_str()])
            .output()
        {
            Ok(out) if !out.status.success() => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing::warn!(
                    cmd = "notify-send",
                    exit = out.status.code().unwrap_or(-1),
                    stderr = %stderr.trim(),
                    "subprocess failed"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(cmd = "notify-send", error = %e, "subprocess spawn failed");
            }
        }
    }

    // Terminal bell as universal fallback
    eprint!("\x07");

    log_sent(&title, subtitle.as_deref(), &message);
}

fn log_sent(title: &str, subtitle: Option<&str>, message: &str) {
    tracing::info!(
        title = title,
        subtitle = subtitle.unwrap_or(""),
        message = message,
        "notification sent",
    );
}

/// Strip control characters (including newlines/tabs) that break AppleScript
/// string literals. Keep spaces.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect()
}

#[cfg(target_os = "macos")]
fn try_custom_notifier(title: &str, subtitle: Option<&str>, message: &str) -> bool {
    let Ok(path) = std::env::var("EMBER_NOTIFIER") else {
        return false;
    };
    let mut cmd = std::process::Command::new(&path);
    cmd.args(["-title", title, "-message", message]);
    if let Some(s) = subtitle.filter(|s| !s.is_empty()) {
        cmd.args(["-subtitle", s]);
    }
    let Ok(status) = cmd.status() else {
        tracing::warn!(path = %path, "EMBER_NOTIFIER configured but failed to spawn");
        return false;
    };
    status.success()
}

#[cfg(target_os = "macos")]
fn try_terminal_notifier(
    title: &str,
    subtitle: Option<&str>,
    message: &str,
    click_url: Option<&str>,
) -> bool {
    // Look up `terminal-notifier` on PATH; skip without warning if absent —
    // that's the common case and we fall back cleanly.
    let mut cmd = std::process::Command::new("terminal-notifier");
    cmd.args(["-title", title, "-message", message]);
    if let Some(s) = subtitle.filter(|s| !s.is_empty()) {
        cmd.args(["-subtitle", s]);
    }
    if let Some(url) = click_url {
        cmd.args(["-open", url]);
    }
    let Ok(status) = cmd.status() else {
        return false;
    };
    status.success()
}

#[cfg(target_os = "macos")]
fn try_osascript(title: &str, subtitle: Option<&str>, message: &str) {
    // AppleScript escape: backslash and double-quote.
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    // `display notification` supports: "BODY" with title "TITLE" subtitle "SUB".
    let script = match subtitle.filter(|s| !s.is_empty()) {
        Some(s) => format!(
            "display notification \"{}\" with title \"{}\" subtitle \"{}\"",
            escape(message),
            escape(title),
            escape(s),
        ),
        None => format!(
            "display notification \"{}\" with title \"{}\"",
            escape(message),
            escape(title),
        ),
    };
    match std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
    {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::warn!(
                exit = out.status.code().unwrap_or(-1),
                stderr = %stderr.trim(),
                "osascript notification failed — did you grant Script Editor notification permission in System Settings > Notifications? Install terminal-notifier (brew) for a more reliable path."
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "osascript spawn failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize("hello\nworld"), "helloworld");
        assert_eq!(sanitize("a\tb"), "ab");
        assert_eq!(sanitize("normal text"), "normal text");
    }

    #[test]
    fn sanitize_keeps_unicode() {
        assert_eq!(sanitize("naïve résumé"), "naïve résumé");
    }
}
