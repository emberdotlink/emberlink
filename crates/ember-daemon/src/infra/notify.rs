use std::path::Path;

#[cfg(target_os = "macos")]
const EMBER_ENABLE_LEGACY_MACOS_NOTIFIER_ENV: &str = "EMBER_ENABLE_LEGACY_MACOS_NOTIFIER";

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacosNotificationPolicy {
    CustomOnly,
    LegacyFallbackAllowed,
    BellOnly,
}

/// Errors returned by [`validate_notifier_path`].
#[derive(Debug)]
pub enum NotifyError {
    RelativePath,
    DotDotComponent,
    NotFound,
    NotAFile,
    NotExecutable,
    WorldWritable,
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::RelativePath => write!(f, "EMBER_NOTIFIER path must be absolute"),
            NotifyError::DotDotComponent => {
                write!(f, "EMBER_NOTIFIER path must not contain '..' components")
            }
            NotifyError::NotFound => write!(f, "EMBER_NOTIFIER path does not exist"),
            NotifyError::NotAFile => write!(f, "EMBER_NOTIFIER path is not a regular file"),
            NotifyError::NotExecutable => {
                write!(f, "EMBER_NOTIFIER path does not have execute permission")
            }
            NotifyError::WorldWritable => {
                write!(f, "EMBER_NOTIFIER path is world-writable (unsafe)")
            }
        }
    }
}

/// Validate that `path` is safe to use as the `EMBER_NOTIFIER` binary.
///
/// Checks (in order):
/// 1. Must be an absolute path.
/// 2. Must not contain `..` components.
/// 3. Must exist on disk.
/// 4. Must be a regular file.
/// 5. Must have at least one execute bit set.
/// 6. Must NOT be world-writable.
#[cfg(unix)]
pub fn validate_notifier_path(path: &Path) -> Result<(), NotifyError> {
    use std::os::unix::fs::PermissionsExt;

    if !path.is_absolute() {
        return Err(NotifyError::RelativePath);
    }

    for component in path.components() {
        use std::path::Component;
        if matches!(component, Component::ParentDir) {
            return Err(NotifyError::DotDotComponent);
        }
    }

    let meta = std::fs::metadata(path).map_err(|_| NotifyError::NotFound)?;

    if !meta.is_file() {
        return Err(NotifyError::NotAFile);
    }

    let mode = meta.permissions().mode();

    // At least one of owner/group/other execute bits must be set.
    if mode & 0o111 == 0 {
        return Err(NotifyError::NotExecutable);
    }

    // World-writable: other write bit (bit 1 in the "other" triad).
    if mode & 0o002 != 0 {
        return Err(NotifyError::WorldWritable);
    }

    Ok(())
}

/// Send a desktop notification. Best-effort — failures are logged but not fatal.
///
/// ## macOS notifier selection (in order):
///
/// 1. `EMBER_NOTIFIER` env var — path to a custom notifier binary, called
///    as `<path> --title <title> --message <message>` (terminal-notifier
///    compatible).
/// 2. Bell + log only — default when no custom notifier is configured.
///    This avoids the legacy `terminal-notifier` / `osascript` macOS
///    surface, which produced stale system-style approval banners.
/// 3. `terminal-notifier` / `osascript` — legacy fallback, opt-in only via
///    `EMBER_ENABLE_LEGACY_MACOS_NOTIFIER=1`.
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
    let mut delivered = false;

    #[cfg(target_os = "macos")]
    {
        match macos_notification_policy(
            std::env::var_os("EMBER_NOTIFIER").is_some(),
            std::env::var(EMBER_ENABLE_LEGACY_MACOS_NOTIFIER_ENV)
                .ok()
                .as_deref(),
        ) {
            MacosNotificationPolicy::CustomOnly => {
                delivered = try_custom_notifier(&title, subtitle.as_deref(), &message);
                if !delivered {
                    tracing::warn!(
                        env = EMBER_ENABLE_LEGACY_MACOS_NOTIFIER_ENV,
                        "EMBER_NOTIFIER is configured but did not deliver; skipping legacy macOS desktop notification fallback"
                    );
                }
            }
            MacosNotificationPolicy::LegacyFallbackAllowed => {
                delivered = try_terminal_notifier(&title, subtitle.as_deref(), &message, click_url);
                if !delivered {
                    if click_url.is_some() {
                        tracing::debug!(
                            "click-through URL not supported on osascript path; install terminal-notifier (brew) for click-through support"
                        );
                    }
                    delivered = try_osascript(&title, subtitle.as_deref(), &message);
                }
            }
            MacosNotificationPolicy::BellOnly => {
                tracing::info!(
                    env = EMBER_ENABLE_LEGACY_MACOS_NOTIFIER_ENV,
                    "legacy macOS desktop notification fallback disabled; configure EMBER_NOTIFIER for a real desktop surface or set EMBER_ENABLE_LEGACY_MACOS_NOTIFIER=1 to opt back in temporarily"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        delivered = try_notify_send(&title, subtitle.as_deref(), &message);
    }

    if delivered {
        log_sent(&title, subtitle.as_deref(), &message);
    } else {
        eprint!("\x07");
        tracing::info!(
            title = title,
            subtitle = subtitle.as_deref().unwrap_or(""),
            message = message,
            "notification fell back to bell/log only",
        );
    }
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
    s.chars().filter(|c| !c.is_control() || *c == ' ').collect()
}

#[cfg(target_os = "macos")]
fn macos_notification_policy(
    custom_notifier_configured: bool,
    legacy_opt_in_raw: Option<&str>,
) -> MacosNotificationPolicy {
    if custom_notifier_configured {
        MacosNotificationPolicy::CustomOnly
    } else if legacy_opt_in_raw == Some("1") {
        MacosNotificationPolicy::LegacyFallbackAllowed
    } else {
        MacosNotificationPolicy::BellOnly
    }
}

#[cfg(target_os = "macos")]
fn try_custom_notifier(title: &str, subtitle: Option<&str>, message: &str) -> bool {
    let Ok(path_str) = std::env::var("EMBER_NOTIFIER") else {
        return false;
    };
    let path = std::path::Path::new(&path_str);
    if let Err(e) = validate_notifier_path(path) {
        tracing::warn!(path = %path_str, error = %e, "EMBER_NOTIFIER validation failed — skipping notification");
        return false;
    }
    let mut cmd = std::process::Command::new(path);
    cmd.args(["-title", title, "-message", message]);
    if let Some(s) = subtitle.filter(|s| !s.is_empty()) {
        cmd.args(["-subtitle", s]);
    }
    let Ok(status) = cmd.status() else {
        tracing::warn!(path = %path_str, "EMBER_NOTIFIER configured but failed to spawn");
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
fn try_osascript(title: &str, subtitle: Option<&str>, message: &str) -> bool {
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
            false
        }
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(error = %e, "osascript spawn failed");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn try_notify_send(title: &str, subtitle: Option<&str>, message: &str) -> bool {
    let combined = match subtitle {
        Some(s) if !s.is_empty() => format!("{s}\n{message}"),
        _ => message.to_string(),
    };
    match std::process::Command::new("notify-send")
        .args([title, combined.as_str()])
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
            false
        }
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(cmd = "notify-send", error = %e, "subprocess spawn failed");
            false
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

    #[cfg(target_os = "macos")]
    mod macos_policy {
        use super::super::{MacosNotificationPolicy, macos_notification_policy};

        #[test]
        fn defaults_to_bell_only_without_custom_notifier_or_opt_in() {
            assert_eq!(
                macos_notification_policy(false, None),
                MacosNotificationPolicy::BellOnly
            );
        }

        #[test]
        fn opt_in_reenables_legacy_macos_fallbacks() {
            assert_eq!(
                macos_notification_policy(false, Some("1")),
                MacosNotificationPolicy::LegacyFallbackAllowed
            );
        }

        #[test]
        fn custom_notifier_beats_legacy_opt_in() {
            assert_eq!(
                macos_notification_policy(true, Some("1")),
                MacosNotificationPolicy::CustomOnly
            );
        }
    }

    #[cfg(unix)]
    mod validate_notifier {
        use super::super::validate_notifier_path;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn validate_rejects_relative_path() {
            let path = std::path::Path::new("relative/path/to/notifier");
            assert!(validate_notifier_path(path).is_err());
        }

        #[test]
        fn validate_rejects_dotdot_in_path() {
            let path = std::path::Path::new("/usr/local/../bin/notifier");
            assert!(validate_notifier_path(path).is_err());
        }

        #[test]
        fn validate_rejects_nonexistent_path() {
            let path = std::path::Path::new("/absolutely/does/not/exist/notifier-xyz");
            assert!(validate_notifier_path(path).is_err());
        }

        #[test]
        fn validate_rejects_world_writable_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file_path = dir.path().join("notifier");
            std::fs::write(&file_path, b"#!/bin/sh\n").expect("write");
            // 0o666 = rw-rw-rw- (world-writable, no execute)
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o666))
                .expect("chmod");
            assert!(validate_notifier_path(&file_path).is_err());
        }

        #[test]
        fn validate_accepts_safe_executable() {
            let dir = tempfile::tempdir().expect("tempdir");
            let file_path = dir.path().join("notifier");
            std::fs::write(&file_path, b"#!/bin/sh\n").expect("write");
            // 0o755 = rwxr-xr-x
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            assert!(validate_notifier_path(&file_path).is_ok());
        }
    }
}
