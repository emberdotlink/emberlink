//! CLASSIFICATION: PUBLIC
//! Bounded INI parser for `.git/config` — resolves a remote's URL by name.
//!
//! META-ARCH-DCC-4-GITCONFIG-READER — Phase 2 subtask of
//! META-ARCH-DAEMON-CONTROLLED-CONFIG. Used by DCC-6 (HTTPS dispatch) at
//! credential-injection time to verify the binding's stored URL matches what
//! the user's `.git/config` actually says for the target remote.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum GitConfigError {
    #[error("no .git/config at {0:?}")]
    NotFound(std::path::PathBuf),
    #[error(".git/config too large ({0} bytes; cap 4096)")]
    TooLarge(u64),
    #[error("[include] directive refused (line {0})")]
    IncludeDirectivePresent(usize),
    #[error("non-ASCII content at byte {0}")]
    NonAsciiContent(usize),
    #[error("[remote {0:?}] block not found")]
    RemoteNotFound(String),
    #[error("[remote {0:?}] has no url = ... line")]
    UrlMissing(String),
    #[error("parse failed: {0}")]
    ParseFailed(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads `<working_tree_root>/.git/config` and returns the URL declared
/// for the named remote (e.g. "origin"). Refuses any input that:
/// - Has `[include]` or `[includeIf]` directives (security gate)
/// - Exceeds 4096 bytes (length cap)
/// - Contains any non-ASCII byte
///
/// Does NOT parse the URL beyond returning it as a String — URL grammar
/// validation is downstream of this function.
pub fn read_remote_url_from_gitconfig(
    working_tree_root: &Path,
    remote_name: &str,
) -> Result<String, GitConfigError> {
    let config_path = working_tree_root.join(".git").join("config");

    // Check existence before metadata to give the right error variant.
    if !config_path.exists() {
        return Err(GitConfigError::NotFound(config_path));
    }

    // Size gate — refuse before reading.
    let meta = std::fs::metadata(&config_path)?;
    let file_size = meta.len();
    if file_size > 4096 {
        return Err(GitConfigError::TooLarge(file_size));
    }

    // Read as bytes and scan for non-ASCII.
    let bytes = std::fs::read(&config_path)?;
    for (i, &b) in bytes.iter().enumerate() {
        if b > 0x7F {
            return Err(GitConfigError::NonAsciiContent(i));
        }
    }

    // Safe to treat as ASCII/UTF-8 now.
    let content = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => return Err(GitConfigError::ParseFailed(e.to_string())),
    };

    // Security gate: refuse [include] and [includeIf] before any further parsing.
    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("[include]") || lower.starts_with("[includei") {
            return Err(GitConfigError::IncludeDirectivePresent(line_idx + 1));
        }
    }

    // Hand-rolled INI parse: track current section, extract url from matching remote.
    let target_section = format!("[remote \"{}\"]", remote_name);
    let mut in_target = false;
    let mut found_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        // Section header detection.
        if trimmed.starts_with('[') {
            // If we were in the target section and now leaving it, the url wasn't found.
            if in_target {
                return Err(GitConfigError::UrlMissing(remote_name.to_string()));
            }
            in_target = trimmed.eq_ignore_ascii_case(&target_section);
            if in_target {
                found_section = true;
            }
            continue;
        }

        // Key-value pair inside the target section.
        if in_target
            && let Some((key, value)) = trimmed.split_once('=')
            && key.trim().eq_ignore_ascii_case("url")
        {
            return Ok(value.trim().to_string());
        }
    }

    if !found_section {
        return Err(GitConfigError::RemoteNotFound(remote_name.to_string()));
    }

    // Reached end of file while still in the target section — no url line found.
    Err(GitConfigError::UrlMissing(remote_name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_origin_url_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[remote "origin"]
    url = git@github.com:foo/bar.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"#,
        )
        .unwrap();

        let url = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap();
        assert_eq!(url, "git@github.com:foo/bar.git");
    }

    #[test]
    fn refuses_include_directive() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[include]
    path = /etc/passwd
[remote "origin"]
    url = git@github.com:foo/bar.git
"#,
        )
        .unwrap();

        let err = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap_err();
        assert!(matches!(err, GitConfigError::IncludeDirectivePresent(_)));
    }

    #[test]
    fn refuses_oversized_file() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        // 5000 bytes of comments — over the 4096 cap
        let big = "# ".to_string() + &"x".repeat(5000);
        std::fs::write(git_dir.join("config"), big).unwrap();

        let err = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap_err();
        assert!(matches!(err, GitConfigError::TooLarge(_)));
    }

    #[test]
    fn refuses_non_ascii() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        // Embed non-ASCII bytes (UTF-8 for Cyrillic "гит") directly as a byte slice.
        let content: &[u8] =
            b"[remote \"origin\"]\n    url = git@\xd0\xb3\xd0\xb8\xd1\x82hub.com:foo/bar.git\n";
        std::fs::write(git_dir.join("config"), content).unwrap();

        let err = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap_err();
        assert!(matches!(err, GitConfigError::NonAsciiContent(_)));
    }

    #[test]
    fn refuses_remote_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[remote "origin"]
    url = git@github.com:foo/bar.git
"#,
        )
        .unwrap();

        let err = read_remote_url_from_gitconfig(tmp.path(), "upstream").unwrap_err();
        assert!(matches!(err, GitConfigError::RemoteNotFound(_)));
    }

    #[test]
    fn refuses_url_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[remote "origin"]
    fetch = +refs/heads/*:refs/remotes/origin/*
"#,
        )
        .unwrap();

        let err = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap_err();
        assert!(matches!(err, GitConfigError::UrlMissing(_)));
    }

    #[test]
    fn refuses_not_found_when_no_git_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_remote_url_from_gitconfig(tmp.path(), "origin").unwrap_err();
        assert!(matches!(err, GitConfigError::NotFound(_)));
    }
}
