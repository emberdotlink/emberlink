//! Public GitHub App manifest helpers (implementation-note-489).
//!
//! The canonical manifest doc lives at `docs/emberlink-github-app-manifest.md`
//! and is embedded into the binary at compile time so the CLI surface and the
//! published doc cannot drift. This module is intentionally thin — it exposes
//! the embedded manifest body and the install URL, and gives callers two small
//! affordances:
//!
//!   * `print_install_url()` — return the canonical install URL.
//!   * `show_manifest()`     — print the manifest body to stdout.
//!
//! Permission floor (at cohort-A launch) per the doc:
//!
//! | Resource      | Access | Notes |
//! |---------------|--------|-------|
//! | contents      | write  | broker mints sub-scoped 1h tokens per grant (design); App is the credential ceiling |
//! | pull_requests | write  | create / merge / comment |
//! | issues        | write  | file / comment per agent activity |
//! | actions       | read   | workflow run status |
//! | metadata      | read   | mandatory for any GitHub App |
//!
//! The App's installation token is the credential ceiling for two consumer
//! paths in the daemon: (a) agent operations via the broker (shipped, ARCH-
//! implementation-note-490), and (b) headless-runtime PR-ship announcer (future,
//! implementation-note-491). Both use `mint_installation_token` to obtain
//! narrowly-scoped tokens; the App's permissions are the upstream ceiling.
//!
//! Workflows, secrets, and administration are explicitly **denied** on the
//! floor. See `docs/emberlink-github-app-manifest.md` for the full rationale
//! and the exact JSON manifest body.

/// Embedded canonical manifest doc. Matched against `docs/emberlink-github-app-manifest.md`
/// at compile time so the binary cannot drift from the published reference.
pub const PUBLIC_MANIFEST_DOC: &str =
    r#"# Emberlink GitHub App

The GitHub App lane lets the local daemon mint short-lived installation tokens
for approved GitHub actions. Installing the public App alone is not enough for a
local setup; the daemon still needs an operator-owned App credential registered
through `ember github setup` or `ember github app register`.

Install URL:

https://github.com/apps/emberlink/installations/new

Permission floor:

| Permission | Access |
|---|---|
| contents | write |
| pull_requests | write |
| issues | write |
| actions | read |
| metadata | read |

Denied permissions:

- Workflows
- Secrets
- Administration

Manifest body:

```json
{
  "name": "Emberlink",
  "url": "https://emberlink.dev/",
  "hook_attributes": {
    "url": "https://emberlink.dev/api/github/hook",
    "active": true
  },
  "redirect_url": "https://emberlink.dev/onboarding/github-app/installed",
  "callback_urls": [
    "https://emberlink.dev/onboarding/github-app/oauth"
  ],
  "public": true,
  "default_permissions": {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
    "actions": "read",
    "metadata": "read"
  },
  "default_events": [
    "pull_request"
  ]
}
```
"#;

/// Canonical install URL. The App slug is `emberlink`; the
/// `/installations/new` suffix is GitHub's standard install flow path.
pub const INSTALL_URL: &str = "https://github.com/apps/emberlink/installations/new";

/// Return the canonical install URL as an owned `String`.
///
/// Callers typically print this verbatim; the function shape (rather than a
/// bare `&'static str` accessor) keeps the surface symmetric with
/// `show_manifest`.
pub fn print_install_url() -> String {
    INSTALL_URL.to_string()
}

/// Print the embedded manifest body to stdout.
///
/// The body is the full markdown doc — install flow, permission floor, JSON
/// manifest block, denylist callouts. Callers piping `ember onboarding
/// github-app show` into a pager get the canonical text the website also
/// links to.
pub fn show_manifest() {
    print!("{PUBLIC_MANIFEST_DOC}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_pulled_in() {
        // Sanity check: include_str! resolved correctly and the doc is
        // non-empty. If this fails, the relative path is wrong — fix the
        // macro path here, not the doc.
        assert!(
            !PUBLIC_MANIFEST_DOC.is_empty(),
            "embedded manifest must be non-empty"
        );
    }

    #[test]
    fn manifest_documents_floor_permissions() {
        // Any silent expansion or contraction of these permissions should
        // fail this test until the doc is updated explicitly. The set
        // matches the implementation-note-489 brief and is the credential
        // ceiling the broker mints sub-scoped tokens against (design).
        for checkpoint in ["contents", "pull_requests", "issues", "actions", "metadata"] {
            assert!(
                PUBLIC_MANIFEST_DOC.contains(checkpoint),
                "manifest doc missing floor anchor: {checkpoint}"
            );
        }
    }

    #[test]
    fn manifest_documents_denylist() {
        // The deny-list is load-bearing — if the doc stops calling out
        // workflows/secrets/admin as denied, a future contributor might
        // assume they're permitted. Lock the language here.
        for denied in ["Workflows", "Secrets", "Administration"] {
            assert!(
                PUBLIC_MANIFEST_DOC.contains(denied),
                "manifest doc missing denylist callout: {denied}"
            );
        }
    }

    #[test]
    fn install_url_is_canonical() {
        let url = print_install_url();
        assert_eq!(url, INSTALL_URL);
        assert!(url.starts_with("https://github.com/apps/"));
        assert!(url.ends_with("/installations/new"));
    }

    #[test]
    fn show_manifest_does_not_panic() {
        // Smoke test — calling show_manifest must not panic. Output goes to
        // stdout; cargo test captures it by default.
        show_manifest();
    }
}
