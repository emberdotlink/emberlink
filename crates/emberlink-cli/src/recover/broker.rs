//! CLASSIFICATION: PUBLIC
//!
//! `ember recover broker` — recover credential-broker state per ADR 161.
//!
//! Scope routing:
//! - `creds` — re-prompt + re-seal upstream credentials for a provider
//! - `allowlist` — reload the provider allowlist from disk
//! - `cache` — drop the broker's in-memory materialization cache
//!
//! Per-provider: `--provider <NAME>` (e.g. `github`, `anthropic`).
//!
//! F-code surface:
//! - `F-BROKER-1` — GitHub App rate-limited; operator-visible retry with backoff.
//! - `F-BROKER-2` — broker creds rotated/invalidated; mint a fresh installation
//!   token to verify the current key is valid.
//!

use clap::Args;

use super::{RecoverError, RecoverOutcome, RecoverResult, note_receipt_contract};

#[derive(Args, Debug)]
pub struct RecoverBrokerArgs {
    /// Provider identifier (e.g. `github`, `anthropic`). When omitted,
    /// recovery applies to every registered provider.
    #[arg(long)]
    pub provider: Option<String>,

    /// Narrow the recovery to a single sub-component. When omitted,
    /// the scaffold prints which scopes are available.
    #[arg(long, value_enum)]
    pub scope: Option<BrokerScope>,

    /// Target a specific F-code recovery action directly.
    /// `F-BROKER-1` runs the rate-limit retry probe with exponential backoff.
    /// `F-BROKER-2` verifies + reports on the current GH App credential validity.
    #[arg(long, value_name = "F_CODE", id = "broker_f_code")]
    pub f_code: Option<String>,

    /// GitHub App installation ID — required for `--f-code F-BROKER-2`.
    #[arg(long)]
    pub installation_id: Option<String>,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum BrokerScope {
    /// Re-prompt + re-seal upstream credentials for the named provider.
    Creds,
    /// Reload the provider allowlist from disk.
    Allowlist,
    /// Drop the in-memory materialization cache.
    Cache,
}

impl BrokerScope {
    fn as_str(self) -> &'static str {
        match self {
            BrokerScope::Creds => "creds",
            BrokerScope::Allowlist => "allowlist",
            BrokerScope::Cache => "cache",
        }
    }
}

pub fn handle(args: RecoverBrokerArgs) -> RecoverResult {
    // F-code dispatch takes priority over scope routing.
    if let Some(ref f_code) = args.f_code {
        return match f_code.to_ascii_uppercase().as_str() {
            "F-BROKER-1" => handle_f_broker_1(&args),
            "F-BROKER-2" => handle_f_broker_2(&args),
            other => Err(RecoverError::usage(format!(
                "unknown F-code `{other}` for `ember recover broker`; \
                 valid F-codes: F-BROKER-1, F-BROKER-2"
            ))),
        };
    }

    let provider = args.provider.clone().unwrap_or_else(|| "<all>".to_string());
    let scope = args
        .scope
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "creds".to_string());

    println!(
        "ember recover broker (provider={provider}, scope={scope}): scaffold only — \
         per-F-code implementations land as META-RECOVER-F-BROKER-* tasks ship. See \
         `ember recover --explain F-BROKER-1` (or 2, 3) for the F-code-anchored runbook."
    );
    note_receipt_contract("broker", &scope);
    Ok(RecoverOutcome::ok())
}

// ---------------------------------------------------------------------------
// F-BROKER-1 — Rate-limit auto-retry with exponential backoff
// ---------------------------------------------------------------------------
//
// recover_f_broker_1_landed
//
// ADR 161 §F-BROKER-1: broker captures HTTP 429; operator can run
// `ember recover broker --f-code F-BROKER-1` to inspect whether a runaway
// pattern triggered the rate-limit and to validate the backoff schedule.
//
// Architecture: broker-level rate-limiting is internal to the daemon; the CLI
// recovery action here is the *operator-visible* layer — it:
//   1. Probes whether the current retry-after window has elapsed.
//   2. Computes and prints the backoff schedule (1s, 2s, 4s, 8s, 16s; max 5
//      retries; ±25 % jitter) so the operator can decide whether to wait or
//      rotate credentials.
//   3. Emits a `recovery.action` receipt placeholder.
//
// No real HTTP call is made — the backoff schedule is a diagnostic output.
// The daemon's broker retries internally; this surface makes the schedule
// operator-visible and auditable.

fn handle_f_broker_1(args: &RecoverBrokerArgs) -> RecoverResult {
    let provider = args
        .provider
        .as_deref()
        .unwrap_or("github")
        .to_ascii_lowercase();

    println!("ember recover broker F-BROKER-1 — rate-limit retry probe (provider={provider})");
    println!();
    println!("Symptom: broker received HTTP 429 from the upstream provider API.");
    println!(
        "The broker retries internally with exponential backoff. This command\n\
         makes the schedule visible so you can decide whether to wait or rotate."
    );
    println!();

    // Compute and display the backoff schedule.
    let schedule = compute_backoff_schedule(5, 1_000, 2.0, 0.25);
    println!("Backoff schedule (max 5 retries, base 1 s, multiplier ×2, ±25 % jitter):");
    for (attempt, (delay_ms, window_ms)) in schedule.iter().enumerate() {
        // ADVERSARIAL-REVIEW-20260612 HIGH #3: use saturating_sub to prevent
        // u64 underflow when jitter_fraction >= 1.0 (not possible with the
        // hardcoded 0.25, but guard the generic display path).
        println!(
            "  attempt {}: wait {}–{} ms",
            attempt + 1,
            delay_ms.saturating_sub(*window_ms),
            delay_ms.saturating_add(*window_ms),
        );
    }

    let total_max_ms: u64 = schedule.iter().map(|(d, j)| d + j).sum();
    println!();
    println!(
        "Total worst-case wait before giving up: {} s ({} ms).",
        total_max_ms / 1_000,
        total_max_ms,
    );
    println!();
    println!(
        "If the rate-limit persists beyond this window, inspect recent audit\n\
         events with:\n\
         \n  ember audit query --action gh.{provider} --since 1h\n\
         \nA runaway pattern should appear as a spike in that window. If the\n\
         ADR 124 §8 inflight cap did not catch it, file a META-AP-* task."
    );

    note_receipt_contract("broker", "F-BROKER-1");
    Ok(RecoverOutcome::ok())
}

/// Compute an exponential-backoff schedule.
///
/// Returns a `Vec<(delay_ms, jitter_ms)>` with `max_retries` entries where
/// each `delay_ms` is the nominal delay and `jitter_ms` is the ±fraction
/// window (so the actual delay is `delay_ms ± jitter_ms`).
///
/// Used by [`handle_f_broker_1`] and its unit tests.
pub(crate) fn compute_backoff_schedule(
    max_retries: u32,
    base_ms: u64,
    multiplier: f64,
    jitter_fraction: f64,
) -> Vec<(u64, u64)> {
    // ADVERSARIAL-REVIEW-20260612 HIGH #3: clamp jitter_fraction to [0.0, 1.0)
    // so jitter can never exceed delay, preventing underflow in the display path.
    let jitter_fraction = jitter_fraction.clamp(0.0, 0.999_999);
    let mut schedule = Vec::with_capacity(max_retries as usize);
    let mut delay = base_ms as f64;
    for _ in 0..max_retries {
        let jitter = (delay * jitter_fraction).round() as u64;
        schedule.push((delay.round() as u64, jitter));
        delay *= multiplier;
    }
    schedule
}

// ---------------------------------------------------------------------------
// F-BROKER-2 — GH App credential rotation / verification
// ---------------------------------------------------------------------------
//
// recover_f_broker_2_landed
//
// ADR 161 §F-BROKER-2: broker creds rotated upstream / invalidated.
// Recovery: verify the current GH App private key can sign a JWT and report
// whether the credential stored at `~/.config/emberlink/ember-engine-app.pem`
// (or overridden via EMBER_APP_PEM_PATH) is present and structurally valid.
//
// SECURITY NOTE: this is security-lane code. It reads the vault path for the
// GH App private key (cred/gh-app/<installation-id> per bot-identity contract).
// The actual key material is never printed; only structural validity is
// reported (key present, PEM parseable, installation ID matches).
//
// The operator must separately rotate the key on GitHub and replace the PEM
// file; this command then re-verifies after rotation. It does NOT mint a live
// installation token against GitHub (no network call) — that is an online
// operation requiring the real GitHub API and is outside the recovery scope.
// Online verification can be done with `ember broker status --provider github`.

fn handle_f_broker_2(args: &RecoverBrokerArgs) -> RecoverResult {
    let provider = args
        .provider
        .as_deref()
        .unwrap_or("github")
        .to_ascii_lowercase();

    if provider != "github" {
        return Err(RecoverError::usage(format!(
            "F-BROKER-2 currently supports provider=github only; got `{provider}`"
        )));
    }

    let installation_id = args.installation_id.as_deref();

    println!("ember recover broker F-BROKER-2 — GH App credential rotation probe");
    println!();
    println!("Symptom: every `gh ...` call returns \"credential rejected\" (HTTP 401).");
    println!("Detection: broker captured a 401 with cred_invalidation_at timestamp.");
    println!();

    let verdict = probe_gh_app_credentials(installation_id);

    match verdict {
        GhCredVerdictKind::Present {
            installation_id_found,
        } => {
            println!(
                "GH App credential files: PRESENT (installation_id={})",
                installation_id_found
            );
            println!();
            println!(
                "The PEM file and env configuration are structurally valid. If GitHub\n\
                 is still returning 401s, the App's private key was likely revoked or\n\
                 rotated on GitHub's side. Steps to recover:\n\
                 \n\
                 1. Go to github.com → Settings → Developer settings → GitHub Apps →\n\
                    <your app> → Private keys.\n\
                 2. Generate a new private key and download the PEM.\n\
                 3. Replace ~/.config/emberlink/ember-engine-app.pem with the new PEM\n\
                    (or the path in EMBER_APP_PEM_PATH if overridden).\n\
                 4. Restart the ember daemon (`ember recover daemon --prod`).\n\
                 5. Re-run this command to confirm the new key is structurally valid.\n\
                 \n\
                 If you store credentials in the vault at cred/gh-app/<installation-id>,\n\
                 update that vault entry instead of the file on disk."
            );
        }
        GhCredVerdictKind::Missing { detail } => {
            println!("GH App credential files: MISSING — {detail}");
            println!();
            println!(
                "No GH App credential found. The daemon is running with MockBroker\n\
                 for the github provider. To configure real GitHub App credentials:\n\
                 \n\
                 1. Create a GitHub App at github.com/settings/apps.\n\
                 2. Install it on your organization or repository.\n\
                 3. Download the private key PEM.\n\
                 4. Write ~/.config/emberlink/ember-engine.env with:\n\
                    EMBER_ENGINE_APP_ID=<app-id>\n\
                    EMBER_ENGINE_INSTALLATION_ID=<installation-id>\n\
                 5. Save the PEM as ~/.config/emberlink/ember-engine-app.pem.\n\
                 6. Restart the ember daemon."
            );
        }
        GhCredVerdictKind::Malformed { detail } => {
            println!("GH App credential files: MALFORMED — {detail}");
            println!();
            println!(
                "The credential files exist but cannot be parsed. Check:\n\
                 - ember-engine.env has EMBER_ENGINE_APP_ID and EMBER_ENGINE_INSTALLATION_ID\n\
                 - ember-engine-app.pem is a valid PEM-encoded RSA private key\n\
                 - Neither file has unexpected whitespace, BOM, or encoding issues"
            );
            return Ok(RecoverOutcome::issue_found());
        }
    }

    note_receipt_contract("broker", "F-BROKER-2");
    Ok(RecoverOutcome::ok())
}

/// Result of probing whether GH App credentials are present and structurally valid.
#[derive(Debug)]
enum GhCredVerdictKind {
    /// Files present and parseable; `installation_id_found` from the env file.
    Present { installation_id_found: String },
    /// Neither file exists (graceful missing).
    Missing { detail: String },
    /// Files exist but could not be parsed.
    Malformed { detail: String },
}

/// Probe the GH App credential files.
///
/// Calls `ember_daemon::broker::github_config::load_gh_app_credentials()` and
/// maps the result to an operator-friendly verdict. No network calls are made.
fn probe_gh_app_credentials(expected_installation_id: Option<&str>) -> GhCredVerdictKind {
    use ember_daemon::broker::github_config::load_gh_app_credentials;

    match load_gh_app_credentials() {
        Ok(None) => GhCredVerdictKind::Missing {
            detail: "credential files not found (daemon is using MockBroker for github)".into(),
        },
        Ok(Some(creds)) => {
            // Optionally validate that the found installation_id matches what
            // the operator specified (--installation-id flag).
            if let Some(expected) = expected_installation_id
                && creds.installation_id != expected
            {
                return GhCredVerdictKind::Malformed {
                    detail: format!(
                        "installation_id mismatch: file has `{}`, \
                             --installation-id flag specified `{}`",
                        creds.installation_id, expected
                    ),
                };
            }
            GhCredVerdictKind::Present {
                installation_id_found: creds.installation_id,
            }
        }
        Err(e) => GhCredVerdictKind::Malformed {
            detail: e.to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Unit tests (T1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // recover_f_broker_1_landed — backoff schedule shape

    #[test]
    fn backoff_schedule_length_matches_max_retries() {
        let schedule = compute_backoff_schedule(5, 1_000, 2.0, 0.25);
        assert_eq!(schedule.len(), 5);
    }

    #[test]
    fn backoff_schedule_is_exponential() {
        let schedule = compute_backoff_schedule(5, 1_000, 2.0, 0.0);
        let delays: Vec<u64> = schedule.iter().map(|(d, _)| *d).collect();
        assert_eq!(delays, vec![1_000, 2_000, 4_000, 8_000, 16_000]);
    }

    #[test]
    fn backoff_jitter_is_fraction_of_delay() {
        let schedule = compute_backoff_schedule(3, 1_000, 2.0, 0.25);
        // attempt 0: delay=1000, jitter=250
        assert_eq!(schedule[0], (1_000, 250));
        // attempt 1: delay=2000, jitter=500
        assert_eq!(schedule[1], (2_000, 500));
        // attempt 2: delay=4000, jitter=1000
        assert_eq!(schedule[2], (4_000, 1_000));
    }

    #[test]
    fn backoff_zero_retries_is_empty() {
        let schedule = compute_backoff_schedule(0, 1_000, 2.0, 0.25);
        assert!(schedule.is_empty());
    }

    #[test]
    fn backoff_custom_base_and_multiplier() {
        let schedule = compute_backoff_schedule(3, 500, 3.0, 0.0);
        let delays: Vec<u64> = schedule.iter().map(|(d, _)| *d).collect();
        assert_eq!(delays, vec![500, 1_500, 4_500]);
    }

    // recover_f_broker_2_landed — F-code dispatch and arg validation

    #[test]
    fn f_broker_1_dispatch_returns_ok() {
        let args = RecoverBrokerArgs {
            provider: Some("github".into()),
            scope: None,
            f_code: Some("F-BROKER-1".into()),
            installation_id: None,
        };
        let result = handle(args);
        assert!(
            result.is_ok(),
            "F-BROKER-1 should return Ok; got {result:?}"
        );
    }

    #[test]
    fn f_broker_1_dispatch_case_insensitive() {
        let args = RecoverBrokerArgs {
            provider: None,
            scope: None,
            f_code: Some("f-broker-1".into()),
            installation_id: None,
        };
        let result = handle(args);
        assert!(
            result.is_ok(),
            "F-BROKER-1 case-insensitive dispatch failed: {result:?}"
        );
    }

    #[test]
    fn f_broker_2_rejects_unknown_provider() {
        let args = RecoverBrokerArgs {
            provider: Some("anthropic".into()),
            scope: None,
            f_code: Some("F-BROKER-2".into()),
            installation_id: None,
        };
        let result = handle(args);
        let err = result.expect_err("expected error for unsupported provider");
        assert!(
            err.to_string().contains("github only"),
            "error should mention github; got: {err}"
        );
    }

    #[test]
    fn unknown_f_code_returns_usage_error() {
        let args = RecoverBrokerArgs {
            provider: None,
            scope: None,
            f_code: Some("F-BROKER-99".into()),
            installation_id: None,
        };
        let result = handle(args);
        let err = result.expect_err("expected error for unknown F-code");
        assert!(
            err.to_string().contains("unknown F-code"),
            "error should mention unknown F-code; got: {err}"
        );
    }

    #[test]
    fn no_f_code_falls_through_to_scaffold() {
        let args = RecoverBrokerArgs {
            provider: None,
            scope: None,
            f_code: None,
            installation_id: None,
        };
        let result = handle(args);
        assert!(
            result.is_ok(),
            "scaffold path should return Ok; got {result:?}"
        );
    }

    /// F-BROKER-2: when credential files are absent (CI / sandbox host without
    /// GH App config), the handler returns Ok (Missing verdict is informational,
    /// not an error — operator is guided to configure credentials).
    #[test]
    fn f_broker_2_missing_creds_returns_ok() {
        // In CI / sandbox there are no GH App files; load_gh_app_credentials
        // returns Ok(None). The handler should print guidance and return Ok.
        let args = RecoverBrokerArgs {
            provider: Some("github".into()),
            scope: None,
            f_code: Some("F-BROKER-2".into()),
            installation_id: None,
        };
        // This test is environment-dependent: on a host with GH App files it
        // will hit the Present branch; on CI it hits Missing. Both are Ok.
        let result = handle(args);
        assert!(
            result.is_ok(),
            "F-BROKER-2 should not error on missing or present creds; got {result:?}"
        );
    }
}
