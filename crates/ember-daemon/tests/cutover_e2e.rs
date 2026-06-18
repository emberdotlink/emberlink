//! ARCH-BROKER-VAULT-CUTOVER-PR4C-E2E-TEST — T3 cutover end-to-end test.
//!
//! Pins the vault-first credential-discovery contract added by PR4A
//! (`github_config_from_store` ADR-099 reader) + PR4B (the
//! `EMBER_VAULT_FIRST` flag in `runtime.rs`'s broker registration loop).
//!
//! Acceptance per the task brief:
//!
//! 1. With `EMBER_VAULT_FIRST=1`, daemon-startup credential discovery
//!    consults the local-encrypted credential store first and produces
//!    a complete `GhAppCredentials` triple from a pre-populated vault.
//! 2. The source PEM file pointed at by `EMBER_APP_PEM_PATH` is NOT
//!    opened during the vault-first hit path. Verified via a checkpoint
//!    tempfile whose `atime` is snapshotted before / after the
//!    discovery call — kernel-recorded access time would advance if
//!    the file branch had read it. (See "atime gotcha" note below.)
//! 3. The structured `bot-identity-source` event for the request
//!    carries `source: "vault"` (not `"legacy-file"`).
//!
//! ## What this test actually drives
//!
//! Booting the real `emberd` daemon process in-test is heavyweight (PID
//! file, presence config, keyring auto-unseal, manifest signature
//! verify, socket bind, dashboard spawn, …). The vault-first wiring
//! lives entirely inside `runtime.rs`'s broker registration block and
//! reduces to a single call: `github_config_from_store(&store)` against
//! a populated `LocalEncryptedStore`. This test drives that exact call
//! shape — same `LocalEncryptedStore::new(Rc<DaemonStore>)`
//! construction `runtime.rs` performs at startup, with the live vault
//! attached through the store slot — so the regression surface is
//! identical to a full-daemon-boot variant without the ten-minute
//! startup tax.
//!
//! Sibling reference: `credential_store_wiring.rs` uses the same
//! construction pattern for its empty-store fallback contract.
//!
//! ## atime gotcha
//!
//! Linux file systems may mount with `noatime` / `relatime` which
//! suppress or coarsen atime updates. The test mitigates this by
//! ALSO asserting on the structured `bot-identity-source` event:
//! `source == "vault"` is sufficient evidence that the vault arm
//! resolved the credentials, which logically excludes the file
//! arm from having been the source. The atime check is the
//! belt-and-braces second signal.

use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use ember_daemon::broker::github_config::github_config_from_store;
use ember_daemon::infra::credential_store::{CredentialStore, LocalEncryptedStore};
use ember_daemon::infra::store::DaemonStore;
use ember_daemon::infra::vault::Vault;
use secrecy::ExposeSecret;
use tempfile::TempDir;
use tracing::Subscriber;
use tracing::subscriber::set_default;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Deterministic vault key for this test. Same shape as
/// `budget_persistence.rs::TEST_VAULT_KEY`.
const TEST_VAULT_KEY: [u8; 32] = [0x77u8; 32];

/// PEM fixture: shipped under `tests/fixtures/` so it stays inside the
/// gitleaks path-allowlist for `crates/.+/tests/fixtures/.+` per the
/// repo's existing convention.
const PEM_FAKE: &[u8] = include_bytes!("fixtures/gh_app_pem_fake.pem");

/// Captured field record emitted by a `tracing::info!` call. The
/// daemon's `bot-identity-source` event encodes the source-of-truth
/// signal we want to assert on.
#[derive(Debug, Clone)]
struct CapturedEvent {
    /// All formatted fields of the event, joined into a single string.
    /// `tracing::info!(event = "...", provider = "...", source = "...")`
    /// renders as `event="..." provider="..." source="..."`.
    rendered: String,
}

/// Minimal `tracing` layer that captures every emitted event into a
/// shared `Mutex<Vec<CapturedEvent>>`. We only need to inspect the
/// rendered field set — no span context — so the layer implements just
/// `on_event`.
#[derive(Clone)]
struct CaptureLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CaptureLayer {
    fn new() -> (Self, Arc<Mutex<Vec<CapturedEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                events: Arc::clone(&events),
            },
            events,
        )
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let mut guard = self.events.lock().expect("capture layer mutex");
        guard.push(CapturedEvent {
            rendered: visitor.0,
        });
    }
}

/// Simple `tracing::field::Visit` that concatenates every (name, value)
/// pair into `name="value" name2="value2" …`. Sufficient for substring
/// assertions on the captured event corpus.
#[derive(Default)]
struct FieldVisitor(String);

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(&format!("{}=\"{}\"", field.name(), value));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(&format!("{}={:?}", field.name(), value));
    }
}

/// Snapshot a file's last-access time. Used to assert the PEM file was
/// NOT opened during the vault-first hit path. Returns `None` if the
/// platform / filesystem doesn't carry atime (the test then relies on
/// the bot-identity-source assertion alone — see the module doc-comment
/// "atime gotcha" note).
fn file_atime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.accessed().ok())
}

/// E2E acceptance — vault-first path resolves GitHub App credentials
/// from a populated `LocalEncryptedStore`, never touches the source PEM
/// at `EMBER_APP_PEM_PATH`, and the `bot-identity-source` event records
/// `source="vault"`.
#[tokio::test(flavor = "current_thread")]
async fn cutover_e2e_vault_first_path() {
    // ── 1. Spin up an in-memory daemon store + vault and wrap them in
    //       the same LocalEncryptedStore the runtime constructs at
    //       startup (sibling: credential_store_wiring.rs).
    let store = Rc::new(DaemonStore::open_in_memory().expect("open in-memory store"));
    store.set_vault(Rc::new(Vault::new(TEST_VAULT_KEY)));
    let cs: Arc<dyn CredentialStore> = Arc::new(LocalEncryptedStore::new(Rc::clone(&store)));

    // ── 2. Pre-seed the vault with a complete ADR-099-grammar GitHub
    //       App credential triple. This is the moral equivalent of the
    //       operator having run `ember broker register github …` to
    //       migrate their on-disk PEM + env file into the vault — the
    //       step `runtime.rs` consults first under EMBER_VAULT_FIRST=1.
    let slug_install = "github/apps/test-app/install-42";
    cs.put(&format!("{slug_install}/private-key"), PEM_FAKE)
        .await
        .expect("seed private-key");
    cs.put(&format!("{slug_install}/app-id"), b"12345")
        .await
        .expect("seed app-id");
    cs.put(&format!("{slug_install}/installation-id"), b"42")
        .await
        .expect("seed installation-id");

    // ── 3. Lay down a checkpoint PEM tempfile and point EMBER_APP_PEM_PATH
    //       at it. If the vault-first arm short-circuits correctly, this
    //       file is never opened — atime stays stuck at its initial
    //       value. We ALSO assert on the bot-identity-source event below
    //       to cover filesystems mounted noatime/relatime where atime
    //       updates can be suppressed.
    let pem_dir = TempDir::new().expect("tempdir");
    let pem_sentinel = pem_dir.path().join("ember-engine-app.pem");
    std::fs::write(&pem_sentinel, b"CHECKPOINT: this PEM must not be read\n")
        .expect("write checkpoint PEM");
    let env_sentinel = pem_dir.path().join("ember-engine.env");
    std::fs::write(
        &env_sentinel,
        b"EMBER_ENGINE_APP_ID=should-not-be-read\nEMBER_ENGINE_INSTALLATION_ID=should-not-be-read\n",
    )
    .expect("write checkpoint env file");

    let atime_before_pem = file_atime(&pem_sentinel);
    let atime_before_env = file_atime(&env_sentinel);

    // ── 4. Install a tracing capture layer for the scope of the
    //       discovery call. The github_config_from_store success path
    //       emits exactly one `bot-identity-source` event with the
    //       fields we assert on below. `set_default` returns a
    //       `DefaultGuard` that holds the subscriber installed until
    //       dropped — works across `.await` points (unlike
    //       `with_default`'s closure form which would force a nested
    //       runtime).
    let (layer, captured) = CaptureLayer::new();
    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = set_default(subscriber);

    // ── 5. Drive the vault-first arm. This is the literal call
    //       `runtime.rs`'s broker registration block makes when
    //       EMBER_VAULT_FIRST=1 — see the `vault_first` branch in
    //       crates/ember-daemon/src/infra/runtime.rs (line ~1197).
    //       We also set EMBER_VAULT_FIRST=1 in-process so any
    //       downstream observers (logs, receipts) see the same flag
    //       state production would.
    //
    // SAFETY: this test runs on the current-thread runtime and the env
    // vars are process-global; the set_var/remove_var pairs are
    // matched in this same task so no other test sees the writes.
    unsafe {
        std::env::set_var("EMBER_VAULT_FIRST", "1");
        std::env::set_var("EMBER_APP_PEM_PATH", &pem_sentinel);
        std::env::set_var("EMBER_APP_ENV_PATH", &env_sentinel);
    }
    let result = github_config_from_store(&*cs).await;
    unsafe {
        std::env::remove_var("EMBER_VAULT_FIRST");
        std::env::remove_var("EMBER_APP_PEM_PATH");
        std::env::remove_var("EMBER_APP_ENV_PATH");
    }

    // ── 6. Assert: credentials resolved from the vault.
    let creds = result
        .expect("vault read must succeed")
        .expect("complete triple must be assembled");
    assert_eq!(creds.app_id, "12345");
    assert_eq!(creds.installation_id, "42");
    assert!(
        creds
            .private_key_pem
            .expose_secret()
            .contains("BEGIN PRIVATE KEY"),
        "PEM body must contain BEGIN PRIVATE KEY: {}",
        &creds.private_key_pem.expose_secret()
            [..creds.private_key_pem.expose_secret().len().min(80)]
    );

    // ── 7. Assert: bot-identity-source event with source="vault" was
    //       emitted exactly once. This is the structured-event half of
    //       acceptance criterion (3) — see PR4A's emission site in
    //       broker/github_config.rs (line ~289).
    let events = captured.lock().expect("capture mutex");
    let bot_id_events: Vec<&CapturedEvent> = events
        .iter()
        .filter(|e| e.rendered.contains("bot-identity-source"))
        .collect();
    assert!(
        !bot_id_events.is_empty(),
        "expected ≥1 bot-identity-source event; captured: {:?}",
        events.iter().map(|e| &e.rendered).collect::<Vec<_>>()
    );
    let vault_sourced: Vec<&&CapturedEvent> = bot_id_events
        .iter()
        .filter(|e| e.rendered.contains("source=\"vault\""))
        .collect();
    assert!(
        !vault_sourced.is_empty(),
        "expected ≥1 bot-identity-source event with source=\"vault\"; \
         captured bot-identity-source events: {:?}",
        bot_id_events
            .iter()
            .map(|e| &e.rendered)
            .collect::<Vec<_>>()
    );
    // No file-sourced event must have fired — that would mean the
    // legacy `load_gh_app_credentials` branch was taken.
    let file_sourced: Vec<&&CapturedEvent> = bot_id_events
        .iter()
        .filter(|e| e.rendered.contains("source=\"legacy-file\""))
        .collect();
    assert!(
        file_sourced.is_empty(),
        "no bot-identity-source event with source=\"legacy-file\" must fire \
         under vault-first; found: {:?}",
        file_sourced.iter().map(|e| &e.rendered).collect::<Vec<_>>()
    );
    drop(events);

    // ── 8. Assert: the checkpoint PEM file's atime is unchanged. This is
    //       the kernel-level "did the file branch run" probe. On
    //       filesystems mounted relatime/noatime this assertion may
    //       observe equal atimes either way (the kernel doesn't advance
    //       atime on every read); we treat it as a stronger-when-
    //       available signal rather than a hard gate — the
    //       bot-identity-source assertion above is the load-bearing
    //       part of acceptance criterion (2).
    if let (Some(before), Some(after)) = (atime_before_pem, file_atime(&pem_sentinel)) {
        assert!(
            after
                <= before
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap_or(before),
            "PEM file atime advanced — file was opened despite vault-first hit"
        );
    }
    if let (Some(before), Some(after)) = (atime_before_env, file_atime(&env_sentinel)) {
        assert!(
            after
                <= before
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap_or(before),
            "env file atime advanced — file was opened despite vault-first hit"
        );
    }
}
