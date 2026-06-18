use super::*;
use clap::{Args, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "ember", about = "The trust layer for AI agents")]
pub(super) struct Cli {
    /// Path to config file
    #[arg(long, global = true)]
    pub(super) config: Option<PathBuf>,

    /// Output as JSON
    #[arg(long, global = true)]
    pub(super) json: bool,

    /// Reduce non-essential human output
    #[arg(long, global = true)]
    pub(super) quiet: bool,

    /// Increase diagnostic output where supported
    #[arg(long, global = true)]
    pub(super) verbose: bool,

    /// Color control for human-facing output
    #[arg(long, global = true, value_enum, default_value_t = CliColorChoice::Auto)]
    pub(super) color: CliColorChoice,

    /// Refuse interactive prompts and guided input
    #[arg(long, global = true)]
    pub(super) no_input: bool,

    /// Skip interactive confirmation prompts and run the chosen action
    #[arg(long, short = 'y', global = true)]
    pub(super) yes: bool,

    #[command(subcommand)]
    pub(super) command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum CliColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum SandboxRuntime {
    Sandvault,
}

#[derive(Subcommand)]
pub(super) enum Commands {
    /// Initialize ember — canonical first-run setup
    Init {
        /// Your display name
        #[arg(long)]
        name: Option<String>,
        /// Keyring service name to write into config.toml (overrides default)
        #[arg(long)]
        keyring_service: Option<String>,
        /// Keyring account name to write into config.toml (overrides default)
        #[arg(long)]
        keyring_account: Option<String>,
        /// Use Touch ID (Secure Enclave-wrapped master key) instead of a
        /// passphrase. macOS only. Currently a stub: actual SE wrapping is
        /// gated behind P63.A-SE-WIRE; the flag is accepted today so the
        /// init flow can route through `VaultKeyStore::SecureEnclave` once
        /// the wiring lands. Until then, passing `--touch-id` prints a
        /// notice and falls back to the passphrase lane.
        #[arg(long, hide = true)]
        touch_id: bool,
        /// Canonical onboarding for Claude, Codex, Cursor, or Gemini.
        ///
        /// Canonical value: `claude`. When set, `ember init` completes the
        /// standard first-run setup, creates or reuses the default Claude
        /// persona/grant wiring, patches `~/.claude/settings.json`, and
        /// reports whether GitHub is already ready or needs
        /// `ember github setup`. If `CLAUDE_CODE_OAUTH_TOKEN` is present
        /// (for example, after `claude setup-token`), init imports it
        /// under a fingerprint-keyed `anthropic/plan/claude-oauth/<fingerprint>`
        /// credential and the launcher can reuse a brokered Claude plan/OAuth
        /// runtime grant. Otherwise, if `ANTHROPIC_API_KEY` is present, init
        /// imports it under `anthropic/api/key/<fingerprint>` for the fallback
        /// API-key lane; without either, Claude's own upstream auth remains
        /// ambient.
        ///
        /// Codex (target value `codex`) is the parallel onboarding lane.
        /// When complete it creates or reuses the Codex persona/grant wiring
        /// and imports `~/.codex/auth.json` under
        /// `openai/plan/chatgpt-oauth/<account>/<subject>`, so Codex model
        /// traffic can use Ember's brokered OpenAI Responses lane. `codex
        /// login status` remains the native auth-readiness check and `codex
        /// login --device-auth` remains the headless sign-in escape hatch.
        ///
        /// Cursor (target value `cursor`) sets up the baseline host launcher
        /// persona and local-only runtime grant. Cursor account/model auth
        /// remains Cursor-owned on this lane; Ember does not broker Cursor
        /// model spend unless a separate mediation mode is explicitly designed.
        #[arg(long = "for", value_name = "TARGET")]
        for_target: Option<OnboardingTarget>,
        /// Skip all interactive prompts. When set and the daemon is not
        /// installed, `ember init` exits with a repair command instead of
        /// prompting to run `sudo ember daemon install`. Useful for CI and
        /// scripted provisioning where stdin is not a TTY.
        #[arg(long)]
        non_interactive: bool,
        /// Relocate old-layout
        /// PATH-shadow shims at `~/.ember/shadow/<tool>` to the new
        /// `~/.ember/shadow/bin/<tool>` layout, replacing the old paths
        /// with symlinks pointing into `bin/` so any PATH or wrapper
        /// still referencing the old location keeps working for one
        /// release window. Idempotent on `layout=new` /
        /// `layout=both` / `layout=none` hosts. Only meaningful with
        /// `--for claude-code`. Anchor:
        /// `shadow_path_migrate_flag_landed`.
        #[arg(long)]
        migrate: bool,
    },
    /// Uninstall ember integrations.
    ///
    /// `--for claude` removes only the lines this onboarding path added to
    /// `~/.claude/settings.json`. `--for codex` removes only the hook block
    /// this onboarding path added to `~/.codex/hooks.json`. `--for cursor`
    /// is currently a no-op for Cursor config because baseline Cursor launch
    /// does not mutate Cursor-owned settings.
    /// Persona, grant, and vault entries are left in place — they may be in
    /// use by other tools.
    Uninstall {
        /// Integration target to uninstall. Canonical: `claude`.
        #[arg(long = "for", value_name = "TARGET")]
        for_target: OnboardingTarget,
    },
    /// Legacy hidden shortcut for the isolated Claude launcher.
    ///
    /// Kept only to redirect older scripts to the canonical
    /// `ember claude --isolated` surface.
    #[command(hide = true)]
    Up {
        /// Profile name selecting the compose service set (`dev` /
        /// `autopilot` / `demo`).
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    /// Tear down a container-mode session (scaffold).
    #[command(hide = true)]
    Down {
        /// Eager-revoke this session's grants instead of letting them expire at TTL.
        #[arg(long = "revoke-grants")]
        revoke_grants: bool,
        /// Remove named compose volumes after teardown.
        #[arg(long)]
        purge: bool,
    },
    // BKR-4c (ADR 205 §6): the `ember delegation {list,revoke,show}` surface was
    // folded into `ember grant {list,revoke,...}`. The per-session authority is
    // the runtime persona's standing grant (an AccessGrant), so `ember grant
    // list` enumerates it and `ember grant revoke <id>` kills a runaway lane —
    // no separate delegation command or `--delegation-id`/`--workflow-id` alias.
    /// Operator recovery surface (ADR 161 §Component 1, ADR 195).
    ///
    /// `ember recover {daemon,authority,broker,audit,install}` — class
    /// entry points; each routes to a sub-module that is incrementally
    /// populated as per-F-code implementations land.
    /// `ember recover diagnose` — lifecycle umbrella that composes existing
    /// read primitives and emits a `recovery.action` receipt.
    /// `ember recover explain F-CODE` — print the matching runbook
    /// excerpt from `docs/runbook/recovery.md`.
    ///
    /// Recovery actions emit Receipts of kind `recovery.action`; the
    /// authority class is gated by `PresenceProof` (Touch ID). Today
    /// the scaffold prints those contracts without performing the
    /// action.
    Recover {
        #[command(subcommand)]
        action: emberlink_cli::recover::RecoverCmd,
    },
    /// Install, inspect, and repair the ember daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage agent personas
    Persona {
        #[command(subcommand)]
        action: PersonaAction,
    },
    /// Manage operator authority devices.
    ///
    /// The v0.3.0 path is device-rooted authority, not the retired WebAuthn
    /// scaffold: list current custody devices, enroll presence/recovery
    /// devices through ADR 200/206 ceremonies, verify AC-2 confirmation
    /// cards, and revoke non-last presence devices.
    #[command(hide = true)]
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Manage the credential vault
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Manage the binary-pin manifest used for daemon-socket peer-binary
    /// content-hash binding. Per KEYCHAIN-CONSOLIDATE-CLI adversarial-
    /// review HIGH-1: every `local_state_key_*` call verifies the peer's
    /// binary blake3 against this manifest. The manifest is daemon-self-
    /// signed (v0.3 trust model: TOFU at the moment generate runs).
    #[command(name = "binary-pin", hide = true)]
    BinaryPin {
        #[command(subcommand)]
        action: BinaryPinAction,
    },
    /// Manage access grants
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Manage agent sandboxes
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Manage approval requests
    Approval {
        #[command(subcommand)]
        action: ApprovalAction,
    },
    /// View audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Inspect Grant Receipts — signed artifacts emitted at terminal grant state
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },
    /// Manage broker materializations (ADR 094 / ADR 096)
    ///
    /// The credential broker mints scoped, time-bounded provider tokens
    /// (Cloudflare API tokens, Anthropic admin keys, etc.) on demand —
    /// agents and operators never hold long-lived material. See
    /// ADR 094 §5 for the request/response shapes and ADR 096 for the
    /// daemon-side broker registry design.
    #[command(hide = true)]
    Broker {
        #[command(subcommand)]
        action: emberlink_cli::broker::BrokerCmd,
    },
    /// Manage daemon-controlled credential bindings.
    ///
    /// A binding ties `(persona, working-tree, remote)` to a remote URL
    /// the broker is authorized to inject credentials for. This is the
    /// EXPLICIT admin path — operators use it to pre-register bindings
    /// during admin work (no biometric required) and to recover from
    /// rename/repo-move scenarios. Biometric will gate the TOFU flow
    /// (DCC-3), not this verb.
    #[command(hide = true)]
    Bind {
        #[command(subcommand)]
        action: emberlink_cli::bind::BindCmd,
    },
    /// View or evaluate policy rules
    #[command(hide = true)]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// View configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect and configure GitHub transport posture
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },
    /// Inspect trust roots and verification chains
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
    /// Show daemon status, local state summary, and repair guidance
    Status {
        /// Append a bounded next-steps section for repair and operator checks
        #[arg(long)]
        troubleshoot: bool,
        /// Operator-facing attestation that the current shell session IS
        /// brokered. Reports session_id, daemon socket, manifest fingerprint,
        /// trust roots, dev_mode_active stamp, and active grants
        /// (ADR 157 follow-up).
        #[arg(long, conflicts_with = "troubleshoot")]
        session: bool,
        /// Inspect a specific session by id instead of the calling shell's
        /// `EMBER_SESSION_ID`. Implies `--session`.
        #[arg(long = "session-id", value_name = "ID", requires = "session")]
        session_id: Option<String>,
        /// List every active session attached to the daemon (composes with
        /// `--session`). Mutually exclusive with `--session-id`.
        #[arg(long, requires = "session", conflicts_with = "session_id")]
        all: bool,
    },
    /// Deep diagnosis and repair routing for the current Ember posture
    Doctor,
    /// Explain a command, delegated-authority surface, or error in more depth
    Explain {
        /// Topic to explain, for example `init`, `status`, `github setup`,
        /// or `error E-DAEMON-NOT-INSTALLED`
        #[arg(
            value_name = "TOPIC",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        topic: Vec<String>,
    },
    /// Show ember version
    Version,
    /// Cluster snapshot management
    #[command(hide = true)]
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Launch Claude with ember-managed env + PATH wiring.
    ///
    /// This is the ergonomic launcher alias. The canonical launch model is
    /// `ember session open claude ...`; this top-level verb remains a
    /// thin preset over that shared session-open contract.
    ///
    /// `claude-code` is accepted as a deprecated alias of `claude` so the
    /// pre-rename invocation shape continues to work.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    /// `--isolated` starts Ember's isolated/container launcher path.
    /// Trailing Claude args are forwarded on both host and isolated paths.
    /// `--backend` / `--preset` only apply with `--isolated`.
    #[command(
        name = "claude",
        visible_aliases = ["claude-code"],
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    ClaudeCode {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with_all = ["isolated", "sandbox"])]
        host: bool,
        /// Force Ember's isolated/container launcher path.
        #[arg(long, conflicts_with_all = ["host", "sandbox"])]
        isolated: bool,
        /// Force an external sandbox runtime adapter.
        #[arg(long, value_enum, conflicts_with_all = ["host", "isolated"])]
        sandbox: Option<SandboxRuntime>,
        /// Deny out-of-scope authority instead of falling through to JIT approval.
        #[arg(long)]
        strict: bool,
        /// Delegation template to attach at launch. When omitted, Claude opens
        /// the delegation selector before session registration.
        #[arg(long = "delegated", value_name = "TEMPLATE")]
        delegated: Option<String>,
        /// Explicitly attach to an already-live runtime persona instead of
        /// minting a fresh runtime for this launch.
        #[arg(
            long = "attach",
            value_name = "RUNTIME_PERSONA_ID",
            conflicts_with = "fork_runtime"
        )]
        attach_runtime_persona_id: Option<String>,
        /// Explicitly open a fresh runtime persona. This is the default unless
        /// `--attach` is supplied; pair with `--delegated` to fork-and-reattest.
        #[arg(long = "fork")]
        fork_runtime: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        /// Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, autopilot, demo).
        /// Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to `claude`.
        #[arg(value_name = "CLAUDE_ARGS")]
        args: Vec<String>,
    },
    /// Launch Codex with ember-managed env + PATH wiring.
    ///
    /// Thin preset over `ember session open codex ...` — mirrors the
    /// `claude` top-level subcommand for parity. The canonical launch
    /// model is `ember session open codex`; this top-level verb is the
    /// ergonomic alias.
    ///
    /// Codex auth stays on Codex's native login lane. Run `codex login`
    /// on the host first; if the host is headless or browser login is
    /// blocked, use `codex login --device-auth`. `--isolated` keeps the
    /// host auth root live while masking the write-heavy Codex runtime
    /// state with per-session overlays instead of creating a separate
    /// container login.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    /// `--isolated` starts Ember's isolated/container launcher path.
    /// Trailing Codex args are forwarded on both host and isolated paths.
    /// `--backend` / `--preset` only apply with `--isolated`.
    #[command(name = "codex", trailing_var_arg = true, allow_hyphen_values = true)]
    Codex {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with_all = ["isolated", "sandbox"])]
        host: bool,
        /// Force Ember's isolated/container launcher path.
        /// Keeps host auth live while routing mutable Codex state through
        /// per-session overlays.
        #[arg(long, conflicts_with_all = ["host", "sandbox"])]
        isolated: bool,
        /// Force an external sandbox runtime adapter.
        #[arg(long, value_enum, conflicts_with_all = ["host", "isolated"])]
        sandbox: Option<SandboxRuntime>,
        /// Deny out-of-scope authority instead of falling through to JIT approval.
        #[arg(long)]
        strict: bool,
        /// Delegation template to attach at launch.
        #[arg(long = "delegated", value_name = "TEMPLATE")]
        delegated: Option<String>,
        /// Explicitly attach to an already-live runtime persona instead of
        /// minting a fresh runtime for this launch.
        #[arg(
            long = "attach",
            value_name = "RUNTIME_PERSONA_ID",
            conflicts_with = "fork_runtime"
        )]
        attach_runtime_persona_id: Option<String>,
        /// Explicitly open a fresh runtime persona. This is the default unless
        /// `--attach` is supplied; pair with `--delegated` to fork-and-reattest.
        #[arg(long = "fork")]
        fork_runtime: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        /// Leave unset to auto-detect. Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, autopilot, demo).
        /// Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to `codex`.
        #[arg(value_name = "CODEX_ARGS")]
        args: Vec<String>,
    },
    /// Launch Cursor with ember-managed env + PATH wiring.
    ///
    /// Thin preset over `ember session open cursor ...`. Baseline Cursor
    /// support registers an Ember session and installs the PATH shadow for
    /// brokered tools, while Cursor account/model auth remains Cursor-owned.
    /// This lane must not be described as governing model spend unless a
    /// separate Cursor loopback-projector mediation mode is explicitly designed.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    /// `--isolated` and `--sandbox sandvault` are accepted for a canonical
    /// error, but are not wired for Cursor baseline launch.
    /// Trailing Cursor args are forwarded on the host path.
    #[command(name = "cursor", trailing_var_arg = true, allow_hyphen_values = true)]
    Cursor {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with_all = ["isolated", "sandbox"])]
        host: bool,
        /// Reserved for a future governed loopback-projector mediation lane; currently errors.
        #[arg(long, conflicts_with_all = ["host", "sandbox"])]
        isolated: bool,
        /// Reserved for a future sandbox adapter; currently errors.
        #[arg(long, value_enum, conflicts_with_all = ["host", "isolated"])]
        sandbox: Option<SandboxRuntime>,
        /// Deny out-of-scope authority instead of falling through to JIT approval.
        #[arg(long)]
        strict: bool,
        /// Delegation template to attach at launch.
        #[arg(long = "delegated", value_name = "TEMPLATE")]
        delegated: Option<String>,
        /// Explicitly attach to an already-live runtime persona instead of
        /// minting a fresh runtime for this launch.
        #[arg(
            long = "attach",
            value_name = "RUNTIME_PERSONA_ID",
            conflicts_with = "fork_runtime"
        )]
        attach_runtime_persona_id: Option<String>,
        /// Explicitly open a fresh runtime persona. This is the default unless
        /// `--attach` is supplied; pair with `--delegated` to fork-and-reattest.
        #[arg(long = "fork")]
        fork_runtime: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        /// Requires `--isolated`; reserved for future Cursor isolated support.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, autopilot, demo).
        /// Requires `--isolated`; reserved for future Cursor isolated support.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to Cursor.
        #[arg(value_name = "CURSOR_ARGS")]
        args: Vec<String>,
    },
    /// Launch the Gemini CLI under an Ember-managed session (ADR 215 §2).
    ///
    /// Brokers Google's Gemini CLI on its free "Sign in with Google" (Code
    /// Assist) OAuth tier: the daemon injects a refreshed Bearer server-side and
    /// the launcher relocates `GEMINI_CLI_HOME` so the child never holds the
    /// durable credential. Run `ember init --for gemini` first to import your
    /// `~/.gemini/oauth_creds.json`.
    ///
    /// `--prod` is implicit when neither lane flag is given.
    /// `--isolated` and `--sandbox sandvault` are accepted for a canonical
    /// error, but are not wired for the host-only brokered Gemini lane.
    /// Trailing Gemini args are forwarded on the host path.
    #[command(name = "gemini", trailing_var_arg = true, allow_hyphen_values = true)]
    Gemini {
        /// Use the current worktree's dev daemon flavor.
        /// Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the prod daemon flavor (~/.ember/run/daemon.sock). Default when
        /// neither --dev nor --prod is given.
        /// Mutually exclusive with --dev.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with_all = ["isolated", "sandbox"])]
        host: bool,
        /// Reserved for a future container-side mediation lane; currently errors.
        #[arg(long, conflicts_with_all = ["host", "sandbox"])]
        isolated: bool,
        /// Reserved for a future sandbox adapter; currently errors.
        #[arg(long, value_enum, conflicts_with_all = ["host", "isolated"])]
        sandbox: Option<SandboxRuntime>,
        /// Deny out-of-scope authority instead of falling through to JIT approval.
        #[arg(long)]
        strict: bool,
        /// Delegation template to attach at launch.
        #[arg(long = "delegated", value_name = "TEMPLATE")]
        delegated: Option<String>,
        /// Explicitly attach to an already-live runtime persona instead of
        /// minting a fresh runtime for this launch.
        #[arg(
            long = "attach",
            value_name = "RUNTIME_PERSONA_ID",
            conflicts_with = "fork_runtime"
        )]
        attach_runtime_persona_id: Option<String>,
        /// Explicitly open a fresh runtime persona. This is the default unless
        /// `--attach` is supplied; pair with `--delegated` to fork-and-reattest.
        #[arg(long = "fork")]
        fork_runtime: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        /// Requires `--isolated`; reserved for future Gemini isolated support.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, autopilot, demo).
        /// Requires `--isolated`; reserved for future Gemini isolated support.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded verbatim to the Gemini CLI.
        #[arg(value_name = "GEMINI_ARGS")]
        args: Vec<String>,
    },
    /// Demo subcommands — canned flows for friendly-dev onboarding and
    /// the locked composite-grant recording flow.
    ///
    /// `wedge`  — 60-second canned fallback. Spins up an isolated daemon
    ///            + seeded vault + MCP server via `qember.sh demo up`.
    /// `bundle` — submit the locked 4-statement composite-grant approval.
    ///            In-process store call; no socket round-trip.
    #[command(hide = true)]
    Demo {
        #[command(subcommand)]
        action: DemoAction,
    },
    /// Validate grant manifest files (`validate <file>`).
    #[command(hide = true)]
    Grants {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Session lifecycle subcommands. Dev-internal substrate — the
    /// canonical friendly surface is `ember claude` / `ember codex` /
    /// `ember cursor` / `ember headless`. Hidden from top-level help per the v0.3.0
    /// help_surface invariant.
    #[command(hide = true)]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Construct binary signing (AP-CONSTRUCT-SIGNING-CLI).
    ///
    /// `ember construct sign --binary <path> --construct-toml <path>
    ///   --version <semver> --identity-root-keypath <path>`
    ///
    /// Produces a JSON sidecar at `<binary>.sig` with a blake3 content hash +
    /// Ed25519 publisher signature. See `docs/construct-signing-pipeline.md`.
    #[command(hide = true)]
    Construct {
        #[command(subcommand)]
        action: ConstructAction,
    },
    /// Manage content-hash-pinned binaries.
    ///
    /// Reads/writes `/usr/local/lib/ember/binaries/manifest.toml` by default.
    /// Pass `--manifest-path` for noncanonical or test manifests. Verbs:
    ///   `install <tool>@<version> --from-path <path> [--manifest-path <path>]`
    ///   `list [--manifest-path <path>]`
    ///   `update <tool>`   (stub — not yet implemented)
    ///   `remove <tool>@<version> [--manifest-path <path>]`
    #[command(hide = true)]
    Binary {
        #[command(subcommand)]
        action: BinaryAction,
    },
    /// Manage headless (attested-device) enrollments — variable
    /// duration credential delegation for autopilot / scheduled jobs.
    ///
    /// `ember headless enroll --input <tasks.json>
    ///                        [--duration <4h|3d|1w>] [--persona <id>] [--yes]`
    /// `ember headless revoke [--enrollment-id <id>]`
    /// `ember headless status`
    ///
    /// Dev0 cohort: 7-day ceiling, 4-hour default. The daemon-side
    /// enroll/revoke arms are Phase 1 stubs today (PR #2578); status
    /// returns the steady-state shape. Phase 2 wires MEK sourcing +
    /// `headless_enrollment` Receipt emission.
    Headless {
        #[command(subcommand)]
        action: HeadlessAction,
    },
    /// Preflight authority coverage before launch (P10-S3).
    ///
    /// Before opening an `ember claude` / `ember codex` lane, see — per planned
    /// action — whether it is already `covered`, will `prompt` for Approve once,
    /// will `deny`, or is `missing` a prerequisite. The daemon (authority root)
    /// owns the verdict; this is a read-only check that mutates nothing.
    ///
    /// `ember preflight [SERVICE]`
    ///   Scope to one service (name or plugin address); default is every
    ///   installed service.
    ///
    /// `ember preflight gh --strict`
    ///   Preview the strict lane: out-of-scope actions deny instead of
    ///   prompting.
    ///
    /// `ember preflight --headless`
    ///   Preview the unattended lane, which cannot prompt.
    Preflight {
        /// Service name or plugin address to scope the check (default: all).
        service: Option<String>,
        /// Persona to evaluate against (default: all active grants).
        #[arg(long)]
        persona: Option<String>,
        /// Preview the strict lane (out-of-scope actions deny, not prompt).
        #[arg(long)]
        strict: bool,
        /// Preview the unattended/headless lane (cannot prompt).
        #[arg(long)]
        headless: bool,
        /// Emit JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Authority Catalog planning surface (ADR 194).
    ///
    /// `ember catalog plan` is the service-first bridge between the Catalog and
    /// delegated authority: start from which services/actions you want a lane to
    /// use and a posture, and see the lane-effective coverage answer before you
    /// launch. Preview-only — it mutates nothing. Coverage is computed by the
    /// daemon's preflight evaluator (P10-S3), not a second engine.
    ///
    /// `ember catalog plan --service gh --posture bounded`
    ///   Preview a strict delegated lane scoped to the ember-gh service.
    Catalog {
        #[command(subcommand)]
        action: CatalogAction,
    },
    /// Manage the ember KMS edge CA and peer enrollment lifecycle
    /// (ADR 100 Amendment 1 v3).
    ///
    /// `ember kms init-edge`
    ///   Generate the self-signed edge CA and persist the seed at
    ///   `<data_dir>/kms/edge-ca/ca.seed`. Prints the CA fingerprint for
    ///   out-of-band sharing with peers.
    ///
    /// `ember kms peer prepare <persona>@<peer-hostname>`
    ///   Generate an Ed25519 keypair locally (mode 0600); write a CSR.
    ///   The private key NEVER traverses any wire.
    ///
    /// `ember kms peer enroll <csr>`
    ///   Verify the CSR, check persona grants, mint a client cert, emit
    ///   a PeerEnroll Receipt, write the bundle (cert + CA chain).
    ///
    /// `ember kms peer install <bundle> --ca-fingerprint <sha>`
    ///   Verify the CA fingerprint and install cert + CA chain.
    ///
    /// `ember kms peer revoke <name>`
    ///   Revoke by cert serial; emit a PeerRevoke Receipt.
    #[command(hide = true)]
    Kms {
        #[command(subcommand)]
        action: KmsAction,
    },
    /// Manage the SCION recursive orchestrator (ADR 140 §3).
    ///
    /// `ember orchestrator spawn [--max-depth N] [--template T] [--brief TEXT]`
    ///   Mint an orchestrator-class Persona, acquire the single-orchestrator
    ///   flock guard at `/tmp/ember-orchestrator-<uid>.lock`, and launch
    ///   `ember-scion start`. Only host-side callers may reach this verb;
    ///   in-container callers are refused at the broker boundary.
    ///
    /// `ember orchestrator status [--verbose]`
    ///   Show whether an orchestrator is running, its Persona ID, and
    ///   (with `--verbose`) a JSON status object.
    ///
    /// `ember orchestrator stop`
    ///   Revoke the orchestrator Persona via daemon RPC and release the flock.
    #[command(hide = true)]
    Orchestrator {
        #[command(subcommand)]
        action: emberlink_cli::orchestrator::OrchestratorAction,
    },
    /// Dev daemon install + info + sync (ADR 157 Phase 4).
    ///
    /// `ember dev install` — provision the current worktree's dev daemon
    /// end-to-end (11 phases).
    ///   Returns non-zero if the workstation did not reach ready state.
    ///
    /// `ember dev info` / `ember dev status` — print the current worktree's
    ///   dev install state (IdentityRoot, GH App, paths, daemon/runtime truth).
    ///
    /// `ember dev sync` — incremental rebuild + content-hash diff + copy +
    ///   daemon kickstart for the current worktree runtime, then fail-loud
    ///   if manifest refresh or daemon readiness verification does not
    ///   complete cleanly. Use this after editing daemon or construct code.
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Manage the ember mTLS bridge (ADR 154 Component 1).
    ///
    /// `ember bridge endpoint [--emit-file <path>] [--json]`
    ///   Print or write the bridge endpoint JSON used by in-container agents.
    ///   The JSON contains `addr` (`host.docker.internal:<port>`) and
    ///   `ca_fingerprint_sha256` (hex SHA-256 of the KMS edge CA cert DER).
    #[command(hide = true)]
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
    /// Administrative helpers — internal release evidence collection.
    ///
    /// `ember admin v030-survey complete` is retired for v0.3.0. Audit-backed
    /// evidence replaced the survey after the 2026-06-17 operator correction;
    /// free-form exception notes are context, not a replacement form.
    #[command(hide = true)]
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
}

/// `ember init --for <TARGET>` value enum.
///
/// Anchor: onboarding_target_codex_variant_landed
///
/// `claude` is the canonical onboarding lane with full
/// implementation: persona/grant wiring, `~/.claude/settings.json`
/// patcher, and the Claude runtime grant.
///
/// `cursor` provisions the baseline host launcher lane only. It deliberately
/// does not import or broker Cursor account/model credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum OnboardingTarget {
    #[value(name = "claude")]
    Claude,
    #[value(name = "codex")]
    Codex,
    #[value(name = "cursor")]
    Cursor,
    #[value(name = "gemini")]
    Gemini,
}

#[derive(Subcommand, Debug)]
pub(super) enum AdminAction {
    /// Retired v0.3.0 ship-gate friendly-tester dogfood survey.
    #[command(name = "v030-survey")]
    V030Survey {
        #[command(subcommand)]
        action: V030SurveyAction,
    },
    // Anchor: `v030_ship_gate_dashboard_landed`.
}

#[derive(Subcommand, Debug)]
pub(super) enum V030SurveyAction {
    /// Refuse the retired end-of-week survey.
    Complete {
        /// Retained for compatibility with old runbooks; ignored because the
        /// v0.3.0 survey collector is retired.
        #[arg(long = "out-dir", value_name = "PATH")]
        out_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub(super) enum GithubAction {
    /// Diagnose the current GitHub auth posture and next setup step
    Status,
    /// Recommended v0.3.0 path: walk the local GitHub App setup flow
    Setup(GithubSetupArgs),
    /// Hidden low-level GitHub App helpers. Most operators should use `ember github setup`.
    #[command(hide = true)]
    App {
        #[command(subcommand)]
        action: GithubAppAction,
    },
}

#[derive(Subcommand, Debug)]
pub(super) enum TrustAction {
    /// List the daemon's current trust roots
    List,
    /// Show one trust root by full fingerprint or unique prefix
    Show {
        /// Full fingerprint or unique hex prefix
        root_id: String,
    },
    /// Explain how a signed artifact verifies back to a trust root
    Explain {
        /// Signed artifact path
        artifact_path: PathBuf,
        /// Sidecar signature path; defaults to `<artifact>.sig` for binary manifests
        #[arg(long)]
        sidecar: Option<PathBuf>,
        /// Artifact kind: binary_manifest, receipt, or authority_delegation (delegated-authority grant)
        #[arg(long, default_value = "binary_manifest")]
        kind: String,
    },
    /// Backup exportable keychain-held operator/workstation Persona keys.
    Backup {
        /// Output path for the encrypted backup file
        #[arg(long = "to")]
        to: PathBuf,
        /// Overwrite an existing backup file at --to
        #[arg(long)]
        force: bool,
        /// Skip the Touch ID confirmation prompt
        #[arg(long = "no-biometric")]
        no_biometric: bool,
    },
    /// Restore exportable keychain-held operator/workstation Persona keys.
    Restore {
        /// Encrypted backup file path
        #[arg(long = "from")]
        from: PathBuf,
        /// Skip the Touch ID confirmation prompt
        #[arg(long = "no-biometric")]
        no_biometric: bool,
    },
    /// Rotate a Principal. The target may be the self-parented root
    /// Principal, the workstation Durable Persona, the operator-role
    /// Durable Persona, or any later Principal with a rotation policy.
    /// ADR 200 (2026-06-15 amendment) + ADR 162 §Component 3 (amended).
    Rotate {
        /// Principal id (e.g. `did:key:...`) or label
        /// (`@workstation`, `@operator`). The transitional
        /// `dev-identity-root` token from PR #6019 is mapped with a
        /// migration hint rather than extended as target vocabulary.
        target: String,
        /// Optional rationale recorded with the rotation receipt.
        #[arg(long)]
        reason: Option<String>,
        /// Override the default 7-day grace window (in seconds).
        /// Floor: 1 hour (3600s).
        #[arg(long = "grace-window-secs")]
        grace_window_secs: Option<u64>,
        /// Skip the Touch ID confirmation prompt
        #[arg(long = "no-biometric")]
        no_biometric: bool,
        /// Path to the dev binary manifest to re-sign with the new
        /// key. When omitted, the re-sign step is skipped (warned in
        /// stdout) and the rotation registers without touching disk.
        #[arg(long = "manifest-path")]
        manifest_path: Option<PathBuf>,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub(super) struct GithubSetupArgs {
    /// Register a new operator-owned GitHub App through GitHub's manifest flow
    #[arg(
        long = "from-manifest",
        conflicts_with_all = ["pem_file", "app_id", "installation_id", "slug"]
    )]
    pub(super) from_manifest: bool,
    /// Path to the GitHub App's RSA private key (PEM-encoded PKCS#8 or PKCS#1)
    #[arg(long = "pem-file")]
    pub(super) pem_file: Option<PathBuf>,
    /// Numeric GitHub App ID
    #[arg(long = "app-id")]
    pub(super) app_id: Option<String>,
    /// Numeric GitHub installation ID
    #[arg(long = "installation-id")]
    pub(super) installation_id: Option<String>,
    /// Human-readable App slug
    #[arg(long)]
    pub(super) slug: Option<String>,
    /// Skip slug verification against GitHub API
    #[arg(long = "allow-unverified-slug")]
    pub(super) allow_unverified_slug: bool,
    /// Replace an existing stored triple for the same slug+installation
    #[arg(long)]
    pub(super) replace: bool,
}

#[derive(Subcommand, Debug)]
pub(super) enum GithubAppAction {
    /// Print the canonical public GitHub App install URL
    InstallUrl,
    /// Print the GitHub App permission-floor reference
    Show,
    /// Hidden low-level registration surface. Most operators should use `ember github setup`.
    Register(GithubAppRegisterArgs),
}

#[derive(Args, Debug, Clone)]
pub(super) struct GithubAppRegisterArgs {
    /// Path to the GitHub App's RSA private key (PEM-encoded PKCS#8 or PKCS#1)
    #[arg(long = "pem-file")]
    pub(super) pem_file: PathBuf,
    /// Numeric GitHub App ID
    #[arg(long = "app-id")]
    pub(super) app_id: String,
    /// Numeric GitHub installation ID
    #[arg(long = "installation-id")]
    pub(super) installation_id: String,
    /// Human-readable App slug
    #[arg(long)]
    pub(super) slug: String,
    /// Skip slug verification against GitHub API
    #[arg(long = "allow-unverified-slug")]
    pub(super) allow_unverified_slug: bool,
    /// Replace an existing stored triple for the same slug+installation
    #[arg(long)]
    pub(super) replace: bool,
}

/// `ember dev` subcommands (ADR 157 Phase 4).
#[derive(Subcommand)]
pub(super) enum DevAction {
    /// Install the dev daemon (5-stage pipeline per ADR 163 §Component 1+2).
    /// Returns non-zero until the workstation reaches ready state.
    ///
    /// State persists to `~/.config/emberlink/install-state.toml`. Re-running
    /// resumes from the first incomplete stage by default.
    Install {
        /// Pick up at the first non-complete stage. Implied when re-running
        /// against an existing partial state file; this flag is the explicit
        /// opt-in for symmetry with `--redo`.
        #[arg(long)]
        resume: bool,
        /// Force re-execution starting at the named stage. Accepts canonical
        /// slugs (`preflight`, `primitives`, `github_provisioning`,
        /// `daemon_install`, `smoke_test`) or aliases (`0`..=`4`, `github`,
        /// `daemon`, `smoke`). Mutually exclusive with `--resume`.
        #[arg(long, value_name = "STAGE")]
        redo: Option<String>,
    },
    /// Print dev install state (IdentityRoot, GH App, paths, daemon/runtime truth).
    #[command(visible_alias = "status")]
    Info,
    /// Incremental rebuild + content-hash diff + copy + daemon kickstart.
    ///
    /// Runs `cargo build --release -p emberlink-cli -p ember-daemon -p
    /// ember-construct`, diffs each built binary (SHA-256) against the dev
    /// install root copy, copies any changed binaries, refreshes the signed
    /// dev manifest, then restarts and verifies the dev daemon via launchctl.
    Sync {
        /// Skip the `launchctl kickstart` step. Use this on hosts that have
        /// not run `ember dev install` yet, or in CI where launchctl is absent.
        #[arg(long)]
        no_launchctl: bool,
    },
}

/// `ember bridge` subcommands (ADR 154 Component 1).
#[derive(Subcommand)]
pub(super) enum BridgeAction {
    /// Print or write the bridge endpoint JSON.
    ///
    /// The JSON shape is:
    ///   `{"addr": "host.docker.internal:<port>", "ca_fingerprint_sha256": "<hex>"}`
    ///
    /// `addr` is derived from the daemon's configured bridge bind address
    /// (substituting `host.docker.internal` as the host-reachable name for
    /// in-container callers). `ca_fingerprint_sha256` is the SHA-256 hex of
    /// the KMS edge CA cert DER (from `~/.ember/kms/edge-ca/ca.seed`).
    ///
    /// Exits non-zero if the daemon is not running or the bridge is not bound.
    Endpoint {
        /// Write the endpoint JSON to this path instead of stdout.
        /// Default (when flag absent): `~/.ember/bridge-endpoint.json`.
        #[arg(long, value_name = "PATH")]
        emit_file: Option<PathBuf>,
        /// Print the endpoint JSON to stdout (in addition to writing the file
        /// when --emit-file is given, or as the sole output when it is not).
        #[arg(long)]
        json: bool,
    },
}

/// `ember kms` subcommands.
#[derive(Subcommand)]
pub(super) enum KmsAction {
    /// Generate the self-signed edge CA (ADR 100 Amendment 1 v3).
    ///
    /// Persists the 32-byte raw Ed25519 seed at
    /// `<data_dir>/kms/edge-ca/ca.seed` (mode 0600). Prints the CA
    /// fingerprint (SHA-256 hex of cert DER) for out-of-band sharing.
    #[command(name = "init-edge")]
    InitEdge,
    /// Manage mTLS edge peer certificates.
    Peer {
        #[command(subcommand)]
        action: KmsPeerAction,
    },
}

/// `ember kms peer` subcommands.
#[derive(Subcommand)]
pub(super) enum KmsPeerAction {
    /// Generate an Ed25519 keypair locally and write a CSR.
    ///
    /// Private key is written at `~/.config/emberlink/peer-keys/
    /// <persona>-<peer-hostname>.key` (mode 0600) and NEVER appears in
    /// the CSR file or any wire message.
    Prepare {
        /// Target in the form `<persona>@<peer-hostname>`.
        target: String,
    },
    /// Verify a CSR, mint a client cert, write the enrollment bundle.
    ///
    /// The bundle contains the client certificate and CA chain but NO
    /// private key material.
    Enroll {
        /// Path to the PEM-encoded CSR file.
        csr_file: PathBuf,
    },
    /// Install a peer bundle (cert + CA chain) into local Pulumi config.
    ///
    /// `--ca-fingerprint` is REQUIRED — clap-level, no Option.
    /// The fingerprint is SHA-256 hex of the CA cert DER, as printed by
    /// `ember kms init-edge`.
    Install {
        /// Path to the peer bundle file (written by `peer enroll`).
        bundle_file: PathBuf,
        /// SHA-256 hex fingerprint of the edge CA cert (REQUIRED).
        #[arg(long)]
        ca_fingerprint: String,
        /// Install globally (in `~/.config/emberlink/peer-certs/`).
        /// Default: per-project (in `.ember/peer-certs/` in CWD).
        #[arg(long, default_value_t = false)]
        global: bool,
    },
    /// Revoke a peer certificate by name and emit a PeerRevoke Receipt.
    Revoke {
        /// Peer name in the form `<persona>-<peer-hostname>` or
        /// `<persona>@<peer-hostname>`.
        name: String,
    },
}

#[derive(Subcommand)]
pub(super) enum BinaryPinAction {
    /// Generate (or regenerate) the binary-pin manifest. Hashes the
    /// ember binaries at the supplied paths, signs the manifest with the
    /// daemon's persona key, and stores it in the daemon vault.
    ///
    /// Subsequent `local_state_key_*` calls verify the calling peer's
    /// binary blake3 against this manifest. Per KEYCHAIN-CONSOLIDATE-CLI
    /// adversarial-review HIGH-1.
    ///
    /// First-time use auto-detects the running `ember` binary via
    /// `current_exe()`; pass `--path caller=<path>` repeatedly to pin
    /// other callers (gui, native-host). Subsequent generates require
    /// `--force` AND a fresh user-presence proof (Touch ID).
    Generate {
        /// Additional `caller=path` pins to include alongside the auto-
        /// detected CLI binary. Examples:
        ///   --path gui=/Applications/Emberlink.app/Contents/MacOS/emberlink-gui
        ///   --path native-host=~/Library/Application\ Support/ember/...
        #[arg(long = "path", value_name = "caller=path")]
        paths: Vec<String>,
        /// Overwrite an existing manifest. Requires a fresh Touch ID via
        /// the HighRiskOp::BinaryPinGenerate presence gate.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum DemoAction {
    /// 60-second canned fallback demo for friendly devs. Shells
    /// `qember.sh demo up`/`down` and prints the live approval-flow next
    /// steps.
    Wedge {
        /// Tear down the demo environment (calls `qember.sh demo down`).
        #[arg(long)]
        teardown: bool,
    },
    /// Mint the locked 4-statement composite-grant bundle. Submits a
    /// single composite approval entry that bundles credential +
    /// session + time + credential statements via the in-process daemon
    /// store.
    Bundle,
    /// **Demo-only.** Seed synthetic Grant Receipts onto an existing grant
    /// chain so `ember receipt tree --grant <id>` has artifacts to render
    /// when a real spawn flow has not produced any yet.
    ///
    /// Never invoked in production. The seeded receipts pass v1 signature
    /// verification (signed by the local daemon persona) but their bodies
    /// are placeholders, not real audit data.
    Seed {
        /// Root grant id to attach the seed receipts to.
        #[arg(long)]
        grant: String,
        /// Number of synthetic receipts to mint on this grant.
        #[arg(long, default_value = "3")]
        count: usize,
    },
}

#[derive(Subcommand)]
pub(super) enum ConfigAction {
    /// Show current configuration
    Show,
    /// Show config file path
    Path,
}

#[derive(Subcommand)]
pub(super) enum ClusterAction {
    /// List locally-stored cluster snapshots (pulled from a remote EIC)
    Snapshots {
        /// Filter by cluster id (lists all clusters when omitted)
        #[arg(long)]
        cluster_id: Option<String>,
    },
    /// Single-phase EmberSeal bootstrap — generate Daemon Persona keypair (ADR 117).
    ///
    /// Generates an Ed25519 Daemon Persona keypair for the given cluster, stores
    /// the privkey seed in the operator's vault under
    /// `cluster-daemon-persona/<cluster-id>`, and prints the Ed25519 pubkey and
    /// derived X25519 recipient pubkey for embedding in the EmberSeal CR.
    ///
    /// Single-phase is the v1 default (ADR 117 §Decision): operator holds the
    /// Daemon Persona privkey from creation, so PVC wipe → redeploy with the
    /// same key → recovery without human re-sealing.
    ///
    /// Pass `--two-phase` to print documentation for the original ADR 115
    /// two-phase flow (opt-out fallback for clusters that do not pre-generate
    /// the Daemon Persona keypair).
    Bootstrap {
        /// Cluster identifier (e.g. "team-zero-dev"). Must be a valid vault
        /// path segment: lowercase letters, digits, hyphens; starts with a
        /// letter (ADR 099 grammar).
        cluster_id: String,
        /// Print two-phase bootstrap documentation instead of generating a
        /// keypair. Use this to document that a cluster uses the original
        /// ADR 115 two-phase flow as an explicit opt-out of single-phase.
        #[arg(long)]
        two_phase: bool,
    },
    /// Operator-driven cluster restore after a PVC wipe (ADR 117).
    ///
    /// Reads the Daemon Persona privkey seed from the operator's vault at
    /// `cluster-daemon-persona/<cluster-id>`, prints the recovery plan, and
    /// writes the seed to a temp file for the operator to inject as a
    /// Kubernetes secret. The EmberSeal CR's `recipientPubkey` stays the same
    /// because the same key material is reused.
    ///
    /// After the operator re-deploys EIC with the recovered key, run with
    /// `--verify` to probe the daemon socket and confirm readiness.
    Restore {
        /// Cluster identifier (must match the one used during bootstrap).
        cluster_id: String,
        /// After the operator re-deploys EIC, probe the daemon socket and
        /// print readiness status (success / partial / failed).
        #[arg(long)]
        verify: bool,
        /// Write the privkey seed envelope to this path instead of a
        /// system-chosen temp file (useful in CI pipelines).
        #[arg(long)]
        seed_out: Option<String>,
    },
}

#[derive(Subcommand)]
pub(super) enum CatalogAction {
    /// Plan a delegated lane from services/actions/posture and preview its
    /// lane-effective authority coverage (ADR 194). Preview-only.
    Plan {
        /// Service by name or plugin address (repeatable; at least one).
        #[arg(long = "service", required = true)]
        service: Vec<String>,
        /// Restrict to specific action keys or refs (repeatable; default: all).
        #[arg(long = "action")]
        action: Vec<String>,
        /// Planner posture: ambient | elastic | bounded.
        #[arg(long, default_value = "ambient")]
        posture: String,
        /// Persona to evaluate against (default: all active grants).
        #[arg(long)]
        persona: Option<String>,
        /// Save the plan as a reusable delegated artifact under this name, then
        /// print the launch invocation (ADR 194 §5 outputs 3 & 4). Requires a
        /// delegated posture (elastic | bounded).
        #[arg(long, value_name = "NAME")]
        save: Option<String>,
        /// Advanced TTL override for --save (e.g. 4h). Defaults to a
        /// posture-derived ceiling (bounded 4h, elastic 8h).
        #[arg(long, value_name = "DUR", requires = "save")]
        ttl: Option<String>,
        /// Emit JSON instead of the human-readable preview.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum SessionAction {
    /// Canonical session-launch surface.
    ///
    /// Top-level launchers like `ember claude` should delegate here
    /// rather than grow independent launch semantics.
    #[command(trailing_var_arg = true, allow_hyphen_values = true)]
    Open {
        /// Session surface to open.
        target: emberlink_cli::session::OpenSurface,
        /// Use the mutable dev lane. Mutually exclusive with --prod.
        #[arg(long, conflicts_with = "prod")]
        dev: bool,
        /// Use the managed prod lane. Default when neither lane flag is given.
        #[arg(long, conflicts_with = "dev")]
        prod: bool,
        /// Force the host-resident launcher path.
        #[arg(long, conflicts_with_all = ["isolated", "sandbox"])]
        host: bool,
        /// Force the isolated/container launcher path.
        #[arg(long, conflicts_with_all = ["host", "sandbox"])]
        isolated: bool,
        /// Force an external sandbox runtime adapter.
        #[arg(long, value_enum, conflicts_with_all = ["host", "isolated"])]
        sandbox: Option<SandboxRuntime>,
        /// Deny out-of-scope authority instead of falling through to JIT approval.
        #[arg(long)]
        strict: bool,
        /// Delegation template to attach at launch. When omitted for Claude,
        /// the delegation selector opens before session registration.
        #[arg(long = "delegated", value_name = "TEMPLATE")]
        delegated: Option<String>,
        /// Explicitly attach to an already-live runtime persona instead of
        /// minting a fresh runtime for this launch.
        #[arg(
            long = "attach",
            value_name = "RUNTIME_PERSONA_ID",
            conflicts_with = "fork_runtime"
        )]
        attach_runtime_persona_id: Option<String>,
        /// Explicitly open a fresh runtime persona. This is the default unless
        /// `--attach` is supplied; pair with `--delegated` to fork-and-reattest.
        #[arg(long = "fork")]
        fork_runtime: bool,
        /// Advanced isolated-path backend hint (docker, orbstack, podman).
        /// Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        backend: Option<String>,
        /// Advanced isolated-path preset/profile hint (dev, autopilot, demo).
        /// Requires `--isolated`.
        #[arg(long, value_name = "NAME", conflicts_with = "sandbox")]
        preset: Option<String>,
        /// Launch the session from an Ember-managed git worktree.
        #[arg(long, value_name = "NAME")]
        worktree: Option<String>,
        /// Override the branch name created for a new managed worktree.
        #[arg(long, requires = "worktree")]
        branch: Option<String>,
        /// Short operator note recorded in `.agent-session`.
        #[arg(long, requires = "worktree")]
        purpose: Option<String>,
        /// Trailing arguments forwarded to the target surface.
        #[arg(value_name = "TARGET_ARGS")]
        args: Vec<String>,
    },
    /// Tail the session sidecar JSONL (`~/.ember/sessions/<id>/sidecar.jsonl`).
    Tail {
        /// Session ID. Defaults to the active session.
        id: Option<String>,
        /// Format JSON lines via `jq`; falls back to raw on jq missing.
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum ConstructAction {
    /// Sign a Construct binary, producing a `.sig` sidecar file.
    ///
    /// Computes blake3(binary_bytes || construct_toml_bytes), builds a
    /// canonical JCS payload, signs with the publisher's Ed25519 key, and
    /// writes a JSON sidecar at `<binary>.sig`.
    Sign {
        /// Path to the compiled binary (the Construct executable).
        #[arg(long)]
        binary: std::path::PathBuf,
        /// Path to the embedded construct.toml policy file.
        #[arg(long)]
        construct_toml: std::path::PathBuf,
        /// Semver version string (e.g. `1.0.0`).
        #[arg(long)]
        version: String,
        /// Path to the publisher's Ed25519 secret key (raw 32-byte seed file).
        #[arg(long)]
        identity_root_keypath: std::path::PathBuf,
    },
    /// Register a directory as an L1 authoring scope.
    ///
    /// `ember construct dev <path>` writes the canonicalized path to
    /// `~/.ember/authoring-paths.toml` (mode 0600). Daemon-side, scripts
    /// resident under any registered path are accepted by `broker.resolve`
    /// and emit Receipts tagged `authoring = true`. End-user installs
    /// (registry empty) refuse all unsigned-script broker calls.
    ///
    /// Use `--list` to print registered paths; `--unregister <path>` to
    /// remove one.
    Dev {
        /// Path to register (must exist on disk; canonicalized at
        /// registration time).
        path: Option<std::path::PathBuf>,
        /// Print all registered paths and exit.
        #[arg(long, conflicts_with_all = ["path", "unregister"])]
        list: bool,
        /// Remove a previously-registered path.
        #[arg(long, conflicts_with_all = ["path", "list"], value_name = "PATH")]
        unregister: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
pub(super) enum BinaryAction {
    /// Register a binary by path, computing its blake3 content hash.
    Install {
        /// Tool name and version: `<name>@<version>` (e.g. `ember-gh@1.0.0`).
        tool_at_version: String,
        /// Path to the binary file to register.
        #[arg(long)]
        from_path: std::path::PathBuf,
        /// Publisher DID (defaults to "did:unknown").
        #[arg(long, default_value = "did:unknown")]
        publisher: String,
        /// Manifest TOML path. Defaults to `/usr/local/lib/ember/binaries/manifest.toml`.
        #[arg(long)]
        manifest_path: Option<std::path::PathBuf>,
    },
    /// Batch-register all Cohort-A Construct binaries from a directory
    /// into a single signed manifest. The manifest is signed with the dev
    /// IdentityRoot from Keychain and written to the bundled system manifest
    /// path by default. Used by release packaging and host refresh scripts.
    InstallBundle {
        /// Directory holding the bundled Construct binaries.
        #[arg(long)]
        from_dir: Option<std::path::PathBuf>,
        /// Destination TOML path. Defaults to `/usr/local/lib/ember/binaries/manifest.toml`.
        #[arg(long)]
        manifest_path: Option<std::path::PathBuf>,
        /// Publisher DID stamped on every entry.
        #[arg(long, default_value = "did:emberlink")]
        publisher: String,
        /// Version string stamped on every entry.
        #[arg(long, default_value = "0.3.0")]
        version: String,
        /// Release/pkgbuild mode: read payload bytes from this staged root
        /// while writing manifest paths for their installed `/usr/local/...`
        /// locations.
        #[arg(long)]
        staged_root: Option<std::path::PathBuf>,
        /// Sign with a raw 32-byte Ed25519 seed file instead of the operator
        /// Keychain dev IdentityRoot.
        #[arg(long)]
        identity_root_keypath: Option<std::path::PathBuf>,
    },
    /// Print all registered binaries from the manifest.
    List {
        /// Manifest TOML path. Defaults to `/usr/local/lib/ember/binaries/manifest.toml`.
        #[arg(long)]
        manifest_path: Option<std::path::PathBuf>,
    },
    /// Stub: not yet implemented. Use install with the new version explicitly.
    Update {
        /// Tool name to update (e.g. `ember-gh`).
        tool_name: String,
    },
    /// Remove a binary entry from the manifest.
    Remove {
        /// Tool name and version: `<name>@<version>` (e.g. `ember-gh@1.0.0`).
        tool_at_version: String,
        /// Manifest TOML path. Defaults to `/usr/local/lib/ember/binaries/manifest.toml`.
        #[arg(long)]
        manifest_path: Option<std::path::PathBuf>,
    },
}

/// `ember headless <action>` — attested-device enrollment management.
/// Surface for the daemon-side headless enroll / revoke / status
/// socket methods.
#[derive(Subcommand)]
pub(super) enum HeadlessAction {
    /// Enroll a persona for bounded headless delegation from a declared
    /// queued task file. Interactive `[Y/n]` confirm by default; pass
    /// `--yes` for scripted use (qember.sh T3, smoke tests).
    Enroll {
        /// Path to a JSON file with the input shape
        /// `{ "tasks": [{ "task_id", "constructs" }], "template": [..] }`.
        /// Required for bounded headless enrollment.
        #[arg(long = "input")]
        input: Option<std::path::PathBuf>,
        /// Duration spec — `4h`, `3d`, `1w`, etc. Default: `4h`. Ceiling: `7d` at dev0.
        #[arg(long)]
        duration: Option<String>,
        /// Persona ID to enroll. Default: `main`.
        #[arg(long)]
        persona: Option<String>,
    },
    /// Revoke an active headless enrollment.
    Revoke {
        /// Enrollment ID to revoke. When omitted, the daemon revokes
        /// the only active enrollment (Phase 2 semantics).
        #[arg(long = "enrollment-id")]
        enrollment_id: Option<String>,
    },
    /// Show the active headless enrollment (or `none`).
    Status,
    /// Run the Layer-1 pre-flight scope check.
    ///
    /// Resolves the union of permissions each queued task's declared
    /// Constructs require, diffs against the enrolled persona's
    /// template, and prints the gap list. Use this before
    /// `ember headless enroll` to confirm autopilot can run the
    /// candidate queue under the current template.
    Preflight {
        /// Path to a JSON file with the input shape
        /// `{ "tasks": [{ "task_id", "constructs" }], "template": [..] }`.
        /// When omitted, an empty task list is sent (smoke probe).
        #[arg(long = "input")]
        input: Option<std::path::PathBuf>,
        /// Emit raw JSON gap list instead of the table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum PolicyAction {
    /// Show current policy rules
    Show,
    /// Evaluate an action against the policy
    Eval {
        /// Action to evaluate (e.g., "git.push.main")
        action: String,
    },
}

#[derive(Subcommand)]
pub(super) enum DaemonAction {
    /// Start the daemon (runs in foreground by default)
    #[command(hide = true)]
    Start {
        /// Run in background (daemonize)
        #[arg(long, short, conflicts_with = "foreground")]
        background: bool,
        /// Explicitly run in foreground (no-op unless used by launchd/systemd)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop a running daemon
    Stop,
    /// Show daemon status
    Status,
    /// Gracefully restart the daemon (SIGTERM; managed service respawns)
    Reload {
        /// Seconds to wait for the new daemon to come up
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    /// Install the dev-only same-uid daemon as an always-up user service
    /// (LaunchAgent/systemd)
    #[command(hide = true)]
    InstallAgent {
        /// Write the service file but don't bootstrap/enable it
        #[arg(long)]
        no_autostart: bool,
    },
    /// Uninstall the dev-only daemon user service
    #[command(hide = true)]
    UninstallAgent,
    /// Install the ember daemon (separate-uid posture by default).
    ///
    /// Default behaviour provisions the dedicated `ember` system user and
    /// `ember-clients` connect group, chowns the daemon's at-rest state to
    /// `ember:ember-clients`, and installs the platform launcher
    /// (LaunchDaemon on macOS / systemd unit on Linux). Pass `--single-uid`
    /// to opt into the relaxed-threat-model dev posture (reserved — not
    /// yet implemented).
    Install {
        #[command(flatten)]
        args: DaemonInstallArgs,
    },
    /// Migrate a running single-uid installation to the separate-uid
    /// posture while preserving all on-disk state (vault rows, grants,
    /// sessions). Only `--to separate-uid` is accepted in v1.
    ///
    /// If the host is already on the separate-uid posture the command exits
    /// immediately with a success message ("already on separate-uid posture").
    Migrate {
        /// Target posture. Only `separate-uid` is accepted.
        #[arg(long, value_name = "POSTURE")]
        to: String,
    },
    /// Idempotent + auditable wipe sequence for the MEK-missing-with-state
    /// recovery path.
    ///
    /// Replaces the hand-typed `mv + security delete-generic-password +
    /// launchctl` paste-block operators used to run for this recovery.
    /// Steps:
    ///   1. Stop the daemon (best-effort)
    ///   2. Archive `~/.ember/data/` to `<archive-to>/` (refuses if dir exists)
    ///   3. Print keychain-clear instruction (slice D-bis owns the actual
    ///      System.keychain delete; CLI today emits the canonical command)
    ///   4. Print re-seed checklist for operator next steps
    ///
    /// `--archive-to` is REQUIRED — no destructive default. Idempotent: a
    /// re-run with an existing archive dir errors instead of overwriting.
    RecoverFresh {
        /// Required: archive the current daemon data dir to this path
        /// before wiping. Must not exist (idempotent guard).
        #[arg(long, value_name = "PATH")]
        archive_to: PathBuf,
    },
    /// Diagnose daemon state — `git fsck`-style detector for the
    /// MEK-persistence-failed pattern.
    ///
    /// Detects four patterns:
    ///   HEALTHY — keychain MEK + daemon.db state + fingerprint all align
    ///   MEK-MISSING-WITH-STATE — keychain empty but daemon.db has rows
    ///     (run `ember daemon recover-fresh`)
    ///   FINGERPRINT-MISMATCH — keychain MEK loaded but
    ///     vault_meta.mek_fingerprint disagrees (vault import --sealed)
    ///   STATE-EMPTY — fresh install; `ember init` to provision
    ///
    /// Outputs a deterministic runbook for each non-HEALTHY pattern.
    /// Fingerprint-check shape depends on the MEK-fingerprint-column
    /// slice landing; pre-slice, the FINGERPRINT row reports
    /// "unavailable (slice B pending)".
    Diagnose,
}

/// Flags for `ember daemon install`. ADR 131 §Dev mode locks the default
/// to separate-uid; `--single-uid` is the dev-mode escape hatch.
///
/// `--non-interactive` drives the prompt-free install path
/// ([`emberlink_cli::install::install_non_interactive`]) used by CI runners
/// and `RUN ember install --non-interactive` Dockerfile lines. When set,
/// banners and prompts are suppressed, structured `[install] phase=...`
/// lines are emitted to stderr per phase, and the install refuses with a
/// clear error if neither root nor cached sudo is available rather than
/// hanging on a password prompt.
#[derive(Debug, Args)]
pub struct DaemonInstallArgs {
    /// Install daemon under the operator's uid (relaxed-threat-model dev posture).
    /// Default off — production posture is separate-uid per ADR 131.
    #[arg(long)]
    pub single_uid: bool,
    /// Run the install without any interactive prompts, banners, or
    /// progress UI. Refuses with a clear error if neither root nor a cached
    /// sudo timestamp is available. Emits one `[install] phase=<step>`
    /// line per install phase to stderr for log scrapers.
    #[arg(long)]
    pub non_interactive: bool,
    /// Acknowledge that default values will be used for any otherwise-prompted
    /// choice. Implied by `--non-interactive`. Captured separately so a future
    /// slice can branch on `--non-interactive` without `--accept-defaults`.
    #[arg(long)]
    pub accept_defaults: bool,
    /// Daemon posture to install (only `separate-uid` accepted today).
    /// Default `separate-uid` per ADR 131. Currently informational — pinned
    /// here so downstream tooling (Dockerfile authors, CI runners) can lock
    /// the posture explicitly without ambiguity.
    #[arg(long, value_name = "POSTURE")]
    pub posture: Option<String>,
}

#[derive(Subcommand)]
pub(super) enum PersonaAction {
    /// Create a new agent persona
    Create {
        /// Human-readable name for the persona
        #[arg(long)]
        name: String,
    },
    /// List all personas
    List,
    /// Revoke a persona
    Revoke {
        /// Persona ID to revoke
        id: String,
    },
}

/// Device-management verbs for ADR 200/206 operator authority custody.
///
/// v0.3.0 device authority is live through Secure Enclave, external-signer,
/// recovery-recipient, AC-2 verification, and revoke flows. The old WebAuthn /
/// iCloud Passkey scaffold is historical residue and must not describe this
/// command surface.
#[derive(Subcommand)]
pub(super) enum DeviceAction {
    /// List enrolled presence devices (ADR 200 §1). ConnectOnly — no vault
    /// tap, no presence gate. Shows device_id, label, role, custody class,
    /// attestation kind, status, and truncated public keys. Use `--json` for
    /// structured output (V030-EMBER-DEVICE-LIST).
    ///
    /// Anchor: `ember_device_list_surface_landed`.
    List,
    /// Enroll a device under the operator IdentityRoot via the out-of-band
    /// prepare→commit ceremony (ADR 200 §5, §6). The daemon never holds the
    /// device key (presence) or the recovery secret (recovery).
    ///
    /// **Default (no flags, macOS with signed-SE binary):** behaves as
    /// `--secure-enclave` — runs the dev0 presence floor in one shot
    /// (find-or-create Touch-ID-gated SE keys, prepare→Touch-ID sign→commit).
    /// On non-macOS or unsigned builds, falls back to the explicit-flag error
    /// pointing at `--secure-enclave` / `--external-signer` / `--recovery-code`.
    ///
    /// **`--recovery-code` (capability: KEK_s recipient only):** generates a
    /// fresh age x25519 recovery identity in this session, prints the secret
    /// ONCE, registers the public half as a `recovery`-class device under the
    /// operator root, and seals KEK_s to it. The daemon never holds the
    /// recovery secret. Authorized by your existing presence device (one tap).
    ///
    /// **`--secure-enclave` (capability: signing + KEK_s recipient):** runs
    /// the whole ceremony against a Touch-ID-gated SE key. Requires a signed
    /// binary built with real SE support; refuses to bind a software key.
    ///
    /// **`--external-signer` (capability: signing + KEK_s recipient):** the
    /// two-call off-host signer flow (YubiKey PIV / PKCS#11 / `gpg` /
    /// `ssh-keygen -Y sign`). Run WITHOUT `--operator-signature-hex` to
    /// PREPARE (print the bytes to sign), then re-run supplying one
    /// `--operator-signature-hex <DER-hex>` per blob to COMMIT. Legacy:
    /// supplying `--device-key` continues to imply `--external-signer` for
    /// backward compat with existing scripts.
    ///
    /// Capability is intrinsic to the class enrolled — there is no orthogonal
    /// flag. ADR 200 amendment 2026-06-12: capabilities flow from device
    /// class.
    Enroll {
        /// Presence-device SIGNING public key in `p256:<sec1-hex>` wire form.
        /// For first-device enrollment, supplying this implies the external
        /// signer lane. For `--backup`, this is the BACKUP Device signing
        /// pubkey; the authority signer defaults to the existing local SE key
        /// unless `--external-signer` or `--operator-signature-hex` is supplied.
        #[arg(
            long,
            value_name = "P256_PUBKEY",
            conflicts_with_all = ["recovery_code"]
        )]
        device_key: Option<String>,
        /// §4 ECIES recipient public key in `p256:<sec1-hex>` wire form — a
        /// key DISTINCT from `--device-key` (ADR 206 §4: the sealing recipient
        /// cannot be the signing key). For `--backup`, this is the BACKUP
        /// Device encryption pubkey.
        #[arg(
            long,
            value_name = "P256_PUBKEY",
            conflicts_with_all = ["recovery_code"]
        )]
        encryption_key: Option<String>,
        /// Human-readable label recorded on the enrolled device.
        #[arg(long, default_value = "Operator Presence Device")]
        label: String,
        /// Enroll this key as a second/bootstrap-backup presence Device. The
        /// existing presence Device signs the backup enrollment event. On
        /// macOS with a signed SE-capable binary, the default authority signer
        /// is the local Secure Enclave key; use `--external-signer` for the
        /// two-call off-host authority-signature lane.
        /// (Capability still flows from class: backup-of-presence IS presence.)
        #[arg(long, conflicts_with_all = ["recovery_code"])]
        backup: bool,
        /// Public key of the existing presence Device that signs `--backup`
        /// enrollment. Also the operator-root pubkey recorded in the backup
        /// AC-2 card.
        #[arg(
            long = "authority-device-key",
            value_name = "P256_PUBKEY",
            requires = "backup"
        )]
        authority_device_key: Option<String>,
        /// Find-or-create a Touch-ID-gated Secure Enclave key and auto-sign
        /// the ceremony with it (the dev0 presence floor). Default on macOS
        /// when this binary has real SE support.
        #[arg(
            long,
            conflicts_with_all = ["operator_signature_hex", "external_signer", "recovery_code"]
        )]
        secure_enclave: bool,
        /// Keychain label for the Secure Enclave presence key (with
        /// `--secure-enclave` or the SE default).
        #[arg(long, default_value = "ember-operator-presence")]
        se_label: String,
        /// Skip the ADR 206 §4 presence-as-decryption custody provision that
        /// `--secure-enclave` otherwise runs automatically after enrollment.
        /// Default = provision §4 custody in the same command. Use this only
        /// for a manual/deferred §4 cutover via `vault se-provision`.
        #[arg(long)]
        no_provision: bool,
        /// Write the ADR 200 AC-2 out-of-band confirmation card JSON. Keep
        /// this file outside daemon-controlled storage; it is the operator-held
        /// copy an independent verifier compares against.
        #[arg(long = "ac2-card", value_name = "PATH")]
        ac2_card: Option<PathBuf>,
        /// One ECDSA-P256 DER signature (hex) per prepared step, in order.
        /// Omit to PREPARE (print the bytes to sign); supply to COMMIT. Used
        /// by `--external-signer`.
        #[arg(
            long = "operator-signature-hex",
            value_name = "DER_HEX",
            conflicts_with_all = ["secure_enclave", "recovery_code"]
        )]
        operator_signature_hex: Vec<String>,
        /// **Off-host external signer flow** (YubiKey PIV / PKCS#11 / `gpg` /
        /// `ssh-keygen -Y sign`). Two-call PREPARE → COMMIT against the
        /// daemon. Renamed from the implicit `--manual` flow for clarity.
        /// Legacy: supplying `--device-key` continues to imply this mode for
        /// backward compat with existing scripts.
        #[arg(
            long = "external-signer",
            conflicts_with_all = ["secure_enclave", "recovery_code"]
        )]
        external_signer: bool,
        /// **Enroll a printed recovery code** as a `recovery`-class device
        /// (ADR 206 §6). Capability: KEK_s recipient only — never signs.
        /// Generates a fresh age x25519 recovery identity, prints the secret
        /// ONCE (never written to disk), seals the matching scope KEK to it.
        /// Authorized by your existing presence device (one Touch ID tap).
        #[arg(
            long = "recovery-code",
            conflicts_with_all = [
                "device_key", "encryption_key", "backup",
                "authority_device_key", "secure_enclave",
                "operator_signature_hex", "external_signer",
            ]
        )]
        recovery_code: bool,
    },
    /// Legacy paired-device WebAuthn stub.
    ///
    /// This is not the v0.3.0 authority path. Current enrollment flows use
    /// `device enroll` with Secure Enclave, external-signer, or recovery-code
    /// custody; `pair` remains only as historical CLI compatibility for the
    /// future genuine-app/WebAuthn lane.
    Pair,
    /// Verify one or two operator-held AC-2 out-of-band confirmation cards
    /// (ADR 200 §5 / AC-2). Re-computes the digest each card carries
    /// against `(schema, ceremony, device_class, ids, pubkeys)` and, when
    /// two cards are supplied, cross-checks they share the same operator
    /// root and distinct hardware-device pubkeys (§6 C9 1-of-2 dev0
    /// recovery floor). Pure operator-side check — no daemon roundtrip; an
    /// attacker-substituted card fails the digest re-check.
    #[command(name = "verify-ac2-cards")]
    VerifyAc2Cards {
        /// One or two AC-2 confirmation card JSON paths. Pass one to verify
        /// a single card in isolation; pass two to additionally cross-check
        /// the pair.
        #[arg(value_name = "CARD_PATH", required = true, num_args = 1..=2)]
        cards: Vec<PathBuf>,
    },
    /// Revoke an enrolled presence Device (ADR 200 §5/§6). Drives the
    /// daemon's `identity.device.revoke` RPC, which appends a `DeviceRevoked`
    /// event to the operator identity log signed by an EXISTING operator
    /// presence Device — the daemon never holds that key. After revocation
    /// the Device drops out of the operator's authority set, so its signature
    /// can no longer satisfy a widening op. The daemon REFUSES to revoke the
    /// LAST active `presence` Device — bricking the authority set is
    /// structurally refused (no key would remain to widen anything, including
    /// a future enroll/restore).
    ///
    /// **Default (no flags, macOS with signed-SE binary):** the CLI drives
    /// the whole ceremony with the operator's Secure Enclave presence key
    /// (one Touch ID tap), exactly like `device enroll --secure-enclave`.
    /// The CLI fetches PREPARE, signs the returned bytes with the SE
    /// signing key, and submits COMMIT — no second invocation, no
    /// `--operator-signature-hex`. `--authority-device-key` is optional
    /// in this lane: when omitted it is inferred from the SE
    /// `ember-operator-presence` key.
    ///
    /// **`--external-signer`:** the two-call PREPARE/COMMIT off-host signer
    /// flow (YubiKey PIV / PKCS#11 / `gpg` / `ssh-keygen -Y sign`). Run
    /// WITHOUT `--operator-signature-hex` to PREPARE (print the bytes to
    /// sign), then re-run supplying one `--operator-signature-hex <DER_HEX>`
    /// to COMMIT. `--authority-device-key` is required in this lane
    /// (the CLI cannot derive it).
    ///
    /// Before revoking a lost or compromised device, ENROLL its replacement
    /// first (`ember device enroll --backup`) so the operator retains a
    /// presence Device. See `docs/runbook/recovery.md` §"When a presence
    /// device is lost or compromised".
    ///
    /// Anchor: `ember_device_revoke_surface_landed`.
    Revoke {
        /// Device id of the Device to revoke (as shown by `ember device list`).
        #[arg(long)]
        device_id: String,
        /// Public key of the EXISTING active presence Device that signs this
        /// revocation. Optional in the default SE-driven lane (inferred from
        /// the operator's `ember-operator-presence` SE key); REQUIRED with
        /// `--external-signer`. When omitted and 2+ active presence Devices
        /// exist (the SE key cannot disambiguate), the CLI errors with the
        /// candidate list so the operator can pick.
        #[arg(long = "authority-device-key", value_name = "P256_PUBKEY")]
        authority_device_key: Option<String>,
        /// Human-readable reason recorded on the `DeviceRevoked` event.
        #[arg(long, default_value = "operator-initiated revoke")]
        reason: String,
        /// One ECDSA-P256 DER signature (hex) over the prepared
        /// `DeviceRevoked` event bytes. Omit to PREPARE (print the bytes to
        /// sign); supply to COMMIT. Only meaningful with `--external-signer`.
        #[arg(long = "operator-signature-hex", value_name = "DER_HEX")]
        operator_signature_hex: Option<String>,
        /// **Off-host external signer flow** (YubiKey PIV / PKCS#11 / `gpg` /
        /// `ssh-keygen -Y sign`). Two-call PREPARE → COMMIT against the
        /// daemon. Requires `--authority-device-key`. Without this flag the
        /// CLI defaults to the SE-driven single-command lane (one Touch ID
        /// tap; matches `device enroll --secure-enclave`). Supplying
        /// `--operator-signature-hex` implies `--external-signer` for
        /// backward compatibility.
        #[arg(long = "external-signer")]
        external_signer: bool,
        /// Keychain label of the Secure Enclave signing key the SE-driven
        /// lane uses. Defaults to `ember-operator-presence` (the same default
        /// `device enroll --secure-enclave` writes to).
        #[arg(long, default_value = "ember-operator-presence")]
        se_label: String,
        /// Treat the revoked Device as compromised (its private key may have
        /// leaked): in addition to the always-on cascade-delete of the
        /// Device's `presence_scope_kek` wraps, the daemon rotates `KEK_s`
        /// per persona scope under the operator root. A fresh `KEK_s` is
        /// generated, surviving recipients receive a new wrap, and the old
        /// wraps the leaked Device could have unwrapped are replaced
        /// wholesale. Use when the lost Device's ECIES private key may be in
        /// adversary hands; omit for a routine retire / hardware swap
        /// (cascade-delete only).
        #[arg(long)]
        compromised: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum VaultAction {
    /// Add a credential to the vault
    ///
    /// Default behavior (no --value, no --stdin) prompts interactively with
    /// echo off — the safest form. Use --stdin for pipes/scripts. Use --value
    /// only for non-secret values; the value will appear in shell history.
    Add {
        /// Credential name
        #[arg(long)]
        name: String,
        /// REFUSED — passing secrets via argv leaks them. Kept for argv-parse so we
        /// can emit a structured error pointing at --stdin / --file.
        #[arg(long, hide = true)]
        value: Option<String>,
        /// Read credential value from stdin (no shell history leak; trailing newline trimmed).
        #[arg(long, conflicts_with_all = ["value", "file"])]
        stdin: bool,
        /// Read credential value from a file (binary-safe; no leak).
        #[arg(long, conflicts_with_all = ["value", "stdin"])]
        file: Option<std::path::PathBuf>,
        /// With --file: zero the file's bytes then unlink it after vault-encrypt.
        /// Use for one-shot transfers (paste into a tmpfile, ember adds, file is gone).
        #[arg(long, requires = "file")]
        delete_source: bool,
        /// Allow --file paths under ~/Downloads (default: refused — Downloads is a
        /// known cleartext-credential leak surface).
        #[arg(long, requires = "file")]
        from_downloads: bool,
        /// Optional metadata
        #[arg(long)]
        metadata: Option<String>,
        /// Require a fresh biometric presence proof for every future read.
        #[arg(long)]
        require_biometric: bool,
    },
    /// List stored credentials
    List(VaultListArgs),
    /// Retrieve a credential value (masked by default)
    Get(VaultGetArgs),
    /// Store a credential value (alias for `add`; safe-input flags only).
    ///
    /// This is the operator-facing
    /// surface for the `CredentialStore::put` trait method shipped in
    /// PR #2454. Refuses `--value <secret>` argv form (leaks via shell
    /// history); use `--stdin` or `--file <path>`.
    Put(VaultPutArgs),
    /// Remove a credential
    Remove {
        /// Credential name
        name: String,
    },
    /// Export every credential as an age-encrypted JSON envelope.
    ///
    /// Each value is sealed individually under the operator's age
    /// recipient key (`~/.config/emberlink/recipient.age` by default);
    /// names are visible so the operator can audit what's stored. Use
    /// `ember vault import` to restore on another host.
    Export(VaultExportArgs),
    /// Import a JSON envelope produced by `ember vault export`.
    ///
    /// All entries decrypt-and-write atomically: any decryption failure
    /// aborts before any `put` runs, so the live vault never sees a
    /// partial restore.
    Import(VaultImportArgs),
    /// Re-lock the vault session.
    ///
    /// Equivalent to letting the idle timer expire — but explicit. After
    /// this runs, the next high-risk op (vault add, vault remove, grant
    /// create, persona key export) will require fresh user presence
    /// (Touch ID on macOS).
    Lock,
    /// Re-open the vault session explicitly after `ember vault lock`.
    ///
    /// On the daemon-backed path this is the current non-session operator
    /// reopen seam. It does not yet make the accepted lazy first-session
    /// unlock posture live; it is an explicit operator action.
    Unlock,
    /// ADR 206 §4 — provision presence-as-decryption custody (one-shot, post-enroll).
    ///
    /// Generates the operator authority scope KEK, seals it to this device's
    /// Secure-Enclave ECIES recipient key (no Touch ID — public-key wrap), and
    /// registers the wrapped blob with the daemon so a later `vault se-unlock`
    /// can recover it with one tap. Also installs the KEK for the current window
    /// so persona creation can seal immediately. macOS only.
    SeProvision {
        /// Keychain label of the presence SIGNING key (the ECIES recipient is
        /// derived as `<se-label>-ecies`). Must match the label used at enroll.
        #[arg(long, default_value = "ember-operator-presence")]
        se_label: String,
    },
    /// ADR 206 §4 — unlock authority-bearing custody with a presence tap.
    ///
    /// Fetches the daemon's stored wrapped scope KEK for this device, performs
    /// the Secure-Enclave `se_unwrap` (the Touch ID / passcode gesture), and
    /// hands the unwrapped KEK back to the daemon to serve the unlock window.
    /// The daemon never holds the presence-gated SE key. macOS only.
    SeUnlock {
        /// Keychain label of the presence SIGNING key (ECIES recipient is
        /// `<se-label>-ecies`). Must match the label used at enroll/provision.
        #[arg(long, default_value = "ember-operator-presence")]
        se_label: String,
        /// ADR 206 §6 — recover with a printed `age` recovery code instead of a
        /// presence tap (use after device loss). Pass the `AGE-SECRET-KEY-1…`
        /// secret; it is used locally to decrypt `KEK_s` and is never sent to the
        /// daemon. Rotate the code after use.
        #[arg(long, value_name = "AGE-SECRET-KEY")]
        recovery_code: Option<String>,
    },
    /// ADR 206 §6 — enroll an off-host **recovery recipient** (printed `age` code)
    /// so device loss never becomes identity loss.
    ///
    /// Generates a one-time `age` recovery code IN THIS SESSION (the daemon never
    /// sees the secret), prints it ONCE to store off-host, enrolls its public half
    /// as a `CustodyClass::Recovery` Device under your operator root (one presence
    /// tap by your existing device), and wraps the authority scope `KEK_s` to it.
    /// Recover later with `ember vault se-unlock --recovery-code …`. macOS only.
    EnrollRecovery {
        /// Keychain label of the presence SIGNING key that AUTHORIZES the
        /// enrollment (your existing operator device). Must match enroll/provision.
        #[arg(long, default_value = "ember-operator-presence")]
        se_label: String,
        /// Human label recorded for this recovery recipient.
        #[arg(long, default_value = "Printed recovery code")]
        label: String,
    },
    /// Re-store the vault MEK passphrase with the platform-current ACL.
    ///
    /// One-shot migration for pre-existing MEK entries created before
    /// the macOS biometric ACL shipped. After this runs, vault unlocks
    /// via Touch ID / device passcode instead of the plain keychain password.
    /// Idempotent: safe to run multiple times.
    MigrateAcl,
}

/// Args for `ember vault list`.
///
/// `--prefix <pat>` filters to credential names beginning with `<pat>`.
/// Empty prefix lists every credential (the default).
#[derive(Debug, Args)]
pub struct VaultListArgs {
    /// Filter to names starting with this prefix.
    #[arg(long)]
    pub prefix: Option<String>,
}

/// Args for `ember vault get`.
///
/// Default behaviour masks all but the last 4 chars (e.g. `****abcd` for
/// `<long>abcd`; `****` for values shorter than 4 chars). `--unmask`
/// prints the raw value but only when stdout is non-TTY (e.g. piped) or
/// `--i-know-what-im-doing` is set, to protect screen-recording demos
/// from accidental leaks.
#[derive(Debug, Args)]
pub struct VaultGetArgs {
    /// Credential name.
    pub name: String,
    /// Print the raw value. Refused on a TTY unless --i-know-what-im-doing.
    #[arg(long)]
    pub unmask: bool,
    /// Acknowledge the leak risk and unmask even on a TTY.
    #[arg(long)]
    pub i_know_what_im_doing: bool,
}

/// Args for `ember vault put`.
///
/// Mirrors `ember vault add` for the safe-input flags (`--stdin`,
/// `--file`, `--delete-source`, `--from-downloads`); `--value <secret>`
/// argv form is refused via [`refuse_value_in_argv`].
#[derive(Debug, Args)]
pub struct VaultPutArgs {
    /// Credential name.
    #[arg(long)]
    pub name: String,
    /// REFUSED — passing secrets via argv leaks them. Surfaces a
    /// structured error pointing at `--stdin` / `--file`.
    #[arg(long, hide = true)]
    pub value: Option<String>,
    /// Read credential value from stdin (no shell history leak).
    #[arg(long, conflicts_with_all = ["value", "file"])]
    pub stdin: bool,
    /// Read credential value from a file (binary-safe; no leak).
    #[arg(long, conflicts_with_all = ["value", "stdin"])]
    pub file: Option<std::path::PathBuf>,
    /// With `--file`: zero the file's bytes then unlink it after vault-encrypt.
    #[arg(long, requires = "file")]
    pub delete_source: bool,
    /// Allow `--file` paths under `~/Downloads` (default: refused).
    #[arg(long, requires = "file")]
    pub from_downloads: bool,
    /// Optional metadata.
    #[arg(long)]
    pub metadata: Option<String>,
    /// Require a fresh biometric presence proof for every future read.
    #[arg(long)]
    pub require_biometric: bool,
}

/// Args for `ember vault export`.
///
/// Lists every credential and seals each value individually under the
/// operator's age recipient key. Output JSON shape:
///
/// ```json
/// {
///   "version": 1,
///   "exported_at": "2026-05-10T...",
///   "recipient": "age1...",
///   "entries": [
///     { "name": "azure/tenant-id", "value_age_armored": "-----BEGIN AGE..." }
///   ]
/// }
/// ```
#[derive(Debug, Args)]
pub struct VaultExportArgs {
    /// Output format. Currently only `json` is supported.
    #[arg(long, default_value = "json")]
    pub format: String,
    /// Export a passphrase-sealed EMVS backup of the vault MEK instead of
    /// the age-encrypted JSON credential envelope.
    #[arg(long)]
    pub sealed: bool,
    /// Require the recovery-passphrase input lane. Supplying a value is
    /// accepted at parse time so dispatch can emit the standard argv-secret
    /// refusal; use `--stdin` or `--file`.
    #[arg(
        long = "recovery-passphrase",
        requires = "sealed",
        num_args = 0..=1,
        default_missing_value = "",
        value_name = "VALUE"
    )]
    pub recovery_passphrase: Option<Option<String>>,
    /// Read the sealed-export recovery passphrase from stdin.
    #[arg(long, requires = "sealed", conflicts_with = "file")]
    pub stdin: bool,
    /// Read the sealed-export recovery passphrase from a file.
    #[arg(long, requires = "sealed", conflicts_with = "stdin")]
    pub file: Option<std::path::PathBuf>,
    /// With sealed `--file`: zero the passphrase file's bytes then unlink it
    /// after the daemon accepts the export.
    #[arg(long, requires = "file")]
    pub delete_source: bool,
    /// Allow sealed `--file` paths under `~/Downloads` (default: refused).
    #[arg(long, requires = "file")]
    pub from_downloads: bool,
    /// Output file path (default: stdout). Created with mode 0600.
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,
    /// Path to the operator's age recipient public key.
    /// Defaults to `$XDG_CONFIG_HOME/emberlink/recipient.age` (or `~/.config/...`).
    #[arg(long)]
    pub recipient_key: Option<std::path::PathBuf>,
}

/// Args for `ember vault import`.
///
/// Decrypts every entry first; only on full success does it `put` each
/// entry. Any decryption failure aborts before any write so the live
/// vault never sees a partial restore.
#[derive(Debug, Args)]
pub struct VaultImportArgs {
    /// Input format. Currently only `json` is supported.
    #[arg(long, default_value = "json")]
    pub format: String,
    /// Path to the JSON envelope produced by `ember vault export`.
    #[arg(long, conflicts_with = "file")]
    pub from: Option<std::path::PathBuf>,
    /// Import a passphrase-sealed EMVS vault-MEK backup instead of the
    /// age-encrypted JSON credential envelope.
    #[arg(long)]
    pub sealed: bool,
    /// Path to the sealed EMVS blob for `--sealed` import.
    #[arg(long, requires = "sealed", conflicts_with = "from")]
    pub file: Option<std::path::PathBuf>,
    /// Expected blake3(MEK) fingerprint for the sealed import.
    #[arg(long, requires = "sealed")]
    pub expected_fingerprint: Option<String>,
    /// Require the recovery-passphrase input lane. Supplying a value is
    /// accepted at parse time so dispatch can emit the standard argv-secret
    /// refusal; use `--stdin`.
    #[arg(
        long = "recovery-passphrase",
        requires = "sealed",
        num_args = 0..=1,
        default_missing_value = "",
        value_name = "VALUE"
    )]
    pub recovery_passphrase: Option<Option<String>>,
    /// Read the sealed-import recovery passphrase from stdin.
    #[arg(long, requires = "sealed")]
    pub stdin: bool,
    /// With sealed `--file`: zero the blob file's bytes then unlink it after
    /// the daemon accepts the import.
    #[arg(long, requires = "file")]
    pub delete_source: bool,
    /// Allow sealed `--file` paths under `~/Downloads` (default: refused).
    #[arg(long, requires = "file")]
    pub from_downloads: bool,
    /// Path to the operator's age identity (private key) file.
    /// Defaults to `$XDG_CONFIG_HOME/emberlink/identity.age` (or `~/.config/...`).
    #[arg(long)]
    pub identity_key: Option<std::path::PathBuf>,
}

// boxing the variant is a separate change; allow for the lint-clear.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(super) enum GrantAction {
    /// Create a new grant
    Create {
        /// Persona ID
        #[arg(long)]
        persona: String,
        /// Optional rendered grant kind. `spend` creates a payment statement
        /// instead of a credential/session lane.
        #[arg(long, value_enum)]
        kind: Option<GrantSurfaceKind>,
        /// Credential name (required for standard grants)
        #[arg(long)]
        credential: Option<String>,
        /// Access scope (required for standard grants)
        #[arg(long)]
        scope: Option<String>,
        /// Time-to-live (humantime: 5s, 5m, 2h — bare integer also accepted as seconds)
        #[arg(long)]
        ttl: Option<String>,
        /// Spend-grant vendor allowlist entry (required for `--kind spend`)
        #[arg(long)]
        vendor: Option<String>,
        /// Spend-grant per-attempt approval threshold in integer cents
        #[arg(long)]
        max_cents: Option<u64>,
        /// Spend-grant validity window (alias for TTL on the spend lane)
        #[arg(long)]
        window: Option<String>,
        /// Spend-grant total hard cap in integer cents
        #[arg(long)]
        hard_cap: Option<u64>,
        /// Max uses per hour (rate limit)
        #[arg(long)]
        rate_limit: Option<u64>,
        /// Allowed hours start (0-23 UTC)
        #[arg(long)]
        hours_start: Option<u32>,
        /// Allowed hours end (0-23 UTC)
        #[arg(long)]
        hours_end: Option<u32>,
        /// Allowed target domains (comma-separated)
        #[arg(long)]
        allowed_targets: Option<String>,
        /// Max delegation depth for sub-agents
        #[arg(long)]
        delegation_depth: Option<u32>,
        /// Token budget ceiling
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Cost budget ceiling in USD (e.g. "0.50" → 50 cents stored). Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Request count budget ceiling
        #[arg(long)]
        budget_requests: Option<u64>,
        /// Wall-clock seconds budget ceiling
        #[arg(long)]
        budget_seconds: Option<u64>,
        /// Attestation runtime label (e.g. "claude_code")
        #[arg(long)]
        attestation_runtime: Option<String>,
        /// Mark the grant as a standing parent (P69L.3) — subsequent
        /// `ember grant delegate <id>` calls mint child grants without
        /// re-prompting, subject to `--max-children-per-day`.
        #[arg(long)]
        standing: bool,
        /// Trailing-24h delegation ceiling for a standing parent. Required
        /// when `--standing` is set; ignored otherwise.
        #[arg(long)]
        max_children_per_day: Option<u64>,
        /// Opaque scope template the orchestrator applies when auto-
        /// delegating from this standing parent. Advisory — stored on
        /// the parent, read by the orchestrator.
        #[arg(long)]
        auto_delegate_scope_template: Option<String>,
    },
    /// Delegate a grant to a sub-agent with narrowed scope
    ///
    /// Child authority is bounded by the parent on every axis (scope,
    /// budget, expiry) per ADR 072 § Offline attenuation. Violations
    /// exit non-zero with a message naming only the failing dimension.
    Delegate {
        /// Parent grant ID
        #[arg(value_name = "PARENT_GRANT_ID")]
        parent: String,
        /// Child persona ID
        #[arg(long = "to", value_name = "CHILD_PERSONA_ID")]
        persona: String,
        /// Narrowed scope (must be a subset of parent scope)
        #[arg(long)]
        scope: String,
        /// Time-to-live (e.g. 1h, 30m, 60s; bare integer = seconds)
        #[arg(long)]
        ttl: Option<String>,
        /// Child token budget (must fit parent's remaining allowance)
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Child cost budget in USD (e.g. "0.50" → 50 cents stored). Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Child request-count budget
        #[arg(long)]
        budget_requests: Option<u64>,
        /// Child wall-clock budget in seconds
        #[arg(long)]
        budget_seconds: Option<u64>,
    },
    /// List all grants
    List {
        /// Show only active grants
        #[arg(long)]
        active: bool,
        /// Restrict the list to the spend/payment grant renderer
        #[arg(long, value_enum)]
        kind: Option<GrantSurfaceKind>,
    },
    /// Show one grant in detail
    Show {
        /// Grant ID
        id: String,
    },
    /// Preflight a spend attempt against an existing grant
    Evaluate {
        /// Grant ID
        #[arg(long)]
        grant: String,
        /// TOML file describing the spend attempt (`vendor`, `amount_cents`, optional `attempt_id`, ...)
        #[arg(long)]
        attempt: PathBuf,
    },
    /// Revoke a grant
    Revoke {
        /// Grant ID to revoke
        id: String,
    },
    /// Expire stale grants
    Expire,
    /// Show budget and usage for a grant
    Budget {
        /// Grant ID
        grant_id: String,
    },
    /// Extend a grant's budget and/or TTL
    Extend {
        /// Grant ID
        grant_id: String,
        /// Additional tokens to add to budget
        #[arg(long)]
        tokens: Option<u64>,
        /// Additional cents to add to budget (e.g. "0.25")
        #[arg(long)]
        cents: Option<String>,
        /// Additional TTL duration (e.g. 15s, 5m, 2h, 1d, or bare seconds)
        #[arg(long)]
        ttl: Option<String>,
    },
}

#[derive(Subcommand)]
pub(super) enum SandboxAction {
    /// Create a new sandbox
    Create {
        /// Sandbox name
        #[arg(long)]
        name: String,
        /// Container image
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Run container with elevated privileges (refused by invariant unless --unsafe-root)
        #[arg(long)]
        privileged: bool,
        /// Bind mount in `host:container[:ro]` form. Denylisted sources are refused.
        #[arg(long = "volume", short = 'v')]
        volume: Vec<String>,
        /// User override. `--user 0` / `--user root` refused unless --unsafe-root.
        #[arg(long)]
        user: Option<String>,
        /// Docker network mode. Default is bridge. `host` is refused.
        #[arg(long)]
        network: Option<String>,
        /// Explicit opt-in to run as root (overrides the no-root-user invariant).
        #[arg(long)]
        unsafe_root: bool,
        /// Clone the given git URL into the sandbox's workspace before starting.
        #[arg(long = "workspace-from")]
        workspace_from: Option<String>,
        /// Additional `KEY=VAL` env var to pass into the container.
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
        /// Owner persona ID recorded for future `exec` authorization.
        /// Defaults to the `EMBER_PERSONA_ID` environment variable.
        #[arg(long = "persona")]
        persona: Option<String>,
    },
    /// List all sandboxes
    List,
    /// Stop a sandbox
    Stop {
        /// Sandbox ID
        id: String,
    },
    /// Delete a sandbox: remove container + DB row + (if no other refs)
    /// auto-created persona. Idempotent on already-gone state.
    ///
    /// Unblocks `ember sandbox create --name X` retries
    /// after a previous container start failed and left the persona row +
    /// stale docker container behind. `ember sandbox delete <id|name>` is
    /// the GC path; `stop` only halts (sandbox row + persona stay).
    Delete {
        /// Sandbox ID or name
        id: String,
    },
    /// Execute a command in a sandbox
    Exec {
        /// Sandbox ID
        id: String,
        /// Calling persona ID. Defaults to the `EMBER_PERSONA_ID` environment variable.
        /// Must match the sandbox's owner persona.
        #[arg(long = "persona")]
        persona: Option<String>,
        /// Command to run
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run an agent in a new sandbox with a 3-statement composite grant
    /// (Credential + Session + Time) in a single approval envelope.
    Run {
        /// Sandbox name
        name: String,
        /// Container image
        #[arg(long, default_value = "ubuntu:24.04")]
        image: String,
        /// Clone the given git URL into the sandbox's workspace before starting.
        #[arg(long = "workspace-from")]
        workspace_from: Option<String>,
        /// Additional `KEY=VAL` env var (or bare `KEY` to pass-through from host env) to inject.
        #[arg(long = "env", short = 'e')]
        env: Vec<String>,
        /// Credential object ID for the Credential statement (e.g. "obj-github-token").
        /// Required to mint the 3-statement composite grant; omit to skip grant creation.
        #[arg(long)]
        credential_resource: Option<String>,
        /// Token budget ceiling for the Session statement (LLM tokens).
        #[arg(long)]
        budget_tokens: Option<u64>,
        /// Cost budget ceiling in USD (e.g. "0.50" → 50 cents stored) for the Session statement. Accepts decimal.
        #[arg(long)]
        budget_usd: Option<String>,
        /// Wall-clock seconds ceiling for the Time statement.
        #[arg(long)]
        budget_seconds: Option<u64>,
        /// Grant TTL (e.g. "30m", "2h", "1d"). Default: no expiry.
        #[arg(long)]
        ttl: Option<String>,
        /// Prompt to pass to the agent inside the sandbox.
        #[arg(long)]
        prompt: Option<String>,
    },
    /// Run an agent task end-to-end through the SCION container-isolated
    /// orchestration loop: grant-mint → orchestrator-ready → brief-delivery →
    /// worker-spawn → task-running → diff-integrate → pr-ship → receipt-rollup.
    ///
    /// This is the intended operator-facing entrypoint for the SCION
    /// lane. Today it drives real host-side orchestrator spawn,
    /// terminal spawn-checkpoint completion, and brief forwarding;
    /// later worker/task/ship/receipt steps are still scaffolded.
    RunScion {
        /// Task ID to run (e.g. DEPLOY-PREVIEW). Must be UPPERCASE with
        /// hyphens only.
        #[arg(long)]
        task: String,
        /// Optional TTL for the orchestrator grant (e.g. "30m", "2h", "1d").
        #[arg(long)]
        ttl: Option<String>,
        /// Print the 8-step execution plan and exit 0 without running anything.
        #[arg(long)]
        dry_run: bool,
        /// Stream checkpoint events to stdout as each step completes.
        #[arg(long)]
        stream_checkpoints: bool,
        /// Skip receipt-rollup (step 8). Useful for debugging earlier steps.
        #[arg(long)]
        no_receipt_tree: bool,
    },
}

#[derive(Subcommand)]
pub(super) enum ApprovalAction {
    /// List pending approval requests
    List,
    /// Approve a pending request
    Approve {
        /// Approval request ID
        id: String,
        /// Create a standing grant so future matching requests auto-approve
        #[arg(long)]
        always: bool,
        /// TTL for the standing grant (e.g. 7d, 30d, 90d, never). Default: 30d
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Deny a pending request
    Deny {
        /// Approval request ID
        id: String,
        /// Reason for denial
        #[arg(long)]
        reason: String,
    },
    /// Narrow and approve with reduced scope
    Narrow {
        /// Approval request ID
        id: String,
        /// New narrowed scope
        #[arg(long)]
        scope: String,
    },
}

#[derive(Subcommand)]
pub(super) enum ReceiptAction {
    /// List receipts, most-recent first
    List {
        /// Filter by persona id
        #[arg(long)]
        persona: Option<String>,
        /// Emit a JSON array with full UUIDs (no truncation) instead of the table view
        #[arg(long)]
        json: bool,
    },
    /// Show the full receipt for a given id
    Show {
        /// Receipt id (or grant id)
        id: String,
        /// Output format: `json` (default) or `md` (markdown).
        #[arg(long, default_value = "json")]
        format: String,
        /// Show full sidecar content. Today a no-op (forward-compat
        /// surface; the v2 receipt envelope carries the full sidecar
        /// inline, so this flag is reserved for the v3 split-sidecar
        /// shape).
        #[arg(long)]
        raw: bool,
    },
    /// Export a receipt's signed JSON to stdout
    Export {
        /// Receipt id.
        #[arg(required_unless_present = "latest")]
        id: Option<String>,
        /// Export the most recent receipt (friendly Touch-2 shortcut).
        #[arg(long, conflicts_with = "id")]
        latest: bool,
        /// Output format: `json` (default) or `md` (markdown).
        #[arg(long, default_value = "json")]
        format: String,
        /// Show full sidecar content. Today a no-op (forward-compat
        /// surface; the v2 receipt envelope carries the full sidecar
        /// inline, so this flag is reserved for the v3 split-sidecar
        /// shape).
        #[arg(long)]
        raw: bool,
    },
    /// Verify a receipt's Ed25519 signature against the daemon's identity key.
    ///
    /// Either pass a receipt `id` (looked up in the local daemon's store) or
    /// `--file <PATH>` to verify an exported receipt JSON offline (use `-`
    /// for stdin). Offline verification is what makes Grant Receipts a
    /// third-party-verifiable artifact (CEO-009).
    ///
    /// `--tree <PATH> --offline` verifies a tree-export JSON produced by
    /// `ember receipt tree --export`. The verify path is daemon-free: the
    /// trust anchor pubkey is embedded in the export file and no socket
    /// connection is made. This is the Beat 8 demo close.
    Verify {
        /// Receipt id (looked up from the local daemon store).
        /// Mutually exclusive with `--file`.
        #[arg(conflicts_with_all = ["file", "materialization", "tree"])]
        id: Option<String>,
        /// Verify a receipt JSON file. `-` reads from stdin.
        /// Mutually exclusive with `id`.
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
        /// Override the trust anchor — expected signer pubkey (hex).
        /// When omitted, reads from the Daemon Persona key file under
        /// `<data_dir>/daemon_persona.key`. Required in practice for
        /// `--file` mode against receipts signed by a different daemon.
        #[arg(long)]
        pubkey: Option<String>,
        /// Verify chain integrity for a construct-invocation rollup, keyed
        /// by `materialization_id`. Walks the sub-Receipts in
        /// `--events` and exits non-zero if the chain is broken (e.g.
        /// missing `broker.materialization` head, or `Incomplete` because
        /// the daemon crashed mid-spawn).
        #[arg(long, value_name = "MATERIALIZATION_ID")]
        materialization: Option<String>,
        /// Override the events-log path used by `--materialization`.
        /// Defaults to `<data_dir>/events.jsonl`.
        #[arg(long, value_name = "PATH")]
        events: Option<PathBuf>,
        /// Verify a tree-export JSON produced by `ember receipt tree
        /// --export <path>`. Daemon-free: the trust anchor is embedded in
        /// the file.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["id", "file", "materialization"])]
        tree: Option<PathBuf>,
        /// Confirm the offline-verify intent. When `--tree` is set,
        /// `--offline` documents that no daemon RPC will be made. Today
        /// the flag is informational — the verify path is always
        /// daemon-free.
        #[arg(long)]
        offline: bool,
    },
    /// Walk the grant graph rooted at `--grant <id>` and render the
    /// delegated authority + receipt artifact set as a tree.
    ///
    /// `--export <PATH>` additionally writes a JSON export shape that
    /// `ember receipt verify --tree <PATH> --offline` consumes for
    /// third-party verification after `ember daemon stop`. This is the
    /// Beat 8 demo close artifact.
    Tree {
        /// Root grant id — typically the orchestrator's composite grant.
        #[arg(long)]
        grant: String,
        /// Optional JSON-export destination for offline verify.
        #[arg(long, value_name = "PATH")]
        export: Option<PathBuf>,
    },
    /// Aggregate construct-invocation sub-Receipts into one row per
    /// `materialization_id` (per `docs/construct-receipt-rollup.md`).
    ///
    /// Reads the daemon's `events.jsonl` (or `--events <PATH>`), groups by
    /// `materialization_id`, and renders a `RECEIPTS / STARTED / OUTCOME / ACTION`
    /// table. Use `--json` for machine-parseable output.
    Rollup {
        /// Filter rollups whose `started_at` is older than this cutoff.
        /// Forms: `1h`, `24h`, `7d`, `all`, or any RFC-3339 timestamp.
        #[arg(long, default_value = "all")]
        since: String,
        /// Show only the rollup matching this `materialization_id`.
        #[arg(long, value_name = "MATERIALIZATION_ID")]
        materialization: Option<String>,
        /// Restrict output to chains missing `session.construct_invocation`
        /// (operator-followup signal — daemon crashed mid-spawn).
        #[arg(long)]
        incomplete_only: bool,
        /// Override the events-log path. Defaults to
        /// `<data_dir>/events.jsonl`.
        #[arg(long, value_name = "PATH")]
        events: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(super) enum AuditAction {
    /// Show recent audit entries
    Show {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
        /// Maximum number of entries
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Export audit log
    Export {
        /// Output format (json or csv)
        #[arg(long, default_value = "json")]
        format: String,
        /// Maximum entries
        #[arg(long)]
        limit: Option<usize>,
        /// Filter by agent
        #[arg(long)]
        agent: Option<String>,
        /// Output file (stdout if not specified)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Lower bound on receipt created_at for signed CBOR export.
        /// Accepts ISO-8601 or relative duration (`24h`, `7d`, `30m`).
        #[arg(long)]
        since: Option<String>,
        /// Filter signed CBOR export by workflow/delegation template name.
        #[arg(long)]
        workflow: Option<String>,
        /// Closed-set redaction rules: gh-token-values, pr-titles, binary-paths.
        #[arg(long, value_name = "RULE,...")]
        redact: Option<String>,
        /// Produce an ADR 160 signed CBOR compliance bundle.
        #[arg(long)]
        sign: bool,
    },
    /// Explain the full decision chain for an audit event
    Explain {
        /// Audit event ID
        id: String,
    },
    /// Query the receipts table.
    ///
    /// Returns the unified audit view across grant, kms_wrap, and
    /// kms_unwrap receipts. Filters AND-combine. Use `--json` for raw
    /// machine-readable rows; default rendering is a fixed-width table.
    Query {
        /// Lower bound on `materialized_at`. Accepts ISO-8601
        /// (`2026-04-01T00:00:00Z`) or relative duration (`24h`, `7d`).
        #[arg(long)]
        since: Option<String>,
        /// Filter by actor (persona id).
        #[arg(long)]
        actor: Option<String>,
        /// Filter by receipt kind (`grant`, `kms_wrap`, `kms_unwrap`).
        #[arg(long)]
        kind: Option<String>,
        /// Filter by grant id.
        #[arg(long)]
        grant_id: Option<String>,
        /// Substring match on the resource label.
        #[arg(long)]
        resource: Option<String>,
        /// Emit raw JSON rows instead of the fixed-width table.
        #[arg(long)]
        json: bool,
        /// Maximum rows to return (default 100).
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Aggregate receipt-backed audit rows.
    Summary {
        /// Lower bound on `created_at`. Accepts ISO-8601
        /// (`2026-04-01T00:00:00Z`) or relative duration (`24h`, `7d`).
        #[arg(long)]
        since: Option<String>,
        /// Filter by workflow/delegation template name.
        #[arg(long)]
        workflow: Option<String>,
        /// Filter by persona id.
        #[arg(long)]
        persona: Option<String>,
        /// Output format.
        #[arg(long, default_value = "human", value_parser = ["human", "json"])]
        format: String,
        /// Emit raw JSON summary.
        #[arg(long)]
        json: bool,
    },
    /// Walk the audit chain and
    /// verify each row's `blake3(prev_hash || canonical_row_bytes)`
    /// matches its stored `row_hash`. Routes through the daemon's
    /// `audit_verify` socket method so the verdict is authoritative
    /// (same path the daemon's startup verify uses).
    Verify {
        /// Limit the walk to the most recent N rows. Omit for a full-chain walk.
        #[arg(long, conflicts_with_all = ["import", "since"])]
        tail: Option<usize>,
        /// Compatibility window for ship-gate runbooks. Accepts ISO-8601 or relative durations
        /// like `1d`, `7d`, or `24h`; currently walks the full chain.
        #[arg(long, value_name = "WINDOW", conflicts_with_all = ["tail", "import"])]
        since: Option<String>,
        /// Verify a signed CBOR audit export bundle offline.
        #[arg(
            long = "import",
            value_name = "PATH",
            conflicts_with_all = ["tail", "since"]
        )]
        import: Option<PathBuf>,
        /// Trust roots used to verify daemon ReceiptEnvelope signatures.
        #[arg(long = "trust-roots", value_name = "ROOT,...", value_delimiter = ',')]
        trust_roots: Vec<String>,
        /// Expected operator public key for the detached bundle signature.
        #[arg(long = "operator-pubkey", value_name = "PUBKEY")]
        operator_pubkey: Option<String>,
    },
    /// Report combined audit disk footprint across
    /// the prod (`~/.ember/audit/`) and dev (`~/.ember-dev/audit/`)
    /// daemons. Splits the total into primary / archive / sidecar
    /// buckets per ADR 160 §C2 and flags daemons within 80% / above
    /// 100% of the v0.3.0 dev0 ceiling (5 GiB per cohort-defaults
    /// Knob 14). audit_df_command_landed.
    Usage,
    /// Emit the canonical bytes the operator's presence Device co-signs
    /// for an `audit_repair_chain` repair intent (ADR 174 v2 §4 / ADR
    /// 200 §6 / PR #5684). Pure offline helper — pipes the bytes (and
    /// their SHA-256 + BLAKE3) into off-host signing tools (e.g.
    /// `yubico-piv-tool -a sign-data -A ECCP256 -s 9c`) so the operator
    /// hardware step is reproducible without a separate
    /// `audit_repair_chain_prepare` daemon RPC.
    #[command(name = "canonical-repair-intent")]
    CanonicalRepairIntent {
        /// `from_row_id` — the audit_log row id from which the repair
        /// truncates (the operator-asserted last good row).
        #[arg(long, value_name = "I64")]
        from_row: i64,
        /// `current_chain_tip_hash` — the BLAKE3 hex `row_hash` of the
        /// audit_log row at `--from-row` BEFORE any truncate (the hash the
        /// daemon will preserve as the new chain tip's `prev_hash`).
        #[arg(long, value_name = "HEX")]
        tip_hash: String,
        /// `daemon_identity_root_fingerprint` — the daemon identity-root
        /// fingerprint at the time of co-signing, bound into the canonical
        /// bytes so a stolen operator signature from one daemon cannot be
        /// replayed against another.
        #[arg(long, value_name = "HEX")]
        daemon_fingerprint: String,
    },
    /// Offline-verify a `RepairIntent` JSON against one or more enrolled
    /// presence-Device pubkeys (ADR 200 §6 / PR #5684). Reconstructs the
    /// canonical bytes, verifies the P-256 signature against each
    /// supplied `--presence-pubkey`, and reports which device_id would
    /// have matched the daemon-side `verify_repair_intent_signature`.
    /// Pure operator-side check — no daemon roundtrip.
    #[command(name = "verify-repair-intent")]
    VerifyRepairIntent {
        /// Path to a RepairIntent JSON (the wire shape the
        /// `audit_repair_chain` RPC accepts).
        #[arg(value_name = "INTENT_PATH")]
        intent: PathBuf,
        /// One or more candidate enrolled presence-Device signing
        /// pubkeys (`p256:<sec1-hex>` from the AC-2 cards). Verifier
        /// matches the signature against the first one that verifies and
        /// emits the corresponding device_id (per
        /// `operator_oob_ids_from_device_key`). Pass primary AND backup
        /// to mirror the daemon's 1-of-N presence-set check.
        #[arg(long = "presence-pubkey", value_name = "P256_PUBKEY")]
        presence_pubkeys: Vec<String>,
    },
    /// Submit an operator co-signed `audit_repair_chain` repair to the
    /// daemon (ADR 174 v2 §2 / ADR 200 §6 / PR #5684). The operator has
    /// already (a) gotten canonical bytes via `canonical-repair-intent`,
    /// (b) signed them off-host with a presence Device, and (c)
    /// offline-verified the signed intent via `verify-repair-intent`.
    /// This verb submits the signed intent over the daemon socket. The
    /// daemon-side `verify_repair_intent_signature` is the trust source;
    /// a sig that didn't actually verify against the daemon-materialized
    /// presence set is rejected regardless of what the offline check said.
    #[command(name = "repair-chain")]
    RepairChain {
        /// `from_row_id` — the audit_log row id from which the repair
        /// truncates (the operator-asserted last good row).
        #[arg(long, value_name = "I64")]
        from_row: i64,
        /// `current_chain_tip_hash` — the BLAKE3 hex `row_hash` of the
        /// audit_log row at `--from-row` BEFORE any truncate.
        #[arg(long, value_name = "HEX")]
        tip_hash: String,
        /// `daemon_identity_root_fingerprint` — bound into the canonical
        /// bytes so a stolen operator sig cannot be replayed against
        /// another daemon.
        #[arg(long, value_name = "HEX")]
        daemon_fingerprint: String,
        /// The operator's presence Device signing pubkey
        /// (`p256:<sec1-hex>`) — the one whose AC-2 card recorded the
        /// `device_id` the daemon will stamp on the repair receipt.
        #[arg(long, value_name = "P256_PUBKEY")]
        operator_pubkey: String,
        /// DER-encoded ECDSA-P256 signature (hex) over the canonical
        /// repair-intent bytes, produced off-host by the presence
        /// Device (`yubico-piv-tool -a sign-data -A ECCP256 -s 9c` or
        /// Apple Secure-Enclave equivalent).
        #[arg(long, value_name = "DER_HEX")]
        operator_signature_hex: String,
        /// Repair strategy. v0.3 ships exactly `truncate`;
        /// `tombstone_segment` is reserved (the daemon rejects it
        /// today). Default `truncate`.
        #[arg(long, value_name = "STRATEGY", default_value = "truncate")]
        repair_kind: String,
    },
}
