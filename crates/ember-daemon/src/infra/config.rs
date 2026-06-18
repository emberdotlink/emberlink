use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::spawn::runtime::RuntimeBackend;

pub const DEFAULT_DASHBOARD_ADDR: &str = "127.0.0.1:3141";
pub const DEFAULT_LLM_PROXY_ADDR: &str = "127.0.0.1:3142";
pub const DEFAULT_GIT_PROXY_ADDR: &str = "127.0.0.1:3143";

// V030-AUTH-LEASE-3 — single-knob per-window lease TTL (ADR 211 §2 /
// §"Tiering, threat model & residuals" / OQ-1).
//
// The lease TTL is the dev0 friction/risk dial: "how long the system runs
// without me" = "max compromise window" (ADR 211 §2 elegant property). One
// knob, one place. There is intentionally NO separate "max ceiling" knob: STS
// has two knobs because it has two principals (role owner = policy,
// requester = operator); dev0 collapses to one principal (the operator), so a
// separate ceiling vs default would be performative — same hand sets both
// and the per-window TTL IS the bound. Anchor:
// `lease_ttl_single_knob_dev0_one_principal`.
//
// Renewal is unbounded as long as fresh presence + active grant
// (ADR 211 §2 "renew/extend = presence (tap)"); there is no total session
// cap. Anchor: `lease_renewal_requires_fresh_presence`.
//
// Bounds are typo-protection, NOT a security cap (the TTL itself is the
// security cap). 60s lower bound rules out "ttl = 0" / sub-second floors that
// would thrash the renewal flow. 7-day upper bound rules out
// "30 days" / "10 years" typos that would silently disable the time-box.
// Out-of-range fails closed at config load (`DaemonConfig::validate`).
/// Default per-window lease TTL when no operator override is set.
/// 1 hour matches the operator-locked dev0 dial — short enough to bound an
/// honest compromise window, long enough that interactive operators don't
/// re-tap inside a single working session.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 3600;
/// Minimum permitted per-window lease TTL (typo-protection floor, not a
/// security knob). A sub-60s lease thrashes the renewal flow and provides
/// no honest signal that the operator chose a tight window deliberately.
pub const MIN_LEASE_TTL_SECS: u64 = 60;
/// Maximum permitted per-window lease TTL (typo-protection ceiling, not a
/// security knob). 7 days is the longest reasonable dogfooding window;
/// values above this are almost always a typo silently disabling the
/// time-box.
pub const MAX_LEASE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Environment-variable override for [`DaemonConfig::lease_ttl_secs`] —
/// useful for ephemeral testing / scripted runs without editing
/// `config.toml`. Takes precedence over the TOML field, same convention as
/// `EMBER_BRIDGE_BIND` / `EMBER_TRUST_ROOTS`.
pub const EMBER_LEASE_TTL_SECS_ENV: &str = "EMBER_LEASE_TTL_SECS";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("could not determine home directory")]
    NoHomeDir,
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// Deployment tier — declares the operational posture of this daemon
/// instance per `.claude/rules/agent-discipline.md` §"dev0/team0/ent0"
/// vocabulary.
///
/// Default is [`DeploymentTier::Dev0`] — single operator on one machine,
/// `ember-clients` group has exactly one human, file-ACL connect-eligibility
/// is the auth boundary. Team0+ deployments have multiple operators
/// sharing the same daemon and require additional authorization controls:
/// ConnectOnly persona-keyed reads must principal-scope or fail closed, and
/// intentionally global diagnostics must be named as daemon/operator posture.
///
/// The tier is declared explicitly in `config.toml` (`[daemon].tier`)
/// rather than auto-inferred from ember-clients member count, because
/// the count is ambiguous on dev0 (the daemon's own `ember` uid is in
/// the group, service accounts may be too, etc.). Operators who deploy
/// to team0 or ent0 MUST set the field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentTier {
    /// Single operator, single machine. Cohort A. File-ACL connect-
    /// eligibility (`0660 ember:ember-clients`) is the auth boundary.
    #[default]
    Dev0,
    /// Small team sharing one daemon (operator + maintainer, 2-5
    /// operators). Persona-keyed read-class methods MUST filter results
    /// through the caller's daemon-bound principal; global diagnostics must
    /// remain daemon/operator posture only.
    Team0,
    /// Enterprise multi-tenant. Same gap as Team0 + retention /
    /// compliance / SLA requirements per ADR 044.
    Ent0,
}

impl DeploymentTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeploymentTier::Dev0 => "dev0",
            DeploymentTier::Team0 => "team0",
            DeploymentTier::Ent0 => "ent0",
        }
    }

    /// ADR 139 default interactive grace window after the last live session
    /// pin closes on this tier.
    pub fn interactive_grace_window(&self) -> std::time::Duration {
        match self {
            DeploymentTier::Dev0 => std::time::Duration::from_secs(5 * 60),
            DeploymentTier::Team0 => std::time::Duration::from_secs(2 * 60),
            DeploymentTier::Ent0 => std::time::Duration::ZERO,
        }
    }

    /// `true` for tiers that require multi-uid authorization controls on
    /// read-class ConnectOnly methods.
    pub fn requires_multi_uid_authz(&self) -> bool {
        match self {
            DeploymentTier::Dev0 => false,
            DeploymentTier::Team0 | DeploymentTier::Ent0 => true,
        }
    }
}

/// Raw TOML structure — paths may contain `~` and are expanded on load.
#[derive(Debug, Deserialize)]
struct RawDaemonSection {
    socket_dir: Option<String>,
    data_dir: Option<String>,
    pid_file: Option<String>,
    policy_file: Option<String>,
    log_level: Option<LogLevel>,
    dashboard_addr: Option<String>,
    stale_approval_threshold_secs: Option<u64>,
    /// Bind address for the git-echo credential-injection proxy. `None` (key
    /// absent) ⇒ default `127.0.0.1:3143` (stable loopback port). Empty
    /// string ⇒ disabled.
    git_proxy_addr: Option<String>,
    /// Bind address for the general LLM/HTTP credential-injection proxy
    /// (`run_proxy` / `handle_request` — provider-aware auth, X-Ember-* header
    /// protocol). `None` (key absent) ⇒ default `127.0.0.1:3142`. Empty
    /// string ⇒ disabled. The Anthropic SDK demo path posts to this listener.
    llm_proxy_addr: Option<String>,
    /// ADR 117: vault snapshot interval. Defaults to 3600 (1 hour). `0` disables.
    snapshot_interval_secs: Option<u64>,
    /// Snapshot pull: interval in seconds between snapshot pull
    /// attempts. Defaults to 600 (10 minutes). `0` disables pulling.
    snapshot_pull_interval_secs: Option<u64>,
    /// Snapshot pull: base URL of the remote EIC snapshot endpoint.
    /// `None` disables pulling. Example: `http://eic.tz-net.ts.net:3141`.
    snapshot_pull_endpoint: Option<String>,
    /// Snapshot pull: cluster id for keying pulled snapshots in the
    /// local vault. Required when `snapshot_pull_endpoint` is set.
    snapshot_pull_cluster_id: Option<String>,
    /// SCION binary hash pin: absolute path to the pre-built SCION
    /// fork binary the daemon shells out to at agent-spawn time. `None`
    /// (key absent) ⇒ pin verification is disabled (development /
    /// non-SCION installs).
    scion_binary_path: Option<String>,
    /// SCION binary hash pin: operator-pinned SHA-256 of the SCION
    /// fork binary (lower-hex, 64 chars). `None` (key absent) ⇒ pin
    /// verification is disabled. When `Some`, the daemon refuses to
    /// fork-exec the binary unless its on-disk bytes hash to this value
    /// (CRIT-B TOCTOU defense).
    scion_binary_sha256: Option<String>,
    /// ADR 154 Component 1 — bind address for the in-container mTLS bridge.
    /// `None` (key absent) ⇒ bridge lane disabled until an operator explicitly
    /// opts in. Empty string ⇒ disabled. Env-var override `EMBER_BRIDGE_BIND`
    /// takes precedence over both.
    bridge_bind: Option<String>,
    /// ADR 157 §Component 1 — additive trust-root fingerprints (hex
    /// Ed25519 pubkeys, optionally `did:key:`-prefixed, comma-separated).
    /// `None` / empty ⇒ daemon trusts ONLY the compiled-in release
    /// `IdentityRoot`. Operators add dev / org-policy / endorsement
    /// roots here without re-shipping the daemon binary. Env-var
    /// override `EMBER_TRUST_ROOTS` takes precedence when set.
    trust_roots: Option<String>,
    /// Deployment tier — `dev0` (default), `team0`, or `ent0`. See
    /// [`DeploymentTier`] for the operational-posture semantics. Operators
    /// who deploy to team0 or ent0 MUST set this field so the daemon applies
    /// the multi-uid ConnectOnly scoping rules.
    tier: Option<DeploymentTier>,
    /// V030-AUTH-LEASE-3 — per-window lease TTL in seconds (ADR 211 §2 /
    /// OQ-1). `None` ⇒ [`DEFAULT_LEASE_TTL_SECS`] (3600s / 1h). Bounded by
    /// [`MIN_LEASE_TTL_SECS`]..=[`MAX_LEASE_TTL_SECS`]; out-of-range fails
    /// closed at config load. Env override:
    /// [`EMBER_LEASE_TTL_SECS_ENV`] takes precedence.
    ///
    /// Single knob: there is no separate "default vs ceiling" — see the
    /// module-level docs on [`DEFAULT_LEASE_TTL_SECS`] for why dev0's
    /// one-principal model collapses STS-style two-knob configurations.
    lease_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    daemon: Option<RawDaemonSection>,
    runtime: Option<RawRuntimeSection>,
    keyring: Option<KeyringConfig>,
    presence: Option<PresenceConfigSection>,
    credential_store: Option<CredentialStoreConfig>,
    /// Top-level `[spawn_pool]`
    /// table. Holds the pre-provisioned uid pool that
    /// `handle_broker_exec` checks out a uid from before fork+execve
    /// to drop privileges into. Absent ⇒ pool is disabled and
    /// `broker_exec` refuses with `-32021` (forces `ember daemon
    /// install` to provision the pool; the daemon will not silently
    /// fall back to spawning children as the daemon's own uid).
    spawn_pool: Option<crate::broker::uid_alloc::SpawnPoolConfig>,
}

/// Raw `[runtime]` selector.
///
/// ```toml
/// [runtime]
/// backend = "docker-engine"
/// ```
///
/// Supported values are `docker-engine` (default), `apple-container`,
/// and `none-host-resident`. The Docker-compatible baseline is the
/// accepted ADR 207 default and covers Docker Desktop,
/// OrbStack-as-Docker-backend, colima, and Rancher Desktop.
#[derive(Debug, Deserialize)]
struct RawRuntimeSection {
    backend: Option<String>,
}

/// Credential-store backend selector (ADR 137 — sub-piece D).
///
/// `[credential_store]` section in `config.toml`. When absent the daemon
/// defaults to `backend = "local"` (the existing local-encrypted vault).
/// When `backend = "hashicorp-vault"` the daemon constructs a
/// `HashiVaultStore` and authenticates per the auth fields below.
///
/// ```toml
/// [credential_store]
/// backend = "hashicorp-vault"
/// addr = "https://vault.example.com:8200"
/// mount = "secret"
/// auth = "approle"
/// role_id = "abcd-..."
/// secret_id = "@/run/secrets/vault-secret-id"
/// unavailable_policy = "fall-back-to-cache"
/// cache_ttl_secs = 60
/// ```
///
/// For the AWS IAM auth method the wire shape is:
///
/// ```toml
/// [credential_store]
/// backend = "hashicorp-vault"
/// addr = "https://vault.example.com:8200"
/// mount = "secret"
/// auth = "aws"
/// role = "ember-daemon"        # the Vault AWS-auth role name
/// unavailable_policy = "fail-hard"
/// ```
///
/// AWS credentials themselves are NOT in TOML — they come from the
/// daemon's surrounding AWS IAM identity (env vars / instance metadata
/// / IRSA / ECS task role / Fargate). Vault re-plays a SigV4-signed
/// `sts:GetCallerIdentity` request server-side as the proof.
///
/// For HashiCorp Cloud Platform (HCP) Vault —
/// the wire shape is:
///
/// ```toml
/// [credential_store]
/// backend = "hashicorp-vault"
/// addr = "https://vault-cluster-public-vault-abc.abc.aws.hashicorp.cloud:8200"
/// mount = "secret"
/// auth = "hcp-service-principal"
/// client_id = "abcd1234-..."
/// client_secret = "@/run/secrets/hcp-sp-client-secret"
/// unavailable_policy = "fail-hard"
/// ```
///
/// `token`, `secret_id`, and `client_secret` accept a `@<path>` prefix
/// to read the value from a file (file mode 600) instead of inline
/// TOML — useful for ops flows that mount short-lived tokens via the
/// filesystem rather than shipping them in `config.toml` next to
/// non-secret settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStoreConfig {
    /// Selector: `"local"` (default) or `"hashicorp-vault"`. Unknown
    /// values cause daemon startup to fail closed.
    #[serde(default = "default_backend")]
    pub backend: String,

    /// HashiCorp Vault server base URL (no trailing `/v1`). Required
    /// when `backend = "hashicorp-vault"`.
    #[serde(default)]
    pub addr: Option<String>,

    /// KV v2 mount path. Defaults to `"secret"` so a freshly-`enable`d
    /// Vault works without extra config.
    #[serde(default = "default_mount")]
    pub mount: String,

    /// Vault auth method. `"token"` (default), `"approle"`, `"aws"`,
    /// or `"hcp-service-principal"`. The `"aws"` variant uses the
    /// daemon's surrounding AWS IAM identity (env vars / instance
    /// metadata) to sign a `sts:GetCallerIdentity` request that Vault
    /// re-plays as the proof. The
    /// `"hcp-service-principal"` variant exchanges
    /// `(client_id, client_secret)` at HashiCorp Cloud Platform's
    /// OAuth2 IdP for an access_token, then uses that as
    /// `Authorization: Bearer` against the HCP-hosted Vault cluster.
    /// Other methods (Kubernetes SA, JWT/OIDC,
    /// cert) are out of scope.
    #[serde(default)]
    pub auth: Option<String>,

    /// Token-auth: long-lived static token. Supports `@<path>` to read
    /// from a file. Only consulted when `auth = "token"`.
    #[serde(default)]
    pub token: Option<String>,

    /// AppRole auth: role id (always inline — non-secret).
    #[serde(default)]
    pub role_id: Option<String>,

    /// AppRole auth: secret id. Supports `@<path>` to read from a file.
    /// Only consulted when `auth = "approle"`.
    #[serde(default)]
    pub secret_id: Option<String>,

    /// AWS-IAM auth: Vault role name (the role configured at
    /// `vault auth/aws/role/<role>`). Only consulted when
    /// `auth = "aws"`. AWS credentials themselves come from the
    /// daemon's surrounding identity (env / IMDS / IRSA / etc.), not
    /// from this config.
    #[serde(default)]
    pub role: Option<String>,

    /// HCP service-principal auth: client id (always inline —
    /// non-secret). Only consulted when
    /// `auth = "hcp-service-principal"`.
    #[serde(default)]
    pub client_id: Option<String>,

    /// HCP service-principal auth: client secret. Supports `@<path>`
    /// to read from a file. Only consulted when
    /// `auth = "hcp-service-principal"`.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Behaviour when Vault returns 5xx / connect refused / TLS fail.
    /// `"fail-hard"` (default) → `StoreError::Unavailable` to the
    /// caller. `"fall-back-to-cache"` → consult the in-memory per-key
    /// cache before erroring; entries older than `cache_ttl_secs` are
    /// treated as misses.
    #[serde(default = "default_unavail")]
    pub unavailable_policy: String,

    /// Per-key in-memory cache TTL. `None` disables caching (and
    /// `fall-back-to-cache` then degrades to "always Unavailable" on
    /// 5xx).
    #[serde(default)]
    pub cache_ttl_secs: Option<u64>,
}

fn default_backend() -> String {
    "local".to_string()
}

fn default_mount() -> String {
    "secret".to_string()
}

fn default_unavail() -> String {
    "fail-hard".to_string()
}

impl Default for CredentialStoreConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            addr: None,
            mount: default_mount(),
            auth: None,
            token: None,
            role_id: None,
            secret_id: None,
            role: None,
            client_id: None,
            client_secret: None,
            unavailable_policy: default_unavail(),
            cache_ttl_secs: None,
        }
    }
}

/// Resolve a `[credential_store]` string field that supports a `@<path>`
/// file-reference prefix. Returns the literal string when no `@` prefix
/// is present; otherwise reads the file at the given path and trims a
/// trailing newline.
///
/// This keeps short-lived secret material (Vault tokens, AppRole secret
/// ids minted by tooling) out of `config.toml` itself — the operator can
/// drop the value into a 600-mode file and reference it by path.
pub fn resolve_at_ref(value: &str) -> Result<String, ConfigError> {
    if let Some(path) = value.strip_prefix('@') {
        let raw = fs::read_to_string(path).map_err(|e| {
            ConfigError::Validation(format!(
                "credential_store: failed to read @-ref file '{}': {}",
                path, e
            ))
        })?;
        Ok(raw.trim_end_matches(['\n', '\r']).to_string())
    } else {
        Ok(value.to_string())
    }
}

/// Keyring service/account identifiers written into `config.toml`.
///
/// Resolution order in `Vault::open_from_config`:
/// 1. Config field (if `Some`)
/// 2. Env var override (`EMBER_KEYRING_SERVICE` / `EMBER_KEYRING_ACCOUNT`) — debug backdoor
/// 3. Compile-time default (`"ember-daemon"` / `"vault"`)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyringConfig {
    pub service: Option<String>,
    pub account: Option<String>,
}

/// Per-operation user-presence gate config. Optional; all
/// `None` ⇒ presence module uses defaults (15min idle, no quiet hours).
///
/// ```toml
/// [presence]
/// idle_timeout_secs = 900       # default 900 (15min)
/// quiet_hours_start = 22        # 22:00 UTC
/// quiet_hours_end = 6           #  6:00 UTC (wrap-around supported)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceConfigSection {
    pub idle_timeout_secs: Option<u64>,
    pub quiet_hours_start: Option<u8>,
    pub quiet_hours_end: Option<u8>,
}

/// Daemon-level configuration loaded from `~/.ember/config.toml` (or the path
/// resolved from `--config` / `EMBER_CONFIG`).
///
/// **No `impl Default`** — every
/// constructor must be explicit so that test partial-overrides can't silently
/// pull user-home paths. The type system pins the rule:
///
/// ```compile_fail
/// use ember_daemon::infra::config::DaemonConfig;
/// let _ = DaemonConfig::default();
/// ```
///
/// Use [`DaemonConfig::for_test`] in tests and [`DaemonConfig::load`] in
/// production. The latter calls a private `load_defaults` ctor for per-field
/// fallbacks when the on-disk TOML omits a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub socket_dir: PathBuf,
    pub data_dir: PathBuf,
    pub pid_file: PathBuf,
    pub policy_file: PathBuf,
    pub log_level: LogLevel,
    /// Address for the dashboard HTTP listener. `None` disables the dashboard (useful for tests).
    /// Defaults to `127.0.0.1:3141` — loopback only, never 0.0.0.0.
    pub dashboard_addr: Option<SocketAddr>,
    /// Bind address for the git-echo credential-injection proxy used by
    /// sandboxed agents (`EMBER_GIT_PROXY_URL`). `None` disables the proxy.
    /// Defaults to `127.0.0.1:3143` (stable loopback port).
    pub git_proxy_addr: Option<SocketAddr>,
    /// Bind address for the general LLM/HTTP credential-injection proxy
    /// (`run_proxy` / `handle_request`). Surfaced to clients as
    /// `EMBER_PROXY_URL` and `<data_dir>/run/proxy.url`. Provider-aware auth
    /// (Anthropic `x-api-key`, generic Bearer). `None` disables the listener.
    /// Defaults to `127.0.0.1:3142` (stable loopback port).
    pub llm_proxy_addr: Option<SocketAddr>,
    /// Keyring service/account override. `None` fields fall back to env var, then compile-time default.
    pub keyring: KeyringConfig,
    /// Startup sweep: mark `pending` approval_requests older than this many seconds as `timed_out`.
    /// Default 3600 (1 hour). Set to 0 to disable the sweep.
    pub stale_approval_threshold_secs: u64,
    /// ADR 117 — vault snapshot interval in seconds. Default 3600 (1 hour).
    /// Set to 0 to disable periodic snapshots.
    pub snapshot_interval_secs: u64,
    /// Snapshot pull — periodic pull interval in seconds. Default
    /// 600 (10 min). Set to 0 to disable pulling.
    pub snapshot_pull_interval_secs: u64,
    /// Snapshot pull — base URL of the remote EIC snapshot endpoint.
    /// `None` means pulling is not configured.
    pub snapshot_pull_endpoint: Option<String>,
    /// Snapshot pull — cluster id used to key pulled snapshots in
    /// the local vault. Required when `snapshot_pull_endpoint` is `Some`.
    pub snapshot_pull_cluster_id: Option<String>,
    /// Per-op user-presence gate. Loaded from `[presence]`
    /// in config.toml; `None` fields fall back to module defaults.
    pub presence: PresenceConfigSection,
    /// ADR 137 — pluggable credential-store backend selector. `None`
    /// means no `[credential_store]` section was present, which the
    /// daemon treats as `backend = "local"` (the existing vault path).
    pub credential_store: Option<CredentialStoreConfig>,
    /// ADR 207 runtime backend selector. Loaded from top-level
    /// `[runtime].backend`; defaults to `docker-engine`.
    ///
    /// Supported values:
    /// - `docker-engine` — Docker-compatible baseline (Docker Desktop,
    ///   OrbStack-as-Docker-backend, colima, Rancher Desktop)
    /// - `apple-container`
    /// - `none-host-resident`
    pub runtime_backend: RuntimeBackend,
    /// SCION binary hash pin — absolute path to the pre-built
    /// SCION fork binary the daemon shells out to at agent-spawn time.
    /// `PathBuf::new()` (empty) means pin verification is disabled
    /// (development / non-SCION installs).
    pub scion_binary_path: PathBuf,
    /// SCION binary hash pin — operator-pinned SHA-256 of the
    /// SCION fork binary (lower-hex, 64 chars). Empty string means
    /// pin verification is disabled. When non-empty, the spawn path
    /// calls [`crate::spawn::scion::verify_scion_binary_hash`] before
    /// fork-exec and refuses on mismatch (CRIT-B TOCTOU defense).
    pub scion_binary_sha256: String,
    /// ADR 154 Component 1 — bind address for the in-container mTLS
    /// bridge. `None` disables the bridge listener.
    ///
    /// The lane is currently explicit opt-in: when neither the config file nor
    /// `EMBER_BRIDGE_BIND` env var is set, startup treats the bridge as
    /// disabled and skips the Bridge CA private-key bootstrap path.
    /// Operators who want the bridge lane set this to a concrete bind address;
    /// see [ADR 154 §"Multi-tenant hardening"] for Linux scoping guidance.
    pub bridge_bind: Option<SocketAddr>,
    /// ADR 157 §Component 1 — comma-separated additive trust-root
    /// fingerprints (hex Ed25519 pubkeys, optionally `did:key:`-prefixed).
    /// Empty string ⇒ daemon trusts only the compiled-in release
    /// `IdentityRoot`. The verifier UNION's this set with the bundled
    /// release root and tries each on every manifest-signature check —
    /// the verification code path runs unconditionally; dev/prod
    /// daemons share one flow parameterized only by the trust-set
    /// contents.
    ///
    /// Resolution order (highest precedence first):
    ///   1. `EMBER_TRUST_ROOTS` env var (operator override).
    ///   2. `[daemon].trust_roots` config field.
    ///   3. Empty (release-only).
    pub trust_roots: String,
    /// Pre-provisioned uid pool the
    /// broker_exec spawn paths drop into before execve. `None` ⇒ the
    /// pool is not configured and `handle_broker_exec` refuses with
    /// `-32021` ("spawn pool not configured — `ember daemon install`
    /// must provision the uid pool"). Closes Finding 14 (refuse to
    /// spawn a child as the daemon's own uid) and the cross-spawn
    /// `/proc/<pid>/environ` side-channel. See `broker/uid_alloc.rs`
    /// for the pool primitives; see ADR 167 (amendment to ADR 131)
    /// for the per-spawn ephemeral-uid allocation strategy.
    ///
    /// ```toml
    /// [spawn_pool]
    /// uids = [10010, 10011, 10012, 10013, 10014, 10015, 10016, 10017]
    /// gid = 10010
    /// ```
    pub spawn_pool: Option<crate::broker::uid_alloc::SpawnPoolConfig>,
    /// Deployment tier — see [`DeploymentTier`]. Default [`DeploymentTier::Dev0`].
    /// Read from `[daemon].tier` in config.toml. Team0 and Ent0 enable
    /// the multi-uid ConnectOnly authorization posture.
    pub tier: DeploymentTier,
    /// V030-AUTH-LEASE-3 — per-window lease TTL in seconds (ADR 211 §2 /
    /// OQ-1 resolved). Default [`DEFAULT_LEASE_TTL_SECS`] (3600s / 1h);
    /// bounded by [[`MIN_LEASE_TTL_SECS`], [`MAX_LEASE_TTL_SECS`]] (typo
    /// protection, not a security cap).
    ///
    /// Resolution order (highest precedence first):
    ///   1. `EMBER_LEASE_TTL_SECS` env var (operator override).
    ///   2. `[daemon].lease_ttl_secs` config field.
    ///   3. [`DEFAULT_LEASE_TTL_SECS`].
    ///
    /// Out-of-range values fail closed at [`DaemonConfig::validate`] — the
    /// daemon refuses to start with a typo-shaped TTL rather than silently
    /// disabling the time-box.
    ///
    /// Anchor: `lease_ttl_single_knob_dev0_one_principal`.
    pub lease_ttl_secs: u64,
}

fn expand_tilde(path: &str) -> Result<PathBuf, ConfigError> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs_next::home_dir().ok_or(ConfigError::NoHomeDir)?;
        Ok(home.join(rest))
    } else if path == "~" {
        dirs_next::home_dir().ok_or(ConfigError::NoHomeDir)
    } else {
        Ok(PathBuf::from(path))
    }
}

// `impl Default for DaemonConfig`
// is REMOVED. The May-12 25-hour leaked-daemon incident was rooted in
// `DaemonConfig { data_dir: tmpdir.path()..., ..Default::default() }`
// partial-overrides silently inheriting user-home paths. The type
// system now enforces "every constructor is explicit": tests use
// `DaemonConfig::for_test(&tmpdir)`, production uses
// `DaemonConfig::load(&path)`, and `load`'s field-level fallbacks come
// from `Self::load_defaults()` (private; see below). See doc-test on
// the struct above for the compile_fail pin.

impl DaemonConfig {
    /// Tempdir-scoped
    /// test constructor. Sets every path-bearing field under `tmpdir` so a
    /// test cannot accidentally bind the operator's real
    /// `~/.ember/run/daemon.sock` (the May-12 25-hour leaked-daemon
    /// incident root cause).
    ///
    /// Tests MUST use this instead of `..Default::default()` partial-overrides.
    /// A follow-up migrates existing
    /// callers off `Default` so the type system enforces the rule by
    /// removing `impl Default` entirely.
    ///
    /// # target_state_anchor
    ///
    /// `DaemonConfig::for_test`
    /// Private fallback ctor used by
    /// `load` when the on-disk TOML omits a field. Replaces the prior
    /// `impl Default` role. Tests that previously asserted on
    /// `DaemonConfig::default()`'s shape now call this method directly via
    /// the `mod tests` re-export.
    pub(crate) fn load_defaults() -> Self {
        // ADR 218 (operator-locked 2026-06-14): daemon at-rest state +
        // runtime socket + config live at OS system paths, NOT under
        // any user's $HOME. The legacy `~/.ember/...` layout this
        // function previously returned is superseded; only the
        // ADR-131 auth model (SO_PEERCRED + ember-clients group ACL
        // + per-method gate) stays verbatim. See
        // `crate::paths::DaemonPaths` for the per-OS table.
        let paths = crate::paths::DaemonPaths::system();

        Self {
            socket_dir: paths.run_dir.clone(),
            data_dir: paths.data_dir.clone(),
            pid_file: paths.pid_file.clone(),
            policy_file: paths.policy_file(),
            log_level: LogLevel::Info,
            dashboard_addr: Some(DEFAULT_DASHBOARD_ADDR.parse().expect("valid default addr")),
            git_proxy_addr: Some(DEFAULT_GIT_PROXY_ADDR.parse().expect("valid default addr")),
            llm_proxy_addr: Some(DEFAULT_LLM_PROXY_ADDR.parse().expect("valid default addr")),
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            presence: PresenceConfigSection::default(),
            credential_store: None,
            runtime_backend: RuntimeBackend::DockerEngine,
            // SCION binary hash pin: empty defaults mean verification
            // is opt-in — production configs MUST set both.
            scion_binary_path: PathBuf::new(),
            scion_binary_sha256: String::new(),
            // Bridge lane is explicit opt-in in current shipped posture.
            bridge_bind: None,
            // ADR 157 §Component 1 — empty default means "release-only trust
            // set"; operators add dev / org roots via `EMBER_TRUST_ROOTS`
            // or `[daemon].trust_roots` without re-shipping the binary.
            trust_roots: String::new(),
            // Default is `None`
            // ("pool not configured"). The installer writes
            // `[spawn_pool]` into the operator's config.toml when
            // `ember daemon install` runs; daemons running pre-
            // installer must surface `-32011` rather than silently
            // spawning as their own uid.
            spawn_pool: None,
            // Default tier is Dev0 — single-operator file-ACL boundary.
            // Operators deploying team0/ent0 set this in config.toml.
            tier: DeploymentTier::Dev0,
            // V030-AUTH-LEASE-3: 1-hour default per-window lease TTL.
            // Single knob, dev0 one-principal — see DEFAULT_LEASE_TTL_SECS.
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        }
    }

    pub fn for_test(tmpdir: &std::path::Path) -> Self {
        // Flat layout — every test artifact lives directly under tmpdir.
        // Matches the pre-for_test pattern (`let mut c = DaemonConfig::default();
        // c.data_dir = tmp.path()`) so vault tests that expect to write
        // `<data_dir>/vault.salt` find an existing parent directory.
        // Path uniqueness across socket / data / pid / policy is via
        // filename, not subdirectory.
        Self {
            socket_dir: tmpdir.to_path_buf(),
            data_dir: tmpdir.to_path_buf(),
            pid_file: tmpdir.join("emberd.pid"),
            policy_file: tmpdir.join("policy.toml"),
            log_level: LogLevel::Info,
            // Tests default the dashboard / proxies to disabled. A test that
            // wants them enabled overrides explicitly — that's safer than
            // tests silently binding loopback ports they don't expect.
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            snapshot_interval_secs: 0,
            snapshot_pull_interval_secs: 0,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            presence: PresenceConfigSection::default(),
            credential_store: None,
            runtime_backend: RuntimeBackend::DockerEngine,
            scion_binary_path: PathBuf::new(),
            scion_binary_sha256: String::new(),
            // Tests disable the bridge by default — explicit opt-in via
            // override matches dashboard_addr / git_proxy_addr / llm_proxy_addr.
            bridge_bind: None,
            // ADR 157 §Component 1 — tests default to release-only (the
            // compiled-in IdentityRoot). Tests that exercise dev-mode
            // trust-root semantics override explicitly.
            trust_roots: String::new(),
            // Tests default to
            // `None`. Broker-exec tests that need a working spawn
            // path call `uid_alloc::init_uid_pool_for_test()` directly
            // to install a process-global pool keyed on the current
            // uid; this field stays `None` so DaemonConfig round-trip
            // tests stay deterministic.
            spawn_pool: None,
            // Tests default to Dev0 (the cohort A posture). Tests that
            // exercise the team0+ startup-WARN path override explicitly.
            tier: DeploymentTier::Dev0,
            // V030-AUTH-LEASE-3: tests default to the production 1-hour
            // window. Tests asserting a different TTL override explicitly.
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        }
    }

    pub fn default_config_path() -> PathBuf {
        // ADR 218: config lives at the per-OS system config dir
        // (`/Library/Application Support/Emberlink/config/` on macOS;
        // `/etc/ember/` on Linux). Superseded the legacy
        // `~/.ember/config.toml` location.
        crate::paths::DaemonPaths::system().config_file()
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&text)?;

        let defaults = DaemonConfig::load_defaults();
        let section = raw.daemon.unwrap_or(RawDaemonSection {
            socket_dir: None,
            data_dir: None,
            pid_file: None,
            policy_file: None,
            log_level: None,
            dashboard_addr: None,
            stale_approval_threshold_secs: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            snapshot_interval_secs: None,
            snapshot_pull_interval_secs: None,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            scion_binary_path: None,
            scion_binary_sha256: None,
            bridge_bind: None,
            trust_roots: None,
            tier: None,
            lease_ttl_secs: None,
        });

        let socket_dir = match section.socket_dir {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.socket_dir,
        };
        let data_dir = match section.data_dir {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.data_dir,
        };
        let pid_file = match section.pid_file {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.pid_file,
        };
        let policy_file = match section.policy_file {
            Some(ref s) => expand_tilde(s)?,
            None => defaults.policy_file,
        };
        let log_level = section.log_level.unwrap_or(defaults.log_level);

        let dashboard_addr = match section.dashboard_addr {
            Some(ref s) if s.is_empty() => None,
            Some(ref s) => Some(SocketAddr::from_str(s).map_err(|e| {
                ConfigError::Validation(format!("invalid dashboard_addr '{}': {}", s, e))
            })?),
            None => defaults.dashboard_addr,
        };

        let git_proxy_addr = match section.git_proxy_addr {
            Some(ref s) if s.is_empty() => None,
            Some(ref s) => Some(SocketAddr::from_str(s).map_err(|e| {
                ConfigError::Validation(format!("invalid git_proxy_addr '{}': {}", s, e))
            })?),
            None => defaults.git_proxy_addr,
        };

        let llm_proxy_addr = match section.llm_proxy_addr {
            Some(ref s) if s.is_empty() => None,
            Some(ref s) => Some(SocketAddr::from_str(s).map_err(|e| {
                ConfigError::Validation(format!("invalid llm_proxy_addr '{}': {}", s, e))
            })?),
            None => defaults.llm_proxy_addr,
        };

        let keyring = raw.keyring.unwrap_or_default();
        let presence = raw.presence.unwrap_or_default();
        let stale_approval_threshold_secs = section
            .stale_approval_threshold_secs
            .unwrap_or(defaults.stale_approval_threshold_secs);
        let snapshot_interval_secs = section
            .snapshot_interval_secs
            .unwrap_or(defaults.snapshot_interval_secs);

        let snapshot_pull_interval_secs = section
            .snapshot_pull_interval_secs
            .unwrap_or(defaults.snapshot_pull_interval_secs);
        let snapshot_pull_endpoint = section.snapshot_pull_endpoint;
        let snapshot_pull_cluster_id = section.snapshot_pull_cluster_id;

        let credential_store = raw.credential_store;

        // ADR 207 runtime backend selection. The field intentionally
        // lives in a top-level `[runtime]` table so container-engine
        // selection is not confused with authority-space daemon knobs.
        let runtime_backend = match raw.runtime.and_then(|section| section.backend) {
            Some(value) => RuntimeBackend::parse_config_value(&value).map_err(|e| {
                ConfigError::Validation(format!(
                    "runtime.backend: {e}; set one of {}",
                    RuntimeBackend::supported_values_csv()
                ))
            })?,
            None => defaults.runtime_backend,
        };

        // SCION binary hash pin: expand `~` so operators can write
        // the path naturally; empty/absent fields fall back to defaults
        // (empty path, empty hash) which disable verification — same
        // semantics as not setting the keys at all.
        let scion_binary_path = match section.scion_binary_path {
            Some(ref s) if s.is_empty() => defaults.scion_binary_path,
            Some(ref s) => expand_tilde(s)?,
            None => defaults.scion_binary_path,
        };
        let scion_binary_sha256 = section
            .scion_binary_sha256
            .unwrap_or(defaults.scion_binary_sha256);

        // ADR 154 Component 1 — bridge_bind resolution order:
        //   1. `EMBER_BRIDGE_BIND` env var (operator override, highest precedence;
        //      empty string disables, matches dashboard/proxy convention).
        //   2. `[daemon].bridge_bind` config field (empty string disables).
        //   3. Absent at both layers ⇒ bridge lane disabled by default.
        let bridge_bind: Option<SocketAddr> = {
            let env_value = std::env::var("EMBER_BRIDGE_BIND").ok();
            match (env_value.as_deref(), section.bridge_bind.as_deref()) {
                // Empty string at either layer disables the bridge.
                (Some(""), _) | (None, Some("")) => None,
                // Env override wins when present + non-empty.
                (Some(s), _) => Some(SocketAddr::from_str(s).map_err(|e| {
                    ConfigError::Validation(format!(
                        "invalid EMBER_BRIDGE_BIND env value '{}': {}",
                        s, e
                    ))
                })?),
                // Config-file value when env is absent + config is non-empty.
                (None, Some(s)) => Some(SocketAddr::from_str(s).map_err(|e| {
                    ConfigError::Validation(format!("invalid bridge_bind '{}': {}", s, e))
                })?),
                // Neither override present → bridge disabled.
                (None, None) => defaults.bridge_bind,
            }
        };

        // ADR 157 §Component 1 — trust-root resolution order:
        //   1. `EMBER_TRUST_ROOTS` env var (operator override; matches the
        //      `EMBER_BRIDGE_BIND` precedence convention).
        //   2. `[daemon].trust_roots` config field.
        //   3. Empty string (release-only).
        let trust_roots: String = match std::env::var("EMBER_TRUST_ROOTS").ok() {
            Some(v) => v,
            None => section.trust_roots.unwrap_or_default(),
        };

        // Top-level `[spawn_pool]`
        // table is consumed verbatim. `None` (absent) ⇒ broker_exec
        // refuses with `-32021`; `Some` ⇒ the pool is installed via
        // `uid_alloc::init_uid_pool` during runtime startup.
        let spawn_pool = raw.spawn_pool;

        // Deployment tier — `[daemon].tier`. Absent ⇒ DeploymentTier::Dev0
        // (single-operator cohort A). Team0/Ent0 enable multi-uid
        // ConnectOnly authorization controls.
        let tier = section.tier.unwrap_or(DeploymentTier::Dev0);

        // V030-AUTH-LEASE-3 — per-window lease TTL resolution order:
        //   1. `EMBER_LEASE_TTL_SECS` env var (operator override, highest
        //      precedence; matches `EMBER_BRIDGE_BIND` / `EMBER_TRUST_ROOTS`).
        //   2. `[daemon].lease_ttl_secs` config field.
        //   3. `DEFAULT_LEASE_TTL_SECS` (3600s / 1h).
        //
        // An env var that is present but not parseable as a u64 (e.g. `60s`,
        // `abc`, empty) is rejected at load time — silently falling back to
        // the config field or default on a typo would defeat the operator's
        // intent. Range validation happens in `validate()` so the same gate
        // covers all three input lanes (env / toml / default).
        let lease_ttl_secs: u64 = match std::env::var(EMBER_LEASE_TTL_SECS_ENV).ok() {
            Some(raw) => raw.parse().map_err(|e| {
                ConfigError::Validation(format!(
                    "invalid {EMBER_LEASE_TTL_SECS_ENV} env value '{raw}': {e}"
                ))
            })?,
            None => section.lease_ttl_secs.unwrap_or(DEFAULT_LEASE_TTL_SECS),
        };

        let cfg = DaemonConfig {
            socket_dir,
            data_dir,
            pid_file,
            policy_file,
            log_level,
            dashboard_addr,
            git_proxy_addr,
            llm_proxy_addr,
            keyring,
            stale_approval_threshold_secs,
            snapshot_interval_secs,
            snapshot_pull_interval_secs,
            snapshot_pull_endpoint,
            snapshot_pull_cluster_id,
            presence,
            credential_store,
            runtime_backend,
            scion_binary_path,
            scion_binary_sha256,
            bridge_bind,
            trust_roots,
            spawn_pool,
            tier,
            lease_ttl_secs,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.socket_dir.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "socket_dir cannot be empty".to_string(),
            ));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "data_dir cannot be empty".to_string(),
            ));
        }
        if self.pid_file.as_os_str().is_empty() {
            return Err(ConfigError::Validation(
                "pid_file cannot be empty".to_string(),
            ));
        }
        if self.socket_dir == self.data_dir {
            return Err(ConfigError::Validation(
                "socket_dir and data_dir must be different".to_string(),
            ));
        }
        // V030-AUTH-LEASE-3 — single-knob lease TTL bounds (typo protection,
        // NOT a security cap). Out-of-range fails closed at config load
        // rather than silently disabling the time-box. The check covers the
        // env override, the TOML field, and the default in one place — every
        // path runs through `validate()`.
        if self.lease_ttl_secs < MIN_LEASE_TTL_SECS || self.lease_ttl_secs > MAX_LEASE_TTL_SECS {
            return Err(ConfigError::Validation(format!(
                "lease_ttl_secs ({}) out of range [{}, {}]; \
                 set a value within bounds (1h default, 60s..7d). \
                 The bound is typo protection — see ADR 211 §2 / OQ-1.",
                self.lease_ttl_secs, MIN_LEASE_TTL_SECS, MAX_LEASE_TTL_SECS,
            )));
        }
        Ok(())
    }

    pub fn ensure_dirs(&self) -> Result<(), ConfigError> {
        fs::create_dir_all(&self.socket_dir)?;
        fs::create_dir_all(&self.data_dir)?;
        if let Some(parent) = self.pid_file.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    /// ADR 218 (operator-locked 2026-06-14): default paths land at OS
    /// system roots, NOT under any user's `$HOME`. The legacy
    /// `~/.ember/...` shape this test previously asserted is
    /// superseded — see `crate::paths::DaemonPaths::system` and the
    /// 2026-06-14 amendment to ADR 131.
    #[test]
    fn default_paths_land_at_system_root_per_adr_218() {
        let cfg = DaemonConfig::load_defaults();
        let socket_str = cfg.socket_dir.to_string_lossy();
        let data_str = cfg.data_dir.to_string_lossy();
        let pid_str = cfg.pid_file.to_string_lossy();

        // Boundary rule: no daemon data under any user's HOME.
        for s in [&socket_str, &data_str, &pid_str] {
            assert!(
                !s.starts_with("/Users/") && !s.starts_with("/home/"),
                "ADR 218 boundary violated: {s} is under a user HOME"
            );
            assert!(
                !s.contains("/.ember/"),
                "legacy ~/.ember/ layout leaked into default paths: {s}"
            );
        }

        #[cfg(target_os = "macos")]
        {
            assert!(
                socket_str.contains("Emberlink"),
                "expected Emberlink in {socket_str}"
            );
            assert!(
                data_str.contains("Emberlink"),
                "expected Emberlink in {data_str}"
            );
            assert!(
                pid_str.contains("Emberlink"),
                "expected Emberlink in {pid_str}"
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(
                socket_str.contains("ember"),
                "expected ember in {socket_str}"
            );
            assert!(data_str.contains("ember"), "expected ember in {data_str}");
            assert!(pid_str.contains("ember"), "expected ember in {pid_str}");
        }
        assert_eq!(cfg.log_level, LogLevel::Info);
    }

    #[test]
    fn default_proxy_ports_are_stable_loopback_addresses() {
        let cfg = DaemonConfig::load_defaults();
        assert_eq!(
            cfg.llm_proxy_addr,
            Some(
                DEFAULT_LLM_PROXY_ADDR
                    .parse()
                    .expect("parse default llm proxy")
            )
        );
        assert_eq!(
            cfg.git_proxy_addr,
            Some(
                DEFAULT_GIT_PROXY_ADDR
                    .parse()
                    .expect("parse default git proxy")
            )
        );
    }

    // ─── DeploymentTier (MED-2 fix) ─────────────────────────────────────

    #[test]
    fn deployment_tier_default_is_dev0() {
        let cfg = DaemonConfig::load_defaults();
        assert_eq!(cfg.tier, DeploymentTier::Dev0);
    }

    #[test]
    fn deployment_tier_dev0_does_not_require_multi_uid_authz() {
        assert!(!DeploymentTier::Dev0.requires_multi_uid_authz());
    }

    #[test]
    fn deployment_tier_team0_requires_multi_uid_authz() {
        assert!(DeploymentTier::Team0.requires_multi_uid_authz());
    }

    #[test]
    fn deployment_tier_ent0_requires_multi_uid_authz() {
        assert!(DeploymentTier::Ent0.requires_multi_uid_authz());
    }

    #[test]
    fn deployment_tier_as_str_matches_serde_lowercase() {
        // Serde rename_all = "lowercase" must agree with `as_str` so
        // operator-facing TOML and operator-facing log lines use the
        // same identifiers. If these drift, `[daemon].tier = "team0"`
        // in TOML and `tier=Team0` in the log would confuse operators.
        assert_eq!(DeploymentTier::Dev0.as_str(), "dev0");
        assert_eq!(DeploymentTier::Team0.as_str(), "team0");
        assert_eq!(DeploymentTier::Ent0.as_str(), "ent0");
    }

    #[test]
    fn config_load_parses_tier_dev0() {
        let toml_str = "[daemon]\nlog_level = \"info\"\ntier = \"dev0\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let cfg = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(cfg.tier, DeploymentTier::Dev0);
    }

    #[test]
    fn config_load_parses_tier_team0() {
        let toml_str = "[daemon]\nlog_level = \"info\"\ntier = \"team0\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let cfg = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(cfg.tier, DeploymentTier::Team0);
        assert!(cfg.tier.requires_multi_uid_authz());
    }

    #[test]
    fn config_load_parses_tier_ent0() {
        let toml_str = "[daemon]\nlog_level = \"info\"\ntier = \"ent0\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let cfg = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(cfg.tier, DeploymentTier::Ent0);
    }

    #[test]
    fn config_load_absent_tier_defaults_to_dev0() {
        // No tier line in TOML — falls through to Dev0 default. This is
        // the dev0 friction-first path: operators don't need to declare
        // their tier explicitly for cohort A.
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let cfg = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(cfg.tier, DeploymentTier::Dev0);
    }

    #[test]
    fn config_load_rejects_unknown_tier() {
        // Unknown values fail TOML parse (serde enum + lowercase) so
        // operators can't accidentally ship `tier = "team-0"` or
        // `tier = "TEAM0"` and silently fall back to dev0.
        let toml_str = "[daemon]\nlog_level = \"info\"\ntier = \"team-0\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let err = DaemonConfig::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn deployment_tier_interactive_grace_windows_match_adr_139() {
        use std::time::Duration;

        assert_eq!(
            DeploymentTier::Dev0.interactive_grace_window(),
            Duration::from_secs(5 * 60)
        );
        assert_eq!(
            DeploymentTier::Team0.interactive_grace_window(),
            Duration::from_secs(2 * 60)
        );
        assert_eq!(
            DeploymentTier::Ent0.interactive_grace_window(),
            Duration::ZERO
        );
    }

    #[test]
    fn round_trip_toml() {
        let defaults = DaemonConfig::load_defaults();

        // Build a TOML string from defaults and re-parse it.
        let toml_str = format!(
            "[daemon]\nsocket_dir = \"{}\"\ndata_dir = \"{}\"\npid_file = \"{}\"\nlog_level = \"info\"\n",
            defaults.socket_dir.display(),
            defaults.data_dir.display(),
            defaults.pid_file.display(),
        );

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();

        assert_eq!(loaded.socket_dir, defaults.socket_dir);
        assert_eq!(loaded.data_dir, defaults.data_dir);
        assert_eq!(loaded.pid_file, defaults.pid_file);
        assert_eq!(loaded.log_level, defaults.log_level);
    }

    #[test]
    fn ensure_dirs_creates_directories() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("ember");
        let cfg = DaemonConfig {
            socket_dir: base.join("run"),
            data_dir: base.join("data"),
            pid_file: base.join("run").join("emberd.pid"),
            policy_file: base.join("policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            presence: PresenceConfigSection::default(),
            credential_store: None,
            runtime_backend: RuntimeBackend::DockerEngine,
            scion_binary_path: PathBuf::new(),
            scion_binary_sha256: String::new(),
            bridge_bind: None,
            trust_roots: String::new(),
            spawn_pool: None,
            tier: DeploymentTier::Dev0,
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        };

        cfg.ensure_dirs().unwrap();

        assert!(cfg.socket_dir.is_dir());
        assert!(cfg.data_dir.is_dir());
        assert!(cfg.pid_file.parent().unwrap().is_dir());
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        // TOML with only log_level set — other fields use defaults.
        let toml_str = "[daemon]\nlog_level = \"debug\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        let defaults = DaemonConfig::load_defaults();

        assert_eq!(loaded.socket_dir, defaults.socket_dir);
        assert_eq!(loaded.data_dir, defaults.data_dir);
        assert_eq!(loaded.pid_file, defaults.pid_file);
        assert_eq!(loaded.log_level, LogLevel::Debug);
    }

    #[test]
    fn empty_toml_uses_all_defaults() {
        let toml_str = "";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        let defaults = DaemonConfig::load_defaults();

        assert_eq!(loaded, defaults);
    }

    #[test]
    fn invalid_toml_returns_parse_error() {
        let toml_str = "[daemon\nthis is not valid toml :::";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let err = DaemonConfig::load(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn tilde_expansion_in_paths() {
        let home = dirs_next::home_dir().expect("home dir required for this test");
        let toml_str = "[daemon]\nsocket_dir = \"~/.ember/run\"\ndata_dir = \"~/.ember/data\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.socket_dir, home.join(".ember/run"));
        assert_eq!(loaded.data_dir, home.join(".ember/data"));
    }

    /// ADR 218: default config path lives at the per-OS system config
    /// dir (`/Library/Application Support/Emberlink/config/config.toml`
    /// on macOS; `/etc/ember/config.toml` on Linux). The legacy
    /// `~/.ember/config.toml` location this test previously asserted
    /// is superseded.
    #[test]
    fn default_config_path_lands_at_system_config_dir_per_adr_218() {
        let p = DaemonConfig::default_config_path();
        let s = p.to_string_lossy();
        assert!(s.ends_with("config.toml"));
        assert!(
            !s.starts_with("/Users/") && !s.starts_with("/home/"),
            "ADR 218 boundary violated: {s} is under a user HOME"
        );
        assert!(
            !s.contains("/.ember/"),
            "legacy ~/.ember/config.toml layout leaked: {s}"
        );
        #[cfg(target_os = "macos")]
        assert!(s.contains("Emberlink"), "expected Emberlink in {s}");
        #[cfg(not(target_os = "macos"))]
        assert!(s.contains("ember"), "expected ember in {s}");
    }

    #[test]
    fn validate_default_config_passes() {
        let cfg = DaemonConfig::load_defaults();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_empty_socket_dir_fails() {
        let cfg = DaemonConfig {
            socket_dir: PathBuf::from(""),
            data_dir: PathBuf::from("/tmp/.ember/data"),
            pid_file: PathBuf::from("/tmp/.ember/run/emberd.pid"),
            policy_file: PathBuf::from("/tmp/.ember/policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            presence: PresenceConfigSection::default(),
            credential_store: None,
            runtime_backend: RuntimeBackend::DockerEngine,
            scion_binary_path: PathBuf::new(),
            scion_binary_sha256: String::new(),
            bridge_bind: None,
            trust_roots: String::new(),
            spawn_pool: None,
            tier: DeploymentTier::Dev0,
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(ref s) if s.contains("socket_dir")));
    }

    #[test]
    fn validate_same_dirs_fails() {
        let cfg = DaemonConfig {
            socket_dir: PathBuf::from("/tmp/.ember/same"),
            data_dir: PathBuf::from("/tmp/.ember/same"),
            pid_file: PathBuf::from("/tmp/.ember/same/emberd.pid"),
            policy_file: PathBuf::from("/tmp/.ember/policy.toml"),
            log_level: LogLevel::Info,
            dashboard_addr: None,
            git_proxy_addr: None,
            llm_proxy_addr: None,
            keyring: KeyringConfig::default(),
            stale_approval_threshold_secs: 3600,
            snapshot_interval_secs: 3600,
            snapshot_pull_interval_secs: 600,
            snapshot_pull_endpoint: None,
            snapshot_pull_cluster_id: None,
            presence: PresenceConfigSection::default(),
            credential_store: None,
            runtime_backend: RuntimeBackend::DockerEngine,
            scion_binary_path: PathBuf::new(),
            scion_binary_sha256: String::new(),
            bridge_bind: None,
            trust_roots: String::new(),
            spawn_pool: None,
            tier: DeploymentTier::Dev0,
            lease_ttl_secs: DEFAULT_LEASE_TTL_SECS,
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Validation(ref s) if s.contains("must be different")));
    }

    #[test]
    fn keyring_section_loaded_from_toml() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[keyring]\nservice = \"my-service\"\naccount = \"my-account\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring.service.as_deref(), Some("my-service"));
        assert_eq!(loaded.keyring.account.as_deref(), Some("my-account"));
    }

    #[test]
    fn keyring_section_absent_gives_defaults() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring, KeyringConfig::default());
        assert!(loaded.keyring.service.is_none());
        assert!(loaded.keyring.account.is_none());
    }

    #[test]
    fn presence_section_loaded_from_toml() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[presence]\nidle_timeout_secs = 600\nquiet_hours_start = 22\nquiet_hours_end = 6\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.presence.idle_timeout_secs, Some(600));
        assert_eq!(loaded.presence.quiet_hours_start, Some(22));
        assert_eq!(loaded.presence.quiet_hours_end, Some(6));
    }

    #[test]
    fn presence_section_absent_gives_defaults() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert!(loaded.presence.idle_timeout_secs.is_none());
        assert!(loaded.presence.quiet_hours_start.is_none());
        assert!(loaded.presence.quiet_hours_end.is_none());
    }

    #[test]
    fn credential_store_section_absent_gives_none() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert!(loaded.credential_store.is_none());
    }

    #[test]
    fn runtime_backend_absent_defaults_to_docker_engine() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.runtime_backend, RuntimeBackend::DockerEngine);
    }

    #[test]
    fn runtime_backend_loads_supported_values() {
        for (raw, expected) in [
            ("docker-engine", RuntimeBackend::DockerEngine),
            ("apple-container", RuntimeBackend::AppleContainer),
            ("none-host-resident", RuntimeBackend::NoneHostResident),
        ] {
            let toml_str =
                format!("[daemon]\nlog_level = \"info\"\n\n[runtime]\nbackend = \"{raw}\"\n");
            let mut f = NamedTempFile::new().unwrap();
            f.write_all(toml_str.as_bytes()).unwrap();
            let loaded = DaemonConfig::load(f.path()).unwrap();
            assert_eq!(loaded.runtime_backend, expected);
        }
    }

    #[test]
    fn runtime_backend_rejects_unknown_with_supported_values() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[runtime]\nbackend = \"lima\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let err = DaemonConfig::load(f.path()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ConfigError::Validation(_)));
        assert!(msg.contains("runtime.backend"));
        assert!(msg.contains("lima"));
        for value in RuntimeBackend::supported_values() {
            assert!(
                msg.contains(value),
                "error must list supported runtime backend {value}: {msg}",
            );
        }
    }

    #[test]
    fn credential_store_section_local_backend() {
        let toml_str =
            "[daemon]\nlog_level = \"info\"\n\n[credential_store]\nbackend = \"local\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let cs = loaded.credential_store.expect("section parsed");
        assert_eq!(cs.backend, "local");
        assert_eq!(cs.mount, "secret");
        assert_eq!(cs.unavailable_policy, "fail-hard");
    }

    #[test]
    fn credential_store_section_hashicorp_vault_token() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[credential_store]\nbackend = \"hashicorp-vault\"\naddr = \"https://vault.example.com:8200\"\nmount = \"kv\"\nauth = \"token\"\ntoken = \"hvs.literal\"\nunavailable_policy = \"fall-back-to-cache\"\ncache_ttl_secs = 60\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let cs = loaded.credential_store.expect("section parsed");
        assert_eq!(cs.backend, "hashicorp-vault");
        assert_eq!(cs.addr.as_deref(), Some("https://vault.example.com:8200"));
        assert_eq!(cs.mount, "kv");
        assert_eq!(cs.auth.as_deref(), Some("token"));
        assert_eq!(cs.token.as_deref(), Some("hvs.literal"));
        assert_eq!(cs.unavailable_policy, "fall-back-to-cache");
        assert_eq!(cs.cache_ttl_secs, Some(60));
    }

    #[test]
    fn resolve_at_ref_literal_returns_input() {
        let v = resolve_at_ref("hvs.token-literal").unwrap();
        assert_eq!(v, "hvs.token-literal");
    }

    #[test]
    fn resolve_at_ref_file_reads_contents_and_trims_newline() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hvs.from-file\n").unwrap();
        let path_arg = format!("@{}", f.path().display());
        let v = resolve_at_ref(&path_arg).unwrap();
        assert_eq!(v, "hvs.from-file");
    }

    #[test]
    fn resolve_at_ref_missing_file_errors() {
        let path_arg = "@/no/such/file/should/exist/in/tests";
        let err = resolve_at_ref(path_arg).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn keyring_partial_section_service_only() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[keyring]\nservice = \"only-service\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();

        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.keyring.service.as_deref(), Some("only-service"));
        assert!(loaded.keyring.account.is_none());
    }

    #[test]
    fn scion_binary_pin_absent_gives_empty_defaults() {
        // SCION binary hash pin: when neither key is set the
        // daemon treats verification as disabled (dev installs).
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.scion_binary_path, PathBuf::new());
        assert_eq!(loaded.scion_binary_sha256, "");
    }

    #[test]
    fn scion_binary_pin_loaded_from_toml() {
        // SCION binary hash pin: both fields round-trip through
        // TOML so operators can pin the binary in `config.toml`.
        let toml_str = "[daemon]\nlog_level = \"info\"\nscion_binary_path = \"/opt/scion/scion\"\nscion_binary_sha256 = \"abc123\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.scion_binary_path, PathBuf::from("/opt/scion/scion"));
        assert_eq!(loaded.scion_binary_sha256, "abc123");
    }

    // -----------------------------------------------------------------
    // `[spawn_pool]` TOML deserializer.
    // -----------------------------------------------------------------

    #[test]
    fn spawn_pool_absent_defaults_to_none() {
        // Default posture: no [spawn_pool] section means the daemon
        // treats the pool as not-configured and broker_exec refuses
        // with -32021. The installer must provision the pool to
        // unblock broker_exec.
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert!(loaded.spawn_pool.is_none());
    }

    #[test]
    fn spawn_pool_loaded_from_toml() {
        // The installer writes this shape; the daemon parses it on
        // startup and installs the pool via uid_alloc::init_uid_pool.
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[spawn_pool]\nuids = [10010, 10011, 10012]\ngid = 10020\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let pool = loaded.spawn_pool.expect("spawn_pool must round-trip");
        assert_eq!(pool.uids, vec![10010, 10011, 10012]);
        assert_eq!(pool.gid, 10020);
    }

    #[test]
    fn spawn_pool_accepts_empty_uid_list() {
        // An empty uids array is semantically "pool configured but
        // useless"; the daemon surfaces this at checkout time as
        // -32021 (PoolEmpty). The config parser accepts the shape so
        // operators can stage installs that provision uids later.
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[spawn_pool]\nuids = []\ngid = 10020\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let pool = loaded.spawn_pool.expect("spawn_pool present");
        assert!(pool.uids.is_empty());
    }

    // -----------------------------------------------------------------
    // ADR 155 Component 2 subuid range
    // round-trips through the DaemonConfig parser. The installer writes
    // this shape on modern-Linux hosts where unprivileged_userns_clone=1.
    // -----------------------------------------------------------------

    #[test]
    fn spawn_pool_subuid_range_round_trips() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n\n[spawn_pool]\nsubuid_range_start = 100000\nsubuid_range_slots = 8192\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let pool = loaded.spawn_pool.expect("spawn_pool must round-trip");
        assert_eq!(pool.subuid_range_start, Some(100_000));
        assert_eq!(pool.subuid_range_slots, Some(8192));
        // The legacy uid-list fields default to empty on the subuid path
        // (the kernel-side range IS the pool — no enumerated uids).
        assert!(pool.uids.is_empty());
    }

    #[test]
    fn spawn_pool_subuid_absent_defaults_to_none() {
        // Legacy shape (only uids/gid present) — subuid fields default
        // to None so the installer can detect "this is a system-user
        // pool, not a subuid range pool" downstream.
        let toml_str =
            "[daemon]\nlog_level = \"info\"\n\n[spawn_pool]\nuids = [10010]\ngid = 10020\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        let pool = loaded.spawn_pool.expect("spawn_pool present");
        assert_eq!(pool.subuid_range_start, None);
        assert_eq!(pool.subuid_range_slots, None);
        assert_eq!(pool.uids, vec![10010]);
        assert_eq!(pool.gid, 10020);
    }

    #[test]
    fn bridge_bind_absent_defaults_to_disabled() {
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_BRIDGE_BIND").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe {
            std::env::remove_var("EMBER_BRIDGE_BIND");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.bridge_bind, None);
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_BRIDGE_BIND", v),
                None => std::env::remove_var("EMBER_BRIDGE_BIND"),
            }
        }
    }

    #[test]
    fn bridge_bind_from_config_field() {
        let toml_str = "[daemon]\nlog_level = \"info\"\nbridge_bind = \"127.0.0.1:8443\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_BRIDGE_BIND").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe {
            std::env::remove_var("EMBER_BRIDGE_BIND");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.bridge_bind, Some("127.0.0.1:8443".parse().unwrap()));
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_BRIDGE_BIND", v),
                None => std::env::remove_var("EMBER_BRIDGE_BIND"),
            }
        }
    }

    #[test]
    fn bridge_bind_env_overrides_config_field() {
        let toml_str = "[daemon]\nlog_level = \"info\"\nbridge_bind = \"127.0.0.1:8443\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_BRIDGE_BIND").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe {
            std::env::set_var("EMBER_BRIDGE_BIND", "127.0.0.1:9443");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.bridge_bind, Some("127.0.0.1:9443".parse().unwrap()));
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_BRIDGE_BIND", v),
                None => std::env::remove_var("EMBER_BRIDGE_BIND"),
            }
        }
    }

    // -----------------------------------------------------------------
    // ADR 157 §Component 1 — trust-root config parsing tests (T2-shape:
    // exercise the TOML→DaemonConfig load boundary).
    // -----------------------------------------------------------------

    #[test]
    fn trust_roots_absent_defaults_to_empty() {
        // Prod default: no env, no config field → empty trust_roots
        // (daemon's startup wiring then trusts only the compiled-in
        // release IdentityRoot).
        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        // Guard against an env-var leak from a parallel test by clearing
        // EMBER_TRUST_ROOTS for this call. Re-set after to preserve
        // ambient state.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_TRUST_ROOTS").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above; env mutation
        // is scoped to this test body and restored before the lock drops.
        unsafe {
            std::env::remove_var("EMBER_TRUST_ROOTS");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.trust_roots, "");
        if let Some(v) = prior {
            unsafe {
                std::env::set_var("EMBER_TRUST_ROOTS", v);
            }
        }
    }

    #[test]
    fn trust_roots_from_config_field() {
        let toml_str = "[daemon]\nlog_level = \"info\"\ntrust_roots = \"did:key:aabb\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_TRUST_ROOTS").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe {
            std::env::remove_var("EMBER_TRUST_ROOTS");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.trust_roots, "did:key:aabb");
        if let Some(v) = prior {
            unsafe {
                std::env::set_var("EMBER_TRUST_ROOTS", v);
            }
        }
    }

    #[test]
    fn trust_roots_env_overrides_config_field() {
        // Env precedence matches the EMBER_BRIDGE_BIND convention.
        let toml_str = "[daemon]\nlog_level = \"info\"\ntrust_roots = \"did:key:from-toml\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("EMBER_TRUST_ROOTS").ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe {
            std::env::set_var("EMBER_TRUST_ROOTS", "did:key:from-env");
        }
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.trust_roots, "did:key:from-env");
        unsafe {
            match prior {
                Some(v) => std::env::set_var("EMBER_TRUST_ROOTS", v),
                None => std::env::remove_var("EMBER_TRUST_ROOTS"),
            }
        }
    }

    // -----------------------------------------------------------------
    // V030-AUTH-LEASE-3 — single-knob lease TTL (ADR 211 §2 / OQ-1).
    //
    // Checkpoint `lease_ttl_single_knob_dev0_one_principal`: there is no
    // separate "default vs ceiling" knob — dev0 has one principal, so one
    // knob (default IS the ceiling within the typo-protection bounds).
    // -----------------------------------------------------------------

    /// Helper: clear `EMBER_LEASE_TTL_SECS` while the PROCESS_TEST_LOCK is
    /// held, returning the prior value for restoration. Mirrors the
    /// `EMBER_TRUST_ROOTS` / `EMBER_BRIDGE_BIND` pattern in this module.
    fn take_lease_ttl_env_var() -> Option<String> {
        let prior = std::env::var(EMBER_LEASE_TTL_SECS_ENV).ok();
        // SAFETY: caller must hold PROCESS_TEST_LOCK before invoking.
        unsafe { std::env::remove_var(EMBER_LEASE_TTL_SECS_ENV) };
        prior
    }

    fn restore_lease_ttl_env_var(prior: Option<String>) {
        // SAFETY: caller must hold PROCESS_TEST_LOCK before invoking.
        unsafe {
            match prior {
                Some(v) => std::env::set_var(EMBER_LEASE_TTL_SECS_ENV, v),
                None => std::env::remove_var(EMBER_LEASE_TTL_SECS_ENV),
            }
        }
    }

    #[test]
    fn lease_ttl_default_is_one_hour() {
        // The operator-locked dev0 dial: 1 hour = "max compromise window" /
        // "how long the system runs without me." See ADR 211 §2 elegant
        // property + `DEFAULT_LEASE_TTL_SECS` doc-comment.
        let cfg = DaemonConfig::load_defaults();
        assert_eq!(cfg.lease_ttl_secs, 3600);
        assert_eq!(cfg.lease_ttl_secs, DEFAULT_LEASE_TTL_SECS);
    }

    #[test]
    fn lease_ttl_for_test_matches_default() {
        // for_test mirrors the production posture so test grant lifecycles
        // don't accidentally pick a value an operator would never see.
        let tmp = TempDir::new().unwrap();
        let cfg = DaemonConfig::for_test(tmp.path());
        assert_eq!(cfg.lease_ttl_secs, DEFAULT_LEASE_TTL_SECS);
    }

    #[test]
    fn lease_ttl_absent_in_toml_defaults_to_one_hour() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = take_lease_ttl_env_var();

        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.lease_ttl_secs, DEFAULT_LEASE_TTL_SECS);

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_from_config_field() {
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = take_lease_ttl_env_var();

        let toml_str = "[daemon]\nlog_level = \"info\"\nlease_ttl_secs = 1800\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.lease_ttl_secs, 1800);

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_env_overrides_config_field() {
        // Env precedence matches the EMBER_BRIDGE_BIND / EMBER_TRUST_ROOTS
        // convention — operators can dial a shorter TTL for an ephemeral
        // session without editing config.toml.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(EMBER_LEASE_TTL_SECS_ENV).ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var(EMBER_LEASE_TTL_SECS_ENV, "300") };

        let toml_str = "[daemon]\nlog_level = \"info\"\nlease_ttl_secs = 3600\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let loaded = DaemonConfig::load(f.path()).unwrap();
        assert_eq!(loaded.lease_ttl_secs, 300);

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_below_minimum_fails_closed_at_load() {
        // 30s is below the 60s typo-protection floor — config load fails
        // closed rather than silently disabling the time-box.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = take_lease_ttl_env_var();

        let toml_str = "[daemon]\nlog_level = \"info\"\nlease_ttl_secs = 30\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let err = DaemonConfig::load(f.path()).unwrap_err();
        match err {
            ConfigError::Validation(m) => {
                assert!(m.contains("lease_ttl_secs"));
                assert!(m.contains("out of range"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_above_maximum_fails_closed_at_load() {
        // 30 days exceeds the 7-day typo-protection ceiling. The intent of
        // the bound is to catch a "10 years" typo, NOT to act as a security
        // cap — but values above 7d are almost always a mistake.
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = take_lease_ttl_env_var();

        let too_long = 30 * 24 * 60 * 60; // 30 days
        let toml_str = format!("[daemon]\nlog_level = \"info\"\nlease_ttl_secs = {too_long}\n");
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let err = DaemonConfig::load(f.path()).unwrap_err();
        match err {
            ConfigError::Validation(m) => {
                assert!(m.contains("lease_ttl_secs"));
                assert!(m.contains("out of range"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_bounds_are_inclusive() {
        // The exact bound values (MIN, MAX) must succeed — operators can
        // legitimately pin to the floor (e.g. tight presence-test loops) or
        // the ceiling (long-running dogfooding).
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = take_lease_ttl_env_var();

        for ttl in [MIN_LEASE_TTL_SECS, MAX_LEASE_TTL_SECS] {
            let toml_str = format!("[daemon]\nlog_level = \"info\"\nlease_ttl_secs = {ttl}\n");
            let mut f = NamedTempFile::new().unwrap();
            f.write_all(toml_str.as_bytes()).unwrap();
            let loaded = DaemonConfig::load(f.path()).unwrap();
            assert_eq!(loaded.lease_ttl_secs, ttl);
        }

        restore_lease_ttl_env_var(prior);
    }

    #[test]
    fn lease_ttl_env_unparseable_fails_closed_at_load() {
        // An env-var typo (`60s`, `abc`, empty) must NOT silently fall
        // through to the config-file value or default — that would defeat
        // the operator's intent (they set the env to mean "use this TTL").
        let _guard = crate::PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(EMBER_LEASE_TTL_SECS_ENV).ok();
        // SAFETY: serialized via PROCESS_TEST_LOCK above.
        unsafe { std::env::set_var(EMBER_LEASE_TTL_SECS_ENV, "abc") };

        let toml_str = "[daemon]\nlog_level = \"info\"\n";
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(toml_str.as_bytes()).unwrap();
        let err = DaemonConfig::load(f.path()).unwrap_err();
        match err {
            ConfigError::Validation(m) => {
                assert!(m.contains(EMBER_LEASE_TTL_SECS_ENV));
            }
            other => panic!("expected Validation, got {other:?}"),
        }

        restore_lease_ttl_env_var(prior);
    }
}
