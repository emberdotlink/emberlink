use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::infra::store::{DaemonStore, StoreError};

mod docker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub name: String,
    pub persona_id: String,
    pub owner_persona_id: Option<String>,
    pub container_id: Option<String>,
    pub image: String,
    pub status: String,
    pub created_at: String,
    pub workspace_path: Option<String>,
}

/// Options carried into `create_sandbox`. Covers all operator-settable flags
/// that are subject to the MVS-A hardening invariants (ADR 070 §Hardening
/// invariants — Refused at sandbox create).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxCreateOpts {
    pub name: String,
    pub image: String,
    /// Refused unless `unsafe_root` is true. `--privileged` in docker-speak.
    pub privileged: bool,
    /// Mount specs in `host:container[:ro]` form. Each host path is resolved
    /// (canonicalized when it exists) and checked against the denylist.
    pub volumes: Vec<String>,
    /// User override. `"0"` or `"root"` are refused unless `unsafe_root`.
    pub user: Option<String>,
    /// Network mode. `Some("host")` is refused unconditionally. `None` means
    /// bridge (the MVS default); `Some("none")` is available for tests.
    pub network: Option<String>,
    /// Explicit opt-in to run as root. Required to bypass the root-user refusal.
    pub unsafe_root: bool,
    /// Git URL to clone into `<data_dir>/sandboxes/<id>/workspace/`.
    pub workspace_from: Option<String>,
    /// Additional `KEY=VAL` env vars to pass into the container.
    pub extra_env: Vec<(String, String)>,
    /// Persona that is creating this sandbox. Stored as `owner_persona_id`
    /// and required to match on subsequent `exec_sandbox` calls. `None`
    /// skips the ownership check for backwards-compat with legacy callers.
    pub owner_persona_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCreateResult {
    pub sandbox: SandboxInfo,
    pub container_id: Option<String>,
    pub start_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxDeleteResult {
    pub resolved_id: Option<String>,
    pub already_absent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxRunGrantDisposition {
    NotRequested,
    PendingApproval { approval_id: String },
    Minted { grant_id: Option<String> },
    Failed { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRunResult {
    pub sandbox: SandboxInfo,
    pub container_id: Option<String>,
    pub start_error: Option<String>,
    pub grant: SandboxRunGrantDisposition,
}

/// Host paths that must never appear in a mount source, per ADR 070
/// §Hardening invariants. Checked as substring match on the resolved absolute
/// path of the mount source.
const FORBIDDEN_MOUNT_SUBSTRINGS: &[&str] = &[
    "/var/run/docker.sock",
    "/.ssh",
    "/.aws",
    "/.kube",
    "/.gnupg",
];

/// Resolve tilde + $HOME in a path-like string. Returns the canonicalized
/// absolute path if it exists, or the logically resolved path if it doesn't.
fn resolve_host_path(raw: &str) -> PathBuf {
    let expanded = if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if raw == "~" {
            home
        } else if let Some(rest) = raw.strip_prefix("~/") {
            home.join(rest)
        } else if let Some(rest) = raw.strip_prefix("$HOME/") {
            home.join(rest)
        } else if raw == "$HOME" {
            home
        } else {
            PathBuf::from(raw)
        }
    } else {
        PathBuf::from(raw)
    };
    std::fs::canonicalize(&expanded).unwrap_or(expanded)
}

/// Parse a docker-style mount spec (`host:container[:opts]`) and return the
/// host source portion. Everything after the second `:` is options; only the
/// first `:` separates host from container.
fn mount_source(spec: &str) -> &str {
    spec.split(':').next().unwrap_or(spec)
}

/// Validate an `SandboxCreateOpts` against the MVS-A hardening invariants.
/// Returns `Err(StoreError::InvalidInput("sandbox invariant violated: <slug>"))`
/// on first violation. Invariant slugs are stable identifiers — callers and
/// tests depend on them.
pub(crate) fn validate_sandbox_opts(opts: &SandboxCreateOpts) -> Result<(), StoreError> {
    if opts.privileged {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-privileged".into(),
        ));
    }

    if matches!(opts.network.as_deref(), Some("host")) {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-host-network".into(),
        ));
    }

    if let Some(user) = opts.user.as_deref()
        && !opts.unsafe_root
        && (user == "0" || user == "root" || user.starts_with("0:"))
    {
        return Err(StoreError::InvalidInput(
            "sandbox invariant violated: no-root-user".into(),
        ));
    }

    let home = std::env::var("HOME").ok();
    for v in &opts.volumes {
        let raw = mount_source(v);
        let resolved = resolve_host_path(raw);
        let as_str = resolved.to_string_lossy().to_string();

        if as_str.contains("/var/run/docker.sock") || raw.contains("/var/run/docker.sock") {
            return Err(StoreError::InvalidInput(
                "sandbox invariant violated: no-docker-socket-mount".into(),
            ));
        }

        if let Some(ref h) = home {
            let h_trim = h.trim_end_matches('/');
            if !h_trim.is_empty()
                && (as_str == *h_trim || as_str.starts_with(&format!("{h_trim}/")))
            {
                // Any mount under $HOME — refused. Covers $HOME itself,
                // ~/.ssh, ~/.aws, ~/.kube, ~/.gnupg, etc.
                if as_str == *h_trim {
                    return Err(StoreError::InvalidInput(
                        "sandbox invariant violated: no-home-mount".into(),
                    ));
                }
                // Fall through to the sensitive-subpath check for a more
                // specific slug when applicable.
            }
        }

        for forbidden in FORBIDDEN_MOUNT_SUBSTRINGS {
            if as_str.contains(forbidden) || raw.contains(forbidden) {
                let slug = match *forbidden {
                    "/var/run/docker.sock" => "no-docker-socket-mount",
                    "/.ssh" => "no-ssh-mount",
                    "/.aws" => "no-aws-mount",
                    "/.kube" => "no-kube-mount",
                    "/.gnupg" => "no-gnupg-mount",
                    _ => "no-sensitive-mount",
                };
                return Err(StoreError::InvalidInput(format!(
                    "sandbox invariant violated: {slug}"
                )));
            }
        }

        // Final $HOME check after sensitive-subpath pass — catches $HOME itself
        // and any arbitrary subdir not already named above.
        if let Some(ref h) = home {
            let h_trim = h.trim_end_matches('/');
            if !h_trim.is_empty()
                && (as_str == *h_trim || as_str.starts_with(&format!("{h_trim}/")))
            {
                return Err(StoreError::InvalidInput(
                    "sandbox invariant violated: no-home-mount".into(),
                ));
            }
        }
    }

    Ok(())
}

/// Credential env keys that must NEVER reach a sandbox container's `-e` env.
///
/// Per ADR 207 §I1 (Principle #1 — agents never hold raw credentials), the
/// container's LLM lane arrives as a proxy-injected gateway bundle
/// (`ANTHROPIC_BASE_URL` + `X-Ember-*` headers minted by
/// `mint_sandbox_gateway_env`); a raw key in the container env is the exact
/// violation this strip closes. Enforced as a tripwire at the single `-e` emit
/// point in [`build_run_args`] so it holds even if a future caller re-adds
/// host-env passthrough upstream.
///
/// NOTE: the inert `ANTHROPIC_AUTH_TOKEN` *checkpoint*
/// ([`CONTAINER_PROXY_AUTH_PLACEHOLDER`]) is deliberately NOT here — Claude Code
/// refuses to start under a custom `ANTHROPIC_BASE_URL` without some bearer
/// present, and the proxy strips the inbound `authorization` regardless of value
/// before injecting the real vault-backed credential upstream.
pub(crate) const FORBIDDEN_CONTAINER_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY",
];

/// Inert bearer the sandbox container carries so Claude Code clears its
/// client-side auth-presence preflight under a brokered `ANTHROPIC_BASE_URL`.
/// Mirrors the host launcher's `ISOLATED_CLAUDE_PROXY_AUTH_PLACEHOLDER`
/// (`emberlink-cli` `up::ISOLATED_CLAUDE_PROXY_AUTH_PLACEHOLDER`). The real
/// credential is injected server-side by the proxy.
pub(crate) const CONTAINER_PROXY_AUTH_PLACEHOLDER: &str = "ember-proxy-session";

/// Container-side paths for the ADR 154 mTLS bridge client material. The daemon
/// bind-mounts a per-sandbox cert directory read-only at
/// [`CONTAINER_BRIDGE_MOUNT_DIR`]; the agent dials `EMBER_BRIDGE_URL` with the
/// client cert/key and validates the daemon against the CA. Mirrors the CLI
/// isolated lane's `up::CONTAINER_BRIDGE_*` — the two container lanes share the
/// launch contract (ADR 207) while keeping separate implementations (ADR 207
/// open decision: keep daemon-sandbox and launcher-isolated split until a
/// uid/threat-model identity is proven).
const CONTAINER_BRIDGE_MOUNT_DIR: &str = "/run/ember";
const CONTAINER_BRIDGE_CERT: &str = "/run/ember/client.crt";
const CONTAINER_BRIDGE_KEY: &str = "/run/ember/client.key";
const CONTAINER_BRIDGE_CA: &str = "/run/ember/ca.crt";

/// The per-spawn ADR 154 mTLS bridge client material a sandbox container mounts
/// as its emberd control plane (ADR 207 seam 6). `cert_dir` holds `client.crt`,
/// `client.key`, and `ca.crt` on the host and is bind-mounted read-only at
/// `/run/ember`; `port` builds the `EMBER_BRIDGE_URL` the container dials. This
/// replaces the (non-functional, ADR 154) daemon-UDS bind mount that previously
/// shipped into every container — a bind-mounted `AF_UNIX` socket is remapped
/// `root:root` by the runtime userns so the agent uid (1000) can never
/// `connect(2)` to it.
pub struct SandboxBridgeMount<'a> {
    pub cert_dir: &'a Path,
    pub port: u16,
}

/// Rewrite a daemon-loopback proxy URL so a sandbox container can reach the
/// host proxy. `start_container` shells out to the `docker` CLI directly, so the
/// container-reachable host alias is always `host.docker.internal` (Docker
/// Desktop / OrbStack resolve it automatically; Linux needs the
/// `--add-host=host.docker.internal:host-gateway` that [`build_run_args`] adds
/// for non-`none` networks). Mirrors `emberlink-cli`
/// `up::rewrite_loopback_url_for_container` (the compose lane's parity path).
pub(crate) fn rewrite_loopback_url_for_container(url: &str) -> String {
    const CONTAINER_HOST: &str = "host.docker.internal";
    for prefix in [
        "http://127.0.0.1:",
        "https://127.0.0.1:",
        "http://localhost:",
        "https://localhost:",
    ] {
        if let Some(rest) = url.strip_prefix(prefix) {
            let scheme = if prefix.starts_with("https") {
                "https"
            } else {
                "http"
            };
            return format!("{scheme}://{CONTAINER_HOST}:{rest}");
        }
    }
    url.to_string()
}

/// Pure helper: compose the `docker run` argument vector from the sandbox
/// configuration. Kept separate from the subprocess call so tests can assert
/// the exact argument shape without spawning docker.
///
/// target_state_anchor: adr207_seam6_one_response_parser_cli_contract_parity
///
/// ADR 207 §Migration seam 6 — the last container-lane consolidation seam — is
/// complete: the daemon-sandbox and CLI `--isolated` lanes share one launch
/// contract (no daemon UDS in-container; the brokered-tool control path rides the
/// ADR 154 mTLS bridge via the per-spawn client bundle mounted at `/run/ember`),
/// and there is one `register_session` response parser
/// (`launcher::session_rpc::parse_register_session_result`; the duplicate
/// `up::parse_session_open_response` was deleted). Shipped by #5249 (parser) and
/// #5250 (daemon-sandbox bridge control plane).
pub(crate) fn build_run_args(
    name: &str,
    image: &str,
    network: Option<&str>,
    extra_env: &[(String, String)],
    workspace_host_path: Option<&Path>,
    bridge_cert_dir: Option<&Path>,
) -> Vec<String> {
    let net = network.unwrap_or("bridge");

    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.into(),
        format!("--network={net}"),
        "--cap-drop=ALL".into(),
        "--read-only".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--user".into(),
        "1000:1000".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=1g".into(),
        "--tmpfs".into(),
        "/home/agent:rw,nosuid,uid=1000,gid=1000,size=100m".into(),
    ];

    // ADR 154 / ADR 207 seam 6 — the container's emberd control plane is the
    // mTLS bridge, never the daemon UDS. The per-spawn client bundle
    // (`client.crt`/`client.key`/`ca.crt`) is bind-mounted read-only at
    // `/run/ember`; the matching `EMBER_BRIDGE_URL` / `EMBER_CLIENT_*` /
    // `EMBER_CA_CERT` env is set by `start_container`. Absent when the bridge
    // listener is unconfigured (fail-soft: the container still starts, just
    // without a control plane — never with the dead `root:root`-remapped UDS).
    if let Some(cert_dir) = bridge_cert_dir {
        args.push("-v".into());
        args.push(format!(
            "{}:{CONTAINER_BRIDGE_MOUNT_DIR}:ro",
            cert_dir.display()
        ));
    }

    if let Some(ws) = workspace_host_path {
        args.push("-v".into());
        args.push(format!("{}:/workspace:rw", ws.display()));
    }

    // ADR 207 — let the proxy-injected `ANTHROPIC_BASE_URL=http://host.docker.internal:<port>`
    // resolve to the host proxy. Docker Desktop / OrbStack provide
    // `host.docker.internal` automatically but accept the explicit host-gateway
    // mapping too; Linux Docker requires it. Skipped on `--network=none` (the
    // offline test path has no host gateway).
    if net != "none" {
        args.push("--add-host".into());
        args.push("host.docker.internal:host-gateway".into());
    }

    for (k, v) in extra_env {
        // ADR 207 §I1 tripwire — a raw credential key must never become a
        // container `-e` var. Stripped here at the sole emit point so the
        // invariant holds even if an upstream caller re-introduces host-env
        // passthrough; the LLM lane arrives as a proxy-injected gateway bundle.
        if FORBIDDEN_CONTAINER_ENV_KEYS
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(k))
        {
            tracing::warn!(
                key = %k,
                "refusing to pass forbidden credential env var into sandbox container (ADR 207 §I1)"
            );
            continue;
        }
        // ADR 207 §I1 — `ANTHROPIC_AUTH_TOKEN` may ONLY carry the inert proxy
        // checkpoint. The host launcher strips any inherited real bearer and
        // re-sets the checkpoint; mirror that here so a caller cannot smuggle a
        // real token through `extra_env` (the daemon's own injected value is
        // exactly the checkpoint, so it survives this gate).
        if k.eq_ignore_ascii_case("ANTHROPIC_AUTH_TOKEN") && v != CONTAINER_PROXY_AUTH_PLACEHOLDER {
            tracing::warn!(
                key = %k,
                "stripping non-checkpoint ANTHROPIC_AUTH_TOKEN from sandbox container env (ADR 207 §I1)"
            );
            continue;
        }
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }

    args.push(image.into());
    args.push("sleep".into());
    args.push("infinity".into());

    args
}

impl DaemonStore {
    /// Legacy two-arg constructor. Creates a sandbox with default
    /// hardening (no privileged, no overrides). New callers should use
    /// [`create_sandbox_with_opts`] to carry volumes/env/workspace.
    pub fn create_sandbox(&self, name: &str, image: &str) -> Result<SandboxInfo, StoreError> {
        let opts = SandboxCreateOpts {
            name: name.to_string(),
            image: image.to_string(),
            ..Default::default()
        };
        self.create_sandbox_with_opts(&opts, None)
    }

    /// Create a sandbox, enforcing all refusal invariants and provisioning a
    /// fresh-clone workspace when `opts.workspace_from` is set.
    ///
    /// `data_dir` is the daemon's persistent data directory — required when a
    /// workspace clone is requested (the clone target is
    /// `<data_dir>/sandboxes/<id>/workspace/`). Pass `None` when callers know
    /// no workspace is requested (tests, legacy two-arg path).
    pub fn create_sandbox_with_opts(
        &self,
        opts: &SandboxCreateOpts,
        data_dir: Option<&Path>,
    ) -> Result<SandboxInfo, StoreError> {
        validate_sandbox_opts(opts)?;

        if opts.workspace_from.is_some() && data_dir.is_none() {
            return Err(StoreError::InvalidInput(
                "workspace_from requires data_dir".into(),
            ));
        }

        let persona = self.create_persona(&opts.name)?;
        let id = format!("sandbox-{}", Uuid::new_v4());
        let created_at = Utc::now().to_rfc3339();

        // Clone workspace if requested. Must happen before DB insert so a
        // clone failure aborts the whole create.
        let workspace_path: Option<PathBuf> = if let Some(url) = opts.workspace_from.as_deref() {
            let dd = data_dir.expect("checked above");
            let target = dd.join("sandboxes").join(&id).join("workspace");
            if let Some(parent) = target.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Err(StoreError::InvalidInput(format!(
                    "workspace parent create failed: {e}"
                )));
            }
            clone_workspace(url, &target)?;
            chown_workspace_best_effort(&target);
            Some(target)
        } else {
            None
        };

        let workspace_str = workspace_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());

        self.conn().execute(
            "INSERT INTO sandboxes (id, name, persona_id, owner_persona_id, container_id, image, status, created_at, workspace_path)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, 'created', ?6, ?7)",
            rusqlite::params![id, opts.name, persona.id, opts.owner_persona_id, opts.image, created_at, workspace_str],
        )?;

        Ok(SandboxInfo {
            id,
            name: opts.name.clone(),
            persona_id: persona.id,
            owner_persona_id: opts.owner_persona_id.clone(),
            container_id: None,
            image: opts.image.clone(),
            status: "created".to_string(),
            created_at,
            workspace_path: workspace_str,
        })
    }

    /// ADR 207 §I2 — record the internal `register_session` id minted for this
    /// sandbox's proxy LLM lane, so `sandbox_stop` / `sandbox_delete` can later
    /// `close_session` it (releasing the vault-lock pin + host-mode enrollment
    /// + attachment).
    ///
    /// Returns [`StoreError::NotFound`] when no row matched (e.g. a concurrent
    /// delete). The caller MUST treat that as fatal for the lane and close the
    /// minted session itself — a silently-unbound session can never be closed by
    /// stop/delete, stranding the pin.
    pub fn set_sandbox_session_id(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> Result<(), StoreError> {
        let affected = self.conn().execute(
            "UPDATE sandboxes SET session_id = ?1 WHERE id = ?2",
            rusqlite::params![session_id, sandbox_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Read the internal `register_session` id bound to a sandbox (ADR 207 §I2),
    /// if one was minted. `Ok(None)` for sandboxes with no brokered LLM lane or
    /// rows predating the migration.
    pub fn sandbox_session_id(&self, sandbox_id: &str) -> Result<Option<String>, StoreError> {
        self.conn()
            .query_row(
                "SELECT session_id FROM sandboxes WHERE id = ?1",
                rusqlite::params![sandbox_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                other => StoreError::Sqlite(other),
            })
    }

    /// Clear the session binding after the sandbox's session has been closed
    /// (ADR 207 §I2), so a later stop/delete does not attempt a redundant close.
    pub fn clear_sandbox_session_id(&self, sandbox_id: &str) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE sandboxes SET session_id = NULL WHERE id = ?1",
            rusqlite::params![sandbox_id],
        )?;
        Ok(())
    }

    /// Start the container for a previously-created sandbox.
    ///
    /// `network` defaults to bridge (MVS-A default) when `None`; tests pass
    /// `Some("none")` to keep the docker path fast and offline. `extra_env`
    /// is passed through as `-e KEY=VAL` to the container — the daemon also
    /// injects `EMBER_PERSONA_ID`.
    ///
    /// `bridge` carries the per-spawn ADR 154 mTLS bridge client material (ADR
    /// 207 seam 6). When `Some`, the cert dir is bind-mounted at `/run/ember`
    /// and the matching `EMBER_BRIDGE_URL` / `EMBER_CLIENT_CERT` /
    /// `EMBER_CLIENT_KEY` / `EMBER_CA_CERT` env is injected, wiring the
    /// container's brokered-tool (`core-construct-runtime` shim) control path to
    /// the bridge. (The `emberlink-mcp` grant-resolution bridge mode keys off a
    /// separate, still-unwired `EMBER_DAEMON_ENDPOINT` — see the env block below.)
    /// When `None` (bridge listener unconfigured) the container still starts,
    /// just without a control path — the daemon UDS is **never** mounted in (it
    /// is non-functional across the userns, ADR 154).
    ///
    /// ADR 207 §I1: this no longer pushes a raw `ANTHROPIC_API_KEY` (nor an
    /// `EMBER_PROXY_URL`) from the daemon env. The LLM lane reaches the
    /// container as a proxy-injected gateway bundle supplied in `extra_env` by
    /// the sandbox RPC handler (`mint_sandbox_gateway_env`); raw credential keys
    /// are stripped at the `-e` emit point by [`build_run_args`].
    pub fn start_container(
        &self,
        sandbox_id: &str,
        network: Option<&str>,
        extra_env: &[(String, String)],
        bridge: Option<SandboxBridgeMount<'_>>,
    ) -> Result<String, StoreError> {
        let (name, image, persona_id, workspace_path): (String, String, String, Option<String>) =
            self.conn()
                .query_row(
                    "SELECT name, image, persona_id, workspace_path FROM sandboxes WHERE id = ?1",
                    rusqlite::params![sandbox_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                    other => StoreError::Sqlite(other),
                })?;

        // Compose the env block: caller-provided vars first (the daemon's
        // sandbox RPC handler injects the proxy-minted LLM gateway bundle here,
        // ADR 207 §I1/§I2), then the daemon's injected vars.
        let mut env: Vec<(String, String)> = extra_env.to_vec();
        env.push(("EMBER_PERSONA_ID".to_string(), persona_id));
        // ADR 154 / ADR 207 seam 6 — wire the container's BROKER/construct-shim
        // control path onto the mTLS bridge. These are the env vars the in-container
        // `core-construct-runtime` shims (`ember-git` / `ember-gh`) read to broker
        // tool calls over the bridge: `EMBER_BRIDGE_URL` + the cert/key/CA paths
        // under `/run/ember` (bind-mounted by `build_run_args`). This matches the
        // CLI `--isolated` lane's `isolated_child_env` contract (seam 6 parity).
        //
        // SCOPE: this does NOT launch the `emberlink-mcp` grant-resolution bridge
        // lane — that path is still unwired in BOTH container lanes (the
        // orchestrator's launch of emberlink-mcp is an open TODO, ADR 209 §2 /
        // demo invariant #2). As of ADR 215 §4, emberlink-mcp now selects on and
        // reads the SAME unified contract this block sets (`EMBER_BRIDGE_URL` +
        // `EMBER_CLIENT_*`), so wiring it becomes launch-only. The brokered-tool
        // path (construct-shim, the demo's "brokered push" beat) is wired here.
        //
        // The daemon UDS (`EMBER_DAEMON_SOCKET` + the socket bind mount) is GONE —
        // it was remapped `root:root` by the runtime userns so the agent uid could
        // never `connect(2)` to it (ADR 154); it was already non-functional.
        if let Some(ref b) = bridge {
            // `start_container` shells out to the `docker` CLI directly, so the
            // container-reachable host is always `host.docker.internal` (the
            // `--add-host=host.docker.internal:host-gateway` that `build_run_args`
            // adds for non-`none` networks), matching `rewrite_loopback_url_for_container`.
            env.push((
                "EMBER_BRIDGE_URL".to_string(),
                format!("https://host.docker.internal:{}", b.port),
            ));
            env.push((
                "EMBER_CLIENT_CERT".to_string(),
                CONTAINER_BRIDGE_CERT.to_string(),
            ));
            env.push((
                "EMBER_CLIENT_KEY".to_string(),
                CONTAINER_BRIDGE_KEY.to_string(),
            ));
            env.push(("EMBER_CA_CERT".to_string(), CONTAINER_BRIDGE_CA.to_string()));
        }
        // ADR 207 §I1 (Principle #1 — agents never hold raw credentials): the
        // daemon-env pass-through of `EMBER_PROXY_URL` and `ANTHROPIC_API_KEY`
        // is DELETED. The container receives a proxy-injected gateway bundle
        // (`ANTHROPIC_BASE_URL` + `X-Ember-*` headers, minted by
        // `mint_sandbox_gateway_env`) through `extra_env` instead — it never
        // sees a raw key. `build_run_args` strips the forbidden credential keys
        // at the `-e` emit point as a tripwire even if a future caller re-adds
        // host-env passthrough.

        let workspace_buf = workspace_path.as_ref().map(PathBuf::from);
        let args = build_run_args(
            &name,
            &image,
            network,
            &env,
            workspace_buf.as_deref(),
            bridge.as_ref().map(|b| b.cert_dir),
        );

        let output = docker::output(&args)
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::warn!(
                cmd = "docker run",
                sandbox_id = %sandbox_id,
                exit = output.status.code().unwrap_or(-1),
                stderr = %stderr,
                "subprocess failed"
            );
            self.conn().execute(
                "UPDATE sandboxes SET status = 'error' WHERE id = ?1",
                rusqlite::params![sandbox_id],
            )?;
            return Err(StoreError::InvalidInput(format!(
                "docker run failed: {stderr}"
            )));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        self.conn().execute(
            "UPDATE sandboxes SET container_id = ?1, status = 'running' WHERE id = ?2",
            rusqlite::params![container_id, sandbox_id],
        )?;

        Ok(container_id)
    }

    pub fn list_sandboxes(&self) -> Result<Vec<SandboxInfo>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT id, name, persona_id, owner_persona_id, container_id, image, status, created_at, workspace_path
             FROM sandboxes ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SandboxInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                persona_id: row.get(2)?,
                owner_persona_id: row.get(3)?,
                container_id: row.get(4)?,
                image: row.get(5)?,
                status: row.get(6)?,
                created_at: row.get(7)?,
                workspace_path: row.get(8)?,
            })
        })?;
        let mut sandboxes = Vec::new();
        for row in rows {
            sandboxes.push(row?);
        }
        Ok(sandboxes)
    }

    /// Resolve a sandbox name-or-id argument to the canonical UUID.
    ///
    /// Accepts either a full sandbox UUID or a human-readable name.  Returns
    /// `StoreError::NotFound` when no sandbox matches either field.
    pub fn resolve_sandbox_id(&self, name_or_id: &str) -> Result<String, StoreError> {
        self.conn()
            .query_row(
                "SELECT id FROM sandboxes WHERE id = ?1 OR name = ?1 ORDER BY created_at DESC LIMIT 1",
                rusqlite::params![name_or_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                other => StoreError::Sqlite(other),
            })
    }

    /// Stop a sandbox's container, revoke its persona/grants, and remove its
    /// on-disk state. `data_dir`, when `Some`, removes the whole per-sandbox
    /// state dir (`<data_dir>/sandboxes/<id>/`) — workspace + the ADR 154
    /// bridge-cert bundle (ADR 207 seam 6) — so the 0600 client key does not
    /// linger past the (now-closed) session. `None` (legacy / tests) falls back
    /// to removing only the recorded `workspace_path`.
    pub fn stop_sandbox(&self, id: &str, data_dir: Option<&Path>) -> Result<(), StoreError> {
        let (persona_id, container_id, workspace_path): (String, Option<String>, Option<String>) =
            self.conn()
                .query_row(
                    "SELECT persona_id, container_id, workspace_path FROM sandboxes WHERE id = ?1",
                    rusqlite::params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                    other => StoreError::Sqlite(other),
                })?;

        if let Some(ref cid) = container_id {
            match docker::output(["stop", cid.as_str()]) {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        cmd = "docker stop",
                        container_id = %cid,
                        exit = out.status.code().unwrap_or(-1),
                        stderr = %stderr.trim(),
                        "subprocess failed"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(cmd = "docker stop", container_id = %cid, error = %e, "subprocess spawn failed");
                }
            }
            match docker::output(["rm", cid.as_str()]) {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        cmd = "docker rm",
                        container_id = %cid,
                        exit = out.status.code().unwrap_or(-1),
                        stderr = %stderr.trim(),
                        "subprocess failed"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(cmd = "docker rm", container_id = %cid, error = %e, "subprocess spawn failed");
                }
            }
        }

        // Clean up the sandbox's on-disk state (fresh-clone workspace + ADR 154
        // bridge-cert bundle). Container must be removed first (above) so any
        // bind mounts are released. When `data_dir` is known, remove the whole
        // per-sandbox dir so the 0600 bridge client key never lingers past the
        // closed session; otherwise fall back to the recorded workspace path.
        match data_dir {
            Some(dd) => {
                let state_dir = sandbox_state_dir(dd, id);
                match std::fs::remove_dir_all(&state_dir) {
                    Ok(()) => {
                        tracing::info!(state_dir = %state_dir.display(), "sandbox state removed")
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::warn!(state_dir = %state_dir.display(), error = %e, "sandbox state remove failed")
                    }
                }
            }
            None => {
                if let Some(ref ws) = workspace_path {
                    let ws_path = PathBuf::from(ws);
                    match std::fs::remove_dir_all(&ws_path) {
                        Ok(()) => tracing::info!(workspace = %ws, "workspace removed"),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            tracing::warn!(workspace = %ws, error = %e, "workspace remove failed")
                        }
                    }
                }
            }
        }

        let _ = self.revoke_persona(&persona_id);

        let stopped_at = Utc::now().to_rfc3339();
        self.conn().execute(
            "UPDATE sandboxes SET status = 'stopped', stopped_at = ?1 WHERE id = ?2",
            rusqlite::params![stopped_at, id],
        )?;

        Ok(())
    }

    /// Delete a sandbox: remove the container (`docker rm -f`), wipe the
    /// fresh-clone workspace if any, drop the sandbox row, and — if the
    /// auto-created persona has no other references — delete the persona row
    /// too. Idempotent: returns `Ok(())` when the sandbox is already gone so
    /// `ember sandbox delete` retries don't fail loudly.
    ///
    /// DEMO-MAY3-HYGIENE: addresses the "stale `coding-agent` container blocks
    /// retry" demo failure. `stop_sandbox` leaves the row + persona behind so
    /// a second `sandbox create --name coding-agent` hits the
    /// `personas.name` UNIQUE constraint. `delete_sandbox` is the GC path.
    /// Delete a sandbox row, reap its container, and remove its on-disk state.
    ///
    /// `data_dir`, when `Some`, removes the whole per-sandbox state dir
    /// (`<data_dir>/sandboxes/<id>/`), covering both the fresh-clone workspace
    /// and the ADR 154 bridge-cert bundle (ADR 207 seam 6) in one shot. `None`
    /// (legacy / tests) falls back to removing only the recorded `workspace_path`.
    pub fn delete_sandbox(&self, id: &str, data_dir: Option<&Path>) -> Result<(), StoreError> {
        // Look up the row. NotFound is the idempotent path — caller already
        // got what they wanted.
        let row: Option<(String, String, Option<String>, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT name, persona_id, container_id, workspace_path FROM sandboxes WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::Sqlite(other)),
            })?;

        let Some((sandbox_name, persona_id, container_id, workspace_path)) = row else {
            return Ok(());
        };

        // Force-remove the container if we recorded one. `docker rm -f` stops
        // and removes in one shot and is idempotent against an already-gone
        // container (it errors but we tolerate that).
        if let Some(ref cid) = container_id {
            match docker::output(["rm", "-f", cid.as_str()]) {
                Ok(out) if !out.status.success() => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        cmd = "docker rm -f",
                        container_id = %cid,
                        exit = out.status.code().unwrap_or(-1),
                        stderr = %stderr.trim(),
                        "subprocess failed (tolerated — sandbox delete is idempotent)"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        cmd = "docker rm -f",
                        container_id = %cid,
                        error = %e,
                        "subprocess spawn failed (tolerated)"
                    );
                }
            }
        }

        // Belt-and-suspenders: also reap any container whose --name matches
        // the sandbox name. Covers the DEMO-MAY3-HYGIENE case where the row
        // was inserted but `start_container` failed before recording a
        // container_id, leaving an orphan docker container with the sandbox
        // name. `docker rm -f <name>` is a no-op when the container is gone.
        match docker::output(["rm", "-f", sandbox_name.as_str()]) {
            Ok(out) if !out.status.success() => {
                // No-such-container is the common case here; downgrade to debug.
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing::debug!(
                    cmd = "docker rm -f",
                    name = %sandbox_name,
                    exit = out.status.code().unwrap_or(-1),
                    stderr = %stderr.trim(),
                    "name-based reap returned non-zero (likely no such container — fine)"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    cmd = "docker rm -f",
                    name = %sandbox_name,
                    error = %e,
                    "subprocess spawn failed (tolerated)"
                );
            }
        }

        // Clean up the sandbox's on-disk state (fresh-clone workspace + ADR 154
        // bridge-cert bundle). Container must be gone first (above) so any bind
        // mounts are released. When `data_dir` is known, remove the whole
        // per-sandbox dir so the 0600 bridge client key never lingers; otherwise
        // fall back to the recorded workspace path (legacy / tests).
        match data_dir {
            Some(dd) => {
                let state_dir = sandbox_state_dir(dd, id);
                match std::fs::remove_dir_all(&state_dir) {
                    Ok(()) => {
                        tracing::info!(state_dir = %state_dir.display(), "sandbox state removed")
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::warn!(state_dir = %state_dir.display(), error = %e, "sandbox state remove failed")
                    }
                }
            }
            None => {
                if let Some(ref ws) = workspace_path {
                    let ws_path = PathBuf::from(ws);
                    match std::fs::remove_dir_all(&ws_path) {
                        Ok(()) => tracing::info!(workspace = %ws, "workspace removed"),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            tracing::warn!(workspace = %ws, error = %e, "workspace remove failed")
                        }
                    }
                }
            }
        }

        // Drop the sandbox row.
        self.conn()
            .execute("DELETE FROM sandboxes WHERE id = ?1", rusqlite::params![id])?;

        // If the auto-created persona has no other refs, delete it. Refs:
        //   - other sandbox rows (persona_id or owner_persona_id)
        //   - grants
        //   - approval_requests
        //   - standing_grants
        //   - notifications
        //   - receipts
        //
        // `personas.name UNIQUE` is the constraint that bites repeat
        // `sandbox create --name coding-agent` after a failed run, so
        // dropping the orphaned persona is the actual unblock.
        let other_refs: i64 = self.conn().query_row(
            "SELECT
                (SELECT COUNT(*) FROM sandboxes WHERE persona_id = ?1 OR owner_persona_id = ?1)
              + (SELECT COUNT(*) FROM grants WHERE persona_id = ?1)
              + (SELECT COUNT(*) FROM approval_requests WHERE persona_id = ?1)
              + (SELECT COUNT(*) FROM standing_grants WHERE persona_id = ?1)
              + (SELECT COUNT(*) FROM notifications WHERE persona_id = ?1)
              + (SELECT COUNT(*) FROM receipts WHERE persona_id = ?1)",
            rusqlite::params![persona_id],
            |row| row.get(0),
        )?;

        if other_refs == 0 {
            self.conn().execute(
                "DELETE FROM personas WHERE id = ?1",
                rusqlite::params![persona_id],
            )?;
            tracing::info!(persona_id = %persona_id, "auto-created persona deleted (no other refs)");
        } else {
            tracing::info!(
                persona_id = %persona_id,
                refs = other_refs,
                "persona retained — other rows reference it"
            );
        }

        Ok(())
    }

    /// Return the `owner_persona_id` stored for the given sandbox id.
    /// Returns `None` when the column is NULL (legacy row, no owner recorded).
    pub fn get_sandbox_owner(&self, sandbox_id: &str) -> Result<Option<String>, StoreError> {
        self.conn()
            .query_row(
                "SELECT owner_persona_id FROM sandboxes WHERE id = ?1",
                rusqlite::params![sandbox_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                other => StoreError::Sqlite(other),
            })
    }

    /// Execute a command in a running sandbox container.
    ///
    /// `caller_persona_id` must match the sandbox's `owner_persona_id`. When
    /// the stored `owner_persona_id` is NULL (legacy row predating REVIEW-F9),
    /// the check is skipped so existing single-user deployments continue to
    /// work without migration ceremony. New sandboxes created after this fix
    /// always store an owner and enforce the check.
    pub fn exec_sandbox(
        &self,
        id: &str,
        command: &[&str],
        caller_persona_id: &str,
    ) -> Result<String, StoreError> {
        let (container_id, status, owner_persona_id): (Option<String>, String, Option<String>) =
            self.conn()
                .query_row(
                    "SELECT container_id, status, owner_persona_id FROM sandboxes WHERE id = ?1",
                    rusqlite::params![id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
                    other => StoreError::Sqlite(other),
                })?;

        // Ownership check: when owner_persona_id is set, the caller must match.
        if let Some(ref owner) = owner_persona_id
            && owner != caller_persona_id
        {
            let details = format!(
                "attempted_persona={caller_persona_id} sandbox_owner={owner} sandbox_id={id}"
            );
            let _ = self.log_event(
                Some(caller_persona_id),
                "unauthorized.exec_sandbox",
                None,
                "denied",
                Some(&details),
            );
            tracing::warn!(
                caller_persona_id = %caller_persona_id,
                sandbox_owner = %owner,
                sandbox_id = %id,
                "exec_sandbox: caller persona does not own sandbox"
            );
            return Err(StoreError::Unauthorized);
        }

        if status != "running" {
            return Err(StoreError::InvalidInput(format!(
                "sandbox is not running (status: {status})"
            )));
        }

        let cid = container_id
            .ok_or_else(|| StoreError::InvalidInput("sandbox has no container".to_string()))?;

        let mut args = vec!["exec".to_string(), cid.clone()];
        args.extend(command.iter().map(|arg| arg.to_string()));

        let output = docker::output(&args)
            .map_err(|e| StoreError::InvalidInput(format!("docker not available: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            tracing::warn!(
                cmd = "docker exec",
                container_id = %cid,
                exit = output.status.code().unwrap_or(-1),
                stderr = %stderr,
                "subprocess failed"
            );
            return Err(StoreError::InvalidInput(format!(
                "docker exec failed: {stderr}"
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Shallow-clone a git URL into `target`. Host-side operation — the clone
/// happens as the daemon user; `chown_workspace_best_effort` follows up to
/// make the tree readable/writable by UID 1000 inside the container.
fn clone_workspace(url: &str, target: &Path) -> Result<(), StoreError> {
    // The clone runs as the daemon user BEFORE any container isolation, so the
    // operator-supplied `workspace_from` URL is a host-side injection surface:
    //   * a leading '-' is parsed by git as an option (e.g.
    //     `--upload-pack=<cmd>`), yielding arbitrary command execution;
    //   * the `xxx::yyy` remote-helper syntax (`ext::sh -c <cmd>`, `fd::`) runs
    //     arbitrary commands regardless of a `--` end-of-options separator.
    // Refuse both, and pass `--` so any remaining value is unambiguously a
    // positional repo argument. (Sweep 3 finding S-SANDBOX; ADR 070.)
    if url.starts_with('-') {
        return Err(StoreError::InvalidInput(format!(
            "refusing to clone workspace_from beginning with '-' (git-option injection): {url}"
        )));
    }
    if url.contains("::") {
        return Err(StoreError::InvalidInput(format!(
            "refusing to clone workspace_from with git remote-helper syntax \
             (`ext::`/`fd::` enable command execution): {url}"
        )));
    }
    let output = std::process::Command::new("git")
        .args([
            "clone",
            "--depth=1",
            "--",
            url,
            target.to_string_lossy().as_ref(),
        ])
        .output()
        .map_err(|e| StoreError::InvalidInput(format!("git not available: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        tracing::warn!(
            cmd = "git clone",
            url = %url,
            target = %target.display(),
            exit = output.status.code().unwrap_or(-1),
            stderr = %stderr,
            "subprocess failed"
        );
        return Err(StoreError::InvalidInput(format!(
            "git clone failed: {stderr}"
        )));
    }
    Ok(())
}

/// `chown -R 1000:1000 <target>`. Best-effort: logs a warning on failure
/// instead of aborting the create — macOS hosts without a matching UID still
/// let the container read the tree in practice, and the demo is
/// macOS + Linux-targeted. See ADR 070 §Backoffs.
fn chown_workspace_best_effort(target: &Path) {
    match std::process::Command::new("chown")
        .args(["-R", "1000:1000", target.to_string_lossy().as_ref()])
        .output()
    {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::warn!(
                cmd = "chown",
                target = %target.display(),
                exit = out.status.code().unwrap_or(-1),
                stderr = %stderr.trim(),
                "subprocess failed (workspace owner may not match container uid 1000; tolerated on macOS)"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                cmd = "chown",
                target = %target.display(),
                error = %e,
                "subprocess spawn failed (tolerated)"
            );
        }
    }
}

/// Host directory holding a sandbox's persistent state (`workspace/`,
/// `bridge-certs/`). Removed wholesale by [`DaemonStore::delete_sandbox`].
fn sandbox_state_dir(data_dir: &Path, sandbox_id: &str) -> PathBuf {
    data_dir.join("sandboxes").join(sandbox_id)
}

fn set_unix_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn write_sandbox_cert_file(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    set_unix_mode(path, mode)
}

/// Write a sandbox's per-spawn ADR 154 bridge client bundle to disk so it can be
/// bind-mounted into the container at `/run/ember` (ADR 207 seam 6). Returns the
/// host cert directory for [`SandboxBridgeMount`].
///
/// The cert + CA are world-readable (0644); the client KEY is 0600 inside a 0700
/// dir (so a sibling host uid cannot even list the key). The dir is chowned to
/// the container uid (1000) best-effort so the agent can read the 0600 key on
/// Linux Docker; macOS Docker bind-mounts remap ownership in the VM regardless.
///
/// Honest caveat (same as the fresh-clone workspace, which uses the identical
/// `chown_workspace_best_effort` pattern): on Linux Docker WITHOUT userns-remap
/// and a non-root daemon, the `chown 1000:1000` lacks `CAP_CHOWN` and fails, so
/// the container uid may not be able to read the 0600 key — the bridge then
/// fail-soft degrades. Robust cross-uid key delivery (userns-remap or handshake
/// bootstrap) is a follow-up shared with the workspace mount. Cleaned up with the
/// rest of the sandbox state on `stop_sandbox` / `delete_sandbox`.
pub(crate) fn materialize_sandbox_bridge_certs(
    data_dir: &Path,
    sandbox_id: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
    ca_cert_pem: &str,
) -> std::io::Result<PathBuf> {
    let dir = sandbox_state_dir(data_dir, sandbox_id).join("bridge-certs");
    std::fs::create_dir_all(&dir)?;
    set_unix_mode(&dir, 0o700)?;
    write_sandbox_cert_file(&dir.join("client.crt"), client_cert_pem.as_bytes(), 0o644)?;
    write_sandbox_cert_file(&dir.join("client.key"), client_key_pem.as_bytes(), 0o600)?;
    write_sandbox_cert_file(&dir.join("ca.crt"), ca_cert_pem.as_bytes(), 0o644)?;
    chown_workspace_best_effort(&dir);
    Ok(dir)
}

#[cfg(test)]
fn docker_available() -> bool {
    docker::available_with_local_image("alpine:latest")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn opts(name: &str) -> SandboxCreateOpts {
        SandboxCreateOpts {
            name: name.into(),
            image: "alpine:latest".into(),
            ..Default::default()
        }
    }

    // ---------- create_sandbox existing behavior ----------

    #[test]
    fn create_sandbox_appears_in_list() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("test-box", "alpine:latest").unwrap();
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-box");
        assert_eq!(list[0].image, "alpine:latest");
        assert!(list[0].container_id.is_none());
    }

    #[test]
    fn create_sandbox_auto_creates_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox("persona-box", "ubuntu:22.04").unwrap();
        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.name, "persona-box");
        assert_eq!(persona.status, "active");
    }

    #[test]
    fn stop_sandbox_without_container_changes_status_and_revokes_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("no-container-box", "alpine:latest")
            .unwrap();
        store.stop_sandbox(&sandbox.id, None).unwrap();

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].status, "stopped");

        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.status, "revoked");
    }

    // ---------- DEMO-MAY3-HYGIENE: delete_sandbox ----------

    #[test]
    fn delete_sandbox_removes_row_and_unreferenced_persona() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("coding-agent", "alpine:latest")
            .unwrap();
        let persona_id = sandbox.persona_id.clone();

        store.delete_sandbox(&sandbox.id, None).unwrap();

        // Sandbox row gone.
        let list = store.list_sandboxes().unwrap();
        assert!(list.is_empty(), "sandbox row should be deleted");

        // Persona row gone (no other refs).
        let result = store.get_persona(&persona_id);
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "persona should be deleted when no other refs exist"
        );
    }

    #[test]
    fn delete_sandbox_unblocks_recreate_with_same_name() {
        // The whole point of DEMO-MAY3-HYGIENE: after a stale sandbox is
        // deleted, the demo can re-create a sandbox with the same name
        // without hitting the `personas.name UNIQUE` constraint.
        let store = DaemonStore::open_in_memory().unwrap();
        let first = store
            .create_sandbox("coding-agent", "alpine:latest")
            .unwrap();
        store.delete_sandbox(&first.id, None).unwrap();

        let second = store
            .create_sandbox("coding-agent", "alpine:latest")
            .expect("recreate after delete must succeed");
        assert_ne!(first.id, second.id);
        assert_eq!(second.name, "coding-agent");
    }

    #[test]
    fn delete_sandbox_is_idempotent_on_missing_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        // No sandbox exists; delete must succeed silently.
        store
            .delete_sandbox("sandbox-does-not-exist", None)
            .expect("delete must be idempotent on missing id");
    }

    #[test]
    fn delete_sandbox_keeps_persona_with_other_refs() {
        // If a grant references the auto-created persona, the persona must
        // be retained (the foreign-key would orphan it otherwise) — only the
        // sandbox row itself is deleted.
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox("ref-keeper", "alpine:latest").unwrap();
        // Insert a fake grant row referencing the persona.
        store
            .conn()
            .execute(
                "INSERT INTO grants (id, persona_id, credential_name, scope, created_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    "grant-test-keep",
                    sandbox.persona_id,
                    "demo-cred",
                    "*",
                    Utc::now().to_rfc3339(),
                    "active",
                ],
            )
            .unwrap();

        store.delete_sandbox(&sandbox.id, None).unwrap();

        // Sandbox row gone.
        assert!(store.list_sandboxes().unwrap().is_empty());

        // Persona retained — it has a grant referencing it.
        let persona = store
            .get_persona(&sandbox.persona_id)
            .expect("persona must be retained when other refs exist");
        assert_eq!(persona.status, "active");
    }

    #[test]
    fn create_duplicate_sandbox_name_returns_error() {
        let store = DaemonStore::open_in_memory().unwrap();
        store.create_sandbox("dup-box", "alpine:latest").unwrap();
        let result = store.create_sandbox("dup-box", "alpine:latest");
        assert!(result.is_err());
    }

    // ---------- REVIEW-F7: resolve_sandbox_id determinism + UNIQUE(name) ----------

    #[test]
    fn resolve_sandbox_id_by_name_returns_correct_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sb = store.create_sandbox("resolve-me", "alpine:latest").unwrap();
        let resolved = store.resolve_sandbox_id("resolve-me").unwrap();
        assert_eq!(resolved, sb.id);
    }

    #[test]
    fn resolve_sandbox_id_by_id_returns_correct_id() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sb = store
            .create_sandbox("id-lookup-box", "alpine:latest")
            .unwrap();
        let resolved = store.resolve_sandbox_id(&sb.id).unwrap();
        assert_eq!(resolved, sb.id);
    }

    #[test]
    fn resolve_sandbox_id_missing_returns_not_found() {
        let store = DaemonStore::open_in_memory().unwrap();
        let result = store.resolve_sandbox_id("does-not-exist");
        assert!(matches!(result, Err(StoreError::NotFound)));
    }

    #[test]
    fn sandboxes_unique_name_constraint_enforced() {
        // The UNIQUE index on sandboxes(name) (REVIEW-F7) means inserting a
        // second sandbox with the same name must fail at the DB layer.
        let store = DaemonStore::open_in_memory().unwrap();
        store
            .create_sandbox("unique-check", "alpine:latest")
            .unwrap();
        let result = store.create_sandbox("unique-check", "alpine:latest");
        assert!(
            result.is_err(),
            "expected UNIQUE constraint error on duplicate sandbox name"
        );
    }

    #[test]
    fn resolve_sandbox_id_returns_newest_when_unique_index_dropped() {
        // Simulate an old v0 DB that predates UNIQUE(name) by dropping the
        // unique index, inserting two rows with the same name, then restoring
        // the index via the migration-equivalent CREATE UNIQUE INDEX.
        // The resolver must return the newest row (ORDER BY created_at DESC).
        let store = DaemonStore::open_in_memory().unwrap();

        // Drop the unique index so we can insert duplicates.
        store
            .conn()
            .execute_batch("DROP INDEX IF EXISTS idx_sandboxes_name;")
            .unwrap();

        // Also drop the implicit UNIQUE constraint baked into the CREATE TABLE
        // by recreating the table without it, so both inserts succeed.
        store
            .conn()
            .execute_batch(
                "CREATE TABLE sandboxes_noconstraint (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    persona_id TEXT NOT NULL,
                    container_id TEXT,
                    image TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'created',
                    created_at TEXT NOT NULL,
                    stopped_at TEXT,
                    workspace_path TEXT,
                    owner_persona_id TEXT,
                    session_id TEXT
                );
                INSERT INTO sandboxes_noconstraint SELECT * FROM sandboxes;
                DROP TABLE sandboxes;
                ALTER TABLE sandboxes_noconstraint RENAME TO sandboxes;",
            )
            .unwrap();

        // Insert two rows with the same name but different created_at
        // timestamps so we can assert ORDER BY picks the newer one.
        let older_id = "sandbox-older-000000000000000000000000000000";
        let newer_id = "sandbox-newer-000000000000000000000000000000";

        store
            .conn()
            .execute(
                "INSERT INTO sandboxes (id, name, persona_id, image, status, created_at)
             VALUES (?1, 'dup-name', 'p1', 'alpine:latest', 'created', '2024-01-01T00:00:00Z')",
                rusqlite::params![older_id],
            )
            .unwrap();

        store
            .conn()
            .execute(
                "INSERT INTO sandboxes (id, name, persona_id, image, status, created_at)
             VALUES (?1, 'dup-name', 'p2', 'alpine:latest', 'created', '2024-06-01T00:00:00Z')",
                rusqlite::params![newer_id],
            )
            .unwrap();

        // Resolver must return the newest row.
        let resolved = store.resolve_sandbox_id("dup-name").unwrap();
        assert_eq!(
            resolved, newer_id,
            "resolve_sandbox_id must return the newest sandbox when names collide"
        );
    }

    // ---------- 69J.3: start_container hardening invariants ----------

    fn args_for(env: &[(String, String)], network: Option<&str>) -> Vec<String> {
        build_run_args("test-name", "alpine:latest", network, env, None, None)
    }

    #[test]
    fn start_container_applies_no_new_privileges() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--security-opt" && w[1] == "no-new-privileges"),
            "missing --security-opt no-new-privileges in {args:?}"
        );
    }

    #[test]
    fn start_container_applies_user_1000() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--user" && w[1] == "1000:1000"),
            "missing --user 1000:1000 in {args:?}"
        );
    }

    #[test]
    fn start_container_applies_tmpfs_flags() {
        let args = args_for(&[], Some("none"));
        let mut saw_tmp = false;
        let mut saw_home = false;
        for w in args.windows(2) {
            if w[0] == "--tmpfs" {
                if w[1] == "/tmp:rw,noexec,nosuid,size=1g" {
                    saw_tmp = true;
                }
                if w[1] == "/home/agent:rw,nosuid,uid=1000,gid=1000,size=100m" {
                    saw_home = true;
                }
            }
        }
        assert!(saw_tmp, "missing tmpfs /tmp with full flags in {args:?}");
        assert!(
            saw_home,
            "missing tmpfs /home/agent with full flags in {args:?}"
        );
    }

    #[test]
    fn start_container_applies_readonly_root_and_cap_drop_all() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.iter().any(|a| a == "--read-only"),
            "missing --read-only"
        );
        assert!(
            args.iter().any(|a| a == "--cap-drop=ALL"),
            "missing --cap-drop=ALL"
        );
    }

    #[test]
    fn start_container_default_network_is_bridge() {
        let args = args_for(&[], None);
        assert!(
            args.iter().any(|a| a == "--network=bridge"),
            "expected --network=bridge when network is None, got {args:?}"
        );
    }

    #[test]
    fn start_container_test_override_none() {
        let args = args_for(&[], Some("none"));
        assert!(
            args.iter().any(|a| a == "--network=none"),
            "expected --network=none when explicitly set, got {args:?}"
        );
    }

    #[test]
    fn build_run_args_never_mounts_daemon_socket() {
        // ADR 154 / ADR 207 seam 6 — the daemon UDS is never bind-mounted into a
        // container: it is remapped `root:root` by the runtime userns so the
        // agent uid (1000) can never `connect(2)` to it. The container's control
        // plane is the mTLS bridge instead.
        let args = args_for(&[], Some("none"));
        assert!(
            !args.iter().any(|a| a.contains("daemon.sock")),
            "daemon UDS must never be mounted into a sandbox container; got {args:?}"
        );
    }

    #[test]
    fn build_run_args_mounts_bridge_certs_when_present() {
        // ADR 207 seam 6 — when a per-spawn mTLS bridge bundle was minted, its
        // host cert dir is bind-mounted read-only at /run/ember.
        let cert_dir = PathBuf::from("/var/data/sandboxes/sbx-1/bridge-certs");
        let args = build_run_args(
            "test-name",
            "alpine:latest",
            Some("none"),
            &[],
            None,
            Some(cert_dir.as_path()),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-v"
                    && w[1] == "/var/data/sandboxes/sbx-1/bridge-certs:/run/ember:ro"),
            "missing -v <cert_dir>:/run/ember:ro in {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.contains("daemon.sock")),
            "bridge mount must not reintroduce the daemon UDS; got {args:?}"
        );
    }

    #[test]
    fn build_run_args_omits_bridge_mount_when_absent() {
        // Fail-soft: no bridge bundle ⇒ no /run/ember mount (container still
        // starts, just without an emberd control plane).
        let args = args_for(&[], Some("none"));
        assert!(
            !args
                .windows(2)
                .any(|w| w[0] == "-v" && w[1].contains(":/run/ember:ro")),
            "expected no bridge cert mount when bridge is absent; got {args:?}"
        );
    }

    #[test]
    fn start_container_passes_persona_id_env() {
        let args = args_for(
            &[("EMBER_PERSONA_ID".into(), "persona-xyz".into())],
            Some("none"),
        );
        let mut saw = false;
        for w in args.windows(2) {
            if w[0] == "-e" && w[1] == "EMBER_PERSONA_ID=persona-xyz" {
                saw = true;
                break;
            }
        }
        assert!(saw, "missing -e EMBER_PERSONA_ID=persona-xyz in {args:?}");
    }

    #[test]
    fn build_run_args_sets_bridge_env_via_extra_env() {
        // The bridge control-plane env (`EMBER_BRIDGE_URL` / `EMBER_CLIENT_*` /
        // `EMBER_CA_CERT`) is assembled by `start_container` into `extra_env`;
        // `build_run_args` emits it as `-e`. Verify the emit point passes it
        // through (and never the removed `EMBER_DAEMON_SOCKET`).
        let args = args_for(
            &[
                (
                    "EMBER_BRIDGE_URL".into(),
                    "https://host.docker.internal:8765".into(),
                ),
                ("EMBER_CLIENT_CERT".into(), "/run/ember/client.crt".into()),
            ],
            Some("none"),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-e"
                    && w[1] == "EMBER_BRIDGE_URL=https://host.docker.internal:8765"),
            "missing -e EMBER_BRIDGE_URL in {args:?}"
        );
        assert!(
            !args.iter().any(|a| a.contains("EMBER_DAEMON_SOCKET")),
            "EMBER_DAEMON_SOCKET must no longer appear; got {args:?}"
        );
    }

    #[test]
    fn materialize_bridge_certs_perms_and_cleanup() {
        use std::os::unix::fs::PermissionsExt;
        // ADR 207 seam 6 — bridge bundle on disk: dir 0700, client.key 0600,
        // cert/CA 0644; removed wholesale by stop/delete so the key never lingers.
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("bridge-cert-box", "alpine:latest")
            .unwrap();

        let cert_dir =
            materialize_sandbox_bridge_certs(data_dir, &sandbox.id, "CERT", "KEY", "CA").unwrap();
        assert!(cert_dir.join("client.crt").exists());
        assert!(cert_dir.join("client.key").exists());
        assert!(cert_dir.join("ca.crt").exists());

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&cert_dir), 0o700, "bridge-certs dir must be 0700");
        assert_eq!(
            mode(&cert_dir.join("client.key")),
            0o600,
            "client.key must be 0600"
        );
        assert_eq!(mode(&cert_dir.join("client.crt")), 0o644);

        // delete removes the whole per-sandbox state dir (incl. the 0600 key).
        store.delete_sandbox(&sandbox.id, Some(data_dir)).unwrap();
        assert!(
            !cert_dir.exists(),
            "delete_sandbox must remove the bridge-cert dir"
        );
        assert!(!sandbox_state_dir(data_dir, &sandbox.id).exists());
    }

    // ADR 207 §I1 tripwire: a raw credential key in `extra_env` must NEVER reach
    // the container `-e` env — the strip drops it (and its value) at the sole
    // emit point. This test fails if host-env credential passthrough is ever
    // re-added. (Replaces the prior test that asserted ANTHROPIC_API_KEY
    // pass-through — that behavior was the Principle #1 violation ADR 207 closes.)
    #[test]
    fn start_container_strips_forbidden_credential_keys() {
        for key in FORBIDDEN_CONTAINER_ENV_KEYS {
            let args = args_for(
                &[((*key).to_string(), "sk-secret-value".to_string())],
                Some("none"),
            );
            assert!(
                !args.iter().any(|a| a.starts_with(&format!("{key}="))),
                "forbidden credential key {key} leaked into container env: {args:?}"
            );
            assert!(
                !args.iter().any(|a| a.contains("sk-secret-value")),
                "forbidden credential value for {key} leaked into container env: {args:?}"
            );
        }

        // The inert checkpoint `ANTHROPIC_AUTH_TOKEN` (and ONLY that exact value)
        // passes — Claude needs a bearer present to start under a brokered base
        // URL, and the proxy strips inbound `authorization` regardless.
        let args = args_for(
            &[(
                "ANTHROPIC_AUTH_TOKEN".into(),
                CONTAINER_PROXY_AUTH_PLACEHOLDER.into(),
            )],
            Some("none"),
        );
        assert!(
            args.windows(2).any(|w| w[0] == "-e"
                && w[1] == format!("ANTHROPIC_AUTH_TOKEN={CONTAINER_PROXY_AUTH_PLACEHOLDER}")),
            "inert checkpoint ANTHROPIC_AUTH_TOKEN must pass through: {args:?}"
        );

        // ADR 207 §I1 — a caller-smuggled REAL `ANTHROPIC_AUTH_TOKEN` (any value
        // other than the checkpoint) is stripped, so `extra_env` can't bypass the
        // broker with a raw bearer.
        let args = args_for(
            &[("ANTHROPIC_AUTH_TOKEN".into(), "sk-ant-real-bearer".into())],
            Some("none"),
        );
        assert!(
            !args.iter().any(|a| a.contains("sk-ant-real-bearer")),
            "non-checkpoint ANTHROPIC_AUTH_TOKEN must be stripped: {args:?}"
        );
    }

    // ADR 207 — the host-gateway mapping must be present on a real (bridge)
    // network so the proxy-injected `host.docker.internal` base URL resolves,
    // and absent on the offline `--network=none` test path.
    #[test]
    fn start_container_adds_host_gateway_on_bridge_only() {
        let args = args_for(&[], Some("bridge"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--add-host" && w[1] == "host.docker.internal:host-gateway"),
            "expected --add-host host.docker.internal:host-gateway on bridge: {args:?}"
        );
        let args_none = args_for(&[], Some("none"));
        assert!(
            !args_none
                .iter()
                .any(|a| a == "host.docker.internal:host-gateway"),
            "must not add host-gateway mapping on --network=none: {args_none:?}"
        );
    }

    // ADR 207 §I2 — the sandbox↔session binding must round-trip and clear, so
    // `sandbox_stop`/`sandbox_delete` can close the internal LLM-lane session.
    #[test]
    fn sandbox_session_id_round_trips_and_clears() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("session-bind", "alpine:latest")
            .unwrap();

        // Freshly created: no session bound.
        assert_eq!(store.sandbox_session_id(&sandbox.id).unwrap(), None);

        store
            .set_sandbox_session_id(&sandbox.id, "sess_abc123")
            .unwrap();
        assert_eq!(
            store.sandbox_session_id(&sandbox.id).unwrap().as_deref(),
            Some("sess_abc123")
        );

        store.clear_sandbox_session_id(&sandbox.id).unwrap();
        assert_eq!(store.sandbox_session_id(&sandbox.id).unwrap(), None);

        // Unknown sandbox id surfaces NotFound, not a silent None.
        assert!(matches!(
            store.sandbox_session_id("sandbox-does-not-exist"),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn rewrite_loopback_url_for_container_maps_to_host_docker_internal() {
        assert_eq!(
            rewrite_loopback_url_for_container("http://127.0.0.1:8484"),
            "http://host.docker.internal:8484"
        );
        assert_eq!(
            rewrite_loopback_url_for_container("https://localhost:4243"),
            "https://host.docker.internal:4243"
        );
        // Non-loopback URLs pass through untouched.
        assert_eq!(
            rewrite_loopback_url_for_container("https://api.anthropic.com"),
            "https://api.anthropic.com"
        );
    }

    #[test]
    fn start_container_passes_proxy_url_when_set() {
        // When EMBER_PROXY_URL is in the env slice it should appear as -e EMBER_PROXY_URL=...
        let args = args_for(
            &[("EMBER_PROXY_URL".into(), "http://127.0.0.1:4141".into())],
            Some("none"),
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-e" && w[1] == "EMBER_PROXY_URL=http://127.0.0.1:4141"),
            "expected EMBER_PROXY_URL pass-through in {args:?}"
        );

        // When the env slice does not contain the var it must not leak in.
        let args = args_for(&[], Some("none"));
        assert!(
            !args.iter().any(|a| a.starts_with("EMBER_PROXY_URL=")),
            "expected no EMBER_PROXY_URL when unset, got {args:?}"
        );
    }

    #[test]
    fn start_container_mounts_workspace_when_set() {
        let args = build_run_args(
            "test-name",
            "alpine:latest",
            Some("none"),
            &[],
            Some(&PathBuf::from("/var/data/ws")),
            None,
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "-v" && w[1] == "/var/data/ws:/workspace:rw"),
            "missing workspace bind mount in {args:?}"
        );
    }

    // ---------- 69J.4: refused-input invariants ----------

    #[test]
    fn create_sandbox_refuses_privileged() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("priv-box");
        o.privileged = true;
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-privileged"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_docker_socket_mount() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("dsock-box");
        o.volumes = vec!["/var/run/docker.sock:/var/run/docker.sock".into()];
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-docker-socket-mount"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_home_mount() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("home-box");
        o.volumes = vec!["$HOME:/mnt".into()];
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-home-mount"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn create_sandbox_refuses_ssh_aws_kube_gnupg_mounts() {
        for (path, slug) in [
            ("~/.ssh:/mnt/ssh", "no-ssh-mount"),
            ("~/.aws:/mnt/aws", "no-aws-mount"),
            ("~/.kube:/mnt/kube", "no-kube-mount"),
            ("~/.gnupg:/mnt/gnupg", "no-gnupg-mount"),
        ] {
            let store = DaemonStore::open_in_memory().unwrap();
            let mut o = opts(&format!("secret-{slug}"));
            o.volumes = vec![path.into()];
            let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
            match err {
                StoreError::InvalidInput(msg) => {
                    assert!(
                        msg.starts_with(&format!("sandbox invariant violated: {slug}")),
                        "path {path} expected slug {slug}, got msg: {msg}"
                    );
                }
                other => panic!("expected InvalidInput, got {other:?}"),
            }
        }
    }

    #[test]
    fn create_sandbox_refuses_root_user() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("root-box");
        o.user = Some("0".into());
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-root-user"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        // user=root also refused
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("root-named-box");
        o.user = Some("root".into());
        assert!(matches!(
            store.create_sandbox_with_opts(&o, None),
            Err(StoreError::InvalidInput(_))
        ));

        // With unsafe_root=true, user=0 is allowed
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("unsafe-root-box");
        o.user = Some("0".into());
        o.unsafe_root = true;
        assert!(store.create_sandbox_with_opts(&o, None).is_ok());
    }

    #[test]
    fn create_sandbox_refuses_host_network() {
        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("host-net-box");
        o.network = Some("host".into());
        let err = store.create_sandbox_with_opts(&o, None).unwrap_err();
        match err {
            StoreError::InvalidInput(msg) => {
                assert!(
                    msg.starts_with("sandbox invariant violated: no-host-network"),
                    "unexpected msg: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    // ---------- 69J.6: fresh-clone workspace ----------

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn make_bare_repo(base: &Path) -> PathBuf {
        // Create a source repo with one commit, then clone --bare to produce
        // a clonable URL (file path).
        let src = base.join("src-repo");
        std::fs::create_dir_all(&src).unwrap();
        let run = |args: &[&str], cwd: &Path| {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "-q", "-b", "main"], &src);
        run(&["config", "user.email", "t@t"], &src);
        run(&["config", "user.name", "t"], &src);
        std::fs::write(src.join("README.md"), "hello\n").unwrap();
        run(&["add", "."], &src);
        run(&["commit", "-q", "-m", "init"], &src);

        let bare = base.join("bare-repo.git");
        let out = std::process::Command::new("git")
            .args([
                "clone",
                "--bare",
                src.to_string_lossy().as_ref(),
                bare.to_string_lossy().as_ref(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "bare clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bare
    }

    #[test]
    fn clone_workspace_refuses_injection_urls() {
        // git-option injection (leading '-') and remote-helper command exec
        // (ext::/fd::) must be refused before git runs. (Sweep 3 S-SANDBOX.)
        let target = std::env::temp_dir().join("bosco-clone-injection-target");
        for bad in [
            "--upload-pack=touch /tmp/pwned",
            "-x",
            "ext::sh -c touch% /tmp/pwned",
            "fd::17/foo",
        ] {
            let r = clone_workspace(bad, &target);
            assert!(
                matches!(r, Err(StoreError::InvalidInput(_))),
                "expected refusal for {bad:?}, got {r:?}"
            );
        }
    }

    #[test]
    fn create_sandbox_with_workspace_from_clones_repo() {
        if !git_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let bare = make_bare_repo(tmp.path());
        let data_dir = tmp.path().join("data");

        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("ws-box");
        o.workspace_from = Some(bare.to_string_lossy().to_string());
        let sandbox = store.create_sandbox_with_opts(&o, Some(&data_dir)).unwrap();

        let ws = sandbox
            .workspace_path
            .as_deref()
            .expect("workspace_path should be set");
        let ws_path = PathBuf::from(ws);
        assert!(ws_path.exists(), "workspace dir {ws_path:?} should exist");
        assert!(
            ws_path.join("README.md").exists(),
            "cloned README.md should exist"
        );
    }

    #[test]
    fn stop_sandbox_removes_workspace_dir() {
        if !git_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let bare = make_bare_repo(tmp.path());
        let data_dir = tmp.path().join("data");

        let store = DaemonStore::open_in_memory().unwrap();
        let mut o = opts("ws-stop-box");
        o.workspace_from = Some(bare.to_string_lossy().to_string());
        let sandbox = store.create_sandbox_with_opts(&o, Some(&data_dir)).unwrap();
        let ws = PathBuf::from(sandbox.workspace_path.unwrap());
        assert!(ws.exists());

        store.stop_sandbox(&sandbox.id, None).unwrap();
        assert!(!ws.exists(), "workspace dir should be removed after stop");
    }

    // ---------- existing docker-gated integration tests ----------

    /// RAII guard that runs `docker rm -f <name>` on drop. Prevents
    /// hardcoded container-name collisions from leaking across test
    /// runs when a panic skips the explicit `stop_sandbox` cleanup —
    /// the failure mode that left `start-test-box` and `exec-test-box`
    /// pinned "Up 6 hours" before this fix and tripped every subsequent
    /// cargo-test run with "container name already in use."
    struct DockerContainerGuard(String);
    impl Drop for DockerContainerGuard {
        fn drop(&mut self) {
            let _ = docker::output(["rm", "-f", self.0.as_str()]);
        }
    }

    /// Unique container name per cargo-test process so two concurrent
    /// cargo invocations (e.g. orchestrator + dev shell) don't collide.
    fn unique_container_name(prefix: &str) -> String {
        format!("{}-{}", prefix, std::process::id())
    }

    #[test]
    fn start_container_docker_available() {
        if !docker_available() {
            return;
        }
        let name = unique_container_name("start-test-box");
        let _cleanup = DockerContainerGuard(name.clone());
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox(&name, "alpine:latest").unwrap();
        // Use --network=none so this test doesn't need to pull a bridge image.
        let container_id = store
            .start_container(&sandbox.id, Some("none"), &[], None)
            .unwrap();
        assert!(!container_id.is_empty());

        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].container_id.as_deref(), Some(container_id.as_str()));
        assert_eq!(list[0].status, "running");

        // Clean up
        store.stop_sandbox(&sandbox.id, None).unwrap();
    }

    #[test]
    fn exec_in_running_container_docker_available() {
        if !docker_available() {
            return;
        }
        let name = unique_container_name("exec-test-box");
        let _cleanup = DockerContainerGuard(name.clone());
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store.create_sandbox(&name, "alpine:latest").unwrap();
        store
            .start_container(&sandbox.id, Some("none"), &[], None)
            .unwrap();

        let output = store
            .exec_sandbox(&sandbox.id, &["echo", "hello"], "any-persona")
            .unwrap();
        assert!(output.contains("hello"));

        // Clean up
        store.stop_sandbox(&sandbox.id, None).unwrap();
    }

    #[test]
    fn stop_sandbox_cascades_grant_revocation() {
        let store = DaemonStore::open_in_memory().unwrap();
        let sandbox = store
            .create_sandbox("grant-cascade-box", "alpine:latest")
            .unwrap();

        // Create a grant for the sandbox's persona
        store
            .create_grant(&sandbox.persona_id, "api-key", "read", None)
            .unwrap();

        // Verify grant is active
        let grant = store
            .evaluate_grant(&sandbox.persona_id, "api-key")
            .unwrap();
        assert_eq!(grant.status, "active");

        // Stop sandbox
        store.stop_sandbox(&sandbox.id, None).unwrap();

        // Grant should be revoked
        let result = store.evaluate_grant(&sandbox.persona_id, "api-key");
        assert!(result.is_err()); // NotFound because revoked
    }

    #[test]
    fn sandbox_full_lifecycle() {
        let store = DaemonStore::open_in_memory().unwrap();

        // Create
        let sandbox = store
            .create_sandbox("lifecycle-box", "alpine:latest")
            .unwrap();
        assert_eq!(sandbox.status, "created");

        // List
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list.len(), 1);

        // Stop
        store.stop_sandbox(&sandbox.id, None).unwrap();
        let list = store.list_sandboxes().unwrap();
        assert_eq!(list[0].status, "stopped");

        // Persona revoked
        let persona = store.get_persona(&sandbox.persona_id).unwrap();
        assert_eq!(persona.status, "revoked");
    }

    // ---------- REVIEW-F9: exec_sandbox ownership enforcement ----------

    #[test]
    fn exec_sandbox_rejects_wrong_persona() {
        let store = DaemonStore::open_in_memory().unwrap();

        // persona-A creates the sandbox
        let mut o = opts("owned-box");
        o.owner_persona_id = Some("persona-A".to_string());
        let sandbox = store.create_sandbox_with_opts(&o, None).unwrap();
        assert_eq!(sandbox.owner_persona_id.as_deref(), Some("persona-A"));

        // Manually flip status to 'running' so exec gets past the status check.
        // (We don't spin up docker here — the ownership check fires first.)
        store
            .conn()
            .execute(
                "UPDATE sandboxes SET status = 'running', container_id = 'fake-cid' WHERE id = ?1",
                rusqlite::params![sandbox.id],
            )
            .unwrap();

        // persona-B's exec attempt must be rejected with Unauthorized.
        let err = store
            .exec_sandbox(&sandbox.id, &["echo", "hello"], "persona-B")
            .unwrap_err();
        assert!(
            matches!(err, StoreError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    #[test]
    fn exec_sandbox_allows_owner_persona() {
        let store = DaemonStore::open_in_memory().unwrap();

        let mut o = opts("owned-box-owner");
        o.owner_persona_id = Some("persona-A".to_string());
        let sandbox = store.create_sandbox_with_opts(&o, None).unwrap();

        store
            .conn()
            .execute(
                "UPDATE sandboxes SET status = 'running', container_id = 'fake-cid' WHERE id = ?1",
                rusqlite::params![sandbox.id],
            )
            .unwrap();

        // persona-A is the owner — exec proceeds past the ownership check.
        // It will fail later (docker exec on a fake container id), but we get
        // a docker-level error, not Unauthorized.
        let result = store.exec_sandbox(&sandbox.id, &["echo", "hi"], "persona-A");
        assert!(
            !matches!(result, Err(StoreError::Unauthorized)),
            "owner should not get Unauthorized: {result:?}"
        );
    }

    #[test]
    fn exec_sandbox_null_owner_skips_check() {
        let store = DaemonStore::open_in_memory().unwrap();

        // Legacy sandbox: create_sandbox sets owner_persona_id = None.
        let sandbox = store.create_sandbox("legacy-box", "alpine:latest").unwrap();
        assert!(sandbox.owner_persona_id.is_none());

        store
            .conn()
            .execute(
                "UPDATE sandboxes SET status = 'running', container_id = 'fake-cid' WHERE id = ?1",
                rusqlite::params![sandbox.id],
            )
            .unwrap();

        // Any caller persona is allowed when owner is NULL.
        let result = store.exec_sandbox(&sandbox.id, &["echo", "hi"], "any-persona");
        assert!(
            !matches!(result, Err(StoreError::Unauthorized)),
            "null owner should skip check: {result:?}"
        );
    }

    #[test]
    fn exec_sandbox_audit_event_emitted_on_unauthorized() {
        use crate::infra::audit::AuditFilter;

        let store = DaemonStore::open_in_memory().unwrap();

        let mut o = opts("audit-box");
        o.owner_persona_id = Some("persona-owner".to_string());
        let sandbox = store.create_sandbox_with_opts(&o, None).unwrap();

        store
            .conn()
            .execute(
                "UPDATE sandboxes SET status = 'running', container_id = 'fake-cid' WHERE id = ?1",
                rusqlite::params![sandbox.id],
            )
            .unwrap();

        let _ = store.exec_sandbox(&sandbox.id, &["ls"], "persona-intruder");

        let entries = store
            .query_audit(&AuditFilter {
                action: Some("unauthorized.exec_sandbox".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "expected one unauthorized.exec_sandbox audit entry"
        );
        let e = &entries[0];
        assert_eq!(e.outcome, "denied");
        assert_eq!(e.agent_id.as_deref(), Some("persona-intruder"));
    }
}
